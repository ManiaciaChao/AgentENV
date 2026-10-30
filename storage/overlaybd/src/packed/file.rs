//! Logical-block adapter. This experimental API is deliberately not selected by
//! existing upper creation paths until lifecycle and performance acceptance pass.
use super::{
    core::{Core, ReadView, DIRTY_LIMIT},
    disk::{FileDisk, PAGE},
    Policy, Stats,
};
use crate::{
    io::virtual_file::VirtualFile,
    lsmt::{
        file::{compact_to, CommitArgs, LSMTReadOnlyFile},
        index::SegmentMapping,
    },
};
use anyhow::{ensure, Context, Result};
use async_trait::async_trait;
use bytes::Bytes;
use std::collections::BTreeMap;
use std::{
    path::Path,
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};
use tokio::sync::{Notify, RwLock};
type Dirty = BTreeMap<u64, Arc<[u8; PAGE]>>;
// Leave half the dirty budget available to the foreground while committing.
const GENERATION_LIMIT: usize = DIRTY_LIMIT / 2;

struct Front {
    pending: Dirty,
    inflight: Dirty,
    recycled: Vec<Arc<[u8; PAGE]>>,
    view: ReadView,
    sequence: u64,
    durable: u64,
    requested: u64,
    policy: Policy,
    stats: Stats,
}
#[derive(Default)]
struct Ranges {
    active: Mutex<(u64, BTreeMap<u64, (u64, u64)>)>,
    changed: Notify,
}
struct RangeLease {
    ranges: Arc<Ranges>,
    id: Option<u64>,
}
impl Drop for RangeLease {
    fn drop(&mut self) {
        if let Some(id) = self.id {
            self.ranges.active.lock().unwrap().1.remove(&id);
            self.ranges.changed.notify_waiters();
        }
    }
}
struct Shared {
    front: Arc<Mutex<Front>>,
    notify: Arc<Notify>,
    lower: Option<Arc<LSMTReadOnlyFile>>,
    size: u64,
    uuid: uuid::Uuid,
    gate: RwLock<()>,
    ranges: Arc<Ranges>,
    wake: std::sync::mpsc::SyncSender<()>,
    stop: Arc<std::sync::atomic::AtomicBool>,
    worker: Mutex<Option<thread::JoinHandle<()>>>,
}
impl Drop for Shared {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Release);
        let _ = self.wake.try_send(());
        if let Some(worker) = self.worker.get_mut().unwrap().take() {
            let _ = worker.join();
        }
        // Drop is not an acknowledgement boundary. The caller must explicitly sync.
    }
}
#[derive(Clone)]
pub struct PackedUpper(Arc<Shared>);
impl PackedUpper {
    #[cfg(test)]
    pub(super) fn from_core(core: Core) -> Result<Self> {
        let size = core.size();
        Self::start(core, None, size)
    }
    pub fn create(path: &Path, size: u64, policy: Policy) -> Result<()> {
        let disk = Arc::new(FileDisk::open(path, true)?);
        Core::create(disk, size, policy)?;
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::File::open(parent)?.sync_all()?;
        }
        Ok(())
    }
    pub async fn open(
        path: &Path,
        lower: Option<Arc<LSMTReadOnlyFile>>,
        policy: Policy,
    ) -> Result<Self> {
        let core = Core::open(Arc::new(FileDisk::open(path, false)?), policy)?;
        let size = core.size();
        if let Some(lower) = &lower {
            ensure!(
                lower.size().await? == size,
                "packed/lower geometry mismatch"
            );
        }
        Self::start(core, lower, size)
    }
    fn start(mut core: Core, lower: Option<Arc<LSMTReadOnlyFile>>, size: u64) -> Result<Self> {
        let uuid = core.uuid();
        let front = Arc::new(Mutex::new(Front {
            pending: Dirty::new(),
            inflight: Dirty::new(),
            recycled: Vec::new(),
            view: core.view(),
            sequence: 0,
            durable: 0,
            requested: 0,
            policy: core.policy,
            stats: core.stats()?,
        }));
        let notify = Arc::new(Notify::new());
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (wake, rx) = std::sync::mpsc::sync_channel(1);
        let (state, changed, stopping) = (front.clone(), notify.clone(), stop.clone());
        let publication_wake = wake.clone();
        let worker = thread::Builder::new()
            .name("packed-commit".into())
            .spawn(move || {
                let mut immediate = false;
                let mut publication_boundary = 0;
                let mut last_commit = std::time::Instant::now();
                loop {
                    if !immediate {
                        let timeout = if core.publication_pending() {
                            Duration::from_millis(100)
                        } else {
                            Duration::from_millis(100).saturating_sub(last_commit.elapsed())
                        };
                        let _ = rx.recv_timeout(timeout);
                    }
                    if stopping.load(std::sync::atomic::Ordering::Acquire) {
                        break;
                    }
                    match core.finish_publication(false) {
                        Ok(true) => {
                            let stats = core.stats();
                            let mut f = state.lock().unwrap();
                            match stats {
                                Ok(stats) => f.stats = stats,
                                Err(error) => f.view.fail(&error),
                            }
                            f.durable = f.durable.max(publication_boundary);
                            f.view = core.view();
                            drop(f);
                            changed.notify_waiters();
                        }
                        Err(error) => state.lock().unwrap().view.fail(&error),
                        Ok(false) => {}
                    }
                    // Only the coordinator owns Core. Foreground locks protect short
                    // pointer/map operations, never compression, disk I/O or barriers.
                    let batch = {
                        let mut f = state.lock().unwrap();
                        if f.view.check().is_err() {
                            last_commit = std::time::Instant::now();
                            immediate = false;
                            changed.notify_waiters();
                            continue;
                        }
                        let commit = !core.publication_pending()
                            && (f.requested > f.durable
                                || last_commit.elapsed() >= Duration::from_millis(100));
                        // Capacity wakeups from the previous inflight generation can
                        // be stale. Do not turn them into undersized new commits.
                        if !f.pending.is_empty()
                            && f.requested <= f.durable
                            && f.pending.len() * PAGE < GENERATION_LIMIT
                            && last_commit.elapsed() < Duration::from_millis(100)
                        {
                            immediate = false;
                            continue;
                        }
                        let split = if !commit {
                            f.pending.keys().nth(GENERATION_LIMIT / PAGE).copied()
                        } else {
                            None
                        };
                        let (pending, boundary) = if let Some(key) = split {
                            let remaining = f.pending.split_off(&key);
                            // A key-sorted subset is not a sequence prefix. Do not
                            // advance durable until a subsequent complete drain.
                            (std::mem::replace(&mut f.pending, remaining), f.durable)
                        } else {
                            (std::mem::take(&mut f.pending), f.sequence)
                        };
                        f.inflight = pending.clone();
                        (pending, boundary, f.policy, commit)
                    };
                    let wrote = !batch.0.is_empty();
                    core.pending = batch.0;
                    core.policy = batch.2;
                    let result = if wrote || core.has_writeback() {
                        if batch.3 {
                            core.begin_commit(publication_wake.clone()).map(|began| {
                                if began {
                                    publication_boundary = batch.1;
                                }
                            })
                        } else {
                            core.writeback()
                        }
                    } else {
                        core.maintenance_interruptible(|| !state.lock().unwrap().pending.is_empty())
                    };
                    if batch.3 {
                        last_commit = std::time::Instant::now();
                    }
                    // Collect observability without holding the foreground lock.
                    let statistics = if result.is_ok() {
                        Some(core.stats())
                    } else {
                        None
                    };
                    let mut f = state.lock().unwrap();
                    match result {
                        Ok(()) => {
                            f.view = core.view();
                            let retired = std::mem::take(&mut f.inflight);
                            for block in retired.into_values() {
                                if Arc::strong_count(&block) == 1
                                    && f.recycled.len() + f.pending.len() < DIRTY_LIMIT / PAGE
                                {
                                    f.recycled.push(block);
                                }
                            }
                            match statistics.unwrap() {
                                Ok(stats) => f.stats = stats,
                                Err(e) => f.view.fail(&e),
                            }
                        }
                        Err(e) => f.view.fail(&e),
                    }
                    let more = !f.pending.is_empty();
                    drop(f);
                    changed.notify_waiters();
                    // Don't wait for the timer when capacity pressure queued another batch.
                    immediate = more;
                }
            })?;
        Ok(Self(Arc::new(Shared {
            front,
            notify,
            lower,
            size,
            uuid,
            gate: RwLock::new(()),
            ranges: Arc::new(Ranges::default()),
            wake,
            stop,
            worker: Mutex::new(Some(worker)),
        })))
    }
    async fn wait_durable(&self, boundary: u64) -> Result<()> {
        loop {
            let notified = self.0.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let mut f = self.0.front.lock().unwrap();
                f.view.check()?;
                f.requested = f.requested.max(boundary);
                if f.durable >= boundary {
                    return Ok(());
                }
            }
            let _ = self.0.wake.try_send(());
            notified.await;
        }
    }
    async fn flush_locked(&self) -> Result<()> {
        let boundary = self.0.front.lock().unwrap().sequence;
        self.wait_durable(boundary).await
    }
    async fn stage(&self, lba: u64, block: Arc<[u8; PAGE]>) -> Result<()> {
        loop {
            let notified = self.0.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let mut f = self.0.front.lock().unwrap();
                f.view.check()?;
                if f.pending.contains_key(&lba)
                    || (f.pending.len() + f.inflight.len()) * PAGE < DIRTY_LIMIT
                {
                    if let Some(old) = f.pending.insert(lba, block) {
                        if Arc::strong_count(&old) == 1
                            && f.recycled.len() + f.pending.len() + f.inflight.len()
                                < DIRTY_LIMIT / PAGE
                        {
                            f.recycled.push(old);
                        }
                    }
                    f.sequence = f
                        .sequence
                        .checked_add(1)
                        .context("packed write sequence overflow")?;
                    return Ok(());
                }
            }
            let _ = self.0.wake.try_send(());
            notified.await;
        }
    }
    async fn lock_range(&self, offset: u64, len: usize) -> RangeLease {
        let ranges = &self.0.ranges;
        if len == 0 {
            return RangeLease {
                ranges: ranges.clone(),
                id: None,
            };
        }
        // Partial sector writes replace a whole logical block after RMW.
        // Adjacent byte ranges in that block must share the same lease.
        let end = (offset + len as u64 - 1) / PAGE as u64 + 1;
        let offset = offset / PAGE as u64;
        loop {
            let changed = ranges.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            {
                let mut active = ranges.active.lock().unwrap();
                if !active
                    .1
                    .values()
                    .any(|&(start, stop)| start < end && offset < stop)
                {
                    let id = active.0;
                    active.0 = active.0.wrapping_add(1);
                    active.1.insert(id, (offset, end));
                    return RangeLease {
                        ranges: ranges.clone(),
                        id: Some(id),
                    };
                }
            }
            changed.await;
        }
    }
    fn bounds(&self, offset: u64, len: usize) -> Result<()> {
        ensure!(
            offset
                .checked_add(len as u64)
                .is_some_and(|end| end <= self.0.size),
            "packed I/O outside volume"
        );
        Ok(())
    }
    async fn block(&self, lba: u64) -> Result<Box<[u8; PAGE]>> {
        let (pending, view) = {
            let f = self.0.front.lock().unwrap();
            f.view.check()?;
            (
                f.pending
                    .get(&lba)
                    .or_else(|| f.inflight.get(&lba))
                    .cloned(),
                f.view.clone(),
            )
        };
        if let Some(block) = pending {
            return Ok(Box::new(*block));
        }
        if let Some(block) = view.read(lba)? {
            return Ok(block);
        }
        let mut block = Box::new([0; PAGE]);
        if let Some(lower) = &self.0.lower {
            let offset = lba * PAGE as u64;
            let n = (self.0.size - offset).min(PAGE as u64) as usize;
            ensure!(
                lower.read_at_into(offset, &mut block[..n]).await? == n,
                "short packed lower read"
            );
        }
        Ok(block)
    }
    // Keep aligned bulk writes in bounded 128 KiB frontend batches. The range
    // lease still serializes overlaps; one short lock admits data and assigns
    // sequence numbers, without per-4-KiB async staging/lock round trips.
    async fn stage_aligned(&self, offset: u64, bytes: &[u8]) -> Result<usize> {
        loop {
            let notified = self.0.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let (done, wake) = {
                let mut f = self.0.front.lock().unwrap();
                f.view.check()?;
                let mut done = 0;
                for chunk in bytes.chunks_exact(PAGE).take(32) {
                    let lba = (offset + done as u64) / PAGE as u64;
                    if !f.pending.contains_key(&lba)
                        && (f.pending.len() + f.inflight.len()) * PAGE >= DIRTY_LIMIT
                    {
                        break;
                    }
                    let sequence = f
                        .sequence
                        .checked_add(1)
                        .context("packed write sequence overflow")?;
                    let mut block = f.recycled.pop().unwrap_or_else(|| Arc::new([0; PAGE]));
                    Arc::get_mut(&mut block)
                        .expect("exclusive recycled block")
                        .copy_from_slice(chunk);
                    if let Some(old) = f.pending.insert(lba, block) {
                        if Arc::strong_count(&old) == 1
                            && f.recycled.len() + f.pending.len() + f.inflight.len()
                                < DIRTY_LIMIT / PAGE
                        {
                            f.recycled.push(old);
                        }
                    }
                    f.sequence = sequence;
                    done += PAGE;
                }
                (done, f.pending.len() * PAGE >= GENERATION_LIMIT)
            };
            if wake || done == 0 {
                let _ = self.0.wake.try_send(());
            }
            if done != 0 {
                return Ok(done);
            }
            notified.await;
        }
    }
    async fn write_locked(&self, offset: u64, bytes: &[u8]) -> Result<usize> {
        let mut done = 0;
        while done < bytes.len() {
            let pos = offset + done as u64;
            if pos % PAGE as u64 == 0 && bytes.len() - done >= PAGE {
                done += self.stage_aligned(pos, &bytes[done..]).await?;
                continue;
            }
            let lba = pos / PAGE as u64;
            let inside = (pos % PAGE as u64) as usize;
            let n = (PAGE - inside).min(bytes.len() - done);
            let mut block = self
                .0
                .front
                .lock()
                .unwrap()
                .recycled
                .pop()
                .unwrap_or_else(|| Arc::new([0; PAGE]));
            let plain = Arc::get_mut(&mut block).expect("recycled block is exclusively owned");
            if inside != 0 || n != PAGE {
                plain.copy_from_slice(self.block(lba).await?.as_slice());
            }
            plain[inside..inside + n].copy_from_slice(&bytes[done..done + n]);
            self.stage(lba, block).await?;
            done += n;
        }
        Ok(done)
    }

    pub fn policy(&self) -> Policy {
        self.0.front.lock().unwrap().policy
    }
    pub fn lower_files_bottom_to_top(&self) -> Vec<Arc<dyn VirtualFile>> {
        let mut files = self
            .0
            .lower
            .as_ref()
            .map(|l| l.get_lower_files())
            .unwrap_or_default();
        files.reverse();
        files
    }
    pub fn get_uuid(&self, layer: usize) -> Result<uuid::Uuid> {
        let count = self
            .0
            .lower
            .as_ref()
            .map(|l| l.get_lower_files().len())
            .unwrap_or(0);
        if layer == count {
            Ok(self.uuid())
        } else {
            self.0
                .lower
                .as_ref()
                .context("packed layer index out of bounds")?
                .get_uuid(layer)
        }
    }
    fn mappings(&self, include_lower: bool) -> Vec<SegmentMapping> {
        use crate::lsmt::index::{MutableIndex, Segment};
        let mut index = MutableIndex::new();
        if include_lower {
            if let Some(lower) = &self.0.lower {
                let mut offset = 0;
                let sectors = self.0.size / 512;
                while offset < sectors {
                    let n = (sectors - offset).min(u32::MAX as u64) as u32;
                    let mut mappings = Vec::new();
                    lower.index().lookup(Segment::new(offset, n), &mut mappings);
                    for mut m in mappings {
                        m.moffset = m.offset();
                        m.tag = 0;
                        index.insert(m);
                    }
                    offset += n as u64;
                }
            }
        }
        let entries = {
            let f = self.0.front.lock().unwrap();
            let mut entries: BTreeMap<_, _> = f.view.mappings().into_iter().collect();
            entries.extend(
                f.inflight
                    .iter()
                    .chain(f.pending.iter())
                    .map(|(&l, b)| (l, b.iter().all(|x| *x == 0))),
            );
            entries
        };
        for (lba, zero) in entries {
            index.insert(SegmentMapping::new(
                lba * 8,
                ((self.0.size - lba * PAGE as u64).min(PAGE as u64) / 512) as u32,
                lba * 8,
                zero,
                0,
            ));
        }
        index.dump()
    }
    pub fn data_stat(&self) -> Result<crate::lsmt::file::DataStat> {
        Ok(crate::lsmt::file::DataStat {
            total_data_size: self.stats()?.host_bytes,
            valid_data_size: self
                .mappings(true)
                .iter()
                .filter(|m| !m.zeroed)
                .map(|m| m.length() as u64 * 512)
                .sum(),
        })
    }
    pub async fn flatten(&self, output: Arc<dyn VirtualFile>) -> Result<()> {
        let _gate = self.0.gate.write().await;
        self.flush_locked().await?;
        compact_to(
            &[Arc::new(self.clone())],
            &self.mappings(true),
            self.0.size,
            CommitArgs::new(output),
        )
        .await
    }
    pub fn uuid(&self) -> uuid::Uuid {
        self.0.uuid
    }
    pub fn stats(&self) -> Result<Stats> {
        {
            let f = self.0.front.lock().unwrap();
            f.view.check()?;
            let mut stats = f.stats.clone();
            stats.dirty_bytes = (f.pending.len() + f.inflight.len()) * PAGE;
            Ok(stats)
        }
    }
    pub async fn set_policy(&self, policy: Policy) -> Result<()> {
        let _gate = self.0.gate.write().await;
        self.flush_locked().await?;
        self.0.front.lock().unwrap().policy = policy;
        Ok(())
    }
    /// Schedule background maintenance; user flush never waits for cleaner completion.
    pub async fn maintenance(&self) -> Result<()> {
        self.0.front.lock().unwrap().view.check()?;
        let _ = self.0.wake.try_send(());
        Ok(())
    }
    pub async fn export_upper_as_sealed(&self, mut args: CommitArgs) -> Result<()> {
        let _gate = self.0.gate.write().await;
        self.flush_locked().await?;
        let mappings = self.mappings(false);
        args.parent_uuid = self
            .0
            .lower
            .as_ref()
            .map(|lower| lower.get_uuid(0))
            .transpose()?;
        compact_to(&[Arc::new(self.clone())], &mappings, self.0.size, args).await
    }
}
#[async_trait]
impl VirtualFile for PackedUpper {
    async fn size(&self) -> Result<u64> {
        Ok(self.0.size)
    }
    async fn read_at(&self, offset: u64, len: usize) -> Result<Bytes> {
        let n = (self.0.size.saturating_sub(offset)).min(len as u64) as usize;
        let mut bytes = vec![0; n];
        self.read_at_into(offset, &mut bytes).await?;
        Ok(bytes.into())
    }
    async fn read_at_into(&self, offset: u64, dst: &mut [u8]) -> Result<usize> {
        let n = self.0.size.saturating_sub(offset).min(dst.len() as u64) as usize;
        let _locks = self.lock_range(offset, n).await;
        let mut done = 0;
        while done < n {
            let pos = offset + done as u64;
            let inside = (pos % PAGE as u64) as usize;
            let take = (PAGE - inside).min(n - done);
            let block = self.block(pos / PAGE as u64).await?;
            dst[done..done + take].copy_from_slice(&block[inside..inside + take]);
            done += take;
        }
        Ok(n)
    }
    async fn write_at(&self, offset: u64, bytes: &[u8]) -> Result<usize> {
        self.bounds(offset, bytes.len())?;
        let _gate = self.0.gate.read().await;
        let _locks = self.lock_range(offset, bytes.len()).await;
        self.write_locked(offset, bytes).await
    }
    async fn seek_data(&self, offset: u64) -> Result<Option<u64>> {
        let _gate = self.0.gate.write().await;
        Ok(self
            .mappings(true)
            .iter()
            .filter(|m| !m.zeroed && m.end() * 512 > offset)
            .map(|m| (m.offset() * 512).max(offset))
            .next())
    }
    async fn seek_hole(&self, offset: u64) -> Result<Option<u64>> {
        let _gate = self.0.gate.write().await;
        if offset >= self.0.size {
            return Ok(None);
        }
        let mut cursor = offset;
        for m in self
            .mappings(true)
            .iter()
            .filter(|m| !m.zeroed && m.end() * 512 > offset)
        {
            if m.offset() * 512 > cursor {
                break;
            }
            cursor = cursor.max(m.end() * 512);
        }
        Ok(Some(cursor.min(self.0.size)))
    }
    async fn sync(&self) -> Result<()> {
        let gate = self.0.gate.write().await;
        let boundary = self.0.front.lock().unwrap().sequence;
        drop(gate);
        self.wait_durable(boundary).await
    }
    async fn discard(&self, offset: u64, len: u64) -> Result<()> {
        self.bounds(offset, usize::try_from(len)?)?;
        let _gate = self.0.gate.read().await;
        let _locks = self.lock_range(offset, len as usize).await;
        // Reuse RMW so even unaligned discard masks the lower without losing neighbours.
        let zeros = [0; PAGE];
        let mut done = 0;
        while done < len {
            let n = (len - done).min(PAGE as u64) as usize;
            self.write_locked(offset + done, &zeros[..n]).await?;
            done += n as u64;
        }
        Ok(())
    }
}
