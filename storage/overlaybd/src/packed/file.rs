//! Logical-block adapter. This experimental API is deliberately not selected by
//! existing upper creation paths until lifecycle and performance acceptance pass.
mod coordinator;
use super::{
    core::{Core, ReadMask, ReadView, DIRTY_LIMIT, READ_BLOCKS},
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
#[cfg(test)]
use std::time::Duration;
use std::{
    path::Path,
    sync::{Arc, Mutex},
    thread,
};
use tokio::sync::{Notify, RwLock};
type Dirty = super::memory::Map<super::buffer::Block>;
// Leave half the dirty budget available to the foreground while committing.
const GENERATION_LIMIT: usize = DIRTY_LIMIT / 2;
// Four 1 MiB jobs keep all encoder workers busy without consuming the
// entire next-generation plaintext allowance.
const PREPARE_THRESHOLD: usize = 4 * 1024 * 1024;

struct Prepared {
    blocks: Arc<Dirty>,
    boundary: u64,
    policy: Policy,
    encoding: Option<super::encode::Encoding>,
}
struct Front {
    prepared: Option<Prepared>,
    pending: Dirty,
    inflight: Arc<Dirty>,
    pressure: bool,
    view: ReadView,
    sequence: u64,
    durable: u64,
    requested: u64,
    policy: Policy,
    stats: Stats,
}
impl Front {
    fn dirty_blocks(&self) -> usize {
        self.pending.len()
            + self.inflight.len()
            + self.prepared.as_ref().map_or(0, |p| p.blocks.len())
    }
    fn has_pending(&self) -> bool {
        !self.pending.is_empty() || self.prepared.is_some()
    }
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
    budget: Arc<super::buffer::Budget>,
    caller_qos: std::sync::atomic::AtomicU32,
    stage_ns: std::sync::atomic::AtomicU64,
    wait_ns: std::sync::atomic::AtomicU64,
    lower: Option<Arc<LSMTReadOnlyFile>>,
    size: u64,
    uuid: uuid::Uuid,
    gate: RwLock<()>,
    ranges: Arc<Ranges>,
    wake: std::sync::mpsc::SyncSender<()>,
    prefetch_wake: std::sync::mpsc::SyncSender<()>,
    prefetch_worker: Mutex<Option<thread::JoinHandle<()>>>,
    stop: Arc<std::sync::atomic::AtomicBool>,
    worker: Mutex<Option<thread::JoinHandle<()>>>,
}
impl Drop for Shared {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Release);
        let _ = self.wake.try_send(());
        let _ = self.prefetch_wake.try_send(());
        if let Some(worker) = self.worker.get_mut().unwrap().take() {
            let _ = worker.join();
        }
        if let Some(worker) = self.prefetch_worker.get_mut().unwrap().take() {
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
    async fn stage(&self, lba: u64, block: Box<[u8; PAGE]>) -> Result<()> {
        self.stage_aligned(lba * PAGE as u64, block.as_slice())
            .await?;
        Ok(())
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
                    .or_else(|| f.prepared.as_ref().and_then(|p| p.blocks.get(&lba)))
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
    async fn read_aligned(&self, offset: u64, dst: &mut [u8]) -> Result<()> {
        let lba = offset / PAGE as u64;
        let count = dst.len() / PAGE;
        let (pending, view) = {
            let f = self.0.front.lock().unwrap();
            f.view.check()?;
            let pending: Vec<_> = (0..count)
                .map(|i| {
                    let lba = lba + i as u64;
                    f.pending
                        .get(&lba)
                        .or_else(|| f.prepared.as_ref().and_then(|p| p.blocks.get(&lba)))
                        .or_else(|| f.inflight.get(&lba))
                        .cloned()
                })
                .collect();
            (pending, f.view.clone())
        };
        let mut skip = ReadMask::default();
        for (i, block) in pending.iter().enumerate() {
            if let Some(block) = block {
                dst[i * PAGE..(i + 1) * PAGE].copy_from_slice(block.as_ref());
                skip.insert(i);
            }
        }
        let covered = view.read_blocks(lba, skip, dst)?;
        let mut i = 0;
        while i < count {
            if covered.contains(i) {
                i += 1;
                continue;
            }
            let first = i;
            while i < count && !covered.contains(i) {
                i += 1;
            }
            let bytes = &mut dst[first * PAGE..i * PAGE];
            if let Some(lower) = &self.0.lower {
                ensure!(
                    lower
                        .read_at_into(offset + (first * PAGE) as u64, bytes)
                        .await?
                        == bytes.len(),
                    "short packed lower read"
                );
            } else {
                bytes.fill(0);
            }
        }
        Ok(())
    }
    // Keep aligned bulk writes in bounded 128 KiB frontend batches. The range
    // lease still serializes overlaps. Short locks reserve capacity and publish
    // mappings, with the immutable copy prepared between them.
    async fn stage_aligned(&self, offset: u64, bytes: &[u8]) -> Result<usize> {
        if self.0.caller_qos.load(std::sync::atomic::Ordering::Relaxed) == 0 {
            self.0.caller_qos.store(
                super::scheduling::current(),
                std::sync::atomic::Ordering::Relaxed,
            );
        }
        loop {
            let notified = self.0.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let started = std::time::Instant::now();
            let admitted = {
                let mut f = self.0.front.lock().unwrap();
                f.view.check()?;
                let count = (bytes.len() / PAGE)
                    .min(32)
                    .min(DIRTY_LIMIT / PAGE - f.dirty_blocks());
                let count = count.min((DIRTY_LIMIT - self.0.budget.used()) / PAGE);
                let len = count * PAGE;
                let lease = if len == 0 {
                    None
                } else {
                    self.0.budget.reserve(len)
                };
                if lease.is_none() {
                    f.pressure = true;
                }
                lease.map(|lease| (len, lease))
            };
            let (done, wake) = if let Some((len, lease)) = admitted {
                // The reservation already counts against the shared budget.
                // Keep copying/allocation outside Front so the coordinator and
                // readers can advance independently. The caller's range lease
                // and lifecycle gate protect ordering and flush admission.
                let values: Vec<_> = super::buffer::Block::batch(&bytes[..len], lease)
                    .enumerate()
                    .map(|(i, block)| (offset / PAGE as u64 + i as u64, block))
                    .collect();
                let mut f = self.0.front.lock().unwrap();
                f.view.check()?;
                let sequence = f
                    .sequence
                    .checked_add((len / PAGE) as u64)
                    .context("packed write sequence overflow")?;
                f.pending.replace_sorted(&values);
                f.sequence = sequence;
                (len, f.pending.len() * PAGE >= PREPARE_THRESHOLD)
            } else {
                (0, true)
            };
            self.0.stage_ns.fetch_add(
                started.elapsed().as_nanos() as u64,
                std::sync::atomic::Ordering::Relaxed,
            );
            if wake || done == 0 {
                let _ = self.0.wake.try_send(());
                let _ = self.0.prefetch_wake.try_send(());
            }
            if done != 0 {
                return Ok(done);
            }
            let waiting = std::time::Instant::now();
            notified.await;
            self.0.wait_ns.fetch_add(
                waiting.elapsed().as_nanos() as u64,
                std::sync::atomic::Ordering::Relaxed,
            );
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
            let mut block = self.block(lba).await?;
            block[inside..inside + n].copy_from_slice(&bytes[done..done + n]);
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
                    .chain(f.prepared.iter().flat_map(|p| p.blocks.iter()))
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
            stats.dirty_bytes = f.dirty_blocks() * PAGE;
            stats.plaintext_buffer_bytes = self.0.budget.used();
            stats.frontend_stage_ns = self.0.stage_ns.load(std::sync::atomic::Ordering::Relaxed);
            stats.frontend_wait_ns = self.0.wait_ns.load(std::sync::atomic::Ordering::Relaxed);
            stats.caller_qos = self.0.caller_qos.load(std::sync::atomic::Ordering::Relaxed);
            f.view.read_statistics(&mut stats);
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
            if inside == 0 && n - done >= PAGE {
                let take = ((n - done) / PAGE).min(READ_BLOCKS) * PAGE;
                self.read_aligned(pos, &mut dst[done..done + take]).await?;
                done += take;
                continue;
            }
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

#[cfg(test)]
mod generation_tests {
    use super::*;
    #[tokio::test]
    async fn fragmented_slab_pressure_makes_progress() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let core = Core::create(
            Arc::new(FileDisk::open(&dir.path().join("slabs"), true)?),
            (DIRTY_LIMIT * 4) as u64,
            Policy::default(),
        )?;
        let upper = PackedUpper::from_core(core)?;
        tokio::time::timeout(Duration::from_secs(30), async {
            let batch = vec![5; PAGE * 32];
            for round in 0..3u8 {
                for i in 0..256 {
                    let offset = (i * batch.len()) as u64;
                    upper.write_at(offset, &batch).await?;
                    upper.write_at(offset + PAGE as u64, &[round; PAGE]).await?;
                    assert!(upper.stats()?.plaintext_buffer_bytes <= DIRTY_LIMIT);
                }
            }
            upper.sync().await?;
            for i in 0..256 {
                let bytes = upper.read_at((i * PAGE * 32) as u64, PAGE * 2).await?;
                assert_eq!(&bytes[..PAGE], &[5; PAGE]);
                assert_eq!(&bytes[PAGE..], &[2; PAGE]);
            }
            anyhow::Ok(())
        })
        .await??;
        Ok(())
    }
    #[tokio::test]
    async fn prepared_generation_preserves_read_order_and_dirty_budget() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let core = Core::create(
            Arc::new(FileDisk::open(&dir.path().join("upper"), true)?),
            (DIRTY_LIMIT + PAGE) as u64,
            Policy::default(),
        )?;
        let upper = PackedUpper::from_core(core)?;
        // Freeze the consumer to inspect all three queue stages deterministically.
        // This unit test intentionally never calls sync on the stopped adapter.
        upper
            .0
            .stop
            .store(true, std::sync::atomic::Ordering::Release);
        let _ = upper.0.wake.try_send(());
        let _ = upper.0.prefetch_wake.try_send(());
        upper
            .0
            .worker
            .lock()
            .unwrap()
            .take()
            .unwrap()
            .join()
            .unwrap();
        upper
            .0
            .prefetch_worker
            .lock()
            .unwrap()
            .take()
            .unwrap()
            .join()
            .unwrap();
        {
            let mut f = upper.0.front.lock().unwrap();
            f.inflight = Arc::new(
                [
                    (0, Box::new([1; PAGE]).into()),
                    (1, Box::new([1; PAGE]).into()),
                ]
                .into_iter()
                .collect(),
            );
            f.prepared = Some(Prepared {
                blocks: Arc::new(
                    [
                        (0, Box::new([2; PAGE]).into()),
                        (2, Box::new([2; PAGE]).into()),
                    ]
                    .into_iter()
                    .collect(),
                ),
                boundary: 2,
                policy: Policy::default(),
                encoding: None,
            });
            f.pending.insert(0, Box::new([3; PAGE]).into());
        }
        let mut bytes = vec![0; PAGE * 3];
        upper.read_at_into(0, &mut bytes).await?;
        assert_eq!(&bytes[..PAGE], &[3; PAGE]);
        assert_eq!(&bytes[PAGE..PAGE * 2], &[1; PAGE]);
        assert_eq!(&bytes[PAGE * 2..], &[2; PAGE]);
        assert_eq!(upper.stats()?.dirty_bytes, 5 * PAGE);
        {
            let mut f = upper.0.front.lock().unwrap();
            f.prepared.as_mut().unwrap().blocks = Arc::new(
                (2..(DIRTY_LIMIT / PAGE - 1) as u64)
                    .map(|lba| (lba, Box::new([2; PAGE]).into()))
                    .collect(),
            );
        }
        assert_eq!(upper.stats()?.dirty_bytes, DIRTY_LIMIT);
        let offset = DIRTY_LIMIT as u64;
        assert!(tokio::time::timeout(
            Duration::from_millis(20),
            upper.write_at(offset, &[9; PAGE])
        )
        .await
        .is_err());
        {
            let mut f = upper.0.front.lock().unwrap();
            Arc::make_mut(&mut f.prepared.as_mut().unwrap().blocks).remove(&2);
        }
        upper.write_at(offset, &[9; PAGE]).await?;
        assert_eq!(upper.stats()?.dirty_bytes, DIRTY_LIMIT);
        let mut last = [0; PAGE];
        upper.read_at_into(offset, &mut last).await?;
        assert_eq!(last, [9; PAGE]);
        Ok(())
    }
}
