//! Coordinator-owned state and immutable read views. Transaction mechanics are
//! private children so no other packed module can mutate roots or allocation state.
mod allocation;
#[cfg(test)]
mod allocation_tests;
mod format;
mod reclaim;
mod recovery;
mod transaction;
use super::{
    disk::{Disk, PAGE},
    memory::{Map, PageSet},
    tree::{self, Value},
};
use super::{policy::Policy, stats::Stats};
use anyhow::{bail, ensure, Context, Result};
use format::Root;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    sync::{Arc, Weak},
};
pub const SEGMENT: u64 = 2 * 1024 * 1024;
pub const DIRTY_LIMIT: usize = 16 * 1024 * 1024;
fn fragment_reserve_pages(live_aligned_bytes: u64) -> u64 {
    (live_aligned_bytes / PAGE as u64 / 16).min(32 * 1024 * 1024 / PAGE as u64)
}
pub(super) const READ_BLOCKS: usize = 256;
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct ReadMask(pub [u64; READ_BLOCKS / 64]);
impl ReadMask {
    pub fn contains(self, index: usize) -> bool {
        self.0[index / 64] & (1 << (index % 64)) != 0
    }
    pub fn insert(&mut self, index: usize) {
        self.0[index / 64] |= 1 << (index % 64);
    }
}
#[derive(Clone)]
pub struct ReadView {
    writes: Arc<super::writeback::ReadCache>,
    root: Arc<Root>,
    disk: Arc<dyn Disk>,
    poison: Arc<std::sync::Mutex<Option<String>>>,
}
impl ReadView {
    pub fn check(&self) -> Result<()> {
        let p = self.poison.lock().unwrap();
        ensure!(p.is_none(), "packed upper poisoned: {:?}", *p);
        Ok(())
    }
    pub fn fail(&self, e: &anyhow::Error) {
        *self.poison.lock().unwrap() = Some(format!("{e:#}"));
    }
    pub fn mappings(&self) -> Vec<(u64, bool)> {
        self.root.map.iter().map(|(&l, v)| (l, *v == 0)).collect()
    }
    pub fn read(&self, lba: u64) -> Result<Option<Box<[u8; PAGE]>>> {
        self.check()?;
        let result = (|| match self.root.map.get(&lba) {
            None => Ok(None),
            Some(v) if *v == 0 => Ok(Some(Box::new([0; PAGE]))),
            Some(v) => Ok(Some(
                self.decode(self.root.objects.get(v).context("missing packed object")?)?,
            )),
        })();
        if let Err(e) = &result {
            self.fail(e);
        }
        result
    }
    /// Read one immutable mapping version, sorting physical objects so a
    /// contiguous logical request does not become one host pread per 4 KiB.
    /// Bits in skip belong to newer frontend buffers; unset return bits use lower.
    pub(super) fn read_blocks(&self, lba: u64, skip: ReadMask, dst: &mut [u8]) -> Result<ReadMask> {
        self.check()?;
        ensure!(
            dst.len().is_multiple_of(PAGE) && dst.len() / PAGE <= READ_BLOCKS,
            "invalid packed read batch"
        );
        let result = (|| {
            let mut covered = skip;
            let mut entries = Vec::with_capacity(dst.len() / PAGE);
            for i in 0..dst.len() / PAGE {
                if skip.contains(i) {
                    continue;
                }
                let Some(&id) = self.root.map.get(&(lba + i as u64)) else {
                    continue;
                };
                covered.insert(i);
                if id == 0 {
                    dst[i * PAGE..(i + 1) * PAGE].fill(0);
                } else {
                    entries.push((
                        i,
                        *self
                            .root
                            .objects
                            .get(&id)
                            .context("missing packed object")?,
                    ));
                }
            }
            let count = entries.len();
            self.writes.count_read_blocks(count);
            entries.sort_unstable_by_key(|(_, value)| value[0]);
            let mut stored = Vec::new();
            let mut first = 0;
            while first < count {
                let start = entries[first].1[0];
                let mut end = start + entries[first].1[1];
                let mut last = first + 1;
                while last < count {
                    let v = &entries[last].1;
                    let next_end = end.max(v[0] + v[1]);
                    // Only alignment padding may be read speculatively. Bound
                    // temporary memory and I/O even for fragmented/random maps.
                    if v[0] > end + 64 || next_end - start > (READ_BLOCKS * PAGE) as u64 {
                        break;
                    }
                    end = next_end;
                    last += 1;
                }
                let bytes = (end - start) as usize;
                stored.reserve_exact(bytes.saturating_sub(stored.len()));
                stored.resize(bytes, 0);
                self.writes.read(self.disk.as_ref(), start, &mut stored)?;
                for &(i, v) in &entries[first..last] {
                    let at = (v[0] - start) as usize;
                    decode_into(
                        &v,
                        &stored[at..at + v[1] as usize],
                        &mut dst[i * PAGE..(i + 1) * PAGE],
                    )?;
                }
                first = last;
            }
            Ok(covered)
        })();
        if let Err(error) = &result {
            self.fail(error);
        }
        result
    }
    pub(super) fn read_statistics(&self, stats: &mut Stats) {
        let (blocks, calls, bytes) = self.writes.read_statistics();
        stats.upper_read_blocks = blocks;
        stats.host_read_calls = calls;
        stats.host_read_bytes = bytes;
        (stats.host_writeback_syncs, stats.host_writeback_sync_ns) =
            self.disk.writeback_statistics();
    }
    fn decode(&self, v: &Value) -> Result<Box<[u8; PAGE]>> {
        self.writes.count_read_blocks(1);
        let mut stored = vec![0; v[1] as usize];
        self.writes.read(self.disk.as_ref(), v[0], &mut stored)?;
        let mut out = Box::new([0; PAGE]);
        decode_into(v, &stored, out.as_mut_slice())?;
        Ok(out)
    }
}
fn decode_into(v: &Value, stored: &[u8], out: &mut [u8]) -> Result<()> {
    match v[2] {
        0 => out.copy_from_slice(stored),
        1 => {
            let n = unsafe {
                lz4_sys::LZ4_decompress_safe(
                    stored.as_ptr().cast(),
                    out.as_mut_ptr().cast(),
                    stored.len() as i32,
                    PAGE as i32,
                )
            };
            ensure!(n == PAGE as i32, "corrupt packed LZ4 object");
        }
        2 => {
            let n = zstd::bulk::decompress_to_buffer(stored, out)?;
            ensure!(n == PAGE, "corrupt packed Zstd object");
        }
        _ => bail!("unsupported packed codec"),
    }
    ensure!(
        crc32c::crc32c(out) as u64 == v[3],
        "packed data checksum mismatch"
    );
    Ok(())
}

struct Publication {
    root: Arc<Root>,
    slot: usize,
    blocks: u64,
    done: std::sync::mpsc::Receiver<super::publish::Outcome>,
}
struct Punching {
    pages: Vec<u64>,
    done: std::sync::mpsc::Receiver<(Result<()>, u64, u64, u64)>,
}
pub struct Core {
    pub async_data: bool,
    writes: Arc<super::writeback::ReadCache>,
    disk: Arc<dyn Disk>,
    roots: [Option<Arc<Root>>; 2],
    current: usize,
    working: Option<Arc<Root>>,
    working_blocks: u64,
    // Deltas relative to the latest durable trees. Working reads use Root's
    // in-memory indexes; capacity writeback does not serialize these trees.
    map_delta: Map<u64>,
    object_delta: Map<Option<Value>>,
    pub policy: Policy,
    pub pending: Arc<super::memory::Map<super::buffer::Block>>,
    poison: Arc<std::sync::Mutex<Option<String>>>,
    dedupe: HashMap<[u8; 32], u64>,
    encoders: super::encode::Pool,
    pub prepared: Option<super::encode::Encoding>,
    publisher: Option<super::publish::Publisher>,
    publication: Option<Publication>,
    cleaner: Option<super::cleaner::Cleaner>,
    punching: Option<Punching>,
    cleaner_rotate: bool,
    tree_cache: tree::Cache,
    output_buffer: Vec<u8>,
    data_writer: Option<super::writeback::Writer>,
    punched: BTreeSet<u64>,
    warm_cursor: u64,
    readers: Vec<Weak<Root>>,
    stats: Stats,
}
impl Core {
    fn root(&self) -> &Root {
        self.working
            .as_ref()
            .or(self.roots[self.current].as_ref())
            .unwrap()
    }
    pub fn has_writeback(&self) -> bool {
        self.working.is_some()
    }
    pub fn size(&self) -> u64 {
        self.root().size
    }
    pub fn uuid(&self) -> uuid::Uuid {
        uuid::Uuid::from_bytes(self.root().uuid)
    }
    pub fn check(&self) -> Result<()> {
        let poison = self.poison.lock().unwrap();
        ensure!(poison.is_none(), "packed upper poisoned: {:?}", *poison);
        Ok(())
    }
    pub fn mappings(&self) -> Vec<(u64, bool)> {
        let mut entries: BTreeMap<_, _> = self
            .root()
            .map
            .iter()
            .map(|(&lba, v)| (lba, *v == 0))
            .collect();
        entries.extend(
            self.pending
                .iter()
                .map(|(&lba, bytes)| (lba, bytes.iter().all(|b| *b == 0))),
        );
        entries.into_iter().collect()
    }
    fn decode(&self, v: &Value) -> Result<Box<[u8; PAGE]>> {
        self.view().decode(v)
    }
    pub fn read_block(&self, lba: u64) -> Result<Option<Box<[u8; PAGE]>>> {
        self.check()?;
        if let Some(b) = self.pending.get(&lba) {
            return Ok(Some(Box::new(**b)));
        }
        let result = (|| match self.root().map.get(&lba) {
            None => Ok(None),
            Some(v) if *v == 0 => Ok(Some(Box::new([0; PAGE]))),
            Some(v) => Ok(Some(
                self.decode(
                    self.root()
                        .objects
                        .get(v)
                        .context("missing packed object")?,
                )?,
            )),
        })();
        if let Err(e) = &result {
            *self.poison.lock().unwrap() = Some(format!("{e:#}"));
        }
        result
    }

    pub fn stage(&mut self, lba: u64, b: Box<[u8; PAGE]>) -> Result<()> {
        self.check()?;
        ensure!(
            lba < self.size().div_ceil(PAGE as u64),
            "packed write outside volume"
        );
        Arc::make_mut(&mut self.pending).insert(lba, b.into());
        Ok(())
    }
    fn protected_roots(&self) -> PageSet {
        let mut protected: PageSet = [0, 1].into_iter().collect();
        for root in self
            .roots
            .iter()
            .flatten()
            .cloned()
            .chain(self.working.iter().cloned())
            .chain(self.publication.iter().map(|p| p.root.clone()))
            .chain(self.readers.iter().filter_map(Weak::upgrade))
        {
            protected.union(&root.pages);
        }
        protected
    }
    fn protected(&self) -> PageSet {
        let mut protected = self.protected_roots();
        self.writes.protect(&mut protected);
        if let Some(punching) = &self.punching {
            protected.extend(punching.pages.iter().copied());
        }
        protected
    }
    pub fn view(&self) -> ReadView {
        ReadView {
            writes: self.writes.clone(),
            root: self
                .working
                .as_ref()
                .or(self.roots[self.current].as_ref())
                .unwrap()
                .clone(),
            disk: self.disk.clone(),
            poison: self.poison.clone(),
        }
    }
    pub fn warm_dedupe(&mut self, limit: usize) -> Result<()> {
        if !self.policy.dedupe {
            return Ok(());
        }
        let ids: Vec<_> = self
            .root()
            .objects
            .after(self.warm_cursor)
            .take(limit)
            .map(|(&id, _)| id)
            .collect();
        for id in ids {
            self.warm_cursor = id;
            let b = self.decode(&self.root().objects[&id])?;
            if self.dedupe.len() >= 262144 {
                break;
            }
            self.dedupe.insert(Sha256::digest(b.as_slice()).into(), id);
        }
        Ok(())
    }
    pub fn set_policy(&mut self, p: Policy) -> Result<()> {
        self.commit()?;
        self.policy = p;
        self.dedupe.clear();
        self.warm_cursor = 0;
        Ok(())
    }
    pub fn stats(&self) -> Result<Stats> {
        let mut s = self.stats.clone();
        s.host_bytes = self.disk.allocated()?;
        s.dirty_bytes = self.pending.len() * PAGE;
        self.view().read_statistics(&mut s);
        s.live_encoded_bytes = self.root().encoded_bytes;
        s.unique_plaintext_bytes = self.root().objects.len() as u64 * PAGE as u64;
        s.fragment_reserve_bytes = fragment_reserve_pages(self.root().aligned_bytes) * PAGE as u64;
        let protected = self.protected();
        s.cleaner_pending_bytes = self
            .punching
            .as_ref()
            .map_or(0, |p| p.pages.len() as u64 * PAGE as u64);
        s.retired_bytes = self
            .protected_roots()
            .difference_count(&self.root().pages)
            .saturating_sub(2) as u64
            * PAGE as u64;
        s.reclaimable_bytes = (self
            .disk
            .len()?
            .div_ceil(PAGE as u64)
            .saturating_sub(protected.len() as u64)
            .saturating_sub(self.punched.len() as u64))
            * PAGE as u64;
        Ok(s)
    }
}
