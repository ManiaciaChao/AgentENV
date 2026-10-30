use super::{
    disk::{Disk, PAGE},
    memory::{Map, PageSet},
    tree::{self, Pages, Value},
};
use anyhow::{bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    sync::{Arc, Weak},
    time::Instant,
};
pub const SEGMENT: u64 = 2 * 1024 * 1024;
pub const DIRTY_LIMIT: usize = 16 * 1024 * 1024;
const MAGIC: &[u8; 8] = b"OBDPACK1";
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Codec {
    None,
    Lz4,
    Zstd,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct Policy {
    pub compression: Codec,
    pub dedupe: bool,
}
impl Default for Policy {
    fn default() -> Self {
        Self {
            compression: Codec::Lz4,
            dedupe: false,
        }
    }
}
#[derive(Clone, Default, Debug, Serialize)]
pub struct Stats {
    pub generations: u64,
    pub writeback_batches: u64,
    pub writeback_ns: u64,
    pub barriers: u64,
    pub barrier_ns: u64,
    pub committed_blocks: u64,
    pub compression_fallbacks: u64,
    pub dedupe_hits: u64,
    pub host_bytes: u64,
    pub host_peak_bytes: u64,
    pub commit_ns: u64,
    pub prepare_ns: u64,
    pub coordinator_qos: u32,
    pub objects_and_data_ns: u64,
    pub metadata_ns: u64,
    pub encoding_wait_ns: u64,
    pub payload_io_ns: u64,
    pub publication_ns: u64,
    pub metadata_cache_hits: u64,
    pub metadata_cache_misses: u64,
    pub bookkeeping_ns: u64,
    pub data_write_calls: u64,
    pub data_write_bytes: u64,
    pub live_encoded_bytes: u64,
    pub retired_bytes: u64,
    pub reclaimable_bytes: u64,
    pub reclaimed_bytes: u64,
    pub dirty_bytes: usize,
    pub metadata_pages_written: u64,
    pub metadata_write_calls: u64,
}
fn object_pages(v: &Value) -> std::ops::RangeInclusive<u64> {
    v[0] / PAGE as u64..=(v[0] + v[1] - 1) / PAGE as u64
}
#[derive(Clone)]
struct Root {
    generation: u64,
    map_root: u64,
    objects_root: u64,
    next_id: u64,
    size: u64,
    uuid: [u8; 16],
    map: Map<u64>,
    objects: Map<Value>,
    pages: PageSet,
    data_counts: Map<u32>,
    encoded_bytes: u64,
    aligned_bytes: u64,
}
impl Root {
    fn encode(&self) -> [u8; PAGE] {
        let mut b = [0; PAGE];
        b[..8].copy_from_slice(MAGIC);
        for (o, v) in [
            (8, 1),
            (16, 0),
            (24, self.generation),
            (32, self.size),
            (40, self.map_root),
            (48, self.objects_root),
            (56, self.next_id),
        ] {
            tree::put64(&mut b, o, v);
        }
        b[64..80].copy_from_slice(&self.uuid);
        tree::seal(&mut b);
        b
    }
    fn decode(d: &dyn Disk, b: &[u8; PAGE]) -> Result<Self> {
        ensure!(
            &b[..8] == MAGIC && tree::valid(b),
            "invalid packed superblock"
        );
        ensure!(
            tree::get64(b, 8) == 1 && tree::get64(b, 16) == 0,
            "unsupported packed version/features"
        );
        let mut r = Self {
            generation: tree::get64(b, 24),
            size: tree::get64(b, 32),
            map_root: tree::get64(b, 40),
            objects_root: tree::get64(b, 48),
            next_id: tree::get64(b, 56),
            uuid: b[64..80].try_into().unwrap(),
            map: Map::new(),
            objects: Map::new(),
            pages: PageSet::new(),
            data_counts: Map::new(),
            encoded_bytes: 0,
            aligned_bytes: 0,
        };
        ensure!(
            r.generation > 0 && r.size > 0 && r.size % 512 == 0 && r.next_id > 0,
            "invalid packed geometry"
        );
        let (map, mp) = tree::load(d, r.map_root)?;
        let (objects, op) = tree::load(d, r.objects_root)?;
        ensure!(mp.is_disjoint(&op), "packed metadata trees overlap");
        r.pages = mp.into_iter().collect();
        r.pages.extend(op);
        let mut refs: BTreeMap<u64, u64> = BTreeMap::new();
        for (&lba, v) in &map {
            ensure!(
                lba < r.size.div_ceil(PAGE as u64),
                "packed LBA out of bounds"
            );
            if v[0] != 0 {
                *refs.entry(v[0]).or_default() += 1;
            }
        }
        ensure!(
            refs.len() == objects.len(),
            "packed object reachability mismatch"
        );
        let disk_len = d.len()?;
        for (&id, v) in &objects {
            ensure!(
                id < r.next_id && refs.get(&id) == Some(&v[4]),
                "packed reference count mismatch"
            );
            ensure!(
                v[1] > 0
                    && v[1] <= PAGE as u64
                    && v[0] >= 2 * PAGE as u64
                    && v[0] % SEGMENT + v[1] <= SEGMENT
                    && v[0] % 64 == 0
                    && v[0].checked_add(v[1]).is_some_and(|end| end <= disk_len),
                "packed object bounds"
            );
            ensure!(
                v[2] <= 2 && (v[2] != 0 || v[1] == PAGE as u64),
                "invalid packed codec"
            );
            ensure!(
                object_pages(v).all(|p| !r.pages.contains(&p)),
                "packed data overlaps metadata"
            );
        }
        for v in objects.values() {
            for page in object_pages(v) {
                *r.data_counts.get_or_default(page) += 1;
            }
        }
        r.pages.extend(r.data_counts.keys().copied());
        r.map = map
            .into_iter()
            .map(|(key, value)| (key, value[0]))
            .collect();
        r.encoded_bytes = objects.values().map(|v| v[1]).sum();
        r.aligned_bytes = objects.values().map(|v| v[1].next_multiple_of(64)).sum();
        r.objects = objects.into_iter().collect();
        Ok(r)
    }
}
struct Allocation {
    disk: Arc<dyn Disk>,
    free: BTreeSet<u64>,
    end: u64,
    pack: Option<(u64, [u8; PAGE], usize)>,
    metadata: u64,
    cache: tree::Cache,
    created: BTreeSet<u64>,
    retired: BTreeSet<u64>,
    excluded: Option<u64>,
    output: Vec<u8>,
    output_offset: u64,
    write_calls: u64,
    write_bytes: u64,
    io_ns: u64,
}
impl Pages for Allocation {
    fn allocate(&mut self) -> u64 {
        self.metadata += 1;
        let p = self.page();
        self.created.insert(p);
        p
    }
    fn disk(&self) -> &dyn Disk {
        self.disk.as_ref()
    }
    fn retire(&mut self, p: u64) {
        self.retired.insert(p);
    }
    fn read_page(&mut self, page: u64, level: u8) -> Result<[u8; PAGE]> {
        self.cache.read(self.disk.as_ref(), page, level)
    }
    fn write_page(&mut self, page: u64, bytes: &[u8; PAGE]) -> Result<()> {
        self.data_page(page, bytes)?;
        self.cache.insert(page, bytes);
        Ok(())
    }
}
impl Allocation {
    fn page(&mut self) -> u64 {
        if let Some(p) = self.free.pop_first() {
            // A former metadata page may now hold data or a different tree.
            self.cache.invalidate(p);
            p
        } else {
            if self.excluded == Some(self.end * PAGE as u64 / SEGMENT) {
                self.end = (self.end * PAGE as u64 / SEGMENT + 1) * (SEGMENT / PAGE as u64);
            }
            let p = self.end;
            self.end += 1;
            p
        }
    }
    fn flush_data(&mut self) -> Result<()> {
        if !self.output.is_empty() {
            let started = Instant::now();
            self.disk.write(self.output_offset, &self.output)?;
            self.io_ns += started.elapsed().as_nanos() as u64;
            self.write_calls += 1;
            self.write_bytes += self.output.len() as u64;
            self.output.clear();
        }
        Ok(())
    }
    fn data_page(&mut self, page: u64, data: &[u8; PAGE]) -> Result<()> {
        let offset = page * PAGE as u64;
        if !self.output.is_empty()
            && (self.output_offset + self.output.len() as u64 != offset
                || self.output.len() >= 1024 * 1024)
        {
            self.flush_data()?;
        }
        if self.output.is_empty() {
            self.output_offset = offset;
        }
        self.output.extend_from_slice(data);
        Ok(())
    }
    fn finish_pack(&mut self) -> Result<()> {
        if let Some((p, b, _)) = self.pack.take() {
            self.data_page(p, &b)?;
        }
        Ok(())
    }

    fn payload(&mut self, b: &[u8]) -> Result<u64> {
        let n = b.len().next_multiple_of(64);
        if self
            .pack
            .as_ref()
            .is_some_and(|(_, _, used)| *used == PAGE || n == PAGE)
        {
            self.finish_pack()?;
        }
        if let Some((p, _, used)) = &self.pack {
            if used + n > PAGE {
                let next = p + 1;
                let contiguous = (*p * PAGE as u64 / SEGMENT == next * PAGE as u64 / SEGMENT)
                    && self.excluded != Some(next * PAGE as u64 / SEGMENT)
                    && (self.free.contains(&next) || next == self.end);
                if contiguous {
                    self.cache.invalidate(next);
                    if !self.free.remove(&next) {
                        self.end += 1;
                    }
                    let (page, mut data, used) = self.pack.take().unwrap();
                    let first = PAGE - used;
                    data[used..].copy_from_slice(&b[..first]);
                    self.data_page(page, &data)?;
                    let mut tail = [0; PAGE];
                    tail[..b.len() - first].copy_from_slice(&b[first..]);
                    self.pack = Some((next, tail, n - first));
                    return Ok(page * PAGE as u64 + used as u64);
                }
                self.finish_pack()?;
            }
        }
        if self.pack.is_none() {
            let p = self.page();
            self.pack = Some((p, [0; PAGE], 0));
        }
        let (p, page, used) = self.pack.as_mut().unwrap();
        let at = *p * PAGE as u64 + *used as u64;
        page[*used..*used + b.len()].copy_from_slice(b);
        *used += n;
        Ok(at)
    }
}

#[derive(Clone)]
pub struct ReadView {
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
    fn decode(&self, v: &Value) -> Result<Box<[u8; PAGE]>> {
        let mut stored = vec![0; v[1] as usize];
        self.disk.read(v[0], &mut stored)?;
        let mut out = Box::new([0; PAGE]);
        match v[2] {
            0 => out.copy_from_slice(&stored),
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
                let b = zstd::bulk::decompress(&stored, PAGE)?;
                ensure!(b.len() == PAGE, "corrupt packed Zstd object");
                out.copy_from_slice(&b);
            }
            _ => bail!("unsupported packed codec"),
        }
        ensure!(
            crc32c::crc32c(out.as_slice()) as u64 == v[3],
            "packed data checksum mismatch"
        );
        Ok(out)
    }
}

struct Publication {
    root: Arc<Root>,
    slot: usize,
    blocks: u64,
    done: std::sync::mpsc::Receiver<super::publish::Outcome>,
}
pub struct Core {
    disk: Arc<dyn Disk>,
    roots: [Option<Arc<Root>>; 2],
    current: usize,
    working: Option<Arc<Root>>,
    working_blocks: u64,
    // Deltas relative to the latest durable trees. Working reads use Root's
    // in-memory indexes; capacity writeback does not serialize these trees.
    map_delta: BTreeMap<u64, u64>,
    object_delta: BTreeMap<u64, Option<Value>>,
    pub policy: Policy,
    pub pending: BTreeMap<u64, Arc<[u8; PAGE]>>,
    poison: Arc<std::sync::Mutex<Option<String>>>,
    dedupe: HashMap<[u8; 32], u64>,
    encoders: super::encode::Pool,
    publisher: Option<super::publish::Publisher>,
    publication: Option<Publication>,
    tree_cache: tree::Cache,
    punched: BTreeSet<u64>,
    warm_cursor: u64,
    readers: Vec<Weak<Root>>,
    stats: Stats,
}
impl Core {
    pub fn create(disk: Arc<dyn Disk>, size: u64, policy: Policy) -> Result<Self> {
        ensure!(size > 0 && size % 512 == 0, "invalid packed virtual size");
        let root = Root {
            generation: 1,
            map_root: 0,
            objects_root: 0,
            next_id: 1,
            size,
            uuid: *uuid::Uuid::new_v4().as_bytes(),
            map: Map::new(),
            objects: Map::new(),
            pages: PageSet::new(),
            data_counts: Map::new(),
            encoded_bytes: 0,
            aligned_bytes: 0,
        };
        disk.write(0, &root.encode())?;
        disk.write(PAGE as u64, &[0; PAGE])?;
        disk.barrier()?;
        Ok(Self {
            disk,
            roots: [Some(Arc::new(root)), None],
            current: 0,
            working: None,
            working_blocks: 0,
            map_delta: BTreeMap::new(),
            object_delta: BTreeMap::new(),
            policy,
            pending: BTreeMap::new(),
            poison: Arc::new(std::sync::Mutex::new(None)),
            dedupe: HashMap::new(),
            encoders: super::encode::Pool::default(),
            publisher: None,
            publication: None,
            tree_cache: tree::Cache::default(),
            punched: BTreeSet::new(),
            warm_cursor: 0,
            readers: Vec::new(),
            stats: Stats::default(),
        })
    }
    pub fn open(disk: Arc<dyn Disk>, policy: Policy) -> Result<Self> {
        let mut headers = Vec::new();
        for slot in 0..2 {
            let mut b = [0; PAGE];
            disk.read((slot * PAGE) as u64, &mut b)?;
            if tree::valid(&b) {
                ensure!(&b[..8] == MAGIC, "invalid packed magic");
                headers.push((tree::get64(&b, 24), slot, b));
            }
        }
        headers.sort_by_key(|h| h.0);
        ensure!(!headers.is_empty(), "no valid packed superblock");
        let current = headers.last().unwrap().1;
        let mut roots = [None, None];
        // Never fall back when a checksum-valid root references corrupt metadata.
        for (_, slot, b) in headers {
            roots[slot] = Some(Arc::new(Root::decode(disk.as_ref(), &b)?));
        }
        if let (Some(a), Some(b)) = (&roots[0], &roots[1]) {
            ensure!(
                a.uuid == b.uuid && a.size == b.size,
                "packed superblocks disagree"
            );
        }
        Ok(Self {
            disk,
            roots,
            current,
            working: None,
            working_blocks: 0,
            map_delta: BTreeMap::new(),
            object_delta: BTreeMap::new(),
            policy,
            pending: BTreeMap::new(),
            poison: Arc::new(std::sync::Mutex::new(None)),
            dedupe: HashMap::new(),
            encoders: super::encode::Pool::default(),
            publisher: None,
            publication: None,
            tree_cache: tree::Cache::default(),
            punched: BTreeSet::new(),
            warm_cursor: 0,
            readers: Vec::new(),
            stats: Stats::default(),
        })
    }
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
        self.pending.insert(lba, b.into());
        Ok(())
    }
    fn protected(&self) -> PageSet {
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
    pub fn view(&self) -> ReadView {
        ReadView {
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
    fn barrier(&mut self) -> Result<()> {
        self.stats.host_peak_bytes = self.stats.host_peak_bytes.max(self.disk.allocated()?);
        let t = Instant::now();
        let r = self.disk.barrier();
        self.stats.barriers += 1;
        self.stats.barrier_ns += t.elapsed().as_nanos() as u64;
        r
    }
    fn metadata_base(&self) -> &Root {
        self.publication
            .as_ref()
            .map(|p| p.root.as_ref())
            .unwrap_or_else(|| self.roots[self.current].as_ref().unwrap())
    }
    pub fn publication_pending(&self) -> bool {
        self.publication.is_some()
    }
    pub fn begin_commit(&mut self, wake: std::sync::mpsc::SyncSender<()>) -> Result<bool> {
        self.check()?;
        ensure!(
            self.publication.is_none(),
            "packed publication already in progress"
        );
        if self.pending.is_empty() && self.working.is_none() {
            return Ok(false);
        }
        self.run_publish(None, true, Some(wake))?;
        Ok(true)
    }
    pub fn finish_publication(&mut self, wait: bool) -> Result<bool> {
        let Some(publication) = &self.publication else {
            return Ok(false);
        };
        let outcome = if wait {
            publication.done.recv().context("packed publisher exited")
        } else {
            match publication.done.try_recv() {
                Ok(outcome) => Ok(outcome),
                Err(std::sync::mpsc::TryRecvError::Empty) => return Ok(false),
                Err(error) => Err(anyhow::anyhow!(error)),
            }
        };
        let publication = self.publication.take().unwrap();
        let result = (|| {
            let outcome = outcome?;
            self.stats.barriers += outcome.barriers;
            self.stats.barrier_ns += outcome.barrier_ns;
            self.stats.publication_ns += outcome.elapsed_ns;
            self.stats.host_peak_bytes = self.stats.host_peak_bytes.max(outcome.peak);
            outcome.result?;
            self.stats.committed_blocks += publication.blocks;
            self.stats.generations += 1;
            if let Some(old) = &self.roots[publication.slot] {
                self.readers.push(Arc::downgrade(old));
            }
            if self
                .working
                .as_ref()
                .is_some_and(|r| Arc::ptr_eq(r, &publication.root))
            {
                self.working = None;
            }
            self.roots[publication.slot] = Some(publication.root);
            self.current = publication.slot;
            Ok(true)
        })();
        if let Err(error) = &result {
            *self.poison.lock().unwrap() = Some(format!("{error:#}"));
        }
        result
    }
    pub fn commit(&mut self) -> Result<()> {
        self.publish(false, None)
    }
    // Capacity writeback is visible to live readers, but never publishes a
    // recoverable root or acknowledges durability. Commit retains both barriers.
    pub fn writeback(&mut self) -> Result<()> {
        self.check()?;
        if self.pending.is_empty() {
            return Ok(());
        }
        self.run_publish(None, false, None)
    }
    fn publish(&mut self, force: bool, victim: Option<u64>) -> Result<()> {
        self.finish_publication(true)?;
        self.check()?;
        if !force && self.pending.is_empty() && self.working.is_none() {
            return Ok(());
        }
        self.run_publish(victim, true, None)
    }
    fn run_publish(
        &mut self,
        victim: Option<u64>,
        durable: bool,
        wake: Option<std::sync::mpsc::SyncSender<()>>,
    ) -> Result<()> {
        #[cfg(target_os = "macos")]
        unsafe {
            let mut class: libc::qos_class_t = std::mem::zeroed();
            if libc::pthread_get_qos_class_np(
                libc::pthread_self(),
                &mut class,
                std::ptr::null_mut(),
            ) == 0
            {
                self.stats.coordinator_qos = class as u32;
            }
        }
        let started = Instant::now();
        let result = self.publish_inner(victim, durable, wake);
        if durable {
            self.stats.commit_ns += started.elapsed().as_nanos() as u64;
        } else {
            self.stats.writeback_ns += started.elapsed().as_nanos() as u64;
        }
        if let Err(e) = &result {
            *self.poison.lock().unwrap() = Some(format!("{e:#}"));
        }
        result
    }
    fn publish_inner(
        &mut self,
        victim: Option<u64>,
        durable: bool,
        wake: Option<std::sync::mpsc::SyncSender<()>>,
    ) -> Result<()> {
        let prepare_started = Instant::now();
        let mut next = self.root().clone();
        next.generation = self
            .metadata_base()
            .generation
            .checked_add(1)
            .context("packed generation overflow")?;
        let end = self.disk.len()?.div_ceil(PAGE as u64).max(2);
        let protected = self.protected();
        let free = protected
            .holes(end)
            .filter(|p| victim != Some(*p * PAGE as u64 / SEGMENT))
            .collect();
        let mut a = Allocation {
            disk: self.disk.clone(),
            free,
            end,
            pack: None,
            metadata: 0,
            cache: std::mem::take(&mut self.tree_cache),
            created: BTreeSet::new(),
            retired: BTreeSet::new(),
            excluded: victim,
            output: Vec::with_capacity(1024 * 1024),
            output_offset: 0,
            write_calls: 0,
            write_bytes: 0,
            io_ns: 0,
        };
        self.stats.prepare_ns += prepare_started.elapsed().as_nanos() as u64;
        let objects_started = Instant::now();
        let (mut maps, mut objects) = (Vec::new(), BTreeMap::new());
        let pending = self.pending.clone();
        let mut fresh: HashMap<[u8; 32], (u64, Arc<[u8; PAGE]>)> = HashMap::new();
        let encoding_started = Instant::now();
        let mut batches = self.encoders.encode(&pending, self.policy)?;
        self.stats.encoding_wait_ns += encoding_started.elapsed().as_nanos() as u64;
        loop {
            let waiting = Instant::now();
            let batch = batches.next();
            self.stats.encoding_wait_ns += waiting.elapsed().as_nanos() as u64;
            let Some(batch) = batch else { break };
            let batch = batch?;
            for encoded in &batch.blocks {
                let lba = &encoded.lba;
                let b = &encoded.plain;
                let id = if encoded.zero {
                    0
                } else {
                    let hash = encoded.hash;
                    let mut found = None;
                    if self.policy.dedupe {
                        if let Some((id, plain)) = fresh.get(&hash) {
                            if plain.as_slice() == b.as_slice() && next.objects.contains_key(id) {
                                found = Some(*id);
                            }
                        }
                        if found.is_none() {
                            if let Some(id) = self.dedupe.get(&hash) {
                                if let Some(v) = next.objects.get(id) {
                                    if self.decode(v)?.as_slice() == b.as_slice() {
                                        found = Some(*id);
                                    }
                                }
                            }
                        }
                    }
                    if let Some(id) = found {
                        self.stats.dedupe_hits += 1;
                        let value = next.objects.get_mut(&id).unwrap();
                        value[4] += 1;
                        objects.insert(id, Some(*value));
                        id
                    } else {
                        let id = next.next_id;
                        next.next_id = id.checked_add(1).context("packed object id overflow")?;
                        let codec = encoded.codec;
                        if encoded.fallback {
                            self.stats.compression_fallbacks += 1;
                        }
                        let bytes = if codec == 0 {
                            b.as_slice()
                        } else {
                            &batch.bytes[encoded.offset..encoded.offset + encoded.len]
                        };
                        let offset = a.payload(bytes)?;
                        let value = [offset, bytes.len() as u64, codec, encoded.crc, 1, 0];
                        next.objects.insert(id, value);
                        objects.insert(id, Some(value));
                        if self.policy.dedupe {
                            fresh.insert(hash, (id, b.clone()));
                        }
                        id
                    }
                };
                if let Some(old) = next.map.insert(*lba, id) {
                    if old != 0 {
                        let v = next
                            .objects
                            .get_mut(&old)
                            .context("packed old object missing")?;
                        ensure!(v[4] > 0, "packed reference underflow");
                        v[4] -= 1;
                        objects.insert(old, Some(*v));
                    }
                }
                maps.push((*lba, id));
            }
        }
        let dead: Vec<_> = objects
            .iter()
            .filter(|(_, v)| v.as_ref().is_some_and(|v| v[4] == 0))
            .map(|(&id, _)| id)
            .collect();
        for id in dead {
            next.objects.remove(&id);
            objects.insert(id, None);
        }
        if let Some(seg) = victim {
            let ids: Vec<_> = next
                .objects
                .iter()
                .filter(|(_, v)| v[0] / SEGMENT == seg)
                .map(|(&id, _)| id)
                .collect();
            for id in ids {
                let v = next.objects.get_mut(&id).unwrap();
                {
                    let mut bytes = vec![0; v[1] as usize];
                    self.disk.read(v[0], &mut bytes)?;
                    v[0] = a.payload(&bytes)?;
                    objects.insert(id, Some(*v));
                }
            }
        }
        a.finish_pack()?;
        a.flush_data()?;
        self.stats.objects_and_data_ns += objects_started.elapsed().as_nanos() as u64;
        self.stats.payload_io_ns += a.io_ns;
        let data_write_calls = a.write_calls;
        let data_write_bytes = a.write_bytes;
        let metadata_started = Instant::now();
        self.map_delta.extend(maps);
        let durable_next_id = self.metadata_base().next_id;
        for (&key, &value) in &objects {
            if value.is_none() && key >= durable_next_id {
                // Born and retired within this generation: never serialize it.
                self.object_delta.remove(&key);
            } else {
                self.object_delta.insert(key, value);
            }
        }
        if durable {
            next.map_root = tree::update_mappings(&mut a, next.map_root, &self.map_delta)?;
            next.objects_root =
                tree::update(&mut a, next.objects_root, tree::HEIGHT, &self.object_delta)?;
        }
        // Only immutable old tree nodes are read during the COW traversal.
        // New nodes may be coalesced, but must reach the file before barrier one.
        a.flush_data()?;
        self.stats.metadata_write_calls += a.write_calls - data_write_calls;
        self.stats.metadata_ns += metadata_started.elapsed().as_nanos() as u64;
        let slot = 1 - self.current;
        if durable && wake.is_none() {
            self.barrier()?;
            self.disk.write((slot * PAGE) as u64, &next.encode())?;
            self.barrier()?;
        }
        let bookkeeping_started = Instant::now();
        // Volatile working views never replace either recoverable root.
        // Update only changed object extents. Shared packed pages remain live
        // until their last distinct object has gone, independent of dedupe refs.
        for (&id, new) in &objects {
            let old = self.root().objects.get(&id);
            if let Some(v) = old {
                next.encoded_bytes -= v[1];
                next.aligned_bytes -= v[1].next_multiple_of(64);
            }
            if let Some(v) = new {
                next.encoded_bytes += v[1];
                next.aligned_bytes += v[1].next_multiple_of(64);
            }
            if old
                .zip(new.as_ref())
                .is_some_and(|(a, b)| a[0] == b[0] && a[1] == b[1])
            {
                continue;
            }
            if let Some(v) = old {
                for p in object_pages(v) {
                    let count = next
                        .data_counts
                        .get_mut(&p)
                        .context("missing data-page reference")?;
                    *count -= 1;
                    if *count == 0 {
                        next.data_counts.remove(&p);
                        next.pages.remove(&p);
                    }
                }
            }
            if let Some(v) = new {
                for p in object_pages(v) {
                    *next.data_counts.get_or_default(p) += 1;
                    next.pages.insert(p);
                }
            }
        }
        for p in &a.retired {
            next.pages.remove(p);
        }
        next.pages.extend(a.created.iter().copied());
        self.stats.metadata_pages_written += a.metadata;
        self.stats.data_write_calls += data_write_calls;
        self.stats.data_write_bytes += data_write_bytes;
        self.working_blocks += pending.len() as u64;
        if let Some(old) = self.working.take() {
            self.readers.push(Arc::downgrade(&old));
        }
        if durable {
            self.map_delta.clear();
            self.object_delta.clear();
            let blocks = std::mem::take(&mut self.working_blocks);
            let next = Arc::new(next);
            if let Some(wake) = wake {
                if self.publisher.is_none() {
                    self.publisher = Some(super::publish::Publisher::new()?);
                }
                let done = self.publisher.as_ref().unwrap().submit(
                    self.disk.clone(),
                    slot,
                    next.encode(),
                    self.poison.clone(),
                    wake,
                )?;
                self.working = Some(next.clone());
                self.publication = Some(Publication {
                    root: next,
                    slot,
                    blocks,
                    done,
                });
            } else {
                self.stats.committed_blocks += blocks;
                self.stats.generations += 1;
                if let Some(old) = &self.roots[slot] {
                    self.readers.push(Arc::downgrade(old));
                }
                self.roots[slot] = Some(next);
                self.current = slot;
            }
        } else {
            self.stats.writeback_batches += 1;
            self.working = Some(Arc::new(next));
        }
        self.readers.retain(|r| r.strong_count() > 0);
        self.pending.clear();
        if self.policy.dedupe {
            for (h, (id, _)) in fresh {
                if self.dedupe.len() >= 262144 {
                    self.dedupe.clear();
                }
                self.dedupe.insert(h, id);
            }
        }
        self.punched.retain(|p| a.free.contains(p));
        self.stats.metadata_cache_hits = a.cache.hits;
        self.stats.metadata_cache_misses = a.cache.misses;
        self.tree_cache = a.cache;
        self.stats.bookkeeping_ns += bookkeeping_started.elapsed().as_nanos() as u64;
        Ok(())
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
    pub fn maintenance(&mut self) -> Result<()> {
        self.maintenance_interruptible(|| false)
    }
    pub fn maintenance_interruptible(&mut self, should_yield: impl Fn() -> bool) -> Result<()> {
        self.check()?;
        let r = self.maintenance_inner(&should_yield);
        if let Err(e) = &r {
            *self.poison.lock().unwrap() = Some(format!("{e:#}"));
        }
        r
    }
    fn maintenance_inner(&mut self, should_yield: &impl Fn() -> bool) -> Result<()> {
        if self.publication.is_some()
            || !self.pending.is_empty()
            || self.working.is_some()
            || should_yield()
        {
            return Ok(());
        }
        let end = self.disk.len()?.div_ceil(PAGE as u64);
        let protected = self.protected();
        // Dual roots ARE the persistent retirement ledger: a page stays quarantined
        // until neither recoverable root references it. Reopen reconstructs this set.
        let latest = &self.root().pages;
        let retired = protected.difference_count(latest).saturating_sub(2) as u64 * PAGE as u64;
        let live = self.root().aligned_bytes;
        let used = latest.len() as u64 * PAGE as u64;
        let data_bytes = self.root().data_counts.len() as u64 * PAGE as u64;
        let fragmented = data_bytes.saturating_sub(live);
        if retired >= 8 * 1024 * 1024 || retired * 10 >= used.max(PAGE as u64) * 3 {
            self.publish(true, None)?;
            if should_yield() {
                return Ok(());
            }
        }
        if fragmented >= 8 * 1024 * 1024
            || (data_bytes > SEGMENT && fragmented * 10 >= data_bytes * 3)
        {
            let mut segments: BTreeMap<u64, (u64, BTreeSet<u64>)> = BTreeMap::new();
            for v in self.root().objects.values() {
                let s = segments.entry(v[0] / SEGMENT).or_default();
                s.0 += v[1].next_multiple_of(64);
                s.1.extend(object_pages(v));
            }
            if let Some((&seg, _)) = segments
                .iter()
                .filter(|(_, v)| v.0 * 10 < (v.1.len() as u64 * PAGE as u64) * 7)
                .min_by_key(|(_, v)| v.0)
            {
                if should_yield() {
                    return Ok(());
                }
                self.publish(true, Some(seg))?;
                if should_yield() {
                    return Ok(());
                }
                self.publish(true, None)?;
            }
        }
        let protected = self.protected();
        let free: Vec<_> = protected
            .holes(end)
            .filter(|p| !self.punched.contains(p))
            .collect();
        let mut i = 0;
        while i < free.len() {
            if should_yield() {
                break;
            }
            let start = free[i];
            let mut n = 1;
            while i + n < free.len()
                && free[i + n] == start + n as u64
                && n < SEGMENT as usize / PAGE
            {
                n += 1;
            }
            self.disk
                .punch(start * PAGE as u64, n as u64 * PAGE as u64)?;
            self.stats.reclaimed_bytes += n as u64 * PAGE as u64;
            self.punched.extend(free[i..i + n].iter().copied());
            i += n;
        }
        if i > 0 {
            self.barrier()?;
        }
        self.warm_dedupe(32)?;
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
        s.live_encoded_bytes = self.root().encoded_bytes;
        let protected = self.protected();
        s.retired_bytes = protected
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
