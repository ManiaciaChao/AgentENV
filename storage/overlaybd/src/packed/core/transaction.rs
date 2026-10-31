//! Prepare working roots and publish generations with two durability barriers.
use super::super::{disk::PAGE, memory::Map, tree};
use super::{
    allocation::Allocation, format::object_pages, fragment_reserve_pages, Core, Publication, Root,
    SEGMENT,
};
use anyhow::{ensure, Context, Result};
use std::{
    collections::{BTreeSet, HashMap},
    sync::Arc,
    time::Instant,
};
impl Core {
    pub(super) fn barrier(&mut self) -> Result<()> {
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
            self.stats.publication_data_barrier_ns += outcome.phase_ns[0];
            self.stats.publication_root_barrier_ns += outcome.phase_ns[1];
            self.stats.publication_max_barrier_ns = self
                .stats
                .publication_max_barrier_ns
                .max(outcome.phase_ns[0])
                .max(outcome.phase_ns[1]);
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
    pub(super) fn publish(&mut self, force: bool, victim: Option<u64>) -> Result<()> {
        self.finish_publication(true)?;
        self.check()?;
        if !force && self.pending.is_empty() && self.working.is_none() {
            return Ok(());
        }
        self.run_publish(victim, true, None)
    }
    pub(super) fn run_publish(
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
        let end = self
            .disk
            .len()?
            .max(self.writes.end())
            .div_ceil(PAGE as u64)
            .max(2);
        let protected = self.protected();
        let free = protected
            .holes(end)
            .filter(|p| victim != Some(*p * PAGE as u64 / SEGMENT))
            .collect();
        let mut output = std::mem::take(&mut self.output_buffer);
        output.reserve_exact(super::super::writeback::WRITE_BYTES);
        let mut a = Allocation {
            disk: self.disk.clone(),
            free,
            fragment_budget: fragment_reserve_pages(self.root().aligned_bytes),
            fragment_appends: 0,
            end,
            pack: None,
            metadata: 0,
            cache: std::mem::take(&mut self.tree_cache),
            created: BTreeSet::new(),
            retired: BTreeSet::new(),
            excluded: victim,
            output,
            output_offset: 0,
            write_calls: 0,
            write_bytes: 0,
            io_ns: 0,
            metadata_io_ns: 0,
            queue_wait_ns: 0,
            writer: match self.data_writer.take() {
                Some(writer) => writer,
                None => super::super::writeback::Writer::new(
                    self.disk.clone(),
                    self.poison.clone(),
                    self.writes.clone(),
                )?,
            },
        };
        self.stats.prepare_ns += prepare_started.elapsed().as_nanos() as u64;
        let objects_started = Instant::now();
        let (mut maps, mut objects) = (Vec::new(), Map::new());
        let pending = self.pending.clone();
        let mut fresh: HashMap<[u8; 32], (u64, super::super::buffer::Block)> = HashMap::new();
        let encoding_started = Instant::now();
        let mut batches = match self.prepared.take() {
            Some(prepared) => {
                self.stats.prefetched_batches += 1;
                prepared
            }
            None => self.encoders.encode(&pending, self.policy)?,
        };
        self.stats.encoding_wait_ns += encoding_started.elapsed().as_nanos() as u64;
        loop {
            let waiting = Instant::now();
            let batch = batches.next();
            self.stats.encoding_wait_ns += waiting.elapsed().as_nanos() as u64;
            let Some(batch) = batch else { break };
            let mut batch = batch?;
            let packed_at = if batch.packed {
                let spans: Vec<_> = batch.blocks.iter().map(|b| (b.offset, b.len)).collect();
                a.packed_batch(&mut batch.bytes, &spans)?
            } else {
                None
            };
            if batch.packed {
                if packed_at.is_some() {
                    self.stats.packed_batches += 1;
                } else {
                    self.stats.fragmented_batches += 1;
                }
            }
            let batch_start = maps.len();
            let mut new_objects = Vec::with_capacity(batch.blocks.len());
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
                        let offset = match &packed_at {
                            Some(run) => run.at(encoded.offset),
                            None => {
                                let bytes = if codec == 0 {
                                    b.as_slice()
                                } else {
                                    &batch.bytes[encoded.offset..encoded.offset + encoded.len]
                                };
                                a.payload(bytes)?
                            }
                        };
                        let value = [offset, encoded.len as u64, codec, encoded.crc, 1, 0];
                        if self.policy.dedupe {
                            next.objects.insert(id, value);
                            objects.insert(id, Some(value));
                            fresh.insert(hash, (id, b.clone()));
                        } else {
                            new_objects.push((id, value));
                        }
                        id
                    }
                };
                maps.push((*lba, id));
            }
            next.objects.replace_sorted(&new_objects);
            let changes: Vec<_> = new_objects
                .into_iter()
                .map(|(id, v)| (id, Some(v)))
                .collect();
            objects.replace_sorted(&changes);
            for old in next
                .map
                .replace_sorted(&maps[batch_start..])
                .into_iter()
                .flatten()
            {
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
            let mut bytes = Vec::new();
            let mut spans = Vec::with_capacity(ids.len());
            for &id in &ids {
                let v = &next.objects[&id];
                let at = bytes.len();
                let len = v[1] as usize;
                bytes.resize(at + len.next_multiple_of(64), 0);
                self.disk.read(v[0], &mut bytes[at..at + len])?;
                spans.push((at, len));
            }
            let relocated = bytes.len() as u64;
            bytes.resize(bytes.len().next_multiple_of(PAGE), 0);
            let run = a
                .packed_batch(&mut bytes, &spans)?
                .context("cleaner failed to reserve contiguous destination")?;
            for (&id, &(at, _)) in ids.iter().zip(&spans) {
                let v = next.objects.get_mut(&id).unwrap();
                v[0] = run.at(at);
                objects.insert(id, Some(*v));
            }
            self.stats.cleaner_relocations += 1;
            self.stats.cleaner_relocated_bytes += relocated;
        }
        a.finish_pack()?;
        a.flush_data()?;
        self.stats.objects_and_data_ns += objects_started.elapsed().as_nanos() as u64;
        let data_write_calls = a.write_calls;
        let data_write_bytes = a.write_bytes;
        let metadata_started = Instant::now();
        self.map_delta.replace_sorted(&maps);
        let durable_next_id = self.metadata_base().next_id;
        let mut changes = Vec::with_capacity(objects.len());
        for (&key, &value) in objects.iter() {
            if value.is_none() && key >= durable_next_id {
                // Born and retired within this generation: never serialize it.
                self.object_delta.remove(&key);
            } else {
                changes.push((key, value));
            }
        }
        self.object_delta.replace_sorted(&changes);
        if durable {
            next.map_root = tree::update_mappings(&mut a, next.map_root, &self.map_delta)?;
            next.objects_root =
                tree::update_objects(&mut a, next.objects_root, &self.object_delta)?;
        }
        // Only immutable old tree nodes are read during the COW traversal.
        // New nodes may be coalesced, but must reach the file before barrier one.
        a.flush_data()?;
        // Volatile working roots read queued payloads through the bounded cache.
        // Durable roots still drain ALL prior data/metadata before barrier one.
        if durable || !self.async_data {
            a.finish_io()?;
        } else {
            let timings = a.writer.progress()?;
            a.io_ns += timings.data_ns;
            a.metadata_io_ns += timings.metadata_ns;
            a.queue_wait_ns += timings.wait_ns;
        }
        self.stats.payload_io_ns += a.io_ns;
        self.stats.metadata_io_ns += a.metadata_io_ns;
        self.stats.data_queue_wait_ns += a.queue_wait_ns;
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
        for (&id, new) in objects.iter() {
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
                let seg = next
                    .segments
                    .get_mut(&(v[0] / SEGMENT))
                    .context("missing packed segment")?;
                seg.0 -= v[1].next_multiple_of(64);
                for p in object_pages(v) {
                    let count = next
                        .data_counts
                        .get_mut(&p)
                        .context("missing data-page reference")?;
                    *count -= 1;
                    if *count == 0 {
                        seg.1 -= 1;
                        next.data_counts.remove(&p);
                        next.pages.remove(&p);
                    }
                }
                if seg.1 == 0 {
                    debug_assert_eq!(seg.0, 0);
                    next.segments.remove(&(v[0] / SEGMENT));
                }
            }
            if let Some(v) = new {
                let seg = next.segments.get_or_default(v[0] / SEGMENT);
                seg.0 += v[1].next_multiple_of(64);
                for p in object_pages(v) {
                    let count = next.data_counts.get_or_default(p);
                    if *count == 0 {
                        seg.1 += 1;
                    }
                    *count += 1;
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
        self.stats.fragment_append_batches += a.fragment_appends;
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
                    self.publisher = Some(super::super::publish::Publisher::new()?);
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
        self.pending = Arc::new(Map::new());
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
        self.output_buffer = a.output;
        self.data_writer = Some(a.writer);
        self.stats.bookkeeping_ns += bookkeeping_started.elapsed().as_nanos() as u64;
        Ok(())
    }
}
