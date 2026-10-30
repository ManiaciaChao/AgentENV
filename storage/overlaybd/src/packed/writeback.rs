//! Ordered payload/metadata writes, bounded to 4 MiB of queued buffer capacity.
//! Working reads pin queued buffers; durable publication always drains the queue.
use super::disk::Disk;
use anyhow::{Context, Result};
use std::{
    sync::{Arc, Mutex},
    thread,
    time::Instant,
};

#[derive(Default)]
pub(super) struct ReadCache {
    buffers: Mutex<std::collections::BTreeMap<u64, Arc<Vec<u8>>>>,
    high_water: std::sync::atomic::AtomicU64,
}
impl ReadCache {
    pub fn end(&self) -> u64 {
        self.high_water.load(std::sync::atomic::Ordering::Acquire)
    }
    fn insert(&self, offset: u64, bytes: Arc<Vec<u8>>) -> Result<()> {
        let end = offset
            .checked_add(bytes.len() as u64)
            .context("packed write offset overflow")?;
        let mut buffers = self.buffers.lock().unwrap();
        anyhow::ensure!(
            buffers
                .range(..end)
                .next_back()
                .is_none_or(|(&start, b)| start + b.len() as u64 <= offset),
            "overlapping packed queued writes"
        );
        self.high_water
            .fetch_max(end, std::sync::atomic::Ordering::AcqRel);
        buffers.insert(offset, bytes);
        Ok(())
    }
    pub fn protect(&self, pages: &mut super::memory::PageSet) {
        let buffers = self.buffers.lock().unwrap();
        for (&offset, bytes) in buffers.iter() {
            pages.extend(
                offset / super::disk::PAGE as u64
                    ..(offset + bytes.len() as u64).div_ceil(super::disk::PAGE as u64),
            );
        }
    }
    pub fn read(&self, disk: &dyn Disk, offset: u64, dst: &mut [u8]) -> Result<()> {
        let end = offset
            .checked_add(dst.len() as u64)
            .context("packed read offset overflow")?;
        // Pin first, then release the cache lock before copying or doing I/O.
        // Removal only follows a completed pwrite, so uncached ranges are on disk.
        let pinned: Vec<_> = self
            .buffers
            .lock()
            .unwrap()
            .range(..end)
            .filter(|(start, b)| **start + b.len() as u64 > offset)
            .map(|(&start, b)| (start, b.clone()))
            .collect();
        let mut at = offset;
        for (start, bytes) in pinned {
            if start > at {
                disk.read(
                    at,
                    &mut dst[(at - offset) as usize..(start - offset) as usize],
                )?;
                at = start;
            }
            let take_end = end.min(start + bytes.len() as u64);
            dst[(at - offset) as usize..(take_end - offset) as usize]
                .copy_from_slice(&bytes[(at - start) as usize..(take_end - start) as usize]);
            at = take_end;
        }
        if at < end {
            disk.read(at, &mut dst[(at - offset) as usize..])?;
        }
        Ok(())
    }
}

pub(super) const WRITE_BYTES: usize = 2 * 1024 * 1024;
const QUEUE_BYTES: usize = 4 * 1024 * 1024;
const QUEUE_DEPTH: usize = 1024;

struct Job {
    offset: u64,
    bytes: Arc<Vec<u8>>,
    metadata: bool,
}
struct Done {
    bytes: Arc<Vec<u8>>,
    result: Result<()>,
    ns: u64,
    metadata: bool,
}
#[derive(Default)]
pub(super) struct Timings {
    pub data_ns: u64,
    pub metadata_ns: u64,
    pub wait_ns: u64,
}
pub(super) struct Writer {
    tx: Option<std::sync::mpsc::SyncSender<Job>>,
    done: std::sync::mpsc::Receiver<Done>,
    pending: usize,
    pending_bytes: usize,
    timings: Timings,
    thread: Option<thread::JoinHandle<()>>,
    cache: Arc<ReadCache>,
}
impl Writer {
    pub fn new(
        disk: Arc<dyn Disk>,
        poison: Arc<Mutex<Option<String>>>,
        cache: Arc<ReadCache>,
    ) -> Result<Self> {
        let (tx, rx) = std::sync::mpsc::sync_channel::<Job>(QUEUE_DEPTH);
        let (completed, done) = std::sync::mpsc::sync_channel(QUEUE_DEPTH);
        let written = cache.clone();
        let thread = thread::Builder::new()
            .name("packed-data".into())
            .spawn(move || {
                super::scheduling::foreground();
                while let Ok(job) = rx.recv() {
                    let started = Instant::now();
                    let result = disk.write(job.offset, &job.bytes);
                    let ns = started.elapsed().as_nanos() as u64;
                    if let Err(error) = &result {
                        *poison.lock().unwrap() = Some(format!("{error:#}"));
                    }
                    if result.is_ok() {
                        written.buffers.lock().unwrap().remove(&job.offset);
                    }
                    let _ = completed.send(Done {
                        bytes: job.bytes,
                        result,
                        ns,
                        metadata: job.metadata,
                    });
                }
            })?;
        Ok(Self {
            tx: Some(tx),
            done,
            pending: 0,
            pending_bytes: 0,
            timings: Timings::default(),
            thread: Some(thread),
            cache,
        })
    }
    fn reap(&mut self) -> Result<Option<Vec<u8>>> {
        let started = Instant::now();
        let done = self.done.recv().context("packed data writer exited")?;
        self.timings.wait_ns += started.elapsed().as_nanos() as u64;
        self.record(done)
    }
    fn record(&mut self, done: Done) -> Result<Option<Vec<u8>>> {
        self.pending -= 1;
        if done.metadata {
            self.timings.metadata_ns += done.ns;
        } else {
            self.timings.data_ns += done.ns;
        }
        self.pending_bytes -= done.bytes.capacity();
        done.result?;
        Ok(Arc::try_unwrap(done.bytes).ok().map(|mut bytes| {
            bytes.clear();
            bytes
        }))
    }
    pub fn submit(&mut self, offset: u64, mut bytes: Vec<u8>, metadata: bool) -> Result<Vec<u8>> {
        anyhow::ensure!(
            bytes.capacity() <= WRITE_BYTES,
            "packed write buffer exceeds limit: len={} capacity={} limit={}",
            bytes.len(),
            bytes.capacity(),
            WRITE_BYTES
        );
        // Compression usually leaves much of the input-sized allocation unused.
        // Return that capacity before charging the queue. This preserves the
        // 4 MiB live-buffer limit while allowing more encoded work to overlap
        // publication. Unlike copying into a new Arc slice, realloc can shrink
        // these page-sized allocations in place; correctness does not require it.
        bytes.shrink_to_fit();
        let mut recycled = None;
        while self.pending == QUEUE_DEPTH || self.pending_bytes + bytes.capacity() > QUEUE_BYTES {
            recycled = self.reap()?.or(recycled);
        }
        if recycled.is_none() {
            if let Ok(done) = self.done.try_recv() {
                recycled = self.record(done)?;
            }
        }
        // Transfer the allocation, not its contents. Charge capacity so short
        // batches cannot conceal retained memory. Readers may pin a completed
        // buffer; recycle only after the last such reference is gone.
        let queued = Arc::new(bytes);
        self.cache.insert(offset, queued.clone())?;
        let capacity = queued.capacity();
        self.tx
            .as_ref()
            .unwrap()
            .send(Job {
                offset,
                bytes: queued,
                metadata,
            })
            .context("packed data writer exited")?;
        self.pending += 1;
        self.pending_bytes += capacity;
        Ok(recycled.unwrap_or_default())
    }
    pub fn progress(&mut self) -> Result<Timings> {
        while let Ok(done) = self.done.try_recv() {
            self.record(done)?;
        }
        Ok(std::mem::take(&mut self.timings))
    }
    pub fn finish(&mut self) -> Result<Timings> {
        while self.pending > 0 {
            self.reap()?;
        }
        Ok(std::mem::take(&mut self.timings))
    }
}
impl Drop for Writer {
    fn drop(&mut self) {
        self.tx.take();
        // Consume outstanding completions so a full result queue cannot prevent
        // the worker from exiting, including after an earlier write failed.
        while self.pending > 0 {
            if self.done.recv().is_err() {
                break;
            }
            self.pending -= 1;
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cache_reads_span_disk_gaps_and_queued_buffers_beyond_eof() -> Result<()> {
        struct Base;
        impl Disk for Base {
            fn read(&self, o: u64, b: &mut [u8]) -> Result<()> {
                anyhow::ensure!(o + b.len() as u64 <= 16384, "read past backing EOF");
                b.fill(1);
                Ok(())
            }
            fn write(&self, _: u64, _: &[u8]) -> Result<()> {
                unreachable!()
            }
            fn barrier(&self) -> Result<()> {
                unreachable!()
            }
            fn len(&self) -> Result<u64> {
                Ok(16384)
            }
            fn allocated(&self) -> Result<u64> {
                Ok(16384)
            }
            fn punch(&self, _: u64, _: u64) -> Result<()> {
                unreachable!()
            }
        }
        let cache = ReadCache::default();
        cache.insert(4096, Arc::new(vec![2; 8192]))?;
        cache.insert(16384, Arc::new(vec![3; 4096]))?;
        assert!(cache.insert(8192, Arc::new(vec![9; 4096])).is_err());
        let mut bytes = vec![0; 19000];
        cache.read(&Base, 1000, &mut bytes)?;
        for (i, b) in bytes.iter().enumerate() {
            let at = i + 1000;
            assert_eq!(
                *b,
                if (4096..12288).contains(&at) {
                    2
                } else if at >= 16384 {
                    3
                } else {
                    1
                }
            );
        }
        let mut pages = super::super::memory::PageSet::new();
        cache.protect(&mut pages);
        assert_eq!(pages.len(), 3);
        assert_eq!(cache.end(), 20480);
        Ok(())
    }
    #[test]
    fn queue_is_bounded_and_preserves_write_order() -> Result<()> {
        use std::sync::mpsc;
        struct Held {
            started: mpsc::SyncSender<()>,
            release: Mutex<mpsc::Receiver<()>>,
            writes: Mutex<Vec<u64>>,
        }
        impl Disk for Held {
            fn write(&self, offset: u64, _: &[u8]) -> Result<()> {
                let first = self.writes.lock().unwrap().is_empty();
                if first {
                    self.started.send(())?;
                    self.release.lock().unwrap().recv()?;
                }
                self.writes.lock().unwrap().push(offset);
                Ok(())
            }
            fn read(&self, _: u64, _: &mut [u8]) -> Result<()> {
                unreachable!()
            }
            fn barrier(&self) -> Result<()> {
                unreachable!()
            }
            fn len(&self) -> Result<u64> {
                Ok(0)
            }
            fn allocated(&self) -> Result<u64> {
                Ok(0)
            }
            fn punch(&self, _: u64, _: u64) -> Result<()> {
                unreachable!()
            }
        }
        struct Release(mpsc::SyncSender<()>);
        impl Drop for Release {
            fn drop(&mut self) {
                let _ = self.0.try_send(());
            }
        }
        let (started, ready) = mpsc::sync_channel(1);
        let (release, receive) = mpsc::sync_channel(1);
        let disk = Arc::new(Held {
            started,
            release: Mutex::new(receive),
            writes: Mutex::new(Vec::new()),
        });
        let mut writer = Writer::new(
            disk.clone(),
            Arc::new(Mutex::new(None)),
            Arc::new(ReadCache::default()),
        )?;
        let release = Release(release);
        let jobs = 8;
        let part = QUEUE_BYTES / jobs;
        for offset in 0..jobs {
            let mut short = Vec::with_capacity(WRITE_BYTES);
            short.resize(part, 7);
            writer.submit((offset * part) as u64, short, false)?;
        }
        ready.recv_timeout(std::time::Duration::from_secs(5))?;
        assert_eq!(writer.pending, jobs);
        assert_eq!(writer.pending_bytes, QUEUE_BYTES);
        let (tx, rx) = mpsc::channel();
        let join = std::thread::spawn(move || -> Result<()> {
            writer.submit((jobs * part) as u64, vec![8; part], true)?;
            tx.send(())?;
            let timings = writer.finish()?;
            assert_eq!(writer.pending, 0);
            assert!(timings.data_ns > 0 && timings.metadata_ns > 0);
            Ok(())
        });
        assert!(rx
            .recv_timeout(std::time::Duration::from_millis(30))
            .is_err());
        drop(release);
        rx.recv_timeout(std::time::Duration::from_secs(5))?;
        join.join().unwrap()?;
        assert_eq!(
            *disk.writes.lock().unwrap(),
            (0..=jobs).map(|i| (i * part) as u64).collect::<Vec<_>>()
        );
        Ok(())
    }
}
