//! Bounded parallel preparation; workers never mutate mappings or publish roots.
use super::{
    core::{Codec, Policy, DIRTY_LIMIT},
    disk::PAGE,
};
use anyhow::{ensure, Context, Result};
use sha2::{Digest, Sha256};
use std::{collections::VecDeque, sync::Arc, thread};
type Input = Vec<(u64, super::buffer::Block)>;
pub(super) struct Block {
    pub lba: u64,
    pub plain: super::buffer::Block,
    pub offset: usize,
    pub len: usize,
    pub codec: u64,
    pub crc: u64,
    pub hash: [u8; 32],
    pub zero: bool,
    pub fallback: bool,
}
pub(super) struct Batch {
    pub blocks: Vec<Block>,
    pub bytes: Vec<u8>,
    pub packed: bool,
    recycle: Option<crossbeam_channel::Sender<Vec<u8>>>,
}
#[derive(Clone)]
struct Buffers {
    tx: crossbeam_channel::Sender<Vec<u8>>,
    rx: crossbeam_channel::Receiver<Vec<u8>>,
}
impl Drop for Batch {
    fn drop(&mut self) {
        if let Some(recycle) = &self.recycle {
            let mut bytes = std::mem::take(&mut self.bytes);
            bytes.clear();
            if bytes.capacity() <= JOB_BLOCKS * PAGE {
                let _ = recycle.try_send(bytes);
            }
        }
    }
}
fn prepare(input: Input, policy: Policy, buffers: Option<&Buffers>) -> Result<Batch> {
    let mut batch = Batch {
        blocks: Vec::with_capacity(input.len()),
        bytes: buffers
            .and_then(|b| b.rx.try_recv().ok())
            .unwrap_or_else(|| Vec::with_capacity(input.len() * PAGE)),
        recycle: buffers.map(|b| b.tx.clone()),
        packed: !policy.dedupe,
    };
    let mut scratch = [0u8; PAGE * 2];
    let mut zstd = if policy.compression == Codec::Zstd {
        Some(zstd::bulk::Compressor::new(1)?)
    } else {
        None
    };
    for (lba, plain) in input {
        let zero = plain.iter().all(|b| *b == 0);
        let hash = if policy.dedupe && !zero {
            Sha256::digest(plain.as_slice()).into()
        } else {
            [0; 32]
        };
        let (mut len, mut codec) = if zero {
            (0, 0)
        } else {
            match policy.compression {
                Codec::None => (PAGE, 0),
                Codec::Lz4 => {
                    let n = unsafe {
                        lz4_sys::LZ4_compress_default(
                            plain.as_ptr().cast(),
                            scratch.as_mut_ptr().cast(),
                            PAGE as i32,
                            scratch.len() as i32,
                        )
                    };
                    ensure!(n > 0, "LZ4 compression failed");
                    (n as usize, 1)
                }
                Codec::Zstd => (
                    zstd.as_mut()
                        .unwrap()
                        .compress_to_buffer(plain.as_slice(), scratch.as_mut_slice())?,
                    2,
                ),
            }
        };
        let fallback = codec != 0 && len.next_multiple_of(64) >= PAGE;
        if fallback {
            len = PAGE;
            codec = 0;
        }
        let offset = batch.bytes.len();
        if !zero {
            if codec != 0 {
                batch.bytes.extend_from_slice(&scratch[..len]);
            } else if batch.packed {
                batch.bytes.extend_from_slice(plain.as_slice());
            }
            if batch.packed {
                batch
                    .bytes
                    .resize(batch.bytes.len().next_multiple_of(64), 0);
            }
        }
        let crc = if zero {
            0
        } else {
            crc32c::crc32c(plain.as_slice()) as u64
        };
        batch.blocks.push(Block {
            lba,
            plain,
            offset,
            len,
            codec,
            crc,
            hash,
            zero,
            fallback,
        });
    }
    if batch.packed {
        batch
            .bytes
            .resize(batch.bytes.len().next_multiple_of(PAGE), 0);
    }
    Ok(batch)
}
struct Job {
    input: Input,
    policy: Policy,
    result: std::sync::mpsc::Sender<Result<Batch>>,
}
// Sleeping waits release the queue mutex. No receiver owns the queue while
// waiting, and no worker yields repeatedly when the producer is temporarily idle.
#[derive(Default)]
struct Jobs {
    state: std::sync::Mutex<(VecDeque<Job>, bool)>,
    ready: std::sync::Condvar,
    space: std::sync::Condvar,
}
impl Jobs {
    fn send(&self, job: Job) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        while state.0.len() == 4 && !state.1 {
            state = self.space.wait(state).unwrap();
        }
        ensure!(!state.1, "packed encoder exited");
        state.0.push_back(job);
        self.ready.notify_one();
        Ok(())
    }
    fn recv(&self) -> Option<Job> {
        let mut state = self.state.lock().unwrap();
        while state.0.is_empty() && !state.1 {
            state = self.ready.wait(state).unwrap();
        }
        let job = state.0.pop_front();
        if job.is_some() {
            self.space.notify_one();
        }
        job
    }
    fn close(&self) {
        self.state.lock().unwrap().1 = true;
        self.ready.notify_all();
        self.space.notify_all();
    }
}
struct SharedPool {
    jobs: Arc<Jobs>,
    workers: Vec<thread::JoinHandle<()>>,
}
// Process-lifetime ownership prevents teardown/recreation from briefly spawning
// two pools when the last upper closes concurrently with another opening.
static SHARED: std::sync::Mutex<Option<Arc<SharedPool>>> = std::sync::Mutex::new(None);
impl SharedPool {
    fn acquire() -> Result<Arc<Self>> {
        let mut shared = SHARED.lock().unwrap();
        if let Some(pool) = shared.as_ref() {
            return Ok(pool.clone());
        }
        let count = thread::available_parallelism()
            .map_or(1, |n| n.get())
            .min(4);
        let mut pool = Self {
            jobs: Arc::new(Jobs::default()),
            workers: Vec::new(),
        };
        let (tx, rx_buffers) = crossbeam_channel::bounded(8);
        let buffers = Buffers { tx, rx: rx_buffers };
        for i in 0..count {
            let buffers = buffers.clone();
            let jobs = pool.jobs.clone();
            pool.workers.push(
                thread::Builder::new()
                    .name(format!("packed-encode-{i}"))
                    .spawn(move || loop {
                        let job = jobs.recv();
                        match job {
                            Some(job) => {
                                let _ =
                                    job.result
                                        .send(prepare(job.input, job.policy, Some(&buffers)));
                            }
                            None => break,
                        }
                    })?,
            );
        }
        let pool = Arc::new(pool);
        *shared = Some(pool.clone());
        Ok(pool)
    }
}
impl Drop for SharedPool {
    fn drop(&mut self) {
        self.jobs.close();
        for join in self.workers.drain(..) {
            let _ = join.join();
        }
    }
}
#[derive(Default)]
pub(super) struct Pool {
    shared: Option<Arc<SharedPool>>,
}
// At most four 1 MiB jobs are outstanding. Consuming one result schedules the
// next job before the coordinator applies it, overlapping encode and disk work.
// Amortize channel handoffs and page packing across a bounded 1 MiB input.
const JOB_BLOCKS: usize = 256;
pub(super) struct Encoding {
    inline: Option<Result<Batch>>,
    queued: VecDeque<Input>,
    running: VecDeque<std::sync::mpsc::Receiver<Result<Batch>>>,
    pool: Option<Arc<SharedPool>>,
    policy: Policy,
    failed: bool,
}
impl Encoding {
    fn submit(&mut self) -> Result<()> {
        if let Some(input) = self.queued.pop_front() {
            // Exactly one result per job; the single-use channel cannot grow.
            // Use the blocking standard channel instead of yielding on a
            // crossbeam bounded array while the encoder is running.
            let (result, rx) = std::sync::mpsc::channel();
            self.pool
                .as_ref()
                .unwrap()
                .jobs
                .send(Job {
                    input,
                    policy: self.policy,
                    result,
                })
                .map_err(|_| anyhow::anyhow!("packed encoder exited"))?;
            self.running.push_back(rx);
        }
        Ok(())
    }
}
impl Iterator for Encoding {
    type Item = Result<Batch>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.failed {
            return None;
        }
        if let Some(batch) = self.inline.take() {
            return Some(batch);
        }
        let rx = self.running.pop_front()?;
        let result = (|| {
            let batch = rx.recv().context("packed encoder exited")??;
            self.submit()?;
            Ok(batch)
        })();
        self.failed = result.is_err();
        Some(result)
    }
}
impl Pool {
    pub fn encode(
        &mut self,
        pending: &super::memory::Map<super::buffer::Block>,
        policy: Policy,
    ) -> Result<Encoding> {
        ensure!(
            pending.len() <= DIRTY_LIMIT / PAGE,
            "packed encoding exceeds dirty budget"
        );
        let mut stream = Encoding {
            inline: None,
            queued: VecDeque::new(),
            running: VecDeque::new(),
            pool: None,
            policy,
            failed: false,
        };
        if pending.len() < 128 {
            stream.inline = Some(prepare(
                pending.iter().map(|(&l, b)| (l, b.clone())).collect(),
                policy,
                None,
            ));
            return Ok(stream);
        }
        if self.shared.is_none() {
            self.shared = Some(SharedPool::acquire()?);
        }
        let pool = self.shared.as_ref().unwrap().clone();
        let mut input = pending.iter();
        loop {
            let job: Input = input
                .by_ref()
                .take(JOB_BLOCKS)
                .map(|(&l, b)| (l, b.clone()))
                .collect();
            if job.is_empty() {
                break;
            }
            stream.queued.push_back(job);
        }
        let count = pool.workers.len();
        stream.pool = Some(pool);
        for _ in 0..count {
            stream.submit()?;
        }
        Ok(stream)
    }
}
#[cfg(test)]
mod tests {
    #[test]
    fn job_queue_close_releases_senders_and_drains_admitted_jobs() {
        use super::*;
        let jobs = Arc::new(Jobs::default());
        let job = || Job {
            input: Vec::new(),
            policy: Policy {
                compression: Codec::Lz4,
                dedupe: false,
            },
            result: std::sync::mpsc::channel().0,
        };
        for _ in 0..4 {
            jobs.send(job()).unwrap();
        }
        let blocked = jobs.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        let sender = thread::spawn(move || {
            tx.send(blocked.send(job()).is_err()).unwrap();
        });
        jobs.close();
        assert!(rx.recv_timeout(std::time::Duration::from_secs(2)).unwrap());
        sender.join().unwrap();
        for _ in 0..4 {
            assert!(jobs.recv().is_some());
        }
        assert!(jobs.recv().is_none());
    }

    use super::*;
    #[test]
    #[ignore = "manual codec throughput/ratio diagnostic, outside FSKit acceptance"]
    fn lz4_acceleration_profile() {
        let mut seed = 4981u64;
        let mut input = vec![[0u8; PAGE]; 1024];
        for block in &mut input {
            for word in block.chunks_exact_mut(8) {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                word.copy_from_slice(&seed.to_le_bytes());
            }
        }
        let mut output = [0u8; PAGE * 2];
        for corpus in ["random", "half-compressible", "source"] {
            if corpus == "half-compressible" {
                for block in &mut input {
                    for i in 2048..PAGE {
                        block[i] = block[i % 256];
                    }
                }
            } else if corpus == "source" {
                let source = include_bytes!("core.rs");
                for (i, block) in input.iter_mut().enumerate() {
                    for (j, byte) in block.iter_mut().enumerate() {
                        *byte = source[(i * 4096 + j) % source.len()];
                    }
                }
            }
            for acceleration in [1, 2, 4, 8] {
                let started = std::time::Instant::now();
                let mut encoded = 0usize;
                for _ in 0..32 {
                    for block in &input {
                        let n = unsafe {
                            lz4_sys::LZ4_compress_fast(
                                block.as_ptr().cast(),
                                output.as_mut_ptr().cast(),
                                PAGE as i32,
                                output.len() as i32,
                                acceleration,
                            )
                        };
                        assert!(n > 0);
                        encoded += (n as usize).next_multiple_of(64).min(PAGE);
                        std::hint::black_box(&output[..n as usize]);
                    }
                }
                eprintln!(
                    "{corpus} acceleration={acceleration} MiB/s={:.1} ratio={:.4}",
                    128.0 / started.elapsed().as_secs_f64(),
                    encoded as f64 / (128.0 * 1048576.0)
                );
            }
        }
    }
    #[test]
    fn stream_bounds_inflight_jobs_and_can_be_abandoned() -> Result<()> {
        let input = (0..4096)
            .map(|i| (i, Box::new([i as u8; PAGE]).into()))
            .collect();
        let mut pool = Pool::default();
        let mut stream = pool.encode(&input, Policy::default())?;
        let workers = stream.pool.as_ref().unwrap().workers.len();
        assert_eq!(stream.running.len(), workers);
        assert_eq!(
            stream.queued.len() + stream.running.len(),
            input.len().div_ceil(JOB_BLOCKS)
        );
        let first = stream.next().unwrap()?;
        assert_eq!(first.blocks.len(), JOB_BLOCKS);
        assert_eq!(stream.running.len(), workers);
        assert_eq!(
            stream.queued.len() + stream.running.len(),
            input.len().div_ceil(JOB_BLOCKS) - 1
        );
        drop(stream); // Outstanding replies can be discarded without blocking workers.
        let mut count = 0;
        for batch in pool.encode(
            &input,
            Policy {
                compression: Codec::None,
                dedupe: false,
            },
        )? {
            let batch = batch?;
            assert!(batch.blocks.iter().all(|b| b.codec == 0));
            count += batch.blocks.len();
        }
        assert_eq!(count, input.len());
        Ok(())
    }
    #[test]
    fn different_uppers_share_at_most_four_workers() -> Result<()> {
        let a = SharedPool::acquire()?;
        let b = SharedPool::acquire()?;
        assert!(Arc::ptr_eq(&a, &b));
        assert!((1..=4).contains(&a.workers.len()));
        Ok(())
    }
    #[test]
    fn parallel_blocks_decode_independently_across_policy_switches() -> Result<()> {
        let mut input = super::super::memory::Map::new();
        let mut seed = 17u64;
        for i in 0..257 {
            let mut b = [0; PAGE];
            for byte in &mut b {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                *byte = seed as u8;
            }
            if i % 3 == 0 {
                b.fill(0);
            } else if i % 3 == 1 {
                b[1024..].fill(i as u8);
            }
            input.insert(i, Box::new(b).into());
        }
        let mut pool = Pool::default();
        for (compression, dedupe) in [Codec::Lz4, Codec::None, Codec::Zstd, Codec::Lz4]
            .into_iter()
            .flat_map(|codec| [(codec, false), (codec, true)])
        {
            let batches = pool.encode(
                &input,
                Policy {
                    compression,
                    dedupe,
                },
            )?;
            let mut seen = 0;
            for batch in batches {
                let batch = batch?;
                assert_eq!(batch.packed, !dedupe);
                if batch.packed {
                    assert_eq!(batch.bytes.len() % PAGE, 0);
                }
                for block in &batch.blocks {
                    assert_eq!(block.lba, seen);
                    seen += 1;
                    let mut out = [0; PAGE];
                    if block.zero {
                        assert!(input[&block.lba].iter().all(|x| *x == 0));
                        continue;
                    }
                    match block.codec {
                        0 => out.copy_from_slice(if batch.packed {
                            &batch.bytes[block.offset..block.offset + block.len]
                        } else {
                            block.plain.as_slice()
                        }),
                        1 => {
                            let n = unsafe {
                                lz4_sys::LZ4_decompress_safe(
                                    batch.bytes[block.offset..].as_ptr().cast(),
                                    out.as_mut_ptr().cast(),
                                    block.len as i32,
                                    PAGE as i32,
                                )
                            };
                            assert_eq!(n, PAGE as i32);
                        }
                        2 => out.copy_from_slice(&zstd::bulk::decompress(
                            &batch.bytes[block.offset..block.offset + block.len],
                            PAGE,
                        )?),
                        _ => unreachable!(),
                    }
                    assert_eq!(out, *input[&block.lba]);
                    assert_eq!(block.crc, crc32c::crc32c(&out) as u64);
                    assert_eq!(
                        block.hash,
                        if dedupe {
                            <[u8; 32]>::from(Sha256::digest(out))
                        } else {
                            [0; 32]
                        }
                    );
                    if batch.packed {
                        assert_eq!(block.offset % 64, 0);
                    }
                }
            }
            assert_eq!(seen, 257);
        }
        Ok(())
    }
}
