//! Bounded parallel preparation; workers never mutate mappings or publish roots.
use super::{
    core::{Codec, Policy, DIRTY_LIMIT},
    disk::PAGE,
};
use anyhow::{ensure, Context, Result};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, VecDeque},
    sync::Arc,
    thread,
};
type Input = Vec<(u64, Arc<[u8; PAGE]>)>;
pub(super) struct Block {
    pub lba: u64,
    pub plain: Arc<[u8; PAGE]>,
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
}
fn prepare(input: Input, policy: Policy) -> Result<Batch> {
    let mut batch = Batch {
        blocks: Vec::with_capacity(input.len()),
        bytes: Vec::with_capacity(input.len() * PAGE),
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
    result: crossbeam_channel::Sender<Result<Batch>>,
}
struct SharedPool {
    tx: Option<crossbeam_channel::Sender<Job>>,
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
        let (tx, rx) = crossbeam_channel::bounded::<Job>(4);
        let mut pool = Self {
            tx: Some(tx),
            workers: Vec::new(),
        };
        for i in 0..count {
            let jobs = rx.clone();
            pool.workers.push(
                thread::Builder::new()
                    .name(format!("packed-encode-{i}"))
                    .spawn(move || loop {
                        // Every worker waits directly on the bounded MPMC queue.
                        // No sleeping receiver holds a mutex needed by its peers.
                        let job = jobs.recv();
                        match job {
                            Ok(job) => {
                                let _ = job.result.send(prepare(job.input, job.policy));
                            }
                            Err(_) => break,
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
        self.tx.take();
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
    running: VecDeque<crossbeam_channel::Receiver<Result<Batch>>>,
    pool: Option<Arc<SharedPool>>,
    policy: Policy,
    failed: bool,
}
impl Encoding {
    fn submit(&mut self) -> Result<()> {
        if let Some(input) = self.queued.pop_front() {
            let (result, rx) = crossbeam_channel::bounded(1);
            self.pool
                .as_ref()
                .unwrap()
                .tx
                .as_ref()
                .unwrap()
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
        pending: &BTreeMap<u64, Arc<[u8; PAGE]>>,
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
        let input = (0..4096).map(|i| (i, Arc::new([i as u8; PAGE]))).collect();
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
        let mut input = BTreeMap::new();
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
            input.insert(i, Arc::new(b));
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
                for block in batch.blocks {
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
