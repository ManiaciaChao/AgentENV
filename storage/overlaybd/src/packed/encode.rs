//! Bounded parallel preparation; workers never mutate mappings or publish roots.
use super::{
    core::{Codec, Policy, DIRTY_LIMIT},
    disk::PAGE,
};
use anyhow::{ensure, Context, Result};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    sync::{mpsc, Arc},
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
}
fn prepare(input: Input, policy: Policy) -> Result<Batch> {
    let mut batch = Batch {
        blocks: Vec::with_capacity(input.len()),
        bytes: Vec::with_capacity(input.len() * PAGE),
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
        if codec != 0 {
            batch.bytes.extend_from_slice(&scratch[..len]);
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
    Ok(batch)
}
struct Job {
    input: Input,
    policy: Policy,
    result: mpsc::Sender<Result<Batch>>,
}
struct SharedPool {
    tx: Option<mpsc::SyncSender<Job>>,
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
        let (tx, rx) = mpsc::sync_channel::<Job>(4);
        let jobs = Arc::new(std::sync::Mutex::new(rx));
        let mut pool = Self {
            tx: Some(tx),
            workers: Vec::new(),
        };
        for i in 0..count {
            let jobs = jobs.clone();
            pool.workers.push(
                thread::Builder::new()
                    .name(format!("packed-encode-{i}"))
                    .spawn(move || loop {
                        // Only receiving is serialized; preparation runs outside the lock.
                        let job = jobs.lock().unwrap().recv();
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
impl Pool {
    pub fn encode(
        &mut self,
        pending: &BTreeMap<u64, Arc<[u8; PAGE]>>,
        policy: Policy,
    ) -> Result<Vec<Batch>> {
        ensure!(
            pending.len() <= DIRTY_LIMIT / PAGE,
            "packed encoding exceeds dirty budget"
        );
        if pending.len() < 128 {
            return Ok(vec![prepare(
                pending.iter().map(|(&l, b)| (l, b.clone())).collect(),
                policy,
            )?]);
        }
        if self.shared.is_none() {
            self.shared = Some(SharedPool::acquire()?);
        }
        let pool = self.shared.as_ref().unwrap();
        let per_worker = pending.len().div_ceil(pool.workers.len());
        let mut input = pending.iter();
        let mut results = Vec::new();
        for _ in &pool.workers {
            let job: Input = input
                .by_ref()
                .take(per_worker)
                .map(|(&l, b)| (l, b.clone()))
                .collect();
            if job.is_empty() {
                break;
            }
            let (result, rx) = mpsc::channel();
            pool.tx
                .as_ref()
                .unwrap()
                .send(Job {
                    input: job,
                    policy,
                    result,
                })
                .map_err(|_| anyhow::anyhow!("packed encoder exited"))?;
            results.push(rx);
        }
        // Per-call reply channels keep simultaneous uppers and policies isolated.
        results
            .into_iter()
            .map(|rx| rx.recv().context("packed encoder exited")?)
            .collect()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
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
        for compression in [Codec::Lz4, Codec::None, Codec::Zstd, Codec::Lz4] {
            let batches = pool.encode(
                &input,
                Policy {
                    compression,
                    dedupe: true,
                },
            )?;
            let mut seen = 0;
            for batch in batches {
                for block in batch.blocks {
                    assert_eq!(block.lba, seen);
                    seen += 1;
                    let mut out = [0; PAGE];
                    if block.zero {
                        assert!(input[&block.lba].iter().all(|x| *x == 0));
                        continue;
                    }
                    match block.codec {
                        0 => out.copy_from_slice(block.plain.as_slice()),
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
                    assert_eq!(block.hash, <[u8; 32]>::from(Sha256::digest(out)));
                }
            }
            assert_eq!(seen, 257);
        }
        Ok(())
    }
}
