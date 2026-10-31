//! Single-owner commit coordinator and bounded preparation worker.
use super::super::disk::PAGE;
use super::{
    Core, Dirty, Front, PackedUpper, Prepared, Ranges, Shared, GENERATION_LIMIT, PREPARE_THRESHOLD,
};
use crate::lsmt::file::LSMTReadOnlyFile;
use anyhow::Result;
use std::{
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};
use tokio::sync::{Notify, RwLock};
impl PackedUpper {
    pub(super) fn start(
        mut core: Core,
        lower: Option<Arc<LSMTReadOnlyFile>>,
        size: u64,
    ) -> Result<Self> {
        core.async_data = true;
        let uuid = core.uuid();
        let front = Arc::new(Mutex::new(Front {
            prepared: None,
            pending: Dirty::new(),
            inflight: Arc::new(Dirty::new()),
            pressure: false,
            view: core.view(),
            sequence: 0,
            durable: 0,
            requested: 0,
            policy: core.policy,
            stats: core.stats()?,
        }));
        let notify = Arc::new(Notify::new());
        let budget = super::super::buffer::Budget::new(notify.clone());
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (wake, rx) = std::sync::mpsc::sync_channel(1);
        let (prefetch_wake, prefetch_rx) = std::sync::mpsc::sync_channel(1);
        let prefetch_request = prefetch_wake.clone();
        let (state, changed, stopping) = (front.clone(), notify.clone(), stop.clone());
        let publication_wake = wake.clone();
        let prefetch_state = front.clone();
        let mut prefetch_pool = super::super::encode::Pool::default();
        let mut prepare = move || -> Result<bool> {
            let (blocks, policy) = {
                let mut f = prefetch_state.lock().unwrap();
                if f.inflight.is_empty()
                    || f.prepared.is_some()
                    || f.pending.len() * PAGE < PREPARE_THRESHOLD
                {
                    return Ok(false);
                }
                f.view.check()?;
                let split = f.pending.keys().nth(GENERATION_LIMIT / PAGE).copied();
                let (blocks, boundary) = if let Some(key) = split {
                    let remaining = f.pending.split_off(&key);
                    (std::mem::replace(&mut f.pending, remaining), f.durable)
                } else {
                    (std::mem::take(&mut f.pending), f.sequence)
                };
                let blocks = Arc::new(blocks);
                let policy = f.policy;
                // Install the immutable plaintext view before dispatch, so reads
                // and capacity accounting remain correct while workers start.
                f.prepared = Some(Prepared {
                    blocks: blocks.clone(),
                    boundary,
                    policy,
                    encoding: None,
                });
                (blocks, policy)
            };
            let encoding = prefetch_pool.encode(&blocks, policy)?;
            prefetch_state
                .lock()
                .unwrap()
                .prepared
                .as_mut()
                .unwrap()
                .encoding = Some(encoding);
            Ok(true)
        };
        let worker = thread::Builder::new()
            .name("packed-commit".into())
            .spawn(move || {
                super::super::scheduling::foreground();
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
                    if let Err(error) = core.finish_cleaning(false) {
                        state.lock().unwrap().view.fail(&error);
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
                        if f.prepared.as_ref().is_some_and(|p| p.encoding.is_none()) {
                            immediate = false;
                            continue;
                        }
                        if !f.has_pending() && core.publication_pending() {
                            // Only publisher completion can advance a waiting
                            // flush here. Do not generate no-op wakeup cycles.
                            immediate = false;
                            continue;
                        }
                        let needs_flush = f.requested
                            > f.durable.max(if core.publication_pending() {
                                publication_boundary
                            } else {
                                0
                            });
                        let commit = !core.publication_pending()
                            && (f.requested > f.durable
                                || last_commit.elapsed() >= Duration::from_millis(100));
                        // Capacity wakeups from the previous inflight generation can
                        // be stale. Do not turn them into undersized new commits.
                        if f.prepared.is_none()
                            && !f.pending.is_empty()
                            && !needs_flush
                            && !f.pressure
                            && f.pending.len() * PAGE < GENERATION_LIMIT
                            && (core.publication_pending()
                                || last_commit.elapsed() < Duration::from_millis(100))
                        {
                            immediate = false;
                            continue;
                        }
                        f.pressure = false;
                        if let Some(mut prepared) = f.prepared.take() {
                            // Avoid publishing only a prefix of an explicit flush
                            // when a newer pending batch must also be drained.
                            let commit = commit
                                && (f.requested <= prepared.boundary || f.pending.is_empty());
                            f.inflight = prepared.blocks.clone();
                            let encoding = prepared
                                .encoding
                                .take()
                                .expect("preparer signaled completion before reuse");
                            (
                                prepared.blocks,
                                prepared.boundary,
                                prepared.policy,
                                commit,
                                Some(encoding),
                            )
                        } else {
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
                            let pending = Arc::new(pending);
                            f.inflight = pending.clone();
                            (pending, boundary, f.policy, commit, None)
                        }
                    };
                    let wrote = !batch.0.is_empty();
                    core.pending = batch.0;
                    core.policy = batch.2;
                    core.prepared = batch.4;
                    let _ = prefetch_request.try_send(());
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
                        core.maintenance_async(publication_wake.clone(), || {
                            state.lock().unwrap().has_pending()
                        })
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
                            f.inflight = Arc::new(Dirty::new());
                            match statistics.unwrap() {
                                Ok(stats) => f.stats = stats,
                                Err(e) => f.view.fail(&e),
                            }
                        }
                        Err(e) => f.view.fail(&e),
                    }
                    let more = f.has_pending();
                    drop(f);
                    changed.notify_waiters();
                    // Don't wait for the timer when capacity pressure queued another batch.
                    immediate = more;
                }
            })?;
        let (preparing, prepared_front, prepared_notify, prepared_wake) =
            (stop.clone(), front.clone(), notify.clone(), wake.clone());
        let prefetch_worker =
            thread::Builder::new()
                .name("packed-prepare".into())
                .spawn(move || {
                    super::super::scheduling::foreground();
                    while prefetch_rx.recv().is_ok() {
                        if preparing.load(std::sync::atomic::Ordering::Acquire) {
                            break;
                        }
                        let completed = match prepare() {
                            Ok(completed) => completed,
                            Err(error) => {
                                prepared_front.lock().unwrap().view.fail(&error);
                                prepared_notify.notify_waiters();
                                true
                            }
                        };
                        // Wake only after installing a stream (or poisoning it).
                        // Echoing no-op requests would form an idle wakeup cycle.
                        if completed {
                            let _ = prepared_wake.try_send(());
                        }
                    }
                });
        let prefetch_worker = match prefetch_worker {
            Ok(worker) => worker,
            Err(error) => {
                stop.store(true, std::sync::atomic::Ordering::Release);
                let _ = wake.try_send(());
                let _ = worker.join();
                return Err(error.into());
            }
        };
        Ok(Self(Arc::new(Shared {
            front,
            notify,
            budget,
            caller_qos: std::sync::atomic::AtomicU32::new(0),
            stage_ns: std::sync::atomic::AtomicU64::new(0),
            wait_ns: std::sync::atomic::AtomicU64::new(0),
            lower,
            size,
            uuid,
            gate: RwLock::new(()),
            ranges: Arc::new(Ranges::default()),
            wake,
            prefetch_wake,
            prefetch_worker: Mutex::new(Some(prefetch_worker)),
            stop,
            worker: Mutex::new(Some(worker)),
        })))
    }
}
