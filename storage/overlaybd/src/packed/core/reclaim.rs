//! Retirement, relocation selection and safe asynchronous hole punching.
use super::super::{disk::PAGE, memory::Map};
use super::{Core, Punching, SEGMENT};
use anyhow::Result;
use std::time::Instant;
// Occupancy alone is insufficient: a sparse one-page tail cannot shrink.
// Reserve one page for padding at a destination segment boundary, and demand
// strictly positive physical-page savings even in that worst case.
pub(super) fn cleaner_victim(segments: &Map<(u64, u64)>) -> Option<u64> {
    segments
        .iter()
        .filter(|(_, v)| v.0 * 10 < v.1 * PAGE as u64 * 7 && v.0.div_ceil(PAGE as u64) + 1 < v.1)
        .min_by_key(|(_, v)| v.0)
        .map(|(&seg, _)| seg)
}
impl Core {
    pub fn maintenance(&mut self) -> Result<()> {
        self.maintenance_interruptible(|| false)
    }
    pub fn maintenance_interruptible(&mut self, should_yield: impl Fn() -> bool) -> Result<()> {
        self.check()?;
        self.finish_cleaning(true)?;
        let r = self.maintenance_inner(&should_yield, None);
        if let Err(e) = &r {
            *self.poison.lock().unwrap() = Some(format!("{e:#}"));
        }
        r
    }
    pub fn maintenance_async(
        &mut self,
        wake: std::sync::mpsc::SyncSender<()>,
        should_yield: impl Fn() -> bool,
    ) -> Result<()> {
        self.check()?;
        let result = self.maintenance_inner(&should_yield, Some(wake));
        if let Err(error) = &result {
            *self.poison.lock().unwrap() = Some(format!("{error:#}"));
        }
        result
    }
    pub fn finish_cleaning(&mut self, wait: bool) -> Result<bool> {
        let Some(punching) = &self.punching else {
            return Ok(false);
        };
        let outcome = if wait {
            punching.done.recv().map_err(|error| {
                *self.poison.lock().unwrap() = Some(format!("packed cleaner exited: {error}"));
                anyhow::anyhow!("packed cleaner exited: {error}")
            })?
        } else {
            match punching.done.try_recv() {
                Ok(outcome) => outcome,
                Err(std::sync::mpsc::TryRecvError::Empty) => return Ok(false),
                Err(error) => {
                    *self.poison.lock().unwrap() = Some(format!("packed cleaner exited: {error}"));
                    return Err(error.into());
                }
            }
        };
        let punching = self.punching.take().unwrap();
        self.stats.cleaner_ns += outcome.1;
        self.stats.barrier_ns += outcome.2;
        // Count attempted barriers, including failures. A punch failure can
        // occur before any barrier. The worker poisons before sending errors.
        self.stats.barriers += outcome.3;
        outcome.0?;
        self.stats.reclaimed_bytes += punching.pages.len() as u64 * PAGE as u64;
        self.punched.extend(punching.pages);
        Ok(true)
    }
    fn maintenance_inner(
        &mut self,
        should_yield: &impl Fn() -> bool,
        wake: Option<std::sync::mpsc::SyncSender<()>>,
    ) -> Result<()> {
        if self.publication.is_some()
            || !self.pending.is_empty()
            || self.working.is_some()
            || should_yield()
        {
            return Ok(());
        }
        let end = self.disk.len()?.div_ceil(PAGE as u64);
        let protected = self.protected_roots();
        // Dual roots ARE the persistent retirement ledger: a page stays quarantined
        // until neither recoverable root references it. Reopen reconstructs this set.
        let latest = &self.root().pages;
        let retired = protected.difference_count(latest).saturating_sub(2) as u64 * PAGE as u64;
        let live = self.root().aligned_bytes;
        let used = latest.len() as u64 * PAGE as u64;
        let data_bytes = self.root().data_counts.len() as u64 * PAGE as u64;
        let fragmented = data_bytes.saturating_sub(live);
        let free_bytes = end
            .saturating_sub(protected.len() as u64)
            .saturating_sub(self.punched.len() as u64)
            * PAGE as u64;
        let invalid = retired
            .saturating_add(fragmented)
            .saturating_add(free_bytes);
        let allocated = end.saturating_sub(self.punched.len() as u64) * PAGE as u64;
        // Small reusable holes do not justify a punch + full durability barrier.
        // Reuse remains available to foreground allocation below this threshold.
        if !self.cleaner_rotate
            && invalid < 8 * 1024 * 1024
            && invalid.saturating_mul(10) < allocated.max(PAGE as u64).saturating_mul(3)
        {
            self.warm_dedupe(32)?;
            return Ok(());
        }
        let rotation_can_release_pages = self.roots[1 - self.current]
            .as_ref()
            .is_some_and(|root| root.pages.difference_count(latest) != 0);
        if self.cleaner_rotate
            || (rotation_can_release_pages
                && (retired >= 8 * 1024 * 1024 || retired * 10 >= used.max(PAGE as u64) * 3))
        {
            if let Some(wake) = wake {
                self.run_publish(None, true, Some(wake))?;
                self.cleaner_rotate = false;
                return Ok(());
            }
            self.publish(true, None)?;
            self.cleaner_rotate = false;
            if should_yield() {
                return Ok(());
            }
        }
        if fragmented >= 8 * 1024 * 1024
            || (data_bytes > SEGMENT && fragmented * 10 >= data_bytes * 3)
        {
            let selection_started = Instant::now();
            let victim = cleaner_victim(&self.root().segments);
            self.stats.cleaner_selection_ns += selection_started.elapsed().as_nanos() as u64;
            if let Some(seg) = victim {
                if should_yield() {
                    return Ok(());
                }
                if let Some(wake) = wake {
                    self.run_publish(Some(seg), true, Some(wake))?;
                    self.cleaner_rotate = true;
                    return Ok(());
                }
                self.publish(true, Some(seg))?;
                if should_yield() {
                    return Ok(());
                }
                self.publish(true, None)?;
            }
        }
        if self.punching.is_some() {
            return Ok(());
        }
        let protected = self.protected();
        let free: Vec<_> = protected
            .holes(end)
            .filter(|p| !self.punched.contains(p))
            .take(if wake.is_some() { 4096 } else { usize::MAX })
            .collect();
        // Pinned retirement and fragmentation are not punchable space. They
        // must not turn each tiny metadata hole into its own fullsync job.
        // Below the threshold, holes remain immediately reusable by writers.
        let punch_bytes = free.len() as u64 * PAGE as u64;
        if punch_bytes < 8 * 1024 * 1024
            && punch_bytes.saturating_mul(10) < allocated.max(PAGE as u64).saturating_mul(3)
        {
            self.warm_dedupe(32)?;
            return Ok(());
        }
        if let Some(wake) = wake {
            if !free.is_empty() {
                self.stats.cleaner_punch_batches += 1;
                if self.cleaner.is_none() {
                    self.cleaner = Some(super::super::cleaner::Cleaner::new()?);
                }
                let (tx, done) = std::sync::mpsc::channel();
                let pages = free.clone();
                let disk = self.disk.clone();
                let poison = self.poison.clone();
                self.cleaner.as_ref().unwrap().submit(move || {
                    let started = Instant::now();
                    let mut barrier_ns = 0;
                    let mut barriers = 0;
                    let result = (|| {
                        let mut i = 0;
                        while i < pages.len() {
                            let start = pages[i];
                            let mut n = 1;
                            while i + n < pages.len()
                                && pages[i + n] == start + n as u64
                                && n < SEGMENT as usize / PAGE
                            {
                                n += 1;
                            }
                            disk.punch(start * PAGE as u64, n as u64 * PAGE as u64)?;
                            i += n;
                        }
                        let before = Instant::now();
                        barriers = 1;
                        let result = disk.barrier();
                        barrier_ns = before.elapsed().as_nanos() as u64;
                        result
                    })();
                    if let Err(error) = &result {
                        *poison.lock().unwrap() = Some(format!("{error:#}"));
                    }
                    let _ = tx.send((
                        result,
                        started.elapsed().as_nanos() as u64,
                        barrier_ns,
                        barriers,
                    ));
                    let _ = wake.try_send(());
                })?;
                self.punching = Some(Punching { pages: free, done });
            }
            self.warm_dedupe(32)?;
            return Ok(());
        }
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
            self.stats.cleaner_punch_batches += 1;
            self.barrier()?;
        }
        self.warm_dedupe(32)?;
        Ok(())
    }
}
