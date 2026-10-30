//! One ordered root publisher per upper. Payload preparation may continue while
//! the two durability barriers run; only completion acknowledges the generation.
use super::disk::{Disk, PAGE};
use anyhow::{Context, Result};
use std::{
    sync::{mpsc, Arc, Mutex},
    thread,
    time::Instant,
};

pub(super) struct Outcome {
    pub result: Result<()>,
    pub barriers: u64,
    pub barrier_ns: u64,
    pub phase_ns: [u64; 2],
    pub elapsed_ns: u64,
    pub peak: u64,
}
struct Job {
    disk: Arc<dyn Disk>,
    slot: usize,
    header: [u8; PAGE],
    poison: Arc<Mutex<Option<String>>>,
    done: mpsc::Sender<Outcome>,
    wake: mpsc::SyncSender<()>,
}
pub(super) struct Publisher {
    jobs: Option<mpsc::SyncSender<Job>>,
    thread: Option<thread::JoinHandle<()>>,
}
impl Publisher {
    pub fn new() -> Result<Self> {
        let (tx, rx) = mpsc::sync_channel::<Job>(1);
        let thread = thread::Builder::new()
            .name("packed-publish".into())
            .spawn(move || {
                while let Ok(job) = rx.recv() {
                    let started = Instant::now();
                    let mut outcome = Outcome {
                        result: Ok(()),
                        barriers: 0,
                        barrier_ns: 0,
                        phase_ns: [0; 2],
                        elapsed_ns: 0,
                        peak: 0,
                    };
                    let mut durability = super::disk::PublicationStats::default();
                    outcome.result = job.disk.publish(
                        job.slot as u64 * PAGE as u64,
                        &job.header,
                        &mut durability,
                    );
                    outcome.barriers = durability.barriers;
                    outcome.barrier_ns = durability.barrier_ns;
                    outcome.phase_ns = durability.phase_ns;
                    outcome.peak = durability.peak;
                    outcome.elapsed_ns = started.elapsed().as_nanos() as u64;
                    if let Err(error) = &outcome.result {
                        *job.poison.lock().unwrap() = Some(format!("{error:#}"));
                    }
                    let _ = job.done.send(outcome);
                    let _ = job.wake.try_send(());
                }
            })?;
        Ok(Self {
            jobs: Some(tx),
            thread: Some(thread),
        })
    }
    pub fn submit(
        &self,
        disk: Arc<dyn Disk>,
        slot: usize,
        header: [u8; PAGE],
        poison: Arc<Mutex<Option<String>>>,
        wake: mpsc::SyncSender<()>,
    ) -> Result<mpsc::Receiver<Outcome>> {
        let (done, rx) = mpsc::channel();
        self.jobs
            .as_ref()
            .unwrap()
            .send(Job {
                disk,
                slot,
                header,
                poison,
                done,
                wake,
            })
            .context("packed publisher exited")?;
        Ok(rx)
    }
}
impl Drop for Publisher {
    fn drop(&mut self) {
        self.jobs.take();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
