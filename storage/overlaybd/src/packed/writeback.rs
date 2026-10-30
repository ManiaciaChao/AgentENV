//! Ordered payload/metadata writes, bounded to four outstanding 1 MiB buffers.
//! A generation must drain this queue before exposing its root or publishing it.
use super::disk::Disk;
use anyhow::{Context, Result};
use std::{
    sync::{Arc, Mutex},
    thread,
    time::Instant,
};

struct Job {
    offset: u64,
    bytes: Vec<u8>,
    metadata: bool,
}
struct Done {
    bytes: Vec<u8>,
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
    tx: Option<crossbeam_channel::Sender<Job>>,
    done: crossbeam_channel::Receiver<Done>,
    pending: usize,
    spare: Vec<Vec<u8>>,
    timings: Timings,
    thread: Option<thread::JoinHandle<()>>,
}
impl Writer {
    pub fn new(disk: Arc<dyn Disk>, poison: Arc<Mutex<Option<String>>>) -> Result<Self> {
        let (tx, rx) = crossbeam_channel::bounded::<Job>(4);
        let (completed, done) = crossbeam_channel::bounded(4);
        let thread = thread::Builder::new()
            .name("packed-data".into())
            .spawn(move || {
                while let Ok(job) = rx.recv() {
                    let started = Instant::now();
                    let result = disk.write(job.offset, &job.bytes);
                    let ns = started.elapsed().as_nanos() as u64;
                    if let Err(error) = &result {
                        *poison.lock().unwrap() = Some(format!("{error:#}"));
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
            spare: Vec::new(),
            timings: Timings::default(),
            thread: Some(thread),
        })
    }
    fn reap(&mut self) -> Result<()> {
        let started = Instant::now();
        let mut done = self.done.recv().context("packed data writer exited")?;
        self.timings.wait_ns += started.elapsed().as_nanos() as u64;
        self.pending -= 1;
        if done.metadata {
            self.timings.metadata_ns += done.ns;
        } else {
            self.timings.data_ns += done.ns;
        }
        done.bytes.clear();
        self.spare.push(done.bytes);
        done.result
    }
    pub fn submit(&mut self, offset: u64, bytes: Vec<u8>, metadata: bool) -> Result<Vec<u8>> {
        anyhow::ensure!(
            bytes.len() <= 1024 * 1024,
            "packed write buffer exceeds limit"
        );
        if self.pending == 4 {
            self.reap()?;
        }
        self.tx
            .as_ref()
            .unwrap()
            .send(Job {
                offset,
                bytes,
                metadata,
            })
            .context("packed data writer exited")?;
        self.pending += 1;
        Ok(self
            .spare
            .pop()
            .unwrap_or_else(|| Vec::with_capacity(1024 * 1024)))
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
        let mut writer = Writer::new(disk.clone(), Arc::new(Mutex::new(None)))?;
        let release = Release(release);
        for offset in 0..4 {
            writer.submit(offset, vec![7; 4096], false)?;
        }
        ready.recv_timeout(std::time::Duration::from_secs(5))?;
        assert_eq!(writer.pending, 4);
        let (tx, rx) = mpsc::channel();
        let join = std::thread::spawn(move || -> Result<()> {
            writer.submit(4, vec![8; 4096], true)?;
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
        assert_eq!(*disk.writes.lock().unwrap(), vec![0, 1, 2, 3, 4]);
        Ok(())
    }
}
