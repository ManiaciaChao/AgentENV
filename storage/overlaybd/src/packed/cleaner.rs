//! A bounded maintenance worker. The coordinator reserves every punched page
//! before dispatch and keeps it unavailable until the completion is consumed.
use anyhow::Result;
use std::{sync::mpsc, thread};
type Work = Box<dyn FnOnce() + Send>;
pub(super) struct Cleaner {
    tx: Option<mpsc::SyncSender<Work>>,
    worker: Option<thread::JoinHandle<()>>,
}
impl Cleaner {
    pub fn new() -> Result<Self> {
        let (tx, rx) = mpsc::sync_channel::<Work>(1);
        let worker = thread::Builder::new()
            .name("packed-clean".into())
            .spawn(move || {
                while let Ok(work) = rx.recv() {
                    work();
                }
            })?;
        Ok(Self {
            tx: Some(tx),
            worker: Some(worker),
        })
    }
    pub fn submit(&self, work: impl FnOnce() + Send + 'static) -> Result<()> {
        self.tx
            .as_ref()
            .unwrap()
            .send(Box::new(work))
            .map_err(|_| anyhow::anyhow!("packed cleaner exited"))
    }
}
impl Drop for Cleaner {
    fn drop(&mut self) {
        self.tx.take();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
