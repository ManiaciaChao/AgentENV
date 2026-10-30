//! Experimental VDO-backed Hybrid upper data file.
//!
//! OverlayBD keeps the layer index; VDO owns compression, dedupe and physical
//! allocation underneath that file. Each volume runs in an isolated worker:
//! upstream's current userspace compatibility runtime contains global state.
use crate::virtual_file::VirtualFile;
use anyhow::{bail, ensure, Context, Result};
use async_trait::async_trait;
use bytes::Bytes;
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::unix::{fs::OpenOptionsExt, io::AsRawFd},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    sync::{Arc, Mutex},
};
const MAGIC_V1: &[u8; 8] = b"OBDVDO01";
const MAGIC: &[u8; 8] = b"OBDVDO02";
const MAX_IO: usize = 4 * 1024 * 1024;

pub fn backing_path(path: &Path) -> PathBuf {
    path.with_extension("vdo")
}
/// The marker selects decoding, independently of the current machine's policy.
pub fn capacity(path: &Path) -> Result<Option<u64>> {
    let mut file = File::open(path)?;
    let mut header = [0; 16];
    let n = file.read(&mut header)?;
    if n < 8 || (&header[..8] != MAGIC && &header[..8] != MAGIC_V1) {
        return Ok(None);
    }
    ensure!(n == 16, "truncated VDO marker");
    let value = u64::from_le_bytes(header[8..].try_into().unwrap());
    ensure!(
        value >= 4096 && value % 4096 == 0 && value <= 2u64 << 40,
        "invalid VDO capacity"
    );
    Ok(Some(value))
}
fn worker_path() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("OBD_VDO_WORKER") {
        return Ok(path.into());
    }
    let exe = std::env::current_exe()?;
    let adjacent = exe
        .parent()
        .context("executable directory")?
        .join("obd-vdo-worker");
    if adjacent.is_file() {
        return Ok(adjacent);
    }
    for ancestor in exe.ancestors() {
        if ancestor.extension().is_some_and(|ext| ext == "app") {
            let bundled = ancestor.join("Contents/Helpers/obd-vdo-worker");
            if bundled.is_file() {
                return Ok(bundled);
            }
        }
    }
    bail!("obd-vdo-worker missing; build with scripts/build-vdo.sh or set OBD_VDO_WORKER")
}
struct Worker {
    child: Child,
    input: ChildStdin,
    output: ChildStdout,
    length: u64,
    capacity: u64,
    failed: bool,
}
impl Worker {
    fn nonblocking(fd: std::os::fd::RawFd) -> Result<()> {
        // SAFETY: caller supplies a live owned pipe descriptor.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        ensure!(flags >= 0, "get VDO pipe flags failed");
        ensure!(
            unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } >= 0,
            "set VDO pipe nonblocking failed"
        );
        Ok(())
    }
    fn wait_pipe(fd: std::os::fd::RawFd, events: i16, deadline: std::time::Instant) -> Result<()> {
        loop {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            ensure!(!left.is_zero(), "VDO worker request timed out");
            let ms = left.as_millis().max(1).min(i32::MAX as u128) as i32;
            let mut pollfd = libc::pollfd {
                fd,
                events,
                revents: 0,
            };
            // SAFETY: one valid pollfd and bounded timeout.
            let ready = unsafe { libc::poll(&mut pollfd, 1, ms) };
            if ready < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error.into());
            }
            ensure!(ready > 0, "VDO worker request timed out");
            ensure!(pollfd.revents & libc::POLLNVAL == 0, "invalid VDO pipe");
            // Let read/write report EOF/EPIPE for HUP/ERR, including buffered data.
            return Ok(());
        }
    }
    fn receive(&mut self, deadline: std::time::Instant) -> Result<Vec<u8>> {
        let mut header = [0; 8];
        self.read_exact_timeout(&mut header, deadline)?;
        let status = u32::from_le_bytes(header[..4].try_into().unwrap());
        let len = u32::from_le_bytes(header[4..].try_into().unwrap()) as usize;
        ensure!(status == 0, "VDO worker I/O failed: status {status}");
        ensure!(len <= MAX_IO, "invalid VDO response length");
        let mut data = vec![0; len];
        self.read_exact_timeout(&mut data, deadline)?;
        Ok(data)
    }
    fn read_exact_timeout(
        &mut self,
        mut data: &mut [u8],
        deadline: std::time::Instant,
    ) -> Result<()> {
        while !data.is_empty() {
            Self::wait_pipe(self.output.as_raw_fd(), libc::POLLIN, deadline)?;
            match self.output.read(data) {
                Ok(0) => bail!("VDO worker closed its response pipe"),
                Ok(n) => data = &mut data[n..],
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
                    ) =>
                {
                    continue
                }
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }
    fn write_all_timeout(&mut self, mut data: &[u8], deadline: std::time::Instant) -> Result<()> {
        while !data.is_empty() {
            Self::wait_pipe(self.input.as_raw_fd(), libc::POLLOUT, deadline)?;
            match self.input.write(data) {
                Ok(0) => bail!("VDO worker request pipe closed"),
                Ok(n) => data = &data[n..],
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
                    ) =>
                {
                    continue
                }
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }
    fn start(path: &Path, capacity: u64, create: bool) -> Result<Self> {
        let layout = if create {
            "compact-v2"
        } else {
            let mut marker = [0u8; 8];
            File::open(path)?.read_exact(&mut marker)?;
            if &marker == MAGIC {
                "compact-v2"
            } else if &marker == MAGIC_V1 {
                "legacy-v1"
            } else {
                bail!("invalid VDO marker")
            }
        };
        let mut child = Command::new(worker_path()?)
            .args([if create { "create" } else { "open" }])
            .arg(backing_path(path))
            .arg(capacity.to_string())
            .arg("lz4")
            .arg(layout)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .context("start obd-vdo-worker")?;
        let input = child.stdin.take().unwrap();
        let output = child.stdout.take().unwrap();
        let mut worker = Self {
            child,
            input,
            output,
            length: 0,
            capacity,
            failed: false,
        };
        Self::nonblocking(worker.input.as_raw_fd())?;
        Self::nonblocking(worker.output.as_raw_fd())?;
        let initial =
            worker.receive(std::time::Instant::now() + std::time::Duration::from_secs(120))?;
        ensure!(initial.len() == 8, "invalid VDO handshake");
        worker.length = u64::from_le_bytes(initial.try_into().unwrap());
        ensure!(worker.length <= capacity, "invalid VDO file length");
        Ok(worker)
    }
    fn request(&mut self, op: u32, offset: u64, len: usize, data: &[u8]) -> Result<Vec<u8>> {
        self.request_until(
            op,
            offset,
            len,
            data,
            std::time::Instant::now() + std::time::Duration::from_secs(120),
        )
    }
    fn request_until(
        &mut self,
        op: u32,
        offset: u64,
        len: usize,
        data: &[u8],
        deadline: std::time::Instant,
    ) -> Result<Vec<u8>> {
        ensure!(!self.failed, "VDO worker connection is poisoned");
        ensure!(
            len <= MAX_IO && offset <= self.capacity && len as u64 <= self.capacity - offset,
            "VDO request out of range"
        );
        let result = (|| {
            let mut header = [0u8; 16];
            header[..4].copy_from_slice(&op.to_le_bytes());
            header[4..8].copy_from_slice(&(len as u32).to_le_bytes());
            header[8..].copy_from_slice(&offset.to_le_bytes());
            self.write_all_timeout(&header, deadline)?;
            self.write_all_timeout(data, deadline)?;
            self.receive(deadline)
        })();
        if result.is_err() {
            self.failed = true;
            let _ = self.child.kill();
        }
        result
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        // A destructor must not turn a failed flush into success. Explicit sync
        // owns durability. Killing after sync intentionally exercises recovery.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
/// Counts at the last durable reclamation checkpoint; host_bytes is current.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SpaceUsage {
    pub live_physical_bytes: u64,
    pub host_bytes: u64,
    pub reclaimed_bytes: u64,
    pub checkpoints: u64,
    pub index_extent_bytes: u64,
    pub reclaim_ns: u64,
}
pub struct VdoFile {
    worker: Arc<Mutex<Worker>>,
}
impl VdoFile {
    pub async fn open_async(path: &Path) -> Result<Self> {
        let path = path.to_owned();
        tokio::task::spawn_blocking(move || Self::open(&path)).await?
    }
    pub async fn initialize_async(path: &Path, virtual_size: u64) -> Result<()> {
        let path = path.to_owned();
        tokio::task::spawn_blocking(move || Self::initialize(&path, virtual_size)).await?
    }
    pub fn open(path: &Path) -> Result<Self> {
        let size = capacity(path)?.context("not a VDO data marker")?;
        Ok(Self {
            worker: Arc::new(Mutex::new(Worker::start(path, size, false)?)),
        })
    }
    /// Convert only a fresh header-only Hybrid upper, before publication.
    pub fn initialize(path: &Path, virtual_size: u64) -> Result<()> {
        let initial = std::fs::read(path)?;
        ensure!(
            initial.len() == 4096,
            "VDO initialization requires a fresh header-only upper"
        );
        let size = (virtual_size
            .checked_add(4096)
            .context("capacity overflow")?)
        .div_ceil(4096)
            * 4096;
        let mut worker = Worker::start(path, size, true)?;
        worker.request(2, 0, initial.len(), &initial)?;
        worker.request(3, 0, 0, &[])?;
        worker.request(5, 0, 0, &[])?;
        ensure!(
            worker.child.wait()?.success(),
            "VDO initialization shutdown failed"
        );
        let staging = path.with_extension("vdo-marker-new");
        let mut marker = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&staging)?;
        let mut header = [0u8; 4096];
        header[..8].copy_from_slice(MAGIC);
        header[8..16].copy_from_slice(&size.to_le_bytes());
        marker.write_all(&header)?;
        marker.sync_all()?;
        std::fs::rename(&staging, path)?;
        File::open(path.parent().context("upper parent")?)?.sync_all()?;
        Ok(())
    }
    async fn with<T: Send + 'static>(
        &self,
        f: impl FnOnce(&mut Worker) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let state = self.worker.clone();
        tokio::task::spawn_blocking(move || {
            f(&mut *state
                .lock()
                .map_err(|_| anyhow::anyhow!("VDO lock poisoned"))?)
        })
        .await?
    }
    pub async fn space_usage(&self) -> Result<SpaceUsage> {
        self.with(|w| {
            let data = w.request(7, 0, 0, &[])?;
            ensure!(data.len() == 48, "invalid space statistics");
            let v: Vec<u64> = data
                .chunks_exact(8)
                .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
                .collect();
            Ok(SpaceUsage {
                live_physical_bytes: v[0] * 4096,
                host_bytes: v[1],
                reclaimed_bytes: v[2],
                checkpoints: v[3],
                index_extent_bytes: v[4],
                reclaim_ns: v[5],
            })
        })
        .await
    }
    pub async fn allocated_blocks(&self) -> Result<u64> {
        self.with(|w| {
            let data = w.request(6, 0, 0, &[])?;
            ensure!(data.len() == 8, "invalid statistics");
            Ok(u64::from_le_bytes(data.try_into().unwrap()))
        })
        .await
    }
}
#[async_trait]
impl VirtualFile for VdoFile {
    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }
    async fn read_at(&self, offset: u64, len: usize) -> Result<Bytes> {
        self.with(move |w| {
            let len = len.min(w.length.saturating_sub(offset) as usize);
            if len == 0 {
                return Ok(Bytes::new());
            }
            let data = w.request(1, offset, len, &[])?;
            ensure!(data.len() == len, "short VDO read");
            Ok(Bytes::from(data))
        })
        .await
    }
    async fn write_at(&self, offset: u64, data: &[u8]) -> Result<usize> {
        let data = data.to_vec();
        self.with(move |w| {
            w.request(2, offset, data.len(), &data)?;
            w.length = w.length.max(offset + data.len() as u64);
            Ok(data.len())
        })
        .await
    }
    async fn size(&self) -> Result<u64> {
        self.with(|w| Ok(w.length)).await
    }
    async fn sync(&self) -> Result<()> {
        self.with(|w| {
            w.request(3, 0, 0, &[])?;
            Ok(())
        })
        .await
    }
    async fn discard(&self, offset: u64, len: u64) -> Result<()> {
        self.with(move |w| {
            ensure!(
                offset <= w.length && len <= w.length - offset,
                "discard beyond EOF"
            );
            let mut done = 0;
            while done < len {
                let n = (len - done).min(MAX_IO as u64) as usize;
                w.request(8, offset + done, n, &[])?;
                done += n as u64;
            }
            Ok(())
        })
        .await
    }
    async fn truncate(&self, size: u64) -> Result<()> {
        self.with(move |w| {
            if size < w.length {
                bail!("VDO shrinking is unsupported");
            }
            w.request(4, size, 0, &[])?;
            w.length = size;
            Ok(())
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stalled_send_and_receive_share_request_deadline() {
        for payload in [0, 1024 * 1024] {
            let mut child = Command::new("/bin/sleep")
                .arg("60")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();
            let mut worker = Worker {
                input: child.stdin.take().unwrap(),
                output: child.stdout.take().unwrap(),
                child,
                length: 0,
                capacity: 8 * 1024 * 1024,
                failed: false,
            };
            Worker::nonblocking(worker.input.as_raw_fd()).unwrap();
            Worker::nonblocking(worker.output.as_raw_fd()).unwrap();
            let started = std::time::Instant::now();
            let error = worker
                .request_until(
                    2,
                    0,
                    payload,
                    &vec![1; payload],
                    started + std::time::Duration::from_millis(50),
                )
                .unwrap_err();
            assert!(error.to_string().contains("timed out"), "{error}");
            assert!(started.elapsed() < std::time::Duration::from_secs(2));
            assert!(worker.failed);
            assert!(worker
                .request(3, 0, 0, &[])
                .unwrap_err()
                .to_string()
                .contains("poisoned"));
            assert!(!worker.child.wait().unwrap().success());
        }
    }
}
