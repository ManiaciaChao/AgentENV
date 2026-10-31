//! Positional storage boundary. Tests replace this with a reorderable volatile disk.
use anyhow::{ensure, Result};
use std::{
    fs::{File, OpenOptions},
    os::unix::{
        fs::{FileExt, OpenOptionsExt},
        io::AsRawFd,
    },
    path::Path,
};
pub const PAGE: usize = 4096;
#[cfg(any(target_os = "macos", test))]
const CACHED_DIRTY_BYTES: usize = 4 * 1024 * 1024;

// Keep clean pages available to random reads, but move dirty payload writeback
// into the ordered writer rather than accumulating it until root publication.
// This is not a durability acknowledgement: publication still has two barriers.
#[cfg(any(target_os = "macos", test))]
fn write_cached(
    mut offset: u64,
    mut bytes: &[u8],
    dirty: &mut usize,
    mut write: impl FnMut(u64, &[u8]) -> Result<()>,
    mut writeback: impl FnMut() -> Result<()>,
) -> Result<()> {
    while !bytes.is_empty() {
        if *dirty == CACHED_DIRTY_BYTES {
            writeback()?;
            *dirty = 0;
        }
        let take = bytes.len().min(CACHED_DIRTY_BYTES - *dirty);
        write(offset, &bytes[..take])?;
        *dirty += take;
        offset += take as u64;
        bytes = &bytes[take..];
    }
    if *dirty == CACHED_DIRTY_BYTES {
        writeback()?;
        *dirty = 0;
    }
    Ok(())
}
#[derive(Default)]
pub struct PublicationStats {
    pub barriers: u64,
    pub barrier_ns: u64,
    pub phase_ns: [u64; 2],
    pub peak: u64,
}
fn publish_steps(
    mut header: impl FnMut() -> Result<()>,
    mut barrier: impl FnMut() -> Result<()>,
    mut allocated: impl FnMut() -> Result<u64>,
    stats: &mut PublicationStats,
) -> Result<()> {
    for phase in 0..2 {
        stats.peak = stats.peak.max(allocated()?);
        let started = std::time::Instant::now();
        let result = barrier();
        stats.barriers += 1;
        let elapsed = started.elapsed().as_nanos() as u64;
        stats.barrier_ns += elapsed;
        stats.phase_ns[phase] += elapsed;
        result?;
        if phase == 0 {
            header()?;
        }
    }
    Ok(())
}
pub trait Disk: Send + Sync {
    fn read(&self, offset: u64, bytes: &mut [u8]) -> Result<()>;
    fn write(&self, offset: u64, bytes: &[u8]) -> Result<()>;
    fn barrier(&self) -> Result<()>;
    fn len(&self) -> Result<u64>;
    fn punch(&self, offset: u64, length: u64) -> Result<()>;
    fn allocated(&self) -> Result<u64>;
    fn writeback_statistics(&self) -> (u64, u64) {
        (0, 0)
    }
    fn publish(&self, offset: u64, header: &[u8], stats: &mut PublicationStats) -> Result<()> {
        publish_steps(
            || self.write(offset, header),
            || self.barrier(),
            || self.allocated(),
            stats,
        )
    }
}
pub struct FileDisk(
    File,
    std::sync::Mutex<usize>,
    std::sync::atomic::AtomicU64,
    std::sync::atomic::AtomicU64,
);
impl Drop for FileDisk {
    fn drop(&mut self) {
        // The last engine/view reference owns the lock lifetime. A concurrent
        // fork must not prolong it via a descriptor waiting to be closed at exec.
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}
impl FileDisk {
    pub fn open(path: &Path, create: bool) -> Result<Self> {
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(create)
            .custom_flags(libc::O_NOFOLLOW)
            .mode(0o600)
            .open(path)?;
        ensure!(
            f.metadata()?.is_file(),
            "packed backing must be a regular file"
        );
        ensure!(
            unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "packed backing is already owned: {}",
            std::io::Error::last_os_error()
        );
        if create {
            f.set_len((PAGE * 2) as u64)?;
        }
        Ok(Self(f, std::sync::Mutex::new(0), 0.into(), 0.into()))
    }
}
impl Disk for FileDisk {
    fn read(&self, o: u64, b: &mut [u8]) -> Result<()> {
        self.0.read_exact_at(b, o)?;
        Ok(())
    }
    fn write(&self, o: u64, b: &[u8]) -> Result<()> {
        let mut dirty = self.1.lock().unwrap();
        #[cfg(target_os = "macos")]
        return write_cached(
            o,
            b,
            &mut dirty,
            |offset, bytes| self.0.write_all_at(bytes, offset).map_err(Into::into),
            || self.writeback(),
        );
        #[cfg(not(target_os = "macos"))]
        {
            let _ = &mut dirty;
            self.0.write_all_at(b, o)?;
            Ok(())
        }
    }
    fn barrier(&self) -> Result<()> {
        let mut dirty = self.1.lock().unwrap();
        self.full_sync()?;
        *dirty = 0;
        Ok(())
    }
    fn publish(&self, offset: u64, header: &[u8], stats: &mut PublicationStats) -> Result<()> {
        // New payload writes must not extend either full-sync phase. Preparation
        // and cached reads remain concurrent; only this file's physical writes wait.
        let mut dirty = self.1.lock().unwrap();
        publish_steps(
            || self.0.write_all_at(header, offset).map_err(Into::into),
            || {
                self.full_sync()?;
                *dirty = 0;
                Ok(())
            },
            || self.allocated(),
            stats,
        )
    }
    fn len(&self) -> Result<u64> {
        Ok(self.0.metadata()?.len())
    }
    fn punch(&self, o: u64, n: u64) -> Result<()> {
        let _writing = self.1.lock().unwrap();
        #[cfg(target_os = "macos")]
        {
            #[repr(C)]
            struct Range {
                flags: u32,
                reserved: u32,
                offset: i64,
                length: i64,
            }
            let r = Range {
                flags: 0,
                reserved: 0,
                offset: o as i64,
                length: n as i64,
            };
            ensure!(
                unsafe { libc::fcntl(self.0.as_raw_fd(), 99, &r) } == 0,
                "packed punch: {}",
                std::io::Error::last_os_error()
            );
        }
        #[cfg(target_os = "linux")]
        ensure!(
            unsafe {
                libc::fallocate(
                    self.0.as_raw_fd(),
                    libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
                    o as i64,
                    n as i64,
                )
            } == 0,
            "packed punch: {}",
            std::io::Error::last_os_error()
        );
        Ok(())
    }
    fn allocated(&self) -> Result<u64> {
        use std::os::unix::fs::MetadataExt;
        Ok(self.0.metadata()?.blocks() * 512)
    }
    fn writeback_statistics(&self) -> (u64, u64) {
        use std::sync::atomic::Ordering::Relaxed;
        (self.2.load(Relaxed), self.3.load(Relaxed))
    }
}

impl FileDisk {
    #[cfg(target_os = "macos")]
    fn writeback(&self) -> Result<()> {
        use std::sync::atomic::Ordering::Relaxed;
        let started = std::time::Instant::now();
        self.2.fetch_add(1, Relaxed);
        let result = loop {
            if unsafe { libc::fsync(self.0.as_raw_fd()) } == 0 {
                break Ok(());
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                break Err(error.into());
            }
        };
        self.3
            .fetch_add(started.elapsed().as_nanos() as u64, Relaxed);
        result
    }
    fn full_sync(&self) -> Result<()> {
        #[cfg(target_os = "macos")]
        loop {
            if unsafe { libc::fcntl(self.0.as_raw_fd(), libc::F_FULLFSYNC) } == 0 {
                break;
            }
            let e = std::io::Error::last_os_error();
            if e.kind() != std::io::ErrorKind::Interrupted {
                return Err(e.into());
            }
        }
        #[cfg(not(target_os = "macos"))]
        self.0.sync_all()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cached_writeback_bounds_dirty_data_and_keeps_order() -> Result<()> {
        let events = std::cell::RefCell::new(Vec::new());
        let payload = vec![7; CACHED_DIRTY_BYTES * 2 + PAGE];
        let mut dirty = PAGE;
        write_cached(
            8192,
            &payload,
            &mut dirty,
            |offset, bytes| {
                assert!(bytes.iter().all(|b| *b == 7));
                events.borrow_mut().push((offset, bytes.len()));
                Ok(())
            },
            || {
                events.borrow_mut().push((0, 0));
                Ok(())
            },
        )?;
        assert_eq!(dirty, 2 * PAGE);
        assert_eq!(
            events.into_inner(),
            vec![
                (8192, CACHED_DIRTY_BYTES - PAGE),
                (0, 0),
                (
                    8192 + (CACHED_DIRTY_BYTES - PAGE) as u64,
                    CACHED_DIRTY_BYTES
                ),
                (0, 0),
                (8192 + (2 * CACHED_DIRTY_BYTES - PAGE) as u64, 2 * PAGE),
            ]
        );
        Ok(())
    }

    #[test]
    fn failed_cached_writeback_does_not_accept_the_next_chunk() {
        let written = std::cell::Cell::new(0);
        let mut dirty = 0;
        let payload = vec![3; CACHED_DIRTY_BYTES + PAGE];
        let result = write_cached(
            0,
            &payload,
            &mut dirty,
            |_, bytes| {
                written.set(written.get() + bytes.len());
                Ok(())
            },
            || anyhow::bail!("injected writeback I/O error"),
        );
        assert!(result.is_err());
        assert_eq!(written.get(), CACHED_DIRTY_BYTES);
        assert_eq!(dirty, CACHED_DIRTY_BYTES);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn cached_file_writeback_does_not_replace_publication_barriers() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("upper.packed");
        let disk = FileDisk::open(&path, true)?;
        let payload = vec![5; CACHED_DIRTY_BYTES + PAGE];
        disk.write((PAGE * 2) as u64, &payload)?;
        assert_eq!(disk.writeback_statistics().0, 1);
        let mut read = vec![0; payload.len()];
        disk.read((PAGE * 2) as u64, &mut read)?;
        assert_eq!(read, payload);
        let mut stats = PublicationStats::default();
        disk.publish(0, &[9; PAGE], &mut stats)?;
        assert_eq!(stats.barriers, 2);
        assert_eq!(*disk.1.lock().unwrap(), 0);
        disk.punch((PAGE * 2) as u64, PAGE as u64)?;
        disk.barrier()?;
        let mut zero = [1; PAGE];
        disk.read((PAGE * 2) as u64, &mut zero)?;
        assert_eq!(zero, [0; PAGE]);
        disk.write((PAGE * 2) as u64, &[8; PAGE])?;
        disk.read((PAGE * 2) as u64, &mut zero)?;
        assert_eq!(zero, [8; PAGE]);
        Ok(())
    }

    #[test]
    fn closed_owner_does_not_leave_an_inherited_flock() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("upper.packed");
        let owner = FileDisk::open(&path, true)?;
        let inherited = owner.0.try_clone()?;
        assert!(FileDisk::open(&path, false).is_err());
        drop(owner);
        let next = FileDisk::open(&path, false)?;
        drop(inherited);
        assert!(FileDisk::open(&path, false).is_err());
        drop(next);
        FileDisk::open(&path, false)?;
        Ok(())
    }
}
