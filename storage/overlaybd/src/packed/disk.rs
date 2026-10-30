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
    fn publish(&self, offset: u64, header: &[u8], stats: &mut PublicationStats) -> Result<()> {
        publish_steps(
            || self.write(offset, header),
            || self.barrier(),
            || self.allocated(),
            stats,
        )
    }
}
pub struct FileDisk {
    reader: File,
    writer: File,
    writing: std::sync::Mutex<()>,
}
impl Drop for FileDisk {
    fn drop(&mut self) {
        // The last engine/view reference owns the lock lifetime. A concurrent
        // fork must not prolong it via a descriptor waiting to be closed at exec.
        unsafe {
            libc::flock(self.reader.as_raw_fd(), libc::LOCK_UN);
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
        // F_NOCACHE is per open-file description. A separate open keeps
        // repeated reads cacheable without deferring bulk writes to publication.
        // A dup would share the flag and defeat this separation on Darwin.
        #[cfg(target_os = "macos")]
        let writer = {
            use std::os::unix::fs::MetadataExt;
            let writer = OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(path)?;
            let (a, b) = (f.metadata()?, writer.metadata()?);
            ensure!(
                a.dev() == b.dev() && a.ino() == b.ino(),
                "packed backing changed while opening writer"
            );
            ensure!(
                unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_NOCACHE, 1) } == 0,
                "packed direct I/O hint: {}",
                std::io::Error::last_os_error()
            );
            writer
        };
        #[cfg(not(target_os = "macos"))]
        let writer = f.try_clone()?;
        ensure!(
            unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "packed backing is already owned: {}",
            std::io::Error::last_os_error()
        );
        if create {
            f.set_len((PAGE * 2) as u64)?;
        }
        Ok(Self {
            reader: f,
            writer,
            writing: std::sync::Mutex::new(()),
        })
    }
}
impl Disk for FileDisk {
    fn read(&self, o: u64, b: &mut [u8]) -> Result<()> {
        self.reader.read_exact_at(b, o)?;
        Ok(())
    }
    fn write(&self, o: u64, b: &[u8]) -> Result<()> {
        let _writing = self.writing.lock().unwrap();
        self.writer.write_all_at(b, o)?;
        Ok(())
    }
    fn barrier(&self) -> Result<()> {
        let _writing = self.writing.lock().unwrap();
        self.full_sync()
    }
    fn publish(&self, offset: u64, header: &[u8], stats: &mut PublicationStats) -> Result<()> {
        // New payload writes must not extend either full-sync phase. Preparation
        // and cached reads remain concurrent; only this file's physical writes wait.
        let _writing = self.writing.lock().unwrap();
        publish_steps(
            || self.writer.write_all_at(header, offset).map_err(Into::into),
            || self.full_sync(),
            || self.allocated(),
            stats,
        )
    }
    fn len(&self) -> Result<u64> {
        Ok(self.reader.metadata()?.len())
    }
    fn punch(&self, o: u64, n: u64) -> Result<()> {
        let _writing = self.writing.lock().unwrap();
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
                unsafe { libc::fcntl(self.reader.as_raw_fd(), 99, &r) } == 0,
                "packed punch: {}",
                std::io::Error::last_os_error()
            );
        }
        #[cfg(target_os = "linux")]
        ensure!(
            unsafe {
                libc::fallocate(
                    self.reader.as_raw_fd(),
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
        Ok(self.reader.metadata()?.blocks() * 512)
    }
}

impl FileDisk {
    fn full_sync(&self) -> Result<()> {
        #[cfg(target_os = "macos")]
        loop {
            if unsafe { libc::fcntl(self.writer.as_raw_fd(), libc::F_FULLFSYNC) } == 0 {
                break;
            }
            let e = std::io::Error::last_os_error();
            if e.kind() != std::io::ErrorKind::Interrupted {
                return Err(e.into());
            }
        }
        #[cfg(not(target_os = "macos"))]
        self.writer.sync_all()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cached_reader_observes_direct_rewrite_and_punch() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let disk = FileDisk::open(&temp.path().join("upper.packed"), true)?;
        let offset = 2 * PAGE as u64;
        let mut read = [0; PAGE];
        disk.write(offset, &[7; PAGE])?;
        disk.read(offset, &mut read)?;
        assert_eq!(read, [7; PAGE]);
        disk.barrier()?;
        disk.punch(offset, PAGE as u64)?;
        disk.read(offset, &mut read)?;
        assert_eq!(read, [0; PAGE]);
        disk.barrier()?;
        disk.write(offset, &[9; PAGE])?;
        disk.read(offset, &mut read)?;
        assert_eq!(read, [9; PAGE]);
        disk.barrier()?;
        Ok(())
    }
    #[test]
    fn closed_owner_does_not_leave_an_inherited_flock() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("upper.packed");
        let owner = FileDisk::open(&path, true)?;
        let inherited = owner.reader.try_clone()?;
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
