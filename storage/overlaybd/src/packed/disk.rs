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
pub trait Disk: Send + Sync {
    fn read(&self, offset: u64, bytes: &mut [u8]) -> Result<()>;
    fn write(&self, offset: u64, bytes: &[u8]) -> Result<()>;
    fn barrier(&self) -> Result<()>;
    fn len(&self) -> Result<u64>;
    fn punch(&self, offset: u64, length: u64) -> Result<()>;
    fn allocated(&self) -> Result<u64>;
}
pub struct FileDisk(File);
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
        Ok(Self(f))
    }
}
impl Disk for FileDisk {
    fn read(&self, o: u64, b: &mut [u8]) -> Result<()> {
        self.0.read_exact_at(b, o)?;
        Ok(())
    }
    fn write(&self, o: u64, b: &[u8]) -> Result<()> {
        self.0.write_all_at(b, o)?;
        Ok(())
    }
    fn barrier(&self) -> Result<()> {
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
    fn len(&self) -> Result<u64> {
        Ok(self.0.metadata()?.len())
    }
    fn punch(&self, o: u64, n: u64) -> Result<()> {
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
}
