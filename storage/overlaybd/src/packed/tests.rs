use super::{
    core::Core,
    disk::{Disk, PAGE},
    Codec, Policy,
};
use anyhow::{bail, Context, Result};
use std::sync::{Arc, Mutex};

// Writes reach the volatile view immediately. A barrier makes them durable.
// At a crash, arbitrary pending writes can reach stable storage in reverse order,
// with the last persisted write optionally torn. This is not a process-kill model.
#[derive(Clone, Default)]
struct State {
    volatile: Vec<u8>,
    stable: Vec<u8>,
    writes: Vec<(usize, Vec<u8>)>,
    ops: usize,
    fail: Option<usize>,
    short_write: bool,
    errno: i32,
}
#[derive(Default)]
struct Model(Mutex<State>);
fn put(dst: &mut Vec<u8>, at: usize, bytes: &[u8]) {
    dst.resize(dst.len().max(at + bytes.len()), 0);
    dst[at..at + bytes.len()].copy_from_slice(bytes);
}
impl Model {
    fn from(s: State) -> Arc<Self> {
        Arc::new(Self(Mutex::new(s)))
    }
    fn cut(&self, persist_mask: u64, torn: bool) {
        let mut s = self.0.lock().unwrap();
        let writes = std::mem::take(&mut s.writes);
        for (i, (o, b)) in writes.iter().enumerate().rev() {
            if persist_mask & (1u64 << (i % 64)) != 0 {
                let n = if torn { b.len() / 2 } else { b.len() };
                put(&mut s.stable, *o, &b[..n]);
            }
        }
        s.volatile = s.stable.clone();
        s.fail = None;
    }
    fn step(s: &mut State) -> Result<()> {
        s.ops += 1;
        if s.fail == Some(s.ops) {
            return Err(std::io::Error::from_raw_os_error(if s.errno == 0 {
                libc::EIO
            } else {
                s.errno
            })
            .into());
        }
        Ok(())
    }
}
impl Disk for Model {
    fn read(&self, o: u64, b: &mut [u8]) -> Result<()> {
        let s = self.0.lock().unwrap();
        let o = o as usize;
        if o + b.len() > s.volatile.len() {
            bail!("short read");
        }
        b.copy_from_slice(&s.volatile[o..o + b.len()]);
        Ok(())
    }
    fn write(&self, o: u64, b: &[u8]) -> Result<()> {
        let mut s = self.0.lock().unwrap();
        if let Err(error) = Self::step(&mut s) {
            if s.short_write {
                let n = b.len() / 2;
                put(&mut s.volatile, o as usize, &b[..n]);
                s.writes.push((o as usize, b[..n].to_vec()));
            }
            return Err(error);
        }
        put(&mut s.volatile, o as usize, b);
        s.writes.push((o as usize, b.to_vec()));
        Ok(())
    }
    fn barrier(&self) -> Result<()> {
        let mut s = self.0.lock().unwrap();
        Self::step(&mut s)?;
        s.stable = s.volatile.clone();
        s.writes.clear();
        Ok(())
    }
    fn len(&self) -> Result<u64> {
        Ok(self.0.lock().unwrap().volatile.len() as u64)
    }
    fn punch(&self, o: u64, n: u64) -> Result<()> {
        self.write(o, &vec![0; n as usize])
    }
    fn allocated(&self) -> Result<u64> {
        self.len()
    }
}
fn policy(codec: Codec, dedupe: bool) -> Policy {
    Policy {
        compression: codec,
        dedupe,
    }
}
#[test]
fn policy_changes_preserve_mixed_objects_and_zero_masks() -> Result<()> {
    let d = Arc::new(Model::default());
    let mut c = Core::create(d.clone(), PAGE as u64 * 128, Policy::default())?;
    assert!(c.read_block(0)?.is_none());
    for (i, codec) in [Codec::Lz4, Codec::None, Codec::Zstd]
        .into_iter()
        .enumerate()
    {
        c.set_policy(policy(codec, true))?;
        c.stage(i as u64, Box::new([i as u8 + 1; PAGE]))?;
        c.stage(i as u64 + 8, Box::new([i as u8 + 1; PAGE]))?;
        c.commit()?;
    }
    assert_eq!(c.stats()?.dedupe_hits, 3);
    c.set_policy(policy(Codec::None, false))?;
    c.stage(8, Box::new([0; PAGE]))?;
    c.commit()?;
    drop(c);
    d.cut(0, false);
    let c = Core::open(d, Policy::default())?;
    for i in 0..3 {
        assert_eq!(c.read_block(i)?.unwrap().as_slice(), &[i as u8 + 1; PAGE]);
    }
    assert_eq!(c.read_block(8)?.unwrap().as_slice(), &[0; PAGE]);
    assert!(c.read_block(100)?.is_none());
    let mut batched = vec![99; 32 * PAGE];
    assert_eq!(c.view().read_blocks(0, 0, &mut batched)?, 0x707);
    for i in 0..32 {
        let value = match i {
            0..=2 => i as u8 + 1,
            8 => 0,
            9..=10 => i as u8 - 7,
            _ => 99,
        };
        assert!(batched[i * PAGE..(i + 1) * PAGE]
            .iter()
            .all(|b| *b == value));
    }
    Ok(())
}
#[test]
fn crash_at_every_commit_boundary_preserves_acknowledged_generation() -> Result<()> {
    let d = Arc::new(Model::default());
    let mut c = Core::create(d.clone(), PAGE as u64 * 16, Policy::default())?;
    c.stage(0, Box::new([1; PAGE]))?;
    c.commit()?;
    let initial = d.0.lock().unwrap().clone();
    let probe = Model::from(initial.clone());
    let mut c = Core::open(probe.clone(), Policy::default())?;
    c.stage(0, Box::new([2; PAGE]))?;
    c.stage(1, Box::new([3; PAGE]))?;
    c.commit()?;
    let count = probe.0.lock().unwrap().ops - initial.ops;
    for fail in 1..=count + 1 {
        for mask in [0, u64::MAX, 0x5555555555555555, 0xaaaaaaaaaaaaaaaa] {
            for torn in [false, true] {
                let d = Model::from(initial.clone());
                d.0.lock().unwrap().fail = Some(initial.ops + fail);
                let mut c = Core::open(d.clone(), Policy::default())?;
                c.stage(0, Box::new([2; PAGE]))?;
                c.stage(1, Box::new([3; PAGE]))?;
                let acknowledged = c.commit().is_ok();
                if !acknowledged {
                    assert!(c.stage(2, Box::new([9; PAGE])).is_err());
                }
                drop(c);
                d.cut(mask, torn);
                let recovered = Core::open(d, Policy::default())?;
                let b = recovered.read_block(0)?.unwrap();
                assert!(b[0] == 1 || b[0] == 2, "invalid value, cut {fail}");
                if acknowledged {
                    assert_eq!(b[0], 2);
                }
                if b[0] == 2 {
                    assert_eq!(recovered.read_block(1)?.unwrap()[0], 3);
                } else {
                    assert!(recovered.read_block(1)?.is_none());
                }
            }
        }
    }
    Ok(())
}
#[test]
fn corrupt_published_metadata_never_falls_back() -> Result<()> {
    let d = Arc::new(Model::default());
    let mut c = Core::create(d.clone(), PAGE as u64 * 16, Policy::default())?;
    c.stage(0, Box::new([1; PAGE]))?;
    c.commit()?;
    let mut s = d.0.lock().unwrap();
    let root = super::tree::get64(&s.volatile[PAGE..PAGE * 2], 40) as usize * PAGE;
    s.volatile[root + 100] ^= 1;
    drop(s);
    assert!(Core::open(d, Policy::default()).is_err());
    Ok(())
}
#[test]
fn overwrite_reuse_and_cleaner_preserve_every_live_byte() -> Result<()> {
    let d = Arc::new(Model::default());
    let mut c = Core::create(d.clone(), PAGE as u64 * 128, Policy::default())?;
    for generation in 1..=20 {
        for lba in 0..128 {
            c.stage(lba, Box::new([((lba + generation) % 255 + 1) as u8; PAGE]))?;
        }
        c.commit()?;
        c.maintenance()?;
        drop(c);
        d.cut(0, false);
        c = Core::open(d.clone(), Policy::default())?;
        for lba in 0..128 {
            assert_eq!(
                c.read_block(lba)?.unwrap().as_slice(),
                &[((lba + generation) % 255 + 1) as u8; PAGE]
            );
        }
    }
    assert!(d.len()? < 2 * 1024 * 1024, "unbounded growth: {}", d.len()?);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lower_rmw_discard_and_standard_export_interoperate() -> Result<()> {
    use super::PackedUpper;
    use crate::{
        backend::local::LocalFile,
        io::virtual_file::VirtualFile,
        lsmt::file::{CommitArgs, LSMTReadOnlyFile},
    };
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("lower.packed");
    let size = PAGE * 32;
    PackedUpper::create(&path, size as u64, Policy::default())?;
    let lower = PackedUpper::open(&path, None, Policy::default()).await?;
    lower.write_at(0, &vec![7; size]).await?;
    let sealed = Arc::new(LocalFile::new(dir.path().join("lower.sealed"))?);
    lower
        .export_upper_as_sealed(CommitArgs::new(sealed.clone()))
        .await?;
    sealed.sync().await?;
    let lower = Arc::new(LSMTReadOnlyFile::open(sealed).await?);
    let upperpath = dir.path().join("upper.packed");
    PackedUpper::create(&upperpath, size as u64, Policy::default())?;
    let upper = PackedUpper::open(&upperpath, Some(lower), Policy::default()).await?;
    let mut reference = vec![7; size];
    let mut seed = 32u64;
    for i in 0..120 {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        let offset = (seed as usize) % (size - 8192);
        let len = (seed.rotate_left(19) as usize) % 8192 + 1;
        if i % 3 == 0 {
            upper.discard(offset as u64, len as u64).await?;
            reference[offset..offset + len].fill(0);
        } else {
            let bytes = vec![i as u8; len];
            upper.write_at(offset as u64, &bytes).await?;
            reference[offset..offset + len].copy_from_slice(&bytes);
        }
        if i % 10 == 0 {
            upper.sync().await?;
            assert_eq!(upper.read_at(0, size).await?.as_ref(), reference);
        }
    }
    upper.sync().await?;
    // Applying the exported upper through the existing LSMT stack must retain
    // both untouched lower bytes and explicit zero mappings.
    let output = Arc::new(LocalFile::new(dir.path().join("upper.sealed"))?);
    upper
        .export_upper_as_sealed(CommitArgs::new(output.clone()))
        .await?;
    output.sync().await?;
    let bottom: Arc<dyn VirtualFile> =
        Arc::new(LocalFile::open_ro(dir.path().join("lower.sealed"))?);
    let top: Arc<dyn VirtualFile> = output;
    let merged = crate::lsmt::file::open_files_ro(&[bottom, top]).await?;
    assert_eq!(merged.read_at(0, size).await?.as_ref(), reference);
    Ok(())
}

#[test]
fn corrupt_data_poison_prevents_further_acknowledgements() -> Result<()> {
    let disk = Arc::new(Model::default());
    let mut core = Core::create(disk.clone(), PAGE as u64 * 16, policy(Codec::None, false))?;
    core.stage(0, Box::new([9; PAGE]))?;
    core.commit()?;
    // First allocated data page is page 2; both headers remain checksum-valid.
    disk.0.lock().unwrap().volatile[PAGE * 2 + 31] ^= 1;
    let mut recovered = Core::open(disk, Policy::default())?;
    assert!(recovered.read_block(0).is_err());
    assert!(recovered.stage(1, Box::new([2; PAGE])).is_err());
    assert!(recovered.commit().is_err());
    Ok(())
}

#[test]
fn short_write_and_enospc_at_each_operation_keep_old_root_readable() -> Result<()> {
    let disk = Arc::new(Model::default());
    let mut core = Core::create(disk.clone(), PAGE as u64 * 16, Policy::default())?;
    core.stage(0, Box::new([8; PAGE]))?;
    core.commit()?;
    let initial = disk.0.lock().unwrap().clone();
    let probe = Model::from(initial.clone());
    let mut core = Core::open(probe.clone(), Policy::default())?;
    core.stage(0, Box::new([3; PAGE]))?;
    core.commit()?;
    let operations = probe.0.lock().unwrap().ops - initial.ops;
    for errno in [libc::EIO, libc::ENOSPC] {
        for cut in 1..=operations {
            let disk = Model::from(initial.clone());
            {
                let mut s = disk.0.lock().unwrap();
                s.fail = Some(initial.ops + cut);
                s.errno = errno;
                s.short_write = true;
            }
            let mut core = Core::open(disk.clone(), Policy::default())?;
            core.stage(0, Box::new([3; PAGE]))?;
            assert!(core.commit().is_err());
            assert!(core.commit().is_err());
            drop(core);
            disk.cut(u64::MAX, false);
            let core = Core::open(disk, Policy::default())?;
            let value = core.read_block(0)?.unwrap();
            assert!(value.iter().all(|b| *b == 8) || value.iter().all(|b| *b == 3));
        }
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_partial_writes_do_not_lose_neighbour_sectors() -> Result<()> {
    use super::PackedUpper;
    use crate::io::virtual_file::VirtualFile;
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("upper.packed");
    PackedUpper::create(&path, 8192, Policy::default())?;
    let upper = PackedUpper::open(&path, None, Policy::default()).await?;
    let mut jobs = Vec::new();
    for sector in 0..8 {
        let upper = upper.clone();
        jobs.push(tokio::spawn(async move {
            for _ in 0..30 {
                upper
                    .write_at(sector * 512, &[sector as u8 + 1; 512])
                    .await?;
                tokio::task::yield_now().await;
            }
            anyhow::Ok(())
        }));
    }
    for job in jobs {
        job.await??;
    }
    upper.sync().await?;
    drop(upper);
    let upper = PackedUpper::open(&path, None, Policy::default()).await?;
    for sector in 0..8 {
        assert_eq!(
            upper.read_at(sector * 512, 512).await?.as_ref(),
            &[sector as u8 + 1; 512]
        );
    }
    Ok(())
}

#[test]
fn real_file_overwrite_space_stabilizes_without_hiding_flush_allocation() -> Result<()> {
    use super::disk::FileDisk;
    struct Measured {
        disk: FileDisk,
        peak: Mutex<u64>,
    }
    impl Measured {
        fn sample(&self) -> Result<()> {
            let bytes = self.disk.allocated()?;
            let mut peak = self.peak.lock().unwrap();
            *peak = (*peak).max(bytes);
            Ok(())
        }
    }
    impl Disk for Measured {
        fn read(&self, o: u64, b: &mut [u8]) -> Result<()> {
            self.disk.read(o, b)
        }
        fn write(&self, o: u64, b: &[u8]) -> Result<()> {
            self.disk.write(o, b)?;
            self.sample()
        }
        fn barrier(&self) -> Result<()> {
            self.disk.barrier()
        }
        fn len(&self) -> Result<u64> {
            self.disk.len()
        }
        fn punch(&self, o: u64, n: u64) -> Result<()> {
            self.disk.punch(o, n)?;
            self.sample()
        }
        fn allocated(&self) -> Result<u64> {
            self.disk.allocated()
        }
    }
    let dir = tempfile::tempdir()?;
    let mut results = Vec::new();
    for codec in [Codec::None, Codec::Lz4, Codec::Zstd] {
        let disk = Arc::new(Measured {
            disk: FileDisk::open(&dir.path().join(format!("{codec:?}.packed")), true)?,
            peak: Mutex::new(0),
        });
        let mut core = Core::create(disk.clone(), PAGE as u64 * 128, policy(codec, false))?;
        let mut samples = Vec::new();
        for generation in 0u64..=20 {
            for lba in 0..128 {
                let mut block = Box::new([0; PAGE]);
                // Unique per block and generation, with compressible source-like content.
                let source = include_bytes!("file.rs");
                for (i, b) in block.iter_mut().enumerate() {
                    *b = source[(i + lba as usize * 17) % source.len()];
                }
                block[..8].copy_from_slice(&(generation * 128 + lba).to_le_bytes());
                core.stage(lba, block)?;
            }
            core.commit()?;
            let immediate = disk.allocated()?;
            core.maintenance()?;
            let settled = disk.allocated()?;
            drop(core);
            core = Core::open(disk.clone(), policy(codec, false))?;
            for lba in 0..128 {
                let block = core.read_block(lba)?.unwrap();
                assert_eq!(&block[..8], &(generation * 128 + lba).to_le_bytes());
                let source = include_bytes!("file.rs");
                for i in 8..PAGE {
                    assert_eq!(block[i], source[(i + lba as usize * 17) % source.len()]);
                }
            }
            samples.push((immediate, settled));
        }
        let peak = *disk.peak.lock().unwrap();
        eprintln!(
            "packed storage-only space {codec:?}: initial={:?}, overwrite20={:?}, peak={peak}",
            samples[0], samples[20]
        );
        assert!(
            samples[20].1 < samples[1].1 + 2 * 1024 * 1024,
            "space grew without bound"
        );
        results.push(samples[20].1);
    }
    // This is a storage-unit regression, not the required raw OverlayBD/FSKit acceptance.
    assert!(results[1] < results[0]);
    assert!(results[2] < results[0]);
    Ok(())
}

#[test]
fn fragmented_segment_relocation_preserves_cross_page_objects() -> Result<()> {
    let disk = Arc::new(Model::default());
    let count = 4096u64;
    let mut core = Core::create(disk.clone(), count * PAGE as u64, policy(Codec::Lz4, false))?;
    let source = include_bytes!("file.rs");
    for lba in 0..count {
        let mut block = Box::new([0; PAGE]);
        for (i, b) in block.iter_mut().enumerate() {
            *b = source[(i + lba as usize * 17) % source.len()];
        }
        block[..8].copy_from_slice(&lba.to_le_bytes());
        core.stage(lba, block)?;
    }
    core.commit()?;
    // Leave scattered live extents in densely packed segments.
    for lba in 0..count {
        if lba % 4 != 0 {
            core.stage(lba, Box::new([0; PAGE]))?;
        }
    }
    core.commit()?;
    let before = core.stats()?.generations;
    core.maintenance()?;
    assert!(
        core.stats()?.generations >= before + 2,
        "cleaner did not relocate a victim"
    );
    // Background work must converge. Low occupancy alone is not evidence
    // that moving a segment can free another physical page.
    for _ in 0..32 {
        core.maintenance()?;
    }
    let settled = core.stats()?;
    for _ in 0..8 {
        core.maintenance()?;
    }
    assert_eq!(core.stats()?.generations, settled.generations);
    assert_eq!(
        core.stats()?.cleaner_relocations,
        settled.cleaner_relocations
    );
    drop(core);
    disk.cut(0, false);
    let core = Core::open(disk, Policy::default())?;
    for lba in 0..count {
        let block = core.read_block(lba)?.unwrap();
        if lba % 4 != 0 {
            assert!(block.iter().all(|b| *b == 0));
        } else {
            assert_eq!(&block[..8], &lba.to_le_bytes());
            for i in 8..PAGE {
                assert_eq!(block[i], source[(i + lba as usize * 17) % source.len()]);
            }
        }
    }
    Ok(())
}

#[test]
fn pinned_read_version_survives_root_rotation_and_cleaner() -> Result<()> {
    let disk = Arc::new(Model::default());
    let mut core = Core::create(disk, 16 * PAGE as u64, Policy::default())?;
    core.stage(0, Box::new([17; PAGE]))?;
    core.commit()?;
    let pinned = core.view();
    for i in 1..=20 {
        core.stage(0, Box::new([i; PAGE]))?;
        core.commit()?;
        core.maintenance()?;
        assert_eq!(pinned.read(0)?.unwrap().as_slice(), &[17; PAGE]);
        assert_eq!(core.read_block(0)?.unwrap().as_slice(), &[i; PAGE]);
    }
    drop(pinned);
    core.maintenance()?;
    assert_eq!(core.read_block(0)?.unwrap().as_slice(), &[20; PAGE]);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn slow_durable_barrier_does_not_hold_foreground_io_lock() -> Result<()> {
    use super::PackedUpper;
    use crate::io::virtual_file::VirtualFile;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Condvar,
    };
    struct Slow {
        disk: Model,
        hold: AtomicBool,
        entered: tokio::sync::Notify,
        released: Mutex<bool>,
        ready: Condvar,
    }
    impl Disk for Slow {
        fn read(&self, o: u64, b: &mut [u8]) -> Result<()> {
            self.disk.read(o, b)
        }
        fn write(&self, o: u64, b: &[u8]) -> Result<()> {
            self.disk.write(o, b)
        }
        fn len(&self) -> Result<u64> {
            self.disk.len()
        }
        fn allocated(&self) -> Result<u64> {
            self.disk.allocated()
        }
        fn punch(&self, o: u64, n: u64) -> Result<()> {
            self.disk.punch(o, n)
        }
        fn barrier(&self) -> Result<()> {
            if self.hold.swap(false, Ordering::AcqRel) {
                self.entered.notify_one();
                let mut released = self.released.lock().unwrap();
                while !*released {
                    released = self.ready.wait(released).unwrap();
                }
            }
            self.disk.barrier()
        }
    }
    let disk = Arc::new(Slow {
        disk: Model::default(),
        hold: AtomicBool::new(false),
        entered: tokio::sync::Notify::new(),
        released: Mutex::new(false),
        ready: Condvar::new(),
    });
    let core = Core::create(
        disk.clone(),
        (super::core::DIRTY_LIMIT * 3) as u64,
        Policy::default(),
    )?;
    let upper = PackedUpper::from_core(core)?;
    upper.write_at(0, &[7; PAGE]).await?;
    disk.hold.store(true, Ordering::Release);
    let flushing = {
        let upper = upper.clone();
        tokio::spawn(async move { upper.sync().await })
    };
    disk.entered.notified().await;
    let progress = tokio::time::timeout(std::time::Duration::from_secs(3), async {
        // Exceed the entire plaintext budget while the first barrier is held.
        // This requires actual next-generation writeback, not just buffering.
        upper
            .write_at(PAGE as u64, &vec![9; super::core::DIRTY_LIMIT * 2])
            .await?;
        assert_eq!(upper.read_at(0, PAGE).await?.as_ref(), &[7; PAGE]);
        anyhow::Ok(())
    })
    .await;
    // Always release the coordinator before asserting, including on regression.
    *disk.released.lock().unwrap() = true;
    disk.ready.notify_all();
    progress.context("foreground was blocked by durable barrier")??;
    flushing.await??;
    upper.sync().await?;
    assert_eq!(upper.read_at(PAGE as u64, PAGE).await?.as_ref(), &[9; PAGE]);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pipelined_out_of_order_ranges_flush_all_prior_writes() -> Result<()> {
    use super::PackedUpper;
    use crate::io::virtual_file::VirtualFile;
    let disk = Arc::new(Model::default());
    let half = super::core::DIRTY_LIMIT;
    let upper = PackedUpper::from_core(Core::create(
        disk.clone(),
        (half * 2) as u64,
        Policy::default(),
    )?)?;
    // Logical key order differs from write sequence order across split batches.
    upper.write_at(half as u64, &vec![0x73; half]).await?;
    upper.write_at(0, &vec![0x29; half]).await?;
    upper.sync().await?;
    drop(upper);
    disk.cut(0, false);
    let recovered = Core::open(disk, Policy::default())?;
    for lba in 0..half * 2 / PAGE {
        let expected = if lba * PAGE < half { 0x29 } else { 0x73 };
        assert_eq!(
            *recovered.read_block(lba as u64)?.unwrap(),
            [expected; PAGE]
        );
    }
    Ok(())
}

#[test]
fn writeback_is_visible_but_not_durable_and_keeps_reader_pins() -> Result<()> {
    let disk = Arc::new(Model::default());
    let mut core = Core::create(disk.clone(), PAGE as u64 * 16, Policy::default())?;
    core.stage(0, Box::new([1; PAGE]))?;
    core.commit()?;
    let before = core.stats()?.barriers;
    let metadata_before = core.stats()?.metadata_pages_written;
    core.stage(0, Box::new([2; PAGE]))?;
    core.writeback()?;
    let pinned = core.view();
    for value in 3..20 {
        core.stage(0, Box::new([value; PAGE]))?;
        core.writeback()?;
    }
    assert_eq!(core.stats()?.barriers, before);
    assert_eq!(core.stats()?.metadata_pages_written, metadata_before);
    assert_eq!(pinned.read(0)?.unwrap()[0], 2);
    assert_eq!(core.read_block(0)?.unwrap()[0], 19);
    let uncommitted = disk.0.lock().unwrap().clone();
    for mask in [0, u64::MAX, 0x5555555555555555] {
        for torn in [false, true] {
            let crashed = Model::from(uncommitted.clone());
            crashed.cut(mask, torn);
            assert_eq!(
                Core::open(crashed, Policy::default())?
                    .read_block(0)?
                    .unwrap()[0],
                1
            );
        }
    }
    core.commit()?; // No plaintext pending: this must still publish writeback.
    assert_eq!(core.stats()?.barriers, before + 2);
    assert!(!core.has_writeback());
    drop(core);
    drop(pinned);
    disk.cut(0, false);
    assert_eq!(
        Core::open(disk, Policy::default())?.read_block(0)?.unwrap()[0],
        19
    );
    Ok(())
}

#[test]
fn writeback_and_publication_faults_preserve_acknowledged_root() -> Result<()> {
    fn update(c: &mut Core) -> Result<()> {
        c.stage(0, Box::new([2; PAGE]))?;
        c.writeback()?;
        c.stage(1, Box::new([3; PAGE]))?;
        c.writeback()?;
        c.commit()
    }
    let disk = Arc::new(Model::default());
    let mut c = Core::create(disk.clone(), PAGE as u64 * 16, Policy::default())?;
    c.stage(0, Box::new([1; PAGE]))?;
    c.commit()?;
    let initial = disk.0.lock().unwrap().clone();
    let probe = Model::from(initial.clone());
    update(&mut Core::open(probe.clone(), Policy::default())?)?;
    let count = probe.0.lock().unwrap().ops - initial.ops;
    for fail in 1..=count + 1 {
        for short_write in [false, true] {
            for errno in [libc::EIO, libc::ENOSPC] {
                for mask in [0, u64::MAX, 0xaaaaaaaaaaaaaaaa] {
                    for torn in [false, true] {
                        let disk = Model::from(initial.clone());
                        {
                            let mut s = disk.0.lock().unwrap();
                            s.fail = Some(initial.ops + fail);
                            s.short_write = short_write;
                            s.errno = errno;
                        }
                        let mut core = Core::open(disk.clone(), Policy::default())?;
                        let acknowledged = update(&mut core).is_ok();
                        if !acknowledged {
                            assert!(core.stage(2, Box::new([9; PAGE])).is_err());
                        }
                        drop(core);
                        disk.cut(mask, torn);
                        let recovered = Core::open(disk, Policy::default())?;
                        let first = recovered.read_block(0)?.unwrap()[0];
                        assert!(first == 1 || first == 2);
                        if acknowledged {
                            assert_eq!(first, 2);
                        }
                        if first == 2 {
                            assert_eq!(recovered.read_block(1)?.unwrap()[0], 3);
                        } else {
                            assert!(recovered.read_block(1)?.is_none());
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

#[test]
fn tree_partition_preserves_sparse_keys_and_previous_roots() -> Result<()> {
    use super::tree::{self, Pages};
    use std::collections::BTreeMap;
    struct Alloc {
        disk: Arc<Model>,
        next: u64,
    }
    impl Pages for Alloc {
        fn allocate(&mut self) -> u64 {
            let page = self.next;
            self.next += 1;
            page
        }
        fn disk(&self) -> &dyn Disk {
            self.disk.as_ref()
        }
        fn retire(&mut self, _: u64) {}
    }
    let mut alloc = Alloc {
        disk: Arc::new(Model::default()),
        next: 2,
    };
    let mut expected = BTreeMap::new();
    let mut seed = 7u64;
    for i in 0..2048 {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        expected.insert(seed, [i; 6]);
        expected.insert(i, [i; 6]);
    }
    for key in [0, 63, 64, 4095, 4096, u64::MAX] {
        expected.insert(key, [key; 6]);
    }
    let changes = expected.iter().map(|(&k, &v)| (k, Some(v))).collect();
    let root = tree::update(&mut alloc, 0, tree::HEIGHT, &changes)?;
    assert_eq!(tree::load(alloc.disk.as_ref(), root)?.0, expected);
    let before = expected.clone();
    let changes = expected
        .keys()
        .copied()
        .enumerate()
        .map(|(i, k)| (k, if i % 3 == 0 { None } else { Some([!k; 6]) }))
        .collect::<BTreeMap<_, _>>();
    for (&k, v) in &changes {
        match v {
            Some(v) => {
                expected.insert(k, *v);
            }
            None => {
                expected.remove(&k);
            }
        }
    }
    let new = tree::update(&mut alloc, root, tree::HEIGHT, &changes)?;
    assert_eq!(tree::load(alloc.disk.as_ref(), new)?.0, expected);
    assert_eq!(tree::load(alloc.disk.as_ref(), root)?.0, before);
    let deletes = expected.keys().map(|&k| (k, None)).collect();
    assert_eq!(tree::update(&mut alloc, new, tree::HEIGHT, &deletes)?, 0);
    Ok(())
}

#[test]
fn metadata_cache_collision_and_reuse_never_return_stale_pages() -> Result<()> {
    use super::tree;
    let disk = Model::default();
    let mut cache = tree::Cache::default();
    let mut page = [0; PAGE];
    page[..8].copy_from_slice(b"OBDPBT01");
    page[8] = 3;
    tree::seal(&mut page);
    disk.write(2 * PAGE as u64, &page)?;
    assert_eq!(cache.read(&disk, 2, 3)?, page);
    assert_eq!(cache.read(&disk, 2, 3)?, page);
    assert_eq!((cache.hits, cache.misses), (1, 1));
    assert!(cache.read(&disk, 2, 2).is_err());
    let mut other = page;
    other[32] = 17;
    tree::seal(&mut other);
    disk.write(2050 * PAGE as u64, &other)?;
    cache.insert(2050, &other); // Collides in the same set, but both fit.
    assert_eq!(cache.read(&disk, 2, 3)?, page);
    assert_eq!((cache.hits, cache.misses), (2, 1));
    // Fill this set and keep one hot path alive while a ninth node arrives.
    for i in 1..7 {
        cache.insert(2 + i * 256, &page);
    }
    assert_eq!(cache.read(&disk, 2, 3)?, page);
    cache.insert(2 + 7 * 256, &other);
    assert_eq!(cache.read(&disk, 2, 3)?, page);
    assert_eq!(cache.misses, 1);
    assert_eq!(cache.read(&disk, 2050, 3)?, other);
    assert_eq!(cache.misses, 2); // Least recently used entry was evicted.
    disk.write(2 * PAGE as u64, &other)?;
    cache.invalidate(2);
    assert_eq!(cache.read(&disk, 2, 3)?, other);
    cache.invalidate(2);
    disk.write(2 * PAGE as u64, &[0; PAGE])?;
    assert!(cache.read(&disk, 2, 3).is_err());
    Ok(())
}

#[test]
fn deferred_metadata_merges_shared_objects_overwrites_and_zeroes() -> Result<()> {
    let disk = Arc::new(Model::default());
    let mut core = Core::create(disk.clone(), PAGE as u64 * 1024, policy(Codec::Lz4, true))?;
    let mut expected = vec![0u8; 1024];
    for generation in 1..=8u8 {
        for (lba, value) in expected.iter_mut().enumerate() {
            // Shared objects, transitions back to zero, and objects born and
            // retired without ever appearing in a durable tree.
            *value = if (lba + generation as usize) % 7 == 0 {
                0
            } else {
                generation
            };
            core.stage(lba as u64, Box::new([*value; PAGE]))?;
        }
        core.writeback()?;
    }
    assert_eq!(core.stats()?.metadata_pages_written, 0);
    core.commit()?;
    assert_eq!(core.stats()?.barriers, 2);
    drop(core);
    disk.cut(0, false);
    let core = Core::open(disk, policy(Codec::None, false))?;
    for (lba, value) in expected.into_iter().enumerate() {
        assert_eq!(*core.read_block(lba as u64)?.unwrap(), [value; PAGE]);
    }
    Ok(())
}

#[test]
fn asynchronous_publication_protects_frozen_root_during_next_writeback() -> Result<()> {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc, Condvar,
    };
    struct Gated {
        disk: Model,
        remaining: AtomicUsize,
        entered: mpsc::Sender<()>,
        released: Mutex<bool>,
        ready: Condvar,
    }
    impl Disk for Gated {
        fn read(&self, o: u64, b: &mut [u8]) -> Result<()> {
            self.disk.read(o, b)
        }
        fn write(&self, o: u64, b: &[u8]) -> Result<()> {
            self.disk.write(o, b)
        }
        fn len(&self) -> Result<u64> {
            self.disk.len()
        }
        fn allocated(&self) -> Result<u64> {
            self.disk.allocated()
        }
        fn punch(&self, o: u64, n: u64) -> Result<()> {
            self.disk.punch(o, n)
        }
        fn barrier(&self) -> Result<()> {
            if self
                .remaining
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_sub(1))
                == Ok(1)
            {
                self.entered.send(())?;
                let mut released = self.released.lock().unwrap();
                while !*released {
                    released = self.ready.wait(released).unwrap();
                }
            }
            self.disk.barrier()
        }
    }
    // Gate either barrier. Fail the barrier or the subsequent superblock write,
    // including a short write; preserve exact confirmed roots under crash cuts.
    for phase in [1, 2] {
        for failure in [0, 1, 2, 3] {
            if phase == 2 && failure == 2 {
                continue;
            }
            let (entered, notification) = mpsc::channel();
            let disk = Arc::new(Gated {
                disk: Model::default(),
                remaining: AtomicUsize::new(0),
                entered,
                released: Mutex::new(false),
                ready: Condvar::new(),
            });
            let mut core =
                Core::create(disk.clone(), (PAGE * 16) as u64, policy(Codec::Lz4, true))?;
            core.stage(0, Box::new([1; PAGE]))?;
            core.commit()?;
            disk.remaining.store(phase, Ordering::Release);
            core.stage(0, Box::new([2; PAGE]))?;
            core.stage(1, Box::new([2; PAGE]))?;
            let (wake, _rx) = mpsc::sync_channel(1);
            core.begin_commit(wake)?;
            notification.recv_timeout(std::time::Duration::from_secs(3))?;
            let frozen = core.view();
            if failure == 3 {
                let mut state = disk.disk.0.lock().unwrap();
                state.fail = Some(state.ops + 1);
                state.short_write = true;
                state.errno = libc::EIO;
            }
            let progress = (|| -> Result<()> {
                core.stage(0, Box::new([3; PAGE]))?;
                core.stage(1, Box::new([0; PAGE]))?;
                core.writeback()?;
                anyhow::ensure!(
                    core.read_block(0)?.unwrap()[0] == 3,
                    "working root mismatch"
                );
                anyhow::ensure!(frozen.read(0)?.unwrap()[0] == 2, "frozen root mismatch");
                Ok(())
            })();
            if failure == 1 || failure == 2 {
                let mut state = disk.disk.0.lock().unwrap();
                state.fail = Some(state.ops + failure);
                state.short_write = true;
                state.errno = libc::ENOSPC;
            }
            *disk.released.lock().unwrap() = true;
            disk.ready.notify_all();
            if failure == 3 {
                assert!(progress.is_err());
            } else {
                progress?;
            }
            let published = failure == 0 || failure == 3;
            assert_eq!(core.finish_publication(true).is_ok(), published);
            if failure != 0 {
                assert!(core.stage(2, Box::new([4; PAGE])).is_err());
            }
            let state = disk.disk.0.lock().unwrap().clone();
            for mask in [0, u64::MAX, 0x5555555555555555] {
                for torn in [false, true] {
                    let crashed = Model::from(state.clone());
                    crashed.cut(mask, torn);
                    let recovered = Core::open(crashed, Policy::default())?;
                    let value = recovered.read_block(0)?.unwrap()[0];
                    if published {
                        assert_eq!(value, 2);
                    } else {
                        assert!(value == 1 || value == 2);
                    }
                    if value == 2 {
                        assert_eq!(recovered.read_block(1)?.unwrap()[0], 2);
                    }
                }
            }
            if failure == 0 {
                core.commit()?;
                let crashed = Model::from(disk.disk.0.lock().unwrap().clone());
                crashed.cut(0, false);
                let recovered = Core::open(crashed, Policy::default())?;
                assert_eq!(recovered.read_block(0)?.unwrap()[0], 3);
                assert_eq!(recovered.read_block(1)?.unwrap()[0], 0);
            }
        }
    }
    Ok(())
}

#[test]
fn asynchronous_punch_reserves_ranges_without_stalling_flush_and_poison_on_error() -> Result<()> {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Condvar,
    };
    #[derive(Default)]
    struct HeldPunch {
        disk: Model,
        state: Mutex<(bool, bool)>,
        changed: Condvar,
        fail: AtomicBool,
    }
    impl Disk for HeldPunch {
        fn read(&self, o: u64, b: &mut [u8]) -> Result<()> {
            self.disk.read(o, b)
        }
        fn write(&self, o: u64, b: &[u8]) -> Result<()> {
            self.disk.write(o, b)
        }
        fn barrier(&self) -> Result<()> {
            self.disk.barrier()
        }
        fn len(&self) -> Result<u64> {
            self.disk.len()
        }
        fn allocated(&self) -> Result<u64> {
            self.disk.allocated()
        }
        fn punch(&self, o: u64, n: u64) -> Result<()> {
            let mut state = self.state.lock().unwrap();
            state.0 = true;
            self.changed.notify_all();
            while !state.1 {
                state = self.changed.wait(state).unwrap();
            }
            drop(state);
            if self.fail.load(Ordering::Relaxed) {
                bail!("injected punch EIO");
            }
            self.disk.punch(o, n)
        }
    }
    struct Release(Arc<HeldPunch>);
    impl Drop for Release {
        fn drop(&mut self) {
            self.0.state.lock().unwrap().1 = true;
            self.0.changed.notify_all();
        }
    }
    for fail in [false, true] {
        let disk = Arc::new(HeldPunch::default());
        let mut c = Core::create(disk.clone(), 256 * PAGE as u64, policy(Codec::None, false))?;
        let release = Release(disk.clone());
        for generation in 1..=3 {
            for lba in 0..256 {
                c.stage(lba, Box::new([generation; PAGE]))?;
            }
            c.commit()?;
        }
        let (wake, _rx) = std::sync::mpsc::sync_channel(1);
        // Root rotation is also asynchronous. Retired data becomes eligible
        // only after both recoverable roots have moved away from it.
        for _ in 0..4 {
            c.maintenance_async(wake.clone(), || false)?;
            if c.stats()?.cleaner_pending_bytes > 0 {
                break;
            }
            c.finish_publication(true)?;
        }
        assert!(c.stats()?.cleaner_pending_bytes > 0);
        let state = disk.state.lock().unwrap();
        let (state, timeout) = disk
            .changed
            .wait_timeout_while(state, std::time::Duration::from_secs(5), |s| !s.0)
            .unwrap();
        assert!(!timeout.timed_out());
        drop(state);
        // No cleaner completion exists yet. Commit must still complete, and its
        // allocator must not reuse any reserved hole that the punch will erase.
        for lba in 0..256 {
            c.stage(lba, Box::new([19; PAGE]))?;
        }
        c.commit()?;
        for lba in 0..256 {
            assert_eq!(*c.read_block(lba)?.unwrap(), [19; PAGE]);
        }
        disk.fail.store(fail, Ordering::Relaxed);
        drop(release);
        if fail {
            assert!(c.finish_cleaning(true).is_err());
            assert!(c.stage(0, Box::new([23; PAGE])).is_err());
            assert!(c.commit().is_err());
        } else {
            assert!(c.finish_cleaning(true)?);
        }
        drop(c);
        let reopened = Core::open(disk, policy(Codec::None, false))?;
        for lba in 0..256 {
            assert_eq!(*reopened.read_block(lba)?.unwrap(), [19; PAGE]);
        }
    }
    Ok(())
}

#[test]
fn queued_data_is_readable_and_flush_waits_for_actual_io() -> Result<()> {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Condvar,
    };
    #[derive(Default)]
    struct HeldWrite {
        model: Model,
        held: Mutex<bool>,
        entered: Condvar,
        release: Condvar,
        waiting: AtomicBool,
        fail: AtomicBool,
    }
    impl Disk for HeldWrite {
        fn read(&self, o: u64, b: &mut [u8]) -> Result<()> {
            self.model.read(o, b)
        }
        fn write(&self, o: u64, b: &[u8]) -> Result<()> {
            let mut held = self.held.lock().unwrap();
            while *held {
                self.waiting.store(true, Ordering::Release);
                self.entered.notify_all();
                held = self.release.wait(held).unwrap();
            }
            drop(held);
            if self.fail.load(Ordering::Acquire) {
                bail!("injected queued write failure");
            }
            self.model.write(o, b)
        }
        fn barrier(&self) -> Result<()> {
            self.model.barrier()
        }
        fn len(&self) -> Result<u64> {
            self.model.len()
        }
        fn allocated(&self) -> Result<u64> {
            self.model.allocated()
        }
        fn punch(&self, o: u64, n: u64) -> Result<()> {
            self.model.punch(o, n)
        }
    }
    struct Release(Arc<HeldWrite>);
    impl Drop for Release {
        fn drop(&mut self) {
            *self.0.held.lock().unwrap() = false;
            self.0.release.notify_all();
        }
    }
    for fail in [false, true] {
        let disk = Arc::new(HeldWrite::default());
        let mut core = Core::create(disk.clone(), PAGE as u64 * 16, policy(Codec::None, false))?;
        core.stage(0, Box::new([1; PAGE]))?;
        core.commit()?;
        core.async_data = true;
        *disk.held.lock().unwrap() = true;
        let release = Release(disk.clone());
        core.stage(0, Box::new([2; PAGE]))?;
        core.writeback()?;
        {
            let held = disk.held.lock().unwrap();
            let (_held, timeout) = disk
                .entered
                .wait_timeout_while(held, std::time::Duration::from_secs(5), |_| {
                    !disk.waiting.load(Ordering::Acquire)
                })
                .unwrap();
            assert!(!timeout.timed_out());
        }
        let pinned = core.view();
        core.stage(0, Box::new([3; PAGE]))?;
        core.stage(1, Box::new([4; PAGE]))?;
        core.writeback()?;
        assert_eq!(*pinned.read(0)?.unwrap(), [2; PAGE]);
        assert_eq!(*core.read_block(0)?.unwrap(), [3; PAGE]);
        assert_eq!(*core.read_block(1)?.unwrap(), [4; PAGE]);
        let (tx, rx) = mpsc::channel();
        let join = std::thread::spawn(move || {
            let result = core.commit();
            tx.send(result.is_ok()).unwrap();
            core
        });
        assert!(rx
            .recv_timeout(std::time::Duration::from_millis(30))
            .is_err());
        disk.fail.store(fail, Ordering::Release);
        drop(release);
        assert_eq!(rx.recv_timeout(std::time::Duration::from_secs(5))?, !fail);
        let mut core = join.join().unwrap();
        if fail {
            assert!(core.stage(2, Box::new([9; PAGE])).is_err());
        }
        drop(core);
        drop(pinned);
        disk.model.cut(0, false);
        let reopened = Core::open(disk, Policy::default())?;
        assert_eq!(
            *reopened.read_block(0)?.unwrap(),
            [if fail { 1 } else { 3 }; PAGE]
        );
        if !fail {
            assert_eq!(*reopened.read_block(1)?.unwrap(), [4; PAGE]);
        }
    }
    Ok(())
}

#[test]
fn queued_data_faults_survive_reordered_and_torn_power_loss() -> Result<()> {
    let disk = Arc::new(Model::default());
    let mut core = Core::create(disk.clone(), PAGE as u64 * 16, Policy::default())?;
    core.stage(0, Box::new([1; PAGE]))?;
    core.commit()?;
    drop(core);
    let initial = disk.0.lock().unwrap().clone();
    fn update(core: &mut Core) -> Result<()> {
        core.async_data = true;
        core.stage(0, Box::new([2; PAGE]))?;
        core.writeback()?;
        core.stage(0, Box::new([3; PAGE]))?;
        core.stage(1, Box::new([4; PAGE]))?;
        core.writeback()?;
        core.commit()
    }
    let probe = Model::from(initial.clone());
    let mut core = Core::open(probe.clone(), Policy::default())?;
    update(&mut core)?;
    drop(core);
    let count = probe.0.lock().unwrap().ops - initial.ops;
    for failure in 1..=count + 1 {
        for errno in [libc::EIO, libc::ENOSPC] {
            for mask in [0, u64::MAX, 0x5555555555555555, 0xaaaaaaaaaaaaaaaa] {
                for torn in [false, true] {
                    let disk = Model::from(initial.clone());
                    {
                        let mut s = disk.0.lock().unwrap();
                        s.fail = Some(initial.ops + failure);
                        s.errno = errno;
                        s.short_write = torn;
                    }
                    let mut core = Core::open(disk.clone(), Policy::default())?;
                    let acknowledged = update(&mut core).is_ok();
                    if !acknowledged {
                        assert!(core.stage(2, Box::new([9; PAGE])).is_err());
                    }
                    // Join queued I/O before applying the simulated power cut.
                    drop(core);
                    disk.cut(mask, torn);
                    let recovered = Core::open(disk, Policy::default())?;
                    let value = *recovered.read_block(0)?.unwrap();
                    if acknowledged {
                        assert_eq!(value, [3; PAGE]);
                    } else {
                        assert!(value == [1; PAGE] || value == [3; PAGE]);
                    }
                    if value == [3; PAGE] {
                        assert_eq!(*recovered.read_block(1)?.unwrap(), [4; PAGE]);
                    }
                }
            }
        }
    }
    Ok(())
}

#[test]
fn mixed_size_batches_cross_segments_and_reopen_after_overwrite() -> Result<()> {
    let disk = Arc::new(Model::default());
    let mut core = Core::create(disk.clone(), 2048 * PAGE as u64, Policy::default())?;
    let mut expected = vec![Box::new([0; PAGE]); 2048];
    let mut seed = 991u64;
    for (round, codec) in [Codec::Lz4, Codec::Zstd, Codec::None, Codec::Lz4]
        .into_iter()
        .enumerate()
    {
        core.set_policy(policy(codec, false))?;
        core.async_data = true;
        for (lba, block) in expected.iter_mut().enumerate() {
            if round != 0 && lba % 3 != round % 3 {
                continue;
            }
            for word in block.chunks_exact_mut(8) {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                word.copy_from_slice(&seed.to_le_bytes());
            }
            if lba % 7 != 0 {
                let prefix = 256 + (lba % 13) * 256;
                for at in prefix..PAGE {
                    block[at] = block[at % 256];
                }
            }
            if lba % 17 == 0 {
                block.fill(0);
            }
            core.stage(lba as u64, block.clone())?;
        }
        core.writeback()?;
        for lba in (0..2048).step_by(31) {
            assert_eq!(core.read_block(lba as u64)?.unwrap(), expected[lba]);
        }
        core.commit()?;
        drop(core);
        disk.cut(0, false);
        core = Core::open(disk.clone(), Policy::default())?;
        for (lba, block) in expected.iter().enumerate() {
            assert_eq!(&core.read_block(lba as u64)?.unwrap(), block);
        }
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn streamed_mixed_capacity_buffers_preserve_contents() -> Result<()> {
    use super::{disk::FileDisk, PackedUpper};
    use crate::io::virtual_file::VirtualFile;
    let temp = tempfile::tempdir()?;
    let path = temp.path().join("stream.packed");
    let size = 128 * 1024 * 1024u64;
    PackedUpper::create(&path, size, Policy::default())?;
    let upper = PackedUpper::open(&path, None, Policy::default()).await?;
    let mut data = vec![0; 1024 * 1024];
    let mut random = 4981u64;
    for block in data.chunks_exact_mut(PAGE) {
        for b in &mut block[..2048] {
            random ^= random << 13;
            random ^= random >> 7;
            random ^= random << 17;
            *b = random as u8;
        }
        for i in 2048..PAGE {
            block[i] = block[i % 256];
        }
    }
    for at in (0..size).step_by(data.len()) {
        upper.write_at(at, &data).await?;
    }
    upper.sync().await?;
    drop(upper);
    let core = Core::open(Arc::new(FileDisk::open(&path, false)?), Policy::default())?;
    for lba in 0..size / PAGE as u64 {
        assert_eq!(
            core.read_block(lba)?.unwrap().as_slice(),
            &data[(lba as usize * PAGE) % data.len()..(lba as usize * PAGE) % data.len() + PAGE]
        );
    }
    Ok(())
}

#[test]
fn coalesced_reads_preserve_codecs_shared_objects_and_pinned_versions() -> Result<()> {
    for policy in [
        policy(Codec::None, false),
        policy(Codec::Lz4, false),
        policy(Codec::Zstd, false),
        policy(Codec::Lz4, true),
    ] {
        let disk = Arc::new(Model::default());
        let mut core = Core::create(disk.clone(), 64 * PAGE as u64, policy)?;
        let mut expected = vec![0; 32 * PAGE];
        for i in 0..32 {
            let value = (i % 8 + 1) as u8;
            expected[i * PAGE..(i + 1) * PAGE].fill(value);
            core.stage(i as u64, Box::new([value; PAGE]))?;
        }
        core.commit()?;
        let before = core.stats()?;
        let pinned = core.view();
        let mut out = vec![0; expected.len()];
        assert_eq!(pinned.read_blocks(0, 0, &mut out)?, u32::MAX);
        assert_eq!(out, expected);
        let after = core.stats()?;
        assert_eq!(after.upper_read_blocks - before.upper_read_blocks, 32);
        assert_eq!(after.host_read_calls - before.host_read_calls, 1);
        for i in 0..32 {
            if i % 3 == 0 {
                core.stage(i as u64, Box::new([0; PAGE]))?;
            }
        }
        core.commit()?;
        core.maintenance()?;
        assert_eq!(pinned.read_blocks(0, 0, &mut out)?, u32::MAX);
        assert_eq!(out, expected);
        for i in (0..32).step_by(3) {
            expected[i * PAGE..(i + 1) * PAGE].fill(0);
        }
        drop(pinned);
        drop(core);
        disk.cut(0, false);
        let core = Core::open(disk, Policy::default())?;
        assert_eq!(core.view().read_blocks(0, 0, &mut out)?, u32::MAX);
        assert_eq!(out, expected);
        // Absence must be distinguishable from explicit zero. The caller owns
        // skipped frontend bytes and lower fallback for uncovered blocks.
        out.fill(99);
        assert_eq!(core.view().read_blocks(32, 1 << 7, &mut out)?, 1 << 7);
        assert!(out.iter().all(|b| *b == 99));
    }
    Ok(())
}

#[test]
fn coalesced_read_checks_each_object_and_does_not_decode_skipped_data() -> Result<()> {
    let disk = Arc::new(Model::default());
    let mut core = Core::create(disk.clone(), 32 * PAGE as u64, Policy::default())?;
    for i in 0..32 {
        core.stage(i, Box::new([i as u8 + 1; PAGE]))?;
    }
    core.commit()?;
    let object_root = {
        let state = disk.0.lock().unwrap();
        super::tree::get64(&state.volatile[PAGE..2 * PAGE], 48)
    };
    let (objects, _) = super::tree::load(disk.as_ref(), object_root)?;
    let target = objects.get(&8).unwrap()[0] as usize;
    disk.0.lock().unwrap().volatile[target] ^= 0x80;
    let view = core.view();
    let mut out = vec![99; PAGE * 32];
    assert_eq!(view.read_blocks(0, 1 << 7, &mut out)?, u32::MAX);
    assert!(out[7 * PAGE..8 * PAGE].iter().all(|b| *b == 99));
    assert!(view.read_blocks(0, 0, &mut out).is_err());
    assert!(core.stage(0, Box::new([0; PAGE])).is_err());
    Ok(())
}
