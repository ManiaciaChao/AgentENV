use super::super::Codec;
use super::*;
use super::{allocation::Allocation, format::object_pages, reclaim::cleaner_victim};

#[test]
fn sparse_tails_do_not_starve_reclaimable_segments() {
    let mut segments: Map<(u64, u64)> = [
        (1, (64, 1)),
        (2, (PAGE as u64 * 12, 32)),
        (3, (PAGE as u64 + 64, 3)),
    ]
    .into_iter()
    .collect();
    // The old minimum-live-bytes selector chose segment 1 forever.
    assert_eq!(cleaner_victim(&segments), Some(2));
    segments.remove(&2);
    assert_eq!(cleaner_victim(&segments), None);
}

fn check_segments(root: &Root) {
    let mut expected: BTreeMap<u64, (u64, BTreeSet<u64>)> = BTreeMap::new();
    for (_, v) in root.objects.iter() {
        let entry = expected.entry(v[0] / SEGMENT).or_default();
        entry.0 += v[1].next_multiple_of(64);
        entry.1.extend(object_pages(v));
    }
    let expected: BTreeMap<_, _> = expected
        .into_iter()
        .map(|(seg, (bytes, pages))| (seg, (bytes, pages.len() as u64)))
        .collect();
    let actual: BTreeMap<_, _> = root.segments.iter().map(|(&k, &v)| (k, v)).collect();
    assert_eq!(actual, expected);
}

#[test]
fn segment_occupancy_tracks_shared_objects_relocation_and_reopen() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let disk = Arc::new(super::super::disk::FileDisk::open(
        &dir.path().join("pack"),
        true,
    )?);
    let mut core = Core::create(disk.clone(), 2048 * PAGE as u64, Policy::default())?;
    let mut rng = 17u64;
    for policy in [
        Policy {
            compression: Codec::None,
            dedupe: false,
        },
        Policy {
            compression: Codec::Lz4,
            dedupe: true,
        },
        Policy {
            compression: Codec::Zstd,
            dedupe: false,
        },
    ] {
        core.set_policy(policy)?;
        for lba in 0..2048 {
            let mut block = Box::new([0; PAGE]);
            if lba % 4 != 0 {
                for byte in &mut block[..2048] {
                    rng ^= rng << 13;
                    rng ^= rng >> 7;
                    rng ^= rng << 17;
                    *byte = rng as u8;
                }
            } else {
                block.fill(37);
            }
            core.stage(lba, block)?;
        }
        core.commit()?;
        check_segments(core.root());
        let pinned = core.view();
        for lba in (0..2048).step_by(3) {
            core.stage(lba, Box::new([0; PAGE]))?;
        }
        core.commit()?;
        check_segments(core.root());
        let victim = *core.root().segments.iter().next().unwrap().0;
        core.publish(true, Some(victim))?;
        check_segments(core.root());
        assert_eq!(pinned.read(0)?.unwrap().as_slice(), &[37; PAGE]);
        drop(pinned);
        drop(core);
        core = Core::open(disk.clone(), policy)?;
        check_segments(core.root());
    }
    Ok(())
}

#[test]
fn pinned_retirement_does_not_trigger_tiny_punch_barriers() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let disk = Arc::new(super::super::disk::FileDisk::open(
        &dir.path().join("pack"),
        true,
    )?);
    let mut core = Core::create(
        disk,
        4096 * PAGE as u64,
        Policy {
            compression: Codec::None,
            dedupe: false,
        },
    )?;
    for lba in 0..4096 {
        core.stage(lba, Box::new([19; PAGE]))?;
    }
    core.commit()?;
    let pinned = core.view();
    for lba in 0..4096 {
        core.stage(lba, Box::new([0; PAGE]))?;
    }
    core.commit()?;
    // Retire a small subsequent allocation while the large old data set
    // remains pinned, then rotate away its last recoverable reference.
    core.stage(0, Box::new([21; PAGE]))?;
    core.commit()?;
    core.stage(0, Box::new([0; PAGE]))?;
    core.commit()?;
    core.publish(true, None)?;
    let before = core.stats()?;
    assert!(before.retired_bytes >= 8 * 1024 * 1024);
    assert!(before.reclaimable_bytes > 0 && before.reclaimable_bytes < 8 * 1024 * 1024);
    for _ in 0..8 {
        core.maintenance()?;
    }
    assert_eq!(core.stats()?.barriers, before.barriers);
    assert_eq!(core.stats()?.cleaner_punch_batches, 0);
    assert_eq!(pinned.read(0)?.unwrap().as_slice(), &[19; PAGE]);
    drop(pinned);
    core.maintenance()?;
    assert!(core.stats()?.reclaimed_bytes >= 8 * 1024 * 1024);
    assert_eq!(core.read_block(0)?.unwrap().as_slice(), &[0; PAGE]);
    Ok(())
}

#[test]
fn packed_payloads_cross_pages_and_output_batches_without_rewriting_closed_pages() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let disk = Arc::new(super::super::disk::FileDisk::open(
        &dir.path().join("pack"),
        true,
    )?);
    // Gaps force noncontiguous output, followed by append allocation across
    // 1 MiB write boundaries and 2 MiB segment boundaries.
    let mut a = Allocation {
        disk: disk.clone(),
        free: (2..1024).filter(|p| p % 7 != 0).collect(),
        fragment_budget: 0,
        fragment_appends: 0,
        end: 1024,
        pack: None,
        metadata: 0,
        cache: tree::Cache::default(),
        created: BTreeSet::new(),
        retired: BTreeSet::new(),
        excluded: None,
        output: Vec::with_capacity(1024 * 1024),
        output_offset: 0,
        write_calls: 0,
        write_bytes: 0,
        io_ns: 0,
        metadata_io_ns: 0,
        queue_wait_ns: 0,
        writer: super::super::writeback::Writer::new(
            disk.clone(),
            Arc::new(std::sync::Mutex::new(None)),
            Arc::new(super::super::writeback::ReadCache::default()),
        )?,
    };
    let sizes = [1, 63, 64, 65, 2049, 2050, 4032, 4095, 4096];
    let mut records = Vec::new();
    let mut occupied = BTreeSet::new();
    for i in 0..5000 {
        let size = sizes[i % sizes.len()];
        let data = vec![(i % 251 + 1) as u8; size];
        let offset = a.payload(&data)?;
        assert_eq!(offset % 64, 0);
        assert!(offset % SEGMENT + size as u64 <= SEGMENT);
        for slot in offset / 64..(offset + size as u64).div_ceil(64) {
            assert!(occupied.insert(slot), "overlapping packed objects");
        }
        records.push((offset, data));
    }
    a.finish_pack()?;
    a.flush_data()?;
    a.finish_io()?;
    assert!(a.write_calls > 10);
    for (offset, expected) in records {
        let mut actual = vec![0; expected.len()];
        disk.read(offset, &mut actual)?;
        assert_eq!(actual, expected);
    }
    // An append that crosses a segment boundary must also skip an excluded
    // destination segment, not just check the segment containing its start.
    a.free.clear();
    a.end = 8 * SEGMENT / PAGE as u64 - 1;
    a.excluded = Some(8);
    let bytes = vec![93; PAGE * 2];
    let offset = a.packed_batch(&mut bytes.clone(), &[])?.unwrap().offset;
    assert_eq!(offset, 9 * SEGMENT);
    a.flush_data()?;
    a.finish_io()?;
    let mut actual = vec![0; bytes.len()];
    disk.read(offset, &mut actual)?;
    assert_eq!(actual, bytes);
    // Reuse a sufficiently large hole; leave isolated holes for fallback.
    a.excluded = None;
    a.free = [3, 5, 10, 11].into_iter().collect();
    assert_eq!(
        a.packed_batch(&mut bytes.clone(), &[])?.map(|r| r.offset),
        Some(10 * PAGE as u64)
    );
    assert!(a.packed_batch(&mut bytes.clone(), &[])?.is_none());
    assert_eq!(a.free, [3, 5].into_iter().collect());
    // Cleaner relocation instead uses a contiguous destination, retaining
    // isolated holes for foreground writes. It must not recreate sparse pages.
    a.excluded = Some(8);
    assert!(a.packed_batch(&mut bytes.clone(), &[])?.is_some());
    assert_eq!(a.free, [3, 5].into_iter().collect());
    a.flush_data()?;
    a.finish_io()?;
    disk.read(10 * PAGE as u64, &mut actual)?;
    assert_eq!(actual, bytes);
    // Keep the batch contiguous across a segment boundary, but pad only the
    // object which would straddle it. Exercise both append and reused runs.
    for reuse in [false, true] {
        let start = 10 * SEGMENT / PAGE as u64 - 1;
        a.end = start;
        a.excluded = None;
        a.free = if reuse {
            (start..start + 3).collect()
        } else {
            BTreeSet::new()
        };
        let spans = [(0, 3000), (3008, 4096), (7104, 500)];
        let mut packed = vec![0; 8192];
        for (i, &(at, len)) in spans.iter().enumerate() {
            packed[at..at + len].fill(i as u8 + 11);
        }
        let run = a.packed_batch(&mut packed, &spans)?.unwrap();
        assert_eq!(run.offset, start * PAGE as u64);
        assert_eq!(run.shift, 1088);
        a.flush_data()?;
        a.finish_io()?;
        for (i, &(at, len)) in spans.iter().enumerate() {
            let offset = run.at(at);
            assert!(offset % SEGMENT + len as u64 <= SEGMENT);
            let mut actual = vec![0; len];
            disk.read(offset, &mut actual)?;
            assert_eq!(actual, vec![i as u8 + 11; len]);
        }
    }
    // Bulk writes may leave a bounded reserve of isolated holes, but must
    // still reuse a full run, single-page holes, and holes at the
    // reserve limit. Keep a neighbouring allocated page unchanged.
    a.end = 12 * SEGMENT / PAGE as u64;
    a.excluded = None;
    a.free = (2..514).step_by(2).collect();
    a.fragment_budget = 512;
    let start = a.end;
    disk.write((start - 1) * PAGE as u64, &[77; PAGE])?;
    let large = vec![53; 256 * PAGE];
    let calls = a.write_calls;
    let run = a.packed_batch(&mut large.clone(), &[])?.unwrap();
    assert_eq!(run.offset, start * PAGE as u64);
    assert_eq!(a.write_calls - calls, 1);
    assert_eq!(a.fragment_appends, 1);
    assert_eq!(a.free.len(), 256);
    a.finish_io()?;
    let mut actual = vec![0; large.len()];
    disk.read(run.offset, &mut actual)?;
    assert_eq!(actual, large);
    let mut sentinel = [0; PAGE];
    disk.read((start - 1) * PAGE as u64, &mut sentinel)?;
    assert_eq!(sentinel, [77; PAGE]);
    let end = a.end;
    a.fragment_budget = 256;
    assert!(a.packed_batch(&mut large.clone(), &[])?.is_none());
    assert_eq!(a.end, end);
    a.fragment_budget = 512;
    assert_eq!(
        a.packed_batch(&mut vec![1; PAGE], &[])?.unwrap().offset,
        2 * PAGE as u64
    );
    assert_eq!(a.end, end);
    // Compression can make a large logical batch much smaller than 128 KiB.
    // Preserve batching even then, without increasing the fragment reserve.
    let small = a.packed_batch(&mut vec![2; 16 * PAGE], &[])?.unwrap();
    assert_eq!(small.offset, end * PAGE as u64);
    assert_eq!(a.free.len(), 255);
    let end = a.end;
    a.free = (400..656).collect();
    assert_eq!(
        a.packed_batch(&mut large.clone(), &[])?.unwrap().offset,
        400 * PAGE as u64
    );
    assert_eq!(a.end, end);
    a.finish_io()?;
    Ok(())
}

#[test]
fn cleaner_relocation_bounds_mixed_object_buffer_capacity() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let disk = Arc::new(super::super::disk::FileDisk::open(
        &dir.path().join("pack"),
        true,
    )?);
    let policy = Policy {
        compression: Codec::Lz4,
        dedupe: false,
    };
    let mut core = Core::create(disk.clone(), 1536 * PAGE as u64, policy)?;
    let mut rng = 43u64;
    let mut expected = Vec::new();
    for lba in 0..1536 {
        let mut block = Box::new([0; PAGE]);
        for byte in &mut block[..2073 + (lba as usize % 17) * 7] {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            *byte = rng as u8;
        }
        expected.push(block.clone());
        core.stage(lba, block)?;
    }
    core.commit()?;
    for lba in (0..1536).step_by(3) {
        expected[lba] = Box::new([0; PAGE]);
        core.stage(lba as u64, expected[lba].clone())?;
    }
    core.commit()?;
    let victim = *core.root().segments.iter().next().unwrap().0;
    core.publish(true, Some(victim))?;
    drop(core);
    let reopened = Core::open(disk, policy)?;
    for (lba, block) in expected.iter().enumerate() {
        assert_eq!(
            reopened.view().read(lba as u64)?.unwrap().as_slice(),
            block.as_slice()
        );
    }
    Ok(())
}
