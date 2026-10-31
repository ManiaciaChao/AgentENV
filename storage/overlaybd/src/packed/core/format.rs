//! Superblock encoding and validation of recovered mapping/object trees.
use super::super::{
    disk::{Disk, PAGE},
    memory::{Map, PageSet},
    tree::{self, Value},
};
use super::SEGMENT;
use anyhow::{ensure, Result};
use std::collections::BTreeMap;
pub(super) const MAGIC: &[u8; 8] = b"OBDPACK1";
pub(super) fn object_pages(v: &Value) -> std::ops::RangeInclusive<u64> {
    v[0] / PAGE as u64..=(v[0] + v[1] - 1) / PAGE as u64
}
#[derive(Clone)]
pub(super) struct Root {
    pub(super) generation: u64,
    pub(super) map_root: u64,
    pub(super) objects_root: u64,
    pub(super) next_id: u64,
    pub(super) size: u64,
    pub(super) uuid: [u8; 16],
    pub(super) map: Map<u64>,
    pub(super) objects: Map<Value>,
    pub(super) pages: PageSet,
    pub(super) data_counts: Map<u32>,
    // Derived COW index: aligned live bytes and occupied pages per segment.
    // Rebuilt on open; it is not a second durable allocation ledger.
    pub(super) segments: Map<(u64, u64)>,
    pub(super) encoded_bytes: u64,
    pub(super) aligned_bytes: u64,
}
impl Root {
    pub(super) fn encode(&self) -> [u8; PAGE] {
        let mut b = [0; PAGE];
        b[..8].copy_from_slice(MAGIC);
        for (o, v) in [
            (8, 1),
            (16, 0),
            (24, self.generation),
            (32, self.size),
            (40, self.map_root),
            (48, self.objects_root),
            (56, self.next_id),
        ] {
            tree::put64(&mut b, o, v);
        }
        b[64..80].copy_from_slice(&self.uuid);
        tree::seal(&mut b);
        b
    }
    pub(super) fn decode(d: &dyn Disk, b: &[u8; PAGE]) -> Result<Self> {
        ensure!(
            &b[..8] == MAGIC && tree::valid(b),
            "invalid packed superblock"
        );
        ensure!(
            tree::get64(b, 8) == 1 && tree::get64(b, 16) == 0,
            "unsupported packed version/features"
        );
        let mut r = Self {
            generation: tree::get64(b, 24),
            size: tree::get64(b, 32),
            map_root: tree::get64(b, 40),
            objects_root: tree::get64(b, 48),
            next_id: tree::get64(b, 56),
            uuid: b[64..80].try_into().unwrap(),
            map: Map::new(),
            objects: Map::new(),
            pages: PageSet::new(),
            data_counts: Map::new(),
            segments: Map::new(),
            encoded_bytes: 0,
            aligned_bytes: 0,
        };
        ensure!(
            r.generation > 0 && r.size > 0 && r.size % 512 == 0 && r.next_id > 0,
            "invalid packed geometry"
        );
        let (map, mp) = tree::load(d, r.map_root)?;
        let (objects, op) = tree::load(d, r.objects_root)?;
        ensure!(mp.is_disjoint(&op), "packed metadata trees overlap");
        r.pages = mp.into_iter().collect();
        r.pages.extend(op);
        let mut refs: BTreeMap<u64, u64> = BTreeMap::new();
        for (&lba, v) in &map {
            ensure!(
                lba < r.size.div_ceil(PAGE as u64),
                "packed LBA out of bounds"
            );
            if v[0] != 0 {
                *refs.entry(v[0]).or_default() += 1;
            }
        }
        ensure!(
            refs.len() == objects.len(),
            "packed object reachability mismatch"
        );
        let disk_len = d.len()?;
        for (&id, v) in &objects {
            ensure!(
                id < r.next_id && refs.get(&id) == Some(&v[4]),
                "packed reference count mismatch"
            );
            ensure!(
                v[1] > 0
                    && v[1] <= PAGE as u64
                    && v[0] >= 2 * PAGE as u64
                    && v[0] % SEGMENT + v[1] <= SEGMENT
                    && v[0] % 64 == 0
                    && v[0].checked_add(v[1]).is_some_and(|end| end <= disk_len),
                "packed object bounds"
            );
            ensure!(
                v[2] <= 2 && (v[2] != 0 || v[1] == PAGE as u64),
                "invalid packed codec"
            );
            ensure!(
                object_pages(v).all(|p| !r.pages.contains(&p)),
                "packed data overlaps metadata"
            );
        }
        for v in objects.values() {
            r.segments.get_or_default(v[0] / SEGMENT).0 += v[1].next_multiple_of(64);
            for page in object_pages(v) {
                let count = r.data_counts.get_or_default(page);
                if *count == 0 {
                    r.segments.get_or_default(v[0] / SEGMENT).1 += 1;
                }
                *count += 1;
            }
        }
        r.pages.extend(r.data_counts.keys().copied());
        r.map = map
            .into_iter()
            .map(|(key, value)| (key, value[0]))
            .collect();
        r.encoded_bytes = objects.values().map(|v| v[1]).sum();
        r.aligned_bytes = objects.values().map(|v| v[1].next_multiple_of(64)).sum();
        r.objects = objects.into_iter().collect();
        Ok(r)
    }
}
