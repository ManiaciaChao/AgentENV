//! Fixed-range COW B+tree: sorted 64-way internal pages and 64-value leaves.
//! Only paths touched by a batch are rewritten. Zero pointers mean absent subtrees.
use super::disk::{Disk, PAGE};
use anyhow::{ensure, Result};
use std::collections::{BTreeMap, BTreeSet};
pub type Value = [u64; 6];
pub const HEIGHT: u8 = 10; // 66 key bits, covering every u64 key.
const MAGIC: &[u8; 8] = b"OBDPBT01";
pub fn put64(b: &mut [u8], o: usize, v: u64) {
    b[o..o + 8].copy_from_slice(&v.to_le_bytes());
}
pub fn get64(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}
pub fn seal(b: &mut [u8; PAGE]) {
    let c = crc32c::crc32c(&b[..PAGE - 4]);
    b[PAGE - 4..].copy_from_slice(&c.to_le_bytes());
}
pub fn valid(b: &[u8; PAGE]) -> bool {
    crc32c::crc32c(&b[..PAGE - 4]) == u32::from_le_bytes(b[PAGE - 4..].try_into().unwrap())
}
pub trait Pages {
    fn allocate(&mut self) -> u64;
    fn disk(&self) -> &dyn Disk;
    fn retire(&mut self, page: u64);
    fn read_page(&mut self, page: u64, level: u8) -> Result<[u8; PAGE]> {
        read(self.disk(), page, level)
    }
    fn write_page(&mut self, page: u64, bytes: &[u8; PAGE]) -> Result<()> {
        self.disk().write(page * PAGE as u64, bytes)
    }
}
fn read(d: &dyn Disk, p: u64, level: u8) -> Result<[u8; PAGE]> {
    ensure!(
        p >= 2 && p < d.len()?.div_ceil(PAGE as u64),
        "packed tree pointer out of bounds"
    );
    let mut b = [0; PAGE];
    d.read(p * PAGE as u64, &mut b)?;
    ensure!(
        &b[..8] == MAGIC && valid(&b) && b[8] == level,
        "corrupt packed tree page {p}"
    );
    Ok(b)
}
// Bounded, direct-mapped cache of immutable, validated metadata pages. It is
// owned only by the commit coordinator and never substitutes for recovery reads.
#[derive(Default)]
pub(super) struct Cache {
    slots: Vec<Option<(u64, Box<[u8; PAGE]>)>>,
    pub hits: u64,
    pub misses: u64,
}
impl Cache {
    const SLOTS: usize = 2048; // At most 8 MiB of metadata, separate from dirty data.
    pub fn invalidate(&mut self, page: u64) {
        if let Some(slot) = self.slots.get_mut(page as usize % Self::SLOTS) {
            if slot.as_ref().is_some_and(|(key, _)| *key == page) {
                *slot = None;
            }
        }
    }
    pub fn insert(&mut self, page: u64, bytes: &[u8; PAGE]) {
        if self.slots.is_empty() {
            self.slots.resize_with(Self::SLOTS, || None);
        }
        let slot = &mut self.slots[page as usize % Self::SLOTS];
        if let Some((key, data)) = slot {
            *key = page;
            data.copy_from_slice(bytes);
        } else {
            *slot = Some((page, Box::new(*bytes)));
        }
    }
    pub fn read(&mut self, disk: &dyn Disk, page: u64, level: u8) -> Result<[u8; PAGE]> {
        if let Some(Some((key, bytes))) = self.slots.get(page as usize % Self::SLOTS) {
            if *key == page {
                ensure!(bytes[8] == level, "packed cached tree level mismatch");
                self.hits += 1;
                return Ok(**bytes);
            }
        }
        self.misses += 1;
        let bytes = read(disk, page, level)?;
        self.insert(page, &bytes);
        Ok(bytes)
    }
}
// Logical mappings only need an object ID in memory. Expand to the existing
// six-word disk value only when serializing a durable generation.
pub fn update_mappings(
    a: &mut impl Pages,
    root: u64,
    changes: &super::memory::Map<u64>,
) -> Result<u64> {
    let changes: Vec<_> = changes
        .iter()
        .map(|(&key, &id)| (key, Some([id, 0, 0, 0, 0, 0])))
        .collect();
    update_sorted(a, root, HEIGHT, &changes)
}
pub fn update_objects(
    a: &mut impl Pages,
    root: u64,
    changes: &super::memory::Map<Option<Value>>,
) -> Result<u64> {
    let changes: Vec<_> = changes.iter().map(|(&key, &value)| (key, value)).collect();
    update_sorted(a, root, HEIGHT, &changes)
}
#[cfg(test)]
pub fn update(
    a: &mut impl Pages,
    root: u64,
    level: u8,
    changes: &BTreeMap<u64, Option<Value>>,
) -> Result<u64> {
    // Flatten once: recursive partitioning borrows sorted contiguous ranges,
    // avoiding a fresh BTreeMap (and copies of every value) at each level.
    let changes: Vec<_> = changes.iter().map(|(&key, &value)| (key, value)).collect();
    update_sorted(a, root, level, &changes)
}
fn update_sorted(
    a: &mut impl Pages,
    root: u64,
    level: u8,
    changes: &[(u64, Option<Value>)],
) -> Result<u64> {
    if changes.is_empty() {
        return Ok(root);
    }
    if root != 0 {
        a.retire(root);
    }
    let mut b = if root == 0 {
        let mut p = [0; PAGE];
        p[..8].copy_from_slice(MAGIC);
        p[8] = level;
        p
    } else {
        a.read_page(root, level)?
    };
    if level == 0 {
        for (k, v) in changes {
            let i = (k & 63) as usize;
            let o = 32 + i * 48;
            let mut mask = get64(&b, 16);
            if let Some(v) = v {
                mask |= 1 << i;
                for (j, x) in v.iter().enumerate() {
                    put64(&mut b, o + j * 8, *x);
                }
            } else {
                mask &= !(1 << i);
                b[o..o + 48].fill(0);
            }
            put64(&mut b, 16, mask);
        }
        if get64(&b, 16) == 0 {
            return Ok(0);
        }
    } else {
        let shift = level as u32 * 6;
        let first = ((changes.first().unwrap().0 >> shift) & 63) as usize;
        let last = ((changes.last().unwrap().0 >> shift) & 63) as usize;
        if first == last {
            // High sparse levels share one path. Reuse the batch instead of
            // allocating/copying its entire map at each of those levels.
            let old = get64(&b, 32 + first * 8);
            let new = update_sorted(a, old, level - 1, changes)?;
            put64(&mut b, 32 + first * 8, new);
        } else {
            let mut remaining = changes;
            while let Some(&(key, _)) = remaining.first() {
                let i = ((key >> shift) & 63) as usize;
                let count =
                    remaining.partition_point(|(key, _)| ((key >> shift) & 63) as usize == i);
                let (group, tail) = remaining.split_at(count);
                let old = get64(&b, 32 + i * 8);
                let new = update_sorted(a, old, level - 1, group)?;
                put64(&mut b, 32 + i * 8, new);
                remaining = tail;
            }
        }
        if (0..64).all(|i| get64(&b, 32 + i * 8) == 0) {
            return Ok(0);
        }
    }
    seal(&mut b);
    let p = a.allocate();
    a.write_page(p, &b)?;
    Ok(p)
}
pub fn load(d: &dyn Disk, root: u64) -> Result<(BTreeMap<u64, Value>, BTreeSet<u64>)> {
    fn walk(
        d: &dyn Disk,
        p: u64,
        l: u8,
        base: u64,
        out: &mut BTreeMap<u64, Value>,
        pages: &mut BTreeSet<u64>,
    ) -> Result<()> {
        if p == 0 {
            return Ok(());
        }
        ensure!(pages.insert(p), "packed tree cycle/shared metadata pointer");
        let b = read(d, p, l)?;
        for i in 0..64 {
            if l == 0 {
                if get64(&b, 16) & (1 << i) != 0 {
                    let mut v = [0; 6];
                    for (j, x) in v.iter_mut().enumerate() {
                        *x = get64(&b, 32 + i * 48 + j * 8);
                    }
                    out.insert(base | i as u64, v);
                }
            } else {
                if l == HEIGHT && i >= 16 {
                    ensure!(get64(&b, 32 + i * 8) == 0, "packed key overflow");
                    continue;
                }
                walk(
                    d,
                    get64(&b, 32 + i * 8),
                    l - 1,
                    base | ((i as u64) << (l as u32 * 6)),
                    out,
                    pages,
                )?;
            }
        }
        Ok(())
    }
    let (mut entries, mut pages) = (BTreeMap::new(), BTreeSet::new());
    walk(d, root, HEIGHT, 0, &mut entries, &mut pages)?;
    Ok((entries, pages))
}
