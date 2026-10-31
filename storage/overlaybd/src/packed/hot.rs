//! Verified immutable plaintext, bounded to 8 MiB. Object IDs never repeat
//! within an engine lifetime, including across relocation and pinned roots.
//! Streaming requests bypass admission so they cannot evict the small-read set.
use super::disk::PAGE;
use std::sync::{
    atomic::{AtomicU64, Ordering::Relaxed},
    Mutex,
};

const SETS: usize = 512;
const WAYS: usize = 4;
pub(super) const MAX_REQUEST: usize = 32 * PAGE;

struct Entry {
    id: u64,
    bytes: Box<[u8; PAGE]>,
}

pub(super) struct Cache {
    sets: Box<[Mutex<Vec<Entry>>]>,
    hits: AtomicU64,
    misses: AtomicU64,
    bytes: AtomicU64,
}
impl Default for Cache {
    fn default() -> Self {
        Self {
            sets: (0..SETS).map(|_| Mutex::new(Vec::new())).collect(),
            hits: 0.into(),
            misses: 0.into(),
            bytes: 0.into(),
        }
    }
}
impl Cache {
    fn set(&self, id: u64) -> &Mutex<Vec<Entry>> {
        &self.sets[(id as usize) % SETS]
    }
    pub fn get(&self, id: u64, dst: &mut [u8]) -> bool {
        let mut set = self.set(id).lock().unwrap();
        let Some(at) = set.iter().position(|entry| entry.id == id) else {
            self.misses.fetch_add(1, Relaxed);
            return false;
        };
        let entry = set.remove(at);
        dst.copy_from_slice(entry.bytes.as_slice());
        set.push(entry);
        self.hits.fetch_add(1, Relaxed);
        true
    }
    // Only call after decoding and checking the entire object's checksum.
    pub fn insert(&self, id: u64, bytes: &[u8]) {
        let mut set = self.set(id).lock().unwrap();
        if set.iter().any(|entry| entry.id == id) {
            return;
        }
        let mut entry = if set.len() == WAYS {
            set.remove(0)
        } else {
            self.bytes.fetch_add(PAGE as u64, Relaxed);
            Entry {
                id,
                bytes: Box::new([0; PAGE]),
            }
        };
        entry.id = id;
        entry.bytes.copy_from_slice(bytes);
        set.push(entry);
    }
    pub fn statistics(&self) -> (u64, u64, u64) {
        (
            self.hits.load(Relaxed),
            self.misses.load(Relaxed),
            self.bytes.load(Relaxed),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_lru_keeps_recent_collisions_and_never_aliases_ids() {
        let cache = Cache::default();
        let mut out = [0; PAGE];
        for id in 0..(SETS * WAYS) as u64 {
            cache.insert(id, &[id as u8; PAGE]);
        }
        assert!(cache.get(0, &mut out));
        cache.insert((SETS * WAYS) as u64, &[91; PAGE]);
        assert!(!cache.get(SETS as u64, &mut out));
        assert!(cache.get(0, &mut out));
        assert_eq!(out, [0; PAGE]);
        assert!(cache.get((SETS * WAYS) as u64, &mut out));
        assert_eq!(out, [91; PAGE]);
        for id in (SETS * WAYS)..(SETS * WAYS * 3) {
            cache.insert(id as u64, &[id as u8; PAGE]);
        }
        assert_eq!(cache.statistics().2, (SETS * WAYS * PAGE) as u64);
    }
}
