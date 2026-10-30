//! In-memory COW indexes. Disk format and durable publication are unchanged.
//! A root clone shares chunks; updates copy only the chunks they touch.
use std::{collections::BTreeMap, ops::Index, sync::Arc};

#[derive(Clone, Default)]
pub(super) struct Map<V: Clone> {
    chunks: BTreeMap<u64, Arc<BTreeMap<u64, V>>>,
    len: usize,
}
impl<V: Clone> Map<V> {
    pub fn new() -> Self {
        Self {
            chunks: BTreeMap::new(),
            len: 0,
        }
    }
    pub fn len(&self) -> usize {
        self.len
    }
    pub fn get(&self, key: &u64) -> Option<&V> {
        self.chunks.get(&(key / 256))?.get(key)
    }
    pub fn contains_key(&self, key: &u64) -> bool {
        self.get(key).is_some()
    }
    pub fn get_mut(&mut self, key: &u64) -> Option<&mut V> {
        Arc::make_mut(self.chunks.get_mut(&(key / 256))?).get_mut(key)
    }
    pub fn insert(&mut self, key: u64, value: V) -> Option<V> {
        let old = Arc::make_mut(self.chunks.entry(key / 256).or_default()).insert(key, value);
        if old.is_none() {
            self.len += 1;
        }
        old
    }
    pub fn remove(&mut self, key: &u64) -> Option<V> {
        let chunk = self.chunks.get_mut(&(key / 256))?;
        let old = Arc::make_mut(chunk).remove(key);
        if old.is_some() {
            self.len -= 1;
        }
        if chunk.is_empty() {
            self.chunks.remove(&(key / 256));
        }
        old
    }
    pub fn iter(&self) -> impl Iterator<Item = (&u64, &V)> {
        self.chunks.values().flat_map(|c| c.iter())
    }
    pub fn values(&self) -> impl Iterator<Item = &V> {
        self.iter().map(|(_, v)| v)
    }
    pub fn keys(&self) -> impl Iterator<Item = &u64> {
        self.iter().map(|(k, _)| k)
    }
    pub fn after(&self, key: u64) -> impl Iterator<Item = (&u64, &V)> {
        self.chunks
            .range(key / 256..)
            .flat_map(|(_, c)| c.iter())
            .filter(move |(k, _)| **k > key)
    }
}
impl<V: Clone + Default> Map<V> {
    pub fn get_or_default(&mut self, key: u64) -> &mut V {
        let chunk = Arc::make_mut(self.chunks.entry(key / 256).or_default());
        match chunk.entry(key) {
            std::collections::btree_map::Entry::Occupied(e) => e.into_mut(),
            std::collections::btree_map::Entry::Vacant(e) => {
                self.len += 1;
                e.insert(V::default())
            }
        }
    }
}
impl<V: Clone> FromIterator<(u64, V)> for Map<V> {
    fn from_iter<T: IntoIterator<Item = (u64, V)>>(it: T) -> Self {
        let mut m = Self::new();
        for (k, v) in it {
            m.insert(k, v);
        }
        m
    }
}
impl<V: Clone> Index<&u64> for Map<V> {
    type Output = V;
    fn index(&self, key: &u64) -> &V {
        self.get(key).expect("missing COW map key")
    }
}

#[derive(Clone)]
struct Bits {
    words: [u64; 64],
    count: usize,
}
impl Default for Bits {
    fn default() -> Self {
        Self {
            words: [0; 64],
            count: 0,
        }
    }
}
#[derive(Clone, Default)]
pub(super) struct PageSet {
    chunks: BTreeMap<u64, Arc<Bits>>,
    len: usize,
}
fn bits(base: u64, mut word: u64) -> impl Iterator<Item = u64> {
    std::iter::from_fn(move || {
        if word == 0 {
            return None;
        }
        let bit = word.trailing_zeros() as u64;
        word &= word - 1;
        Some(base + bit)
    })
}
impl PageSet {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn len(&self) -> usize {
        self.len
    }
    pub fn contains(&self, p: &u64) -> bool {
        self.word(p / 64) & (1 << (p % 64)) != 0
    }
    fn word(&self, w: u64) -> u64 {
        self.chunks
            .get(&(w / 64))
            .map_or(0, |c| c.words[w as usize % 64])
    }
    pub fn insert(&mut self, p: u64) {
        let c = Arc::make_mut(self.chunks.entry(p / 4096).or_default());
        let w = &mut c.words[(p / 64) as usize % 64];
        let bit = 1 << (p % 64);
        if *w & bit == 0 {
            *w |= bit;
            c.count += 1;
            self.len += 1;
        }
    }
    pub fn remove(&mut self, p: &u64) {
        if !self.contains(p) {
            return;
        }
        let c = Arc::make_mut(self.chunks.get_mut(&(p / 4096)).unwrap());
        c.words[(p / 64) as usize % 64] &= !(1 << (p % 64));
        c.count -= 1;
        self.len -= 1;
        if c.count == 0 {
            self.chunks.remove(&(p / 4096));
        }
    }
    pub fn union(&mut self, other: &Self) {
        for (&key, source) in &other.chunks {
            if let Some(dest) = self.chunks.get_mut(&key) {
                if Arc::ptr_eq(dest, source) {
                    continue;
                }
                let dest = Arc::make_mut(dest);
                let before = dest.count;
                for (d, s) in dest.words.iter_mut().zip(source.words) {
                    *d |= s;
                }
                dest.count = dest.words.iter().map(|w| w.count_ones() as usize).sum();
                self.len += dest.count - before;
            } else {
                self.chunks.insert(key, source.clone());
                self.len += source.count;
            }
        }
    }
    pub fn difference_count(&self, other: &Self) -> usize {
        self.chunks
            .iter()
            .map(|(&key, c)| match other.chunks.get(&key) {
                Some(o) if Arc::ptr_eq(c, o) => 0,
                Some(o) => c
                    .words
                    .iter()
                    .zip(o.words)
                    .map(|(a, b)| (a & !b).count_ones() as usize)
                    .sum(),
                None => c.count,
            })
            .sum()
    }
    pub fn holes(&self, end: u64) -> impl Iterator<Item = u64> + '_ {
        (0..end.div_ceil(64)).flat_map(move |w| {
            let valid = if end - w * 64 < 64 {
                (1 << (end - w * 64)) - 1
            } else {
                u64::MAX
            };
            bits(w * 64, !self.word(w) & valid)
        })
    }
}
impl Extend<u64> for PageSet {
    fn extend<T: IntoIterator<Item = u64>>(&mut self, it: T) {
        for p in it {
            self.insert(p);
        }
    }
}
impl FromIterator<u64> for PageSet {
    fn from_iter<T: IntoIterator<Item = u64>>(it: T) -> Self {
        let mut s = Self::new();
        s.extend(it);
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cow_chunks_preserve_old_roots_and_match_standard_collections() {
        let mut map = Map::new();
        let mut reference = BTreeMap::new();
        let mut pages = PageSet::new();
        let mut set = std::collections::BTreeSet::new();
        let mut seed = 7u64;
        for round in 0..20 {
            let old = map.clone();
            let old_ref = reference.clone();
            let old_pages = pages.clone();
            let old_set = set.clone();
            for _ in 0..1000 {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                let k = (seed >> 32) % 20000;
                if seed & 1 == 0 {
                    map.insert(k, round);
                    reference.insert(k, round);
                    pages.insert(k);
                    set.insert(k);
                } else {
                    map.remove(&k);
                    reference.remove(&k);
                    pages.remove(&k);
                    set.remove(&k);
                }
            }
            assert_eq!(
                map.iter()
                    .map(|(&k, &v)| (k, v))
                    .collect::<BTreeMap<_, _>>(),
                reference
            );
            assert_eq!(
                old.iter()
                    .map(|(&k, &v)| (k, v))
                    .collect::<BTreeMap<_, _>>(),
                old_ref
            );
            assert_eq!(pages.len(), set.len());
            assert_eq!(
                pages.holes(20000).collect::<Vec<_>>(),
                (0..20000).filter(|p| !set.contains(p)).collect::<Vec<_>>()
            );
            assert_eq!(
                old_pages.difference_count(&pages),
                old_set.difference(&set).count()
            );
            let mut union = old_pages;
            union.union(&pages);
            assert_eq!(union.len(), old_set.union(&set).count());
        }
    }
}
