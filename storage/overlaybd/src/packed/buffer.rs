//! Immutable plaintext slabs. A surviving block pins and charges the whole slab.
use super::{core::DIRTY_LIMIT, disk::PAGE};
use std::{
    ops::Deref,
    sync::{Arc, Mutex},
};
use tokio::sync::Notify;
#[derive(Default)]
struct State {
    used: usize,
    spare: Vec<Box<[u8]>>,
    spare_bytes: usize,
}
pub(super) struct Budget {
    state: Mutex<State>,
    notify: Arc<Notify>,
}
impl Budget {
    pub fn new(notify: Arc<Notify>) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State::default()),
            notify,
        })
    }
    pub fn used(&self) -> usize {
        self.state.lock().unwrap().used
    }
    pub fn reserve(self: &Arc<Self>, len: usize) -> Option<Lease> {
        let mut state = self.state.lock().unwrap();
        if state.used.checked_add(len)? > DIRTY_LIMIT {
            return None;
        }
        let spare = state
            .spare
            .iter()
            .rposition(|b| b.len() == len)
            .map(|i| state.spare.swap_remove(i));
        if spare.is_some() {
            state.spare_bytes -= len;
        }
        // Recycled buffers are included in the same allocation ceiling. Evict
        // incompatible sizes before admitting a new allocation.
        while state.used + state.spare_bytes + len > DIRTY_LIMIT {
            let old = state.spare.pop().unwrap();
            state.spare_bytes -= old.len();
        }
        state.used += len;
        Some(Lease {
            budget: self.clone(),
            len,
            spare,
        })
    }
}
pub(super) struct Lease {
    budget: Arc<Budget>,
    len: usize,
    spare: Option<Box<[u8]>>,
}
impl Drop for Lease {
    fn drop(&mut self) {
        let mut state = self.budget.state.lock().unwrap();
        state.used -= self.len;
        if let Some(bytes) = self.spare.take() {
            if state.spare.len() < 128 {
                state.spare_bytes += bytes.len();
                state.spare.push(bytes);
            }
        }
        debug_assert!(state.used + state.spare_bytes <= DIRTY_LIMIT);
        drop(state);
        self.budget.notify.notify_waiters();
    }
}
struct Slab {
    bytes: Box<[u8]>,
    lease: Option<Lease>,
}
impl Drop for Slab {
    fn drop(&mut self) {
        if let Some(lease) = &mut self.lease {
            lease.spare = Some(std::mem::take(&mut self.bytes));
        }
    }
}
#[derive(Clone)]
pub(super) struct Block {
    slab: Arc<Slab>,
    offset: usize,
}
impl Block {
    pub fn batch(bytes: &[u8], mut lease: Lease) -> impl Iterator<Item = Self> {
        assert_eq!(bytes.len(), lease.len);
        assert_eq!(bytes.len() % PAGE, 0);
        let len = bytes.len();
        let bytes = if let Some(mut spare) = lease.spare.take() {
            spare.copy_from_slice(bytes);
            spare
        } else {
            bytes.into()
        };
        let slab = Arc::new(Slab {
            bytes,
            lease: Some(lease),
        });
        (0..len).step_by(PAGE).map(move |offset| Self {
            slab: slab.clone(),
            offset,
        })
    }
}
impl From<Box<[u8; PAGE]>> for Block {
    fn from(bytes: Box<[u8; PAGE]>) -> Self {
        Self {
            slab: Arc::new(Slab { bytes, lease: None }),
            offset: 0,
        }
    }
}
impl Deref for Block {
    type Target = [u8; PAGE];
    fn deref(&self) -> &Self::Target {
        self.slab.bytes[self.offset..self.offset + PAGE]
            .try_into()
            .unwrap()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn recycled_storage_and_live_slabs_share_one_limit() {
        let budget = Budget::new(Arc::new(Notify::new()));
        let data = vec![7; PAGE * 32];
        let mut blocks: Vec<_> = Block::batch(&data, budget.reserve(data.len()).unwrap()).collect();
        let ptr = blocks[0].as_ptr();
        blocks.clear();
        let again: Vec<_> = Block::batch(&data, budget.reserve(data.len()).unwrap()).collect();
        assert_eq!(again[0].as_ptr(), ptr);
        drop(again);
        let all = budget.reserve(DIRTY_LIMIT).unwrap();
        assert_eq!(budget.state.lock().unwrap().spare_bytes, 0);
        assert!(budget.reserve(1).is_none());
        drop(all);
        assert_eq!(budget.used(), 0);
    }
    #[test]
    fn last_view_retains_entire_slab_budget() {
        let budget = Budget::new(Arc::new(Notify::new()));
        let data: Vec<_> = (0..PAGE * 32).map(|n| (n / PAGE) as u8).collect();
        let mut blocks: Vec<_> = Block::batch(&data, budget.reserve(data.len()).unwrap()).collect();
        let last = blocks.pop().unwrap();
        drop(blocks);
        assert_eq!(budget.used(), PAGE * 32);
        assert_eq!(*last, [31; PAGE]);
        let rest = budget.reserve(DIRTY_LIMIT - PAGE * 32).unwrap();
        assert!(budget.reserve(PAGE).is_none());
        drop(last);
        assert_eq!(budget.used(), DIRTY_LIMIT - PAGE * 32);
        let extra = budget.reserve(PAGE * 32).unwrap();
        drop((rest, extra));
        assert_eq!(budget.used(), 0);
    }
}
