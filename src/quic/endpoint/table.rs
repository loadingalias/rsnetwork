//! A fixed-capacity routing table. Deletion closes the probe chain, so churn leaves no tombstones.

#[cfg(test)]
mod tests;

use core::alloc::Layout;
use core::hash::{BuildHasher as _, Hash};

use rscrypto::SipRandomState;
use rstypes::capacity::{Budget, Permit};

use super::NO_ROOM;
use crate::drive::Error;

pub(super) fn array<T>(
    length: usize,
    budget: &Budget,
    make: impl FnMut(usize) -> T,
) -> Result<(Vec<T>, Permit), Error> {
    let layout = Layout::array::<T>(length).map_err(|_| NO_ROOM)?;
    let permit = budget.reserve(layout.size() as u64).map_err(|_| NO_ROOM)?;
    let mut entries = Vec::new();
    entries.try_reserve_exact(length).map_err(|_| NO_ROOM)?;
    entries.extend((0..length).map(make));
    Ok((entries, permit))
}

struct Entry<K, V> {
    hash: u64,
    key: K,
    value: V,
}

pub(super) struct Table<K, V> {
    slots: Vec<Option<Entry<K, V>>>,
    key: SipRandomState,
    _storage: Permit,
}

impl<K: Hash + Eq, V: Copy> Table<K, V> {
    pub(super) fn new(
        max: usize,
        fill: impl FnOnce(&mut [u8]) -> Result<(), rustls::crypto::GetRandomFailed>,
        budget: &Budget,
    ) -> Result<Self, Error> {
        let key = SipRandomState::try_new_with(fill).map_err(|_| super::RANDOM)?;
        let size = max
            .checked_mul(2)
            .and_then(usize::checked_next_power_of_two)
            .ok_or(NO_ROOM)?;
        let (slots, storage) = array(size, budget, |_| None)?;
        Ok(Self {
            slots,
            key,
            _storage: storage,
        })
    }

    fn home(&self, hash: u64) -> usize {
        usize::try_from(hash & (self.slots.len() - 1) as u64).expect("a masked index fits the table")
    }

    fn position(&self, hash: u64, matches: impl Fn(&K) -> bool) -> Option<usize> {
        let start = self.home(hash);
        let mask = self.slots.len() - 1;
        for distance in 0..self.slots.len() {
            let i = start.wrapping_add(distance) & mask;
            if self.slots[i].as_ref().is_none_or(|e| e.hash == hash && matches(&e.key)) {
                return Some(i);
            }
        }
        None
    }

    pub(super) fn get(&self, key: &K) -> Option<V> {
        self.checked(key, |found| found == key)
    }

    pub(super) fn checked(&self, key: &K, matches: impl Fn(&K) -> bool) -> Option<V> {
        self.slots[self.position(self.key.hash_one(key), matches)?]
            .as_ref()
            .map(|e| e.value)
    }

    pub(super) fn insert(&mut self, key: K, value: V) -> bool {
        let hash = self.key.hash_one(&key);
        let Some(i) = self.position(hash, |found| *found == key) else {
            return false;
        };
        if self.slots[i].is_some() {
            return false;
        }
        self.slots[i] = Some(Entry { hash, key, value });
        true
    }

    pub(super) fn remove(&mut self, key: &K) {
        let Some(mut hole) = self.position(self.key.hash_one(key), |found| found == key) else {
            return;
        };
        if self.slots[hole].take().is_none() {
            return;
        }
        let mask = self.slots.len() - 1;
        let mut i = hole;
        for _ in 0..self.slots.len() {
            i = i.wrapping_add(1) & mask;
            let Some(entry) = &self.slots[i] else { break };
            let home = self.home(entry.hash);
            if (hole.wrapping_sub(home) & mask) < (i.wrapping_sub(home) & mask) {
                self.slots[hole] = self.slots[i].take();
                hole = i;
            }
        }
    }
}
