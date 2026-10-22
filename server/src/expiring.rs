//! Short-lived entries kept in memory (sign-ins in progress, verified credentials, spent
//! challenges): each one is dropped when its time is up, and only so many can wait at once.

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use parking_lot::Mutex;

pub struct Expiring<V> {
    ttl: Duration,
    capacity: usize,
    /// key → (value, deadline).
    entries: Mutex<HashMap<String, (V, Instant)>>,
}

impl<V> Expiring<V> {
    pub fn new(ttl: Duration, capacity: usize) -> Self {
        Expiring { ttl, capacity, entries: Mutex::new(HashMap::new()) }
    }

    /// Adds an entry that lives for the TTL. Refused (`false`) when the key is already there
    /// or the map is full of live entries.
    pub fn insert(&self, key: String, value: V) -> bool {
        self.insert_until(key, value, Instant::now() + self.ttl)
    }

    /// [`Self::insert`] with a deadline of its own.
    pub fn insert_until(&self, key: String, value: V, deadline: Instant) -> bool {
        self.insert_limited(key, value, deadline, |_| false, 0)
    }

    /// [`Self::insert_until`], also refused when `per_group` live entries already satisfy
    /// `same_group` (for example: opened from the same network).
    pub fn insert_limited(&self, key: String, value: V, deadline: Instant, same_group: impl Fn(&V) -> bool, per_group: usize) -> bool {
        let mut entries = self.entries.lock();
        let now = Instant::now();
        entries.retain(|_, (_, until)| *until > now);
        if entries.len() >= self.capacity || entries.contains_key(&key) || (per_group > 0 && entries.values().filter(|(v, _)| same_group(v)).count() >= per_group) {
            return false;
        }
        entries.insert(key, (value, deadline));
        true
    }

    /// The live entry under `key`.
    pub fn get(&self, key: &str) -> Option<V>
    where
        V: Clone,
    {
        self.entries.lock().get(key).filter(|(_, until)| *until > Instant::now()).map(|(value, _)| value.clone())
    }

    /// Removes the entry under `key` and returns it if it was still live.
    pub fn take(&self, key: &str) -> Option<V> {
        self.entries.lock().remove(key).filter(|(_, until)| *until > Instant::now()).map(|(value, _)| value)
    }

    /// Changes the live entry under `key` in place.
    pub fn update<R>(&self, key: &str, change: impl FnOnce(&mut V) -> R) -> Option<R> {
        self.entries.lock().get_mut(key).filter(|(_, until)| *until > Instant::now()).map(|(value, _)| change(value))
    }

    pub fn remove(&self, key: &str) {
        self.entries.lock().remove(key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entries_expire_and_are_bounded() {
        let map = Expiring::new(Duration::from_secs(60), 2);
        assert!(map.insert("a".into(), 1));
        assert!(!map.insert("a".into(), 2), "the key is taken");
        assert!(map.insert_until("b".into(), 2, Instant::now()));
        assert_eq!(map.get("b"), None, "expired");
        assert!(map.insert("c".into(), 3), "the expired entry made room");
        assert!(!map.insert("d".into(), 4), "full");
        assert_eq!(map.update("a", |v| { *v += 10; *v }), Some(11));
        assert_eq!(map.take("a"), Some(11));
        assert_eq!(map.get("a"), None);

        let groups = Expiring::new(Duration::from_secs(60), 10);
        let later = Instant::now() + Duration::from_secs(60);
        assert!(groups.insert_limited("1".into(), "net", later, |v| *v == "net", 1));
        assert!(!groups.insert_limited("2".into(), "net", later, |v| *v == "net", 1));
        assert!(groups.insert_limited("3".into(), "other", later, |v| *v == "other", 1));
    }
}
