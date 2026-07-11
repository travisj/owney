//! TTL-respecting in-memory DNS record cache.
//!
//! Serves two purposes: in production it saves repeated TXT/PTR lookups for
//! busy senders, and in tests it lets fixture records be injected so the whole
//! verification stack runs with zero network access.

use std::borrow::Borrow;
use std::collections::HashMap;
use std::hash::Hash;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;
use std::time::Instant;

use mail_auth::common::resolver::ToFqdn;
use mail_auth::{MX, RecordSet, ResolverCache, Txt};

pub struct MemoryCache<K, V> {
    entries: Mutex<HashMap<K, (V, Instant)>>,
    capacity: usize,
}

impl<K, V> std::fmt::Debug for MemoryCache<K, V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryCache")
            .field("capacity", &self.capacity)
            .finish_non_exhaustive()
    }
}

impl<K: Eq + Hash, V: Clone> MemoryCache<K, V> {
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            capacity,
        }
    }
}

impl<K: Eq + Hash, V: Clone> ResolverCache<K, V> for MemoryCache<K, V> {
    fn get<Q>(&self, name: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let mut entries = self.entries.lock().ok()?;
        match entries.get(name) {
            Some((value, valid_until)) if *valid_until > Instant::now() => Some(value.clone()),
            Some(_) => {
                entries.remove(name);
                None
            }
            None => None,
        }
    }

    fn remove<Q>(&self, name: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.entries
            .lock()
            .ok()?
            .remove(name)
            .map(|(value, _)| value)
    }

    fn insert(&self, key: K, value: V, valid_until: Instant) {
        let Ok(mut entries) = self.entries.lock() else {
            return;
        };
        // Crude but effective bound: drop everything when full. DNS records
        // repopulate on demand; correctness never depends on cache contents.
        if entries.len() >= self.capacity {
            entries.clear();
        }
        entries.insert(key, (value, valid_until));
    }
}

/// The full cache set used by every verification call.
pub struct DnsCaches {
    pub txt: MemoryCache<Box<str>, Txt>,
    pub mx: MemoryCache<Box<str>, RecordSet<MX>>,
    pub ipv4: MemoryCache<Box<str>, RecordSet<Ipv4Addr>>,
    pub ipv6: MemoryCache<Box<str>, RecordSet<Ipv6Addr>>,
    pub ptr: MemoryCache<IpAddr, RecordSet<Box<str>>>,
}

impl DnsCaches {
    pub fn new() -> Self {
        Self {
            txt: MemoryCache::new(4096),
            mx: MemoryCache::new(1024),
            ipv4: MemoryCache::new(1024),
            ipv6: MemoryCache::new(1024),
            ptr: MemoryCache::new(1024),
        }
    }

    /// Test/fixture helper: inject a TXT record (SPF, DKIM key, DMARC policy).
    pub fn add_txt(&self, name: impl ToFqdn, value: impl Into<Txt>, ttl_secs: u64) {
        self.txt.insert(
            name.to_fqdn(),
            value.into(),
            Instant::now() + std::time::Duration::from_secs(ttl_secs),
        );
    }

    /// Test/fixture helper: inject a PTR record for FCrDNS.
    pub fn add_ptr(&self, ip: IpAddr, hostname: &str, ttl_secs: u64) {
        self.ptr.insert(
            ip,
            RecordSet {
                rrset: std::sync::Arc::from(vec![Box::from(hostname)].into_boxed_slice()),
                dnssec_status: mail_auth::DnssecStatus::Indeterminate,
            },
            Instant::now() + std::time::Duration::from_secs(ttl_secs),
        );
    }

    /// Test/fixture helper: inject an A record for the FCrDNS forward check.
    pub fn add_ipv4(&self, name: impl ToFqdn, addrs: Vec<Ipv4Addr>, ttl_secs: u64) {
        self.ipv4.insert(
            name.to_fqdn(),
            RecordSet {
                rrset: std::sync::Arc::from(addrs.into_boxed_slice()),
                dnssec_status: mail_auth::DnssecStatus::Indeterminate,
            },
            Instant::now() + std::time::Duration::from_secs(ttl_secs),
        );
    }
}

impl Default for DnsCaches {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for DnsCaches {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DnsCaches").finish_non_exhaustive()
    }
}
