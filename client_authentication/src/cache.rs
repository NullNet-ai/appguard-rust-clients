use nullnet_libappguard::appguard_commands::{FirewallDefaults, FirewallPolicy};
use std::collections::{BTreeMap, HashMap};

pub struct Cache {
    active: bool,
    entries: HashMap<CacheKey, FirewallPolicy>,
}

impl Cache {
    pub(crate) fn new(defaults: FirewallDefaults) -> Cache {
        Self {
            active: defaults.cache,
            entries: HashMap::new(),
        }
    }

    pub fn get(&self, key: &CacheKey) -> Option<&FirewallPolicy> {
        if self.active {
            self.entries.get(key)
        } else {
            None
        }
    }

    pub fn insert(&mut self, key: CacheKey, policy: FirewallPolicy) {
        if self.active {
            self.entries.insert(key, policy);
        }
    }
}

/// Data structure used by clients to create a cache entry for each request.
#[derive(PartialEq, Eq, Hash)]
pub struct CacheKey {
    pub original_url: String,
    pub method: String,
    pub query: BTreeMap<String, String>,
    pub headers: BTreeMap<String, String>,
    pub body: String,
    pub source_ip: String,
}
