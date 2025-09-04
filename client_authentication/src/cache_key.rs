use std::collections::BTreeMap;

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
