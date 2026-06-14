//! QueryCache — per-tenant hot-result cache.
//!
//! Caches query results in-process, keyed by (tenant_id, sql_sha256).
//! Invalidated when the underlying data or contract changes (or lazily via TTL).
//!
//! # Design
//!
//! * LRU eviction, bounded at max 256MB or 10k entries (whichever hits first).
//! * Per-tenant isolation: cache entries are prefixed with tenant_id, so one
//!   tenant can never read another tenant's cached results.
//! * TTL: 60 seconds (configurable). Entries older than the TTL are lazily
//!   evicted on next read.
//! * Contract change invalidation: the pool manager calls `invalidate_tenant`
//!   when T03 pushes a contract update for a tenant.
//! * Data change invalidation: the pool manager calls `invalidate_tenant` when
//!   T02 emits a catalog change event for a table the tenant accesses. (The
//!   fine-grained table-level invalidation is a future wave; for now we
//!   invalidate all entries for the tenant on any catalog event.)
//! * Does NOT survive engine restart. Stateless per-instance.
//!
//! # Thread safety
//!
//! The cache is wrapped in `Arc<Mutex<...>>` for shared access across the pool
//! workers. Each worker holds an `Arc<QueryCache>` clone.
//!
//! # Semantic Law
//!
//! * INV-2 (No read without satisfaction): cache entries are only stored AFTER
//!   the full enforcement pipeline (ContractCheckRule + RowFilter + Masking +
//!   DP noise). Cached results are already enforced.
//! * INV-1: a cache miss requires a new query — which goes through the full
//!   contract check.

use arrow::record_batch::RecordBatch;
use lru::LruCache;
use sha2::{Digest, Sha256};
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::{debug, info};

// ─── Cache entry ─────────────────────────────────────────────────────────────

/// A cached query result.
#[derive(Debug, Clone)]
struct CacheEntry {
    /// The enforced result batches.
    batches: Vec<RecordBatch>,
    /// Total byte size of the batches (approximate, for eviction budget tracking).
    byte_size: usize,
    /// When this entry was inserted.
    inserted_at: Instant,
    /// Attestation JWS for this result (signed by T05).
    attestation_jws: String,
}

// ─── Cache key ────────────────────────────────────────────────────────────────

/// Cache key: tenant_id + SHA-256 of the normalized SQL.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    tenant_id: String,
    sql_sha256: [u8; 32],
}

impl CacheKey {
    fn new(tenant_id: &str, sql: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(sql.as_bytes());
        let digest: [u8; 32] = hasher.finalize().into();
        Self {
            tenant_id: tenant_id.to_string(),
            sql_sha256: digest,
        }
    }
}

// ─── Configuration ────────────────────────────────────────────────────────────

/// QueryCache configuration.
#[derive(Debug, Clone)]
pub struct QueryCacheConfig {
    /// Maximum number of entries in the LRU. Default 10_000.
    pub max_entries: usize,
    /// Maximum total byte size of cached batches. Default 256MB.
    pub max_bytes: usize,
    /// Cache entry TTL in seconds. Default 60.
    pub ttl_secs: u64,
}

impl Default for QueryCacheConfig {
    fn default() -> Self {
        Self {
            max_entries: 10_000,
            max_bytes: 256 * 1024 * 1024, // 256MB
            ttl_secs: 60,
        }
    }
}

// ─── Cache ────────────────────────────────────────────────────────────────────

/// Per-tenant hot-result cache.
///
/// Wrapping the LruCache in a Mutex is intentional — concurrent cache access is
/// infrequent (pool workers fan out requests by tenant) and the critical section
/// is short (key lookup + clone bytes).
#[derive(Debug)]
pub struct QueryCache {
    inner: Mutex<CacheInner>,
    config: QueryCacheConfig,
}

#[derive(Debug)]
struct CacheInner {
    lru: LruCache<CacheKey, CacheEntry>,
    total_bytes: usize,
}

impl QueryCache {
    /// Create a new QueryCache with the given configuration.
    pub fn new(config: QueryCacheConfig) -> Arc<Self> {
        let max_entries = NonZeroUsize::new(config.max_entries.max(1)).unwrap();
        Arc::new(Self {
            inner: Mutex::new(CacheInner {
                lru: LruCache::new(max_entries),
                total_bytes: 0,
            }),
            config,
        })
    }

    /// Look up a cached result for (tenant_id, sql).
    ///
    /// Returns `None` if not cached, or if the entry has expired (TTL).
    /// Expired entries are lazily evicted.
    pub fn get(&self, tenant_id: &str, sql: &str) -> Option<(Vec<RecordBatch>, String)> {
        let key = CacheKey::new(tenant_id, sql);
        let mut inner = self.inner.lock().expect("query cache lock poisoned");
        let ttl = Duration::from_secs(self.config.ttl_secs);

        if let Some(entry) = inner.lru.get(&key) {
            if entry.inserted_at.elapsed() > ttl {
                // Expired — evict lazily.
                let byte_size = entry.byte_size;
                inner.lru.pop(&key);
                inner.total_bytes = inner.total_bytes.saturating_sub(byte_size);
                debug!(tenant_id, "query cache TTL eviction");
                return None;
            }
            debug!(tenant_id, "query cache hit");
            return Some((entry.batches.clone(), entry.attestation_jws.clone()));
        }

        None
    }

    /// Store a query result in the cache.
    ///
    /// If the cache is at capacity (by byte size), the LRU entry is evicted first.
    ///
    /// # Arguments
    ///
    /// * `tenant_id` — tenant context (for isolation).
    /// * `sql` — the SQL query string.
    /// * `batches` — the enforced result batches to cache.
    /// * `attestation_jws` — the T05-signed attestation JWS for this result.
    pub fn put(
        &self,
        tenant_id: &str,
        sql: &str,
        batches: Vec<RecordBatch>,
        attestation_jws: String,
    ) {
        let key = CacheKey::new(tenant_id, sql);
        let byte_size = estimate_batches_bytes(&batches);

        let mut inner = self.inner.lock().expect("query cache lock poisoned");

        // Evict until we have room by byte budget.
        while inner.total_bytes + byte_size > self.config.max_bytes && !inner.lru.is_empty() {
            if let Some((_, evicted)) = inner.lru.pop_lru() {
                inner.total_bytes = inner.total_bytes.saturating_sub(evicted.byte_size);
            }
        }

        let entry = CacheEntry {
            batches,
            byte_size,
            inserted_at: Instant::now(),
            attestation_jws,
        };
        inner.total_bytes += byte_size;
        inner.lru.put(key, entry);

        debug!(
            tenant_id,
            entry_bytes = byte_size,
            total_bytes = inner.total_bytes,
            "query cache put"
        );
    }

    /// Invalidate all cached entries for a tenant.
    ///
    /// Called when T03 pushes a contract update or T02 emits a catalog change
    /// event for the tenant.
    pub fn invalidate_tenant(&self, tenant_id: &str) {
        let mut inner = self.inner.lock().expect("query cache lock poisoned");

        let keys_to_remove: Vec<CacheKey> = inner
            .lru
            .iter()
            .filter(|(k, _)| k.tenant_id == tenant_id)
            .map(|(k, _)| k.clone())
            .collect();

        let count = keys_to_remove.len();
        for key in keys_to_remove {
            if let Some(entry) = inner.lru.pop(&key) {
                inner.total_bytes = inner.total_bytes.saturating_sub(entry.byte_size);
            }
        }

        if count > 0 {
            info!(tenant_id, count, "query cache tenant invalidation");
        }
    }

    /// Invalidate ALL cache entries across all tenants.
    ///
    /// Called on engine startup or when a global contract redeployment occurs.
    pub fn invalidate_all(&self) {
        let mut inner = self.inner.lock().expect("query cache lock poisoned");
        inner.lru.clear();
        inner.total_bytes = 0;
        info!("query cache full invalidation");
    }

    /// Return current cache statistics.
    pub fn stats(&self) -> CacheStats {
        let inner = self.inner.lock().expect("query cache lock poisoned");
        CacheStats {
            entry_count: inner.lru.len(),
            total_bytes: inner.total_bytes,
        }
    }
}

/// Cache statistics for Prometheus metrics export.
#[derive(Debug, Clone, Copy)]
pub struct CacheStats {
    /// Number of entries currently in the cache.
    pub entry_count: usize,
    /// Approximate total bytes of cached batch data.
    pub total_bytes: usize,
}

/// Estimate the in-memory byte size of a slice of RecordBatches.
///
/// This is an approximation based on buffer sizes. Exact measurement requires
/// deeper Arrow introspection; the approximation is sufficient for eviction budgeting.
fn estimate_batches_bytes(batches: &[RecordBatch]) -> usize {
    batches
        .iter()
        .flat_map(|b| b.columns().to_vec())
        .map(|c| {
            c.to_data()
                .buffers()
                .iter()
                .map(|buf| buf.len())
                .sum::<usize>()
        })
        .sum()
}
