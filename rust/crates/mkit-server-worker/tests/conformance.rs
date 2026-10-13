//! The storage suite against the Workers stores, over simulated backends
//! (`common`): `DoNamespaceStore` through the real JSON wire into one
//! `SqlKvStore` per Durable Object on a simulated Durable Object
//! connection, and `R2BlobStore` over simulated R2. Zero declared skips.
//!
//! What this cannot prove (DO bindings are always local in `wrangler
//! dev`): placement, Cloudflare's own limits and point-in-time recovery.
//! M0-17's `wrangler dev` wire suite and, from M1, the staging runs cover
//! the real runtime.

mod common;

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use common::{DoConfig, Loopback, SimBucket, capacity_above_empty};
use mkit_server::Clock;
use mkit_server::NamespaceKey;
use mkit_server::{Batch, Key, NamespaceStore, Partition, RangeScan, Value};
use mkit_server_conformance::multipart_suite;
use mkit_server_conformance::storage::KvHarness;
use mkit_server_conformance::storage_suite;
use mkit_server_worker::ns_client::DoNamespaceStore;
use mkit_server_worker::r2::{PACKS_KEYSPACE, R2BlobStore};

/// Each store is a fresh set of Durable Objects under its own directory.
struct Workers {
    dir: tempfile::TempDir,
    next: AtomicU64,
}

impl Workers {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().expect("a temp dir"),
            next: AtomicU64::new(0),
        }
    }

    fn fresh(&self, config: DoConfig) -> DoNamespaceStore<Loopback> {
        let n = self.next.fetch_add(1, Ordering::Relaxed);
        let dir = self.dir.path().join(format!("deployment-{n}"));
        std::fs::create_dir_all(&dir).expect("a deployment dir");
        Loopback::store(dir, config)
    }
}

impl KvHarness for Workers {
    type Store = DoNamespaceStore<Loopback>;

    fn store(&self) -> Self::Store {
        self.fresh(DoConfig::default())
    }

    fn store_with_clock(&self, clock: Arc<dyn Clock>) -> Option<Self::Store> {
        Some(self.fresh(DoConfig {
            clock: Some(clock),
            ..DoConfig::default()
        }))
    }

    fn store_with_capacity(&self, bytes: u64) -> Option<Self::Store> {
        Some(self.fresh(capacity_above_empty(bytes)))
    }

    /// The same Durable Object databases, reopened after every handle
    /// dropped.
    fn open_at(&self, dir: &Path) -> Option<Self::Store> {
        Some(Loopback::store(dir.to_path_buf(), DoConfig::default()))
    }

    fn refresh_stats(&self, store: &Self::Store) -> impl Future<Output = ()> + Send {
        store.transport().clear_stats();
        async {}
    }
}

fn r2() -> R2BlobStore<SimBucket> {
    R2BlobStore::new(SimBucket::default(), PACKS_KEYSPACE)
}

storage_suite!(workers, kv = Workers::new(), blob = r2);
multipart_suite!(
    workers_r2_multipart,
    store = r2,
    heap = common::multipart_allocator::probe
);

/// The same simulated Workers wire stores with opt-in caching enabled.
struct CachedWorkers(Workers);

type CachedNamespace = mkit_server::store::CachingNamespaceStore<
    DoNamespaceStore<Loopback>,
    mkit_server::store::MemoryImmutableCache,
>;
type CachedBlob = mkit_server::store::CachingBlobStore<
    R2BlobStore<SimBucket>,
    mkit_server::store::MemoryImmutableCache,
>;

fn cache_config() -> mkit_server::store::CacheConfig {
    mkit_server::store::CacheConfig::new(
        "workers-conformance",
        Arc::new(mkit_server::ManualSleep::new()),
        std::time::Duration::from_millis(10),
    )
    .unwrap()
}

fn cache_backend() -> mkit_server::store::MemoryImmutableCache {
    mkit_server::store::MemoryImmutableCache::new(
        8 * 1024 * 1024,
        std::time::Duration::from_secs(60),
        Arc::new(mkit_server::ManualClock::new(0)),
    )
}

fn cached_namespace(store: DoNamespaceStore<Loopback>) -> CachedNamespace {
    mkit_server::store::CachingNamespaceStore::new(store, cache_backend(), cache_config())
}

impl KvHarness for CachedWorkers {
    type Store = CachedNamespace;

    fn store(&self) -> Self::Store {
        cached_namespace(self.0.store())
    }

    fn store_with_clock(&self, clock: Arc<dyn Clock>) -> Option<Self::Store> {
        self.0.store_with_clock(clock).map(cached_namespace)
    }

    fn store_with_capacity(&self, bytes: u64) -> Option<Self::Store> {
        self.0.store_with_capacity(bytes).map(cached_namespace)
    }

    fn open_at(&self, dir: &Path) -> Option<Self::Store> {
        self.0.open_at(dir).map(cached_namespace)
    }

    fn refresh_stats(&self, store: &Self::Store) -> impl Future<Output = ()> + Send {
        self.0.refresh_stats(store.inner())
    }
}

fn cached_r2() -> CachedBlob {
    mkit_server::store::CachingBlobStore::new(r2(), cache_backend(), cache_config())
}

storage_suite!(
    workers_cached,
    kv = CachedWorkers(Workers::new()),
    blob = cached_r2
);
multipart_suite!(
    workers_cached_multipart,
    store = cached_r2,
    heap = common::multipart_allocator::probe
);

#[test]
fn scan_many_real_json_wire_obeys_combined_reply_bytes() {
    use futures::executor::block_on;
    let workers = Workers::new();
    let store = workers.store();
    let partition = Partition::Namespace(NamespaceKey::deployment_default());
    let mut ranges = Vec::new();
    for n in 0..20u8 {
        let key = Key::new(vec![b'k', n]);
        block_on(store.apply(
            &partition,
            Batch::new().put(key.clone(), Value::new(vec![n; 512 * 1024])),
        ))
        .unwrap();
        ranges.push(RangeScan::new(
            key.clone(),
            Key::new(vec![b'k', n, 0xff]),
            None,
            1,
        ));
    }
    let pages = block_on(store.scan_many(&partition, &ranges)).unwrap();
    assert!(!pages.is_empty() && pages.len() < ranges.len());
    assert!(pages.iter().all(|page| page.entries.len() == 1));
    let bytes: usize = pages
        .iter()
        .flat_map(|page| &page.entries)
        .map(|(key, value)| key.as_bytes().len() + value.as_bytes().len())
        .sum();
    assert!(bytes <= mkit_server_worker::ns_object::MAX_PAGE_BYTES);
}

/// The blob cases again, with R2 answering failed conditions and 429s
/// before it reads the body.
fn r2_early() -> R2BlobStore<SimBucket> {
    R2BlobStore::new(SimBucket::default().answer_early(), PACKS_KEYSPACE)
}

storage_suite!(workers_r2_early, blob = r2_early);
