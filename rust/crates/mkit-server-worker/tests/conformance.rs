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

/// The blob cases again, with R2 answering failed conditions and 429s
/// before it reads the body.
fn r2_early() -> R2BlobStore<SimBucket> {
    R2BlobStore::new(SimBucket::default().answer_early(), PACKS_KEYSPACE)
}

storage_suite!(workers_r2_early, blob = r2_early);
