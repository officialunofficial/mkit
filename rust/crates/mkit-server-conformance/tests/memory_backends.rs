//! The storage suite against the in-memory reference backends: a
//! full-capability store, a reduced-capability (`RefsOnly`, single-key)
//! store, and a memory store that outlives its handles so the crash/restart
//! case runs too.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use mkit_server::{
    Batch, BatchOutcome, Clock, Cursor, Key, MemoryBlobStore, MemoryKv, NamespaceStore, Partition,
    PartitionStats, ScanPage, StoreCapabilities, StoreError, Value,
};
use mkit_server_conformance::storage::KvHarness;
use mkit_server_conformance::storage_suite;

/// Full-capability [`MemoryKv`]s with an injectable clock and a capacity cap.
struct Full;

impl KvHarness for Full {
    type Store = MemoryKv;

    fn store(&self) -> MemoryKv {
        MemoryKv::default()
    }

    fn store_with_clock(&self, clock: Arc<dyn Clock>) -> Option<MemoryKv> {
        Some(MemoryKv::with_clock(clock))
    }

    fn store_with_capacity(&self, bytes: u64) -> Option<MemoryKv> {
        Some(MemoryKv::default().with_capacity_limit(bytes))
    }
}

/// Refs-only, one-key-per-batch [`MemoryKv`]s (the `FsLayoutStore` shape).
struct RefsOnly;

impl KvHarness for RefsOnly {
    type Store = MemoryKv;

    fn store(&self) -> MemoryKv {
        MemoryKv::new(StoreCapabilities::refs_only())
    }

    fn store_with_clock(&self, clock: Arc<dyn Clock>) -> Option<MemoryKv> {
        Some(MemoryKv::with_clock(clock).with_capabilities(StoreCapabilities::refs_only()))
    }

    fn store_with_capacity(&self, bytes: u64) -> Option<MemoryKv> {
        Some(self.store().with_capacity_limit(bytes))
    }
}

/// Memory stores kept per directory: `open_at` hands out a new handle on
/// the rows of `dir`, so dropping every handle (and any in-flight apply)
/// then reopening models a crash without shutdown.
struct Persistent;

/// A handle on a [`Persistent`] store.
struct Handle(Arc<MemoryKv>);

fn stores() -> &'static Mutex<HashMap<PathBuf, Arc<MemoryKv>>> {
    static STORES: OnceLock<Mutex<HashMap<PathBuf, Arc<MemoryKv>>>> = OnceLock::new();
    STORES.get_or_init(Mutex::default)
}

impl KvHarness for Persistent {
    type Store = Handle;

    fn store(&self) -> Handle {
        Handle(Arc::new(MemoryKv::default()))
    }

    fn open_at(&self, dir: &Path) -> Option<Handle> {
        let mut stores = stores().lock().unwrap_or_else(PoisonError::into_inner);
        Some(Handle(stores.entry(dir.to_path_buf()).or_default().clone()))
    }
}

impl NamespaceStore for Handle {
    fn capabilities(&self) -> StoreCapabilities {
        self.0.capabilities()
    }

    async fn get(&self, p: &Partition, key: &Key) -> Result<Option<Value>, StoreError> {
        self.0.get(p, key).await
    }

    async fn scan(
        &self,
        p: &Partition,
        start: &Key,
        end: &Key,
        after: Option<&Cursor>,
        limit: u32,
    ) -> Result<ScanPage, StoreError> {
        self.0.scan(p, start, end, after, limit).await
    }

    async fn apply(&self, p: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
        self.0.apply(p, batch).await
    }

    async fn stats(&self, p: &Partition) -> Result<PartitionStats, StoreError> {
        self.0.stats(p).await
    }

    async fn probe(&self) -> Result<(), StoreError> {
        self.0.probe().await
    }
}

storage_suite!(memory, kv = Full, blob = MemoryBlobStore::default);
storage_suite!(memory_refs_only, kv = RefsOnly);
storage_suite!(memory_persistent, kv = Persistent);
