//! The storage suite against the in-memory reference backends: a
//! full-capability store (no skips) and a reduced-capability (`RefsOnly`,
//! single-key) store that skips exactly its capability-gated cases. Stores
//! are kept per `open_at` id and outlive their handles, so dropping every
//! handle and reopening models a crash without shutdown.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use mkit_server::{
    Batch, BatchOutcome, Clock, Cursor, Key, MemoryBlobStore, MemoryKv, NamespaceStore, Partition,
    PartitionStats, ScanPage, StoreCapabilities, StoreError, Value,
};
use mkit_server_conformance::storage::KvHarness;
use mkit_server_conformance::storage_suite;

/// [`MemoryKv`]s with `caps`: injectable clock, capacity cap and reopen.
struct Memory {
    caps: StoreCapabilities,
    skips: &'static [&'static str],
}

/// A handle on a memory store; handles opened at one id share its rows.
struct Handle(Arc<MemoryKv>);

fn stores() -> &'static Mutex<HashMap<PathBuf, Arc<MemoryKv>>> {
    static STORES: OnceLock<Mutex<HashMap<PathBuf, Arc<MemoryKv>>>> = OnceLock::new();
    STORES.get_or_init(Mutex::default)
}

impl KvHarness for Memory {
    type Store = Handle;

    fn store(&self) -> Handle {
        Handle(Arc::new(MemoryKv::new(self.caps)))
    }

    fn store_with_clock(&self, clock: Arc<dyn Clock>) -> Option<Handle> {
        let kv = MemoryKv::with_clock(clock).with_capabilities(self.caps);
        Some(Handle(Arc::new(kv)))
    }

    fn store_with_capacity(&self, bytes: u64) -> Option<Handle> {
        let kv = MemoryKv::new(self.caps).with_capacity_limit(bytes);
        Some(Handle(Arc::new(kv)))
    }

    fn open_at(&self, dir: &Path) -> Option<Handle> {
        let mut stores = stores().lock().unwrap_or_else(PoisonError::into_inner);
        let kv = stores
            .entry(dir.to_path_buf())
            .or_insert_with(|| Arc::new(MemoryKv::new(self.caps)));
        Some(Handle(kv.clone()))
    }

    fn expected_skips(&self) -> &'static [&'static str] {
        self.skips
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

/// What a refs-only, single-key store cannot run.
const REFS_ONLY_SKIPS: &[&str] = &[
    "kv_first_failing_precondition_index",
    "kv_failed_batch_writes_nothing",
    "kv_put_delete_same_key_last_write_wins",
    "kv_batch_limits_invalid",
    "kv_layout_version_key_roundtrip",
    "kv_class_tags_are_zero_terminated",
    "idx_holder_add_idempotent",
    "idx_holder_remove",
    "idx_holders_pagination",
    "idx_hold_blocks_collection",
    "idx_expired_hold_allows_collection",
    "idx_grace_period",
    "idx_block_unblock",
    "idx_objects_in_different_shards_isolated",
    "idx_gc_commit_then_add_hold_unavailable",
    "idx_blocked_on_add",
    "idx_hold_extension_keeps_max",
    "idx_expired_holds_pruned_on_mutation",
];

storage_suite!(
    memory,
    kv = Memory {
        caps: StoreCapabilities::full(),
        skips: &[],
    },
    blob = MemoryBlobStore::default,
);
storage_suite!(
    memory_refs_only,
    kv = Memory {
        caps: StoreCapabilities::refs_only(),
        skips: REFS_ONLY_SKIPS,
    },
);
