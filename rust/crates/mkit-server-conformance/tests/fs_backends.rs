//! The storage suite against the `.mkit`-layout stores (`mkit-server`'s
//! `fs` feature): `FsBlobStore` runs every blob case; `FsLayoutStore`
//! (`RefsOnly`, single-key) runs every kv and durability case its
//! capabilities allow, with an injected clock and a persistent reopen.
//!
//! An `FsLayoutStore` holds one partition, so the harness routes each
//! partition a case uses to its own store in its own directory, as an FS
//! deployment that needed several partitions would. Reopening a directory
//! builds fresh stores over the same files: a crash without shutdown.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use mkit_server::fs::{FsBlobStore, FsLayoutStore, FsPackSink};
use mkit_server::{
    Batch, BatchOutcome, BlobBody, BlobKey, BlobMeta, BlobStore, ByteRange, Clock, Cursor, Key,
    NamespaceStore, Partition, PartitionStats, RepoName, ScanPage, StoreCapabilities, StoreError,
    Value,
};
use mkit_server_conformance::storage::KvHarness;
use mkit_server_conformance::storage_suite;

/// A fresh directory under the system temp dir, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let name = format!("mkit-fs-{tag}-{}-{n}", std::process::id());
        let dir = std::env::temp_dir().join(name);
        std::fs::create_dir_all(&dir).expect("create a temp dir");
        Self(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The repo every suite key names (`r 00 conformance 00 …`).
fn repo() -> RepoName {
    RepoName::new("conformance").expect("a valid repo name")
}

/// `FsLayoutStore`s: the host clock or an injected one, and a persistent
/// reopen. No capacity cap: a filesystem has none of its own.
struct Fs;

/// One `FsLayoutStore` per partition, each rooted at
/// `<base>/<hex(partition encoding)>`.
struct Routed {
    base: PathBuf,
    clock: Option<Arc<dyn Clock>>,
    stores: Mutex<HashMap<Partition, Arc<FsLayoutStore>>>,
    _owned: Option<TempDir>,
}

impl Routed {
    fn new(base: PathBuf, clock: Option<Arc<dyn Clock>>, owned: Option<TempDir>) -> Self {
        Self {
            base,
            clock,
            stores: Mutex::default(),
            _owned: owned,
        }
    }

    fn fresh(clock: Option<Arc<dyn Clock>>) -> Self {
        let dir = TempDir::new("layout");
        Self::new(dir.0.clone(), clock, Some(dir))
    }

    /// The store of partition `p`, created on first use.
    fn at(&self, p: &Partition) -> Result<Arc<FsLayoutStore>, StoreError> {
        let mut stores = self.stores.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(store) = stores.get(p) {
            return Ok(store.clone());
        }
        let mut name = String::new();
        for byte in &p.encode()? {
            let _ = write!(name, "{byte:02x}");
        }
        let root = self.base.join(name);
        std::fs::create_dir_all(&root).map_err(StoreError::unavailable)?;
        let mut store = FsLayoutStore::in_partition(root, p.clone(), repo());
        if let Some(clock) = &self.clock {
            store = store.with_clock(clock.clone());
        }
        let store = Arc::new(store);
        stores.insert(p.clone(), store.clone());
        Ok(store)
    }
}

impl KvHarness for Fs {
    type Store = Routed;

    fn store(&self) -> Routed {
        Routed::fresh(None)
    }

    fn store_with_clock(&self, clock: Arc<dyn Clock>) -> Option<Routed> {
        Some(Routed::fresh(Some(clock)))
    }

    fn open_at(&self, dir: &Path) -> Option<Routed> {
        Some(Routed::new(dir.to_path_buf(), None, None))
    }

    fn expected_skips(&self) -> &'static [&'static str] {
        SKIPS
    }
}

impl NamespaceStore for Routed {
    fn capabilities(&self) -> StoreCapabilities {
        StoreCapabilities::refs_only()
    }

    async fn get(&self, p: &Partition, key: &Key) -> Result<Option<Value>, StoreError> {
        self.at(p)?.get(p, key).await
    }

    async fn scan(
        &self,
        p: &Partition,
        start: &Key,
        end: &Key,
        after: Option<&Cursor>,
        limit: u32,
    ) -> Result<ScanPage, StoreError> {
        self.at(p)?.scan(p, start, end, after, limit).await
    }

    async fn apply(&self, p: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
        self.at(p)?.apply(p, batch).await
    }

    async fn stats(&self, p: &Partition) -> Result<PartitionStats, StoreError> {
        self.at(p)?.stats(p).await
    }

    async fn probe(&self) -> Result<(), StoreError> {
        match std::fs::metadata(&self.base) {
            Ok(meta) if meta.is_dir() => Ok(()),
            Ok(_) => Err(StoreError::unavailable("the base is not a directory")),
            Err(e) => Err(StoreError::unavailable(e)),
        }
    }
}

/// What a refs-only, single-key store cannot run (as the memory
/// `RefsOnly` store), plus the capacity case: a filesystem has no cap of
/// its own, so it never returns `Full`.
const SKIPS: &[&str] = &[
    "kv_first_failing_precondition_index",
    "kv_failed_batch_writes_nothing",
    "kv_put_delete_same_key_last_write_wins",
    "kv_batch_limits_invalid",
    "kv_layout_version_key_roundtrip",
    "kv_class_tags_are_zero_terminated",
    "kv_full_store_rejects_writes_but_serves_reads_and_deletes",
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

/// An `FsBlobStore` in a temp dir it removes when dropped.
struct TempBlobs {
    store: FsBlobStore,
    _dir: TempDir,
}

fn temp_blobs() -> TempBlobs {
    let dir = TempDir::new("blobs");
    TempBlobs {
        store: FsBlobStore::new(dir.0.clone()),
        _dir: dir,
    }
}

impl BlobStore for TempBlobs {
    type Sink = FsPackSink;

    async fn begin(&self, key: BlobKey, len: u64) -> Result<FsPackSink, StoreError> {
        self.store.begin(key, len).await
    }

    async fn get(
        &self,
        key: &BlobKey,
        range: Option<ByteRange>,
    ) -> Result<Option<BlobBody>, StoreError> {
        self.store.get(key, range).await
    }

    async fn head(&self, key: &BlobKey) -> Result<Option<BlobMeta>, StoreError> {
        self.store.head(key).await
    }

    async fn probe(&self) -> Result<(), StoreError> {
        self.store.probe().await
    }

    async fn delete(&self, key: &BlobKey) -> Result<bool, StoreError> {
        self.store.delete(key).await
    }
}

storage_suite!(fs, kv = Fs, blob = temp_blobs);
