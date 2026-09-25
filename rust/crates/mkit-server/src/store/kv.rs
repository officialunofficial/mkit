//! The key-level metadata contract (PRD §5.3): a partitioned, ordered
//! key-value store whose only write is one declarative [`Batch`].

use core::future::Future;

use bytes::Bytes;

use super::error::StoreError;
use super::keys;
use crate::repo::{NamespaceKey, RepoName};
use crate::rt::{MaybeSend, MaybeSync};

/// Longest accepted key, in bytes.
pub const MAX_KEY_BYTES: usize = 1024;
/// Longest accepted value, in bytes: below the Durable Object `SQLite` 2 MB
/// row limit.
pub const MAX_VALUE_BYTES: usize = 1024 * 1024;

/// A storage partition: one D34 shard. Everything that must commit
/// atomically lives in one partition. The core computes the partition of
/// every operation; a backend maps partitions to whatever it likes (a
/// Durable Object each, rows keyed by partition in `SQLite`, a qmdb
/// instance each).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Partition {
    /// The whole namespace: single-partition mode. Used by M0 (today's
    /// single `root` Durable Object) and by the ssh / fs-layout path for
    /// good; not by D34-sharded deployments.
    Namespace(NamespaceKey),
    /// D34 (M1): the namespace coordinator: config, the grant epoch and the
    /// table of currently epoch-leased shards. Rarely written.
    Coordinator(NamespaceKey),
    /// D34 (M1): one per (repo, ref). A branch's head and packmap share it
    /// (`shard_ref` is the `refs/heads/<x>` name). Strongly consistent.
    Ref {
        /// Namespace.
        ns: NamespaceKey,
        /// Repository.
        repo: RepoName,
        /// The ref whose shard this is.
        shard_ref: String,
    },
    /// D34 (M1): repo membership by object-id prefix over the fixed
    /// `INDEX_FANOUT` (default 4096). Never resharded; eventually
    /// consistent.
    RepoIndex {
        /// Namespace.
        ns: NamespaceKey,
        /// Repository.
        repo: RepoName,
        /// Object-id prefix bucket.
        prefix: u16,
    },
    /// D34 (M1): the ref-name index `ListRefs` reads, hash-sharded over the
    /// fixed `REF_INDEX_FANOUT` (default 16). Eventually consistent.
    RefIndex {
        /// Namespace.
        ns: NamespaceKey,
        /// Repository.
        repo: RepoName,
        /// Ref-name hash bucket.
        bucket: u16,
    },
    /// A global `ContentIndex` shard, by object-id prefix over
    /// `INDEX_FANOUT`.
    ContentShard(u16),
}

macro_rules! bytes_newtype {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
        pub struct $name(Bytes);

        impl $name {
            /// Wrap `bytes`.
            #[must_use]
            pub fn new(bytes: impl Into<Bytes>) -> Self {
                Self(bytes.into())
            }

            /// The raw bytes.
            #[must_use]
            pub fn as_bytes(&self) -> &[u8] {
                &self.0
            }

            /// The underlying buffer.
            #[must_use]
            pub fn into_bytes(self) -> Bytes {
                self.0
            }
        }
    };
}

bytes_newtype!(
    /// A key. Keys order by raw bytes; `store::keys` owns every layout.
    Key
);
bytes_newtype!(
    /// An opaque value. A backend never interprets it.
    Value
);
bytes_newtype!(
    /// An opaque scan cursor. Callers only pass back one that a
    /// [`NamespaceStore::scan`] returned for the same range.
    Cursor
);

/// A condition a [`Batch`] checks before it writes: raw key/byte checks,
/// not the ref CAS. A planner decides a ref write with
/// [`crate::refs::evaluate_condition`] on the value it read, then guards
/// that read here (`Absent` or `Equals` on the ref key) so the decision
/// still holds at commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Precondition {
    /// The key holds no value. `observed` on failure: the value it holds.
    Absent(Key),
    /// The key holds a value. `observed` on failure: `None`.
    Present(Key),
    /// The key holds exactly this value. `observed` on failure: the value
    /// it holds, if any.
    Equals(Key, Value),
    /// Commit deadline (Unix ms): the batch commits only if the backend's
    /// own clock, read inside the check-and-write step, is `<=` it. It
    /// names no key, so every store accepts it. `observed` on failure: the
    /// backend's clock reading as 8 big-endian bytes.
    NotAfter(u64),
}

/// A write in a [`Batch`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Write {
    /// Set the key's value.
    Put(Key, Value),
    /// Remove the key; removing an absent key is not an error.
    Delete(Key),
}

/// One atomic, declarative write: preconditions, then puts and deletes in
/// order (a later write to the same key wins). A batch with no writes only
/// checks.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Batch {
    /// Checked in order; the first failure aborts the batch.
    pub preconditions: Vec<Precondition>,
    /// Applied in order if every precondition holds.
    pub writes: Vec<Write>,
}

impl Batch {
    /// An empty batch.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a precondition.
    #[must_use]
    pub fn require(mut self, precondition: Precondition) -> Self {
        self.preconditions.push(precondition);
        self
    }

    /// Append a put.
    #[must_use]
    pub fn put(mut self, key: Key, value: Value) -> Self {
        self.writes.push(Write::Put(key, value));
        self
    }

    /// Append a delete.
    #[must_use]
    pub fn delete(mut self, key: Key) -> Self {
        self.writes.push(Write::Delete(key));
        self
    }

    /// Whether the batch adds data (holds a put): what a full partition
    /// rejects with [`StoreError::Full`].
    #[must_use]
    pub fn has_put(&self) -> bool {
        self.writes.iter().any(|w| matches!(w, Write::Put(..)))
    }

    /// Check the batch against the size limits and a store's capabilities,
    /// before anything is read or written. Every backend calls this first
    /// in [`NamespaceStore::apply`].
    ///
    /// # Errors
    /// [`StoreError::Invalid`] for a key over [`MAX_KEY_BYTES`] or a value
    /// over [`MAX_VALUE_BYTES`]; [`StoreError::Unsupported`] for a key
    /// outside `caps.key_classes`, or, without `atomic_multi_key`, more
    /// than one write or a key precondition on another key than the write.
    pub fn validate(&self, caps: &StoreCapabilities) -> Result<(), StoreError> {
        let mut keys = Vec::new();
        for pre in &self.preconditions {
            match pre {
                Precondition::Absent(k) | Precondition::Present(k) => keys.push((k, None)),
                Precondition::Equals(k, v) => keys.push((k, Some(v))),
                Precondition::NotAfter(_) => {}
            }
        }
        let key_preconditions = keys.len();
        for write in &self.writes {
            match write {
                Write::Put(k, v) => keys.push((k, Some(v))),
                Write::Delete(k) => keys.push((k, None)),
            }
        }
        for (key, value) in &keys {
            if key.as_bytes().len() > MAX_KEY_BYTES {
                return Err(StoreError::Invalid("key exceeds MAX_KEY_BYTES".into()));
            }
            if value.is_some_and(|v| v.as_bytes().len() > MAX_VALUE_BYTES) {
                return Err(StoreError::Invalid("value exceeds MAX_VALUE_BYTES".into()));
            }
            if caps.key_classes == KeyClasses::RefsOnly && !keys::is_ref_key(key) {
                return Err(StoreError::Unsupported(
                    "this store holds only ref keys".into(),
                ));
            }
        }
        if !caps.atomic_multi_key {
            let (pre, writes) = keys.split_at(key_preconditions);
            let one_key = match (pre, writes) {
                ([], [] | [_]) | ([_], []) => true,
                ([(p, _)], [(w, _)]) => p == w,
                _ => false,
            };
            if !one_key {
                return Err(StoreError::Unsupported(
                    "this store commits at most one key per batch".into(),
                ));
            }
        }
        Ok(())
    }
}

/// The result of [`NamespaceStore::apply`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BatchOutcome {
    /// Every precondition held and every write is durable.
    Committed,
    /// `preconditions[index]` failed; nothing was written.
    PreconditionFailed {
        /// Index of the first failing precondition.
        index: usize,
        /// What the store saw (see [`Precondition`]).
        observed: Option<Value>,
    },
}

/// One page of a [`NamespaceStore::scan`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ScanPage {
    /// Entries in ascending key order.
    pub entries: Vec<(Key, Value)>,
    /// Resume point, if the range may hold more entries.
    pub next: Option<Cursor>,
}

/// Which key classes (`store::keys`) a store accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyClasses {
    /// Every class.
    All,
    /// Refs only (the `r` class): `FsLayoutStore`.
    RefsOnly,
}

/// How repo membership of a pack is decided (overview Q16).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MembershipMode {
    /// A pack in the blob store is a member (M0).
    StorePresence,
    /// Only packs recorded by an `AdvanceRefs` apply are members (M1+).
    Explicit,
}

/// What a store supports. The pipeline plans around it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoreCapabilities {
    /// `false`: a batch holds at most one write, and at most one key
    /// precondition, on that same key (plus any `NotAfter`). The pipeline
    /// then issues sequential batches.
    pub atomic_multi_key: bool,
    /// Which key classes the store accepts.
    pub key_classes: KeyClasses,
    /// How membership is decided.
    pub membership: MembershipMode,
    /// The layout version of a store that cannot hold the `v` key
    /// (`RefsOnly`): its format is versioned elsewhere, and planners skip
    /// the layout-version precondition. `None` for stores that hold `v`.
    pub implicit_layout_version: Option<u32>,
}

impl StoreCapabilities {
    /// A full store: atomic multi-key batches over every class.
    #[must_use]
    pub const fn full() -> Self {
        Self {
            atomic_multi_key: true,
            key_classes: KeyClasses::All,
            membership: MembershipMode::StorePresence,
            implicit_layout_version: None,
        }
    }

    /// A refs-only, single-key store with an implicit layout version.
    #[must_use]
    pub const fn refs_only() -> Self {
        Self {
            atomic_multi_key: false,
            key_classes: KeyClasses::RefsOnly,
            membership: MembershipMode::StorePresence,
            implicit_layout_version: Some(keys::LAYOUT_VERSION),
        }
    }
}

/// Storage used by one partition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PartitionStats {
    /// Bytes used; may be approximate.
    pub bytes: u64,
    /// Number of keys, if the backend knows it cheaply.
    pub keys: Option<u64>,
}

/// The metadata store: a partitioned, ordered key-value store. Any backend
/// that can do an atomic conditional multi-key write per partition and an
/// ordered range read can implement it: SQL is not required.
///
/// # Normative rules
///
/// 1. **Declarative batch.** [`Self::apply`] is the only write. A backend
///    never evaluates CAS, quota or replay logic: the pipeline plans every
///    write and guards every value it read with a precondition. Size limits
///    ([`Batch::validate`]) are checked first, and a violation writes
///    nothing.
/// 2. **Reads are `get`, `has`, `get_many` and `scan`.** No other query
///    exists; every index is a key layout (`store::keys`).
/// 3. **Single writer is enough.** Nothing may assume two `apply` calls on
///    one partition run concurrently, and nothing may hold a lock across an
///    `.await` waiting for another `apply`. The pipeline handles contention
///    with an optimistic re-plan loop.
/// 4. **Cancellation safety.** Dropping an `apply` future at any `.await`
///    leaves the partition fully before or fully after the batch, and the
///    store usable: check-and-write runs in one non-yielding step (a
///    synchronous transaction that runs to completion even if the future is
///    dropped, a Durable Object `transactionSync`, a mutex held without
///    awaits). A poisoned lock is recovered, never propagated.
/// 5. **Durability.** `Committed` means durable to the level the backend
///    documents.
/// 6. **Atomicity scope.** One batch is one partition; nothing needs
///    atomicity across partitions. Cross-partition effects are ordered by
///    the pipeline or carried by outbox rows a core-owned relay delivers at
///    least once, idempotently. A backend needs nothing beyond this trait
///    and a way to run timers.
/// 7. **Bounded growth.** The core deletes what it no longer needs through
///    ordinary batches; a backend reclaims deleted keys and reports
///    [`Self::stats`]. At its cap it returns [`StoreError::Full`] for
///    batches that add data and keeps serving reads and deletes.
/// 8. **Commit deadline.** [`Precondition::NotAfter`] is evaluated against
///    the **backend's own clock** (the `SQLite` host's, the Durable
///    Object's, an injected one in memory), read once inside the same
///    non-yielding check-and-write step as the key checks, never the
///    caller's clock. A late batch therefore cannot commit after its
///    deadline, whenever it arrives. Callers allow for skew between their
///    clock and the backend's.
pub trait NamespaceStore: MaybeSend + MaybeSync {
    /// What this store supports.
    fn capabilities(&self) -> StoreCapabilities;

    /// The value at `key`, if any.
    fn get(
        &self,
        p: &Partition,
        key: &Key,
    ) -> impl Future<Output = Result<Option<Value>, StoreError>> + MaybeSend;

    /// Whether `key` holds a value.
    fn has(
        &self,
        p: &Partition,
        key: &Key,
    ) -> impl Future<Output = Result<bool, StoreError>> + MaybeSend {
        async move { Ok(self.get(p, key).await?.is_some()) }
    }

    /// Several keys in one round trip; results in input order. The default
    /// issues sequential [`Self::get`] calls.
    fn get_many(
        &self,
        p: &Partition,
        keys: &[Key],
    ) -> impl Future<Output = Result<Vec<Option<Value>>, StoreError>> + MaybeSend {
        async move {
            let mut values = Vec::with_capacity(keys.len());
            for key in keys {
                values.push(self.get(p, key).await?);
            }
            Ok(values)
        }
    }

    /// Up to `limit` (at least 1) entries in `[start, end)`, ascending by
    /// key bytes. `after` resumes strictly after the cursor's position.
    fn scan(
        &self,
        p: &Partition,
        start: &Key,
        end: &Key,
        after: Option<&Cursor>,
        limit: u32,
    ) -> impl Future<Output = Result<ScanPage, StoreError>> + MaybeSend;

    /// One atomic, all-or-nothing batch: validate it, read the backend
    /// clock once, check every precondition in order against committed
    /// state (`NotAfter` against that reading); on the first failure return
    /// [`BatchOutcome::PreconditionFailed`] and write nothing, otherwise
    /// apply every write and return [`BatchOutcome::Committed`].
    fn apply(
        &self,
        p: &Partition,
        batch: Batch,
    ) -> impl Future<Output = Result<BatchOutcome, StoreError>> + MaybeSend;

    /// Storage used by one partition; may be approximate or up to 60 s
    /// stale.
    fn stats(
        &self,
        p: &Partition,
    ) -> impl Future<Output = Result<PartitionStats, StoreError>> + MaybeSend;

    /// A cheap health check.
    fn probe(&self) -> impl Future<Output = Result<(), StoreError>> + MaybeSend;
}
