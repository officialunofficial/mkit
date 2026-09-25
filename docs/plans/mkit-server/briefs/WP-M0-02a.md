# WP-M0-02a: Storage contract core (key-level `NamespaceStore` with `NotAfter` deadlines, key layouts, codecs, `BlobStore`), replay-ledger model, in-memory reference backends

- **Milestone/track:** M0
- **Base:** `feat/mkit-server`; **branch:** `mkit-server/wp-m0-02a-storage-contract`
- **Depends on:** M0-01
- **Size:** L (~1000–1250 lines; roughly 45% tests)
- **Reconciliation:** rewritten for the backend-agnostic storage contract (00-plan.md R-16..R-24). Review 01 split the
  former WP-M0-02 into this WP and WP-M0-02b (R-72), added the time-bounded `NotAfter` precondition (R-61), the
  `0x00` terminator after every key-class tag, the `RefsOnly` layout-version rule (R-82) and `StoreError::Full`
  (R-83). The earlier semantic `Mutation` (replay intent + quota charges + ref CAS evaluated inside the store) is
  replaced by a declarative key-level `Batch`; the semantics move into pure planners that the pipeline (M0-05a) runs.

## Conventions

Same as WP-M0-01 "Conventions": TMPDIR, trailer, no CI polling, no proto change, a size check, workspace lints.

## Goal

Settle the design everything later builds on (PRD §8 M0), in a form any backend can implement, including a non-SQL,
single-writer key-value store (e.g. commonware qmdb in a Rust container), without a trait change:

1. The **storage contract**:
   - `NamespaceStore`: a partitioned, ordered key-value store whose only write is one atomic, declarative
     `apply(partition, Batch)` of preconditions plus puts and deletes. Preconditions are key-level (`Absent`,
     `Present`, `Equals`) plus one time-bounded kind, **`NotAfter(deadline_ms)`, evaluated against the backend's own
     clock at apply time**. Reads are `get`, `has`, `get_many` and an ordered range `scan` with an opaque cursor. No
     SQL, no interactive transactions, no store-side business logic.
   - **Key layouts** (`store/keys.rs`): every row and every index the server needs (refs and `list_refs`, the replay
     ledger and its expiry, quota windows, the grant epoch, timers, the layout version, and the reserved later rows)
     spelled out as key byte layouts, not queries.
   - `BlobStore` + `PackSink` (content-addressed, verify-before-visible, put-if-absent, streaming), because the
     pipeline (M0-05a) is generic over it.
2. The **replay-ledger state model**: fingerprint, `in_flight`/`committed`, stored result, and "never store
   challenges or pending_verification", as a pure classification function plus a value codec.

Also provide the in-memory reference backends (`MemoryKv`, a `BTreeMap`, and `MemoryBlobStore`), which are the
template for third-party backends.

**Not here (WP-M0-02b):** the `ContentIndex` layer, portable export/import, and the optional `StoreMaintenance` /
`StateCommitment` hooks. Nothing in the M0 pipeline needs them, which keeps M0-02b off the critical path.

## PRD refs

§5.3 (all of it: "Custom backends must provide (a) strong consistency and an atomic multi-row write per shard …";
the epoch-lease commit deadline; "every shard reports its storage size"; `SQLITE_FULL` at the cap), §5.4 stages 0
and 4, "Lifecycle per RPC" (key layouts only), §6.2 membership rule, D2, D10, D12, D15, D28, D34. Overview Q5
(resume), Q14 (quota scope), Q16 (membership mode).

## Scope

**IN:** `store` module (contract incl. `NotAfter`, key layouts, codecs, typed readers, `BlobStore` trait, errors),
`replay` module, `memory` module (`MemoryKv` implementing `NamespaceStore`, `MemoryBlobStore`) behind a `memory`
cargo feature (also enabled in dev-deps). Unit tests.

**OUT:** `ContentIndex`, export/import, optional hooks (M0-02b); the planners that turn an RPC into a `Batch`
(M0-05a); FS/SQL/S3/R2/DO backends (M0-08/09/11/16); the generic conformance suite (M0-03; this WP writes focused
unit tests); outbox *delivery* (M3); timers *execution* (WP-1.24; only the key layout is reserved here); multipart
sessions (WP-1.11 adds a `MultipartBlobStore` sub-trait); per-branch published pointers (WP-5.4 adds the layout).

## Files and symbols

Create in `rust/crates/mkit-server/src/`:
- `store/mod.rs` (re-exports), `store/kv.rs` (the contract), `store/keys.rs` (layouts), `store/codec.rs` (value
  codecs), `store/read.rs` (typed readers), `store/blob.rs`, `store/error.rs`
- `replay.rs`
- `memory/mod.rs`, `memory/kv.rs`, `memory/blob.rs`

Modify:
- `rust/crates/mkit-server/Cargo.toml`: feature `memory = []`; normal deps `serde = { version = "1", features =
  ["derive"] }` and `serde_json = "1"` (the value codec needs them on every target, so they are not optional);
  dev-deps enable `memory`.
- `src/lib.rs`: modules and re-exports.

Reference behaviors to encode (read these; don't copy them into the contract):
- `apps/vcs-worker/src/worker_impl/refstore.rs:215-274` (`handle_advance`: evaluate the packmap CAS first, then the
  head; a conflict leaves both untouched). With the new contract this becomes precondition order in the batch.
- `refstore.rs:360-383` (`mutate`: replay reserve, quota, action, finish, all in one transaction). This becomes one
  planned batch.
- `apps/mkit-worker-common/src/replay.rs:115-180` (`Ledger::reserve`/`finish`: fingerprint check, `reply=NULL`
  means an interrupted publication, prune on insert)
- `apps/vcs-worker/src/write_quota.rs:76-107` (`evaluate_quota`)
- `rust/crates/mkit-transport-file/src/lib.rs:400-456` (CAS semantics for `Any`/`Missing`/`Match`)

## Design

### The key-level contract (`store/kv.rs`)

```rust
/// A storage partition = a D34 shard (reconciliation R-29). Everything that must commit atomically lives in ONE
/// partition. The core computes the partition for every operation (M0-05a `ShardMap`); a backend maps partitions to
/// whatever it likes (a DO per partition, rows keyed by partition in SQLite, a qmdb instance per partition).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Partition {
    /// Whole-namespace partition: single-partition mode. Used by M0 (today's single "root" DO) and by the ssh /
    /// fs-layout path for good. Not used by D34-sharded deployments.
    Namespace(NamespaceKey),
    /// D34 (M1): namespace coordinator — config, grant epoch, and the table of currently epoch-leased shards
    /// (bounded by active shards, not by refs). Rarely written.
    Coordinator(NamespaceKey),
    /// D34 (M1): one per (repo, ref); a branch's head and packmap share it (`shard_ref` = the `refs/heads/<x>` name).
    /// Strongly consistent: head/packmap, tickets, reservations, replay, outbox, epoch lease + cached epoch, quota counters.
    Ref { ns: NamespaceKey, repo: RepoName, shard_ref: String },
    /// D34 (M1): repo membership by object-id prefix over a large FIXED fan-out (`INDEX_FANOUT`, default 4096, a
    /// deployment constant advertised in GetServerInfo). Created lazily on first write; never resharded.
    /// Eventually consistent.
    RepoIndex { ns: NamespaceKey, repo: RepoName, prefix: u16 },
    /// D34 (M1): ref-name index that ListRefs reads, HASH-sharded by ref name over a fixed fan-out
    /// (`REF_INDEX_FANOUT`, deployment constant, default 16). ListRefs k-way merges the buckets behind an opaque
    /// cursor (WP-1.28). No resharding anywhere. Eventually consistent (may lag by seconds). R-33.
    RefIndex { ns: NamespaceKey, repo: RepoName, bucket: u16 },
    /// Global ContentIndex shard: object-id prefix over the same fixed fan-out (`INDEX_FANOUT`, default 4096).
    ContentShard(u16),
}
pub const MAX_KEY_BYTES: usize = 1024;
pub const MAX_VALUE_BYTES: usize = 1024 * 1024;   // < the Durable Object SQLite 2 MB row limit
pub struct Key(bytes::Bytes);   pub struct Value(bytes::Bytes);    // ordered by raw bytes
pub struct Cursor(bytes::Bytes);   // opaque: callers only pass back what a scan returned

#[derive(Debug, Clone)]
pub enum Precondition {
    Absent(Key),
    Present(Key),
    Equals(Key, Value),
    /// Time-bounded commit (review 01, R-61). The batch commits only if the BACKEND'S OWN CLOCK, read inside the
    /// same non-yielding check-and-write step as the other preconditions, is <= deadline_ms (Unix ms). It carries
    /// no key, so it is valid on every store, including RefsOnly and non-atomic ones. On failure `observed` is the
    /// backend's clock reading as 8 big-endian bytes (useful for skew diagnostics).
    NotAfter(u64),
}
#[derive(Debug, Clone)]
pub enum Write { Put(Key, Value), Delete(Key) }
#[derive(Debug, Clone, Default)]
pub struct Batch { pub preconditions: Vec<Precondition>, pub writes: Vec<Write> }
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BatchOutcome { Committed, PreconditionFailed { index: usize, observed: Option<Value> } }
pub struct ScanPage { pub entries: Vec<(Key, Value)>, pub next: Option<Cursor> }

pub struct StoreCapabilities {
    /// false: a batch may hold at most one write, and its only key precondition must be on that same key (a
    /// NotAfter may be added) (FsLayoutStore). The pipeline then issues sequential batches (M0-05a).
    pub atomic_multi_key: bool,
    /// Which key classes (store/keys.rs) the store accepts. FsLayoutStore: RefsOnly.
    pub key_classes: KeyClasses,          // All | RefsOnly
    pub membership: MembershipMode,       // StorePresence (M0) | Explicit (M1+), overview Q16
    /// Layout version of a store that can't hold the `v` key (RefsOnly): its on-disk format is versioned elsewhere
    /// (FileTransport's layout), so it reports a constant here and planners skip the `v` precondition. None for
    /// stores that accept the `v` key (review 01 nit, R-82).
    pub implicit_layout_version: Option<u32>,
}

pub trait NamespaceStore: MaybeSend + MaybeSync {
    fn capabilities(&self) -> StoreCapabilities;
    fn get(&self, p: &Partition, key: &Key) -> impl Future<Output = Result<Option<Value>, StoreError>> + MaybeSend;
    /// Default: `get(..).is_some()`. Backends may override.
    fn has(&self, p: &Partition, key: &Key) -> impl Future<Output = Result<bool, StoreError>> + MaybeSend;
    /// One round trip for several keys (the Workers adapter needs this to keep DO calls to ~2 per RPC).
    /// Default: sequential `get`. Result order = input order.
    fn get_many(&self, p: &Partition, keys: &[Key]) -> impl Future<Output = Result<Vec<Option<Value>>, StoreError>> + MaybeSend;
    /// Ordered by key bytes over [start, end). `after` resumes strictly after the cursor's key. `limit` ≥ 1.
    fn scan(&self, p: &Partition, start: &Key, end: &Key, after: Option<&Cursor>, limit: u32)
        -> impl Future<Output = Result<ScanPage, StoreError>> + MaybeSend;
    /// ONE atomic, all-or-nothing batch. Read the backend clock once, then check every precondition, in order,
    /// against committed state (NotAfter against that clock reading); on the first failure return
    /// `PreconditionFailed{index, observed}` and write nothing. Otherwise apply every write and return `Committed`.
    /// Nothing else: no business logic, no reads by the caller inside the commit.
    fn apply(&self, p: &Partition, batch: Batch) -> impl Future<Output = Result<BatchOutcome, StoreError>> + MaybeSend;
    /// Storage used by one partition (reconciliation R-31: bounded growth). Required; may be approximate or cached
    /// (≤ 60 s stale). DO: `storage.sql.databaseSize`; SQLite: sum over the partition's rows; memory: exact.
    fn stats(&self, p: &Partition) -> impl Future<Output = Result<PartitionStats, StoreError>> + MaybeSend;
    fn probe(&self) -> impl Future<Output = Result<(), StoreError>> + MaybeSend;
}
pub struct PartitionStats { pub bytes: u64, pub keys: Option<u64> }
```

`StoreError` (`store/error.rs`) has `Invalid`, `Unsupported`, `Corrupt`, `Unavailable(BoxError)` and **`Full`**: the
backend is at its storage cap and rejects writes, while reads and deletes still work (Durable Objects: `SQLITE_FULL`,
documented at https://developers.cloudflare.com/durable-objects/platform/limits/; rusqlite: `SQLITE_FULL` too). The
pipeline maps `Full` to a fail-closed retryable `unavailable` ("storage partition full"), never `resource_exhausted`
(00-plan P-24); WP-1.29 alerts on it.

Normative rules, written as the trait's doc comment (these are what M0-03 tests):
1. **Declarative batch.** `apply` is the only write. A backend never evaluates CAS, quota or replay logic; the
   pipeline plans (M0-05a) and guards every value it read with a precondition. Key/value size limits are checked
   and violations return `StoreError::Invalid` with nothing written.
2. **Reads are get / has / get_many / scan.** No other query exists. Every index is a key layout (below).
3. **Single writer is enough.** Nothing in `mkit-server` may assume two `apply` calls on one partition run
   concurrently, and nothing may hold a lock across an `.await` waiting for another `apply`. Contention is handled
   by the pipeline's optimistic re-plan loop (M0-05a).
4. **Cancellation safety.** Dropping an `apply` future at any `.await` point must leave the partition either fully
   before or fully after the batch, and the store usable (no poisoned lock, no half-written state). Backends
   achieve this by performing check-and-write in one non-yielding step (a synchronous SQL transaction on a blocking
   thread that runs to completion even if the future is dropped; DO `transactionSync`; a mutex held without awaits).
   The memory backend must recover from `PoisonError` rather than propagate it.
5. **Durability.** `Committed` means durable to the backend's stated level (documented per backend).
6. **Atomicity scope.** One batch = one partition. Nothing requires atomicity across partitions. Cross-partition
   effects are ordered by the pipeline (a ContentIndex hold before the ref-shard apply, PRD §5.3) or carried by
   **outbox rows** that a core-owned relay delivers at least once, idempotently, to the target partition (D34; the
   relay is WP-1.23 and runs on timers, WP-1.24). A backend therefore needs nothing beyond this trait plus a way to
   run timers (DO alarm, a native periodic task, or the implementer's scheduler).
7. **Bounded growth** (R-31, PRD §5.3). The core deletes what it no longer needs through ordinary batches (replay
   records after the envelope window, quota windows, tickets at expiry, outbox rows on ack); a backend must actually
   reclaim deleted keys and must report `stats`. The deployment exports `mkit_server_partition_bytes{kind}` and
   alerts at 70% and 90% of its per-partition cap (configurable; 10 GB on Durable Objects), from the timer tick
   (WP-1.24; M0 only exposes `stats`). A backend at its cap returns `StoreError::Full` for writes and keeps serving
   reads and deletes.
8. **Commit deadline** (R-61). `NotAfter(deadline_ms)` is evaluated with the **backend's** clock (the SQLite host's
   clock natively, the Durable Object's clock on Workers, an injected clock in memory), read inside the same
   non-yielding step as the key checks, never the caller's clock. This is what makes a late batch (queued, stalled,
   retried after a restart) harmless: it can't commit after its deadline no matter when it arrives. Callers set
   deadlines (M0-05a: `plan_time + MAX_APPLY_WINDOW`; WP-1.25: also `≤ lease_expires − margin`) and must allow for
   clock skew between their clock and the backend's.

### Key layouts (`store/keys.rs`, reconciliation R-17)

One module owns every layout, as constructor + parser functions with golden byte tests. **Every key starts with its
class tag followed by `0x00`** (review 01: tags such as `o`/`oq`/`os`/`oc`, `p`/`px`/`pp`, `t`/`tb` and `e`/`el`
share prefixes, so a scan of one class must never see another). Separator `0x00` never occurs in repo names, ref
names or scopes; integers are big-endian so byte order = numeric order. `<repo>` is the `RepoName` bytes; the
partition identifies the namespace (and, under D34, the shard), never the key. The layouts below are the
single-partition (M0) layouts; under D34 (M1) the same classes live in the partition kinds noted in the last column,
and WP-1.22/1.23/1.25 add the coordinator (config, leased-shard table), index and epoch-lease layouts.

| Class | Key | Value | Used by (D34 home) |
|---|---|---|---|
| Layout version | `"v" 00` | be32 | first planned batch per partition: `Absent` or `Equals(1)`; **not used on `RefsOnly` stores** (their version is `capabilities().implicit_layout_version`) |
| Refs | `"r" 00 <repo> 00 <refname>` | 32-byte id | `read_ref`; `list_refs` = scan `["r"00<repo>00<prefix>, succ(...))` (D34: head/packmap in `Ref`; names mirrored into `RefIndex` for ListRefs) |
| Replay record | `"p" 00 <scope:32>` | codec `ReplayRecord` | stage-0 lookup; guarded by `Absent`/`Equals` |
| Replay expiry index | `"px" 00 <expires_at:be64> <scope:32>` | empty | pruning = scan up to `now` |
| Quota state | `"q" 00 <scope>` | codec `QuotaState` | admission charge, guarded by `Equals`/`Absent` |
| Quota window index | `"qx" 00 <window_start:be64> <scope>` | empty | pruning |
| Grant epoch | `"e" 00` | be64 (absent ≡ 0; never written as 0) | M2 write preconditions (D34: authoritative in `Coordinator`; each `Ref` shard holds an **epoch lease** `"el" 00` = (epoch, expires_at, config_version) and may use it only while leased, WP-1.25) |
| Timers (reserved; WP-1.24) | `"w" 00 <due_at:be64> <kind:u8> <ref>` | codec per kind | alarm = first key ≥ `"w"00`; `timers(due_at, kind, ref)` |
| Reserved M1+ (layouts added by their WP, each `<tag> 00 …`) | tickets/reservations `"t"`, membership `"m" 00 <repo> 00 <pack:32>`, outbox `"o"` + pending index `"oq"` + sequence `"os"` (WP-1.7); relay high-water marks `"rh"` (WP-1.23); object index `"i"` (WP-4.5); leases `"l"` (WP-5.2); published pointers `"pp"` (WP-5.4); tombstones `"tb"` (WP-5.6); verification cursors `"vc"` (WP-4.8) | | |
| ContentIndex (shard partitions; layer in M0-02b) | holders `"h" 00 <obj:32> <ns> 00 <repo>`; holds `"g" 00 <obj:32> <hold_id>`; blocklist `"b" 00 <obj:32>`; last change `"c" 00 <obj:32>` | codecs | `ContentIndex` layer. **Provisional for holders:** WP-4.10a sub-shards holder rows by (object, hash(holder)) into their own partitions and keeps a holder count on the object's primary shard, so one widely held object can't fill a shard (R-34). Counts move in the safe direction (increment before adding a row, decrement after removing one), so a crash can only over-count, never let GC delete a held object. |
| Outbox backlog counter (reserved; WP-1.7 writes it, WP-3.3 enforces it) | `"oc" 00` | codec {rows, bytes} | backpressure: above the configured backlog a ref shard rejects new admitted writes with retryable `unavailable` (R-35) |

`KeyClasses::RefsOnly` = the `r` class only. Every later WP that adds a row adds its layout here, with a golden
test and a conformance case; this table is the registry.

`LAYOUT_VERSION: u32 = 1`. On stores that accept the `v` class, the first planned batch for a partition carries
`Absent("v"00)` + `Put("v"00, 1)` or `Equals("v"00, 1)`; a binary that reads a newer layout version refuses to serve
that partition. `RefsOnly` stores never see the key.

### Value codecs (`store/codec.rs`)

`serde_json` with a leading version byte (`0x01`), for `ReplayRecord`, `StoredResult`, `QuotaState`, holds and
blocklist entries. Refs are raw 32 bytes; integers raw be64. Decoding a value with an unknown version byte →
`StoreError::Corrupt`. Keep every value far below `MAX_VALUE_BYTES`.

### Typed readers (`store/read.rs`)

Backend-independent helpers over `NamespaceStore` (so no backend reimplements them):
`read_ref`, `list_refs(repo, prefix, after, limit) -> RefPage` (names returned in full; the binding strips the
prefix), `replay_lookup(scope)`, `quota_state(scope)`, `grant_epoch()`, `expired_replay_keys(now, limit)`,
`stale_quota_keys(now, window, limit)`. The conformance suite also uses them to assert "nothing was allocated".

### Replay (`replay.rs`, unchanged in meaning)

```rust
pub struct ReplayKey(pub Hash);   // == write_auth Authorized.scope = BLAKE3(audience\nrepository\npubkey\nnonce) (write_auth.rs:487-496)
pub struct ReplayRecord { pub fingerprint: Hash, pub expires_at_ms: i64, pub state: ReplayState }
pub enum ReplayState { InFlight { resumable: bool }, Committed(StoredResult) }
/// No variant for an admission challenge or pending_verification: they can't be stored by construction.
pub enum StoredResult { UpdateRef(UpdateRefResult), AdvanceRefs(mkit_core::protocol::AdvanceOutcome), UploadPack,
                        Rejected { code: crate::Code, message: String } }
pub enum UpdateRefResult { Committed, Conflict { current: Option<Hash> } }
pub enum ReplayDecision { New, Return(StoredResult), Resume, RetryLater, FingerprintMismatch }
pub fn classify(existing: Option<&ReplayRecord>, fingerprint: &Hash) -> ReplayDecision;
```

### `BlobStore` (`store/blob.rs`)

```rust
// Content-addressed, immutable (PRD §5.3). Keyspaces (R-07): every concrete store is constructed with a keyspace
// (default "packs" = today's `packs/<hex>`); M4 instantiates a second store with keyspace "objects" for the global
// object CAS (D32), so a second keyspace needs no trait change. BLAKE3(bytes) == key is the pack keyspace rule;
// WP-4.10 adds a caller-verified object sink. Resumable multipart sessions are WP-1.11's `MultipartBlobStore`
// sub-trait (R-08).
pub type BlobKey = mkit_core::protocol::PackKey;
pub struct ByteRange { pub start: u64, pub end_inclusive: u64 }
pub struct BlobMeta { pub len: u64 }
pub enum BlobBody { Bytes(bytes::Bytes), Stream { len: u64, stream: crate::rt::BoxStream<'static, Result<bytes::Bytes, StoreError>> } }
pub enum CommitOutcome { Created, AlreadyPresent }
pub trait BlobStore: MaybeSend + MaybeSync {
    type Sink: PackSink;
    fn begin(&self, key: BlobKey, len: u64) -> impl Future<Output = Result<Self::Sink, StoreError>> + MaybeSend;
    /// Backends SHOULD return `Stream` for anything larger than one chunk; no backend may buffer a whole pack (R-25).
    fn get(&self, key: &BlobKey, range: Option<ByteRange>) -> impl Future<Output = Result<Option<BlobBody>, StoreError>> + MaybeSend;
    fn head(&self, key: &BlobKey) -> impl Future<Output = Result<Option<BlobMeta>, StoreError>> + MaybeSend;
    fn probe(&self) -> impl Future<Output = Result<(), StoreError>> + MaybeSend;
    /// Never called by the M0 pipeline; reserved for GC and takedown (WP-5.3b, WP-5.6) so M5 doesn't reshape
    /// four backends (R-06). Returns whether the blob existed.
    fn delete(&self, key: &BlobKey) -> impl Future<Output = Result<bool, StoreError>> + MaybeSend;
}
pub trait PackSink: MaybeSend {
    fn write(&mut self, chunk: bytes::Bytes) -> impl Future<Output = Result<(), StoreError>> + MaybeSend;
    /// Visible only after BLAKE3(bytes) == key and total == declared len. A mismatch → Err(Invalid), nothing visible.
    /// Memory use must be bounded by one chunk, not the pack (streaming backends withhold the final chunk until the
    /// hash verifies, R-25).
    fn commit(self) -> impl Future<Output = Result<CommitOutcome, StoreError>> + MaybeSend;
    fn abort(self) -> impl Future<Output = ()> + MaybeSend;
}
```

### Memory backends

`MemoryKv`: `Mutex<BTreeMap<(Partition, Key), Value>>` plus an injected `Arc<dyn Clock>` (`MemoryKv::with_clock`;
the default is the M0-01 system clock). `apply` takes the lock, reads the clock once, checks every precondition and
writes with no await, recovers from poisoning, and is the reference implementation third-party KV backends copy.
`MemoryKv::new(caps)` builds reduced-capability stores for tests (a `RefsOnly` store reports
`implicit_layout_version: Some(1)`); `with_fault(FaultPoint)` injects one failure at `apply` or at a chosen
`BlobStore` write; `with_capacity_limit(bytes)` makes writes past the limit return `StoreError::Full` while reads
and deletes keep working (so M0-05a can test the `Full` mapping). `MemoryBlobStore` hashes incrementally with
`mkit_core::hash::Hasher` (`hash.rs:31-55`).

## Tests to write first

In `replay.rs`: `classify_none_is_new`, `classify_other_fingerprint_is_mismatch` (both states),
`classify_committed_returns_stored_result`, `classify_inflight_resumable_is_resume`,
`classify_inflight_not_resumable_is_retry_later`, `no_stored_result_variant_for_challenge` (exhaustive match).

In `store/keys.rs`: `layouts_golden_bytes` (one fixed example per class, each with its `0x00` terminator),
`class_scans_never_overlap` (for every pair of tags where one is a prefix of the other — `o`/`oq`/`os`/`oc`,
`p`/`px`/`pp`, `t`/`tb`, `e`/`el` — a scan of one class returns no key of the other),
`ref_prefix_scan_bounds_cover_exactly_the_prefix` (proptest over ref names with `/`, `.`, `-`),
`be64_orders_numerically`, `parse_roundtrip_every_class`.

In `store/codec.rs`: `codec_roundtrip_every_value_type`, `unknown_version_byte_is_corrupt`.

In `memory/*` (the full generic suite arrives in M0-03):
- `apply_all_or_nothing_reports_first_failing_precondition_and_observed_value`
- `apply_rejects_oversize_key_and_value_writing_nothing`
- `not_after_uses_store_clock_at_apply` (build a batch with `NotAfter(t)`, advance the injected clock past `t`,
  apply → `PreconditionFailed{index, observed = be64(store_now)}`, nothing written; at `t` exactly it commits)
- `not_after_accepted_by_refs_only_non_atomic_store` (one ref write + one key precondition + `NotAfter`)
- `capacity_limit_returns_full_but_reads_and_deletes_work`
- `scan_orders_by_bytes_and_cursor_resumes_strictly_after`
- `get_many_preserves_order`
- `dropped_apply_future_leaves_store_consistent` (poll once, drop, then read)
- `poisoned_lock_recovers`
- `blob_commit_rejects_hash_and_len_mismatch_leaving_nothing`; `blob_commit_identical_bytes_is_already_present`;
  `blob_get_range`; `blob_delete_then_get_none_and_second_delete_false`

## Gate

```bash
export TMPDIR="$HOME/.cache/mkit-test-tmp"; mkdir -p "$TMPDIR"
cd rust && cargo fmt --check
cargo clippy --all-targets --all-features --workspace -- -D warnings
cargo nextest run -p mkit-server --all-features && cargo test --doc -p mkit-server --all-features
cargo check -p mkit-server --target wasm32-unknown-unknown --features memory
cd .. && just ci-scripts && just ci-security        # serde/serde_json deps; Cargo.lock touched → also `just ci`
```

## Acceptance criteria

- [ ] `NamespaceStore` has exactly: `capabilities`, `get`, `has`, `get_many`, `scan`, `apply`, `stats`, `probe`. `apply` takes a
      declarative `Batch`; there is no closure-taking or SQL-shaped method anywhere in the contract.
- [ ] `Precondition` has exactly `Absent`, `Present`, `Equals`, `NotAfter`; rule 8 states that `NotAfter` uses the
      backend's clock inside the check-and-write step.
- [ ] The eight normative rules are in the trait's doc comment. The memory backend satisfies them, including
      cancellation safety, poisoning recovery and the store-clock deadline (tests).
- [ ] `store/keys.rs` documents every M0 layout with a `0x00` after each class tag and reserves the M1–M5 prefixes;
      golden tests pin the bytes; no class scan can see another class.
- [ ] `RefsOnly` stores report `implicit_layout_version`; nothing requires them to hold `v`.
- [ ] `StoreError::Full` exists and is documented (reads and deletes still work).
- [ ] The "challenge / pending_verification never stored" rule is enforced by the `StoredResult` type.
- [ ] Every public type is `Debug`. The crate checks for wasm32 with `memory`. The diff stays ≲ 1500 lines; if it
      doesn't, move typed readers (`store/read.rs`) to M0-02b and say so in the PR.

## Risks / gotchas

- `impl Future` in traits makes them non-object-safe. That's intended: the pipeline is generic. PRD §5.2 reserves
  `BoxFuture` for hook lists (M3).
- `StoreError::Unavailable`'s boxed source must be `Send + Sync` on native only (cfg'd `BoxError` alias).
- Round trips: on Workers each `get_many`/`scan`/`apply` is a DO call. Planners (M0-05a) must read everything they
  need in one `get_many`, so a typical write costs two DO calls.
- Don't encode anything a backend must interpret inside values. Backends see opaque bytes, except the size limits.
- `NotAfter` is the only precondition that reads a clock. Test clock-skew directives (M0-05b) must never feed it:
  deadlines are computed from the real clock (00-plan P-21), and the backend always uses its own.
