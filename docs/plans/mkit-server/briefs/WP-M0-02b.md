# WP-M0-02b: Storage contract layers (`ContentIndex` over shard partitions, portable export/import, optional `StoreMaintenance` / `StateCommitment` hooks)

- **Milestone/track:** M0
- **Base:** `feat/mkit-server`; **branch:** `mkit-server/wp-m0-02b-storage-layers`
- **Depends on:** M0-02a
- **Size:** M (~500–750 lines; roughly half tests)
- **Reconciliation:** the second half of the former WP-M0-02, split by review 01 (00-plan.md R-72). Everything here
  is a layer over the M0-02a contract, and nothing in the M0 pipeline (M0-05a/05b) needs it, so this WP is off the
  critical path and can run in parallel with M0-05a. R-19, R-20, R-21, R-60 carry over unchanged.

## Conventions

Same as WP-M0-01 "Conventions": TMPDIR, trailer, no CI polling, no proto change, a size check, workspace lints.

## Goal

Add the parts of the storage design that later milestones and backups rely on, without touching the M0-02a trait:

1. `ContentIndex`: a typed layer over any `NamespaceStore`, on `Partition::ContentShard` partitions, giving the PRD's
   "atomic per-object updates" on any backend.
2. **Portable logical export/import** (R-20) that works on every backend, so backup is portable across backends.
3. The optional hooks no pipeline code requires: `StoreMaintenance` (backend-defined export/import/migrate, R-19)
   and `StateCommitment` (a future verifiable ref-state root, R-21).

## PRD refs

§5.3 (`ContentIndex` "global, sharded by object id"; "A backup and restore procedure and versioned schema migrations
are required for every backend"), §6.7 GC roots and holds, D15, D34.

## Scope

**IN:** `store/content_index.rs`, `store/maintenance.rs`, their unit tests over `MemoryKv`, re-exports.

**OUT:** Workers DO wiring for content shards and holder sub-sharding (WP-4.10a); GC use of `collectable`
(WP-5.3a/b); the generic conformance cases (M0-03 runs `idx.*` and `dur.export_import_roundtrip` against every
backend); SQLite `StoreMaintenance` implementation (M0-09).

## Files and symbols

Create in `rust/crates/mkit-server/src/`: `store/content_index.rs`, `store/maintenance.rs`. Modify
`store/mod.rs` and `src/lib.rs` (re-exports).

## Design

### `ContentIndex` (`store/content_index.rs`)

A struct, not a backend trait: `pub struct ContentIndex<S: NamespaceStore> { store: S }` using
`Partition::ContentShard(shard_of(obj))` and the `h/g/b/c` layouts registered in M0-02a (`<tag> 00 …`). Every
per-object update is one batch in one shard partition. Methods:
`add_hold` (documented: BEFORE the ref-shard apply; the hold's TTL must exceed `MAX_APPLY_WINDOW` plus the relay-lag
bound, 00-plan P-21/P-23), `release_hold` (documented: called by the relay step that records the holder row, in the
same batch, WP-4.10, R-75), `add_holder` (idempotent), `remove_holder`, `holders(obj, after, limit)`, `block`,
`unblock`, `blocked`, `collectable(obj, now_ms, grace_ms)` (zero holders AND zero unexpired holds AND
`now - last_change >= grace`). Every mutating method updates the `c` (last change) key in the same batch, so a GC
delete guarded by `Equals` on `c` (WP-5.3b) fails if anything changed since its mark. On Workers the shard partitions
route to their own DOs (`ci:<shard>`, M0-16 naming); wiring them is WP-4.10a.

### Export/import and optional hooks (`store/maintenance.rs`)

```rust
/// Portable logical backup (R-20): a full ordered scan of every partition the backend holds, as a stream of
/// (partition, key, value) records with a header {layout_version, exported_at}. Works on ANY NamespaceStore.
pub fn export_partition<S: NamespaceStore>(s: &S, p: &Partition) -> impl Stream<Item = Result<ExportRecord, StoreError>>;
pub async fn import_partition<S: NamespaceStore>(s: &S, p: &Partition, records: impl Stream<..>) -> Result<(), StoreError>;
/// Backend-defined operations (R-19). Optional: the pipeline never calls it. SQLite implements it with versioned
/// physical migrations and VACUUM INTO (M0-09); a KV backend may implement it however it likes.
pub trait StoreMaintenance { fn layout_version(&self) -> u32; fn migrate(&self) -> ..; fn backup_to(&self, dest: &str) -> ..; }
/// Future verifiable ref-state root (R-21). Optional and unimplemented in the epic; the pipeline never requires it.
pub trait StateCommitment: NamespaceStore {
    fn root(&self, p: &Partition) -> impl Future<Output = Result<Option<(String /*scheme*/, Hash)>, StoreError>> + MaybeSend;
    fn prove(&self, p: &Partition, key: &Key) -> impl Future<Output = Result<Option<bytes::Bytes>, StoreError>> + MaybeSend;
}
```

Import writes in batches of bounded size (≤ 100 writes and ≤ 1 MiB per batch, so it fits Durable Object limits)
and refuses a stream whose `layout_version` is newer than the binary's. Export of a `RefsOnly` store exports the `r`
class only and records the store's `implicit_layout_version`.

## Tests to write first

- `content_index_collectable_rules` (holders, unexpired holds, grace); `content_index_holder_add_idempotent`
- `content_index_every_mutation_bumps_last_change`
- `content_index_objects_in_different_shards_isolated`
- `export_import_roundtrip_is_identical` (byte-for-byte full scan equality), `import_refuses_newer_layout_version`,
  `import_batches_stay_within_do_limits`

## Gate

```bash
export TMPDIR="$HOME/.cache/mkit-test-tmp"; mkdir -p "$TMPDIR"
cd rust && cargo fmt --check
cargo clippy --all-targets --all-features --workspace -- -D warnings
cargo nextest run -p mkit-server --all-features && cargo test --doc -p mkit-server --all-features
cargo check -p mkit-server --target wasm32-unknown-unknown --features memory
cd .. && just ci-scripts
```

## Acceptance criteria

- [ ] `ContentIndex` works over any `NamespaceStore` via shard partitions; every mutation is one batch that also
      bumps the last-change key.
- [ ] `StoreMaintenance` and `StateCommitment` exist, are optional, and nothing in the pipeline requires them.
- [ ] Export/import round-trips a partition byte for byte and refuses newer layouts.
- [ ] No change to the M0-02a trait or key layouts (only new modules).

## Risks / gotchas

- Keep `ContentIndex` a struct over the contract: a backend-specific ContentIndex trait would reintroduce the
  per-backend logic the key-level contract removed.
- Holder rows are provisional until WP-4.10a sub-shards them; don't let callers depend on scanning all holders of an
  object in one partition.
