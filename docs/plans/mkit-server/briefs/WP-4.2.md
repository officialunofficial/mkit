# WP-4.2: mkit-core repo-isolated delta-base seam and incremental push verification

- **Milestone/track:** M4 / core (pure mkit-core + one CLI call-site swap; may land during M0)
- **Base:** `feat/mkit-server` at `392072d3` or later; **branch:** `mkit-server/wp-4-2-delta-base-seam`
- **Depends on:** P1 (merged). **Merge after 4.1** (both edit `rust/crates/mkit-core/src/pack.rs`). If 4.1 is still
  open, develop in parallel and rebase before review.
- **Unblocks:** 4.7 (indexed ingestion), 4.8a (windowed reader), 5.7a (delta-safe rewrite)
- **Parallel with:** 1.3, 2.3, 2.4a, 4.3. `verify.rs` overlaps with 4.3: different functions; the later PR rebases.
- **Size:** L (~1,200–1,400 changed lines). Contingency split below.
- **Area gates (registry):** `rust`, `wasm`, `full`

## Conventions

- `git fetch origin && git switch -c mkit-server/wp-4-2-delta-base-seam origin/feat/mkit-server`.
- `export TMPDIR="$HOME/.cache/mkit-test-tmp"; mkdir -p "$TMPDIR"` before tests.
- Commit trailer: `Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>`. Don't poll CI or comment on
  GitHub or Linear.
- **No CI on `feat/mkit-server`.** Paste the local gate output into the PR body (including before/after bench
  numbers).
- Pre-production policy; `CHANGELOG.md`; workspace lints; no `unsafe`; no proto change.
- **Size cap.** If the diff passes ~1500 changed lines, stop and split at the seam below.
- Carry-forward notes:
  - `connectrpc` 0.9.1: no dependency changes are expected in this WP, so `rust/Cargo.lock` stays untouched.
  - wasm32 clippy needs `--no-deps`. mkit-core has **6 pre-existing wasm32 lints** (`ops/restore.rs:647/707/789`,
    `repo_lock.rs:136/216`, `protocol.rs:458`); add none.
  - Test timeouts under load also happen on the base branch. The pack/closure suites are heavy, so re-run
    individually before suspecting a regression.

## Goal

1. **Delta-base seam.**
   - `DeltaBaseSource` makes "where may a delta's external base come from" an explicit parameter. A server can then
     resolve bases **only** from the pushing repository's membership; `ObjectStore` becomes one implementation.
   - `decode_entries_with` is a store-less decoder over that seam.
   - `PackReader::read` stays byte-identical, including error order.
2. **Incremental push verification.** `verify_push` walks each new tip's closure through the shared `children`
   function, and does four things:
   - re-derives every object id
   - verifies commit, remix and tag signatures, through a signature helper lifted from the CLI into
     `mkit_core::sign`, which the CLI then calls
   - stops at a caller-supplied frontier of objects already verified in this repository
   - reports missing, corrupt and badly signed objects, so the server can reject before refs move

## PRD and spec refs

- PRD §6.5 (indexed mode): "Before refs move, the server re-hashes objects, verifies commit and tag signatures, checks
  closure". "Delta bases, `AlreadyPresent`, and every object lookup during verification resolve **only against the
  pushing repo's membership**." §5.4 step 5; D3, D14, D15.
- SPEC-PACKFILE §3.2 (a delta base must be reachable at resolution time: an earlier entry in the same pack, or "the
  destination object store"). §4 (ordering rule, `DeltaBaseMissing`, "Readers MUST NOT buffer undefined delta
  chains"). §3.1–§3.4 (canonical-object validation of every raw payload and reconstructed target; type-dependent id
  rule). §12 invariants.
- SPEC-DISCLOSURE §7.1 (modes and `children`): Snapshot omits parents, History includes them; never follow remix
  `sources` or `Delta.base_hash`.
- `docs/INVARIANTS.md`: "Closure walks share one `children` function" (:553), and "Streaming closure verification
  reads only reachable objects, each once" (:578).

## Scope

**IN:** as described in the Goal (seam, decoder, walker generalization, `verify_push`, signature lift, CLI swap,
INVARIANTS, CHANGELOG). Plus a bench comparison.

**OUT**
- Any server use (4.7), membership and index (4.5), the uniform-error conformance test across repos (4.7).
- Windowed/streaming decoding (4.8a), pack rewrite (5.7a).
- Batch signature verification inside `verify_push`: optional; `batch-verify` is off on wasm; a follow-up if 4.7
  profiling asks for it.

## Files and symbols (tip `392072d3`)

| File | What exists | Change |
|---|---|---|
| `rust/crates/mkit-core/src/pack.rs` | `PackReader::read` :794 → `read_inner` :828 (phase 1 drains `PackEntries`; phase 2 fans out raw staging into a `WriteBatch`; phase 3 replays in pack order); `stage_delta_target` :1375; `resolve_delta_target(store, in_pack, base, stream)` :1399 (in-pack first, then `store.contains`/`store.read` + `validate_storable_object`, caching the base into `in_pack`, #643); `validate_storable_object` :1433; `validate_delta_result_size` :1448; `PackEntries` :1156; `delta_base_hashes` :715 | Add `DeltaBaseSource`, `NoExternalBases`, the `&ObjectStore` impl, `DecodedEntry`, `DecodeReport`, `decode_entries_with`. Make `resolve_delta_target`/`stage_delta_target` generic over `B: DeltaBaseSource`. `read_inner` passes `&mut &ObjectStore`. |
| `rust/crates/mkit-core/src/verify/closure.rs` | `trait ObjectSource { fn fetch(&mut self, &Hash) -> Result<Option<Cow<[u8]>>, VerifyError> }` :49; private `walk_closure(root, mode, source)` :214 (BFS, re-derives ids, root-type check, `children`); callers :484/:550/:631 | Generalize the walker into a `pub(crate)` multi-root, frontier-aware walk with a per-object visitor. `walk_closure` becomes a thin wrapper that passes `known = \|_\| false`. |
| `rust/crates/mkit-core/src/verify/push.rs` (new) + `verify.rs` (`mod push; pub use push::{…}` next to `pub use closure::{…}` :340) | — | `verify_push`, `PushReport` |
| `rust/crates/mkit-core/src/sign.rs` | `verify_batch` :318; `verify_tag` :536; `verify_commit` :560; `verify_remix` :568 | Add `pub fn verify_object_signature(obj: &Object) -> Result<(), MkitError>` (Ok for Blob/Tree/ChunkedBlob/Delta); re-export it from `lib.rs` next to `verify_commit` |
| `rust/crates/mkit-core/src/ops/graph.rs` | `children` :107 | Unchanged (the single source of edges) |
| `rust/crates/mkit-cli/src/remote_dispatch/packmap.rs` | `verify_new_object_signatures` :778; `verify_one_object` :801 (matches Commit/Remix/Tag → `verify_*`); `collect_batch_entries` :822; `verify_slice` :896 | `verify_one_object` calls `sign::verify_object_signature` and keeps its `DispatchError::UnsignedOrInvalidObject` mapping. Batch path unchanged. |
| `docs/INVARIANTS.md` | :553 and :578 | Add `verify_push` to "share one `children`". New invariant: "Push verification resolves only from the supplied source and stops only at caller-verified objects". |
| `CHANGELOG.md` | | `### Added` |

## Design

```rust
// ---- pack.rs ----
/// Where a delta's *external* base (one not earlier in the same pack) may come from. SPEC-PACKFILE §3.2's
/// "destination object store" becomes the implementor: the local `ObjectStore` on the CLI; the pushing repository's
/// membership on a server (never a global content store — PRD §6.5 isolation).
pub trait DeltaBaseSource {
    /// Whether `base` returns bytes already verified to hash to `id` (the store's `read` verifies).
    /// When false, the decoder deserializes the bytes and re-derives the id itself, rejecting a mismatch as
    /// `DeltaBaseMissing` — an untrusted source can never smuggle a different object in as a base.
    const VERIFIED: bool = false;
    /// Canonical object bytes for `id`, or `None` if this source may not provide it. `None` and "does not exist"
    /// are indistinguishable to the decoder by design (both → `DeltaBaseMissing`).
    fn base(&mut self, id: &Hash) -> Result<Option<Vec<u8>>, PackError>;
}
/// A source with no external bases: self-contained packs (closure profile, 5.7a rewrite, tests).
pub struct NoExternalBases;
impl DeltaBaseSource for NoExternalBases { fn base(&mut self, _: &Hash) -> Result<Option<Vec<u8>>, PackError> { Ok(None) } }
impl DeltaBaseSource for &ObjectStore { const VERIFIED: bool = true; /* contains + read, exactly as today */ }

pub struct DecodedEntry<'p> { pub id: Hash, pub bytes: Cow<'p, [u8]>, pub object: Object, pub from_delta: bool }
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DecodeReport { pub raw_count: usize, pub delta_count: usize, pub ids: Vec<Hash> /* pack order */ }

/// Store-less decode: validate the pack (header/trailer/caps via `PackEntries`), then in pack order validate each raw
/// payload as a storable canonical object, resolve each delta (in-pack first, then `bases`), validate the target, and
/// hand every entry to `sink` in pack order. Stops at the first error (sink errors included).
pub fn decode_entries_with<'p, B: DeltaBaseSource>(
    pack: &'p [u8],
    bases: &mut B,
    sink: impl FnMut(DecodedEntry<'_>) -> Result<(), PackError>,
) -> Result<DecodeReport, PackError>;
```

- **`PackReader::read` stays byte-identical.** Keep `read_inner`'s three phases and its parallel raw staging. Only
  change `resolve_delta_target`'s base lookup to go through `B: DeltaBaseSource`, with `&ObjectStore` as the source.
  `VERIFIED = true` keeps today's single hash-verify per external base (`store.read` already checks), and the #643
  cache of external bases in `in_pack` stays. Error precedence stays as the existing tests pin it:
  `delta_before_its_base_is_rejected_under_parallel_raw_fanout`,
  `earlier_delta_base_missing_wins_over_later_malformed_raw_entry`,
  `multiple_deltas_against_shared_external_base_read_store_once`.
- **Owned `Vec<u8>` rather than `Cow` from `base()`.** A borrow from `&mut self` can't live in `in_pack`, which
  outlives the call. Today's store path already clones (`pack.rs:1419–1421`), so this costs nothing. If you find a
  zero-copy design that keeps these semantics, say so in the PR.
- **Chain depth.** In-pack chains are resolved in order, as today. `decode_entries_with` itself never recurses into
  external bases' own deltas. Bases are canonical objects, never pack-only `Delta` (`validate_storable_object` rejects
  those). Server-side cross-pack chain resolution with a depth cap is 4.7's job.

```rust
// ---- verify/push.rs ----
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PushReport {
    pub verified: usize,                              // objects fetched, re-hashed and (if signed) signature-checked
    pub skipped_known: usize,                         // frontier stops (never fetched)
    pub missing: Vec<Hash>,                           // closure not closed → reject
    pub corrupt: Vec<(Hash, String)>,                 // bytes don't deserialize or hash to the requested id
    pub bad_signatures: Vec<(Hash, String)>,          // commit/remix/tag signature failure
    pub bad_tips: Vec<(Hash, crate::object::ObjectType)>, // a tip that is not a commit/remix/tag
}
impl PushReport { #[must_use] pub fn is_accepted(&self) -> bool; }  // all four lists empty

/// Verify the history a push introduces, before refs move. BFS from every tip over `ops::graph::children(obj, mode)`,
/// fetching each id at most once from `source` (which MUST only serve this repository's members + the pushed packs);
/// ids for which `known(id)` holds are frontier stops: not fetched, not descended (they were verified in this repo).
pub fn verify_push(
    new_tips: &[Hash],
    mode: ClosureMode,
    source: &mut impl ObjectSource,
    known: impl FnMut(&Hash) -> bool,
) -> Result<PushReport, VerifyError>;   // Err only for source errors or the MAX_ENTRIES visit cap
```

- **Walker sharing (the invariant).** Refactor `walk_closure` (`closure.rs:214`) into
  `pub(crate) fn walk(roots: &[Hash], mode, source, known, visit: impl FnMut(&Hash, &Object) -> Result<(), VerifyError>)`.
  Keep the existing behaviors:
  - one visited set, and the `pack::MAX_ENTRIES` cap
  - re-derivation via `crate::object::id_from_object`
  - the root-type rule, reported to closure callers as `ClosureRootWrongType` and to `verify_push` in `bad_tips`
  - drop bytes after extracting children

  `verify_closure_*` call it with `known = |_| false` and a no-op visit, so their reports are identical.
  `verify_push`'s visit runs `sign::verify_object_signature`.
- **Frontier safety.** A `known` object's descendants are never fetched. The doc comment must state the caller
  contract: `known(id)` is true only for objects whose whole closure (in this `mode`) was already verified in this
  repository.

## Tests to write first

`pack.rs`:
- `decode_with_no_external_bases_matches_reader`: for every existing pack test shape (raw, raw+delta in pack, v2
  `0x03`/`0x04` under `pack-zstd`), `decode_entries_with(NoExternalBases)` yields the same ids, bytes and order as
  `PackReader::read` into a fresh store.
- `external_base_outside_source_is_delta_base_missing`: the base is in an `ObjectStore` the decoder is not given.
  Error = `DeltaBaseMissing(hex)`, byte-identical to "the base exists nowhere".
- `untrusted_source_returning_wrong_bytes_is_rejected`: a `VERIFIED = false` source returns a different valid object
  for the requested id → `DeltaBaseMissing`, and no target is emitted.
- `store_source_is_verified_once`: counts reads on `&ObjectStore`, keeping the `multiple_deltas_against_shared_external_base_read_store_once` property.
- `sink_error_stops_decode`.
- All existing `pack.rs` tests pass unchanged (they are the byte-identity and error-order guard).

`verify/push.rs`:
- `good_push_verifies_all_new_objects`.
- `frontier_stop`: a parent is `known`, so it is never fetched (the counting source panics on it). `skipped_known`
  counts it.
- `known_tip_is_noop`.
- `unsigned_commit_rejected`: zeroed signature → `bad_signatures`.
- `forged_tag_rejected`: a valid tag's signer changed → `bad_signatures`.
- `remix_signature_checked`.
- `tree_referencing_absent_blob_is_missing`.
- `wrong_bytes_for_id_is_corrupt`.
- `tip_is_tree_is_bad_tip`.
- `tag_of_tag_of_commit_walks_through`.
- `chunked_blob_children_walked`.
- `history_vs_snapshot`: a missing parent is reported in History, not in Snapshot.
- `each_object_fetched_once_across_multiple_tips`: shared ancestry, counting source.
- `remix_sources_never_followed`.

Regression:
- Existing `verify::closure::tests` (including `streaming_fetches_each_reachable_object_once_and_only`,
  `history_on_snapshot_reports_parent_missing`) and `tests/golden_closure.rs` pass unchanged.
- The CLI tests covering `verify_new_object_signatures` pass unchanged.

Optional: extend the `pack_entries` fuzz body (`rust/fuzz/src/lib.rs:487`) to assert
`decode_entries_with(NoExternalBases)` accepts exactly when `PackReader::read` into an empty store does.

## Golden-vector plan

No new wire format, so no new goldens. The existing goldens are the byte-identity proof and must pass unchanged:
- `rust/crates/mkit-core/tests/golden_closure.rs` (fixtures `rust/tests/golden/closure/*`)
- `tests/golden_pack.rs`
- `tests/golden_disclosure.rs`

Confirm `git diff --exit-code rust/tests/golden/` after running the whole suite.

## Gate commands (repo root)

```bash
export TMPDIR="$HOME/.cache/mkit-test-tmp"; mkdir -p "$TMPDIR"
( cd rust && cargo fmt --check )
( cd rust && cargo clippy --all-targets --all-features --workspace -- -D warnings )
( cd rust && cargo nextest run -p mkit-core --all-features )
( cd rust && cargo nextest run -p mkit-core --no-default-features )
( cd rust && cargo nextest run -p mkit-cli -p mkit-server -p mkit-wasm -p mkit-transport-connect )
( cd rust && cargo test --doc -p mkit-core )
( cd rust && cargo test -p mkit-fuzz )                        # plain-unit fuzz bodies
# wasm
( cd rust && cargo check -p mkit-core --no-default-features --target wasm32-unknown-unknown )
( cd rust && cargo clippy -p mkit-core --no-default-features --target wasm32-unknown-unknown --no-deps -- -D warnings 2>&1 \
    | grep -E '^ +--> ' | sort -u )   # ONLY the 6 baseline sites
( cd rust && cargo clippy -p mkit-server -p mkit-wasm --target wasm32-unknown-unknown --no-deps -- -D warnings )
( cd rust && cargo build -p mkit-wasm --target wasm32-unknown-unknown )
just ci-scripts
git diff --exit-code rust/tests/golden/
# perf guard (hot unpack path, #643/#647): run on base and on the branch, paste both
( cd rust && cargo bench -p mkit-benches --bench pack_unpack_fanout )
( cd rust && cargo bench -p mkit-benches --bench closure_verify_fanout )
just ci                                                        # mkit-core public API changed (full gate)
```

## Acceptance checklist

- [ ] `PackReader::read` output and error precedence are unchanged. Every existing `pack.rs` test and golden passes
      without edits.
- [ ] `decode_entries_with(NoExternalBases)` agrees with `PackReader::read` on every test pack. An untrusted source
      can't inject a base (re-derived id). "Not in source" and "doesn't exist" give the same error bytes.
- [ ] `verify_push` uses the shared walker and `ops::graph::children`. It fetches each id at most once and never
      fetches a `known` id. It re-hashes and signature-checks commit, remix and tag objects.
- [ ] `sign::verify_object_signature` exists; the CLI's `verify_one_object` delegates to it, and the CLI tests pass.
- [ ] INVARIANTS updated. Bench deltas are within noise (≤ ~5%), or explained in the PR.
- [ ] wasm32 check passes; wasm clippy shows only the baseline sites. `just ci` is green.

## Contingency split (only if the diff exceeds ~1500 lines)

- **4.2a** (`mkit-server/wp-4-2a-delta-base-seam`, `pack.rs` only): `DeltaBaseSource`, `NoExternalBases`,
  `decode_entries_with`, the generic `resolve_delta_target`, and the pack tests. This unblocks 5.7a.
- **4.2b** (`mkit-server/wp-4-2b-verify-push`): walker generalization, `verify_push`, `verify_object_signature`, the
  CLI swap and INVARIANTS.

4.7 and 4.8a need both halves. Tell the orchestrator so the registry rows and 5.7a's dependency (→ 4.2a) can be
updated.

## Risks

- **Hot-path regression.** `read_inner` is performance-tuned (#643 base cache, #647 Cow borrows, parallel raw
  staging). Keep the store path monomorphic (`&ObjectStore`), don't add a `dyn` call per entry, and show the bench.
- **Error-order drift.** Subtle reorderings between "delta base missing" and "malformed raw entry" are pinned by
  tests. Don't restructure phase 3.
- **Walker invariant.** Adding a second walker instead of generalizing the first would violate "Closure walks share
  one `children` function". The reviewer will check that there is exactly one BFS.
- **Frontier misuse.** `known` must mean "closure verified in this repo", not "exists somewhere". A global-CAS
  `known` would reintroduce the cross-repo oracle PRD §6.5 forbids. State this prominently in the rustdoc.

## Spec vs breakdown (specs win)

- No conflict. Notes for the implementer:
  - SPEC-PACKFILE §3.2/§4 say "destination object store". The seam keeps that meaning (the store you are writing
    into), and a server supplies its repository membership as that store. No normative edit is needed.
  - The breakdown's `base(&mut self, &Hash) -> Result<Option<Cow<[u8]>>, PackError>` becomes `Option<Vec<u8>>`,
    because of the `in_pack` lifetime, plus the `VERIFIED` flag. SPEC-PACKFILE §3.2 requires the base's identity, and
    a generic source must not be trusted for it.
  - The breakdown's sink `FnMut(Hash, Cow<[u8]>, Object)` becomes `FnMut(DecodedEntry) -> Result<(), PackError>`, so
    a consumer (4.7 staging index rows) can abort.
