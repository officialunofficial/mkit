# WP-4.3: mkit-core `build_disclosure` over a generic object source

- **Milestone/track:** M4 / core (pure mkit-core; may land during M0)
- **Base:** `feat/mkit-server` at `392072d3` or later; **branch:** `mkit-server/wp-4-3-disclosure-source`
- **Depends on:** P1 (merged)
- **Unblocks:** 4.14 (proofs over the repository index or the global CAS)
- **Parallel with:** 1.3, 2.3, 2.4a, 4.1. `verify.rs` overlaps with 4.2 (4.2 adds `mod push` next to `pub use closure`
  at :340; this WP edits :1268–1474). Different hunks; the later PR rebases.
- **Size:** S (~200–300 changed lines incl. tests)
- **Area gates (registry):** `rust`, `wasm`, `golden`

## Conventions

- `git fetch origin && git switch -c mkit-server/wp-4-3-disclosure-source origin/feat/mkit-server`.
- `export TMPDIR="$HOME/.cache/mkit-test-tmp"; mkdir -p "$TMPDIR"` before tests.
- Commit trailer: `Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>`. Don't poll CI or comment on
  GitHub or Linear.
- **No CI on `feat/mkit-server`.** Paste the local gate output into the PR body.
- Pre-production policy; `CHANGELOG.md`; workspace lints; no `unsafe`; no proto change; stop above ~1500 lines (not
  expected).
- Carry-forward notes:
  - `connectrpc` 0.9.1: no dependency change expected (`rust/Cargo.lock` untouched).
  - wasm32 clippy needs `--no-deps`. mkit-core has **6 pre-existing wasm32 lints** (`ops/restore.rs:647/707/789`,
    `repo_lock.rs:136/216`, `protocol.rs:458`); add none.
  - Test timeouts under load also happen on the base branch.

## Goal

Make the disclosure-bundle producer independent of the on-disk `ObjectStore`. Add
`build_disclosure_from<S: store::ObjectSource + ?Sized>`, so the server can build SPEC-DISCLOSURE bundles from its
per-repository index or the global object CAS. `build_disclosure(&ObjectStore, …)` becomes a thin wrapper. Bundles are
**byte-identical** for every input.

## PRD and spec refs

- PRD §6.6 (HTTP serving with `?proof=1` inclusion and range proofs), §6.5 (per-repo index, global CAS), M4-a/M4-b
  (the proof format is decided in 4.11; this WP changes no format).
- **SPEC-DISCLOSURE** §2 (authentication chain), §3 (wire format: `MKDP`, version 2, steps, payload kinds), §4
  (verification algorithm), §5 (bounds), §6 (golden vectors under `rust/tests/golden/disclosure/`, pinned by
  `MANIFEST.txt`; `golden_disclosure.rs` reads committed files only and never calls the generator).

## Scope

**IN**
- `build_disclosure_from` and its generic helpers.
- The wrapper.
- A doc fix: `verify.rs` module docs :36–47 and the `lib.rs` :56–60 comment call `build_disclosure` "native-only".
  After this WP the generic builder has no store dependency (it already compiled on wasm32).
- Equivalence tests and the golden regeneration check.
- CHANGELOG.

**OUT**
- Any change to the bundle format or `Selector`.
- Cross-chunk ranges (still `RangeCrossesChunkBoundary`; 4.11/4.14 decide the multi-chunk bundle).
- Server code (4.14).
- `mkit-wasm` exports.

## Files and symbols (tip `392072d3`)

| File | What exists | Change |
|---|---|---|
| `rust/crates/mkit-core/src/verify.rs` | `extract_bao_slice` :1253; `pub fn build_disclosure(store: &crate::store::ObjectStore, commit_id, path: &[&[u8]], selector: Selector) -> Result<Vec<u8>, VerifyError>` :1279 (uses `store.read` :1285 and `store.read_object` :1297); `fn build_payload(store: &ObjectStore, …)` :1330 (`read`/`read_object` at :1337, :1341, :1354, :1372, :1378); `fn build_chunked_range_payload(store: &ObjectStore, …)` :1398 (`read` :1412); `encode_disclosure` :1025; `Selector` :482; module docs :36–47 | Make the three builders generic over `S: crate::store::ObjectSource + ?Sized`. Add `pub fn build_disclosure_from`. `build_disclosure` delegates. Fix the docs. |
| `rust/crates/mkit-core/src/store/source.rs` | `pub trait ObjectSource { fn read(&self, &Hash) -> StoreResult<Vec<u8>>; fn read_object(..); fn read_unverified(..) }` :19; impls for `ObjectStore` :49, `EphemeralSink` :165, and `DisplaySource` :242 (whose `read` is **unverified**) | Unchanged. Doc note only (see Design). |
| `rust/crates/mkit-core/src/lib.rs` | comment :56–60 | Fix "native-only" wording |
| `rust/crates/mkit-cli/src/commands/prove.rs` | `build_disclosure(&store, …)` :110 | Unchanged (wrapper keeps the signature) |
| `rust/crates/mkit-core/tests/golden_disclosure.rs` | generator via `MKIT_WRITE_GOLDEN=1` (:51, :1132); calls `verify::build_disclosure` at :331, :349, :401, :454 | Unchanged. Used to prove byte identity (see the golden plan). |
| `CHANGELOG.md` | | `### Added` |

**Two traits share the name `ObjectSource`.** This WP uses `crate::store::ObjectSource` (`read(&self)`, verifying).
`crate::verify::ObjectSource` (`closure.rs:49`, `fetch(&mut self)`, non-verifying) is the closure walker's trait. Use
the full path in the signature and rustdoc to avoid confusion.

## Design

```rust
/// Build a disclosure bundle proving `selector`'s content at `path` under `commit_id`, reading only through `source`.
///
/// `source` MUST return verified bytes from `read`/`read_object` (the `store::ObjectSource` contract). The builder
/// never calls `read_unverified`. It adds no verification of its own, so bundle bytes are identical to
/// `build_disclosure`'s. A lying source can only produce a bundle that `verify_disclosure` rejects: the bundle is
/// self-authenticating against `commit_id`.
///
/// # Errors
/// As [`build_disclosure`].
pub fn build_disclosure_from<S: crate::store::ObjectSource + ?Sized>(
    source: &S,
    commit_id: &Hash,
    path: &[&[u8]],
    selector: Selector,
) -> Result<Vec<u8>, VerifyError>;

/// Unchanged signature; now `build_disclosure_from(store, commit_id, path, selector)`.
pub fn build_disclosure(store: &crate::store::ObjectStore, commit_id: &Hash, path: &[&[u8]], selector: Selector)
    -> Result<Vec<u8>, VerifyError>;

fn build_payload<S: crate::store::ObjectSource + ?Sized>(source: &S, leaf_id: &Hash, selector: Selector)
    -> Result<PayloadWire, VerifyError>;
fn build_chunked_range_payload<S: crate::store::ObjectSource + ?Sized>(source: &S, cb: &ChunkedBlob, offset: u64,
    len: u64, with_offsets: bool) -> Result<PayloadWire, VerifyError>;
```

- **Error mapping stays identical.** `StoreError` still converts through the existing `VerifyError::Store(#[from])`
  (`verify.rs:270`). A server source reports "not a member" as `StoreError::ObjectNotFound`, so a missing object is
  the same error as today.
- **The same calls, in the same order, per selector.** Keep each `read` vs `read_object` call exactly as written.
  `ObjectStore`'s trait impl of `read_object` delegates to the inherent single-decode method
  (`store/source.rs:66–73`), so behavior and performance on the CLI path are unchanged.
- **`DisplaySource` is not a valid source here** (its `read` skips verification). Say so in the rustdoc. Don't add a
  runtime guard: the bundle is self-authenticating, and the contract is documented.

## Tests to write first

In `verify.rs` `mod tests`, using the existing fixture builder at :1488–1499 (`ObjectStore` over a temp
`RepoLayout`):
- `build_from_map_source_equals_store_builder`: a test-local `MapSource(BTreeMap<Hash, Vec<u8>>)` implements
  `store::ObjectSource`, verifying ids via `crate::verify::verify_object_id` in `read`. Load it with every object of the
  fixture repository. For each case, `build_disclosure_from(&map, …) == build_disclosure(&store, …)` byte for byte:
  - root tree (empty path)
  - shallow, nested and executable files
  - `Selector::Chunk(i)` for every chunk
  - `Selector::Range` in a small blob (first block, last partial block, whole)
  - a range inside a chunk, with and without offsets
- `build_from_ephemeral_sink_equals_store_builder`: the same through `EphemeralSink` over the store, a real
  in-tree source.
- `missing_object_in_source_is_store_error`: remove one tree object from the map; the error is
  `VerifyError::Store(StoreError::ObjectNotFound(_))`, identical to the store path with that object absent.
- `lying_source_bundle_fails_verification`: the map returns a different valid blob for a leaf id without
  verification (a deliberately non-verifying test source). The built bundle is rejected by `verify_disclosure` with
  a payload-id mismatch. This documents the self-authentication argument.
- Every existing `verify.rs` test and `tests/golden_disclosure.rs` passes unchanged.

## Golden-vector plan

The format is unchanged, so there are no new fixtures. **The byte-identity proof is mandatory.** `golden_disclosure.rs`
never calls the builder in a normal run, so the goldens alone don't prove the refactor. Regenerate them with the
refactored builder and require a zero diff:

```bash
( cd rust && MKIT_WRITE_GOLDEN=1 cargo test -p mkit-core --test golden_disclosure )
git diff --exit-code rust/tests/golden/disclosure/     # must print nothing (MANIFEST.txt digests unchanged)
( cd rust && cargo test -p mkit-core --test golden_disclosure )   # normal read-only verification run
```

Run it, then revert anything the generator touched (there should be nothing), and paste both commands' output into
the PR body.

## Gate commands (repo root)

```bash
export TMPDIR="$HOME/.cache/mkit-test-tmp"; mkdir -p "$TMPDIR"
( cd rust && cargo fmt --check )
( cd rust && cargo clippy --all-targets --all-features --workspace -- -D warnings )
( cd rust && cargo nextest run -p mkit-core -p mkit-cli -p mkit-wasm -p mkit-server )
( cd rust && cargo test --doc -p mkit-core )
( cd rust && MKIT_WRITE_GOLDEN=1 cargo test -p mkit-core --test golden_disclosure ) && git diff --exit-code rust/tests/golden/disclosure/
# wasm
( cd rust && cargo check -p mkit-core --no-default-features --target wasm32-unknown-unknown )
( cd rust && cargo clippy -p mkit-core --no-default-features --target wasm32-unknown-unknown --no-deps -- -D warnings 2>&1 \
    | grep -E '^ +--> ' | sort -u )   # ONLY the 6 baseline sites
( cd rust && cargo clippy -p mkit-server -p mkit-wasm --target wasm32-unknown-unknown --no-deps -- -D warnings )
( cd rust && cargo build -p mkit-wasm --target wasm32-unknown-unknown )
just ci-scripts
just ci                          # mkit-core public API (additive) — full gate per plan §1
```

## Acceptance checklist

- [ ] `build_disclosure_from` exists; `build_disclosure` is a one-line delegate; `mkit prove` is unchanged.
- [ ] Byte identity: the golden regeneration produces a zero diff, and the map-source and ephemeral-sink equivalence
      tests pass for every selector kind.
- [ ] Error mapping is identical (a missing object gives `VerifyError::Store(ObjectNotFound)`).
- [ ] The docs no longer call the builder native-only, and name the two `ObjectSource` traits unambiguously.
- [ ] wasm32 check/build pass; wasm clippy shows only the baseline sites.

## Risks

- **Silent double decode or extra reads.** A generic `read_object` default (`deserialize(read(h))`) on a source
  without an override decodes twice. That's fine for correctness; performance matters only on the CLI path, which
  keeps `ObjectStore`'s override.
- **Name collision** between the two `ObjectSource` traits (see above).
- **Scope creep** into cross-chunk ranges. That belongs to 4.11/4.14.

## Spec vs breakdown (specs win)

No conflict. The breakdown's "unchanged fixtures" is necessary but not sufficient, because the read-only golden test
never exercises the builder. The regeneration zero-diff step above is what actually proves byte identity.
