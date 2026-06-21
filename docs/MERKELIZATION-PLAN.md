# Merkelization Plan — "Merkelize Everything"

Status: **APPROVED FOR IMPLEMENTATION** (synthesized from three design lenses + adversarial
review; the review's BLOCKER/MAJOR corrections are applied below). Pre-1.0, breaking, no
migration. Stacks on PR #401 (`feat/push-delta-encoding`).

This document is the single source of truth for the stacked merkelization PR. Where the three
design lenses disagreed, **this document picks one answer** and the others are dead. The
normative crypto formulas live in the new `docs/SPEC-MERKLE-OBJECTS.md` (created by this work);
this plan is the engineering/sequencing contract.

> **As-built reconciliation (post-merge).** Three forward-looking choices below were superseded
> during implementation. Where they conflict, the code and `SPEC-MERKLE-OBJECTS.md` win:
> 1. **The BMT is vendored, not a `commonware-storage` dependency.** At the pinned
>    `commonware =2026.5.0`, `storage::bmt` is `std`-gated (drags in `zstd-sys`, no `wasm32`
>    target), and `mkit-core/src/merkle.rs` must compile to wasm for `mkit-core` *itself*. It
>    vendors the byte-identical BMT over `blake3`; `commonware-storage`/`-cryptography` are
>    **dev-dependencies** (a cross-check oracle), and only `commonware-codec` actually became
>    non-optional. Upstreaming of a `no_std` `bmt` is tracked by commonwarexyz/monorepo#4090.
> 2. **The inclusion-proof wire format is hand-rolled and provisional**
>    (`[u32 LE leaf_count][u32 LE n][n × 32B]`), not commonware-codec `Proof<Blake3::Digest>`,
>    and has no in-tree consumer yet (`SPEC-MERKLE-OBJECTS.md` §5). The `Proof<…>` / `decode_cfg`
>    references in §3.6/§5/§6.4 are superseded.
> 3. **Drift is guarded by a native equality test, not `commonware-conformance`.**
>    `merkle::tests::vendored_root_matches_commonware` pins the vendored root byte-for-byte against
>    `commonware_storage::bmt`.

---

## 1. Decision summary

| Axis | Decision |
|---|---|
| **Scope** | Merkelize **everything** that has a child-hash list: `ChunkedBlob` and `Tree` get BMT-root identities; the transfer/delta layer is reframed around that structure. Blob/Commit/Remix/Delta/Tag stay byte-hashed. |
| **Identity** | A merkelized object's content-address **IS its (domain-bound) BMT root** — `id = domain_digest(TYPE_DOMAIN, build(leaves).root().0)`. BREAKING. Pre-1.0, **no migration**. |
| **Primitive** | `commonware_storage::bmt` (stateless `Builder::<Blake3>` + `Tree`), **not** the MMR family — mirroring makechain `transactions_root.rs`: leaf sets are fixed and known up front, so MMR append/range-proof properties add no value. |
| **Shipping** | PR #401 gets the small structural cleanups (commonware-codec for the packlist; legacy per-object transfer deletion). Merkelization is a **NEW stacked PR** off #401's head. |
| **Legacy** | The legacy per-object transfer path is **DELETED**; fetch becomes single-format packmap-driven. |
| **Wire format** | `schema_version` stays `0x01`. The serialized **bytes** of Tree/ChunkedBlob do **not** change — only the byte→id function changes. Cross-format safety is a new **mandatory** `.mkit/format` repo marker, not a prologue bump. |

### Corrections applied from the adversarial review (do not relitigate)

These collapse the three lenses into one and fix two unsound variants:

1. **One identity formula** (review BLOCKER-1): domain-bound BMT root with per-type leaf schemes
   (below). The "bare root" (TRANSFER lens) and the un-typed-root variants are dead.
2. **ChunkedBlob metadata MUST be bound** (review BLOCKER-3): `total_size`/`chunk_size` are not
   derivable from the chunk list; a chunk-list-only root is a second-preimage hole. We bind them
   via a **meta leaf at position 0**.
3. **Empty-object id is computed, never hand-written** (review BLOCKER-2): the commonware empty
   BMT root is `H(leaf_count_be32 ‖ H(""))` (empty hasher finalize, *no* position prefix —
   verified at `storage/src/bmt/mod.rs:124-169`), **not** `H(0_be32 ‖ H(0_be32))` as two lenses
   claimed. We do not write the constant from prose; we pin it from a test run.
4. **Identity dispatch lives inside `ObjectSink::put_parts`** (review BLOCKER-4), not a parallel
   `put_object`, so every existing ingest call site is correct unchanged and `EphemeralSink` /
   `BulkWriter` cannot silently diverge.
5. **`diff_bmt` is dropped** (review MAJOR-2): keep the existing O(n) hashset pairing + size gate.
   The transfer payoff is "id==root makes the existing read-time re-hash a free completeness
   check" — pure deletion, nothing new on the wire.
6. **`.mkit/format` marker is mandatory and checked at repo-open** (review MAJOR-5); git-bridge +
   on-disk index are promoted to must-change (review MAJOR-4).

---

## 2. The exact leaf & root formulas

All formulas use the verified commonware `bmt` semantics: `Builder::<Blake3>::new(count)`,
`builder.add(&digest)` (the builder internally position-hashes each leaf as `H(pos_be32 ‖ digest)`),
`builder.build()`, `tree.root()` returns the **finalized** root `H(leaf_count_be32 ‖ tree_root)`
(binds the leaf count → malleability-resistant). `Hash = [u8;32]` ↔ `blake3::Digest` is the
trivial `#[repr(transparent)]` bridge (`Digest(h)` / `d.0`), exactly as makechain does.

`domain_digest(domain, body) = BLAKE3(len_le16(domain) ‖ domain ‖ body)` — the existing
`hash.rs` recipe.

### 2.0 The headline formula (both types)

```
id = domain_digest(TYPE_DOMAIN, build(leaves).root().0)
```

The outer `domain_digest` wrap is a **deliberate hardening** of the brief's literal "id BECOMES
its BMT root" — it is still the BMT root, now domain-separated. It buys three things the bare
root cannot:
- **Cross-type collision immunity**: empty Tree id ≠ empty ChunkedBlob id; a 1-entry Tree ≠ a
  1-chunk ChunkedBlob with the same child hash (different domains → different ids even for
  identical leaf streams). The prologue type byte is in the stored bytes but is **not** in a
  pure root, so without this wrap these collide.
- **A well-defined, type-distinct empty-object id** without the empty BMT sentinel ambiguity.
- Cost: one extra BLAKE3 over a 32-byte input. Negligible.

`TYPE_DOMAIN`:
- ChunkedBlob → `b"mkit.chunked\x00"`
- Tree → `b"mkit.tree\x00"`

### 2.1 ChunkedBlob

`ChunkedBlob { total_size: u64, chunk_size: u32, chunks: Vec<Hash> }`.

Leaves fed to `builder.add()`, in order:

```
leaf[0]      = meta_digest = domain_digest(b"mkit-cblob-meta-v1",
                               total_size.to_le_bytes() ‖ chunk_size.to_le_bytes())
leaf[1..=N]  = chunks[0], chunks[1], ..., chunks[N-1]      // raw 32-byte chunk hashes
```

```
chunked_id = domain_digest(b"mkit.chunked\x00",
                           Builder::<Blake3>::new(1 + N){add(meta), add(chunk_i)...}.build().root().0)
```

- **Chunk `i` lives at BMT position `i + 1`** (meta is position 0). The proof builder MUST
  document and apply this `+1` offset.
- **Metadata binding**: `total_size` and `chunk_size` change `meta_digest` → change leaf 0 →
  change the root. This closes review BLOCKER-3.
- **N=0** is well-defined (a 1-leaf tree, meta only); the empty ChunkedBlob does not occur in
  practice (worktree only emits ChunkedBlob above `CHUNK_THRESHOLD`) but needs no sentinel.
- **Proof semantics**: a chunk inclusion proof attests "chunk hash X is at chunk index `i`"
  (BMT position `i+1`). A meta proof attests the metadata. Both verify against `chunked_id`'s
  *inner* root (see §2.3 proof note).

### 2.2 Tree

`Tree { entries: Vec<TreeEntry{ name: Vec<u8>, mode: EntryMode, object_hash: Hash }> }`,
already lex-sorted by name and unique (enforced at decode).

Leaves fed to `builder.add()`, in existing lex order, one per entry:

```
leaf[i] = entry_digest = domain_digest(b"mkit-tree-entry-v1",
                            name_len.to_le_bytes()::u32 ‖ name ‖ mode_u8 ‖ object_hash_32)
```

```
tree_id = domain_digest(b"mkit.tree\x00",
                        Builder::<Blake3>::new(M){add(entry_digest_i)...}.build().root().0)
```

- The `name_len` u32 LE prefix is the anti-ambiguity guard so that
  `("ab", mode, h)` and `("a", mode, "b"‖h-prefix…)` cannot alias.
- **Why `entry_digest` and not the raw `object_hash` as the leaf** (review MAJOR-3): the leaf is
  what an inclusion proof attests. Feeding `entry_digest` means a Tree proof proves the full
  `(name, mode, object_hash)` triple is entry `i`. Feeding the raw `object_hash` would prove only
  "this child hash is at position i" — useless for a Tree. The differ/proof helpers MUST use
  `entry_digest` as the leaf.
- **Empty tree** (`entries = []`, real and common): `tree_id = domain_digest(b"mkit.tree\x00",
  build([]).root().0)`, where `build([]).root()` is the commonware empty root
  `H(0_be32 ‖ H(""))`. This is a fixed 32-byte constant — **pin it from an actual test run** as
  `TREE_EMPTY_ID`, never transcribe it from this prose (review BLOCKER-2).

### 2.3 Malleability binding summary (what each formula nails down)

| Mutation | Detected because |
|---|---|
| any chunk hash / entry field changed | leaf content changes |
| chunk / entry **reorder** | bmt position-hashes each leaf |
| chunk / entry **count** changed | finalized root binds `leaf_count_be32` |
| ChunkedBlob `total_size`/`chunk_size` forged | meta leaf (pos 0) changes |
| Tree name/mode/hash boundary ambiguity | `name_len` prefix in `entry_digest` |
| cross-type collision (empty Tree vs empty ChunkedBlob; 1-entry vs 1-chunk) | `TYPE_DOMAIN` wrap |

---

## 3. Store, serialize, hash, and the new `merkle` module

### 3.1 The core conflict and its resolution

The store's load-bearing invariant is: **on-disk key == `BLAKE3(canonical bytes)`**, re-verified
on every read. Merkelization wants key == BMT root, which is not `BLAKE3(serialized manifest)`.
Both cannot hold for Tree/ChunkedBlob. **Resolution:** the BMT root becomes the canonical id; the
store verifies Tree/ChunkedBlob **structurally** (decode → recompute root → compare to key) and
verifies all other types by byte-hash. The serialized manifest is still stored **verbatim** at the
path named by the root (the manifest holds `total_size`/`chunk_size`/`chunks`/entries, which the
root alone cannot reconstruct). Only *which function maps bytes→id* changes, and only for two types.

### 3.2 Write path — dispatch inside `ObjectSink::put_parts`

The `ObjectSink` trait's contract today is "hash the bytes, return the id." **Every** producer is
generic over it: `BulkWriter::write`, `ObjectStore::write`/`put`/`put_parts`,
`EphemeralSink::put_parts`, and all the worktree builders (`build_tree*`, `store_file_object`, the
chunk-emit loop). A merkelized object's id is therefore computed in two places that must agree
forever — the sink (for storage) and `build_tree`/`compute_tree_id` (for the parent's entry leaf).

**Decision (review BLOCKER-4):** make `ObjectSink::put` / `put_parts` **type-dispatch on the
prologue byte** (`bytes[0]`, already present and validated against the `MKT1` magic + version):

```
fn put_parts(parts) -> Hash:
    bytes = concat(parts)                            // see §3.3 buffering note
    match ObjectType::from_u8(bytes[0]):
        Tree        => key = merkle::compute_tree_id(&deserialize_tree(bytes)?)
        ChunkedBlob => key = merkle::compute_chunked_id(&deserialize_chunked(bytes)?)
        _           => key = hash::hash(&bytes)       // unchanged byte-hash
    write bytes to objects/<2hex of key>/<62hex of key>
    return key
```

This makes **every existing call site correct with zero edits**, structurally closes the
`EphemeralSink` / `BulkWriter` silent-divergence hazard, and keeps the
`put_object_via_batch_equals_via_store` invariant test passing. There is **no** parallel
`put_object` method.

### 3.3 Buffering note (review MAJOR-1 — do not claim zero ingest cost)

`EphemeralSink::put_parts` and the batch writer currently **stream** the hash over `parts` without
materializing the concatenation (copy-free). Computing a BMT root requires the full contiguous
bytes (to decode the leaves), so **for Tree/ChunkedBlob the sink must buffer-then-decode**.
Manifests are small, so the cost is negligible — but the spec must state it honestly: blobs and
chunks (the bulk of bytes) stay streaming/copy-free; only the two manifest types pay a buffer +
decode on put.

### 3.4 Read path — dispatch on the prologue byte

```
fn verify(key, bytes):                               # store.read / read_object / verify_object_type
    match ObjectType::from_u8(bytes[0]):
        Tree        => if merkle::compute_tree_id(&deserialize_tree(bytes)?)    != key: HashMismatch
        ChunkedBlob => if merkle::compute_chunked_id(&deserialize_chunked(bytes)?) != key: HashMismatch
        _           => if hash::hash(&bytes) != key: HashMismatch
```

- **Still content-addressed** (key is a deterministic function of canonical content, via BMT).
- **Still tamper-evident** (flip any byte → leaf/meta/order/count changes → root changes →
  `HashMismatch`; the `read_detects_corruption` test now exercises root-recompute).
- **Strengthening**: verification now goes through `deserialize`, so a structurally-invalid but
  correctly-addressed manifest cannot pass read (it could never be addressed in the first place).
- **Cost**: a raw `read()` of a Tree/ChunkedBlob now pays a decode. Documented and accepted; do
  NOT skip verification for these types (that would break tamper-evidence).

### 3.5 serialize.rs / hash.rs

- **serialize.rs**: NO change to writers/readers. The wire byte layout of Tree/ChunkedBlob is
  unchanged. The `MKT1` 6-byte prologue and `schema_version = 0x01` are unchanged.
- **hash.rs**: add two tiny bridge helpers next to the commonware import:
  `to_digest(h: Hash) -> Digest { Digest(h) }`, `from_digest(d: Digest) -> Hash { d.0 }`.
  No `executor.block_on` anywhere — `bmt` is fully synchronous (unlike the MMR path in
  `history.rs`).

### 3.6 New module — `mkit-core/src/merkle.rs` (mirror `transactions_root.rs`)

Mirror the makechain module 1:1 in shape. Public API:

```rust
// identity
pub fn compute_chunked_id(cb: &ChunkedBlob) -> Hash;
pub fn compute_tree_id(tree: &Tree) -> Hash;
pub const TREE_EMPTY_ID: Hash;                 // pinned from a test run (§2.2)

// index lookup (mirror makechain message_index)
pub fn chunk_position(cb: &ChunkedBlob, chunk_hash: &Hash) -> Option<u32>;  // returns i+1
pub fn tree_entry_position(tree: &Tree, name: &[u8]) -> Option<u32>;

// inclusion proofs (commonware-codec Proof bytes)
pub fn build_chunk_inclusion_proof(cb: &ChunkedBlob, position: u32) -> Result<Vec<u8>, MerkleError>;
pub fn verify_chunk_inclusion_proof(inner_root: &Hash, chunk_hash: &Hash, position: u32, proof: &[u8]) -> Result<(), MerkleError>;
pub fn build_tree_inclusion_proof(tree: &Tree, position: u32) -> Result<Vec<u8>, MerkleError>;
pub fn verify_tree_inclusion_proof(inner_root: &Hash, entry_digest: &Hash, position: u32, proof: &[u8]) -> Result<(), MerkleError>;
```

Internals: `Builder::<Blake3>::new(count)` / `add(&Digest)` / `build()` / `tree.root().0`;
proofs via `tree.proof(pos)` → `Encode::encode`; verify via
`Proof::<Digest>::decode_cfg(bytes, &max)` + `verify_element_inclusion(&mut Blake3::default(),
&leaf, pos, &root)` — byte-for-byte the makechain pattern. **Proofs verify against the inner
(pre-domain-wrap) root**, since `verify_element_inclusion` checks a BMT root, not the wrapped id;
expose an `inner_root(...)` helper or carry both. Leaf builders (`meta_digest`, `entry_digest`)
call `hash::domain_digest`. `Object`/`ObjectType` enums are unchanged.

### 3.7 graph.rs — UNAFFECTED

`reachable_closure` enqueues the child hashes *read out of* decoded objects
(`Tree.entries[].object_hash`, `ChunkedBlob.chunks[]`); it never recomputes a parent id. Subtree
entry hashes are now BMT roots, but graph.rs enqueues whatever hash it reads. No change.

### 3.8 worktree.rs — automatic via §3.2

Because identity dispatch lives in the sink, `store_file_object`, `build_tree*`, and the
chunk-emit loop are correct unchanged. The **one** explicit edit is `hash_file_object` (the
read-only status/diff mirror that does `hash(serialize(manifest))` directly, bypassing the sink):
change it to `merkle::compute_chunked_id(&cb)` so change-detection ids match what the sink would
store. Preserve the existing store-vs-hash equivalence test with the new function on both sides.

---

## 4. Transfer / delta rewire

### 4.1 Base selection — keep the existing O(n) hashset pairing (drop `diff_bmt`)

Per review MAJOR-2, **do not** introduce the merkle subtree differ. It would re-hand-roll the BMT
node ladder locally (commonware exposes no internal-node accessor), reintroducing exactly the
hand-rolled-merkle risk the effort exists to kill — and the win is illusory (n is one file's chunk
count; both the existing hashset diff and `diff_bmt` must build/hash all n leaves first; for the
canonical 30-chunk/1-edit case both are trivially fast).

Keep `pair_chunks` / `pair_trees` as the existing hashset-membership, same-index pairing feeding
`plan_pack`'s `HashMap<Hash, Hash>` (`new_chunk → base_chunk`). The raw-fallback **size gate**
(`HASH_LEN + stream.len() < target.len()`, else raw) is **unchanged** — a bad base proposal costs
one wasted encode, never correctness. If position-alignment improvement is wanted later, it is a
~3-line tweak to the existing same-index logic, not a new differ.

### 4.2 What merkelizing transfer actually buys — adopt completeness-via-root only

Evaluated honestly, the only real win is: **once a ChunkedBlob/Tree reconstructs, its id IS its
BMT root, so the store's existing read-time id check is simultaneously a proof that every
chunk/entry under it is present and correctly ordered.** The bespoke fetch-side closure-completeness
walk becomes redundant and is **deleted**. This is net code removal.

Explicitly **rejected** (ceremony without payoff):
- **(a) Subtree-possession proofs over the wire**: the push side already computes the local
  closure to build the pack; a possession proof replaces a free set-difference with a round-trip.
- **(c) Over-the-wire inclusion proofs for manifest deltas**: the receiver needs *all* leaves to
  reconstruct the file, so per-leaf proofs are dead weight; reconstructing the manifest and
  re-deriving its id already verifies the whole leaf set. Adopt only the "changed-leaf list" half
  of #410, which is just "the manifest is a delta-eligible object" — widen `try_delta` eligibility
  to Tree/ChunkedBlob manifests, gated by the same size check.

**Normative statement for SPEC-TRANSPORT: mkit transfer does NOT ship merkle proofs over the
wire; completeness is the chain of root-equals-id checks on reconstruction.**

### 4.3 Packmap chain — stays a content-addressed prev-pointer hash chain (NOT an MMR)

Apply makechain's own BMT-vs-MMR reasoning in reverse: the packmap chain is intrinsically
append-only with an unknown-up-front set (the MMR case), **but** content addressing already gives
it append-only tamper-evidence (each node id = hash of its bytes incl. `prev`; mutating any node
breaks every downstream id), and **no consumer wants history range-proofs** — fetch replays the
chain oldest-first. Adding an MMR here would contradict the house idiom's stated reasoning. Keep
the hash chain.

### 4.4 commonware-codec adoption (this lands in PR #401, not the merkle PR)

Replace hand-rolled `encode_packlist`/`decode_packlist` byte-offset arithmetic with
commonware-codec `Encode`/`Decode`/`Read`/`Write`/`EncodeSize` on `PackListNode`. Keep the `MKPL`
magic + version byte as a leading literal (preserve loud `InvalidMagic`/`UnsupportedVersion`).
`prev: Option<Digest>` and `packs: Vec<Digest>` encode directly; `PACKLIST_MAX_ENTRIES` maps to
the decode `Cfg` (range cap), matching makechain's `decode_cfg(bytes, &max)`. `PACKLIST_VERSION`
stays `1`. This is the structural-cleanup bucket of #401.

### 4.5 Post-legacy fetch — single format

1. Read `refs/mkit/packmap/<branch>` → head id; walk `prev` oldest-first (codec-decode each node).
   The legacy completeness pass and per-object `Transport` verbs are **deleted**.
2. `PackReader` applies each pack, resolving deltas against already-present bases (ordering
   guarantee unchanged).
3. **Completeness = root-equals-id** (§4.2): each manifest's reconstruction re-derives its BMT
   root via the store read check; a missing/misordered child → root mismatch → existing fatal
   `RemoteMissingObject`/`HashMismatch`. No separate traversal.

---

## 5. Spec doc edits + version bump decision

### 5.1 New doc

**Create `docs/SPEC-MERKLE-OBJECTS.md`** (normative, v1, status stable). Owns:
- §1 Primitive & rationale (BMT over MMR — the makechain three-bullet justification).
- §2 Leaf convention (per-type leaf schemes from §2 of this plan; raw child digest fed to `add`,
  builder position-hashes internally).
- §3 Root + identity: `id = domain_digest(TYPE_DOMAIN, build(leaves).root().0)`, with the bare
  inner root as the intermediate.
- §4 Empty-object id (computed/pinned, with the corrected empty BMT root note).
- §5 Inclusion-proof wire format: commonware-codec `Proof<Blake3::Digest>`, `decode_cfg` = max
  items, `verify_element_inclusion(&mut hasher, &leaf, pos, &inner_root)` — leaf is a `&Digest`.
- §6 Determinism/malleability invariants (§2.3 table).
- §7 Test vectors (committed goldens, both inner root and final id).

### 5.2 Edits to existing docs

- **SPEC-OBJECTS.md**:
  - §4 (Tree) + §7 (ChunkedBlob): identity paragraph → "object id is the BMT root per
    SPEC-MERKLE-OBJECTS, NOT `BLAKE3(serialized bytes)`." Wire byte layout unchanged.
  - §10 (Storage): read-time verification is **type-dependent** — recompute BMT root for
    Tree/ChunkedBlob, flat `BLAKE3` otherwise. Add the `.mkit/format` repo marker requirement.
  - §12 (Version history): the no-bump decision (§5.3).
  - §13 (Test vectors): regenerate Tree/ChunkedBlob id pins; add a negative
    "id ≠ BLAKE3(serialized bytes)" vector.
- **SPEC-FASTCDC.md**: §6/§8 one sentence each — chunk boundaries/blob hashes unchanged (frozen);
  the **manifest** id is now the BMT root (cross-ref SPEC-MERKLE-OBJECTS). Boundary goldens
  untouched.
- **SPEC-PACKFILE.md**: §3.1/§3.2 — "verify object id matches storage path" is type-dependent
  (BMT root for tree/chunked, flat BLAKE3 otherwise). Packfile framing/version unchanged.
- **SPEC-DELTA.md**: §1/§6 clarifying note — reconstructed bytes are addressed per
  SPEC-OBJECTS §10 (BMT root for merkelized types); `base_hash` is "the base object's id" (a BMT
  root if the base is merkelized). No wire change.
- **SPEC-TRANSPORT.md**: note codec adoption for the packlist; **normative**: no merkle proofs on
  the wire; completeness via root-equals-id. Confirm no object-granular transfer verb survives.
- **SPEC-CONFIG-SECURITY.md** (or SPEC-OBJECTS §10): document the mandatory `.mkit/format` /
  `core.objectAddressing = bmt-v1` marker and the `IncompatibleRepoFormat` open-time error.

### 5.3 Version bump decision — DO NOT bump `schema_version` (stays `0x01`)

The `schema_version` byte binds the serialized **layout**, which is genuinely unchanged for every
type — only the byte→id function changes, and only for two types. Bumping would (a) falsely signal
a wire change, (b) needlessly churn every unaffected Blob/Commit/Remix/Tag golden, and (c)
contradict §12's own rule ("a bump is reserved for changes that alter an existing type's layout").
The cross-format hazard is caught by **two louder, more specific guards**:
1. **Mandatory `.mkit/format` marker** checked at repo-open → early `IncompatibleRepoFormat`
   (the only *upfront* guard; old repos lack it → rejected before any object read).
2. The **read-time id mismatch** for Tree/ChunkedBlob (old byte-hash path ≠ recomputed root) →
   loud `HashMismatch`. Free and unavoidable, but late — hence the marker is mandatory, not
   optional (review MAJOR-5: an old repo's Blob/Commit objects are still valid under new rules, so
   a partial walk can get surprisingly far before the first Tree fails confusingly).

---

## 6. Invariants, tests, fuzz/conformance

### 6.1 Invariants the tests must lock

1. **Cross-machine determinism**: same leaf stream → identical id on every platform (bmt uses
   fixed BE; our wrap/prefixes are BE; no endian leakage). Pinned as goldens.
2. **Leaf-count binding**: N vs N+1 chunks/entries never collide; a duplicated-last-leaf padded
   list of length N+1 must not collide with the length-N tree (the odd-node-duplication
   malleability — defeated by the `leaf_count` prefix). Lock with a test.
3. **Type binding**: empty Tree id ≠ empty ChunkedBlob id; 1-entry Tree id ≠ 1-chunk ChunkedBlob
   id with the same child hash. Golden negatives.
4. **Metadata binding (ChunkedBlob)**: same chunks, different `total_size`/`chunk_size` → different
   id (closes BLOCKER-3; the only lens that listed this was IDENTITY — make it a hard test).
5. **Tree ordering binding**: reordering entries changes the id; unsorted input rejected at decode
   (`InvalidEntryOrder`); canonical order → stable id.
6. **id ≠ BLAKE3(serialized bytes)**: explicit negative for any non-degenerate object.
7. **Round-trip addressing**: `parse(serialize(obj))` → same id; store-write-then-read returns an
   object whose recomputed root == path.
8. **Empty-object ids are the pinned computed constants** (golden; most-cited cross-impl vectors).
9. **Inclusion-proof soundness/completeness**: valid proof verifies; wrong root/leaf/position/
   leaf-count rejects cleanly.

### 6.2 Unit tests (`merkle.rs::tests`, mirror `transactions_root.rs::tests`)

`{tree,chunked}_id_is_32_bytes`, `id_is_deterministic`, `id_changes_when_a_leaf_changes`,
`id_changes_when_leaf_count_changes`, `chunked_id_changes_when_metadata_changes`,
`ordering_matters` (Tree), `empty_tree_id_matches_golden_constant`,
`empty_tree_id_ne_empty_chunked_id`, `single_entry_tree_ne_single_chunk_blob_same_child`,
`id_ne_flat_blake3_of_serialized_bytes`, and the full proof suite copied from makechain
(`proof_round_trip_{first,middle,last}`, `wrong_{root,leaf,position}_fails`,
`out_of_range_position_rejected`, `proof_against_wrong_leaf_count_root_fails`).

### 6.3 Integration tests

- **Extend `mkit-cli/tests/push_delta.rs`** (named template): it commits a >1 MiB FastCDC file,
  edits 16 bytes, asserts a delta-sized second push, clones byte-identically with hash-verified
  closure. Two required changes/additions:
  - **Fix the hard-coded `hash::hash(&bytes) == h` closure checks** (around the clone read-back) —
    these will FAIL on merkelized objects; switch to the type-dispatched id check (BMT root for
    tree/chunked). This is a concrete known breakage.
  - Add: the ChunkedBlob manifest id is **stable across the v1→v2 edit for unchanged chunks**, and
    the parent Tree/Commit ids change deterministically (pin them) — proves merkle addressing
    didn't break dedup.
- **New `mkit-cli/tests/merkle_id_stability.rs`**: commit a large file in two fresh repos →
  identical Tree/ChunkedBlob/Commit ids (cross-repo determinism); edit one leaf → only the
  affected ChunkedBlob + ancestors change.
- **New `IncompatibleRepoFormat` test**: a pre-merkle on-disk repo/index (no `.mkit/format`) is
  rejected loudly at open, not silently misread (review MAJOR-4/5).

### 6.4 Golden / conformance

- New `rust/tests/golden/phaseN/` (next free index): `tree_empty`, `tree_single`, `chunked_3`
  with unchanged `.mkit.bin`, `.json` sidecar carrying **both** the inner `tree_root` and the
  final domain-bound `id`, plus `MANIFEST.txt`. Regenerate invalidated `phase1/` and `git-bridge/`
  vectors in a dedicated commit.
- **commonware-conformance** applied to the `Proof<Blake3::Digest>` wire encoding (now a public
  mkit wire structure) and to the canonical-vector ids — the idiomatic guard against silent
  proof-format drift across a commonware bump.

### 6.5 Fuzz

New `rust/fuzz/fuzz_targets/merkle_id.rs` and `merkle_proof.rs`, mirroring commonware
`storage/fuzz/bmt_operations.rs`: arbitrary `(leaf_count, leaf_bytes, position)` → building never
panics, id deterministic, `build_proof(pos)` then `verify` round-trips, `verify` on arbitrary
bytes never panics and rejects cleanly. Register both in `rust/fuzz/Cargo.toml`.

---

## 7. Dependency-ordered build sequence

Stacking: branch `feat/merkle-objects` off PR #401's head (`feat/push-delta-encoding`). Do **not**
fold merkelization into #401. Each numbered step is an independently testable commit/sub-PR; the
tree stays green at every step.

| Step | Commit | Depends on | Parallelizable? |
|---|---|---|---|
| **0** | (in #401) commonware-codec for `PackListNode`; delete legacy per-object transfer path | — | independent of merkle work; lands first in #401 |
| **1** | `merkle.rs` — `compute_*_id`, proofs, `TREE_EMPTY_ID` (pinned from a test run), full unit tests. Add hash.rs Digest bridge. No callers. | 0 | the **spec doc draft (step 6)** can be written in parallel |
| **2** | Make `commonware-cryptography`/`-storage`/`-codec` **non-optional** in `mkit-core`; confirm `bmt` builds on `wasm32` with `default-features=false` (no `std`/fs leakage) **before** flipping | 1 | gate on the wasm check (review MINOR) |
| **3** | `Object::id()` type-dispatched method (flat BLAKE3 vs `merkle::compute_*`); invariant test `id != flat_hash`. No store behavior change yet (purely additive) | 1 | — |
| **4** | `store.rs` — flip identity dispatch **inside `ObjectSink::put_parts`** + read-verify (§3.2/§3.4); `hash_file_object` (§3.8); `.mkit/format` write at init + mandatory `IncompatibleRepoFormat` check at open. **This is the breaking flip** — regenerate goldens in the SAME logical unit | 2, 3 | — (the one non-green-able boundary; keep it atomic) |
| **5** | `pack.rs` unpack verify via `Object::id()`; widen `try_delta` eligibility to manifests | 4 | with step 6/7 |
| **6** | Transfer rewire: completeness-via-root (delete bespoke walk); confirm packlist codec untouched; finish legacy deletion residue | 4 | with step 5 |
| **7** | Specs: land SPEC-MERKLE-OBJECTS.md + the 5–6 edits (move with the code) | 4 | draftable from step 1; finalize after 4 |
| **8** | Integration + fuzz: fix `push_delta.rs` closure checks, add `merkle_id_stability.rs` + `IncompatibleRepoFormat` test, register fuzz targets, wire conformance | 5, 6 | tests for store (4) can start once 4 lands |
| **9** | Golden regen commit (regenerated `phase1/`, `git-bridge/`, new `phaseN/`) — its own commit for reviewability | 4 | — |

**Why this never breaks the tree:** steps 1–3 are purely additive (new code, no id change). The id
flip (4) and its hard dependents (5, 6) plus regenerated goldens (9) land as one consistent unit —
there is no intermediate state where the store writes one addressing and reads another. Specs (7)
and tests (8) describe the now-consistent behavior. **Parallelizable for a future team:** step 6
(transfer) and step 5 (pack) run concurrently after step 4; the spec doc (7) drafts alongside step
1; fuzz/conformance (8) parallelizes once its dependencies land.

### Blast-radius checklist (must-change vs must-audit)

- **Must change**: `merkle.rs` (new); `hash.rs` (bridge); `store.rs` (`ObjectSink::put_parts`
  dispatch + read-verify + `.mkit/format`); `worktree.rs::hash_file_object`; `object.rs`
  (`Object::id()`); `pack.rs` (unpack verify + manifest delta eligibility); `transfer.rs`
  (completeness-via-root, legacy deletion); `Cargo.toml` (three crates non-optional).
- **Must change (promoted by review MAJOR-4)**: git-bridge `import.rs`/`reconstruct.rs`/
  `translate.rs` (git tree → mkit Tree stored under BMT root; round-trip golden ids change; **purge
  any persisted git↔mkit oid map**); `index.rs` (on-disk index entries holding tree ids must be
  regenerated; reject a pre-merkle index).
- **Must audit (construct a Tree/ChunkedBlob then store/expect an id)**: `ops/merge.rs`,
  `ops/restore.rs`, `ops/cherry_pick.rs`, `ops/revert.rs`, `ops/gc.rs`, `ops/graph.rs` (tests),
  and every test asserting a literal Tree/ChunkedBlob id (`ops_integration.rs`,
  `ops2_integration.rs`, `tree_depth.rs`, `chunked_blob_roundtrip.rs`, `golden.rs`). These are
  automatically correct **as long as they store via the sink** (§3.2) — audit confirms none
  byte-hash a manifest directly.
- **Explicitly NOT touched**: `graph.rs` closure logic; Blob/Commit/Remix/Delta/Tag identity;
  `serialize.rs` wire format; `ObjectType`/`Object` enums; the prologue and `schema_version`; the
  packmap-chain shape (stays a hash chain).

---

## 8. Open questions / residual risks (need a human decision)

1. **Domain-bound root vs bare root** (hardening of the literal brief). This plan uses
   `domain_digest(TYPE_DOMAIN, root)` to kill cross-type collisions. It is "the BMT root" in
   spirit but is one BLAKE3 step removed from `tree.root()` literally. **Confirm** this hardening
   is acceptable, since the brief said "id BECOMES its BMT root." If a bare root is mandated
   instead, we need an alternative cross-type-collision defense (e.g. a type-tag leaf at position
   0 for both types) — uglier and it perturbs the makechain-mirrored shape.
2. **WASM viability of non-optional `commonware-storage`** (review MINOR / step 2 gate). `bmt` is
   pure-compute, but `commonware-storage` is currently imported with `features=["std"]`. **Must
   confirm** `bmt` compiles for `wasm32` with `default-features=false` (codec+crypto only) before
   committing to non-optional. If it does not, the fallback is a thin vendored/feature-gated bmt
   shim — decide before step 2.
3. **`.mkit/format` marker semantics**: file vs config key, exact value (`bmt-v1`), and whether the
   open-time check is fatal everywhere or has a `--force` escape for power users. Recommended:
   fatal, no escape (pre-1.0, clean break). **Confirm.**
4. **Persisted git↔mkit oid mappings** (review MAJOR-4): if any notes/cache maps git sha ↔ mkit
   hash on disk, it is invalidated by the Tree-id cascade. Confirm whether such a map is persisted
   and must be dropped/regenerated (vs recomputed lazily).
5. **Conformance scope**: do we gate CI on commonware-conformance for the `Proof` encoding now, or
   land it as a follow-up? It is the only guard against silent proof-format drift across a
   commonware version bump; recommended to gate now.
6. **Empty ChunkedBlob**: defined but never produced today. Confirm we keep it as a well-defined id
   (N=0 → meta-only 1-leaf tree) rather than forbidding it at construction, in case a future
   zero-length large-file path emits one.

---

*Precedent mirrored:* makechain `crates/makechain-consensus/src/transactions_root.rs`.
*Primitive:* `commonware_storage::bmt` v2026.5.0 (`storage/src/bmt/mod.rs`).
*Verified empty BMT root:* `H(leaf_count_be32 ‖ H(""))` — empty hasher finalize, no position
prefix (`bmt/mod.rs:124-169`).

---

## 9. Follow-up issues #406 / #408 — determination (transfer chain depth)

The transfer follow-ups #406 (bound packmap chain depth via re-baseline) and #408
(atomic branch+packmap advance) were investigated and are **deliberately not landed
client-side**. The reasoning is now test-backed, not just asserted:

- **#406 (re-baseline) is unsound without #408.** Two client-side forms exist, both
  rejected:
  - *Reset-and-orphan* (reset the packmap to a fresh self-contained chain) **leaks
    storage**: the `Transport` API has no delete verb (`upload_pack`/`download_pack`/
    `pack_exists`/`upload_blob`/`download_blob`/`update_ref`/`read_ref`/`list_refs` only),
    so orphaned nodes/packs are unreclaimable until server GC (makechain **#849**).
  - *Checkpoint truncation* (append a `self_contained` node; walk back only to the most
    recent checkpoint) is leak-free but **unsound under concurrent/divergent pushes**.
    A prototype was written and the existing `divergent_concurrent_push_leaves_cloneable_remote`
    integration test caught it: a losing divergent pusher who lacks the winner's commit
    plans a full-closure (self-contained) pack, so the packmap head becomes a *checkpoint
    that reconstructs the loser's closure* while `refs/heads/<branch>` points at the
    winner's tip. The truncated walk then reconstructs the wrong closure and the clone is
    missing objects. The current full-chain walk masks this by unpacking everything.
    Correctness requires the packmap head to always match the head ref — i.e. **#408's
    atomic head+packmap advance**.

- **#408 (atomic advance) requires a server protocol change.** Making `refs/heads/<branch>`
  and `refs/mkit/packmap/<branch>` advance atomically needs a multi-ref server-side
  transaction; the CAS-only `update_ref` cannot express it. This is makechain-server work,
  not a client change. The client invariant *"head never advances past a packmap that
  fails to reconstruct it"* already holds via the packmap-before-head ordering in
  `advance_packmap`.

**Client-side bound that IS in place:** `MAX_PACK_CHAIN_DEPTH` (100k nodes) makes a
pathologically long or cyclic chain fail loudly (`PackChainInvalid`) rather than hang.
That is the correct client guard until #408 lands the server-atomic advance that makes a
true re-baseline sound.
