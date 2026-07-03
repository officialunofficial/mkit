---
spec: SPEC-BLAME-PROOF
version: 1
status: draft
audience: implementers of provable-blame proof producers and verifiers (mkit-core blame/merkle/sign, mkit-attest, mkit-cli)
---

# SPEC-BLAME-PROOF — mkit v1 provable blame

Status: **Draft. This document is the design spec (issue #495, "PR A");
no code implements it yet.** `mkit blame` already answers "which commit
last touched each line" (`rust/crates/mkit-core/src/ops/blame/`). This
spec defines a proof object that makes one blame *result* — "line N of
file F at commit C is attributed to commit X" — tamper-evident and
checkable by a verifier that never runs blame itself and never
downloads the full parent chain.

Scope: the predicate schema, the verification algorithm, the ancestry
proof (v1 chain-walk, v2 roadmap), the pinned `BlameOptions` record, and
the CLI surface. This spec also freezes `SPEC-MERKLE-OBJECTS.md` §5 (the
BMT inclusion-proof wire format), whose first in-tree consumer this is.

Out of scope for this document (see §11): proving the attribution
*computation* itself, and any new verifiable-database dependency.

Sequencing: this is deliverable 1 of 3 for issue #495 (PR A, docs
only). PR B (`mkit-core` build/verify functions + golden tests) and
PR C (attest/CLI wiring) follow in separate PRs against this frozen
schema. See §12.

---

## 1. Motivation

mkit's thesis is cryptographic attribution: content is identified by
Merkle-rooted hashes (`SPEC-MERKLE-OBJECTS.md`), commits are signed
(`SPEC-SIGNING.md`), and branch membership is provable via an MMR
(`SPEC-HISTORY-PROOF.md`). Blame is the one attribution surface that
still requires a verifier to trust a full local recomputation. This
spec composes the existing primitives — BMT tree-path proofs, the
commit-signing preimage, and a DSSE attestation envelope — into a
proof that a light verifier can check without either re-running blame
or holding the object store.

## 2. Trust model (D1): data, not computation

Provable blame proves the *result* is tamper-evident and bound to real
objects; it does **not** prove the attribution algorithm ran correctly.
The attributor's computation is trusted the same way a signed commit's
authorship is trusted — by the signature, not by re-execution. Quoting
issue #495 verbatim, since these two statements are the boundary of
what this spec does and does not claim:

> Verify the computation (out of scope). Proving that the diff/LCS
> attribution algorithm itself ran correctly over the whole history is
> SNARK-shaped and far larger. Explicitly not in scope here; note it as
> a non-goal.

> A provable-blame proof would compose these existing primitives rather
> than import a new verifiable database (e.g. qmdb). qmdb / commonware's
> ADB would only be worth considering for a dedicated, persisted,
> authenticated `(commit, path, line) → origin` index; default to the
> in-house BMT+MMR for consistency with the object format.

What the proof *does* guarantee, given a verifier that trusts the
signer identified by the envelope's `keyid`:

- The attributed content (`attributions`) is exactly what the signer
  attested — nobody altered the per-line origins after signing.
- The claimed file bytes really are the tree at commit `C` (BMT
  tree-path, §7 step 2) and `C` really is the commit whose id and
  signature this envelope carries (§7 step 3–4).
- Every distinct origin commit named in `attributions` really is an
  ancestor of `C` (§8) — the proof cannot silently attribute a line to
  a commit outside `C`'s history.

It does **not** guarantee the LCS/diff walk that produced the mapping
was itself correct; a dishonest but well-formed signer could attest a
wrong mapping and this proof would verify. That risk is identical to,
and no worse than, trusting any other signed mkit object.

## 3. Carrier and subject (D2)

The proof is a DSSE envelope through the existing `mkit-attest`
machinery (`SPEC-ATTESTATIONS.md`), not a new wire primitive and not a
new `Commit` field. This is placement "(b) signed sidecar" from the
issue's design notes: no wire break, attester-trusted.

**Predicate type URI.** `mkit-attest::statement` is predicate-agnostic
(`rust/crates/mkit-attest/src/statement.rs` enforces only that the
predicate is a JSON object; `predicate_type` is caller-supplied). The
issue's initial sketch proposed `https://mkit.dev/attestation/blame-proof/v1`,
but every predicate type URI that actually ships in this codebase
follows one convention instead:

```
https://github.com/officialunofficial/mkit/spec/predicate/<name>/v1
```

— `git-bridge/v1` (`mkit-cli/src/commands/git.rs`), `git-import/v1`
(`mkit-cli/src/commands/git_import.rs`), `release/v1`
(`mkit-cli/src/commands/self_update.rs`), and the CLI's own
placeholder default `.../predicate/empty/v1` (`docs/SPEC-ATTESTATIONS.md`
§8). This spec follows that convention rather than the issue's sketch:

```
predicateType = "https://github.com/officialunofficial/mkit/spec/predicate/blame-proof/v1"
```

**Subject.** One subject entry, per `statement::Subject`
(`digest.blake3` + optional `name`):

```json
{ "digest": { "blake3": "<blob object id, hex64>" }, "name": "<repo-relative path>" }
```

The subject digest is the **blamed file's blob object id** — the
`ChunkedBlob` id (SPEC-MERKLE-OBJECTS §2) for a chunked file, or the
flat blob id (SPEC-OBJECTS §10) for a small unchunked one — not the
commit hash. `name` carries the repo-relative path instead of the
`mkit-attest::statement::for_commit` default of `"commit"`; producers
build the `Statement` directly rather than through that convenience
helper.

## 4. Verifier input assumption (D3)

The verifier is assumed to hold **the exact file bytes at commit `C`**
being blamed — that is what a blame proof is a proof *of*. Given that
assumption:

- The verifier splits the provided bytes into lines itself; the proof
  never has to carry a per-line Merkle commitment or a chunk+offset
  construction. This closes the "line-level addressing" gap the design
  notes flagged (BMT addresses chunks, not lines).
- The proof only has to bind the given bytes to `C` (via the blob id
  and the tree-path, §7 steps 1–2) and to the per-line origin map
  (§6's `attributions`, carried inside the signed predicate itself —
  no separate commitment needed since the whole predicate is under
  signature).

A verifier that does **not** have the file bytes cannot use this proof
to learn line content; it can still check the shape and ancestry of
the proof but only the `commit`/`path`/`blob` identifiers, not that any
particular byte content is what the attributions describe.

## 5. Reference code this spec is normative against

| Concept | Reference |
|---|---|
| BMT tree inclusion proof build/verify | `merkle::{tree_entry_position, build_tree_inclusion_proof, verify_tree_inclusion_proof}` (`rust/crates/mkit-core/src/merkle.rs`) |
| BMT object identity (`Tree`/`ChunkedBlob`) | `merkle::{compute_tree_id, compute_chunked_id, tree_inner_root, chunked_inner_root}` (same file); `SPEC-MERKLE-OBJECTS.md` §2 |
| Commit signing preimage | `sign::commit_signing_bytes` (`rust/crates/mkit-core/src/sign.rs`) |
| Ancestor-set walk / ancestry check | `ops::graph::collect_ancestor_set`, `ops::merge::is_ancestor` (`rust/crates/mkit-core/src/ops/{graph,merge}.rs`) |
| Per-line attribution record | `ops::blame::BlameLine` (`rust/crates/mkit-core/src/ops/blame/mod.rs`) |
| Attribution knobs | `ops::blame::BlameOptions` (same file) |
| DSSE statement / predicate encoding | `mkit_attest::statement` (`rust/crates/mkit-attest/src/statement.rs`) |
| Envelope verification | `mkit_attest::verify::{verify_envelope, verify}` (`rust/crates/mkit-attest/src/verify.rs`) |

## 6. Predicate schema (D4)

The predicate body is **JCS-canonical JSON** (RFC 8785, same
canonicalisation `mkit-attest::jcs` already uses for the enclosing
Statement — member keys sorted, no insignificant whitespace). Field
names are camelCase, matching every other mkit predicate that ships
today (e.g. `git-import/v1`'s `gitCommit`/`refName`/`remoteUrl`).

All hash fields are lowercase 64-character hex (`hash::to_hex`
output) unless noted otherwise. `v` (the outermost field,
alphabetically last but semantically primary) is a plain integer,
**always present**, so a v2 ancestry section can be introduced later
without an envelope-format break (per D5, §8.3).

Shown here in JCS member order (alphabetical):

```json
{
  "attributions": [[1, "<hex64 origin commit>"], [2, "<hex64>"], "..."],
  "blameOptions": {
    "copies": null,
    "firstParent": false,
    "ignoreRevPrecise": false,
    "ignoreRevs": [],
    "ignoreWhitespace": false,
    "moves": null
  },
  "blob": "<hex64>",
  "chunkLayout": { "chunkSize": 0, "totalSize": 4096 },
  "commit": "<hex64>",
  "commitHeader": {
    "author": { "bytes": "<hex>", "kind": 1 },
    "message": "<base64>",
    "parents": ["<hex64>", "..."],
    "signer": "<hex64>",
    "timestamp": 1751500000,
    "tree": "<hex64>"
  },
  "origins": [
    { "commit": "<hex64>", "header": { "...": "same shape as commitHeader" } }
  ],
  "path": "src/lib.rs",
  "treePath": [
    {
      "childId": "<hex64>",
      "entryMode": 1,
      "entryName": "lib.rs",
      "innerRoot": "<hex64>",
      "position": 3,
      "proof": "<hex bytes>"
    }
  ],
  "v": 1
}
```

### 6.1 Field reference

| Field | Type / encoding | Meaning |
|---|---|---|
| `v` | `u32`, literal `1` for this spec | Predicate format version. Lets v2 (§8.3) swap the ancestry representation without an envelope break. |
| `commit` | hex64 | `C`, the blamed commit, as its **derived identity** (§6.3a) — `BLAKE3(commit_signing_bytes(commitHeader))` — not the commit's store object id. |
| `path` | UTF-8 string | Repo-relative path of the blamed file (forward slashes, matching worktree path conventions elsewhere in mkit). |
| `blob` | hex64 | The blamed file's blob object id at `C` — `ChunkedBlob` id (SPEC-MERKLE-OBJECTS §2) if chunked, else the flat blob id (SPEC-OBJECTS §10). Must equal the innermost `treePath` entry's `childId`. |
| `chunkLayout` | `null` \| `{ "totalSize": u64, "chunkSize": u32 }` | `null` when `blob` is a flat (unchunked) `Blob` — recompute its id per SPEC-OBJECTS §10 directly from the file bytes. Otherwise the two `ChunkedBlob` metadata fields (SPEC-MERKLE-OBJECTS §3.1): `chunkSize = 0` means content-defined chunking (SPEC-FASTCDC, fully deterministic given the file bytes — no chunk boundary list is needed since the gear-table seed and cut parameters are normative constants); `chunkSize > 0` means fixed-size chunking at that width. Either way the verifier re-derives the chunk list and `compute_chunked_id` from the file bytes alone. |
| `attributions` | array of `[u32 lineNum, hex64 originCommit]` pairs | Dense, 1-based, one entry per line of the file at `C`, in line order. `lineNum` values are exactly `1..=N` where `N` is the number of lines the verifier gets by splitting the provided file bytes (§4) — a gap or duplicate is a proof-shape error, not silently ignored. Each `originCommit` is that origin's **derived identity** (§6.3a). |
| `blameOptions` | object, see §9 | The `BlameOptions` the attributor ran blame with, so a verifier knows which attribution semantics (`-w`, `-M`, `-C`, ignore-revs, first-parent) produced this mapping. |
| `treePath` | array, leaf → root, see §6.2 | BMT inclusion proof chain from the blob's tree entry up to `commitHeader.tree`. |
| `commitHeader` | object, see §6.3 | The preimage fields of `commit_signing_bytes` for `C` — rehashing them must reproduce `commit` (the derived identity, §6.3a). |
| `origins` | array of `{ "commit": hex64, "header": <commitHeader shape> }` | Deduplicated headers for every commit reachable while walking ancestry (§8) for each distinct origin in `attributions`, plus every commit on the connecting path(s) to `C`. Typically shared across multiple origins, so the bundle is the *union* of paths, not one path per origin. `commit` is the entry's derived identity (§6.3a); its `header` must rehash to it. |

### 6.2 `treePath` entries

One entry per directory level from the file's immediate parent tree up
to the tree commit `C` points at, **leaf → root** order:

| Field | Type | Meaning |
|---|---|---|
| `entryName` | UTF-8 string | The `TreeEntry.name` at this level (one path component). |
| `entryMode` | `u8` | The `TreeEntry.mode` raw discriminant (`EntryMode`: `1`=Blob, `2`=Tree, `3`=Symlink, `4`=Executable). Required because `merkle::tree_entry_leaf` hashes the full `(name, mode, object_hash)` triple — omitting `mode` (as the issue's initial sketch did) would let the verifier reconstruct the wrong leaf digest. |
| `childId` | hex64 | The object id this entry points at: `blob` at the innermost level, or the previous level's derived tree id otherwise. Carried explicitly (rather than only derived) so each level verifies independently. |
| `innerRoot` | hex64 | The **bare** (pre-domain-wrap) BMT root of the `Tree` object that contains this entry — the value `merkle::tree_inner_root` would produce, and the required input to `verify_tree_inclusion_proof`. This is deliberately not the same as the tree's wrapped object id (SPEC-MERKLE-OBJECTS §2); see verification step 2 below. |
| `position` | `u32` | The entry's BMT position within that tree (`merkle::tree_entry_position`). |
| `proof` | hex bytes | Wire form `[u32 LE leaf_count][u32 LE n_siblings][n × 32B]`, exactly `merkle::build_tree_inclusion_proof`'s output (SPEC-MERKLE-OBJECTS §5, frozen by this spec — §13). |

### 6.3 `commitHeader` / `origins[].header`

Every field `sign::commit_signing_bytes` folds into the signing
preimage, so that rehashing this object reproduces the commit's
**derived identity** (§6.3a) exactly:

| Field | Type | Meaning |
|---|---|---|
| `tree` | hex64 | `Commit.tree_hash`. |
| `parents` | array of hex64 | `C`'s parents, in order (order matters — it is part of the signing bytes), each encoded as the parent's own **derived identity** (§6.3a), not the raw `Commit.parents` store hash. |
| `author` | `{ "bytes": hex, "kind": u8 }` | `Commit.author` (`Identity`): `kind` is `IdentityKind`'s raw discriminant (`1`=Ed25519, `2`=DidKey, `3`=Opaque); `bytes` is the identity payload (32-byte Ed25519 pubkey, or arbitrary bytes for the other kinds). |
| `message` | base64 (standard alphabet) | `Commit.message`. Base64, not hex, because the message is arbitrary-length text/bytes, not a fixed-width digest — matching the DSSE envelope's own `payload`/`sig` convention (`mkit-attest::envelope`), not the fixed-hex convention used for hashes and keys elsewhere in this document. |
| `timestamp` | `u64` | `Commit.timestamp`. |
| `signer` | hex64 | `Commit.signer` (the pubkey identifying who signed `C` — distinct from `author`, which is attribution metadata, not itself verified by the commit's own signature check here). |

`commitHeader` deliberately omits `Commit.signature`,
`Commit.message_hash`, and `Commit.content_digest` — none of the three
are part of `commit_signing_bytes` (SPEC-OBJECTS §5.1 / `sign.rs`
doc comment), so they cannot be recomputed from this object and are
not needed to prove `commit` is correct. The issue's initial D4 sketch
omitted `message` from this list; it is required here because leaving
it out would make it impossible to reproduce `commit_signing_bytes`
byte-for-byte for any commit with a non-empty message.

### 6.3a Derived commit identity

A commit's real store object id is `BLAKE3` of its **full** serialized
bytes (SPEC-OBJECTS §10 / `serialize::write_commit`), which include
`Commit.signature`, `Commit.message_hash`, and `Commit.content_digest`
— the three fields §6.3 deliberately omits from `commitHeader`. A
verifier holding only a header therefore can never reconstruct the
real object id. Every commit-identity field in this predicate —
`commit`, `origins[].commit`, each `attributions` origin, and every
`parents` entry inside a header — is instead the proof's own **derived
identity**:

```
derived_id(header) = BLAKE3(commit_signing_bytes(header))
```

i.e. the plain BLAKE3 of the SPEC-SIGNING §3 signing-byte
serialization rebuilt from the header, where the header's `parents`
are themselves derived identities — the construction is applied
recursively from the root commits up, so the whole identity domain is
internally consistent without any reference to store object ids.

Security rationale: `commit_signing_bytes` is exactly the byte string
the commit's Ed25519 signature attests (SPEC-SIGNING §3), so binding
the proof to `derived_id` binds it to precisely the content the
commit's own signature covers — nothing weaker. The three omitted
fields are unsigned annotations plus the signature itself, none of
which carry attribution-relevant content. And because the derived
preimage includes `tree`, the tree binding of §7 step 2 (blob →
tree-path → `commitHeader.tree`) is unaffected: an attacker who swaps
`tree` changes the derived identity and fails step 3.

Carrying `parents` as derived identities is what lets a store-less
verifier (§8.1) match a header's parent pointers directly against
`origins[]` keys, without ever resolving a real object id. The
trade-off for store-holding verifiers is described in §8.1's shortcut
note.

## 7. Verification algorithm (full verifier, holds an object store)

Given `(predicate, fileBytes)`:

1. **Blob identity.** Recompute the blob id from `fileBytes` and
   `chunkLayout` (§6.1) — either the flat SPEC-OBJECTS §10 hash, or
   `merkle::compute_chunked_id` over a freshly-chunked `ChunkedBlob`.
   The result MUST equal `predicate.blob`.
2. **Tree path.** Walk `treePath` leaf → root. At each level, build a
   `TreeEntry { name: entryName, mode: entryMode, object_hash: childId }`
   and call `merkle::verify_tree_inclusion_proof(&innerRoot, &entry,
   position, &proof)`; it MUST succeed. Then compute this level's own
   tree id as `domain_digest(TREE_TYPE_DOMAIN, innerRoot)` (SPEC-MERKLE-OBJECTS
   §2) and check it equals either the next level's `childId`, or —
   at the final (root) entry — `commitHeader.tree`. The first level's
   `childId` MUST equal `predicate.blob` (step 1's result).
3. **Commit identity.** Rebuild `sign::commit_signing_bytes` from
   `commitHeader` (prologue `[0x03, "MKT1", 0x01]` + `tree` + `parents`
   (count-prefixed) + `author` + `message` (length-prefixed) +
   `timestamp` + `signer`), hash it, and check it equals
   `predicate.commit` — the **derived identity** of §6.3a, not the
   commit's store object id (which is unreconstructable from the
   header by design). This is the step that binds the verified tree
   root (step 2) to a specific commit identity — an attacker who
   swapped `tree` here would fail this check even if steps 1–2 passed
   against a different tree.
4. **Signature.** Verify the enclosing DSSE envelope against a trust
   registry via the existing `mkit_attest::verify::verify_envelope` /
   `Registry` path (SPEC-ATTESTATIONS.md §4–§6). At least one signature
   MUST verify under a trusted `keyid`.
5. **Ancestry.** For every distinct origin commit named in
   `attributions`, prove it is an ancestor of `predicate.commit` — see
   §8.

Steps 1–4 require no history access beyond the bytes already inside
the predicate — a verifier with no object store can run them
standalone. Step 5 is the one place a store, if present, offers a
shortcut (§8.2).

Failure at any step MUST be reported as a distinct, identifiable
error condition (not a single opaque boolean) — this is the
tamper-matrix requirement PR B's golden tests exercise: a flipped
attribution line, a dropped `treePath` step, a swapped origin header,
a truncated ancestry path, and wrong file bytes are each expected to
fail at a *different* step above, and implementations MUST surface
which one.

## 8. Ancestry (D5)

The blame proof needs `origin ⪯ commit` — "commit `X` really is an
ancestor of `C`" — which the commit-history MMR (`SPEC-HISTORY-PROOF.md`)
does not by itself provide: the MMR proves "`X` was the `N`-th leaf on
a branch", a fact about append order, not DAG ancestry. Merge-aware
blame (already landed — #458/#488/#503/#507) deliberately attributes
lines to non-first-parent commits that may never have been branch
tips, so branch-MMR membership is not even available for them, let
alone ancestry.

### 8.1 v1: chain-walk, no MMR

For each distinct origin `O` named in `attributions`:

1. Recompute `O`'s claimed derived identity (§6.3a) from `origins[]`'s
   matching `header` entry the same way as verification step 3 (§7) —
   the header's rehash MUST equal its claimed `commit` hex.
2. Starting from `predicate.commit`'s already-verified header (step 3
   of §7), walk `parents` pointers — themselves derived identities
   (§6.3a) — through the `origins[]` map (keyed by derived-identity
   hex) until reaching `O`, or `O == predicate.commit` itself (a line
   attributed to `C` in its own commit is a trivial, always-true
   case).
3. If the walk exhausts reachable headers without finding `O`, the
   proof fails ancestry for that origin. The prover is expected to
   include every header on the connecting path(s) from `C` down to
   each origin; because origins commonly share ancestors, the honest
   bundle is the *union* of those paths, not `K` independent full
   chains. Worst case this is `O(depth)` headers — the honest v1 cost
   the issue's design notes call out.

A **store-holding** verifier MAY skip `origins[]`/the walk entirely
and instead check ancestry against its own object store via
`ops::merge::is_ancestor`. Because the predicate carries derived
identities (§6.3a) while `is_ancestor` addresses real store hashes,
the verifier must first resolve each derived identity back to a real
commit hash by scanning its store's commit objects and rehashing each
one's header — `O(store size)`, a known v1 cost (the predicate
deliberately carries no real-hash anchor) — and only then call
`is_ancestor(store, real_origin, real_commit)`. Both paths are
equally valid implementations of "prove `O ⪯ C`"; `origins[]` exists
so a store-less verifier can do the same check.

This resolves the #349/#361 (MMR proof-size) coupling for v1 the same
way the issue's decision does: **no MMR proofs ship in v1 at all**, so
no batch-MMR / peak-bagging format freeze happens in this document.

### 8.2 Why not the history MMR directly

`index(X) < index(C)` under a topologically-ordered MMR is necessary
but not sufficient for ancestry — two commits on divergent branches
can each be "earlier than" a later common descendant without either
being its ancestor. Ancestry requires committing to each commit's
*out-edges* (parent pointers), which is exactly what
`commit_signing_bytes` already authenticates (`sign.rs`) — the v1
chain-walk in §8.1 is "prove a path exists in that already-authenticated
edge set", not a new commitment.

### 8.3 v2 roadmap: accumulator (option 2a)

Recorded here (not specified normatively — this is roadmap, not a v1
requirement) from the issue's design-session comment "Option 2 sketch:
a per-commit ancestry accumulator":

> **2a — per-commit ancestor accumulator (recommended).** `anc_root(C)`
> = a Merkle root (reuse the SPEC-MERKLE-OBJECTS BMT, or a per-commit
> ancestor-MMR reusing SPEC-HISTORY-PROOF's inclusion-proof format)
> over C's ancestor set, keyed by a canonical order (topo index or
> commit hash).
> - Proof of `X ⪯ C` = **one inclusion proof** of `X` into `anc_root(C)`.
>   `O(log N)` verifier, in a proof format mkit already ships.
> - Build: a **linear** commit is `{C} ∪ ancestors(p1)` = a single
>   insert/append into `p1`'s structure → `O(log N)` new nodes via a
>   persistent/copy-on-write tree (structure-shared, ~`O(N log N)` total
>   storage). A **merge** is a set **union** of the parents' sets —
>   `O(side-branch size)`, but merges are comparatively rare, so
>   amortized cost stays reasonable.
> - Drops straight into the blame-proof bundle: it **replaces the "MMR
>   ancestry" step**; the content-BMT + claim-BMT + signature parts are
>   unchanged.

Placement of `anc_root(C)` is an open format decision the design notes
flag as either a new `Commit.ancestry_root` field (a wire/signing-bytes
break, which should ride the same v0.2 break as the planned
`Commit.history_root` field rather than go alone) or another signed
sidecar (no wire break, same attester-trust tradeoff as this whole
predicate). Both `2a` and the rejected alternative (`2b`, Merkle
skip-lists — cheaper build, but the verifier has to find a short path
through merges, which is exactly blame's hard case) are v2 material.
`v: 1` (§6) exists precisely so that whichever construction v2 picks
can replace §8.1's chain-walk section of the predicate without
breaking already-issued v1 envelopes — old verifiers keep working
against `v: 1` proofs, new verifiers dispatch on `v` to pick the
ancestry algorithm.

## 9. `BlameOptions` record (D6)

`blameOptions` mirrors `ops::blame::BlameOptions` field-for-field
(`rust/crates/mkit-core/src/ops/blame/mod.rs`), including
`ignore_rev_precise` — landed on this branch via #496 (commit
`1441425c`), so this spec pins it rather than deferring it to a
follow-up.

| JSON field | Rust field | Type / encoding |
|---|---|---|
| `ignoreWhitespace` | `ignore_whitespace` | `bool` |
| `moves` | `moves` | `null` (⇔ `MoveDetection::Off`) \| `{ "threshold": u32 }` (⇔ `MoveDetection::On { threshold }`) |
| `copies` | `copies` | `null` (⇔ `CopyDetection::Off`) \| `{ "level": u8, "threshold": u32 }` (⇔ `CopyDetection::On { level, threshold }`) |
| `ignoreRevs` | `ignore_revs` | array of hex64, **sorted ascending** for determinism (the Rust field is an unordered `Arc<HashSet<Hash>>`; JCS requires deterministic member order, so producers MUST sort before encoding) |
| `ignoreRevPrecise` | `ignore_rev_precise` | `bool` — mkit-only refinement of ignore-revs fall-through (content-matching instead of git's positional guess); recording it is required because it changes which origin a fallen-through line resolves to |
| `firstParent` | `first_parent` | `bool` |

Attesting a non-default combination (e.g. `firstParent: true`, which
reproduces the older linear-history attribution instead of git's
merge-aware default) is allowed — the options are part of the signed
statement, so a verifier always knows which semantics produced the
attached `attributions`, rather than assuming mkit's default.

## 10. CLI surface (D7)

```
mkit blame --prove <file> [-o <path>]
    Run blame on <file> at HEAD (or the resolved commit), build the
    predicate (§6), and emit a signed DSSE envelope. Signing uses the
    same signer-selection flags as `mkit attest` (--algorithm,
    --signer, --external-signer-arg, --additional-signer).
    Default output path: <file>.blame-proof.json.
```

Verification does **not** get a new top-level `verify-blame` command.
It goes through the existing `mkit verify-attest`
(`rust/crates/mkit-cli/src/commands/verify_attest.rs`), extended with a
predicate-specific deep-verify hook: once `verify-attest` confirms the
envelope's signature (§7 step 4), it dispatches on
`predicateType == ".../predicate/blame-proof/v1"` to also run §7 steps
1–3 and 5 against the caller-supplied file bytes, rather than stopping
at "the signature verifies."

## 11. Non-goals

- **Proving the diff/attribution computation itself** (SNARK
  territory) — see §2's verbatim quote. This spec proves the result is
  tamper-evident and correctly bound to real objects, not that the
  LCS walk that produced it was correct.
- **Importing qmdb or any new external verifiable database** — see
  §2's verbatim quote. Provable blame composes the existing BMT +
  commit-signing primitives; it does not introduce a new authenticated
  index.
- **A per-line Merkle commitment or chunk+offset construction** — made
  unnecessary by the D3 verifier-input assumption (§4): the verifier
  already holds the file bytes and splits lines itself.
- **Batch / accumulator ancestry proofs in v1** — §8.3 is roadmap, not
  a v1 requirement. v1 ships only the `O(depth)` chain-walk.
- **A new `Commit` wire field or signing-bytes break** — this proof is
  a signed sidecar (§3); it does not touch `sign::commit_signing_bytes`
  or `SPEC-OBJECTS.md`'s commit layout. (v2's accumulator placement,
  §8.3, may eventually need one, but that is out of scope here and
  would ride the same v0.2 break as `Commit.history_root`.)
- **Non-blob subjects / whole-repo proofs** — this spec covers one
  file at one commit; batching multiple files or commits into a single
  envelope is not addressed.

## 12. Deliverables and sequencing

| PR | Scope | Status |
|---|---|---|
| A (this document) | `docs/SPEC-BLAME-PROOF.md`; `SPEC-MERKLE-OBJECTS.md` §5 freeze | Landing now |
| B | `mkit-core`: `build_blame_proof` / `verify_blame_proof`, golden fixture repo, tamper-matrix tests (flipped attribution, dropped tree-path step, swapped origin header, truncated ancestry path, wrong file bytes — each a distinct error variant per §7) | Landed (`ops::blame::proof`, same change as the §6.3a amendment) |
| C | `mkit-attest`/`mkit-cli`: predicate registration, `blame --prove`, `verify-attest` deep-verify hook, `cli_wire.rs` end-to-end test, `docs/CLI.md` update | Landed (`mkit-cli::commands::blame_proof` — JCS codec; `blame.rs`'s `--prove`; `verify_attest.rs`'s `--envelope-file`/`--subject-file` + deep-verify dispatch) |

Hard prerequisite already satisfied: #458 (merge-aware blame) landed,
so this spec does not need to special-case first-parent-only
attribution as a divergence from "real" blame.

## 13. Freezes

This spec is the first in-tree consumer of `SPEC-MERKLE-OBJECTS.md`
§5's inclusion-proof API and wire format (`build_tree_inclusion_proof`
/ `verify_tree_inclusion_proof`, used by §6.2's `treePath`). That
section is updated in the same change as this document to drop its
"provisional / unstable" marker; see its freeze note for the
versioning decision.

## 14. Version history

| Version | Changes |
|---------|---------|
| 1 | Initial design spec: trust model, predicate schema, verification algorithm, v1 chain-walk ancestry + v2 accumulator roadmap, pinned `BlameOptions`, CLI surface, non-goals. No implementation yet (PR A of #495). |
| 1 (PR B amendment) | Derived commit identity (§6.3a), landed with the `mkit-core` implementation: `commit` / `origins[].commit` / attribution origins / header `parents` are `BLAKE3(commit_signing_bytes(header))`, not store object ids — the real object id hashes the full serialized commit (`signature`, `message_hash`, `content_digest`) which `commitHeader` omits by design, so it is unreconstructable from a header. §6.1/§6.3/§7 step 3/§8.1 updated accordingly; §8.1's store-holding shortcut now notes the derived→real resolution scan (`O(store size)`, known v1 cost). Same `v: 1` — this clarifies the identity domain before any envelope ever shipped; no issued proof is invalidated. |
| 1 (PR C, CLI wiring) | Landed the attest/CLI layer per §10 (D7): `mkit-cli::commands::blame_proof` implements the JCS-canonical encode/decode of §6 (a hand-built `mkit_attest::jcs::Value` tree, following the same pattern as `git-import/v1`/`release/v1` — `mkit-core` has no `serde`); `mkit blame --prove [-o <path>]` builds the predicate, wraps it in a Statement whose subject is the blamed blob digest (name = repo-relative path, §3), and signs it with the same signer-selection flags as `mkit attest`; `mkit verify-attest` gained `--envelope-file <path>` (verify one standalone envelope directly — a blame-proof's subject is not a commit hash, so the existing `--commit`-scoped attestation-store flow doesn't apply) and `--subject-file <path>` (the verifier-input flag §10 left open — this PR's decision) wired to a predicate-dispatch deep-verify hook that runs core `verify_blame_proof` after the envelope signature checks out. No predicate/wire changes; `v: 1` unaffected. |
