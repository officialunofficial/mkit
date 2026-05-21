---
spec: SPEC-HISTORY-PROOF
version: 0
status: draft (Phase 1)
audience: implementers of light-client verifiers and mirror-attestation services
---

# SPEC-HISTORY-PROOF — mkit commit-history MMR and inclusion proofs

Status: **Draft, Phase 1 of issue #157.**
Scope: the in-memory append-only Merkle Mountain Range (MMR) that mkit
keeps over each branch's commit chain, and the wire format of the
inclusion proof that lets a light client verify "commit `X` was the
`N`-th commit on branch `Y` at root `R`".

This document is normative for the `mkit-core::history` module and for
any future on-disk or on-wire consumer. It deliberately does **not**
yet mandate a persisted journal, a wire `Commit` field, or an
attestation predicate — those are Phase 2 / Phase 3 / `mkit-attest`
respectively (see §4).

---

## 1. Motivation

SPEC-SIGNING §6 currently requires a verifier that wants to prove
"commit `X` is in branch `Y`" to walk the full parent chain rooted at
the branch tip. That is `O(depth)` hash work and requires the
verifier to fetch every commit on the chain. The signature alone
proves authorship, not membership.

For the light-client use cases enumerated in issue #157 —

- attestation envelopes that ship a single commit plus its membership
  proof, without the surrounding pack;
- mirror servers that prove they have replicated a branch up to a tip
  without re-uploading the objects;
- a future Cloudflare-Worker hook that verifies branch-membership
  before accepting a deployment trigger —

we need an authenticated data structure whose root commits to the
*sequence* of commits on a branch and whose inclusion proofs are
`O(log n)` in branch depth. A Merkle Mountain Range (MMR) is the
canonical fit: append-only, dense leaf indices, stable positions, root
hash compresses arbitrary history into one digest.

mkit reuses [`commonware-storage`'s MMR][cw-mmr], specifically the
`merkle::mmr::mem::Mmr` type pinned to `=2026.4.0`. The wire shape of
the inclusion proof in this spec is byte-for-byte the wire shape of
that crate's `merkle::mmr::Proof` at the same version (see §2 below).
We accept that crate's ALPHA stability marker and explicitly tie our
own pre-`v0.2` window to it: see §4.

[cw-mmr]: https://docs.rs/commonware-storage/2026.4.0/commonware_storage/merkle/mmr/

---

## 2. Wire format

### 2.1 Digest

All node digests are 32-byte **BLAKE3** outputs, identical in length
and primitive to mkit's existing [`hash::Hash`](../rust/crates/mkit-core/src/hash.rs).

The MMR's hashing schedule is *not* the same as `hash::hash()`:
commonware's `Hasher` trait injects each node's MMR position into the
parent / leaf digest input (see commonware's `merkle::hasher` module).
That domain separation is what binds a leaf digest to its position in
the tree, and removing it would break inclusion proofs. Treat the
MMR's internal hash schedule as opaque — consumers should only ever
compare 32-byte digests, never reconstruct them.

### 2.2 `InclusionProof`

`InclusionProof` is the type alias

```rust
pub type InclusionProof =
    commonware_storage::merkle::mmr::Proof<commonware_cryptography::blake3::Digest>;
```

Its public fields, normatively:

| Field     | Type                | Meaning                                   |
| --------- | ------------------- | ----------------------------------------- |
| `leaves`  | `Location` (u64)    | Total leaf count of the MMR at proof time |
| `digests` | `Vec<Blake3Digest>` | Authentication path, fold-prefix layout   |

The `digests` layout is the **fold-based** layout documented in
commonware-storage `merkle::proof`:

1. If there are MMR peaks entirely *before* the proven range, the
   first entry of `digests` is a single accumulator digest produced
   by left-folding those peaks with `Hash(acc || peak)`. If no such
   peaks exist (the proven leaf is in the tallest mountain), this
   entry is **absent** — the list starts directly at step 2.
2. The digests of peaks entirely *after* the proven range, in peak
   iteration order (descending height).
3. The sibling digests required to reconstruct the proven range's
   own peak, in depth-first / forward-consumption order.

The codec used to serialise `InclusionProof` over the wire is
commonware-codec's `Write` / `Read` impls for `Proof`. In summary:

```text
InclusionProof ::= varint(leaves)
                || varint(digests.len())
                || digests.len() × digest32
```

— where `varint` is the commonware-codec variable-length `u64` encoding
and `digest32` is the raw 32 bytes of a BLAKE3 digest. Mkit does NOT
re-frame this; consumers MUST use commonware-codec at the same pinned
version.

### 2.3 Root

The MMR root is a 32-byte BLAKE3 digest computed as

```text
root = Blake3(leaf_count_be_u64 || fold(peak_digests))
```

with `fold(p0, p1, …, pk) = Blake3(Blake3(… Blake3(p0 || p1) … ) || pk)`,
peaks taken in descending-height order. For an **empty** MMR (no
commits appended yet) the iteration is empty and the root degenerates
to `Blake3(u64::to_be_bytes(0))`. This value is deterministic and
well-defined; `mkit-core::history::CommitHistory::open().root()`
returns it.

### 2.4 Position semantics

A commit's `Position(n)` is its **0-based leaf index** — the value
returned by `CommitHistory::append`. It is NOT the MMR's internal node
position (commonware calls that `Position`; we hide the distinction at
the mkit boundary by exposing only leaf indices). The first append on
an empty history returns `Position(0)`; the *n*-th append returns
`Position(n − 1)`. Positions never shift because the MMR is
append-only.

---

## 3. Verifier algorithm

Pseudocode for a Phase-1 light client:

```text
fn verify_inclusion(
    commit_hash: [u8; 32],   # the commit being proven
    position:    u64,        # 0-based leaf index
    proof:       InclusionProof,
    root:        [u8; 32],   # MMR root the verifier already trusts
) -> bool:
    leaf_digest := blake3_typed(commit_hash)          # see §2.1
    root_digest := blake3_typed(root)
    loc         := Location(position)

    return proof.verify_element_inclusion(
        hasher = StandardHasher<Blake3>,
        element = leaf_digest.as_bytes(),
        loc = loc,
        root = root_digest,
    )
```

The verifier:

1. Reconstructs the leaf digest for `position` from `commit_hash`
   using commonware's `Hasher::leaf_digest(pos, element)` schedule.
2. Walks the `digests` field per §2.2: combines siblings with the
   range-peak, prepends any peaks that came after, and prefixes the
   fold-accumulator if present.
3. Compares the recomputed root with `root_digest`. Returns `true`
   iff they match.

Failure modes that MUST return `false` (not panic):

- Tampered sibling / peak digest.
- `position` does not match the leaf the proof was built for.
- `commit_hash` is not the hash that was actually appended at that
  position.
- `root` is the root of a different (or different-length) history.
- `proof.leaves` disagrees with the number of leaves the prover claims.
- Truncated or over-long `digests` vector (rejected by step 2's
  consumer-pointer check).

The reference implementation lives at
[`mkit-core::history::verify_inclusion`](../rust/crates/mkit-core/src/history.rs).
Its acceptance tests cover the 1000-commit / position-712
round-trip and the bit-flip tamper case.

---

## 4. Implementation status and roadmap

| Phase   | Scope                                                                  | Lands in     |
| ------- | ---------------------------------------------------------------------- | ------------ |
| Phase 1 | `mem`-backed MMR, `CommitHistory::{open, append, root, prove}`, `verify_inclusion()`, this spec | `feat/history-mmr-phase1` (issue #157) |
| Phase 2 | Persisted journaled MMR; on-disk layout under `.mkit/history/<branch>.mmr`; atomic update alongside `refs::update_ref` | follow-up    |
| Phase 3 | New `Commit.history_root` proto field at the v0.2 break; new signing-bytes layout + golden vectors; SPEC-OBJECTS update | v0.2         |
| Phase 4 | `mkit-attest` `commit_in_branch` predicate bundling `(commit, position, proof)` | v0.2         |
| Phase 5 | Compatibility shim: v0.1.x repos rebuild the MMR on first v0.2.x open by walking the parent chain | v0.2         |
| Phase 6 | Promote `history-mmr` from opt-in feature to default                   | v0.3         |

Phase 1 (this PR) deliberately does *not*:

- touch `rust/crates/mkit-rpc/proto/` — no Commit field yet,
  no wire-breaking change yet;
- touch `rust/crates/mkit-core/src/sign.rs` — signing bytes unchanged,
  no golden-vector churn;
- expose any CLI surface — the module is feature-gated behind
  `history-mmr` (default off) and only compiles when consumers opt in.

Stability call: commonware-storage is ALPHA. We pin to an exact
`=2026.4.0` and accept that future minor versions may change the
proof's `digests` layout. Because Phase 3 includes a new signing-bytes
golden vector anyway, the wire format documented in §2 is "frozen
relative to the v0.2 break" — any change to commonware's proof codec
between now and v0.2 lands as part of the same migration, not as a
separate break.

### 4.1 On-disk layout (Phase 2 sketch — not yet normative)

Reserved for the Phase 2 PR. The intended shape is one
commonware-journal append-log per branch at
`.mkit/history/<branch>.mmr`, updated under the existing
`repo_lock::RepoLock` whenever `refs::update_ref` advances a branch.
The exact journal frame format, fsync schedule, and reconstruction-on-
open behaviour will be specified there; consumers MUST NOT rely on any
particular layout under `.mkit/history/` until Phase 2 lands.
