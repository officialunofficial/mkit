---
spec: SPEC-HISTORY-PROOF
version: 0
status: draft (journaled persistence shipped)
audience: implementers of light-client verifiers and mirror-attestation services
---

# SPEC-HISTORY-PROOF — mkit commit-history MMR and inclusion proofs

Status: **Draft, journaled-persistence stage of issue #157 (shipped).**
Scope: the append-only Merkle Mountain Range (MMR) that mkit keeps
over each branch's commit chain, the on-disk layout that persists it,
and the wire format of the inclusion proof that lets a light client
verify "commit `X` was the `N`-th commit on branch `Y` at root `R`".

This document is normative for the `mkit-core::history` module and for
any future on-disk or on-wire consumer. It does **not** yet mandate a
wire `Commit` field or an attestation predicate — those are the
proto-field integration stage / `mkit-attest` respectively (see §4).

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

mkit reuses [`commonware-storage`'s MMR][cw-mmr] pinned to `=2026.5.0`:
- `merkle::mmr::mem::Mmr` for the in-memory mem-only flavour
  ([`CommitHistory::open`]).
- `merkle::mmr::full::Mmr` for the journaled persisted flavour
  ([`CommitHistory::open_at`]). The on-disk layout is normatively
  defined in §4 below.

The wire shape of the inclusion proof is byte-for-byte the wire shape
of that crate's `merkle::mmr::Proof` at the same version (see §2
below). We accept that crate's ALPHA stability marker and explicitly
tie our own pre-`v0.2` window to it: see §4.

[cw-mmr]: https://docs.rs/commonware-storage/2026.5.0/commonware_storage/merkle/mmr/

---

## 2. Wire format

### 2.1 Digest

All node digests are 32-byte **BLAKE3** outputs, identical in length
and primitive to mkit's existing [`hash::Hash`](../../rust/crates/mkit-core/src/hash.rs).

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

mkit pins commonware's peak-bagging policy to `Bagging::ForwardFold`
for both producers (`CommitHistory::root` / `CommitHistory::prove`) and
verifiers (`verify_inclusion`). This preserves the root produced by the
pre-2026.5 commonware default and avoids a history-root migration for
existing `history-mmr` feature builds.

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

Pseudocode for a light client:

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
[`mkit-core::history::verify_inclusion`](../../rust/crates/mkit-core/src/history.rs).
Its acceptance tests cover the 1000-commit / position-712
round-trip and the bit-flip tamper case.

---

## 4. On-disk layout (normative, journaled persistence)

The persisted MMR for each branch lives under `<mkit_dir>/history/`.
mkit does **not** invent a custom format: the durable representation
is commonware-storage's native full-MMR shape pinned to the
`=2026.5.0` release train. mkit owns the directory layout that selects
*which* journal to open; the byte layout *inside* each partition is
commonware's, documented at
<https://docs.rs/commonware-storage/2026.5.0/commonware_storage/merkle/mmr/full/>.

### 4.1 Directory layout

```text
<mkit_dir>/
└─ history/
   ├─ <sanitized_branch>__journal-blobs/       # commonware's fixed-item journal
   ├─ <sanitized_branch>__journal-metadata/    # commonware's journal segment table
   └─ <sanitized_branch>__metadata/            # commonware's pruned-pinned-node sidecar
```

Each `<sanitized_branch>__journal-blobs/` directory contains commonware's
fixed-item-length blob files for the node-digest journal; each
`__metadata/` directory contains commonware's metadata-store
key/value blobs (used for pinned-node bookkeeping). mkit MUST NOT
write into these directories itself; all mutation goes through
`commonware-storage`'s `mmr::full::Mmr` API.

### 4.2 Branch-name sanitisation

commonware partition names are restricted to `[A-Za-z0-9_-]+`. mkit
ref names may contain `.`, `/`, and `_`, so the sanitiser
in [`mkit_core::history`] uses a hex-escape encoding:

- `[A-Za-z0-9-]` → unchanged.
- Every other byte (including `_`, `/`, `.`) → `_xx` where `xx` is
  the lowercase-hex byte value.

This encoding is injective on the [`validate_ref_name`] domain, so
two distinct valid ref names always map to distinct partition tokens.
Implementations MUST use the same sanitiser; cross-implementation
consumers can rely on it to derive partition names from ref names
without further normalisation.

### 4.3 Update protocol

A ref advance on a `history-mmr`-enabled mkit goes through
[`refs::update_ref_with_history`], which is the atomic boundary of
the durable couple:

1. Acquire `<mkit_dir>/refs-history.lock` via `repo_lock::RepoLock`.
2. [`CommitHistory::reopen`] — re-derive the caller's `CommitHistory`
   handle from the current on-disk journal. The handle is typically
   opened (via `open_at`) *before* this lock is taken (the caller has
   no lock yet at that point), so another process could have appended
   in the window between that `open_at` and this call taking the
   lock; reopening under the lock guarantees the next two steps act
   on what is truly on disk, not a stale in-memory view.
3. Crash-recovery check: if the journal is non-empty, verify that its
   last leaf already matches the ref's *current* (pre-this-write)
   value via an inclusion proof. A mismatch means a prior call's step
   5 never landed (see below) — heal by appending the ref's current
   value directly, since it is precisely the one missing leaf; no
   parent-chain walk is needed. An empty journal is left untouched
   here — see §4.5 for why.
4. CAS-write `<mkit_dir>/refs/heads/<branch>`.
5. Call [`CommitHistory::append`], which itself calls commonware's
   `Journaled::sync` after applying the leaf-batch, so the new node
   is fsync'd before the function returns.
6. Drop the lock.

If step 4 fails the lock is released without touching the MMR. If
step 5 fails after step 4 succeeded, the ref is one commit ahead of
the MMR; the next call's step 3 heals it automatically. If the
journal was empty going into step 3 (no prior leaf to check against)
and the crash happened on the branch's very first tracked write, or
the repo is mid-migration per §4.5, the same next call's
`mkit-cli`-level rebuild shim (§4.5) is what heals it instead — step 3
alone cannot, since it has no `ObjectStore` access to discover what
(if anything) should already be there.

### 4.4 Crash recovery

mkit relies on commonware's native journaled-MMR recovery semantics,
documented at the link above and verified by the integration test
`history::tests::truncated_journal_rolls_forward_or_surfaces_corruption`.
On reopen via `CommitHistory::open_at`:

- A trailing **torn leaf** (the journal's final blob ends mid-frame)
  is rewound to the last valid leaf-aligned size by
  `mmr::full::Mmr::init`. The MMR's in-memory state is rebuilt from
  the surviving leaves; the root matches a clean replay of those
  leaves.
- A **deeper corruption** (the metadata sidecar disagrees with the
  journal beyond what roll-forward can resolve, or a blob's
  earliest leaf is missing) is surfaced as
  [`HistoryError::Corrupted`] with the underlying commonware error
  message attached. The repo administrator MUST intervene; mkit
  does not attempt to fabricate digests.
- A missing `history/<branch>/` directory is treated as "first
  open" and an empty MMR is initialised. For repos created against
  v0.1.x mkit (no history persistence) this is the entry point to
  the rebuild shim — see §4.5.

mkit's own contract is narrower than commonware's: **reopening a
half-written journal MUST NOT panic, MUST NOT silently expose stale
data, and MUST surface any unrecoverable state through `HistoryError`.**

### 4.5 v0.1.x → v0.2.x rebuild shim

A repo created against an older mkit has `refs/heads/<branch>` on
disk but no `history/<branch>/` directory. The first
[`CommitHistory::open_at`] against such a repo returns an empty
journaled MMR. Its production call site is `mkit-cli`'s
`write_ref_recording_history`: before delegating to
`update_ref_with_history`, if the journal is empty AND the branch
already has a ref value on disk, it opens an `ObjectStore` rooted at
the repo and invokes
[`mkit_core::history::rebuild_from_chain(history, current, parent_of)`],
which:

1. Walks the first-parent chain from `current` (the ref's value
   *before* this write) via the caller-supplied `parent_of` function,
   backed here by `ObjectStore::read_object`.
2. Reverses the chain so the root commit is appended first.
3. Calls [`CommitHistory::append`] for each entry in order.

This same call degenerates safely to a single append when `current`
is a root commit — which is exactly what happens when the "empty
journal" case is not a deep v0.1.x migration but a crash on the
branch's very first tracked write (§4.3): `rebuild_from_chain` just
walks the one-commit chain and appends it, no different in effect
from the §4.3 step-3 heal that the non-empty case uses. This is why
`update_ref_with_history` itself does not need to distinguish the two
sub-cases of an empty journal — only `mkit-core::refs`, which has no
`ObjectStore` access, defers *both* to this shim.

The shim is one-shot (subsequent `open_at` calls find a non-empty
journal and skip it). Cost is `O(n)` BLAKE3 hashes for an `n`-commit
branch; on commodity hardware this completes in single-digit
milliseconds for branches up to a few hundred thousand commits. A
backfill failure (an unreadable or non-commit object anywhere on the
chain) is fail-closed: `write_ref_recording_history` propagates the
error rather than proceeding with a silently incomplete journal.

## 5. Implementation status and roadmap

| Stage   | Scope                                                                  | Lands in     |
| ------- | ---------------------------------------------------------------------- | ------------ |
| In-memory MMR | `mem`-backed MMR, `CommitHistory::{open, append, root, prove}`, `verify_inclusion()`, §1–§3 of this spec | `feat/history-mmr-phase1` (issue #157, merged in PR #162) |
| Journaled persistence | **Shipped.** Journaled persistence via `commonware-storage::merkle::mmr::full::Mmr` pinned to `=2026.5.0`, with `Bagging::ForwardFold`. `CommitHistory::open_at`, `refs::update_ref_with_history`, `rebuild_from_chain`. §4 of this spec. | `feat/history-mmr-phase2-commonware` |
| Proto-field integration | New `Commit.history_root` proto field at the v0.2 break; new signing-bytes layout + golden vectors; SPEC-OBJECTS update | v0.2         |
| Attestation predicate | `mkit-attest` `commit_in_branch` predicate bundling `(commit, position, proof)` | v0.2         |
| Default-on promotion | Promote `history-mmr` from opt-in feature to default                   | v0.3         |

The journaled-persistence stage (this PR) deliberately does *not*:

- touch `rust/crates/mkit-rpc/proto/` — no Commit field yet,
  no wire-breaking change yet;
- touch `rust/crates/mkit-core/src/sign.rs` — signing bytes unchanged,
  no golden-vector churn;
- expose any CLI surface — the module is feature-gated behind
  `history-mmr` (default off) and only compiles when consumers opt in.

Stability call: commonware-storage is ALPHA. We pin to an exact
`=2026.5.0` and accept that future minor versions may change the
proof's `digests` layout *and* the on-disk partition shape described
in §4. Because the proto-field integration stage includes a new
signing-bytes golden vector anyway, the wire format documented in §2 and the on-disk format
documented in §4 are both "frozen relative to the v0.2 break" — any
change to commonware between now and v0.2 lands as part of the same
migration, not as a separate break.

---

## 6. Invariants

| Invariant | Enforced by |
|---|---|
| A commit's `Position(n)` never shifts | the MMR is append-only; positions are 0-based dense leaf indices (§2.4) |
| A leaf digest cannot be replayed at another position | commonware's hasher injects the node's MMR position into every digest (§2.1) |
| The root binds the commit *sequence* and its length | `root = Blake3(leaf_count_be_u64 \|\| fold(peak_digests))` (§2.3) |
| Producers and verifiers compute the same root | peak bagging pinned to `Bagging::ForwardFold` on both sides (§2.3) |
| A tampered digest, wrong position, wrong commit, foreign root, mismatched `leaves`, or truncated/over-long `digests` never verifies | `verify_inclusion` returns `false` — never panics — per the enumerated failure modes (§3) |
| Two distinct branches never share a history partition | the hex-escape sanitiser is injective on the `validate_ref_name` domain (§4.2) |
| A ref advance and its MMR append cannot interleave with another writer | both run under `<mkit_dir>/refs-history.lock`; the handle is re-derived from disk (`CommitHistory::reopen`) after the lock is taken, even if it was opened before (§4.3) |
| An appended leaf is durable before the update returns | `CommitHistory::append` calls `Journaled::sync` (§4.3) |
| A crash leaves the ref at most one commit ahead of the MMR, and the next write heals it without manual intervention | ref CAS precedes the append; the next `update_ref_with_history` call detects a non-empty journal's stale last leaf via an inclusion-proof check and appends the ref's current value directly, or (empty journal) `write_ref_recording_history`'s rebuild shim backfills from the object store (§4.3, §4.5) |
| Reopening a half-written journal never panics or silently exposes stale data | torn trailing leaf rewound by `mmr::full::Mmr::init`; anything deeper surfaces as `HistoryError::Corrupted` (§4.4) |
| Proof bytes decode identically for every consumer | commonware-codec at the pinned `=2026.5.0` (§2.2) |

These invariants are frozen relative to the v0.2 break: any upstream
commonware change to the proof layout or partition shape lands as part
of that migration, not as a separate break (§5).
