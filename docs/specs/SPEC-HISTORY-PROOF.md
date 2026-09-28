---
spec: SPEC-HISTORY-PROOF
version: 1
status: draft-normative
audience: implementers of first-parent ancestry proofs and local history recovery
---

# SPEC-HISTORY-PROOF — first-parent ancestry snapshots

Normative for the opt-in `history-mmr` feature (the feature and directory
names predate this document's move to a Merkle Mountain **Belt**; they are
identifiers, not a claim about the tree shape below). Existing object IDs,
commit signatures, and the frozen digest/bagging parameters are unchanged.
v1 introduces an auxiliary namespace and context descriptor for verified
first-parent ancestry.

## 1. Membership and generations

A proof establishes membership in the **first-parent chain ending at an exact
tip**, ordered root to tip. It does not establish all-parent DAG membership,
author identity, or freshness after that tip was observed. A merge contributes
its first parent and the merge commit; commits reachable only through another
parent do not belong to this sequence.

Sequential updates, one multi-commit first-parent fast-forward, and backfill of
the same tip MUST yield identical MMB roots, leaf counts, and positions.
A no-op write appends nothing. First-parent fast-forwards retain the generation
and include every missing commit. Reset/other rewrites, delete/recreate, rename,
and first ancestry publication create a fresh random 32-byte generation. A raw ref write
that changes a tip invalidates its active snapshot, including in builds without
`history-mmr`; writing away and back cannot revive an old generation.

Generation and repository identities are outside the MMB digest. Two branch
incarnations with the same ancestry may therefore share an MMB root; their
context descriptors distinguish them.

The primitive is the existing `CommitHistory` in-memory Merkle Mountain Belt
(MMB) using the pinned commonware train (`rust/Cargo.toml`) and
`Bagging::ForwardFold`. An MMB is an append-only forest of perfect binary
trees, like the older Merkle Mountain Range (MMR) it replaced in this spec,
but without the MMR's constraint that peak heights strictly decrease: an MMB
allows up to two consecutive peaks of the same height, so appending a leaf
merges at most one pair of peaks and creates at most one new internal node.
An MMR append can cascade up to `O(log N)` merges (whenever a run of
same-height peaks all collapse at once, e.g. crossing a power-of-two leaf
count) — MMB bounds that worst case to a constant, which matters for
`mkit commit`'s one-append-per-publish pattern. See
`commonware-storage::merkle::mmb`'s module documentation and
<https://arxiv.org/abs/2511.13582> for the full construction; mkit uses only
the base MMB structure with forward-fold bagging (what that paper calls
F-MMB), not its "Pyramid" P-MMB bagging variant, which is not yet
implemented in the pinned commonware release.

## 2. Wire format

### 2.1 Digest

All node digests are 32-byte **BLAKE3** outputs, identical in length
and primitive to mkit's existing [`hash::Hash`](../../rust/crates/mkit-core/src/hash.rs).

The MMB's hashing schedule is *not* the same as `hash::hash()`:
commonware's `Hasher` trait injects each node's MMB position into the
parent/leaf digest input (see commonware's `merkle::hasher` module).
That domain separation is what binds a leaf digest to its position in
the tree, and removing it would break inclusion proofs. Treat the
MMB's internal hash schedule as opaque &mdash; consumers should only ever
compare 32-byte digests, never reconstruct them.

### 2.2 `InclusionProof`

`InclusionProof` is the type alias

```rust
pub type InclusionProof =
    commonware_storage::merkle::mmb::Proof<commonware_cryptography::blake3::Digest>;
```

This is `commonware_storage::merkle::proof::Proof<Family, Digest>` with
`Family = mmb::Family` &mdash; the same generic proof type, wire shape, and
codec the crate's MMR (`merkle::mmr::Proof`) used with `Family = mmr::Family`
before this spec switched structures, so everything below besides the
concrete `Family` (and therefore the peak/digest *content*, since MMB's
forest topology differs from MMR's) is unchanged.

Its public fields, normatively:

| Field            | Type                | Meaning                                   |
| ---------------- | ------------------- | ----------------------------------------- |
| `leaves`         | `Location` (u64)    | Total leaf count of the MMB at proof time |
| `inactive_peaks` | `usize`             | Number of leading peaks the proof commits to as inactive; always `0` in mkit |
| `digests`        | `Vec<Blake3Digest>` | Authentication path, fold-prefix layout   |

mkit has no inactivity floor: producers (`CommitHistory::root`,
`CommitHistory::prove`) pass zero inactive peaks, so every proof mkit
emits has `inactive_peaks = 0`. A verifier MUST reject a proof whose
`inactive_peaks` is nonzero. With commonware-storage 2026.9.0 this
follows from the root computation rather than from a separate check:
the decoder accepts any value, but a nonzero `inactive_peaks` adds
`u64_be(inactive_peaks)` to the root preimage (commonware's
`Hasher::root_with_folded_peaks`), so the reconstructed root can never
equal an mkit root computed with zero inactive peaks (§2.3), and
`verify_inclusion` returns `false`.

The `digests` layout is the **fold-based** layout documented in
commonware-storage `merkle::proof`:

1. If there are MMB peaks entirely *before* the proven range, the
   first entry of `digests` is a single accumulator digest produced
   by left-folding those peaks with `Hash(acc || peak)`. If no such
   peaks exist (the proven leaf is in the tallest mountain), this
   entry is **absent** &mdash; the list starts directly at step 2.
2. The digests of peaks entirely *after* the proven range, in peak
   iteration order (oldest-to-newest, i.e. non-increasing height &mdash;
   ties are possible on an MMB, unlike the strictly-decreasing peak
   heights an MMR guarantees).
3. The sibling digests required to reconstruct the proven range's
   own peak, in depth-first/forward-consumption order.

One practical consequence of MMB's forest shape: the most recently
appended leaf's proof is at most 2 digests regardless of how large the
history grows (commonware-storage's own
`mmb::proof::test_last_element_proof_size_is_two` pins this), versus an
MMR proof for the newest leaf, which grows with `O(log N)`.

The codec used to serialize `InclusionProof` over the wire is
commonware-codec's `Write` / `Read` impls for `Proof`. In summary:

```text
InclusionProof ::= varint(leaves)
                || varint(inactive_peaks)
                || varint(digests.len())
                || digests.len() × digest32
```

&mdash; where `varint` is the commonware-codec variable-length `u64` encoding
and `digest32` is the raw 32 bytes of a BLAKE3 digest. Because mkit
always writes `inactive_peaks = 0`, that field is the single byte `0x00`
immediately after the `leaves` varint. For example, a proof of position
0 in a 2-leaf history encodes as `02 00 01` followed by one 32-byte
digest (35 bytes). Mkit does NOT re-frame this; consumers MUST use
commonware-codec at the same pinned version (2026.9.0, pinned in
`rust/Cargo.toml`).

### 2.3 Root

The MMB root is a 32-byte BLAKE3 digest computed as

```text
root = Blake3(leaf_count_be_u64 || fold(peak_digests))
```

with `fold(p0, p1, …, pk) = Blake3(Blake3(… Blake3(p0 || p1) … ) || pk)`,
peaks taken in oldest-to-newest (non-increasing height) order &mdash; the
same fold formula an MMR root used, just over an MMB's peaks. For an
**empty** MMB (no commits appended yet) the iteration is empty and the
root degenerates to `Blake3(u64::to_be_bytes(0))`. This value is
deterministic and well-defined; `mkit-core::history::CommitHistory::open().root()`
returns it. The formula is commonware's root with zero inactive peaks;
a nonzero inactive-peak count would add a `u64_be(inactive_peaks)` term
between the two parts, which mkit never uses (§2.2).

mkit pins commonware's peak-bagging policy to `Bagging::ForwardFold`
for both producers (`CommitHistory::root` / `CommitHistory::prove`) and
verifiers (`verify_inclusion`). This policy defines the specified peak order.

### 2.4 Position semantics

A commit's `Position(n)` is its **0-based leaf index** &mdash; the value
returned by `CommitHistory::append`. It is NOT the MMB's internal node
position (commonware calls that `Position`; mkit hides the distinction at
the mkit boundary by exposing only leaf indices). The first append on
an empty history returns `Position(0)`; the *n*-th append returns
`Position(n − 1)`. Positions are stable within a generation while its first-parent chain
only extends. A rewrite establishes a different generation.

---

## 3. Trust and verification

`AncestryDescriptor` binds all of:

- repository identity (32 random bytes, locally persisted);
- full ref name, including `refs/heads/`;
- generation (32 random bytes);
- exact tip hash;
- leaf count;
- MMB root.

`AncestrySnapshot::load` is the supported trust-anchor path. Under the history
and ref-mutation locks it reads the active snapshot, rejects an unfinished
transaction, checks repository/ref/generation/tip context, and reconstructs the
first-parent chain from verified local objects. Only after all checks pass may
it return a `TrustedAncestryDescriptor`. This trusts the local repository and
its authoritative ref, not a remote server's claim about that repository.

`verify_ancestry` requires the supplied descriptor to equal BOTH an independently
trusted descriptor and the caller's explicit expected descriptor. It then checks
the leaf position and the existing `verify_inclusion` proof against that root.
Wrong repository, ref, generation, tip, leaf count, root, leaf or proof MUST fail.
An untrusted remote descriptor has no constructor for the trusted wrapper. A
remote root cannot authenticate itself; remote authenticated descriptors and
freshness policy require a separately specified trust mechanism and are not
implemented by v1. The low-level `verify_inclusion` API only establishes an MMB
mathematical relation and MUST NOT itself be called verified branch membership.

`mkit reflog` remains a first-parent-chain view, not a Git event reflog. With the
feature enabled its summary reports first-parent commits and cross-checks them
against the trusted local snapshot. Missing or pending state yields
no verified ancestry marker. Intermediate rebase commits are included when the
final branch tip is published.

## 4. Versioned durable state and publication

### 4.1 Layout

All paths are under the common directory, shared by linked worktrees:

```text
history-v1/repository-id                 # strict 65-byte lowercase hex + LF
history-v1/branches/<ref-key>/
  current                              # generation, strict 65-byte hash wire
  transaction                          # durable publication intent, below
  pending-snapshot                     # prepared target snapshot
  generations/<generation>.snapshot    # latest ancestry for this generation
  scrub                                # advisory re-verification schedule, §4.5
```

`ref-key` is lowercase BLAKE3 hex of the UTF-8 full ref name. The snapshot and
transaction also contain that full name and readers check it against the path.
The repository ID is created with atomic no-replace semantics. Renames and
creates are followed by the directory durability barriers needed for their
containing paths. Prior generations remain evidence; their mere presence is not
a GC retention root or a freshness assertion.

### 4.2 Snapshot encoding

Integers are little-endian. Exact bytes:

```text
"MKHA" || u8(1)
repository[32] || generation[32] || tip[32]
u64(leaf_count) || root[32]
u16(ref_name_byte_length) || full_ref_name
leaf_count * commit_hash[32]             # root-to-tip first-parent order
BLAKE3(all preceding bytes)[32]
```

Readers MUST check the checksum, exact length/no trailing bytes, valid branch
ref name, nonzero count, last leaf equals tip, and the recomputed MMB root.
Traversal and allocation are capped at 1,000,000 leaves; persisted input is
bounded at `32 * 1,000,000 + 8192` bytes. Cycles, missing ancestors, non-commit/
non-remix nodes and excessive depth fail before publication. No existing
object identity is changed by this encoding.

The first implementation persists a complete bounded ancestry snapshot and
reconstructs its in-memory proof index on load. Publication and verified loads
therefore cost O(chain length) work and snapshot I/O, including a fast-forward;
this is a deliberate recovery-first implementation, not an incremental-journal
performance claim. It retains one latest snapshot per generation. §4.5's scrub
state is the one deliberate exception, bounding a fast-forward's *store-read*
cost without changing this encoding or what gets persisted; any other future
incremental storage representation must preserve this descriptor/proof
contract and independently version any changed auxiliary bytes.

### 4.3 Transaction encoding and roots

UTF-8, exactly eight LF-terminated lines (no extra whitespace):

```text
mkit-history-transaction-v1
<repository lower-hex>
<full ref name>
<previous ref lower-hex or ->
<previous generation lower-hex or ->
<target ref lower-hex>
<target generation lower-hex>
<BLAKE3 of every preceding byte, including LFs, lower-hex>
```

The file is capped at 8192 bytes. Both previous and target ref values contribute
GC roots until the transaction is removed, including on builds without the
history feature. Corrupt transaction metadata aborts GC. Raw writers refuse to
step over a pending intent and tell the caller to recover with the feature
enabled. These rules prevent a pending target from being pruned or overwritten
before recovery.

### 4.4 Update and recovery state machine

The caller holds its normal worktree/registry guards, then acquires the branch
history lock and the full-ref mutation lock (SPEC-CONCURRENCY §4). Both remain
held throughout validation, publication and recovery.

1. Finish any recorded transaction, then check the new CAS condition.
2. Determine the target's first-parent chain and select the retained
   generation for an extension, otherwise a fresh generation. A true no-op
   (target already the live, already-published tip) leaves the descriptor
   untouched and performs no store read. Otherwise: when the target is a
   fast-forward of the live, already-published tip, verify only the new
   suffix in full plus a bounded, scheduled window of the reused prefix
   (§4.5) — not the whole prefix, unless the schedule requires it. Any other
   case (a new branch, or a target that is not a fast-forward of the live
   tip) verifies the complete first-parent ancestry from scratch, as before.
3. Atomically persist and sync the transaction, including previous/target ref
   and generation. This is the durable intent to finish that exact target.
4. Write and sync `pending-snapshot` built from verified authoritative objects.
5. Publish the target ref with the already-held guard.
6. Rename the pending snapshot into its generation path and sync directories.
7. Atomically publish `current`, sync it, then remove/sync `transaction`.

An error may leave intent or target state on disk; proofs MUST be withheld while
an intent exists. Recovery accepts only the recorded previous or target ref,
rebuilds the entire recorded target from verified objects, and completes steps
4–7. It never heals a multi-commit fast-forward by appending only the tip. A ref
that disagrees with both recorded values fails closed. A raw writer cannot
create that divergence through the supported APIs.

Deletion recovers any pending publication, invalidates/syncs `current`, then
removes/syncs the ref under the same mutation guard. Recreating that name starts
a new generation; archived snapshots are retained. A crash
between invalidation and ref deletion leaves a ref needing an ancestry rebuild,
not a trusted descriptor for a different incarnation.

### 4.5 Scrub state

A fast-forward publish still verifies its new suffix in full, every time, by
reading and content-hash-checking every new commit/remix object from the
store. What it does not do on every publish is re-read and re-hash the
*entire* reused prefix — that cost is bounded and scheduled instead, tracked
per branch in an advisory auxiliary file, `scrub`, alongside `current`:

```text
"MKSC" || u8(2)
generation[32]
u64(cursor) || u64(verified_through) || u64(last_full_verify_unix)
BLAKE3(all preceding bytes)[32]
```

The file is exactly 93 bytes, and its integers are little-endian (§4.2).
`generation` is the generation the state was computed against. A file
whose `generation` differs from the generation being fast-forwarded is
treated as missing, so a scrub state left behind by a rewrite that
crashed before the scrub write cannot be applied to a different chain.
A version-1 file (no `generation`) fails the length and magic checks and
is also treated as missing.
`cursor` is the next scrub window's start index into the prefix.
`verified_through` is the prefix length as of the last full verification —
the range `cursor` rotates through; leaves published after that were each
freshly verified when first appended and are not re-scrubbed until the next
full verification folds them in. `last_full_verify_unix` is Unix seconds.

On a fast-forward, when the on-disk `scrub` file parses and its checksum
matches, and fewer than 604800 seconds (7 days) have elapsed since
`last_full_verify_unix`: verify `prefix[cursor .. min(cursor + window,
verified_through)]` from the store, where `window` is
`max(512, verified_through / 64)`, and persist the advanced cursor once the
publish durably succeeds. When that window would reach `verified_through`
(a completed rotation), or the window's end exceeds the generation's
stored prefix length (for example, a rolled-back snapshot paired with a
newer `scrub` file), or the file is missing, fails to parse, fails its
checksum, belongs to another generation, or the 7-day bound has elapsed,
verify the complete first-parent
ancestry instead, exactly as a non-fast-forward publish does, and persist a
reset `scrub` reflecting that fresh full verification (`cursor` 0,
`verified_through` the new chain length, `last_full_verify_unix` now). Either
way the *persisted* chain and root are unaffected: this file changes only how
much of an already-published prefix gets re-verified against the live store
on a given publish, never what gets published. A missing, corrupt, or stale
`scrub` file MUST always be treated as "no prior full verification on
record" — implementations MUST fail closed toward more verification, never
less.

A rotation started at `verified_through = vt` takes
`floor((vt - 1) / window)` window publishes followed by one publish that
walks the whole chain again, so `floor((vt - 1) / window) + 1` fast-forward
publishes in all. The largest value of that count is 65, not 64: for
example, `vt = 32769` has `window = 512` and needs 64 window publishes plus
the full walk. Every leaf appended during a rotation is verified when it is
appended and again by the full walk that ends the rotation. So, when every
advisory `scrub` write lands, no leaf goes more than 65 fast-forward
publishes, or more than 7 days of wall-clock time as measured at a
publish, without being re-read from the store, whichever comes first.

Both bounds are evaluated only when a fast-forward publish runs. An idle
branch is not re-verified in the background, and a publish is the only
event that checks the 7-day bound. Proof serving does not depend on the
scrub: `AncestrySnapshot::load` re-walks the whole chain from the store
on every verified load.

The publish-count bound does **not** hold when the advisory `scrub` write
is lost. The write is best-effort and not synced: an I/O failure is
ignored, and a crash after the publish commits but before the write
reaches disk leaves the previous `cursor` in place. The next fast-forward
then re-reads the same window, and repeated loss can defer the rest of the
rotation indefinitely. In that case only the 7-day bound applies. It fails
toward more verification, because a lost write after a full walk leaves
the older `last_full_verify_unix` on disk. The 7-day bound also assumes a
wall clock that does not step backwards: elapsed time is computed with a
saturating subtraction, so a `last_full_verify_unix` in the future counts
as zero elapsed seconds and delays the full walk.

The schedule does not, and is not intended to, defend against deliberate
same-process tampering (out of scope per the threat model) — only against
accidental local corruption (bit rot, a bad GC, a torn write) between two
publications, which content addressing guarantees is always detectable,
never silently wrong, whenever it is eventually re-read.

## 5. Format and scope

The auxiliary namespace and descriptor are version 1. This is a deliberate
pre-release replacement of ref-event history; no native journal reader,
executor bridge, or compatibility API is supported. `CommitHistory` is an
in-memory MMB used to construct canonical snapshots. Its `ForwardFold` bagging
policy is a cryptographic format parameter shared by producers and verifiers.

No change to SPEC-OBJECTS, signing bytes, object IDs or frozen RPC messages is
required. The feature remains opt-in. Builds without it still recognize pending
intent roots and invalidate snapshots on raw mutations. No network trust
bootstrap, signed descriptor predicate, shallow ancestry, or all-parent DAG
proof is claimed.

## 6. Conformance and recovery tests

- `sequential_fast_forward_and_backfill_have_identical_roots_and_positions`
- `generation_changes_on_reset_and_recreation_but_not_noop_or_fast_forward`
- `merge_ancestry_uses_only_first_parent`
- `proof_cannot_substitute_repository_ref_generation_tip_count_or_root`
- `every_publication_boundary_recovers_the_whole_fast_forward`
- `missing_ancestor_fails_before_publication`
- `raw_aba_mutation_invalidates_the_old_generation`
- `tampered_snapshot_and_transaction_fail_closed`
- CLI `a_noop_ref_write_keeps_the_same_ancestry_root`, branch lifecycle and
  reflog/rebase/amend tests.

The fault-injection test stops after each persisted boundary (intent, prepared
snapshot, ref, generation snapshot, active pointer, intent removal), checks
proof withholding and pending GC roots, then requires complete ancestry after
recovery. It does not assert that an arbitrary host filesystem survived an
actual power loss.
