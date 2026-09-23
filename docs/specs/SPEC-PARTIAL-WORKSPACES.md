---
spec: SPEC-PARTIAL-WORKSPACES
version: 1
status: draft-normative
audience: implementers of portable mkit selected-file snapshot, overlay, signing, and update tooling
---

# SPEC-PARTIAL-WORKSPACES &mdash; portable selected-file snapshots and updates

Status: **Draft, normative.** This revision specifies `MKWB` v1 partial
snapshot bundles, authenticated replacement overlays, ordinary Commit signing
handoff, `MKWU` v1 explicit update export, the durable scoped-workspace
local-state format (§16), and factual full-data recipient validation plus
generic explicit-object transfer (§17). Managed admission remains outside
this revision.

## 1. Trust and coverage

A verifier receives three independent inputs: an expected Commit/Remix object
id, an exact ordered path selection, and untrusted bundle bytes. A successful
verification proves that:

- the canonical base object has the expected id and a valid strict Ed25519
  signature under its embedded signer;
- every selected path is derived from complete canonical ancestor Trees whose
  ids are authenticated from that base;
- every selected regular/executable file has a complete valid Blob or
  ChunkedBlob representation, including every referenced Blob chunk; and
- the bundle carries exactly the required union of those objects.

The result has **selected-only** coverage. It does not prove complete snapshot
or history closure, signer identity/trust, permission, ownership, current time,
or remote publication authority. Signature integrity and identity trust remain
separate as specified by SPEC-SIGNING §6.

## 2. Bundle format

`MKWB` is a portable container, not an mkit object kind. It has no object id or
additional signature. Existing object ids authenticate its canonical object
bytes; the independently supplied base and selection bind its context.

Unlike SPEC-CONVENTIONS §3's general little-endian default, fixed-width
integers in this format are **big-endian**, matching the commonware codec
convention already used by SPEC-DISCLOSURE. Vector and byte-string lengths use
minimal unsigned LEB128 varints. Fixed arrays are raw, without a length prefix.

```text
magic: [u8; 4] = "MKWB"
version: u8 = 1
base_id: [u8; 32]
paths: Vec<Path>
  Path: Vec<Component>
  Component: Vec<u8>
objects: Vec<PartialObject>
  PartialObject {
    id: [u8; 32]
    canonical_bytes: Vec<u8>
  }
```

The decoder MUST reject an unsupported version, non-minimal or invalid varint,
truncation, a count/length outside the active limits, and trailing bytes. It
MUST check count and aggregate byte limits before allocating the corresponding
vector or byte string.

Paths MUST be strictly increasing by the bytewise lexicographic order of their
components joined with literal `/` bytes. Objects MUST be strictly increasing
by `id`. Duplicates are invalid. Producers MUST NOT normalize names or silently
sort/deduplicate caller input.

## 3. Selected path profile

Every selected path MUST contain 1..=32 components. Each component MUST:

- contain 1..=255 bytes and be valid UTF-8;
- satisfy the Tree name grammar in SPEC-OBJECTS §4.1;
- contain no Unicode control character; and
- when it is the root component, not equal `.mkit-scoped` under ASCII
  case-insensitive comparison.

The joined path MUST contain at most 1,024 bytes; all joined paths together at
most 64 KiB. No Unicode normalization or case folding is performed beyond the
specific ASCII-insensitive reserved-name checks. Unselected Tree entry names
need only satisfy SPEC-OBJECTS; this profile does not rewrite or discard them.

## 4. V1 limits

These limits apply to this opt-in format, not to ordinary object storage,
clones, packs, refs, or grant/policy systems. Callers MAY lower any value but
MUST NOT raise it while claiming v1 profile conformance.

| Quantity | Maximum |
| --- | ---: |
| selected paths | 256 |
| path depth | 32 |
| one component | 255 bytes |
| one joined path | 1,024 bytes |
| aggregate selected path bytes | 64 KiB |
| one selected file | 4 MiB |
| aggregate selected file bytes | 16 MiB |
| canonical base object | 4 MiB |
| one canonical Tree | 16 MiB |
| entries in one Tree | 100,000 |
| deduplicated Tree witness bytes | 32 MiB |
| Tree visits | 8,193 |
| complete bundle | 56 MiB |
| object records | 65,536 |
| one canonical object | 16 MiB |
| changed paths in one update | 256 |
| Commit message in the partial-update workflow | 4 KiB |
| raw update pack | 48 MiB |
| object records in one update pack | 65,536 |
| complete encoded update | 56 MiB |

All additions and integer conversions MUST be checked. A producer's generic
object source returns already allocated bytes; source implementations MUST
bound their own reads. The producer MUST check the returned size immediately,
before object decode or copy, and MUST charge the complete encoded bundle
framing before retaining each new id. That incremental charge includes the
header and selected paths, object-count varint growth, and each object's id,
length prefix, and canonical bytes. Object bytes are charged once per id;
selected file bytes and chunk lengths are counted per occurrence. The producer
MUST stop collecting after a detectable layout or resource failure.

The current `ObjectSource` return allocation, decoded-object and cache
overhead remain separate bounded costs, so the bundle limit is not an exact
process-RSS cap. This limitation of the source interface MUST NOT be described
as producer-controlled allocation safety. Bundle decoding itself MUST enforce
the table before allocation.

## 5. Producer

Given a full object source, expected base id, exact selection, and limits, a
producer MUST:

1. Read only the base, selected paths' necessary ancestor Trees, and selected
   file representations/chunks. It MUST NOT traverse parents, hidden
   subtrees, or unselected file payloads.
2. Recompute every returned object's type-dependent id. Tree and ChunkedBlob
   ids are the domain-wrapped BMT ids in SPEC-MERKLE-OBJECTS, never flat
   BLAKE3 of their serialized bytes.
3. Require canonical decode/serialize equality and strict base signature
   verification.
4. Deduplicate bytes by id but validate every edge occurrence in its expected
   role. Once a selected file's authenticated length is known, enforce the
   per-file and aggregate selected-byte limits before collecting its chunks.
   Reject a chunk layout as soon as its running occurrence length exceeds the
   manifest's declared `total_size`; exact equality remains required at the
   end. Resource-limit failures detected first take precedence over latent
   object or layout failures.
5. Emit exactly the object union required by §6, sorted by id.

No fallback to a full pack/clone is permitted when a selected witness exceeds
this profile.

The core producer also exposes a consuming, one-request-at-a-time
`PartialSnapshotBuilder`. It derives each requested id from the pinned base
or a previously authenticated selected edge, advertises a cap for a source
to enforce before allocating, and terminally rejects a bad supply. The
existing synchronous producer drives this same state machine and retains
the independent final bundle verification. The request is not a grant to
fetch arbitrary ids; host authorization remains external.

`identify_snapshot_object` derives the type-aware id and intrinsic facts of
one bounded canonical Snapshot-kind object, while
`inspect_snapshot_object` also checks an independently expected id and
incoming role. Neither identifies a complete Snapshot. In particular,
ChunkedBlob metadata alone does not establish referenced chunk types,
per-position lengths or the final sum. Complete traversal is a separate
recipient obligation, and selected-file caps do not constrain untouched
files inspected for that purpose.

## 6. Verification

A verifier MUST perform these checks atomically and return no partially usable
verified value on failure:

1. Check the complete input size, header, bounded canonical decode, ordering,
   duplicates, and trailing-byte rule.
2. Require `base_id` to equal the independently expected base and `paths` to
   equal the independently expected exact selection.
3. Locate the base bytes by that id; require a canonical Commit or Remix,
   recompute its id, and strictly verify its embedded signature.
4. Starting at its `tree_hash`, load a complete canonical Tree for every
   selected path component. Before decoding a Tree, preflight its encoded entry
   count against the 100,000-entry limit. Recompute its Tree id and find the
   selected component locally by exact bytes.
5. Require every intermediate entry mode to be Tree. Require the final entry
   mode to be Blob or Executable. Selected symlinks and directories are
   unsupported.
6. Require the final object to be Blob or ChunkedBlob. Check its complete
   content length before materialization; never allocate from an untrusted
   `total_size`.
7. For ChunkedBlob, require every chunk occurrence to resolve to a canonical
   Blob and sum occurrence lengths with checked arithmetic to exactly
   `total_size`. When `chunk_size > 0`, every non-final chunk MUST equal
   `chunk_size` and the final chunk MUST contain 1..=`chunk_size` bytes. When
   `chunk_size == 0`, alternative valid CDC boundaries are accepted: the
   verifier checks types/order/total only and MUST NOT rechunk using the
   current writer policy.
8. Compare the supplied object set with the exact union of base, visited
   Trees, selected top-level representations, and chunks. Missing objects are
   insufficient witnesses; extras (including unrelated history or sibling
   payloads) are invalid.

The same id reused under multiple edges is stored once, but every occurrence
MUST be checked. An id required as incompatible object roles fails even if it
was valid under another edge.

## 7. Verified result

The verified type MUST have private construction and private mutable state. It
retains the canonical base object bytes/object, embedded signer fact, exact
selection, complete decoded ancestor Trees, selected-file mode/id/content
length/chunk ids, and the exact canonical object table. Accessors are immutable.
Its coverage value is `SelectedOnly`; there is no full-closure success flag.

A proof-only disclosure that lacks the complete Tree/file materialization
required here MUST fail as an insufficient witness. There is no metadata-proof
fallback.

## 8. Authenticated replacement overlay

An overlay accepts a non-empty batch of replacements against a
`VerifiedPartialSnapshot`. Each replacement MUST name an exact selected path
and provide either:

- complete caller-supplied file bytes; or
- an explicit reference to the complete representation of another file in the
  same verified snapshot.

The overlay MUST NOT accept a bare caller-supplied object id. It MUST reject the
whole batch when a destination is duplicated, absent, unselected, a directory,
or a symlink. New paths, deletions, renames, mode changes, subtree replacement,
and chunk-only edits are unsupported. A destination's authenticated Blob or
Executable mode MUST remain unchanged.

Implementations MUST compare validated file content, not only representation
ids. If supplied bytes or a reused verified representation have the same
content as the destination, the overlay MUST retain the destination's original
mode and representation id. It MUST omit that path from the change set. If all
requested replacements are content no-ops, the operation MUST fail with
`NoChanges`. This helper rule does not change ordinary mkit's empty-Commit
rules.

New byte content of at most 1 MiB MUST use one Blob. Larger content MUST use a
ChunkedBlob with `chunk_size = 0` and the v1 boundaries from SPEC-FASTCDC. A
valid selected representation reused from another path keeps its existing
representation and chunk ids. Callers cannot edit or choose individual chunks.

The overlay MUST preserve every untouched `(name, mode, object_id)` Tree entry
triple exactly, including hidden siblings, symlinks, subtrees, and empty Trees.
It MUST rebuild changed ancestors bottom-up and apply all sibling changes before
serializing their common parent. Rewrite contexts are keyed by path occurrence,
not by original Tree id: if `a/` and `b/` point to the same Tree, editing
`a/x` MUST NOT alter `b/x`, and independent edits below both paths MUST survive.
Produced object bytes MAY deduplicate by id.

Overlay construction uses only the verified base object, authenticated complete
ancestor Trees, and complete selected file representations. It MUST NOT read a
hidden payload, hidden subtree, parent Commit, network service, or unrelated
object store. Any failure returns no usable prepared value. The prepared type
MUST have private construction and private mutable state.

For export inventory, dependencies are retained once per unique object id, and
a reused representation's chunk occurrences are traversed at most once no
matter how many destinations use it. Repeated chunk occurrences remain part of
that representation's validated layout and per-destination content accounting;
inventory deduplication does not collapse those semantic occurrences. A
semantic no-op MUST NOT retain or traverse export dependencies after equality
is established.

## 9. Ordinary Commit preparation and signing

Commit preparation produces an ordinary unannotated SPEC-OBJECTS Commit with:

- `tree_hash` equal to the prepared overlay root;
- exactly one parent, equal to the verified base id, whether that base is a
  Commit or Remix;
- caller-supplied author, signer public key, message, and timestamp;
- zero `message_hash` and `content_digest`; and
- a zero signature for the signing handoff.

The message MUST fit the active limit, at most 4 KiB for the v1 profile.
Preparation does not require `author` to equal `signer`. Identity binding,
signer trust, key custody, owner policy, permissions, clocks, grants, and remote
services remain application concerns.

The caller signs the prepared Commit through the existing SPEC-SIGNING Commit
domain and interface. No new signing domain or signature field exists. Before
export, an implementation MUST receive the expected unsigned Commit explicitly
alongside the verified base, prepared overlay, and signed Commit. It MUST:

1. require the unsigned root and sole parent to equal the prepared root and
   verified base;
2. require its annotations and signature to be zero;
3. require the signed Commit to equal every unsigned field exactly after only
   its signature is zeroed; and
4. strictly verify the signed Commit under its embedded signer.

The exporter MUST reject author, signer, message, timestamp, root, parent,
annotation, or signature substitution. It MUST NOT infer those fields from the
tree-only prepared edit.

## 10. Update container format

`MKWU` is a bounded portable carrier, not an mkit object kind, closure format,
authorization token, or publication request. Its change manifest is unsigned
contextual metadata. The signed candidate Commit authenticates its parent,
root, authorship fields, and signer under SPEC-SIGNING.

As with `MKWB`, fixed-width integers are **big-endian**, vector and byte-string
lengths use minimal unsigned LEB128 varints, and fixed arrays are raw. The
`pack_length` field is followed by the ordinary byte-vector encoding of
`pack_bytes`, so the wire contains both the fixed-width length and a minimal
LEB128 vector length. Both lengths MUST equal the actual remaining pack bytes.

```text
magic: [u8; 4] = "MKWU"
version: u8 = 1
base_id: [u8; 32]
candidate_id: [u8; 32]
changes: Vec<Change>
  Change {
    path: Vec<Component>
    Component: Vec<u8>
    old_mode: u8
    old_id: [u8; 32]
    new_id: [u8; 32]
  }
pack_hash: [u8; 32]
pack_length: u64 BE
pack_bytes: Vec<u8>
```

`old_mode` uses the exact SPEC-OBJECTS §4.2 values and MUST be `0x01` Blob
or `0x04` Executable. No second mode mapping is defined. `old_id` and `new_id`
MUST differ. Paths obey §3 and MUST be strictly increasing by joined raw path
bytes. Duplicates are invalid. A conforming encoder emits at least one and at
most 256 changes.

`pack_hash` is the SPEC-PACKFILE transport identity: BLAKE3 over the complete
pack bytes, including the pack trailer. It is distinct from that trailer. A
decoder MUST reject wrong magic/version, non-minimal or overflowing varints,
invalid paths or modes, duplicate/unsorted changes, length mismatch,
pack-identity mismatch, truncation, and bytes after the declared pack.

## 11. Exact raw-object inventory

The embedded pack MUST be a SPEC-PACKFILE v1 raw-only pack. Every entry type is
`0x00`; compressed and delta entries are invalid. Entries MUST be strictly
increasing by their recomputed type-dependent object id, with no duplicates.
Each payload MUST be a canonical storable SPEC-OBJECTS object whose recomputed
id matches its inventory position. A Tree or ChunkedBlob id uses
SPEC-MERKLE-OBJECTS, not flat BLAKE3 of canonical bytes.

The inventory is exactly the deduplicated union of:

1. the ordinary signed candidate Commit;
2. every rebuilt Tree on a changed path from the candidate root; and
3. every changed file's complete Blob or ChunkedBlob representation and, for a
   ChunkedBlob, every referenced Blob chunk.

Rule 3 applies even when the representation or chunks were present in the
selected input, were reused from another selected path, already exist in a
recipient or global store, or appear under another changed path. Deduplication
is only within the output pack. An exporter MUST NOT omit retained ids based on
external store membership.

The pack MUST NOT add the base object, parent history, hidden payloads, hidden
subtree closure, unchanged selected representations, or unrelated objects merely
to make an ordinary closure walk complete. Exporters MUST NOT use full
closure-difference push planning. A decoded update alone therefore makes no
snapshot-closure or history-closure claim.

The candidate MUST be a strictly valid Commit with exactly one parent equal to
`base_id`; `candidate_id` MUST equal its type-dependent id. Walking each changed
path through packed rebuilt Trees MUST end at an entry whose mode equals
`old_mode` and whose object id equals `new_id`. The complete new representation
and chunks MUST be present. The derived inventory MUST equal the pack inventory
exactly; missing and extra objects are invalid.

These checks do not authenticate each `old_id` against a complete retained base
or decide whether a ref may move. A later complete-base recipient validates the
actual old-to-new diff and resulting closure before any publication. That
separation does not weaken the exporter's requirement to derive `old_id` from
the verified selected base.

## 12. Resource accounting

The §4 limits apply independently to snapshot and update operations. Overlay
code MUST validate caller byte lengths before avoidable copies or chunking and
count replacement lengths per occurrence, even when representations deduplicate.
Generated objects, canonical bytes, metadata, object count, raw-pack entry
framing, pack header/trailer, update manifest, both pack lengths, and complete
update framing MUST be charged with checked arithmetic as soon as each cost is
known. Implementations MUST stop at the first detectable resource failure; they
MUST NOT build an oversized object set or pack and reject only afterward.

The raw pack is limited to 48 MiB and 65,536 objects. The complete `MKWU` bytes
are limited to 56 MiB. Each canonical object retains §4's 16 MiB cap. A caller
MAY lower these limits but MUST NOT raise them while claiming v1 profile
conformance. These bounds do not change the larger ordinary SPEC-PACKFILE limits
or guarantee exact process RSS.

Every operation MUST apply the limits supplied to that operation; provenance
from a verified snapshot or prepared edit does not establish compliance with a
later caller's stricter bounds. Commit preparation MUST check the candidate's
canonical object size. Before allocating the raw pack, export MUST recheck the
candidate, rebuilt Trees, reused and generated file representations/chunks,
changed-file occurrence totals, path/change counts, object count, raw-pack
framing, and complete update framing. Consequently, an update successfully
exported and encoded with one limit set MUST be accepted by the `MKWU` decoder
with that same set, absent mutation.

The base-object, witness-byte, Tree-visit, bundle-byte, and snapshot object-count
limits apply only while producing or verifying `MKWB`; they are not hidden
second caps on `MKWU`. The path profile, changed-file per-file and aggregate
bytes, Tree object/entry bounds, canonical object size, Commit message, update
object count, raw pack, and complete update limits apply to update production
and decoding. Unique retained dependency identities and generated objects share
one incrementally enforced update-object and exact raw-entry-framing budget;
the two sources MUST NOT each consume an independent full allowance before
their union is checked. Collection-node allocator overhead is not an exact RSS
measurement.

## 13. Errors and security cases

Implementations expose typed failures including unsupported version,
non-canonical bytes, base/selection mismatch, insufficient witness, wrong
object type, invalid signature/chunk layout, incomplete selection, unsupported
operation, witness/workspace size, and validation-budget exhaustion.

Conformance tests cover wrong independently supplied base/selection; mutated,
missing, or mode-substituted Trees; missing/wrong chunks and lengths; duplicate,
trailing, and non-minimal bytes; unsolicited payload/history; shared ids with
per-edge checks; over-limit counts/lengths; valid alternative fixed/CDC
representations; and a source proving hidden subtrees/payloads were not read.
Overlay/update cases cover batch convergence and repeated Tree ids at distinct
path occurrences, untouched hidden triples, alternative-representation no-ops,
canonical chunking, signed-field substitution, raw inventory completeness,
wrong update lengths/hash, duplicate/extra entries, trailing bytes, and
compressed/delta pack entries. A malformed fixture MUST otherwise be complete
and valid so its intended defect determines rejection.

Ordinary snapshot closure verification over a valid partial object set MUST
still report hidden reachable objects as missing. Selected verification never
changes or weakens the meaning of complete closure.

Protocol validity is independent of permission. No result in this document is a
grant, owner claim, trusted timestamp, service admission, ref publication, or
makechain-specific authorization.

## 14. Golden vectors

`rust/tests/golden/partial_workspace/` contains `plain_file`, `chunked_file`,
and `shared_ancestor` accepts plus independently encoded malformed/contextual
rejects. Each `.bin` has a `.json` sidecar and is pinned by `MANIFEST.txt`.
`golden_partial_workspace.rs` consumes committed files without running the
producer.

`rust/tests/golden/partial_update/` contains deterministic accepts plus
independently formed rejects for length/hash, duplicate/extra inventory,
trailing bytes, and compressed/delta entries. Each `.bin` has a `.json`
sidecar and is pinned by `MANIFEST.txt`. `golden_partial_update.rs` consumes
only committed artifacts when `MKIT_WRITE_GOLDEN` is unset.

`rust/tests/golden/partial_local/` contains accepted `MKWS`, `MKST`, `MKPN`,
`MKAC`, `MKGM`, and `MKCR` envelopes captured from real workspace
transitions, plus independently byte-constructed rejects for bad checksum,
unsupported version, trailing bytes, non-minimal varint, and unknown
option/status tags. Each `.bin` has a `.json` sidecar and is pinned by
`MANIFEST.txt`. `golden_partial_local.rs` consumes only committed artifacts
when `MKIT_WRITE_GOLDEN` is unset.

`rust/tests/golden/partial_publication/request_v1.bin` is an independently
encoded §18 fingerprint preimage; its JSON sidecar and manifest pin the digest.

## 15. Caller-lowered limits

A consumer MAY pass a `PartialLimits` value that is a subset of the v1 profile
in §4. It MUST NOT raise any field while claiming v1 interoperability. Generic
wasm bindings accept an optional JSON object whose keys are those field names;
omitted keys keep the v1 default. Unknown keys, non-integers, negatives,
overflows, and values above v1 are invalid. Host-specific caps belong in the
consumer, not in a named profile inside generic wasm.

A public selected-file consumer is not a confidential host and MUST NOT treat
`MKWU` export as remote publication or complete closure.

## 16. Durable scoped-workspace local state

A **scoped workspace** is a directory that materializes exactly the verified
selected files of a base Commit/Remix plus durable local state under a private
metadata directory. It is not an ordinary repository: it has no object store,
index, refs, config, or key state, and ordinary commands MUST refuse to run
inside it. This section specifies the on-disk format only; admission,
publication, and fetch are out of scope.

### 16.1 Physical layout

```text
<root>/.mkit                       regular file, exact bytes "mkit-scoped: 1\n"
<root>/.mkit-scoped/workspace.lock stable-inode lock file, never unlinked
<root>/.mkit-scoped/CURRENT        MKCR envelope selecting one generation
<root>/.mkit-scoped/generations/<manifest-digest>/
    manifest.bin                   MKGM envelope
    workspace.bin                  MKWS envelope
    stage.bin                      MKST envelope
    pending.bin                    MKPN envelope, iff the manifest names it
    accepted.bin                   MKAC envelope, iff the manifest names it
<root>/.mkit-scoped/bundles/<digest>.mkwb    verified base bundle
<root>/.mkit-scoped/objects/<object-id>      stage-produced canonical objects
<root>/.mkit-scoped/updates/<digest>.mkwu    pending update artifact
```

Generation directory names are the lowercase 64-hex flat BLAKE3 of the
complete `MKGM` envelope. Member file names are fixed by code and never
decoded from disk. Artifact names are digest-derived. The pending update path
is canonically `.mkit-scoped/updates/<lowercase update_digest hex>.mkwu`; that
digest/path pair is the exact pending artifact and is never caller-controlled
or encoded. A `service/` name is reserved and never created by this revision.

### 16.2 Envelope grammar

Every durable-state envelope is `[magic:4][version:1][payload][checksum:32]`
with `version = 1` and `checksum` the flat BLAKE3 of `magic ‖ version ‖
payload`. A complete envelope is at most 1 MiB. Fixed-width integers are
big-endian; counts and byte strings use minimal unsigned LEB128; fixed arrays
carry no length; option tags are exactly `0` or `1`. Paths are component
vectors as in `MKWB`, strictly sorted by joined raw bytes; modes are exactly
`0x01` (regular) or `0x04` (executable). Decoders MUST reject unknown
versions, unknown tags or statuses, non-minimal varints, out-of-bound counts,
trailing bytes, and checksum mismatches. The checksum detects corruption and
torn writes; it is not a signature and confers no authority.

Payload orders, in field order:

```text
MKWS WorkspaceStateV1:
    workspace_id[32]
    transaction_generation u64
    base_revision u64
    base_id[32]
    base_bundle_digest[32]
    selection_count varint
        repeated path, mode u8, base_file_id[32]
    20 PartialLimits u64 fields in declaration order
    target_tag u8
        if 1: endpoint bytes, repository bytes, exact_ref bytes

MKST StageStateV1:
    workspace_id[32]
    base_id[32]
    base_revision u64
    entry_count varint
        repeated path, mode u8, staged_id[32]
    required_object_count varint
        repeated object_id[32]

MKPN PendingStateV1:
    workspace_id[32]
    base_id[32]
    base_revision u64
    created_generation u64
    candidate_id[32]
    update_digest[32]
    update_length u64
    status u8        (0 prepared, 1 exported, 2 conflict, 3 unknown)
    operation_tag u8
        if 1: operation_id[32], request_fingerprint[32]

MKAC AcceptedStateV1:
    workspace_id[32]
    prior_base_id[32]
    accepted_base_revision u64
    candidate_id[32]
    update_digest[32]
    operation_tag u8
        if 1: operation_id[32], request_fingerprint[32]

MKGM generation manifest:
    transaction_generation u64
    workspace_digest[32]
    stage_digest[32]
    pending_digest_tag u8 + digest[32] iff 1
    accepted_digest_tag u8 + digest[32] iff 1

MKCR CURRENT:
    transaction_generation u64
    manifest_digest[32]
```

Member digests in `MKGM` are flat BLAKE3 of complete member envelopes. The
initial transaction generation and base revision are `0`. Every non-idempotent
successful transition increments the transaction generation (overflow is
rejected); accepted advancement alone increments the base revision. The
workspace `transaction_generation` MUST equal the manifest/CURRENT generation.
Stage and pending records bind the workspace id, base id, and base revision;
the accepted record binds the prior base id and the new base revision. Readers
MUST verify all redundant bindings.

### 16.3 Commit algorithm and crash recovery

`CURRENT` is the sole authority: readers decode exactly the generation it
names and MUST NOT scan `generations/` or pick a highest generation, and MUST
NOT fall back to working-tree contents. A transition commits by:

1. validating and precomputing under the exclusive `workspace.lock`, held by a
   fresh per-operation descriptor that is inode-verified against the stable
   `workspace.lock` sentinel and released by descriptor close, so threads
   sharing one workspace handle serialize and a panic cannot strand the lock.
   After the blocking flock returns, the sentinel name is re-opened no-follow
   and its type, link count, and inode identity MUST be re-verified against
   the pinned identity before the mutation runs &mdash; a sentinel replaced
   while the operation waited leaves the acquired lock on a detached inode,
   and the operation MUST refuse without invoking its mutation;
2. validating the complete proposed next state BEFORE any publication effect:
   workspace/stage/pending/accepted bindings, selection coverage, the
   pending/accepted no-duplication rule, the required-object inventory against
   the same `max_update_objects`/`max_raw_pack_bytes` accounting the producing
   overlay was charged, every staged representation resolving through the
   authenticated sources, the complete selected-file aggregate limit, and the
   deterministic retained-inventory equality reopen enforces &mdash;
   a state the reopen checks would reject MUST NOT reach `CURRENT`;
3. writing each immutable artifact (bundle/object/update) and each generation
   member to a fresh sibling temporary, fsyncing it, installing it under its
   canonical digest name with an atomic no-replace rename, then fsyncing the
   containing directory &mdash; a pre-existing canonical name with identical
   bytes is an idempotent retry whose file and directory durability MUST be
   established before the new authority relies on it, and differing bytes are
   an error; an interrupted temporary never occupies the canonical name;
4. ordering members before `manifest.bin` within the generation, then fsyncing
   the generation and `generations` dirs;
5. writing and fsyncing a sibling `CURRENT` temp file, then atomically
   replacing `CURRENT`;
6. fsyncing `.mkit-scoped`.

The `CURRENT` replacement is the linearization point. A fault before it
leaves the prior generation authoritative; a fault after it but before the
final directory fsync reports durability uncertainty rather than rolling back
or claiming success. Orphaned generations, stale sibling temporaries, and temp
files MAY remain and MUST be skipped on later runs; there is no garbage
collection of scoped state in this revision.

A persisted stage replays through the same authenticated replacement overlay
that produced it, preserving representation identity: a `staged_id` naming a
verified selected file's representation replays as that reuse &mdash; never
re-canonicalized to fresh bytes. The retained `required_object_ids` inventory
follows ONE deterministic rule, independent of the caller's `Bytes` versus
`ReuseSelected` operation form: exactly the produced-object set of the
representation-preserving overlay MINUS any id the verified base selection
already authenticates &mdash; where the base-authenticated set is each
selected file's representation id AND the complete dependency closure that
representation declares (every chunk of a selected ChunkedBlob), plus any
other object the verified snapshot retains &mdash; including rebuilt
ancestor Trees and no unrelated objects. The same dedup applies when a
chunk is shared between a reused base representation and newly generated
content: the shared chunk is base-authenticated and not retained, while
the new representation's manifest and its genuinely new chunks are.
Producer persistence, pre-publication validation, and reopen
verification all apply that same rule, so a `Bytes` replacement equal to
another selected file persists exactly what its `reuse_selected` equivalent
would, for plain and chunked representations alike. This is a LOCAL
storage contract only &mdash; the exported update
inventory still lists every changed representation and chunk per &sect;11.
Persisted chunked representations are validated per occurrence against their
declared totals BEFORE any content is materialized, retained objects are
charged incrementally against the raw-pack budget by descriptor-reported
length before each read, and each object's actual read is bounded by the
REMAINING headroom so a file grown after metadata inspection still cannot
exceed the aggregate.

### 16.4 Threat and authority limits

Scoped local state is a host-local durability mechanism. The workspace id is
random per create, `RemotePublicationTargetV1` is descriptive only, and a
recorded `Accepted` outcome is a caller assertion &mdash; none of them establish
signer trust, permission, ownership, receipt, or publication authority.
`workspace.lock` is an isolated scoped-root lock domain and is never composed
with ordinary repository lock ordering (SPEC-CONCURRENCY).

Filesystem-facing rules: all state access is descriptor-anchored with
no-follow opens; symlink ancestors and leaves, non-regular authoritative
files, multi-linked files, path-prefix/case/normalization aliases, and
reserved names are rejected; creation installs the complete workspace with the
marker last, by an atomic no-replace directory rename; `init`/`open`/ordinary
commands at or below a scoped root, a corrupt marker, an incomplete recognized
install, or an ordinary/scoped layout conflict MUST refuse before touching
filesystem state.

Scoped-root classification obeys the same anchoring: on descriptor-capable
targets the marker, `CURRENT`, and `generations` lookups open beneath a
no-follow root descriptor and inspect the actual opened object &mdash; a
symlink or non-regular leaf is never followed or blocked on, so a
`.mkit-scoped/generations` link to outside content cannot redirect the
classification read, and a leaf swapped for a FIFO cannot stall it. An entry
named `.mkit-scoped` or `generations` &mdash; or a `CURRENT`/`manifest.bin`
that is a directory, FIFO, symlink, or other non-regular shape &mdash;
carrying no recognizable scoped authority is an unrelated user file, not an
incomplete install, and cannot hide genuine authority found elsewhere
beneath `.mkit-scoped`: ordinary repositories MUST continue to discover and
open past it. Once genuine scoped authority is recognized, missing or
corrupt marker/state fails closed and ordinary permission or I/O errors
propagate.

The ancestor walk resolves the longest EXISTING prefix of the probed path
and continues classification on that resolved directory's REAL ancestors,
so a directory alias cannot smuggle a missing descendant past the boundary
&mdash; whether the alias names the scoped root itself or a directory
INSIDE it, where the probed path's textual ancestors never spell the
enclosing root. Missing suffix components cannot contain authority and are
skipped; a symlinked directory component surfaced as `ENOTDIR` is
normalized to the alias case and resolved, while a genuine non-directory
component is not authority. Resolving an external alias only pins where
the ancestor walk examines `.mkit-scoped` &mdash; it never authorizes
following the state entries themselves.

## 17. Full-data recipient validation and explicit transfer

Full-data recipient validation takes an independently expected base id, MKWU
bytes, a source of canonical objects keyed by id, portable format limits, and
separate recipient-wide limits. It is pure: verification MUST NOT update refs
or mutate the source. MKWU decode
continues to establish portable carrier structure, candidate signature and
one-parent binding, and exact raw inventory. It does not establish that the
manifest describes the actual complete-base change.

A recipient MUST authenticate the expected complete base Commit/Remix and its
entire retained Snapshot from its own source before uploaded bytes can supply
the candidate. Each canonical object MUST be re-identified with its object
kind's ID algorithm, and the base and candidate signatures MUST verify
strictly. Typed traversal MUST check Commit/Remix-to-Tree,
Tree-mode-to-child-kind, ChunkedBlob-to-Blob and every chunk occurrence's
length and layout. The actual base-to-candidate diff MUST match every
manifest old mode/id and new id by path occurrence and MUST contain only
existing regular/executable file replacements with preserved modes and
untouched entry triples. A shared Tree id does not merge two distinct path
occurrences. Closure verification MUST report a complete resulting Snapshot;
parent History is outside this result. Signer identity trust and host policy
remain caller decisions.

The default recipient budget is 100,000 distinct objects, 256 MiB retained
canonical bytes, 16 MiB per object, root Tree depth zero through depth 128,
and 1,000,000 occurrence/work units shared across upload intake, base,
candidate, diff and closure. Before cloning the embedded pack, decoding any
contained object, or reading the base source, the recipient MUST scan borrowed
raw pack entries and reject any count, individual canonical payload, or
aggregate canonical payload that already exceeds its recipient budget. Pack
framing is excluded from
canonical-byte accounting. The intake scan reserves two work units per raw
entry for its own traversal and the subsequent inventory pass; graph traversal
and edge occurrences consume further units. Work units are bounded traversal
accounting, not an exact CPU or memory measurement. A repeated Tree or chunk
occurrence consumes work again even when its object bytes are cached once. A
Tree reached at multiple depths MUST pass the deepest reached depth. The
portable selected-file 4 MiB/16 MiB caps apply to MKWU changed files, not
untouched files in the full recipient's snapshot. The source remains responsible
for bounding its initial fetch allocation; verification bounds returned bytes
before retaining or decoding.

An incremental complete-Snapshot walk MAY keep its frontier and unique-ID
ledger in trusted recipient storage. Its root is independently pinned; each
child request follows an authenticated root Tree, Tree entry, or manifest
chunk position. The recipient MUST recheck every incoming role and Tree depth
per occurrence, even for an ID whose canonical bytes were checked earlier.
It MUST validate each chunk position's type, fixed-size rule and checked
running sum, including repeated IDs. A local cursor preflight rejects a
nonzero initial sum or an impossible fixed-size prefix sum, but cannot prove
that an arbitrary persisted cursor has completed its prior positions.
Distinct reachable IDs and their
canonical lengths count once; each visited occurrence and expanded Tree entry
counts one work unit, and each manifest chunk position counts two units
(expansion plus the chunk occurrence). Page width changes scheduling, not
these semantic totals. A bounded local step never establishes whole-graph
completion. For each committed step, a service MUST consume its prior record
and enqueue every exact successor, including a page continuation, in the same
transaction as counters and unique-ID decisions. It MUST exhaust that frontier
and compare the reached logical ID set with its independently selected catalog
before claiming completion. Persisted work records are service bookkeeping,
not portable cryptographic proofs or authorization. Physical packs may retain
objects outside a later successor's
logical Snapshot; a successor catalog check concerns its logical membership.

The separate generic publisher takes exact MKWU bytes and in-memory exchange
context: repository identity, exact branch ref, 32-byte operation id, expected
base, and digest/length of those exact bytes. This metadata grants no access
and defines no new wire format or receipt. The publisher MUST require an
existing, recipient-owned packmap ref for the pinned base and MUST NOT create
or reset that chain. It uploads the full raw MKWU pack without a closure
difference plan or hidden-object download, appends one PackListNode to the
currently read packmap, and advances head under `Match(base)` and packmap
under `Match(prior)`. It MAY retry at most three explicit packmap conflicts,
re-reading and extending the latest chain each time; it MUST NOT change the
expected head or rebase the candidate. Existing packmap content is assumed to
cover the retained base; generic transfer does not validate remote closure.

Only a transport that explicitly promises one mutable advance without hidden
mutating retries may perform generic publication under this profile. Atomic
two-ref capability says only whether the refs move atomically; it does not
imply durable results. An ordered packmap-first transport may leave an
append-only superset packmap after a head conflict. A lost response after the
advance call begins is publication-unknown even if a later head read matches
the candidate. This profile defines no durable operation-result ledger or
managed admission.

## 18. Offline pending publication state

An offline signed candidate is recorded as Prepared with no required target or
operation. Export copies its exact persisted MKWU bytes to a new external file
and does not alter its publication state. An export after Unknown MUST retain
Unknown. Its destination MUST be outside scoped roots and repository metadata
(`.mkit` or `.mkit-scoped`), including filesystem aliases to those metadata
directories. Export does not advance the base or prove recipient acceptance.

Before the first publication attempt, one local transaction binds the pending
candidate to an exact descriptive endpoint, repository identity, branch ref,
and random 32-byte operation ID. The endpoint/repository/ref are stored in the
existing MKWS optional target; the operation and request fingerprint use the
existing MKPN optional operation. The binding MUST work for an already saved
offline pending candidate. A target already present MUST match exactly. The
fingerprint is the flat BLAKE3 of these canonical bytes in this order:

```text
ASCII "mkit.scoped-publication-request.v1\0"
endpoint UTF-8 length u32 BE, then endpoint bytes
repository UTF-8 length u32 BE, then repository bytes
exact_ref UTF-8 length u32 BE, then exact_ref bytes
base_id[32]
candidate_id[32]
update_digest[32] (flat BLAKE3 of exact persisted MKWU bytes)
update_length u64 BE
operation_id[32]
```

The field limits in §16.2 make every u32 length representable. The fingerprint
is local request identity, not an authorization credential, signature or
receipt. It contains no secret or service credential. The in-memory exchange
context uses the same target/base/operation and exact MKWU digest/length.

Before calling any mutable recipient path, the client MUST durably commit a
new local generation changing Prepared or Exported to Unknown. An error or
durability uncertainty in that write-ahead step MUST prevent the remote call.
Unknown MUST NOT be changed back to Prepared or Exported by export, an exact
save retry, or a repeated status call. A restarted generic client MUST NOT
automatically retry Unknown, infer historical acceptance from the current
head, substitute the pinned target, or reuse an operation identity for a
different request. Every permission to begin an attempt requires the exact
current generation, even when a status update would otherwise be idempotent.
Only a definite successful attempt response lets the caller assert Accepted;
a definite head conflict preserves the candidate. File transport offers no
durable result ledger; a lost reply leaves Unknown.

Explicit local abandonment requires the exact pending candidate ID and an
acknowledgement that remote publication may already have occurred. It clears
the active pending slot while preserving stage and immutable historical
artifacts. It cannot undo a remote effect.
