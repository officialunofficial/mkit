---
spec: SPEC-PARTIAL-WORKSPACES
version: 1
status: draft-normative
audience: implementers of portable mkit selected-file snapshot, overlay, signing, and update tooling
---

# SPEC-PARTIAL-WORKSPACES &mdash; portable selected-file snapshots and updates

Status: **Draft, normative.** This revision specifies `MKWB` v1 partial
snapshot bundles, authenticated replacement overlays, ordinary Commit signing
handoff, and `MKWU` v1 explicit update export. Local workspace state, complete
base recipient admission, and publication are outside this revision.

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

## 15. Caller-lowered limits

A consumer MAY pass a `PartialLimits` value that is a subset of the v1 profile
in §4. It MUST NOT raise any field while claiming v1 interoperability. Generic
wasm bindings accept an optional JSON object whose keys are those field names;
omitted keys keep the v1 default. Unknown keys, non-integers, negatives,
overflows, and values above v1 are invalid. Host-specific caps belong in the
consumer, not in a named profile inside generic wasm.

A public selected-file consumer is not a confidential host and MUST NOT treat
`MKWU` export as remote publication or complete closure.
