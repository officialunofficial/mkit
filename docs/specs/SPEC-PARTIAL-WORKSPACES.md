---
spec: SPEC-PARTIAL-WORKSPACES
version: 1
status: draft-normative
audience: implementers of portable mkit selected-file snapshot producers and verifiers
---

# SPEC-PARTIAL-WORKSPACES — portable selected-file snapshots

Status: **Draft, normative.** This revision specifies only `MKWB` v1 partial
snapshot bundles and selected-only verification. Replacement overlays, local
workspace state, update export, and publication are outside this revision.

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

## 8. Errors and security cases

Implementations expose typed failures including unsupported version,
non-canonical bytes, base/selection mismatch, insufficient witness, wrong
object type, invalid signature/chunk layout, incomplete selection, unsupported
operation, witness/workspace size, and validation-budget exhaustion.

Conformance tests cover wrong independently supplied base/selection; mutated,
missing, or mode-substituted Trees; missing/wrong chunks and lengths; duplicate,
trailing, and non-minimal bytes; unsolicited payload/history; shared ids with
per-edge checks; over-limit counts/lengths; valid alternative fixed/CDC
representations; and a source proving hidden subtrees/payloads were not read.

Ordinary snapshot closure verification over a valid partial object set MUST
still report hidden reachable objects as missing. Selected verification never
changes or weakens the meaning of complete closure.

## 9. Golden vectors

`rust/tests/golden/partial_workspace/` contains `plain_file`, `chunked_file`,
and `shared_ancestor` accepts plus independently encoded malformed/contextual
rejects. Each `.bin` has a `.json` sidecar and is pinned by `MANIFEST.txt`.
`golden_partial_workspace.rs` consumes committed files without running the
producer.
