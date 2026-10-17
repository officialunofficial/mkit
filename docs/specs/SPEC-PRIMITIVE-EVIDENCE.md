---
spec: SPEC-PRIMITIVE-EVIDENCE
version: 1
status: draft-normative
audience: implementers of portable verification evidence and resumable verification
---

# SPEC-PRIMITIVE-EVIDENCE &mdash; retained verification state

Status: **Draft normative** for the formats and recovery contract below.
Scope: reconstructible retained pages, membership paths, and trusted-at-rest
verification checkpoints. These formats do not change pack or object bytes and
do not establish repository acceptance or remote attestation.
Endianness: little-endian for numeric fields. A fixed array has exactly its
stated width and no implicit length prefix.

## 1. Versions and trust

**Protocol requirement.**

API versions, normative rulesets, semantic profiles, page formats, proof
formats, and checkpoint formats are independent. A decoder MUST refuse an
unsupported format, ruleset, or profile. It MUST NOT guess a historical
encoding or continue after a partially decoded incompatible checkpoint.

Retained state is reconstructible from the immutable source and authoritative
external facts. An unsupported or unusable checkpoint requires re-verification;
no compatibility reader or migration of prior checkpoint formats is required
by this initial format. This deliberately does not preserve unshipped formats.
It changes no authoritative repository state.

A page decoder establishes canonical structure. Authentication additionally
requires the expected commitment and exact source/ruleset binding. A
checkpoint corruption checksum detects accidental modification; it does not
authenticate hostile state. A host accepting checkpoint bytes from an
untrusted client MUST authenticate the complete envelope and all bindings or
discard them and restart. Decoding MUST NOT directly construct a trusted pack,
closure proof, or guarded acceptance decision.

## 2. Page envelope

**Protocol requirement.**

Every page has the following exact fields, in order:

```text
magic[4]                 ASCII "MKEP"
format_version:u16       1
repository[32]
source_id[32]            whole-pack content address
source_len:u64           complete pack length including trailer
source_binding[32]       immutable caller source version
ruleset:u32              1
profile:u8               1 = indexed
kind:u8                  0 objects, 1 occurrences, 2 dependencies, 3 closure
height:u8                0 leaf, 1..32 internal
items:u16                0..16 leaf records, 1..16 internal children
payload_len:u32
payload[payload_len]
```

The fixed envelope is 123 bytes. The complete encoding MUST NOT exceed
1 MiB or the caller's smaller page cap. `source_len` MUST be at least 44.
Every nested page MUST have the same repository, source, ruleset, profile,
and kind as its root. A missing page MUST NOT stand in for an empty page.

The page digest is BLAKE3 over `u16_le(21)`, the exact 21 ASCII bytes
`mkit-evidence-page:v1`, then the complete canonical page bytes. The length
prefix is part of the hash framing. The root uses the root page's commitment;
there is no separate root hashing domain.

A leaf payload contains exactly `items` records:

```text
key[32]
value_len:u32
value[value_len]
```

Keys MUST be strictly increasing by unsigned bytewise lexicographic order.
Duplicate keys are invalid. The caller's finite value cap applies before any
copy. Values are semantic payloads defined by their owning format; generic
page decoding MUST NOT imply their object or authority validation.

The canonical empty tree is one empty leaf page. An internal page MUST NOT
contain empty children. Each child has height exactly one less than its parent.

An internal payload starts with one child commitment and then repeats
`separator[32], child_commitment` for every remaining child. Separators MUST
be strictly increasing. A commitment is:

```text
digest[32]
kind:u8
encoded_len:u64
items:u64                immediate records or children, not a subtree total
```

Its encoded length is 49 bytes. The decoded child MUST match every commitment
field. For query key K, choose the last child whose preceding separator is
less than or equal to K, or the first child when no separator qualifies.
The chosen child's lower bound is inclusive and upper bound is exclusive.
All descendant keys and separators MUST respect the inherited interval.

Object pages use type-dependent object IDs as keys. Ordered sequences use
24 zero bytes followed by a u64 ordinal in big-endian form as their opaque
32-byte key. This explicit key ordering does not alter the little-endian
encoding of numeric envelope fields.

## 3. Retention and refusal

**Protocol requirement.**

A portable proof encodes `magic[4] = "MKPF"`, `format_version:u16 = 1`, the
49-byte root commitment, `query_key[32]`, `path_count:u16`, and exactly that
many `page_len:u32, canonical_page[page_len]` pairs in root-to-leaf order.
The fixed prefix is 89 bytes. A path contains 1..33 pages and is additionally
limited by the caller's finite path-count, byte, and work caps. The last page
MUST be the correctly routed leaf; an incomplete internal path is unavailable
evidence. An extra page or trailing bytes is invalid.

A retention request binds the exact immutable page commitment and bytes. A
machine MUST NOT advance a dependent checkpoint, root, or completion until the
host acknowledges that commitment. Wrong, unsolicited, stale, or duplicate
acknowledgments are host-protocol misuse.

A missing or unavailable retained page is acquisition failure. It MUST NOT
produce a membership, nonmembership, or completion result. Recovery may discard
dependent progress and re-verify from a safe boundary. A nonmembership answer
requires an authenticated path to the correctly routed leaf and the absence
of the queried key in that leaf.

Every decoder MUST enforce finite input, nested-count, value, resident-memory,
allocation, and work limits before allocation or processing. Nested page
decoding shares the enclosing operation's cumulative budget. Truncated fields,
unknown tags, count/length disagreement, noncanonical ordering, overflow, and
trailing bytes refuse the entire value. Limit exhaustion MUST remain distinct
from malformed content and unavailable acquisition.

## 4. Recovery boundaries

**Protocol requirement.**

A checkpoint binds exact source identity, length and version, repository,
ruleset/profile, effective content and execution limits, run generation,
phase, logical position, declared/consumed counts, cumulative resource usage,
current evidence roots, and retention acknowledgment position. Resume MUST
validate consistency among these fields before producing progress.

Only completed integrity subtrees and safe entry/evidence boundaries may be
checkpointed. A partial subtree or active entry is replayed from its bound
start. Private decoder or cryptographic-library memory MUST NOT be serialized.
Cold resume authenticates the consumed prefix of its current input window.
Changed source bindings, missing retained evidence, unsupported versions, or
inconsistent geometry require recovery or restart and never manufactured
success. Cumulative work and evidence charges survive restart; replay adds
charges for the repeated work.

### 4.1 Checkpoint envelope

**Protocol requirement.**

The current checkpoint encoding has the following exact order. `optional(T)`
is a one-byte tag (`0` absent, `1` present), followed by T only when present.
Any other tag is invalid. A hash is 32 bytes; a page commitment uses the
49-byte encoding in §2.

```text
magic[4]                         ASCII "MKCP"
format_version:u16               1
source_id[32]
source_len:u64
source_binding[32]
repository[32]
ruleset:u32                      1
profile:u8                       1 = indexed
limits:
  acquisition_bytes:u64
  resident_bytes:u64
  page_bytes:u64
  resident_pages:u32
  checkpoint_bytes:u64
  evidence_bytes:u64
  evidence_pages:u64
  decoded_bytes:u64
  dependency_edges:u64
  external_lookups:u64
  work:u64
indexed_content_profile:
  pack_bytes:u64
  decoded_bytes:u64
  delta_depth:u32
run_generation:u64
request_sequence:u64
phase:u8                         0 header, 1 integrity, 2 decode, 3 complete
header:optional(pack_version:u32, entry_count:u32)
consumed_entries:u64
consumed_wire_payload:u64
verified_pack_trailer[32]
acknowledged_pages:u64
last_retained:optional(page_commitment)
usage:
  resident_bytes:u64              0; restored allocations are charged again
  peak_resident_bytes:u64
  evidence_bytes:u64
  evidence_pages:u64
  work:u64
integrity:optional(
  acquired_offset:u64,
  whole_cv_count:u16, whole_cvs[whole_cv_count][32],
  trailer_cv_count:u16, trailer_cvs[trailer_cv_count][32],
  whole_root:optional(hash), trailer_root:optional(hash),
  partial_trailer[32], partial_trailer_used:u8
)
core_cursor_len:u16
core_cursor[core_cursor_len]
checksum[32]
```

The checksum is BLAKE3 over `u16_le(27)`, the exact 27 ASCII bytes
`mkit-checkpoint-checksum:v1`, then every preceding envelope byte. There is no
NUL byte after the domain. Page hashing follows the same length-prefixed
framing with its distinct domain (§2). Neither checksum is a signature.

A checkpoint without optional payloads is 369 bytes, including its checksum.
The caller's finite checkpoint, work, and allocation caps also apply to nested
frontiers and the core cursor. Each frontier contains at most 518 chaining
values. The core cursor is at most 4096 bytes and uses the core reader's own
strict decoder; this specification does not duplicate that grammar.

Header phase has no header, integrity frontier, cursor, consumed entries,
payload, or verified trailer. Integrity phase has a header and integrity
frontier, but no cursor or decoded entries. Decode phase has a header and core
cursor, but no integrity frontier. Complete phase has neither frontier nor
cursor; its consumed count and byte position MUST exactly reach the declared
entry count and trailer boundary.

For every checkpoint, acknowledged page count MUST equal consumed entry count
and cumulative evidence page count. A last retained commitment exists exactly
when this count is nonzero; it names one occurrence record. Cumulative usage
MUST fit the encoded limits. The source length MUST fit both protocol and
content-profile ceilings. Resume additionally compares the envelope with the
caller's expected source, repository, ruleset, limits, and run binding, and
checks core cursor metadata against the outer phase and counters. Successful
envelope decoding alone does not perform those resume checks.

Integrity frontiers represent completed 8 MiB subtrees. A nonfinal acquired
offset MUST lie on a subtree boundary. Sources no larger than 8 MiB have no
stored chaining values; their incomplete hash work is replayed. A root exists
exactly when its stream is complete. The trailer stream covers source length
minus 32 bytes. Unused bytes of the partial trailer MUST be zero.

### 4.2 Ordered frame evidence

**Protocol requirement.**

The framing driver emits one occurrence leaf for each decoded frame. Its
single key is the ordered ordinal key defined in §2. The value is exactly
58 bytes:

```text
record_version:u8        1
frame_offset:u64
frame_len:u64
wire_type:u8             pack frame type
decoded_len:u64         decoded raw payload or delta instruction length
previous_page_digest[32]
```

The first record uses an all-zero predecessor digest. Every later record
names the immediately preceding acknowledged occurrence page. Each complete page is 217 bytes. This chain
records framing and retention; it does not establish canonical object identity,
delta resolution, signatures, membership, or acceptance.

## 5. Version history

| Format | Version | Policy |
|---|---|---|
| Page | 1 | Initial source-bound canonical page envelope. |
| Proof | 1 | Exact routed root-to-leaf page path. |
| Frame record | 1 | Ordered framing-only retention chain. |
| Checkpoint | 1 | Current-only reconstructible state; unsupported versions restart. |

## 6. Test vectors

The empty page bytes are pinned in
**rust/tests/golden/primitives/page-empty.bin** and consumed from the portable
fixture inventory with its semantic sidecar. Tests cover every truncated
prefix, unsupported version/ruleset/profile, changed context, duplicate keys,
wrong kind/height, cap exhaustion, trailing bytes, and bounded nested work.

## 7. Invariants

| Invariant | Enforcement |
|---|---|
| Decoding cannot create trusted acceptance evidence | Separate private artifact construction (§1). |
| Every page belongs to one exact source and ruleset | Committed binding and expected context (§2). |
| Missing input never proves absence | Authenticated route to a leaf (§3). |
| Checkpoints reference acknowledged retained state | Retention backpressure (§3). |
| Restart cannot reset cumulative execution charges | Bound counters and replay accounting (§4). |
| Unsupported disposable formats never guess compatibility | Strict refusal and restart (§1). |
