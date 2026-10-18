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
kind:u8                  0 objects, 1 occurrences, 2 dependencies, 3 closure,
                         4 heads, 5 ordinals
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

**Page lifetime.** Evidence pages are scoped to one verification run. They are
reconstructible: re-verifying the same source reproduces every page and root
byte for byte, and nothing reads a page after the run's terminal completion.
The sealed result carries root digests and counts only. A machine MAY hold
pages it produced without handing them to the host, and MAY drop one it never
handed out once the committed roots stop reaching it. It MUST hand the host,
and obtain acknowledgment for, every page reachable from a checkpoint's roots
before that checkpoint exists. A machine that produced a page the host holds
MUST tell the host when neither the machine's committed roots nor its latest
checkpoint reach the page, and MUST NOT request it afterwards. The host MAY
then discard it. Pages the latest checkpoint reaches stay available until the
next checkpoint exists, so a host persists the new checkpoint before
processing the release that its existence permits. Execution ceilings on
retained evidence count the pages a host currently holds (handed out and not
released), not every page ever produced; the work ceiling stays cumulative.
Completion ends the obligation: the host MAY discard every page of the run,
including pages it was never told to release.

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
Framing checkpoints authenticate the consumed prefix of their current input
window. All-entry verification checkpoints instead retain the hash frontier
through the already-acquired window and authenticate its unconsumed suffix;
they MUST NOT reacquire bytes before the saved entry boundary.
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
phase:u8                         0 header, 1 integrity, 2 decode, 3 complete,
                                 4 integrity drain (version 3 only)
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

For a format version 1 checkpoint, acknowledged page count MUST equal consumed
entry count and cumulative evidence page count. A last retained commitment
exists exactly when this count is nonzero; it names one occurrence record. A
format version 3 checkpoint instead records the cumulative acknowledged page
count, which MUST be at least the number of pages the host still holds
(`evidence_pages`; released pages leave that count), and its last retained
commitment may name any acknowledged evidence page kind, including one the host
has since released (see 4.1.1). Cumulative usage MUST fit the encoded limits. The source length MUST
fit both protocol and content-profile ceilings. Resume additionally compares the envelope with the
caller's expected source, repository, ruleset, limits, and run binding, and
checks core cursor metadata against the outer phase and counters. Successful
envelope decoding alone does not perform those resume checks.

#### 4.1.1 Verify-state section (format version 3)

**Protocol requirement.**

`format_version:u16 = 3` appends one verify-state section after `core_cursor`
and before `checksum`. The section exists exactly when the version is 3 and
the phase is decode or integrity drain. Version 1 remains the framing-only
format and carries no section. Version 2 is unsupported; discard that
reconstructible state and restart from the immutable source. Every earlier
field keeps the §4.1 v1 layout except for the additional phase value. A version-3
envelope has no separate integrity frontier and uses the exact-boundary core
cursor described below. Its `verified_pack_trailer` remains zero until final
integrity acceptance.

```text
objects:page_commitment,     count:u64     kind byte MUST be 0
ordinals:page_commitment,    count:u64     kind byte MUST be 5
occurrences:page_commitment, count:u64     kind byte MUST be 1
dependencies:page_commitment,count:u64     kind byte MUST be 2
referenced:page_commitment,  count:u64     kind byte MUST be 0
heads:page_commitment,       count:u64     kind byte MUST be 4
delta_entries:u64
decoded:u64
edges:u64
external_lookups:u64
signature_failure:optional(object_id[32], ordinal:u64)
deferred_refusal:optional(
  code:u8,
  ordinal:optional(u64), offset:optional(u64),
  detail:u8,                     0 none; 1 followed by expected:u64, actual:u64
)
```

Each index entry is the 49-byte root commitment followed by the committed
record count. `signature_failure` is a two-field optional value: `0` absent,
`1` present with an object id and the owning occurrence ordinal; any other
tag is invalid.

The deferred refusal occupies at most 37 bytes, including its presence tag.
It records exactly one refusal, selected in wire order. Its code byte uses
this fixed checkpoint-local table; these tags do not replace public refusal
codes:

| Tag | Code | Tag | Code |
|---|---|---|---|
| 0 | UnexpectedEof | 10 | DecompressionLimitExceeded |
| 1 | InvalidEntryType | 11 | InvalidDelta |
| 2 | TooManyObjects | 12 | DeltaBaseMismatch |
| 3 | PackfileTooLarge | 13 | DeltaSizeMismatch |
| 4 | ZstdEntryTruncated | 14 | NonCanonicalObject |
| 5 | DeltaEntryTruncated | 15 | ObjectHashMismatch |
| 6 | NonStorableObject | 16 | DeltaChainTooDeep |
| 7 | TrailingData | 17 | ExternalBaseAbsent |
| 8 | DecompressionFailed | 18 | ResourceLimit |
| 9 | DecompressedSizeMismatch | 19 | UnsupportedCapability |

Unknown code, optional, or detail tags are invalid. A present offset MUST NOT
exceed source length, and a present ordinal MUST NOT exceed consumed entries.
The refusal exists exactly in integrity-drain phase. Unavailable acquisition
and invalid responses MUST NOT be encoded as deferred content verdicts.

Consistency rules for decode phase, all of which resume MUST check before progress:

- `occurrences.count = consumed_entries`; every consumed wire entry owns
  exactly one occurrence record.
- `objects.count = ordinals.count`; only first occurrences add object and
  ordinal records.
- `ordinals.count <= consumed_entries`, `heads.count <= ordinals.count`,
  `delta_entries <= consumed_entries`, and
  `dependencies.count <= edges + external_lookups`.
- `decoded` fits both the encoded execution limits and the encoded content
  profile; `edges` and `external_lookups` fit the encoded execution limits.
- A present `signature_failure` ordinal is below `consumed_entries`.
- Every committed page commitment names a canonical page within the encoded
  page-byte and fan-out ceilings.

For either verification phase, cumulative performed work plus three times the
unacquired source length MUST fit the encoded work ceiling. Resume MUST
protect that remaining integrity allowance before charging provisional work.
The allowance is derived from the exact cursor’s acquired end and is not
performed work or a separate encoded field.

Cold verify resume re-authenticates every committed evidence page through
caller-supplied page requests before continuing; a lost page is unavailable
input, never absence. The retained set is not serialized into the envelope
beyond its root commitments. A checkpoint exists only at a drained entry
boundary where every buffered record sits under its sequence root and the host
holds every page the roots reach; a machine MAY defer that work until a
checkpoint is requested. A run that declares it will never resume MAY refuse
checkpoints and need not hand the host any page it did not evict.

Integrity-drain phase cannot produce an acceptance artifact or resume entry
decoding. Committed occurrence, object, ordinal, head, and delta counts MUST
NOT exceed consumed entries; dependency and byte counters keep their bounds
above. The last completed entry boundary can precede the deferred refusal.
Resumption continues hashing from the saved acquisition frontier and reports
the deferred refusal only after final integrity succeeds. Those roots remain
inert; the drain does not require an evidence audit to refuse the pack.

The exact-boundary core cursor uses version 2. It stores explicit BLAKE3
subtree chaining values for the trailer and whole-pack streams through the
end of the acquired window, the logical entry boundary, that acquired end,
the collected trailer bytes, an integrity-only flag, and an optional BLAKE3
commitment to the remaining window suffix. Decode resume requests the suffix
starting exactly at the entry boundary, authenticates it against that
commitment, and does not absorb it into the hash frontiers again. Drain resume
starts at the acquired end. The cursor remains bounded by 4096 bytes; no
opaque hasher or decoder state enters its encoding.

The framing driver’s separate integrity frontier represents completed 8 MiB
subtrees. Its nonfinal acquired offset MUST lie on a subtree boundary. Sources
no larger than 8 MiB have no stored chaining values in that frontier; their
incomplete hash work is replayed. The exact-boundary verification cursor instead
uses the acquisition-window geometry, including windows smaller than 8 MiB. A root exists
exactly when its stream is complete. The trailer stream covers source length
minus 32 bytes. Unused bytes of the partial trailer MUST be zero.

#### 4.1.2 Caller-owned computation

Compute descriptors and outputs are process-local execution state, not encoded
checkpoint or evidence records. An implementation exposing such jobs MUST bind
them to the source, run generation, frame ordinal and placement, operation,
input commitments, and resource permits. It MUST merge completed work in the
same verification order regardless of worker completion order. Stale
completions MUST NOT advance a resumed run or change its charged counters.

A checkpoint MUST NOT capture outstanding compute work, completed outputs that
have not merged, or a read-ahead frame beyond its committed ordinal. The host
retires old jobs before replacing their resource envelope. A fresh generation
prevents stale acceptance; it does not reclaim caller-owned worker memory.
These requirements add no encoded fields or format version.

A checkpoint MAY retain a fully committed prefix while later jobs remain
outstanding in the current process. Such a snapshot MUST exclude those jobs
and their entry evidence. Resuming it under a fresh generation replays only the
uncommitted entries and retains the host's worker-retirement obligation.

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

### 4.3 All-entry verify evidence

**Protocol requirement.**

The all-entry verify driver commits five ordered sequences and one keyed
index. Ordered sequences use the ordinal key of §2; the object index and the
referenced-object index use type-dependent object ids as keys. Every record
begins with `record_version:u8 = 1`; any other version is invalid. Numeric
fields are little-endian. A `kind` byte names a SPEC-OBJECTS type: 1 blob,
2 tree, 3 commit, 4 remix, 5 chunked_blob, 7 tag. A boolean byte is `0` or
`1`; any other value is invalid. `signature` is `0` none, `1` valid,
`2` invalid; `domain` is `0` none, `1` commit, `2` remix, `3` tag. `domain`
MUST equal the signing domain implied by `kind` — commit→`1`, remix→`2`,
tag→`3`, every other kind→`0` — and domain `none` and signature `none` agree
exactly: a record with one set and not the other is invalid. Unsigned
records carry all-zero `signer` and `signing_digest`; any nonzero value
under signature `none` is invalid.

Ordered sequences grow one leaf at a time: a leaf holds 16 records before the
next begins, and every internal split lands where appending the records singly
would put it. A sequence root therefore depends only on the record stream and
never on how appends were batched, flushed, or interleaved with checkpoints.
The object and referenced indexes split an overfull leaf evenly.

The **object record** (120 bytes, kind `objects`) is written once per
distinct object, at its first wire occurrence:

```text
record_version:u8        1
kind:u8
canonical_len:u64
first_ordinal:u64
delta_depth:u32
signature:u8
domain:u8
signer[32]
signing_digest[32]
dep_start:u64            first dependency-sequence ordinal this object owns
dep_count:u64
chunk_total:u64          chunked_blob payload length, else 0
chunk_count:u64          chunked_blob chunk count, else 0
```

`chunk_total` and `chunk_count` are nonzero only when `kind` is
`chunked_blob`; they summarize the chunked manifest for consumers that
cannot re-read canonical bytes. `dep_start`/`dep_count` delimit the
object's slice of the dependency sequence.

The **occurrence record** (179 bytes, kind `occurrences`) is written once
per wire entry, in wire order:

```text
record_version:u8        1
object[32]
kind:u8
canonical_len:u64
frame_offset:u64
frame_len:u64
wire_type:u8             pack frame type (SPEC-PACKFILE §3)
from_delta:u8            boolean
delta_base[32]           all-zero when from_delta is 0
delta_depth:u32
signature:u8
first:u8                 boolean; the owning occurrence that wrote the
                         object record
domain:u8
signer[32]
signing_digest[32]
ext_start:u64            first external-fact ordinal this occurrence owns
ext_count:u64
```

The **ordinal record** (42 bytes, kind `ordinals`) enumerates the distinct
object set in first-occurrence order for positional lookup; its sequence
position is the object's first-occurrence rank, not a wire ordinal (the
occurrence record already maps wire ordinal to object):

```text
record_version:u8        1
object[32]
kind:u8
canonical_len:u64
```

The **head record** (99 bytes, kind `heads`) is one immutable head-candidate
fact: an object never named as another object's edge target. Whether a
candidate kind is an allowed head is a closure decision, not a verify one.

```text
record_version:u8        1
object[32]
kind:u8
occurrence_ordinal:u64   owning wire occurrence
page:page_commitment     object-index leaf holding the object record
ordinal_in_page:u64      record position within that leaf
```

The `page` commitment's kind byte MUST be `0` (objects). With the verified
object-set root, `page` plus `ordinal_in_page` completes an authenticated
object-record lookup.

The **dependency record** (kind `dependencies`) has two tagged layouts.
Tag `1` is an object edge (93 bytes):

```text
record_version:u8        1
tag:u8                   1
subject[32]              referencing object id
subject_ordinal:u64      subject's first-occurrence ordinal
target[32]
edge_kind:u8             0 tree-entry, 1 tree, 2 parent, 3 chunk, 4 tag-target
edge_ordinal:u64         edge position within the subject
flags:u8                 bit0 expected_kind present, bit1 expected_len present;
                         other bits invalid
expected_kind:u8         kind byte, or 0 when bit0 clear
expected_len:u64         or 0 when bit1 clear
```

Tag `2` is an external delta-base fact (289 bytes):

```text
record_version:u8        1
tag:u8                   2
consumed_ordinal:u64     wire ordinal of the delta entry that consumed it
child[32]                object the consuming entry produced
repository[32]
incarnation[32]
object[32]
kind:u8
canonical_len:u64
supplier_id[32]          supplier pack identity
supplier_len:u64
supplier_binding[32]
canonical_binding[32]
revision[32]             membership observation revision
delta_depth:u32          supplier-reported base depth
published:u8             boolean
held:u8                  boolean
```

External facts are repository-scoped verified-member answers the caller
supplied during verification; recording them binds the evidence to the exact
repository, incarnation, supplier, and observation revision used. A
verification that consumed no external base commits no tag-2 record, and
the `dep_start`/`dep_count` + `ext_start`/`ext_count` spans let a consumer
attribute every dependency record to its owning object or occurrence without
rescanning the sequence.

## 5. Version history

| Format | Version | Policy |
|---|---|---|
| Page | 1 | Initial source-bound canonical page envelope; kinds 4–5 added with verify. |
| Proof | 1 | Exact routed root-to-leaf page path. |
| Frame record | 1 | Ordered framing-only retention chain. |
| Checkpoint | 1, 3 | Framing uses 1; one-pass verification uses 3 with exact-boundary hashing and deferred refusal; its usage counts the pages the host holds. Version 2 is unsupported; restart. |
| Verify records | 1 | All-entry object, occurrence, ordinal, head, and dependency evidence. |

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
| Checkpoints reference acknowledged retained state | Retention backpressure and checkpoint boundary (§3, §4.1). |
| A host never loses a page its latest checkpoint reaches | Release deferred until the next checkpoint exists (§3). |
| Sequence roots are independent of flush timing | Full-first leaf packing (§4.3). |
| Restart cannot reset cumulative execution charges | Bound counters and replay accounting (§4). |
| Unsupported disposable formats never guess compatibility | Strict refusal and restart (§1). |
