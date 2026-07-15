---
spec: SPEC-PACKFILE
version: 2
status: stable
audience: implementers of compatible packfile readers and writers; transport implementers
---

# SPEC-PACKFILE &mdash; mkit packfile format (v1 + v2)

Status: **Normative** for mkit v1 and v2.
Scope: the byte layout of a `.mkit`-produced packfile, used for
transport upload/download and for bundle exchange.

Resolves red-team R-05 (no spec at all) and R-06 (magic rename risk).
Version 2 (§3.3, §3.4) adds per-entry zstd compression (issue #646);
it does not change header framing, caps, ordering, or trailer
semantics from v1 &mdash; only two new entry types.

---

## 1. High-level layout

```
offset  size          field
0       4             magic               "MKIT"   (0x4D 0x4B 0x49 0x54)
4       4             version             u32 LE, == 1 or 2
8       4             entry_count         u32 LE
12      …             entries             entry_count entries
…       32            trailer             BLAKE3(all preceding bytes)
```

The **trailer** is computed over bytes `[0 .. trailer_offset)` &mdash; that is,
everything written before the trailer itself. It is not a signature.
Its purpose is defense-in-depth against bit-rot on transports that do
not guarantee byte-exact delivery (for example S3 after a proxy).

The first four bytes MUST be the ASCII literal `"MKIT"`. Any reader
encountering something else MUST fail with `InvalidMagic`.

**Version byte rule:** the first four bytes MUST remain `"MKIT"` in
every future version. Format evolution is signaled by the `version`
field. A reader seeing `"MKIT"` plus unknown version MUST fail
`UnsupportedPackVersion` (not `InvalidMagic`), so clients can
distinguish "wrong tool" from "too-new pack".

**Writer version-selection rule (v2):** `PackWriter` decides `version`
per pack, not per build. It emits `version = 1` when the finished pack
contains zero compressed entries (`0x03`/`0x04`), and `version = 2`
when it contains at least one &mdash; even if the pack is otherwise a mix of
compressed and uncompressed entries. This is the simplest correct
rule: a v1-capable reader can consume any pack that doesn't actually
use the v2-only entry types, and any pack that does is unambiguously
flagged v2 so an old reader fails closed (`UnsupportedPackVersion`)
instead of misinterpreting a `0x03`/`0x04` payload as something else.
Callers never choose the version explicitly; it falls out of whether
any pushed entry ended up compressed under the policy in §3.3.

---

## 2. Entry framing

Each entry:

```
[u8 entry_type]
[u32 LE payload_len]                         0 .. 2^31 - 1
[payload_len bytes payload]                  type-specific, see §3
```

`payload_len` is the length of the payload only; it excludes the
1-byte `entry_type` and the 4-byte length field itself. Readers MUST
bounds-check every `payload_len` against the remaining packfile tail
(before the trailer) to avoid buffer over-read.

---

## 3. Entry types

```
0x00    raw          payload = serialized mkit object (see SPEC-OBJECTS)
0x02    delta        payload = [32 base_hash] [instructions]  (see SPEC-DELTA)
0x03    zstd-raw     v2 only. payload = [4 uncompressed_len][zstd frame]
0x04    zstd-delta   v2 only. payload = [32 base_hash][4 uncompressed_len][zstd frame]
```

Notes:

- `0x01` is **reserved** and MUST NOT be emitted by any writer. Readers
  MUST reject it with `InvalidEntryType`.
- `0x03` and `0x04` are legal ONLY inside a `version = 2` pack. A
  reader encountering `0x03`/`0x04` inside a `version = 1`-declared
  pack MUST reject it with `InvalidEntryType` &mdash; it is exactly as
  invalid there as any other unrecognized type, not silently accepted
  or reinterpreted. (§9 note: this is a stricter-than-strictly-necessary
  rule &mdash; nothing about the byte layout of `0x03`/`0x04` depends on the
  header version &mdash; but pinning entry-type legality to the declared
  version keeps "which entry types can appear here" a single,
  header-derived fact instead of something a reader has to discover
  per-entry.)
- Any other value → `InvalidEntryType`.

### 3.1 `raw` (0x00)

Payload is exactly the bytes you would get from SPEC-OBJECTS
serialization, starting with the object prologue. Unpackers insert
these bytes into the object store verbatim (writing
`.mkit/objects/<dd>/<rr...>`) after verifying the object's id &mdash; computed
per the type-dependent rule in SPEC-OBJECTS §10 (a flat BLAKE3 digest of
the serialized bytes for most object types; the domain-wrapped Merkle
root of SPEC-MERKLE-OBJECTS for `Tree` and `ChunkedBlob`) &mdash; matches the
expected storage path. It is never simply `BLAKE3(bytes)` for every
type.

### 3.2 `delta` (0x02)

Payload:

```
[32 bytes base_hash]
[all remaining payload bytes = SPEC-DELTA stream]
```

`base_hash` MUST be reachable at delta-resolution time: either as a
previous `raw` entry in the same pack or already present in the
destination object store. If unresolvable → `DeltaBaseMissing`.

Delta payloads reconstruct a full serialized object (with its
SPEC-OBJECTS prologue). The reconstructed bytes are then run through
the same type-dependent id rule as a `raw` entry (SPEC-OBJECTS §10 /
SPEC-MERKLE-OBJECTS) to produce the object's storage path &mdash; never a
flat `BLAKE3(bytes)` for a reconstructed `Tree` or `ChunkedBlob`.

Readers MUST validate every `raw` payload and every reconstructed delta
target as a canonical SPEC-OBJECTS object before storing it. Payloads
that fail object deserialization, or deserialize as pack-only
`Object::Delta`, are rejected and MUST NOT be written to the object
store.

### 3.3 `zstd-raw` (0x03, v2 only)

Payload:

```
[4 bytes uncompressed_len]     u32 LE
[remaining payload bytes]      one zstd frame
```

Decompressing the zstd frame MUST yield exactly `uncompressed_len`
bytes, and those bytes are byte-for-byte what a `0x00 raw` entry's
payload would be for the same object &mdash; a fully serialized SPEC-OBJECTS
object, prologue included. A `0x03` entry is otherwise handled
identically to `0x00`: the decompressed bytes are validated as a
canonical storable object and hashed to produce the storage path.

**Compression is per-entry, not whole-pack.** Each `0x03`/`0x04`
entry carries its own independent zstd frame; there is no shared
dictionary and no whole-pack compression stream. This keeps every
other section of this spec (§2 framing, §5 caps, §6 parsing model, §8
trailer) unchanged &mdash; a reader can still bounds-check, cap, and hash
the pack exactly as before, treating each entry's payload as an
opaque, independently-sized blob. It also bounds decompression memory
to one entry at a time regardless of pack size.

**Writer compression policy.** A writer MAY choose not to compress at
all (an all-`0x00`/`0x02` pack is always valid, and stays `version =
1`, see §1). When a writer does apply compression, this spec pins the
decision rule so independent implementations produce comparable
packs: compress a candidate payload of `raw_len` bytes only when
`raw_len >= 64` (skip tiny payloads &mdash; compression's per-entry framing
overhead and CPU cost isn't worth it below this) **and** `4 +
zstd_compressed_len < raw_len` (strictly smaller on the wire than
sending it uncompressed &mdash; the same "strictly smaller or don't bother"
posture as the delta-preference heuristic in §3, mirrored here for
consistency). mkit's own writer uses zstd compression level 3 (the
library default); this spec does not mandate a specific level, since
the byte layout is level-independent &mdash; any level a compliant zstd
decoder can read is valid.

**Decoder bomb-guarding is normative, not a suggestion.** Before
allocating a decompression buffer, a reader MUST check the claimed
`uncompressed_len` against the object-store size cap
(`mkit_core::store::MAX_RAW_OBJECT_SIZE`, 1 GiB) and reject
oversized claims before allocating anything for them. Decompression
MUST then be bounded to at most `uncompressed_len` bytes (for example via a
capacity-bounded decompress call, not an unbounded stream copy) so a
truncated `uncompressed_len` claim can't be used to force an
over-large allocation. After decompression, the reader MUST compare
the actual decompressed byte count against the claimed
`uncompressed_len` and reject on any mismatch (too few bytes &mdash; a
truncated/short frame &mdash; or too many). A pack that fails either check
MUST NOT have any of its entries written to the object store, exactly
like any other rejected pack (§6, §8).

### 3.4 `zstd-delta` (0x04, v2 only)

Payload:

```
[32 bytes base_hash]           UNCOMPRESSED
[4 bytes uncompressed_len]     u32 LE
[remaining payload bytes]      one zstd frame
```

`base_hash` is identical in placement and semantics to `0x02`'s
`base_hash` (§3.2) and is deliberately left **uncompressed** &mdash; a
reader resolving delta-base ordering (§4) or pre-fetching bases
(`delta_base_hashes`-style scans) never needs to decompress an entry
just to discover which object it depends on.

Decompressing the zstd frame MUST yield exactly `uncompressed_len`
bytes, and those bytes are byte-for-byte what a `0x02` entry's payload
would be *after* its 32-byte `base_hash` prefix &mdash; that is, a SPEC-DELTA
stream (SPEC-DELTA). Once decompressed, a `0x04` entry is handled
identically to `0x02`: the same base-resolution rule (§4), the same
`DeltaBaseMissing` failure mode, and the same reconstruct-then-hash
storage path.

The writer compression policy and decoder bomb-guarding rules in §3.3
apply here identically, with one adjustment: the payload being
measured/compressed for the `raw_len >= 64`/`4 +
zstd_compressed_len < raw_len` decision is the delta **stream only**
(post-`base_hash`), matching what §3.3 says about the reconstructed
`0x02` payload &mdash; `base_hash` is never a candidate for compression
since it is fixed-size, already-random-looking (a BLAKE3 digest), and
needed uncompressed for cheap base discovery.

Writers MAY emit all-`raw` packs for simplicity; readers MUST handle
both mixes. `PackWriter`'s raw-vs-delta choice is policy-free at the
writer level &mdash; it accepts whatever entries the caller pushes and does
not itself decide raw vs. delta. That choice lives in callers above
the writer: mkit's own transfer-planning path (`transfer.rs`'s
`try_delta`) already ships a "prefer delta when it is strictly smaller
on the wire than raw" gate (`HASH_LEN + delta_stream.len() <
target_bytes.len()`), so &mdash; correcting an earlier draft of this
section &mdash; that heuristic is not purely hypothetical future work; it is
live, informative (not normative) caller policy today. A future
revision MAY promote it to a normative rule; this document does not
pin its exact thresholds since a conforming writer is free to use a
different one, or none, and still produce a valid pack.

Compression (§3.3, §3.4), by contrast, IS writer-internal as of v2:
`PackWriter::push_raw`/`push_delta` decide per-entry whether to emit
the compressed or uncompressed variant, per the fixed rule in §3.3.
Callers do not choose compression per entry the way they choose
delta-vs-raw.

---

## 4. Ordering rule

Base objects MUST precede their deltas. Specifically, for any
`0x02 delta` or `0x04 zstd-delta` entry with `base_hash = H` (§3.4's
`base_hash` field is uncompressed precisely so this rule never
requires decompressing anything to evaluate), at least one of:

1. An earlier entry in the same pack whose computed hash is `H`, or
2. An object already present at path `objects/<H>` in the destination
   store at unpack time.

Must hold. Readers MUST NOT buffer undefined delta chains.

Writers SHOULD emit non-blob objects first (commits, trees,
chunked_blob, remix), then base blobs, then delta blobs. This lets a
streaming reader complete without buffering.

---

## 5. Size limits

Normative, for both v1 and v2 packs:

- `entry_count <= 10_000_000`.
- Sum of all `payload_len` <= **4 GiB**.
- Single entry `payload_len` must fit in a `u32` (≤ ~4 GiB).

These are policy caps, not wire limits. Implementations MUST fail with
`TooManyObjects`/`PackfileTooLarge` on violation rather than
silently truncating.

**These caps are measured on the wire (compressed) size.** For a
`0x03`/`0x04` entry, `payload_len` is the on-wire length &mdash; the
`uncompressed_len` prefix plus the zstd frame &mdash; exactly as framed in
§2, not the decompressed size. §3.3's separate `MAX_RAW_OBJECT_SIZE`
(1 GiB) check applies only to the *decompressed* side and is enforced
independently at decode time; it is not folded into `MAX_TOTAL_PAYLOAD`
or `entry_count`.

**The per-pack cap is a format choice, not a transport ceiling.**
Earlier versions of this section justified the 4 GiB figure by AWS
S3/Cloudflare R2's 5 GiB single-`PUT` limit, and flagged multipart
upload as a future-version candidate (red-team R-14). That framing is
stale: S3/R2 multipart upload (issue #704) shipped without a `version`
bump, because it turned out to be a purely transport-layer concern
&mdash; `CreateMultipartUpload`/`UploadPart` against each backend's own
single-`PUT` ceiling, resolved entirely inside the transport
implementations, never touching this spec. The 4 GiB figure is simply
the bound this version chose to keep pack construction and
verification bounded in memory and time; it is not derived from, and
no longer needs to track, any transport's own object-size limits.

**A push whose payload exceeds one pack's cap is not blocked &mdash; it
splits.** `remote_dispatch::build_and_upload_packs` (issue #831) seals
and uploads a new pack the moment the next entry would exceed the cap,
chaining every pack one push produced onto a single packlist node
(`PackListNode.packs: Vec<Hash>`, in apply/build order &mdash; see the
packlist/packmap chain documentation in `mkit_core::transfer`). The
fetch side needs no pack-count-specific handling: it already resolves
and unpacks every pack a node lists, in order, whether that's one pack
or several. A push whose plan fits in one pack &mdash; the overwhelming
common case &mdash; is completely unaffected.

**Known future relaxations** (not part of v1 or v2): a streaming pack
format that doesn't require `entry_count` or trailer position known in
advance, and removal of the 10M entry count. Each requires a `version`
bump.

---

## 6. Parsing model

mkit packfiles (v1 and v2 alike) are **buffered**, not streamed. The
reader reads the entire packfile into memory and then walks entries.
This is a deliberate simplification. Consequences:

- Memory = packfile size (4 GiB worst-case on the wire; per-entry
  decompression of a `0x03`/`0x04` entry adds at most one
  `MAX_RAW_OBJECT_SIZE` (1 GiB) buffer at a time &mdash; see §3.3).
- Random access to entries is O(n) scan since no entry index exists.

A future version may add a trailing index; neither v1 nor v2 does.

Readers MUST reject any bytes between the end of the declared entry list
and the 32-byte trailer. A pack with trailing data is malformed even if
the trailer hashes those extra bytes correctly.

---

## 7. Transport key layout

For all object-storage transports (S3, HTTP, file), packfile objects
are stored under the fixed key:

```
packs/<64-char-hex-of-BLAKE3(pack_bytes)>    — 70 bytes total
```

Writers and readers MUST use this exact layout. Lowercase hex only;
comparison is byte-exact.

The digest that names the pack is computed over the *entire packfile*
including the 32-byte trailer. This is slightly redundant (trailer
covers pack, digest covers trailer-covered bytes) but it means
`upload_pack` callers can pass the same `digest` they used to compute
the trailer.

---

## 8. Trailer computation detail

Let `P` be the packfile bytes from offset 0 through
`trailer_offset = len(packfile) - 32`. The trailer is
`BLAKE3(P)` written as 32 raw bytes, NOT hex.

Readers MUST:

1. Verify `len(packfile) >= 12 + 32 = 44`. (Minimum: header + empty
   entries + trailer.)
2. Slice `trailer = packfile[len-32 ..]`.
3. Compute `BLAKE3(packfile[0 .. len-32])`.
4. Compare byte-equal. Mismatch → `PackfileCorrupted`.

Step 3 MUST happen before any entry is stored to the destination.

Implementation note: the mkit-core `PackWriter::finish` writes the
trailer over `header + entries`, and `PackReader::read` verifies it
before touching the store (`pack.rs::PackReader::read` step 4, which
runs after the magic+version checks but before any entry framing is
parsed). The check ordering means a corrupt trailer surfaces as
`PackfileCorrupted` even when later entry framing is also malformed.

---

## 9. Backward compatibility rule

mkit v1 is the first version. The format rule going forward is:

- First 4 bytes MUST be ASCII `"MKIT"`. Forever. (The magic is the
  format family marker, not a version marker.)
- Format changes MUST bump the `version` u32.
- `version` values are monotonically assigned; gaps are allowed but
  reservations SHOULD be documented here before use.
- Reserved version codes:
  - `0` &mdash; never emitted; reserved to distinguish "all-zero buffer" from
    a real pack.
  - `2` &mdash; **consumed.** Per-entry zstd compression, `0x03`/`0x04`
    entry types (§3.3, §3.4; issue #646). A pre-v2 reader that has not
    taken this spec revision correctly fails closed on a `version = 2`
    header with `UnsupportedPackVersion` &mdash; it does not attempt to
    parse `0x03`/`0x04` entries it doesn't know about. That IS the
    intended behavior, not a bug to work around: v2 packs are only
    exchanged between peers that both understand them (for example after a
    capability negotiation at a higher layer), and there is
    deliberately no graceful degradation path in-band.
  - `3`, `4` &mdash; still reserved for future format work (streaming index,
    multipart, etc.).

---

## 10. Test vectors

The conformance vectors below are exercised in
`rust/crates/mkit-core/tests/golden_pack.rs` and the unit tests in
`rust/crates/mkit-core/src/pack.rs::tests`. They are inline byte pins
rather than on-disk goldens, so any framing drift fails the test suite
immediately. Reader-error vectors map to `PackError` variants on the
Rust API surface; the spec-level names below stay protocol-neutral.

1. **Empty pack**: header, `entry_count=0`, and trailer. Length
   = 12 + 32 = 44 bytes. Pinned by `empty_pack_pin_bytes` and
   `empty_pack_is_44_bytes`.
2. **Single-raw pack**: a `Blob{ data: b"hi" }` round-trips through
   `PackWriter` + `PackReader`; pinned by `pack_basic_pin_bytes_roundtrip`.
3. **Two-entry pack with delta**: raw base blob + delta entry resolving
   in the same pack. Covered by `raw_then_delta_resolves_in_pack`.
4. **Pack with non-`MKIT` magic** → reader returns `InvalidMagic`
   (`rejects_invalid_magic`).
5. **Pack with version = 99** → reader returns `UnsupportedVersion(99)`
   (`rejects_unknown_version`). The Rust API spells the error
   `UnsupportedVersion`; the SPEC-level name `UnsupportedPackVersion`
   refers to the same condition.
6. **Bit-flipped trailer** → `PackfileCorrupted`
   (`rejects_bit_flipped_trailer`).
7. **Delta entry referring to unknown base** → `DeltaBaseMissing`
   (`delta_base_missing_is_loud`). Also covers the "resolve base
   from the destination object store" path (`delta_resolves_against_pre_existing_store_object`).
8. **Pack exceeding 4 GiB payload sum** → `PackfileTooLarge` emitted
   during parse, before any entry is stored. Enforced by
   `PackWriter::check_caps_for` and re-checked in `PackReader::read`
   while walking entries.
9. **Entry with `payload_len` pointing past trailer** → `UnexpectedEof`
   (`entry_payload_past_trailer_rejected`).
10. **Reserved entry type 0x01** → `InvalidEntryType(0x01)`
    (`rejects_reserved_entry_type_0x01`).
11. **`entry_count` over the 10M cap** → `TooManyObjects`
    (`entry_count_over_cap_rejected`).
12. **Pack key**: `pack_key(pack_bytes)` equals `BLAKE3(pack_bytes)`
    over the whole pack including the trailer
    (`pack_key_is_blake3_of_pack_bytes`).
13. **Minimal v2 pack, compressed-raw entry**: a highly-compressible
    synthetic object pushed with compression on ends up as a `0x03`
    entry, the pack header reads `version = 2`, and `PackReader::read`
    recovers byte-identical original content. Pinned by
    `compressed_raw_entry_roundtrips` (`pack.rs::tests`) and the
    golden byte-layout pin
    `pack_v2_compressed_raw_pin_bytes_roundtrip` (`golden_pack.rs`).
14. **Minimal v2 pack, compressed-delta entry**: same shape as #13 for
    a `0x04` entry &mdash; raw base plus delta stream compressed against a
    highly-compressible target. Pinned by
    `compressed_delta_entry_roundtrips` and
    `pack_v2_compressed_delta_pin_bytes_roundtrip`.
15. **`0x03`/`0x04` entry inside a `version = 1`-declared pack** →
    `InvalidEntryType` (`rejects_v2_entry_type_in_v1_pack`) &mdash; the
    entry-type/version legality rule in §3 is enforced, not just
    documented.
16. **Tampered zstd frame decompressing to the wrong length** →
    `DecompressedSizeMismatch` (`rejects_decompressed_len_mismatch`).
17. **`uncompressed_len` claim exceeding `MAX_RAW_OBJECT_SIZE`** →
    rejected before any decompression allocation
    (`rejects_decompressed_len_over_object_cap`).
18. **Pre-existing v1 golden vectors decode unchanged** after the v2
    writer/reader changes &mdash; `v1_pack_still_reads_bit_identical`
    re-runs vectors #1–#12 above and asserts byte-identical output,
    the no-regression guardrail for the format this revision does not
    otherwise touch.

---

## 11. Streaming hook (informative)

Implementations MAY provide a streaming unpack API that yields each
entry as it is parsed, for callers that want to pipe entries into a
content-addressable store without buffering. v1 does not require this.
Streaming implementations MUST still verify the trailer at end-of-stream
and retroactively reject partially-stored objects if trailer
verification fails.

---

## 12. Invariants

| Invariant | Enforced by |
|---|---|
| A pack is unambiguously an mkit pack of a known version | `"MKIT"` magic → `InvalidMagic`; unknown `version` → `UnsupportedPackVersion`, distinguishably (§1) |
| Any bit-flip or truncation before the trailer is detected | 32-byte BLAKE3 trailer, verified **before** any entry is stored (§8) |
| No entry read past the pack tail | mandatory `payload_len` bounds-check against the remaining pre-trailer bytes → `UnexpectedEof` (§2) |
| Only known entry types are processed | anything but `0x00`/`0x02`/`0x03`/`0x04` (incl. reserved `0x01`) → `InvalidEntryType`; `0x03`/`0x04` additionally require `version = 2` or the same error fires (§3) |
| Every stored object's bytes match its storage path | id computed via the type-dependent rule (SPEC-OBJECTS §10 / SPEC-MERKLE-OBJECTS) and verified before writing `objects/<dd>/<rr…>`; delta targets reconstructed (decompressed first, for `0x03`/`0x04`), then run through the same rule (§3.1–§3.4) |
| No malformed or pack-only object reaches the object store | canonical SPEC-OBJECTS deserialization gate; `Object::Delta` payloads rejected (§3) |
| Every delta is resolvable when encountered | ordering rule: base precedes its delta in-pack or pre-exists in the store; else `DeltaBaseMissing`; no buffering of undefined chains; `0x04`'s uncompressed `base_hash` needs no decompression to check (§4) |
| Resource use is bounded on the wire | `entry_count ≤ 10M` → `TooManyObjects`; payload sum ≤ 4 GiB → `PackfileTooLarge`, never silent truncation (§5) |
| Resource use is bounded on decompression | claimed `uncompressed_len` checked against `MAX_RAW_OBJECT_SIZE` (1 GiB) before any decompression allocation; decompression capacity-bounded to the claim; actual decompressed length re-checked against the claim exactly → `DecompressedSizeOverCap`/`DecompressedSizeMismatch` (§3.3) |
| No hidden trailing data | bytes between the entry list and the trailer are rejected even if the trailer hashes them (§6) |
| Pack identity is deterministic and byte-exact | key = lowercase hex `BLAKE3(pack_bytes)` over the whole pack including the trailer; byte-exact comparison (§7) |
| Streaming unpack cannot leave corrupt state | trailer verified at end-of-stream; partially-stored objects retroactively rejected (§11) |
| A `version = 1` pack decodes identically whether or not the reader understands v2 | `0x03`/`0x04` are illegal under `version = 1`; a v1 pack contains only entry types every reader has always understood (§1, §3, §9) |

The trailer detects accidental corruption; it is not a signature (§1).
Authenticity rests on the caller-supplied content address (§7) and the
per-object hash verification of §3.
