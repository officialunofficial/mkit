---
spec: SPEC-PACKFILE
version: 1
status: stable
audience: implementers of compatible packfile readers and writers; transport implementers
---

# SPEC-PACKFILE — mkit v1 packfile format

Status: **Normative** for mkit v1.
Scope: the byte layout of a `.mkit`-produced packfile, used for
transport upload/download and for bundle exchange.

Resolves red-team R-05 (no spec at all) and R-06 (magic rename risk).

---

## 1. High-level layout

```
offset  size          field
0       4             magic               "MKIT"   (0x4D 0x4B 0x49 0x54)
4       4             version             u32 LE, == 1
8       4             entry_count         u32 LE
12      …             entries             entry_count entries
…       32            trailer             BLAKE3(all preceding bytes)
```

The **trailer** is computed over bytes `[0 .. trailer_offset)` — i.e.
everything written before the trailer itself. It is not a signature.
Its purpose is defense-in-depth against bit-rot on transports that do
not guarantee byte-exact delivery (e.g. S3 after a proxy).

The first four bytes MUST be the ASCII literal `"MKIT"`. Any reader
encountering something else MUST fail with `InvalidMagic`.

**Version byte rule:** the first four bytes MUST remain `"MKIT"` in
every future version. Format evolution is signalled by the `version`
field. A reader seeing `"MKIT"` + unknown version MUST fail
`UnsupportedPackVersion` (not `InvalidMagic`), so clients can
distinguish "wrong tool" from "too-new pack".

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
0x00    raw       payload = serialised mkit object (see SPEC-OBJECTS)
0x02    delta     payload = [32 base_hash] [instructions]  (see SPEC-DELTA)
```

Notes:

- `0x01` is **reserved** and MUST NOT be emitted by v1 writers. Readers
  MUST reject it with `InvalidEntryType`.
- Any other value → `InvalidEntryType`.

### 3.1 `raw` (0x00)

Payload is exactly the bytes you would get from SPEC-OBJECTS
serialisation, starting with the object prologue. Unpackers insert
these bytes into the object store verbatim (writing
`.mkit/objects/<dd>/<rr...>`) after verifying BLAKE3 matches the
expected storage path.

### 3.2 `delta` (0x02)

Payload:

```
[32 bytes base_hash]
[all remaining payload bytes = SPEC-DELTA stream]
```

`base_hash` MUST be reachable at delta-resolution time: either as a
previous `raw` entry in the same pack or already present in the
destination object store. If unresolvable → `DeltaBaseMissing`.

Delta payloads reconstruct a full serialised object (with its
SPEC-OBJECTS prologue). The reconstructed bytes are then hashed to
produce the object's storage path — the same way a `raw` entry is
stored.

Writers MAY emit all-`raw` packs for simplicity; readers MUST handle
both mixes. mkit v1's `PackWriter` API is policy-free — it accepts
whatever entries the caller pushes and does not itself decide raw
vs. delta. Any "prefer delta when delta is < N% of target" heuristic
lives in callers above the writer (none ship in v1). A future revision
MAY pin such a heuristic normatively; today it is informative.

---

## 4. Ordering rule

Base objects MUST precede their deltas. Specifically, for any
`0x02 delta` entry with `base_hash = H`, at least one of:

1. An earlier entry in the same pack whose computed hash is `H`, or
2. An object already present at path `objects/<H>` in the destination
   store at unpack time.

Must hold. Readers MUST NOT buffer undefined delta chains.

Writers SHOULD emit non-blob objects first (commits, trees,
chunked_blob, remix), then base blobs, then delta blobs. This lets a
streaming reader complete without buffering.

---

## 5. Size limits (v1)

Normative:

- `entry_count <= 10_000_000`.
- Sum of all `payload_len` <= **4 GiB**.
- Single entry `payload_len` must fit in a `u32` (≤ ~4 GiB).

These are policy caps, not wire limits. Implementations MUST fail with
`TooManyObjects` / `PackfileTooLarge` on violation rather than
silently truncating.

**S3 single-PUT limit:** AWS S3 and Cloudflare R2 enforce a 5 GiB single-
object cap; our 4 GiB cap stays under it. Larger packs require
multipart upload, which is a v2 candidate (red-team R-14).

**Known future relaxations** (not part of v1): streaming packs,
multipart upload, removal of the 10M entry count. Each requires a
`version` bump.

---

## 6. Parsing model

mkit v1 packfiles are **buffered**, not streamed. The reader reads the
entire packfile into memory and then walks entries. This is a
deliberate simplification. Consequences:

- Memory = packfile size (4 GiB worst-case).
- Random access to entries is O(n) scan since no entry index exists.

Future v2 may add a trailing index, but v1 does not.

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
- Reserved version codes (v1):
  - `0` — never emitted; reserved to distinguish "all-zero buffer" from
    a real pack.
  - `2`, `3`, `4` — reserved for future format work (streaming index,
    multipart, etc.).

---

## 10. Test vectors

The conformance vectors below are exercised in
`rust/crates/mkit-core/tests/golden_pack.rs` and the unit tests in
`rust/crates/mkit-core/src/pack.rs::tests`. They are inline byte pins
rather than on-disk goldens, so any framing drift fails the test suite
immediately. Reader-error vectors map to `PackError` variants on the
Rust API surface; the spec-level names below stay protocol-neutral.

1. **Empty pack**: header + `entry_count=0` + trailer. Length
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

---

## 11. Streaming hook (informative)

Implementations MAY provide a streaming unpack API that yields each
entry as it is parsed, for callers that want to pipe entries into a
content-addressable store without buffering. v1 does not require this.
Streaming implementations MUST still verify the trailer at end-of-stream
and retroactively reject partially-stored objects if trailer
verification fails.

---

*~1300 words.*
