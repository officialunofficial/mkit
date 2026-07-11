---
spec: SPEC-DELTA
version: 1
status: stable
audience: implementers of compatible packfile readers and writers
---

# SPEC-DELTA — mkit v1 delta instruction format

Status: **Normative** for mkit v1.
Scope: the byte layout of the delta instruction stream referenced by
packfile `0x02 delta` entries (see SPEC-PACKFILE §3.2).

Resolves red-team R-19 (no delta format spec, no version byte).

---

## 1. Framing context

Delta streams appear exclusively inside packfile entries. The
enclosing entry provides:

- `base_hash` (32 bytes) — the BLAKE3 of the full serialised base
  object (including its SPEC-OBJECTS prologue).
- Byte range containing the delta stream.

There is no standalone delta file. There is no per-entry `result_size`
in v1 (the unpacker discovers it from the actual reconstruction). If a
caller needs result-size verification, the outer SPEC-OBJECTS delta
object (§8) supplies a `result_size` field; pack entries do not.

---

## 2. Stream layout

```
[u8 stream_version]     == 0x01
[u32 LE base_len]       length of the base object in bytes
[u32 LE result_len]     expected length of the reconstructed object
[instructions …]        concatenation of opcodes, see §3
```

The `stream_version` byte is required: readers use it to reject any
future format they don't recognise.

Readers MUST reject `stream_version != 0x01` with
`UnsupportedDeltaVersion`. The Rust API surfaces this as
`MkitError::UnsupportedObjectVersion`; the SPEC-level name refers to
the same condition.

`base_len` and `result_len` enable readers to validate the stream
before executing. Writers MUST populate both fields correctly; readers
MUST verify:

- `base_len` equals the actual length of the supplied base buffer
  (the v1 reader rejects mismatches before executing any opcode).
- Every `COPY(offset, length)` satisfies `offset + length <= base_len`.
- The running emitted-byte count NEVER exceeds `result_len` (the v1
  reader enforces this per-opcode, not only at end-of-stream).
- The sum of all emitted bytes equals `result_len` at end-of-stream.

Mismatches yield `DeltaCorrupt`. The Rust implementation collapses
"COPY past base", "reserved bits set", "zero opcode", "zero-length
COPY", "result_len overrun", and "result_len underrun at EOF" into
the single error `MkitError::TrailingData`; matching on the variant
discriminates only "truncated input" (`UnexpectedEof`) from
"structurally corrupt" (`TrailingData`).

---

## 3. Instructions

Two opcodes, distinguished by the top bit of the first byte:

### 3.1 `COPY` — top bit set

```
[u8 opcode]             opcode & 0x80 != 0; remaining 7 bits reserved, MUST be 0 in v1
[u32 LE offset]         offset into base
[u16 LE length]         1 .. 65_535 bytes
```

Total size: 7 bytes. Semantics: append `base[offset .. offset+length]`
to the reconstruction buffer.

`length == 0` is illegal (writers MUST NOT emit, readers MUST reject as
`DeltaCorrupt`).

Currently v1 always emits `opcode == 0x80` with low 7 bits zero. Any
other COPY opcode byte is reserved.

### 3.2 `INSERT` — top bit clear, non-zero length

```
[u8 length]             1 .. 127
[length bytes literal]
```

Total size: `1 + length` bytes. Semantics: append `literal` to the
reconstruction buffer.

`length == 0` (i.e. the opcode byte itself is 0) is illegal and MUST be
rejected with `DeltaCorrupt`. This reserves the all-zero byte sequence,
which is both a robustness check and prevents a trivial stream that
produces empty output.

Long literals are split into multiple INSERTs of up to 127 bytes each.
There is no 2-byte or 4-byte extended INSERT form in v1.

---

## 4. Reconstruction algorithm

Reference implementation (pseudo-code):

```
fn apply(base: &[u8], stream: &[u8]) -> Vec<u8>:
    assert stream[0] == 0x01                    # stream version
    assert len(base) == le_u32(stream[1..5])
    result_len = le_u32(stream[5..9])
    pos = 9
    out = Vec::with_capacity(result_len)
    while pos < len(stream):
        op = stream[pos]; pos += 1
        if op & 0x80 != 0:                      # COPY
            if op & 0x7F != 0: fail DeltaCorrupt  # reserved bits
            if pos + 6 > len(stream): fail UnexpectedEof
            offset = le_u32(stream[pos..pos+4]); pos += 4
            length = le_u16(stream[pos..pos+2]); pos += 2
            if length == 0: fail DeltaCorrupt
            if offset + length > len(base): fail DeltaCorrupt
            if len(out) + length > result_len: fail DeltaCorrupt
            out.extend(base[offset..offset+length])
        elif op > 0:                            # INSERT
            if pos + op > len(stream): fail UnexpectedEof
            if len(out) + op > result_len: fail DeltaCorrupt
            out.extend(stream[pos..pos+op])
            pos += op
        else:
            fail DeltaCorrupt                   # opcode 0x00 reserved
    if len(out) != result_len: fail DeltaCorrupt
    return out
```

Implementation note: the reference decoder also caps its initial
`Vec::with_capacity` against attacker-controlled length fields. The
hint is `min(result_len, stream.len() * 256)`; crucially `base.len()`
does NOT scale the allocation, because a tiny crafted stream pointing
at a huge base would otherwise trip a multi-gigabyte reservation
(see `mkit-core` `delta::compute_cap_hint` and finding G5). This is
implementation guidance, not a wire-format requirement; conformant
decoders are free to size their output buffer however they like
provided behaviour matches the pseudo-code above.

---

## 5. Writing algorithm (informative)

The reference writer uses a 16-byte block hash-table scan over the base,
extends matches greedily, and emits INSERTs for unmatched runs. The
block hash is FNV-1a 64-bit.

This algorithm is not normative. Any writer that produces a stream that
passes the v1 verify rules in §4 is conformant. In particular, a writer
that emits a single all-INSERTs stream (no COPY) is valid (and trivially
correct, just wasteful). A writer that emits only COPY instructions
covering `[0, base_len)` is valid iff `result_len == base_len` and the
reconstructed bytes equal the target.

---

## 6. What the delta stream is NOT

- **Not signed.** The delta bytes are not covered by any commit
  signature. Integrity comes from:
  1. The packfile trailer (SPEC-PACKFILE §8) — end-to-end pack hash.
  2. The reconstructed object's hash matching the path under which it
     is stored in the object store.
  3. The commit signature over the reconstructed tree hash etc.

- **Not independently verifiable.** A delta stream must be paired with
  its declared base. Tamper detection is transitive through the pack
  trailer and the object-store hash check.

- **Not a transport format.** Deltas are only meaningful inside pack
  entries. Any API that returned a raw delta stream would be
  mis-designed; mkit does not expose one.

---

## 7. Size limits

- Stream header: fixed 9 bytes.
- Per-INSERT literal: 1..127 bytes.
- Per-COPY: 7 bytes, `length <= 65_535`.
- Overall stream length: implicit cap equal to the enclosing packfile
  entry's `payload_len - 32` (see SPEC-PACKFILE §3.2). Practical cap
  is the packfile's 4 GiB total.
- `result_len`: any `u32` value, but bounded by SPEC-OBJECTS object
  limits (1 GiB per stored object).

---

## 8. Test vectors

The vectors below are exercised in
`rust/crates/mkit-core/tests/golden_pack.rs` and the unit tests in
`rust/crates/mkit-core/src/delta.rs::tests`. The pinned vectors (2, 3)
are inline byte arrays so any framing drift trips immediately.

1. **Identity delta**: base = 64-byte string of "0123456789abcdef" × 4;
   target = same bytes. Stream round-trips through `decode`
   (`identity_roundtrip`).
2. **Pure INSERT**: base = `"aaa"`, target = `"zzz"`. The 13-byte stream
   `[0x01, 0x03,0x00,0x00,0x00, 0x03,0x00,0x00,0x00, 0x03, 'z','z','z']`
   is pinned by `delta_basic_pin_bytes_and_roundtrip`.
3. **Pure COPY**: base = 16-byte pattern `0..15`, target = base; stream
   = `[ver=1][base_len=16 LE][result_len=16 LE][0x80][0,0,0,0][16,0]`
   (16 bytes total). Pinned by `delta_pure_copy_pin_bytes`.
4. **Mixed near-duplicate**: same-text base + small trailing edit;
   delta MUST be smaller than the target
   (`near_duplicate_yields_smaller_delta`).
5. **Reject 0x00 opcode** → `DeltaCorrupt` / `MkitError::TrailingData`
   (`rejects_zero_opcode`).
6. **Reject COPY past base_len** → `DeltaCorrupt`
   (`rejects_copy_past_base_end`).
7. **Reject stream_version 0x02** → `UnsupportedDeltaVersion` /
   `MkitError::UnsupportedObjectVersion` (`rejects_unknown_version`).
8. **Reject result_len mismatch** (INSERT sums > declared result_len)
   → `DeltaCorrupt` (`rejects_result_len_mismatch_at_end`). The v1
   reader fails this as soon as `out.len() + length > result_len`, not
   only at end-of-stream.
9. **Reject base_len mismatch** (stream says 16, base supplied is 8) →
   `DeltaCorrupt` (`rejects_base_len_mismatch`).
10. **Reject COPY with reserved low bits** (opcode `0x81`) →
    `DeltaCorrupt` (`rejects_copy_with_reserved_low_bits`).
11. **Reject COPY with `length == 0`** → `DeltaCorrupt`
    (`rejects_copy_with_zero_length`).
12. **Truncated header / COPY / INSERT** → `UnexpectedEof`
    (`rejects_truncated_header`, `rejects_truncated_copy`,
    `rejects_truncated_insert`).
13. **`encode` rejects > u32 lengths** → `DeltaLengthOverflow`
    (`check_length_bounds_rejects_over_u32`). This avoids silently
    saturating to `u32::MAX` and producing a stream that `decode`
    would reject far from the call site (finding H8).
14. **G5 regression**: tiny stream + huge base must not trigger a
    multi-GiB capacity reservation
    (`rejects_huge_result_len_without_preallocating`,
    `cap_hint_does_not_scale_with_base_len`).
15. **Fuzz harness**: `apply(base, arbitrary_bytes)` MUST NOT panic,
    MUST NOT read out of bounds, MUST either succeed or return a
    well-defined error (see red-team R-18).

---

## 9. Future work (non-v1)

- 4-byte extended INSERT length (would consume opcode `0x00` for
  escape).
- COPY length extension to `u32` (would use the currently-reserved 7
  low bits of the COPY opcode byte).
- Multi-base deltas (a delta that references two or more bases).

Any of these require a `stream_version` bump; backward readers MUST
refuse unknown versions.

---

## 10. Invariants

| Invariant | Enforced by |
|---|---|
| A reader executes only streams it understands | `stream_version` byte; `!= 0x01` → `UnsupportedDeltaVersion` (§2) |
| The stream is applied only to the base it was written against | `base_len` MUST equal the supplied base length, checked before any opcode executes (§2, §4) |
| COPY never reads outside the base | `offset + length <= base_len` → `DeltaCorrupt` (§2, §4) |
| Output never exceeds the declared size, even mid-stream | per-opcode `out.len() + length <= result_len` check (§2, §4) |
| Output is exactly `result_len` bytes at end-of-stream | final length check → `DeltaCorrupt` (§2, §4) |
| No degenerate or reserved encodings decode | opcode `0x00`, zero-length COPY, and non-zero reserved COPY bits all → `DeltaCorrupt` (§3, §4) |
| Truncation is distinguishable from structural corruption | `UnexpectedEof` vs `DeltaCorrupt` (§2, §4) |
| A crafted stream cannot panic the decoder, read out of bounds, or force a multi-GiB reservation | fuzz requirement (§8 vector 15); capacity-hint cap, implementation guidance (§4) |
| Stream and result sizes are bounded | fixed field widths, the enclosing pack-entry cap, and the 1 GiB per-object limit on `result_len` (§7) |

The stream itself carries no integrity or signature (§6): tamper
detection is transitive through the packfile trailer, the object-store
hash check on the reconstructed object, and the commit signature.
