//! Delta instruction stream — implements the versioned format required
//! by `docs/specs/SPEC-DELTA.md`.
//!
//! Stream layout (SPEC-DELTA §2):
//!
//! ```text
//! [u8  stream_version == 0x01]
//! [u32 LE base_len]            length of the base object
//! [u32 LE result_len]          expected length of the reconstruction
//! [instructions ...]           sequence of opcodes
//! ```
//!
//! Two opcodes (SPEC-DELTA §3):
//!
//! * `0x80` (COPY): `[opcode][u32 LE offset][u16 LE length]` = 7 bytes.
//!   `length` MUST be `>= 1` and `offset + length <= base_len`. The
//!   remaining 7 low bits of the opcode are reserved and MUST be 0 in v1.
//! * `0x01..=0x7F` (INSERT): the opcode byte is the literal length (1..127),
//!   followed by that many literal bytes. Long literals are split into
//!   multiple INSERTs; there is no extended-length form in v1.
//!
//! `0x00` is **reserved** and MUST be rejected.

use crate::object::MkitError;

/// Version byte at offset 0 of every v1 delta stream.
pub const STREAM_VERSION: u8 = 0x01;
/// `COPY` opcode — top bit set, low seven bits reserved (must be zero).
pub const OP_COPY: u8 = 0x80;
/// Maximum bytes encodable in a single `INSERT` opcode.
pub const MAX_INSERT_LEN: usize = 127;
/// Fixed prefix size: 1 byte version + 4 byte `base_len` + 4 byte `result_len`.
pub const HEADER_LEN: usize = 1 + 4 + 4;

/// Block size for the writer's hash index. Power of two for cheap
/// alignment math. Not part of the wire format — readers don't care.
const BLOCK_SIZE: usize = 16;

/// Multiplier applied to `stream.len()` when bounding the decoder's
/// initial `Vec::with_capacity`. The worst-case expansion of a COPY op
/// is 7 bytes of stream → `u16::MAX` output bytes (≈ 9363×), but in
/// practice stream-sized * 256 dwarfs real deltas and still keeps the
/// attacker's reach tiny: a 9-byte stream can only request ≤ 2304
/// bytes of pre-allocation, independent of `base.len()` or the
/// declared `result_len`. The final `result_len` self-consistency
/// check still catches inflated payloads.
pub(crate) const CAP_MULTIPLIER: usize = 256;

/// Compute the decoder's initial capacity hint.
///
/// This is a small, explicitly attacker-resistant helper, exposed to
/// the crate so that the regression test can pin down the bound
/// without reaching into `decode`. The hint is the smaller of:
///
/// * the declared `result_len` (can't exceed declared output), and
/// * `stream.len() * CAP_MULTIPLIER` (attacker bounded by on-wire size).
///
/// Crucially, `base.len()` does NOT appear here: letting the base size
/// influence the cap would let an attacker pair a small delta stream with
/// a large base to pre-reserve a huge output buffer (a ~1 GiB
/// attacker-controlled allocation), so the cap is bounded only by the
/// declared output length and the on-wire stream size.
#[inline]
pub(crate) fn compute_cap_hint(result_len: usize, _base_len: usize, stream_len: usize) -> usize {
    result_len.min(stream_len.saturating_mul(CAP_MULTIPLIER))
}

/// Build a v1 delta stream that reconstructs `result` from `base`.
///
/// The writer is an FNV-1a-on-16-byte-blocks scan. Any conformant
/// writer is acceptable; this one is greedy. Output is always at least
/// [`HEADER_LEN`] bytes.
///
/// # Errors
///
/// Returns [`MkitError::DeltaLengthOverflow`] if either `base.len()`
/// or `result.len()` exceeds `u32::MAX`. SPEC-PACKFILE caps individual
/// payloads under this bound, so this is a programmer error rather
/// than a normal runtime condition — but silently saturating (the
/// old behaviour) produced a stream that `decode()` rejected with a
/// confusing "length mismatch" far from the actual source.
///
/// # Panics
///
/// Panics only on invariant violations in the writer's bookkeeping
/// (insert-buffer length > 127, match length > `u16::MAX`); both are
/// guarded above and unreachable for any valid input.
pub fn encode(base: &[u8], result: &[u8]) -> Result<Vec<u8>, MkitError> {
    use std::collections::HashMap;

    check_length_bounds(base.len(), result.len())?;

    let mut out = Vec::with_capacity(HEADER_LEN + result.len());
    write_header(&mut out, base.len(), result.len());

    // Build hash table: hash(block) -> first-seen position. We cap
    // `base.len()` at `u32::MAX` for COPY offsets — bases over 4 GiB
    // are out of scope for v1 (SPEC-PACKFILE caps individual payloads).
    let num_blocks = base.len() / BLOCK_SIZE;
    let mut index: HashMap<u64, u32> = HashMap::with_capacity(num_blocks);
    for i in 0..num_blocks {
        let pos = i * BLOCK_SIZE;
        if let Ok(pos_u32) = u32::try_from(pos) {
            let block = &base[pos..pos + BLOCK_SIZE];
            let h = block_hash(block);
            index.entry(h).or_insert(pos_u32);
        } else {
            break; // base too large for u32 offsets; fall back to all-INSERT
        }
    }

    let mut insert_buf: Vec<u8> = Vec::with_capacity(MAX_INSERT_LEN);
    let mut ti = 0usize;
    while ti < result.len() {
        let mut matched = false;
        if ti + BLOCK_SIZE <= result.len() {
            let target_block = &result[ti..ti + BLOCK_SIZE];
            let h = block_hash(target_block);
            if let Some(&base_pos) = index.get(&h) {
                let base_pos_usize = base_pos as usize;
                if &base[base_pos_usize..base_pos_usize + BLOCK_SIZE] == target_block {
                    flush_insert(&mut out, &mut insert_buf);

                    // Greedy forward extension, capped at u16::MAX.
                    let mut match_len = BLOCK_SIZE;
                    while base_pos_usize + match_len < base.len()
                        && ti + match_len < result.len()
                        && base[base_pos_usize + match_len] == result[ti + match_len]
                        && match_len < u16::MAX as usize
                    {
                        match_len += 1;
                    }
                    // match_len is bounded by u16::MAX above.
                    emit_copy(
                        &mut out,
                        base_pos,
                        u16::try_from(match_len).expect("<= u16::MAX"),
                    );
                    ti += match_len;
                    matched = true;
                }
            }
        }
        if !matched {
            insert_buf.push(result[ti]);
            ti += 1;
            if insert_buf.len() == MAX_INSERT_LEN {
                flush_insert(&mut out, &mut insert_buf);
            }
        }
    }
    flush_insert(&mut out, &mut insert_buf);
    Ok(out)
}

/// Validate that `base_len` and `result_len` both fit in the v1 wire
/// format's `u32` cap. Extracted as a helper so tests can exercise
/// the bound without actually allocating multi-gigabyte buffers.
pub(crate) fn check_length_bounds(base_len: usize, result_len: usize) -> Result<(), MkitError> {
    if u32::try_from(base_len).is_err() {
        return Err(MkitError::DeltaLengthOverflow {
            field: "base_len",
            len: base_len,
        });
    }
    if u32::try_from(result_len).is_err() {
        return Err(MkitError::DeltaLengthOverflow {
            field: "result_len",
            len: result_len,
        });
    }
    Ok(())
}

/// Apply a v1 delta stream to `base`, returning the reconstructed bytes.
/// Verifies header version, base length, COPY bounds, and the final
/// `result_len`.
///
/// # Errors
///
/// Returns [`MkitError::UnsupportedObjectVersion`] for stream version
/// other than `0x01`, [`MkitError::UnexpectedEof`] for truncated input,
/// and [`MkitError::TrailingData`] for any other corruption (zero
/// opcode, COPY past base, length mismatch at end-of-stream, reserved
/// bits set, etc.).
///
/// # Panics
///
/// Slice-to-fixed-array conversions in this function are guarded by
/// the preceding bounds checks; the `expect` calls trip only if the
/// compiler's slice-bounds elision is wrong.
pub fn decode(base: &[u8], stream: &[u8]) -> Result<Vec<u8>, MkitError> {
    if stream.len() < HEADER_LEN {
        return Err(MkitError::UnexpectedEof);
    }
    if stream[0] != STREAM_VERSION {
        return Err(MkitError::UnsupportedObjectVersion);
    }
    let base_len = u32::from_le_bytes(stream[1..5].try_into().expect("4 bytes")) as usize;
    let result_len = u32::from_le_bytes(stream[5..9].try_into().expect("4 bytes")) as usize;
    if base_len != base.len() {
        return Err(MkitError::TrailingData);
    }

    // Bound the pre-allocation against attacker-controlled length fields.
    // See [`compute_cap_hint`]: the hint is strictly a function of
    // `stream.len()` (with `result_len` as an upper bound) — `base.len()`
    // MUST NOT appear, because a 1 GiB base + 9-byte crafted stream
    // otherwise triggers a ≈ 1 GiB allocation. The final `result_len`
    // equality check below still enforces wire-level self-consistency.
    let cap_hint = compute_cap_hint(result_len, base.len(), stream.len());
    let mut out: Vec<u8> = Vec::with_capacity(cap_hint);
    let mut pos = HEADER_LEN;
    while pos < stream.len() {
        let op = stream[pos];
        pos += 1;
        if op & 0x80 != 0 {
            // COPY. Reserved low seven bits MUST be zero in v1.
            if op & 0x7F != 0 {
                return Err(MkitError::TrailingData);
            }
            if pos + 6 > stream.len() {
                return Err(MkitError::UnexpectedEof);
            }
            let offset =
                u32::from_le_bytes(stream[pos..pos + 4].try_into().expect("4 bytes")) as usize;
            pos += 4;
            let length =
                u16::from_le_bytes(stream[pos..pos + 2].try_into().expect("2 bytes")) as usize;
            pos += 2;
            if length == 0 {
                return Err(MkitError::TrailingData);
            }
            // Use checked math: an attacker-controlled offset could
            // overflow `usize` on 32-bit targets when added to length, so
            // reject the input rather than wrapping or clamping.
            let end = offset.checked_add(length).ok_or(MkitError::TrailingData)?;
            if end > base.len() {
                return Err(MkitError::TrailingData);
            }
            // Don't overshoot the declared result_len.
            if out.len().checked_add(length).is_none_or(|v| v > result_len) {
                return Err(MkitError::TrailingData);
            }
            out.extend_from_slice(&base[offset..end]);
        } else if op > 0 {
            // INSERT. opcode IS the literal length (1..=127).
            let length = op as usize;
            if pos + length > stream.len() {
                return Err(MkitError::UnexpectedEof);
            }
            if out.len().checked_add(length).is_none_or(|v| v > result_len) {
                return Err(MkitError::TrailingData);
            }
            out.extend_from_slice(&stream[pos..pos + length]);
            pos += length;
        } else {
            // 0x00 reserved.
            return Err(MkitError::TrailingData);
        }
    }
    if out.len() != result_len {
        return Err(MkitError::TrailingData);
    }
    Ok(out)
}

// --- helpers ---

fn write_header(out: &mut Vec<u8>, base_len: usize, result_len: usize) {
    // `check_length_bounds` has already been called by `encode`, so
    // both fit in u32. The `expect()`s are invariant-preserving
    // rather than user-facing: reaching them means the caller
    // bypassed `encode`.
    let bl: u32 = u32::try_from(base_len).expect("base_len <= u32::MAX (checked)");
    let rl: u32 = u32::try_from(result_len).expect("result_len <= u32::MAX (checked)");
    out.push(STREAM_VERSION);
    out.extend_from_slice(&bl.to_le_bytes());
    out.extend_from_slice(&rl.to_le_bytes());
}

fn emit_copy(out: &mut Vec<u8>, offset: u32, length: u16) {
    out.push(OP_COPY);
    out.extend_from_slice(&offset.to_le_bytes());
    out.extend_from_slice(&length.to_le_bytes());
}

fn flush_insert(out: &mut Vec<u8>, buf: &mut Vec<u8>) {
    if buf.is_empty() {
        return;
    }
    debug_assert!(buf.len() <= MAX_INSERT_LEN);
    out.push(u8::try_from(buf.len()).expect("<= 127"));
    out.extend_from_slice(buf);
    buf.clear();
}

fn block_hash(block: &[u8]) -> u64 {
    // FNV-1a 64-bit.
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in block {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0001_0000_01b3);
    }
    h
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn header(base_len: u32, result_len: u32) -> [u8; HEADER_LEN] {
        let mut h = [0u8; HEADER_LEN];
        h[0] = STREAM_VERSION;
        h[1..5].copy_from_slice(&base_len.to_le_bytes());
        h[5..9].copy_from_slice(&result_len.to_le_bytes());
        h
    }

    #[test]
    fn identity_roundtrip() {
        let data = b"0123456789abcdef".repeat(4); // 64 bytes
        let stream = encode(&data, &data).unwrap();
        let restored = decode(&data, &stream).unwrap();
        assert_eq!(restored, data);
    }

    #[test]
    fn pure_insert_roundtrip() {
        let base = b"aaa";
        let target = b"zzz";
        let stream = encode(base, target).unwrap();
        // After the 9-byte header, the very next byte is the INSERT length.
        assert_eq!(stream[HEADER_LEN] & 0x80, 0);
        assert_eq!(stream[HEADER_LEN], 3);
        let restored = decode(base, &stream).unwrap();
        assert_eq!(restored, target);
    }

    #[test]
    fn pure_copy_full_base() {
        let base: Vec<u8> = (0..16u8).cycle().take(128).collect();
        let target = &base[..64];
        // Hand-build a stream that is exactly one COPY(0, 64).
        let mut stream = header(
            u32::try_from(base.len()).unwrap(),
            u32::try_from(target.len()).unwrap(),
        )
        .to_vec();
        stream.push(OP_COPY);
        stream.extend_from_slice(&0u32.to_le_bytes());
        stream.extend_from_slice(&64u16.to_le_bytes());
        assert_eq!(stream.len(), HEADER_LEN + 7);
        let restored = decode(&base, &stream).unwrap();
        assert_eq!(restored, target);
    }

    #[test]
    fn near_duplicate_yields_smaller_delta() {
        let v1 = include_str!("delta.rs"); // any sizable text
        let mut v2 = String::from(v1);
        v2.push_str("\n// trailing edit\n");
        let stream = encode(v1.as_bytes(), v2.as_bytes()).unwrap();
        let restored = decode(v1.as_bytes(), &stream).unwrap();
        assert_eq!(restored, v2.as_bytes());
        assert!(stream.len() < v2.len(), "delta should be smaller than v2");
    }

    #[test]
    fn rejects_zero_opcode() {
        let mut stream = header(0, 0).to_vec();
        stream.push(0x00);
        let err = decode(&[], &stream).unwrap_err();
        assert!(matches!(err, MkitError::TrailingData));
    }

    #[test]
    fn rejects_unknown_version() {
        let mut bytes = header(0, 0);
        bytes[0] = 0x02;
        let err = decode(&[], &bytes).unwrap_err();
        assert!(matches!(err, MkitError::UnsupportedObjectVersion));
    }

    #[test]
    fn rejects_truncated_header() {
        let bytes = [0x01u8, 0x00, 0x00];
        let err = decode(&[], &bytes).unwrap_err();
        assert!(matches!(err, MkitError::UnexpectedEof));
    }

    #[test]
    fn rejects_truncated_copy() {
        let mut stream = header(16, 16).to_vec();
        stream.push(OP_COPY);
        stream.extend_from_slice(&0u32.to_le_bytes()); // missing 2-byte length
        let err = decode(&[0u8; 16], &stream).unwrap_err();
        assert!(matches!(err, MkitError::UnexpectedEof));
    }

    #[test]
    fn rejects_truncated_insert() {
        let mut stream = header(0, 10).to_vec();
        stream.push(10); // claim 10 literal bytes
        stream.extend_from_slice(b"abc"); // only 3 supplied
        let err = decode(&[], &stream).unwrap_err();
        assert!(matches!(err, MkitError::UnexpectedEof));
    }

    #[test]
    fn rejects_copy_past_base_end() {
        let base = b"short"; // 5 bytes
        let mut stream = header(u32::try_from(base.len()).unwrap(), 100).to_vec();
        stream.push(OP_COPY);
        stream.extend_from_slice(&0u32.to_le_bytes());
        stream.extend_from_slice(&100u16.to_le_bytes());
        let err = decode(base, &stream).unwrap_err();
        assert!(matches!(err, MkitError::TrailingData));
    }

    #[test]
    fn rejects_copy_with_zero_length() {
        let base = [0u8; 16];
        let mut stream = header(16, 16).to_vec();
        stream.push(OP_COPY);
        stream.extend_from_slice(&0u32.to_le_bytes());
        stream.extend_from_slice(&0u16.to_le_bytes());
        let err = decode(&base, &stream).unwrap_err();
        assert!(matches!(err, MkitError::TrailingData));
    }

    #[test]
    fn rejects_base_len_mismatch() {
        let stream = header(16, 0).to_vec();
        let err = decode(&[0u8; 8], &stream).unwrap_err();
        assert!(matches!(err, MkitError::TrailingData));
    }

    #[test]
    fn rejects_result_len_mismatch_at_end() {
        // INSERTs sum to 5 but header says result_len = 3.
        let mut stream = header(0, 3).to_vec();
        stream.push(5);
        stream.extend_from_slice(b"hello");
        let err = decode(&[], &stream).unwrap_err();
        assert!(matches!(err, MkitError::TrailingData));
    }

    #[test]
    fn rejects_huge_result_len_without_preallocating() {
        // Regression: a 9-byte header claiming result_len = u32::MAX MUST NOT
        // trigger a 4 GiB `Vec::with_capacity`. The pre-allocation is now
        // capped against the stream+base size. The decoder still returns an
        // error (TrailingData) because no ops follow — but the point is that
        // it does so without first reserving 4 GiB of virtual memory.
        let stream = header(0, u32::MAX);
        let err = decode(&[], &stream).unwrap_err();
        assert!(matches!(err, MkitError::TrailingData));
    }

    #[test]
    fn rejects_copy_with_reserved_low_bits() {
        let base = [0u8; 16];
        let mut stream = header(16, 4).to_vec();
        stream.push(OP_COPY | 0x01); // reserved bit set
        stream.extend_from_slice(&0u32.to_le_bytes());
        stream.extend_from_slice(&4u16.to_le_bytes());
        let err = decode(&base, &stream).unwrap_err();
        assert!(matches!(err, MkitError::TrailingData));
    }

    #[test]
    fn empty_base_pure_insert() {
        let target = b"all new content here!";
        let stream = encode(b"", target).unwrap();
        let restored = decode(b"", &stream).unwrap();
        assert_eq!(restored, target);
    }

    #[test]
    fn cap_hint_does_not_scale_with_base_len() {
        // G5 regression: the decoder's pre-allocation must be bounded by
        // `stream.len()`, not by `base.len()`. Previously a 9-byte stream
        // with a 1 GiB base could drive `Vec::with_capacity` to ~1 GiB.
        //
        // Assert: for a huge base + tiny stream, cap_hint is tiny.
        let huge_base = 1usize << 30; // 1 GiB
        let tiny_stream = 9usize; // just the header
        let declared_result = u32::MAX as usize;
        let cap = super::compute_cap_hint(declared_result, huge_base, tiny_stream);
        assert!(
            cap <= tiny_stream.saturating_mul(CAP_MULTIPLIER),
            "cap_hint {cap} must be bounded by stream.len() * CAP_MULTIPLIER, \
             not by base.len()",
        );
        assert!(
            cap < 1024 * 1024,
            "cap_hint {cap} must stay well below 1 MiB for a 9-byte stream",
        );
    }

    /// `encode()` used to saturate `base_len`/`result_len` to
    /// `u32::MAX` for inputs over 4 GiB, silently producing a stream
    /// that `decode()` would reject with a confusing "length mismatch".
    /// Now `check_length_bounds` errors out explicitly with
    /// `DeltaLengthOverflow` so misuse surfaces at the call site.
    #[test]
    fn check_length_bounds_rejects_over_u32() {
        // base_len above u32::MAX.
        let over = (u32::MAX as usize).saturating_add(1);
        assert!(matches!(
            check_length_bounds(over, 0),
            Err(MkitError::DeltaLengthOverflow { .. })
        ));
        // result_len above u32::MAX.
        assert!(matches!(
            check_length_bounds(0, over),
            Err(MkitError::DeltaLengthOverflow { .. })
        ));
        // Exactly at u32::MAX is fine.
        assert!(check_length_bounds(u32::MAX as usize, u32::MAX as usize).is_ok());
        // Small is fine.
        assert!(check_length_bounds(1, 1).is_ok());
    }
}
