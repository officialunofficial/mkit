// SPDX-License-Identifier: MIT OR Apache-2.0
//
// BLAKE3 content-addressing helpers, backed by mkit-core::hash (the SAME
// BLAKE3 the Rust node uses), so object ids computed here are byte-for-byte
// identical to the rest of mkit.

use mkit_core::hash::{hash, to_hex};

/// BLAKE3 digest of `data` as 32 raw bytes.
#[must_use]
pub fn blake3(data: &[u8]) -> [u8; 32] {
    hash(data)
}

/// BLAKE3 digest of `data` as 64-char lowercase hex.
#[must_use]
pub fn blake3_hex(data: &[u8]) -> String {
    to_hex(&hash(data))
}

/// Content-addressing check: `BLAKE3(bytes) == object_id`.
///
/// `object_id` is the raw 32-byte id (proto wire form). Returns false on any
/// length mismatch rather than panicking.
#[must_use]
pub fn object_id_matches(bytes: &[u8], object_id: &[u8]) -> bool {
    if object_id.len() != 32 {
        return false;
    }
    hash(bytes).as_slice() == object_id
}

/// Constant-time byte comparison (no early-exit on the first mismatch), so a
/// timing side channel can't leak how many leading bytes of a secret a guess
/// got right. Used by `worker_impl::auth` to compare the `X-Admin-Token`
/// header against the `ADMIN_TOKEN` secret — pulled out here (rather than
/// living in `worker_impl`, which is wasm32-only) so it's host-testable under
/// plain `cargo test --lib`. `len()` itself is not treated as secret — the
/// check short-circuits on a length mismatch, which is fine because the
/// secret's length isn't attacker-discoverable information worth hiding here
/// (unlike its content).
#[must_use]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    // Conformance vector: BLAKE3 of the empty input.
    #[test]
    fn empty_input_vector() {
        assert_eq!(
            blake3_hex(b""),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
    }

    #[test]
    fn one_byte_flip_changes_hash() {
        assert_ne!(blake3_hex(b"object-bytes"), blake3_hex(b"Object-bytes"));
    }

    #[test]
    fn object_id_matches_roundtrip() {
        let bytes = b"raw mkit object bytes";
        let id = blake3(bytes);
        assert!(object_id_matches(bytes, &id));
        // one-byte flip
        let mut bad = id;
        bad[0] ^= 1;
        assert!(!object_id_matches(bytes, &bad));
        // wrong length
        assert!(!object_id_matches(bytes, &id[..31]));
        // different bytes
        assert!(!object_id_matches(b"other", &id));
    }

    #[test]
    fn constant_time_eq_matches_slice_eq() {
        assert!(constant_time_eq(b"secret-token", b"secret-token"));
        assert!(!constant_time_eq(b"secret-token", b"secret-tokeN"));
        assert!(!constant_time_eq(b"secret-token", b"secret-toke"));
        assert!(!constant_time_eq(b"secret-token", b"secret-token-longer"));
        assert!(constant_time_eq(b"", b""));
        assert!(!constant_time_eq(b"", b"x"));
    }
}
