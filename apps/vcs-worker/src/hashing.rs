// SPDX-License-Identifier: MIT OR Apache-2.0
//
// BLAKE3 content-addressing helpers, backed by mkit-core::hash (the SAME
// BLAKE3 the Rust node uses), so pack/object ids computed here are
// byte-for-byte identical to the rest of mkit. Mirrors
// apps/repo-worker/src/hashing.rs.

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

/// Content-addressing check: `BLAKE3(bytes) == pack_id`.
///
/// `pack_id` is the raw 32-byte id (proto wire form). Returns false on any
/// length mismatch rather than panicking.
#[must_use]
pub fn pack_id_matches(bytes: &[u8], pack_id: &[u8]) -> bool {
    if pack_id.len() != 32 {
        return false;
    }
    hash(bytes).as_slice() == pack_id
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_vector() {
        assert_eq!(
            blake3_hex(b""),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
    }

    #[test]
    fn pack_id_matches_roundtrip() {
        let bytes = b"raw mkit pack bytes";
        let id = blake3(bytes);
        assert!(pack_id_matches(bytes, &id));
        let mut bad = id;
        bad[0] ^= 1;
        assert!(!pack_id_matches(bytes, &bad));
        assert!(!pack_id_matches(bytes, &id[..31]));
        assert!(!pack_id_matches(b"other", &id));
    }
}
