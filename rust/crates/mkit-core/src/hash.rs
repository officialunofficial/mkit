//! BLAKE3 hashing helpers.
//!
//! A [`Hash`] is a fixed 32-byte digest. The canonical hex form is 64
//! lowercase characters. Object-store paths split the digest into a
//! first-byte directory and 62-char file-name (see `SPEC-OBJECTS.md`
//! §10).

use core::fmt;

/// Length, in bytes, of a BLAKE3 digest used throughout mkit.
pub const HASH_LEN: usize = 32;
/// Length of the lowercase-hex encoding of a [`Hash`].
pub const HEX_LEN: usize = 64;

/// Fixed-size BLAKE3 digest. `Copy` because it is tiny and cheap.
pub type Hash = [u8; HASH_LEN];

/// The all-zero digest. Used as the "absent" sentinel for optional
/// annotation fields on commit objects (`message_hash`, `content_digest`).
pub const ZERO: Hash = [0u8; HASH_LEN];

/// Hash arbitrary bytes in one shot.
#[must_use]
pub fn hash(data: &[u8]) -> Hash {
    let h = blake3::hash(data);
    *h.as_bytes()
}

/// Incremental BLAKE3 hasher for streaming data.
#[derive(Debug, Default, Clone)]
pub struct Hasher {
    inner: blake3::Hasher,
}

impl Hasher {
    /// Create a fresh hasher.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: blake3::Hasher::new(),
        }
    }

    /// Absorb a chunk of input.
    pub fn update(&mut self, data: &[u8]) -> &mut Self {
        self.inner.update(data);
        self
    }

    /// Finalise into a 32-byte digest.
    #[must_use]
    pub fn finalize(&self) -> Hash {
        *self.inner.finalize().as_bytes()
    }
}

/// Errors returned by [`from_hex`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FromHexError {
    /// The input was not exactly [`HEX_LEN`] bytes.
    #[error("hex digest must be {} chars, got {actual}", HEX_LEN)]
    InvalidLength { actual: usize },
    /// The input contained a non-hex character.
    #[error("hex digest contained a non-hex byte")]
    InvalidChar,
}

/// Render a [`Hash`] as lowercase hex.
#[must_use]
pub fn to_hex(h: &Hash) -> String {
    let mut out = String::with_capacity(HEX_LEN);
    for b in h {
        // `format!` with "{:02x}" allocates per-byte; hand-roll for speed.
        const HEX: &[u8; 16] = b"0123456789abcdef";
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Parse a lowercase-or-uppercase 64-char hex string into a [`Hash`].
/// Rejects any non-hex byte.
pub fn from_hex(s: &str) -> Result<Hash, FromHexError> {
    let bytes = s.as_bytes();
    if bytes.len() != HEX_LEN {
        return Err(FromHexError::InvalidLength {
            actual: bytes.len(),
        });
    }
    let mut out = [0u8; HASH_LEN];
    for i in 0..HASH_LEN {
        let hi = hex_nibble(bytes[i * 2])?;
        let lo = hex_nibble(bytes[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Result<u8, FromHexError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(10 + (b - b'a')),
        b'A'..=b'F' => Ok(10 + (b - b'A')),
        _ => Err(FromHexError::InvalidChar),
    }
}

/// Object-store path split: `<first-byte-hex>/<remaining-62-hex>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectPath {
    /// Two-char directory prefix, ASCII lowercase hex.
    pub dir: [u8; 2],
    /// 62-char file name, ASCII lowercase hex.
    pub file: [u8; 62],
}

impl fmt::Display for ObjectPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Both halves are ASCII hex by construction.
        write!(
            f,
            "{}/{}",
            core::str::from_utf8(&self.dir).expect("ascii hex"),
            core::str::from_utf8(&self.file).expect("ascii hex"),
        )
    }
}

/// Split a [`Hash`] into its object-store path components.
#[must_use]
pub fn object_path(h: &Hash) -> ObjectPath {
    let hex = to_hex(h);
    let bytes = hex.as_bytes();
    let mut dir = [0u8; 2];
    let mut file = [0u8; 62];
    dir.copy_from_slice(&bytes[..2]);
    file.copy_from_slice(&bytes[2..]);
    ObjectPath { dir, file }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vector_hello() {
        let h = hash(b"hello");
        assert_eq!(
            to_hex(&h),
            "ea8f163db38682925e4491c5e58d4bb3506ef8c14eb78a86e908c5624a67200f"
        );
    }

    #[test]
    fn incremental_matches_oneshot() {
        let oneshot = hash(b"hello world");
        let mut h = Hasher::new();
        h.update(b"hello ").update(b"world");
        assert_eq!(oneshot, h.finalize());
    }

    #[test]
    fn from_hex_roundtrip() {
        let h = hash(b"test");
        let hex = to_hex(&h);
        let parsed = from_hex(&hex).unwrap();
        assert_eq!(h, parsed);
    }

    #[test]
    fn from_hex_accepts_mixed_case() {
        let lower = "ea8f163db38682925e4491c5e58d4bb3506ef8c14eb78a86e908c5624a67200f";
        let upper = lower.to_ascii_uppercase();
        assert_eq!(from_hex(lower).unwrap(), from_hex(&upper).unwrap());
    }

    #[test]
    fn from_hex_rejects_too_short() {
        assert!(matches!(
            from_hex("abcdef"),
            Err(FromHexError::InvalidLength { .. })
        ));
    }

    #[test]
    fn from_hex_rejects_bad_char() {
        let bad: String = "gg".chars().chain("00".repeat(31).chars()).collect();
        assert_eq!(from_hex(&bad), Err(FromHexError::InvalidChar));
    }

    #[test]
    fn to_hex_of_zero_is_all_zeros() {
        assert_eq!(to_hex(&ZERO), "0".repeat(HEX_LEN));
    }

    #[test]
    fn object_path_splits_correctly() {
        let h = hash(b"test");
        let path = object_path(&h);
        let hex = to_hex(&h);
        assert_eq!(&path.dir, &hex.as_bytes()[..2]);
        assert_eq!(&path.file[..], &hex.as_bytes()[2..]);
    }
}
