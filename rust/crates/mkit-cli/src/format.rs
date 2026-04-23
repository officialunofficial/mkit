//! Human-oriented output formatters — the CLI's thin presentation
//! layer. Anything that emits canonical on-disk or wire bytes belongs
//! in `mkit-core` (`serialize.rs`, `pack.rs`, etc.), not here. Port of
//! `src/format.zig` — only the helpers the wired commands need in the
//! Rust port are included so far; the remainder will land alongside
//! their commands in later phases.

use mkit_core::hash::Hash;

/// Render a [`Hash`] as 64 lowercase hex chars. Wrapper over
/// `mkit_core`'s byte-level API that keeps a stable name at this layer.
#[must_use]
pub fn hex_hash(h: &Hash) -> String {
    mkit_core::hash::to_hex(h)
}

/// Render the first `n` hex chars of a hash (min 4, max 64).
#[must_use]
pub fn short_hash(h: &Hash, n: usize) -> String {
    let full = hex_hash(h);
    let take = n.clamp(4, 64);
    full[..take].to_owned()
}

static HEX_ALPHABET: &[u8; 16] = b"0123456789abcdef";

/// Render a short [`mkit_core::Identity`]: for 8-byte opaque keys we
/// show the LE u64 decimal; otherwise `<kind>:<8-hex>`.
#[must_use]
pub fn short_identity(id: &mkit_core::Identity) -> String {
    match id.kind {
        mkit_core::IdentityKind::Opaque if id.bytes.len() == 8 => {
            let mut arr = [0u8; 8];
            arr.copy_from_slice(&id.bytes);
            u64::from_le_bytes(arr).to_string()
        }
        kind => {
            let kind_name = match kind {
                mkit_core::IdentityKind::Ed25519 => "ed25519",
                mkit_core::IdentityKind::DidKey => "did:key",
                mkit_core::IdentityKind::Opaque => "opaque",
            };
            let take = id.bytes.len().min(4);
            let mut hex = String::with_capacity(take * 2);
            for b in &id.bytes[..take] {
                hex.push(HEX_ALPHABET[(b >> 4) as usize] as char);
                hex.push(HEX_ALPHABET[(b & 0x0F) as usize] as char);
            }
            format!("{kind_name}:{hex}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mkit_core::hash;

    #[test]
    fn hex_hash_is_64_chars() {
        let h = hash::hash(b"hello");
        assert_eq!(hex_hash(&h).len(), 64);
        assert!(hex_hash(&h).chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn short_hash_clamps() {
        let h = hash::hash(b"x");
        assert_eq!(short_hash(&h, 0).len(), 4);
        assert_eq!(short_hash(&h, 8).len(), 8);
        assert_eq!(short_hash(&h, 999).len(), 64);
    }
}
