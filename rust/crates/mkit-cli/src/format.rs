//! Human-oriented output formatters — the CLI's thin presentation
//! layer. Anything that emits canonical on-disk or wire bytes belongs
//! in `mkit-core` (`serialize.rs`, `pack.rs`, etc.), not here.

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

/// Full-detail rendering of an [`mkit_core::Identity`] suitable for
/// machine-readable output (e.g. JSONL from `mkit log --format=json`).
///
/// Format mirrors the parser shorthands accepted by
/// `mkit config user.identity` so a value emitted here round-trips:
/// `ed25519:<full-hex>`, `did:key:<full-hex>`, `mid:<decimal-u64>`
/// for 8-byte opaque keys, and `opaque:<full-hex>` for other opaque
/// lengths.
#[must_use]
pub fn full_identity(id: &mkit_core::Identity) -> String {
    match id.kind {
        mkit_core::IdentityKind::Opaque if id.bytes.len() == 8 => {
            let mut arr = [0u8; 8];
            arr.copy_from_slice(&id.bytes);
            format!("mid:{}", u64::from_le_bytes(arr))
        }
        mkit_core::IdentityKind::Ed25519 => format!("ed25519:{}", to_hex(&id.bytes)),
        mkit_core::IdentityKind::DidKey => format!("did:key:{}", to_hex(&id.bytes)),
        mkit_core::IdentityKind::Opaque => format!("opaque:{}", to_hex(&id.bytes)),
    }
}

/// Escape a Rust string for inclusion in a JSON string literal.
/// Sufficient for the small, known fields emitted by `--format=json`
/// callers (commit messages, hashes, identity strings). Does NOT
/// handle surrogate pairs — UTF-8 round-trips as itself since JSON
/// strings are UTF-8.
#[must_use]
pub fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x08' => out.push_str("\\b"),
            '\x0c' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                use std::fmt::Write as _;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX_ALPHABET[(b >> 4) as usize] as char);
        out.push(HEX_ALPHABET[(b & 0x0F) as usize] as char);
    }
    out
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

    #[test]
    fn json_escape_basic() {
        assert_eq!(json_escape("hello"), "hello");
        assert_eq!(json_escape("a\"b"), "a\\\"b");
        assert_eq!(json_escape("a\\b"), "a\\\\b");
        assert_eq!(json_escape("a\nb"), "a\\nb");
        assert_eq!(json_escape("a\tb"), "a\\tb");
    }

    #[test]
    fn json_escape_control_chars() {
        // \x01 escapes as .
        assert_eq!(json_escape("\x01"), "\\u0001");
        // \x7f stays unescaped (only chars < 0x20 are special).
        assert_eq!(json_escape("\x7f"), "\x7f");
    }

    #[test]
    fn full_identity_mid() {
        let id = mkit_core::Identity {
            kind: mkit_core::IdentityKind::Opaque,
            bytes: 42u64.to_le_bytes().to_vec(),
        };
        assert_eq!(full_identity(&id), "mid:42");
    }

    #[test]
    fn full_identity_ed25519() {
        let id = mkit_core::Identity {
            kind: mkit_core::IdentityKind::Ed25519,
            bytes: vec![0xab; 32],
        };
        let s = full_identity(&id);
        assert!(s.starts_with("ed25519:"));
        assert_eq!(s.len(), "ed25519:".len() + 64);
    }
}
