//! Author/committer/tagger line synthesis (SPEC-GIT-BRIDGE §6.2).
//!
//! The line is display-only — reconstruction reads the `mkit-author` /
//! `mkit-tagger` header — but it is part of the hashed git bytes, so
//! the synthesis is normative and a pure function of the identity
//! payload and timestamp.

use crate::b64;
use mkit_core::object::{Identity, IdentityKind};

/// Fixed, never-routable email (RFC 2606 reserved TLD).
pub const BRIDGE_EMAIL: &str = "bridge@mkit.invalid";

/// Bytes that may not appear in a git author-line name slot.
fn name_byte_ok(b: u8) -> bool {
    !(b == b'<' || b == b'>' || b < 0x20 || b == 0x7F)
}

/// Deterministic display name for an identity (§6.2).
#[must_use]
pub fn display_name(identity: &Identity) -> String {
    match identity.kind {
        IdentityKind::Ed25519 => {
            format!("mkit:ed25519:{}", crate::gitobj::bytes_hex(&identity.bytes))
        }
        IdentityKind::DidKey => {
            if identity.bytes.iter().all(|&b| name_byte_ok(b))
                && let Ok(s) = std::str::from_utf8(&identity.bytes)
            {
                format!("did:key:{s}")
            } else {
                opaque_name(&identity.bytes)
            }
        }
        IdentityKind::Opaque => {
            if identity.bytes.iter().all(|&b| name_byte_ok(b))
                && let Ok(s) = std::str::from_utf8(&identity.bytes)
            {
                s.to_owned()
            } else {
                opaque_name(&identity.bytes)
            }
        }
    }
}

fn opaque_name(payload: &[u8]) -> String {
    format!("mkit:opaque:{}", b64::encode(payload))
}

/// Full synthesized line value: `<name> <email> <ts> +0000`.
///
/// The caller has already rejected timestamps above `i64::MAX`
/// (`Refusal::TimestampOverflow`), so this renders unconditionally.
#[must_use]
pub fn line(identity: &Identity, timestamp: u64) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(display_name(identity).as_bytes());
    out.extend_from_slice(b" <");
    out.extend_from_slice(BRIDGE_EMAIL.as_bytes());
    out.extend_from_slice(b"> ");
    out.extend_from_slice(timestamp.to_string().as_bytes());
    out.extend_from_slice(b" +0000");
    out
}

/// Extract the timestamp back out of a synthesized line
/// (reconstruction path). Returns `None` when the line does not match
/// the bridge shape.
#[must_use]
pub fn parse_timestamp(line: &[u8]) -> Option<u64> {
    // ... <email>> <ts> +0000
    let s = std::str::from_utf8(line).ok()?;
    let rest = s.strip_suffix(" +0000")?;
    let (_, ts) = rest.rsplit_once(' ')?;
    ts.parse::<u64>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ed25519_name_is_hex() {
        let id = Identity::ed25519([0xAA; 32]);
        let n = display_name(&id);
        assert!(n.starts_with("mkit:ed25519:aaaa"));
        assert_eq!(n.len(), "mkit:ed25519:".len() + 64);
    }

    #[test]
    fn printable_opaque_is_verbatim() {
        let id = Identity::opaque(b"Alice Example".to_vec());
        assert_eq!(display_name(&id), "Alice Example");
    }

    #[test]
    fn angle_bracket_opaque_falls_back_to_base64() {
        let id = Identity::opaque(b"Alice <alice@example.com>".to_vec());
        let n = display_name(&id);
        assert!(n.starts_with("mkit:opaque:"), "got {n}");
        assert!(!n.contains('<'));
    }

    #[test]
    fn non_utf8_opaque_falls_back_to_base64() {
        let id = Identity::opaque(vec![0xFF, 0xFE, 0x00]);
        assert!(display_name(&id).starts_with("mkit:opaque:"));
    }

    #[test]
    fn line_round_trips_timestamp() {
        let id = Identity::opaque(b"x".to_vec());
        let l = line(&id, 1_700_000_000);
        assert!(l.ends_with(b" +0000"));
        assert_eq!(parse_timestamp(&l), Some(1_700_000_000));
    }
}
