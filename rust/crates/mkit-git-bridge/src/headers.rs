//! `mkit-*` header names and value encodings (SPEC-GIT-BRIDGE §6, §7).

use crate::b64;
use crate::gitobj::{bytes_from_hex, bytes_hex};
use mkit_core::object::{IDENTITY_MAX_LEN, Identity, IdentityKind};

/// Header names, in the exact emission order the spec pins for
/// commits (§6.1). `MKIT_PARENT` repeats; the two annotation headers
/// are emitted only when non-zero.
pub const MKIT_SCHEMA: &str = "mkit-schema";
pub const MKIT_AUTHOR: &str = "mkit-author";
pub const MKIT_TAGGER: &str = "mkit-tagger";
pub const MKIT_SIGNER: &str = "mkit-signer";
pub const MKIT_SIGNATURE: &str = "mkit-signature";
pub const MKIT_TREE: &str = "mkit-tree";
pub const MKIT_PARENT: &str = "mkit-parent";
pub const MKIT_MESSAGE_HASH: &str = "mkit-message-hash";
pub const MKIT_CONTENT_DIGEST: &str = "mkit-content-digest";
pub const MKIT_TARGET: &str = "mkit-target";
pub const MKIT_TARGET_TYPE: &str = "mkit-target-type";

/// Reserved by §8 for the future remix mapping — never emitted, and
/// reconstruction rejects them so a v1 verifier cannot silently
/// accept a future-format object.
pub const RESERVED: &[&str] = &["mkit-remix-source", "mkit-object-type"];

/// The schema version this mapping covers (§1.2).
pub const SCHEMA_VALUE: &str = "1";

/// Encode an identity header value: `<kind-hex2>:<unpadded base64>`.
#[must_use]
pub fn identity_value(identity: &Identity) -> String {
    format!(
        "{:02x}:{}",
        identity.kind as u8,
        b64::encode(&identity.bytes)
    )
}

/// Strict inverse of [`identity_value`].
#[must_use]
pub fn parse_identity(value: &str) -> Option<Identity> {
    let (kind_hex, payload_b64) = value.split_once(':')?;
    let kind_bytes = bytes_from_hex(kind_hex, 1)?;
    let kind = match kind_bytes[0] {
        0x01 => IdentityKind::Ed25519,
        0x02 => IdentityKind::DidKey,
        0x03 => IdentityKind::Opaque,
        _ => return None,
    };
    let bytes = b64::decode(payload_b64)?;
    if bytes.is_empty() || bytes.len() > IDENTITY_MAX_LEN as usize {
        return None;
    }
    let id = Identity { kind, bytes };
    id.is_valid().then_some(id)
}

/// Encode a 32-byte hash header value.
#[must_use]
pub fn hash_value(h: &[u8; 32]) -> String {
    bytes_hex(h)
}

/// Strict 32-byte lowercase-hex decode.
#[must_use]
pub fn parse_hash(value: &str) -> Option<[u8; 32]> {
    let v = bytes_from_hex(value, 32)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    Some(out)
}

/// Strict 64-byte lowercase-hex decode (signatures).
#[must_use]
pub fn parse_signature(value: &str) -> Option<[u8; 64]> {
    let v = bytes_from_hex(value, 64)?;
    let mut out = [0u8; 64];
    out.copy_from_slice(&v);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_round_trips_all_kinds() {
        for id in [
            Identity::ed25519([7; 32]),
            Identity {
                kind: IdentityKind::DidKey,
                bytes: b"z6Mk".to_vec(),
            },
            Identity::opaque(vec![0xFF, 0x00, 0x10]),
        ] {
            let v = identity_value(&id);
            assert_eq!(parse_identity(&v).unwrap(), id, "value {v}");
        }
    }

    #[test]
    fn identity_rejects_bad_kind_and_empty() {
        assert!(parse_identity("04:QQ").is_none());
        assert!(parse_identity("03:").is_none());
        assert!(
            parse_identity("3:QQ").is_none(),
            "kind must be two hex digits"
        );
    }

    #[test]
    fn hash_value_round_trips() {
        let h = [0x5A; 32];
        assert_eq!(parse_hash(&hash_value(&h)).unwrap(), h);
        assert!(parse_hash("zz").is_none());
    }
}
