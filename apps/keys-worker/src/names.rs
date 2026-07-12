// Display-name normalization + the KV record shape.
//
// Names are non-unique display handles keyed by the owner's Ed25519 pubkey
// (lowercase hex). The pubkey is the real identity; the name is a label.

use serde::{Deserialize, Serialize};

/// Max stored handle length (chars). Keeps a tidy single handle, not a bio.
pub const MAX_NAME_LEN: usize = 32;

/// The JSON record stored in KV under the lowercase pubkey hex.
#[derive(Serialize, Deserialize)]
pub struct NameRecord {
    pub pubkey: String,
    pub name: String,
    pub updated_at: i64,
}

/// Collapse internal whitespace, trim, and clamp to MAX_NAME_LEN. Returns None
/// if nothing usable remains (empty after trim).
pub fn normalize_name(raw: &str) -> Option<String> {
    let collapsed = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    let trimmed = collapsed.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.chars().take(MAX_NAME_LEN).collect())
}

/// True for a syntactically valid 64-char lowercase-hex Ed25519 pubkey.
pub fn is_pubkey_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The request body for `PUT /name/<pubkey>`.
#[derive(Deserialize)]
pub struct SetNameBody {
    pub name: String,
}

/// The request body for `POST /resolve`.
#[derive(Deserialize)]
pub struct ResolveBody {
    pub pubkeys: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_trims_and_collapses_whitespace() {
        assert_eq!(
            normalize_name("  slate   badger  "),
            Some("slate badger".to_owned())
        );
    }

    #[test]
    fn normalize_rejects_empty_after_trim() {
        assert_eq!(normalize_name(""), None);
        assert_eq!(normalize_name("   "), None);
        assert_eq!(normalize_name("\t\n"), None);
    }

    #[test]
    fn normalize_clamps_to_max_len() {
        let raw = "a".repeat(MAX_NAME_LEN + 10);
        let got = normalize_name(&raw).expect("non-empty input normalizes");
        assert_eq!(got.chars().count(), MAX_NAME_LEN);
        assert_eq!(got, "a".repeat(MAX_NAME_LEN));
    }

    #[test]
    fn normalize_preserves_short_name() {
        assert_eq!(normalize_name("Ada"), Some("Ada".to_owned()));
    }

    #[test]
    fn pubkey_hex_accepts_64_lowercase_hex() {
        let pk = "a".repeat(64);
        assert!(is_pubkey_hex(&pk));
        let pk = "0123456789abcdef".repeat(4);
        assert!(is_pubkey_hex(&pk));
    }

    #[test]
    fn pubkey_hex_rejects_wrong_length() {
        assert!(!is_pubkey_hex(&"a".repeat(63)));
        assert!(!is_pubkey_hex(&"a".repeat(65)));
        assert!(!is_pubkey_hex(""));
    }

    #[test]
    fn pubkey_hex_rejects_uppercase_and_non_hex() {
        assert!(!is_pubkey_hex(&"A".repeat(64)));
        assert!(!is_pubkey_hex(&"g".repeat(64)));
        assert!(!is_pubkey_hex(&"z".repeat(64)));
    }
}
