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
