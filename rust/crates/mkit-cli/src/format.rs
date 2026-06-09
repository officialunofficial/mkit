//! Human-oriented output formatters — the CLI's thin presentation
//! layer. Anything that emits canonical on-disk or wire bytes belongs
//! in `mkit-core` (`serialize.rs`, `pack.rs`, etc.), not here.

use mkit_core::hash::Hash;

/// Render a [`Hash`](tyalias@mkit_core::Hash) as 64 lowercase hex chars. Wrapper over
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
        // A DidKey payload is a printable-ASCII multibase string, so show a
        // readable prefix of it (e.g. `did:key:z6MkExam`) rather than hex.
        mkit_core::IdentityKind::DidKey => {
            let s = String::from_utf8_lossy(&id.bytes);
            let prefix: String = s.chars().take(8).collect();
            format!("did:key:{prefix}")
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
/// Format mirrors the parser shorthands accepted by `mkit config
/// user.identity` / `--author` so a value emitted here round-trips:
/// `ed25519:<full-hex>`, `did:key:<multibase>` (the payload verbatim,
/// matching `--author did:key:…`), `mid:<decimal-u64>` for 8-byte opaque
/// keys, and `opaque:<full-hex>` for other opaque lengths.
#[must_use]
pub fn full_identity(id: &mkit_core::Identity) -> String {
    match id.kind {
        mkit_core::IdentityKind::Opaque if id.bytes.len() == 8 => {
            let mut arr = [0u8; 8];
            arr.copy_from_slice(&id.bytes);
            format!("mid:{}", u64::from_le_bytes(arr))
        }
        mkit_core::IdentityKind::Ed25519 => format!("ed25519:{}", to_hex(&id.bytes)),
        // DidKey bytes are the multibase payload (printable ASCII); emit it
        // verbatim so it round-trips through `--author did:key:<multibase>`.
        mkit_core::IdentityKind::DidKey => {
            format!("did:key:{}", String::from_utf8_lossy(&id.bytes))
        }
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

/// Render a Unix timestamp (seconds since the epoch, UTC) as a stable,
/// human-readable string: `YYYY-MM-DD HH:MM:SS +0000`.
///
/// The format is fixed UTC (`+0000`) and intentionally locale- and
/// timezone-independent so log output is reproducible across machines.
/// Machine-readable callers (e.g. `mkit log --format=json`) keep the
/// raw integer instead — only the default human log uses this.
///
/// Implemented with Howard Hinnant's civil-from-days algorithm to avoid
/// pulling in a date/time crate. Valid for the entire `u64` range.
#[must_use]
pub fn human_date_utc(secs: u64) -> String {
    let days = i64::try_from(secs / 86_400).unwrap_or(i64::MAX);
    let rem = secs % 86_400;
    let hour = rem / 3_600;
    let minute = (rem % 3_600) / 60;
    let second = rem % 60;

    // Civil date from a day count relative to 1970-01-01 (Hinnant).
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let day = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = if month <= 2 { y + 1 } else { y };

    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02} +0000")
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
    fn human_date_utc_epoch() {
        assert_eq!(human_date_utc(0), "1970-01-01 00:00:00 +0000");
    }

    #[test]
    fn human_date_utc_known_instant() {
        // 1700000000 = 2023-11-14 22:13:20 UTC.
        assert_eq!(human_date_utc(1_700_000_000), "2023-11-14 22:13:20 +0000");
    }

    #[test]
    fn human_date_utc_leap_day() {
        // 1582934400 = 2020-02-29 00:00:00 UTC (leap day).
        assert_eq!(human_date_utc(1_582_934_400), "2020-02-29 00:00:00 +0000");
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
