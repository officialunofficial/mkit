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
        // Printable opaque identities (e.g. an imported git
        // `Name <email>` carried verbatim) render as their text — the
        // hex fallback below is for genuinely binary payloads.
        mkit_core::IdentityKind::Opaque if printable_text(&id.bytes).is_some() => {
            printable_text(&id.bytes).unwrap_or_default().to_owned()
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

/// The payload as text iff it is valid UTF-8 with no control
/// characters (terminal-safe to print verbatim).
fn printable_text(bytes: &[u8]) -> Option<&str> {
    let s = std::str::from_utf8(bytes).ok()?;
    (!s.is_empty() && !s.chars().any(char::is_control)).then_some(s)
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

/// Default abbreviation length for the git-style ref-update summary
/// lines (`<old7>..<new7>`). Matches `log --oneline`'s default; mkit ids
/// stay BLAKE3 prefixes (the documented hash-length divergence).
pub const SUMMARY_ABBREV: usize = 7;

/// A single git-style ref-update summary line, as printed under the
/// `To <url>` / `From <url>` header of a push or fetch. `old` is the
/// previous value of the destination ref (None = the ref did not exist),
/// `new` the value just written; `src -> dst` is the refspec mapping.
///
/// Shapes match git's `transport.c` for the single-ref case:
/// - new ref:   ` * [new branch]      <src> -> <dst>`
/// - forced:    ` + <old>...<new> <src> -> <dst> (forced update)`
/// - fast-fwd:  `   <old>..<new>  <src> -> <dst>`
///
/// Object ids are mkit BLAKE3 prefixes rather than git SHA-1 (documented
/// divergence); everything else is byte-shaped like git.
#[must_use]
pub fn ref_update_line(
    old: Option<&Hash>,
    new: &Hash,
    src: &str,
    dst: &str,
    forced: bool,
) -> String {
    let n = short_hash(new, SUMMARY_ABBREV);
    match old {
        None => format!(" * [new branch]      {src} -> {dst}"),
        Some(o) => {
            let o = short_hash(o, SUMMARY_ABBREV);
            if forced {
                format!(" + {o}...{n} {src} -> {dst} (forced update)")
            } else {
                format!("   {o}..{n}  {src} -> {dst}")
            }
        }
    }
}

/// The git-style rejected-ref summary line (non-fast-forward), printed
/// alongside the actionable hint when a push is refused.
#[must_use]
pub fn ref_rejected_line(src: &str, dst: &str) -> String {
    format!(" ! [rejected]        {src} -> {dst} (non-fast-forward)")
}

/// A minimal single-object JSON builder for `--format=json` on the
/// mutating commands (`commit`, `push`, `pull`, `fetch`, `merge`,
/// `cherry-pick`, `revert`, `rebase`, `stash`, `tag`, `verify-attest`):
/// each invocation emits exactly one JSON object to stdout describing
/// the outcome, unlike `log`/`branch`'s per-record JSONL streaming.
///
/// Keeps the same hand-rolled-escaping approach as the rest of this
/// module (`json_escape`) rather than pulling `serde_json` into the
/// CLI's presentation layer — see `branch.rs`/`log.rs` for the
/// precedent this mirrors. Fields are written in insertion order, so
/// callers should add them in a fixed, documented order to keep output
/// deterministic and snapshot-friendly.
#[derive(Debug, Default)]
pub struct JsonObject {
    buf: String,
    first: bool,
}

impl JsonObject {
    #[must_use]
    pub fn new() -> Self {
        Self {
            buf: String::from("{"),
            first: true,
        }
    }

    fn comma(&mut self) {
        if !self.first {
            self.buf.push(',');
        }
        self.first = false;
    }

    /// Append `"<key>":"<escaped value>"`.
    pub fn field_str(&mut self, key: &str, value: &str) -> &mut Self {
        self.comma();
        self.buf.push('"');
        self.buf.push_str(key);
        self.buf.push_str("\":\"");
        self.buf.push_str(&json_escape(value));
        self.buf.push('"');
        self
    }

    /// Append `"<key>":<hash-as-64-hex-string>"`.
    pub fn field_hash(&mut self, key: &str, h: &Hash) -> &mut Self {
        self.field_str(key, &hex_hash(h))
    }

    /// Append `"<key>":null` when `h` is `None`, else the hex hash.
    pub fn field_opt_hash(&mut self, key: &str, h: Option<&Hash>) -> &mut Self {
        match h {
            Some(h) => self.field_hash(key, h),
            None => self.field_raw(key, "null"),
        }
    }

    /// Append `"<key>":null` when `s` is `None`, else the escaped string.
    pub fn field_opt_str(&mut self, key: &str, s: Option<&str>) -> &mut Self {
        match s {
            Some(s) => self.field_str(key, s),
            None => self.field_raw(key, "null"),
        }
    }

    /// Append `"<key>":true`/`"<key>":false`.
    pub fn field_bool(&mut self, key: &str, v: bool) -> &mut Self {
        self.field_raw(key, if v { "true" } else { "false" })
    }

    /// Append `"<key>":<integer>`.
    pub fn field_u64(&mut self, key: &str, v: u64) -> &mut Self {
        use std::fmt::Write as _;
        self.comma();
        let _ = write!(self.buf, "\"{key}\":{v}");
        self
    }

    /// Append `"<key>":<raw>` verbatim — `raw` must already be valid
    /// JSON (a literal, number, array, or nested object built via a
    /// nested `JsonObject`/`json_string_array`).
    pub fn field_raw(&mut self, key: &str, raw: &str) -> &mut Self {
        self.comma();
        self.buf.push('"');
        self.buf.push_str(key);
        self.buf.push_str("\":");
        self.buf.push_str(raw);
        self
    }

    /// Consume the builder and return the closed `{...}` JSON text (no
    /// trailing newline — callers `writeln!` it).
    #[must_use]
    pub fn finish(mut self) -> String {
        self.buf.push('}');
        self.buf
    }
}

/// Render a slice of strings as a JSON array of escaped string
/// literals, e.g. for a `field_raw` value: `["a","b"]`.
#[must_use]
pub fn json_string_array<S: AsRef<str>>(items: &[S]) -> String {
    let mut out = String::from("[");
    for (i, s) in items.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('"');
        out.push_str(&json_escape(s.as_ref()));
        out.push('"');
    }
    out.push(']');
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
    fn ref_update_line_shapes_match_git() {
        let old = hash::hash(b"old");
        let new = hash::hash(b"new");
        let o7 = short_hash(&old, SUMMARY_ABBREV);
        let n7 = short_hash(&new, SUMMARY_ABBREV);
        // new branch (no old)
        assert_eq!(
            ref_update_line(None, &new, "main", "main", false),
            " * [new branch]      main -> main"
        );
        // fast-forward: `   <old>..<new>  src -> dst`
        assert_eq!(
            ref_update_line(Some(&old), &new, "main", "main", false),
            format!("   {o7}..{n7}  main -> main")
        );
        // forced: `+ <old>...<new> src -> dst (forced update)`
        assert_eq!(
            ref_update_line(Some(&old), &new, "main", "main", true),
            format!(" + {o7}...{n7} main -> main (forced update)")
        );
        // rejected
        assert_eq!(
            ref_rejected_line("main", "main"),
            " ! [rejected]        main -> main (non-fast-forward)"
        );
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

    #[test]
    fn json_object_empty() {
        assert_eq!(JsonObject::new().finish(), "{}");
    }

    #[test]
    fn json_object_fields_in_insertion_order() {
        let h = hash::hash(b"x");
        let mut obj = JsonObject::new();
        obj.field_bool("ok", true)
            .field_str("branch", "main")
            .field_hash("hash", &h)
            .field_opt_hash("parent", None)
            .field_opt_str("note", None)
            .field_u64("count", 3)
            .field_raw("items", &json_string_array(&["a", "b"]));
        let out = obj.finish();
        assert_eq!(
            out,
            format!(
                "{{\"ok\":true,\"branch\":\"main\",\"hash\":\"{}\",\"parent\":null,\"note\":null,\"count\":3,\"items\":[\"a\",\"b\"]}}",
                hex_hash(&h)
            )
        );
    }

    #[test]
    fn json_object_escapes_string_fields() {
        let mut obj = JsonObject::new();
        obj.field_str("message", "line one\nline \"two\"");
        assert_eq!(
            obj.finish(),
            "{\"message\":\"line one\\nline \\\"two\\\"\"}"
        );
    }

    #[test]
    fn json_string_array_empty_and_populated() {
        let empty: &[&str] = &[];
        assert_eq!(json_string_array(empty), "[]");
        assert_eq!(
            json_string_array(&["a.txt", "b.txt"]),
            "[\"a.txt\",\"b.txt\"]"
        );
    }
}
