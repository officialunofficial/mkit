//! Shared trust-roots TOML file model.
//!
//! Three call sites read/write the same `[[trust_root]]` file format:
//! `mkit trust {add,list,remove}` (`commands/trust.rs`), `mkit verify
//! --trusted`/`--trust-roots` (`commands/verify.rs`), and `mkit
//! verify-attest --trust-roots` (`commands/verify_attest.rs`). This
//! module owns the parser, the writer, and the repo-local path-fencing
//! policy so none of the three grow a second trust-file format
//! (issue #693).
//!
//! Grammar (a strict subset of TOML):
//!
//! ```toml
//! [[trust_root]]
//! keyid = "ed25519:..."
//! kind  = "ed25519"
//! pubkey_hex = "..."
//! ```
//!
//! * `kind` is one of `ed25519`, `secp256k1` (alias `secp256k1-sec1`),
//!   `p256-sec1` (alias `p256`), or `bls12381-thr`. Anything else is
//!   ignored.
//! * `algorithm` is accepted as an alias for `kind` (per
//!   `docs/specs/SPEC-RELEASE-THRESHOLD.md`); either field name works.
//! * `pubkey_hex` is the raw public key bytes in lowercase hex. For
//!   `bls12381-thr`, the bytes are the 96-byte G2 compressed
//!   aggregated cohort public key (the `MinSig` variant).
//!
//! Lines outside a `[[trust_root]]` block, comments (`#`), and blank
//! lines are ignored. A missing file parses to zero entries — the
//! caller's documented "no trust-roots configured" UX.

use std::io::Write;
use std::path::{Path, PathBuf};

use mkit_attest::{Registry, TrustRoot};

use crate::exit;

/// One validated `[[trust_root]]` block: hex-decoded is deferred to
/// the consumer (registry build / commit-signer compare) so callers
/// that only need to list or rewrite the file never touch key bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustEntry {
    pub keyid: String,
    pub kind: String,
    pub pubkey_hex: String,
}

/// Resolve the user-scoped default trust-roots path:
/// `$XDG_CONFIG_HOME/mkit/trust-roots.toml`.
#[must_use]
pub fn default_trust_roots_path() -> PathBuf {
    crate::config::xdg_config_home().join("mkit/trust-roots.toml")
}

/// Refuse to operate on an in-repo trust-roots file unless the user
/// passed `--trust-roots` explicitly. Without this gate, a hostile
/// cloned repo could ship `<repo>/.mkit/trust-roots.toml` listing
/// attacker keys and a trust-consuming command would trust it
/// implicitly. See `docs/THREAT-MODEL.md` §5 "Trust-roots scope".
pub fn warn_if_unsafe_trust_roots(
    trust_path: &Path,
    mkit_dir: &Path,
    user_provided_flag: bool,
) -> Result<(), u8> {
    if user_provided_flag {
        return Ok(());
    }
    if trust_path.starts_with(mkit_dir) {
        return Err(super::error(
            &format!(
                "refusing to use in-repo trust-roots at {} — pass `--trust-roots` \
                 explicitly or move the file to {}",
                trust_path.display(),
                default_trust_roots_path().display()
            ),
            exit::CONFIG_ERROR,
        ));
    }
    Ok(())
}

/// Print a hint (not an error) when a trust-roots path passed a safety
/// check but the file doesn't exist yet. An empty registry means every
/// signer check will fail closed; the caller's own report loop covers
/// the substance, this is just so a first-time user isn't left
/// wondering why nothing verified.
pub fn note_if_missing(trust_path: &Path) {
    if !trust_path.exists() {
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(
            stderr,
            "note: trust-roots file not found at {} — no keys loaded",
            trust_path.display()
        );
    }
}

/// Parse every `[[trust_root]]` block in `text`. Blocks with missing
/// `keyid`/`pubkey_hex`, unparsable hex, or a keyid/pubkey mismatch
/// (#223) are dropped with a stderr note rather than surfaced as a
/// hard error — matches `verify-attest`'s tolerant-parser policy.
#[must_use]
pub fn parse(text: &str) -> Vec<TrustEntry> {
    let mut out = Vec::new();
    let mut in_block = false;
    let mut keyid = String::new();
    let mut kind = String::new();
    let mut pubkey_hex = String::new();

    let flush = |keyid: &str, kind: &str, pubkey_hex: &str, out: &mut Vec<TrustEntry>| {
        if keyid.is_empty() || pubkey_hex.is_empty() {
            return;
        }
        let Some(pk_bytes) = hex_decode(pubkey_hex) else {
            return;
        };
        if !keyid_matches_pubkey(keyid, &pk_bytes) {
            let mut stderr = std::io::stderr().lock();
            let _ = writeln!(
                stderr,
                "note: trust-root '{}' dropped — keyid does not match its pubkey_hex",
                short_keyid(keyid)
            );
            return;
        }
        out.push(TrustEntry {
            keyid: keyid.to_owned(),
            kind: if kind.is_empty() {
                "ed25519".to_owned()
            } else {
                kind.to_owned()
            },
            pubkey_hex: pubkey_hex.to_owned(),
        });
    };

    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line == "[[trust_root]]" {
            if in_block {
                flush(&keyid, &kind, &pubkey_hex, &mut out);
            }
            in_block = true;
            keyid.clear();
            kind.clear();
            pubkey_hex.clear();
            continue;
        }
        if !in_block {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let key = k.trim();
        let val = v.trim().trim_matches('"').to_owned();
        match key {
            "keyid" => keyid = val,
            "kind" | "algorithm" => kind = val,
            "pubkey_hex" => pubkey_hex = val,
            _ => {}
        }
    }
    if in_block {
        flush(&keyid, &kind, &pubkey_hex, &mut out);
    }
    out
}

/// Load and parse the trust-roots file at `path`. A missing file
/// parses to an empty list (not an error).
pub fn load_entries(path: &Path) -> Result<Vec<TrustEntry>, (String, u8)> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(parse(&text)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err((format!("read {}: {e}", path.display()), exit::NOINPUT)),
    }
}

/// Load the trust-roots file at `path` into an `mkit-attest` [`Registry`],
/// for DSSE attestation verification (`mkit verify-attest`).
pub fn load_registry(path: &Path) -> Result<Registry, (String, u8)> {
    let entries = load_entries(path)?;
    let mut reg = Registry::new();
    for e in &entries {
        add_entry_to_registry(&mut reg, e);
    }
    Ok(reg)
}

fn add_entry_to_registry(reg: &mut Registry, e: &TrustEntry) {
    let Some(pk_bytes) = hex_decode(&e.pubkey_hex) else {
        return;
    };
    match e.kind.as_str() {
        "ed25519" if pk_bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&pk_bytes);
            reg.add(e.keyid.clone(), TrustRoot::Ed25519PubKey(arr));
        }
        "p256-sec1" | "p256" => {
            reg.add(e.keyid.clone(), TrustRoot::P256PubKeySec1(pk_bytes));
        }
        "secp256k1" | "secp256k1-sec1" => {
            reg.add(e.keyid.clone(), TrustRoot::Secp256k1PubKeySec1(pk_bytes));
        }
        #[cfg(feature = "bls-threshold")]
        "bls12381-thr" if pk_bytes.len() == mkit_attest::BLS_THRESHOLD_PUBLIC_KEY_SIZE => {
            reg.add(
                e.keyid.clone(),
                TrustRoot::Bls12381ThresholdPubKey(pk_bytes),
            );
        }
        _ => {}
    }
}

/// Does `entries` contain a live `ed25519` trust root whose pubkey
/// bytes equal `signer`? Used by `mkit verify --trusted` to cross-check
/// a commit/remix/tag's embedded `signer` field — commit signing is
/// Ed25519-only today (issue #693 implementation notes).
///
/// Returns the matching entry's `keyid` on success.
#[must_use]
pub fn find_ed25519_signer<'a>(entries: &'a [TrustEntry], signer: &[u8; 32]) -> Option<&'a str> {
    entries.iter().find_map(|e| {
        if e.kind != "ed25519" {
            return None;
        }
        let bytes = hex_decode(&e.pubkey_hex)?;
        if bytes.len() == 32 && bytes == signer {
            Some(e.keyid.as_str())
        } else {
            None
        }
    })
}

/// Serialize `entries` back to the `[[trust_root]]` file grammar.
/// Round-trips through `parse` (modulo comments — this rewrites the
/// whole file, so any hand-added comments in a file `mkit trust`
/// subsequently edits are NOT preserved).
#[must_use]
pub fn serialize(entries: &[TrustEntry]) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    for e in entries {
        out.push_str("[[trust_root]]\n");
        let _ = writeln!(out, "keyid = \"{}\"", e.keyid);
        let _ = writeln!(out, "kind = \"{}\"", e.kind);
        let _ = writeln!(out, "pubkey_hex = \"{}\"", e.pubkey_hex);
        out.push('\n');
    }
    out
}

/// Write `entries` to `path`, creating parent directories as needed.
pub fn save(path: &Path, entries: &[TrustEntry]) -> Result<(), (String, u8)> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .map_err(|e| (format!("create {}: {e}", parent.display()), exit::CANTCREAT))?;
    }
    std::fs::write(path, serialize(entries))
        .map_err(|e| (format!("write {}: {e}", path.display()), exit::CANTCREAT))
}

/// Cross-check (#223) that `keyid` is consistent with the declared
/// public key bytes. The canonical keyid shape is `<prefix>:<body>`:
///
/// - `blake3:<hex>` — body is `blake3(pubkey)`; verify the digest.
/// - `ed25519` / `secp256k1` / `p256` / `bls12381-thr:<hex>` — body is
///   the raw lowercase-hex pubkey; verify it equals `pubkey_hex`.
/// - Anything else (unknown prefix, no `:` separator) is left
///   uncross-checked here — return `true` so forward-compatible
///   keyids are not dropped.
#[must_use]
pub fn keyid_matches_pubkey(keyid: &str, pubkey: &[u8]) -> bool {
    let Some((prefix, body)) = keyid.split_once(':') else {
        return true;
    };
    let body = body.to_ascii_lowercase();
    match prefix {
        "blake3" => {
            let digest = mkit_core::hash::hash(pubkey);
            body == mkit_core::hash::to_hex(&digest)
        }
        "ed25519" | "secp256k1" | "p256" | "bls12381-thr" => {
            body == mkit_core::hash::to_hex_bytes(pubkey)
        }
        _ => true,
    }
}

/// Shorten a keyid for display: `<prefix>:<first-16-hex>…`.
#[must_use]
pub fn short_keyid(keyid: &str) -> String {
    match keyid.split_once(':') {
        Some((prefix, body)) if body.len() > 16 => {
            format!("{prefix}:{}…", &body[..16])
        }
        _ => keyid.to_owned(),
    }
}

#[must_use]
pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let hi = nibble(b[i])?;
        let lo = nibble(b[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Some(out)
}

fn nibble(c: u8) -> Option<u8> {
    Some(match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => 10 + c - b'a',
        b'A'..=b'F' => 10 + c - b'A',
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_missing_file_is_empty() {
        assert!(parse("").is_empty());
    }

    #[test]
    fn parse_round_trips_through_serialize() {
        let hex = "aa".repeat(32);
        let keyid = format!("ed25519:{hex}");
        let text = format!(
            "[[trust_root]]\nkeyid = \"{keyid}\"\nkind = \"ed25519\"\npubkey_hex = \"{hex}\"\n"
        );
        let entries = parse(&text);
        assert_eq!(entries.len(), 1);
        let re_serialized = serialize(&entries);
        let re_parsed = parse(&re_serialized);
        assert_eq!(entries, re_parsed);
    }

    #[test]
    fn parse_drops_keyid_pubkey_mismatch() {
        let keyid_hex = "aa".repeat(32);
        let wrong_pubkey = "bb".repeat(32);
        let keyid = format!("ed25519:{keyid_hex}");
        let text = format!(
            "[[trust_root]]\nkeyid = \"{keyid}\"\nkind = \"ed25519\"\npubkey_hex = \"{wrong_pubkey}\"\n"
        );
        assert!(parse(&text).is_empty());
    }

    #[test]
    fn find_ed25519_signer_matches_pubkey_bytes_not_keyid() {
        let pk = [0x42u8; 32];
        let hex = mkit_core::hash::to_hex_bytes(&pk);
        // Deliberately use a human label instead of the "ed25519:<hex>"
        // convention — the commit-trust check must key off pubkey
        // bytes, not a specific keyid shape.
        let entries = vec![TrustEntry {
            keyid: "alice-laptop".to_owned(),
            kind: "ed25519".to_owned(),
            pubkey_hex: hex,
        }];
        assert_eq!(find_ed25519_signer(&entries, &pk), Some("alice-laptop"));
        assert_eq!(find_ed25519_signer(&entries, &[0u8; 32]), None);
    }

    #[test]
    fn warn_if_unsafe_trust_roots_refuses_in_repo_path_without_explicit_flag() {
        let mkit_dir = Path::new("/repo/.mkit");
        let trust_path = mkit_dir.join("trust-roots.toml");
        let err = warn_if_unsafe_trust_roots(&trust_path, mkit_dir, false).unwrap_err();
        assert_eq!(err, exit::CONFIG_ERROR);
    }

    #[test]
    fn warn_if_unsafe_trust_roots_allows_explicit_flag() {
        let mkit_dir = Path::new("/repo/.mkit");
        let trust_path = mkit_dir.join("trust-roots.toml");
        warn_if_unsafe_trust_roots(&trust_path, mkit_dir, true).unwrap();
    }

    #[test]
    fn save_then_load_round_trips() {
        let td = tempfile::tempdir().unwrap();
        let path = td.path().join("tr.toml");
        let hex = "cc".repeat(32);
        let entries = vec![TrustEntry {
            keyid: format!("ed25519:{hex}"),
            kind: "ed25519".to_owned(),
            pubkey_hex: hex,
        }];
        save(&path, &entries).unwrap();
        let loaded = load_entries(&path).unwrap();
        assert_eq!(loaded, entries);
    }
}
