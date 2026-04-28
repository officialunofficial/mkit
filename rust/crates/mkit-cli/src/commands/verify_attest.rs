//! `mkit verify-attest` — verify every attestation attached to a commit.
//!
//! ```text
//! mkit verify-attest [--commit <hash>] [--trust-roots <path>]
//!                    [--algorithm <filter>]
//! ```
//!
//! Trust-roots file (TOML, simple flat schema):
//!
//! ```toml
//! [[trust_root]]
//! keyid = "ed25519:..."
//! kind  = "ed25519"
//! pubkey_hex = "..."
//! ```
//!
//! * `kind` is one of `ed25519`, `secp256k1`, `p256-sec1`. Anything
//!   else is ignored with a warning.
//! * `pubkey_hex` is the raw public key bytes in lowercase hex.
//!
//! Exit code is 0 iff every listed attestation has `any_verified = true`,
//! nonzero otherwise.

use std::io::Write;
use std::path::{Path, PathBuf};

use mkit_attest::{Algorithm, Registry, TrustRoot, store, verify_envelope};
use mkit_core::hash::Hash;
use mkit_core::{hash as hash_mod, refs};

use crate::exit;

struct Args {
    commit: Option<String>,
    trust_roots: Option<String>,
    algorithm: Option<String>,
}

fn parse_args(args: &[String]) -> Result<Args, String> {
    let mut out = Args {
        commit: None,
        trust_roots: None,
        algorithm: None,
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--commit" if i + 1 < args.len() => {
                out.commit = Some(args[i + 1].clone());
                i += 2;
            }
            "--trust-roots" if i + 1 < args.len() => {
                out.trust_roots = Some(args[i + 1].clone());
                i += 2;
            }
            "--algorithm" if i + 1 < args.len() => {
                out.algorithm = Some(args[i + 1].clone());
                i += 2;
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    Ok(out)
}

#[must_use]
#[allow(clippy::too_many_lines)]
pub fn run(args: &[String]) -> u8 {
    let parsed = match parse_args(args) {
        Ok(p) => p,
        Err(e) => {
            return emit_err(
                &format!(
                    "{e}\nusage: mkit verify-attest [--commit <hash>] [--trust-roots <path>] [--algorithm <filter>]"
                ),
                exit::USAGE,
            );
        }
    };
    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("cwd: {e}"), exit::NOINPUT),
    };
    let mkit_dir = cwd.join(mkit_core::MKIT_DIR);
    if !mkit_dir.is_dir() {
        return emit_err("not a mkit repo", exit::GENERAL_ERROR);
    }

    // --- Resolve commit. --------------------------------------------
    let commit_hash = match resolve_commit(&mkit_dir, parsed.commit.as_deref()) {
        Ok(h) => h,
        Err((msg, code)) => return emit_err(&msg, code),
    };

    // --- Build Registry. --------------------------------------------
    //
    // Trust-roots default to the **user-scoped** path
    // `$XDG_CONFIG_HOME/mkit/trust-roots.toml`. A repo-local default
    // would let a hostile clone ship its own trust-roots and have
    // `mkit verify-attest` print "ok" against attacker keys; see
    // `docs/THREAT-MODEL.md` §"Trust-roots scope". An explicit
    // `--trust-roots <path>` always wins so CI flows can point at a
    // pinned file.
    let trust_path = parsed
        .trust_roots
        .as_deref()
        .map_or_else(default_trust_roots_path, PathBuf::from);
    if let Err(code) =
        warn_if_unsafe_trust_roots(&trust_path, &mkit_dir, parsed.trust_roots.is_some())
    {
        return code;
    }
    let registry = match load_trust_roots(&trust_path) {
        Ok(r) => r,
        Err((msg, code)) => return emit_err(&msg, code),
    };

    // --- Algorithm filter. ------------------------------------------
    let filter: Option<Algorithm> = match parsed.algorithm.as_deref() {
        Some(s) => match s.parse::<Algorithm>() {
            Ok(a) => Some(a),
            Err(_) => {
                return emit_err(&format!("unknown algorithm filter '{s}'"), exit::USAGE);
            }
        },
        None => None,
    };

    // --- Enumerate envelopes. ---------------------------------------
    let envelopes = match store::list(&mkit_dir, &commit_hash) {
        Ok(v) => v,
        Err(e) => return emit_err(&format!("list attestations: {e}"), exit::NOINPUT),
    };
    let mut stdout = std::io::stdout().lock();
    if envelopes.is_empty() {
        let _ = writeln!(
            stdout,
            "no attestations for commit {}",
            hash_mod::to_hex(&commit_hash)
        );
        return exit::GENERAL_ERROR;
    }

    let _ = writeln!(
        stdout,
        "verifying {} attestation(s) for commit {}",
        envelopes.len(),
        hash_mod::to_hex(&commit_hash)
    );

    let mut all_ok = true;
    for path in &envelopes {
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => {
                let _ = writeln!(stdout, "  {}: read error: {e}", path.display());
                all_ok = false;
                continue;
            }
        };
        let att_id = mkit_attest::attestation_id(&bytes);
        let result = match verify_envelope(&bytes, &registry) {
            Ok(r) => r,
            Err(e) => {
                let _ = writeln!(
                    stdout,
                    "  {}: malformed envelope: {e}",
                    hash_mod::to_hex(&att_id)
                );
                all_ok = false;
                continue;
            }
        };
        let _ = writeln!(
            stdout,
            "  attestation {}: {} signature(s)",
            hash_mod::to_hex(&att_id),
            result.signatures.len()
        );
        let mut any_shown = false;
        for sig in &result.signatures {
            let alg = Algorithm::from_keyid(&sig.keyid);
            if let (Some(filter_alg), Some(sig_alg)) = (filter, alg)
                && filter_alg != sig_alg
            {
                continue;
            }
            any_shown = true;
            let alg_str = alg.map_or_else(|| "unknown".to_owned(), |a| a.to_string());
            let verdict = if sig.verified {
                "verified".to_owned()
            } else {
                format!("FAILED ({:?})", sig.reason)
            };
            let _ = writeln!(
                stdout,
                "    [{alg_str}] {} — {verdict}",
                short_keyid(&sig.keyid)
            );
        }
        if !any_shown && filter.is_some() {
            let _ = writeln!(stdout, "    (no signatures matched --algorithm filter)");
        }
        if !result.any_verified {
            all_ok = false;
        }
    }

    if all_ok {
        let _ = writeln!(stdout, "ok: all attestations verified");
        exit::OK
    } else {
        let _ = writeln!(stdout, "bad: at least one attestation failed verification");
        exit::DATAERR
    }
}

/// Resolve the user-scoped default trust-roots path:
/// `$XDG_CONFIG_HOME/mkit/trust-roots.toml`.
fn default_trust_roots_path() -> PathBuf {
    crate::config::xdg_config_home().join("mkit/trust-roots.toml")
}

/// Refuse to verify against an in-repo trust-roots file unless the user
/// passed `--trust-roots` explicitly. Without this gate, a hostile
/// cloned repo could ship `<repo>/.mkit/attest-trust-roots.toml` listing
/// attacker keys and `mkit verify-attest` would print "ok".
fn warn_if_unsafe_trust_roots(
    trust_path: &Path,
    mkit_dir: &Path,
    user_provided_flag: bool,
) -> Result<(), u8> {
    if user_provided_flag {
        return Ok(());
    }
    if trust_path.starts_with(mkit_dir) {
        return Err(emit_err(
            &format!(
                "refusing to use in-repo trust-roots at {} — pass `--trust-roots` \
                 explicitly or move the file to {}",
                trust_path.display(),
                default_trust_roots_path().display()
            ),
            exit::CONFIG_ERROR,
        ));
    }
    if !trust_path.exists() {
        // Print a hint, but do NOT silently fall back to the in-repo
        // path. Empty registry → no signatures will pass; the loop
        // below prints the per-attestation failure.
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(
            stderr,
            "note: trust-roots file not found at {} — no keys loaded",
            trust_path.display()
        );
    }
    Ok(())
}

/// Shorten a keyid for display: `<prefix>:<first-16-hex>…`.
fn short_keyid(keyid: &str) -> String {
    match keyid.split_once(':') {
        Some((prefix, body)) if body.len() > 16 => {
            format!("{prefix}:{}…", &body[..16])
        }
        _ => keyid.to_owned(),
    }
}

fn resolve_commit(mkit_dir: &Path, flag: Option<&str>) -> Result<Hash, (String, u8)> {
    if let Some(hex) = flag {
        return hash_mod::from_hex(hex)
            .map_err(|e| (format!("bad --commit hash: {e}"), exit::DATAERR));
    }
    match refs::resolve_head(mkit_dir) {
        Ok(Some(h)) => Ok(h),
        Ok(None) => Err(("HEAD has no commit yet".to_owned(), exit::GENERAL_ERROR)),
        Err(e) => Err((format!("read HEAD: {e}"), exit::GENERAL_ERROR)),
    }
}

/// Hand-rolled TOML-ish parser for the trust-roots file. Recognised
/// grammar (a strict subset of TOML):
///
/// ```toml
/// [[trust_root]]
/// keyid = "..."
/// kind  = "ed25519"
/// pubkey_hex = "..."
/// ```
///
/// Lines outside a `[[trust_root]]` block, comments (`#`), and blank
/// lines are ignored. Missing-file case returns an empty registry —
/// the caller's signatures will all report `UnknownKeyid`, which is
/// the documented "no trust-roots configured" UX.
fn load_trust_roots(path: &Path) -> Result<Registry, (String, u8)> {
    let mut reg = Registry::new();
    let text = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(reg);
        }
        Err(e) => {
            return Err((format!("read {}: {e}", path.display()), exit::NOINPUT));
        }
    };

    let mut in_block = false;
    let mut keyid = String::new();
    let mut kind = String::new();
    let mut pubkey_hex = String::new();

    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line == "[[trust_root]]" {
            if in_block {
                flush_trust_root(&mut reg, &keyid, &kind, &pubkey_hex);
            }
            in_block = true;
            keyid.clear();
            kind.clear();
            pubkey_hex.clear();
            continue;
        }
        if !in_block {
            // Silently ignore top-level noise — keeps the parser tolerant.
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let key = k.trim();
        let val = v.trim().trim_matches('"').to_owned();
        match key {
            "keyid" => keyid = val,
            "kind" => kind = val,
            "pubkey_hex" => pubkey_hex = val,
            _ => {} // tolerate unknown keys
        }
    }
    if in_block {
        flush_trust_root(&mut reg, &keyid, &kind, &pubkey_hex);
    }
    Ok(reg)
}

fn flush_trust_root(reg: &mut Registry, keyid: &str, kind: &str, pubkey_hex: &str) {
    if keyid.is_empty() || pubkey_hex.is_empty() {
        return;
    }
    let Some(pk_bytes) = hex_decode(pubkey_hex) else {
        return;
    };
    match kind {
        "ed25519" if pk_bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&pk_bytes);
            reg.add(keyid.to_owned(), TrustRoot::Ed25519PubKey(arr));
        }
        "p256-sec1" | "p256" => {
            // mkit-attest default features enable algo-p256, so the
            // variant is always present in the public API.
            reg.add(keyid.to_owned(), TrustRoot::P256PubKeySec1(pk_bytes));
        }
        "secp256k1" | "secp256k1-sec1" => {
            reg.add(keyid.to_owned(), TrustRoot::Secp256k1PubKeySec1(pk_bytes));
        }
        _ => {
            // Unknown kind — skip.
        }
    }
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
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

fn emit_err(msg: &str, code: u8) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "error: {msg}");
    code
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn parse_args_defaults() {
        let p = parse_args(&[]).unwrap();
        assert!(p.commit.is_none());
        assert!(p.trust_roots.is_none());
        assert!(p.algorithm.is_none());
    }

    #[test]
    fn parse_args_accepts_all_flags() {
        let args = vec![
            "--commit".into(),
            "abc".into(),
            "--trust-roots".into(),
            "/tmp/tr.toml".into(),
            "--algorithm".into(),
            "p256".into(),
        ];
        let p = parse_args(&args).unwrap();
        assert_eq!(p.commit.as_deref(), Some("abc"));
        assert_eq!(p.trust_roots.as_deref(), Some("/tmp/tr.toml"));
        assert_eq!(p.algorithm.as_deref(), Some("p256"));
    }

    #[test]
    fn load_trust_roots_missing_file_returns_empty_registry() {
        let td = tempfile::tempdir().unwrap();
        let path = td.path().join("nope.toml");
        let reg = load_trust_roots(&path).unwrap();
        assert!(reg.lookup("anything").is_none());
    }

    #[test]
    fn load_trust_roots_parses_ed25519_block() {
        let td = tempfile::tempdir().unwrap();
        let path = td.path().join("tr.toml");
        let hex = "aa".repeat(32);
        fs::write(
            &path,
            format!(
                "[[trust_root]]\nkeyid = \"ed25519:abc\"\nkind = \"ed25519\"\npubkey_hex = \"{hex}\"\n"
            ),
        )
        .unwrap();
        let reg = load_trust_roots(&path).unwrap();
        assert!(reg.lookup("ed25519:abc").is_some());
    }

    #[test]
    fn load_trust_roots_tolerates_comments_and_blank_lines() {
        let td = tempfile::tempdir().unwrap();
        let path = td.path().join("tr.toml");
        let hex = "bb".repeat(32);
        fs::write(
            &path,
            format!(
                "# leading comment\n\n\
                 [[trust_root]]\n# mid-comment\n\
                 keyid = \"blake3:xyz\"\n\
                 kind = \"ed25519\"\n\
                 pubkey_hex = \"{hex}\"\n\n\n"
            ),
        )
        .unwrap();
        let reg = load_trust_roots(&path).unwrap();
        assert!(reg.lookup("blake3:xyz").is_some());
    }

    #[test]
    fn load_trust_roots_multiple_blocks() {
        let td = tempfile::tempdir().unwrap();
        let path = td.path().join("tr.toml");
        let hex_a = "aa".repeat(32);
        let hex_b = "cc".repeat(32);
        fs::write(
            &path,
            format!(
                "[[trust_root]]\nkeyid = \"ed25519:a\"\nkind = \"ed25519\"\npubkey_hex = \"{hex_a}\"\n\
                 [[trust_root]]\nkeyid = \"ed25519:b\"\nkind = \"ed25519\"\npubkey_hex = \"{hex_b}\"\n"
            ),
        )
        .unwrap();
        let reg = load_trust_roots(&path).unwrap();
        assert!(reg.lookup("ed25519:a").is_some());
        assert!(reg.lookup("ed25519:b").is_some());
    }

    #[test]
    fn short_keyid_abbreviates_long_hex() {
        let kid = "ed25519:".to_owned() + &"a".repeat(64);
        let short = short_keyid(&kid);
        assert!(short.starts_with("ed25519:"));
        assert!(short.ends_with('…'));
        assert!(short.len() < kid.len());
    }

    #[test]
    fn short_keyid_keeps_short_ones_intact() {
        assert_eq!(short_keyid("ed25519:abc"), "ed25519:abc");
    }
}
