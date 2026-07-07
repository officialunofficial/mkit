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
//! * `kind` is one of `ed25519`, `secp256k1` (alias `secp256k1-sec1`),
//!   `p256-sec1` (alias `p256`), or `bls12381-thr`. Anything else is
//!   ignored.
//! * `algorithm` is accepted as an alias for `kind` (per
//!   `docs/specs/SPEC-RELEASE-THRESHOLD.md`); either field name works.
//! * `pubkey_hex` is the raw public key bytes in lowercase hex. For
//!   `bls12381-thr`, the bytes are the 96-byte G2 compressed
//!   aggregated cohort public key (the `MinSig` variant).
//!
//! Exit code is 0 iff every listed attestation is bound to the requested
//! commit and has `any_verified = true`, nonzero otherwise.

use std::io::Write;
use std::path::{Path, PathBuf};

use clap::Parser;
use mkit_attest::envelope;
use mkit_attest::verify::{extract_primary_commit_hash, verify};
use mkit_attest::{Algorithm, Registry, TrustRoot, store};
use mkit_core::hash::Hash;
use mkit_core::layout::RepoLayout;
use mkit_core::{hash as hash_mod, refs};

use crate::clap_shim;
use crate::exit;

#[derive(Debug, Parser)]
#[command(
    name = "mkit verify-attest",
    about = "Verify every attestation attached to a commit."
)]
struct Args {
    /// Commit hash to verify attestations for. Defaults to HEAD.
    #[arg(long, value_name = "HASH")]
    commit: Option<String>,
    /// Path to a trust-roots TOML file.
    #[arg(long, value_name = "PATH")]
    trust_roots: Option<String>,
    /// Filter signatures by algorithm.
    #[arg(long, value_name = "ALG")]
    algorithm: Option<String>,
}

#[must_use]
#[allow(clippy::too_many_lines)]
pub fn run(args: &[String]) -> u8 {
    let parsed = match clap_shim::parse::<Args>("mkit verify-attest", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("cwd: {e}"), exit::NOINPUT),
    };
    let layout = super::resolve_layout(&cwd);
    if !layout.common_dir().is_dir() {
        return emit_err("not a mkit repo", exit::GENERAL_ERROR);
    }

    // --- Resolve commit. --------------------------------------------
    let commit_hash = match resolve_commit(&layout, parsed.commit.as_deref()) {
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
    if let Err(code) = warn_if_unsafe_trust_roots(
        &trust_path,
        layout.common_dir(),
        parsed.trust_roots.is_some(),
    ) {
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
    let envelopes = match store::list(&layout, &commit_hash) {
        Ok(v) => v,
        Err(e) => return emit_err(&format!("list attestations: {e}"), exit::NOINPUT),
    };
    // All `verify-attest` report lines are human-readable prose; the
    // verdict is conveyed via the exit code (OK / DATAERR /
    // GENERAL_ERROR). Route the entire report to stderr so stdout
    // stays clean for a future `--format=json` output mode.
    let mut report = std::io::stderr().lock();
    if envelopes.is_empty() {
        let _ = writeln!(
            report,
            "no attestations for commit {}",
            hash_mod::to_hex(&commit_hash)
        );
        return exit::GENERAL_ERROR;
    }

    let _ = writeln!(
        report,
        "verifying {} attestation(s) for commit {}",
        envelopes.len(),
        hash_mod::to_hex(&commit_hash)
    );

    let mut all_ok = true;
    for path in &envelopes {
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => {
                let _ = writeln!(report, "  {}: read error: {e}", path.display());
                all_ok = false;
                continue;
            }
        };
        let att_id = mkit_attest::attestation_id(&bytes);
        let env = match envelope::decode(&bytes) {
            Ok(env) => env,
            Err(e) => {
                let _ = writeln!(
                    report,
                    "  {}: malformed envelope: {e}",
                    hash_mod::to_hex(&att_id)
                );
                all_ok = false;
                continue;
            }
        };
        let subject_hash = match extract_primary_commit_hash(&env.payload) {
            Ok(subject_hash) => subject_hash,
            Err(e) => {
                let _ = writeln!(
                    report,
                    "  {}: subject error: {e}",
                    hash_mod::to_hex(&att_id)
                );
                all_ok = false;
                continue;
            }
        };
        if subject_hash != commit_hash {
            let _ = writeln!(
                report,
                "  {}: subject mismatch: statement names {}, requested {}",
                hash_mod::to_hex(&att_id),
                hash_mod::to_hex(&subject_hash),
                hash_mod::to_hex(&commit_hash)
            );
            all_ok = false;
            continue;
        }
        let result = match verify(&env, &registry) {
            Ok(r) => r,
            Err(e) => {
                let _ = writeln!(
                    report,
                    "  {}: malformed envelope: {e}",
                    hash_mod::to_hex(&att_id)
                );
                all_ok = false;
                continue;
            }
        };
        let _ = writeln!(
            report,
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
                report,
                "    [{alg_str}] {} — {verdict}",
                short_keyid(&sig.keyid)
            );
        }
        if !any_shown && filter.is_some() {
            let _ = writeln!(report, "    (no signatures matched --algorithm filter)");
        }
        if !result.any_verified {
            all_ok = false;
        }
    }

    if all_ok {
        let _ = writeln!(report, "ok: all attestations verified");
        exit::OK
    } else {
        let _ = writeln!(report, "bad: at least one attestation failed verification");
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

fn resolve_commit(layout: &RepoLayout, flag: Option<&str>) -> Result<Hash, (String, u8)> {
    if let Some(hex) = flag {
        return hash_mod::from_hex(hex)
            .map_err(|e| (format!("bad --commit hash: {e}"), exit::DATAERR));
    }
    match refs::resolve_head(layout) {
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
            // `algorithm` is an alias for `kind` to match the wording
            // in `docs/specs/SPEC-RELEASE-THRESHOLD.md` §6. Either field
            // name parses to the same arm.
            "kind" | "algorithm" => kind = val,
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
    // #223: cross-check the keyid against the declared pubkey so a
    // trust-roots file that lists keyid `secp256k1:<A>` next to
    // `pubkey_hex = <B>` (a copy-paste mix-up that would silently trust
    // the wrong key) is rejected rather than loaded. Skip the entry on a
    // mismatch — `verify-attest` then reports the keyid as
    // `UnknownKeyid` instead of verifying against the wrong pubkey.
    if !keyid_matches_pubkey(keyid, &pk_bytes) {
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(
            stderr,
            "note: trust-root '{}' dropped — keyid does not match its pubkey_hex",
            short_keyid(keyid)
        );
        return;
    }
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
        // BLS12-381 threshold cohort public key — see
        // `docs/specs/SPEC-RELEASE-THRESHOLD.md` §6. The `bls12381-thr`
        // prefix matches the canonical algorithm tag returned by
        // `mkit_attest::Algorithm::prefix`. Pinned to the 96-byte
        // MinSig G2 compressed encoding; anything else is dropped.
        #[cfg(feature = "bls-threshold")]
        "bls12381-thr" if pk_bytes.len() == mkit_attest::BLS_THRESHOLD_PUBLIC_KEY_SIZE => {
            reg.add(
                keyid.to_owned(),
                TrustRoot::Bls12381ThresholdPubKey(pk_bytes),
            );
        }
        _ => {
            // Unknown kind — skip.
        }
    }
}

/// Cross-check (#223) that the keyid is consistent with the declared
/// public key bytes. The canonical keyid shape is `<prefix>:<body>`:
///
/// - `blake3:<hex>` — body is `blake3(pubkey)`; verify the digest.
/// - `ed25519` / `secp256k1` / `p256` / `bls12381-thr:<hex>` — body is
///   the raw lowercase-hex pubkey; verify it equals `pubkey_hex`.
/// - Anything else (unknown prefix, no `:` separator) is left to the
///   downstream `kind`-based loader and not cross-checked here — return
///   `true` so forward-compatible keyids are not dropped.
fn keyid_matches_pubkey(keyid: &str, pubkey: &[u8]) -> bool {
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
        // Unknown / opaque (e.g. `sigstore:`) keyids carry no embedded
        // pubkey to compare against.
        _ => true,
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

use super::error as emit_err;

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use std::fs;

    /// Test-only adapter: drive the clap-derive parser with just the
    /// trailing args.
    fn parse_args(args: &[String]) -> Result<Args, clap::Error> {
        let mut full: Vec<String> = vec!["mkit verify-attest".into()];
        full.extend_from_slice(args);
        Args::try_parse_from(full)
    }

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
    fn warn_if_unsafe_trust_roots_refuses_in_repo_path_without_explicit_flag() {
        // A hostile clone shipping `<repo>/.mkit/attest-trust-roots.toml`
        // must not be trusted implicitly — only an explicit
        // `--trust-roots` flag can point at an in-repo path.
        let mkit_dir = Path::new("/repo/.mkit");
        let trust_path = mkit_dir.join("attest-trust-roots.toml");
        let err = warn_if_unsafe_trust_roots(&trust_path, mkit_dir, false).unwrap_err();
        assert_eq!(err, exit::CONFIG_ERROR);
    }

    #[test]
    fn warn_if_unsafe_trust_roots_allows_in_repo_path_when_explicitly_passed() {
        let mkit_dir = Path::new("/repo/.mkit");
        let trust_path = mkit_dir.join("attest-trust-roots.toml");
        warn_if_unsafe_trust_roots(&trust_path, mkit_dir, true)
            .expect("an explicit --trust-roots flag must be honored even in-repo");
    }

    #[test]
    fn warn_if_unsafe_trust_roots_allows_user_scoped_path_without_flag() {
        let mkit_dir = Path::new("/repo/.mkit");
        let trust_path = Path::new("/home/user/.config/mkit/trust-roots.toml");
        warn_if_unsafe_trust_roots(trust_path, mkit_dir, false)
            .expect("a path outside the repo is never the in-repo hazard this gate guards against");
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
        // Canonical ed25519 keyid embeds the raw pubkey hex as its body.
        let hex = "aa".repeat(32);
        let keyid = format!("ed25519:{hex}");
        fs::write(
            &path,
            format!(
                "[[trust_root]]\nkeyid = \"{keyid}\"\nkind = \"ed25519\"\npubkey_hex = \"{hex}\"\n"
            ),
        )
        .unwrap();
        let reg = load_trust_roots(&path).unwrap();
        assert!(reg.lookup(&keyid).is_some());
    }

    #[test]
    fn load_trust_roots_tolerates_comments_and_blank_lines() {
        let td = tempfile::tempdir().unwrap();
        let path = td.path().join("tr.toml");
        // `blake3:` keyid embeds blake3(pubkey); compute it so the
        // keyid↔pubkey cross-check passes.
        let pk = [0xbbu8; 32];
        let hex = mkit_core::hash::to_hex_bytes(&pk);
        let digest = mkit_core::hash::to_hex(&mkit_core::hash::hash(&pk));
        let keyid = format!("blake3:{digest}");
        fs::write(
            &path,
            format!(
                "# leading comment\n\n\
                 [[trust_root]]\n# mid-comment\n\
                 keyid = \"{keyid}\"\n\
                 kind = \"ed25519\"\n\
                 pubkey_hex = \"{hex}\"\n\n\n"
            ),
        )
        .unwrap();
        let reg = load_trust_roots(&path).unwrap();
        assert!(reg.lookup(&keyid).is_some());
    }

    #[test]
    fn load_trust_roots_multiple_blocks() {
        let td = tempfile::tempdir().unwrap();
        let path = td.path().join("tr.toml");
        let hex_a = "aa".repeat(32);
        let hex_b = "cc".repeat(32);
        let keyid_a = format!("ed25519:{hex_a}");
        let keyid_b = format!("ed25519:{hex_b}");
        fs::write(
            &path,
            format!(
                "[[trust_root]]\nkeyid = \"{keyid_a}\"\nkind = \"ed25519\"\npubkey_hex = \"{hex_a}\"\n\
                 [[trust_root]]\nkeyid = \"{keyid_b}\"\nkind = \"ed25519\"\npubkey_hex = \"{hex_b}\"\n"
            ),
        )
        .unwrap();
        let reg = load_trust_roots(&path).unwrap();
        assert!(reg.lookup(&keyid_a).is_some());
        assert!(reg.lookup(&keyid_b).is_some());
    }

    #[test]
    fn load_trust_roots_drops_keyid_pubkey_mismatch() {
        // #223: keyid embeds pubkey `aa..`, but pubkey_hex says `bb..`.
        // The entry must be dropped, not silently trusted.
        let td = tempfile::tempdir().unwrap();
        let path = td.path().join("tr.toml");
        let keyid_hex = "aa".repeat(32);
        let wrong_pubkey = "bb".repeat(32);
        let keyid = format!("ed25519:{keyid_hex}");
        fs::write(
            &path,
            format!(
                "[[trust_root]]\nkeyid = \"{keyid}\"\nkind = \"ed25519\"\npubkey_hex = \"{wrong_pubkey}\"\n"
            ),
        )
        .unwrap();
        let reg = load_trust_roots(&path).unwrap();
        assert!(reg.lookup(&keyid).is_none());
    }

    #[test]
    fn keyid_matches_pubkey_canonical_and_blake3() {
        let pk = [0x11u8; 32];
        let hex = mkit_core::hash::to_hex_bytes(&pk);
        assert!(keyid_matches_pubkey(&format!("ed25519:{hex}"), &pk));
        assert!(keyid_matches_pubkey(&format!("secp256k1:{hex}"), &pk));
        let digest = mkit_core::hash::to_hex(&mkit_core::hash::hash(&pk));
        assert!(keyid_matches_pubkey(&format!("blake3:{digest}"), &pk));
        // Opaque / unknown prefixes are not cross-checked.
        assert!(keyid_matches_pubkey("sigstore:https://x", &pk));
        // Mismatched body is rejected.
        assert!(!keyid_matches_pubkey("ed25519:dead", &pk));
    }

    /// `[[trust_root]]` blocks with `kind = "bls12381-thr"` (or the
    /// `algorithm = "bls12381-thr"` alias) load into the registry as
    /// `TrustRoot::Bls12381ThresholdPubKey` and verify-dispatch picks
    /// them up. Pinned to the 96-byte `MinSig` G2 compressed length —
    /// anything shorter is silently dropped (per the parser's
    /// tolerate-and-skip policy).
    #[cfg(feature = "bls-threshold")]
    #[test]
    fn load_trust_roots_parses_bls_threshold_block() {
        let td = tempfile::tempdir().unwrap();
        let path = td.path().join("tr.toml");
        // 96 bytes of dummy hex — exact length matches MinSig G2
        // compressed encoding.
        let hex = "ab".repeat(96);
        fs::write(
            &path,
            format!(
                "[[trust_root]]\n\
                 keyid = \"bls12381-thr:{hex}\"\n\
                 kind = \"bls12381-thr\"\n\
                 pubkey_hex = \"{hex}\"\n"
            ),
        )
        .unwrap();
        let reg = load_trust_roots(&path).unwrap();
        let lookup = format!("bls12381-thr:{hex}");
        assert!(reg.lookup(&lookup).is_some());
    }

    /// Spec wording in `docs/specs/SPEC-RELEASE-THRESHOLD.md` says
    /// `algorithm = "bls12381-thr"`; the parser accepts that as an
    /// alias for `kind` to keep both forms compatible.
    #[cfg(feature = "bls-threshold")]
    #[test]
    fn load_trust_roots_accepts_algorithm_alias() {
        let td = tempfile::tempdir().unwrap();
        let path = td.path().join("tr.toml");
        let hex = "cd".repeat(96);
        fs::write(
            &path,
            format!(
                "[[trust_root]]\n\
                 keyid = \"bls12381-thr:{hex}\"\n\
                 algorithm = \"bls12381-thr\"\n\
                 pubkey_hex = \"{hex}\"\n"
            ),
        )
        .unwrap();
        let reg = load_trust_roots(&path).unwrap();
        assert!(reg.lookup(&format!("bls12381-thr:{hex}")).is_some());
    }

    /// Wrong-length BLS public key (e.g. someone mistakenly pasted a
    /// G1 sig or a truncated key) is silently dropped — the
    /// `verify-attest` run will then surface the keyid as
    /// `UnknownKeyid` rather than panic on a malformed registry.
    #[cfg(feature = "bls-threshold")]
    #[test]
    fn load_trust_roots_skips_wrong_length_bls_pubkey() {
        let td = tempfile::tempdir().unwrap();
        let path = td.path().join("tr.toml");
        let short = "ee".repeat(32); // 32 bytes, not 96
        let keyid = "bls12381-thr:abc";
        fs::write(
            &path,
            format!(
                "[[trust_root]]\n\
                 keyid = \"{keyid}\"\n\
                 kind = \"bls12381-thr\"\n\
                 pubkey_hex = \"{short}\"\n"
            ),
        )
        .unwrap();
        let reg = load_trust_roots(&path).unwrap();
        assert!(reg.lookup(keyid).is_none());
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
