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
//!
//! `--format=json` emits one JSON object to stdout describing the
//! outcome (in addition to the stderr prose report above, which stays
//! unconditional):
//!
//! ```json
//! {
//!   "ok": <bool>,
//!   "commit": "<64-hex>",
//!   "error": "<string>|null",
//!   "attestations": [
//!     {
//!       "id": "<64-hex>|null",
//!       "error": "<string>|null",
//!       "signatures": [
//!         {"keyid": "...", "algorithm": "<string>|null", "verified": <bool>, "reason": "<string>|null"}
//!       ]
//!     }
//!   ]
//! }
//! ```
//!
//! `error` at the attestation level covers read/decode/subject-mismatch
//! failures (in which case `signatures` is empty); `error` at the
//! top level is set whenever `ok` is `false`.

use std::io::Write;
use std::path::PathBuf;

use clap::{Parser, ValueEnum};
use mkit_attest::envelope;
use mkit_attest::verify::{extract_primary_commit_hash, verify};
use mkit_attest::{Algorithm, store};
use mkit_core::hash::Hash;
use mkit_core::layout::RepoLayout;
use mkit_core::{hash as hash_mod, refs};

use crate::clap_shim;
use crate::exit;
use crate::format::JsonObject;

#[derive(Debug, Clone, Copy, ValueEnum)]
enum VerifyAttestFormat {
    Default,
    Json,
}

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
    /// Emit a machine-readable JSON result object to stdout alongside
    /// the human report on stderr.
    #[arg(long, value_enum, default_value = "default")]
    format: VerifyAttestFormat,
}

/// One reported signature verdict, collected for the JSON envelope.
struct SigRecord {
    keyid: String,
    algorithm: Option<String>,
    verified: bool,
    reason: Option<String>,
}

/// One reported attestation, collected for the JSON envelope. `error`
/// covers read/decode/subject-mismatch failures (mutually exclusive
/// with a populated `signatures`).
struct AttRecord {
    id: Option<Hash>,
    error: Option<String>,
    signatures: Vec<SigRecord>,
}

fn emit_json(commit: &Hash, ok: bool, error: Option<&str>, atts: &[AttRecord]) {
    let mut items = Vec::with_capacity(atts.len());
    for a in atts {
        let mut obj = JsonObject::new();
        obj.field_opt_hash("id", a.id.as_ref())
            .field_opt_str("error", a.error.as_deref());
        let mut sigs = Vec::with_capacity(a.signatures.len());
        for s in &a.signatures {
            let mut sobj = JsonObject::new();
            sobj.field_str("keyid", &s.keyid)
                .field_opt_str("algorithm", s.algorithm.as_deref())
                .field_bool("verified", s.verified)
                .field_opt_str("reason", s.reason.as_deref());
            sigs.push(sobj.finish());
        }
        obj.field_raw("signatures", &format!("[{}]", sigs.join(",")));
        items.push(obj.finish());
    }
    let mut top = JsonObject::new();
    top.field_bool("ok", ok)
        .field_hash("commit", commit)
        .field_opt_str("error", error)
        .field_raw("attestations", &format!("[{}]", items.join(",")));
    let mut stdout = std::io::stdout().lock();
    let _ = writeln!(stdout, "{}", top.finish());
}

#[must_use]
#[allow(clippy::too_many_lines)]
pub fn run(args: &[String]) -> u8 {
    let parsed = match clap_shim::parse::<Args>("mkit verify-attest", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    let json = matches!(parsed.format, VerifyAttestFormat::Json);
    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("cwd: {e}"), exit::NOINPUT),
    };
    let layout = match super::resolve_layout(&cwd) {
        Ok(layout) => layout,
        Err(code) => return code,
    };
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
    note_if_missing(&trust_path);
    // Below this point `commit_hash` is fixed, so error returns can
    // populate a `--format=json` payload; shadow `emit_err` with a
    // wrapper that also prints the JSON envelope when requested.
    let err = |msg: &str, code: u8| -> u8 {
        if json {
            emit_json(&commit_hash, false, Some(msg), &[]);
        }
        emit_err(msg, code)
    };

    let registry = match load_trust_roots(&trust_path) {
        Ok(r) => r,
        Err((msg, code)) => return err(&msg, code),
    };

    // --- Algorithm filter. ------------------------------------------
    let filter: Option<Algorithm> = match parsed.algorithm.as_deref() {
        Some(s) => match s.parse::<Algorithm>() {
            Ok(a) => Some(a),
            Err(_) => {
                return err(&format!("unknown algorithm filter '{s}'"), exit::USAGE);
            }
        },
        None => None,
    };

    // --- Enumerate envelopes. ---------------------------------------
    let envelopes = match store::list(&layout, &commit_hash) {
        Ok(v) => v,
        Err(e) => return err(&format!("list attestations: {e}"), exit::NOINPUT),
    };
    // All `verify-attest` report lines are human-readable prose; the
    // verdict is conveyed via the exit code (OK / DATAERR /
    // GENERAL_ERROR). Route the entire report to stderr — unconditional,
    // regardless of `--format=json` — while stdout carries the JSON
    // envelope (see `emit_json`).
    let mut report = std::io::stderr().lock();
    if envelopes.is_empty() {
        let msg = format!(
            "no attestations for commit {}",
            hash_mod::to_hex(&commit_hash)
        );
        let _ = writeln!(report, "{msg}");
        drop(report);
        if json {
            emit_json(&commit_hash, false, Some(&msg), &[]);
        }
        return exit::GENERAL_ERROR;
    }

    let _ = writeln!(
        report,
        "verifying {} attestation(s) for commit {}",
        envelopes.len(),
        hash_mod::to_hex(&commit_hash)
    );

    let mut all_ok = true;
    let mut atts: Vec<AttRecord> = Vec::with_capacity(envelopes.len());
    for path in &envelopes {
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => {
                let _ = writeln!(report, "  {}: read error: {e}", path.display());
                all_ok = false;
                atts.push(AttRecord {
                    id: None,
                    error: Some(format!("read error: {e}")),
                    signatures: Vec::new(),
                });
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
                atts.push(AttRecord {
                    id: Some(att_id),
                    error: Some(format!("malformed envelope: {e}")),
                    signatures: Vec::new(),
                });
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
                atts.push(AttRecord {
                    id: Some(att_id),
                    error: Some(format!("subject error: {e}")),
                    signatures: Vec::new(),
                });
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
            atts.push(AttRecord {
                id: Some(att_id),
                error: Some(format!(
                    "subject mismatch: statement names {}, requested {}",
                    hash_mod::to_hex(&subject_hash),
                    hash_mod::to_hex(&commit_hash)
                )),
                signatures: Vec::new(),
            });
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
                atts.push(AttRecord {
                    id: Some(att_id),
                    error: Some(format!("malformed envelope: {e}")),
                    signatures: Vec::new(),
                });
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
        // The JSON record carries EVERY signature (unfiltered) so an
        // agent parsing it never loses data to `--algorithm`; only the
        // human stderr report is filtered.
        let mut sig_records = Vec::with_capacity(result.signatures.len());
        for sig in &result.signatures {
            let alg = Algorithm::from_keyid(&sig.keyid);
            let alg_str = alg.map_or_else(|| "unknown".to_owned(), |a| a.to_string());
            sig_records.push(SigRecord {
                keyid: sig.keyid.clone(),
                algorithm: alg.map(|_| alg_str.clone()),
                verified: sig.verified,
                reason: (!sig.verified).then(|| format!("{:?}", sig.reason)),
            });
            if let (Some(filter_alg), Some(sig_alg)) = (filter, alg)
                && filter_alg != sig_alg
            {
                continue;
            }
            any_shown = true;
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
        atts.push(AttRecord {
            id: Some(att_id),
            error: None,
            signatures: sig_records,
        });
        if !any_shown && filter.is_some() {
            let _ = writeln!(report, "    (no signatures matched --algorithm filter)");
        }
        if !result.any_verified {
            all_ok = false;
        }
    }

    drop(report);
    if all_ok {
        if json {
            emit_json(&commit_hash, true, None, &atts);
        }
        {
            let mut stderr = std::io::stderr().lock();
            let _ = writeln!(stderr, "ok: all attestations verified");
        }
        exit::OK
    } else {
        if json {
            emit_json(
                &commit_hash,
                false,
                Some("at least one attestation failed verification"),
                &atts,
            );
        }
        {
            let mut stderr = std::io::stderr().lock();
            let _ = writeln!(stderr, "bad: at least one attestation failed verification");
        }
        exit::DATAERR
    }
}

// The trust-roots file format (`[[trust_root]]` TOML blocks), the
// in-repo path-fencing policy, and the keyid<->pubkey cross-check all
// live in `commands/trust_roots.rs` now — shared with `mkit trust
// add/list/remove` and `mkit verify --trusted` so the three never grow
// separate trust-file formats (issue #693). Pull the names this module
// still uses directly into scope; the `mod tests` block below resolves
// them via `use super::*`.
use super::trust_roots::{
    default_trust_roots_path, load_registry as load_trust_roots, note_if_missing, short_keyid,
    warn_if_unsafe_trust_roots,
};

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

use super::error as emit_err;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::trust_roots::keyid_matches_pubkey;
    use clap::Parser;
    use std::fs;
    use std::path::Path;

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
