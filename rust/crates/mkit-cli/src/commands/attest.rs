//! `mkit attest` — produce a signed DSSE attestation for a commit.
//!
//! ```text
//! mkit attest [--commit <hash>] [--algorithm ed25519|secp256k1|p256]
//!             [--signer repo-key|external]
//!             [--predicate-type <URI>] [--predicate-file <path>]
//! ```
//!
//! Defaults:
//! * `--commit` — HEAD.
//! * `--algorithm` — `attest.default_algorithm` in config, else `ed25519`.
//! * `--signer` — `attest.signer` in config, else `repo-key`.
//! * `--predicate-type` — `https://mkit.io/predicate/empty/v1`.
//! * `--predicate-file` — omitted ⇒ `{}`.
//!
//! On success, prints the att-id (64 hex chars) and exits 0.

use std::io::Write;
use std::path::Path;

use mkit_attest::{Envelope, PAYLOAD_TYPE_IN_TOTO, Sig, statement, store};
use mkit_core::hash::Hash;
use mkit_core::{hash as hash_mod, refs};

use crate::commands::attest_factory::{self, FactoryError};
use crate::exit;

/// Default predicate type URI — placeholder; real callers pass their own.
const DEFAULT_PREDICATE_TYPE: &str = "https://mkit.io/predicate/empty/v1";

struct Args {
    commit: Option<String>,
    algorithm: Option<String>,
    signer: Option<String>,
    predicate_type: Option<String>,
    predicate_file: Option<String>,
}

fn parse_args(args: &[String]) -> Result<Args, String> {
    let mut out = Args {
        commit: None,
        algorithm: None,
        signer: None,
        predicate_type: None,
        predicate_file: None,
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--commit" if i + 1 < args.len() => {
                out.commit = Some(args[i + 1].clone());
                i += 2;
            }
            "--algorithm" if i + 1 < args.len() => {
                out.algorithm = Some(args[i + 1].clone());
                i += 2;
            }
            "--signer" if i + 1 < args.len() => {
                out.signer = Some(args[i + 1].clone());
                i += 2;
            }
            "--predicate-type" if i + 1 < args.len() => {
                out.predicate_type = Some(args[i + 1].clone());
                i += 2;
            }
            "--predicate-file" if i + 1 < args.len() => {
                out.predicate_file = Some(args[i + 1].clone());
                i += 2;
            }
            other => {
                return Err(format!("unknown argument: {other}"));
            }
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
                    "{e}\nusage: mkit attest [--commit <hash>] [--algorithm ed25519|secp256k1|p256] [--signer repo-key|external] [--predicate-type <URI>] [--predicate-file <path>]"
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

    let cfg = match crate::config::read_or_default(&cwd) {
        Ok(c) => c,
        Err(e) => return emit_err(&format!("config: {e}"), exit::CONFIG_ERROR),
    };

    // --- Resolve commit. --------------------------------------------
    let commit_hash = match resolve_commit(&mkit_dir, parsed.commit.as_deref()) {
        Ok(h) => h,
        Err((msg, code)) => return emit_err(&msg, code),
    };

    // --- Resolve algorithm + signer. --------------------------------
    let alg_str = parsed
        .algorithm
        .clone()
        .unwrap_or_else(|| cfg.attest.default_algorithm_or_fallback().to_owned());
    let algorithm = match attest_factory::parse_algorithm(&alg_str) {
        Ok(a) => a,
        Err(FactoryError::UnknownAlgorithm(s)) => {
            return emit_err(
                &format!("unknown algorithm '{s}' — expected one of: ed25519, secp256k1, p256"),
                exit::USAGE,
            );
        }
        Err(e) => return emit_err(&format!("{e}"), exit::USAGE),
    };
    let signer_kind = parsed
        .signer
        .clone()
        .unwrap_or_else(|| cfg.attest.signer_or_fallback().to_owned());

    let mut signer = match attest_factory::build_signer(&cwd, algorithm, &signer_kind, &cfg.attest)
    {
        Ok(s) => s,
        Err(e) => {
            let code = match &e {
                FactoryError::UnknownSignerKind(_) | FactoryError::UnknownAlgorithm(_) => {
                    exit::USAGE
                }
                FactoryError::MissingKeyFile { .. } => exit::NOINPUT,
                _ => exit::CONFIG_ERROR,
            };
            return emit_err(&format!("{e}"), code);
        }
    };

    // --- Build predicate bytes. ------------------------------------
    let predicate_bytes: Vec<u8> = match parsed.predicate_file.as_deref() {
        Some(p) => match std::fs::read(p) {
            Ok(b) => b,
            Err(e) => return emit_err(&format!("predicate file '{p}': {e}"), exit::NOINPUT),
        },
        None => b"{}".to_vec(),
    };
    let predicate_type = parsed
        .predicate_type
        .unwrap_or_else(|| DEFAULT_PREDICATE_TYPE.to_owned());

    // --- Build Statement. statement::encode enforces that predicate
    //     bytes are a valid JSON object; a malformed file bubbles up as
    //     a DATAERR-class failure with a clear message.
    let stmt_bytes = match statement::for_commit(&commit_hash, &predicate_type, &predicate_bytes) {
        Ok(s) => s.into_bytes(),
        Err(
            mkit_attest::Error::PredicateMustBeJsonObject
            | mkit_attest::Error::PredicateNotJsonObject
            | mkit_attest::Error::PredicateNotUtf8,
        ) => {
            return emit_err(
                "--predicate-file must contain a JCS-canonical JSON object",
                exit::DATAERR,
            );
        }
        Err(e) => return emit_err(&format!("statement: {e}"), exit::DATAERR),
    };

    // --- Sign. -----------------------------------------------------
    let pae = mkit_attest::pae_of(PAYLOAD_TYPE_IN_TOTO, &stmt_bytes);
    let sig_bytes = match signer.sign(&pae) {
        Ok(b) => b,
        Err(e) => return emit_err(&format!("sign: {e}"), exit::GENERAL_ERROR),
    };
    let keyid = match signer.keyid() {
        Ok(k) => k,
        Err(e) => return emit_err(&format!("keyid: {e}"), exit::GENERAL_ERROR),
    };

    let envelope = Envelope {
        payload_type: PAYLOAD_TYPE_IN_TOTO.to_owned(),
        payload: stmt_bytes,
        signatures: vec![Sig {
            keyid,
            sig: sig_bytes,
        }],
    };
    let encoded = match envelope.encode() {
        Ok(s) => s,
        Err(e) => return emit_err(&format!("encode envelope: {e}"), exit::DATAERR),
    };

    // --- Save. ----------------------------------------------------
    let (att_id, path) = match store::save(&mkit_dir, &commit_hash, encoded.as_bytes()) {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("store: {e}"), exit::CANTCREAT),
    };
    let mut stdout = std::io::stdout().lock();
    let _ = writeln!(
        stdout,
        "attested {} → {}",
        hash_mod::to_hex(&att_id),
        path.display()
    );
    exit::OK
}

/// Parse `--commit` value or fall back to HEAD.
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

fn emit_err(msg: &str, code: u8) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "error: {msg}");
    code
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_args_accepts_all_flags() {
        let args = vec![
            "--commit".into(),
            "abc".into(),
            "--algorithm".into(),
            "p256".into(),
            "--signer".into(),
            "external".into(),
            "--predicate-type".into(),
            "https://example.com/p".into(),
            "--predicate-file".into(),
            "/tmp/x.json".into(),
        ];
        let p = parse_args(&args).unwrap();
        assert_eq!(p.commit.as_deref(), Some("abc"));
        assert_eq!(p.algorithm.as_deref(), Some("p256"));
        assert_eq!(p.signer.as_deref(), Some("external"));
        assert_eq!(p.predicate_type.as_deref(), Some("https://example.com/p"));
        assert_eq!(p.predicate_file.as_deref(), Some("/tmp/x.json"));
    }

    #[test]
    fn parse_args_rejects_unknown() {
        let args = vec!["--bogus".into(), "x".into()];
        assert!(parse_args(&args).is_err());
    }

    #[test]
    fn parse_args_all_defaults_when_empty() {
        let p = parse_args(&[]).unwrap();
        assert!(p.commit.is_none());
        assert!(p.algorithm.is_none());
        assert!(p.signer.is_none());
        assert!(p.predicate_type.is_none());
        assert!(p.predicate_file.is_none());
    }
}
