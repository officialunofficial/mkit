//! `mkit attest` — produce a signed DSSE attestation for a commit.
//!
//! ```text
//! mkit attest [--commit <hash>] [--algorithm ed25519|secp256k1|p256]
//!             [--signer repo-key|external]
//!             [--predicate-type <URI>] [--predicate-file <path>]
//!             [--external-signer-arg <V>]...
//!             [--additional-signer "<spec>"]...
//! ```
//!
//! `--external-signer-arg` is repeatable; each instance adds one
//! argv token to the external signer subprocess. If any are passed,
//! they REPLACE (not append to) `attest.external_signer_args` from
//! `.mkit/config` — per-invocation override for "sign with tag X
//! this one time" that avoids shell-quoting hell.
//!
//! Defaults:
//! * `--commit` — HEAD.
//! * `--algorithm` — `attest.default_algorithm` in config, else `ed25519`.
//! * `--signer` — `attest.signer` in config, else `repo-key`.
//! * `--predicate-type` — `https://mkit.io/predicate/empty/v1`.
//! * `--predicate-file` — omitted ⇒ `{}`.
//!
//! Multi-signature envelopes are produced by passing one or more
//! `--additional-signer` flags after the primary signer. Each spec is
//! a comma-separated `key=value` list:
//!
//! ```text
//! --additional-signer "algorithm=<algo>,signer=<kind>[,path=<file-or-binary>][,args=<a>|<b>|<c>]"
//! ```
//!
//! The optional `args=` clause is pipe-separated (commas would clash
//! with the outer key=value separator) and applies only when
//! `signer=external`. Each pipe-separated token becomes one argv
//! entry for the child process, same as `--external-signer-arg` on
//! the primary signer.
//!
//! Signers are invoked in order (primary first, then each
//! `--additional-signer` as they appear on the command line) and the
//! resulting `{keyid, sig}` tuples are written into one envelope in
//! that same order. Any signer failure aborts the attest — no
//! partial envelopes are written to disk.
//!
//! On success, prints the att-id (64 hex chars) and exits 0.

use std::io::Write;
use std::path::Path;

use mkit_attest::{Algorithm, Envelope, PAYLOAD_TYPE_IN_TOTO, Sig, Signer, statement, store};
use mkit_core::hash::Hash;
use mkit_core::{hash as hash_mod, refs};

use crate::commands::attest_factory::{self, FactoryError};
use crate::config::Config;
use crate::exit;

/// Default predicate type URI — placeholder; real callers pass their own.
const DEFAULT_PREDICATE_TYPE: &str = "https://mkit.io/predicate/empty/v1";

#[allow(clippy::struct_field_names)]
struct Args {
    commit: Option<String>,
    algorithm: Option<String>,
    signer: Option<String>,
    predicate_type: Option<String>,
    predicate_file: Option<String>,
    additional_signers: Vec<String>,
    /// Repeatable `--external-signer-arg <V>`. If any instance appears,
    /// these REPLACE (not append to) `attest.external_signer_args` from
    /// config — per-invocation override for "sign with this tag just
    /// once" without editing `.mkit/config`. An empty `Vec` means the
    /// flag was not passed (fall through to config); to force zero argv
    /// when config has some, the user can `config unset` the key.
    external_signer_args: Option<Vec<String>>,
}

fn parse_args(args: &[String]) -> Result<Args, String> {
    let mut out = Args {
        commit: None,
        algorithm: None,
        signer: None,
        predicate_type: None,
        predicate_file: None,
        additional_signers: Vec::new(),
        external_signer_args: None,
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
            "--additional-signer" if i + 1 < args.len() => {
                out.additional_signers.push(args[i + 1].clone());
                i += 2;
            }
            "--external-signer-arg" if i + 1 < args.len() => {
                out.external_signer_args
                    .get_or_insert_with(Vec::new)
                    .push(args[i + 1].clone());
                i += 2;
            }
            other => {
                return Err(format!("unknown argument: {other}"));
            }
        }
    }
    Ok(out)
}

/// Parsed `--additional-signer` spec. The `path` field overrides the
/// per-algorithm key path (for `repo-key`) or the external-signer
/// binary path (for `external`); if unset we fall back to the
/// `[attest]` config section just like the primary signer does.
#[derive(Debug, PartialEq, Eq)]
struct SignerSpec {
    algorithm: Algorithm,
    signer_kind: String,
    path: Option<String>,
    /// Parsed `args=a|b|c` clause. `None` ⇒ fall through to
    /// `attest.external_signer_args`; `Some(vec)` ⇒ override for this
    /// signer only. Pipe-separated on the wire because comma is the
    /// spec's key=value separator.
    args: Option<Vec<String>>,
}

fn parse_signer_spec(s: &str) -> Result<SignerSpec, String> {
    let mut algorithm: Option<Algorithm> = None;
    let mut signer_kind: Option<String> = None;
    let mut path: Option<String> = None;
    let mut args: Option<Vec<String>> = None;
    for part in s.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let Some((k, v)) = part.split_once('=') else {
            return Err(format!(
                "--additional-signer spec part '{part}' is not key=value"
            ));
        };
        match k.trim() {
            "algorithm" => {
                let v = v.trim();
                let alg = attest_factory::parse_algorithm(v).map_err(|_| {
                    format!("--additional-signer: unknown algorithm '{v}' — expected one of: ed25519, secp256k1, p256")
                })?;
                algorithm = Some(alg);
            }
            "signer" => {
                let v = v.trim();
                if !matches!(v, "repo-key" | "external") {
                    return Err(format!(
                        "--additional-signer: unknown signer '{v}' — expected one of: repo-key, external"
                    ));
                }
                signer_kind = Some(v.to_owned());
            }
            "path" => {
                path = Some(v.trim().to_owned());
            }
            "args" => {
                // Pipe-separator is a deliberate divergence from the
                // `,`-separator used between spec keys: `,` is already
                // taken, and `|` is the shortest ASCII separator that
                // doesn't need shell-quoting. An empty value means
                // "zero argv" and is valid (overrides a non-empty
                // config explicitly).
                args = Some(crate::config::parse_pipe_list(v.trim()));
            }
            other => {
                return Err(format!("--additional-signer: unknown spec key '{other}'"));
            }
        }
    }
    let algorithm =
        algorithm.ok_or_else(|| "--additional-signer: missing algorithm=...".to_owned())?;
    let signer_kind =
        signer_kind.ok_or_else(|| "--additional-signer: missing signer=...".to_owned())?;
    Ok(SignerSpec {
        algorithm,
        signer_kind,
        path,
        args,
    })
}

#[must_use]
#[allow(clippy::too_many_lines)]
pub fn run(args: &[String]) -> u8 {
    let parsed = match parse_args(args) {
        Ok(p) => p,
        Err(e) => {
            return emit_err(
                &format!(
                    "{e}\nusage: mkit attest [--commit <hash>] [--algorithm ed25519|secp256k1|p256] \
                     [--signer repo-key|external] [--predicate-type <URI>] [--predicate-file <path>] \
                     [--external-signer-arg <V>]... \
                     [--additional-signer \"algorithm=<a>,signer=<k>[,path=<p>][,args=<a>|<b>|<c>]\"]..."
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

    let mut cfg = match crate::config::read_or_default(&cwd) {
        Ok(c) => c,
        Err(e) => return emit_err(&format!("config: {e}"), exit::CONFIG_ERROR),
    };

    // `--external-signer-arg` REPLACES `attest.external_signer_args`
    // when present. Per-invocation override, intentionally not additive
    // so a user can cleanly reproduce `mkit-sign-se sign --tag demo`
    // without having to remember (or clobber) whatever's in config.
    if let Some(argv) = parsed.external_signer_args.clone() {
        cfg.attest.external_signer_args = argv;
    }

    // --- Resolve commit. --------------------------------------------
    let commit_hash = match resolve_commit(&mkit_dir, parsed.commit.as_deref()) {
        Ok(h) => h,
        Err((msg, code)) => return emit_err(&msg, code),
    };

    // --- Resolve primary algorithm + signer. ------------------------
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

    let primary_signer = match attest_factory::build_signer(&cwd, algorithm, &signer_kind, &cfg) {
        Ok(s) => s,
        Err(e) => return emit_err(&format!("{e}"), factory_error_code(&e)),
    };

    // --- Resolve additional signers. --------------------------------
    // Parse ALL specs before building ANY signer so a malformed spec
    // surfaces as a USAGE error without any crypto happening.
    let mut additional_specs: Vec<SignerSpec> = Vec::with_capacity(parsed.additional_signers.len());
    for spec_str in &parsed.additional_signers {
        match parse_signer_spec(spec_str) {
            Ok(s) => additional_specs.push(s),
            Err(e) => return emit_err(&e, exit::USAGE),
        }
    }

    let mut signers: Vec<Box<dyn Signer>> = Vec::with_capacity(1 + additional_specs.len());
    signers.push(primary_signer);
    for spec in &additional_specs {
        let signer = match build_additional_signer(&cwd, spec, &cfg) {
            Ok(s) => s,
            Err(e) => return emit_err(&format!("{e}"), factory_error_code(&e)),
        };
        signers.push(signer);
    }

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

    // --- Build Statement. ------------------------------------------
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

    // --- Sign with every signer, aborting on the first failure. -----
    let pae = mkit_attest::pae_of(PAYLOAD_TYPE_IN_TOTO, &stmt_bytes);
    let mut signatures: Vec<Sig> = Vec::with_capacity(signers.len());
    for (idx, signer) in signers.iter_mut().enumerate() {
        let sig_bytes = match signer.sign(&pae) {
            Ok(b) => b,
            Err(e) => {
                return emit_err(
                    &format!("sign (signer #{}): {e}", idx + 1),
                    exit::GENERAL_ERROR,
                );
            }
        };
        let keyid = match signer.keyid() {
            Ok(k) => k,
            Err(e) => {
                return emit_err(
                    &format!("keyid (signer #{}): {e}", idx + 1),
                    exit::GENERAL_ERROR,
                );
            }
        };
        signatures.push(Sig {
            keyid,
            sig: sig_bytes,
        });
    }

    let envelope = Envelope {
        payload_type: PAYLOAD_TYPE_IN_TOTO.to_owned(),
        payload: stmt_bytes,
        signatures,
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
        "attested {} → {} ({} signature(s))",
        hash_mod::to_hex(&att_id),
        path.display(),
        envelope.signatures.len()
    );
    exit::OK
}

/// Build an additional signer from a parsed spec.
///
/// `path` overrides the per-algorithm key path (repo-key) or the
/// external-signer binary path (external); if unset we fall through to
/// the same `[attest]` config the primary signer uses.
fn build_additional_signer(
    root: &Path,
    spec: &SignerSpec,
    base: &Config,
) -> Result<Box<dyn Signer>, FactoryError> {
    match spec.signer_kind.as_str() {
        "repo-key" => {
            // A per-spec path overrides the config-level key path; we
            // synthesise a one-off Config to feed the factory so it
            // still does the load-and-validate dance we want.
            let mut cfg = base.clone();
            if let Some(p) = spec.path.as_deref() {
                // Path-traversal guard at the spec layer, mirroring the
                // user-config validator. A per-spec `path=...` value
                // can come from `--additional-signer` argv or, in the
                // multi-sig flow, from a CI-controlled string. Either
                // way `..` traversal is rejected.
                if let Err(e) = crate::config::validate_key_path(p) {
                    return Err(FactoryError::InvalidKeyFile {
                        path: p.to_owned(),
                        reason: e.to_string(),
                    });
                }
                match spec.algorithm {
                    Algorithm::Ed25519 => p.clone_into(&mut cfg.signing_key),
                    Algorithm::Secp256k1 => p.clone_into(&mut cfg.attest.secp256k1_key_path),
                    Algorithm::P256 => p.clone_into(&mut cfg.attest.p256_key_path),
                }
            }
            attest_factory::build_signer(root, spec.algorithm, "repo-key", &cfg)
        }
        "external" => {
            let mut cfg = base.clone();
            if let Some(p) = spec.path.as_deref() {
                p.clone_into(&mut cfg.attest.external_signer_path);
            }
            // Per-spec `args=...` REPLACES the config-level argv so
            // multi-sig specs can independently drive different
            // external binaries. Absent `args=` ⇒ inherit the primary
            // signer's config value, matching how `path=` falls through.
            if let Some(argv) = spec.args.as_ref() {
                cfg.attest.external_signer_args.clone_from(argv);
            }
            attest_factory::build_signer(root, spec.algorithm, "external", &cfg)
        }
        other => Err(FactoryError::UnknownSignerKind(other.to_owned())),
    }
}

fn factory_error_code(e: &FactoryError) -> u8 {
    match e {
        FactoryError::UnknownSignerKind(_) | FactoryError::UnknownAlgorithm(_) => exit::USAGE,
        FactoryError::MissingKeyFile { .. } => exit::NOINPUT,
        _ => exit::CONFIG_ERROR,
    }
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
        assert!(p.additional_signers.is_empty());
    }

    #[test]
    fn parse_args_collects_repeatable_external_signer_args() {
        let args = vec![
            "--external-signer-arg".into(),
            "sign".into(),
            "--external-signer-arg".into(),
            "--tag".into(),
            "--external-signer-arg".into(),
            "demo".into(),
        ];
        let p = parse_args(&args).unwrap();
        let expected = vec!["sign".to_owned(), "--tag".to_owned(), "demo".to_owned()];
        assert_eq!(p.external_signer_args, Some(expected));
    }

    #[test]
    fn parse_args_external_signer_arg_none_when_absent() {
        // Distinguishes "flag not passed" (None → fall through to config)
        // from "flag passed with no values" (impossible: the flag needs
        // a value).
        let p = parse_args(&[]).unwrap();
        assert!(p.external_signer_args.is_none());
    }

    #[test]
    fn parse_args_collects_multiple_additional_signers() {
        let args = vec![
            "--additional-signer".into(),
            "algorithm=ed25519,signer=repo-key".into(),
            "--additional-signer".into(),
            "algorithm=p256,signer=external,path=/x".into(),
        ];
        let p = parse_args(&args).unwrap();
        assert_eq!(p.additional_signers.len(), 2);
        assert_eq!(p.additional_signers[0], "algorithm=ed25519,signer=repo-key");
    }

    #[test]
    fn parse_args_rejects_unknown() {
        let args = vec!["--bogus".into(), "x".into()];
        assert!(parse_args(&args).is_err());
    }

    #[test]
    fn parse_signer_spec_ok() {
        let s = parse_signer_spec("algorithm=secp256k1,signer=repo-key,path=k.key").unwrap();
        assert_eq!(s.algorithm, Algorithm::Secp256k1);
        assert_eq!(s.signer_kind, "repo-key");
        assert_eq!(s.path.as_deref(), Some("k.key"));
    }

    #[test]
    fn parse_signer_spec_with_args() {
        let s = parse_signer_spec(
            "algorithm=p256,signer=external,path=/usr/bin/signer,args=sign|--tag|demo",
        )
        .unwrap();
        assert_eq!(s.algorithm, Algorithm::P256);
        assert_eq!(s.signer_kind, "external");
        assert_eq!(s.path.as_deref(), Some("/usr/bin/signer"));
        assert_eq!(
            s.args.as_deref(),
            Some(["sign".to_owned(), "--tag".to_owned(), "demo".to_owned()].as_slice())
        );
    }

    #[test]
    fn parse_signer_spec_args_empty_means_zero_argv() {
        // `args=` with no value is a valid override that means "this
        // signer gets zero argv, regardless of config." Distinct from
        // omitting `args=` entirely (which inherits from config).
        let s = parse_signer_spec("algorithm=ed25519,signer=external,args=").unwrap();
        assert_eq!(s.args.as_deref(), Some([].as_slice()));
    }

    #[test]
    fn parse_signer_spec_without_path() {
        let s = parse_signer_spec("algorithm=p256,signer=external").unwrap();
        assert_eq!(s.algorithm, Algorithm::P256);
        assert_eq!(s.signer_kind, "external");
        assert!(s.path.is_none());
    }

    #[test]
    fn parse_signer_spec_missing_algorithm() {
        let e = parse_signer_spec("signer=repo-key").unwrap_err();
        assert!(e.contains("algorithm"), "{e}");
    }

    #[test]
    fn parse_signer_spec_missing_signer() {
        let e = parse_signer_spec("algorithm=ed25519").unwrap_err();
        assert!(e.contains("signer"), "{e}");
    }

    #[test]
    fn parse_signer_spec_unknown_algorithm() {
        let e = parse_signer_spec("algorithm=rsa,signer=repo-key").unwrap_err();
        assert!(e.contains("rsa"), "{e}");
    }

    #[test]
    fn parse_signer_spec_unknown_signer_kind() {
        let e = parse_signer_spec("algorithm=ed25519,signer=sigstore").unwrap_err();
        assert!(e.contains("sigstore"), "{e}");
    }

    #[test]
    fn parse_signer_spec_not_key_value() {
        // Missing comma between key=value pairs — `split_once('=')` swallows
        // the rest into the value of the first key. This surfaces as an
        // "unknown algorithm" error for the bogus algorithm value, which is
        // clear enough for the user to fix.
        let e = parse_signer_spec("algorithm=ed25519 signer=repo-key").unwrap_err();
        assert!(e.contains("algorithm") || e.contains("key=value"), "{e}");
    }

    #[test]
    fn parse_args_all_defaults_when_empty() {
        let p = parse_args(&[]).unwrap();
        assert!(p.commit.is_none());
        assert!(p.algorithm.is_none());
        assert!(p.signer.is_none());
        assert!(p.predicate_type.is_none());
        assert!(p.predicate_file.is_none());
        assert!(p.additional_signers.is_empty());
    }
}
