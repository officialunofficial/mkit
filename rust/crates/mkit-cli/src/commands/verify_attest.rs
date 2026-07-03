//! `mkit verify-attest` — verify every attestation attached to a commit.
//!
//! ```text
//! mkit verify-attest [--commit <hash>] [--trust-roots <path>]
//!                    [--algorithm <filter>]
//! mkit verify-attest --envelope-file <path> [--trust-roots <path>]
//!                    [--algorithm <filter>] [--subject-file <path>]
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
//!   `docs/SPEC-RELEASE-THRESHOLD.md`); either field name works.
//! * `pubkey_hex` is the raw public key bytes in lowercase hex. For
//!   `bls12381-thr`, the bytes are the 96-byte G2 compressed
//!   aggregated cohort public key (the `MinSig` variant).
//!
//! Exit code is 0 iff every listed attestation is bound to the requested
//! commit and has `any_verified = true`, nonzero otherwise.
//!
//! ## `--envelope-file` — standalone envelope + deep-verify hook (D7)
//!
//! `mkit blame --prove` (SPEC-BLAME-PROOF.md, issue #495) writes its DSSE
//! envelope to a standalone file (`<file>.blame-proof.json`), NOT into the
//! per-commit `.mkit/attestations/<commit>/` store — its subject is the
//! blamed file's blob digest, not a commit hash, so the store-scoped
//! `--commit` flow's subject-binding check does not apply. `--envelope-file
//! <path>` verifies that one envelope directly: envelope well-formedness +
//! signature (same crypto path as the `--commit` flow), then, if the
//! envelope's `predicateType` is registered with a deep-verify hook, parses
//! the predicate back to its typed form and runs the predicate-specific
//! check. The only hook registered today is
//! `blame_proof::BLAME_PROOF_PREDICATE_TYPE`, which needs the exact file
//! bytes the proof was built over (SPEC-BLAME-PROOF §4/D3) — supplied via
//! `--subject-file <path>` (the spec doc does not pin this flag name; this
//! is this PR's decision for the minimal verifier-input surface). Without
//! `--subject-file` the signature is still checked but the deep-verify step
//! is skipped (reported as a note, not a failure) — with it, a failing deep
//! verification (corrupt predicate, wrong subject bytes, broken tree-path,
//! …) fails the whole command.
//!
//! `--commit` is not used in this mode: a standalone envelope's subject is
//! not, in general, a commit hash.

use std::io::Write;
use std::path::{Path, PathBuf};

use clap::Parser;
use mkit_attest::envelope;
use mkit_attest::verify::{extract_primary_commit_hash, verify};
use mkit_attest::{Algorithm, Registry, TrustRoot, store};
use mkit_core::hash::Hash;
use mkit_core::store::ObjectStore;
use mkit_core::{hash as hash_mod, refs};

use super::blame_proof;
use crate::clap_shim;
use crate::exit;

#[derive(Debug, Parser)]
#[command(
    name = "mkit verify-attest",
    about = "Verify every attestation attached to a commit."
)]
struct Args {
    /// Commit hash to verify attestations for. Defaults to HEAD. Ignored
    /// when `--envelope-file` is given.
    #[arg(long, value_name = "HASH")]
    commit: Option<String>,
    /// Path to a trust-roots TOML file.
    #[arg(long, value_name = "PATH")]
    trust_roots: Option<String>,
    /// Filter signatures by algorithm.
    #[arg(long, value_name = "ALG")]
    algorithm: Option<String>,
    /// Verify a single standalone DSSE envelope file directly (e.g. a
    /// `mkit blame --prove` output) instead of listing the commit-scoped
    /// attestation store. Runs the predicate-specific deep-verify hook when
    /// the envelope's `predicateType` has one registered.
    #[arg(long = "envelope-file", value_name = "PATH")]
    envelope_file: Option<String>,
    /// File bytes to feed a predicate's deep-verify hook (e.g. the exact
    /// file `mkit blame --prove` was run against — SPEC-BLAME-PROOF §4/D3).
    /// Only meaningful with `--envelope-file`.
    #[arg(long = "subject-file", value_name = "PATH")]
    subject_file: Option<String>,
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
    let mkit_dir = cwd.join(mkit_core::MKIT_DIR);
    if !mkit_dir.is_dir() {
        return emit_err("not a mkit repo", exit::GENERAL_ERROR);
    }

    if let Some(path) = parsed.envelope_file.as_deref() {
        return run_envelope_file(&parsed, &cwd, &mkit_dir, path);
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

// ===========================================================================
// `--envelope-file` — standalone envelope + deep-verify hook (D7)
// ===========================================================================

/// Outcome of dispatching a predicate to a registered deep-verify hook. See
/// [`deep_verify`].
#[derive(Debug, PartialEq, Eq)]
enum DeepVerifyOutcome {
    /// No hook is registered for this `predicateType` — envelope signature
    /// verification is the whole check.
    NotApplicable,
    /// A hook is registered but couldn't run (e.g. `--subject-file` was not
    /// supplied). Not itself a failure — the signature already verified.
    Skipped(String),
    /// The hook ran and every check passed.
    Passed,
    /// The hook ran and a check failed.
    Failed(String),
}

/// Predicate-specific deep-verification hook (SPEC-BLAME-PROOF.md §10, D7):
/// once the enclosing DSSE envelope's signature has verified, dispatch on
/// `predicate_type` to run any additional, predicate-shaped checks. The only
/// hook registered today is the blame-proof predicate
/// ([`blame_proof::BLAME_PROOF_PREDICATE_TYPE`]): parse `predicate_json`
/// back to its typed [`mkit_core::ops::blame::proof::BlameProofPredicate`]
/// and run `verify_blame_proof` (spec §7 steps 1–3 and 5) against
/// `subject_file` — the exact file bytes the proof was built over (§4/D3).
///
/// `store`, if given, lets the ancestry check use the store-holding
/// shortcut (§8.2) instead of requiring the predicate's `origins[]` to carry
/// the full connecting-path bundle.
fn deep_verify(
    predicate_type: &str,
    predicate_json: &[u8],
    subject_file: Option<&[u8]>,
    store: Option<&ObjectStore>,
) -> DeepVerifyOutcome {
    if predicate_type != blame_proof::BLAME_PROOF_PREDICATE_TYPE {
        return DeepVerifyOutcome::NotApplicable;
    }
    let Some(file_bytes) = subject_file else {
        return DeepVerifyOutcome::Skipped(
            "blame-proof predicate needs --subject-file to deep-verify".to_owned(),
        );
    };
    let predicate = match blame_proof::decode_predicate(predicate_json) {
        Ok(p) => p,
        Err(e) => return DeepVerifyOutcome::Failed(format!("predicate decode: {e}")),
    };
    match mkit_core::ops::blame::proof::verify_blame_proof(&predicate, file_bytes, store) {
        Ok(()) => DeepVerifyOutcome::Passed,
        Err(e) => DeepVerifyOutcome::Failed(e.to_string()),
    }
}

/// Parse an in-toto Statement payload's `predicateType` + `predicate`
/// members. Unlike [`extract_primary_commit_hash`] (which only needs the
/// subject), the deep-verify dispatch needs the predicate body verbatim —
/// re-serialized (not necessarily JCS-canonical; `decode_predicate` uses a
/// relaxed parser, same convention as the subject helper) so it can be
/// handed to a predicate-specific decoder.
fn parse_statement_predicate(payload: &[u8]) -> Result<(String, Vec<u8>), String> {
    let v: serde_json::Value =
        serde_json::from_slice(payload).map_err(|e| format!("malformed statement: {e}"))?;
    let predicate_type = v
        .get("predicateType")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "Statement has no `predicateType`".to_owned())?
        .to_owned();
    let predicate = v
        .get("predicate")
        .ok_or_else(|| "Statement has no `predicate`".to_owned())?;
    let body = serde_json::to_vec(predicate).map_err(|e| format!("serialize predicate: {e}"))?;
    Ok((predicate_type, body))
}

/// `mkit verify-attest --envelope-file <path>`: verify one standalone DSSE
/// envelope directly (see the module doc-comment's "`--envelope-file`"
/// section for why this bypasses the commit-scoped attestation store).
#[allow(clippy::too_many_lines)]
fn run_envelope_file(parsed: &Args, cwd: &Path, mkit_dir: &Path, envelope_path: &str) -> u8 {
    let trust_path = parsed
        .trust_roots
        .as_deref()
        .map_or_else(default_trust_roots_path, PathBuf::from);
    if let Err(code) =
        warn_if_unsafe_trust_roots(&trust_path, mkit_dir, parsed.trust_roots.is_some())
    {
        return code;
    }
    let registry = match load_trust_roots(&trust_path) {
        Ok(r) => r,
        Err((msg, code)) => return emit_err(&msg, code),
    };
    let filter: Option<Algorithm> = match parsed.algorithm.as_deref() {
        Some(s) => match s.parse::<Algorithm>() {
            Ok(a) => Some(a),
            Err(_) => return emit_err(&format!("unknown algorithm filter '{s}'"), exit::USAGE),
        },
        None => None,
    };

    let bytes = match std::fs::read(envelope_path) {
        Ok(b) => b,
        Err(e) => return emit_err(&format!("read '{envelope_path}': {e}"), exit::NOINPUT),
    };
    let att_id = mkit_attest::attestation_id(&bytes);
    let env = match envelope::decode(&bytes) {
        Ok(env) => env,
        Err(e) => return emit_err(&format!("malformed envelope: {e}"), exit::DATAERR),
    };

    let mut report = std::io::stderr().lock();
    let _ = writeln!(
        report,
        "verifying standalone envelope {} ({envelope_path})",
        hash_mod::to_hex(&att_id)
    );

    let result = match verify(&env, &registry) {
        Ok(r) => r,
        Err(e) => {
            let _ = writeln!(report, "  malformed envelope: {e}");
            return exit::DATAERR;
        }
    };

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
        let _ = writeln!(report, "bad: no signature verified");
        return exit::DATAERR;
    }

    let (predicate_type, predicate_body) = match parse_statement_predicate(&env.payload) {
        Ok(pair) => pair,
        Err(e) => {
            let _ = writeln!(report, "  subject error: {e}");
            return exit::DATAERR;
        }
    };

    let subject_bytes = match parsed.subject_file.as_deref() {
        Some(p) => match std::fs::read(p) {
            Ok(b) => Some(b),
            Err(e) => {
                let _ = writeln!(report, "  read --subject-file '{p}': {e}");
                return exit::NOINPUT;
            }
        },
        None => None,
    };
    // Opening the store is best-effort: the deep-verify hook's ancestry
    // check (§8.1) can chain-walk `origins[]` with no store at all; a store
    // only unlocks the store-holding shortcut (§8.2). A missing/unopenable
    // store must not fail an otherwise-valid envelope.
    let store = ObjectStore::open(cwd).ok();

    match deep_verify(
        &predicate_type,
        &predicate_body,
        subject_bytes.as_deref(),
        store.as_ref(),
    ) {
        DeepVerifyOutcome::NotApplicable => {
            let _ = writeln!(
                report,
                "ok: signature verified (no deep-verify hook for predicateType {predicate_type})"
            );
            exit::OK
        }
        DeepVerifyOutcome::Skipped(msg) => {
            let _ = writeln!(report, "note: deep verification skipped: {msg}");
            let _ = writeln!(report, "ok: signature verified (deep verification not run)");
            exit::OK
        }
        DeepVerifyOutcome::Passed => {
            let _ = writeln!(
                report,
                "ok: signature verified and blame-proof deep verification passed"
            );
            exit::OK
        }
        DeepVerifyOutcome::Failed(msg) => {
            let _ = writeln!(report, "bad: blame-proof deep verification failed: {msg}");
            exit::DATAERR
        }
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
            // `algorithm` is an alias for `kind` to match the wording
            // in `docs/SPEC-RELEASE-THRESHOLD.md` §6. Either field
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
        // `docs/SPEC-RELEASE-THRESHOLD.md` §6. The `bls12381-thr`
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

    /// Spec wording in `docs/SPEC-RELEASE-THRESHOLD.md` says
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

    // -- `--envelope-file` deep-verify dispatch (SPEC-BLAME-PROOF.md D7) --

    use mkit_core::hash::Hash;
    use mkit_core::object::{Blob, Commit, EntryMode, Identity, Object, Tree, TreeEntry};
    use mkit_core::ops::blame::BlameOptions;
    use mkit_core::ops::blame::proof::build_blame_proof;
    use mkit_core::serialize;
    use mkit_core::store::ObjectStore;

    fn fresh_store() -> (tempfile::TempDir, ObjectStore) {
        let dir = tempfile::TempDir::new().unwrap();
        let store = ObjectStore::init(dir.path()).unwrap();
        (dir, store)
    }

    /// Build a minimal one-commit, one-file fixture and its blame-proof
    /// predicate (JCS-encoded), for exercising [`deep_verify`] without
    /// spawning the CLI binary.
    fn blame_proof_fixture() -> (tempfile::TempDir, ObjectStore, Vec<u8>, Vec<u8>) {
        let (dir, store) = fresh_store();
        let content = b"one\ntwo\nthree\n".to_vec();
        let blob = Object::Blob(Blob {
            data: content.clone(),
        });
        let blob_hash = store.write(&serialize::serialize(&blob).unwrap()).unwrap();
        let tree = Object::Tree(Tree {
            entries: vec![TreeEntry {
                name: b"f.txt".to_vec(),
                mode: EntryMode::Blob,
                object_hash: blob_hash,
            }],
        });
        let tree_hash = store.write(&serialize::serialize(&tree).unwrap()).unwrap();
        let commit = Object::Commit(Commit::new_unannotated(
            tree_hash,
            vec![],
            Identity::opaque(1u64.to_le_bytes()),
            [0x11; 32],
            b"msg".to_vec(),
            100,
            [0u8; 64],
        ));
        let commit_hash: Hash = store
            .write(&serialize::serialize(&commit).unwrap())
            .unwrap();

        let predicate =
            build_blame_proof(&store, &BlameOptions::default(), commit_hash, "f.txt").unwrap();
        let predicate_json = blame_proof::encode_predicate(&predicate).unwrap();
        (dir, store, predicate_json.into_bytes(), content)
    }

    #[test]
    fn deep_verify_not_applicable_for_unknown_predicate_type() {
        let outcome = deep_verify("https://example.com/other/v1", b"{}", Some(b"bytes"), None);
        assert_eq!(outcome, DeepVerifyOutcome::NotApplicable);
    }

    #[test]
    fn deep_verify_skipped_without_subject_file() {
        let (_dir, _store, predicate_json, _content) = blame_proof_fixture();
        let outcome = deep_verify(
            blame_proof::BLAME_PROOF_PREDICATE_TYPE,
            &predicate_json,
            None,
            None,
        );
        assert!(matches!(outcome, DeepVerifyOutcome::Skipped(_)));
    }

    #[test]
    fn deep_verify_passes_with_correct_subject_bytes() {
        let (_dir, store, predicate_json, content) = blame_proof_fixture();
        let outcome = deep_verify(
            blame_proof::BLAME_PROOF_PREDICATE_TYPE,
            &predicate_json,
            Some(&content),
            Some(&store),
        );
        assert_eq!(outcome, DeepVerifyOutcome::Passed);
    }

    #[test]
    fn deep_verify_fails_with_wrong_subject_bytes() {
        let (_dir, _store, predicate_json, _content) = blame_proof_fixture();
        let outcome = deep_verify(
            blame_proof::BLAME_PROOF_PREDICATE_TYPE,
            &predicate_json,
            Some(b"not the right file content at all"),
            None,
        );
        assert!(matches!(outcome, DeepVerifyOutcome::Failed(_)));
    }

    #[test]
    fn deep_verify_fails_on_undecodable_predicate() {
        let outcome = deep_verify(
            blame_proof::BLAME_PROOF_PREDICATE_TYPE,
            b"not json",
            Some(b"bytes"),
            None,
        );
        assert!(matches!(outcome, DeepVerifyOutcome::Failed(_)));
    }

    #[test]
    fn parse_statement_predicate_extracts_type_and_body() {
        let stmt = b"{\"predicateType\":\"https://example.com/x/v1\",\"predicate\":{\"a\":1}}";
        let (ty, body) = parse_statement_predicate(stmt).unwrap();
        assert_eq!(ty, "https://example.com/x/v1");
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["a"], 1);
    }

    #[test]
    fn parse_statement_predicate_rejects_missing_predicate_type() {
        let stmt = b"{\"predicate\":{}}";
        let err = parse_statement_predicate(stmt).unwrap_err();
        assert!(err.contains("predicateType"));
    }
}
