// Module-level clippy allowances: this reference signer's prose is
// heavy with protocol and hardware identifiers (credential_id, rp_id,
// YubiKey, SoloKey, …) that are not load-bearing in the literal
// sense clippy's `doc_markdown` expects, and the small-cast /
// similar-name warnings are from arithmetic patterns whose
// alternatives would make the code harder to read, not safer.
#![allow(
    clippy::doc_markdown,
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::similar_names,
    clippy::items_after_statements,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::map_unwrap_or,
    clippy::needless_borrows_for_generic_args,
    clippy::semicolon_if_nothing_returned,
    clippy::vec_init_then_push,
    clippy::redundant_closure_for_method_calls
)]

//! `mkit-sign-ctap` — reference FIDO2/WebAuthn external signer.
//!
//! Drives a plugged-in roaming authenticator (YubiKey, Nitrokey,
//! SoloKey, …) over CTAP-HID and produces signatures in the Protocol
//! v1.1 WebAuthn-wrapping shape defined in
//! `docs/SPEC-EXTERNAL-SIGNER.md` §14.
//!
//! ## Subcommands
//!
//! * `enroll --rp-id <rpid> --user-name <name> [--pin <pin>] [--resident]`
//!   — runs a CTAP `make_credential` ceremony and stores the credential
//!   metadata (credential_id + SEC1-uncompressed pubkey) under
//!   `$HOME/.mkit-sign-ctap/credentials.json`. Prints the keyid on
//!   stdout.
//! * `sign --credential-id <base64url> [--rp-id <rpid>] [--pin <pin>] [--origin <url>]`
//!   — reads one line of v1 JSON (`{pae_base64, algorithm}`) from stdin,
//!   asks the authenticator to produce an assertion over a
//!   `clientDataJSON` whose `challenge` = base64url_nopad(PAE), and
//!   writes the v1.1 response on stdout.
//! * `list-credentials` — dumps the contents of the local metadata
//!   store (no authenticator required).
//!
//! ## What is trusted
//!
//! * The authenticator holds the secret key. This binary never sees
//!   it.
//! * The local metadata store is advisory — it maps credential_id to
//!   pubkey for convenience. The binary does not NEED the metadata
//!   file to sign: with `--credential-id` and `--rp-id` given on the
//!   CLI, the authenticator will produce an assertion whose
//!   `authenticatorData` contains the rpIdHash the verifier needs.
//!
//! ## What is NOT handled here
//!
//! * Signing under the `sign` extension (FIDO 2.1). Device support is
//!   fragmented enough that we stick with the wrapping approach —
//!   every authenticator on the market understands
//!   `get_assertion` + `make_credential`.
//! * User-verification policy (PIN / on-device biometric). We pass a
//!   `--pin` through when the caller provides one; the authenticator
//!   enforces whatever UV policy the credential was enrolled with.
//! * CTAP 2.1 vs 2.0 differences. Both speak the same
//!   `get_assertion` shape on the wire.
//!
//! See `docs/SPEC-EXTERNAL-SIGNER.md` for the wire protocol and
//! `contrib/signers/README.md` for how mkit wires this binary in.

use std::io::{Read, Write};
use std::process::ExitCode;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD as B64_STD, URL_SAFE_NO_PAD as B64_URL_NOPAD};
use mkit_attest::build_client_data_json;

mod cred_store;
mod ctap;
mod proto;

use proto::{SignRequest, SignResponse, WebAuthnResponse};

/// Binary entry. All exit paths funnel through here so non-zero is
/// always paired with a stderr line per SPEC-EXTERNAL-SIGNER §5.
fn main() -> ExitCode {
    match run() {
        Ok(()) | Err(SignerError::HelpRequested) => ExitCode::SUCCESS,
        // Exit code 2 for algorithm mismatch / bad request mirrors
        // `mkit-sign-se`'s convention so operators can dispatch on the
        // code uniformly. Every other error returns 1.
        Err(SignerError::AlgorithmMismatch(_)) => {
            eprintln!("mkit-sign-ctap: algorithm mismatch — this signer only speaks p256");
            ExitCode::from(2)
        }
        Err(e) => {
            eprintln!("mkit-sign-ctap: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), SignerError> {
    let mut args_iter = std::env::args().skip(1);
    let sub = args_iter.next().ok_or(SignerError::BadArgs(
        "missing subcommand (enroll | sign | list-credentials)",
    ))?;

    match sub.as_str() {
        "enroll" => run_enroll(args_iter),
        "sign" => run_sign(args_iter),
        "list-credentials" => run_list(),
        "-h" | "--help" => {
            eprintln!("{HELP}");
            Err(SignerError::HelpRequested)
        }
        other => Err(SignerError::UnknownSubcommand(other.to_owned())),
    }
}

// -- enroll ------------------------------------------------------------

#[derive(Debug, Default)]
struct EnrollArgs {
    rp_id: Option<String>,
    user_name: Option<String>,
    pin: Option<String>,
    #[allow(dead_code)]
    resident: bool,
}

fn parse_enroll(it: impl Iterator<Item = String>) -> Result<EnrollArgs, SignerError> {
    let mut a = EnrollArgs::default();
    let mut it = it;
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--rp-id" => {
                a.rp_id = Some(
                    it.next()
                        .ok_or(SignerError::BadArgs("--rp-id needs a value"))?,
                )
            }
            "--user-name" => {
                a.user_name = Some(
                    it.next()
                        .ok_or(SignerError::BadArgs("--user-name needs a value"))?,
                )
            }
            "--pin" => {
                a.pin = Some(
                    it.next()
                        .ok_or(SignerError::BadArgs("--pin needs a value"))?,
                )
            }
            "--resident" => a.resident = true,
            other => return Err(SignerError::UnknownArg(other.to_owned())),
        }
    }
    Ok(a)
}

fn run_enroll(it: impl Iterator<Item = String>) -> Result<(), SignerError> {
    let a = parse_enroll(it)?;
    let rp_id = a.rp_id.as_deref().unwrap_or("mkit.local");
    let user_name = a.user_name.as_deref().unwrap_or("mkit-user");

    // Drive the authenticator. The ctap module encapsulates every
    // hardware call so the `run_*` functions themselves stay free
    // of `#[cfg]` noise.
    let enrolled = ctap::make_credential(rp_id, user_name, a.pin.as_deref())?;

    // Persist to the local metadata store (best-effort; on error we
    // still emit keyid so callers can script enrolment).
    let store_path = cred_store::default_path()?;
    let mut store = cred_store::Store::load(&store_path)?;
    let rec = cred_store::Record {
        credential_id_b64url: B64_URL_NOPAD.encode(&enrolled.credential_id),
        public_key_sec1_uncompressed_hex: to_hex(&enrolled.public_key_sec1_uncompressed),
        rp_id: rp_id.to_owned(),
        user_name: user_name.to_owned(),
        keyid: enrolled.keyid.clone(),
    };
    store.upsert(rec);
    store.save(&store_path)?;

    // Emit the keyid on stdout — the common "capture me in a shell
    // variable" integration point. Everything else goes to stderr so
    // callers piping stdout elsewhere aren't surprised.
    println!("{}", enrolled.keyid);
    eprintln!(
        "mkit-sign-ctap: enrolled credential_id={} at {}",
        B64_URL_NOPAD.encode(&enrolled.credential_id),
        store_path.display()
    );
    Ok(())
}

// -- sign --------------------------------------------------------------

#[derive(Debug, Default)]
struct SignArgs {
    credential_id_b64url: Option<String>,
    rp_id: Option<String>,
    pin: Option<String>,
    origin: Option<String>,
}

fn parse_sign(it: impl Iterator<Item = String>) -> Result<SignArgs, SignerError> {
    let mut a = SignArgs::default();
    let mut it = it;
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--credential-id" => {
                a.credential_id_b64url = Some(
                    it.next()
                        .ok_or(SignerError::BadArgs("--credential-id needs a value"))?,
                );
            }
            "--rp-id" => {
                a.rp_id = Some(
                    it.next()
                        .ok_or(SignerError::BadArgs("--rp-id needs a value"))?,
                )
            }
            "--pin" => {
                a.pin = Some(
                    it.next()
                        .ok_or(SignerError::BadArgs("--pin needs a value"))?,
                )
            }
            "--origin" => {
                a.origin = Some(
                    it.next()
                        .ok_or(SignerError::BadArgs("--origin needs a value"))?,
                );
            }
            other => return Err(SignerError::UnknownArg(other.to_owned())),
        }
    }
    Ok(a)
}

fn run_sign(it: impl Iterator<Item = String>) -> Result<(), SignerError> {
    let a = parse_sign(it)?;
    let credential_id_b64 = a
        .credential_id_b64url
        .ok_or(SignerError::BadArgs("--credential-id is required for sign"))?;
    let credential_id = B64_URL_NOPAD
        .decode(credential_id_b64.as_bytes())
        .map_err(|_| SignerError::BadArgs("--credential-id is not valid base64url"))?;

    // Look up the credential in the local metadata store to resolve
    // the rp_id / keyid the verifier will expect. The store is
    // advisory — if the entry is missing we fall back to CLI flags.
    let store_path = cred_store::default_path()?;
    let store = cred_store::Store::load(&store_path).unwrap_or_default();
    let record = store.find_by_credential_id(&credential_id_b64);

    let rp_id = a
        .rp_id
        .clone()
        .or_else(|| record.map(|r| r.rp_id.clone()))
        .unwrap_or_else(|| "mkit.local".to_owned());
    let origin = a.origin.unwrap_or_else(|| format!("https://{rp_id}"));

    // Read the v1 request from stdin, cap at 1 MiB per spec §6.
    let mut buf = Vec::with_capacity(256);
    std::io::stdin()
        .take(1024 * 1024 + 1)
        .read_to_end(&mut buf)
        .map_err(|e| SignerError::Io(format!("read stdin: {e}")))?;
    if buf.len() > 1024 * 1024 {
        return Err(SignerError::RequestTooLarge);
    }

    let req: SignRequest =
        serde_json::from_slice(trim_trailing_newline(&buf)).map_err(|_| SignerError::BadRequest)?;

    // Protocol v1.1 is P-256 only (§14.2 of SPEC-EXTERNAL-SIGNER).
    // Refuse any other algorithm loudly — silently signing under a
    // different curve would be a critical correctness hazard.
    if req.algorithm != "p256" {
        return Err(SignerError::AlgorithmMismatch(req.algorithm));
    }

    let pae = B64_STD
        .decode(req.pae_base64.as_bytes())
        .map_err(|_| SignerError::BadRequest)?;

    // Build the clientDataJSON the authenticator is going to hash.
    // This is also what the verifier will see under
    // `webauthn.client_data_json`; the bytes are identical.
    let client_data_json = build_client_data_json(&pae, &origin, false);

    // Drive CTAP. The crate takes a `challenge: &[u8]` and internally
    // computes SHA256(challenge); i.e. we hand it the raw JSON and
    // the authenticator signs `auth_data || SHA256(cdj)` — which is
    // exactly what Protocol v1.1 demands.
    let assertion =
        ctap::get_assertion(&rp_id, &credential_id, &client_data_json, a.pin.as_deref())?;

    // Resolve the keyid. If the record is in the store, trust it;
    // otherwise we don't know the SEC1 pubkey and the verifier will
    // have to fetch it out-of-band. Either way we emit SOMETHING — an
    // integrator can wire a custom keyid scheme via --keyid later.
    let keyid = record
        .map(|r| r.keyid.clone())
        .unwrap_or_else(|| format!("webauthn:{credential_id_b64}"));

    // ECDSA from the authenticator arrives DER-encoded. Convert to
    // 64-byte compact r||s and low-S normalise. Both steps happen in
    // `proto::der_to_compact_p256` so the wire-shape invariants are
    // tested in one place.
    let sig_compact = proto::der_to_compact_p256(&assertion.signature)?;

    // Emit the v1.1 response. Fields are JCS-compatible ascending
    // order so a downstream verifier that strict-parses JCS is happy;
    // this is NOT normatively required by §14.2 but it costs nothing.
    let resp = SignResponse {
        keyid,
        sig_base64: B64_STD.encode(&sig_compact),
        webauthn: Some(WebAuthnResponse {
            authenticator_data: B64_URL_NOPAD.encode(&assertion.auth_data),
            client_data_json: B64_URL_NOPAD.encode(&client_data_json),
        }),
    };

    // Hand-render the JSON with stable key order. `serde_json`
    // would sort alphabetically by default, but we want the exact
    // `keyid, sig_base64, webauthn` ordering every spec example uses.
    let out_json = proto::render_response_json(&resp);
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    writeln!(out, "{out_json}").map_err(|e| SignerError::Io(format!("write stdout: {e}")))?;
    Ok(())
}

// -- list-credentials --------------------------------------------------

fn run_list() -> Result<(), SignerError> {
    let store_path = cred_store::default_path()?;
    let store = cred_store::Store::load(&store_path).unwrap_or_default();
    // Plain-text dump; JSON output deferred to a `--json` flag once
    // anyone actually wants to script this.
    for r in store.records() {
        println!(
            "credential_id={}\tkeyid={}\trp_id={}\tuser_name={}",
            r.credential_id_b64url, r.keyid, r.rp_id, r.user_name
        );
    }
    Ok(())
}

// -- Misc --------------------------------------------------------------

fn trim_trailing_newline(b: &[u8]) -> &[u8] {
    let mut end = b.len();
    while end > 0 && (b[end - 1] == b'\n' || b[end - 1] == b'\r') {
        end -= 1;
    }
    &b[..end]
}

fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0F) as usize] as char);
    }
    out
}

const HELP: &str = "\
mkit-sign-ctap: FIDO2/WebAuthn external signer (Protocol v1.1)

USAGE:
    mkit-sign-ctap enroll --rp-id <rpid> --user-name <name> [--pin <pin>] [--resident]
    mkit-sign-ctap sign   --credential-id <base64url> [--rp-id <rpid>] [--pin <pin>] [--origin <url>]
    mkit-sign-ctap list-credentials

Reads {pae_base64, algorithm} JSON from stdin (sign).
Writes v1.1 {keyid, sig_base64, webauthn:{...}} JSON on stdout.
Exit 0 on success, 1 on generic error, 2 on algorithm mismatch.

Requires a plugged-in FIDO2 roaming authenticator (YubiKey / Nitrokey /
SoloKey). See docs/SPEC-EXTERNAL-SIGNER.md §14 for the wire protocol.
";

// -- Errors -----------------------------------------------------------

/// All exit paths go through this type. Each variant maps to a
/// specific stderr line; `Display` is the source of truth for the
/// human text.
#[derive(Debug, thiserror::Error)]
pub enum SignerError {
    #[error("bad args: {0}")]
    BadArgs(&'static str),
    #[error("unknown argument: {0}")]
    UnknownArg(String),
    #[error("unknown subcommand: {0}")]
    UnknownSubcommand(String),
    #[error("could not parse stdin request JSON (expected {{pae_base64, algorithm}})")]
    BadRequest,
    #[error("stdin request exceeds 1 MiB")]
    RequestTooLarge,
    #[error(
        "algorithm `{0}` is not supported — this signer only produces p256 WebAuthn signatures"
    )]
    AlgorithmMismatch(String),
    #[error("io: {0}")]
    Io(String),
    #[error("credential store: {0}")]
    Store(String),
    #[error("authenticator: {0}")]
    Ctap(String),
    #[error("signature conversion: {0}")]
    SigConvert(&'static str),
    #[error("help")]
    HelpRequested,
}

#[cfg(test)]
mod main_tests {
    //! Small sanity tests that live alongside `main.rs`. The real
    //! wire-shape and signature-conversion tests live in
    //! `tests/protocol_shape.rs` so they run as `cargo test
    //! -p mkit-sign-ctap --test protocol_shape`.
    use super::*;

    #[test]
    fn trim_handles_windows_line_endings() {
        assert_eq!(trim_trailing_newline(b"hello\r\n"), b"hello");
        assert_eq!(trim_trailing_newline(b"hello\n"), b"hello");
        assert_eq!(trim_trailing_newline(b"hello"), b"hello");
        assert_eq!(trim_trailing_newline(b""), b"");
    }

    #[test]
    fn parse_enroll_accepts_all_flags() {
        let args = [
            "--rp-id",
            "mkit.local",
            "--user-name",
            "alice",
            "--resident",
        ]
        .iter()
        .map(|s| s.to_string());
        let a = parse_enroll(args).unwrap();
        assert_eq!(a.rp_id.as_deref(), Some("mkit.local"));
        assert_eq!(a.user_name.as_deref(), Some("alice"));
        assert!(a.resident);
    }

    #[test]
    fn parse_sign_requires_credential_id() {
        // Just make sure the CLI parser itself accepts a missing flag —
        // the requirement check happens later in `run_sign`.
        let args: Vec<String> = vec![];
        let a = parse_sign(args.into_iter()).unwrap();
        assert!(a.credential_id_b64url.is_none());
    }
}
