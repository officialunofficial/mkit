// Module-level clippy allowances: this reference signer's prose is
// heavy with protocol and hardware identifiers (credential_id, rp_id,
// YubiKey, SoloKey, …) that are not load-bearing in the literal sense
// clippy's `doc_markdown` expects, and the small-cast / similar-name
// warnings are from arithmetic patterns whose alternatives would make
// the code harder to read.
#![allow(
    clippy::doc_markdown,
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::similar_names,
    clippy::items_after_statements,
    clippy::missing_panics_doc,
    clippy::must_use_candidate
)]

//! `mkit-sign-ctap` — reference FIDO2/WebAuthn external signer.
//!
//! Drives a plugged-in roaming authenticator (YubiKey, Nitrokey,
//! SoloKey, …) over CTAP-HID and produces signatures wrapped in a
//! WebAuthn assertion. Speaks the mkit-rpc signer protocol
//! (`signer.proto` + `WebAuthnData` extension on `SignResponse`) over
//! length-prefixed buffa frames on stdin/stdout.
//!
//! ## Subcommands
//!
//! * `enroll --rp-id <rpid> --user-name <name> [--pin <pin>]`
//!   — runs a CTAP `make_credential` ceremony and stores the credential
//!   metadata under `$HOME/.mkit-sign-ctap/credentials.json`.
//! * `sign --credential-id <base64url> [--rp-id <rpid>] [--pin <pin>] [--origin <url>]`
//!   — enters the mkit-rpc signer protocol loop on stdin/stdout.
//!   `--credential-id` is a default; the caller MAY override per
//!   request via `SignRequest.key_ref`.
//! * `list-credentials` — dumps the local metadata store.
//!
//! See `docs/specs/SPEC-EXTERNAL-SIGNER.md` for the wire protocol and
//! `contrib/signers/README.md` for how mkit wires this binary in.

use std::io;
use std::process::ExitCode;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64_URL_NOPAD;

mod cred_store;
mod ctap;
mod proto;
mod server;

use ctap::{CtapDevice, RealCtapDevice};
use server::SignDefaults;

fn main() -> ExitCode {
    match run() {
        Ok(()) | Err(SignerError::HelpRequested) => ExitCode::SUCCESS,
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
                );
            }
            "--user-name" => {
                a.user_name = Some(
                    it.next()
                        .ok_or(SignerError::BadArgs("--user-name needs a value"))?,
                );
            }
            "--pin" => {
                a.pin = Some(
                    it.next()
                        .ok_or(SignerError::BadArgs("--pin needs a value"))?,
                );
            }
            other => return Err(SignerError::UnknownArg(other.to_owned())),
        }
    }
    Ok(a)
}

fn run_enroll(it: impl Iterator<Item = String>) -> Result<(), SignerError> {
    let a = parse_enroll(it)?;
    let rp_id = a.rp_id.as_deref().unwrap_or("mkit.local");
    let user_name = a.user_name.as_deref().unwrap_or("mkit-user");

    let device = RealCtapDevice;
    let enrolled = device.make_credential(rp_id, user_name, a.pin.as_deref())?;

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
                );
            }
            "--pin" => {
                a.pin = Some(
                    it.next()
                        .ok_or(SignerError::BadArgs("--pin needs a value"))?,
                );
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
    let defaults = SignDefaults {
        credential_id_b64url: a.credential_id_b64url,
        rp_id: a.rp_id,
        pin: a.pin,
        origin: a.origin,
    };
    let device = RealCtapDevice;
    let stdin = io::stdin();
    let stdout = io::stdout();
    server::serve(&mut stdin.lock(), &mut stdout.lock(), &device, &defaults)
}

// -- list-credentials --------------------------------------------------

fn run_list() -> Result<(), SignerError> {
    let store_path = cred_store::default_path()?;
    let store = cred_store::Store::load(&store_path).unwrap_or_default();
    for r in store.records() {
        println!(
            "credential_id={}\tkeyid={}\trp_id={}\tuser_name={}",
            r.credential_id_b64url, r.keyid, r.rp_id, r.user_name
        );
    }
    Ok(())
}

// -- Misc --------------------------------------------------------------

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
mkit-sign-ctap: FIDO2/WebAuthn external signer

USAGE:
    mkit-sign-ctap enroll --rp-id <rpid> --user-name <name> [--pin <pin>]
    mkit-sign-ctap sign   [--credential-id <base64url>] [--rp-id <rpid>] [--pin <pin>] [--origin <url>]
    mkit-sign-ctap list-credentials

The `sign` subcommand enters the mkit-rpc signer protocol loop on
stdin/stdout (length-prefixed buffa SignerFrames). `--credential-id`
is a default; the caller MAY override per request via
SignRequest.key_ref.

Setup-phase errors (no device, bad args, store IO failure) exit
non-zero with a stderr message. Per-request errors are returned as
protobuf Error frames on stdout.

Requires a plugged-in FIDO2 roaming authenticator (YubiKey / Nitrokey /
SoloKey). See docs/specs/SPEC-EXTERNAL-SIGNER.md for the wire protocol.
";

// -- Errors -----------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum SignerError {
    #[error("bad args: {0}")]
    BadArgs(&'static str),
    #[error("unknown argument: {0}")]
    UnknownArg(String),
    #[error("unknown subcommand: {0}")]
    UnknownSubcommand(String),
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
    use super::*;

    #[test]
    fn parse_enroll_accepts_all_flags() {
        let args = [
            "--rp-id",
            "mkit.local",
            "--user-name",
            "alice",
            "--pin",
            "1234",
        ]
        .iter()
        .map(std::string::ToString::to_string);
        let a = parse_enroll(args).unwrap();
        assert_eq!(a.rp_id.as_deref(), Some("mkit.local"));
        assert_eq!(a.user_name.as_deref(), Some("alice"));
        assert_eq!(a.pin.as_deref(), Some("1234"));
    }

    #[test]
    fn parse_sign_accepts_optional_credential_id() {
        let args: Vec<String> = vec![];
        let a = parse_sign(args.into_iter()).unwrap();
        assert!(a.credential_id_b64url.is_none());
    }
}
