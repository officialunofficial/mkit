// `clippy::ref_option` flags `&Option<T>` arguments. Wire-frame
// fields are `Option<T>` (Edition 2023 explicit presence); passing
// references through helpers is the natural shape.
#![allow(clippy::ref_option)]
#![allow(clippy::too_many_lines)]

//! `mkit-sign-file` — reference external-signer binary.
//!
//! Speaks the mkit-rpc signer protocol (`signer.proto`, length-prefixed
//! buffa frames over stdin/stdout) defined in `docs/SPEC-EXTERNAL-SIGNER.md`.
//!
//! * Reads framed [`SignerFrame`] messages from stdin.
//! * Loads a 32-byte raw private key from disk (`--key <path>` or env var
//!   `MKIT_SIGN_FILE_KEY`).
//! * On Unix, refuses to start if the key file's mode is not `0600` —
//!   the only access control this reference signer performs.
//! * Signs the requested PAE per the requested algorithm using the
//!   per-curve signers in `mkit_attest::signer_*`.
//! * Writes framed responses on stdout.
//!
//! This is a **reference / test implementation**. It is explicitly NOT
//! a production signer:
//!
//! * The secret lives on disk as raw bytes.
//! * No key unwrap / KDF / passphrase.
//! * No audit log.
//! * No rate limiting.
//!
//! Use it to validate your mkit + external-signer setup end-to-end, and
//! as a starting point for your own signer (Secure Enclave, Ledger,
//! `WebAuthn`, `MetaMask` bridge, HSM, …). See SPEC-EXTERNAL-SIGNER.md §12
//! for the security model.

use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use mkit_attest::Algorithm;
use mkit_attest::signer_k256::Secp256k1Signer;
use mkit_attest::signer_p256::P256Signer;
use mkit_attest::signer_repo_key::RepoKeySigner;
use mkit_core::sign::KeyPair;
use mkit_rpc::mkit::rpc::v1::signer::{
    Capabilities, HelloResponse, SignResponse, SignerFrame, signer_frame,
};
use mkit_rpc::mkit::rpc::v1::{Algorithm as RpcAlgorithm, ErrorCode, KeyForm, ProtocolVersion};
use mkit_rpc::{FrameError, read_frame, signer_error_frame, write_frame};
use zeroize::Zeroizing;

/// Top-level entry. Two error layers:
///
/// 1. Setup errors (no key configured, bad permissions, bad argv) exit
///    non-zero with a stderr message — same as before. The signer never
///    got far enough to send a frame.
/// 2. Per-request errors (unsupported algorithm, malformed payload)
///    are sent back as [`SignerFrame::Error`] frames; the binary
///    keeps running until stdin closes.
fn main() -> ExitCode {
    match run() {
        Ok(()) | Err(SignerError::HelpRequested) => ExitCode::SUCCESS,
        Err(e) => {
            // Setup-phase failures — stderr only. Stdout is reserved
            // for the framed protocol; writing a non-frame to stdout
            // would desync any caller still reading.
            eprintln!("mkit-sign-file: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), SignerError> {
    let args = Args::parse(std::env::args().skip(1))?;
    let key_path = args
        .key
        .clone()
        .or_else(|| std::env::var_os("MKIT_SIGN_FILE_KEY").map(PathBuf::from))
        .ok_or(SignerError::NoKey)?;

    let secret = load_key(&key_path)?;

    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut r = stdin.lock();
    let mut w = stdout.lock();

    serve(&mut r, &mut w, &secret, args.algorithm.as_deref())
}

/// Drive the protocol until stdin closes or a fatal error is sent.
///
/// Each iteration reads exactly one frame, dispatches on the oneof
/// body, and writes exactly one response frame. Per-request failures
/// are reported as [`SignerFrame::Error`] without terminating the
/// loop; this matches the protocol's "callers MAY send multiple
/// requests on a single connection" promise even though the file
/// signer is most often spawned per-request by mkit.
fn serve<R: Read, W: Write>(
    r: &mut R,
    w: &mut W,
    secret: &Zeroizing<[u8; 32]>,
    algorithm_override: Option<&str>,
) -> Result<(), SignerError> {
    loop {
        let req: SignerFrame = match read_frame(r) {
            Ok(f) => f,
            // Clean EOF — caller closed the pipe. Exit success.
            Err(FrameError::LengthTruncated) => return Ok(()),
            // Anything else is a protocol-level fatal: oversize frame,
            // truncated body, decode failure. Send a final Error and
            // exit non-zero.
            Err(FrameError::LengthTooLarge(n)) => {
                let _ = write_error(
                    w,
                    ErrorCode::ERROR_CODE_INVALID_REQUEST,
                    format!("frame length {n} exceeds 1 MiB cap"),
                );
                return Err(SignerError::ProtocolFatal("oversize frame".into()));
            }
            Err(FrameError::BodyTruncated { expected, .. }) => {
                let _ = write_error(
                    w,
                    ErrorCode::ERROR_CODE_INVALID_REQUEST,
                    format!("frame body truncated (expected {expected} bytes)"),
                );
                return Err(SignerError::ProtocolFatal("truncated frame".into()));
            }
            Err(FrameError::DecodeFailed) => {
                let _ = write_error(
                    w,
                    ErrorCode::ERROR_CODE_INVALID_REQUEST,
                    "frame failed to decode as SignerFrame".to_owned(),
                );
                return Err(SignerError::ProtocolFatal("decode failure".into()));
            }
            Err(FrameError::Io(e)) => return Err(SignerError::Io(format!("read frame: {e}"))),
        };

        match req.body {
            Some(signer_frame::Body::Hello(_h)) => {
                // Always reply with capabilities. The wire is cheap
                // enough that gating on `want_capabilities` adds
                // complexity without a payoff.
                let resp = SignerFrame {
                    body: Some(signer_frame::Body::HelloResponse(Box::new(HelloResponse {
                        protocol: Some(ProtocolVersion::PROTOCOL_VERSION_1.into()),
                        signer_id: Some(format!("mkit-sign-file/{}", env!("CARGO_PKG_VERSION"))),
                        capabilities: buffa::MessageField::some(Capabilities {
                            algorithms: vec![
                                RpcAlgorithm::ALGORITHM_ED25519.into(),
                                RpcAlgorithm::ALGORITHM_SECP256K1.into(),
                                RpcAlgorithm::ALGORITHM_P256.into(),
                            ],
                            key_forms: vec![KeyForm::KEY_FORM_RAW_BYTES.into()],
                            supports_pin: Some(false),
                            supports_certificate_chain: Some(false),
                            max_payload_bytes: Some(0), // 0 = use framing default
                            requires_user_presence: Some(false),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }))),
                    ..Default::default()
                };
                write_frame(w, &resp).map_err(|e| SignerError::Io(format!("write hello: {e}")))?;
            }

            Some(signer_frame::Body::SignRequest(req_box)) => {
                let resp = handle_sign(&req_box, secret, algorithm_override);
                write_frame(w, &resp).map_err(|e| SignerError::Io(format!("write sign: {e}")))?;
            }

            // The file signer never prompts for a PIN, so a stray
            // PinResponse from the caller is a protocol error.
            Some(signer_frame::Body::PinResponse(_)) => {
                write_error(
                    w,
                    ErrorCode::ERROR_CODE_INVALID_REQUEST,
                    "mkit-sign-file does not request a PIN".to_owned(),
                )?;
            }

            // Everything else is a server-only frame the caller has
            // no business sending us, or an unset oneof.
            Some(other) => {
                write_error(
                    w,
                    ErrorCode::ERROR_CODE_INVALID_REQUEST,
                    format!("unexpected frame: {}", oneof_name(&other)),
                )?;
            }
            None => {
                write_error(
                    w,
                    ErrorCode::ERROR_CODE_INVALID_REQUEST,
                    "empty frame body".to_owned(),
                )?;
            }
        }
    }
}

fn handle_sign(
    req: &mkit_rpc::mkit::rpc::v1::signer::SignRequest,
    secret: &Zeroizing<[u8; 32]>,
    algorithm_override: Option<&str>,
) -> SignerFrame {
    // `--algorithm` argv override takes precedence over the wire
    // request — useful in test harnesses; in normal use the wire
    // value is authoritative.
    let algorithm = match algorithm_override
        .map(parse_argv_algorithm)
        .transpose()
        .and_then(|opt| match opt {
            Some(a) => Ok(a),
            None => map_rpc_algorithm(req.algorithm.as_ref().map_or(0, buffa::EnumValue::to_i32)),
        }) {
        Ok(a) => a,
        Err(e) => {
            return signer_error_frame(ErrorCode::ERROR_CODE_UNSUPPORTED_ALGORITHM, e.to_string());
        }
    };

    // The reference signer only accepts KEY_FORM_RAW_BYTES — the key
    // is a 32-byte file on disk. Reject anything else loudly.
    let key_form = req.key_form.as_ref().map_or(0, buffa::EnumValue::to_i32);
    if key_form != KeyForm::KEY_FORM_RAW_BYTES as i32 && key_form != 0 {
        return signer_error_frame(
            ErrorCode::ERROR_CODE_UNSUPPORTED_KEY_FORM,
            "mkit-sign-file only supports KEY_FORM_RAW_BYTES".to_owned(),
        );
    }

    let pae = req.payload.clone().unwrap_or_default();

    let (keyid, sig, public_key, rpc_alg) = match algorithm {
        Algorithm::Ed25519 => {
            // Borrow through `from_seed_zeroizing` so the inner
            // `[u8; 32]` is never materialised as a `Copy` on this
            // frame — the only memory copies are the `Zeroizing`
            // already-owned one and the `KeyPair::secret` field that
            // zeros on drop.
            let kp = KeyPair::from_seed_zeroizing(secret);
            let pubkey = kp.public.0.to_vec();
            let mut s = RepoKeySigner::new(kp);
            let sig = match <RepoKeySigner as mkit_attest::Signer>::sign(&mut s, &pae) {
                Ok(b) => b,
                Err(e) => {
                    return signer_error_frame(
                        ErrorCode::ERROR_CODE_INTERNAL,
                        format!("ed25519 sign: {e}"),
                    );
                }
            };
            (
                s.keyid_string(),
                sig,
                pubkey,
                RpcAlgorithm::ALGORITHM_ED25519,
            )
        }
        Algorithm::Secp256k1 => {
            // Same rationale as the Ed25519 arm above — pass through
            // the `Zeroizing` borrow rather than `**secret`.
            let s = match Secp256k1Signer::from_seed_zeroizing(secret) {
                Ok(s) => s,
                Err(e) => {
                    return signer_error_frame(
                        ErrorCode::ERROR_CODE_INTERNAL,
                        format!("secp256k1 init: {e}"),
                    );
                }
            };
            let pubkey = s.public_key_sec1();
            let sig = match s.sign_dsse(&pae) {
                Ok(b) => b,
                Err(e) => {
                    return signer_error_frame(
                        ErrorCode::ERROR_CODE_INTERNAL,
                        format!("secp256k1 sign: {e}"),
                    );
                }
            };
            (
                s.keyid_string(),
                sig,
                pubkey,
                RpcAlgorithm::ALGORITHM_SECP256K1,
            )
        }
        Algorithm::P256 => {
            // Same rationale as Ed25519/Secp256k1.
            let s = match P256Signer::from_seed_zeroizing(secret) {
                Ok(s) => s,
                Err(e) => {
                    return signer_error_frame(
                        ErrorCode::ERROR_CODE_INTERNAL,
                        format!("p256 init: {e}"),
                    );
                }
            };
            let pubkey = s.public_key_sec1();
            let sig = match s.sign_dsse(&pae) {
                Ok(b) => b,
                Err(e) => {
                    return signer_error_frame(
                        ErrorCode::ERROR_CODE_INTERNAL,
                        format!("p256 sign: {e}"),
                    );
                }
            };
            (s.keyid(), sig, pubkey, RpcAlgorithm::ALGORITHM_P256)
        }
        #[cfg(feature = "bls-threshold")]
        Algorithm::Bls12381Threshold => {
            return signer_error_frame(
                ErrorCode::ERROR_CODE_UNSUPPORTED_ALGORITHM,
                "mkit-sign-file does not support BLS threshold (issue #160 Phase 3)".to_owned(),
            );
        }
    };

    SignerFrame {
        body: Some(signer_frame::Body::SignResponse(Box::new(
            SignResponse::default()
                .with_signature(sig)
                .with_public_key(public_key)
                .with_algorithm(rpc_alg)
                .with_key_id(keyid),
        ))),
        ..Default::default()
    }
}

fn write_error<W: Write>(w: &mut W, code: ErrorCode, message: String) -> Result<(), SignerError> {
    let frame = signer_error_frame(code, message);
    write_frame(w, &frame).map_err(|e| SignerError::Io(format!("write error frame: {e}")))
}

fn oneof_name(b: &signer_frame::Body) -> &'static str {
    use signer_frame::Body;
    match b {
        Body::Hello(_) => "hello",
        Body::HelloResponse(_) => "hello_response",
        Body::SignRequest(_) => "sign_request",
        Body::SignResponse(_) => "sign_response",
        Body::PinPrompt(_) => "pin_prompt",
        Body::PinResponse(_) => "pin_response",
        Body::Error(_) => "error",
    }
}

fn map_rpc_algorithm(value: i32) -> Result<Algorithm, &'static str> {
    if value == RpcAlgorithm::ALGORITHM_ED25519 as i32 {
        Ok(Algorithm::Ed25519)
    } else if value == RpcAlgorithm::ALGORITHM_SECP256K1 as i32 {
        Ok(Algorithm::Secp256k1)
    } else if value == RpcAlgorithm::ALGORITHM_P256 as i32 {
        Ok(Algorithm::P256)
    } else if value == RpcAlgorithm::ALGORITHM_ED25519_WEBAUTHN as i32 {
        Err("ed25519-webauthn requires the CTAP signer, not the file signer")
    } else {
        Err("unspecified or unknown algorithm")
    }
}

fn parse_argv_algorithm(s: &str) -> Result<Algorithm, &'static str> {
    match s {
        "ed25519" => Ok(Algorithm::Ed25519),
        "secp256k1" => Ok(Algorithm::Secp256k1),
        "p256" => Ok(Algorithm::P256),
        _ => Err("--algorithm must be ed25519 | secp256k1 | p256"),
    }
}

// -- Key loading ----------------------------------------------------------

fn load_key(path: &Path) -> Result<Zeroizing<[u8; 32]>, SignerError> {
    mkit_core::sign::load_raw_32(path).map_err(|e| match e {
        mkit_core::MkitError::InsecureKeyPermissions { actual } => {
            SignerError::KeyBadPermissions(actual)
        }
        mkit_core::MkitError::InvalidKeyLength { actual } => SignerError::KeyBadLength(actual),
        other => SignerError::KeyIo(other.to_string()),
    })
}

// -- Argv / errors --------------------------------------------------------

#[derive(Debug, Default)]
struct Args {
    key: Option<PathBuf>,
    algorithm: Option<String>,
}

impl Args {
    fn parse<I: IntoIterator<Item = String>>(args: I) -> Result<Self, SignerError> {
        let mut out = Args::default();
        let mut it = args.into_iter();
        while let Some(a) = it.next() {
            match a.as_str() {
                "--key" => {
                    let v = it
                        .next()
                        .ok_or(SignerError::BadArgs("--key needs a path"))?;
                    out.key = Some(PathBuf::from(v));
                }
                "--algorithm" => {
                    let v = it
                        .next()
                        .ok_or(SignerError::BadArgs("--algorithm needs a value"))?;
                    out.algorithm = Some(v);
                }
                "-h" | "--help" => {
                    eprintln!("{HELP}");
                    return Err(SignerError::HelpRequested);
                }
                other => {
                    return Err(SignerError::UnknownArg(other.to_owned()));
                }
            }
        }
        Ok(out)
    }
}

const HELP: &str = "\
mkit-sign-file: reference external signer (NOT production)

USAGE:
    mkit-sign-file --key <path> [--algorithm <ed25519|secp256k1|p256>]

Speaks the mkit-rpc signer protocol over stdin/stdout — see
docs/SPEC-EXTERNAL-SIGNER.md and rust/crates/mkit-rpc/proto/signer.proto.

Setup-phase errors (no key, bad permissions, bad argv) exit non-zero
with a stderr message. Per-request errors are returned as protobuf
Error frames on stdout.
";

#[derive(Debug)]
enum SignerError {
    NoKey,
    BadArgs(&'static str),
    UnknownArg(String),
    KeyIo(String),
    KeyBadPermissions(u32),
    KeyBadLength(usize),
    Io(String),
    ProtocolFatal(String),
    HelpRequested,
}

impl std::fmt::Display for SignerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoKey => write!(
                f,
                "no key path — pass --key <path> or set MKIT_SIGN_FILE_KEY"
            ),
            Self::BadArgs(s) => write!(f, "bad args: {s}"),
            Self::UnknownArg(a) => write!(f, "unknown argument: {a}"),
            Self::KeyIo(s) => write!(f, "key file: {s}"),
            Self::KeyBadPermissions(mode) => write!(
                f,
                "key file permissions 0{mode:o} — must be 0600 (chmod 600 <path>)"
            ),
            Self::KeyBadLength(n) => {
                write!(
                    f,
                    "key file is {n} bytes — reference signer expects exactly 32"
                )
            }
            Self::Io(s) => write!(f, "io: {s}"),
            Self::ProtocolFatal(s) => write!(f, "protocol: {s}"),
            Self::HelpRequested => write!(f, "help"),
        }
    }
}

impl std::error::Error for SignerError {}
