//! `mkit-sign-file` — reference external-signer binary.
//!
//! Implements the v1 protocol defined in `docs/SPEC-EXTERNAL-SIGNER.md`:
//!
//! * Reads one line of JSON `{pae_base64, algorithm}` from stdin.
//! * Loads a 32-byte raw private key from disk (`--key <path>` or env var
//!   `MKIT_SIGN_FILE_KEY`).
//! * On Unix, rejects keys whose file mode is not `0600` — the
//!   permission check is the only access control this reference signer
//!   performs.
//! * Signs the PAE per the requested algorithm using the signers in
//!   `mkit_attest::signer_*`.
//! * Emits one line of JSON `{keyid, sig_base64}` on stdout.
//! * Exits 0 on success, non-zero with a stderr message on any error.
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

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use mkit_attest::Algorithm;
use mkit_attest::signer_k256::Secp256k1Signer;
use mkit_attest::signer_p256::P256Signer;
use mkit_attest::signer_repo_key::RepoKeySigner;
use mkit_core::sign::KeyPair;
use serde::Deserialize;

/// Top-level entry. Routes every error through a single stderr-and-exit
/// path so a non-zero exit always carries a human-readable one-liner
/// per SPEC-EXTERNAL-SIGNER §5.
fn main() -> ExitCode {
    match run() {
        // Both `Ok(())` and a `--help` early-exit are success cases:
        // on help, the text was already printed to stderr inside
        // `Args::parse` and stdout was never touched, so exiting 0
        // leaves callers with a clean read-buffer.
        Ok(()) | Err(SignerError::HelpRequested) => ExitCode::SUCCESS,
        Err(e) => {
            // Never write to stdout on the error path — the spec says
            // "stdout SHOULD be empty on error" and mkit treats a
            // non-empty stdout from a failing child as a parse hazard.
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

    // Read the request JSON from stdin. Cap the buffer at 1 MiB per
    // SPEC-EXTERNAL-SIGNER §6 — mkit's real requests are ~200 bytes
    // but we accept the same DoS cap mkit itself advertises.
    let mut buf = Vec::with_capacity(256);
    std::io::stdin()
        .take(1024 * 1024 + 1)
        .read_to_end(&mut buf)
        .map_err(|e| SignerError::Io(format!("read stdin: {e}")))?;
    if buf.len() > 1024 * 1024 {
        return Err(SignerError::RequestTooLarge);
    }

    let req: Request =
        serde_json::from_slice(trim_trailing_newline(&buf)).map_err(|_| SignerError::BadRequest)?;

    // `--algorithm` override lets a caller force a different algorithm
    // than the request asks for. Useful for testing; in normal use
    // mkit's `algorithm` field is authoritative.
    let algorithm = if let Some(ref explicit) = args.algorithm {
        parse_algorithm(explicit)?
    } else {
        parse_algorithm(&req.algorithm)?
    };

    let pae = B64
        .decode(req.pae_base64.as_bytes())
        .map_err(|_| SignerError::BadRequest)?;

    // Dispatch per algorithm. Each signer re-parses the raw 32-byte
    // scalar under its own curve's validity rules; an out-of-range
    // scalar surfaces as the per-algorithm typed error.
    let (keyid, sig) = match algorithm {
        Algorithm::Ed25519 => {
            // `RepoKeySigner` wraps mkit-core's KeyPair which derives
            // the Ed25519 pubkey from the 32-byte seed. The keyid it
            // emits is `blake3:<hex-of-pubkey-hash>` — legacy-compat
            // form, accepted by the verifier (see Algorithm::from_keyid).
            let kp = KeyPair::from_seed(secret);
            let mut s = RepoKeySigner::new(kp);
            let sig = <RepoKeySigner as mkit_attest::Signer>::sign(&mut s, &pae)
                .map_err(SignerError::Attest)?;
            (s.keyid_string(), sig)
        }
        Algorithm::Secp256k1 => {
            let s = Secp256k1Signer::new(secret).map_err(SignerError::Attest)?;
            let sig = s.sign_dsse(&pae).map_err(SignerError::Attest)?;
            (s.keyid_string(), sig)
        }
        Algorithm::P256 => {
            let s = P256Signer::new(secret).map_err(SignerError::Attest)?;
            let sig = s.sign_dsse(&pae).map_err(SignerError::Attest)?;
            (s.keyid(), sig)
        }
    };

    // Single-line JSON response, trailing newline. Emitting keys in
    // `keyid` then `sig_base64` order matches every example in the
    // spec; field order is not normatively required.
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    writeln!(
        out,
        "{{\"keyid\":\"{}\",\"sig_base64\":\"{}\"}}",
        keyid,
        B64.encode(&sig)
    )
    .map_err(|e| SignerError::Io(format!("write stdout: {e}")))?;
    Ok(())
}

// -- Key loading ----------------------------------------------------------

/// Load the 32-byte raw key at `path`. On Unix, refuses to proceed if
/// the file's permission bits are not exactly `0600` — this reference
/// signer's only access-control story is that the OS already enforces
/// "only the owning user can read this file." A mode of 0644 or more
/// permissive allows other users on a multi-user box to read the key
/// out of band; we fail closed.
fn load_key(path: &Path) -> Result<[u8; 32], SignerError> {
    mkit_core::sign::load_raw_32(path)
        .map_err(|e| match e {
            mkit_core::MkitError::InsecureKeyPermissions { actual } => {
                SignerError::KeyBadPermissions(actual)
            }
            mkit_core::MkitError::InvalidKeyLength { actual } => SignerError::KeyBadLength(actual),
            other => SignerError::KeyIo(other.to_string()),
        })
        .map(|secret| *secret)
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
                    // Help goes to stdout per POSIX convention when
                    // explicitly requested; but because this binary's
                    // normal stdout is reserved for the response JSON,
                    // we print help to stderr and exit 0. Callers
                    // parsing stdout never see it.
                    eprintln!("{HELP}");
                    // Swallow exit via a dedicated sentinel. `run` will
                    // treat this as success.
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

Reads {pae_base64, algorithm} JSON from stdin.
Writes  {keyid, sig_base64}     JSON to   stdout.
Exits 0 on success, non-zero with a stderr message otherwise.

See docs/SPEC-EXTERNAL-SIGNER.md for the wire protocol.
";

fn parse_algorithm(s: &str) -> Result<Algorithm, SignerError> {
    match s {
        "ed25519" => Ok(Algorithm::Ed25519),
        "secp256k1" => Ok(Algorithm::Secp256k1),
        "p256" => Ok(Algorithm::P256),
        other => Err(SignerError::UnknownAlgorithm(other.to_owned())),
    }
}

fn trim_trailing_newline(b: &[u8]) -> &[u8] {
    let mut end = b.len();
    while end > 0 && (b[end - 1] == b'\n' || b[end - 1] == b'\r') {
        end -= 1;
    }
    &b[..end]
}

#[derive(Debug, Deserialize)]
struct Request {
    pae_base64: String,
    algorithm: String,
}

#[derive(Debug)]
enum SignerError {
    NoKey,
    BadArgs(&'static str),
    UnknownArg(String),
    UnknownAlgorithm(String),
    BadRequest,
    RequestTooLarge,
    KeyIo(String),
    KeyBadPermissions(u32),
    KeyBadLength(usize),
    Io(String),
    Attest(mkit_attest::Error),
    /// Internal sentinel so `--help` prints without `main` returning
    /// `ExitCode::FAILURE`. Converted to `Ok(())` in `run`'s caller is
    /// too spread out — we just special-case at the top of `main`
    /// through a distinct branch.
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
            Self::UnknownAlgorithm(a) => write!(
                f,
                "unknown algorithm `{a}` (want ed25519 | secp256k1 | p256)"
            ),
            Self::BadRequest => write!(
                f,
                "could not parse stdin request JSON (expected {{pae_base64, algorithm}})"
            ),
            Self::RequestTooLarge => write!(f, "stdin request exceeds 1 MiB"),
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
            Self::Attest(e) => write!(f, "attest: {e}"),
            Self::HelpRequested => write!(f, "help"),
        }
    }
}

impl std::error::Error for SignerError {}
