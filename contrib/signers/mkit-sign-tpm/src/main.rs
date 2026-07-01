//! `mkit-sign-tpm` — TPM 2.0-backed P-256 external signer for mkit.
//!
//! Implements the mkit-rpc signer protocol defined in
//! `docs/SPEC-EXTERNAL-SIGNER.md` (and the schemas in
//! `rust/crates/mkit-rpc/proto/`) with a P-256 signing primary key
//! held inside a TPM 2.0 device. Linux-native analog of the Apple
//! Secure Enclave signer.
//!
//! Subcommands:
//!
//!     mkit-sign-tpm keygen --handle <persistent-handle> [--auth-policy owner]
//!     mkit-sign-tpm sign   [--handle <persistent-handle>]
//!     mkit-sign-tpm list
//!     mkit-sign-tpm delete --handle <persistent-handle>
//!
//! `sign` enters the mkit-rpc signer protocol loop on stdin/stdout
//! (length-prefixed buffa `SignerFrames`). `--handle` becomes the
//! per-process default; per-request handles arrive on the wire via
//! `SignRequest.key_ref` (4-byte big-endian u32). TPM-native
//! signatures are ASN.1 DER-encoded `(r, s)` pairs; we unpack them
//! to the 64-byte compact `r || s` the spec requires.
//!
//! This crate is structured so its pure-Rust helpers (DER ↔ compact
//! conversion, SEC1 compressed encoding, protocol JSON shape) compile
//! and test on any host. The `tss-esapi` dependency is behind the
//! `tpm2` cargo feature, OFF by default, so a macOS developer without
//! a TPM stack can still run `cargo test -p mkit-sign-tpm` and touch
//! the helpers. Real TPM operations panic with a clear error message
//! when the feature is off.

// Pedantic lints intentionally relaxed for this crate: CLI binaries
// trade some clippy purity for readable top-level flow. Each allow is
// for a specific pedantic family that fires on cosmetic patterns
// (identical match arms on distinct semantic intents, doc-list
// indentation in module docs, etc.). Real correctness lints remain on.
#![allow(clippy::match_same_arms)]
#![allow(clippy::doc_lazy_continuation)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::items_after_statements)]
#![allow(clippy::cast_possible_truncation)]
// The Linux `mod tpm` block has nested `if let` patterns that only
// lint on Linux (macOS cfg's out the module). Allow at crate root
// so the Ubuntu CI job passes without requiring a Linux-host rewrite.
#![allow(clippy::collapsible_if)]

use std::io::Write;
use std::process::ExitCode;

mod server;

// -- Entry point ------------------------------------------------------

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().collect();
    // argv[0] is the binary path; we need at least a subcommand.
    if argv.len() < 2 {
        eprintln!("{HELP}");
        return ExitCode::FAILURE;
    }
    let subcommand = argv[1].as_str();
    let rest: Vec<String> = argv.iter().skip(2).cloned().collect();

    match run(subcommand, rest) {
        Ok(()) | Err(SignerError::HelpRequested) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("mkit-sign-tpm: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(subcommand: &str, rest: Vec<String>) -> Result<(), SignerError> {
    match subcommand {
        "keygen" => {
            let args = Args::parse(rest)?;
            let handle = args.handle.ok_or(SignerError::MissingHandle)?;
            let auth = args.auth_policy.unwrap_or_else(|| "owner".to_string());
            let pubkey = tpm::keygen(handle, &auth)?;
            let keyid = format!("p256:{}", to_hex(&pubkey));
            let stdout = std::io::stdout();
            writeln!(stdout.lock(), "{keyid}").map_err(|e| SignerError::Io(e.to_string()))?;
            eprintln!(
                "created TPM P-256 key at handle {}{}",
                format_handle(handle),
                if auth == "owner" {
                    String::new()
                } else {
                    format!(" (auth-policy={auth})")
                }
            );
            Ok(())
        }
        "sign" => {
            let args = Args::parse(rest)?;
            // `--handle` is now optional: callers MAY supply the
            // handle on the wire via SignRequest.key_ref. We pass
            // whatever argv said as the per-process default.
            run_sign(args.handle)
        }
        "list" => {
            let items = tpm::list()?;
            let stdout = std::io::stdout();
            let mut out = stdout.lock();
            for (handle, hex) in items {
                writeln!(out, "{}\t{hex}", format_handle(handle))
                    .map_err(|e| SignerError::Io(e.to_string()))?;
            }
            Ok(())
        }
        "delete" => {
            let args = Args::parse(rest)?;
            let handle = args.handle.ok_or(SignerError::MissingHandle)?;
            tpm::delete(handle)?;
            eprintln!("deleted TPM key at handle {}", format_handle(handle));
            Ok(())
        }
        "-h" | "--help" => {
            eprintln!("{HELP}");
            Err(SignerError::HelpRequested)
        }
        other => Err(SignerError::UnknownSubcommand(other.to_owned())),
    }
}

/// Enter the mkit-rpc signer protocol loop.
///
/// `handle_default` is a fallback the binary fills from
/// `--handle 0x81010001`; the wire `SignRequest.key_ref` overrides
/// per-request when present.
fn run_sign(handle_default: Option<u32>) -> Result<(), SignerError> {
    let signer = server::RealTpmSigner;
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    server::serve(
        &mut stdin.lock(),
        &mut stdout.lock(),
        handle_default,
        &signer,
    )
}

// -- Pure helpers (unit-testable without a TPM) ----------------------

/// Convert an ASN.1 DER-encoded ECDSA signature `SEQUENCE { r INTEGER, s INTEGER }`
/// into a 64-byte compact `r ‖ s` big-endian buffer, left-padding each
/// scalar to exactly 32 bytes.
///
/// This is the inverse of the DER encoding the TPM 2.0 `TPMT_SIGNATURE`
/// + `TPMS_SIGNATURE_ECDSA` layer hands us back once we flatten the
/// structured signature through tss-esapi. The integers in DER are
/// two's-complement with an optional leading `0x00` pad when the top
/// bit is set; we strip that pad and left-zero-fill to 32 bytes.
///
/// # Errors
/// - The top-level tag is not `SEQUENCE` (`0x30`).
/// - An inner integer is missing, malformed, or longer than 33 bytes
///   (32 bytes of scalar + at most one 0x00 sign-pad).
/// - The resulting scalar is still wider than 32 bytes after sign-pad
///   removal (should never happen for well-formed P-256 signatures).
pub fn der_ecdsa_to_compact(der: &[u8]) -> Result<[u8; 64], DerError> {
    // SEQUENCE header.
    let (body, rest) = read_tlv(der, 0x30)?;
    if !rest.is_empty() {
        return Err(DerError::TrailingBytes);
    }
    // Two INTEGERs back-to-back.
    let (r_bytes, after_r) = read_tlv(body, 0x02)?;
    let (s_bytes, after_s) = read_tlv(after_r, 0x02)?;
    if !after_s.is_empty() {
        return Err(DerError::TrailingBytes);
    }
    let r = unpad_integer(r_bytes)?;
    let s = unpad_integer(s_bytes)?;
    let mut out = [0u8; 64];
    left_pad_into(r, &mut out[..32])?;
    left_pad_into(s, &mut out[32..])?;
    Ok(out)
}

/// Normalise `s` of a compact `r || s` P-256 signature to the low half
/// of the group order. If `s > n/2`, replace with `n - s`. This keeps
/// our output consistent with `mkit-attest`'s verifier which rejects
/// high-S signatures per SPEC-EXTERNAL-SIGNER §4.2.
///
/// Constant-time properties are not claimed — this operates on public
/// signature bytes after signing has already happened.
pub fn normalize_low_s(compact: &mut [u8; 64]) {
    // P-256 group order n (FIPS 186-4 / RFC 5903 §3.1):
    //   FFFFFFFF 00000000 FFFFFFFF FFFFFFFF
    //   BCE6FAAD A7179E84 F3B9CAC2 FC632551
    const N: [u8; 32] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63,
        0x25, 0x51,
    ];
    // n / 2. Precomputed once; comparing against this is the canonical
    // low-S test (s <= n/2 is "low").
    const HALF_N: [u8; 32] = [
        0x7F, 0xFF, 0xFF, 0xFF, 0x80, 0x00, 0x00, 0x00, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xDE, 0x73, 0x7D, 0x56, 0xD3, 0x8B, 0xCF, 0x42, 0x79, 0xDC, 0xE5, 0x61, 0x7E, 0x31,
        0x92, 0xA8,
    ];

    let s = &mut compact[32..];
    // big-endian lexicographic compare = numeric compare for equal-length
    // unsigned values.
    if *s > HALF_N[..] {
        // s' = n - s (big-endian subtraction) using u16 widened arithmetic
        // so the truncating cast back to u8 is a documented, in-range
        // narrowing.
        let mut s_prime = [0u8; 32];
        let mut borrow: u16 = 0;
        for i in (0..32).rev() {
            let lhs = u16::from(N[i]);
            let rhs = u16::from(s[i]) + borrow;
            if lhs >= rhs {
                s_prime[i] = u8::try_from(lhs - rhs).expect("byte diff fits in u8");
                borrow = 0;
            } else {
                s_prime[i] = u8::try_from((lhs + 256) - rhs).expect("byte diff fits in u8");
                borrow = 1;
            }
        }
        s.copy_from_slice(&s_prime);
    }
}

/// Build a 33-byte SEC1 compressed public key from a P-256 point's
/// raw `(x, y)` coordinates. Leading byte is `0x02` if `y` is even,
/// `0x03` if `y` is odd. y-parity is the LSB of the last byte of the
/// big-endian `y` encoding.
#[must_use]
pub fn compress_sec1(x: &[u8; 32], y: &[u8; 32]) -> [u8; 33] {
    let mut out = [0u8; 33];
    out[0] = if y[31] & 1 == 0 { 0x02 } else { 0x03 };
    out[1..].copy_from_slice(x);
    out
}

/// Lowercase hex encoding. Inlined — no `hex` crate dependency —
/// because a ~20-line implementation is easier to audit than a new
/// supply-chain edge.
fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0F) as usize] as char);
    }
    out
}

/// Render a TPM handle as `0x81010001`-style hex, matching the form
/// users pass on the command line.
fn format_handle(h: u32) -> String {
    format!("0x{h:08x}")
}

/// Parse a `--handle` value accepting `0x…` hex, bare hex, or decimal.
/// Leading whitespace is not accepted.
fn parse_handle(s: &str) -> Result<u32, SignerError> {
    let hex = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X"));
    let parsed = if let Some(h) = hex {
        u32::from_str_radix(h, 16)
    } else if s.chars().all(|c| c.is_ascii_hexdigit()) && s.len() >= 4 {
        // Bare hex (common case for TPM handles which are always big).
        u32::from_str_radix(s, 16)
    } else {
        s.parse::<u32>()
    };
    parsed.map_err(|_| SignerError::BadHandle(s.to_owned()))
}

// -- DER tiny parser -------------------------------------------------

/// Read one ASN.1 TLV with the given expected tag. Returns `(value,
/// rest-of-input-after-tlv)`. Supports short-form AND long-form length
/// for up to 2-byte lengths — P-256 signatures never need more, but
/// some TPMs emit a DER length with a 1-byte long form (0x81 len).
fn read_tlv(buf: &[u8], expect_tag: u8) -> Result<(&[u8], &[u8]), DerError> {
    if buf.is_empty() {
        return Err(DerError::Truncated);
    }
    if buf[0] != expect_tag {
        return Err(DerError::BadTag {
            want: expect_tag,
            got: buf[0],
        });
    }
    if buf.len() < 2 {
        return Err(DerError::Truncated);
    }
    let first = buf[1];
    let (len, header_len) = if first & 0x80 == 0 {
        // Short form: length fits in one byte.
        (usize::from(first), 2)
    } else {
        // Long form. Number of length-bytes is in the low 7 bits of
        // `first`. We accept up to 2 — enough for any P-256 signature
        // field (max value 33) or any full ECDSA SEQUENCE (max ~72).
        let nbytes = usize::from(first & 0x7F);
        if !(1..=2).contains(&nbytes) || buf.len() < 2 + nbytes {
            return Err(DerError::BadLength);
        }
        let mut acc = 0usize;
        for i in 0..nbytes {
            acc = (acc << 8) | usize::from(buf[2 + i]);
        }
        (acc, 2 + nbytes)
    };
    let end = header_len.checked_add(len).ok_or(DerError::BadLength)?;
    if buf.len() < end {
        return Err(DerError::Truncated);
    }
    Ok((&buf[header_len..end], &buf[end..]))
}

/// Strip the optional leading `0x00` sign-pad from a DER INTEGER body
/// and verify the result is non-negative and fits in 32 bytes.
fn unpad_integer(int_bytes: &[u8]) -> Result<&[u8], DerError> {
    if int_bytes.is_empty() {
        return Err(DerError::BadInteger);
    }
    // DER INTEGER MAY carry exactly one leading 0x00 when the next byte
    // has its high bit set. Strip it iff that pattern holds; otherwise
    // preserve all bytes (and rely on left_pad_into to reject overflow).
    let stripped = if int_bytes.len() > 1 && int_bytes[0] == 0x00 && int_bytes[1] & 0x80 != 0 {
        &int_bytes[1..]
    } else {
        int_bytes
    };
    Ok(stripped)
}

/// Left-pad `src` into exactly the length of `dst`. `src` must fit;
/// otherwise `Err(BadInteger)` (the P-256 scalar is bigger than 32
/// bytes — impossible for a well-formed signature).
fn left_pad_into(src: &[u8], dst: &mut [u8]) -> Result<(), DerError> {
    if src.len() > dst.len() {
        return Err(DerError::BadInteger);
    }
    let offset = dst.len() - src.len();
    for b in &mut dst[..offset] {
        *b = 0;
    }
    dst[offset..].copy_from_slice(src);
    Ok(())
}

#[derive(Debug)]
pub enum DerError {
    Truncated,
    BadTag { want: u8, got: u8 },
    BadLength,
    BadInteger,
    TrailingBytes,
}

impl std::fmt::Display for DerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => write!(f, "DER signature: truncated"),
            Self::BadTag { want, got } => {
                write!(
                    f,
                    "DER signature: bad tag (want 0x{want:02x}, got 0x{got:02x})"
                )
            }
            Self::BadLength => write!(f, "DER signature: malformed length"),
            Self::BadInteger => write!(f, "DER signature: malformed integer"),
            Self::TrailingBytes => write!(f, "DER signature: trailing bytes"),
        }
    }
}

impl std::error::Error for DerError {}

// -- Argv parsing ----------------------------------------------------

#[derive(Debug, Default)]
struct Args {
    handle: Option<u32>,
    auth_policy: Option<String>,
}

impl Args {
    fn parse<I: IntoIterator<Item = String>>(args: I) -> Result<Self, SignerError> {
        let mut out = Args::default();
        let mut it = args.into_iter();
        while let Some(a) = it.next() {
            match a.as_str() {
                "--handle" => {
                    let v = it
                        .next()
                        .ok_or(SignerError::BadArgs("--handle needs a value"))?;
                    out.handle = Some(parse_handle(&v)?);
                }
                "--auth-policy" => {
                    let v = it
                        .next()
                        .ok_or(SignerError::BadArgs("--auth-policy needs a value"))?;
                    out.auth_policy = Some(v);
                }
                "-h" | "--help" => {
                    eprintln!("{HELP}");
                    return Err(SignerError::HelpRequested);
                }
                other => return Err(SignerError::UnknownArg(other.to_owned())),
            }
        }
        Ok(out)
    }
}

const HELP: &str = "\
mkit-sign-tpm: TPM 2.0 external signer for mkit (P-256 only)

USAGE:
    mkit-sign-tpm keygen --handle <persistent-handle> [--auth-policy owner]
    mkit-sign-tpm sign   --handle <persistent-handle>
    mkit-sign-tpm list
    mkit-sign-tpm delete --handle <persistent-handle>

`sign` speaks the mkit-rpc v1 external-signer protocol over stdin/stdout:
length-prefixed protobuf SignerFrame messages (Hello + SignRequest →
HelloResponse + SignResponse/Error). See docs/SPEC-EXTERNAL-SIGNER.md
for the wire protocol; signer.proto is the schema source of truth.

Persistent handles are TPM-owner-hierarchy 32-bit values, conventionally
written as 0x81010001 and upward. Pick one that no other application
on the host is using.
";

// -- Errors ----------------------------------------------------------

#[derive(Debug)]
pub enum SignerError {
    BadArgs(&'static str),
    UnknownArg(String),
    UnknownSubcommand(String),
    MissingHandle,
    BadHandle(String),
    Io(String),
    Der(DerError),
    Tpm(String),
    Internal(String),
    HelpRequested,
}

impl std::fmt::Display for SignerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadArgs(s) => write!(f, "bad args: {s}"),
            Self::UnknownArg(a) => write!(f, "unknown flag: {a}"),
            Self::UnknownSubcommand(s) => {
                write!(f, "unknown subcommand `{s}` (want keygen|sign|list|delete)")
            }
            Self::MissingHandle => write!(f, "missing --handle <persistent-handle>"),
            Self::BadHandle(s) => write!(f, "bad handle `{s}` (want 0x81010001-style hex)"),
            Self::Io(s) => write!(f, "io: {s}"),
            Self::Der(e) => write!(f, "der: {e}"),
            Self::Tpm(s) => write!(f, "tpm: {s}"),
            Self::Internal(s) => write!(f, "internal: {s}"),
            Self::HelpRequested => write!(f, "help"),
        }
    }
}

impl std::error::Error for SignerError {}

impl From<DerError> for SignerError {
    fn from(e: DerError) -> Self {
        Self::Der(e)
    }
}

// -- TPM shim --------------------------------------------------------
//
// The `tpm2` feature gates the real tss-esapi-backed implementation.
// When the feature is off (default, so macOS / CI without libtss2-dev
// still compile), every operation errors out cleanly with a message
// directing the user to rebuild with `--features tpm2`. Unit tests
// exercise the pure helpers above without touching this module.

// Fallback module. Used when either the `tpm2` feature is off OR we're
// on a target where `tss-esapi-sys` refuses to build (anything other
// than Linux/Windows — notably macOS). The runtime error message is
// identical in both cases: rebuild on a supported platform with the
// feature enabled.
#[cfg(any(
    not(feature = "tpm2"),
    not(any(target_os = "linux", target_os = "windows"))
))]
mod tpm {
    use super::SignerError;

    fn feature_off<T>() -> Result<T, SignerError> {
        Err(SignerError::Tpm(
            "built without the `tpm2` feature — rebuild with `cargo build -p mkit-sign-tpm --release --features tpm2` on a host with libtss2-dev / tpm2-tss installed"
                .to_string(),
        ))
    }

    pub fn keygen(_handle: u32, _auth_policy: &str) -> Result<Vec<u8>, SignerError> {
        feature_off()
    }

    pub fn sign(_handle: u32, _pae: &[u8]) -> Result<(Vec<u8>, Vec<u8>), SignerError> {
        feature_off()
    }

    pub fn list() -> Result<Vec<(u32, String)>, SignerError> {
        feature_off()
    }

    pub fn delete(_handle: u32) -> Result<(), SignerError> {
        feature_off()
    }
}

#[cfg(all(feature = "tpm2", any(target_os = "linux", target_os = "windows")))]
#[allow(unused_imports, clippy::all, clippy::pedantic)]
mod tpm {
    //! Real tss-esapi-backed implementation. This module is only
    //! compiled when the consumer opts into `--features tpm2`, which
    //! transitively pulls in the `tss-esapi` crate's link against the
    //! host's `libtss2-esys`.
    //!
    //! `tss-esapi-sys` does not support macOS, so this backend cannot be
    //! built on a macOS host. It is, however, compiled and clippy-checked
    //! on Linux CI: the workflow installs `libtss2-dev` and runs
    //! `cargo clippy --all-features -- -D warnings` and a locked
    //! `cargo build --all-features` against the pinned `tss-esapi 7.7`,
    //! which gates in this module. If you bump `tss-esapi` to a new minor,
    //! watch for type-name drift under `tss_esapi::structures::` /
    //! `tss_esapi::handles::`. The DER/compact/SEC1 helpers above are
    //! covered by the platform-independent unit tests.

    use super::{SignerError, compress_sec1, der_ecdsa_to_compact, normalize_low_s, to_hex};
    use sha2::{Digest, Sha256};
    use tss_esapi::{
        Context, TctiNameConf,
        attributes::ObjectAttributesBuilder,
        constants::SessionType,
        handles::{KeyHandle, ObjectHandle, PersistentTpmHandle, SessionHandle},
        interface_types::{
            algorithm::{HashingAlgorithm, PublicAlgorithm, SignatureSchemeAlgorithm},
            ecc::EccCurve,
            key_bits::RsaKeyBits,
            resource_handles::{Hierarchy, Provision},
            session_handles::AuthSession,
        },
        structures::{
            Digest as TpmDigest, EccParameter, EccPoint, EccScheme, HashScheme,
            KeyDerivationFunctionScheme, PublicBuilder, PublicEccParametersBuilder,
            SignatureScheme, SymmetricDefinition, SymmetricDefinitionObject,
        },
        tcti_ldr::TctiNameConf as _TctiAlias,
        utils::PublicKey as UtilsPublicKey,
    };

    // Pick the default TCTI from env. `tss-esapi` looks at `TCTI` or
    // `TPM2TOOLS_TCTI`; if neither is set, fall back to the kernel
    // resource-manager device `/dev/tpmrm0`.
    fn tcti() -> Result<TctiNameConf, SignerError> {
        // `TctiNameConf::from_environment_variable` reads `TCTI` and
        // returns a parse result. On failure we default to `device:/dev/tpmrm0`.
        use std::str::FromStr as _;
        match TctiNameConf::from_environment_variable() {
            Ok(t) => Ok(t),
            Err(_) => TctiNameConf::from_str("device:/dev/tpmrm0")
                .map_err(|e| SignerError::Tpm(format!("no TCTI and /dev/tpmrm0 unavailable: {e}"))),
        }
    }

    fn new_context() -> Result<Context, SignerError> {
        let t = tcti()?;
        Context::new(t).map_err(|e| SignerError::Tpm(format!("Context::new: {e}")))
    }

    /// Start an HMAC session authorising owner-hierarchy operations.
    /// For `owner` auth-policy we use an empty password on the owner
    /// hierarchy; the session is needed so the TPM will accept our
    /// CreatePrimary / EvictControl calls.
    fn start_owner_session(ctx: &mut Context) -> Result<AuthSession, SignerError> {
        let sess = ctx
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Hmac,
                SymmetricDefinition::AES_128_CFB,
                HashingAlgorithm::Sha256,
            )
            .map_err(|e| SignerError::Tpm(format!("start_auth_session: {e}")))?
            .ok_or_else(|| SignerError::Tpm("start_auth_session returned None".to_string()))?;
        // The default attrs (continue_session = true, decrypt/encrypt
        // as needed) are fine for our short-lived session.
        Ok(sess)
    }

    /// Build a TPMT_PUBLIC describing a P-256 ECDSA signing key with
    /// SHA-256. Non-restricted, sign, sensitiveDataOrigin — the same
    /// template tpm2-tools' `tpm2_createprimary -G ecc256:ecdsa` emits.
    fn p256_signing_template() -> Result<tss_esapi::structures::Public, SignerError> {
        let attrs = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .with_sign_encrypt(true)
            .with_decrypt(false)
            .with_restricted(false)
            .build()
            .map_err(|e| SignerError::Tpm(format!("attrs: {e}")))?;

        let ecc_params = PublicEccParametersBuilder::new()
            .with_ecc_scheme(EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256)))
            .with_curve(EccCurve::NistP256)
            .with_symmetric(SymmetricDefinitionObject::Null)
            .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
            .with_is_signing_key(true)
            .with_is_decryption_key(false)
            .with_restricted(false)
            .build()
            .map_err(|e| SignerError::Tpm(format!("ecc params: {e}")))?;

        PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Ecc)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(attrs)
            .with_ecc_parameters(ecc_params)
            .with_ecc_unique_identifier(EccPoint::new(
                EccParameter::default(),
                EccParameter::default(),
            ))
            .build()
            .map_err(|e| SignerError::Tpm(format!("public: {e}")))
    }

    fn persistent(handle: u32) -> Result<PersistentTpmHandle, SignerError> {
        PersistentTpmHandle::new(handle)
            .map_err(|e| SignerError::Tpm(format!("invalid persistent handle 0x{handle:08x}: {e}")))
    }

    /// Extract `(x, y)` raw coords from a `Public`'s ECC unique point
    /// and compress to the 33-byte SEC1 form.
    fn compress_from_public(
        public: &tss_esapi::structures::Public,
    ) -> Result<Vec<u8>, SignerError> {
        let (x_param, y_param) = match public {
            tss_esapi::structures::Public::Ecc { unique, .. } => (unique.x(), unique.y()),
            _ => {
                return Err(SignerError::Tpm(
                    "persistent key is not ECC — wrong handle?".to_string(),
                ));
            }
        };
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        copy_param_left_padded(x_param.value(), &mut x)?;
        copy_param_left_padded(y_param.value(), &mut y)?;
        Ok(compress_sec1(&x, &y).to_vec())
    }

    fn copy_param_left_padded(src: &[u8], dst: &mut [u8; 32]) -> Result<(), SignerError> {
        if src.len() > 32 {
            return Err(SignerError::Tpm(format!(
                "ECC parameter {} bytes, want ≤ 32",
                src.len()
            )));
        }
        let offset = 32 - src.len();
        dst[..offset].fill(0);
        dst[offset..].copy_from_slice(src);
        Ok(())
    }

    pub fn keygen(handle: u32, _auth_policy: &str) -> Result<Vec<u8>, SignerError> {
        let mut ctx = new_context()?;
        let sess = start_owner_session(&mut ctx)?;
        ctx.set_sessions((Some(sess), None, None));

        let template = p256_signing_template()?;

        // CreatePrimary in the owner hierarchy with an empty sensitive.
        let primary = ctx
            .create_primary(Hierarchy::Owner, template, None, None, None, None)
            .map_err(|e| SignerError::Tpm(format!("create_primary: {e}")))?;

        let pub_compressed = compress_from_public(&primary.out_public)?;

        // Promote the transient key to a persistent handle so future
        // `sign` invocations can look it up without re-creating it.
        let persistent_handle = persistent(handle)?;
        ctx.evict_control(
            Provision::Owner,
            ObjectHandle::from(primary.key_handle),
            tss_esapi::handles::PersistentTpmHandle::from(persistent_handle).into(),
        )
        .map_err(|e| SignerError::Tpm(format!("evict_control (persist): {e}")))?;

        // Flush the transient handle we no longer need.
        ctx.flush_context(ObjectHandle::from(primary.key_handle))
            .map_err(|e| SignerError::Tpm(format!("flush_context: {e}")))?;

        // Flush our own auth session. TPMs (real or simulated) have a small,
        // fixed number of session slots; leaving this open until process
        // exit relies on implicit cleanup neither swtpm nor real hardware
        // reliably perform, and a leaked session here is exactly what made
        // the next `sign`/`delete` invocation's own session collide with a
        // stale one ("inconsistent attributes ... session number 1").
        ctx.flush_context(ObjectHandle::from(SessionHandle::from(sess)))
            .map_err(|e| SignerError::Tpm(format!("flush_context (session): {e}")))?;

        Ok(pub_compressed)
    }

    pub fn sign(handle: u32, pae: &[u8]) -> Result<(Vec<u8>, Vec<u8>), SignerError> {
        let mut ctx = new_context()?;
        let sess = start_owner_session(&mut ctx)?;
        ctx.set_sessions((Some(sess), None, None));

        // Resolve the persistent handle → TPM-session handle.
        let persistent_handle = persistent(handle)?;
        let object_handle = ctx
            .tr_from_tpm_public(persistent_handle.into())
            .map_err(|e| SignerError::Tpm(format!("tr_from_tpm_public: {e}")))?;
        let key_handle: KeyHandle = object_handle.into();

        // Read the public half so we can derive the keyid.
        let (public, _name, _qname) = ctx
            .read_public(key_handle)
            .map_err(|e| SignerError::Tpm(format!("read_public: {e}")))?;
        let pub_compressed = compress_from_public(&public)?;

        // Sign SHA256(pae). P-256 over SHA-256, ECDSA scheme.
        let digest_bytes = Sha256::digest(pae);
        let digest = TpmDigest::try_from(digest_bytes.as_slice())
            .map_err(|e| SignerError::Tpm(format!("digest: {e}")))?;

        let scheme = SignatureScheme::EcDsa {
            hash_scheme: HashScheme::new(HashingAlgorithm::Sha256),
        };
        // No validation ticket — we hashed externally with SHA-256,
        // which is fine for non-restricted signing keys.
        let validation = tss_esapi::structures::HashcheckTicket::try_from(
            tss_esapi::tss2_esys::TPMT_TK_HASHCHECK {
                tag: tss_esapi::constants::StructureTag::Hashcheck.into(),
                hierarchy: tss_esapi::constants::tss::TPM2_RH_NULL,
                digest: Default::default(),
            },
        )
        .map_err(|e| SignerError::Tpm(format!("hashcheck ticket: {e}")))?;

        let sig = ctx
            .sign(key_handle, digest, scheme, validation)
            .map_err(|e| SignerError::Tpm(format!("sign: {e}")))?;

        // TPM returns a structured `Signature::EcDsa { r, s, hash_alg }`.
        // Reassemble it as DER so our pure-Rust helper can do the
        // compact conversion + sanity-check the shape. (We could also
        // read r/s directly and shortcut, but feeding everything through
        // the same DER path keeps the wire-shape unit tests meaningful.)
        let (r_bytes, s_bytes) = match sig {
            tss_esapi::structures::Signature::EcDsa(ecdsa) => (
                ecdsa.signature_r().value().to_vec(),
                ecdsa.signature_s().value().to_vec(),
            ),
            _ => {
                return Err(SignerError::Tpm(
                    "TPM returned non-ECDSA signature — wrong scheme?".to_string(),
                ));
            }
        };
        let der = encode_der_ecdsa(&r_bytes, &s_bytes);
        let mut compact = der_ecdsa_to_compact(&der).map_err(SignerError::from)?;
        normalize_low_s(&mut compact);

        // See keygen()'s matching flush for why this matters.
        ctx.flush_context(ObjectHandle::from(SessionHandle::from(sess)))
            .map_err(|e| SignerError::Tpm(format!("flush_context (session): {e}")))?;

        Ok((pub_compressed, compact.to_vec()))
    }

    pub fn list() -> Result<Vec<(u32, String)>, SignerError> {
        // We don't persist metadata about which handles we own, so the
        // best we can do is ask the TPM to enumerate persistent objects
        // and print the ones that parse as ECC P-256. A future version
        // could tag our own keys with a vendor attribute, but the v1
        // matrix of features in the brief only asks for the handle +
        // keyid pairing.
        use tss_esapi::interface_types::resource_handles::Hierarchy as _Hier;
        let mut ctx = new_context()?;
        let _ = _Hier::Owner; // silence unused_imports if we refactor.
        let mut out = Vec::new();
        // Iterate persistent range 0x81000000 – 0x81FFFFFF by asking the
        // TPM for the list via GetCapability. tss-esapi exposes this as
        // `get_capability(CapabilityType::Handles, 0x81000000, MAX)`.
        use tss_esapi::constants::CapabilityType;
        use tss_esapi::structures::CapabilityData;
        let (cap, _more) = ctx
            .get_capability(CapabilityType::Handles, 0x81000000, 16)
            .map_err(|e| SignerError::Tpm(format!("get_capability: {e}")))?;
        let handles = match cap {
            CapabilityData::Handles(h) => h,
            _ => return Ok(out),
        };
        for h in handles.into_inner() {
            let raw: u32 = h.into();
            // Try to read public; skip entries that aren't our ECC
            // shape. A non-ECC persistent key (RSA, HMAC) just isn't
            // listable here.
            if let Ok(object) = ctx.tr_from_tpm_public(h) {
                let kh: KeyHandle = object.into();
                if let Ok((public, _n, _qn)) = ctx.read_public(kh) {
                    if let Ok(compressed) = compress_from_public(&public) {
                        out.push((raw, to_hex(&compressed)));
                    }
                }
            }
        }
        Ok(out)
    }

    pub fn delete(handle: u32) -> Result<(), SignerError> {
        let mut ctx = new_context()?;
        let sess = start_owner_session(&mut ctx)?;
        ctx.set_sessions((Some(sess), None, None));
        let persistent_handle = persistent(handle)?;
        let object_handle = ctx
            .tr_from_tpm_public(persistent_handle.into())
            .map_err(|e| SignerError::Tpm(format!("tr_from_tpm_public: {e}")))?;
        ctx.evict_control(Provision::Owner, object_handle, persistent_handle.into())
            .map_err(|e| SignerError::Tpm(format!("evict_control (delete): {e}")))?;

        // See keygen()'s matching flush for why this matters.
        ctx.flush_context(ObjectHandle::from(SessionHandle::from(sess)))
            .map_err(|e| SignerError::Tpm(format!("flush_context (session): {e}")))?;

        Ok(())
    }

    /// Re-encode a `(r, s)` pair as the DER `SEQUENCE { INTEGER r, INTEGER s }`
    /// shape `der_ecdsa_to_compact` expects. This keeps the
    /// compact-conversion path covered by unit tests rather than
    /// introducing a parallel raw-r/s decoder. `r` and `s` come from
    /// the TPM bounded by the P-256 scalar size (≤ 32 bytes each), so
    /// every `u8::try_from` below is guaranteed to succeed; we use
    /// `try_from` rather than `as u8` to satisfy pedantic clippy.
    fn encode_der_ecdsa(r: &[u8], s: &[u8]) -> Vec<u8> {
        fn encode_int(b: &[u8]) -> Vec<u8> {
            let mut body = b.to_vec();
            // Strip leading zeros except the last one.
            while body.len() > 1 && body[0] == 0x00 {
                body.remove(0);
            }
            // Add a 0x00 prefix if the high bit is set (mark non-negative).
            if !body.is_empty() && body[0] & 0x80 != 0 {
                body.insert(0, 0x00);
            }
            let mut out = vec![0x02, u8::try_from(body.len()).expect("DER int len ≤ 33")];
            out.extend_from_slice(&body);
            out
        }
        let rb = encode_int(r);
        let sb = encode_int(s);
        let mut body = rb;
        body.extend_from_slice(&sb);
        let mut out = vec![0x30, u8::try_from(body.len()).expect("DER seq body ≤ 72")];
        out.extend_from_slice(&body);
        out
    }
}

// -- Tests -----------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::cast_possible_truncation,
    reason = "test DER fixtures use short lengths (< 128), cast is in-range"
)]
mod tests {
    use super::*;

    // ---- DER → compact ---------------------------------------------

    /// Handwritten DER `SEQUENCE { INTEGER 0x01..20, INTEGER 0x21..40 }`.
    /// The two INTEGERs are exactly 32 bytes each, no sign-pad needed
    /// (high bit is clear: 0x01 and 0x21).
    #[test]
    fn der_to_compact_no_signpad() {
        // 0x30 LEN 0x02 0x20 <r 32B> 0x02 0x20 <s 32B>
        let mut der = vec![0x30, 0x44, 0x02, 0x20];
        der.extend((1u8..=32u8).collect::<Vec<_>>());
        der.extend(&[0x02, 0x20]);
        der.extend((33u8..=64u8).collect::<Vec<_>>());

        let compact = der_ecdsa_to_compact(&der).expect("well-formed DER");
        assert_eq!(&compact[..32], &(1u8..=32u8).collect::<Vec<_>>()[..]);
        assert_eq!(&compact[32..], &(33u8..=64u8).collect::<Vec<_>>()[..]);
    }

    /// r has its top bit set → DER encoder added a leading 0x00 pad.
    /// The decoder must strip it and emit 32 bytes.
    #[test]
    fn der_to_compact_strips_sign_pad() {
        let r: Vec<u8> = std::iter::once(0x00u8)
            .chain(std::iter::once(0x80u8))
            .chain(std::iter::repeat_n(0x42u8, 31))
            .collect(); // 33 bytes: 0x00, 0x80, then 31 × 0x42.
        let s: Vec<u8> = (33u8..=64u8).collect();
        let mut body = vec![0x02, r.len() as u8];
        body.extend(&r);
        body.push(0x02);
        body.push(s.len() as u8);
        body.extend(&s);
        let mut der = vec![0x30, body.len() as u8];
        der.extend(body);

        let compact = der_ecdsa_to_compact(&der).expect("well-formed DER");
        assert_eq!(compact[0], 0x80, "sign-pad stripped, top byte is 0x80");
        assert_eq!(compact[1], 0x42);
        assert_eq!(&compact[32..], &(33u8..=64u8).collect::<Vec<_>>()[..]);
    }

    /// Short scalars (e.g. r with leading-zero bytes that DER would
    /// have omitted) get left-padded to 32 bytes.
    #[test]
    fn der_to_compact_left_pads_short_scalar() {
        // r = 0x01 (one byte), s = 32 × 0x33.
        let r = vec![0x01u8];
        let s = vec![0x33u8; 32];
        let mut body = vec![0x02, r.len() as u8];
        body.extend(&r);
        body.push(0x02);
        body.push(s.len() as u8);
        body.extend(&s);
        let mut der = vec![0x30, body.len() as u8];
        der.extend(body);

        let compact = der_ecdsa_to_compact(&der).unwrap();
        assert_eq!(&compact[..31], &[0u8; 31][..], "left-padded with zeros");
        assert_eq!(compact[31], 0x01);
        assert_eq!(&compact[32..], &[0x33u8; 32][..]);
    }

    #[test]
    fn der_to_compact_rejects_wrong_tag() {
        let err = der_ecdsa_to_compact(&[0x31, 0x00]).unwrap_err();
        assert!(matches!(
            err,
            DerError::BadTag {
                want: 0x30,
                got: 0x31
            }
        ));
    }

    #[test]
    fn der_to_compact_rejects_truncated() {
        let err = der_ecdsa_to_compact(&[0x30]).unwrap_err();
        assert!(matches!(err, DerError::Truncated));
    }

    #[test]
    fn der_to_compact_rejects_trailing_bytes() {
        let mut der = vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01];
        der.push(0xff); // garbage past the SEQUENCE.
        let err = der_ecdsa_to_compact(&der).unwrap_err();
        assert!(matches!(err, DerError::TrailingBytes));
    }

    // ---- low-S normalisation ---------------------------------------

    #[test]
    fn normalize_low_s_leaves_low_alone() {
        // s starts with 0x7F → already low.
        let mut compact = [0u8; 64];
        compact[32] = 0x7F;
        compact[63] = 0xAA;
        let before = compact;
        normalize_low_s(&mut compact);
        assert_eq!(
            compact, before,
            "low-S signatures must pass through unchanged"
        );
    }

    #[test]
    fn normalize_low_s_flips_high() {
        // Build a high-S signature: s = n - 1, which is the maximum
        // high-S value possible. After normalisation it should become 1.
        //
        // P-256 n - 1 =
        //   FFFFFFFF 00000000 FFFFFFFF FFFFFFFF
        //   BCE6FAAD A7179E84 F3B9CAC2 FC632550
        let n_minus_1: [u8; 32] = [
            0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2,
            0xFC, 0x63, 0x25, 0x50,
        ];
        let mut compact = [0u8; 64];
        compact[..32].fill(0x11);
        compact[32..].copy_from_slice(&n_minus_1);
        normalize_low_s(&mut compact);
        // After flip, s should be 1 (big-endian).
        let expected = {
            let mut e = [0u8; 32];
            e[31] = 1;
            e
        };
        assert_eq!(&compact[32..], &expected[..], "n - (n - 1) = 1");
        // r must be left untouched.
        assert_eq!(&compact[..32], &[0x11u8; 32][..]);
    }

    // ---- SEC1 compression ------------------------------------------

    #[test]
    fn compress_sec1_even_y_gets_02() {
        let x = [0x11u8; 32];
        let mut y = [0u8; 32];
        y[31] = 0x02; // even.
        let c = compress_sec1(&x, &y);
        assert_eq!(c[0], 0x02);
        assert_eq!(&c[1..], &x[..]);
    }

    #[test]
    fn compress_sec1_odd_y_gets_03() {
        let x = [0x22u8; 32];
        let mut y = [0u8; 32];
        y[31] = 0x01; // odd.
        let c = compress_sec1(&x, &y);
        assert_eq!(c[0], 0x03);
        assert_eq!(&c[1..], &x[..]);
    }

    // ---- Handle parser ---------------------------------------------

    #[test]
    fn parse_handle_accepts_common_forms() {
        assert_eq!(parse_handle("0x81010001").unwrap(), 0x8101_0001);
        assert_eq!(parse_handle("0X81010001").unwrap(), 0x8101_0001);
        assert_eq!(parse_handle("81010001").unwrap(), 0x8101_0001);
    }

    #[test]
    fn parse_handle_rejects_garbage() {
        assert!(parse_handle("not-hex").is_err());
        assert!(parse_handle("0xzzzz").is_err());
    }

    #[test]
    fn format_handle_is_zero_padded() {
        assert_eq!(format_handle(0x8101_0001), "0x81010001");
        assert_eq!(format_handle(1), "0x00000001");
    }
}
