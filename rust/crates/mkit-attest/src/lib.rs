#![cfg_attr(not(test), deny(clippy::print_stdout, clippy::print_stderr))]
#![doc = include_str!("../README.md")]
//!
//! mkit-attest — JCS + in-toto v1 Statement + DSSE envelope + signers.
//!
//! The wire format and on-disk layout this crate produces are defined,
//! normatively, in `docs/SPEC-ATTESTATIONS.md` — any change to this
//! crate MUST update the spec in the same PR.
//!
//! The crate is layered as follows (each module's doc-comment has the
//! deeper detail):
//!
//! * [`jcs`] — RFC 8785 JSON Canonicalisation writer for the subset of
//!   JSON DSSE + in-toto need (string, uint, bool, null, array,
//!   pre-sorted ASCII-keyed object).
//! * [`statement`] — in-toto v1 Statement encoder. Predicate bodies are
//!   passed through as already-canonical bytes (mkit never parses
//!   predicates).
//! * [`envelope`] — DSSE envelope encoder + strict decoder + PAE +
//!   `attestation_id`.
//! * [`signer`] — common Signer trait.
//! * [`signer_repo_key`] — Ed25519 over the repo key (default).
//! * [`signer_external`] — length-prefixed buffa `SignerFrame`
//!   protocol over stdin/stdout to a caller-supplied subprocess
//!   (see `rust/crates/mkit-rpc/proto/signer.proto`).
//! * [`signer_sigstore`] — scaffold; returns `SigstoreNotImplemented`.
//! * [`store`] — content-addressed `.mkit/attestations/<commit>/<id>.dsse`
//!   on-disk layout with atomic writes.
//! * [`verify`] — per-signature crypto verdict against a trust-root
//!   registry, plus a subject-extraction helper.
//!
//! No `serde_json::to_string` is used on the emit path — the canonical
//! encoder is hand-rolled per RFC 8785 because `serde_json` does NOT
//! satisfy JCS's sort and number-format rules. `serde` and `serde_json`
//! are used only for **parsing** envelopes-from-third-parties; the
//! external-signer path uses the binary buffa `SignerFrame` protocol,
//! not JSON.

#![forbid(unsafe_code)]
#![allow(clippy::multiple_crate_versions)]

pub mod algorithm;
pub mod envelope;
pub mod jcs;
pub mod signer;
#[cfg(feature = "bls-threshold")]
pub mod signer_bls_threshold;
pub mod signer_external;
#[cfg(feature = "algo-secp256k1")]
pub mod signer_k256;
#[cfg(feature = "algo-p256")]
pub mod signer_p256;
#[cfg(feature = "algo-ed25519")]
pub mod signer_repo_key;
pub mod signer_sigstore;
pub mod statement;
pub mod store;
pub mod verify;
// Protocol v1.1 — WebAuthn signature wrapping. Gated on `algo-p256`
// because WebAuthn authenticators emit ECDSA over NIST P-256; all
// roaming-authenticator dispatch compiles out when `algo-p256` is off.
#[cfg(feature = "algo-p256")]
pub mod webauthn;

pub use algorithm::Algorithm;
pub use envelope::{Envelope, PAYLOAD_TYPE_IN_TOTO, Sig, attestation_id, pae_of};
pub use signer::Signer;
#[cfg(feature = "bls-threshold")]
pub use signer_bls_threshold::{
    KEYID_PREFIX as BLS_THRESHOLD_KEYID_PREFIX, NAMESPACE as BLS_THRESHOLD_NAMESPACE,
    PUBLIC_KEY_SIZE as BLS_THRESHOLD_PUBLIC_KEY_SIZE, ThresholdSigner,
    aggregate as bls_threshold_aggregate, threshold_for as bls_threshold_for,
    trusted_dealer as bls_threshold_trusted_dealer, verify as bls_threshold_verify,
};
pub use signer_external::ExternalSigner;
#[cfg(feature = "algo-ed25519")]
pub use signer_repo_key::{KEYID_PREFIX, RepoKeySigner};
pub use signer_sigstore::SigstoreSigner;
pub use statement::{IN_TOTO_TYPE, Statement, Subject};
pub use verify::{
    Reason, Registry, SignatureResult, TrustRoot, VerifyResult, verify_envelope, verify_signature,
};
#[cfg(feature = "algo-p256")]
pub use webauthn::{
    WebAuthnPolicy, WebAuthnWrapping, build_client_data_json, verify_webauthn_wrapping,
    verify_webauthn_wrapping_with_policy,
};

/// Errors surfaced by the mkit-attest crate.
///
/// The list is deliberately flat (one variant per failure mode) so
/// callers can `match` on the specific failure without unwrapping a
/// nested `source()`. `Io` and `ExternalSignerSpawn` carry a string
/// because their root cause is the OS error, which is not stable
/// across platforms and not useful to pattern-match on.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    // -- JCS / encoding --
    #[error("JCS object members must be strictly ascending by key")]
    JcsObjectKeysUnsorted,

    // -- Statement --
    #[error("predicate body must be a JCS-canonical JSON object (start `{{`, end `}}`)")]
    PredicateMustBeJsonObject,
    #[error("predicate body is not valid UTF-8")]
    PredicateNotUtf8,
    #[error("predicate body is not parseable as a JSON object")]
    PredicateNotJsonObject,

    // -- Envelope --
    #[error("DSSE envelope needs at least one signature")]
    EnvelopeNeedsAtLeastOneSignature,
    #[error("DSSE envelope payloadType must be non-empty")]
    PayloadTypeEmpty,
    #[error("malformed DSSE envelope")]
    MalformedEnvelope,

    // -- Verify --
    #[error("DSSE envelope payloadType is not `application/vnd.in-toto+json`")]
    UnsupportedPayloadType,
    #[error("DSSE envelope has zero signatures")]
    EmptySignatures,
    #[error("malformed in-toto v1 Statement")]
    MalformedStatement,
    #[error("Statement has no subject entries")]
    SubjectMissing,
    #[error("Statement subject has no `blake3` digest")]
    SubjectDigestMissing,
    #[error("Statement subject digest is not 64 hex characters")]
    InvalidDigestLength,
    #[error("Statement subject digest is not valid hex")]
    InvalidDigestHex,

    // -- Signers --
    #[error("external signer keyid is unknown until the first sign call")]
    KeyIdNotKnownUntilFirstSign,
    #[error("external signer spawn failed: {0}")]
    ExternalSignerSpawn(String),
    #[error("external signer exited non-zero: {0}")]
    ExternalSignerFailed(String),
    #[error("external signer response could not be parsed: {0}")]
    ExternalSignerBadResponse(String),
    #[error("external signer binary path must be absolute: {0}")]
    ExternalSignerRelativePath(String),
    /// The signer conversation exceeded the configured deadline at the
    /// named phase. The child has been killed and reaped before this is
    /// returned. The `&'static str` is the phase name:
    /// `"spawn"`, `"request-write"`, `"response-read"`, `"stderr-drain"`,
    /// or `"child-exit"` — so callers can distinguish a hung touch-prompt
    /// (`response-read`) from a wedged-after-output child (`child-exit`).
    #[error("external signer timed out during {0} phase")]
    ExternalSignerTimeout(&'static str),
    #[error("sigstore signer is not yet implemented")]
    SigstoreNotImplemented,

    // -- Algorithm dispatch --
    #[error("signature algorithm {0} is not enabled in this build")]
    AlgorithmNotEnabled(Algorithm),

    // -- Store --
    #[error("envelope is {len} bytes, exceeds the {max}-byte cap")]
    EnvelopeTooLarge { len: usize, max: usize },
    #[error("attestation store I/O: {0}")]
    Io(String),

    // -- secp256k1 / ES256K (feature `algo-secp256k1`) --
    //
    // Flat variants (matching this enum's established style) rather than
    // a single `Secp256k1(String)` aggregator, so callers can pattern-
    // match on the specific failure mode without re-parsing strings.
    #[error("secp256k1 key bytes are invalid (zero scalar, >= n, or bad PKCS#8)")]
    Secp256k1KeyInvalid,
    #[error("secp256k1 signature bytes are malformed (wrong length or not a valid (r, s))")]
    Secp256k1SignatureInvalid,
    #[error("secp256k1 signature did not verify against the given public key and message")]
    Secp256k1VerifyFailed,

    // -- P-256 / ES256 (feature `algo-p256`) --
    #[error("P-256 private key is invalid (scalar out of range or malformed PKCS#8)")]
    P256KeyInvalid,
    #[error("P-256 signature is malformed (wrong length, non-canonical, or high-S)")]
    P256SignatureInvalid,
    #[error("P-256 signature verification failed")]
    P256VerifyFailed,

    // -- WebAuthn Protocol v1.1 wrapping (feature `algo-p256`) --
    //
    // Distinct variants per failure mode so a downstream verifier can
    // surface "challenge did not match PAE" to a human differently
    // from "the client_data was garbage". These are NOT subsumed into
    // P256VerifyFailed because the WebAuthn wrapping protocol has
    // binding semantics the raw ECDSA layer cannot see.
    #[error(
        "WebAuthn clientDataJSON.challenge does not match base64url(PAE) — wrapping not bound to this payload"
    )]
    WebAuthnChallengeMismatch,
    #[error(
        "WebAuthn clientDataJSON is not a valid UTF-8 JSON object with string `type` + `challenge`, or `type` is not `webauthn.get`"
    )]
    WebAuthnBadClientDataJson,
    #[error("WebAuthn authenticatorData is malformed (less than 37 bytes or bad base64url)")]
    WebAuthnBadAuthenticatorData,
    #[error(
        "WebAuthn signature did not verify against the reconstructed authenticatorData || SHA256(clientDataJSON)"
    )]
    WebAuthnSignatureFailed,
    // -- WebAuthn ceremony-policy failures (feature `algo-p256`) --
    //
    // These are policy verdicts layered ON TOP of the cryptographic
    // wrapping check (above). They only fire when a non-permissive
    // `WebAuthnPolicy` knob is configured; the permissive default never
    // emits them. Distinct variants so a relying party can tell "wrong
    // origin" from "authenticator did not assert user verification".
    #[error("WebAuthn authenticatorData rpIdHash does not match the policy's expected RP ID")]
    WebAuthnRpIdMismatch,
    #[error("WebAuthn clientDataJSON origin is not in the policy's allow-list")]
    WebAuthnOriginNotAllowed,
    #[error("WebAuthn assertion did not set the User Present (UP) flag, but policy requires it")]
    WebAuthnUserPresenceRequired,
    #[error("WebAuthn assertion did not set the User Verified (UV) flag, but policy requires it")]
    WebAuthnUserVerificationRequired,
    #[error("WebAuthn clientDataJSON crossOrigin is true, but policy disallows cross-origin")]
    WebAuthnCrossOriginNotAllowed,
    #[error(
        "WebAuthn assertion signCount is lower than the previously-seen counter (possible cloned authenticator)"
    )]
    WebAuthnCounterRollback,

    // -- BLS12-381 threshold (feature `bls-threshold`) --
    //
    // Flat variants matching the established style. The aggregator
    // path can fail in three independent ways (decode a partial,
    // recover the threshold signature, verify the aggregate); we
    // surface each with its own variant so a future release-party
    // CLI can render the right diagnostic.
    #[error("BLS12-381 threshold partial signature is not a valid wire encoding")]
    BlsThresholdPartialDecode,
    #[error(
        "BLS12-381 threshold recovery failed: fewer than `threshold` distinct partials supplied"
    )]
    BlsThresholdInsufficientPartials,
    #[error("BLS12-381 threshold aggregate public key is malformed (bad G2 compressed encoding)")]
    BlsThresholdPublicKeyDecode,
    #[error("BLS12-381 threshold signature is malformed (wrong length or bad G1 encoding)")]
    BlsThresholdSignatureDecode,
    #[error("BLS12-381 threshold signature did not verify against the aggregated public key")]
    BlsThresholdVerifyFailed,
}
