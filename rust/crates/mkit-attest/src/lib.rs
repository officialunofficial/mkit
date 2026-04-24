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
//! * [`signer_external`] — JSON-over-stdin/stdout subprocess.
//! * [`signer_sigstore`] — scaffold; returns `SigstoreNotImplemented`.
//! * [`store`] — content-addressed `.mkit/attestations/<commit>/<id>.dsse`
//!   on-disk layout with atomic writes.
//! * [`verify`] — per-signature crypto verdict against a trust-root
//!   registry, plus a subject-extraction helper.
//!
//! No `serde_json::to_string` is used on the emit path — the canonical
//! encoder is hand-rolled per RFC 8785 because `serde_json` does NOT
//! satisfy JCS's sort and number-format rules. `serde` and `serde_json`
//! are used only for **parsing** envelopes-from-third-parties and the
//! external-signer response line.

#![forbid(unsafe_code)]
#![allow(clippy::multiple_crate_versions)]

pub mod envelope;
pub mod jcs;
pub mod signer;
pub mod signer_external;
pub mod signer_repo_key;
pub mod signer_sigstore;
pub mod statement;
pub mod store;
pub mod verify;

pub use envelope::{Envelope, PAYLOAD_TYPE_IN_TOTO, Sig, attestation_id, pae_of};
pub use signer::Signer;
pub use signer_external::ExternalSigner;
pub use signer_repo_key::{KEYID_PREFIX, RepoKeySigner};
pub use signer_sigstore::SigstoreSigner;
pub use statement::{IN_TOTO_TYPE, Statement, Subject};
pub use verify::{Reason, Registry, SignatureResult, TrustRoot, VerifyResult, verify_envelope};

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
    #[error("Statement subject digest is not lowercase hex")]
    InvalidDigestHex,

    // -- Signers --
    #[error("external signer keyid is unknown until the first sign call")]
    KeyIdNotKnownUntilFirstSign,
    #[error("external signer spawn failed: {0}")]
    ExternalSignerSpawn(String),
    #[error("external signer exited non-zero: {0}")]
    ExternalSignerFailed(String),
    #[error("external signer response could not be parsed")]
    ExternalSignerBadResponse,
    #[error("external signer output exceeded the 1 MiB cap")]
    ExternalSignerOutputTooLarge,
    #[error("sigstore signer is not yet implemented")]
    SigstoreNotImplemented,

    // -- Store --
    #[error("envelope is {len} bytes, exceeds the {max}-byte cap")]
    EnvelopeTooLarge { len: usize, max: usize },
    #[error("attestation store I/O: {0}")]
    Io(String),
}
