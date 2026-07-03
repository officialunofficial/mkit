//! Signer trait — uniform interface for producing a DSSE signature.
//!
//! See `docs/SPEC-ATTESTATIONS.md` §6.1. A signer is handed the DSSE PAE
//! bytes by the envelope builder and returns the raw signature bytes;
//! `envelope::encode` base64-wraps them on the way into the final JSON.
//!
//! The trait deliberately says nothing about *how* a signer produces its
//! signature. Concrete implementations:
//!
//! * [`crate::signer_repo_key::RepoKeySigner`] — Ed25519 over the same
//!   key the commit signer uses.
//! * [`crate::signer_external::ExternalSigner`] — length-prefixed buffa
//!   `SignerFrame` protocol over stdin/stdout to a caller-supplied
//!   subprocess (see `rust/crates/mkit-rpc/proto/signer.proto`).
//! * [`crate::signer_sigstore::SigstoreSigner`] — scaffold; returns
//!   `Error::SigstoreNotImplemented`.
//!
//! Verification lives separately (see [`crate::verify`]) because the
//! verifier often has no knowledge of how the signature was produced.

use crate::Error;
use crate::algorithm::Algorithm;

/// Dynamic-dispatch Signer. Used as a `&dyn Signer` so attest pipelines
/// can hold heterogeneous signer collections without genericising every
/// call site.
pub trait Signer {
    /// The signature algorithm this signer produces.
    ///
    /// Callers use this to (a) pick the right verifier path on the
    /// receive side without reparsing the keyid, and (b) record the
    /// algorithm in per-signature metadata. Required — no default;
    /// every signer implementation must report its algorithm.
    fn algorithm(&self) -> Algorithm;

    /// Return an identifier the verifier registry uses to look up this
    /// signer's trust root. Conventions in SPEC-ATTESTATIONS §6.3 (e.g.
    /// `"blake3:<hex>"` for repo-key).
    ///
    /// # Errors
    /// Implementation-specific; e.g. [`crate::signer_external::ExternalSigner`]
    /// returns `Error::KeyIdNotKnownUntilFirstSign` before the first
    /// `sign` call.
    fn keyid(&self) -> Result<String, Error>;

    /// Sign the DSSE PAE. Returns raw signature bytes — the envelope
    /// encoder base64-wraps them. Ed25519 sigs are 64 bytes; other
    /// schemes are variable-length.
    ///
    /// # Errors
    /// Implementation-specific.
    fn sign(&mut self, pae: &[u8]) -> Result<Vec<u8>, Error>;
}

/// Convenience tuple form returned by helper builders that want to
/// surface both fields in one shot. Not used by the trait itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedBytes {
    pub keyid: String,
    pub sig: Vec<u8>,
}
