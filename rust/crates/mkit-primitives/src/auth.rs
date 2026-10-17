//! Pure auth-v2 verification and upload-claims binding.
//!
//! SPEC-TRANSPORT-CONNECT §7.1 defines the inherited core grammar and ingress
//! time checks. Verification establishes a signature, not current permission.
//! Hosts authenticate their own ticket tokens before supplying claims (§7.6).
//! No token encoding, MAC, clock access, or replay storage lives here.
//! Hosts bound aggregate raw metadata and body acquisition before supplying
//! the retained header strings. Core retains its canonical field caps; the
//! façade adds fixed-size conversions, not a second decoder or owned buffer.

use crate::error::FailureCode;
use mkit_core::hash::{Hash, from_hex};
use mkit_core::write_auth::{
    self, Authorized, ContentCommitment, Context, ExpectedCommitment, Headers,
};

/// Auth-v2 fields, including addressing and nonce, in core [`Headers`] order.
pub const HEADER_NAMES: [&str; 10] = [
    "x-envelope-version",
    "x-audience",
    "x-repository",
    "x-public-key",
    "x-signature",
    "x-digest",
    "x-content-commitment",
    "x-created-at",
    "x-expires-at",
    "idempotency-key",
];

/// Headers that require full signed-envelope verification when present.
/// Repository addressing and an idempotency key alone do not mark a signature.
pub const TRIGGER_HEADER_NAMES: [&str; 8] = [
    "x-public-key",
    "x-signature",
    "x-digest",
    "x-created-at",
    "x-expires-at",
    "x-envelope-version",
    "x-audience",
    "x-content-commitment",
];

/// Whether transport metadata supplies an auth-v2 envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EnvelopePresence {
    /// No auth-v2 headers; the host's unsigned-request policy applies.
    Absent,
    /// Every required header occurs exactly once; values still need full
    /// canonical, destination, commitment, time, and signature verification.
    Present,
}

/// Inspect raw header multiplicities before transports collapse repeated fields.
/// Counts follow [`HEADER_NAMES`]. A unary request requires the digest header;
/// upload streams may omit it. Any [`TRIGGER_HEADER_NAMES`] field marks an
/// envelope, and a partial or duplicate envelope fails closed rather than
/// becoming anonymous. X-Repository is addressing, not an envelope field: its
/// absence is classified by host routing, while a duplicate still fails closed.
/// Without a trigger, addressing and unsigned replay
/// metadata validation remain host obligations.
/// The check inspects ten fixed counts without allocation.
///
/// # Errors
/// Returns [`FailureCode::InvalidEnvelope`] for duplicate or missing headers
/// when any trigger header is present. Empty values count as present and must
/// subsequently pass [`validate_envelope`].
pub fn inspect_headers(
    counts: &[usize; 10],
    requires_digest: bool,
) -> Result<EnvelopePresence, AuthFailure> {
    if !HEADER_NAMES
        .iter()
        .zip(counts)
        .any(|(name, count)| *count != 0 && TRIGGER_HEADER_NAMES.contains(name))
    {
        return Ok(EnvelopePresence::Absent);
    }
    if counts.iter().any(|count| *count > 1) {
        return Err(AuthFailure {
            reason: "duplicate auth v2 header",
        });
    }
    // Missing fields follow verify_headers_with's order and diagnostics;
    // repository addressing stays with routing. Values still
    // pass through that verifier; this is only a multiplicity check.
    let missing = [
        (0, "auth v2 required"),
        (1, "missing auth v2 header"),
        (6, "missing auth v2 header"),
        (7, "missing validity header"),
        (8, "missing validity header"),
        (9, "missing auth v2 header"),
        (5, "body digest mismatch"),
        (3, "missing signature header"),
        (4, "missing signature header"),
    ];
    if let Some((_, reason)) = missing
        .into_iter()
        .find(|(index, _)| counts[*index] == 0 && (*index != 5 || requires_digest))
    {
        return Err(AuthFailure { reason });
    }
    Ok(EnvelopePresence::Present)
}

/// A failed envelope verification. The diagnostic preserves the reference reason;
/// callers classify by the stable code rather than parsing its display text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("{reason}")]
pub struct AuthFailure {
    reason: &'static str,
}

impl AuthFailure {
    /// Stable primitive failure code; maps to `unauthenticated` on Connect.
    #[must_use]
    pub const fn code(&self) -> FailureCode {
        FailureCode::InvalidEnvelope
    }

    /// Bounded public diagnostic from signed addressing or the core verifier.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        self.reason
    }

    fn from_core(error: write_auth::AuthError) -> Self {
        Self { reason: error.0 }
    }
}

/// Privately constructed evidence of full envelope verification.
///
/// Expiry is inclusive at ingress. It does not impose a new commit deadline:
/// host acceptance deadlines, ticket validity, and authority checks are separate.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct AuthenticatedEnvelope {
    authorized: Authorized,
    signer: Hash,
    scope: Hash,
    fingerprint: Hash,
    commitment: ContentCommitment,
    created_at_ms: i64,
}

impl AuthenticatedEnvelope {
    /// Core representation for adapters retaining their existing operation model.
    #[must_use]
    pub fn authorized(&self) -> &Authorized {
        &self.authorized
    }

    /// Strictly verified Ed25519 public key.
    #[must_use]
    pub const fn signer(&self) -> &Hash {
        &self.signer
    }

    /// Destination/repository/signer/nonce replay scope.
    #[must_use]
    pub const fn replay_scope(&self) -> &Hash {
        &self.scope
    }

    /// Signing digest binding all eight canonical fields.
    #[must_use]
    pub const fn fingerprint(&self) -> &Hash {
        &self.fingerprint
    }

    /// Typed canonical commitment; stream handlers still bind its exact fields
    /// to the first message before accepting bytes or reserving quota.
    #[must_use]
    pub const fn commitment(&self) -> ContentCommitment {
        self.commitment
    }

    /// Canonical signed creation time, Unix milliseconds.
    #[must_use]
    pub const fn created_at_ms(&self) -> i64 {
        self.created_at_ms
    }

    /// Inclusive signed expiry at ingress, Unix milliseconds.
    #[must_use]
    pub const fn expires_at_ms(&self) -> i64 {
        self.authorized.expires_at
    }
}

/// Validate raw, unnormalized headers using the core parser and strict verifier.
///
/// `destination` is trusted configured/resolved identity. For unary requests,
/// supply the exact `body:` commitment over the received request bytes. For
/// streams, supply the core stream kind and bind the first message afterwards.
/// Reads call this function too, and never create or query a replay record.
/// Hosts first call [`inspect_headers`] on transport multiplicities, because
/// the core single-value [`Headers`] representation cannot retain duplicates.
///
/// # Errors
/// Returns [`FailureCode::InvalidEnvelope`] for malformed, mismatched, expired, or
/// incorrectly signed input, preserving the reference refusal precedence.
///
/// # Examples
/// ```
/// use mkit_core::write_auth::{Context, ExpectedCommitment, Headers};
/// use mkit_primitives::auth::validate_envelope;
/// let result = validate_envelope(
///     &Headers::default(),
///     Context { audience: "https://example.test", repository: "repo" },
///     "/service/Read", ExpectedCommitment::Exact("body:invalid"), 0,
/// );
/// assert_eq!(result.unwrap_err().code(), mkit_primitives::error::FailureCode::InvalidEnvelope);
/// ```
pub fn validate_envelope(
    raw: &Headers,
    destination: Context<'_>,
    procedure: &str,
    commitment: ExpectedCommitment<'_>,
    now_ms: i64,
) -> Result<AuthenticatedEnvelope, AuthFailure> {
    let authorized =
        write_auth::verify_headers_with(destination, procedure, commitment, now_ms, raw)
            .map_err(AuthFailure::from_core)?;
    // Conversion only: every field below has already passed the core grammar.
    // Fallible conversion keeps even a future core inconsistency fail closed.
    let malformed = || AuthFailure {
        reason: "malformed auth v2 authorization",
    };
    let signer = from_hex(&authorized.public_key).map_err(|_| malformed())?;
    let scope = from_hex(&authorized.scope).map_err(|_| malformed())?;
    let fingerprint = from_hex(&authorized.fingerprint).map_err(|_| malformed())?;
    let commitment = authorized
        .content_commitment()
        .map_err(AuthFailure::from_core)?;
    let created_at_ms = raw
        .created_at
        .as_deref()
        .and_then(|text| text.parse().ok())
        .ok_or_else(malformed)?;
    Ok(AuthenticatedEnvelope {
        authorized,
        signer,
        scope,
        fingerprint,
        commitment,
        created_at_ms,
    })
}

/// Borrowed principal binding extracted from host-authenticated ticket claims.
/// Constructing this view does not authenticate a token or establish ticket
/// openness, expiry, authority, upload completion, or reservation validity.
#[derive(Debug, Clone, Copy)]
pub struct ClaimsPrincipal<'a> {
    /// Canonical audience authenticated by the host token.
    pub audience: &'a str,
    /// Full repository identity authenticated by the host token.
    pub repository: &'a str,
    /// Signer authenticated by the host token.
    pub signer: &'a Hash,
}

/// A claims/request mismatch, mapped to `permission_denied` by the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("upload ticket binding mismatch")]
pub struct ClaimsMismatch;

impl ClaimsMismatch {
    /// Stable code independent of host token representation.
    #[must_use]
    pub const fn code(self) -> FailureCode {
        FailureCode::ClaimsBindingMismatch
    }
}

impl ClaimsPrincipal<'_> {
    /// Bind authenticated claims to the request principal.
    ///
    /// # Errors
    /// Returns [`ClaimsMismatch`] if any identity component differs.
    pub fn check(self, request: ClaimsPrincipal<'_>) -> Result<(), ClaimsMismatch> {
        if self.audience != request.audience
            || self.repository != request.repository
            || self.signer != request.signer
        {
            return Err(ClaimsMismatch);
        }
        Ok(())
    }
}

/// Bind the principal and pack fields of host-authenticated ticket claims to
/// the request. Identity comparisons precede pack comparisons, as in the
/// reference validator. No token format or additional validity rule is imposed.
///
/// # Errors
/// Returns [`ClaimsMismatch`] if the principal, pack id, or byte count differs.
pub fn validate_claims_binding(
    claims: ClaimsPrincipal<'_>,
    request: ClaimsPrincipal<'_>,
    claimed_pack: &Hash,
    claimed_bytes: u64,
    requested_pack: &Hash,
    requested_bytes: u64,
) -> Result<(), ClaimsMismatch> {
    claims.check(request)?;
    if claimed_pack != requested_pack || claimed_bytes != requested_bytes {
        return Err(ClaimsMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
