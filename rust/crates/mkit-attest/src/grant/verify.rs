//! The stateless verifier: SPEC-WRITE-GRANTS §7 steps 1–10 for grants, the
//! §5.2 checks 1–5 for epoch statements, the §9.1 statement checks for
//! visibility statements, and the §10 registration check.
//!
//! Nothing here reads server state or picks a Connect code. §7 step 11 (the
//! grant's epoch equals the stored epoch, at authorize and again inside
//! `apply`), §5.2 checks 6 and 7 ([`super::epoch_transition`]), the §9.1
//! "only a greater `created`" rule and the §11 code mapping are the
//! caller's.
//!
//! Every value this module returns proves a verification ran:
//! [`OwnerVerified`], [`VerifiedGrant`], [`VerifiedEpoch`] and
//! [`VerifiedVisibility`] have no public fields or constructors, so only
//! these functions build them.
//!
//! Only [`OwnerVerified`] may be cached (by exact header bytes). The other
//! three embed a time-window check at one `now`, so they are evidence for
//! that one request and MUST NOT be cached or reused.

use mkit_core::repo_identity::RepositoryIdentity;

use super::epoch::EpochStatement;
use super::owner::verify_owner;
use super::visibility::VisibilityStatement;
use super::webauthn::WebAuthnBinding;
use super::{
    Capability, Grant, GrantError, MAX_CLOCK_LEAD_MS, OwnerScheme, RefFlags, SignedHeader,
    VerifierConfig,
};

/// Generates a verification result type: private fields, read-only
/// accessors, no constructor outside this module.
macro_rules! verified_statement {
    ($(#[$meta:meta])* $name:ident, $statement:ty) => {
        $(#[$meta])*
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub struct $name {
            statement: $statement,
            id: [u8; 32],
            scheme: OwnerScheme,
            webauthn: Option<WebAuthnBinding>,
        }

        impl $name {
            /// The verified statement.
            #[must_use]
            pub fn statement(&self) -> &$statement {
                &self.statement
            }

            /// The statement id: the BLAKE3 of the statement bytes. It
            /// covers neither the scheme nor the signature.
            #[must_use]
            pub fn id(&self) -> &[u8; 32] {
                &self.id
            }

            /// The owner scheme that verified.
            #[must_use]
            pub fn scheme(&self) -> OwnerScheme {
                self.scheme
            }

            /// For a `webauthn-p256` owner signature, the relying-party id
            /// and the `clientDataJSON` origin it was bound to (§4.3 rule 4);
            /// `None` for the other schemes.
            #[must_use]
            pub fn relying_party(&self) -> Option<(&str, &str)> {
                self.webauthn
                    .as_ref()
                    .map(|b| (b.rp_id.as_str(), b.origin.as_str()))
            }
        }
    };
}

verified_statement!(
    /// A grant whose owner signature verified (§7 steps 1, 3 and 4). The id
    /// is the grant id of §3.4.
    ///
    /// [`verify_grant_owner`] depends only on the header bytes, the
    /// configured schemes and (for `webauthn-p256`) the configured relying
    /// parties, so a server MAY cache this value by exact header bytes (§7)
    /// and call [`OwnerVerified::check`] on every request. A cache must be
    /// dropped when that configuration changes; `check` re-tests that the
    /// scheme is still accepted and that a `webauthn-p256` signature's
    /// relying party and origin are still configured, so a stale entry
    /// fails closed.
    ///
    /// Code outside this module cannot build one around an unsigned grant:
    ///
    /// ```compile_fail,E0451
    /// use mkit_attest::grant::{Grant, OwnerScheme, OwnerVerified};
    /// fn forge(statement: Grant) -> OwnerVerified {
    ///     OwnerVerified { statement, id: [0; 32], scheme: OwnerScheme::Ed25519, webauthn: None }
    /// }
    /// ```
    OwnerVerified,
    Grant
);

verified_statement!(
    /// An epoch statement that passed §5.2 checks 1–5 at one `now`.
    ///
    /// It includes the audience and time-window checks, so it is evidence
    /// for one `SetGrantEpoch` call only: it MUST NOT be cached by header
    /// bytes or reused later, since that would skip the expiry check.
    ///
    /// ```compile_fail,E0451
    /// use mkit_attest::grant::{EpochStatement, OwnerScheme, VerifiedEpoch};
    /// fn forge(statement: EpochStatement) -> VerifiedEpoch {
    ///     VerifiedEpoch { statement, id: [0; 32], scheme: OwnerScheme::Ed25519, webauthn: None }
    /// }
    /// ```
    VerifiedEpoch,
    EpochStatement
);

verified_statement!(
    /// A visibility statement that passed the §9.1 checks for one
    /// repository at one `now`.
    ///
    /// It includes the audience and time-window checks, so it is evidence
    /// for one `SetRepoVisibility` call only: it MUST NOT be cached by
    /// header bytes or reused later, since that would skip the expiry check.
    ///
    /// ```compile_fail,E0451
    /// use mkit_attest::grant::{OwnerScheme, VerifiedVisibility, VisibilityStatement};
    /// fn forge(statement: VisibilityStatement) -> VerifiedVisibility {
    ///     VerifiedVisibility { statement, id: [0; 32], scheme: OwnerScheme::Ed25519, webauthn: None }
    /// }
    /// ```
    VerifiedVisibility,
    VisibilityStatement
);

/// One request a grant is checked against (§7 steps 2, 5–7, 9 and 10).
#[derive(Clone, Copy, Debug)]
pub struct GrantRequest<'a> {
    /// `X-Repository`, or the ssh/enc path argument.
    pub repository: &'a RepositoryIdentity,
    /// The auth v2 signer (`X-Public-Key`), or the ssh/enc transport
    /// principal.
    pub signer: &'a [u8; 32],
    /// `Write` for the write procedures, `Read` for a read of a private
    /// repository (§7 step 7).
    pub capability: Capability,
    /// The server's clock, epoch milliseconds.
    pub now_ms: i64,
}

/// A grant that passed §7 steps 1–7, 9 and 10 for one request.
///
/// Only [`OwnerVerified::check`] builds one; it has no public fields or
/// constructors, so holding one proves the checks ran. Step 8 (ref
/// coverage) is [`VerifiedGrant::effective_flags`]. Step 11 is the caller's:
/// compare [`VerifiedGrant::epoch`] with the stored epoch at authorize, and
/// carry it into `apply` as a precondition (§5.4).
///
/// Code outside this module cannot build one:
///
/// ```compile_fail,E0451
/// use mkit_attest::grant::{Capability, Grant, OwnerScheme, RepositoryIdentity, VerifiedGrant};
/// fn forge(grant: Grant, repository: RepositoryIdentity) -> VerifiedGrant {
///     VerifiedGrant {
///         grant,
///         id: [0; 32],
///         scheme: OwnerScheme::Ed25519,
///         repository,
///         signer: [0; 32],
///         capability: Capability::Write,
///     }
/// }
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedGrant {
    grant: Grant,
    id: [u8; 32],
    scheme: OwnerScheme,
    repository: RepositoryIdentity,
    signer: [u8; 32],
    capability: Capability,
}

impl VerifiedGrant {
    /// The verified grant.
    #[must_use]
    pub fn grant(&self) -> &Grant {
        &self.grant
    }

    /// The grant id (§3.4), for logs.
    #[must_use]
    pub fn id(&self) -> &[u8; 32] {
        &self.id
    }

    /// The owner scheme that verified.
    #[must_use]
    pub fn scheme(&self) -> OwnerScheme {
        self.scheme
    }

    /// The repository the grant was checked for.
    #[must_use]
    pub fn repository(&self) -> &RepositoryIdentity {
        &self.repository
    }

    /// The signer the grant was checked for (its grantee).
    #[must_use]
    pub fn signer(&self) -> &[u8; 32] {
        &self.signer
    }

    /// The capability the grant was checked for.
    #[must_use]
    pub fn capability(&self) -> Capability {
        self.capability
    }

    /// The grant's epoch, for §7 step 11 and the `apply` precondition.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.grant.epoch
    }

    /// §7 step 8 and §8.1: the effective flags of `ref_name` under this
    /// grant. [`RefFlags::EMPTY`] unless the grant was checked for
    /// [`Capability::Write`].
    ///
    /// The no-direct-packmap rule holds here: a ref under
    /// `refs/mkit/packmap/` always gets [`RefFlags::EMPTY`], even under
    /// `refs/*` or `refs/mkit/*`. Callers derive packmap coverage from the
    /// head (§8.3): map the packmap ref to its branch with
    /// [`super::packmap_head`], take the head's flags from this method, and
    /// allow the packmap write only together with that head in one
    /// `AdvanceRefs`. A direct `UpdateRef` on a packmap ref is
    /// `permission_denied`.
    #[must_use]
    pub fn effective_flags(&self, ref_name: &str) -> RefFlags {
        if self.capability != Capability::Write {
            return RefFlags::EMPTY;
        }
        self.grant
            .ref_scopes
            .as_ref()
            .map_or(RefFlags::EMPTY, |scopes| scopes.effective_flags(ref_name))
    }
}

/// §7 step 10, §5.2 check 5, §9.1: `created <= now + MAX_CLOCK_LEAD_MS` and
/// `now < expiry`. Expiry is exclusive, unlike auth v2's. A negative clock
/// reading fails closed.
fn check_window(created_ms: i64, expiry_ms: i64, now_ms: i64) -> Result<(), GrantError> {
    if now_ms < 0 || created_ms > now_ms.saturating_add(MAX_CLOCK_LEAD_MS) {
        return Err(GrantError::NotYetValid);
    }
    if now_ms >= expiry_ms {
        return Err(GrantError::Expired);
    }
    Ok(())
}

/// §7 step 5, §5.2 check 4, §9.1: the deployment's own audience is listed,
/// byte for byte.
fn check_audience(cfg: &VerifierConfig, audiences: &[String]) -> Result<(), GrantError> {
    if audiences.iter().any(|a| a == cfg.audience()) {
        Ok(())
    } else {
        Err(GrantError::AudienceNotListed)
    }
}

/// §7 steps 1, 3 and 4: decode the header, parse the grant, and verify the
/// owner signature. Stateless and cacheable by exact header bytes.
///
/// # Errors
/// The first failure: a header or §3.5 parse error, then a
/// [`super::verify_owner_signature`] error.
pub fn verify_grant_owner(cfg: &VerifierConfig, header: &str) -> Result<OwnerVerified, GrantError> {
    let header = SignedHeader::parse(header)?;
    let (grant, id) = Grant::parse_with_id(&header.statement)?;
    let webauthn = verify_owner(
        cfg,
        header.scheme,
        &header.statement,
        &header.blob,
        &grant.namespace,
    )?;
    Ok(OwnerVerified {
        statement: grant,
        id,
        scheme: header.scheme,
        webauthn,
    })
}

impl OwnerVerified {
    /// The per-request §7 steps, in spec order: the scheme is still
    /// accepted and, for `webauthn-p256`, its relying party and origin are
    /// still configured (step 3, re-tested so a cached value fails closed:
    /// `SchemeNotAdvertised`, `OriginNotAllowed`), step 2
    /// (`NamespaceMismatch`), step 5 (`AudienceNotListed`), step 6
    /// (`RepositoryNotInScope`), step 7 (`CapabilityNotGranted`), step 9
    /// (`GranteeMismatch`) and step 10 (`NotYetValid`, `Expired`).
    ///
    /// # Errors
    /// The first failed step.
    pub fn check(
        &self,
        cfg: &VerifierConfig,
        req: &GrantRequest<'_>,
    ) -> Result<VerifiedGrant, GrantError> {
        let g = &self.statement;
        if !cfg.schemes().contains(self.scheme) {
            return Err(GrantError::SchemeNotAdvertised);
        }
        if let Some(b) = &self.webauthn
            && !cfg.allows_relying_party(&b.rp_id, &b.origin)
        {
            return Err(GrantError::OriginNotAllowed);
        }
        if req.repository.namespace() != Some(&g.namespace) {
            return Err(GrantError::NamespaceMismatch);
        }
        check_audience(cfg, &g.audiences)?;
        if !g.scope.covers(&g.namespace, req.repository) {
            return Err(GrantError::RepositoryNotInScope);
        }
        if !g.capabilities.allows(req.capability) {
            return Err(GrantError::CapabilityNotGranted);
        }
        if g.grantee != *req.signer {
            return Err(GrantError::GranteeMismatch);
        }
        check_window(g.created_ms, g.expiry_ms, req.now_ms)?;
        Ok(VerifiedGrant {
            grant: g.clone(),
            id: self.id,
            scheme: self.scheme,
            repository: req.repository.clone(),
            signer: *req.signer,
            capability: req.capability,
        })
    }
}

/// §10 registration of a grant for an ssh or enc transport principal: §7
/// steps 1, 3, 4 and 5, and the grantee is `principal`. Every other step
/// runs per request, through [`OwnerVerified::check`].
///
/// # Errors
/// As [`verify_grant_owner`], then `AudienceNotListed` or `GranteeMismatch`.
pub fn verify_for_registration(
    cfg: &VerifierConfig,
    header: &str,
    principal: &[u8; 32],
) -> Result<OwnerVerified, GrantError> {
    let verified = verify_grant_owner(cfg, header)?;
    check_audience(cfg, &verified.statement.audiences)?;
    if verified.statement.grantee != *principal {
        return Err(GrantError::GranteeMismatch);
    }
    Ok(verified)
}

/// §5.2 checks 1–5 for an epoch statement in the §4.2 encoding: it decodes
/// and parses; the scheme is advertised, valid for the namespace and the
/// signature verifies, so the owner is the namespace; the deployment's own
/// audience is listed; and `created <= now + MAX_CLOCK_LEAD_MS` and
/// `now < expiry`. Check 6 (namespace policy) and check 7 with the retry
/// rule ([`super::epoch_transition`]) are the caller's.
///
/// The result MUST NOT be cached: it holds only at `now_ms`.
///
/// # Errors
/// The first failed check.
pub fn verify_epoch_statement(
    cfg: &VerifierConfig,
    header: &str,
    now_ms: i64,
) -> Result<VerifiedEpoch, GrantError> {
    let header = SignedHeader::parse(header)?;
    let statement = EpochStatement::parse(&header.statement)?;
    let webauthn = verify_owner(
        cfg,
        header.scheme,
        &header.statement,
        &header.blob,
        &statement.namespace,
    )?;
    check_audience(cfg, &statement.audiences)?;
    check_window(statement.created_ms, statement.expiry_ms, now_ms)?;
    Ok(VerifiedEpoch {
        id: mkit_core::hash::hash(&header.statement),
        statement,
        scheme: header.scheme,
        webauthn,
    })
}

/// §9.1 checks for a visibility statement in the §4.2 encoding, sent for
/// `repository` (`X-Repository`): it decodes and parses; its repository is
/// `repository` (`RepositoryMismatch` otherwise); the scheme is advertised,
/// valid for the repository's namespace and the signature verifies, so the
/// owner is that namespace; the deployment's own audience is listed; and
/// `created <= now + MAX_CLOCK_LEAD_MS` and `now < expiry`. Accepting only
/// a `created` greater than the last accepted one is the caller's.
///
/// The result MUST NOT be cached: it holds only at `now_ms`.
///
/// # Errors
/// The first failed check.
pub fn verify_visibility_statement(
    cfg: &VerifierConfig,
    header: &str,
    repository: &RepositoryIdentity,
    now_ms: i64,
) -> Result<VerifiedVisibility, GrantError> {
    let header = SignedHeader::parse(header)?;
    let statement = VisibilityStatement::parse(&header.statement)?;
    if statement.repository != *repository {
        return Err(GrantError::RepositoryMismatch);
    }
    let namespace = statement
        .repository
        .namespace()
        .ok_or(GrantError::Repository)?;
    let webauthn = verify_owner(
        cfg,
        header.scheme,
        &header.statement,
        &header.blob,
        namespace,
    )?;
    check_audience(cfg, &statement.audiences)?;
    check_window(statement.created_ms, statement.expiry_ms, now_ms)?;
    Ok(VerifiedVisibility {
        id: mkit_core::hash::hash(&header.statement),
        statement,
        scheme: header.scheme,
        webauthn,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grant_window_is_exclusive_of_expiry() {
        assert_eq!(check_window(100, 200, 199), Ok(()));
        assert_eq!(check_window(100, 200, 200), Err(GrantError::Expired));
        assert_eq!(check_window(100, 200, 201), Err(GrantError::Expired));
        assert_eq!(check_window(100, 200, 70), Ok(()));
        assert_eq!(
            check_window(30_001, 90_000, 0),
            Err(GrantError::NotYetValid)
        );
        assert_eq!(check_window(30_000, 90_000, 0), Ok(()));
        assert_eq!(check_window(0, 10, -1), Err(GrantError::NotYetValid));
        assert_eq!(check_window(i64::MAX - 1, i64::MAX, i64::MAX - 1), Ok(()));
        assert_eq!(
            check_window(i64::MAX - 1, i64::MAX, i64::MAX),
            Err(GrantError::Expired)
        );
    }
}
