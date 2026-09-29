//! Owner-signed write grant verification.

use mkit_attest::grant::{
    AcceptedSchemes, Capability, GrantError, GrantRequest, RelyingParty, RepositoryIdentity,
    VerifiedEpoch, VerifiedGrant, VerifierConfig, verify_epoch_statement, verify_grant_owner,
};

use crate::error::ServerError;
use crate::op::Operation;

/// Grant verification settings for a Multi/Owner deployment.
#[derive(Clone, Debug)]
pub struct GrantConfig {
    verifier: VerifierConfig,
}

impl GrantConfig {
    /// Build production settings. Loopback audiences and relying parties are refused.
    ///
    /// # Errors
    /// `invalid_argument` if the verifier settings are invalid.
    pub fn new(
        audience: &str,
        schemes: AcceptedSchemes,
        relying_parties: Vec<RelyingParty>,
    ) -> Result<Self, ServerError> {
        VerifierConfig::new(audience, schemes, relying_parties)
            .map(|verifier| Self { verifier })
            .map_err(config_error)
    }

    /// Build settings for tests and local development, allowing loopback origins.
    ///
    /// # Errors
    /// `invalid_argument` if the verifier settings are invalid.
    pub fn new_allowing_loopback(
        audience: &str,
        schemes: AcceptedSchemes,
        relying_parties: Vec<RelyingParty>,
    ) -> Result<Self, ServerError> {
        VerifierConfig::new_allowing_loopback(audience, schemes, relying_parties)
            .map(|verifier| Self { verifier })
            .map_err(config_error)
    }

    /// The byte-exact auth v2 audience this verifier accepts.
    #[must_use]
    pub fn audience(&self) -> &str {
        self.verifier.audience()
    }

    /// Advertised schemes in SPEC-WRITE-GRANTS §4 order.
    #[must_use]
    pub fn schemes(&self) -> AcceptedSchemes {
        self.verifier.schemes()
    }

    /// The owner-scheme verifier, for statement kinds that are not write
    /// grants (visibility statements, WP-2.9).
    pub(crate) fn verifier(&self) -> &VerifierConfig {
        &self.verifier
    }

    pub(crate) fn verify(
        &self,
        header: &str,
        op: &Operation,
    ) -> Result<VerifiedGrant, ServerError> {
        let auth = op.auth.as_ref().ok_or_else(|| {
            ServerError::permission_denied("write grant rejected: missing auth v2 signer")
        })?;
        let now_ms = op.business_now_ms.ok_or_else(|| {
            ServerError::permission_denied("write grant rejected: missing business clock")
        })?;
        let identity = format!("{}/{}", op.repo.namespace.as_str(), op.repo.name.as_str());
        let repository = RepositoryIdentity::parse(&identity)
            .map_err(|_| ServerError::permission_denied("write grant rejected: repository"))?;
        let owner = verify_grant_owner(&self.verifier, header).map_err(rejected)?;
        owner
            .check(
                &self.verifier,
                &GrantRequest {
                    repository: &repository,
                    signer: &auth.signer,
                    capability: Capability::Write,
                    now_ms,
                },
            )
            .map_err(rejected)
    }

    /// §5.2 checks 1–5. This time-dependent result is never cached.
    pub(crate) fn verify_epoch(
        &self,
        header: &str,
        now_ms: i64,
    ) -> Result<VerifiedEpoch, GrantError> {
        verify_epoch_statement(&self.verifier, header, now_ms)
    }
}

fn config_error(error: GrantError) -> ServerError {
    ServerError::invalid_argument(format!("invalid grant configuration: {}", error.reason()))
}

/// The single public mapping for a rejected write grant.
pub(crate) fn rejected(error: GrantError) -> ServerError {
    ServerError::permission_denied(format!("write grant rejected: {}", error.reason()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Code;

    #[test]
    fn every_grant_error_is_permission_denied() {
        for error in [
            GrantError::StatementTooLong,
            GrantError::CarriageReturn,
            GrantError::ByteOutOfRange,
            GrantError::FinalLineFeed,
            GrantError::FieldCount,
            GrantError::EmptyField,
            GrantError::Domain,
            GrantError::Namespace,
            GrantError::RepositoryScope,
            GrantError::ScopeNamespaceMismatch,
            GrantError::Decimal,
            GrantError::DecimalOutOfRange,
            GrantError::Hex,
            GrantError::Capabilities,
            GrantError::Audience,
            GrantError::AudienceWildcard,
            GrantError::AudienceCount,
            GrantError::AudiencesUnordered,
            GrantError::RefScopesOnRead,
            GrantError::RefScopesMissing,
            GrantError::RefPattern,
            GrantError::PackmapPattern,
            GrantError::UnknownRefFlag,
            GrantError::RefFlagsNotCanonical,
            GrantError::RefScopeCount,
            GrantError::RefScopesUnordered,
            GrantError::DuplicateRefPattern,
            GrantError::ExpiryNotAfterCreated,
            GrantError::LifetimeTooLong,
            GrantError::HeaderTooLong,
            GrantError::HeaderFormat,
            GrantError::HeaderBase64,
            GrantError::UnknownScheme,
            GrantError::Repository,
            GrantError::Visibility,
            GrantError::SchemeNotAdvertised,
            GrantError::SchemeNamespaceMismatch,
            GrantError::SignatureLength,
            GrantError::BadSignature,
            GrantError::SignatureRecoveryId,
            GrantError::SignatureScalar,
            GrantError::HighS,
            GrantError::OwnerMismatch,
            GrantError::InvalidOwnerKey,
            GrantError::WebAuthnBlob,
            GrantError::AuthenticatorData,
            GrantError::UserNotPresent,
            GrantError::RelyingPartyMismatch,
            GrantError::ClientData,
            GrantError::ClientDataType,
            GrantError::Challenge,
            GrantError::CrossOrigin,
            GrantError::TopOrigin,
            GrantError::OriginNotAllowed,
            GrantError::NamespaceMismatch,
            GrantError::RepositoryMismatch,
            GrantError::AudienceNotListed,
            GrantError::RepositoryNotInScope,
            GrantError::CapabilityNotGranted,
            GrantError::GranteeMismatch,
            GrantError::NotYetValid,
            GrantError::Expired,
            GrantError::LoopbackAudience,
            GrantError::NoRelyingParty,
            GrantError::RelyingParty,
            GrantError::LoopbackRelyingParty,
        ] {
            let mapped = rejected(error);
            assert_eq!(mapped.code(), Code::PermissionDenied);
            assert_eq!(
                mapped.public_message(),
                format!("write grant rejected: {}", error.reason())
            );
        }
    }

    #[test]
    fn configuration_and_scheme_order() {
        let schemes =
            AcceptedSchemes::from_tokens(["webauthn-p256", "ed25519", "secp256k1-eip191"]).unwrap();
        assert_eq!(
            schemes.tokens().collect::<Vec<_>>(),
            ["ed25519", "secp256k1-eip191", "webauthn-p256"]
        );
        let rp = RelyingParty::new("example.test", ["https://example.test"]).unwrap();
        assert_eq!(
            GrantConfig::new("http://localhost", schemes, vec![rp.clone()])
                .unwrap_err()
                .code(),
            Code::InvalidArgument
        );
        let cfg =
            GrantConfig::new_allowing_loopback("http://localhost", schemes, vec![rp]).unwrap();
        assert_eq!(cfg.audience(), "http://localhost");
        assert_eq!(cfg.schemes(), schemes);
        assert_eq!(
            GrantConfig::new("https://example.test", schemes, vec![])
                .unwrap_err()
                .code(),
            Code::InvalidArgument
        );
    }
}
