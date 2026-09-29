//! Owner-signed write grants and the temporary conservative ref gate.

use mkit_attest::grant::{
    AcceptedSchemes, Capability, GrantError, GrantRequest, RefFlags, RelyingParty,
    RepositoryIdentity, VerifiedGrant, VerifierConfig, head_packmap, verify_grant_owner,
};

use crate::error::ServerError;
use crate::op::{OpKind, Operation};

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
}

fn config_error(error: GrantError) -> ServerError {
    ServerError::invalid_argument(format!("invalid grant configuration: {}", error.reason()))
}

/// The single public mapping for a rejected write grant.
pub(crate) fn rejected(error: GrantError) -> ServerError {
    ServerError::permission_denied(format!("write grant rejected: {}", error.reason()))
}

/// TODO(WP-2.7): replace this narrow gate with the complete §8.2 flag rules.
/// Until then a non-delete ref change needs every `cuf` flag, a delete needs
/// `d`, and an upload target needs any effective flag.
pub(crate) fn interim_ref_gate(grant: &VerifiedGrant, kind: &OpKind) -> Result<(), ServerError> {
    gate_with(kind, |name| grant.effective_flags(name))
}

fn gate_with(kind: &OpKind, flags: impl Fn(&str) -> RefFlags) -> Result<(), ServerError> {
    let allowed = match kind {
        OpKind::UpdateRef(update) => {
            !update.name.starts_with("refs/mkit/packmap/")
                && sufficient(flags(&update.name), update.new.is_none())
        }
        OpKind::AdvanceRefs { head, packmap, .. } => {
            head_packmap(&head.name).as_deref() == Some(packmap.name.as_str())
                && sufficient(flags(&head.name), head.new.is_none())
        }
        OpKind::BeginUpload { ref_name, .. } => !flags(ref_name).is_empty(),
        // A ticketless UploadPack has no ref to scope. Its absent observed
        // epoch rejects it before this gate; a ticketed upload bypasses it.
        _ => false,
    };
    if allowed {
        Ok(())
    } else {
        Err(ServerError::permission_denied(
            "write grant rejected: ref scope",
        ))
    }
}

fn sufficient(flags: RefFlags, deleting: bool) -> bool {
    if deleting {
        flags.contains(RefFlags::DELETE)
    } else {
        flags.contains(
            RefFlags::CREATE
                .union(RefFlags::UPDATE)
                .union(RefFlags::FORCE),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Code;
    use crate::op::RefUpdate;
    use mkit_core::protocol::PackKey;
    use mkit_core::refs::RefWriteCondition;

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

    fn change(name: &str, delete: bool) -> OpKind {
        OpKind::UpdateRef(RefUpdate {
            name: name.into(),
            condition: RefWriteCondition::Any,
            new: (!delete).then_some([1; 32]),
        })
    }

    fn advance(head: &str, packmap: &str) -> OpKind {
        let OpKind::UpdateRef(head) = change(head, false) else {
            unreachable!()
        };
        let OpKind::UpdateRef(packmap) = change(packmap, false) else {
            unreachable!()
        };
        OpKind::AdvanceRefs {
            head,
            packmap,
            tickets: vec![],
        }
    }

    #[test]
    fn interim_gate_is_conservative() {
        let cuf = RefFlags::CREATE
            .union(RefFlags::UPDATE)
            .union(RefFlags::FORCE);
        let d = RefFlags::DELETE;
        let head = "refs/heads/main";
        let packmap = "refs/mkit/packmap/main";
        for (kind, flags, allowed) in [
            (change(head, false), cuf, true),
            (change(head, false), RefFlags::CREATE, false),
            (change(head, true), d, true),
            (change(head, true), cuf, false),
            (change(packmap, false), cuf, false),
            (advance(head, packmap), cuf, true),
            (advance(head, "refs/mkit/packmap/other"), cuf, false),
            (
                OpKind::BeginUpload {
                    ref_name: head.into(),
                    key: PackKey::new([1; 32]),
                    bytes: 1,
                },
                d,
                true,
            ),
            (
                OpKind::BeginUpload {
                    ref_name: head.into(),
                    key: PackKey::new([1; 32]),
                    bytes: 1,
                },
                RefFlags::EMPTY,
                false,
            ),
        ] {
            assert_eq!(gate_with(&kind, |_| flags).is_ok(), allowed, "{kind:?}");
        }
    }
}
