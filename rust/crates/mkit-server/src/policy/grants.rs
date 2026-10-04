//! Owner-signed write grant verification.

use mkit_attest::grant::{
    AcceptedSchemes, Capability, GrantError, GrantRequest, RelyingParty, RepositoryIdentity,
    VerifiedEpoch, VerifiedGrant, VerifierConfig, verify_epoch_statement, verify_grant_owner,
};

use crate::error::ServerError;
use crate::op::Operation;

/// Grant verification settings for a Multi/Owner deployment.
#[derive(Clone, Debug)]
#[non_exhaustive]
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

/// Parse the accepted owner schemes (`--grant-schemes`, the Worker
/// `GRANT_SCHEMES` var): comma-separated SPEC-WRITE-GRANTS §4 tokens. The
/// value must not be blank and may not contain a blank entry. Which tokens
/// exist is `mkit-attest`'s to say.
///
/// # Errors
/// A message for a blank value, a blank entry or an unknown token.
pub fn parse_grant_schemes(text: &str) -> Result<AcceptedSchemes, String> {
    let tokens: Vec<&str> = text.split(',').map(str::trim).collect();
    if tokens.iter().any(|token| token.is_empty()) {
        return Err("grant schemes must be a non-empty, comma-separated list".to_owned());
    }
    AcceptedSchemes::from_tokens(tokens)
        .map_err(|error| format!("invalid grant schemes: {}", error.reason()))
}

/// Parse one relying-party entry, `id=origin[,origin...]`, split on the
/// first `=` (origins never contain a bare `=` before their id ends, but may
/// contain one later, for example in a query-like native-app origin). The id
/// and origin rules are `mkit-attest`'s ([`RelyingParty::new`]).
///
/// # Errors
/// A message for an entry without `=`, or one `RelyingParty::new` refuses.
pub fn parse_relying_party(entry: &str) -> Result<RelyingParty, String> {
    let (id, origins) = entry
        .split_once('=')
        .ok_or_else(|| "a relying party entry is `id=origin[,origin...]`".to_owned())?;
    RelyingParty::new(id.trim(), origins.split(',').map(str::trim))
        .map_err(|error| format!("invalid relying party `{}`: {}", id.trim(), error.reason()))
}

/// Parse the Worker `WEBAUTHN_RPS` var: entries ([`parse_relying_party`])
/// separated by `;` or newlines. A blank entry and a duplicate id are
/// refused, so a stray separator never silently drops a relying party.
///
/// # Errors
/// A message naming the first bad entry, a blank value or a duplicate id.
pub fn parse_relying_parties(text: &str) -> Result<Vec<RelyingParty>, String> {
    let mut parties: Vec<RelyingParty> = Vec::new();
    for entry in text.trim().split([';', '\n']) {
        let entry = entry.trim();
        if entry.is_empty() {
            return Err("relying parties: blank entry".to_owned());
        }
        let party = parse_relying_party(entry)?;
        if parties.iter().any(|known| known.id() == party.id()) {
            return Err(format!("relying parties: duplicate id `{}`", party.id()));
        }
        parties.push(party);
    }
    Ok(parties)
}

/// A deployment's validated write-grant inputs, kept apart from the
/// [`GrantConfig`] built from them so an adapter's configuration can be
/// compared and re-built (a `GrantConfig` holds no equality).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct GrantSettings {
    /// The accepted owner schemes.
    pub schemes: AcceptedSchemes,
    /// The accepted `WebAuthn` relying parties.
    pub relying_parties: Vec<RelyingParty>,
    /// Development only: allow a loopback audience or relying party.
    pub allow_loopback: bool,
}

impl GrantSettings {
    /// Construct explicit deployment settings; fields may be adjusted before use.
    #[must_use]
    pub fn new(
        schemes: AcceptedSchemes,
        relying_parties: Vec<RelyingParty>,
        allow_loopback: bool,
    ) -> Self {
        Self {
            schemes,
            relying_parties,
            allow_loopback,
        }
    }
}

impl GrantSettings {
    /// Combine the adapter's raw settings: `None` when nothing is set
    /// (grants stay off), otherwise the settings, which a bad or partial
    /// value never degrades to "off".
    ///
    /// # Errors
    /// A message when relying parties or the loopback opt-in are set without
    /// any scheme.
    pub fn from_parts(
        schemes: Option<AcceptedSchemes>,
        relying_parties: Vec<RelyingParty>,
        allow_loopback: bool,
    ) -> Result<Option<Self>, String> {
        match schemes {
            Some(schemes) => Ok(Some(Self {
                schemes,
                relying_parties,
                allow_loopback,
            })),
            None if relying_parties.is_empty() && !allow_loopback => Ok(None),
            None => Err(
                "relying parties and the loopback opt-in configure write grants: set the \
                 grant schemes too"
                    .to_owned(),
            ),
        }
    }

    /// Build the verifier for `audience` (the deployment's auth v2 audience):
    /// the production constructor, or the loopback one when the opt-in is set.
    ///
    /// # Errors
    /// `invalid_argument` for any refusal of `mkit-attest`'s verifier rules:
    /// a loopback audience or relying party without the opt-in,
    /// `webauthn-p256` without a relying party, or a duplicate relying party.
    pub fn build(&self, audience: &str) -> Result<GrantConfig, ServerError> {
        if self.allow_loopback {
            GrantConfig::new_allowing_loopback(audience, self.schemes, self.relying_parties.clone())
        } else {
            GrantConfig::new(audience, self.schemes, self.relying_parties.clone())
        }
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
    fn scheme_lists_parse_and_refuse_blanks_and_unknown_tokens() {
        let all = parse_grant_schemes("ed25519, secp256k1-eip191,webauthn-p256").unwrap();
        assert_eq!(
            all,
            AcceptedSchemes::of(&mkit_attest::grant::OwnerScheme::ALL)
        );
        for bad in [
            "",
            "  ",
            "ed25519,",
            ",ed25519",
            "ed25519,,webauthn-p256",
            "rsa",
        ] {
            assert!(parse_grant_schemes(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn relying_party_entries_split_on_the_first_equals() {
        let party =
            parse_relying_party("example.test=https://example.test,https://app.example.test")
                .unwrap();
        assert_eq!(party.id(), "example.test");
        assert_eq!(
            party.origins(),
            ["https://example.test", "https://app.example.test"]
        );
        // A later `=` belongs to the origin.
        let party = parse_relying_party("example.test=android:apk-key-hash:a=b").unwrap();
        assert_eq!(party.origins(), ["android:apk-key-hash:a=b"]);
        for bad in [
            "example.test",
            "=https://example.test",
            "example.test=",
            "example.test=https://a,,https://b",
            "Example.Test=https://a",
            "example.test=https://a,https://a",
        ] {
            assert!(parse_relying_party(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn relying_party_lists_take_semicolons_or_newlines_and_refuse_blanks_and_duplicates() {
        let list = "a.test=https://a.test;b.test=https://b.test\nc.test=https://c.test\n";
        let parties = parse_relying_parties(list).unwrap();
        assert_eq!(
            parties.iter().map(RelyingParty::id).collect::<Vec<_>>(),
            ["a.test", "b.test", "c.test"]
        );
        for bad in [
            "",
            "  ",
            "a.test=https://a.test;;b.test=https://b.test",
            "a.test=https://a.test;",
            "a.test=https://a.test;a.test=https://other.test",
            "a.test",
        ] {
            assert!(parse_relying_parties(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn grant_settings_build_refuses_what_attest_refuses_and_never_degrades() {
        let ed = parse_grant_schemes("ed25519").unwrap();
        let web = parse_grant_schemes("ed25519,webauthn-p256").unwrap();
        let rp = || parse_relying_party("example.test=https://example.test").unwrap();
        // Nothing set: grants are off. Partial settings are refused.
        assert_eq!(GrantSettings::from_parts(None, vec![], false), Ok(None));
        assert!(GrantSettings::from_parts(None, vec![rp()], false).is_err());
        assert!(GrantSettings::from_parts(None, vec![], true).is_err());
        let build = |schemes, rps, loopback, audience: &str| {
            GrantSettings::from_parts(Some(schemes), rps, loopback)
                .unwrap()
                .unwrap()
                .build(audience)
        };
        assert!(build(ed, vec![], false, "https://vcs.example").is_ok());
        assert!(build(web, vec![rp()], false, "https://vcs.example").is_ok());
        assert!(build(web, vec![], false, "https://vcs.example").is_err());
        // Loopback audiences and relying parties need the opt-in.
        assert!(build(ed, vec![], false, "http://localhost:8787").is_err());
        assert!(build(ed, vec![], true, "http://localhost:8787").is_ok());
        let local = parse_relying_party("localhost=http://localhost:8787").unwrap();
        assert!(build(web, vec![local.clone()], false, "https://vcs.example").is_err());
        assert!(build(web, vec![local], true, "https://vcs.example").is_ok());
        let error = build(ed, vec![], false, "not an origin").unwrap_err();
        assert_eq!(error.code(), Code::InvalidArgument);
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
