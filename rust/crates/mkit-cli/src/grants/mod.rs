//! Client side of SPEC-WRITE-GRANTS: the user grant store, owner signing and
//! the local statement checks behind `mkit grant`, `mkit epoch` and
//! `mkit visibility`.
//!
//! Nothing here is repository-scoped. The store lives beside the user
//! config, the relying-party pins come from the user config, and every
//! header is verified with the `mkit-attest` verifier before it is stored or
//! sent (SPEC-CONFIG-SECURITY; WP-2.13).

pub mod cli;
pub mod owner;
pub mod remote;
pub mod spec;
pub mod store;

use std::time::{SystemTime, UNIX_EPOCH};

use mkit_attest::grant::{
    AcceptedSchemes, EpochStatement, GrantError, OwnerScheme, RelyingParty, SignedHeader,
    VerifiedEpoch, VerifiedVisibility, VerifierConfig, verify_epoch_statement, verify_grant_owner,
    verify_visibility_statement,
};
use mkit_attest::grant::{Grant, RepositoryIdentity};

/// Audience used when only the owner signature matters. The grant checks
/// that involve an audience run on the server; the client never compares it.
const OFFLINE_AUDIENCE: &str = "https://mkit-client.invalid";

/// Why a header could not be verified locally.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum HeaderError {
    /// The attest verifier rejected it; the text is its rule name.
    #[error("{0}")]
    Rejected(GrantError),
    /// A `webauthn-p256` signature, and no relying party is pinned.
    #[error(
        "webauthn-p256 signatures need a pinned relying party: set `grant.webauthn_rp = <rp_id> <origin>` in the user config"
    )]
    WebAuthnNotPinned,
}

impl From<GrantError> for HeaderError {
    fn from(error: GrantError) -> Self {
        Self::Rejected(error)
    }
}

/// Parse `grant.webauthn_rp` entries (`<rp_id> <origin>...`, several entries
/// separated by `|`).
///
/// # Errors
/// A malformed entry, or two entries with the same relying-party id.
pub fn parse_relying_parties(entries: &[String]) -> Result<Vec<RelyingParty>, String> {
    let mut out: Vec<RelyingParty> = Vec::new();
    for value in entries {
        for entry in value.split('|') {
            let mut parts = entry.split_whitespace();
            let Some(id) = parts.next() else {
                continue;
            };
            let origins: Vec<&str> = parts.collect();
            let rp = RelyingParty::new(id, origins.iter().copied()).map_err(|e| {
                format!(
                    "relying party `{id}`: {e} (expected `<rp_id> <origin>...`, e.g. `example.com https://example.com`)"
                )
            })?;
            if out.iter().any(|other| other.id() == rp.id()) {
                return Err(format!("relying party `{id}` is pinned twice"));
            }
            out.push(rp);
        }
    }
    Ok(out)
}

/// A verifier that accepts `ed25519` and `secp256k1-eip191`, plus
/// `webauthn-p256` when relying parties are pinned. Loopback audiences and
/// relying parties are allowed: the CLI has no deployment to protect, and the
/// server applies its own production rules.
fn verifier_config(audience: &str, rps: &[RelyingParty]) -> Result<VerifierConfig, GrantError> {
    let mut schemes = vec![OwnerScheme::Ed25519, OwnerScheme::Secp256k1Eip191];
    if !rps.is_empty() {
        schemes.push(OwnerScheme::WebAuthnP256);
    }
    VerifierConfig::new_allowing_loopback(audience, AcceptedSchemes::of(&schemes), rps.to_vec())
}

fn check_pinned(header: &str, rps: &[RelyingParty]) -> Result<(), HeaderError> {
    if rps.is_empty()
        && let Ok(signed) = SignedHeader::parse(header)
        && signed.scheme == OwnerScheme::WebAuthnP256
    {
        return Err(HeaderError::WebAuthnNotPinned);
    }
    Ok(())
}

/// A grant header whose owner signature verified.
#[derive(Debug, Clone)]
pub struct VerifiedGrantHeader {
    pub grant: Grant,
    pub id: [u8; 32],
    pub scheme: OwnerScheme,
}

/// SPEC-WRITE-GRANTS §7 steps 1, 3 and 4 for a grant header.
///
/// # Errors
/// The rule that failed.
pub fn verify_grant_header(
    header: &str,
    rps: &[RelyingParty],
) -> Result<VerifiedGrantHeader, HeaderError> {
    check_pinned(header, rps)?;
    let cfg = verifier_config(OFFLINE_AUDIENCE, rps)?;
    let verified = verify_grant_owner(&cfg, header)?;
    Ok(VerifiedGrantHeader {
        grant: verified.statement().clone(),
        id: *verified.id(),
        scheme: verified.scheme(),
    })
}

/// SPEC-WRITE-GRANTS §5.2 checks 1–5 against the statement's first audience.
///
/// # Errors
/// The rule that failed.
pub fn verify_epoch_header(
    header: &str,
    rps: &[RelyingParty],
    now_ms: i64,
) -> Result<VerifiedEpoch, HeaderError> {
    check_pinned(header, rps)?;
    let signed = SignedHeader::parse(header)?;
    let statement = EpochStatement::parse(&signed.statement)?;
    let audience = statement
        .audiences
        .first()
        .ok_or(GrantError::AudienceCount)?;
    let cfg = verifier_config(audience, rps)?;
    Ok(verify_epoch_statement(&cfg, header, now_ms)?)
}

/// SPEC-WRITE-GRANTS §9.1 checks for a visibility statement sent for
/// `repository`, against the statement's first audience.
///
/// # Errors
/// The rule that failed.
pub fn verify_visibility_header(
    header: &str,
    repository: &RepositoryIdentity,
    rps: &[RelyingParty],
    now_ms: i64,
) -> Result<VerifiedVisibility, HeaderError> {
    check_pinned(header, rps)?;
    let signed = SignedHeader::parse(header)?;
    let statement = mkit_attest::grant::VisibilityStatement::parse(&signed.statement)?;
    let audience = statement
        .audiences
        .first()
        .ok_or(GrantError::AudienceCount)?;
    let cfg = verifier_config(audience, rps)?;
    Ok(verify_visibility_statement(
        &cfg, header, repository, now_ms,
    )?)
}

/// `<namespace>/*` or `<namespace>/<name>`: the repositories a grant covers.
#[must_use]
pub fn scope_text(grant: &Grant) -> String {
    match &grant.scope {
        mkit_attest::grant::RepoScope::Namespace => format!("{}/*", grant.namespace),
        mkit_attest::grant::RepoScope::Repository(id) => id.to_string(),
    }
}

/// Milliseconds since the Unix epoch.
#[must_use]
pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_millis()).ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relying_party_entries_parse_and_reject_duplicates() {
        let rps = parse_relying_parties(&[
            "example.com https://example.com https://app.example.com | other.test https://other.test"
                .to_owned(),
        ])
        .unwrap();
        assert_eq!(rps.len(), 2);
        assert_eq!(rps[0].id(), "example.com");
        assert_eq!(rps[0].origins().len(), 2);
        assert!(parse_relying_parties(&["example.com".to_owned()]).is_err());
        assert!(
            parse_relying_parties(&[
                "example.com https://a.test".to_owned(),
                "example.com https://b.test".to_owned(),
            ])
            .is_err()
        );
        assert!(parse_relying_parties(&[String::new()]).unwrap().is_empty());
    }
}

/// Test helpers shared by the store and command tests.
#[cfg(test)]
pub(crate) mod testutil {
    use std::sync::Arc;

    use mkit_attest::grant::{Capabilities, Grant, RepoScope};
    use mkit_core::hash::to_hex_bytes;
    use mkit_transport_connect::EnvelopeSigner;

    use super::owner::{Kind, NativeOwner, Plan, Produced, produce};

    pub(crate) struct DalekSigner(pub ed25519_dalek::SigningKey);
    impl EnvelopeSigner for DalekSigner {
        fn public_key_hex(&self) -> String {
            to_hex_bytes(&self.0.verifying_key().to_bytes())
        }
        fn sign_hex(&self, message: &[u8; 32]) -> Result<String, String> {
            use ed25519_dalek::Signer as _;
            Ok(to_hex_bytes(&self.0.sign(message).to_bytes()))
        }
    }

    pub(crate) fn owner(seed: u8) -> NativeOwner {
        NativeOwner::ed25519(Arc::new(DalekSigner(
            ed25519_dalek::SigningKey::from_bytes(&[seed; 32]),
        )))
        .unwrap()
    }

    /// A real owner-signed read grant for `audience`, distinct per `nonce`.
    pub(crate) fn signed_grant(seed: u8, nonce: u8, epoch: u64, audience: &str) -> String {
        let now = super::now_ms();
        let Produced::Signed(signed) = produce(
            Plan::Native(owner(seed)),
            |ns| {
                Grant {
                    namespace: *ns,
                    scope: RepoScope::Namespace,
                    grantee: [7; 32],
                    capabilities: Capabilities::Read,
                    audiences: vec![audience.to_owned()],
                    ref_scopes: None,
                    epoch,
                    created_ms: now,
                    expiry_ms: now + 3_600_000,
                    nonce: [nonce; 32],
                }
                .encode()
                .map_err(|e| e.to_string())
            },
            Kind::Grant,
            &[],
            now,
        )
        .unwrap() else {
            panic!("expected a signed grant")
        };
        signed.header
    }
}
