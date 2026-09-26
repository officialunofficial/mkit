//! Auth v2 glue (SPEC-TRANSPORT-CONNECT §7.1): read the ten headers, run
//! [`mkit_core::write_auth::verify_headers`] and decode its result into a
//! [`VerifiedAuth`]. Verification itself (canonical fields, validity window,
//! strict Ed25519) stays in `mkit-core`; nothing here reimplements it.
//!
//! This is step 1, **authenticate**, of the signed-write order in §7.1. It
//! writes no state; the replay lookup comes after it.
//!
//! The canonical copy of `apps/vcs-worker`'s `envelope.rs`, `hashing.rs`, the
//! header reading in `worker_impl/auth.rs` and the pack commitment check in
//! `worker_impl/service.rs`. The old copies go when `vcs-worker` switches in
//! WP-M0-17. `apps/repo-worker` keeps its own copy (planner decision Q11).

use mkit_core::hash::{hash, to_hex};
use mkit_core::write_auth::{AuthError, Context, Headers, validate_audience, verify_headers};

use crate::error::ServerError;
use crate::op::{Commitment, VerifiedAuth};

/// The auth v2 request headers, lowercase, in [`Headers`] field order.
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

/// `Access-Control-Allow-Headers` for browser clients: the auth v2 headers
/// plus the Connect request headers.
pub const CORS_ALLOW_HEADERS: &str = "x-envelope-version, x-audience, x-repository, x-content-commitment, x-expires-at, x-public-key, x-signature, x-digest, x-created-at, \
     idempotency-key, content-type, connect-protocol-version";

/// The trusted audience and Single deployment's expected repository.
/// In Multi mode the pipeline ignores this repository field and verifies
/// against the resolved request identity instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthV2Config {
    audience: String,
    repository: String,
}

impl AuthV2Config {
    /// A configuration for `audience`, the deployment's canonical HTTP(S)
    /// origin, and `repository`, the repository identity it serves.
    ///
    /// # Errors
    /// `audience` is not a canonical origin.
    pub fn new(
        audience: impl Into<String>,
        repository: impl Into<String>,
    ) -> Result<Self, AuthError> {
        let audience = audience.into();
        validate_audience(&audience)?;
        Ok(Self {
            audience,
            repository: repository.into(),
        })
    }

    /// The canonical origin.
    #[must_use]
    pub fn audience(&self) -> &str {
        &self.audience
    }

    /// The repository identity.
    #[must_use]
    pub fn repository(&self) -> &str {
        &self.repository
    }

    fn context<'a>(&'a self, repository: &'a str) -> Context<'a> {
        Context {
            audience: &self.audience,
            repository,
        }
    }
}

/// Read the auth v2 headers through `get`, which looks a header up by its
/// lowercase name. Values are passed through unnormalized.
pub fn headers_from(get: impl Fn(&str) -> Option<String>) -> Headers {
    Headers {
        version: get(HEADER_NAMES[0]),
        audience: get(HEADER_NAMES[1]),
        repository: get(HEADER_NAMES[2]),
        public_key: get(HEADER_NAMES[3]),
        signature: get(HEADER_NAMES[4]),
        digest: get(HEADER_NAMES[5]),
        commitment: get(HEADER_NAMES[6]),
        created_at: get(HEADER_NAMES[7]),
        expires_at: get(HEADER_NAMES[8]),
        idempotency_key: get(HEADER_NAMES[9]),
    }
}

/// Authenticate a unary request: the signature must commit to
/// `body:<BLAKE3 of body>` for `procedure_path` at `now_ms`.
///
/// # Errors
/// [`crate::Code::Unauthenticated`] with `mkit-core`'s reason.
pub fn verify_unary(
    cfg: &AuthV2Config,
    procedure_path: &str,
    body: &[u8],
    now_ms: i64,
    headers: &Headers,
) -> Result<VerifiedAuth, ServerError> {
    verify_unary_for(cfg, cfg.repository(), procedure_path, body, now_ms, headers)
}

/// Verify against the stage-0 resolved repository in Multi mode.
pub(crate) fn verify_unary_for(
    cfg: &AuthV2Config,
    repository: &str,
    procedure_path: &str,
    body: &[u8],
    now_ms: i64,
    headers: &Headers,
) -> Result<VerifiedAuth, ServerError> {
    let commitment = format!("body:{}", to_hex(&hash(body)));
    verify(
        cfg,
        repository,
        procedure_path,
        Some(&commitment),
        now_ms,
        headers,
    )
}

/// Authenticate a streaming upload: the signature must carry a `pack:`
/// commitment, which [`check_pack_commitment`] later compares with the
/// stream's header.
///
/// # Errors
/// [`crate::Code::Unauthenticated`] with `mkit-core`'s reason.
pub fn verify_stream(
    cfg: &AuthV2Config,
    procedure_path: &str,
    now_ms: i64,
    headers: &Headers,
) -> Result<VerifiedAuth, ServerError> {
    verify_stream_for(cfg, cfg.repository(), procedure_path, now_ms, headers)
}

/// Verify a streaming envelope against the resolved repository in Multi mode.
pub(crate) fn verify_stream_for(
    cfg: &AuthV2Config,
    repository: &str,
    procedure_path: &str,
    now_ms: i64,
    headers: &Headers,
) -> Result<VerifiedAuth, ServerError> {
    verify(cfg, repository, procedure_path, None, now_ms, headers)
}

fn verify(
    cfg: &AuthV2Config,
    repository: &str,
    procedure_path: &str,
    commitment: Option<&str>,
    now_ms: i64,
    headers: &Headers,
) -> Result<VerifiedAuth, ServerError> {
    let authorized = verify_headers(
        cfg.context(repository),
        procedure_path,
        commitment,
        now_ms,
        headers,
    )
    .map_err(|e| ServerError::unauthenticated(e.0))?;
    VerifiedAuth::try_from(&authorized)
}

/// An `UploadPack` header that differs from the signed commitment. The
/// caller picks the code: `unauthenticated` for the auth v2 `pack:`
/// commitment, `permission_denied` for a ticket (SPEC-TRANSPORT-CONNECT §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("pack header differs from signed commitment")]
pub struct PackCommitmentMismatch;

/// Check an `UploadPack` header against the signed `pack:` commitment,
/// before any quota is reserved or chunk read.
///
/// # Errors
/// [`PackCommitmentMismatch`] when the commitment is not `pack:` or names a
/// different id or length.
pub fn check_pack_commitment(
    auth: &VerifiedAuth,
    pack_id: &[u8],
    total_bytes: u64,
) -> Result<(), PackCommitmentMismatch> {
    match auth.commitment {
        Commitment::Pack { id, len } if id.as_slice() == pack_id && len == total_bytes => Ok(()),
        _ => Err(PackCommitmentMismatch),
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};
    use mkit_core::hash::{from_hex, to_hex_bytes};
    use mkit_core::write_auth::Operation;

    use super::*;
    use crate::error::Code;

    fn golden() -> serde_json::Value {
        serde_json::from_str(include_str!("../../../tests/golden/auth-v2/unary.json")).unwrap()
    }

    fn field(fixture: &serde_json::Value, name: &str) -> String {
        fixture[name].as_str().unwrap().to_owned()
    }

    /// The fixture's headers, read through [`headers_from`].
    fn golden_headers(fixture: &serde_json::Value) -> Headers {
        let values = [
            "2".to_owned(),
            field(fixture, "audience"),
            field(fixture, "repository"),
            field(fixture, "public_key"),
            field(fixture, "signature"),
            field(fixture, "body_digest"),
            field(fixture, "commitment"),
            fixture["created_at"].as_i64().unwrap().to_string(),
            fixture["expires_at"].as_i64().unwrap().to_string(),
            field(fixture, "nonce"),
        ];
        headers_from(|name| {
            HEADER_NAMES
                .iter()
                .position(|n| *n == name)
                .map(|i| values[i].clone())
        })
    }

    fn golden_config(fixture: &serde_json::Value) -> AuthV2Config {
        AuthV2Config::new(field(fixture, "audience"), field(fixture, "repository")).unwrap()
    }

    #[test]
    fn golden_unary_verifies() {
        let fixture = golden();
        let created_at = fixture["created_at"].as_i64().unwrap();
        let auth = verify_unary(
            &golden_config(&fixture),
            &field(&fixture, "procedure"),
            field(&fixture, "body").as_bytes(),
            created_at + 1,
            &golden_headers(&fixture),
        )
        .unwrap();
        assert_eq!(
            auth.commitment,
            Commitment::Body(from_hex(&field(&fixture, "body_digest")).unwrap())
        );
        assert_eq!(to_hex(&auth.signer), field(&fixture, "public_key"));
        assert_eq!(to_hex(&auth.fingerprint), field(&fixture, "signing_digest"));
        assert_eq!(auth.nonce, field(&fixture, "nonce"));
    }

    #[test]
    fn unary_failures_are_unauthenticated() {
        let fixture = golden();
        let cfg = golden_config(&fixture);
        let procedure = field(&fixture, "procedure");
        let body = field(&fixture, "body");
        let created_at = fixture["created_at"].as_i64().unwrap();
        let expires_at = fixture["expires_at"].as_i64().unwrap();
        let headers = golden_headers(&fixture);
        let other_audience =
            AuthV2Config::new("https://other.example.test", cfg.repository()).unwrap();
        let other_repo = AuthV2Config::new(cfg.audience(), "room-b").unwrap();
        let cases: [(&AuthV2Config, &[u8], i64, &str); 4] = [
            (
                &other_audience,
                body.as_bytes(),
                created_at + 1,
                "request audience or repository mismatch",
            ),
            (
                &other_repo,
                body.as_bytes(),
                created_at + 1,
                "request audience or repository mismatch",
            ),
            (
                &cfg,
                b"tampered body",
                created_at + 1,
                "content commitment mismatch",
            ),
            (
                &cfg,
                body.as_bytes(),
                expires_at + 1,
                "expired or future authorization",
            ),
        ];
        for (cfg, body, now, reason) in cases {
            let err = verify_unary(cfg, &procedure, body, now, &headers).unwrap_err();
            assert_eq!(err.code(), Code::Unauthenticated);
            assert_eq!(err.public_message(), reason);
        }
    }

    #[test]
    fn config_rejects_a_noncanonical_audience() {
        for audience in ["https://API.example.test", "https://a.test/", "a.test"] {
            assert!(AuthV2Config::new(audience, "room-a").is_err(), "{audience}");
        }
    }

    const PACK_ID: [u8; 32] = [0xcd; 32];
    const UPLOAD: &str = "/mkit.transport.v1.TransportService/UploadPack";

    /// Headers for an `UploadPack` signed with the fixture's key over
    /// `commitment`.
    fn signed_stream(fixture: &serde_json::Value, commitment: &str) -> Headers {
        let (audience, repository) = (field(fixture, "audience"), field(fixture, "repository"));
        let nonce = field(fixture, "nonce");
        let (created_at, expires_at) = (
            fixture["created_at"].as_i64().unwrap(),
            fixture["expires_at"].as_i64().unwrap(),
        );
        let operation = Operation {
            context: Context {
                audience: &audience,
                repository: &repository,
            },
            procedure: UPLOAD,
            commitment,
            created_at,
            expires_at,
            nonce: &nonce,
        };
        let seed: [u8; 32] = from_hex(&field(fixture, "seed")).unwrap();
        let key = SigningKey::from_bytes(&seed);
        let signature = key.sign(&operation.digest().unwrap());
        Headers {
            version: Some("2".into()),
            audience: Some(audience.clone()),
            repository: Some(repository.clone()),
            public_key: Some(to_hex(key.verifying_key().as_bytes())),
            signature: Some(to_hex_bytes(&signature.to_bytes())),
            digest: None,
            commitment: Some(commitment.to_owned()),
            created_at: Some(created_at.to_string()),
            expires_at: Some(expires_at.to_string()),
            idempotency_key: Some(nonce.clone()),
        }
    }

    #[test]
    fn stream_verifies_and_checks_the_pack_header() {
        let fixture = golden();
        let now = fixture["created_at"].as_i64().unwrap() + 1;
        let commitment = format!("pack:{}:12", to_hex(&PACK_ID));
        let headers = signed_stream(&fixture, &commitment);
        let auth = verify_stream(&golden_config(&fixture), UPLOAD, now, &headers).unwrap();
        assert_eq!(
            auth.commitment,
            Commitment::Pack {
                id: PACK_ID,
                len: 12
            }
        );

        check_pack_commitment(&auth, &PACK_ID, 12).unwrap();
        for (id, len) in [
            (&[0xce; 32][..], 12),
            (&PACK_ID[..], 13),
            (&PACK_ID[..31], 12),
        ] {
            let err = check_pack_commitment(&auth, id, len).unwrap_err();
            assert_eq!(err, PackCommitmentMismatch);
            assert_eq!(
                err.to_string(),
                "pack header differs from signed commitment"
            );
        }
    }

    #[test]
    fn stream_without_a_pack_commitment_is_unauthenticated() {
        let fixture = golden();
        let now = fixture["created_at"].as_i64().unwrap() + 1;
        let headers = signed_stream(&fixture, &field(&fixture, "commitment"));
        let err = verify_stream(&golden_config(&fixture), UPLOAD, now, &headers).unwrap_err();
        assert_eq!(err.code(), Code::Unauthenticated);
        assert_eq!(err.public_message(), "stream requires a pack commitment");

        // A verified unary authorization never passes the pack check.
        let unary = verify_unary(
            &golden_config(&fixture),
            &field(&fixture, "procedure"),
            field(&fixture, "body").as_bytes(),
            now,
            &golden_headers(&fixture),
        )
        .unwrap();
        assert_eq!(
            check_pack_commitment(&unary, &PACK_ID, 12),
            Err(PackCommitmentMismatch)
        );
    }

    #[test]
    fn cors_allows_every_auth_header() {
        for name in HEADER_NAMES {
            assert!(
                CORS_ALLOW_HEADERS.split(", ").any(|h| h.trim() == name),
                "{name}"
            );
        }
    }
}
