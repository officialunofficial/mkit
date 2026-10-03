//! Stage 0 (authenticate) and stage 1 (identity mapping): pure and
//! synchronous, writing no state. Bindings call it from their interceptor
//! through [`super::Pipeline::authenticate`].

use core::fmt;

use mkit_core::hash::hash;
use subtle::ConstantTimeEq;

use crate::auth_v2::{self, AuthV2Config};
use crate::error::{Redacted, ServerError};
use crate::op::{Procedure, VerifiedAuth};
use crate::principal::Principal;
use crate::repo::ResolvedRepo;

/// How a deployment authenticates requests.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum AuthMode {
    /// No credentials; every request is `Anonymous` (unsafe-any HTTP, or a
    /// trusted caller). No replay ledger.
    Open,
    /// A shared `Authorization: Bearer <token>`, required on every RPC,
    /// unary and streaming (as the removed `mkit serve --http` did). The BLAKE3
    /// digests of the presented and expected values are compared in
    /// constant time, so neither the content nor the length leaks. No
    /// replay ledger.
    Bearer {
        /// The expected token.
        token: Redacted,
    },
    /// Auth v2 on writes, with the replay ledger and quota; a read that
    /// carries an auth header is verified in full (SPEC-WRITE-GRANTS
    /// §9.2), an unsigned read is anonymous.
    AuthV2(AuthV2Config),
    /// The binding supplies the principal (ssh forced command, enc peer).
    /// No replay ledger.
    TransportIdentity,
}

/// Multi-value header lookup supplied by a transport adapter.
pub type HeaderValues<'a> = dyn Fn(&str) -> Vec<String> + 'a;

/// Everything stage 0 needs, without any HTTP or Connect type.
pub struct RequestMeta<'a> {
    /// The procedure called.
    pub procedure: Procedure,
    /// Looks a request header up by its lowercase name.
    pub header: &'a dyn Fn(&str) -> Option<String>,
    /// All values for a header name. Bindings with single-value metadata may omit it.
    pub header_values: Option<&'a HeaderValues<'a>>,
    /// The exact unary request bytes (the auth v2 body commitment); for
    /// `DownloadPack`, the exact framed request body `0x00‖len‖message`;
    /// `None` for other streams.
    pub unary_body: Option<&'a [u8]>,
    /// The identity the transport established (ssh, enc).
    pub transport_principal: Option<Principal>,
}

impl fmt::Debug for RequestMeta<'_> {
    /// Never shows header values or the body.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RequestMeta")
            .field("procedure", &self.procedure)
            .field("unary_body", &self.unary_body.map(<[u8]>::len))
            .field("transport_principal", &self.transport_principal)
            .finish_non_exhaustive()
    }
}

/// A request that passed stage 0, bound to the procedure it was
/// authenticated for. Only [`super::Pipeline::authenticate`] builds one.
#[derive(Clone, PartialEq, Eq)]
pub struct Authenticated {
    /// Who the request acts as.
    pub principal: Principal,
    /// The verified auth v2 authorization of a signed request.
    pub auth: Option<VerifiedAuth>,
    /// A presented write grant, redacted from debug output.
    pub write_grant: Option<Redacted>,
    /// Raw credential header values captured at authentication and validated
    /// only when admission runs (SPEC-SERVER §6.6); never shown in diagnostics.
    pub(super) credential_capture: Vec<super::admission::CapturedCredential>,
    /// Optional repository-local read-your-writes hint (outside auth v2).
    pub ref_hint: Option<String>,
    procedure: Procedure,
    repo: ResolvedRepo,
    /// Added to the business clock for this request only: the test
    /// clock-skew directive. Never feeds a commit deadline.
    pub(crate) business_skew_ms: i64,
    /// Business time used for auth v2 verification, reused for the grant.
    pub(crate) business_now_ms: i64,
    #[cfg(feature = "__test-faults")]
    directives: super::TestDirectives,
}

impl fmt::Debug for Authenticated {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Authenticated")
            .field("principal", &self.principal)
            .field("auth", &self.auth)
            .field("procedure", &self.procedure)
            .field("repo", &self.repo)
            .finish_non_exhaustive()
    }
}

impl Authenticated {
    /// The procedure these credentials were checked for; every entry point
    /// refuses any other.
    #[must_use]
    pub fn procedure(&self) -> Procedure {
        self.procedure
    }

    /// The repository resolved and bound to this request at stage 0.
    #[must_use]
    pub fn repo(&self) -> &ResolvedRepo {
        &self.repo
    }

    /// The request's test directives (feature `__test-faults` only).
    #[cfg(feature = "__test-faults")]
    #[must_use]
    pub fn test_directives(&self) -> &super::TestDirectives {
        &self.directives
    }

    #[cfg(feature = "__test-faults")]
    pub(crate) fn set_test_directives(&mut self, directives: super::TestDirectives) {
        self.directives = directives;
    }
}

/// Whether `meta`'s request verifies in full under `mode`: under auth v2,
/// every write but `SetRepoVisibility` (whose statement mode is unsigned
/// by design, §9.1) and any request carrying an auth header marker.
pub(crate) fn signed_request(mode: &AuthMode, meta: &RequestMeta<'_>) -> bool {
    matches!(mode, AuthMode::AuthV2(_))
        && (meta.procedure.is_write() && meta.procedure != Procedure::SetRepoVisibility
            || auth_v2::carries_auth_headers(meta.header))
}

/// Stage 0 and 1 for `mode` at business time `now_ms`.
pub(crate) fn authenticate(
    mode: &AuthMode,
    meta: &RequestMeta<'_>,
    now_ms: i64,
    repo: ResolvedRepo,
    expected_repository: &str,
) -> Result<Authenticated, ServerError> {
    let procedure = meta.procedure;
    let presented_grant = (meta.header)("x-write-grant").map(Redacted::new);
    let (principal, auth) = match mode {
        AuthMode::Bearer { token } => {
            let got = (meta.header)("authorization").unwrap_or_default();
            let expected = format!("Bearer {}", token.expose());
            let same = hash(got.as_bytes()).ct_eq(&hash(expected.as_bytes()));
            if !bool::from(same) {
                return Err(ServerError::unauthenticated(
                    "missing or invalid Authorization: Bearer <token>",
                ));
            }
            (Principal::BearerHolder, None)
        }
        AuthMode::AuthV2(cfg) => {
            let must_sign = procedure.is_write() && procedure != Procedure::SetRepoVisibility;
            if must_sign || auth_v2::carries_auth_headers(meta.header) {
                // A request carrying any auth v2 marker verifies in full
                // (SPEC-TRANSPORT-CONNECT §7.1); a failure never falls
                // back to anonymous. Signed reads keep no replay ledger.
                let auth = verify_auth_v2(cfg, expected_repository, meta, now_ms)?;
                (
                    Principal::Signer {
                        ed25519: auth.signer,
                    },
                    Some(auth),
                )
            } else if procedure == Procedure::IssueObjectUrl {
                return Err(ServerError::unauthenticated(
                    "IssueObjectUrl requires auth v2 authorization",
                ));
            } else {
                (Principal::Anonymous, None)
            }
        }
        AuthMode::Open => (Principal::Anonymous, None),
        AuthMode::TransportIdentity => (
            meta.transport_principal
                .clone()
                .ok_or_else(|| ServerError::unauthenticated("missing transport identity"))?,
            None,
        ),
    };
    // A presented grant is captured on any procedure
    // (SPEC-WRITE-GRANTS §4.2); `authenticate_inner` rejects it on an
    // unsigned Multi request, and a Single/Open deployment ignores it.
    Ok(Authenticated {
        principal,
        auth,
        write_grant: presented_grant,
        credential_capture: Vec::new(),
        procedure,
        repo,
        ref_hint: None,
        business_skew_ms: 0,
        business_now_ms: now_ms,
        #[cfg(feature = "__test-faults")]
        directives: super::TestDirectives::default(),
    })
}

fn verify_auth_v2(
    cfg: &AuthV2Config,
    repository: &str,
    meta: &RequestMeta<'_>,
    now_ms: i64,
) -> Result<VerifiedAuth, ServerError> {
    let headers = auth_v2::headers_from(meta.header);
    let path = meta.procedure.connect_path();
    if meta.procedure.is_streaming() && meta.procedure != Procedure::DownloadPack {
        return auth_v2::verify_stream_for(cfg, repository, path, now_ms, &headers);
    }
    let body = meta.unary_body.ok_or_else(|| {
        ServerError::internal("authentication failed", "unary request without its body")
    })?;
    auth_v2::verify_unary_for(cfg, repository, path, body, now_ms, &headers)
}
