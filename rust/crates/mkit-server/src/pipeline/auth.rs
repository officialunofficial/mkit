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
    /// Auth v2 on writes (`UpdateRef`, `AdvanceRefs`, `UploadPack`), with
    /// the replay ledger and quota; reads are unsigned (`vcs-worker`
    /// parity).
    AuthV2(AuthV2Config),
    /// The binding supplies the principal (ssh forced command, enc peer).
    /// No replay ledger.
    TransportIdentity,
}

/// Everything stage 0 needs, without any HTTP or Connect type.
pub struct RequestMeta<'a> {
    /// The procedure called.
    pub procedure: Procedure,
    /// Looks a request header up by its lowercase name.
    pub header: &'a dyn Fn(&str) -> Option<String>,
    /// The exact unary request bytes (the auth v2 body commitment); `None`
    /// for streams.
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authenticated {
    /// Who the request acts as.
    pub principal: Principal,
    /// The verified auth v2 authorization of a signed request.
    pub auth: Option<VerifiedAuth>,
    procedure: Procedure,
    /// Added to the business clock for this request only: the test
    /// clock-skew directive. Never feeds a commit deadline.
    pub(crate) business_skew_ms: i64,
    #[cfg(feature = "test-faults")]
    directives: super::TestDirectives,
}

impl Authenticated {
    /// The procedure these credentials were checked for; every entry point
    /// refuses any other.
    #[must_use]
    pub fn procedure(&self) -> Procedure {
        self.procedure
    }

    /// The request's test directives (feature `test-faults` only).
    #[cfg(feature = "test-faults")]
    #[must_use]
    pub fn test_directives(&self) -> &super::TestDirectives {
        &self.directives
    }

    #[cfg(feature = "test-faults")]
    pub(crate) fn set_test_directives(&mut self, directives: super::TestDirectives) {
        self.directives = directives;
    }
}

/// Stage 0 and 1 for `mode` at business time `now_ms`.
pub(crate) fn authenticate(
    mode: &AuthMode,
    meta: &RequestMeta<'_>,
    now_ms: i64,
) -> Result<Authenticated, ServerError> {
    let procedure = meta.procedure;
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
        AuthMode::AuthV2(cfg) if procedure.is_write() => {
            let auth = verify_auth_v2(cfg, meta, now_ms)?;
            (
                Principal::Signer {
                    ed25519: auth.signer,
                },
                Some(auth),
            )
        }
        // Reads stay unsigned under auth v2 (`vcs-worker` parity): auth
        // headers on a read are ignored. SPEC-TRANSPORT-CONNECT §7.1 says a
        // read that carries any auth v2 header MUST verify in full; that
        // lands with signed reads in M2 (SPEC-WRITE-GRANTS §9.2).
        AuthMode::Open | AuthMode::AuthV2(_) => (Principal::Anonymous, None),
        AuthMode::TransportIdentity => (
            meta.transport_principal
                .clone()
                .ok_or_else(|| ServerError::unauthenticated("missing transport identity"))?,
            None,
        ),
    };
    Ok(Authenticated {
        principal,
        auth,
        procedure,
        business_skew_ms: 0,
        #[cfg(feature = "test-faults")]
        directives: super::TestDirectives::default(),
    })
}

fn verify_auth_v2(
    cfg: &AuthV2Config,
    meta: &RequestMeta<'_>,
    now_ms: i64,
) -> Result<VerifiedAuth, ServerError> {
    let headers = auth_v2::headers_from(meta.header);
    let path = meta.procedure.connect_path();
    if meta.procedure.is_streaming() {
        return auth_v2::verify_stream(cfg, path, now_ms, &headers);
    }
    let body = meta.unary_body.ok_or_else(|| {
        ServerError::internal("authentication failed", "unary request without its body")
    })?;
    auth_v2::verify_unary(cfg, path, body, now_ms, &headers)
}
