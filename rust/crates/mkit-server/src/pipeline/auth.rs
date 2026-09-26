//! Stage 0 (authenticate) and stage 1 (identity mapping): pure and
//! synchronous, writing no state. Bindings call it from their interceptor
//! through [`super::Pipeline::authenticate`].

use core::fmt;

use crate::auth_v2::{self, AuthV2Config};
use crate::error::{Redacted, ServerError};
use crate::op::{Procedure, VerifiedAuth};
use crate::principal::Principal;

/// How a deployment authenticates requests.
#[derive(Debug, Clone)]
pub enum AuthMode {
    /// No credentials; every request is `Anonymous` (unsafe-any HTTP, or a
    /// trusted caller). No replay ledger.
    Open,
    /// A shared `Authorization: Bearer <token>`, required on every RPC,
    /// unary and streaming (`mkit serve --http` parity), compared in
    /// constant time. No replay ledger.
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
    /// Added to the business clock for this request only: the M0-05b test
    /// directive. Never feeds a commit deadline.
    pub(crate) business_skew_ms: i64,
}

impl Authenticated {
    /// The procedure these credentials were checked for; every entry point
    /// refuses any other.
    #[must_use]
    pub fn procedure(&self) -> Procedure {
        self.procedure
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
            if !ct_eq(got.as_bytes(), expected.as_bytes()) {
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
        // Reads stay unsigned under auth v2 (`vcs-worker` parity).
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

/// Constant-time equality (`http.rs` rationale: a timing side channel on
/// the bearer check leaks the token). Only the length is not hidden.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let diff = a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y));
    core::hint::black_box(diff) == 0
}

#[cfg(test)]
mod tests {
    use super::ct_eq;

    #[test]
    fn ct_eq_compares_bytes_and_length() {
        assert!(ct_eq(b"Bearer abc", b"Bearer abc"));
        assert!(ct_eq(b"", b""));
        assert!(!ct_eq(b"Bearer abc", b"Bearer abd"));
        assert!(!ct_eq(b"Bearer ab", b"Bearer abc"));
    }
}
