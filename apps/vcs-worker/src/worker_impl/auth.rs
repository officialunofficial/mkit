// SPDX-License-Identifier: MIT OR Apache-2.0
//! Destination and content-bound v2 authentication. Quota and nonce accounting
//! are performed atomically with effects inside RefStore, not in this interceptor.
use crate::envelope::{
    Context, EnvelopeHeaders, VerifyEnvelope, verify_envelope, verify_stream_envelope,
};
use crate::hashing::blake3_hex;
use connectrpc::interceptor::{
    NextStream, PayloadStream, StreamRequest, StreamResponse, UnaryRequest, UnaryResponse,
};
use connectrpc::{ConnectError, Interceptor, Next, async_trait};
use worker::Env;

pub struct AuthInterceptor {
    env: Env,
}
impl AuthInterceptor {
    pub fn new(env: Env) -> Self {
        Self { env }
    }
    fn destination(&self) -> Result<(String, String), ConnectError> {
        Ok((
            self.env
                .var("AUTH_AUDIENCE")
                .map_err(|_| ConnectError::unavailable("AUTH_AUDIENCE is not configured"))?
                .to_string(),
            self.env
                .var("AUTH_REPOSITORY")
                .map_err(|_| ConnectError::unavailable("AUTH_REPOSITORY is not configured"))?
                .to_string(),
        ))
    }
}
fn read_headers(header: impl Fn(&str) -> Option<String>) -> EnvelopeHeaders {
    EnvelopeHeaders {
        version: header("x-envelope-version"),
        audience: header("x-audience"),
        repository: header("x-repository"),
        commitment: header("x-content-commitment"),
        expires_at: header("x-expires-at"),
        public_key: header("x-public-key"),
        signature: header("x-signature"),
        digest: header("x-digest"),
        created_at: header("x-created-at"),
        idempotency_key: header("idempotency-key"),
    }
}
#[async_trait]
impl Interceptor for AuthInterceptor {
    async fn intercept_unary(
        &self,
        mut req: UnaryRequest,
        next: Next<'_>,
    ) -> Result<UnaryResponse, ConnectError> {
        let procedure = req.ctx.path().unwrap_or_default().to_owned();
        if !(procedure.ends_with("/UpdateRef") || procedure.ends_with("/AdvanceRefs")) {
            return next.run(req).await;
        }
        let (audience, repository) = self.destination()?;
        let headers = read_headers(|name| {
            req.ctx
                .header(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned)
        });
        match verify_envelope(
            Context {
                audience: &audience,
                repository: &repository,
            },
            &procedure,
            &blake3_hex(req.payload.bytes()),
            worker::Date::now().as_millis() as i64,
            &headers,
        ) {
            VerifyEnvelope::Ok { authorization, .. } => {
                req.ctx.extensions_mut().insert(authorization);
                next.run(req).await
            }
            VerifyEnvelope::Err { error, .. } => Err(ConnectError::unauthenticated(error)),
        }
    }
    async fn intercept_streaming(
        &self,
        mut req: StreamRequest,
        inbound: PayloadStream,
        next: NextStream<'_>,
    ) -> Result<StreamResponse, ConnectError> {
        let procedure = req.ctx.path().unwrap_or_default().to_owned();
        if !procedure.ends_with("/UploadPack") {
            return next.run(req, inbound).await;
        }
        let (audience, repository) = self.destination()?;
        let headers = read_headers(|name| {
            req.ctx
                .header(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned)
        });
        match verify_stream_envelope(
            Context {
                audience: &audience,
                repository: &repository,
            },
            &procedure,
            worker::Date::now().as_millis() as i64,
            &headers,
        ) {
            VerifyEnvelope::Ok { authorization, .. } => {
                req.ctx.extensions_mut().insert(authorization);
                next.run(req, inbound).await
            }
            VerifyEnvelope::Err { error, .. } => Err(ConnectError::unauthenticated(error)),
        }
    }
}
