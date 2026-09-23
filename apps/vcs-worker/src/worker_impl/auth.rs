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
#[cfg(feature = "managed-access")]
use futures::StreamExt;
#[cfg(feature = "managed-access")]
use std::sync::{Arc, Mutex};
use worker::Env;

#[cfg(feature = "managed-access")]
#[derive(Clone)]
pub enum VerifiedState {
    Unseen,
    Rejected,
    Verified(mkit_worker_common::replay::Proof),
}

pub struct AuthInterceptor {
    env: Env,
    #[cfg(feature = "managed-access")]
    verified: Arc<Mutex<VerifiedState>>,
}
impl AuthInterceptor {
    pub fn new(env: Env) -> Self {
        Self {
            env,
            #[cfg(feature = "managed-access")]
            verified: Arc::new(Mutex::new(VerifiedState::Unseen)),
        }
    }
    #[cfg(feature = "managed-access")]
    pub fn verified(&self) -> Arc<Mutex<VerifiedState>> {
        self.verified.clone()
    }
    #[cfg(feature = "managed-access")]
    fn save(&self, state: VerifiedState) -> Result<(), ConnectError> {
        *self
            .verified
            .lock()
            .map_err(|_| ConnectError::unavailable("managed authorization unavailable"))? = state;
        Ok(())
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
        #[cfg(feature = "managed-access")]
        if crate::access_policy::DataRoute::from_path(&procedure).is_none() {
            return Err(ConnectError::unimplemented("unknown managed procedure"));
        }
        #[cfg(not(feature = "managed-access"))]
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
                #[cfg(feature = "managed-access")]
                self.save(VerifiedState::Verified(
                    mkit_worker_common::replay::Proof::from(&authorization),
                ))?;
                req.ctx.extensions_mut().insert(authorization);
                next.run(req).await
            }
            VerifyEnvelope::Err { error, .. } => {
                #[cfg(feature = "managed-access")]
                self.save(VerifiedState::Rejected)?;
                Err(ConnectError::unauthenticated(error))
            }
        }
    }
    async fn intercept_streaming(
        &self,
        mut req: StreamRequest,
        inbound: PayloadStream,
        next: NextStream<'_>,
    ) -> Result<StreamResponse, ConnectError> {
        let procedure = req.ctx.path().unwrap_or_default().to_owned();
        #[cfg(feature = "managed-access")]
        if crate::access_policy::DataRoute::from_path(&procedure).is_none() {
            return Err(ConnectError::unimplemented("unknown managed procedure"));
        }
        #[cfg(not(feature = "managed-access"))]
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
        #[cfg(feature = "managed-access")]
        if procedure.ends_with("/DownloadPack") {
            let mut inbound = inbound;
            let payload = inbound
                .next()
                .await
                .ok_or_else(|| ConnectError::invalid_argument("missing DownloadPack request"))??;
            if inbound.next().await.is_some() {
                return Err(ConnectError::invalid_argument("extra DownloadPack request"));
            }
            let result = verify_envelope(
                Context {
                    audience: &audience,
                    repository: &repository,
                },
                &procedure,
                &blake3_hex(payload.bytes()),
                worker::Date::now().as_millis() as i64,
                &headers,
            );
            return match result {
                VerifyEnvelope::Ok { authorization, .. } => {
                    self.save(VerifiedState::Verified(
                        mkit_worker_common::replay::Proof::from(&authorization),
                    ))?;
                    req.ctx.extensions_mut().insert(authorization);
                    next.run(req, Box::pin(futures::stream::iter([Ok(payload)])))
                        .await
                }
                VerifyEnvelope::Err { error, .. } => {
                    self.save(VerifiedState::Rejected)?;
                    Err(ConnectError::unauthenticated(error))
                }
            };
        }
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
                #[cfg(feature = "managed-access")]
                self.save(VerifiedState::Verified(
                    mkit_worker_common::replay::Proof::from(&authorization),
                ))?;
                req.ctx.extensions_mut().insert(authorization);
                next.run(req, inbound).await
            }
            VerifyEnvelope::Err { error, .. } => {
                #[cfg(feature = "managed-access")]
                self.save(VerifiedState::Rejected)?;
                Err(ConnectError::unauthenticated(error))
            }
        }
    }
}
