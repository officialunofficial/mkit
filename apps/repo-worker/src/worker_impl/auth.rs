// SPDX-License-Identifier: MIT OR Apache-2.0
//! Auth v2 verifies the deployment audience, decoded room, request commitment,
//! expiry and nonce before dispatch. RefStore couples durable replay, quota and
//! effects in an explicit transaction. PurgeRoom retains its separate admin gate.

use connectrpc::interceptor::{UnaryRequest, UnaryResponse};
use connectrpc::payload::Payload;
use connectrpc::{ConnectError, Interceptor, Next, async_trait};
use worker::{AnalyticsEngineDataPointBuilder, AnalyticsEngineDataset, Env};

use crate::audit::{WriteAudit, audit_for};
use crate::envelope::{Context, EnvelopeHeaders, VerifyEnvelope, verify_envelope};
use crate::hashing::{blake3_hex, constant_time_eq};
use crate::proto::mkit::repo::v1::{
    PostMessageRequest, PutObjectRequest, ReactRequest, UpdateRefRequest,
};

/// Analytics Engine binding name (see wrangler.jsonc `analytics_engine_datasets`).
const WRITE_EVENTS_BINDING: &str = "WRITE_EVENTS";

/// The verified Ed25519 writer pubkey (64-hex), placed on `ctx.extensions`
/// by the interceptor for the handler to read.
#[derive(Clone)]
pub struct AuthorPubkey(pub String);

/// Procedures that mutate state and therefore require a write envelope.
/// PostMessage is a signed write too — the verified pubkey IS the chat
/// author (same open-write/demo model as UpdateRef). ListMessages, like the
/// other reads, is open. PurgeRoom is NOT here — it uses the separate admin
/// gate (`requires_admin_auth`), not the write envelope.
fn requires_write_auth(procedure: &str) -> bool {
    procedure.ends_with("/PutObject")
        || procedure.ends_with("/UpdateRef")
        || procedure.ends_with("/PostMessage")
        || procedure.ends_with("/React")
}

/// Procedures gated by the admin bearer token instead of the write envelope.
fn requires_admin_auth(procedure: &str) -> bool {
    procedure.ends_with("/PurgeRoom")
}

pub struct AuthInterceptor {
    /// Configured audience and WRITE_EVENTS telemetry binding.
    env: Env,
    /// The server's configured `ADMIN_TOKEN` secret, read once per request in
    /// `worker_impl.rs::serve_connect`. `None` when the secret is unset —
    /// every `PurgeRoom` call then fails closed with `unauthenticated`,
    /// regardless of what the caller sends.
    admin_token: Option<String>,
}

impl AuthInterceptor {
    pub fn new(env: Env, admin_token: Option<String>) -> Self {
        Self { env, admin_token }
    }

    fn log_write(&self, audit: WriteAudit) {
        match self.env.analytics_engine(WRITE_EVENTS_BINDING) {
            Ok(dataset) => write_data_point(&dataset, &audit),
            Err(e) => worker::console_error!(
                "auth: {WRITE_EVENTS_BINDING} analytics engine binding unavailable: {e}"
            ),
        }
    }
}

#[async_trait]
impl Interceptor for AuthInterceptor {
    async fn intercept_unary(
        &self,
        req: UnaryRequest,
        next: Next<'_>,
    ) -> Result<UnaryResponse, ConnectError> {
        // The fully-qualified procedure, e.g. "/mkit.repo.v1.RepoService/UpdateRef".
        let procedure = req.ctx.path().unwrap_or_default().to_owned();

        if requires_admin_auth(&procedure) {
            let header = req
                .ctx
                .header("x-admin-token")
                .and_then(|v| v.to_str().ok());
            let authorized = match (self.admin_token.as_deref(), header) {
                (Some(expected), Some(actual)) if !expected.is_empty() => {
                    constant_time_eq(expected.as_bytes(), actual.as_bytes())
                }
                // Either the server has no ADMIN_TOKEN configured, or the
                // caller sent no header — both fail closed, never open.
                _ => false,
            };
            return if authorized {
                next.run(req).await
            } else {
                Err(ConnectError::unauthenticated(
                    "missing or invalid X-Admin-Token",
                ))
            };
        }

        if !requires_write_auth(&procedure) {
            return next.run(req).await; // reads are open
        }

        // BLAKE3 of the raw request body (the serialized protobuf message),
        // computed server-side — this is what the envelope binds to.
        let actual_body_digest = blake3_hex(req.payload.bytes());
        let body_len = req.payload.bytes().len() as u64;

        let header = |name: &str| {
            req.ctx
                .header(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned)
        };

        let headers = EnvelopeHeaders {
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
        };

        let now = now_ms();
        let audience = self
            .env
            .var("AUTH_AUDIENCE")
            .map_err(|_| ConnectError::unavailable("AUTH_AUDIENCE is not configured"))?
            .to_string();
        let repository = room_of(&procedure, &req.payload);
        let result = verify_envelope(
            Context {
                audience: &audience,
                repository: &repository,
            },
            &procedure,
            &actual_body_digest,
            now,
            &headers,
        );
        // `audit_for` only decodes the room on the accepted path (see its
        // doc) — a rejected envelope's body isn't authenticated, so we don't
        // spend a decode on it.
        let audit = audit_for(&procedure, body_len, &result, || {
            room_of(&procedure, &req.payload)
        });
        self.log_write(audit);

        match result {
            VerifyEnvelope::Ok {
                public_key,
                authorization,
                ..
            } => {
                let mut req = req;
                req.ctx.extensions_mut().insert(authorization);
                req.ctx.extensions_mut().insert(AuthorPubkey(public_key));
                next.run(req).await
            }
            VerifyEnvelope::Err { status: 400, error } => {
                Err(ConnectError::invalid_argument(error))
            }
            VerifyEnvelope::Err { error, .. } => Err(ConnectError::unauthenticated(error)),
        }
    }
    // intercept_streaming keeps the default passthrough: WatchRefs is an
    // unauthenticated read.
}

/// Read the write's `room` field out of the request payload. Every
/// procedure `requires_write_auth` covers (PutObject, UpdateRef,
/// PostMessage, React) declares `room` as field 1 of its request message
/// (see proto/mkit/repo/v1/repo.proto) — decoding into the exact generated
/// type for the procedure (via `Payload::message`, which handles both the
/// proto and Connect-JSON wire codecs) keeps this correct instead of
/// hand-parsing the wire format. A decode failure (shouldn't happen — the
/// handler decodes the same bytes right after) yields an empty room rather
/// than failing the request; this is telemetry, not the auth decision.
fn room_of(procedure: &str, payload: &Payload) -> String {
    let room = if procedure.ends_with("/PutObject") {
        payload
            .message::<PutObjectRequest>()
            .ok()
            .and_then(|m| m.room.clone())
    } else if procedure.ends_with("/UpdateRef") {
        payload
            .message::<UpdateRefRequest>()
            .ok()
            .and_then(|m| m.room.clone())
    } else if procedure.ends_with("/PostMessage") {
        payload
            .message::<PostMessageRequest>()
            .ok()
            .and_then(|m| m.room.clone())
    } else if procedure.ends_with("/React") {
        payload
            .message::<ReactRequest>()
            .ok()
            .and_then(|m| m.room.clone())
    } else {
        None
    };
    room.unwrap_or_default()
}

/// Encode one `WriteAudit` as an Analytics Engine data point and write it.
/// `indexes` takes exactly one value (Analytics Engine drops multi-index
/// points) — "accepted"/"rejected" — so the two outcomes are cheaply
/// filterable in a query without parsing blobs.
fn write_data_point(dataset: &AnalyticsEngineDataset, audit: &WriteAudit) {
    let point = match audit {
        WriteAudit::Accepted {
            room,
            procedure,
            author_pubkey,
            bytes,
        } => AnalyticsEngineDataPointBuilder::new()
            .indexes(["accepted"])
            .add_blob(procedure.as_str())
            .add_blob(room.as_str())
            .add_blob(author_pubkey.as_str())
            .add_double(*bytes as f64)
            .build(),
        WriteAudit::Rejected {
            procedure,
            reason,
            status,
        } => AnalyticsEngineDataPointBuilder::new()
            .indexes(["rejected"])
            .add_blob(procedure.as_str())
            .add_blob(reason.as_str())
            .add_double(f64::from(*status))
            .build(),
    };
    if let Err(e) = dataset.write_data_point(&point) {
        worker::console_error!("auth: analytics engine write_data_point failed: {e}");
    }
}

/// Current epoch milliseconds. On wasm32 this reads the JS `Date.now()` via
/// the worker runtime clock; the value is only used for the ±5min freshness
/// window, so wall-clock precision is sufficient.
fn now_ms() -> i64 {
    worker::Date::now().as_millis() as i64
}
