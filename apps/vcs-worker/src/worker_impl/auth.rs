// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Write-envelope auth, as a ConnectRPC `Interceptor` (DEMO MODE — open-write,
// no allow-list), adapted from apps/repo-worker/src/worker_impl/auth.rs.
//
// UpdateRef and AdvanceRefs are unary: `intercept_unary` runs after header
// parse + body decode and before the handler, with the RAW request body
// bytes available — the same body-bound envelope repo-worker uses.
//
// UploadPack is client-streaming: `intercept_streaming` runs ONCE at stream
// establishment, before any message (header or chunk) has arrived, so there
// is no body to bind a digest to yet. It verifies the narrower streaming
// envelope instead (see envelope.rs's module docs for exactly what that
// does and does not prove) — pack content integrity is separately and
// unconditionally enforced inside the UploadPack handler itself
// (SPEC-TRANSPORT-CONNECT §6.1: BLAKE3(received) == header.pack_id).
//
// PackExists/ReadRef/ListRefs are unauthenticated reads (same read/write
// split as apps/repo-worker).
//
// The verified writer pubkey is stashed on `ctx.extensions` as `AuthorPubkey`
// (unused by any handler today — no RPC in this service attributes a writer
// — kept for parity with repo-worker's pattern and any future audit trail).

use connectrpc::interceptor::{
    NextStream, PayloadStream, StreamRequest, StreamResponse, UnaryRequest, UnaryResponse,
};
use connectrpc::{ConnectError, Interceptor, Next, async_trait};

use crate::envelope::{
    EnvelopeHeaders, StreamEnvelopeHeaders, VerifyEnvelope, verify_envelope, verify_stream_envelope,
};
use crate::hashing::blake3_hex;

/// The verified Ed25519 writer pubkey (64-hex), placed on `ctx.extensions` by
/// the interceptor. No handler in this service reads it today — unlike
/// repo-worker's `UpdateRef`, this proto carries no author-attribution field
/// — it is stashed anyway for parity with repo-worker's pattern and any
/// future audit-log RPC.
#[derive(Clone)]
#[allow(dead_code)]
pub struct AuthorPubkey(pub String);

/// Unary procedures that mutate state and therefore require a write envelope.
fn requires_unary_write_auth(procedure: &str) -> bool {
    procedure.ends_with("/UpdateRef") || procedure.ends_with("/AdvanceRefs")
}

/// Streaming procedures that mutate state and therefore require a write
/// envelope. Only UploadPack is client-streaming in this service.
fn requires_stream_write_auth(procedure: &str) -> bool {
    procedure.ends_with("/UploadPack")
}

/// Normalize an incoming hex header: strip an optional `0x`, lowercase.
fn normalize_hex(v: &str) -> String {
    let v = v.trim();
    let v = v
        .strip_prefix("0x")
        .or_else(|| v.strip_prefix("0X"))
        .unwrap_or(v);
    v.to_ascii_lowercase()
}

pub struct AuthInterceptor;

#[async_trait]
impl Interceptor for AuthInterceptor {
    async fn intercept_unary(
        &self,
        req: UnaryRequest,
        next: Next<'_>,
    ) -> Result<UnaryResponse, ConnectError> {
        let procedure = req.ctx.path().unwrap_or_default().to_owned();

        if !requires_unary_write_auth(&procedure) {
            return next.run(req).await; // reads are open
        }

        // BLAKE3 of the raw request body (the serialized protobuf message),
        // computed server-side — this is what the envelope binds to.
        let actual_body_digest = blake3_hex(req.payload.bytes());

        let header = |name: &str| {
            req.ctx
                .header(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned)
        };

        let headers = EnvelopeHeaders {
            public_key: header("x-public-key").map(|s| normalize_hex(&s)),
            signature: header("x-signature").map(|s| normalize_hex(&s)),
            digest: header("x-digest").map(|s| normalize_hex(&s)),
            created_at: header("x-created-at"),
            idempotency_key: header("idempotency-key"),
        };

        let now = now_ms();
        match verify_envelope(&procedure, &actual_body_digest, now, &headers) {
            VerifyEnvelope::Ok { public_key, .. } => {
                let mut req = req;
                req.ctx.extensions_mut().insert(AuthorPubkey(public_key));
                next.run(req).await
            }
            VerifyEnvelope::Err { status: 400, error } => {
                Err(ConnectError::invalid_argument(error))
            }
            VerifyEnvelope::Err { error, .. } => Err(ConnectError::unauthenticated(error)),
        }
    }

    async fn intercept_streaming(
        &self,
        req: StreamRequest,
        inbound: PayloadStream,
        next: NextStream<'_>,
    ) -> Result<StreamResponse, ConnectError> {
        let procedure = req.ctx.path().unwrap_or_default().to_owned();

        if !requires_stream_write_auth(&procedure) {
            return next.run(req, inbound).await;
        }

        let header = |name: &str| {
            req.ctx
                .header(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned)
        };

        let headers = StreamEnvelopeHeaders {
            public_key: header("x-public-key").map(|s| normalize_hex(&s)),
            signature: header("x-signature").map(|s| normalize_hex(&s)),
            created_at: header("x-created-at"),
            idempotency_key: header("idempotency-key"),
        };

        let now = now_ms();
        match verify_stream_envelope(&procedure, now, &headers) {
            VerifyEnvelope::Ok { public_key, .. } => {
                let mut req = req;
                req.ctx.extensions_mut().insert(AuthorPubkey(public_key));
                next.run(req, inbound).await
            }
            VerifyEnvelope::Err { status: 400, error } => {
                Err(ConnectError::invalid_argument(error))
            }
            VerifyEnvelope::Err { error, .. } => Err(ConnectError::unauthenticated(error)),
        }
    }
}

/// Current epoch milliseconds. On wasm32 this reads the JS `Date.now()` via
/// the worker runtime clock; the value is only used for the ±5min freshness
/// window, so wall-clock precision is sufficient.
fn now_ms() -> i64 {
    worker::Date::now().as_millis() as i64
}
