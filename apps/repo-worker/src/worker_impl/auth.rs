// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Write-envelope auth, as a ConnectRPC unary Interceptor (DEMO MODE —
// open-write, no allow-list). It runs after header parse + body decode and
// before the handler, with typed access to the procedure path, the request
// headers, and the RAW request body bytes — exactly the envelope inputs.
//
// Writes (PutObject, UpdateRef) MUST carry a valid, fresh, body-bound
// signed envelope from SOME valid Ed25519 key. Reads (GetObject, GetRef,
// ListRefs, WatchRefs) are unauthenticated. A failed check short-circuits
// with a ConnectError (mapped from the envelope's 400/401 status) before the
// handler runs.
//
// The verified writer pubkey is stashed on `ctx.extensions` as `AuthorPubkey`
// so UpdateRef can attribute the RefEvent without re-parsing headers.

use connectrpc::{async_trait, ConnectError, Interceptor, Next};
use connectrpc::interceptor::{UnaryRequest, UnaryResponse};

use crate::envelope::{verify_envelope, EnvelopeHeaders, VerifyEnvelope};
use crate::hashing::blake3_hex;

/// The verified Ed25519 writer pubkey (64-hex), placed on `ctx.extensions`
/// by the interceptor for the handler to read.
#[derive(Clone)]
pub struct AuthorPubkey(pub String);

/// The request's `Idempotency-Key` (verified as part of the signed envelope),
/// placed on `ctx.extensions` for handlers that need replay protection. Empty
/// when the request carried no key. PostMessage and React use it (keyed on
/// `author`) to dedupe replays of a captured signature. UpdateRef uses it too
/// (keyed on `author` + ref `name`) to close the `REF_EXPECTATION_ANY`
/// replay-clobber hole: a replayed signed ANY-update returns its original
/// result instead of re-running the CAS. PutObject remains naturally
/// idempotent (content-addressed) and ignores it.
#[derive(Clone)]
pub struct IdempotencyKey(pub String);

/// Procedures that mutate state and therefore require a write envelope.
/// PostMessage is a signed write too — the verified pubkey IS the chat
/// author (same open-write/demo model as UpdateRef). ListMessages, like the
/// other reads, is open.
fn requires_write_auth(procedure: &str) -> bool {
    procedure.ends_with("/PutObject")
        || procedure.ends_with("/UpdateRef")
        || procedure.ends_with("/PostMessage")
        || procedure.ends_with("/React")
}

/// Normalize an incoming hex header: strip an optional `0x`, lowercase.
fn normalize_hex(v: &str) -> String {
    let v = v.trim();
    let v = v.strip_prefix("0x").or_else(|| v.strip_prefix("0X")).unwrap_or(v);
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
        // The fully-qualified procedure, e.g. "/mkit.repo.v1.RepoService/UpdateRef".
        let procedure = req.ctx.path().unwrap_or_default().to_owned();

        if !requires_write_auth(&procedure) {
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
            VerifyEnvelope::Ok { public_key, idempotency_key, .. } => {
                let mut req = req;
                req.ctx.extensions_mut().insert(AuthorPubkey(public_key));
                req.ctx.extensions_mut().insert(IdempotencyKey(idempotency_key));
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

/// Current epoch milliseconds. On wasm32 this reads the JS `Date.now()` via
/// the worker runtime clock; the value is only used for the ±5min freshness
/// window, so wall-clock precision is sufficient.
fn now_ms() -> i64 {
    worker::Date::now().as_millis() as i64
}
