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
// The verified writer pubkey is stashed on `ctx.extensions` as `AuthorPubkey`.
// UpdateRef/AdvanceRefs read it here (via `enforce_write_quota`, below);
// UploadPack's handler (`worker_impl/service.rs`) reads the copy stashed by
// `intercept_streaming` to run its own quota check once it knows the pack
// size (see that function's doc for why it can't run in this interceptor).
//
// Once the envelope verifies, every write ALSO consults the verified
// author's write quota (`crate::write_quota`) before the corresponding
// storage write, so a freely-minted Ed25519 key can't flood R2/DO storage
// for free — a valid signature is proof of a distinct key, not a throttled
// one. Ported from apps/repo-worker/src/worker_impl/auth.rs's identical
// `enforce_write_quota`, this fails OPEN *only* when the DO round trip
// itself is unreachable (a plumbing error, logged and tolerated — a
// throttle must not become an outage for every writer when the DO briefly
// can't be reached) and fails CLOSED (an explicit `resource_exhausted`) on
// every other outcome, including a DO response that says the budget is
// exceeded. The budget itself is tracked inside the (single, global)
// RefStore DO (`refstore.rs`'s `/quota` op), NOT here: the DO's serial
// execution is what makes the check race-free, so this interceptor (and
// `upload_pack`) are only the caller + the ConnectError translation, never
// the counter.
//
// UpdateRef/AdvanceRefs charge 0 bytes (a ref CAS carries no chargeable
// payload — same treatment repo-worker gives UpdateRef); UploadPack charges
// the pack's declared size. See `crate::write_quota`'s module docs for the
// full rationale, including why there is no room dimension here (unlike
// repo-worker, this Worker serves a single global repository).

use connectrpc::interceptor::{
    NextStream, PayloadStream, StreamRequest, StreamResponse, UnaryRequest, UnaryResponse,
};
use connectrpc::{ConnectError, Interceptor, Next, async_trait};
use worker::Env;
use worker::send::SendFuture;

use crate::envelope::{
    EnvelopeHeaders, StreamEnvelopeHeaders, VerifyEnvelope, verify_envelope, verify_stream_envelope,
};
use crate::hashing::blake3_hex;

use super::service::do_call;
use super::wire::{QuotaCheckReq, QuotaCheckResp};

/// The verified Ed25519 writer pubkey (64-hex), placed on `ctx.extensions` by
/// the interceptor. Read by `enforce_write_quota` below (UpdateRef/
/// AdvanceRefs) and by `upload_pack`'s handler (UploadPack, once the pack
/// size is known) — see the module docs for why UploadPack's quota check
/// can't run here.
#[derive(Clone)]
pub struct AuthorPubkey(pub String);

/// Check-and-consume `author`'s write budget against the deployment's single
/// global RefStore DO. Returns `Some(ConnectError::resource_exhausted)` when
/// the DO reports the budget exceeded; `None` to let the write proceed —
/// including when the DO round trip itself fails (a plumbing error, logged
/// and FAILS OPEN; see the module docs' justification, ported verbatim from
/// apps/repo-worker/src/worker_impl/auth.rs). Every OTHER outcome (the DO
/// reachable and reporting the budget exceeded) fails CLOSED. Shared by
/// `AuthInterceptor::intercept_unary` (UpdateRef/AdvanceRefs, `bytes = 0`)
/// and `service::upload_pack` (UploadPack, `bytes = header.total_bytes`).
pub(crate) async fn enforce_write_quota(
    env: &Env,
    author: &str,
    incoming_bytes: u64,
) -> Option<ConnectError> {
    let env = env.clone();
    let author = author.to_owned();
    // The DO stub's `fetch_with_request` wraps a `!Send` JS future
    // (`JsFuture`); wrap in `SendFuture` to satisfy callers that themselves
    // run inside a `Send`-bound handler future, exactly like every DO/R2 call
    // in `service.rs` does for its own calls.
    SendFuture::new(async move {
        let resp: QuotaCheckResp = match do_call(
            &env,
            "/quota",
            &QuotaCheckReq {
                author: author.clone(),
                bytes: incoming_bytes,
            },
        )
        .await
        {
            Ok(resp) => resp,
            Err(e) => {
                worker::console_error!("write-quota check failed open for {author}: {e}");
                return None;
            }
        };
        if resp.allowed {
            None
        } else {
            Some(ConnectError::resource_exhausted(
                resp.reason
                    .unwrap_or_else(|| "write quota exceeded".to_string()),
            ))
        }
    })
    .await
}

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

pub struct AuthInterceptor {
    /// Needed to address the (single, global) RefStore DO for the
    /// write-quota check. Cheap to clone (see `worker::Env`'s doc note on
    /// apps/repo-worker's `worker_impl.rs`).
    env: Env,
}

impl AuthInterceptor {
    pub fn new(env: Env) -> Self {
        Self { env }
    }
}

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
                // UpdateRef/AdvanceRefs write-quota check: neither RPC
                // carries a chargeable payload (a ref CAS moves a pointer,
                // not bytes), so this charges 0 bytes and only consumes an
                // op — same treatment apps/repo-worker gives UpdateRef. Runs
                // AFTER the envelope verifies but STILL short-circuits
                // before `next.run` — the handler never sees a request that
                // fails its quota.
                if let Some(err) = enforce_write_quota(&self.env, &public_key, 0).await {
                    return Err(err);
                }

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
                // NO write-quota check here, unlike intercept_unary above:
                // this runs before the stream's `header` message has
                // arrived, so the pack size isn't known yet — there is
                // nothing to charge a byte quota against. `AuthorPubkey` is
                // stashed for `upload_pack`'s handler
                // (`worker_impl/service.rs`) to run the full (op + bytes)
                // quota check itself, right after it decodes `header`, still
                // before any chunk is read or stored.
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
