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
//
// Once the envelope verifies, PutObject/UpdateRef ALSO consult the verified
// author's per-room write quota (`crate::write_quota`) before the handler
// runs, so a freely-minted Ed25519 key can't flood R2/DO storage for free —
// a valid signature is proof of a distinct key, not a throttled one. The
// budget itself is tracked inside the room's RefStore DO (`refstore.rs`
// `/quota` op), NOT here: the DO's serial per-room execution is what makes
// the check race-free, so this interceptor is only the caller + the
// ConnectError translation, never the counter. PostMessage/React already
// have their own DO-side rate limits (`chat::is_rate_limited`,
// `REACT_MIN_INTERVAL_MS`) and are not additionally quota-checked here.
//
// OBSERVABILITY: every write this interceptor sees — accepted or rejected —
// is also mirrored to the `WRITE_EVENTS` Analytics Engine dataset (see
// wrangler.jsonc), so per-room write volume and auth-failure rate are
// queryable instead of invisible. The *decision* of what to log lives in the
// pure, host-testable `crate::audit` module; this file only decodes the room
// (accepted writes only — see `crate::audit::WriteAudit`) and pushes the
// resulting record to Analytics Engine. A dataset write failure (or a
// missing binding, e.g. local `wrangler dev` without it configured) is
// logged via `console_error!` and never fails the request — telemetry must
// never take the write path down (same "count and log, don't silently drop"
// posture as `refstore::broadcast_str`). Logging happens BEFORE the
// write-quota check below: the envelope verified, so the write IS
// `WriteAudit::Accepted` from an observability standpoint even if the quota
// gate then throttles it — quota rejections stay out of
// `WriteAudit::Rejected`, which is reserved for envelope-verification
// failures (see `crate::audit::WriteAudit` doc).
//
// PurgeRoom uses a SEPARATE, simpler gate: a bearer `X-Admin-Token` header
// checked against the `ADMIN_TOKEN` Worker secret (constant-time compare).
// It deliberately does NOT reuse the write envelope — a purge is an operator
// action with no room-participant author to attribute, and requiring an
// Ed25519 keypair for an ops-only endpoint would add ceremony with no
// corresponding benefit. An unset `ADMIN_TOKEN` fails every PurgeRoom call
// closed (never open). PurgeRoom is not write-quota-checked or write-audited
// — it isn't a room-participant write, so neither the budget nor the
// accepted/rejected write-telemetry model applies to it.

use connectrpc::interceptor::{UnaryRequest, UnaryResponse};
use connectrpc::payload::Payload;
use connectrpc::{ConnectError, Interceptor, Next, async_trait};
use worker::{AnalyticsEngineDataPointBuilder, AnalyticsEngineDataset, Env};

use buffa::Message as _;
use worker::send::SendFuture;

use crate::audit::{WriteAudit, audit_for};
use crate::envelope::{EnvelopeHeaders, VerifyEnvelope, verify_envelope};
use crate::hashing::{blake3_hex, constant_time_eq};
use crate::proto::mkit::repo::v1::{
    PostMessageRequest, PutObjectRequest, ReactRequest, UpdateRefRequest,
};
use crate::refs::is_valid_room;

use super::service::do_call;
use super::wire::{QuotaCheckReq, QuotaCheckResp};

/// Analytics Engine binding name (see wrangler.jsonc `analytics_engine_datasets`).
const WRITE_EVENTS_BINDING: &str = "WRITE_EVENTS";

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
    /// Needed to address the room's RefStore DO for the write-quota check,
    /// and to reach the `WRITE_EVENTS` Analytics Engine binding for
    /// accepted/rejected-write telemetry. Cheap to clone (see `worker::Env`'s
    /// doc note on `worker_impl.rs`).
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

    /// Check-and-consume `author`'s write budget for `room` against the
    /// room's RefStore DO. Returns `Some(ConnectError::resource_exhausted)`
    /// when the DO reports the budget exceeded; `None` to let the write
    /// proceed — including when the DO round trip itself fails (a plumbing
    /// error is logged and FAILS OPEN, matching the best-effort tolerance the
    /// rest of the DO's ledgers use for their own housekeeping writes; a
    /// throttle must not become an outage for every writer when the DO is
    /// briefly unreachable).
    async fn enforce_write_quota(
        &self,
        room: &str,
        author: &str,
        incoming_bytes: u64,
    ) -> Option<ConnectError> {
        let env = self.env.clone();
        let room = room.to_owned();
        let author = author.to_owned();
        // The DO stub's `fetch_with_request` wraps a `!Send` JS future
        // (`JsFuture`); wrap in `SendFuture` to satisfy the `Interceptor`
        // trait's `Send` bound, exactly like every handler in `service.rs`
        // does for its own DO/R2 calls (sound under single-threaded wasm).
        SendFuture::new(async move {
            let resp: QuotaCheckResp = match do_call(
                &env,
                &room,
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

    /// Push one audit record to the `WRITE_EVENTS` Analytics Engine dataset.
    /// A missing binding or a failed write is logged and swallowed —
    /// telemetry must never fail the request it's describing.
    fn log_write(&self, audit: WriteAudit) {
        match self.env.analytics_engine(WRITE_EVENTS_BINDING) {
            Ok(dataset) => write_data_point(&dataset, &audit),
            Err(e) => worker::console_error!(
                "auth: {WRITE_EVENTS_BINDING} analytics engine binding unavailable: {e}"
            ),
        }
    }
}

/// For a write procedure that carries a per-room quota (`PutObject`,
/// `UpdateRef`), decode just enough of the raw request body to learn the
/// `room` and the payload size to charge against the budget (the `PutObject`
/// `bytes` field length; `UpdateRef` carries no object bytes, so 0). Returns
/// `None` for any other procedure, or when the body fails to decode as its
/// expected message (malformed input the handler will reject on its own —
/// nothing to charge a quota against yet).
fn parse_write_target(procedure: &str, body: &bytes::Bytes) -> Option<(String, u64)> {
    if procedure.ends_with("/PutObject") {
        let mut buf = body.clone();
        let msg = PutObjectRequest::decode(&mut buf).ok()?;
        let room = msg.room?;
        let len = msg.bytes.as_ref().map_or(0, |b| b.len() as u64);
        Some((room, len))
    } else if procedure.ends_with("/UpdateRef") {
        let mut buf = body.clone();
        let msg = UpdateRefRequest::decode(&mut buf).ok()?;
        let room = msg.room?;
        Some((room, 0))
    } else {
        None
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
            public_key: header("x-public-key").map(|s| normalize_hex(&s)),
            signature: header("x-signature").map(|s| normalize_hex(&s)),
            digest: header("x-digest").map(|s| normalize_hex(&s)),
            created_at: header("x-created-at"),
            idempotency_key: header("idempotency-key"),
        };

        let now = now_ms();
        let result = verify_envelope(&procedure, &actual_body_digest, now, &headers);
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
                idempotency_key,
                ..
            } => {
                // Per-room write-quota check, PutObject/UpdateRef only. Skips
                // cleanly (no check) when the body doesn't decode or carries
                // an invalid room — the handler's own validation rejects
                // those with a clean `invalid_argument`, so there is nothing
                // for a quota to protect yet. Runs AFTER the audit log above
                // (the envelope verified, so the write is "accepted" from an
                // observability standpoint) but STILL short-circuits before
                // `next.run` — the handler never sees a request that fails
                // its quota.
                if let Some((room, incoming_bytes)) =
                    parse_write_target(&procedure, req.payload.bytes())
                    && is_valid_room(&room)
                    && let Some(err) = self
                        .enforce_write_quota(&room, &public_key, incoming_bytes)
                        .await
                {
                    return Err(err);
                }

                let mut req = req;
                req.ctx.extensions_mut().insert(AuthorPubkey(public_key));
                req.ctx
                    .extensions_mut()
                    .insert(IdempotencyKey(idempotency_key));
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
