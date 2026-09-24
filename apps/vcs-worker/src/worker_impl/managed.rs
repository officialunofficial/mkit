// SPDX-License-Identifier: MIT OR Apache-2.0
//! Closed managed fetch boundary and owner-only management transport.
use super::{
    auth::{AuthInterceptor, VerifiedState},
    service::{MAX_PACK_BYTES, TransportServer},
};
use crate::access_policy::{DataRoute, Identity, MAX_ADMIN_BODY};
use crate::envelope::{
    Context as AuthContext, EnvelopeHeaders, VerifyEnvelope, verify_envelope,
    verify_stream_envelope,
};
use crate::hashing::blake3_hex;
use crate::proto::mkit::transport::v1::TransportServiceExt;
use connectrpc::{ConnectRpcService, Limits, Router};
use futures::StreamExt;
use mkit_worker_common::{
    adapter::{
        copy_response_headers, dispatch_oneshot, http_request_from_worker, is_deadline_header,
        respond_buffered,
    },
    cors::with_cors,
    replay::Proof,
};
use serde::{Deserialize, Serialize};
use std::{cell::Cell, sync::Arc};
use worker::{Date, Env, Method, Request, RequestInit, Response, Result};

const MAX_TRANSFER_BODY: usize = MAX_PACK_BYTES + 64 * 1024;
thread_local! { static LARGE_TRANSFER_BUSY: Cell<bool> = const { Cell::new(false) }; }

struct TransferPermit;
impl TransferPermit {
    fn acquire() -> Option<Self> {
        LARGE_TRANSFER_BUSY.with(|busy| if busy.replace(true) { None } else { Some(Self) })
    }
}
impl Drop for TransferPermit {
    fn drop(&mut self) {
        LARGE_TRANSFER_BUSY.with(|busy| busy.set(false));
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AdminWire {
    pub identity: Identity,
    pub proof: Proof,
    pub operation: String,
    pub body: String,
}

enum BoundedBody {
    Ok(Vec<u8>),
    TooLarge,
}

async fn read_bounded_body(req: &mut Request, cap: usize) -> Result<BoundedBody> {
    let length = req.headers().get("content-length")?;
    if length
        .as_deref()
        .and_then(|value| value.parse::<usize>().ok())
        .is_some_and(|value| value > cap)
    {
        return Ok(BoundedBody::TooLarge);
    }
    let mut stream = match req.stream() {
        Ok(stream) => stream,
        Err(worker::Error::RustError(message)) if message == "no body for request" => {
            return Ok(BoundedBody::Ok(Vec::new()));
        }
        Err(error) => return Err(error),
    };
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if chunk.len() > cap - body.len() {
            return Ok(BoundedBody::TooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(BoundedBody::Ok(body))
}

fn reply(status: u16, message: &str) -> Result<Response> {
    let mut response = Response::ok(format!("{message}\n"))?.with_status(status);
    response
        .headers_mut()
        .set("Content-Type", "application/json")?;
    response
        .headers_mut()
        .set("Cache-Control", "private, no-store")?;
    Ok(response)
}

fn headers(req: &Request) -> Result<EnvelopeHeaders> {
    let get = |key| req.headers().get(key);
    Ok(EnvelopeHeaders {
        version: get("x-envelope-version")?,
        audience: get("x-audience")?,
        repository: get("x-repository")?,
        commitment: get("x-content-commitment")?,
        expires_at: get("x-expires-at")?,
        public_key: get("x-public-key")?,
        signature: get("x-signature")?,
        digest: get("x-digest")?,
        created_at: get("x-created-at")?,
        idempotency_key: get("idempotency-key")?,
    })
}

pub async fn dispatch(req: Request, env: Env) -> Result<Response> {
    match dispatch_inner(req, env).await {
        Ok(response) => Ok(response),
        Err(_) => reply(503, "{\"code\":\"unavailable\"}"),
    }
}

async fn dispatch_inner(mut req: Request, env: Env) -> Result<Response> {
    let path = req.path();
    if path == super::snapshot_disclosure::PATH {
        return serve_disclosure(req, env, &path).await;
    }
    if let Some(route) = DataRoute::from_path(&path) {
        return serve_data(req, env, &path, route).await;
    }
    let operation = match path.as_str() {
        "/mkit/host/v1/InitializePolicy" => "initialize",
        "/mkit/host/v1/GetPolicy" => "get",
        "/mkit/host/v1/ReplacePolicy" => "replace",
        "/mkit/host/v1/RegisterGrant" => "register_grant",
        "/mkit/host/v1/RevokeGrant" => "revoke_grant",
        "/mkit/host/v1/GetGrant" => "get_grant",
        "/mkit/host/v1/BeginSnapshot" => "begin_snapshot",
        "/mkit/host/v1/ContinueSnapshot" => "continue_snapshot",
        "/mkit/host/v1/GetSnapshotJob" => "get_snapshot_job",
        "/mkit/host/v1/CancelSnapshot" => "cancel_snapshot",
        "/mkit/host/v1/CleanupSnapshots" => "cleanup_snapshots",
        _ => {
            #[cfg(feature = "test-faults")]
            if let Some(internal_path) = path.strip_prefix("/__test/refstore")
                && [
                    "/get",
                    "/list",
                    "/update",
                    "/advance",
                    "/object",
                    "/authorize",
                    "/managed-policy",
                ]
                .contains(&internal_path)
            {
                let ns = env.durable_object("REFSTORE")?;
                let stub = ns.id_from_name("root")?.get_stub()?;
                let mut init = RequestInit::new();
                let payload = if internal_path == "/managed-policy" {
                    req.text().await?
                } else {
                    "{}".into()
                };
                init.with_method(Method::Post)
                    .with_body(Some(payload.into()));
                let internal =
                    Request::new_with_init(&format!("https://refstore{internal_path}"), &init)?;
                let response = stub.fetch_with_request(internal).await?;
                return reply(response.status_code(), "{\"code\":\"unavailable\"}");
            }
            return reply(503, "{\"code\":\"unavailable\"}");
        }
    };
    if req.method() != Method::Post {
        return reply(405, "{\"code\":\"method_not_allowed\"}");
    }
    if req.headers().get("content-encoding")?.is_some() {
        return reply(415, "{\"code\":\"unsupported_media_type\"}");
    }
    if req.headers().get("content-type")?.as_deref() != Some("application/json") {
        return reply(415, "{\"code\":\"unsupported_media_type\"}");
    }
    let cap = if operation == "register_grant" {
        384 * 1024
    } else {
        MAX_ADMIN_BODY
    };
    let body = match read_bounded_body(&mut req, cap).await? {
        BoundedBody::Ok(body) => body,
        BoundedBody::TooLarge => return reply(413, "{\"code\":\"resource_exhausted\"}"),
    };
    let identity = match (
        env.var("AUTH_AUDIENCE"),
        env.var("AUTH_REPOSITORY"),
        env.var("MANAGED_OWNER_PUBLIC_KEY"),
    ) {
        (Ok(a), Ok(r), Ok(o)) => Identity::parse(&a.to_string(), &r.to_string(), &o.to_string()),
        _ => Err("missing managed configuration"),
    };
    let identity = match identity {
        Ok(i) => i,
        Err(_) => return reply(503, "{\"code\":\"unavailable\"}"),
    };
    let verified = verify_envelope(
        AuthContext {
            audience: &identity.audience,
            repository: &identity.repository,
        },
        &path,
        &blake3_hex(&body),
        Date::now().as_millis() as i64,
        &headers(&req)?,
    );
    let authorization = match verified {
        VerifyEnvelope::Ok { authorization, .. } if authorization.public_key == identity.owner => {
            authorization
        }
        _ => return reply(401, "{\"code\":\"unauthenticated\"}"),
    };
    let body = match String::from_utf8(body) {
        Ok(v) => v,
        Err(_) => return reply(400, "{\"code\":\"invalid_argument\"}"),
    };
    let wire = AdminWire {
        identity,
        proof: Proof::from(&authorization),
        operation: operation.into(),
        body,
    };
    let payload =
        serde_json::to_string(&wire).map_err(|e| worker::Error::RustError(e.to_string()))?;
    let ns = match env.durable_object("REFSTORE") {
        Ok(v) => v,
        Err(_) => return reply(503, "{\"code\":\"unavailable\"}"),
    };
    let stub = match ns.id_from_name("root").and_then(|id| id.get_stub()) {
        Ok(v) => v,
        Err(_) => return reply(503, "{\"code\":\"unavailable\"}"),
    };
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_body(Some(payload.into()));
    let internal_path = if operation.ends_with("_snapshot")
        || operation == "get_snapshot_job"
        || operation == "cleanup_snapshots"
    {
        "/managed-snapshot"
    } else if operation.ends_with("_grant") {
        "/managed-grant"
    } else {
        "/managed-policy"
    };
    let internal = Request::new_with_init(&format!("https://refstore{internal_path}"), &init)?;
    let mut response = match stub.fetch_with_request(internal).await {
        Ok(v) => v,
        Err(_) => return reply(503, "{\"code\":\"unavailable\"}"),
    };
    let status = response.status_code();
    let body = response.text().await?;
    reply(status, &body)
}

async fn serve_disclosure(mut req: Request, env: Env, path: &str) -> Result<Response> {
    if req.method() != Method::Post {
        return reply(405, "{\"code\":\"method_not_allowed\"}");
    }
    if req.headers().get("content-encoding")?.is_some()
        || req.headers().get("content-type")?.as_deref() != Some("application/json")
    {
        return reply(415, "{\"code\":\"unsupported_media_type\"}");
    }
    let body = match read_bounded_body(&mut req, 256 * 1024).await? {
        BoundedBody::Ok(body) => body,
        BoundedBody::TooLarge => return reply(413, "{\"code\":\"resource_exhausted\"}"),
    };
    let identity = match configured_identity(&env) {
        Ok(identity) => identity,
        Err(_) => return reply(503, "{\"code\":\"unavailable\"}"),
    };
    let verified = verify_envelope(
        AuthContext {
            audience: &identity.audience,
            repository: &identity.repository,
        },
        path,
        &blake3_hex(&body),
        Date::now().as_millis() as i64,
        &headers(&req)?,
    );
    let authorization = match verified {
        VerifyEnvelope::Ok { authorization, .. } => authorization,
        VerifyEnvelope::Err { .. } => return reply(401, "{\"code\":\"unauthenticated\"}"),
    };
    let body = match String::from_utf8(body) {
        Ok(body) => body,
        Err(_) => return reply(400, "{\"code\":\"invalid_argument\"}"),
    };
    let payload = serde_json::to_string(&super::snapshot_disclosure::DisclosureWire {
        identity,
        proof: Proof::from(&authorization),
        body,
    })
    .map_err(|e| worker::Error::RustError(e.to_string()))?;
    let ns = env.durable_object("REFSTORE")?;
    let stub = ns.id_from_name("root")?.get_stub()?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_body(Some(payload.into()));
    let internal = Request::new_with_init("https://refstore/managed-disclosure", &init)?;
    stub.fetch_with_request(internal).await
}

async fn serve_data(mut req: Request, env: Env, path: &str, route: DataRoute) -> Result<Response> {
    if req.method() != Method::Post {
        return reply(405, "{\"code\":\"method_not_allowed\"}");
    }
    for key in [
        "content-encoding",
        "connect-content-encoding",
        "grpc-encoding",
    ] {
        if req
            .headers()
            .get(key)?
            .as_deref()
            .is_some_and(|value| value != "identity")
        {
            return reply(415, "{\"code\":\"unsupported_media_type\"}");
        }
    }
    let transfer = matches!(route, DataRoute::UploadPack | DataRoute::DownloadPack);
    let _permit = if transfer {
        match TransferPermit::acquire() {
            Some(permit) => Some(permit),
            None => return reply(429, "{\"code\":\"resource_exhausted\"}"),
        }
    } else {
        None
    };
    if route == DataRoute::UploadPack {
        let identity = configured_identity(&env)?;
        let verified = verify_stream_envelope(
            AuthContext {
                audience: &identity.audience,
                repository: &identity.repository,
            },
            path,
            Date::now().as_millis() as i64,
            &headers(&req)?,
        );
        let authorization = match verified {
            VerifyEnvelope::Ok { authorization, .. } => authorization,
            VerifyEnvelope::Err { .. } => return reply(401, "{\"code\":\"unauthenticated\"}"),
        };
        let mut parts = authorization.commitment.split(':');
        let kind = parts.next();
        let pack_id = parts.next();
        let size_text = parts.next();
        if kind != Some("pack")
            || !pack_id.is_some_and(|id| mkit_core::write_auth::is_hex(id, 32))
            || parts.next().is_some()
        {
            return reply(400, "{\"code\":\"invalid_argument\"}");
        }
        let Some(size_text) = size_text else {
            return reply(400, "{\"code\":\"invalid_argument\"}");
        };
        if size_text.is_empty()
            || (size_text.len() > 1 && size_text.starts_with('0'))
            || !size_text.bytes().all(|byte| byte.is_ascii_digit())
        {
            return reply(400, "{\"code\":\"invalid_argument\"}");
        }
        let size = match size_text.parse::<usize>() {
            Ok(size) => size,
            Err(_) => return reply(413, "{\"code\":\"resource_exhausted\"}"),
        };
        if size > MAX_PACK_BYTES {
            return reply(413, "{\"code\":\"resource_exhausted\"}");
        }
        let allowed = check_access(&env, Proof::from(&authorization), path).await?;
        if !allowed {
            return reply(403, "{\"code\":\"permission_denied\"}");
        }
    }
    let body = match read_bounded_body(
        &mut req,
        if transfer {
            MAX_TRANSFER_BODY
        } else {
            MAX_ADMIN_BODY
        },
    )
    .await?
    {
        BoundedBody::Ok(body) => body,
        BoundedBody::TooLarge => return reply(413, "{\"code\":\"resource_exhausted\"}"),
    };
    let http_req = http_request_from_worker(&req, body.into(), |key| !is_deadline_header(key))?;
    let interceptor = AuthInterceptor::new(env.clone());
    let verified = interceptor.verified();
    let small = Limits::default()
        .with_max_request_body_size(MAX_ADMIN_BODY)
        .with_max_message_size(MAX_ADMIN_BODY);
    let large = Limits::default()
        .with_max_request_body_size(MAX_TRANSFER_BODY)
        .with_max_message_size(MAX_TRANSFER_BODY);
    let mut router: Router = Arc::new(TransportServer::new(env.clone())).register(Router::new());
    for method in [
        "ListRefs",
        "ReadRef",
        "PackExists",
        "UpdateRef",
        "AdvanceRefs",
    ] {
        router = router.with_route_limits(
            &format!("/mkit.transport.v1.TransportService/{method}"),
            small,
        );
    }
    for method in ["UploadPack", "DownloadPack"] {
        router = router.with_route_limits(
            &format!("/mkit.transport.v1.TransportService/{method}"),
            large,
        );
    }
    let svc = ConnectRpcService::new(router).with_interceptor(interceptor);
    let http_resp = dispatch_oneshot(svc, http_req).await;
    let status = http_resp.status().as_u16();
    let headers = http_resp.headers().clone();
    let mut out = respond_buffered(status, http_resp.into_body()).await?;
    if !route.may_write() {
        let state = verified
            .lock()
            .map_err(|_| worker::Error::RustError("managed authorization unavailable".into()))?
            .clone();
        if let VerifiedState::Verified(proof) = state {
            if !check_access(&env, proof, path).await? {
                return reply(403, "{\"code\":\"permission_denied\"}");
            }
        } else if matches!(state, VerifiedState::Unseen)
            && status < 400
            && route != DataRoute::DownloadPack
        {
            return reply(503, "{\"code\":\"unavailable\"}");
        }
    }
    copy_response_headers(&headers, &mut out);
    out.headers_mut()
        .set("Cache-Control", "private, no-store")?;
    Ok(with_cors(out))
}

fn configured_identity(env: &Env) -> Result<Identity> {
    let audience = env.var("AUTH_AUDIENCE")?.to_string();
    let repository = env.var("AUTH_REPOSITORY")?.to_string();
    let owner = env.var("MANAGED_OWNER_PUBLIC_KEY")?.to_string();
    Identity::parse(&audience, &repository, &owner)
        .map_err(|_| worker::Error::RustError("invalid managed configuration".into()))
}

async fn check_access(env: &Env, proof: Proof, procedure: &str) -> Result<bool> {
    let response: super::wire::AccessResp = super::service::do_call(
        env,
        "/authorize",
        &super::wire::AccessReq {
            proof,
            procedure: procedure.to_owned(),
        },
    )
    .await
    .map_err(|_| worker::Error::RustError("managed authority unavailable".into()))?;
    Ok(response.allowed)
}
