// SPDX-License-Identifier: MIT OR Apache-2.0
//! Closed managed fetch boundary and owner-only management transport.
use crate::access_policy::{Identity, MAX_ADMIN_BODY};
use crate::envelope::{Context as AuthContext, EnvelopeHeaders, VerifyEnvelope, verify_envelope};
use crate::hashing::blake3_hex;
use futures::StreamExt;
use mkit_worker_common::replay::Proof;
use serde::{Deserialize, Serialize};
use worker::{Date, Env, Method, Request, RequestInit, Response, Result};

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

async fn read_admin_body(req: &mut Request) -> Result<BoundedBody> {
    let length = req.headers().get("content-length")?;
    if length
        .as_deref()
        .and_then(|value| value.parse::<usize>().ok())
        .is_some_and(|value| value > MAX_ADMIN_BODY)
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
        if chunk.len() > MAX_ADMIN_BODY - body.len() {
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

fn headers(req: &Request) -> EnvelopeHeaders {
    let get = |key| req.headers().get(key).ok().flatten();
    EnvelopeHeaders {
        version: get("x-envelope-version"),
        audience: get("x-audience"),
        repository: get("x-repository"),
        commitment: get("x-content-commitment"),
        expires_at: get("x-expires-at"),
        public_key: get("x-public-key"),
        signature: get("x-signature"),
        digest: get("x-digest"),
        created_at: get("x-created-at"),
        idempotency_key: get("idempotency-key"),
    }
}

pub async fn dispatch(req: Request, env: Env) -> Result<Response> {
    match dispatch_inner(req, env).await {
        Ok(response) => Ok(response),
        Err(_) => reply(503, "{\"code\":\"unavailable\"}"),
    }
}

async fn dispatch_inner(mut req: Request, env: Env) -> Result<Response> {
    let path = req.path();
    let operation = match path.as_str() {
        "/mkit/host/v1/InitializePolicy" => "initialize",
        "/mkit/host/v1/GetPolicy" => "get",
        "/mkit/host/v1/ReplacePolicy" => "replace",
        _ => {
            #[cfg(feature = "test-faults")]
            if let Some(internal_path) = path.strip_prefix("/__test/refstore") {
                if [
                    "/get",
                    "/list",
                    "/update",
                    "/advance",
                    "/object",
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
    let body = match read_admin_body(&mut req).await? {
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
        &headers(&req),
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
    let internal = Request::new_with_init("https://refstore/managed-policy", &init)?;
    let mut response = match stub.fetch_with_request(internal).await {
        Ok(v) => v,
        Err(_) => return reply(503, "{\"code\":\"unavailable\"}"),
    };
    let status = response.status_code();
    let body = response.text().await.unwrap_or_default();
    reply(status, &body)
}
