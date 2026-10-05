// SPDX-License-Identifier: MIT OR Apache-2.0
use futures_util::StreamExt;
use mkit_server::indexed::budget::SliceBudget;
use mkit_server::pipeline::{
    OBJECT_READER_BATCH, ReadLimits, ReaderSession, ReaderView, RequestMeta,
};
use mkit_server::url_token::UrlTarget;
use mkit_server::{Code, Procedure, ServerError};
use mkit_server_worker::adapter::{self, WorkerConfig};
use worker::{Context, Env, Method, Request, RequestInit, Response, Result, event};

use crate::hooks::{config, hooks, sink};
mkit_server_worker::durable_objects!(config, sink);

// Host-owned route. This preview returns canonical lengths, optional metadata
// lengths and tokens; an application can feed the bytes into MemorySource.
async fn read(mut req: Request, env: &Env, cfg: &WorkerConfig, owner: bool) -> Result<Response> {
    if req.method() != Method::Post {
        return Response::error("method not allowed", 405);
    }
    let url = req.url()?;
    if url.query().is_some_and(|q| q.len() > 2048) {
        return Response::error("query too large", 400);
    }
    let mut ids = Vec::new();
    let mut metadata = false;
    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "id" if ids.len() < OBJECT_READER_BATCH => {
                let Ok(id) = hex::decode(value.as_ref()).and_then(|bytes| {
                    bytes
                        .try_into()
                        .map_err(|_| hex::FromHexError::InvalidStringLength)
                }) else {
                    return Response::error("invalid object id", 400);
                };
                ids.push(id);
            }
            "metadata" if value == "true" => metadata = true,
            _ => return Response::error("invalid read query or too many ids", 400),
        }
    }
    // The exact body is committed by the owner's ListRefs envelope. Bound it
    // while streaming, independently of an untrusted Content-Length header.
    let mut body = Vec::new();
    let mut stream = req.stream()?;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if body.len() + chunk.len() > 4096 {
            return Response::error("body too large", 413);
        }
        body.extend(chunk);
    }
    let header = |name: &str| req.headers().get(name).ok().flatten();
    let meta = RequestMeta {
        procedure: Procedure::ListRefs,
        header: &header,
        header_values: None,
        unary_body: Some(&body),
        transport_principal: None,
    };
    // Reserve space for host work. The same physical ledger covers pipeline
    // construction, both reads and URL issuance; it is not platform billing.
    let budget = SliceBudget::new(8_000);
    let mut session = ReaderSession::new(ReadLimits::new(4_000, 8 << 20, 16 << 20, 2 << 20));
    let result = async {
        let target = cfg
            .addressing
            .resolve(header("x-repository").as_deref(), owner)?;
        let pipeline = adapter::embedding_pipeline(
            env,
            cfg,
            hooks(env, cfg).map_err(|_| ServerError::unavailable("host hooks unavailable"))?,
            &budget,
        )
        .map_err(|_| ServerError::unavailable("host pipeline unavailable"))?;
        let view = if owner {
            ReaderView::Owner(&meta)
        } else {
            ReaderView::Public
        };
        let reader = pipeline.object_reader(target.repo, view).await?;
        let bytes = reader.read_canonical_in(&mut session, &ids).await?;
        // Only ask for metadata when the host needs logical file lengths.
        let lengths = if metadata {
            Some(
                reader
                    .object_metadata_in(&mut session, &ids)
                    .await?
                    .iter()
                    .map(|m| m.map(|m| m.logical_len))
                    .collect::<Vec<_>>(),
            )
        } else {
            None
        };
        let targets: Vec<_> = ids.iter().copied().map(UrlTarget::Object).collect();
        // URL issuance always uses published reachability, including for owners.
        // It has its own per-call caps and shares the outer physical allowance.
        let tokens = reader
            .issue_urls(&targets, 60)
            .await?
            .into_iter()
            .map(|t| t.map(|t| t.expose().to_owned()))
            .collect::<Vec<_>>();
        Ok::<_, ServerError>(serde_json::json!({
            "canonical_lengths": bytes.iter().map(|b| b.as_ref().map(Vec::len)).collect::<Vec<_>>(),
            "logical_lengths": lengths, "tokens": tokens,
        }))
    }
    .await;
    // Report failed calls too: they retain their session charges.
    let used = session.used();
    worker::console_log!(
        "REFERENCE reader owner={} calls={} decoded={} encoded={} output={} physical={}",
        owner,
        used.storage_calls,
        used.decoded_bytes,
        used.encoded_bytes,
        used.output_bytes,
        budget.used()
    );
    match result {
        Ok(value) => {
            let mut response = Response::from_json(&value)?;
            response.headers_mut().set("Cache-Control", "no-store")?;
            Ok(response)
        }
        Err(error) => Response::error(
            "read refused",
            match error.code() {
                Code::Unauthenticated => 401,
                Code::PermissionDenied => 403,
                Code::InvalidArgument => 400,
                Code::ResourceExhausted => 429,
                _ => 503,
            },
        ),
    }
}

#[event(fetch)]
async fn fetch(req: Request, env: Env, ctx: Context) -> Result<Response> {
    let mut cfg = config(&env).map_err(|err| worker::Error::RustError(err.to_string()))?;
    cfg.http_mount = cfg.http_mount.take().map(|mount| mount.with_context(ctx));
    let path = req.path();
    if path == "/_embedding/read/public" || path == "/_embedding/read/owner" {
        return read(req, &env, &cfg, path.ends_with("/owner")).await;
    }
    // The host reserves one RPC prefix and explicitly passes HTTP object/key
    // mounts. All other host routes, including the receiver, are absent.
    let target = if let Some(procedure) = path.strip_prefix("/_embedding/mkit/") {
        format!("/{procedure}")
    } else if path.contains("/-/") || path == "/.well-known/mkit-url-token-keys.json" {
        path
    } else {
        return Response::error("host route not found", 404);
    };
    let mut init = RequestInit::new();
    init.with_method(req.method())
        .with_headers(req.headers().clone())
        // Transfer the ReadableStream; never buffer UploadPart in the host.
        .with_body(req.inner().body().map(Into::into));
    let query = req
        .url()?
        .query()
        .map_or_else(String::new, |q| format!("?{q}"));
    let request =
        Request::new_with_init(&format!("https://embedded.invalid{target}{query}"), &init)?;
    // Safe Connect dispatch ignores client deadline headers on wasm.
    adapter::serve_with(request, env, &cfg, hooks).await
}
