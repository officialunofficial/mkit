// keys.mkit.sh — a KV-backed registry mapping an Ed25519 pubkey to a chosen
// display handle (e.g. "slate-badger"). Reads are open; writes are signed with
// the SAME envelope the web app builds for repo writes, and may only set the
// name for the pubkey that signed (owner-only). Non-unique handles: the pubkey
// is the real id, the name is a label.
//
//   GET  /name/<pubkey>   -> { pubkey, name, updated_at }  (404 if unset)
//   PUT  /name/<pubkey>   -> signed write, sets/renames the handle
//   POST /resolve         -> { pubkeys: [...] } -> { names: { <pubkey>: name } }
//   GET  /  | /health     -> liveness

use worker::*;

mod audit;
mod envelope;
mod names;

use audit::{audit_for, WriteAudit};
use envelope::{blake3_hex, verify_envelope, EnvelopeHeaders, VerifyEnvelope};
use names::{is_pubkey_hex, normalize_name, NameRecord, ResolveBody, SetNameBody};

/// KV namespace binding (declared in wrangler.jsonc).
const KV_BINDING: &str = "NAMES";

/// Analytics Engine binding (declared in wrangler.jsonc) for accepted/
/// rejected-write telemetry on `PUT /name/<pubkey>`. Mirrors repo-worker's
/// `WRITE_EVENTS` binding name so the two datasets share vocabulary.
const WRITE_EVENTS_BINDING: &str = "WRITE_EVENTS";

/// Envelope `procedure` field for a name write — the web client signs the same
/// constant, so changing it here is a breaking protocol change.
const SET_NAME_PROCEDURE: &str = "/mkit.keys.v1.Keys/SetName";

const CORS_ALLOW_HEADERS: &str =
    "x-public-key, x-signature, x-digest, x-created-at, idempotency-key, content-type";
const CORS_ALLOW_METHODS: &str = "GET, PUT, POST, OPTIONS";

/// Cap on `/resolve` batch size (KV has no multi-get; we loop sequentially).
const MAX_RESOLVE: usize = 256;

/// Reject any request body larger than this. Both write bodies (`set_name`'s
/// JSON name payload, `resolve`'s pubkey list) are tiny; buffering more than
/// this is refused with `invalid_argument` before `req.bytes()` materializes
/// the whole payload in the isolate. Mirrors apps/repo-worker's
/// `worker_impl::MAX_BODY_BYTES` pattern.
const MAX_BODY_BYTES: usize = 64 * 1024; // 64 KiB

#[event(fetch)]
async fn fetch(mut req: Request, env: Env, _ctx: Context) -> Result<Response> {
    // Answer the CORS preflight before routing so the browser can send the
    // signed-write headers (X-Public-Key, …) cross-origin.
    if req.method() == Method::Options {
        return preflight();
    }

    let method = req.method();
    let path = req.path();

    // Body cap, checked once in the shared entry point so both write routes
    // (`set_name`, `resolve`) get the pre-buffer rejection for free. Reject by
    // Content-Length BEFORE buffering (O(1)); the post-buffer check inside
    // `read_capped_body` is the backstop for chunked/unknown-length requests.
    if let Ok(Some(len)) = req.headers().get("content-length") {
        if len.parse::<usize>().is_ok_and(|n| n > MAX_BODY_BYTES) {
            return Ok(with_cors(body_too_large()?));
        }
    }

    let out = if method == Method::Get && (path == "/" || path == "/health") {
        Response::ok("mkit-keys-worker ok")
    } else if let Some(pubkey) = path.strip_prefix("/name/") {
        let pubkey = pubkey.to_ascii_lowercase();
        match method {
            Method::Get => get_name(&env, &pubkey).await,
            Method::Put => set_name(&mut req, &env, &pubkey).await,
            _ => Response::error("method not allowed", 405),
        }
    } else if method == Method::Post && path == "/resolve" {
        resolve(&mut req, &env).await
    } else {
        Response::error("not found", 404)
    };

    // Every response (success or error) carries the CORS origin header.
    let resp = out.unwrap_or_else(|e| {
        Response::error(format!("internal error: {e}"), 500).expect("error response")
    });
    Ok(with_cors(resp))
}

fn preflight() -> Result<Response> {
    let headers = Headers::new();
    headers.set("Access-Control-Allow-Origin", "*")?;
    headers.set("Access-Control-Allow-Headers", CORS_ALLOW_HEADERS)?;
    headers.set("Access-Control-Allow-Methods", CORS_ALLOW_METHODS)?;
    headers.set("Access-Control-Max-Age", "86400")?;
    Ok(Response::empty()?.with_status(204).with_headers(headers))
}

fn with_cors(mut resp: Response) -> Response {
    let _ = resp.headers_mut().set("Access-Control-Allow-Origin", "*");
    resp
}

fn json_response(body: String) -> Result<Response> {
    let mut resp = Response::ok(body)?;
    resp.headers_mut().set("Content-Type", "application/json")?;
    Ok(resp)
}

/// The `invalid_argument` 400 returned when a request body exceeds the cap.
/// Matches apps/repo-worker's `worker_impl::body_too_large` JSON shape so both
/// workers' HTTP surfaces are consistent.
fn body_too_large() -> Result<Response> {
    let payload = format!(
        "{{\"code\":\"invalid_argument\",\"message\":\"request body exceeds {MAX_BODY_BYTES} bytes\"}}"
    );
    let mut resp = Response::error(payload, 400)?;
    let _ = resp.headers_mut().set("Content-Type", "application/json");
    Ok(resp)
}

/// Read the request body, enforcing `MAX_BODY_BYTES` as a backstop for
/// chunked/unknown-length requests where Content-Length was absent (the
/// `fetch` entry point already rejected any declared Content-Length over the
/// cap before this runs).
async fn read_capped_body(req: &mut Request) -> Result<std::result::Result<Vec<u8>, Response>> {
    let body = req.bytes().await?;
    if body.len() > MAX_BODY_BYTES {
        return Ok(Err(body_too_large()?));
    }
    Ok(Ok(body))
}

/// Push one audit record to the `WRITE_EVENTS` Analytics Engine dataset. A
/// missing binding (e.g. local `wrangler dev` without it configured) or a
/// failed write is logged and swallowed — telemetry must never fail the
/// request it's describing.
fn log_write(env: &Env, audit: &WriteAudit) {
    let dataset = match env.analytics_engine(WRITE_EVENTS_BINDING) {
        Ok(d) => d,
        Err(e) => {
            console_error!("{WRITE_EVENTS_BINDING} analytics engine binding unavailable: {e}");
            return;
        }
    };
    // `indexes` takes exactly one value (Analytics Engine drops multi-index
    // points) — "accepted"/"rejected" — so the two outcomes are cheaply
    // filterable in a query without parsing blobs.
    let point = match audit {
        WriteAudit::Accepted {
            procedure,
            signer_pubkey,
            bytes,
        } => AnalyticsEngineDataPointBuilder::new()
            .indexes(["accepted"])
            .add_blob(procedure.as_str())
            .add_blob(signer_pubkey.as_str())
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
        console_error!("analytics engine write_data_point failed: {e}");
    }
}

fn read_envelope_headers(req: &Request) -> EnvelopeHeaders {
    let h = req.headers();
    EnvelopeHeaders {
        public_key: h.get("X-Public-Key").ok().flatten(),
        signature: h.get("X-Signature").ok().flatten(),
        digest: h.get("X-Digest").ok().flatten(),
        created_at: h.get("X-Created-At").ok().flatten(),
        idempotency_key: h.get("Idempotency-Key").ok().flatten(),
    }
}

/// GET /name/<pubkey> — return the stored record JSON, or 404.
async fn get_name(env: &Env, pubkey: &str) -> Result<Response> {
    if !is_pubkey_hex(pubkey) {
        return Response::error("invalid pubkey", 400);
    }
    let kv = env.kv(KV_BINDING)?;
    match kv.get(pubkey).text().await? {
        Some(json) => json_response(json),
        None => Response::error("not found", 404),
    }
}

/// PUT /name/<pubkey> — signed, owner-only set/rename of the handle.
async fn set_name(req: &mut Request, env: &Env, pubkey: &str) -> Result<Response> {
    if !is_pubkey_hex(pubkey) {
        return Response::error("invalid pubkey", 400);
    }

    let headers = read_envelope_headers(req);
    let body = match read_capped_body(req).await? {
        Ok(body) => body,
        Err(resp) => return Ok(resp),
    };
    let actual_digest = blake3_hex(&body);
    let now = Date::now().as_millis() as i64;

    // Log the accepted/rejected outcome BEFORE branching on it, so a
    // rejected write (bad signature, stale timestamp, …) is observable too —
    // see #695. `audit_for` is pure and unit-tested in `audit.rs`; only the
    // Analytics Engine write below is untested worker glue.
    let verify_result = verify_envelope(SET_NAME_PROCEDURE, &actual_digest, now, &headers);
    log_write(
        env,
        &audit_for(SET_NAME_PROCEDURE, body.len() as u64, &verify_result),
    );

    let signer = match verify_result {
        VerifyEnvelope::Ok { public_key } => public_key.to_ascii_lowercase(),
        VerifyEnvelope::Err { status, error } => return Response::error(error, status),
    };
    // Owner-only: the signer must be the very key it is naming.
    if signer != pubkey {
        return Response::error("signer is not the named key", 403);
    }

    let Ok(parsed) = serde_json::from_slice::<SetNameBody>(&body) else {
        return Response::error("invalid body", 400);
    };
    let Some(name) = normalize_name(&parsed.name) else {
        return Response::error("empty name", 400);
    };

    let record = NameRecord {
        pubkey: pubkey.to_string(),
        name,
        updated_at: now,
    };
    let json = serde_json::to_string(&record).map_err(|e| Error::RustError(e.to_string()))?;
    let kv = env.kv(KV_BINDING)?;
    kv.put(pubkey, &json)?.execute().await?;
    json_response(json)
}

/// POST /resolve — batch-read names for a list of pubkeys (for the commit log).
async fn resolve(req: &mut Request, env: &Env) -> Result<Response> {
    let body = match read_capped_body(req).await? {
        Ok(body) => body,
        Err(resp) => return Ok(resp),
    };
    let Ok(parsed) = serde_json::from_slice::<ResolveBody>(&body) else {
        return Response::error("invalid body", 400);
    };

    let kv = env.kv(KV_BINDING)?;
    let mut names = serde_json::Map::new();
    for pk in parsed.pubkeys.into_iter().take(MAX_RESOLVE) {
        let pk = pk.to_ascii_lowercase();
        if !is_pubkey_hex(&pk) {
            continue;
        }
        if let Some(json) = kv.get(&pk).text().await? {
            if let Ok(rec) = serde_json::from_str::<NameRecord>(&json) {
                names.insert(pk, serde_json::Value::String(rec.name));
            }
        }
    }
    Response::from_json(&serde_json::json!({ "names": names }))
}
