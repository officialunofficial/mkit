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

mod envelope;
mod names;

use envelope::{blake3_hex, verify_envelope, EnvelopeHeaders, VerifyEnvelope};
use names::{is_pubkey_hex, normalize_name, NameRecord, ResolveBody, SetNameBody};

/// KV namespace binding (declared in wrangler.jsonc).
const KV_BINDING: &str = "NAMES";

/// Envelope `procedure` field for a name write — the web client signs the same
/// constant, so changing it here is a breaking protocol change.
const SET_NAME_PROCEDURE: &str = "/mkit.keys.v1.Keys/SetName";

const CORS_ALLOW_HEADERS: &str =
    "x-public-key, x-signature, x-digest, x-created-at, idempotency-key, content-type";
const CORS_ALLOW_METHODS: &str = "GET, PUT, POST, OPTIONS";

/// Cap on `/resolve` batch size (KV has no multi-get; we loop sequentially).
const MAX_RESOLVE: usize = 256;

#[event(fetch)]
async fn fetch(mut req: Request, env: Env, _ctx: Context) -> Result<Response> {
    // Answer the CORS preflight before routing so the browser can send the
    // signed-write headers (X-Public-Key, …) cross-origin.
    if req.method() == Method::Options {
        return preflight();
    }

    let method = req.method();
    let path = req.path();

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
    let body = req.bytes().await?;
    let actual_digest = blake3_hex(&body);
    let now = Date::now().as_millis() as i64;

    let signer = match verify_envelope(SET_NAME_PROCEDURE, &actual_digest, now, &headers) {
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
    let body = req.bytes().await?;
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
