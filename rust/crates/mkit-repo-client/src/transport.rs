//! `ClientTransport` backed by the browser Fetch API via `web-sys`.
//!
//! Two transports live here:
//!
//!   * [`FetchTransport`] — a thin port of the upstream connect-rust
//!     `examples/wasm-client` transport. Used for read (unary, no-auth) calls.
//!
//!   * [`SigningFetchTransport`] — wraps the same fetch path but, *before*
//!     sending, computes `BLAKE3(rawRequestBody)` over the exact serialized
//!     Connect/proto bytes and hands that digest to a JS sign-callback. The
//!     callback returns the signed-write envelope headers, which are attached to
//!     the outgoing request. This is the only place that can honour the server's
//!     contract — the server hashes the *serialized protobuf request body*, and
//!     only the transport sees those bytes (JS never serializes protobuf).
//!
//! The signing dance is what keeps the integration honest: JS owns the Ed25519
//! seed (and signing), the wasm client owns serialization, and the digest that
//! ties them together is computed once over the canonical bytes.

use bytes::Bytes;
use connectrpc::client::{ClientBody, ClientTransport};
use futures::future::BoxFuture;
use http::{Request, Response};
use http_body_util::BodyExt;
use send_wrapper::SendWrapper;
use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

/// JS-side signer. Given the lowercase-hex BLAKE3 digest of the raw request
/// body, it returns the signed-write envelope as a JS object with fields
/// `publicKeyHex`, `signatureHex`, `createdAt`, `idempotencyKey` (and an
/// optional `digestHex`, which — if present — MUST equal the supplied digest).
///
/// May be async: the callback's return value is awaited if it is a `Promise`.
pub type SignFn = js_sys::Function;

/// Header names for the signed-write envelope. Kept here as the single source of
/// truth; mirrored in README.md and `apps/repo-worker/src/lib/envelope.ts`.
pub mod header {
    pub const PUBLIC_KEY: &str = "X-Public-Key";
    pub const SIGNATURE: &str = "X-Signature";
    /// Client-claimed BLAKE3 hex of the raw request body. The server recomputes
    /// `BLAKE3(rawBody)` and rejects on mismatch (`400 body digest mismatch`).
    pub const DIGEST: &str = "X-Digest";
    pub const CREATED_AT: &str = "X-Created-At";
    pub const IDEMPOTENCY_KEY: &str = "Idempotency-Key";
}

/// Read-only fetch transport (no auth). Used for `GetObject` / `GetRef` /
/// `ListRefs`.
#[derive(Clone, Copy)]
pub struct FetchTransport;

/// Fetch transport that signs each request via a JS callback before sending.
/// Used for the write calls (`PutObject` / `UpdateRef`).
#[derive(Clone)]
pub struct SigningFetchTransport {
    sign: SignFn,
}

impl SigningFetchTransport {
    pub fn new(sign: SignFn) -> Self {
        Self { sign }
    }
}

/// Transport error preserving the original error source.
///
/// `JsValue` doesn't implement `Display`/`Error`, so the `Js` variant eagerly
/// converts to a string.
#[derive(Debug)]
pub enum FetchError {
    Js(String),
    Connect(Box<connectrpc::ConnectError>),
    Http(http::Error),
    HeaderToStr(http::header::ToStrError),
    InvalidStatusCode(http::status::InvalidStatusCode),
    Sign(String),
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Js(s) => f.write_str(s),
            Self::Connect(e) => write!(f, "{e}"),
            Self::Http(e) => write!(f, "{e}"),
            Self::HeaderToStr(e) => write!(f, "{e}"),
            Self::InvalidStatusCode(e) => write!(f, "{e}"),
            Self::Sign(s) => write!(f, "sign callback failed: {s}"),
        }
    }
}

impl std::error::Error for FetchError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Connect(e) => Some(e),
            Self::Http(e) => Some(e),
            Self::HeaderToStr(e) => Some(e),
            Self::InvalidStatusCode(e) => Some(e),
            Self::Js(_) | Self::Sign(_) => None,
        }
    }
}

impl From<wasm_bindgen::JsValue> for FetchError {
    fn from(val: wasm_bindgen::JsValue) -> Self {
        Self::Js(val.as_string().unwrap_or_else(|| format!("{val:?}")))
    }
}
impl From<connectrpc::ConnectError> for FetchError {
    fn from(e: connectrpc::ConnectError) -> Self {
        Self::Connect(Box::new(e))
    }
}
impl From<http::Error> for FetchError {
    fn from(e: http::Error) -> Self {
        Self::Http(e)
    }
}
impl From<http::header::ToStrError> for FetchError {
    fn from(e: http::header::ToStrError) -> Self {
        Self::HeaderToStr(e)
    }
}
impl From<http::status::InvalidStatusCode> for FetchError {
    fn from(e: http::status::InvalidStatusCode) -> Self {
        Self::InvalidStatusCode(e)
    }
}

impl ClientTransport for FetchTransport {
    type ResponseBody = http_body_util::Full<Bytes>;
    type Error = FetchError;

    fn send(
        &self,
        request: Request<ClientBody>,
    ) -> BoxFuture<'static, Result<Response<Self::ResponseBody>, Self::Error>> {
        // SendWrapper bridges the Send bound on BoxFuture with web-sys's !Send
        // JS types. Sound on wasm32 because it is single-threaded.
        Box::pin(SendWrapper::new(fetch(request, None)))
    }
}

impl ClientTransport for SigningFetchTransport {
    type ResponseBody = http_body_util::Full<Bytes>;
    type Error = FetchError;

    fn send(
        &self,
        request: Request<ClientBody>,
    ) -> BoxFuture<'static, Result<Response<Self::ResponseBody>, Self::Error>> {
        let sign = self.sign.clone();
        Box::pin(SendWrapper::new(fetch(request, Some(sign))))
    }
}

/// The envelope headers returned by the JS sign-callback.
struct Envelope {
    public_key: String,
    signature: String,
    digest: String,
    audience: String,
    repository: String,
    commitment: String,
    expires_at: String,
    created_at: String,
    idempotency_key: String,
}

/// Call the JS sign-callback with the body digest, awaiting it if it returns a
/// Promise, and read the envelope fields off the returned object.
async fn run_sign(sign: &SignFn, body_digest_hex: &str) -> Result<Envelope, FetchError> {
    let ret = sign
        .call1(&JsValue::NULL, &JsValue::from_str(body_digest_hex))
        .map_err(|e| FetchError::Sign(js_err(&e)))?;

    // Support both sync (object) and async (Promise) signers.
    let obj: JsValue = if ret.is_instance_of::<js_sys::Promise>() {
        JsFuture::from(js_sys::Promise::from(ret))
            .await
            .map_err(|e| FetchError::Sign(js_err(&e)))?
    } else {
        ret
    };

    let get = |k: &str| -> Result<String, FetchError> {
        js_sys::Reflect::get(&obj, &JsValue::from_str(k))
            .ok()
            .and_then(|v| v.as_string())
            .ok_or_else(|| FetchError::Sign(format!("envelope missing string field `{k}`")))
    };

    // If the signer echoes a digest, it must match what we hashed.
    let echoed = js_sys::Reflect::get(&obj, &JsValue::from_str("digestHex"))
        .ok()
        .and_then(|v| v.as_string());
    if echoed.is_some_and(|c| c != body_digest_hex) {
        return Err(FetchError::Sign(format!(
            "signer digest != body digest {body_digest_hex}"
        )));
    }

    Ok(Envelope {
        public_key: get("publicKeyHex")?,
        signature: get("signatureHex")?,
        digest: body_digest_hex.to_string(),
        audience: get("audience")?,
        repository: get("repository")?,
        commitment: get("commitment")?,
        expires_at: get("expiresAt")?,
        created_at: get("createdAt")?,
        idempotency_key: get("idempotencyKey")?,
    })
}

fn js_err(e: &JsValue) -> String {
    e.as_string().unwrap_or_else(|| format!("{e:?}"))
}

/// BLAKE3 (lowercase hex) of the raw request body — the exact bytes the server
/// hashes for the write envelope.
fn blake3_hex(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

async fn fetch(
    request: Request<ClientBody>,
    sign: Option<SignFn>,
) -> Result<Response<http_body_util::Full<Bytes>>, FetchError> {
    let (parts, body) = request.into_parts();
    let body_bytes = body.collect().await?.to_bytes();

    let headers = web_sys::Headers::new()?;
    for (name, value) in &parts.headers {
        headers.append(name.as_str(), value.to_str()?)?;
    }

    // Sign over the EXACT serialized request body bytes the transport sends.
    if let Some(sign) = sign {
        let digest = blake3_hex(body_bytes.as_ref());
        let env = run_sign(&sign, &digest).await?;
        headers.append(header::PUBLIC_KEY, &env.public_key)?;
        headers.append(header::SIGNATURE, &env.signature)?;
        headers.append(header::DIGEST, &env.digest)?;
        headers.append("X-Envelope-Version", "2")?;
        headers.append("X-Audience", &env.audience)?;
        headers.append("X-Repository", &env.repository)?;
        headers.append("X-Content-Commitment", &env.commitment)?;
        headers.append("X-Expires-At", &env.expires_at)?;
        headers.append(header::CREATED_AT, &env.created_at)?;
        if !env.idempotency_key.is_empty() {
            headers.append(header::IDEMPOTENCY_KEY, &env.idempotency_key)?;
        }
    }

    let init = web_sys::RequestInit::new();
    init.set_method(parts.method.as_str());
    init.set_headers(&headers);
    init.set_body(&js_sys::Uint8Array::from(body_bytes.as_ref()));

    let js_req = web_sys::Request::new_with_str_and_init(&parts.uri.to_string(), &init)?;

    let global = js_sys::global();
    let fetch_fn: js_sys::Function = js_sys::Reflect::get(&global, &"fetch".into())?.dyn_into()?;
    let js_resp: web_sys::Response = JsFuture::from(
        fetch_fn
            .call1(&wasm_bindgen::JsValue::undefined(), &js_req)?
            .dyn_into::<js_sys::Promise>()?,
    )
    .await?
    .dyn_into()?;

    let status = http::StatusCode::from_u16(js_resp.status())?;
    let mut builder = Response::builder().status(status);
    if let Some(iter) = js_sys::try_iter(&js_resp.headers())? {
        for entry in iter {
            let pair: js_sys::Array = entry?.into();
            let (Some(key), Some(val)) = (pair.get(0).as_string(), pair.get(1).as_string()) else {
                continue;
            };
            builder = builder.header(key, val);
        }
    }

    let body_buf = JsFuture::from(js_resp.array_buffer()?).await?;
    let body_bytes = Bytes::from(js_sys::Uint8Array::new(&body_buf).to_vec());
    // A Cloudflare Workers quirk: the browser can hand us a STILL-gzipped body
    // while stripping the `content-encoding` header, so ConnectRPC (seeing no
    // encoding) would decode raw gzip → "invalid wire type". Re-assert the
    // encoding from the gzip magic so ConnectRPC's own gzip decompressor runs; a
    // plain/already-decompressed body has no magic and passes through untouched.
    if is_gzip(&body_bytes) {
        builder = builder.header(http::header::CONTENT_ENCODING, "gzip");
    }
    Ok(builder.body(http_body_util::Full::new(body_bytes))?)
}

/// True if `bytes` begins with the gzip magic number (`0x1f 0x8b`).
fn is_gzip(bytes: &[u8]) -> bool {
    bytes.len() >= 2 && bytes[0] == 0x1f && bytes[1] == 0x8b
}

#[cfg(test)]
mod tests {
    #[test]
    fn detects_gzip_magic() {
        assert!(super::is_gzip(&[0x1f, 0x8b, 0x08, 0x00]));
        assert!(!super::is_gzip(b"\x0a\x05proto")); // plain protobuf
        assert!(!super::is_gzip(&[0x1f])); // too short
        assert!(!super::is_gzip(&[]));
    }
}
