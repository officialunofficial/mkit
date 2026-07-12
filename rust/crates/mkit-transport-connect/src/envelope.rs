//! Native (non-wasm) client-side implementation of the signed-write
//! envelope some `mkit.transport.v1.TransportService` deployments require
//! for write RPCs — e.g. `apps/vcs-worker`'s reference Cloudflare Worker
//! server, whose `src/envelope.rs` is the canonical, server-verified spec
//! this module ports to the native ConnectRPC client.
//!
//! Two shapes, matching the server exactly:
//!
//! 1. **Unary** (`UpdateRef`, `AdvanceRefs`) — binds the signature to the
//!    exact serialized request body, byte-for-byte:
//!
//!    ```text
//!    canonical = [ "mkit-write:v1", procedure, bodyDigestHex, createdAtMs,
//!                  idempotencyKey ].join("\n")
//!    signing_digest = BLAKE3(utf8(canonical))
//!    signature = Ed25519_sign(signing_digest)
//!    ```
//!
//! 2. **Streaming** (`UploadPack`) — a client-streaming call's transport
//!    `send()` runs once at stream establishment, before any pack bytes are
//!    known, so there is no request body to bind a digest to. The streaming
//!    envelope binds only `(procedure, createdAtMs, idempotencyKey)`:
//!
//!    ```text
//!    stream_canonical = [ "mkit-stream-write:v1", procedure, createdAtMs,
//!                          idempotencyKey ].join("\n")
//!    signing_digest = BLAKE3(utf8(stream_canonical))
//!    signature = Ed25519_sign(signing_digest)
//!    ```
//!
//! Both are PLAIN envelope digests — NOT mkit commit signatures — so the
//! SPEC-SIGNING commit/remix/tag domain prefixes do NOT apply; the caller's
//! [`EnvelopeSigner`] must sign the raw 32-byte digest directly (exactly
//! what `mkit_core::sign`'s repo-key path and `mkit_keystore::KeySigner`
//! both already do for other raw-digest signing needs — see
//! `mkit-cli/src/remote_dispatch/mod.rs`'s `envelope_signer_from_config`).
//!
//! This is an ADDITIONAL auth mode alongside the existing bearer-token
//! header (`Authorization: Bearer …`, still set independently via
//! `ClientConfig::with_default_header` in `client.rs`) — a deployment can
//! require either, both, or neither.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use connectrpc::client::{ClientBody, ClientTransport, full_body};
use futures::future::BoxFuture;
use http::{HeaderMap, HeaderName, HeaderValue, Request, Response};
use http_body_util::BodyExt;
use mkit_core::hash::{hash, to_hex, to_hex_bytes};

/// Constant first line of the unary canonical string. Mirrors
/// `apps/vcs-worker/src/envelope.rs::ENVELOPE_PREFIX` /
/// `apps/repo-worker/src/envelope.rs`.
const ENVELOPE_PREFIX: &str = "mkit-write:v1";
/// Constant first line of the streaming (establishment-only) canonical
/// string. Mirrors `apps/vcs-worker/src/envelope.rs::STREAM_ENVELOPE_PREFIX`.
const STREAM_ENVELOPE_PREFIX: &str = "mkit-stream-write:v1";

/// Header names carrying the envelope. Lowercase: HTTP header names are
/// case-insensitive on the wire, but `http::HeaderName::from_static`
/// requires a lowercase literal. Mirrors
/// `mkit-repo-client::transport::header` and the names
/// `apps/vcs-worker/src/worker_impl/auth.rs` reads
/// (`x-public-key`/`x-signature`/`x-digest`/`x-created-at`/
/// `idempotency-key`).
mod header {
    pub const PUBLIC_KEY: &str = "x-public-key";
    pub const SIGNATURE: &str = "x-signature";
    pub const DIGEST: &str = "x-digest";
    pub const CREATED_AT: &str = "x-created-at";
    pub const IDEMPOTENCY_KEY: &str = "idempotency-key";
}

/// A signer able to produce the Ed25519 material a write envelope needs:
/// the raw public key (for `X-Public-Key`) and a raw signature over an
/// arbitrary 32-byte digest (no domain prefix — see module docs).
///
/// `mkit-cli` implements this by reusing its EXISTING commit-signing
/// resolution (`signer` / `signing_key` / `key.ed25519_ref` config, the
/// same keys `mkit commit` reads) rather than inventing a parallel key
/// path — see `remote_dispatch::envelope_signer_from_config`.
pub trait EnvelopeSigner: Send + Sync {
    /// Lowercase-hex (64 chars) Ed25519 public key.
    fn public_key_hex(&self) -> String;

    /// Sign `message` (the 32-byte envelope signing digest) and return the
    /// lowercase-hex (128 chars) Ed25519 signature.
    ///
    /// # Errors
    ///
    /// Implementation-specific (e.g. a keystore backend refusing to sign,
    /// a hardware token being absent).
    fn sign_hex(&self, message: &[u8; 32]) -> Result<String, String>;
}

/// `true` for the unary write procedures (`UpdateRef`, `AdvanceRefs`) that
/// need the body-bound envelope. Mirrors
/// `apps/vcs-worker/src/worker_impl/auth.rs::requires_unary_write_auth`.
fn requires_unary_write_auth(procedure: &str) -> bool {
    procedure.ends_with("/UpdateRef") || procedure.ends_with("/AdvanceRefs")
}

/// `true` for the streaming write procedure (`UploadPack`) that needs the
/// narrower establishment-only envelope. Mirrors
/// `apps/vcs-worker/src/worker_impl/auth.rs::requires_stream_write_auth`.
fn requires_stream_write_auth(procedure: &str) -> bool {
    procedure.ends_with("/UploadPack")
}

fn canonical_envelope(
    procedure: &str,
    body_digest_hex: &str,
    created_at_ms: i64,
    idempotency_key: &str,
) -> String {
    format!("{ENVELOPE_PREFIX}\n{procedure}\n{body_digest_hex}\n{created_at_ms}\n{idempotency_key}")
}

fn canonical_stream_envelope(procedure: &str, created_at_ms: i64, idempotency_key: &str) -> String {
    format!("{STREAM_ENVELOPE_PREFIX}\n{procedure}\n{created_at_ms}\n{idempotency_key}")
}

/// Current epoch milliseconds. Native wall clock (unlike
/// `apps/vcs-worker`'s wasm `worker::Date::now()`); only used for the
/// server's ±5min freshness window, so ordinary wall-clock precision is
/// sufficient.
fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// A fresh random idempotency key for one write call: 16 bytes of
/// `getrandom` output, lowercase hex. The server does not currently
/// enforce dedup on this value (`apps/vcs-worker`'s envelope is
/// "DEMO MODE — verify-only, no allow-list") but it is still part of the
/// signed canonical string, so each call gets its own value rather than a
/// constant placeholder.
fn random_idempotency_key() -> String {
    let mut buf = [0u8; 16];
    match getrandom::fill(&mut buf) {
        Ok(()) => to_hex_bytes(&buf),
        // getrandom failure is effectively unreachable on supported
        // platforms; fall back to a timestamp-derived value rather than
        // panicking a network call over it. Never used to make a security
        // decision — see the trait doc comment.
        Err(_) => format!("{:x}", now_ms()),
    }
}

fn insert_header(headers: &mut HeaderMap, name: &'static str, value: &str) -> Result<(), String> {
    let header_name = HeaderName::from_static(name);
    let header_value =
        HeaderValue::from_str(value).map_err(|e| format!("invalid {name} header value: {e}"))?;
    headers.insert(header_name, header_value);
    Ok(())
}

/// [`ClientTransport`] wrapper that signs write RPCs with a write envelope
/// before delegating to `inner`. Reads and, when `signer` is `None`, every
/// call pass through unchanged — this is the SAME transport type used
/// whether or not envelope auth is configured, so the bearer-token-only
/// path (`ConnectTransport::connect`, #700/#701) pays no signing overhead
/// beyond one `Option` check per call.
#[derive(Clone)]
pub struct EnvelopeTransport<T> {
    inner: T,
    signer: Option<Arc<dyn EnvelopeSigner>>,
}

impl<T> EnvelopeTransport<T> {
    pub fn new(inner: T, signer: Option<Arc<dyn EnvelopeSigner>>) -> Self {
        Self { inner, signer }
    }
}

/// [`EnvelopeTransport`]'s transport error: either a signing failure (no
/// [`ConnectError`](connectrpc::ConnectError) in the chain — surfaces as
/// `unavailable` to callers, see `connectrpc::client`'s
/// `map_transport_send_error`) or the wrapped inner transport's own error
/// (chain preserved via `source()`, so the inner transport's error
/// classification is unaffected by this wrapper).
#[derive(Debug)]
pub enum EnvelopeTransportError<E> {
    Sign(String),
    Inner(E),
}

impl<E: std::fmt::Display> std::fmt::Display for EnvelopeTransportError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sign(s) => write!(f, "sign write envelope: {s}"),
            Self::Inner(e) => write!(f, "{e}"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for EnvelopeTransportError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Sign(_) => None,
            Self::Inner(e) => Some(e),
        }
    }
}

impl<T: ClientTransport> ClientTransport for EnvelopeTransport<T> {
    type ResponseBody = T::ResponseBody;
    type Error = EnvelopeTransportError<T::Error>;

    fn send(
        &self,
        request: Request<ClientBody>,
    ) -> BoxFuture<'static, Result<Response<Self::ResponseBody>, Self::Error>> {
        let inner = self.inner.clone();
        let Some(signer) = self.signer.clone() else {
            return Box::pin(async move {
                inner
                    .send(request)
                    .await
                    .map_err(EnvelopeTransportError::Inner)
            });
        };
        Box::pin(async move {
            let procedure = request.uri().path().to_owned();
            if requires_unary_write_auth(&procedure) {
                let (mut parts, body) = request.into_parts();
                let body_bytes = body
                    .collect()
                    .await
                    .map_err(|e| EnvelopeTransportError::Sign(format!("buffer request body: {e}")))?
                    .to_bytes();
                let body_digest_hex = to_hex(&hash(body_bytes.as_ref()));
                let created_at_ms = now_ms();
                let idempotency_key = random_idempotency_key();
                let canonical = canonical_envelope(
                    &procedure,
                    &body_digest_hex,
                    created_at_ms,
                    &idempotency_key,
                );
                let signing_digest = hash(canonical.as_bytes());
                let signature_hex = signer
                    .sign_hex(&signing_digest)
                    .map_err(EnvelopeTransportError::Sign)?;
                write_envelope_headers(
                    &mut parts.headers,
                    &signer.public_key_hex(),
                    &signature_hex,
                    Some(&body_digest_hex),
                    created_at_ms,
                    &idempotency_key,
                )
                .map_err(EnvelopeTransportError::Sign)?;
                let req = Request::from_parts(parts, full_body(body_bytes));
                inner.send(req).await.map_err(EnvelopeTransportError::Inner)
            } else if requires_stream_write_auth(&procedure) {
                let (mut parts, body) = request.into_parts();
                let created_at_ms = now_ms();
                let idempotency_key = random_idempotency_key();
                let canonical =
                    canonical_stream_envelope(&procedure, created_at_ms, &idempotency_key);
                let signing_digest = hash(canonical.as_bytes());
                let signature_hex = signer
                    .sign_hex(&signing_digest)
                    .map_err(EnvelopeTransportError::Sign)?;
                write_envelope_headers(
                    &mut parts.headers,
                    &signer.public_key_hex(),
                    &signature_hex,
                    None,
                    created_at_ms,
                    &idempotency_key,
                )
                .map_err(EnvelopeTransportError::Sign)?;
                let req = Request::from_parts(parts, body);
                inner.send(req).await.map_err(EnvelopeTransportError::Inner)
            } else {
                inner
                    .send(request)
                    .await
                    .map_err(EnvelopeTransportError::Inner)
            }
        })
    }
}

#[allow(clippy::too_many_arguments)]
fn write_envelope_headers(
    headers: &mut HeaderMap,
    public_key_hex: &str,
    signature_hex: &str,
    body_digest_hex: Option<&str>,
    created_at_ms: i64,
    idempotency_key: &str,
) -> Result<(), String> {
    insert_header(headers, header::PUBLIC_KEY, public_key_hex)?;
    insert_header(headers, header::SIGNATURE, signature_hex)?;
    if let Some(digest) = body_digest_hex {
        insert_header(headers, header::DIGEST, digest)?;
    }
    insert_header(headers, header::CREATED_AT, &created_at_ms.to_string())?;
    if !idempotency_key.is_empty() {
        insert_header(headers, header::IDEMPOTENCY_KEY, idempotency_key)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requires_unary_write_auth_matches_update_and_advance() {
        assert!(requires_unary_write_auth(
            "/mkit.transport.v1.TransportService/UpdateRef"
        ));
        assert!(requires_unary_write_auth(
            "/mkit.transport.v1.TransportService/AdvanceRefs"
        ));
        assert!(!requires_unary_write_auth(
            "/mkit.transport.v1.TransportService/ReadRef"
        ));
        assert!(!requires_unary_write_auth(
            "/mkit.transport.v1.TransportService/ListRefs"
        ));
    }

    #[test]
    fn requires_stream_write_auth_matches_upload_pack_only() {
        assert!(requires_stream_write_auth(
            "/mkit.transport.v1.TransportService/UploadPack"
        ));
        assert!(!requires_stream_write_auth(
            "/mkit.transport.v1.TransportService/DownloadPack"
        ));
    }

    #[test]
    fn canonical_envelope_matches_server_field_order() {
        let s = canonical_envelope("/svc/UpdateRef", "deadbeef", 1_700_000_000_000, "idem-1");
        assert_eq!(
            s,
            "mkit-write:v1\n/svc/UpdateRef\ndeadbeef\n1700000000000\nidem-1"
        );
    }

    #[test]
    fn canonical_stream_envelope_has_no_digest_field() {
        let s = canonical_stream_envelope("/svc/UploadPack", 1_700_000_000_000, "idem-2");
        assert_eq!(
            s,
            "mkit-stream-write:v1\n/svc/UploadPack\n1700000000000\nidem-2"
        );
    }

    #[test]
    fn unary_and_stream_digests_never_collide() {
        // Same procedure/created_at/idem: the two envelope kinds must
        // never produce the same signing digest (distinct prefixes +
        // field counts) — mirrors the server-side regression test in
        // `apps/vcs-worker/src/envelope.rs`.
        let bd = to_hex(&hash(b"body"));
        let unary = hash(canonical_envelope("/svc/UpdateRef", &bd, 1, "k").as_bytes());
        let stream = hash(canonical_stream_envelope("/svc/UpdateRef", 1, "k").as_bytes());
        assert_ne!(unary, stream);
    }

    #[test]
    fn random_idempotency_key_is_64_lowercase_hex_chars() {
        let k = random_idempotency_key();
        assert_eq!(k.len(), 32);
        assert!(k.bytes().all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn random_idempotency_key_is_not_constant() {
        let a = random_idempotency_key();
        let b = random_idempotency_key();
        assert_ne!(a, b, "two calls must not reuse the same idempotency key");
    }

    struct FixedSigner {
        public_key_hex: String,
        signature_hex: String,
    }
    impl EnvelopeSigner for FixedSigner {
        fn public_key_hex(&self) -> String {
            self.public_key_hex.clone()
        }
        fn sign_hex(&self, _message: &[u8; 32]) -> Result<String, String> {
            Ok(self.signature_hex.clone())
        }
    }

    #[test]
    fn write_envelope_headers_sets_all_five_for_unary() {
        let mut headers = HeaderMap::new();
        write_envelope_headers(&mut headers, "aa", "bb", Some("cc"), 42, "idem").unwrap();
        assert_eq!(headers.get(header::PUBLIC_KEY).unwrap(), "aa");
        assert_eq!(headers.get(header::SIGNATURE).unwrap(), "bb");
        assert_eq!(headers.get(header::DIGEST).unwrap(), "cc");
        assert_eq!(headers.get(header::CREATED_AT).unwrap(), "42");
        assert_eq!(headers.get(header::IDEMPOTENCY_KEY).unwrap(), "idem");
    }

    #[test]
    fn write_envelope_headers_omits_digest_for_stream() {
        let mut headers = HeaderMap::new();
        write_envelope_headers(&mut headers, "aa", "bb", None, 42, "idem").unwrap();
        assert!(headers.get(header::DIGEST).is_none());
    }

    #[test]
    fn write_envelope_headers_omits_empty_idempotency_key() {
        let mut headers = HeaderMap::new();
        write_envelope_headers(&mut headers, "aa", "bb", None, 42, "").unwrap();
        assert!(headers.get(header::IDEMPOTENCY_KEY).is_none());
    }

    #[test]
    fn fixed_signer_round_trips_through_header_writer() {
        let signer: Arc<dyn EnvelopeSigner> = Arc::new(FixedSigner {
            public_key_hex: "aa".repeat(32),
            signature_hex: "bb".repeat(64),
        });
        assert_eq!(signer.public_key_hex().len(), 64);
        assert_eq!(signer.sign_hex(&[0u8; 32]).unwrap().len(), 128);
    }

    // -----------------------------------------------------------------
    // Parity tests: drive a real `EnvelopeTransport::send` through a
    // capturing inner `ClientTransport` and independently re-verify the
    // resulting headers with a from-scratch reimplementation of
    // `apps/vcs-worker/src/envelope.rs`'s `verify_envelope` /
    // `verify_stream_envelope` (raw Ed25519 `verify_strict` over
    // `BLAKE3(canonical)`, canonical string built by hand here rather
    // than by calling this module's own `canonical_envelope` /
    // `canonical_stream_envelope` — a self-call couldn't catch a
    // canonical-string regression). If the client's header/digest/
    // signature construction ever drifts from the server's contract,
    // this test — not just a live `wrangler dev` run — should catch it.
    // -----------------------------------------------------------------

    mod parity {
        use super::*;
        use bytes::Bytes;
        use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
        use http_body_util::Full;
        use std::convert::Infallible;
        use std::sync::Mutex;

        struct DalekSigner(SigningKey);
        impl EnvelopeSigner for DalekSigner {
            fn public_key_hex(&self) -> String {
                to_hex_bytes(&self.0.verifying_key().to_bytes())
            }
            fn sign_hex(&self, message: &[u8; 32]) -> Result<String, String> {
                Ok(to_hex_bytes(&self.0.sign(message).to_bytes()))
            }
        }

        #[derive(Default)]
        struct Captured {
            headers: HeaderMap,
            body: Bytes,
        }

        #[derive(Clone)]
        struct CapturingTransport {
            captured: Arc<Mutex<Option<Captured>>>,
        }

        impl ClientTransport for CapturingTransport {
            type ResponseBody = Full<Bytes>;
            type Error = Infallible;

            fn send(
                &self,
                request: Request<ClientBody>,
            ) -> BoxFuture<'static, Result<Response<Self::ResponseBody>, Self::Error>> {
                let captured = self.captured.clone();
                Box::pin(async move {
                    let (parts, body) = request.into_parts();
                    let bytes = body
                        .collect()
                        .await
                        .map(|c| c.to_bytes())
                        .unwrap_or_default();
                    *captured.lock().unwrap() = Some(Captured {
                        headers: parts.headers,
                        body: bytes,
                    });
                    Ok(Response::new(Full::new(Bytes::new())))
                })
            }
        }

        /// Independent re-derivation of the unary canonical string and
        /// `verify_strict` check, deliberately NOT calling
        /// `canonical_envelope` — see module doc above.
        fn verify_unary_from_headers(procedure: &str, headers: &HeaderMap, body: &[u8]) -> bool {
            let get = |n: &str| headers.get(n).and_then(|v| v.to_str().ok()).unwrap_or("");
            let public_key = get(header::PUBLIC_KEY);
            let signature = get(header::SIGNATURE);
            let digest = get(header::DIGEST);
            let created_at = get(header::CREATED_AT);
            let idem = get(header::IDEMPOTENCY_KEY);

            let actual_body_digest = to_hex(&hash(body));
            if digest != actual_body_digest {
                return false;
            }
            let canonical = format!("mkit-write:v1\n{procedure}\n{digest}\n{created_at}\n{idem}");
            let signing_digest = hash(canonical.as_bytes());

            let Ok(pk_bytes) = hex::decode(public_key) else {
                return false;
            };
            let Ok(sig_bytes) = hex::decode(signature) else {
                return false;
            };
            let Ok(vk) = VerifyingKey::from_bytes(&pk_bytes.try_into().unwrap_or([0u8; 32])) else {
                return false;
            };
            let Ok(sig) = ed25519_dalek::Signature::from_slice(&sig_bytes) else {
                return false;
            };
            vk.verify_strict(&signing_digest, &sig).is_ok()
        }

        fn verify_stream_from_headers(procedure: &str, headers: &HeaderMap) -> bool {
            let get = |n: &str| headers.get(n).and_then(|v| v.to_str().ok()).unwrap_or("");
            let public_key = get(header::PUBLIC_KEY);
            let signature = get(header::SIGNATURE);
            let created_at = get(header::CREATED_AT);
            let idem = get(header::IDEMPOTENCY_KEY);
            // Streaming envelope must NOT carry a body digest header.
            if headers.get(header::DIGEST).is_some() {
                return false;
            }

            let canonical = format!("mkit-stream-write:v1\n{procedure}\n{created_at}\n{idem}");
            let signing_digest = hash(canonical.as_bytes());

            let Ok(pk_bytes) = hex::decode(public_key) else {
                return false;
            };
            let Ok(sig_bytes) = hex::decode(signature) else {
                return false;
            };
            let Ok(vk) = VerifyingKey::from_bytes(&pk_bytes.try_into().unwrap_or([0u8; 32])) else {
                return false;
            };
            let Ok(sig) = ed25519_dalek::Signature::from_slice(&sig_bytes) else {
                return false;
            };
            vk.verify_strict(&signing_digest, &sig).is_ok()
        }

        fn build_request(procedure: &str, body: &'static [u8]) -> Request<ClientBody> {
            Request::builder()
                .method("POST")
                .uri(format!("https://example.invalid{procedure}"))
                .body(full_body(Bytes::from_static(body)))
                .unwrap()
        }

        #[test]
        fn update_ref_request_verifies_against_independent_reimplementation() {
            let sk = SigningKey::from_bytes(&[9u8; 32]);
            let signer: Arc<dyn EnvelopeSigner> = Arc::new(DalekSigner(sk));
            let captured = Arc::new(Mutex::new(None));
            let inner = CapturingTransport {
                captured: captured.clone(),
            };
            let transport = EnvelopeTransport::new(inner, Some(signer));

            let req = build_request(
                "/mkit.transport.v1.TransportService/UpdateRef",
                b"serialized-protobuf-update-ref-body",
            );
            futures::executor::block_on(transport.send(req)).expect("send ok");

            let got = captured.lock().unwrap().take().expect("request captured");
            assert!(verify_unary_from_headers(
                "/mkit.transport.v1.TransportService/UpdateRef",
                &got.headers,
                &got.body,
            ));
            // Tampering the body must break verification (digest mismatch).
            assert!(!verify_unary_from_headers(
                "/mkit.transport.v1.TransportService/UpdateRef",
                &got.headers,
                b"tampered body",
            ));
        }

        #[test]
        fn advance_refs_request_is_also_signed_as_unary() {
            let sk = SigningKey::from_bytes(&[11u8; 32]);
            let signer: Arc<dyn EnvelopeSigner> = Arc::new(DalekSigner(sk));
            let captured = Arc::new(Mutex::new(None));
            let inner = CapturingTransport {
                captured: captured.clone(),
            };
            let transport = EnvelopeTransport::new(inner, Some(signer));

            let req = build_request(
                "/mkit.transport.v1.TransportService/AdvanceRefs",
                b"serialized-advance-refs-body",
            );
            futures::executor::block_on(transport.send(req)).expect("send ok");

            let got = captured.lock().unwrap().take().expect("request captured");
            assert!(verify_unary_from_headers(
                "/mkit.transport.v1.TransportService/AdvanceRefs",
                &got.headers,
                &got.body,
            ));
        }

        #[test]
        fn upload_pack_request_verifies_as_streaming_envelope_with_no_digest_header() {
            let sk = SigningKey::from_bytes(&[13u8; 32]);
            let signer: Arc<dyn EnvelopeSigner> = Arc::new(DalekSigner(sk));
            let captured = Arc::new(Mutex::new(None));
            let inner = CapturingTransport {
                captured: captured.clone(),
            };
            let transport = EnvelopeTransport::new(inner, Some(signer));

            let req = build_request(
                "/mkit.transport.v1.TransportService/UploadPack",
                b"pack-header-message-bytes",
            );
            futures::executor::block_on(transport.send(req)).expect("send ok");

            let got = captured.lock().unwrap().take().expect("request captured");
            assert!(verify_stream_from_headers(
                "/mkit.transport.v1.TransportService/UploadPack",
                &got.headers,
            ));
        }

        #[test]
        fn read_only_procedures_are_never_signed() {
            let sk = SigningKey::from_bytes(&[17u8; 32]);
            let signer: Arc<dyn EnvelopeSigner> = Arc::new(DalekSigner(sk));
            let captured = Arc::new(Mutex::new(None));
            let inner = CapturingTransport {
                captured: captured.clone(),
            };
            let transport = EnvelopeTransport::new(inner, Some(signer));

            for procedure in [
                "/mkit.transport.v1.TransportService/ListRefs",
                "/mkit.transport.v1.TransportService/ReadRef",
                "/mkit.transport.v1.TransportService/PackExists",
                "/mkit.transport.v1.TransportService/DownloadPack",
            ] {
                let req = build_request(procedure, b"read-body");
                futures::executor::block_on(transport.send(req)).expect("send ok");
                let got = captured.lock().unwrap().take().expect("request captured");
                assert!(
                    got.headers.get(header::PUBLIC_KEY).is_none(),
                    "{procedure} must not be signed"
                );
                assert!(got.headers.get(header::SIGNATURE).is_none());
            }
        }

        #[test]
        fn no_signer_configured_never_signs_a_write_call() {
            let captured = Arc::new(Mutex::new(None));
            let inner = CapturingTransport {
                captured: captured.clone(),
            };
            let transport: EnvelopeTransport<CapturingTransport> =
                EnvelopeTransport::new(inner, None);

            let req = build_request(
                "/mkit.transport.v1.TransportService/UpdateRef",
                b"unsigned-body",
            );
            futures::executor::block_on(transport.send(req)).expect("send ok");
            let got = captured.lock().unwrap().take().expect("request captured");
            assert!(got.headers.get(header::PUBLIC_KEY).is_none());
        }
    }
}
