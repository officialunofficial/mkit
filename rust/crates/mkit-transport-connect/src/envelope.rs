//! Auth v2 client adapter: signs a configured destination and content commitment.
//! Writes allocate nonce/times once per logical operation; reads allocate
//! them on each attempt.
//! Upload metadata is known before streaming and no body is collected here.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use connectrpc::client::{ClientBody, ClientTransport, full_body};
use futures::future::BoxFuture;
use http::{HeaderMap, HeaderName, HeaderValue, Request, Response};
use http_body_util::BodyExt;
use mkit_core::hash::{hash, to_hex, to_hex_bytes};

use mkit_core::write_auth::{Context, MAX_VALIDITY_MS, Operation};

mod header {
    pub const PUBLIC_KEY: &str = "x-public-key";
    pub const SIGNATURE: &str = "x-signature";
    pub const DIGEST: &str = "x-digest";
    pub const CREATED_AT: &str = "x-created-at";
    pub const IDEMPOTENCY_KEY: &str = "idempotency-key";
}

/// One request identity. Write callers retain it across retries; read callers
/// allocate it inside each attempt.
#[derive(Clone)]
pub(crate) struct RetryIdentity {
    nonce: String,
    created_at: String,
    expires_at: String,
}
impl RetryIdentity {
    pub(crate) fn new() -> Result<Self, String> {
        let now = now_ms();
        Ok(Self {
            nonce: random_idempotency_key()?,
            created_at: now.to_string(),
            expires_at: now.saturating_add(MAX_VALIDITY_MS).to_string(),
        })
    }
    pub(crate) fn apply(
        &self,
        options: connectrpc::client::CallOptions,
    ) -> connectrpc::client::CallOptions {
        options
            .with_header(header::CREATED_AT, self.created_at.as_str())
            .with_header("x-expires-at", self.expires_at.as_str())
            .with_header(header::IDEMPOTENCY_KEY, self.nonce.as_str())
    }
}

/// A signer able to produce the Ed25519 material an auth v2 envelope needs:
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProcedureAuth {
    Body,
    Commitment(&'static str),
    Unsigned { repository: bool },
}

/// Exhaustive for the generated service. Future client methods must be
/// classified here before they can send authenticated requests.
fn procedure_auth(procedure: &str) -> Option<ProcedureAuth> {
    let method = procedure.strip_prefix("/mkit.transport.v1.TransportService/")?;
    Some(match method {
        "ListRefs" | "ReadRef" | "PackExists" | "DownloadPack" | "IssueObjectUrl"
        | "GetReceipt" | "UpdateRef" | "AdvanceRefs" | "BeginUpload" | "CompleteUpload"
        | "SetRepoVisibility" => ProcedureAuth::Body,
        "UploadPack" => ProcedureAuth::Commitment("pack:"),
        "UploadPart" => ProcedureAuth::Commitment("part:"),
        "GetServerInfo" => ProcedureAuth::Unsigned { repository: true },
        "GetGrantEpoch" | "SetGrantEpoch" => ProcedureAuth::Unsigned { repository: false },
        _ => return None,
    })
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

fn random_idempotency_key() -> Result<String, String> {
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes).map_err(|e| format!("request nonce entropy unavailable: {e}"))?;
    Ok(to_hex_bytes(&bytes))
}

fn insert_header(headers: &mut HeaderMap, name: &'static str, value: &str) -> Result<(), String> {
    let header_name = HeaderName::from_static(name);
    let header_value =
        HeaderValue::from_str(value).map_err(|e| format!("invalid {name} header value: {e}"))?;
    headers.insert(header_name, header_value);
    Ok(())
}

/// [`ClientTransport`] wrapper that signs read and write RPCs with an auth v2
/// envelope before delegating to `inner`. This is the same transport type used
/// whether or not envelope auth is configured, so the bearer-token-only
/// path (`ConnectTransport::connect`, #700/#701) pays no signing overhead
/// beyond one `Option` check per call.
#[derive(Clone)]
pub struct EnvelopeTransport<T> {
    inner: T,
    signer: Option<Arc<dyn EnvelopeSigner>>,
    audience: String,
    repository: String,
    repository_header: Result<HeaderValue, String>,
}

impl<T> EnvelopeTransport<T> {
    pub fn new(
        inner: T,
        signer: Option<Arc<dyn EnvelopeSigner>>,
        audience: String,
        repository: String,
    ) -> Self {
        let repository_header = HeaderValue::from_str(&repository)
            .map_err(|e| format!("invalid x-repository header value: {e}"));
        Self {
            inner,
            signer,
            audience,
            repository,
            repository_header,
        }
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
            Self::Sign(s) => write!(f, "sign auth v2 envelope: {s}"),
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
        mut request: Request<ClientBody>,
    ) -> BoxFuture<'static, Result<Response<Self::ResponseBody>, Self::Error>> {
        let Some(auth) = procedure_auth(request.uri().path()) else {
            return Box::pin(async {
                Err(EnvelopeTransportError::Sign(
                    "unknown Connect procedure".into(),
                ))
            });
        };
        if matches!(auth, ProcedureAuth::Unsigned { repository: false }) {
            request.headers_mut().remove("x-repository");
        } else {
            let header = match &self.repository_header {
                Ok(header) => header.clone(),
                Err(error) => {
                    let error = error.clone();
                    return Box::pin(async move { Err(EnvelopeTransportError::Sign(error)) });
                }
            };
            request.headers_mut().insert("x-repository", header);
        }
        let inner = self.inner.clone();
        let audience = self.audience.clone();
        let repository = self.repository.clone();
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
            if auth == ProcedureAuth::Body {
                let (mut parts, body) = request.into_parts();
                let body_bytes = body
                    .collect()
                    .await
                    .map_err(|e| EnvelopeTransportError::Sign(format!("buffer request body: {e}")))?
                    .to_bytes();
                let body_digest_hex = to_hex(&hash(body_bytes.as_ref()));
                let commitment = format!("body:{body_digest_hex}");
                sign_headers(
                    &mut parts.headers,
                    &*signer,
                    &audience,
                    &repository,
                    &procedure,
                    &commitment,
                )
                .map_err(EnvelopeTransportError::Sign)?;
                insert_header(&mut parts.headers, header::DIGEST, &body_digest_hex)
                    .map_err(EnvelopeTransportError::Sign)?;
                let req = Request::from_parts(parts, full_body(body_bytes));
                inner.send(req).await.map_err(EnvelopeTransportError::Inner)
            } else if let ProcedureAuth::Commitment(prefix) = auth {
                let (mut parts, body) = request.into_parts();
                let commitment = parts
                    .headers
                    .get("x-content-commitment")
                    .and_then(|v| v.to_str().ok())
                    .ok_or_else(|| {
                        EnvelopeTransportError::Sign("missing streaming commitment".into())
                    })?
                    .to_owned();
                if !commitment.starts_with(prefix) {
                    return Err(EnvelopeTransportError::Sign(format!(
                        "request requires {prefix} commitment"
                    )));
                }
                sign_headers(
                    &mut parts.headers,
                    &*signer,
                    &audience,
                    &repository,
                    &procedure,
                    &commitment,
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

fn sign_headers(
    headers: &mut HeaderMap,
    signer: &dyn EnvelopeSigner,
    audience: &str,
    repository: &str,
    procedure: &str,
    commitment: &str,
) -> Result<(), String> {
    let get = |key| {
        headers
            .get(key)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| format!("missing operation identity header {key}"))
    };
    let created = get(header::CREATED_AT)?
        .parse::<i64>()
        .map_err(|_| "invalid start time")?;
    let expires = get("x-expires-at")?
        .parse::<i64>()
        .map_err(|_| "invalid expiry")?;
    let nonce = get(header::IDEMPOTENCY_KEY)?.to_owned();
    let operation = Operation {
        context: Context {
            audience,
            repository,
        },
        procedure,
        commitment,
        created_at: created,
        expires_at: expires,
        nonce: &nonce,
    };
    let signature = signer.sign_hex(&operation.digest().map_err(|e| e.to_string())?)?;
    for (name, value) in [
        ("x-envelope-version", "2"),
        ("x-audience", audience),
        ("x-repository", repository),
        ("x-content-commitment", commitment),
        (header::PUBLIC_KEY, signer.public_key_hex().as_str()),
        (header::SIGNATURE, signature.as_str()),
    ] {
        insert_header(headers, name, value)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
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
            let audience = get("x-audience");
            let repository = get("x-repository");
            let expires = get("x-expires-at");
            if audience != "https://example.invalid"
                || repository.is_empty()
                || get("x-envelope-version") != "2"
            {
                return false;
            }
            let canonical = format!(
                "mkit-write:v2\n{audience}\n{repository}\n{procedure}\nbody:{digest}\n{created_at}\n{expires}\n{idem}"
            );
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

            let audience = get("x-audience");
            let repository = get("x-repository");
            let expires = get("x-expires-at");
            let commitment = get("x-content-commitment");
            if audience != "https://example.invalid"
                || repository.is_empty()
                || get("x-envelope-version") != "2"
            {
                return false;
            }
            let canonical = format!(
                "mkit-write:v2\n{audience}\n{repository}\n{procedure}\n{commitment}\n{created_at}\n{expires}\n{idem}"
            );
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
                .header("x-created-at", "1000")
                .header("x-expires-at", "2000")
                .header("idempotency-key", "ab".repeat(32))
                .header(
                    "x-content-commitment",
                    format!("pack:{}:25", "cd".repeat(32)),
                )
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
            let transport = EnvelopeTransport::new(
                inner,
                Some(signer),
                "https://example.invalid".into(),
                "default".into(),
            );

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
            let transport = EnvelopeTransport::new(
                inner,
                Some(signer),
                "https://example.invalid".into(),
                "default".into(),
            );

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
        fn upload_pack_request_binds_declared_pack_without_collecting_body() {
            let sk = SigningKey::from_bytes(&[13u8; 32]);
            let signer: Arc<dyn EnvelopeSigner> = Arc::new(DalekSigner(sk));
            let captured = Arc::new(Mutex::new(None));
            let inner = CapturingTransport {
                captured: captured.clone(),
            };
            let transport = EnvelopeTransport::new(
                inner,
                Some(signer),
                "https://example.invalid".into(),
                "default".into(),
            );

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
        fn reads_are_signed_over_the_exact_request_body() {
            let sk = SigningKey::from_bytes(&[17u8; 32]);
            let signer: Arc<dyn EnvelopeSigner> = Arc::new(DalekSigner(sk));
            let captured = Arc::new(Mutex::new(None));
            let inner = CapturingTransport {
                captured: captured.clone(),
            };
            let transport = EnvelopeTransport::new(
                inner,
                Some(signer),
                "https://example.invalid".into(),
                "default".into(),
            );

            for procedure in [
                "/mkit.transport.v1.TransportService/ListRefs",
                "/mkit.transport.v1.TransportService/ReadRef",
                "/mkit.transport.v1.TransportService/PackExists",
                "/mkit.transport.v1.TransportService/DownloadPack",
            ] {
                let body: &'static [u8] = if procedure.ends_with("/DownloadPack") {
                    b"\0\0\0\0\x03abc"
                } else {
                    b"read-body"
                };
                let mut req = build_request(procedure, body);
                let now = now_ms();
                req.headers_mut()
                    .insert("x-created-at", now.to_string().parse().unwrap());
                req.headers_mut().insert(
                    "x-expires-at",
                    now.saturating_add(300_000).to_string().parse().unwrap(),
                );
                futures::executor::block_on(transport.send(req)).expect("send ok");
                let got = captured.lock().unwrap().take().expect("request captured");
                let field = |name| got.headers.get(name).unwrap().to_str().unwrap().to_owned();
                let digest = to_hex(&hash(&got.body));
                let commitment = format!("body:{digest}");
                let headers = mkit_core::write_auth::Headers {
                    version: Some(field("x-envelope-version")),
                    audience: Some(field("x-audience")),
                    repository: Some(field("x-repository")),
                    public_key: Some(field("x-public-key")),
                    signature: Some(field("x-signature")),
                    digest: Some(field("x-digest")),
                    commitment: Some(field("x-content-commitment")),
                    created_at: Some(field("x-created-at")),
                    expires_at: Some(field("x-expires-at")),
                    idempotency_key: Some(field("idempotency-key")),
                };
                assert!(
                    mkit_core::write_auth::verify_headers(
                        Context {
                            audience: "https://example.invalid",
                            repository: "default"
                        },
                        procedure,
                        Some(&commitment),
                        now,
                        &headers,
                    )
                    .is_ok(),
                    "{procedure}"
                );
                assert_ne!(to_hex(&hash(b"abc")), digest, "framing is signed");
                assert_eq!(got.headers["x-repository"], "default");
            }
        }

        #[test]
        fn generated_procedures_are_all_classified() {
            let generated = include_str!("../generated/mkit.transport.v1.transport.__connect.rs");
            let procedures: std::collections::HashSet<_> = generated
                .lines()
                .filter_map(|line| line.trim().strip_prefix('"')?.strip_suffix("\","))
                .filter(|path| path.starts_with("/mkit.transport.v1.TransportService/"))
                .collect();
            assert_eq!(procedures.len(), 16);
            for procedure in procedures {
                let method = procedure.rsplit('/').next().unwrap();
                let expected = match method {
                    "ListRefs" | "ReadRef" | "PackExists" | "DownloadPack" | "GetReceipt"
                    | "IssueObjectUrl" | "UpdateRef" | "AdvanceRefs" | "BeginUpload"
                    | "CompleteUpload" | "SetRepoVisibility" => ProcedureAuth::Body,
                    "UploadPack" => ProcedureAuth::Commitment("pack:"),
                    "UploadPart" => ProcedureAuth::Commitment("part:"),
                    "GetServerInfo" => ProcedureAuth::Unsigned { repository: true },
                    "GetGrantEpoch" | "SetGrantEpoch" => {
                        ProcedureAuth::Unsigned { repository: false }
                    }
                    _ => panic!("new generated procedure requires classification: {procedure}"),
                };
                assert_eq!(procedure_auth(procedure), Some(expected), "{procedure}");
            }
            assert_eq!(
                procedure_auth("/mkit.transport.v1.TransportService/GetGrantEpoch"),
                Some(ProcedureAuth::Unsigned { repository: false })
            );
            assert_eq!(
                procedure_auth("/mkit.transport.v1.TransportService/SetGrantEpoch"),
                Some(ProcedureAuth::Unsigned { repository: false })
            );
            assert_eq!(
                procedure_auth("/mkit.transport.v1.TransportService/IssueObjectUrl"),
                Some(ProcedureAuth::Body)
            );
        }

        #[test]
        fn signed_read_goldens_verify_in_core() {
            use crate::generated::{DownloadPackRequest, ReadRefRequest};
            use buffa::Message as _;
            let golden = include_str!("../../../tests/golden/auth-v2/read.json");
            let manifest = include_str!("../../../tests/golden/auth-v2/MANIFEST.txt");
            assert!(manifest.contains(&format!("read.json {}", to_hex(&hash(golden.as_bytes())))));
            let vectors: Vec<serde_json::Value> = serde_json::from_str(golden).unwrap();
            assert_eq!(vectors.len(), 2);
            for vector in vectors {
                let string = |key| vector[key].as_str().unwrap();
                let body = hex::decode(string("body_hex")).unwrap();
                let expected = if string("procedure").ends_with("/ReadRef") {
                    ReadRefRequest {
                        name: Some("refs/heads/main".into()),
                        ..Default::default()
                    }
                    .encode_to_vec()
                } else {
                    let message = DownloadPackRequest {
                        pack_id: Some(vec![0xcd; 32]),
                        ..Default::default()
                    }
                    .encode_to_vec();
                    let mut framed = vec![0];
                    framed.extend_from_slice(&u32::try_from(message.len()).unwrap().to_be_bytes());
                    framed.extend_from_slice(&message);
                    framed
                };
                assert_eq!(body, expected);
                let digest = to_hex(&hash(&body));
                assert_eq!(digest, string("body_digest"));
                let op = Operation {
                    context: Context {
                        audience: string("audience"),
                        repository: string("repository"),
                    },
                    procedure: string("procedure"),
                    commitment: string("commitment"),
                    created_at: vector["created_at"].as_i64().unwrap(),
                    expires_at: vector["expires_at"].as_i64().unwrap(),
                    nonce: string("nonce"),
                };
                assert_eq!(op.canonical().unwrap(), string("canonical"));
                assert_eq!(to_hex(&op.digest().unwrap()), string("signing_digest"));
                let headers = mkit_core::write_auth::Headers {
                    version: Some("2".into()),
                    audience: Some(string("audience").into()),
                    repository: Some(string("repository").into()),
                    public_key: Some(string("public_key").into()),
                    signature: Some(string("signature").into()),
                    digest: Some(digest),
                    commitment: Some(string("commitment").into()),
                    created_at: Some(op.created_at.to_string()),
                    expires_at: Some(op.expires_at.to_string()),
                    idempotency_key: Some(string("nonce").into()),
                };
                assert!(
                    mkit_core::write_auth::verify_headers(
                        op.context,
                        op.procedure,
                        Some(op.commitment),
                        op.created_at + 1,
                        &headers
                    )
                    .is_ok()
                );
                if op.procedure.ends_with("/DownloadPack") {
                    assert_eq!(&body[..5], &[0, 0, 0, 0, 34]);
                    assert_ne!(to_hex(&hash(&body[5..])), string("body_digest"));
                }
            }
        }

        #[test]
        fn repository_is_present_without_signer_on_every_read() {
            let captured = Arc::new(Mutex::new(None));
            let transport = EnvelopeTransport::new(
                CapturingTransport {
                    captured: captured.clone(),
                },
                None,
                "https://example.invalid".into(),
                "default".into(),
            );
            for method in [
                "ListRefs",
                "ReadRef",
                "PackExists",
                "DownloadPack",
                "GetServerInfo",
            ] {
                let procedure = format!("/mkit.transport.v1.TransportService/{method}");
                let mut req = build_request(&procedure, b"read-body");
                req.headers_mut()
                    .insert("x-repository", HeaderValue::from_static("wrong"));
                futures::executor::block_on(transport.send(req)).unwrap();
                let got = captured.lock().unwrap().take().unwrap();
                assert_eq!(got.headers["x-repository"], "default");
                assert_eq!(got.headers.get_all("x-repository").iter().count(), 1);
                assert!(got.headers.get("x-signature").is_none());
            }
        }

        #[test]
        fn discovery_and_epoch_paths_are_never_signed() {
            let captured = Arc::new(Mutex::new(None));
            let transport = EnvelopeTransport::new(
                CapturingTransport {
                    captured: captured.clone(),
                },
                Some(Arc::new(DalekSigner(SigningKey::from_bytes(&[19; 32])))),
                "https://example.invalid".into(),
                "default".into(),
            );
            for method in ["GetServerInfo", "GetGrantEpoch", "SetGrantEpoch"] {
                let procedure = format!("/mkit.transport.v1.TransportService/{method}");
                let mut request = build_request(&procedure, b"");
                // The shared builder seeds a pack commitment for streaming
                // tests; discovery and epoch calls do not supply one.
                request.headers_mut().remove("x-content-commitment");
                request
                    .headers_mut()
                    .insert("x-repository", HeaderValue::from_static("wrong"));
                futures::executor::block_on(transport.send(request)).unwrap();
                let got = captured.lock().unwrap().take().unwrap();
                assert!(got.headers.get("x-signature").is_none());
                assert!(got.headers.get("x-public-key").is_none());
                assert!(got.headers.get("x-envelope-version").is_none());
                assert!(got.headers.get("x-content-commitment").is_none());
                assert_eq!(
                    got.headers.get("x-repository").is_some(),
                    method == "GetServerInfo"
                );
            }
        }

        const NAMESPACED: &str = "0x0123456789abcdef0123456789abcdef01234567/photos";

        #[test]
        fn ref_hint_is_excluded_from_signed_canonical_string() {
            let captured = Arc::new(Mutex::new(None));
            let transport = EnvelopeTransport::new(
                CapturingTransport {
                    captured: captured.clone(),
                },
                Some(Arc::new(DalekSigner(SigningKey::from_bytes(&[9; 32])))),
                "https://example.invalid".into(),
                NAMESPACED.into(),
            );
            let procedure = "/mkit.transport.v1.TransportService/UpdateRef";
            let mut req = build_request(procedure, b"write-body");
            req.headers_mut()
                .insert("x-mkit-ref", HeaderValue::from_static("refs/heads/main"));
            req.headers_mut()
                .insert("x-write-grant", HeaderValue::from_static("grant-one"));
            futures::executor::block_on(transport.send(req)).unwrap();
            let mut got = captured.lock().unwrap().take().unwrap();
            assert_eq!(got.headers["x-mkit-ref"], "refs/heads/main");
            assert_eq!(got.headers.get_all("x-repository").iter().count(), 1);
            assert!(verify_unary_from_headers(
                procedure,
                &got.headers,
                &got.body
            ));
            got.headers
                .insert("x-mkit-ref", HeaderValue::from_static("refs/heads/other"));
            got.headers
                .insert("x-write-grant", HeaderValue::from_static("grant-two"));
            assert!(verify_unary_from_headers(
                procedure,
                &got.headers,
                &got.body
            ));
            assert_eq!(got.headers["x-repository"], NAMESPACED);
            // The signature binds the repository: another identity fails.
            got.headers
                .insert("x-repository", HeaderValue::from_static("default"));
            assert!(!verify_unary_from_headers(
                procedure,
                &got.headers,
                &got.body
            ));
        }

        #[test]
        fn no_signer_configured_never_signs_a_write_call() {
            let captured = Arc::new(Mutex::new(None));
            let inner = CapturingTransport {
                captured: captured.clone(),
            };
            let transport: EnvelopeTransport<CapturingTransport> = EnvelopeTransport::new(
                inner,
                None,
                "https://example.invalid".into(),
                "default".into(),
            );

            let req = build_request(
                "/mkit.transport.v1.TransportService/UpdateRef",
                b"unsigned-body",
            );
            futures::executor::block_on(transport.send(req)).expect("send ok");
            let got = captured.lock().unwrap().take().expect("request captured");
            assert!(got.headers.get(header::PUBLIC_KEY).is_none());
            assert_eq!(got.headers["x-repository"], "default");
        }
    }
}
