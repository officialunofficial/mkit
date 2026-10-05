use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
};
use buffa::Message;
use http::{HeaderMap, HeaderValue, Request, Response};
use mkit_core::{
    hash::{Hash, hash, to_hex},
    write_auth::{Context, MAX_VALIDITY_MS, Operation},
};
use serde::Deserialize;
use std::time::Duration;

const SERVICE: &str = "/mkit.transport.v1.TransportService/";
const RESPONSE_LIMIT: usize = 1024 * 1024;

/// Injectable HTTP channel. Bound the response while receiving it, refuse
/// redirects, and retain the exact request for any ambiguous retry. Transport
/// errors must never be disguised as a successful or pending RPC response.
#[allow(async_fn_in_trait)]
pub trait HttpTransport {
    async fn send(
        &self,
        request: Request<Vec<u8>>,
        response_limit: usize,
    ) -> Result<Response<Vec<u8>>, String>;
}

/// Host-owned epoch clock, secure entropy and scheduling. No runtime or
/// platform clock is used by the primitive.
#[allow(async_fn_in_trait)]
pub trait Clock {
    fn now_ms(&self) -> i64;
    fn nonce(&self) -> Result<Hash, String>;
    async fn wait(&self, duration: Duration);
}

/// An async Ed25519 signer (the digest has already been domain separated).
#[allow(async_fn_in_trait)]
pub trait Signer {
    fn public_key(&self) -> [u8; 32];
    async fn sign(&self, digest: &Hash) -> Result<[u8; 64], String>;
}

/// Destination identity bound into every signature. The origin must be
/// canonical (no credentials, query, fragment, path or default port).
#[derive(Clone, Debug)]
pub struct Destination {
    pub(crate) origin: String,
    pub(crate) repository: String,
}
impl Destination {
    pub fn new(origin: String, repository: String) -> Result<Self, Error> {
        mkit_core::write_auth::validate_audience(&origin)
            .map_err(|_| Error::Invalid("canonical origin"))?;
        mkit_core::repo_identity::RepositoryIdentity::parse_bare_allowed(&repository)
            .map_err(|_| Error::Invalid("repository identity"))?;
        Ok(Self { origin, repository })
    }
    /// Discover canonical capabilities before preparing a bounded plan.
    pub async fn server_info<T: HttpTransport>(
        &self,
        transport: &T,
    ) -> Result<crate::proto::GetServerInfoResponse, Error> {
        let request = self.info_request()?;
        let (bytes, _) = send_checked(transport, request).await?;
        crate::proto::GetServerInfoResponse::decode_from_slice(&bytes)
            .map_err(|_| Error::Invalid("server info protobuf"))
    }

    fn info_request(&self) -> Result<Request<Vec<u8>>, Error> {
        Request::post(format!("{}{SERVICE}GetServerInfo", self.origin))
            .header("content-type", "application/proto")
            .header("connect-protocol-version", "1")
            .header("x-repository", &self.repository)
            .body(Vec::new())
            .map_err(|_| Error::Invalid("HTTP request"))
    }
}

/// Connect error details remain available to host admission/policy code.
#[derive(Clone, Debug, Deserialize)]
pub struct Detail {
    #[serde(rename = "type")]
    pub type_url: String,
    pub value: Option<String>,
}
#[derive(Clone, Debug, Deserialize)]
pub struct RemoteError {
    pub code: String,
    #[serde(default)]
    pub message: String,
    #[serde(default)]
    pub details: Vec<Detail>,
    #[serde(skip)]
    pub status: u16,
    #[serde(skip)]
    pub headers: HeaderMap,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("push limit: {0}")]
    Limit(&'static str),
    #[error("invalid push response/input: {0}")]
    Invalid(&'static str),
    #[error("transport: {0}")]
    Transport(String),
    #[error("signing: {0}")]
    Signing(String),
    #[error("Connect {0:?}")]
    Remote(Box<RemoteError>),
    #[error("pack: {0}")]
    Pack(#[from] mkit_core::pack::PackError),
    #[error("packlist: {0}")]
    Packlist(#[from] mkit_core::transfer::PackListError),
    #[error("push deadline expired")]
    Deadline,
}

pub(crate) struct Rpc<'a, T, S, C> {
    pub(crate) transport: &'a T,
    pub(crate) signer: &'a S,
    pub(crate) clock: &'a C,
    pub(crate) destination: &'a Destination,
    pub(crate) deadline_ms: i64,
}

impl<T: HttpTransport, S: Signer, C: Clock> Rpc<'_, T, S, C> {
    pub(crate) async fn unary<Q: Message, R: Message + Default>(
        &self,
        method: &str,
        message: &Q,
    ) -> Result<R, Error> {
        let body = message.encode_to_vec();
        let commitment = format!("body:{}", to_hex(&hash(&body)));
        let (bytes, _) = self.call(method, body, &commitment, false).await?;
        R::decode_from_slice(&bytes).map_err(|_| Error::Invalid("protobuf response"))
    }

    pub(crate) async fn stream<Q: Message, R: Message + Default>(
        &self,
        method: &str,
        messages: impl IntoIterator<Item = Q>,
        commitment: &str,
    ) -> Result<R, Error> {
        let mut body = Vec::new();
        for message in messages {
            frame(&mut body, &message.encode_to_vec())?;
        }
        let (bytes, _) = self.call(method, body, commitment, true).await?;
        let frames = decode_stream(&bytes)?;
        if frames.len() != 1 {
            return Err(Error::Invalid("stream response count"));
        }
        R::decode_from_slice(frames[0]).map_err(|_| Error::Invalid("protobuf response"))
    }

    pub(crate) async fn download(&self, key: Hash, head_ref: &str) -> Result<Vec<u8>, Error> {
        use crate::proto::{
            DownloadPackRequest, DownloadPackResponse, download_pack_response::Body,
        };
        let request = DownloadPackRequest {
            pack_id: Some(key.to_vec()),
            ..Default::default()
        };
        let body = request.encode_to_vec();
        let body = framed(&body)?;
        let commitment = format!("body:{}", to_hex(&hash(&body)));
        let (mut request, _) = self
            .request("DownloadPack", body, &commitment, true)
            .await?;
        request.headers_mut().insert(
            "x-mkit-ref",
            HeaderValue::from_str(head_ref).map_err(|_| Error::Invalid("ref hint"))?,
        );
        let (bytes, _) = self.send(&request).await?;
        let mut out = Vec::new();
        let mut expected = None;
        let mut last = false;
        for frame in decode_stream(&bytes)? {
            let response = DownloadPackResponse::decode_from_slice(frame)
                .map_err(|_| Error::Invalid("download protobuf"))?;
            match response.body {
                Some(Body::Header(header)) if expected.is_none() && out.is_empty() => {
                    let size = header.total_bytes.ok_or(Error::Invalid("download size"))?;
                    if size > RESPONSE_LIMIT as u64 {
                        return Err(Error::Limit("packmap node download"));
                    }
                    expected = Some(size);
                }
                Some(Body::Chunk(chunk)) if expected.is_some() && !last => {
                    if chunk.pack_id.as_deref() != Some(key.as_slice())
                        || chunk.offset != Some(out.len() as u64)
                    {
                        return Err(Error::Invalid("download chunk identity"));
                    }
                    out.extend_from_slice(
                        chunk
                            .data
                            .as_deref()
                            .ok_or(Error::Invalid("download chunk"))?,
                    );
                    last = chunk.last.ok_or(Error::Invalid("download last marker"))?;
                }
                _ => return Err(Error::Invalid("download order")),
            }
        }
        if !last || expected != Some(out.len() as u64) || mkit_core::pack::pack_key(&out) != key {
            return Err(Error::Invalid("packmap content commitment"));
        }
        Ok(out)
    }

    pub(crate) async fn advance(
        &self,
        message: &crate::proto::AdvanceRefsRequest,
    ) -> Result<crate::proto::AdvanceRefsResponse, Error> {
        let body = message.encode_to_vec();
        let commitment = format!("body:{}", to_hex(&hash(&body)));
        let (mut request, mut expires) = self
            .request("AdvanceRefs", body.clone(), &commitment, false)
            .await?;
        let mut lag_start = None;
        let mut saw_pending = false;
        let mut renewed_after_unauthenticated = false;
        loop {
            let now = self.clock.now_ms();
            if now >= self.deadline_ms {
                return Err(Error::Deadline);
            }
            // Only a definitive pending/lag answer reaches this continuation.
            // Keep exactly the same nonce and timestamps until actual expiry.
            if now > expires {
                (request, expires) = self
                    .request("AdvanceRefs", body.clone(), &commitment, false)
                    .await?;
            }
            match self.send(&request).await {
                Ok((bytes, _)) => {
                    return crate::proto::AdvanceRefsResponse::decode_from_slice(&bytes)
                        .map_err(|_| Error::Invalid("advance protobuf"));
                }
                Err(Error::Remote(error)) => {
                    // A post-pending authentication rejection is definitive,
                    // including expiry in transit or a small server clock lead.
                    // Recover once; an ambiguous transport error never reaches here.
                    if saw_pending
                        && !renewed_after_unauthenticated
                        && error.code == "unauthenticated"
                    {
                        renewed_after_unauthenticated = true;
                        (request, expires) = self
                            .request("AdvanceRefs", body.clone(), &commitment, false)
                            .await?;
                        continue;
                    }
                    let delay = if let Some(delay) = pending_delay(&error) {
                        lag_start = None;
                        renewed_after_unauthenticated = false;
                        delay
                    } else if !message.ticket_ids.is_empty()
                        && error.code == "unavailable"
                        && error.message == "repository membership not yet visible"
                    {
                        let start = *lag_start.get_or_insert(now);
                        if now.saturating_sub(start) >= 60_000 {
                            return Err(Error::Remote(error));
                        }
                        Duration::from_secs(2)
                    } else {
                        return Err(Error::Remote(error));
                    };
                    saw_pending = true;
                    if now.saturating_add(i64::try_from(delay.as_millis()).unwrap_or(i64::MAX))
                        >= self.deadline_ms
                    {
                        return Err(Error::Deadline);
                    }
                    self.clock.wait(delay).await;
                }
                Err(error) => return Err(error),
            }
        }
    }

    async fn call(
        &self,
        method: &str,
        body: Vec<u8>,
        commitment: &str,
        streaming: bool,
    ) -> Result<(Vec<u8>, HeaderMap), Error> {
        let (request, _) = self.request(method, body, commitment, streaming).await?;
        self.send(&request).await
    }

    async fn request(
        &self,
        method: &str,
        body: Vec<u8>,
        commitment: &str,
        streaming: bool,
    ) -> Result<(Request<Vec<u8>>, i64), Error> {
        let created = self.clock.now_ms();
        if created >= self.deadline_ms {
            return Err(Error::Deadline);
        }
        let expires = created
            .saturating_add(MAX_VALIDITY_MS)
            .min(self.deadline_ms);
        if method == "GetServerInfo" {
            let request = self.destination.info_request()?;
            return Ok((request, expires));
        }
        let nonce = to_hex(&self.clock.nonce().map_err(Error::Signing)?);
        let procedure = format!("{SERVICE}{method}");
        let digest = Operation {
            context: Context {
                audience: &self.destination.origin,
                repository: &self.destination.repository,
            },
            procedure: &procedure,
            commitment,
            created_at: created,
            expires_at: expires,
            nonce: &nonce,
        }
        .digest()
        .map_err(|_| Error::Invalid("signed operation"))?;
        let signature = to_hex_bytes(&self.signer.sign(&digest).await.map_err(Error::Signing)?);
        let key = to_hex(&self.signer.public_key());
        let mut request = Request::post(format!("{}{procedure}", self.destination.origin))
            .header(
                "content-type",
                if streaming {
                    "application/connect+proto"
                } else {
                    "application/proto"
                },
            )
            .header("connect-protocol-version", "1")
            .body(body)
            .map_err(|_| Error::Invalid("HTTP request"))?;
        for (name, value) in [
            ("x-envelope-version", "2".to_owned()),
            ("x-audience", self.destination.origin.clone()),
            ("x-repository", self.destination.repository.clone()),
            ("x-content-commitment", commitment.to_owned()),
            ("x-created-at", created.to_string()),
            ("x-expires-at", expires.to_string()),
            ("idempotency-key", nonce),
            ("x-public-key", key),
            ("x-signature", signature),
        ] {
            request.headers_mut().insert(
                name,
                HeaderValue::from_str(&value).map_err(|_| Error::Invalid("auth header"))?,
            );
        }
        if let Some(value) = commitment.strip_prefix("body:") {
            request.headers_mut().insert(
                "x-digest",
                HeaderValue::from_str(value).map_err(|_| Error::Invalid("digest header"))?,
            );
        }
        Ok((request, expires))
    }

    async fn send(&self, request: &Request<Vec<u8>>) -> Result<(Vec<u8>, HeaderMap), Error> {
        let mut copy = Request::new(request.body().clone());
        *copy.method_mut() = request.method().clone();
        *copy.uri_mut() = request.uri().clone();
        *copy.headers_mut() = request.headers().clone();
        send_checked(self.transport, copy).await
    }
}

async fn send_checked<T: HttpTransport>(
    transport: &T,
    request: Request<Vec<u8>>,
) -> Result<(Vec<u8>, HeaderMap), Error> {
    let content_type = request.headers().get("content-type").cloned();
    let response = transport
        .send(request, RESPONSE_LIMIT)
        .await
        .map_err(Error::Transport)?;
    if response.body().len() > RESPONSE_LIMIT {
        return Err(Error::Limit("RPC response"));
    }
    if !response.status().is_success() {
        let mut error: RemoteError = serde_json::from_slice(response.body())
            .map_err(|_| Error::Invalid("Connect error JSON"))?;
        error.status = response.status().as_u16();
        error.headers = response.headers().clone();
        return Err(Error::Remote(Box::new(error)));
    }
    if response.status() != http::StatusCode::OK
        || response.headers().get("content-type") != content_type.as_ref()
        || response
            .headers()
            .get("content-encoding")
            .is_some_and(|v| v != "identity")
        || response
            .headers()
            .get("connect-content-encoding")
            .is_some_and(|v| v != "identity")
    {
        return Err(Error::Invalid("Connect response status/encoding"));
    }
    let (parts, body) = response.into_parts();
    Ok((body, parts.headers))
}

pub(crate) fn pending_delay(error: &RemoteError) -> Option<Duration> {
    if error.code != "unavailable" {
        return None;
    }
    let mut details = error.details.iter().filter(|detail| {
        detail
            .type_url
            .strip_prefix("type.googleapis.com/")
            .unwrap_or(&detail.type_url)
            == "mkit.transport.v1.PendingVerification"
    });
    let detail = details.next()?;
    if details.next().is_some() {
        return None;
    }
    let bytes = STANDARD_NO_PAD
        .decode(detail.value.as_deref()?)
        .or_else(|_| STANDARD.decode(detail.value.as_deref().unwrap_or_default()))
        .ok()?;
    let pending = crate::proto::PendingVerification::decode_from_slice(&bytes).ok()?;
    let hint = u64::from(pending.retry_after_ms.unwrap_or(0)).clamp(1000, 60_000);
    let header = error
        .headers
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0)
        .saturating_mul(1000)
        .clamp(1000, 60_000);
    Some(Duration::from_millis(hint.max(header)))
}

fn to_hex_bytes(bytes: &[u8]) -> String {
    mkit_core::hash::to_hex_bytes(bytes)
}
fn framed(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    let mut body = Vec::new();
    frame(&mut body, bytes)?;
    Ok(body)
}
fn frame(body: &mut Vec<u8>, bytes: &[u8]) -> Result<(), Error> {
    body.push(0);
    body.extend_from_slice(
        &u32::try_from(bytes.len())
            .map_err(|_| Error::Limit("Connect frame"))?
            .to_be_bytes(),
    );
    body.extend_from_slice(bytes);
    Ok(())
}

fn decode_stream(bytes: &[u8]) -> Result<Vec<&[u8]>, Error> {
    let mut frames = Vec::new();
    let mut rest = bytes;
    while !rest.is_empty() {
        if rest.len() < 5 {
            return Err(Error::Invalid("Connect frame header"));
        }
        let flag = rest[0];
        let len = u32::from_be_bytes(
            rest[1..5]
                .try_into()
                .map_err(|_| Error::Invalid("Connect frame size"))?,
        ) as usize;
        let frame = rest
            .get(5..5_usize.saturating_add(len))
            .ok_or(Error::Invalid("truncated Connect frame"))?;
        rest = &rest[5 + len..];
        match flag {
            0 => frames.push(frame),
            2 if rest.is_empty() => {
                let end: serde_json::Value = serde_json::from_slice(frame)
                    .map_err(|_| Error::Invalid("Connect end JSON"))?;
                if let Some(error) = end.get("error") {
                    return Err(Error::Remote(Box::new(
                        serde_json::from_value(error.clone())
                            .map_err(|_| Error::Invalid("Connect end error"))?,
                    )));
                }
                return Ok(frames);
            }
            _ => return Err(Error::Invalid("Connect frame flags/order")),
        }
    }
    Err(Error::Invalid("missing Connect end frame"))
}

#[cfg(test)]
mod tests;
