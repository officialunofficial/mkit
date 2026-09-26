//! A thin raw Connect client: messages from
//! `mkit_transport_connect::generated`, sent as exact bytes through
//! connectrpc's HTTP client transport. Unlike a generated client it can
//! send anything (a stream without a header, a gzip body under a
//! signature, a reused nonce), and it keeps the HTTP status of an error.

use std::sync::Arc;
use std::time::Duration;

use buffa::Message;
use bytes::Bytes;
use connectrpc::client::{ClientTransport as _, HttpClient, full_body};
use http_body_util::BodyExt as _;
use url::Url;

/// Per-request bound: generous, so a slow staging server fails a case
/// rather than hanging the run.
pub const REQUEST_TIMEOUT: Duration = Duration::from_mins(2);

/// `application/proto`: unary requests.
pub const UNARY_PROTO: &str = "application/proto";
/// `application/connect+proto`: streaming requests.
pub const STREAM_PROTO: &str = "application/connect+proto";
/// `application/json`: health checks.
pub const UNARY_JSON: &str = "application/json";

/// A `mkit.transport.v1.TransportService` procedure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rpc {
    /// `ListRefs`
    ListRefs,
    /// `ReadRef`
    ReadRef,
    /// `UpdateRef`
    UpdateRef,
    /// `AdvanceRefs`
    AdvanceRefs,
    /// `PackExists`
    PackExists,
    /// `UploadPack` (client-streaming)
    UploadPack,
    /// `DownloadPack` (server-streaming)
    DownloadPack,
}

impl Rpc {
    /// The full procedure, e.g. `/mkit.transport.v1.TransportService/ReadRef`.
    #[must_use]
    pub fn procedure(self) -> &'static str {
        match self {
            Self::ListRefs => "/mkit.transport.v1.TransportService/ListRefs",
            Self::ReadRef => "/mkit.transport.v1.TransportService/ReadRef",
            Self::UpdateRef => "/mkit.transport.v1.TransportService/UpdateRef",
            Self::AdvanceRefs => "/mkit.transport.v1.TransportService/AdvanceRefs",
            Self::PackExists => "/mkit.transport.v1.TransportService/PackExists",
            Self::UploadPack => "/mkit.transport.v1.TransportService/UploadPack",
            Self::DownloadPack => "/mkit.transport.v1.TransportService/DownloadPack",
        }
    }

    /// Whether auth v2 requires a signature.
    #[must_use]
    pub fn is_write(self) -> bool {
        matches!(self, Self::UpdateRef | Self::AdvanceRefs | Self::UploadPack)
    }
}

/// An HTTP response.
#[derive(Debug, Clone)]
pub struct Reply {
    /// HTTP status.
    pub status: u16,
    /// Response headers.
    pub headers: http::HeaderMap,
    /// The whole body.
    pub body: Bytes,
}

/// A Connect error as the client received it. Cases compare `code` (and
/// `http_status`, `details` where the spec fixes them), never `message`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcError {
    /// The Connect code, e.g. `invalid_argument`.
    pub code: String,
    /// The HTTP status (200 for an error at the end of a stream).
    pub http_status: u16,
    /// `(type, base64 value)` of each error detail.
    pub details: Vec<(String, String)>,
    /// For diagnostics only.
    pub message: String,
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} (HTTP {}): {}",
            self.code, self.http_status, self.message
        )
    }
}

/// A server-streaming or client-streaming response: the messages, then the
/// end-of-stream error, if any.
#[derive(Debug)]
pub struct StreamReply<M> {
    /// Messages before the end of the stream.
    pub messages: Vec<M>,
    /// The error the stream ended with.
    pub error: Option<RpcError>,
}

/// The raw client of one server.
#[derive(Clone)]
pub struct Client {
    http: HttpClient,
    base: Arc<str>,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("base", &self.base)
            .finish_non_exhaustive()
    }
}

/// The Connect code for an HTTP status whose body is not a Connect error
/// (the Connect protocol's HTTP-to-code table).
fn code_for_status(status: u16) -> &'static str {
    match status {
        400 => "internal",
        401 => "unauthenticated",
        403 => "permission_denied",
        404 => "unimplemented",
        429 | 502..=504 => "unavailable",
        _ => "unknown",
    }
}

/// A Connect error JSON object (a unary error body, or the `error` of an
/// end-of-stream message).
fn parse_error(json: &serde_json::Value, http_status: u16) -> Option<RpcError> {
    let code = json.get("code")?.as_str()?.to_owned();
    let details = json
        .get("details")
        .and_then(|d| d.as_array())
        .map(|details| {
            details
                .iter()
                .map(|d| {
                    let field =
                        |k: &str| d.get(k).and_then(|v| v.as_str()).unwrap_or("").to_owned();
                    (field("type"), field("value"))
                })
                .collect()
        })
        .unwrap_or_default();
    let message = json
        .get("message")
        .and_then(|m| m.as_str())
        .unwrap_or("")
        .to_owned();
    Some(RpcError {
        code,
        http_status,
        details,
        message,
    })
}

/// A non-200 response as an error: its Connect JSON body, or the status.
fn error_reply(reply: &Reply) -> RpcError {
    serde_json::from_slice(&reply.body)
        .ok()
        .and_then(|json| parse_error(&json, reply.status))
        .unwrap_or_else(|| RpcError {
            code: code_for_status(reply.status).to_owned(),
            http_status: reply.status,
            details: Vec::new(),
            message: String::from_utf8_lossy(&reply.body)
                .chars()
                .take(200)
                .collect(),
        })
}

/// One Connect envelope around `payload` (flags 0: an uncompressed message).
#[must_use]
pub fn frame(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + payload.len());
    out.push(0);
    let len = u32::try_from(payload.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// `msgs` as a Connect request stream.
#[must_use]
pub fn frames<M: Message>(msgs: &[M]) -> Vec<u8> {
    msgs.iter()
        .flat_map(|m| frame(&m.encode_to_vec()))
        .collect()
}

fn tls_config() -> Arc<connectrpc::rustls::ClientConfig> {
    // A provider may already be installed process-wide; either way one is.
    let _ = connectrpc::rustls::crypto::ring::default_provider().install_default();
    let mut roots = connectrpc::rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    Arc::new(
        connectrpc::rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

impl Client {
    /// A client of the server at `base` (`http://` or `https://`; a path
    /// prefix is kept, so a server mounted under `/vcs` works).
    ///
    /// # Errors
    /// Another scheme.
    pub fn new(base: &Url) -> Result<Self, String> {
        let http = match base.scheme() {
            "http" => HttpClient::plaintext(),
            "https" => HttpClient::with_tls(tls_config()),
            other => return Err(format!("unsupported scheme `{other}` (http, https)")),
        };
        let base = base.as_str().trim_end_matches('/');
        Ok(Self {
            http,
            base: Arc::from(base),
        })
    }

    async fn send(&self, req: http::Request<Bytes>) -> Result<Reply, String> {
        let (parts, body) = req.into_parts();
        let req = http::Request::from_parts(parts, full_body(body));
        let exchange = async {
            let resp = self
                .http
                .send(req)
                .await
                .map_err(|e| format!("request failed: {e}"))?;
            let (mut parts, body) = resp.into_parts();
            let mut body = body
                .collect()
                .await
                .map_err(|e| format!("reading the response failed: {e}"))?
                .to_bytes();
            // A unary body compressed as the request allowed.
            match parts.headers.remove("content-encoding") {
                None => {}
                Some(v) if v == "identity" => {}
                Some(v) if v == "gzip" => body = gunzip(&body)?.into(),
                Some(v) => return Err(format!("unrequested Content-Encoding {v:?}")),
            }
            Ok(Reply {
                status: parts.status.as_u16(),
                headers: parts.headers,
                body,
            })
        };
        tokio::time::timeout(REQUEST_TIMEOUT, exchange)
            .await
            .map_err(|_| format!("no response within {REQUEST_TIMEOUT:?}"))?
    }

    /// `POST {base}{path}` with `body` as sent, plus
    /// `Connect-Protocol-Version: 1` and, as a stock Connect client sends
    /// them, `Accept-Encoding: gzip` (unary) or
    /// `Connect-Accept-Encoding: gzip` (streaming).
    ///
    /// # Errors
    /// A transport failure or timeout (not an HTTP error status).
    pub async fn post(
        &self,
        path: &str,
        content_type: &str,
        headers: &[(String, String)],
        body: Vec<u8>,
    ) -> Result<Reply, String> {
        let mut req = http::Request::post(format!("{}{path}", self.base))
            .header("content-type", content_type)
            .header("connect-protocol-version", "1");
        let accept = if content_type.starts_with("application/connect+") {
            "connect-accept-encoding"
        } else {
            "accept-encoding"
        };
        if !headers.iter().any(|(n, _)| n.eq_ignore_ascii_case(accept)) {
            req = req.header(accept, "gzip");
        }
        for (name, value) in headers {
            req = req.header(name.as_str(), value.as_str());
        }
        let req = req
            .body(Bytes::from(body))
            .map_err(|e| format!("building the request failed: {e}"))?;
        self.send(req).await
    }

    /// `GET {base}{path}`.
    ///
    /// # Errors
    /// A transport failure or timeout.
    pub async fn get(&self, path: &str) -> Result<Reply, String> {
        let req = http::Request::get(format!("{}{path}", self.base))
            .body(Bytes::new())
            .map_err(|e| format!("building the request failed: {e}"))?;
        self.send(req).await
    }

    /// A unary call with the exact encoded `body`: the decoded response, or
    /// the Connect error.
    ///
    /// # Errors
    /// Transport failure, or a 200 response that does not decode.
    pub async fn unary<M: Message>(
        &self,
        rpc: Rpc,
        body: Vec<u8>,
        headers: &[(String, String)],
    ) -> Result<Result<M, RpcError>, String> {
        let reply = self
            .post(rpc.procedure(), UNARY_PROTO, headers, body)
            .await?;
        decode_unary(&reply)
    }

    /// A streaming call with an already framed `body`.
    ///
    /// # Errors
    /// Transport failure, or a response that breaks Connect stream framing.
    pub async fn stream<M: Message>(
        &self,
        rpc: Rpc,
        body: Vec<u8>,
        headers: &[(String, String)],
    ) -> Result<StreamReply<M>, String> {
        let reply = self
            .post(rpc.procedure(), STREAM_PROTO, headers, body)
            .await?;
        decode_stream(&reply)
    }
}

/// Inflate one gzip member.
fn gunzip(data: &[u8]) -> Result<Vec<u8>, String> {
    use std::io::Read as _;
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(data)
        .read_to_end(&mut out)
        .map_err(|e| format!("undecodable gzip response: {e}"))?;
    Ok(out)
}

/// A unary reply: `M` on 200, else the Connect error.
///
/// # Errors
/// A 200 body that is not an `M`.
pub fn decode_unary<M: Message>(reply: &Reply) -> Result<Result<M, RpcError>, String> {
    if reply.status != 200 {
        return Ok(Err(error_reply(reply)));
    }
    M::decode_from_slice(&reply.body)
        .map(Ok)
        .map_err(|e| format!("undecodable 200 response: {e}"))
}

/// A Connect streaming reply: messages, then exactly one end-of-stream
/// message. A non-200 reply is an error before any message.
///
/// # Errors
/// Broken framing, a compressed frame without a negotiated encoding, a message
/// after the end of the stream, or no end of stream.
pub fn decode_stream<M: Message>(reply: &Reply) -> Result<StreamReply<M>, String> {
    if reply.status != 200 {
        return Ok(StreamReply {
            messages: Vec::new(),
            error: Some(error_reply(reply)),
        });
    }
    let gzip = match reply.headers.get("connect-content-encoding") {
        None => false,
        Some(v) if v == "identity" => false,
        Some(v) if v == "gzip" => true,
        Some(v) => return Err(format!("unrequested Connect-Content-Encoding {v:?}")),
    };
    let mut rest = &reply.body[..];
    let mut messages = Vec::new();
    while rest.len() >= 5 {
        let flags = rest[0];
        let len = u32::from_be_bytes([rest[1], rest[2], rest[3], rest[4]]) as usize;
        let payload = rest.get(5..5 + len).ok_or("truncated stream frame")?;
        rest = &rest[5 + len..];
        let inflated;
        let payload = if flags & 0x01 == 0 {
            payload
        } else if gzip {
            inflated = gunzip(payload)?;
            &inflated[..]
        } else {
            return Err("compressed frame, but no compression was negotiated".to_owned());
        };
        if flags & 0x02 != 0 {
            if !rest.is_empty() {
                return Err("bytes after the end-of-stream message".to_owned());
            }
            let json: serde_json::Value = serde_json::from_slice(payload)
                .map_err(|e| format!("end-of-stream message is not JSON: {e}"))?;
            let error = match json.get("error") {
                None => None,
                Some(e) => Some(parse_error(e, 200).ok_or("end-of-stream error without a code")?),
            };
            return Ok(StreamReply { messages, error });
        }
        messages
            .push(M::decode_from_slice(payload).map_err(|e| format!("undecodable message: {e}"))?);
    }
    Err("stream ended without an end-of-stream message".to_owned())
}

#[cfg(test)]
mod tests {
    use mkit_transport_connect::generated::PackExistsResponse;

    use super::*;

    fn reply(status: u16, body: &[u8]) -> Reply {
        Reply {
            status,
            headers: http::HeaderMap::new(),
            body: Bytes::copy_from_slice(body),
        }
    }

    #[test]
    fn unary_errors_keep_code_status_and_details() {
        let body = br#"{"code":"permission_denied","message":"pay","details":[{"type":"t.D","value":"AQ"}]}"#;
        let err = decode_unary::<PackExistsResponse>(&reply(402, body))
            .unwrap()
            .unwrap_err();
        assert_eq!(err.code, "permission_denied");
        assert_eq!(err.http_status, 402);
        assert_eq!(err.details, [("t.D".to_owned(), "AQ".to_owned())]);
        let raw = decode_unary::<PackExistsResponse>(&reply(401, b"nope")).unwrap();
        assert_eq!(raw.unwrap_err().code, "unauthenticated");
    }

    #[test]
    fn stream_framing_is_checked() {
        let msg = PackExistsResponse {
            exists: Some(true),
            ..Default::default()
        };
        let mut body = frame(&msg.encode_to_vec());
        let end = br#"{"error":{"code":"not_found"}}"#;
        body.push(2);
        body.extend_from_slice(&u32::try_from(end.len()).unwrap().to_be_bytes());
        body.extend_from_slice(end);
        let got = decode_stream::<PackExistsResponse>(&reply(200, &body)).unwrap();
        assert_eq!(got.messages.len(), 1);
        assert_eq!(got.error.unwrap().code, "not_found");
        // No end of stream; a truncated frame; a compressed frame.
        let msgs = frame(&msg.encode_to_vec());
        assert!(decode_stream::<PackExistsResponse>(&reply(200, &msgs)).is_err());
        assert!(decode_stream::<PackExistsResponse>(&reply(200, &body[..body.len() - 1])).is_err());
        let mut compressed = msgs;
        compressed[0] = 1;
        assert!(decode_stream::<PackExistsResponse>(&reply(200, &compressed)).is_err());
        // A gzip frame under a negotiated `Connect-Content-Encoding`.
        let gz = {
            use std::io::Write as _;
            let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
            enc.write_all(&msg.encode_to_vec()).unwrap();
            enc.finish().unwrap()
        };
        let mut body = frame(&gz);
        body[0] = 1;
        body.extend_from_slice(&[2, 0, 0, 0, 2]);
        body.extend_from_slice(b"{}");
        let mut negotiated = reply(200, &body);
        negotiated.headers.insert(
            "connect-content-encoding",
            http::HeaderValue::from_static("gzip"),
        );
        let got = decode_stream::<PackExistsResponse>(&negotiated).unwrap();
        assert_eq!(got.messages[0].exists, Some(true));
    }
}
