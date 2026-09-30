//! Signed operator API (§16), durable replay and a gapless audit chain.
//!
//! Adapters call [`precheck`] before reading a body, hash wire bytes with
//! [`BodyCapture`], then dispatch through [`Engine`]. No keys means no routes.
//! All ledgers and accepted purge work share one deployment partition; a CAS
//! on the audit head commits acceptance, audit and replay before success.

mod auth;
mod automatic;
mod ledger;
#[cfg(test)]
mod tests;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};

use crate::{Code, NamespaceStore, Partition, ServerError};

pub use auth::{Config, HEADER_NAMES};
pub use automatic::{AuditRelayHook, AuditReserveHook, SystemAudit, extend_audit_batch};
pub use ledger::{OperationReplay, plan_operation, plan_system};

/// Canonical admin path prefix; never rewrite paths before verification.
pub const PREFIX: &str = "/mkit.server.admin.v1.AdminService/";
/// Canonical manual purge procedure.
pub const PURGE_PATH: &str = "/mkit.server.admin.v1.AdminService/PurgeCache";
/// Canonical audit export procedure.
pub const AUDIT_PATH: &str = "/mkit.server.admin.v1.AdminService/ReadAuditLog";
/// Maximum admin body size, both on the wire and decoded.
pub const MAX_BODY: usize = 1_048_576;
/// Adapter headers, preserving duplicates and the original values.
pub type Headers = Vec<(String, String)>;

/// Incrementally hashes the complete wire body while retaining at most 1 MiB.
#[derive(Clone, Debug)]
pub struct BodyCapture {
    hasher: blake3::Hasher,
    bytes: Vec<u8>,
    oversized: bool,
}

impl Default for BodyCapture {
    fn default() -> Self {
        Self {
            hasher: blake3::Hasher::new(),
            bytes: Vec::new(),
            oversized: false,
        }
    }
}
impl BodyCapture {
    /// Add raw HTTP bytes, including Connect framing and compressed bytes.
    pub fn push(&mut self, chunk: &[u8]) {
        self.hasher.update(chunk);
        let room = MAX_BODY.saturating_sub(self.bytes.len());
        self.bytes
            .extend_from_slice(&chunk[..room.min(chunk.len())]);
        self.oversized |= chunk.len() > room;
    }
    /// Exact wire-body digest in the signed envelope's canonical form.
    #[must_use]
    pub fn digest(&self) -> String {
        format!("body:{}", self.hasher.finalize().to_hex())
    }
}

/// A bounded raw Connect response, shared by the native and Workers adapters.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Response {
    /// HTTP status, including the Connect error mapping.
    pub status: u16,
    /// JSON unary or Connect JSON streaming content type.
    pub content_type: String,
    /// Exact response bytes. Stored replay results preserve these bytes.
    #[serde(with = "encoded_bytes")]
    pub body: Vec<u8>,
}
impl Response {
    /// A Connect unary error response.
    #[must_use]
    pub fn error(error: &ServerError) -> Self {
        let status = match error.code() {
            Code::Unauthenticated => 401,
            Code::PermissionDenied => 403,
            Code::NotFound => 404,
            Code::Aborted => 409,
            Code::Unavailable => 503,
            Code::Unimplemented => 501,
            Code::Internal | Code::DataLoss => 500,
            _ => 400,
        };
        Self { status, content_type: "application/json".into(), body: serde_json::json!({"code": error.code().as_str(), "message": error.public_message()}).to_string().into_bytes() }
    }
    pub(crate) fn json(value: &serde_json::Value) -> Self {
        Self {
            status: 200,
            content_type: "application/json".into(),
            body: value.to_string().into_bytes(),
        }
    }
    pub(crate) fn stream(value: &serde_json::Value) -> Result<Self, ServerError> {
        let mut body = Vec::new();
        for (flags, bytes) in [
            (0u8, value.to_string().into_bytes()),
            (2, b"{\"metadata\":{}}".to_vec()),
        ] {
            let len = u32::try_from(bytes.len())
                .map_err(|_| ServerError::new(Code::Internal, "admin response overflow"))?;
            body.push(flags);
            body.extend_from_slice(&len.to_be_bytes());
            body.extend(bytes);
        }
        Ok(Self {
            status: 200,
            content_type: "application/connect+json".into(),
            body,
        })
    }
}

/// Check mixed credentials and the eight single-value headers before body I/O.
///
/// # Errors
/// A ready-to-send Connect response for invalid or unauthenticated headers.
pub fn precheck(headers: &Headers) -> Result<(), Response> {
    auth::check_headers(headers).map_err(|e| Response::error(&e))
}

/// Durable admin service over one deployment-wide metadata partition.
#[derive(Debug)]
pub struct Engine<S> {
    store: S,
    partition: Partition,
    config: Config,
}
impl<S: NamespaceStore> Engine<S> {
    /// Build the signed audit export framework.
    pub fn new(store: S, partition: Partition, config: Config) -> Self {
        Self {
            store,
            partition,
            config,
        }
    }
    /// Dispatch exact signed bytes. Adapters must reject decompression errors
    /// through `decoded` after authentication, preserving authenticated audit.
    pub async fn handle(
        &self,
        path: &str,
        headers: &Headers,
        body: &BodyCapture,
        now_ms: i64,
    ) -> Response {
        self.handle_decoded(path, headers, body, None, now_ms).await
    }
    /// Dispatch with separately decompressed request bytes; the signature always
    /// covers `wire`. An error is recorded only after identity verification.
    pub async fn handle_decoded(
        &self,
        path: &str,
        headers: &Headers,
        wire: &BodyCapture,
        decoded: Option<Result<Vec<u8>, ServerError>>,
        now_ms: i64,
    ) -> Response {
        match self.dispatch(path, headers, wire, decoded, now_ms).await {
            Ok(response) => response,
            Err(error) => Response::error(&error),
        }
    }
}

fn payload<'a>(path: &str, bytes: &'a [u8]) -> Result<&'a [u8], ServerError> {
    if path != AUDIT_PATH {
        return Ok(bytes);
    }
    if bytes.len() < 5 || bytes[0] != 0 {
        return Err(auth::invalid("invalid Connect admin envelope"));
    }
    let length = u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as usize;
    if length != bytes.len() - 5 {
        return Err(auth::invalid("invalid Connect admin envelope length"));
    }
    Ok(&bytes[5..])
}

mod encoded_bytes {
    use super::*;
    pub(super) fn serialize<S: serde::Serializer>(
        bytes: &[u8],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }
    pub(super) fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<u8>, D::Error> {
        STANDARD
            .decode(String::deserialize(deserializer)?)
            .map_err(serde::de::Error::custom)
    }
}
