//! Optional grant-scoped MKWB read over the existing signed Connect HTTP client.
//! This is deliberately not a method on the portable `Transport` trait.

use bytes::Bytes;
use connectrpc::client::{ClientTransport, full_body};
use http::{Method, Request, header};
use http_body_util::BodyExt;
use mkit_core::{
    hash::{Hash, to_hex},
    partial::{
        PartialError, PartialLimits, PartialPath, PartialSnapshotBuilder, VerifiedPartialSnapshot,
        verify_partial_snapshot,
    },
    protocol::async_shim::Executor as _,
    refs::validate_ref_name,
};
use serde::Serialize;

use crate::ConnectTransport;

const PATH: &str = "/mkit/partial/v1/GetWorkspace";
const MAX_BODY: usize = 4 * 1024 * 1024;

/// Exact registered grant and locally chosen selection, never a hash-fetch URL.
#[derive(Debug, Clone)]
pub struct HostedWorkspaceRequest {
    pub workspace_id: String,
    pub grant_id: String,
    pub grant_generation: String,
    pub expected_ref: String,
    pub expected_base: Hash,
    pub paths: Vec<PartialPath>,
}

/// Verified portable bundle bytes; the CLI installs these exact bytes.
#[derive(Debug)]
pub struct VerifiedHostedBundle {
    bytes: Vec<u8>,
    verified: VerifiedPartialSnapshot,
}
impl VerifiedHostedBundle {
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    #[must_use]
    pub fn verified(&self) -> &VerifiedPartialSnapshot {
        &self.verified
    }
}

/// Host-only failure classes. No error is an invitation to try public fetch.
#[derive(Debug)]
pub enum HostedReadError {
    AuthRequired,
    UntrustedEndpoint,
    InvalidRequest,
    AccessDenied,
    Conflict,
    UnsupportedProfile,
    ResourceExhausted,
    Unavailable,
    InvalidResponse,
    Verification(PartialError),
}
impl std::fmt::Display for HostedReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for HostedReadError {}

#[derive(Serialize)]
struct Wire<'a> {
    version: u8,
    workspace_id: &'a str,
    grant_id: &'a str,
    grant_generation: &'a str,
    expected_ref: &'a str,
    expected_base: String,
    paths: Vec<Vec<&'a str>>,
}

/// Resource subset for the initial managed native profile.
#[must_use]
pub fn hosted_partial_limits() -> PartialLimits {
    PartialLimits {
        max_bundle_bytes: MAX_BODY,
        max_witness_bytes: 1024 * 1024,
        max_total_selected_bytes: 1024 * 1024,
        max_selected_file_bytes: 256 * 1024,
        max_objects: 2_048,
        max_tree_visits: 2_048,
        max_base_object_bytes: 2 * 1024 * 1024,
        max_tree_object_bytes: 2 * 1024 * 1024,
        max_object_bytes: 2 * 1024 * 1024,
        ..PartialLimits::V1
    }
}

fn wire_body<'a>(request: &'a HostedWorkspaceRequest) -> Result<Vec<u8>, HostedReadError> {
    let canonical_id = |value: &str| {
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    };
    if !canonical_id(&request.workspace_id)
        || !canonical_id(&request.grant_id)
        || request
            .grant_generation
            .parse::<u64>()
            .ok()
            .filter(|n| *n > 0)
            .is_none_or(|n| n.to_string() != request.grant_generation)
        || !request.expected_ref.starts_with("refs/heads/")
        || !validate_ref_name(&request.expected_ref)
    {
        return Err(HostedReadError::InvalidRequest);
    }
    let paths = request
        .paths
        .iter()
        .map(|path| {
            path.iter()
                .map(|part| std::str::from_utf8(part).map_err(|_| HostedReadError::InvalidRequest))
                .collect::<Result<Vec<_>, _>>()
        })
        .collect::<Result<Vec<_>, _>>()?;
    let wire = Wire {
        version: 1,
        workspace_id: &request.workspace_id,
        grant_id: &request.grant_id,
        grant_generation: &request.grant_generation,
        expected_ref: &request.expected_ref,
        expected_base: to_hex(&request.expected_base),
        paths,
    };
    let bytes = serde_json::to_vec(&wire).map_err(|_| HostedReadError::InvalidRequest)?;
    if bytes.len() > 256 * 1024 {
        return Err(HostedReadError::InvalidRequest);
    }
    Ok(bytes)
}

impl ConnectTransport {
    /// One signed request, no redirect, retry, legacy fallback or full-pack read.
    pub fn get_hosted_workspace(
        &self,
        request: &HostedWorkspaceRequest,
        expected_base: Hash,
        expected_paths: &[PartialPath],
        limits: &PartialLimits,
    ) -> Result<VerifiedHostedBundle, HostedReadError> {
        let signer = self
            .signed_reads
            .as_ref()
            .ok_or(HostedReadError::AuthRequired)?;
        if request.expected_base != expected_base || request.paths != expected_paths {
            return Err(HostedReadError::InvalidRequest);
        }
        if !limits.is_v1_subset() || limits.max_bundle_bytes > MAX_BODY {
            return Err(HostedReadError::UnsupportedProfile);
        }
        PartialSnapshotBuilder::new(expected_base, expected_paths, limits)
            .map_err(|_| HostedReadError::InvalidRequest)?;
        let body = wire_body(request)?;
        let signed = signer
            .hosted_headers(&body)
            .map_err(|_| HostedReadError::AuthRequired)?;
        let base_uri = self.host_uri.to_string();
        let uri = format!("{}{PATH}", base_uri.trim_end_matches('/'));
        let mut request = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/octet-stream")
            .body(full_body(Bytes::from(body)))
            .map_err(|_| HostedReadError::InvalidRequest)?;
        request.headers_mut().extend(signed);
        let client = self.host_http.clone();
        // Raw HttpClient does not inherit Connect CallOptions. One overall
        // deadline covers the header wait and every response-body frame.
        let timeout = self.pack_transfer_timeout;
        let bytes = self.executor.block_on(async move {
            tokio::time::timeout(timeout, async move {
                let response = client
                    .send(request)
                    .await
                    .map_err(|_| HostedReadError::Unavailable)?;
                let status = response.status().as_u16();
                if status != 200 {
                    return Err(match status {
                        401 => HostedReadError::AuthRequired,
                        403 | 404 => HostedReadError::AccessDenied,
                        409 => HostedReadError::Conflict,
                        413 | 429 => HostedReadError::ResourceExhausted,
                        422 => HostedReadError::UnsupportedProfile,
                        500..=599 => HostedReadError::Unavailable,
                        _ => HostedReadError::InvalidResponse,
                    });
                }
                let headers = response.headers();
                if headers.get_all(header::CONTENT_TYPE).iter().count() != 1
                    || headers.get_all(header::CONTENT_LENGTH).iter().count() != 1
                {
                    return Err(HostedReadError::InvalidResponse);
                }
                if headers
                    .get(header::CONTENT_TYPE)
                    .and_then(|h| h.to_str().ok())
                    != Some("application/octet-stream")
                    || headers.get(header::CONTENT_ENCODING).is_some()
                {
                    return Err(HostedReadError::InvalidResponse);
                }
                let advertised = headers
                    .get(header::CONTENT_LENGTH)
                    .and_then(|h| h.to_str().ok())
                    .ok_or(HostedReadError::InvalidResponse)?
                    .parse::<usize>()
                    .map_err(|_| HostedReadError::InvalidResponse)?;
                if advertised > MAX_BODY || advertised > limits.max_bundle_bytes {
                    return Err(HostedReadError::ResourceExhausted);
                }
                let mut incoming = response.into_body();
                let mut bytes = Vec::new();
                while let Some(frame) = incoming.frame().await {
                    let frame = frame.map_err(|_| HostedReadError::Unavailable)?;
                    let data = frame
                        .into_data()
                        .map_err(|_| HostedReadError::InvalidResponse)?;
                    if data.len() > advertised.saturating_sub(bytes.len()) {
                        return Err(HostedReadError::InvalidResponse);
                    }
                    bytes.extend_from_slice(&data);
                }
                if bytes.len() != advertised {
                    return Err(HostedReadError::InvalidResponse);
                }
                Ok(bytes)
            })
            .await
            .map_err(|_| HostedReadError::Unavailable)?
        })?;
        let verified = verify_partial_snapshot(expected_base, expected_paths, &bytes, limits)
            .map_err(HostedReadError::Verification)?;
        Ok(VerifiedHostedBundle { bytes, verified })
    }
}
