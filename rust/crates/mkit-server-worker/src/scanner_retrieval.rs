//! Default-off private raw-pack retrieval; never enters Workers Caching.
use std::sync::Arc;

use crate::adapter::{ConfigError, WorkerConfig};
#[cfg(any(target_arch = "wasm32", test))]
use mkit_server::scanner_retrieval::RetrievalResponse;
use mkit_server::scanner_retrieval::{PATH, RetrievalConfig};

/// Dedicated retrieval MAC key secret; scanner public keys are `SCANNER_KEYS`.
pub const KEYS_SECRET: &str = "SCANNER_RETRIEVAL_KEYS";

/// Parse the opt-in and its complete configuration.
/// # Errors
/// Missing keys, conflicting settings, or retrieval outside the launch profile.
pub fn parse(
    var: &impl Fn(&str) -> Option<String>,
    indexed: bool,
    inspecting: bool,
) -> Result<Option<Arc<RetrievalConfig>>, ConfigError> {
    let enabled = match var("SCANNER_RETRIEVAL").as_deref() {
        None | Some("false") => false,
        Some("true") => true,
        _ => {
            return Err(ConfigError(
                "SCANNER_RETRIEVAL must be true or false".into(),
            ));
        }
    };
    let keys = zeroize::Zeroizing::new(var(KEYS_SECRET));
    let scanners = var("SCANNER_KEYS");
    if !enabled {
        if keys.is_some() || scanners.is_some() {
            return Err(ConfigError(
                "scanner keys require SCANNER_RETRIEVAL=true".into(),
            ));
        }
        return Ok(None);
    }
    if !cfg!(feature = "test-faults") && var("LAUNCH_PROFILE").as_deref() != Some("paid-workers") {
        return Err(ConfigError(
            "scanner retrieval requires LAUNCH_PROFILE=paid-workers".into(),
        ));
    }
    if !indexed
        || !inspecting
        || !var("WORKERS_PLAN").is_some_and(|p| p.trim().eq_ignore_ascii_case("paid"))
    {
        return Err(ConfigError(
            "scanner retrieval requires Paid indexed inspection".into(),
        ));
    }
    let config = RetrievalConfig::parse(
        keys.as_deref()
            .ok_or_else(|| ConfigError("SCANNER_RETRIEVAL_KEYS is required".into()))?,
        scanners
            .as_deref()
            .ok_or_else(|| ConfigError("SCANNER_KEYS is required".into()))?,
    )
    .map_err(|_| ConfigError("scanner retrieval keys are invalid".into()))?;
    Ok(Some(Arc::new(config)))
}

/// Exact path matching keeps retrieval off the Connect and HTTP object mounts.
#[must_use]
pub fn mounted(path: &str, cfg: &WorkerConfig) -> bool {
    cfg.scanner_retrieval.is_some() && path == PATH
}

pub(crate) fn check_hook_seed(
    config: &RetrievalConfig,
    key: Option<&str>,
) -> Result<(), ConfigError> {
    if let Some(seed) = key
        .and_then(|text| {
            text.lines()
                .map(str::trim)
                .find(|line| !line.is_empty() && !line.starts_with('#'))
        })
        .and_then(|line| line.split_whitespace().nth(1))
    {
        let seed = zeroize::Zeroizing::new(
            mkit_core::hash::from_hex(seed)
                .map_err(|_| ConfigError("MKIT_HOOK_KEY is invalid".into()))?,
        );
        config
            .check_secret(&seed)
            .map_err(|_| ConfigError("scanner retrieval keys must differ from hook keys".into()))?;
    }
    Ok(())
}

#[cfg(any(target_arch = "wasm32", test))]
fn reply_headers(response: &RetrievalResponse) -> Vec<(&'static str, String)> {
    let mut headers = vec![
        ("content-type", "application/octet-stream".into()),
        ("content-length", response.bytes.len().to_string()),
    ];
    if response.partial {
        headers.push((
            "content-range",
            format!(
                "bytes {}-{}/{}",
                response.start,
                response.start + response.bytes.len() as u64 - 1,
                response.total
            ),
        ));
    }
    headers
}

#[cfg(any(target_arch = "wasm32", test))]
fn append_body(body: &mut Vec<u8>, chunk: &[u8]) -> bool {
    if body.len().saturating_add(chunk.len()) > mkit_server::scanner_retrieval::MAX_REQUEST_BYTES {
        return false;
    }
    body.extend_from_slice(chunk);
    true
}

#[cfg(target_arch = "wasm32")]
pub(crate) fn not_found() -> worker::Result<worker::Response> {
    let mut response = worker::Response::from_bytes(
        br#"{"code":"not_found","message":"pack not found"}"#.to_vec(),
    )?
    .with_status(404);
    response
        .headers_mut()
        .set("content-type", "application/json")?;
    Ok(response)
}

#[cfg(target_arch = "wasm32")]
pub(crate) async fn serve<B, N, H>(
    pipe: &mkit_server::pipeline::Pipeline<B, N, H>,
    mut req: worker::Request,
) -> worker::Result<worker::Response>
where
    B: mkit_server::MultipartBlobStore,
    N: mkit_server::NamespaceStore,
    H: mkit_server::pipeline::HookSet,
{
    use futures::StreamExt;
    use mkit_server::scanner_retrieval::MAX_REQUEST_BYTES;
    if req.method() != worker::Method::Post || req.url().map_or(true, |u| u.query().is_some()) {
        return not_found();
    }
    let headers = mkit_server::auth_v2::headers_from(|name| req.headers().get(name).ok().flatten());
    let Ok(mut stream) = req.stream() else {
        return not_found();
    };
    let mut body = Vec::with_capacity(MAX_REQUEST_BYTES);
    while let Some(chunk) = stream.next().await {
        let Ok(chunk) = chunk else {
            return not_found();
        };
        if !append_body(&mut body, &chunk) {
            return not_found();
        }
    }
    let Ok(reply) = pipe.retrieve_scanner_pack(&body, &headers).await else {
        return not_found();
    };
    let headers = reply_headers(&reply);
    let mut response = worker::Response::from_bytes(reply.bytes.to_vec())?
        .with_status(if reply.partial { 206 } else { 200 })
        .with_encode_body(worker::EncodeBody::Manual);
    for (name, value) in headers {
        response.headers_mut().set(name, &value)?;
    }
    Ok(response)
}

#[cfg(test)]
mod tests;
