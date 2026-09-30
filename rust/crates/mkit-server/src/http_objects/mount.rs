//! Read-only mount policy shared by the native and Workers adapters.
use super::{HttpBody, HttpObjectResponse};
use crate::pipeline::ADMISSION_EXPOSE_HEADERS;
use crate::url_token::{UrlTokenConfig, UrlTokenConfigError};

/// Public key document, outside repository bearer and admission gates.
pub const KEY_PATH: &str = "/.well-known/mkit-url-token-keys.json";

/// Explicit adapter opt-in. Indexed and HTTP pipeline configuration are also required.
#[derive(Debug, Clone, Default)]
pub struct HttpMountOptions {
    /// Allowed origins, compared exactly; empty permits every origin with `*`.
    pub cors_origins: Vec<String>,
}

/// Apply SPEC-HTTP-OBJECTS §8 to every response, including adapter failures.
pub fn apply_cors(
    response: &mut HttpObjectResponse,
    origin: Option<&str>,
    opts: &HttpMountOptions,
) {
    response
        .headers
        .retain(|(name, _)| !name.to_ascii_lowercase().starts_with("access-control-"));
    if opts.cors_origins.is_empty() {
        response
            .headers
            .push(("Access-Control-Allow-Origin", "*".into()));
    } else {
        let mut vary = Vec::new();
        response.headers.retain(|(name, value)| {
            if name.eq_ignore_ascii_case("Vary") {
                vary.extend(
                    value
                        .split(',')
                        .map(str::trim)
                        .filter(|v| !v.is_empty())
                        .map(str::to_owned),
                );
                false
            } else {
                true
            }
        });
        if !vary
            .iter()
            .any(|value| value.eq_ignore_ascii_case("Origin") || value == "*")
        {
            vary.push("Origin".into());
        }
        response.headers.push(("Vary", vary.join(", ")));
        if let Some(origin) =
            origin.filter(|o| opts.cors_origins.iter().any(|allowed| allowed == o))
        {
            response
                .headers
                .push(("Access-Control-Allow-Origin", origin.into()));
        }
    }
    response
        .headers
        .push(("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS".into()));
    response.headers.push(("Access-Control-Allow-Headers", "Range, If-None-Match, If-Range, Payment-Authorization, PAYMENT-SIGNATURE, Authorization, Accept-Payment".into()));
    let mut expose = "ETag, Content-Range, Accept-Ranges, Content-Length, X-Mkit-Commit, X-Mkit-Object, X-Mkit-Object-Type, WWW-Authenticate, Payment-Receipt, PAYMENT-REQUIRED, PAYMENT-RESPONSE, Link".to_owned();
    for header in ADMISSION_EXPOSE_HEADERS {
        if !expose
            .split(',')
            .any(|existing| existing.trim().eq_ignore_ascii_case(header))
        {
            expose.push_str(", ");
            expose.push_str(header);
        }
    }
    response
        .headers
        .push(("Access-Control-Expose-Headers", expose));
}

/// Serve active and retained public keys without any bearer or payment check.
#[must_use]
pub fn key_document(config: &UrlTokenConfig, method: &str) -> HttpObjectResponse {
    match method {
        "OPTIONS" => HttpObjectResponse::new(204).with_header("Allow", "GET, HEAD, OPTIONS"),
        "GET" | "HEAD" => {
            let json = config.keys().key_set_json(config.ttl_ms());
            let mut response = HttpObjectResponse::new(200)
                .with_header("Content-Type", "application/json")
                .with_header("Cache-Control", "public, max-age=300")
                .with_header("Content-Length", json.len().to_string());
            if method == "GET" {
                response.body = HttpBody::Bytes(json.into());
            }
            response
        }
        _ => HttpObjectResponse::error(405).with_header("Allow", "GET, HEAD, OPTIONS"),
    }
}

/// Reject active or retained token keys reused by another deployment role.
///
/// # Errors
/// `Keys` on any public-key collision. No seed material is exported.
pub fn check_key_separation(
    config: &UrlTokenConfig,
    others: &[[u8; 32]],
) -> Result<(), UrlTokenConfigError> {
    if config
        .keys()
        .public_keys()
        .any(|public| others.contains(&public))
    {
        Err(UrlTokenConfigError::Keys)
    } else {
        Ok(())
    }
}
