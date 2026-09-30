//! Explicit Stage 2 HTTP mounting. Environment configuration never opts in.

use mkit_server::http_objects::HttpObjectsConfig;
use mkit_server::http_objects::mount::HttpMountOptions;
use mkit_server::indexed::IndexedConfig;
use mkit_server::url_token::{UrlTokenConfig, UrlTokenKeys};

use crate::adapter::ConfigError;

/// A programmatic indexed deployment with an explicit HTTP mount.
#[derive(Clone, Debug)]
pub struct WorkerHttpMountConfig {
    /// Explicit indexed configuration; the environment's `INDEXED_MODE` remains refused.
    pub indexed: IndexedConfig,
    /// Explicit HTTP configuration, including optional read admission.
    pub http_objects: HttpObjectsConfig,
    /// Read CORS origins.
    pub options: HttpMountOptions,
    /// Retains paid-read settlement using the request lifetime (normally `wait_until`).
    pub read_runtime: Option<mkit_server::http_objects::HttpReadRuntime>,
}

/// Parse the feature-gated token secrets without enabling routes or indexed mode.
/// Errors identify a setting and never expose its value.
///
/// # Errors
/// Invalid keys, a TTL outside the token limits, or TTL without keys.
pub fn token_config(
    var: &impl Fn(&str) -> Option<String>,
) -> Result<Option<UrlTokenConfig>, ConfigError> {
    let keys = var("URL_TOKEN_KEYS");
    let ttl = var("URL_TOKEN_TTL");
    let Some(keys) = keys else {
        return if ttl.is_some() {
            Err(ConfigError("URL_TOKEN_TTL requires URL_TOKEN_KEYS".into()))
        } else {
            Ok(None)
        };
    };
    let keys = UrlTokenKeys::parse_key_file_secret(keys)
        .map_err(|_| ConfigError("URL_TOKEN_KEYS is invalid".into()))?;
    let tokens = match ttl {
        None => UrlTokenConfig::new(keys),
        Some(ttl) => {
            let ttl_ms = ttl
                .parse::<u64>()
                .ok()
                .filter(|seconds| seconds.to_string() == ttl)
                .and_then(|seconds| seconds.checked_mul(1000))
                .ok_or_else(|| ConfigError("URL_TOKEN_TTL is invalid".into()))?;
            UrlTokenConfig::with_ttl_ms(keys, ttl_ms)
                .map_err(|_| ConfigError("URL_TOKEN_TTL is invalid".into()))?
        }
    };
    Ok(Some(tokens))
}

/// Parse tokens and enforce separation from every accepted ticket secret.
pub(crate) fn token_config_for_tickets(
    var: &impl Fn(&str) -> Option<String>,
    tickets: Option<&mkit_server::upload::token::TicketKeys>,
) -> Result<Option<UrlTokenConfig>, ConfigError> {
    let tokens = token_config(var)?;
    if let (Some(tokens), Some(tickets)) = (&tokens, tickets)
        && tokens
            .keys()
            .public_keys()
            .any(|public| tickets.contains_ed25519_public(&public))
    {
        return Err(ConfigError(
            "URL_TOKEN_KEYS must differ from TICKET_KEYS".into(),
        ));
    }
    Ok(tokens)
}

/// Split the runtime's already-serialized URL without decoding or reparsing it.
/// An empty query stays Some(""). No error contains URL text.
///
/// # Errors
/// A URL without a scheme/authority or with a fragment.
pub fn raw_path_query(url: &str) -> Result<(&str, Option<&str>), ConfigError> {
    let authority = url
        .find("://")
        .map(|at| at + 3)
        .ok_or_else(|| ConfigError("invalid request URL".into()))?;
    let suffix = url[authority..]
        .find(['/', '?', '#'])
        .map_or("/", |at| &url[authority + at..]);
    if suffix.contains('#') {
        return Err(ConfigError("invalid request URL".into()));
    }
    let (path, query) = suffix
        .split_once('?')
        .map_or((suffix, None), |(path, query)| (path, Some(query)));
    Ok((if path.is_empty() { "/" } else { path }, query))
}

/// Suppress every HEAD body while retaining the GET representation metadata.
#[must_use]
pub fn prepare_response(
    mut response: mkit_server::http_objects::HttpObjectResponse,
    method: &str,
) -> mkit_server::http_objects::HttpObjectResponse {
    if method == "HEAD" {
        response.body = mkit_server::http_objects::HttpBody::Empty;
    }
    response
}

/// Reject unsupported methods and malformed URLs before Worker binding or hook I/O.
#[must_use]
pub fn early_object_error(
    method: &str,
    url: &str,
) -> Option<mkit_server::http_objects::HttpObjectResponse> {
    use mkit_server::http_objects::{HttpObjectResponse, RepoPrefix, parse};
    if !matches!(method, "GET" | "HEAD") {
        return Some(HttpObjectResponse::error(405).with_header("Allow", "GET, HEAD, OPTIONS"));
    }
    let invalid = !raw_path_query(url)
        .is_ok_and(|(path, query)| parse(path, query, RepoPrefix::Required).is_ok());
    invalid.then(|| HttpObjectResponse::error(400))
}

/// Convert one streamed piece at a time for Workers, redacting stream errors.
/// Creating this bridge never polls or collects the source.
#[must_use]
pub fn bridge_chunks(
    stream: mkit_server::BoxStream<'static, Result<bytes::Bytes, mkit_server::ServerError>>,
) -> mkit_server::BoxStream<'static, Result<Vec<u8>, &'static str>> {
    use futures::StreamExt as _;
    Box::pin(stream.map(|piece| {
        piece
            .map(|bytes| bytes.to_vec())
            .map_err(|_| "HTTP object stream failed")
    }))
}

/// Bridge a response through the Workers streaming runtime and read response policy.
///
/// # Errors
/// The Workers runtime rejects a stream or a response header.
#[cfg(target_arch = "wasm32")]
pub fn response_to_worker(
    response: mkit_server::http_objects::HttpObjectResponse,
    method: &str,
    origin: Option<&str>,
    options: &HttpMountOptions,
) -> worker::Result<worker::Response> {
    glue::finish(glue::bridge(response, method)?, method, origin, options)
}

#[cfg(target_arch = "wasm32")]
pub(crate) mod glue {
    use futures::StreamExt as _;
    use mkit_server::http_objects::mount::{KEY_PATH, apply_cors, key_document};
    use mkit_server::http_objects::{
        HttpBody, HttpObjectRequest, HttpObjectResponse, RedactedQuery, is_http_object_path,
    };
    use mkit_server::pipeline::{HookSet, Pipeline};
    use worker::{Request, Response};

    use super::{
        HttpMountOptions, bridge_chunks, early_object_error, prepare_response, raw_path_query,
    };
    use crate::adapter::WorkerConfig;
    use crate::ns_client::WorkerNamespaceStore;
    use crate::r2::WorkerBlobStore;

    /// Only an explicit programmatic mount can select this dispatcher.
    pub(crate) fn mounted_request(req: &Request, cfg: &WorkerConfig) -> bool {
        cfg.http_mount.is_some()
            && raw_path_query(&req.inner().url())
                .is_ok_and(|(path, _)| path == KEY_PATH || is_http_object_path(path))
    }

    /// CORS and body suppression apply even to adapter/configuration errors.
    pub(crate) fn finish(
        mut response: Response,
        method: &str,
        origin: Option<&str>,
        options: &HttpMountOptions,
    ) -> worker::Result<Response> {
        let mut headers = HttpObjectResponse::new(response.status_code());
        if response.status_code() >= 400 {
            let cache = response.headers().get("Cache-Control")?;
            let private = cache.is_some_and(|value| {
                value.split(',').any(|directive| {
                    directive
                        .split('=')
                        .next()
                        .is_some_and(|name| name.trim().eq_ignore_ascii_case("private"))
                })
            });
            headers.headers.push((
                "Cache-Control",
                if private {
                    "private, no-store"
                } else {
                    "no-store"
                }
                .into(),
            ));
        }
        if let Some(vary) = response.headers().get("Vary")? {
            headers.headers.push(("Vary", vary));
        }
        apply_cors(&mut headers, origin, options);
        // A generic Connect error's wildcard must not survive a restricted read policy.
        response
            .headers_mut()
            .delete("Access-Control-Allow-Origin")?;
        response
            .headers_mut()
            .delete("Access-Control-Allow-Credentials")?;
        for (name, value) in headers.headers {
            response.headers_mut().set(name, &value)?;
        }
        if method == "HEAD" {
            response = Response::empty()?
                .with_status(response.status_code())
                .with_headers(response.headers().clone());
        }
        Ok(response)
    }

    pub(crate) fn bridge(response: HttpObjectResponse, method: &str) -> worker::Result<Response> {
        let response = prepare_response(response, method);
        let mut output = match response.body {
            HttpBody::Empty => Response::empty()?,
            HttpBody::Bytes(bytes) => {
                Response::from_body(worker::ResponseBody::Body(bytes.to_vec()))?
            }
            HttpBody::Stream { stream, len } => {
                let source = bridge_chunks(stream)
                    .map(|piece| piece.map_err(|message| worker::Error::RustError(message.into())));
                // Workers infer Content-Length from a platform FixedLengthStream;
                // setting the header on an ordinary ReadableStream is ignored.
                let fixed: worker::worker_sys::FixedLengthStream =
                    worker::FixedLengthStream::wrap(source, len).into();
                Response::from_body(worker::ResponseBody::Stream(fixed.readable()))?
            }
        }
        .with_status(response.status)
        .with_encode_body(worker::EncodeBody::Manual);
        // Append all occurrences: Workers may combine challenge lists, preserving order.
        for (name, value) in response.headers {
            output.headers_mut().append(name, &value)?;
        }
        Ok(output)
    }

    /// The public key document and preflight precede hook/store construction.
    pub(crate) fn early(req: &Request, cfg: &WorkerConfig) -> worker::Result<Option<Response>> {
        if !mounted_request(req, cfg) {
            return Ok(None);
        }
        let method = req.method();
        let raw = req.inner().url();
        let (path, _) = raw_path_query(&raw)
            .map_err(|_| worker::Error::RustError("invalid request URL".into()))?;
        let response = if method == worker::Method::Options {
            HttpObjectResponse::new(204).with_header("Allow", "GET, HEAD, OPTIONS")
        } else if path == KEY_PATH {
            cfg.url_tokens
                .as_ref()
                .map_or_else(HttpObjectResponse::not_found, |config| {
                    key_document(config, method.as_ref())
                })
        } else {
            let Some(response) = early_object_error(method.as_ref(), &raw) else {
                return Ok(None);
            };
            response
        };
        Ok(Some(bridge(response, method.as_ref())?))
    }

    pub(crate) async fn serve<H: HookSet + 'static>(
        pipe: &Pipeline<WorkerBlobStore, WorkerNamespaceStore, H>,
        req: &Request,
    ) -> worker::Result<Response> {
        let url = req.inner().url();
        let (raw_path, raw_query) = raw_path_query(&url)
            .map_err(|_| worker::Error::RustError("invalid request URL".into()))?;
        let entries: Vec<_> = req.headers().entries().collect();
        let names: Vec<_> = entries.iter().map(|(name, _)| name.as_str()).collect();
        let values = |name: &str| {
            entries
                .iter()
                .filter(|(key, _)| key.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.clone())
                .collect()
        };
        let response = pipe
            .serve_http_object(&HttpObjectRequest {
                method: req.method().as_ref(),
                raw_path,
                raw_query: raw_query.map(RedactedQuery::new),
                headers: &values,
                header_names: &names,
            })
            .await;
        bridge(response, req.method().as_ref())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use futures::{StreamExt as _, executor::block_on};
    use mkit_server::http_objects::{HttpBody, HttpObjectResponse};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    #[test]
    fn bridge_streams_one_piece_per_poll_and_redacts_errors() {
        let polled = Arc::new(AtomicUsize::new(0));
        let counter = polled.clone();
        let source = futures::stream::iter([
            Ok(bytes::Bytes::from_static(b"abc")),
            Ok(bytes::Bytes::from_static(b"def")),
            Err(mkit_server::ServerError::unavailable(
                "token=secret backend URL",
            )),
        ])
        .inspect(move |_| {
            counter.fetch_add(1, Ordering::SeqCst);
        });
        let mut body = bridge_chunks(Box::pin(source));
        assert_eq!(polled.load(Ordering::SeqCst), 0);
        assert_eq!(block_on(body.next()).unwrap().unwrap(), b"abc");
        assert_eq!(polled.load(Ordering::SeqCst), 1);
        assert_eq!(block_on(body.next()).unwrap().unwrap(), b"def");
        assert_eq!(
            block_on(body.next()).unwrap(),
            Err("HTTP object stream failed")
        );
    }

    #[test]
    fn head_has_no_body_on_every_status_and_keeps_repeated_metadata() {
        for status in [
            200, 206, 302, 304, 400, 401, 402, 403, 404, 405, 416, 451, 503,
        ] {
            let mut response = HttpObjectResponse::new(status)
                .with_header("Content-Length", "123")
                .with_header("WWW-Authenticate", "Payment first")
                .with_header("WWW-Authenticate", "Payment second");
            response.body = HttpBody::Stream {
                len: 123,
                stream: Box::pin(futures::stream::poll_fn(|_| panic!("HEAD polled source"))),
            };
            let response = prepare_response(response, "HEAD");
            assert_eq!(response.status, status);
            assert!(matches!(response.body, HttpBody::Empty));
            assert_eq!(
                response
                    .headers
                    .iter()
                    .filter(|(name, _)| *name == "WWW-Authenticate")
                    .count(),
                2
            );
            assert!(
                response
                    .headers
                    .iter()
                    .any(|(name, value)| *name == "Content-Length" && value == "123")
            );
        }
    }

    #[test]
    fn environment_config_cannot_mount_even_with_token_keys() {
        let config = crate::adapter::WorkerConfig::from_vars(|name| match name {
            "AUTH_AUDIENCE" => Some("https://example.org".into()),
            "AUTH_REPOSITORY" => Some("repo".into()),
            "URL_TOKEN_KEYS" => Some(format!("active {}", "11".repeat(32))),
            _ => None,
        })
        .unwrap();
        assert!(config.http_mount.is_none());
        assert!(config.url_tokens.is_some());
        let pipeline = config.pipeline_config().unwrap();
        assert!(pipeline.indexed.is_none());
        assert!(pipeline.http_objects.is_none());
        assert!(pipeline.url_tokens.is_none());
    }

    #[test]
    fn raw_urls_preserve_escapes_and_empty_queries() {
        assert_eq!(
            raw_path_query("https://example.org/-/refs/heads/main/-/a%2Fb%3F?"),
            Ok(("/-/refs/heads/main/-/a%2Fb%3F", Some("")))
        );
        assert_eq!(
            raw_path_query("https://example.org/-/objects/id?token=secret%2B"),
            Ok(("/-/objects/id", Some("token=secret%2B")))
        );
        assert_eq!(
            raw_path_query("https://example.org/-/objects/id"),
            Ok(("/-/objects/id", None))
        );
    }

    #[test]
    fn url_errors_redact_queries() {
        let error = raw_path_query("/-/objects/id?token=secret").unwrap_err();
        assert!(!format!("{error:?}").contains("secret"));
    }

    #[test]
    fn invalid_urls_and_methods_answer_before_worker_bindings() {
        let url = format!(
            "https://example.org/ed25519-{}/repo/-/objects/{}",
            "11".repeat(32),
            "00".repeat(32)
        );
        assert!(early_object_error("GET", &url).is_none());
        assert!(early_object_error("HEAD", &url).is_none());
        assert_eq!(
            early_object_error("GET", &format!("{url}?"))
                .unwrap()
                .status,
            400
        );
        assert_eq!(
            early_object_error("HEAD", &format!("{url}?unknown=secret"))
                .unwrap()
                .status,
            400
        );
        assert_eq!(
            early_object_error("POST", &format!("{url}?unknown=secret"))
                .unwrap()
                .status,
            405
        );
    }

    #[test]
    fn token_vars_are_optional_and_errors_are_redacted() {
        assert!(token_config(&|_| None).unwrap().is_none());
        let error =
            token_config(&|name| (name == "URL_TOKEN_KEYS").then(|| "secret".into())).unwrap_err();
        assert_eq!(error.0, "URL_TOKEN_KEYS is invalid");
        assert!(token_config(&|name| (name == "URL_TOKEN_TTL").then(|| "60".into())).is_err());
    }

    #[test]
    fn active_and_retired_url_keys_cannot_reuse_any_ticket_secret() {
        let reused = token_config(&|name| {
            (name == "URL_TOKEN_KEYS").then(|| format!("active {}", "11".repeat(32)))
        })
        .unwrap()
        .unwrap();
        let public = reused.keys().public_keys().next().unwrap();
        let public_hex = mkit_core::hash::to_hex(&public);
        for keys in [
            format!("active {}", "11".repeat(32)),
            format!("active {}\nretired {public_hex} 1", "22".repeat(32)),
        ] {
            for tickets in [
                format!("ticket {}", "11".repeat(32)),
                format!("active {}\nretained {}", "33".repeat(32), "11".repeat(32)),
            ] {
                let error = crate::adapter::WorkerConfig::from_vars(|name| match name {
                    "AUTH_AUDIENCE" => Some("https://example.org".into()),
                    "AUTH_REPOSITORY" => Some("repo".into()),
                    "URL_TOKEN_KEYS" => Some(keys.clone()),
                    "TICKET_KEYS" => Some(tickets.clone()),
                    _ => None,
                })
                .unwrap_err();
                assert_eq!(error.0, "URL_TOKEN_KEYS must differ from TICKET_KEYS");
            }
        }
    }

    #[test]
    fn token_vars_use_key_file_grammar_and_seconds() {
        let config = token_config(&|name| match name {
            "URL_TOKEN_KEYS" => Some(format!("active {}", "11".repeat(32))),
            "URL_TOKEN_TTL" => Some("60".into()),
            _ => None,
        })
        .unwrap()
        .unwrap();
        assert_eq!(config.ttl_ms(), 60_000);
        for ttl in ["0", "86401", "18446744073709551615", "-1", "01"] {
            assert!(
                token_config(&|name| match name {
                    "URL_TOKEN_KEYS" => Some(format!("active {}", "11".repeat(32))),
                    "URL_TOKEN_TTL" => Some(ttl.into()),
                    _ => None,
                })
                .is_err()
            );
        }
    }
}
