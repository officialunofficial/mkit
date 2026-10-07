//! Explicit HTTP object mounting, including the optional Paid launch mount.

use mkit_server::http_objects::HttpObjectsConfig;
use mkit_server::http_objects::mount::HttpMountOptions;
use mkit_server::indexed::IndexedConfig;
use mkit_server::namespace::NamespaceMode;
use mkit_server::url_token::{UrlTokenConfig, UrlTokenKeys};

use crate::adapter::ConfigError;

/// A programmatic indexed deployment with an explicit HTTP mount.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct WorkerHttpMountConfig {
    /// Indexed configuration selected by the mount or Paid launch profile.
    pub indexed: IndexedConfig,
    /// Explicit HTTP configuration, including optional read admission.
    pub http_objects: HttpObjectsConfig,
    /// Read CORS origins.
    pub options: HttpMountOptions,
    /// Retains paid-read settlement using the request lifetime (normally `wait_until`).
    pub read_runtime: Option<mkit_server::http_objects::HttpReadRuntime>,
}

impl WorkerHttpMountConfig {
    /// Construct explicit deployment settings; fields may be adjusted before use.
    #[must_use]
    pub fn new(
        indexed: IndexedConfig,
        http_objects: HttpObjectsConfig,
        options: HttpMountOptions,
    ) -> Self {
        Self {
            indexed,
            http_objects,
            options,
            read_runtime: None,
        }
    }
}

impl WorkerHttpMountConfig {
    /// Retain read settlement in this fetch event, including body cancellation.
    #[cfg(target_arch = "wasm32")]
    #[must_use]
    pub fn with_context(mut self, context: worker::Context) -> Self {
        self.read_runtime = Some(mkit_server::http_objects::HttpReadRuntime::new(
            std::sync::Arc::new(crate::sleep::WorkerSleep),
            std::sync::Arc::new(ReadSettlement(context)),
        ));
        self
    }
}

#[cfg(target_arch = "wasm32")]
struct ReadSettlement(worker::Context);

#[cfg(target_arch = "wasm32")]
impl mkit_server::Spawner for ReadSettlement {
    fn spawn(&self, future: mkit_server::BoxFuture<'static, ()>) {
        self.0.wait_until(future);
    }
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

/// Optional history MAC secret, using the deployment URL-token key-file pattern.
/// # Errors
/// Invalid key material or fixed TTL (seconds, 1–900), or TTL without keys.
pub fn history_token_config(
    var: &impl Fn(&str) -> Option<String>,
    realm: &str,
) -> Result<Option<mkit_server::history_token::HistoryTokenConfig>, ConfigError> {
    let keys = var("HISTORY_TOKEN_KEYS");
    let ttl = var("HISTORY_TOKEN_TTL");
    let Some(keys) = keys else {
        return if ttl.is_some() {
            Err(ConfigError(
                "HISTORY_TOKEN_TTL requires HISTORY_TOKEN_KEYS".into(),
            ))
        } else {
            Ok(None)
        };
    };
    let ttl_ms = ttl
        .map_or(Some(900_000), |v| {
            v.parse::<u64>()
                .ok()
                .filter(|n| n.to_string() == v)
                .and_then(|n| n.checked_mul(1000))
        })
        .ok_or_else(|| ConfigError("HISTORY_TOKEN_TTL is invalid".into()))?;
    mkit_server::history_token::HistoryTokenConfig::parse_key_file_secret(
        keys,
        realm.into(),
        ttl_ms,
    )
    .map(Some)
    .map_err(|_| ConfigError("HISTORY_TOKEN_KEYS or HISTORY_TOKEN_TTL is invalid".into()))
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
/// Use the deployment namespace mode for the same grammar as object serving.
#[must_use]
pub fn early_object_error(
    method: &str,
    url: &str,
    mode: NamespaceMode,
) -> Option<mkit_server::http_objects::HttpObjectResponse> {
    use mkit_server::http_objects::{HttpObjectResponse, RepoPrefix, parse_with_mode};
    if !matches!(method, "GET" | "HEAD") {
        return Some(HttpObjectResponse::error(405).with_header("Allow", "GET, HEAD, OPTIONS"));
    }
    let invalid = !raw_path_query(url).is_ok_and(|(path, query)| {
        parse_with_mode(path, query, RepoPrefix::Required, mode).is_ok()
    });
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

#[cfg(any(target_arch = "wasm32", test))]
pub(crate) mod glue {
    #[cfg(target_arch = "wasm32")]
    use futures::StreamExt as _;
    #[cfg(target_arch = "wasm32")]
    use mkit_server::http_objects::mount::apply_cors;
    use mkit_server::http_objects::mount::{KEY_PATH, key_document};
    #[cfg(target_arch = "wasm32")]
    use mkit_server::http_objects::{HttpBody, HttpObjectRequest, RedactedQuery};
    use mkit_server::http_objects::{HttpObjectResponse, is_http_object_path};
    #[cfg(target_arch = "wasm32")]
    use mkit_server::pipeline::{HookSet, Pipeline};
    #[cfg(target_arch = "wasm32")]
    use worker::{Request, Response};

    #[cfg(target_arch = "wasm32")]
    use super::{HttpMountOptions, bridge_chunks, prepare_response};
    use super::{early_object_error, raw_path_query};
    use crate::adapter::WorkerConfig;
    #[cfg(target_arch = "wasm32")]
    use crate::ns_client::WorkerNamespaceStore;
    #[cfg(target_arch = "wasm32")]
    use crate::r2::WorkerBlobStore;

    /// Only a configured HTTP mount can select this dispatcher.
    #[cfg(target_arch = "wasm32")]
    pub(crate) fn mounted_request(req: &Request, cfg: &WorkerConfig) -> bool {
        cfg.http_mount.is_some()
            && raw_path_query(&req.inner().url())
                .is_ok_and(|(path, _)| path == KEY_PATH || is_http_object_path(path))
    }

    /// A selected environment mount retains its HTTP error contract even if
    /// another setting prevents the full configuration from being parsed.
    #[cfg(target_arch = "wasm32")]
    pub(crate) fn env_mounted_request(req: &Request, env: &worker::Env) -> bool {
        let selected = env
            .secret("HTTP_OBJECTS")
            .ok()
            .map(|value| value.to_string())
            .or_else(|| env.var("HTTP_OBJECTS").ok().map(|value| value.to_string()))
            .is_some_and(|value| value == "true");
        selected
            && raw_path_query(&req.inner().url())
                .is_ok_and(|(path, _)| path == KEY_PATH || is_http_object_path(path))
    }

    /// CORS and body suppression apply even to adapter/configuration errors.
    #[cfg(target_arch = "wasm32")]
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

    #[cfg(target_arch = "wasm32")]
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
    pub(crate) fn early(method: &str, raw: &str, cfg: &WorkerConfig) -> Option<HttpObjectResponse> {
        cfg.http_mount.as_ref()?;
        let (path, _) = raw_path_query(raw).ok()?;
        if path != KEY_PATH && !is_http_object_path(path) {
            return None;
        }
        let response = if method == "OPTIONS" {
            HttpObjectResponse::new(204).with_header("Allow", "GET, HEAD, OPTIONS")
        } else if path == KEY_PATH {
            cfg.url_tokens
                .as_ref()
                .map_or_else(HttpObjectResponse::not_found, |config| {
                    key_document(config, method)
                })
        } else {
            early_object_error(method, raw, cfg.namespace_mode)?
        };
        Some(response)
    }

    #[cfg(target_arch = "wasm32")]
    pub(crate) fn early_worker(
        req: &Request,
        cfg: &WorkerConfig,
    ) -> worker::Result<Option<Response>> {
        early(req.method().as_ref(), &req.inner().url(), cfg)
            .map(|response| bridge(response, req.method().as_ref()))
            .transpose()
    }

    #[cfg(target_arch = "wasm32")]
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
        assert!(early_object_error("GET", &url, NamespaceMode::SelfCertifying).is_none());
        assert!(early_object_error("HEAD", &url, NamespaceMode::SelfCertifying).is_none());
        assert_eq!(
            early_object_error("GET", &format!("{url}?"), NamespaceMode::SelfCertifying)
                .unwrap()
                .status,
            400
        );
        assert_eq!(
            early_object_error(
                "HEAD",
                &format!("{url}?unknown=secret"),
                NamespaceMode::SelfCertifying
            )
            .unwrap()
            .status,
            400
        );
        assert_eq!(
            early_object_error(
                "POST",
                &format!("{url}?unknown=secret"),
                NamespaceMode::SelfCertifying
            )
            .unwrap()
            .status,
            405
        );
    }

    #[test]
    fn early_object_validation_uses_deployment_namespace_mode() {
        let url = format!(
            "https://example.org/019c88c3-a904-7bd1-8a5d-3182a0c6978a/repo/-/objects/{}",
            "00".repeat(32)
        );
        for method in ["GET", "HEAD"] {
            assert!(early_object_error(method, &url, NamespaceMode::Authority).is_none());
            assert_eq!(
                early_object_error(method, &url, NamespaceMode::SelfCertifying)
                    .unwrap()
                    .status,
                400
            );
            for namespace in [
                format!("ed25519-{}", "11".repeat(32)),
                format!("0x{}", "11".repeat(20)),
                "root".into(),
            ] {
                let url = format!(
                    "https://example.org/{namespace}/repo/-/objects/{}",
                    "00".repeat(32)
                );
                assert_eq!(
                    early_object_error(method, &url, NamespaceMode::Authority)
                        .unwrap()
                        .status,
                    400
                );
            }
        }
        assert_eq!(
            early_object_error("POST", &url, NamespaceMode::Authority)
                .unwrap()
                .status,
            405
        );
    }

    #[test]
    fn authority_worker_mount_passes_uuid_routes_through_early_gate() {
        let mut cfg = crate::adapter::WorkerConfig::from_vars(|name| match name {
            "AUTH_AUDIENCE" => Some("https://example.org".into()),
            "ADDRESSING" => Some("multi".into()),
            "NAMESPACE_POLICY" => Some("any".into()),
            "UNSAFE_OPEN_NAMESPACES" | "AUTHORITY_FENCE" => Some("true".into()),
            "NAMESPACE_MODE" | "AUTHORIZER_ROLE" => Some("authority".into()),
            "HOOK_ROLES" => Some("authorize".into()),
            "AUTHORITY_KEYS" => Some(format!("deployment {} *", "11".repeat(32))),
            "TICKET_KEYS" => Some(format!("ticket {}", "09".repeat(32))),
            _ => None,
        })
        .unwrap();
        cfg.http_mount = Some(WorkerHttpMountConfig::new(
            IndexedConfig::default(),
            HttpObjectsConfig::default(),
            HttpMountOptions::default(),
        ));
        let url = format!(
            "https://example.org/019c88c3-a904-7bd1-8a5d-3182a0c6978a/repo/-/objects/{}",
            "00".repeat(32)
        );
        for method in ["GET", "HEAD"] {
            assert!(glue::early(method, &url, &cfg).is_none());
        }
        cfg.namespace_mode = NamespaceMode::SelfCertifying;
        assert_eq!(glue::early("GET", &url, &cfg).unwrap().status, 400);
    }

    #[test]
    fn unparseable_urls_stay_outside_the_http_mount() {
        let mut cfg = crate::adapter::WorkerConfig::from_vars(|name| match name {
            "AUTH_AUDIENCE" => Some("https://example.org".into()),
            "AUTH_REPOSITORY" => Some("repo".into()),
            _ => None,
        })
        .unwrap();
        cfg.http_mount = Some(WorkerHttpMountConfig::new(
            IndexedConfig::default(),
            HttpObjectsConfig::default(),
            HttpMountOptions::default(),
        ));
        for url in ["not-a-url", "https://example.org/repo#fragment"] {
            assert!(raw_path_query(url).is_err());
            for method in ["GET", "HEAD", "OPTIONS", "POST"] {
                assert!(glue::early(method, url, &cfg).is_none());
            }
        }
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
