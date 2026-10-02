//! Opt-in HTTP object dispatch over original axum request URIs.
use axum::body::Body;
use http::{Request, Response};
use mkit_server::http_objects::mount::{HttpMountOptions, KEY_PATH, apply_cors, key_document};
use mkit_server::http_objects::{
    HttpBody, HttpObjectRequest, HttpObjectResponse, RedactedQuery, is_http_object_path,
};
use mkit_server::pipeline::{HookSet, Pipeline};
use mkit_server::{MultipartBlobStore, NamespaceStore, Redactor};
use std::{convert::Infallible, sync::Arc};
use tower::ServiceExt as _;
use tracing::Instrument as _;

pub(crate) fn mount<B, N, H>(
    rpc: axum::Router,
    pipeline: Arc<Pipeline<B, N, H>>,
    opts: HttpMountOptions,
    redactor: Redactor,
    cap: crate::guard::CapLayer,
) -> axum::Router
where
    B: MultipartBlobStore + 'static,
    N: NamespaceStore + Clone + 'static,
    H: HookSet + 'static,
{
    let final_options = opts.clone();
    let router = axum::Router::new()
        .fallback_service(tower::service_fn(move |req: Request<Body>| {
            let (pipeline, opts, rpc, redactor) = (
                pipeline.clone(),
                opts.clone(),
                rpc.clone(),
                redactor.clone(),
            );
            dispatch(req, rpc, pipeline, opts, redactor)
        }))
        .layer(cap);
    router.layer(axum::middleware::from_fn(
        move |request: Request<Body>, next: axum::middleware::Next| {
            let options = final_options.clone();
            async move {
                let mounted =
                    is_http_object_path(request.uri().path()) || request.uri().path() == KEY_PATH;
                let head = request.method() == http::Method::HEAD;
                let origin = request
                    .headers()
                    .get("origin")
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_owned);
                let early = if mounted && request.method() == http::Method::OPTIONS {
                    Some(HttpObjectResponse::new(204).with_header("Allow", "GET, HEAD, OPTIONS"))
                } else if mounted && request.uri().path() != KEY_PATH {
                    if !matches!(*request.method(), http::Method::GET | http::Method::HEAD) {
                        Some(
                            HttpObjectResponse::error(405)
                                .with_header("Allow", "GET, HEAD, OPTIONS"),
                        )
                    } else if mkit_server::http_objects::parse(
                        request.uri().path(),
                        request.uri().query(),
                        mkit_server::http_objects::RepoPrefix::Required,
                    )
                    .is_err()
                    {
                        Some(HttpObjectResponse::error(400))
                    } else {
                        None
                    }
                } else {
                    None
                };
                let mut response = match early {
                    Some(response) => into_response(response, head),
                    None => next.run(request).await,
                };
                if mounted {
                    let mut policy = HttpObjectResponse::new(response.status().as_u16());
                    if let Some(vary) = combined_vary(response.headers()) {
                        policy.headers.push(("Vary", vary));
                    }
                    apply_cors(&mut policy, origin.as_deref(), &options);
                    for name in [
                        "access-control-allow-origin",
                        "access-control-allow-credentials",
                    ] {
                        response.headers_mut().remove(name);
                    }
                    for (name, value) in policy.headers {
                        if let (Ok(name), Ok(value)) = (
                            http::HeaderName::from_bytes(name.as_bytes()),
                            http::HeaderValue::from_str(&value),
                        ) {
                            response.headers_mut().insert(name, value);
                        }
                    }
                    if response.status().is_client_error() || response.status().is_server_error() {
                        let private = response
                            .headers()
                            .get("cache-control")
                            .and_then(|value| value.to_str().ok())
                            .is_some_and(|value| {
                                value.split(',').any(|part| part.trim() == "private")
                            });
                        response.headers_mut().insert(
                            http::header::CACHE_CONTROL,
                            http::HeaderValue::from_static(if private {
                                "private, no-store"
                            } else {
                                "no-store"
                            }),
                        );
                    }
                    if head {
                        *response.body_mut() = Body::empty();
                    }
                }
                response
            }
        },
    ))
}

fn combined_vary(headers: &http::HeaderMap) -> Option<String> {
    let vary = headers
        .get_all("vary")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect::<Vec<_>>()
        .join(", ");
    (!vary.is_empty()).then_some(vary)
}

async fn dispatch<B, N, H>(
    req: Request<Body>,
    rpc: axum::Router,
    pipeline: Arc<Pipeline<B, N, H>>,
    opts: HttpMountOptions,
    redactor: Redactor,
) -> Result<Response<Body>, Infallible>
where
    B: MultipartBlobStore + 'static,
    N: NamespaceStore + Clone + 'static,
    H: HookSet + 'static,
{
    let path = req.uri().path();
    if !is_http_object_path(path) && path != KEY_PATH {
        return rpc.oneshot(req).await;
    }
    let (parts, _) = req.into_parts();
    let path = parts.uri.path();
    let method = parts.method.as_str();
    // Never trace the URI or credential header values.
    let span = tracing::info_span!("http_object", method);
    let mut response = if path == KEY_PATH {
        pipeline
            .url_token_config()
            .map_or_else(HttpObjectResponse::not_found, |keys| {
                key_document(keys, method)
            })
    } else {
        let headers = |name: &str| {
            parts
                .headers
                .get_all(name)
                .iter()
                .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
                .collect()
        };
        let names: Vec<_> = parts.headers.keys().map(http::HeaderName::as_str).collect();
        let request = HttpObjectRequest {
            method,
            raw_path: path,
            raw_query: parts.uri.query().map(RedactedQuery::new),
            headers: &headers,
            header_names: &names,
        };
        async {
            match tokio::runtime::Handle::try_current() {
                Ok(handle) => {
                    pipeline
                        .serve_http_object_with_proofs(
                            &request,
                            read_runtime(handle),
                            Arc::new(crate::NativeProofs),
                        )
                        .await
                }
                Err(_) => pipeline.serve_http_object(&request).await,
            }
        }
        .instrument(span)
        .await
    };
    if http::StatusCode::from_u16(response.status).is_err()
        || response.headers.iter().any(|(name, value)| {
            http::HeaderName::from_bytes(name.as_bytes()).is_err()
                || http::HeaderValue::from_str(value).is_err()
        })
    {
        let private = response.header("Cache-Control").is_some_and(|cache| {
            cache
                .split(',')
                .any(|directive| directive.trim() == "private")
        });
        response = HttpObjectResponse::error(503);
        if private {
            response
                .headers
                .retain(|(name, _)| !name.eq_ignore_ascii_case("Cache-Control"));
            response
                .headers
                .push(("Cache-Control", "private, no-store".into()));
        }
    }
    apply_cors(
        &mut response,
        parts.headers.get("origin").and_then(|v| v.to_str().ok()),
        &opts,
    );
    let mut response = into_response(response, method == "HEAD");
    for (name, value) in response.headers_mut().iter_mut() {
        if redactor.redacts(name.as_str()) {
            value.set_sensitive(true);
        }
    }
    Ok::<_, Infallible>(response)
}

/// Copy every header occurrence and stream chunks without collecting them.
#[must_use]
pub fn into_response(response: HttpObjectResponse, head: bool) -> Response<Body> {
    let cors: Vec<_> = response
        .headers
        .iter()
        .filter(|(name, value)| {
            (name.to_ascii_lowercase().starts_with("access-control-")
                || name.eq_ignore_ascii_case("Vary"))
                && http::HeaderName::from_bytes(name.as_bytes()).is_ok()
                && http::HeaderValue::from_str(value).is_ok()
        })
        .cloned()
        .collect();
    let body = if head {
        Body::empty()
    } else {
        match response.body {
            HttpBody::Empty => Body::empty(),
            HttpBody::Bytes(bytes) => Body::from(bytes),
            HttpBody::Stream { stream, .. } => Body::from_stream(stream),
        }
    };
    let mut result = Response::new(body);
    let Ok(status) = http::StatusCode::from_u16(response.status) else {
        return adapter_error(head, &cors);
    };
    *result.status_mut() = status;
    for (name, value) in response.headers {
        let (Ok(name), Ok(value)) = (
            http::HeaderName::from_bytes(name.as_bytes()),
            http::HeaderValue::from_str(&value),
        ) else {
            return adapter_error(head, &cors);
        };
        result.headers_mut().append(name, value);
    }
    result
}

fn adapter_error(head: bool, cors: &[(&'static str, String)]) -> Response<Body> {
    let mut response = HttpObjectResponse::error(503);
    response.headers.extend_from_slice(cors);
    into_response(response, head)
}

/// Resolve the feature-gated key flags without configuring any HTTP mount.
///
/// # Errors
/// A malformed/unsafe key file, invalid TTL, or collision with ticket keys.
pub fn resolve_tokens(
    args: &crate::config::ServeArgs,
    pipeline: &mut mkit_server::pipeline::PipelineConfig,
) -> Result<(), crate::config::ConfigError> {
    use crate::{
        config::{ConfigError, read_secret_file},
        exit,
    };
    use mkit_server::url_token::{UrlTokenConfig, UrlTokenKeys};
    let error = || {
        ConfigError::new(
            exit::CONFIG_ERROR,
            "mkit-server: invalid URL-token configuration or key separation",
        )
    };
    let Some(path) = &args.url_token_key_file else {
        if args.url_token_ttl.is_some() {
            return Err(error());
        }
        return Ok(());
    };
    let text = read_secret_file(
        path,
        "--url-token-key-file",
        "a programmatic secret provider",
    )?;
    let keys = UrlTokenKeys::parse_key_file_secret(text).map_err(|_| error())?;
    let ttl = args
        .url_token_ttl
        .unwrap_or(mkit_server::url_token::DEFAULT_TTL_MS / 1000)
        .checked_mul(1000)
        .ok_or_else(error)?;
    let config = UrlTokenConfig::with_ttl_ms(keys, ttl).map_err(|_| error())?;
    if pipeline.ticket_keys.as_ref().is_some_and(|tickets| {
        config
            .keys()
            .public_keys()
            .any(|key| tickets.contains_ed25519_public(&key))
    }) {
        return Err(error());
    }
    pipeline.url_tokens = Some(config);
    Ok(())
}

/// Refuse token/hook/enc role reuse for embedders as well as binary startup.
///
/// # Errors
/// A collision with an active or retained token public key.
pub fn check_other_keys(
    tokens: Option<&mkit_server::url_token::UrlTokenConfig>,
    others: &[[u8; 32]],
) -> Result<(), crate::config::ConfigError> {
    if let Some(tokens) = tokens {
        mkit_server::http_objects::mount::check_key_separation(tokens, others).map_err(|_| {
            crate::config::ConfigError::new(
                crate::exit::CONFIG_ERROR,
                "mkit-server: URL-token keys must differ from hook and enc keys",
            )
        })?;
    }
    Ok(())
}

/// Native runtime retaining settlement after the response body is dropped.
#[must_use]
pub fn read_runtime(handle: tokio::runtime::Handle) -> mkit_server::http_objects::HttpReadRuntime {
    struct Retain(tokio::runtime::Handle);
    impl mkit_server::Spawner for Retain {
        fn spawn(&self, future: mkit_server::BoxFuture<'static, ()>) {
            self.0.spawn(future);
        }
    }
    mkit_server::http_objects::HttpReadRuntime {
        sleep: Arc::new(crate::timers::TokioSleep),
        spawner: Arc::new(Retain(handle)),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use clap::Parser as _;
    use mkit_server::pipeline::{AuthMode, PipelineConfig};
    use mkit_server::upload::{UploadLimits, token::TicketKeys};
    use mkit_server::{Addressing, NamespaceKey, RepoId, RepoName};

    #[derive(clap::Parser)]
    struct Args {
        #[command(flatten)]
        serve: crate::config::ServeArgs,
    }

    fn config() -> PipelineConfig {
        PipelineConfig::new(
            Addressing::Single {
                repo: RepoId {
                    namespace: NamespaceKey::deployment_default(),
                    name: RepoName::new("test").unwrap(),
                },
            },
            AuthMode::Open,
            UploadLimits {
                max_total_bytes: 1024,
                max_chunks: 2,
            },
        )
    }

    #[test]
    fn settlement_spawns_from_a_captured_runtime_handle() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let retained = read_runtime(runtime.handle().clone());
        let (sender, receiver) = tokio::sync::oneshot::channel();
        retained.spawner.spawn(Box::pin(async move {
            let _ = sender.send(());
        }));
        runtime.block_on(receiver).unwrap();
    }

    #[test]
    fn key_file_flags_validate_ttl_permissions_and_ticket_separation() {
        use std::os::unix::fs::PermissionsExt as _;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("url-keys");
        let key = "11".repeat(32);
        std::fs::write(&path, format!("active {key}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let args = |ttl: Option<&str>| {
            let mut flags = vec![
                "serve",
                "--repo-root",
                ".",
                "--url-token-key-file",
                path.to_str().unwrap(),
            ];
            if let Some(ttl) = ttl {
                flags.extend(["--url-token-ttl", ttl]);
            }
            Args::parse_from(flags).serve
        };
        let mut cfg = config();
        resolve_tokens(&args(None), &mut cfg).unwrap();
        assert_eq!(cfg.url_tokens.as_ref().unwrap().ttl_ms(), 900_000);
        assert!(cfg.indexed.is_none() && cfg.http_objects.is_none());
        for ttl in ["1", "86400"] {
            resolve_tokens(&args(Some(ttl)), &mut config()).unwrap();
        }
        for ttl in ["0", "86401", "18446744073709551615"] {
            assert!(resolve_tokens(&args(Some(ttl)), &mut config()).is_err());
        }
        let mut repeated = config();
        repeated.ticket_keys = Some(TicketKeys::new(vec![("ticket".into(), [0x11; 32])]).unwrap());
        assert!(resolve_tokens(&args(None), &mut repeated).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(resolve_tokens(&args(None), &mut config()).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&path, "secret invalid key text").unwrap();
        let error = resolve_tokens(&args(None), &mut config()).unwrap_err();
        assert!(!format!("{error:?}").contains("secret invalid"));
        let no_keys = Args::parse_from(["serve", "--repo-root", ".", "--url-token-ttl", "60"]);
        assert!(resolve_tokens(&no_keys.serve, &mut config()).is_err());
    }
}
