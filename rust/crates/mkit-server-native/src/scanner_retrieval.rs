//! Private scanner mount with bounded request collection and a shared admission cap.
use std::{convert::Infallible, sync::Arc};

use axum::body::{Body, to_bytes};
use http::{Request, Response, StatusCode, header};
use mkit_server::pipeline::{AuthMode, HookSet, Pipeline, PipelineConfig};
use mkit_server::scanner_retrieval::{MAX_REQUEST_BYTES, PATH, RetrievalConfig, RetrievalResponse};
use mkit_server::{MultipartBlobStore, NamespaceStore};
use tower::{Layer as _, ServiceExt as _};

use crate::config::{ConfigError, ServeArgs};
use crate::router::RouterOptions;

pub(crate) fn resolve(
    args: &ServeArgs,
    pipeline: &mut PipelineConfig,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<(), ConfigError> {
    let error = || {
        ConfigError::new(
            crate::exit::CONFIG_ERROR,
            "invalid scanner retrieval configuration or key separation",
        )
    };
    if !args.scanner_retrieval {
        if env("SCANNER_RETRIEVAL_KEYS").is_some() || env("SCANNER_KEYS").is_some() {
            return Err(error());
        }
        return Ok(());
    }
    if !cfg!(feature = "test-faults") && args.launch_profile.is_none() {
        return Err(ConfigError::new(
            crate::exit::CONFIG_ERROR,
            "scanner retrieval requires --launch-profile uno in release builds",
        ));
    }
    #[cfg(feature = "hooks")]
    let inspectors = !args.hooks.hook_inspect_url.is_empty();
    #[cfg(not(feature = "hooks"))]
    let inspectors = false;
    if !inspectors || args.listen.is_none() || !matches!(pipeline.auth, AuthMode::AuthV2(_)) {
        return Err(error());
    }
    let keys = zeroize::Zeroizing::new(env("SCANNER_RETRIEVAL_KEYS").ok_or_else(error)?);
    let config = RetrievalConfig::parse(&keys, &env("SCANNER_KEYS").ok_or_else(error)?)
        .map_err(|_| error())?;
    #[cfg(feature = "hooks")]
    {
        let (id, seed) = crate::hooks::config::read_key(args.hooks.hook_key_file.as_deref(), env)?;
        let signer = mkit_server::hooks::HookSigner::new(id, seed.clone()).map_err(|_| error())?;
        config
            .check_role_keys(&[signer.public_key()], &[*seed])
            .map_err(|_| error())?;
    }
    pipeline.scanner_retrieval = Some(Arc::new(config));
    Ok(())
}

#[cfg(feature = "enc")]
pub(crate) fn check_enc_key(
    retrieval: &RetrievalConfig,
    key: &commonware_cryptography::ed25519::PrivateKey,
) -> Result<(), ConfigError> {
    use commonware_codec::Write as _;
    use commonware_cryptography::Signer as _;
    let error = || {
        ConfigError::new(
            crate::exit::CONFIG_ERROR,
            "invalid scanner/enc key separation",
        )
    };
    let public = <[u8; 32]>::try_from(key.public_key().as_ref()).map_err(|_| error())?;
    let mut encoded = zeroize::Zeroizing::new(Vec::with_capacity(32));
    key.write(&mut *encoded);
    let seed =
        zeroize::Zeroizing::new(<[u8; 32]>::try_from(encoded.as_slice()).map_err(|_| error())?);
    retrieval
        .check_role_keys(&[public], &[*seed])
        .map_err(|_| error())
}

pub(crate) fn mount<B, N, H>(
    rpc: axum::Router,
    pipeline: Arc<Pipeline<B, N, H>>,
    opts: &RouterOptions,
    cap: &crate::guard::CapLayer,
) -> axum::Router
where
    B: MultipartBlobStore + 'static,
    N: NamespaceStore + Clone + 'static,
    H: HookSet + 'static,
{
    if !pipeline.scanner_retrieval_enabled() {
        return rpc;
    }
    let timeout = opts.unary_timeout;
    let route = tower::service_fn(move |request: Request<Body>| {
        let pipeline = pipeline.clone();
        async move {
            let response = tokio::time::timeout(timeout, retrieve(request, pipeline))
                .await
                .unwrap_or_else(|_| not_found());
            Ok::<_, Infallible>(response)
        }
    });
    let route = cap.layer(route).map_response(|response: Response<Body>| {
        if response.status().is_success() {
            response
        } else {
            not_found()
        }
    });
    axum::Router::new()
        .route_service(PATH, route)
        .fallback_service(rpc)
}

async fn retrieve<B, N, H>(
    request: Request<Body>,
    pipeline: Arc<Pipeline<B, N, H>>,
) -> Response<Body>
where
    B: MultipartBlobStore + 'static,
    N: NamespaceStore + Clone + 'static,
    H: HookSet + 'static,
{
    if request.method() != http::Method::POST || request.uri().query().is_some() {
        return not_found();
    }
    let (parts, body) = request.into_parts();
    if mkit_server::auth_v2::HEADER_NAMES
        .iter()
        .any(|name| parts.headers.get_all(*name).iter().count() > 1)
    {
        return not_found();
    }
    let headers = mkit_server::auth_v2::headers_from(|name| {
        parts
            .headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
    });
    let Ok(body) = to_bytes(body, MAX_REQUEST_BYTES).await else {
        return not_found();
    };
    match pipeline.retrieve_scanner_pack(&body, &headers).await {
        Ok(result) => into_response(result),
        Err(_) => not_found(),
    }
}

fn into_response(result: RetrievalResponse) -> Response<Body> {
    let RetrievalResponse {
        bytes,
        start,
        total,
        partial,
    } = result;
    let length = bytes.len();
    let mut response = Response::new(Body::from(bytes));
    *response.status_mut() = if partial {
        StatusCode::PARTIAL_CONTENT
    } else {
        StatusCode::OK
    };
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        http::HeaderValue::from_static("application/octet-stream"),
    );
    let Ok(header_length) = length.to_string().parse() else {
        return not_found();
    };
    response
        .headers_mut()
        .insert(header::CONTENT_LENGTH, header_length);
    if partial {
        let range = format!("bytes {}-{}/{}", start, start + length as u64 - 1, total);
        let Ok(range) = range.parse() else {
            return not_found();
        };
        response.headers_mut().insert(header::CONTENT_RANGE, range);
    }
    response
}

fn not_found() -> Response<Body> {
    let mut response = Response::new(Body::from(
        r#"{"code":"not_found","message":"pack not found"}"#,
    ));
    *response.status_mut() = StatusCode::NOT_FOUND;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        http::HeaderValue::from_static("application/json"),
    );
    response
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Fixture failures are assertions.
mod tests {
    use super::*;
    use bytes::Bytes;
    use http_body_util::BodyExt as _;

    #[tokio::test]
    async fn bounded_range_response_has_no_cache_headers() {
        let bytes = Bytes::from_static(b"staged");
        let response = into_response(RetrievalResponse {
            bytes: bytes.clone(),
            start: 7,
            total: 50,
            partial: true,
        });
        assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(response.headers()[header::CONTENT_RANGE], "bytes 7-12/50");
        assert_eq!(response.headers()[header::CONTENT_LENGTH], "6");
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            "application/octet-stream"
        );
        for name in ["cache-control", "expires", "etag", "last-modified", "vary"] {
            assert!(!response.headers().contains_key(name));
        }
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            bytes
        );
    }

    #[tokio::test]
    async fn admission_failure_uses_the_same_private_failure() {
        let cap = crate::guard::CapLayer::new(0, std::time::Duration::ZERO);
        let route = cap
            .layer(tower::service_fn(|_: Request<Body>| async {
                panic!("zero permits must not call the pipeline");
                #[allow(unreachable_code)]
                Ok::<_, Infallible>(Response::new(Body::empty()))
            }))
            .map_response(|response: Response<Body>| {
                if response.status().is_success() {
                    response
                } else {
                    not_found()
                }
            });
        let response = route.oneshot(Request::new(Body::empty())).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(!response.headers().contains_key("retry-after"));
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            r#"{"code":"not_found","message":"pack not found"}"#
        );
    }
}
