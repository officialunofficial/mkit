//! Synthetic responses through the production bridge and final response policy.
//! This fixture has no deployment bindings and is run only by the local probe.
use bytes::Bytes;
use futures::StreamExt as _;
use mkit_server::http_objects::mount::{HttpMountOptions, key_document};
use mkit_server::http_objects::{HttpBody, HttpObjectResponse};
use mkit_server_worker::http_mount::{raw_path_query, response_to_worker, token_config};
use worker::{Context, Env, Error, Fetch, Method, Request, Response, Result, Url, event};

#[event(fetch)]
pub async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    let url = req.inner().url();
    let (path, query) =
        raw_path_query(&url).map_err(|_| Error::RustError("invalid test request URL".into()))?;
    if path.starts_with("/raw") {
        return Response::from_json(&serde_json::json!({ "path": path, "query": query }));
    }
    let options = HttpMountOptions {
        cors_origins: if path.starts_with("/restricted/") {
            vec!["https://allowed.example".into()]
        } else {
            vec![]
        },
    };
    let response = if path.ends_with("/keys") {
        let config = token_config(&|name| {
            (name == "URL_TOKEN_KEYS").then(|| format!("active {}", "11".repeat(32)))
        })
        .map_err(|_| Error::RustError("invalid test key configuration".into()))?
        .ok_or_else(|| Error::RustError("missing test key configuration".into()))?;
        key_document(&config, req.method().as_ref())
    } else if req.method() == Method::Options {
        HttpObjectResponse::new(204)
    } else if path.ends_with("/adapter-error") || path.ends_with("/private-adapter-error") {
        // The outer finalizer must supply error no-store/security/CORS/HEAD policy.
        let mut response = HttpObjectResponse {
            status: 503,
            headers: vec![("Content-Type", "text/plain"), ("Content-Length", "16")]
                .into_iter()
                .map(|(name, value)| (name, value.into()))
                .collect(),
            body: HttpBody::Bytes(Bytes::from_static(b"adapter failure!")),
        };
        if path.ends_with("/private-adapter-error") {
            response
                .headers
                .push(("Cache-Control", "private, max-age=10".into()));
        }
        response
    } else {
        synthetic_response(&req, &env, path).await?
    };
    let origin = req.headers().get("Origin")?;
    response_to_worker(response, req.method().as_ref(), origin.as_deref(), &options)
}

async fn synthetic_response(req: &Request, env: &Env, path: &str) -> Result<HttpObjectResponse> {
    let status = if path.ends_with("/challenge") {
        402
    } else if path.ends_with("/notfound") {
        404
    } else if path.ends_with("/notmodified") {
        304
    } else if req.headers().get("Range")?.is_some() {
        206
    } else {
        path.rsplit('/')
            .next()
            .and_then(|part| part.parse().ok())
            .unwrap_or(200)
    };
    let data = if status == 206 {
        b"bcd".as_slice()
    } else {
        b"abcdef".as_slice()
    };
    let mut response = HttpObjectResponse::new(status)
        .with_header("Content-Length", data.len().to_string())
        .with_header(
            "Cache-Control",
            if path.ends_with("/private") {
                "private, max-age=10, immutable"
            } else {
                "public, max-age=3600, immutable"
            },
        )
        .with_header("Vary", "Accept-Encoding");
    if status == 402 {
        response.headers.extend([
            ("WWW-Authenticate", "Payment first".into()),
            ("WWW-Authenticate", "Payment second".into()),
        ]);
    }
    if status == 206 {
        response
            .headers
            .push(("Content-Range", "bytes 1-3/6".into()));
    }
    if status != 304 {
        let stream = if path.ends_with("/slow") {
            let origin = env.var("DELAY_ORIGIN")?.to_string();
            let delayed_url = Url::parse(&format!("{origin}/delayed"))
                .map_err(|_| Error::RustError("invalid local delay origin".into()))?;
            let source = futures::stream::once(async { Ok(Bytes::from_static(b"a")) }).chain(
                futures::stream::once(async move {
                    Fetch::Url(delayed_url).send().await.map_err(|_| {
                        mkit_server::ServerError::unavailable("local delay request failed")
                    })?;
                    Ok(Bytes::from_static(b"bcdef"))
                }),
            );
            Box::pin(source) as mkit_server::BoxStream<'static, _>
        } else {
            Box::pin(futures::stream::iter([
                Ok(Bytes::copy_from_slice(&data[..1])),
                Ok(Bytes::copy_from_slice(&data[1..])),
            ])) as mkit_server::BoxStream<'static, _>
        };
        response.body = HttpBody::Stream {
            len: data.len() as u64,
            stream,
        };
    }
    Ok(response)
}
