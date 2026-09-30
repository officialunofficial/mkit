//! HTTP mounts over real indexed ingestion; adapter bodies must stay lazy.
#![cfg(feature = "http-objects")]
#![allow(clippy::unwrap_used)] // Invalid fixtures are test failures.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::body::Body;
use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::BodyExt as _;
use mkit_core::hash::{Hash, hash, to_hex};
use mkit_core::object::{Blob, Commit, EntryMode, Identity, Object, Tree, TreeEntry};
use mkit_core::pack::PackWriter;
use mkit_core::protocol::{AdvanceOutcome, RefWriteCondition};
use mkit_core::repo_identity::Namespace;
use mkit_core::serialize::serialize;
use mkit_core::sign::{KeyPair, sign_commit};
use mkit_server::auth_v2::AuthV2Config;
use mkit_server::http_objects::mount::HttpMountOptions;
use mkit_server::http_objects::{
    AdmitDecision, AdmitRequest, HttpAdmission, HttpObjectResponse, HttpObjectsConfig,
};
use mkit_server::indexed::IndexedConfig;
use mkit_server::pipeline::{
    AuthMode, Authenticated, Hooks, Pipeline, PipelineConfig, RequestMeta,
};
use mkit_server::policy::{NamespacePolicy, WritePolicy};
use mkit_server::store::{
    BlobBody, BlobKey, BlobMeta, BlobStore, ByteRange, MultipartBlobStore, PackSink,
    UnsupportedPartSink, codec, keys,
};
use mkit_server::upload::{UploadLimits, token::TicketKeys};
use mkit_server::url_token::{UrlTarget, UrlTokenConfig, UrlTokenKeys};
use mkit_server::{
    Addressing, Batch, BeginUploadResult, BoxFuture, Code, MemoryBlobStore, MemoryKv,
    MultiAddressing, NamespaceKey, NamespaceStore, NoopMetrics, Partition, Procedure, RefUpdate,
    RepoName, ServerError, StoreError, SystemClock,
};
use mkit_server_conformance::wire::sign::{Signer, now_ms};
use mkit_server_native::{RouterOptions, build_router};
use tower::ServiceExt as _;

const AUDIENCE: &str = "https://http.test";
const KEY_DOCUMENT: &str = "/.well-known/mkit-url-token-keys.json";
const CONTENT: &[u8] = &[42; 20_000];
type TestPipeline = Pipeline<LazyBlobs, Arc<MemoryKv>, Hooks>;

#[derive(Clone, Default)]
struct LazyBlobs {
    inner: MemoryBlobStore,
    produced: Arc<AtomicUsize>,
}

impl BlobStore for LazyBlobs {
    type Sink = <MemoryBlobStore as BlobStore>::Sink;

    async fn begin(&self, key: BlobKey, len: u64) -> Result<Self::Sink, StoreError> {
        self.inner.begin(key, len).await
    }

    async fn get(
        &self,
        key: &BlobKey,
        range: Option<ByteRange>,
    ) -> Result<Option<BlobBody>, StoreError> {
        let body = self.inner.get(key, range).await?;
        if *key != BlobKey::object(*key.hash()) {
            return Ok(body);
        }
        let Some(BlobBody::Bytes(bytes)) = body else {
            return Ok(body);
        };
        let produced = self.produced.clone();
        let len = bytes.len() as u64;
        let stream = futures::stream::unfold(0_usize, move |at| {
            let (bytes, produced) = (bytes.clone(), produced.clone());
            async move {
                (at < bytes.len()).then(|| {
                    produced.fetch_add(1, Ordering::SeqCst);
                    let end = (at + 4096).min(bytes.len());
                    (Ok(bytes.slice(at..end)), end)
                })
            }
        });
        Ok(Some(BlobBody::Stream {
            len,
            stream: Box::pin(stream),
        }))
    }

    async fn head(&self, key: &BlobKey) -> Result<Option<BlobMeta>, StoreError> {
        self.inner.head(key).await
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.inner.probe().await
    }
    async fn delete(&self, key: &BlobKey) -> Result<bool, StoreError> {
        self.inner.delete(key).await
    }
}

impl MultipartBlobStore for LazyBlobs {
    type PartSink = UnsupportedPartSink;
    const MAX_PARTS: u32 = u32::MAX;
}

struct Fixture {
    pipe: TestPipeline,
    meta: Arc<MemoryKv>,
    blobs: LazyBlobs,
    namespace: Namespace,
    identity: String,
    object: Hash,
    tokens: Option<UrlTokenConfig>,
}

fn authenticate(pipe: &TestPipeline, signer: &Signer, procedure: Procedure) -> Authenticated {
    let body = b"HTTP mount fixture";
    let envelope = signer.sign_body(procedure.connect_path(), body);
    pipe.authenticate(&RequestMeta {
        procedure,
        header: &|name| {
            envelope
                .headers
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.clone())
        },
        header_values: None,
        unary_body: Some(body),
        transport_principal: None,
    })
    .unwrap()
}

#[allow(clippy::too_many_lines)] // Real ticketed publish fixture covers the complete indexed path.
async fn fixture(redirect: bool, with_tokens: bool) -> Fixture {
    let owner = Signer::new([7; 32], AUDIENCE, "unused");
    let namespace = Namespace::parse(&format!("ed25519-{}", owner.public_key_hex())).unwrap();
    let identity = format!("{namespace}/room");
    let signer = Signer::new([7; 32], AUDIENCE, &identity);
    let mut cfg = PipelineConfig::new(
        Addressing::Multi(
            MultiAddressing::new()
                .with_namespace_policy(NamespacePolicy::Allowlist([namespace].into())),
        ),
        AuthMode::AuthV2(AuthV2Config::new(AUDIENCE, "").unwrap()),
        UploadLimits {
            max_total_bytes: 1 << 20,
            max_chunks: 64,
        },
    );
    cfg.write_policy = WritePolicy::Owner;
    cfg.ticket_keys = Some(TicketKeys::new(vec![("test".into(), [8; 32])]).unwrap());
    let mut indexed = IndexedConfig::default();
    indexed.extract_min_bytes = 1024;
    cfg.indexed = Some(indexed);
    let mut http = HttpObjectsConfig::default();
    http.redirect_public_refs = redirect;
    cfg.http_objects = Some(http);
    let tokens = with_tokens.then(token_config);
    cfg.url_tokens.clone_from(&tokens);
    let blobs = LazyBlobs::default();
    let meta = Arc::new(MemoryKv::default());
    let pipe = Pipeline::new(
        blobs.clone(),
        meta.clone(),
        Hooks::new(),
        cfg,
        Arc::new(SystemClock),
        Arc::new(NoopMetrics),
    )
    .unwrap();

    let blob = Object::Blob(Blob {
        data: CONTENT.to_vec(),
    });
    let object = blob.id().unwrap();
    let tree = Object::Tree(Tree {
        entries: vec![
            TreeEntry {
                name: b"big.bin".to_vec(),
                mode: EntryMode::Blob,
                object_hash: object,
            },
            TreeEntry {
                name: b"space name".to_vec(),
                mode: EntryMode::Blob,
                object_hash: object,
            },
        ],
    });
    let key = KeyPair::from_seed([9; 32]);
    let mut commit = Commit::new_unannotated(
        tree.id().unwrap(),
        vec![],
        Identity::ed25519(key.public.0),
        key.public.0,
        b"mount".to_vec(),
        42,
        [0; 64],
    );
    commit.signature = sign_commit(&commit, &key).unwrap().0;
    let commit = Object::Commit(commit);
    let mut writer = PackWriter::new_raw_only();
    for object in [&blob, &tree, &commit] {
        writer
            .push_raw(object.id().unwrap(), &serialize(object).unwrap())
            .unwrap();
    }
    let pack = writer.finish().unwrap();
    let pack_id = hash(&pack);
    let auth = authenticate(&pipe, &signer, Procedure::BeginUpload);
    let BeginUploadResult::Ticket { id: ticket, .. } = pipe
        .begin_upload(&auth, "refs/heads/main", &pack_id, pack.len() as u64)
        .await
        .unwrap()
    else {
        panic!("expected an upload ticket");
    };
    let mut sink = blobs
        .begin(BlobKey::pack(pack_id), pack.len() as u64)
        .await
        .unwrap();
    sink.write(Bytes::from(pack)).await.unwrap();
    sink.commit().await.unwrap();
    let marker = [b"mkit-upload-marker:v1\0".as_slice(), &ticket, &pack_id].concat();
    let mut sink = blobs
        .begin(BlobKey::upload_marker(hash(&marker)), marker.len() as u64)
        .await
        .unwrap();
    sink.write(Bytes::from(marker)).await.unwrap();
    sink.commit().await.unwrap();
    let update = |name: &str, id| RefUpdate {
        name: name.into(),
        condition: RefWriteCondition::Missing,
        new: Some(id),
    };
    let outcome = pipe
        .advance_refs_with_tickets(
            &authenticate(&pipe, &signer, Procedure::AdvanceRefs),
            update("refs/heads/main", commit.id().unwrap()),
            update("refs/mkit/packmap/main", pack_id),
            vec![ticket],
        )
        .await
        .unwrap();
    assert_eq!(outcome, AdvanceOutcome::Committed);
    Fixture {
        pipe,
        meta,
        blobs,
        namespace,
        identity,
        object,
        tokens,
    }
}

impl Fixture {
    fn object_url(&self) -> String {
        format!("/{}/-/objects/{}", self.identity, to_hex(&self.object))
    }
    fn ref_url(&self, file: &str) -> String {
        format!("/{}/-/refs/heads/main/-/{file}", self.identity)
    }
    async fn make_private(&self) {
        self.meta
            .apply(
                &Partition::Namespace(NamespaceKey::from_namespace(&self.namespace)),
                Batch::new().put(
                    keys::repo_visibility(&RepoName::new("room").unwrap()),
                    codec::encode_repo_visibility(&codec::RepoVisibilityV1 {
                        visibility: codec::StoredVisibility::Private,
                        last_created_ms: 0,
                        last_statement_id: None,
                    }),
                ),
            )
            .await
            .unwrap();
    }
    fn token(&self) -> String {
        self.tokens
            .as_ref()
            .unwrap()
            .mint(
                AUDIENCE,
                &self.identity,
                &UrlTarget::Object(self.object),
                0,
                now_ms(),
                60,
            )
            .unwrap()
            .expose()
            .to_owned()
    }
}

fn options(origins: &[&str]) -> RouterOptions {
    let mut opts = RouterOptions::default();
    opts.http_objects = Some(HttpMountOptions {
        cors_origins: origins.iter().map(|s| (*s).into()).collect(),
    });
    opts
}

async fn request(
    router: &axum::Router,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
) -> Response<Body> {
    let mut builder = Request::builder().method(method).uri(path);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    router
        .clone()
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap()
}

async fn body(response: Response<Body>) -> Bytes {
    response.into_body().collect().await.unwrap().to_bytes()
}

fn cors(response: &Response<Body>, allowed: Option<&str>, vary: bool) {
    assert_eq!(
        response
            .headers()
            .get("access-control-allow-origin")
            .map(|v| v.to_str().unwrap()),
        allowed
    );
    assert!(
        !response
            .headers()
            .contains_key("access-control-allow-credentials")
    );
    if vary {
        assert!(response.headers().get_all("vary").iter().any(|v| {
            v.to_str()
                .unwrap()
                .split(',')
                .any(|s| s.trim().eq_ignore_ascii_case("origin"))
        }));
    }
}

#[tokio::test]
async fn get_and_range_preserve_length_and_stream_lazily() {
    let fx = fixture(false, false).await;
    let produced = fx.blobs.produced.clone();
    let path = fx.object_url();
    let router = build_router(Arc::new(fx.pipe), &options(&[]));
    let response = request(&router, "GET", &path, &[]).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()["content-length"],
        CONTENT.len().to_string()
    );
    assert_eq!(
        response.headers()["cache-control"],
        "public, max-age=31536000, immutable"
    );
    cors(&response, Some("*"), false);
    assert_eq!(
        produced.load(Ordering::SeqCst),
        0,
        "mount buffered the body"
    );
    let mut stream = response.into_body();
    let first = stream.frame().await.unwrap().unwrap().into_data().unwrap();
    assert_eq!(first.len(), 4096);
    assert_eq!(
        produced.load(Ordering::SeqCst),
        1,
        "mount polled ahead of consumer"
    );
    assert_eq!(
        first.len() + stream.collect().await.unwrap().to_bytes().len(),
        CONTENT.len()
    );
    let response = request(&router, "GET", &path, &[("range", "bytes=13-24")]).await;
    assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(response.headers()["content-length"], "12");
    assert_eq!(response.headers()["content-range"], "bytes 13-24/20000");
    cors(&response, Some("*"), false);
    assert_eq!(body(response).await, &CONTENT[13..25]);
}

#[tokio::test]
async fn http_streams_hold_the_concurrency_slot_and_cap_errors_keep_read_policy() {
    let fx = fixture(false, false).await;
    let path = fx.object_url();
    let mut opts = options(&["https://allowed.test"]);
    opts.max_concurrency = 1;
    opts.queue_timeout = std::time::Duration::ZERO;
    let router = build_router(Arc::new(fx.pipe), &opts);
    let origin = [("origin", "https://allowed.test")];
    let first = request(&router, "GET", &path, &origin).await;
    assert_eq!(first.status(), StatusCode::OK);
    let preflight = request(&router, "OPTIONS", &path, &origin).await;
    assert_eq!(preflight.status(), StatusCode::NO_CONTENT);
    cors(&preflight, Some("https://allowed.test"), true);
    assert!(body(preflight).await.is_empty());
    for method in ["GET", "HEAD"] {
        let response = request(&router, method, &path, &origin).await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        cors(&response, Some("https://allowed.test"), true);
        assert_eq!(response.headers()["cache-control"], "no-store");
        if method == "HEAD" {
            assert!(body(response).await.is_empty());
        }
    }
    drop(first);
    let response = request(&router, "GET", &path, &origin).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body(response).await, CONTENT);
}

#[tokio::test]
async fn raw_escaped_paths_and_trailing_empty_query_reach_the_parser() {
    let fx = fixture(false, false).await;
    let escaped = fx.ref_url("space%20name");
    let double = fx.ref_url("space%2520name");
    let delimiter = fx.ref_url("big%2Fbin");
    let object = fx.object_url();
    let router = build_router(Arc::new(fx.pipe), &options(&[]));
    let response = request(&router, "GET", &escaped, &[]).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body(response).await, CONTENT);
    for (path, expected) in [
        (double, 404),
        (delimiter, 400),
        (format!("{object}?"), 400),
        (format!("{object}?token=x&token=y"), 400),
    ] {
        let response = request(&router, "GET", &path, &[]).await;
        assert_eq!(response.status().as_u16(), expected, "{path}");
        cors(&response, Some("*"), false);
    }
}

#[tokio::test]
async fn cors_and_head_cover_success_conditionals_and_errors() {
    let fx = fixture(false, false).await;
    let path = fx.object_url();
    let etag = format!("\"{}\"", to_hex(&fx.object));
    let proof_path = format!("{}?proof=1", fx.ref_url("big.bin"));
    let router = build_router(Arc::new(fx.pipe), &options(&["https://allowed.test"]));
    let cases = [
        (path.clone(), vec![], 200),
        (path.clone(), vec![("range", "bytes=1-2")], 206),
        (path.clone(), vec![("if-none-match", etag.as_str())], 304),
        (path.clone(), vec![("range", "bytes=999999-")], 416),
        (format!("{path}?"), vec![], 400),
        (
            path.replace(&to_hex(&fx.object), &"00".repeat(32)),
            vec![],
            404,
        ),
        (proof_path, vec![], 416),
    ];
    for (path, headers, expected) in cases {
        for method in ["GET", "HEAD"] {
            for origin in ["https://allowed.test", "https://denied.test"] {
                let mut headers = headers.clone();
                headers.push(("origin", origin));
                let response = request(&router, method, &path, &headers).await;
                assert_eq!(response.status().as_u16(), expected, "{method} {path}");
                cors(
                    &response,
                    (origin == "https://allowed.test").then_some(origin),
                    true,
                );
                if method == "HEAD" || expected == 304 {
                    assert!(body(response).await.is_empty());
                }
            }
        }
    }
    let response = request(
        &router,
        "POST",
        &path,
        &[("origin", "https://allowed.test")],
    )
    .await;
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    cors(&response, Some("https://allowed.test"), true);
}

#[tokio::test]
async fn preflight_is_unpaid_and_exposes_the_spec_and_admission_headers() {
    let fx = fixture(false, false).await;
    fx.make_private().await;
    let path = fx.object_url();
    let pipe = fx.pipe.with_http_seams(|mut s| {
        s.admission = Arc::new(Challenge);
        s
    });
    let router = build_router(Arc::new(pipe), &options(&[]));
    let response = request(
        &router,
        "OPTIONS",
        &path,
        &[
            ("origin", "https://browser.test"),
            ("access-control-request-method", "GET"),
            (
                "access-control-request-headers",
                "Range,Payment-Authorization",
            ),
        ],
    )
    .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    cors(&response, Some("*"), false);
    assert_eq!(
        response.headers()["access-control-allow-methods"],
        "GET, HEAD, OPTIONS"
    );
    let values = |name| {
        response
            .headers()
            .get(name)
            .unwrap()
            .to_str()
            .unwrap()
            .split(',')
            .map(|s| s.trim().to_ascii_lowercase())
            .collect::<Vec<_>>()
    };
    let allow = values("access-control-allow-headers");
    for required in [
        "range",
        "if-none-match",
        "if-range",
        "payment-authorization",
        "payment-signature",
        "authorization",
        "accept-payment",
    ] {
        assert!(
            allow.iter().any(|h| h == required),
            "allow lacks {required}"
        );
    }
    let expose = values("access-control-expose-headers");
    for required in [
        "etag",
        "content-range",
        "accept-ranges",
        "content-length",
        "x-mkit-commit",
        "x-mkit-object",
        "x-mkit-object-type",
        "www-authenticate",
        "payment-receipt",
        "payment-required",
        "payment-response",
        "link",
    ]
    .into_iter()
    .chain(
        mkit_server::pipeline::ADMISSION_EXPOSE_HEADERS
            .iter()
            .copied(),
    ) {
        assert!(
            expose.iter().any(|h| h.eq_ignore_ascii_case(required)),
            "expose lacks {required}"
        );
    }
    assert!(body(response).await.is_empty());
}

struct Challenge;
impl HttpAdmission for Challenge {
    fn admit<'a>(
        &'a self,
        _: &'a AdmitRequest<'a>,
    ) -> BoxFuture<'a, Result<AdmitDecision, ServerError>> {
        Box::pin(async {
            Ok(AdmitDecision::Respond(
                HttpObjectResponse::error(402)
                    .with_header("WWW-Authenticate", "Payment realm=repo")
                    .with_header("WWW-Authenticate", "Other realm=repo")
                    .with_header("Vary", "Accept")
                    .with_header("Vary", "Accept-Encoding"),
            ))
        })
    }
}

#[tokio::test]
async fn repeated_vary_fields_survive_mount_policy() {
    for origins in [&[][..], &["https://allowed.test"][..]] {
        let fx = fixture(false, false).await;
        let path = fx.ref_url("big.bin");
        let pipe = fx.pipe.with_http_seams(|mut seams| {
            seams.admission = Arc::new(Challenge);
            seams
        });
        let router = build_router(Arc::new(pipe), &options(origins));
        let response = request(&router, "GET", &path, &[("origin", "https://allowed.test")]).await;
        let vary: Vec<_> = response
            .headers()
            .get_all("vary")
            .iter()
            .flat_map(|value| value.to_str().unwrap().split(','))
            .map(str::trim)
            .collect();
        assert!(vary.contains(&"Accept"));
        assert!(vary.contains(&"Accept-Encoding"));
        if !origins.is_empty() {
            assert!(vary.contains(&"Origin"));
        }
    }
}

#[tokio::test]
async fn challenges_preserve_repeated_fields_and_head_has_no_body() {
    let fx = fixture(true, false).await;
    let path = fx.ref_url("big.bin");
    let pipe = fx.pipe.with_http_seams(|mut s| {
        s.admission = Arc::new(Challenge);
        s
    });
    let router = build_router(Arc::new(pipe), &options(&[]));
    for method in ["GET", "HEAD"] {
        let response = request(&router, method, &path, &[]).await;
        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
        cors(&response, Some("*"), false);
        let fields: Vec<_> = response
            .headers()
            .get_all("www-authenticate")
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(fields, ["Payment realm=repo", "Other realm=repo"]);
        assert!(!response.headers().contains_key("location"));
        assert_eq!(response.headers()["cache-control"], "no-store");
        if method == "HEAD" {
            assert!(body(response).await.is_empty());
        }
    }
}

#[tokio::test]
async fn non_ascii_payment_headers_and_duplicate_occurrences_are_denied() {
    let fx = fixture(false, false).await;
    let path = fx.object_url();
    let pipe = fx.pipe.with_http_seams(|mut s| {
        s.admission = Arc::new(Challenge);
        s
    });
    let router = build_router(Arc::new(pipe), &options(&[]));
    for repeated in [false, true] {
        for method in ["GET", "HEAD"] {
            let mut req = Request::builder()
                .method(method)
                .uri(&path)
                .body(Body::empty())
                .unwrap();
            if repeated {
                req.headers_mut().append(
                    "payment-authorization",
                    http::HeaderValue::from_static("valid"),
                );
            }
            req.headers_mut().append(
                "payment-authorization",
                http::HeaderValue::from_bytes(b"\x80").unwrap(),
            );
            let response = router.clone().oneshot(req).await.unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
            cors(&response, Some("*"), false);
            if method == "HEAD" {
                assert!(body(response).await.is_empty());
            }
        }
    }
}

#[tokio::test]
async fn private_token_cache_and_uniform_misses_cross_the_mount() {
    let fx = fixture(false, true).await;
    fx.make_private().await;
    let path = fx.object_url();
    let token_path = format!("{path}?token={}", fx.token());
    let etag = format!("\"{}\"", to_hex(&fx.object));
    let missing = path.replace("/room/", "/missing/");
    let router = build_router(Arc::new(fx.pipe), &options(&[]));
    for method in ["GET", "HEAD"] {
        for headers in [
            vec![],
            vec![("if-none-match", etag.as_str())],
            vec![("range", "bytes=1-2")],
        ] {
            let response = request(&router, method, &token_path, &headers).await;
            assert!(matches!(response.status().as_u16(), 200 | 206 | 304));
            assert!(
                response.headers()["cache-control"]
                    .to_str()
                    .unwrap()
                    .starts_with("private, max-age=")
            );
            cors(&response, Some("*"), false);
            if method == "HEAD" {
                assert!(body(response).await.is_empty());
            }
        }
        let baseline = request(&router, method, &missing, &[]).await;
        let baseline_headers = baseline.headers().clone();
        let baseline_body = body(baseline).await;
        for target in [&path, &format!("{path}?token=invalid")] {
            let response = request(&router, method, target, &[]).await;
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
            assert_eq!(response.headers(), &baseline_headers);
            assert_eq!(body(response).await, baseline_body);
        }
    }
}

#[tokio::test]
async fn redirects_are_explicit_and_relative_and_proofs_never_redirect() {
    for enabled in [false, true] {
        let fx = fixture(enabled, false).await;
        let path = fx.ref_url("big.bin");
        let location = fx.object_url();
        let router = build_router(Arc::new(fx.pipe), &options(&[]));
        for method in ["GET", "HEAD"] {
            let response = request(&router, method, &path, &[]).await;
            assert_eq!(response.status().as_u16(), if enabled { 302 } else { 200 });
            if enabled {
                assert_eq!(response.headers()["location"], location);
                assert_eq!(response.headers()["cache-control"], "no-cache");
            }
            cors(&response, Some("*"), false);
            if method == "HEAD" {
                assert!(body(response).await.is_empty());
            }
            let response = request(&router, method, &format!("{path}?proof=1"), &[]).await;
            assert_eq!(response.status(), StatusCode::RANGE_NOT_SATISFIABLE);
            assert!(!response.headers().contains_key("location"));
        }
    }
}

#[tokio::test]
async fn key_document_uses_active_and_retained_keys_and_bypasses_admission() {
    let fx = fixture(false, true).await;
    fx.make_private().await;
    let tokens = fx.tokens.as_ref().unwrap();
    let expected = tokens.keys().key_set_json(tokens.ttl_ms());
    let pipe = fx.pipe.with_http_seams(|mut s| {
        s.admission = Arc::new(Challenge);
        s
    });
    let router = build_router(Arc::new(pipe), &options(&[]));
    for method in ["GET", "HEAD"] {
        let response = request(&router, method, KEY_DOCUMENT, &[]).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["cache-control"], "public, max-age=300");
        assert_eq!(
            response.headers()["content-length"],
            expected.len().to_string()
        );
        cors(&response, Some("*"), false);
        let bytes = body(response).await;
        if method == "HEAD" {
            assert!(bytes.is_empty());
        } else {
            assert_eq!(bytes, expected);
        }
    }
    for (method, status) in [
        ("OPTIONS", StatusCode::NO_CONTENT),
        ("POST", StatusCode::METHOD_NOT_ALLOWED),
    ] {
        let response = request(&router, method, KEY_DOCUMENT, &[]).await;
        assert_eq!(response.status(), status);
        cors(&response, Some("*"), false);
    }
}

fn token_config() -> UrlTokenConfig {
    let retired = ed25519_dalek::SigningKey::from_bytes(&[14; 32])
        .verifying_key()
        .to_bytes();
    UrlTokenConfig::new(
        UrlTokenKeys::parse_key_file(&format!(
            "active {}\nretired {} 1000",
            "0d".repeat(32),
            to_hex(&retired),
        ))
        .unwrap(),
    )
}

#[test]
fn hook_and_enc_role_checks_reject_active_and_retired_public_keys() {
    let tokens = token_config();
    let others = ed25519_dalek::SigningKey::from_bytes(&[15; 32])
        .verifying_key()
        .to_bytes();
    for public in tokens.keys().public_keys() {
        let error =
            mkit_server_native::http_mount::check_other_keys(Some(&tokens), &[others, public])
                .unwrap_err();
        assert!(!error.message.contains(&to_hex(&public)));
    }
    mkit_server_native::http_mount::check_other_keys(Some(&tokens), &[others]).unwrap();
    mkit_server_native::http_mount::check_other_keys(None, &[others]).unwrap();
}

#[tokio::test]
async fn bridge_suppresses_head_bodies_for_every_status() {
    for status in [
        200, 206, 302, 304, 400, 401, 402, 403, 404, 405, 416, 451, 503,
    ] {
        let mut response = HttpObjectResponse::new(status).with_header("Content-Length", "7");
        response.body = mkit_server::http_objects::HttpBody::Bytes(Bytes::from_static(b"payload"));
        let response = mkit_server_native::http_mount::into_response(response, true);
        assert_eq!(response.status().as_u16(), status);
        assert_eq!(response.headers()["content-length"], "7");
        assert!(body(response).await.is_empty());
    }
}

#[derive(Clone, Default)]
struct Captured(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for Captured {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn native_trace_shows_paths_without_any_query_values() {
    let fx = fixture(false, false).await;
    let captured = Captured::default();
    let writer = captured.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    let router = build_router(Arc::new(fx.pipe), &RouterOptions::default());
    let path = "/mkit.transport.v1.TransportService/ReadRef";
    let response = request(
        &router,
        "GET",
        &format!("{path}?token=trace-secret-0123&other=other-secret-4567"),
        &[],
    )
    .await;
    drop(response);
    let output = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
    assert!(output.contains(path), "{output}");
    for secret in ["trace-secret-0123", "other-secret-4567", "token="] {
        assert!(!output.contains(secret), "query leaked: {output}");
    }
}

#[tokio::test]
async fn mount_opt_in_and_http_config_are_both_required_and_stage_one_cannot_issue_urls() {
    let fx = fixture(false, true).await;
    let path = fx.object_url();
    let router = build_router(Arc::new(fx.pipe), &RouterOptions::default());
    for path in [path.as_str(), KEY_DOCUMENT] {
        let response = request(&router, "GET", path, &[]).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(
            !response
                .headers()
                .contains_key("access-control-allow-origin")
        );
    }
    let mut cfg = PipelineConfig::new(
        Addressing::Single {
            repo: mkit_server::RepoId {
                namespace: NamespaceKey::deployment_default(),
                name: RepoName::new("default").unwrap(),
            },
        },
        AuthMode::Open,
        UploadLimits {
            max_total_bytes: 1 << 20,
            max_chunks: 64,
        },
    );
    assert!(cfg.http_objects.is_none() && cfg.indexed.is_none() && cfg.url_tokens.is_none());
    cfg.ticket_keys = Some(TicketKeys::new(vec![("test".into(), [8; 32])]).unwrap());
    let pipe = Pipeline::new(
        LazyBlobs::default(),
        Arc::new(MemoryKv::default()),
        Hooks::new(),
        cfg,
        Arc::new(SystemClock),
        Arc::new(NoopMetrics),
    )
    .unwrap();
    let auth = pipe
        .authenticate(&RequestMeta {
            procedure: Procedure::IssueObjectUrl,
            header: &|_| None,
            header_values: None,
            unary_body: Some(b""),
            transport_principal: None,
        })
        .unwrap();
    assert_eq!(
        pipe.issue_object_url(&auth, UrlTarget::Object([0; 32]), 60)
            .await
            .unwrap_err()
            .code(),
        Code::Unimplemented
    );
    let router = build_router(Arc::new(pipe), &options(&[]));
    for path in ["/-/objects/invalid", KEY_DOCUMENT] {
        let response = request(&router, "GET", path, &[]).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(
            !response
                .headers()
                .contains_key("access-control-allow-origin")
        );
    }
}

#[derive(Debug)]
struct ConfiguredAllowance;
impl HttpAdmission for ConfiguredAllowance {
    fn admit<'a>(
        &'a self,
        _: &'a AdmitRequest<'a>,
    ) -> BoxFuture<'a, Result<AdmitDecision, ServerError>> {
        Box::pin(async {
            Ok(AdmitDecision::Allow(
                mkit_server::http_objects::Admitted::default(),
            ))
        })
    }
}

#[tokio::test]
async fn redirects_follow_conditionals_and_range_and_exclude_private_or_admitted_reads() {
    let fx = fixture(true, false).await;
    let path = fx.ref_url("big.bin");
    let etag = format!("\"{}\"", to_hex(&fx.object));
    let pipe = Arc::new(fx.pipe);
    let router = build_router(pipe.clone(), &options(&[]));
    for method in ["GET", "HEAD"] {
        for (header, value, status) in [
            ("if-none-match", etag.as_str(), StatusCode::NOT_MODIFIED),
            ("range", "bytes=999999-", StatusCode::RANGE_NOT_SATISFIABLE),
        ] {
            let response = request(&router, method, &path, &[(header, value)]).await;
            assert_eq!(response.status(), status);
            assert!(!response.headers().contains_key("location"));
        }
        let response = request(&router, method, &format!("{path}/missing"), &[]).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(!response.headers().contains_key("location"));
    }
    drop(router);
    let pipe = Arc::try_unwrap(pipe).unwrap().with_http_seams(|mut seams| {
        seams.admission = Arc::new(ConfiguredAllowance);
        seams
    });
    let admitted = build_router(Arc::new(pipe), &options(&[]));
    for method in ["GET", "HEAD"] {
        let response = request(&admitted, method, &path, &[]).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["cache-control"], "private, no-cache");
        assert!(!response.headers().contains_key("location"));
    }
    let private = fixture(true, true).await;
    private.make_private().await;
    let token = private
        .tokens
        .as_ref()
        .unwrap()
        .mint(
            AUDIENCE,
            &private.identity,
            &UrlTarget::path("refs/heads/main", "big.bin").unwrap(),
            0,
            now_ms(),
            60,
        )
        .unwrap();
    let path = format!("{}?token={}", private.ref_url("big.bin"), token.expose());
    let router = build_router(Arc::new(private.pipe), &options(&[]));
    for method in ["GET", "HEAD"] {
        let response = request(&router, method, &path, &[]).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["cache-control"], "private, no-cache");
        assert!(!response.headers().contains_key("location"));
    }
}
