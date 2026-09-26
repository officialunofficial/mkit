//! The router's production layers, graceful shutdown, the serve lock and
//! the fail-closed `serve` configuration.

#![allow(clippy::unwrap_used)] // unwrap is the assertion in tests

mod common;

use std::convert::Infallible;
use std::io::Write as _;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::Body;
use buffa::Message as _;
use bytes::Bytes;
use futures::StreamExt as _;
use http::{Request, StatusCode};
use http_body_util::BodyExt as _;
use mkit_core::hash::{hash, to_hex};
use mkit_server::fs::FsLayoutStore;
use mkit_server::pipeline::{AuthMode, Hooks, Pipeline, PipelineConfig};
use mkit_server::upload::UploadLimits;
use mkit_server::{
    Addressing, Batch, BatchOutcome, Cursor, Key, MemoryBlobStore, MemoryKv, NamespaceKey,
    NamespaceStore, NoopMetrics, Partition, PartitionStats, Redacted, RepoId, RepoName, ScanPage,
    StoreCapabilities, StoreError, SystemClock, Value,
};
use mkit_server_conformance::wire::client::{Reply, decode_stream, decode_unary, frame};
use mkit_server_native::config::MetaChoice;
use mkit_server_native::{CorsPolicy, RouterOptions, Shutdown, build_router, exit, server};
use mkit_transport_connect::generated::__buffa::oneof::upload_pack_request::Body as UploadBody;
use mkit_transport_connect::generated::{
    PackChunk, ReadRefRequest, ReadRefResponse, UploadPackHeader, UploadPackRequest,
    UploadPackResponse,
};
use tower::ServiceExt as _;

const READ_REF: &str = "/mkit.transport.v1.TransportService/ReadRef";
const UPLOAD_PACK: &str = "/mkit.transport.v1.TransportService/UploadPack";
const BIN: &str = env!("CARGO_BIN_EXE_mkit-server");

// ---------------------------------------------------------------------------
// A slow store, for the timeout and concurrency tests.

/// [`MemoryKv`] whose `get` sleeps `delay` and counts calls in flight.
#[derive(Clone)]
struct SlowKv {
    inner: Arc<MemoryKv>,
    delay: Duration,
    now: Arc<AtomicUsize>,
    peak: Arc<AtomicUsize>,
}

impl SlowKv {
    fn new(delay: Duration) -> Self {
        Self {
            inner: Arc::new(MemoryKv::default()),
            delay,
            now: Arc::default(),
            peak: Arc::default(),
        }
    }
}

impl NamespaceStore for SlowKv {
    fn capabilities(&self) -> StoreCapabilities {
        self.inner.capabilities()
    }
    async fn get(&self, p: &Partition, key: &Key) -> Result<Option<Value>, StoreError> {
        let n = self.now.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(n, Ordering::SeqCst);
        tokio::time::sleep(self.delay).await;
        self.now.fetch_sub(1, Ordering::SeqCst);
        self.inner.get(p, key).await
    }
    async fn get_many(
        &self,
        p: &Partition,
        keys: &[Key],
    ) -> Result<Vec<Option<Value>>, StoreError> {
        self.inner.get_many(p, keys).await
    }
    async fn scan(
        &self,
        p: &Partition,
        start: &Key,
        end: &Key,
        after: Option<&Cursor>,
        limit: u32,
    ) -> Result<ScanPage, StoreError> {
        self.inner.scan(p, start, end, after, limit).await
    }
    async fn apply(&self, p: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
        self.inner.apply(p, batch).await
    }
    async fn stats(&self, p: &Partition) -> Result<PartitionStats, StoreError> {
        self.inner.stats(p).await
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.inner.probe().await
    }
}

fn pipeline<N: NamespaceStore + 'static>(
    meta: N,
    auth: AuthMode,
) -> Arc<Pipeline<MemoryBlobStore, N, Hooks>> {
    let repo = RepoId {
        namespace: NamespaceKey::deployment_default(),
        name: RepoName::new("default").unwrap(),
    };
    let limits = UploadLimits {
        max_total_bytes: 1 << 20,
        max_chunks: 64,
    };
    let cfg = PipelineConfig::new(Addressing::Single { repo }, auth, limits);
    let pipe = Pipeline::new(
        MemoryBlobStore::default(),
        meta,
        Hooks::new(),
        cfg,
        Arc::new(SystemClock),
        Arc::new(NoopMetrics),
    )
    .unwrap();
    Arc::new(pipe)
}

fn read_ref_request(headers: &[(&str, &str)]) -> Request<Body> {
    let body = ReadRefRequest {
        name: Some("refs/heads/main".to_owned()),
        ..Default::default()
    }
    .encode_to_vec();
    let mut req = Request::post(READ_REF)
        .header("content-type", "application/proto")
        .header("connect-protocol-version", "1");
    for (name, value) in headers {
        req = req.header(*name, *value);
    }
    req.body(Body::from(body)).unwrap()
}

async fn reply(resp: http::Response<Body>) -> Reply {
    let (parts, body) = resp.into_parts();
    Reply {
        status: parts.status.as_u16(),
        headers: parts.headers,
        body: body.collect().await.unwrap().to_bytes(),
    }
}

// ---------------------------------------------------------------------------
// Layers.

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unary_timeout_returns_deadline_exceeded() {
    let mut opts = RouterOptions::default();
    opts.unary_timeout = Duration::from_millis(200);
    let router = build_router(
        pipeline(SlowKv::new(Duration::from_secs(5)), AuthMode::Open),
        &opts,
    );
    let started = Instant::now();
    let resp = router.oneshot(read_ref_request(&[])).await.unwrap();
    let first = reply(resp).await;
    let err = decode_unary::<ReadRefResponse>(&first)
        .unwrap()
        .unwrap_err();
    assert_eq!(err.code, "deadline_exceeded", "{err}");
    assert!(started.elapsed() < Duration::from_secs(4));

    // A client may shorten the deadline, never extend it.
    let resp = build_router(
        pipeline(SlowKv::new(Duration::from_secs(5)), AuthMode::Open),
        &opts,
    )
    .oneshot(read_ref_request(&[("connect-timeout-ms", "600000")]))
    .await
    .unwrap();
    let err = decode_unary::<ReadRefResponse>(&reply(resp).await)
        .unwrap()
        .unwrap_err();
    assert_eq!(err.code, "deadline_exceeded");
    assert!(started.elapsed() < Duration::from_secs(8));

    // A fast call is unaffected.
    let resp = build_router(pipeline(SlowKv::new(Duration::ZERO), AuthMode::Open), &opts)
        .oneshot(read_ref_request(&[]))
        .await
        .unwrap();
    let ok = decode_unary::<ReadRefResponse>(&reply(resp).await).unwrap();
    assert!(ok.is_ok(), "{ok:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrency_limit_queues_or_rejects_excess() {
    let kv = SlowKv::new(Duration::from_millis(300));
    let mut opts = RouterOptions::default();
    opts.max_concurrency = 1;
    let router = build_router(pipeline(kv.clone(), AuthMode::Open), &opts);
    let started = Instant::now();
    let calls: Vec<_> = (0..3)
        .map(|_| tokio::spawn(router.clone().oneshot(read_ref_request(&[]))))
        .collect();
    for call in calls {
        let reply = reply(call.await.unwrap().unwrap()).await;
        assert!(decode_unary::<ReadRefResponse>(&reply).unwrap().is_ok());
    }
    // The excess calls queued: one at a time, across clones of the router.
    assert_eq!(kv.peak.load(Ordering::SeqCst), 1);
    assert!(started.elapsed() >= Duration::from_millis(900));

    // With room for all three, they overlap.
    let kv = SlowKv::new(Duration::from_millis(300));
    opts.max_concurrency = 8;
    let router = build_router(pipeline(kv.clone(), AuthMode::Open), &opts);
    let calls: Vec<_> = (0..3)
        .map(|_| tokio::spawn(router.clone().oneshot(read_ref_request(&[]))))
        .collect();
    for call in calls {
        call.await.unwrap().unwrap();
    }
    assert!(kv.peak.load(Ordering::SeqCst) > 1);
}

#[tokio::test]
async fn body_limit_rejects_oversize_before_handler() {
    let kv = SlowKv::new(Duration::ZERO);
    let mut opts = RouterOptions::default();
    opts.max_body_bytes = 1024;
    let router = build_router(pipeline(kv.clone(), AuthMode::Open), &opts);
    let body = vec![0u8; 4096];
    let req = Request::post(UPLOAD_PACK)
        .header("content-type", "application/connect+proto")
        .header("connect-protocol-version", "1")
        .header("content-length", body.len())
        .body(Body::from(body))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

    // Within the limit, the same route answers normally.
    let resp = router.oneshot(read_ref_request(&[])).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn cors_preflight_ok_without_auth() {
    let auth = AuthMode::Bearer {
        token: Redacted::new("cors-token"),
    };
    let mut opts = RouterOptions::default();
    opts.cors = CorsPolicy::AllowAny;
    let router = build_router(pipeline(MemoryKv::default(), auth), &opts);
    let preflight = Request::options(READ_REF)
        .header("origin", "https://app.example")
        .header("access-control-request-method", "POST")
        .header(
            "access-control-request-headers",
            "authorization,x-signature,content-type",
        )
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(preflight).await.unwrap();
    assert!(resp.status().is_success(), "{}", resp.status());
    let h = resp.headers();
    assert_eq!(h["access-control-allow-origin"], "*");
    assert_eq!(h["access-control-max-age"], "86400");
    let allowed = h["access-control-allow-headers"].to_str().unwrap();
    for name in [
        "authorization",
        "x-signature",
        "x-public-key",
        "content-type",
    ] {
        assert!(allowed.contains(name), "{name} not in {allowed}");
    }
    let methods = h["access-control-allow-methods"].to_str().unwrap();
    assert!(
        methods.contains("POST") && methods.contains("GET"),
        "{methods}"
    );

    // The call itself still needs the token, and carries CORS headers.
    let resp = router
        .oneshot(read_ref_request(&[("origin", "https://app.example")]))
        .await
        .unwrap();
    assert_eq!(resp.headers()["access-control-allow-origin"], "*");
    let err = decode_unary::<ReadRefResponse>(&reply(resp).await)
        .unwrap()
        .unwrap_err();
    assert_eq!(err.code, "unauthenticated");
}

/// A `tracing` writer into a shared buffer.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn authorization_header_is_redacted_in_trace_output() {
    const SECRET: &str = "s3cr3t-bearer-value-0123";
    let captured = Captured::default();
    let writer = captured.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let auth = AuthMode::Bearer {
        token: Redacted::new(SECRET),
    };
    let router = build_router(
        pipeline(MemoryKv::default(), auth),
        &RouterOptions::default(),
    );
    let bearer = format!("Bearer {SECRET}");
    let resp = router
        .oneshot(read_ref_request(&[
            ("authorization", &bearer),
            ("x-signature", "sig-secret-0123"),
            ("cookie", "session=cookie-secret-0123"),
            ("x-trace-marker", "visible-marker-0123"),
        ]))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    drop(resp);

    let out = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
    // The request headers were traced, with the credentials redacted.
    assert!(out.contains("visible-marker-0123"), "{out}");
    assert!(out.contains("Sensitive"), "{out}");
    for secret in [SECRET, "sig-secret-0123", "cookie-secret-0123"] {
        assert!(!out.contains(secret), "{secret} leaked:\n{out}");
    }
}

// ---------------------------------------------------------------------------
// Graceful shutdown.

fn header_msg(id: &[u8], total: u64) -> Vec<u8> {
    frame(
        &UploadPackRequest {
            body: Some(UploadBody::Header(Box::new(UploadPackHeader {
                pack_id: Some(id.to_vec()),
                total_bytes: Some(total),
                ..Default::default()
            }))),
            ..Default::default()
        }
        .encode_to_vec(),
    )
}

fn chunk_msg(id: &[u8], offset: u64, data: &[u8], last: bool) -> Vec<u8> {
    frame(
        &UploadPackRequest {
            body: Some(UploadBody::Chunk(Box::new(PackChunk {
                pack_id: Some(id.to_vec()),
                offset: Some(offset),
                data: Some(data.to_vec()),
                last: Some(last),
                ..Default::default()
            }))),
            ..Default::default()
        }
        .encode_to_vec(),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn graceful_shutdown_drains_inflight_upload() {
    let root = common::repo_root();
    let cfg = common::resolve_with(
        &[
            "--listen",
            "127.0.0.1:0",
            "--repo-root",
            common::s(root.path()),
            "--unsafe-allow-any-peer",
        ],
        &[],
    )
    .unwrap();
    let opened = server::open(&cfg).unwrap();
    let (listener, _) = common::listener().await;
    let addr = listener.local_addr().unwrap();
    let shutdown = Shutdown::new();
    let served = common::spawn_serve(listener, opened.router.clone(), &shutdown);

    // An upload whose body arrives in two halves, around the shutdown.
    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let (mut sender, conn) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
            .await
            .unwrap();
    tokio::spawn(conn);
    let (tx, rx) = futures::channel::mpsc::unbounded::<Bytes>();
    let body = http_body_util::StreamBody::new(
        rx.map(|b| Ok::<_, Infallible>(hyper::body::Frame::data(b))),
    );
    let req = Request::post(UPLOAD_PACK)
        .header("host", addr.to_string())
        .header("content-type", "application/connect+proto")
        .header("connect-protocol-version", "1")
        .body(body)
        .unwrap();
    let response = tokio::spawn(sender.send_request(req));

    let pack: Vec<u8> = (0..20_000u32).map(|i| (i % 251) as u8).collect();
    let id = hash(&pack);
    let (a, b) = pack.split_at(9_000);
    tx.unbounded_send(Bytes::from(header_msg(&id, pack.len() as u64)))
        .unwrap();
    tx.unbounded_send(Bytes::from(chunk_msg(&id, 0, a, false)))
        .unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    shutdown.trigger();
    tokio::time::sleep(Duration::from_millis(300)).await;
    // No new connections once shutdown began.
    assert!(tokio::net::TcpStream::connect(addr).await.is_err());
    tx.unbounded_send(Bytes::from(chunk_msg(&id, a.len() as u64, b, true)))
        .unwrap();
    drop(tx);

    let resp = response.await.unwrap().unwrap();
    let (parts, body) = resp.into_parts();
    let reply = Reply {
        status: parts.status.as_u16(),
        headers: parts.headers,
        body: body.collect().await.unwrap().to_bytes(),
    };
    let stream = decode_stream::<UploadPackResponse>(&reply).unwrap();
    assert!(stream.error.is_none(), "{:?}", stream.error);
    assert_eq!(stream.messages.len(), 1);
    // The server finished once the upload drained.
    tokio::time::timeout(Duration::from_secs(10), served)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(
        std::fs::read(root.path().join("packs").join(to_hex(&id))).unwrap(),
        pack
    );
    drop(opened);
}

// ---------------------------------------------------------------------------
// The binary: serve lock, banner, fail-closed configuration.

#[test]
fn serve_lock_is_held_while_running() {
    let root = common::repo_root();
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let listen = format!("127.0.0.1:{port}");
    let child = Command::new(BIN)
        .args(["serve", "--listen", &listen, "--unsafe-allow-any-peer"])
        .arg("--repo-root")
        .arg(root.path())
        .env_remove("MKIT_API_TOKEN")
        .env_remove("MKIT_SERVE_ROOT")
        .env("RUST_LOG", "warn")
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_mins(1);
    while std::net::TcpStream::connect(&listen).is_err() {
        assert!(Instant::now() < deadline, "mkit-server did not listen");
        std::thread::sleep(Duration::from_millis(50));
    }
    let dot_mkit = root.path().join(".mkit");
    // `false`: another process holds it (mkit-cli's `warn_if_served`).
    assert!(!mkit_core::repo_lock::probe_exclusive(&dot_mkit, "serve.lock").unwrap());

    let pid = child.id().to_string();
    assert!(
        Command::new("kill")
            .args(["-TERM", &pid])
            .status()
            .unwrap()
            .success()
    );
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "{:?}", out.status);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("WARNING: mkit-server serve --unsafe-allow-any-peer"),
        "{stderr}"
    );
    assert!(mkit_core::repo_lock::probe_exclusive(&dot_mkit, "serve.lock").unwrap());
}

#[test]
fn refuses_to_bind_without_auth_choice() {
    let root = common::repo_root();
    let err = common::resolve_with(
        &[
            "--listen",
            "127.0.0.1:0",
            "--repo-root",
            common::s(root.path()),
        ],
        &[],
    )
    .unwrap_err();
    assert_eq!(err.code, exit::CONFIG_ERROR);
    assert!(
        err.message
            .contains("refusing to bind without a bearer token")
    );
    for flag in [
        "--bearer-token-file",
        "MKIT_API_TOKEN",
        "--unsafe-allow-any-peer",
    ] {
        assert!(err.message.contains(flag), "{flag}: {}", err.message);
    }
    // `--auth bearer` without a token is the same refusal.
    let err = common::resolve_with(
        &[
            "--listen",
            "127.0.0.1:0",
            "--repo-root",
            common::s(root.path()),
            "--auth",
            "bearer",
        ],
        &[],
    )
    .unwrap_err();
    assert_eq!(err.code, exit::CONFIG_ERROR);

    // The binary exits with it before binding anything.
    let out = Command::new(BIN)
        .args(["serve", "--listen", "127.0.0.1:0", "--repo-root"])
        .arg(root.path())
        .env_remove("MKIT_API_TOKEN")
        .env_remove("MKIT_SERVE_ROOT")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(i32::from(exit::CONFIG_ERROR)));
    assert!(String::from_utf8_lossy(&out.stderr).contains("refusing to bind"));

    // An empty token is refused too, from the file or the environment.
    let token = root.path().join("token");
    std::fs::File::create(&token)
        .unwrap()
        .write_all(b"\n")
        .unwrap();
    let base = [
        "--listen",
        "127.0.0.1:0",
        "--repo-root",
        common::s(root.path()),
    ];
    let with_file = [&base[..], &["--bearer-token-file", common::s(&token)]].concat();
    let err = common::resolve_with(&with_file, &[]).unwrap_err();
    assert_eq!(err.code, exit::CONFIG_ERROR);
    assert!(err.message.contains("MUST NOT be empty"));
    let err = common::resolve_with(&base, &[("MKIT_API_TOKEN", "")]).unwrap_err();
    assert_eq!(err.code, exit::CONFIG_ERROR);
}

#[test]
fn token_and_unsafe_are_mutually_exclusive() {
    let root = common::repo_root();
    let token = root.path().join("token");
    std::fs::write(&token, "t").unwrap();
    let base = [
        "--listen",
        "127.0.0.1:0",
        "--repo-root",
        common::s(root.path()),
    ];
    let unsafe_flag = [&base[..], &["--unsafe-allow-any-peer"]].concat();
    let err = common::resolve_with(&unsafe_flag, &[("MKIT_API_TOKEN", "t")]).unwrap_err();
    assert_eq!(err.code, exit::USAGE);
    assert!(
        err.message.contains("mutually exclusive"),
        "{}",
        err.message
    );
    let both = [
        &unsafe_flag[..],
        &["--bearer-token-file", common::s(&token)],
    ]
    .concat();
    assert_eq!(
        common::resolve_with(&both, &[]).unwrap_err().code,
        exit::USAGE
    );
    // The unsafe flag alone is the open mode.
    assert!(common::resolve_with(&unsafe_flag, &[]).unwrap().is_open());
    // A token alone is bearer, with fs-layout metadata by default.
    let cfg = common::resolve_with(&base, &[("MKIT_API_TOKEN", "t")]).unwrap();
    assert!(matches!(cfg.pipeline.auth, AuthMode::Bearer { .. }));
    assert_eq!(cfg.meta, MetaChoice::FsLayout);
    // The token never goes on the command line.
    let out = Command::new(BIN)
        .args(["serve", "--bearer-token", "t"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(i32::from(exit::USAGE)));
}

#[test]
fn authv2_requires_sqlite_meta() {
    let root = common::repo_root();
    let base = [
        "--listen",
        "127.0.0.1:0",
        "--repo-root",
        common::s(root.path()),
        "--auth",
        "auth-v2",
        "--audience",
        "https://vcs.example",
    ];
    for meta in [&[][..], &["--meta", "fs-layout"][..]] {
        let err = common::resolve_with(&[&base[..], meta].concat(), &[]).unwrap_err();
        assert_eq!(err.code, exit::CONFIG_ERROR);
        assert!(err.message.contains("--meta sqlite:"), "{}", err.message);
    }
    let db = root.path().join("m.sqlite3");
    let meta = format!("sqlite:{}", common::s(&db));
    let cfg = common::resolve_with(&[&base[..], &["--meta", &meta]].concat(), &[]).unwrap();
    assert!(matches!(cfg.pipeline.auth, AuthMode::AuthV2(_)));
    assert!(cfg.pipeline.write_quota.is_some());
    // A token cannot be combined with auth v2; the audience is required and
    // must be a canonical origin.
    let with_meta = [&base[..], &["--meta", &meta]].concat();
    let err = common::resolve_with(&with_meta, &[("MKIT_API_TOKEN", "t")]).unwrap_err();
    assert_eq!(err.code, exit::USAGE);
    let no_audience = [&base[..6], &["--meta", &meta]].concat();
    assert_eq!(
        common::resolve_with(&no_audience, &[]).unwrap_err().code,
        exit::USAGE
    );
    let bad = [&base[..7], &["https://vcs.example/path", "--meta", &meta]].concat();
    assert_eq!(
        common::resolve_with(&bad, &[]).unwrap_err().code,
        exit::CONFIG_ERROR
    );
}

fn sqlite_cfg(root: &std::path::Path) -> mkit_server_native::config::ServeConfig {
    let meta = format!("sqlite:{}", common::s(&root.join("m.sqlite3")));
    common::resolve_with(
        &[
            "--listen",
            "127.0.0.1:0",
            "--repo-root",
            common::s(root),
            "--meta",
            &meta,
        ],
        &[("MKIT_API_TOKEN", "t")],
    )
    .unwrap()
}

#[test]
fn sqlite_meta_refuses_root_with_file_refs() {
    let root = common::repo_root();
    std::fs::create_dir_all(root.path().join("refs/heads")).unwrap();
    std::fs::write(
        root.path().join("refs/heads/main"),
        format!("{}\n", to_hex(&hash(b"main"))),
    )
    .unwrap();
    let err = server::open(&sqlite_cfg(root.path())).unwrap_err();
    assert_eq!(err.code, exit::CONFIG_ERROR);
    for needle in [
        "already holds file-based refs",
        "--meta fs-layout",
        "--repo-root",
    ] {
        assert!(err.message.contains(needle), "{needle}: {}", err.message);
    }
    // Nothing was marked or created.
    assert!(!root.path().join(".mkit/server-meta").exists());
    assert!(!root.path().join("m.sqlite3").exists());
}

#[test]
fn sqlite_meta_writes_marker_and_fs_layout_refuses_it() {
    let root = common::repo_root();
    let cfg = sqlite_cfg(root.path());
    drop(server::open(&cfg).unwrap());
    let marker = root.path().join(".mkit/server-meta");
    assert_eq!(std::fs::read(&marker).unwrap(), b"sqlite\n");
    // A second sqlite run on the marked root is fine.
    drop(server::open(&cfg).unwrap());

    // `FsLayoutStore::open` and `--meta fs-layout` refuse the root.
    let repo = RepoId {
        namespace: NamespaceKey::deployment_default(),
        name: RepoName::new("default").unwrap(),
    };
    let err = FsLayoutStore::open(root.path(), &repo).unwrap_err();
    assert!(err.to_string().contains("--meta sqlite"), "{err}");
    let fs_cfg = common::resolve_with(
        &[
            "--listen",
            "127.0.0.1:0",
            "--repo-root",
            common::s(root.path()),
        ],
        &[("MKIT_API_TOKEN", "t")],
    )
    .unwrap();
    let err = server::open(&fs_cfg).unwrap_err();
    assert_eq!(err.code, exit::CONFIG_ERROR);
    assert!(err.message.contains("--meta sqlite"), "{}", err.message);
    assert!(err.message.contains("server-meta"), "{}", err.message);
}

#[test]
fn repo_root_must_hold_dot_mkit_and_respect_serve_root() {
    let plain = tempfile::tempdir().unwrap();
    let flags = [
        "--listen",
        "127.0.0.1:0",
        "--repo-root",
        common::s(plain.path()),
    ];
    let err = common::resolve_with(&flags, &[("MKIT_API_TOKEN", "t")]).unwrap_err();
    assert_eq!(err.code, exit::DATAERR);
    let missing = plain.path().join("nope");
    let flags = [
        "--listen",
        "127.0.0.1:0",
        "--repo-root",
        common::s(&missing),
    ];
    let err = common::resolve_with(&flags, &[("MKIT_API_TOKEN", "t")]).unwrap_err();
    assert_eq!(err.code, exit::NOINPUT);

    let root = common::repo_root();
    let flags = [
        "--listen",
        "127.0.0.1:0",
        "--repo-root",
        common::s(root.path()),
    ];
    let elsewhere = tempfile::tempdir().unwrap();
    let env = [
        ("MKIT_API_TOKEN", "t"),
        ("MKIT_SERVE_ROOT", common::s(elsewhere.path())),
    ];
    assert_eq!(
        common::resolve_with(&flags, &env).unwrap_err().code,
        exit::NOPERM
    );
    let env = [
        ("MKIT_API_TOKEN", "t"),
        ("MKIT_SERVE_ROOT", common::s(root.path())),
    ];
    common::resolve_with(&flags, &env).unwrap();
}
