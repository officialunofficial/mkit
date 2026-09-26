//! The router's and listener's denial-of-service posture and the root's exclusivity:
//! slots held by streamed bodies, shedding, the bearer pre-check, the body
//! limit on chunked uploads, the header-read timeout, the connection cap,
//! the bearer token file's permissions, one server per root, and the
//! root-to-database binding (R-81).

#![allow(clippy::unwrap_used)] // unwrap is the assertion in tests

mod common;

use std::convert::Infallible;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body;
use buffa::Message as _;
use bytes::Bytes;
use http::{Request, StatusCode};
use http_body_util::BodyExt as _;
use mkit_core::hash::hash;
use mkit_server::pipeline::{AuthMode, Hooks, Pipeline, PipelineConfig};
use mkit_server::sql::SqlKvStore;
use mkit_server::upload::UploadLimits;
use mkit_server::{
    Addressing, Batch, BatchOutcome, Key, MemoryBlobStore, MemoryKv, NamespaceKey,
    NamespaceStore as _, NoopMetrics, Partition, Redacted, RepoId, RepoName, SystemClock, Value,
};
use mkit_server_conformance::wire::client::{Reply, decode_stream, decode_unary, frame};
use mkit_server_native::{
    RouterOptions, RusqliteConn, ServeOptions, Shutdown, build_router, exit, server,
};
use mkit_transport_connect::generated::__buffa::oneof::upload_pack_request::Body as UploadBody;
use mkit_transport_connect::generated::{
    DownloadPackRequest, DownloadPackResponse, PackChunk, ReadRefRequest, ReadRefResponse,
    UploadPackHeader, UploadPackRequest, UploadPackResponse,
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tower::ServiceExt as _;

const READ_REF: &str = "/mkit.transport.v1.TransportService/ReadRef";
const UPLOAD_PACK: &str = "/mkit.transport.v1.TransportService/UploadPack";
const DOWNLOAD_PACK: &str = "/mkit.transport.v1.TransportService/DownloadPack";
const TOKEN: &str = "hardening-token";

fn pipeline(auth: AuthMode) -> Arc<Pipeline<MemoryBlobStore, MemoryKv, Hooks>> {
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
        MemoryKv::default(),
        Hooks::new(),
        cfg,
        Arc::new(SystemClock),
        Arc::new(NoopMetrics),
    )
    .unwrap();
    Arc::new(pipe)
}

fn bearer() -> AuthMode {
    AuthMode::Bearer {
        token: Redacted::new(TOKEN),
    }
}

fn post(path: &str, content_type: &str, body: Body, auth: bool) -> Request<Body> {
    let mut req = Request::post(path)
        .header("content-type", content_type)
        .header("connect-protocol-version", "1");
    if auth {
        req = req.header("authorization", format!("Bearer {TOKEN}"));
    }
    req.body(body).unwrap()
}

fn read_ref(auth: bool) -> Request<Body> {
    let body = ReadRefRequest {
        name: Some("refs/heads/main".to_owned()),
        ..Default::default()
    }
    .encode_to_vec();
    post(READ_REF, "application/proto", Body::from(body), auth)
}

fn download(id: &[u8], auth: bool) -> Request<Body> {
    let msg = DownloadPackRequest {
        pack_id: Some(id.to_vec()),
        ..Default::default()
    };
    let body = frame(&msg.encode_to_vec());
    post(
        DOWNLOAD_PACK,
        "application/connect+proto",
        Body::from(body),
        auth,
    )
}

fn upload_frames(pack: &[u8]) -> Vec<Vec<u8>> {
    let id = hash(pack);
    let header = UploadPackRequest {
        body: Some(UploadBody::Header(Box::new(UploadPackHeader {
            pack_id: Some(id.to_vec()),
            total_bytes: Some(pack.len() as u64),
            ..Default::default()
        }))),
        ..Default::default()
    };
    let chunk = UploadPackRequest {
        body: Some(UploadBody::Chunk(Box::new(PackChunk {
            pack_id: Some(id.to_vec()),
            offset: Some(0),
            data: Some(pack.to_vec()),
            last: Some(true),
            ..Default::default()
        }))),
        ..Default::default()
    };
    vec![
        frame(&header.encode_to_vec()),
        frame(&chunk.encode_to_vec()),
    ]
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
// The concurrency cap.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn open_downloads_hold_their_slots_and_excess_is_shed() {
    let mut opts = RouterOptions::default();
    opts.max_concurrency = 2;
    opts.queue_timeout = Duration::from_millis(300);
    let router = build_router(pipeline(AuthMode::Open), &opts);
    let pack = vec![7u8; 4096];
    let id = hash(&pack);
    let body = Body::from(upload_frames(&pack).concat());
    let up = router
        .clone()
        .oneshot(post(UPLOAD_PACK, "application/connect+proto", body, false))
        .await
        .unwrap();
    let up = decode_stream::<UploadPackResponse>(&reply(up).await).unwrap();
    assert!(up.error.is_none(), "{:?}", up.error);

    // Two downloads whose bodies are still open hold both slots...
    let first = router.clone().oneshot(download(&id, false)).await.unwrap();
    let second = router.clone().oneshot(download(&id, false)).await.unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(second.status(), StatusCode::OK);

    // ...so the next request waits the queue timeout, then is shed.
    let started = Instant::now();
    let shed = reply(router.clone().oneshot(read_ref(false)).await.unwrap()).await;
    assert!(started.elapsed() >= Duration::from_millis(250));
    assert_eq!(shed.status, 503);
    assert_eq!(shed.headers["retry-after"], "1");
    let err = decode_unary::<ReadRefResponse>(&shed).unwrap().unwrap_err();
    assert_eq!(err.code, "unavailable");

    // Finishing one body frees its slot.
    let done = decode_stream::<DownloadPackResponse>(&reply(first).await).unwrap();
    assert!(done.error.is_none(), "{:?}", done.error);
    let ok = router.clone().oneshot(read_ref(false)).await.unwrap();
    assert_eq!(ok.status(), StatusCode::OK);
    drop(ok);
    // So does dropping one mid-stream.
    drop(second);
    let ok = router.clone().oneshot(read_ref(false)).await.unwrap();
    assert_eq!(ok.status(), StatusCode::OK);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bearer_precheck_takes_no_slot() {
    let mut opts = RouterOptions::default();
    opts.max_concurrency = 1;
    opts.queue_timeout = Duration::from_secs(2);
    let router = build_router(pipeline(bearer()), &opts);
    // An authorized download holds the only slot (a missing pack still
    // answers with a streamed body).
    let held = router
        .clone()
        .oneshot(download(&[0u8; 32], true))
        .await
        .unwrap();

    // Without the token: refused from the headers at once.
    let started = Instant::now();
    for req in [read_ref(false), download(&[1u8; 32], false)] {
        let resp = reply(router.clone().oneshot(req).await.unwrap()).await;
        assert_eq!(resp.status, 401);
        let err = decode_unary::<ReadRefResponse>(&resp).unwrap().unwrap_err();
        assert_eq!(err.code, "unauthenticated");
    }
    assert!(started.elapsed() < Duration::from_secs(1));

    // With the token, the request waits for the slot (and is shed).
    let started = Instant::now();
    let resp = router.clone().oneshot(read_ref(true)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(started.elapsed() >= Duration::from_millis(1500));
    drop(held);

    // Health stays open without the token.
    let health = Request::post("/grpc.health.v1.Health/Check")
        .header("content-type", "application/json")
        .header("connect-protocol-version", "1")
        .body(Body::from("{}"))
        .unwrap();
    let resp = router.oneshot(health).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn chunked_body_over_limit_fails_and_stores_nothing() {
    let mut opts = RouterOptions::default();
    opts.max_body_bytes = 1024;
    let router = build_router(pipeline(AuthMode::Open), &opts);
    let pack = vec![9u8; 3000];
    let id = hash(&pack);
    // No Content-Length: the limit trips while the body streams.
    let pieces: Vec<_> = upload_frames(&pack)
        .concat()
        .chunks(512)
        .map(|c| Ok::<_, Infallible>(Bytes::copy_from_slice(c)))
        .collect();
    let body = Body::from_stream(futures::stream::iter(pieces));
    let req = post(UPLOAD_PACK, "application/connect+proto", body, false);
    assert!(!req.headers().contains_key("content-length"));
    let resp = reply(router.clone().oneshot(req).await.unwrap()).await;
    let failed = resp.status != 200
        || decode_stream::<UploadPackResponse>(&resp)
            .unwrap()
            .error
            .is_some();
    assert!(failed, "an over-limit chunked upload succeeded");

    let fetched = reply(router.oneshot(download(&id, false)).await.unwrap()).await;
    let fetched = decode_stream::<DownloadPackResponse>(&fetched).unwrap();
    assert_eq!(fetched.error.map(|e| e.code).as_deref(), Some("not_found"));
}

// ---------------------------------------------------------------------------
// The listener.

async fn listen(opts: ServeOptions) -> (std::net::SocketAddr, Shutdown) {
    let (listener, _) = common::listener().await;
    let addr = listener.local_addr().unwrap();
    let shutdown = Shutdown::new();
    let router = build_router(pipeline(AuthMode::Open), &RouterOptions::default());
    common::spawn_serve_with(listener, router, &shutdown, opts);
    (addr, shutdown)
}

/// Read until the server closes the connection; how long that took.
async fn until_closed(stream: &mut tokio::net::TcpStream) -> Duration {
    let started = Instant::now();
    let mut sink = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut sink)).await;
    assert!(read.is_ok(), "the server kept the connection open");
    started.elapsed()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn header_read_timeout_disconnects_slow_and_silent_clients() {
    let mut opts = ServeOptions::default();
    opts.header_read_timeout = Duration::from_millis(300);
    let (addr, shutdown) = listen(opts).await;

    // Silent: never picks a protocol.
    let mut silent = tokio::net::TcpStream::connect(addr).await.unwrap();
    assert!(until_closed(&mut silent).await < Duration::from_secs(5));

    // Slow: starts a request, never finishes its headers.
    let mut slow = tokio::net::TcpStream::connect(addr).await.unwrap();
    slow.write_all(b"POST /mkit.transport.v1.TransportService/ReadRef HTTP/1.1\r\nHost: x\r\n")
        .await
        .unwrap();
    assert!(until_closed(&mut slow).await < Duration::from_secs(5));

    // A prompt client is served.
    let mut prompt = tokio::net::TcpStream::connect(addr).await.unwrap();
    prompt
        .write_all(b"GET /nope HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    prompt.read_to_end(&mut response).await.unwrap();
    assert!(response.starts_with(b"HTTP/1.1 "), "{response:?}");
    shutdown.trigger();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn max_connections_queues_excess_connections() {
    let mut opts = ServeOptions::default();
    opts.max_connections = 1;
    opts.header_read_timeout = Duration::from_secs(1);
    let (addr, shutdown) = listen(opts).await;

    // An idle connection takes the only slot until the timeout closes it.
    let mut idle = tokio::net::TcpStream::connect(addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let started = Instant::now();
    let mut next = tokio::net::TcpStream::connect(addr).await.unwrap();
    next.write_all(b"GET /nope HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    next.read_to_end(&mut response).await.unwrap();
    assert!(response.starts_with(b"HTTP/1.1 "), "{response:?}");
    assert!(
        started.elapsed() >= Duration::from_millis(700),
        "served before the first connection freed its slot"
    );
    until_closed(&mut idle).await;
    shutdown.trigger();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn idle_connections_are_closed() {
    let mut opts = ServeOptions::default();
    opts.idle_timeout = Duration::from_millis(300);
    let (addr, shutdown) = listen(opts).await;

    // HTTP/1.1 keep-alive: one request, then silence. (The header-read
    // timeout, 10 s here, is not what closes it.)
    let mut h1 = tokio::net::TcpStream::connect(addr).await.unwrap();
    h1.write_all(b"GET /nope HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    let started = Instant::now();
    let read = tokio::time::timeout(Duration::from_secs(8), h1.read_to_end(&mut response)).await;
    assert!(read.is_ok(), "the idle HTTP/1.1 connection stayed open");
    assert!(response.starts_with(b"HTTP/1.1 "), "{response:?}");
    assert!(started.elapsed() < Duration::from_secs(5));

    // HTTP/2 (prior knowledge): one request, then the client keeps the
    // connection open with no stream; the server closes it.
    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let (mut sender, conn) = hyper::client::conn::http2::handshake(
        hyper_util::rt::TokioExecutor::new(),
        hyper_util::rt::TokioIo::new(stream),
    )
    .await
    .unwrap();
    let conn = tokio::spawn(conn);
    let req = Request::get(format!("http://{addr}/nope"))
        .body(http_body_util::Empty::<Bytes>::new())
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    drop(resp.into_body().collect().await);
    let closed = tokio::time::timeout(Duration::from_secs(5), conn).await;
    assert!(closed.is_ok(), "the idle HTTP/2 connection stayed open");
    drop(sender);
    shutdown.trigger();
}

// ---------------------------------------------------------------------------
// The token file.

#[cfg(unix)]
#[test]
fn token_file_must_be_a_private_regular_file() {
    use std::os::unix::fs::PermissionsExt as _;

    let root = common::repo_root();
    let resolve = |file: &Path| {
        common::resolve_with(
            &[
                "--listen",
                "127.0.0.1:0",
                "--repo-root",
                common::s(root.path()),
                "--bearer-token-file",
                common::s(file),
            ],
            &[],
        )
    };
    let token = root.path().join("token");
    common::secret_file(&token, b"t\n");
    assert!(resolve(&token).is_ok());

    for mode in [0o640, 0o604, 0o660] {
        std::fs::set_permissions(&token, std::fs::Permissions::from_mode(mode)).unwrap();
        let err = resolve(&token).unwrap_err();
        assert_eq!(err.code, exit::CONFIG_ERROR);
        assert!(err.message.contains("chmod 600"), "{}", err.message);
    }
    std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600)).unwrap();

    let link = root.path().join("link");
    std::os::unix::fs::symlink(&token, &link).unwrap();
    let err = resolve(&link).unwrap_err();
    assert!(err.message.contains("symlink"), "{}", err.message);

    let dir = root.path().join("dir");
    std::fs::create_dir(&dir).unwrap();
    let err = resolve(&dir).unwrap_err();
    assert!(
        err.message.contains("not a regular file"),
        "{}",
        err.message
    );
}

// ---------------------------------------------------------------------------
// The root: one server, one database.

fn cfg(root: &Path, meta: &str) -> mkit_server_native::config::ServeConfig {
    common::resolve_with(
        &[
            "--listen",
            "127.0.0.1:0",
            "--repo-root",
            common::s(root),
            "--meta",
            meta,
        ],
        &[("MKIT_API_TOKEN", "t")],
    )
    .unwrap()
}

#[test]
fn one_server_per_root() {
    let root = common::repo_root();
    let fs = cfg(root.path(), "fs-layout");
    let first = server::open(&fs).unwrap();
    let err = server::open(&fs).unwrap_err();
    assert_eq!(err.code, exit::CONFIG_ERROR);
    assert!(
        err.message.contains("another mkit-server already serves"),
        "{}",
        err.message
    );
    // `mkit serve` (ssh) takes the shared serve lock alongside it.
    let dot_mkit = root.path().join(".mkit");
    let ssh = mkit_core::repo_lock::acquire_shared(&dot_mkit, "serve.lock", Duration::ZERO);
    assert!(ssh.is_ok());
    drop(first);
    drop(server::open(&fs).unwrap());
}

#[test]
fn sqlite_marker_binds_the_root_to_one_database() {
    let root = common::repo_root();
    let db = root.path().join("meta.sqlite3");
    let meta = format!("sqlite:{}", common::s(&db));
    drop(server::open(&cfg(root.path(), &meta)).unwrap());

    // The same file by another spelling is the same database.
    std::fs::create_dir(root.path().join("sub")).unwrap();
    let other_spelling = format!("sqlite:{}/sub/../meta.sqlite3", common::s(root.path()));
    drop(server::open(&cfg(root.path(), &other_spelling)).unwrap());

    // Another database for this root is refused.
    let elsewhere = format!("sqlite:{}", common::s(&root.path().join("other.sqlite3")));
    let err = server::open(&cfg(root.path(), &elsewhere)).unwrap_err();
    assert_eq!(err.code, exit::CONFIG_ERROR);
    assert!(
        err.message.contains("is bound to the database"),
        "{}",
        err.message
    );

    // Another root cannot share this root's database.
    let second = common::repo_root();
    let err = server::open(&cfg(second.path(), &meta)).unwrap_err();
    assert_eq!(err.code, exit::CONFIG_ERROR);
    assert!(
        err.message.contains("another served root"),
        "{}",
        err.message
    );

    // A database holding metadata but no binding is refused too.
    let third = common::repo_root();
    let stray = third.path().join("stray.sqlite3");
    let store = SqlKvStore::open(RusqliteConn::open(&stray).unwrap()).unwrap();
    let p = Partition::decode(b"ndefault\0").unwrap();
    let put = Batch::new().put(Key::new(&b"r\0x"[..]), Value::new(&b"1"[..]));
    let applied = futures::executor::block_on(store.apply(&p, put)).unwrap();
    assert_eq!(applied, BatchOutcome::Committed);
    drop(store);
    let stray_meta = format!("sqlite:{}", common::s(&stray));
    let err = server::open(&cfg(third.path(), &stray_meta)).unwrap_err();
    assert!(err.message.contains("no root binding"), "{}", err.message);
}

/// A root under `parent/name` with its database inside it.
fn root_with_db(parent: &Path, name: &str) -> (std::path::PathBuf, String) {
    let root = parent.join(name);
    std::fs::create_dir_all(root.join(".mkit")).unwrap();
    let meta = format!("sqlite:{}", common::s(&root.join("meta.sqlite3")));
    (root, meta)
}

#[test]
fn a_moved_root_with_its_database_is_rebound() {
    let parent = tempfile::tempdir().unwrap();
    let (old, old_meta) = root_with_db(parent.path(), "old");
    drop(server::open(&cfg(&old, &old_meta)).unwrap());
    let marker = |root: &Path| std::fs::read_to_string(root.join(".mkit/server-meta")).unwrap();
    let before = marker(&old);

    let new = parent.path().join("new");
    std::fs::rename(&old, &new).unwrap();
    let new_meta = format!("sqlite:{}", common::s(&new.join("meta.sqlite3")));
    drop(server::open(&cfg(&new, &new_meta)).unwrap());
    let after = marker(&new);
    let db = std::fs::canonicalize(&new).unwrap().join("meta.sqlite3");
    assert!(
        after.ends_with(&format!("\nsqlite {}\n", db.display())),
        "{after}"
    );
    // Same root id; only the path changed.
    assert_eq!(before.lines().nth(1), after.lines().nth(1));
    drop(server::open(&cfg(&new, &new_meta)).unwrap());
}

#[test]
fn another_roots_database_is_not_rebound() {
    let parent = tempfile::tempdir().unwrap();
    let (a, a_meta) = root_with_db(parent.path(), "a");
    let (b, b_meta) = root_with_db(parent.path(), "b");
    drop(server::open(&cfg(&a, &a_meta)).unwrap());
    drop(server::open(&cfg(&b, &b_meta)).unwrap());
    let marker = std::fs::read_to_string(a.join(".mkit/server-meta")).unwrap();

    let err = server::open(&cfg(&a, &b_meta)).unwrap_err();
    assert_eq!(err.code, exit::CONFIG_ERROR);
    for needle in ["not this root's database", "another root"] {
        assert!(err.message.contains(needle), "{needle}: {}", err.message);
    }
    assert_eq!(
        std::fs::read_to_string(a.join(".mkit/server-meta")).unwrap(),
        marker
    );
    drop(server::open(&cfg(&a, &a_meta)).unwrap());
}
