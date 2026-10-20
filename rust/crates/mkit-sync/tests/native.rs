//! clone, pull and fetch over the `mkit-client` backend and the native HTTP
//! channel, against a real in-process self-certifying `mkit-server`.
#![cfg(feature = "connect-native")]
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

mod support;

use mkit_client::Client;
use mkit_core::hash::to_hex;
use mkit_core::layout::RepoLayout;
use mkit_core::refs;
use mkit_sync::{
    ClientSource, CloneRemote, NativeClock, NativeHttp, NoopObserver, PullOutcome, SyncError,
    SyncOptions, TransportSource, clone, fetch, pull,
};
use support::{
    Dalek, Live, READER_SEED, WRITER_SEED, destination, push_commit, self_certifying_namespace,
};

include!("support/counting.rs");

fn remote(url: &str) -> CloneRemote {
    CloneRemote {
        name: "default".to_owned(),
        url: url.to_owned(),
        kind: "http".to_owned(),
    }
}

#[test]
fn an_anonymous_client_clones_pulls_and_no_ops_over_http() {
    let live = Live::self_certifying();
    let http = NativeHttp::new().unwrap();
    let repository = format!("{}/public", self_certifying_namespace());
    let first = push_commit(
        &http,
        &live.origin,
        &repository,
        WRITER_SEED,
        None,
        &[("a.txt", b"one\n")],
    );
    let client = Client::anonymous(&http, destination(&live.origin, &repository));
    let client_source = ClientSource::new(&client, &http);
    let transport = mkit_transport_connect::ConnectTransport::connect_for_test(
        format!("{}/{repository}", live.origin).parse().unwrap(),
    );
    let transport_source = TransportSource::new(&transport);
    // Neither wrapper supplies an identity: both adapters must forward the
    // actual destination to make the checkpoint and two-call path work.
    let sources = [
        CountingSource::new(&client_source),
        CountingSource::new(&transport_source),
    ];
    let dir = tempfile::tempdir().unwrap();
    let targets = [dir.path().join("client"), dir.path().join("transport")];
    for (source, target) in sources.iter().zip(&targets) {
        let cloned = clone(
            target,
            source,
            &remote(&format!("mkit+{}/{repository}", live.origin)),
            &SyncOptions::default(),
            &NoopObserver,
        )
        .unwrap();
        assert_eq!(cloned.pull.fetch.branches_fetched, 1);
        assert!(
            matches!(cloned.pull.outcome, PullOutcome::FastForwarded { new, .. } if new == first)
        );
        assert_eq!(std::fs::read(target.join("a.txt")).unwrap(), b"one\n");
        assert_eq!(source.take().len(), 4); // ListRefs, ReadRef, node, pack
    }
    let second = push_commit(
        &http,
        &live.origin,
        &repository,
        WRITER_SEED,
        Some(first),
        &[("a.txt", b"one\n"), ("b.txt", b"two\n")],
    );
    for (source, target) in sources.iter().zip(&targets) {
        let pulled = pull(
            target,
            source,
            "default",
            &SyncOptions::default(),
            &NoopObserver,
        )
        .unwrap();
        assert!(
            matches!(pulled.outcome, PullOutcome::FastForwarded { old: Some(old), new, .. } if old == first && new == second)
        );
        assert_eq!(source.take().len(), 4); // only the new node and pack
        assert_eq!(pulled.fetch.packs_downloaded, 1);
        assert_eq!(pulled.fetch.packs_already_applied, 1);
        assert_eq!(std::fs::read(target.join("b.txt")).unwrap(), b"two\n");
        let again = pull(
            target,
            source,
            "default",
            &SyncOptions::default(),
            &NoopObserver,
        )
        .unwrap();
        assert!(matches!(again.outcome, PullOutcome::UpToDate { .. }));
        assert_eq!(again.fetch.packs_downloaded, 0);
        assert_eq!(again.fetch.objects_unpacked, 0);
        assert_eq!(
            source.take(),
            ["ListRefs", "ReadRef refs/mkit/packmap/main"]
        );
        assert_eq!(
            refs::read_ref(&RepoLayout::single(target), "main").unwrap(),
            Some(second)
        );
    }
}

#[test]
fn a_signed_client_fetches_with_an_injected_signer() {
    let live = Live::self_certifying();
    let http = NativeHttp::new().unwrap();
    let repository = format!("{}/signed", self_certifying_namespace());
    let tip = push_commit(
        &http,
        &live.origin,
        &repository,
        WRITER_SEED,
        None,
        &[("a.txt", b"signed\n")],
    );
    // A public repository answers a signed or an anonymous caller alike, so
    // the proof that the injected signer is used is that it is called: a
    // signed client signs every RPC but discovery. (The private-read case,
    // where signing decides the answer, is in `tests/authority.rs`.)
    let signer = Counting::new(READER_SEED);
    let clock = NativeClock;
    let client = Client::signed(
        &http,
        destination(&live.origin, &repository),
        &signer,
        &clock,
    );
    let source = ClientSource::new(&client, &http);
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("work");
    mkit_sync::init_clone_dir(&target, &remote("mkit+http://x/y")).unwrap();

    let report = fetch(
        &target,
        &source,
        "default",
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap();

    assert_eq!(report.branches_fetched, 1);
    let layout = RepoLayout::single(&target);
    assert_eq!(
        refs::read_remote_ref(&layout, "default", "main").unwrap(),
        Some(tip)
    );
    assert!(
        signer.calls.load(std::sync::atomic::Ordering::SeqCst) >= 3,
        "the signer must authenticate list, read and download calls"
    );
}

/// A signer that counts how many digests it signed.
struct Counting {
    inner: Dalek,
    calls: std::sync::atomic::AtomicUsize,
}

impl Counting {
    fn new(seed: u8) -> Self {
        Self {
            inner: Dalek::new(seed),
            calls: std::sync::atomic::AtomicUsize::new(0),
        }
    }
}

impl mkit_client::Signer for Counting {
    fn public_key(&self) -> [u8; 32] {
        self.inner.public_key()
    }
    async fn sign(&self, digest: &mkit_core::hash::Hash) -> Result<[u8; 64], String> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.sign(digest).await
    }
}

#[test]
fn a_missing_repository_is_reported_with_its_address() {
    let live = Live::self_certifying();
    let http = NativeHttp::new().unwrap();
    let repository = format!("{}/absent", self_certifying_namespace());
    let client = Client::anonymous(&http, destination(&live.origin, &repository));
    let source = ClientSource::new(&client, &http);
    let dir = tempfile::tempdir().unwrap();

    let err = clone(
        &dir.path().join("work"),
        &source,
        &remote(&format!("mkit+{}/{repository}", live.origin)),
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap_err();

    let mkit_sync::CloneError::Sync(SyncError::RepositoryNotFound {
        identity, origin, ..
    }) = err
    else {
        panic!("expected RepositoryNotFound");
    };
    assert_eq!(identity, repository);
    assert_eq!(origin, live.origin);
}

#[test]
fn an_unknown_pack_is_reported_not_found() {
    let live = Live::self_certifying();
    let http = NativeHttp::new().unwrap();
    let repository = format!("{}/ids", self_certifying_namespace());
    let tip = push_commit(
        &http,
        &live.origin,
        &repository,
        WRITER_SEED,
        None,
        &[("a.txt", b"x\n")],
    );
    let client = Client::anonymous(&http, destination(&live.origin, &repository));
    let source = ClientSource::new(&client, &http);
    let missing = mkit_core::protocol::PackKey::from_hash([0xEE; 32]);
    let err = mkit_sync::RemoteSource::download_pack_via_ref(&source, &missing, "refs/heads/main")
        .unwrap_err();
    assert!(err.is_not_found(), "{err:?} for tip {}", to_hex(&tip));
}

/// Serve exactly one plain HTTP response and retain its request headers.
fn location_response(
    response: &'static [u8],
    body_delay: std::time::Duration,
) -> (String, std::thread::JoinHandle<String>) {
    use std::io::{Read as _, Write as _};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!(
        "http://{}/pack?signature=test",
        listener.local_addr().unwrap()
    );
    let thread = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            stream.read_exact(&mut byte).unwrap();
            request.push(byte[0]);
        }
        std::thread::sleep(body_delay);
        // A deadline may have already closed the receiving connection.
        let _ = stream.write_all(response);
        String::from_utf8(request).unwrap()
    });
    (url, thread)
}

#[test]
fn pack_location_fetch_never_sends_rpc_defaults_or_credentials() {
    use mkit_client::HttpTransport as _;
    use mkit_sync::Executor as _;
    let (url, server) = location_response(
        b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\npack",
        std::time::Duration::ZERO,
    );
    let mut headers = http::HeaderMap::new();
    headers.insert("authorization", "Bearer secret".parse().unwrap());
    headers.insert("cookie", "session=secret".parse().unwrap());
    headers.insert("x-mkit-signature", "secret".parse().unwrap());
    headers.insert("x-host-default", "secret".parse().unwrap());
    let transport = NativeHttp::new()
        .unwrap()
        .with_test_pack_location_http(true)
        .allow_private_pack_locations(true)
        .with_default_headers(headers);
    assert!(transport.supports_pack_locations());
    assert_eq!(
        transport
            .block_on(transport.fetch_pack_location(&url, 4, None))
            .unwrap(),
        b"pack"
    );
    let request = server.join().unwrap().to_ascii_lowercase();
    assert!(request.starts_with("get /pack?signature=test http/1.1\r\n"));
    assert!(request.contains("accept-encoding: identity\r\n"));
    assert!(!request.contains("secret"));
    assert!(!request.contains("authorization:"));
    assert!(!request.contains("cookie:"));
    assert!(!request.contains("x-mkit-"));
    assert!(!request.contains("x-host-default:"));
}

#[test]
fn pack_location_fetch_refuses_redirects_encoding_and_oversize_bodies() {
    use mkit_client::HttpTransport as _;
    use mkit_sync::Executor as _;
    let transport = NativeHttp::new()
        .unwrap()
        .with_test_pack_location_http(true)
        .allow_private_pack_locations(true);
    for response in [
        &b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"[..],
        &b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 4\r\nConnection: close\r\n\r\npack"[..],
        &b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\npacks"[..],
    ] {
        let (url, server) = location_response(response, std::time::Duration::ZERO);
        assert!(
            transport
                .block_on(transport.fetch_pack_location(&url, 4, None))
                .is_err()
        );
        server.join().unwrap();
    }
}

#[test]
fn pack_location_fetch_enforces_its_own_scheme_and_transfer_deadline() {
    use mkit_client::HttpTransport as _;
    use mkit_sync::Executor as _;
    let transport = NativeHttp::new()
        .unwrap()
        .allow_insecure_http(true)
        .with_test_pack_location_http(true)
        .allow_private_pack_locations(true)
        .with_metadata_timeout(std::time::Duration::from_secs(5))
        .with_transfer_timeout(std::time::Duration::from_millis(200));
    for url in [
        "http://example.invalid/pack",
        "ftp://127.0.0.1/pack",
        "https://user:secret@example.invalid/pack",
        "/relative/pack",
    ] {
        assert!(
            transport
                .block_on(transport.fetch_pack_location(url, 4, None))
                .is_err(),
            "{url}"
        );
    }
    let (url, server) = location_response(
        b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\npack",
        std::time::Duration::from_millis(400),
    );
    let error = transport
        .block_on(transport.fetch_pack_location(&url, 4, None))
        .unwrap_err();
    assert!(error.contains("deadline"), "{error}");
    server.join().unwrap();
}

#[test]
fn pack_location_fetch_requires_explicit_test_opt_in_for_loopback_http() {
    use mkit_client::HttpTransport as _;
    use mkit_sync::Executor as _;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}/pack", listener.local_addr().unwrap());
    let transport = NativeHttp::new().unwrap().allow_insecure_http(true);
    assert!(!transport.allows_test_pack_location_http());
    let error = transport
        .block_on(transport.fetch_pack_location(&url, 4, None))
        .unwrap_err();
    assert!(error.contains("HTTPS"), "{error}");
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    let transport = transport
        .with_test_pack_location_http(true)
        .allow_private_pack_locations(true);
    assert!(transport.allows_test_pack_location_http());
    let transport = transport.with_test_pack_location_http(false);
    assert!(!transport.allows_test_pack_location_http());
}

#[test]
fn pack_location_rejects_loopback_before_connecting() {
    use mkit_client::HttpTransport as _;
    use mkit_sync::Executor as _;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let transport = NativeHttp::new()
        .unwrap()
        .with_transfer_timeout(std::time::Duration::from_millis(25));
    let url = format!("https://{}/pack", listener.local_addr().unwrap());
    assert!(
        transport
            .block_on(transport.fetch_pack_location(&url, 4, None))
            .is_err()
    );
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn pack_location_fetch_honors_shorter_local_budget() {
    use mkit_client::HttpTransport as _;
    use mkit_sync::Executor as _;
    let transport = NativeHttp::new()
        .unwrap()
        .with_test_pack_location_http(true)
        .allow_private_pack_locations(true);
    let (url, server) = location_response(
        b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\npack",
        std::time::Duration::from_millis(300),
    );
    let start = std::time::Instant::now();
    let result = transport.block_on(transport.fetch_pack_location(
        &url,
        4,
        Some(std::time::Duration::from_millis(40)),
    ));
    assert!(start.elapsed() < std::time::Duration::from_millis(200));
    assert!(result.is_err());
    server.join().unwrap();
}

#[test]
fn pack_location_rejects_private_literals_before_dispatch() {
    use mkit_client::HttpTransport as _;
    use mkit_sync::Executor as _;
    let transport = NativeHttp::new()
        .unwrap()
        .with_transfer_timeout(std::time::Duration::from_millis(20));
    for host in [
        "127.0.0.1",
        "10.1.2.3",
        "169.254.1.1",
        "[::ffff:127.0.0.1]",
        "[::10.1.2.3]",
    ] {
        let url = format!("https://{host}/pack");
        let error = transport
            .block_on(transport.fetch_pack_location(&url, 4, None))
            .unwrap_err();
        assert!(error.contains("destination refused"), "{host}: {error}");
    }
}
