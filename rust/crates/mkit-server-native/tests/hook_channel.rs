//! `HttpChannel` (WP-3.8): the URL rules, redirects, the streamed response
//! cap, timeouts, TLS verification and the proxy rule, against small local
//! servers. Signing and the roles above the channel are core's (see
//! `hook_e2e.rs`).

#![allow(clippy::unwrap_used)] // unwrap is the assertion in tests

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::Body;
use axum::http::{Response, StatusCode, header};
use mkit_server::hooks::{
    ChannelError, HookChannel, HookClient, HookRequest, HookSigner, RemoteOutcomes,
};
use mkit_server::pipeline::{Outcome, OutcomeSink};
use mkit_server::store::codec::ReservationV1;
use mkit_server::{Sleep, SystemClock};
use mkit_server_native::hooks::HttpChannel;
use mkit_server_native::timers::TokioSleep;
use tokio::net::TcpListener;
use zeroize::Zeroizing;

const PROCEDURE: &str = "/mkit.server.hooks.v1.HooksService/Outcome";
const MAX: usize = 65_536;

fn request(timeout: Duration) -> HookRequest {
    HookRequest::new(
        PROCEDURE,
        vec![("Content-Type", "application/json".to_owned())],
        b"{}".to_vec(),
        timeout,
        MAX,
    )
}

/// Serve `app` on an ephemeral loopback port; its `http://` origin.
async fn serve(app: Router) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    origin
}

#[test]
fn urls_the_spec_refuses_are_refused() {
    for bad in [
        "http://hooks.example",
        "http://10.1.2.3:8080",
        "https://user:pw@hooks.example",
        "https://hooks.example/path?token=1",
        "https://hooks.example/#frag",
        "ftp://hooks.example",
        "not a url",
    ] {
        let err = HttpChannel::new(bad).unwrap_err().to_string();
        assert!(!err.contains("pw") && !err.contains("token"), "{err}");
    }
    for good in [
        "https://hooks.example",
        "https://hooks.example/mkit/",
        "http://127.0.0.1:9",
        "http://localhost:9/x",
        "http://[::1]:9",
    ] {
        HttpChannel::new(good).unwrap_or_else(|e| panic!("{good}: {e}"));
    }
}

#[test]
fn the_audience_is_the_canonical_origin() {
    let channel = HttpChannel::new("HTTPS://Hooks.Example:443/mkit/v1/").unwrap();
    assert_eq!(channel.audience(), Some("https://hooks.example"));
    let channel = HttpChannel::new("http://127.0.0.1:8080/x").unwrap();
    assert_eq!(channel.audience(), Some("http://127.0.0.1:8080"));
    mkit_core::write_auth::validate_audience(channel.audience().unwrap()).unwrap();
}

#[tokio::test]
async fn a_redirect_is_returned_not_followed() {
    let hits = Arc::new(AtomicUsize::new(0));
    let target = {
        let hits = Arc::clone(&hits);
        serve(Router::new().fallback(move || {
            hits.fetch_add(1, Ordering::SeqCst);
            async { "moved here" }
        }))
        .await
    };
    let location = format!("{target}/elsewhere");
    let origin = serve(Router::new().fallback(move || {
        let location = location.clone();
        async move {
            Response::builder()
                .status(StatusCode::FOUND)
                .header(header::LOCATION, location)
                .body(Body::empty())
                .unwrap()
        }
    }))
    .await;
    let channel = HttpChannel::new(&origin).unwrap();
    let response = channel.call(request(Duration::from_secs(5))).await.unwrap();
    assert_eq!(response.status, 302);
    assert_eq!(hits.load(Ordering::SeqCst), 0, "the redirect was followed");
}

#[tokio::test]
async fn an_oversize_body_gives_the_status_and_exactly_max_plus_one_bytes() {
    let origin = serve(Router::new().fallback(|| async { vec![b'x'; 200_000] })).await;
    let channel = HttpChannel::new(&origin).unwrap();
    let response = channel.call(request(Duration::from_secs(5))).await.unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(response.body.len(), MAX + 1);
}

#[tokio::test]
async fn an_endless_body_is_cut_at_the_cap() {
    let origin = serve(Router::new().fallback(|| async {
        let endless = futures::stream::repeat_with(|| {
            Ok::<_, std::convert::Infallible>(bytes::Bytes::from(vec![b'y'; 8192]))
        });
        Response::new(Body::from_stream(endless))
    }))
    .await;
    let channel = HttpChannel::new(&origin).unwrap();
    let response = tokio::time::timeout(
        Duration::from_secs(10),
        channel.call(request(Duration::from_secs(10))),
    )
    .await
    .expect("the call ends at the cap, not at the timeout")
    .unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(response.body.len(), MAX + 1);
}

fn signed_client(origin: &str) -> Arc<HookClient<HttpChannel>> {
    let signer = HookSigner::new("test-key", Zeroizing::new([7u8; 32])).unwrap();
    Arc::new(
        HookClient::new(
            HttpChannel::new(origin).unwrap(),
            "https://server.example",
            Some(signer),
            Arc::new(SystemClock),
            Arc::new(TokioSleep) as Arc<dyn Sleep>,
        )
        .unwrap(),
    )
}

#[tokio::test]
async fn an_oversized_2xx_outcome_still_acknowledges() {
    let origin = serve(Router::new().fallback(|| async { vec![b'z'; 300_000] })).await;
    let sink = RemoteOutcomes::new(signed_client(&origin));
    let outcome = Outcome::from_reservation(
        "r-1".to_owned(),
        "https://server.example".to_owned(),
        ReservationV1::Expired {
            repository: "ns/repo".to_owned(),
            occurred_at_ms: 1_790_000_000_000,
        },
    )
    .unwrap();
    sink.deliver(&outcome).await.unwrap();
}

/// Set when the guard drops: the handler future was cancelled.
struct Cancelled(Arc<AtomicBool>);
impl Drop for Cancelled {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn a_timeout_cancels_the_call() {
    let cancelled = Arc::new(AtomicBool::new(false));
    let origin = {
        let cancelled = Arc::clone(&cancelled);
        serve(Router::new().fallback(move || {
            let guard = Cancelled(Arc::clone(&cancelled));
            async move {
                let _guard = guard;
                std::future::pending::<()>().await;
                "never"
            }
        }))
        .await
    };
    let channel = HttpChannel::new(&origin).unwrap();
    let started = Instant::now();
    let err = channel
        .call(request(Duration::from_millis(300)))
        .await
        .expect_err("a stalled hook times out");
    assert!(matches!(err, ChannelError::Timeout), "{err:?}");
    assert!(started.elapsed() < Duration::from_secs(5));
    // The request was abandoned, so the server sees the connection drop and
    // cancels its handler.
    for _ in 0..100 {
        if cancelled.load(Ordering::SeqCst) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("the server never saw the request cancelled");
}

#[tokio::test]
async fn connection_refused_fails_closed() {
    let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", dead.local_addr().unwrap());
    drop(dead);
    let channel = HttpChannel::new(&origin).unwrap();
    let err = channel
        .call(request(Duration::from_secs(5)))
        .await
        .expect_err("nothing listens");
    assert!(matches!(err, ChannelError::Transport(_)), "{err:?}");
}

/// A TLS server whose certificate no platform trust store vouches for.
#[tokio::test]
async fn a_self_signed_certificate_fails_verification() {
    use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
    let cert = CertificateDer::from(include_bytes!("fixtures/selfsigned-cert.der").to_vec());
    let key =
        PrivateKeyDer::try_from(include_bytes!("fixtures/selfsigned-pk8.der").to_vec()).unwrap();
    let provider = Arc::new(tokio_rustls::rustls::crypto::aws_lc_rs::default_provider());
    let config = tokio_rustls::rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let served = Arc::new(AtomicBool::new(false));
    let handshakes = Arc::new(AtomicUsize::new(0));
    {
        let (served, handshakes) = (Arc::clone(&served), Arc::clone(&handshakes));
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let (acceptor, served, handshakes) = (
                    acceptor.clone(),
                    Arc::clone(&served),
                    Arc::clone(&handshakes),
                );
                tokio::spawn(async move {
                    if let Ok(mut tls) = acceptor.accept(stream).await {
                        handshakes.fetch_add(1, Ordering::SeqCst);
                        let mut buf = [0u8; 1];
                        if tokio::io::AsyncReadExt::read(&mut tls, &mut buf)
                            .await
                            .is_ok_and(|n| n > 0)
                        {
                            served.store(true, Ordering::SeqCst);
                        }
                    }
                });
            }
        });
    }
    let channel = HttpChannel::new(&format!("https://localhost:{port}")).unwrap();
    let err = channel
        .call(request(Duration::from_secs(10)))
        .await
        .expect_err("an untrusted certificate is refused");
    assert!(matches!(err, ChannelError::Transport(_)), "{err:?}");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        !served.load(Ordering::SeqCst),
        "a request was sent over an unverified connection"
    );
    assert_eq!(handshakes.load(Ordering::SeqCst), 0);
    // Control: the same server does complete a handshake with a client that
    // trusts its certificate (webpki, not the platform verifier, which on
    // macOS refuses a 100-year certificate), so the refusal above is about
    // trust alone.
    let trusting = reqwest::Client::builder()
        .tls_certs_only([reqwest::Certificate::from_der(include_bytes!(
            "fixtures/selfsigned-cert.der"
        ))
        .unwrap()])
        .build()
        .unwrap();
    let control = trusting
        .post(format!("https://localhost:{port}"))
        .timeout(Duration::from_secs(5))
        .body("x")
        .send()
        .await;
    let _ = control;
    assert_eq!(handshakes.load(Ordering::SeqCst), 1, "control handshake");
}

/// The proxy rule runs in a child process, so the environment can be set
/// without `unsafe`: the child's `HTTP_PROXY` names this listener, which must
/// see no connection.
#[test]
fn loopback_ignores_http_proxy() {
    let proxy = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    proxy.set_nonblocking(true).unwrap();
    let url = format!("http://{}", proxy.local_addr().unwrap());
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "proxy_child", "--nocapture"])
        .env("MKIT_HOOK_PROXY_CHILD", "1")
        .env("HTTP_PROXY", &url)
        .env("http_proxy", &url)
        .env("HTTPS_PROXY", &url)
        .env("https_proxy", &url)
        .env("ALL_PROXY", &url)
        .env_remove("NO_PROXY")
        .env_remove("no_proxy")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        proxy.accept().is_err(),
        "a loopback hook call went through the proxy"
    );
}

/// The child half of [`loopback_ignores_http_proxy`]; a no-op otherwise.
#[tokio::test]
async fn proxy_child() {
    if std::env::var_os("MKIT_HOOK_PROXY_CHILD").is_none() {
        return;
    }
    assert!(std::env::var_os("HTTP_PROXY").is_some());
    let hits = Arc::new(AtomicUsize::new(0));
    let origin = {
        let hits = Arc::clone(&hits);
        serve(Router::new().fallback(move || {
            hits.fetch_add(1, Ordering::SeqCst);
            async { "ok" }
        }))
        .await
    };
    let channel = HttpChannel::new(&origin).unwrap();
    let response = channel.call(request(Duration::from_secs(5))).await.unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(hits.load(Ordering::SeqCst), 1);
}
