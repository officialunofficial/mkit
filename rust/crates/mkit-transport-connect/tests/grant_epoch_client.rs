//! `ConnectTransport::{get_grant_epoch, set_grant_epoch, set_repo_visibility}`
//! (WP-2.14, R-156) against a stub `TransportService`: what goes on the wire
//! (no envelope and no `X-Repository` for the epoch RPCs; an envelope only in
//! envelope-mode `SetRepoVisibility`), and how `unavailable` + `Retry-After`
//! becomes `Completion::Pending` instead of an error.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use connectrpc::server::Server;
use connectrpc::{ConnectError, RequestContext, Response, Router, handler_fn};
use ed25519_dalek::{Signer as _, SigningKey};
use mkit_core::protocol::TransportError;
use mkit_transport_connect::{
    Completion, ConnectTransport, EnvelopeSigner, VisibilityChoice, VisibilityRequest, generated,
};

const SERVICE: &str = "mkit.transport.v1.TransportService";

struct Dalek(SigningKey);
impl EnvelopeSigner for Dalek {
    fn public_key_hex(&self) -> String {
        hex::encode(self.0.verifying_key().to_bytes())
    }
    fn sign_hex(&self, message: &[u8; 32]) -> Result<String, String> {
        Ok(hex::encode(self.0.sign(message).to_bytes()))
    }
}

#[derive(Clone, Default)]
struct Stub {
    /// Headers of every request, by method.
    seen: Arc<Mutex<Vec<(&'static str, http::HeaderMap)>>>,
    /// `SetGrantEpoch` answers `unavailable` this many times first.
    epoch_pending: Arc<AtomicUsize>,
    /// Value of the `Retry-After` header on those answers, if any.
    retry_after: Arc<Mutex<Option<&'static str>>>,
    /// The visibility requests received.
    visibility: Arc<Mutex<Vec<generated::SetRepoVisibilityRequest>>>,
    /// `SetGrantEpoch` bodies received.
    statements: Arc<Mutex<Vec<String>>>,
}

impl Stub {
    fn record(&self, method: &'static str, ctx: &RequestContext) {
        self.seen
            .lock()
            .unwrap()
            .push((method, ctx.headers().clone()));
    }

    fn headers_of(&self, method: &str) -> Vec<http::HeaderMap> {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .filter(|(m, _)| *m == method)
            .map(|(_, h)| h.clone())
            .collect()
    }
}

fn spawn(
    stub: Stub,
) -> (
    u16,
    tokio::sync::oneshot::Sender<()>,
    std::thread::JoinHandle<()>,
) {
    let (addr_tx, addr_rx) = mpsc::channel();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let bound = Server::bind("127.0.0.1:0").await.unwrap();
            addr_tx.send(bound.local_addr().unwrap().port()).unwrap();
            let get = stub.clone();
            let set = stub.clone();
            let vis = stub.clone();
            let router = Router::new()
                .route(
                    SERVICE,
                    "GetGrantEpoch",
                    handler_fn(
                        move |ctx: RequestContext, _req: generated::GetGrantEpochRequest| {
                            get.record("GetGrantEpoch", &ctx);
                            async move {
                                Ok::<_, ConnectError>(Response::new(
                                    generated::GetGrantEpochResponse {
                                        epoch: Some(4),
                                        ..Default::default()
                                    },
                                ))
                            }
                        },
                    ),
                )
                .route(
                    SERVICE,
                    "SetGrantEpoch",
                    handler_fn(
                        move |ctx: RequestContext, req: generated::SetGrantEpochRequest| {
                            set.record("SetGrantEpoch", &ctx);
                            set.statements
                                .lock()
                                .unwrap()
                                .push(req.signed_statement.clone().unwrap_or_default());
                            let pending = set
                                .epoch_pending
                                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                                    n.checked_sub(1)
                                })
                                .is_ok();
                            let retry_after = *set.retry_after.lock().unwrap();
                            async move {
                                if pending {
                                    let mut headers = http::HeaderMap::new();
                                    if let Some(value) = retry_after {
                                        headers.insert("retry-after", value.parse().unwrap());
                                    }
                                    headers.insert("x-stub", "1".parse().unwrap());
                                    return Err(ConnectError::unavailable(
                                        "revocation in progress",
                                    )
                                    .with_headers(headers));
                                }
                                Ok(Response::new(generated::SetGrantEpochResponse {
                                    epoch: Some(5),
                                    ..Default::default()
                                }))
                            }
                        },
                    ),
                )
                .route(
                    SERVICE,
                    "SetRepoVisibility",
                    handler_fn(
                        move |ctx: RequestContext, req: generated::SetRepoVisibilityRequest| {
                            vis.record("SetRepoVisibility", &ctx);
                            vis.visibility.lock().unwrap().push(req);
                            async move {
                                Ok::<_, ConnectError>(Response::new(
                                    generated::SetRepoVisibilityResponse::default(),
                                ))
                            }
                        },
                    ),
                );
            bound
                .serve_with_graceful_shutdown(router, async {
                    let _ = shutdown_rx.await;
                })
                .await
                .unwrap();
        });
    });
    (addr_rx.recv().unwrap(), shutdown_tx, handle)
}

fn client(port: u16, signed: bool) -> ConnectTransport {
    let uri: http::Uri = format!("http://127.0.0.1:{port}").parse().unwrap();
    let signer: Option<Arc<dyn EnvelopeSigner>> = signed
        .then(|| Arc::new(Dalek(SigningKey::from_bytes(&[7; 32]))) as Arc<dyn EnvelopeSigner>);
    ConnectTransport::connect_for_test_with_signer(uri, signer)
}

fn assert_no_envelope(headers: &http::HeaderMap) {
    for name in [
        "x-signature",
        "x-public-key",
        "x-digest",
        "x-envelope-version",
        "x-audience",
    ] {
        assert!(!headers.contains_key(name), "{name} must be absent");
    }
}

#[test]
fn epoch_rpcs_are_unsigned_and_carry_no_repository_even_with_a_signer() {
    let stub = Stub::default();
    let (port, shutdown, handle) = spawn(stub.clone());
    let tx = client(port, true);
    assert_eq!(
        tx.get_grant_epoch("ed25519-aa").unwrap(),
        Completion::Done(4)
    );
    assert_eq!(
        tx.set_grant_epoch("statement.ed25519.sig").unwrap(),
        Completion::Done(5)
    );
    for method in ["GetGrantEpoch", "SetGrantEpoch"] {
        let seen = stub.headers_of(method);
        assert_eq!(seen.len(), 1, "{method}");
        assert_no_envelope(&seen[0]);
        assert!(!seen[0].contains_key("x-repository"), "{method}");
        assert!(!seen[0].contains_key("x-write-grant"), "{method}");
    }
    let _ = shutdown.send(());
    handle.join().unwrap();
}

#[test]
fn unavailable_with_retry_after_is_pending_and_the_same_statement_is_resent() {
    let stub = Stub::default();
    stub.epoch_pending.store(2, Ordering::SeqCst);
    *stub.retry_after.lock().unwrap() = Some("7");
    let (port, shutdown, handle) = spawn(stub.clone());
    let tx = client(port, false);
    for _ in 0..2 {
        assert_eq!(
            tx.set_grant_epoch("the-same-statement").unwrap(),
            Completion::Pending {
                retry_after: Duration::from_secs(7)
            }
        );
    }
    assert_eq!(
        tx.set_grant_epoch("the-same-statement").unwrap(),
        Completion::Done(5)
    );
    assert_eq!(
        *stub.statements.lock().unwrap(),
        ["the-same-statement"; 3],
        "each call sends the caller's statement unchanged"
    );
    let _ = shutdown.send(());
    handle.join().unwrap();
}

#[test]
fn a_missing_or_garbage_retry_after_is_one_second_and_large_values_are_clamped() {
    for (header, expected) in [
        (None, 1),
        (Some("soon"), 1),
        (Some("0"), 1),
        (Some("3600"), 60),
    ] {
        let stub = Stub::default();
        stub.epoch_pending.store(1, Ordering::SeqCst);
        *stub.retry_after.lock().unwrap() = header;
        let (port, shutdown, handle) = spawn(stub);
        let tx = client(port, false);
        assert_eq!(
            tx.set_grant_epoch("s").unwrap(),
            Completion::Pending {
                retry_after: Duration::from_secs(expected)
            },
            "{header:?}"
        );
        let _ = shutdown.send(());
        handle.join().unwrap();
    }
}

#[test]
fn a_dead_server_is_an_error_not_pending() {
    let port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    let tx = client(port, false);
    let error = tx.set_grant_epoch("s").unwrap_err();
    assert!(
        matches!(
            error,
            TransportError::ServerError { .. } | TransportError::ConnectionFailed
        ),
        "{error:?}"
    );
}

#[test]
fn visibility_statement_mode_is_unsigned_with_x_repository() {
    let stub = Stub::default();
    let (port, shutdown, handle) = spawn(stub.clone());
    let tx = client(port, true);
    assert_eq!(
        tx.set_repo_visibility(VisibilityRequest::Statement("stmt.ed25519.sig"))
            .unwrap(),
        Completion::Done(())
    );
    let seen = stub.headers_of("SetRepoVisibility");
    assert_eq!(seen.len(), 1);
    assert_no_envelope(&seen[0]);
    assert_eq!(seen[0].get("x-repository").unwrap(), "default");
    assert!(!seen[0].contains_key("x-write-grant"));
    let sent = stub.visibility.lock().unwrap();
    assert!(matches!(
        sent[0].mode,
        Some(generated::set_repo_visibility_request::Mode::SignedStatement(ref s))
            if s == "stmt.ed25519.sig"
    ));
    drop(sent);
    let _ = shutdown.send(());
    handle.join().unwrap();
}

#[test]
fn visibility_envelope_mode_is_signed_and_needs_a_signer() {
    let stub = Stub::default();
    let (port, shutdown, handle) = spawn(stub.clone());
    let tx = client(port, true);
    assert_eq!(
        tx.set_repo_visibility(VisibilityRequest::Envelope(VisibilityChoice::Private))
            .unwrap(),
        Completion::Done(())
    );
    let seen = stub.headers_of("SetRepoVisibility");
    assert!(seen[0].contains_key("x-signature"));
    assert!(seen[0].contains_key("x-public-key"));
    assert!(seen[0].contains_key("x-digest"));
    assert_eq!(seen[0].get("x-repository").unwrap(), "default");
    assert!(
        !seen[0].contains_key("x-write-grant"),
        "a grant never authorizes SetRepoVisibility"
    );
    assert!(matches!(
        stub.visibility.lock().unwrap()[0].mode,
        Some(generated::set_repo_visibility_request::Mode::Visibility(v))
            if v.as_known() == Some(generated::RepoVisibility::REPO_VISIBILITY_PRIVATE)
    ));
    // Without a signer the request is refused before it is sent.
    let unsigned = client(port, false);
    assert!(
        unsigned
            .set_repo_visibility(VisibilityRequest::Envelope(VisibilityChoice::Public))
            .is_err()
    );
    assert_eq!(stub.headers_of("SetRepoVisibility").len(), 1);
    let _ = shutdown.send(());
    handle.join().unwrap();
}
