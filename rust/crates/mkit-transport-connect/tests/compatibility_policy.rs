//! Compatibility boundaries for completion outcomes and admission receipts.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use connectrpc::server::Server;
use connectrpc::{ConnectError, RequestContext, Response, Router, handler_fn};
use mkit_core::protocol::{
    AdvanceOutcome, CommitOutcome, RefWriteCondition, Transport, TransportError,
};
use mkit_transport_connect::{
    Completion, ConnectTransport, EnvelopeSigner, PendingEvent, VisibilityRequest, generated,
};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
    mpsc,
};

const SERVICE: &str = "mkit.transport.v1.TransportService";
struct Fixture {
    client: ConnectTransport,
    calls: Arc<AtomicUsize>,
    nonces: Arc<std::sync::Mutex<Vec<String>>>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Fixture {
    fn new(outcome: Option<generated::AdvanceOutcome>, failures: usize) -> Self {
        Self::new_with_pending(outcome, failures, false)
    }
    fn new_with_pending(
        outcome: Option<generated::AdvanceOutcome>,
        failures: usize,
        pending: bool,
    ) -> Self {
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        let nonces = Arc::new(std::sync::Mutex::new(Vec::new()));
        let captured = nonces.clone();
        let (port_tx, port_rx) = mpsc::channel();
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let thread = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let bound = Server::bind("127.0.0.1:0").await.unwrap();
                port_tx.send(bound.local_addr().unwrap().port()).unwrap();
                let advance = count.clone();
                let get = count.clone();
                let set = count.clone();
                let visibility = count.clone();
                let router = Router::new()
                    .route(
                        SERVICE,
                        "AdvanceRefs",
                        handler_fn(
                            move |ctx: RequestContext, _: generated::AdvanceRefsRequest| {
                                captured.lock().unwrap().push(
                                    ctx.headers()
                                        .get("idempotency-key")
                                        .and_then(|v| v.to_str().ok())
                                        .unwrap_or_default()
                                        .to_owned(),
                                );
                                let failed = pending && advance.fetch_add(1, Ordering::SeqCst) == 0;
                                async move {
                                    if failed {
                                        return Err(ConnectError::unavailable(
                                            "verification pending",
                                        )
                                        .with_detail(connectrpc::ErrorDetail::from_message(
                                            "mkit.transport.v1.PendingVerification",
                                            &generated::PendingVerification::default()
                                                .with_retry_after_ms(1_000),
                                        )));
                                    }
                                    Ok::<_, ConnectError>(
                                        Response::new(generated::AdvanceRefsResponse {
                                            outcome: outcome.map(Into::into),
                                            ..Default::default()
                                        })
                                        .with_header("payment-receipt", "receipt"),
                                    )
                                }
                            },
                        ),
                    )
                    .route(
                        SERVICE,
                        "GetGrantEpoch",
                        handler_fn(
                            move |_: RequestContext, _: generated::GetGrantEpochRequest| {
                                let failed = get.fetch_add(1, Ordering::SeqCst) < failures;
                                async move {
                                    if failed {
                                        Err(ConnectError::unavailable("temporary"))
                                    } else {
                                        Ok(Response::new(generated::GetGrantEpochResponse {
                                            epoch: Some(5),
                                            ..Default::default()
                                        }))
                                    }
                                }
                            },
                        ),
                    )
                    .route(
                        SERVICE,
                        "SetGrantEpoch",
                        handler_fn(
                            move |_: RequestContext, _: generated::SetGrantEpochRequest| {
                                let failed = set.fetch_add(1, Ordering::SeqCst) < failures;
                                async move {
                                    if failed {
                                        Err(ConnectError::unavailable("temporary"))
                                    } else {
                                        Ok(Response::new(generated::SetGrantEpochResponse {
                                            epoch: Some(5),
                                            ..Default::default()
                                        }))
                                    }
                                }
                            },
                        ),
                    )
                    .route(
                        SERVICE,
                        "SetRepoVisibility",
                        handler_fn(
                            move |_: RequestContext, _: generated::SetRepoVisibilityRequest| {
                                let failed = visibility.fetch_add(1, Ordering::SeqCst) < failures;
                                async move {
                                    if failed {
                                        Err(ConnectError::unavailable("temporary"))
                                    } else {
                                        Ok(Response::new(
                                            generated::SetRepoVisibilityResponse::default(),
                                        ))
                                    }
                                }
                            },
                        ),
                    );
                bound
                    .serve_with_graceful_shutdown(router, async {
                        let _ = stopped.await;
                    })
                    .await
                    .unwrap();
            });
        });
        let client = ConnectTransport::connect_for_test(
            format!("http://127.0.0.1:{}", port_rx.recv().unwrap())
                .parse()
                .unwrap(),
        );
        Self {
            client,
            calls,
            nonces,
            stop: Some(stop),
            thread: Some(thread),
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.stop.take().unwrap().send(());
        self.thread.take().unwrap().join().unwrap();
    }
}

#[test]
fn advance_receipts_require_a_valid_committed_outcome_on_both_facade_paths() {
    for outcome in [
        Some(generated::AdvanceOutcome::Committed),
        Some(generated::AdvanceOutcome::HeadConflict),
        Some(generated::AdvanceOutcome::PackmapConflict),
        None,
    ] {
        for via_source in [false, true] {
            let mut fixture = Fixture::new(outcome, 0);
            let observed = Arc::new(AtomicUsize::new(0));
            let recorded = observed.clone();
            let client = ConnectTransport::connect_for_test(
                fixture
                    .client
                    .repository_address()
                    .unwrap()
                    .origin
                    .parse()
                    .unwrap(),
            )
            .with_admission_receipt_observer(move |_| {
                recorded.fetch_add(1, Ordering::SeqCst);
            });
            fixture.client = client;
            let result = if via_source {
                fixture
                    .client
                    .with_source(|source| {
                        source.advance_refs_committing(
                            "refs/heads/main",
                            RefWriteCondition::Missing,
                            &[1; 32],
                            "refs/mkit/packmap/main",
                            RefWriteCondition::Missing,
                            &[2; 32],
                            &[],
                        )
                    })
                    .unwrap()
                    .map_err(|error| error.to_string())
            } else {
                fixture
                    .client
                    .advance_refs(
                        "refs/heads/main",
                        RefWriteCondition::Missing,
                        &[1; 32],
                        "refs/mkit/packmap/main",
                        RefWriteCondition::Missing,
                        &[2; 32],
                    )
                    .map(CommitOutcome::Advanced)
                    .map_err(|error| error.to_string())
            };
            match outcome {
                Some(generated::AdvanceOutcome::Committed) => assert_eq!(
                    result.unwrap(),
                    CommitOutcome::Advanced(AdvanceOutcome::Committed)
                ),
                Some(generated::AdvanceOutcome::HeadConflict) => assert_eq!(
                    result.unwrap(),
                    CommitOutcome::Advanced(AdvanceOutcome::HeadConflict)
                ),
                Some(generated::AdvanceOutcome::PackmapConflict) => assert_eq!(
                    result.unwrap(),
                    CommitOutcome::Advanced(AdvanceOutcome::PackmapConflict)
                ),
                None => assert_eq!(result.unwrap_err(), "invalid response from remote"),
                _ => unreachable!(),
            }
            assert_eq!(
                observed.load(Ordering::SeqCst),
                usize::from(outcome == Some(generated::AdvanceOutcome::Committed)),
                "outcome={outcome:?}, via_source={via_source}"
            );
        }
    }
}

#[test]
fn unavailable_without_retry_after_uses_the_retry_ladder_for_completion_rpcs() {
    for method in ["get", "set", "visibility"] {
        let fixture = Fixture::new(None, 2);
        match method {
            "get" => assert_eq!(
                fixture.client.get_grant_epoch("namespace").unwrap(),
                Completion::Done(5)
            ),
            "set" => assert_eq!(
                fixture.client.set_grant_epoch("statement").unwrap(),
                Completion::Done(5)
            ),
            _ => assert_eq!(
                fixture
                    .client
                    .set_repo_visibility(VisibilityRequest::Statement("statement"))
                    .unwrap(),
                Completion::Done(())
            ),
        }
        assert_eq!(fixture.calls.load(Ordering::SeqCst), 3, "{method}");
    }
    let fixture = Fixture::new(None, usize::MAX);
    assert!(matches!(
        fixture.client.get_grant_epoch_once("namespace"),
        Err(TransportError::ServerError { status: 503 })
    ));
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
    let fixture = Fixture::new(None, usize::MAX);
    assert!(matches!(
        fixture.client.set_grant_epoch("statement"),
        Err(TransportError::ServerError { status: 503 })
    ));
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 6);
}

#[test]
fn invalid_advance_after_pending_finishes_progress_as_failed_without_receipts() {
    let mut fixture = Fixture::new_with_pending(None, 0, true);
    let finished = Arc::new(std::sync::Mutex::new(Vec::new()));
    let out = finished.clone();
    let receipts = Arc::new(AtomicUsize::new(0));
    let notes = receipts.clone();
    fixture.client = ConnectTransport::connect_for_test(fixture.client.origin().parse().unwrap())
        .with_pending_observer(move |event| {
            if let PendingEvent::Finished { succeeded, .. } = event {
                out.lock().unwrap().push(succeeded);
            }
            true
        })
        .with_admission_receipt_observer(move |_| {
            notes.fetch_add(1, Ordering::SeqCst);
        });
    assert!(matches!(
        fixture.client.advance_refs(
            "refs/heads/main",
            RefWriteCondition::Missing,
            &[1; 32],
            "refs/mkit/packmap/main",
            RefWriteCondition::Missing,
            &[2; 32]
        ),
        Err(TransportError::InvalidResponse)
    ));
    assert_eq!(*finished.lock().unwrap(), [false]);
    assert_eq!(receipts.load(Ordering::SeqCst), 0);
}

static RENEWAL_TIME: std::sync::atomic::AtomicI64 =
    std::sync::atomic::AtomicI64::new(1_700_000_000_000);
fn renewal_now() -> i64 {
    RENEWAL_TIME.load(Ordering::SeqCst)
}
fn no_advance_retries() -> mkit_core::protocol::BackoffIterator {
    mkit_core::protocol::BackoffIterator::with(
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
        0,
    )
}
struct RenewalSigner;
impl EnvelopeSigner for RenewalSigner {
    fn public_key_hex(&self) -> String {
        "ab".repeat(32)
    }
    fn sign_hex(&self, _: &[u8; 32]) -> Result<String, String> {
        Ok("cd".repeat(64))
    }
}
#[test]
fn advance_renews_for_the_configured_unary_attempt_budget_after_pending() {
    RENEWAL_TIME.store(1_700_000_000_000, Ordering::SeqCst);
    let mut fixture =
        Fixture::new_with_pending(Some(generated::AdvanceOutcome::Committed), 0, true);
    fixture.client = ConnectTransport::connect_for_test_with_signer(
        fixture.client.origin().parse().unwrap(),
        Some(Arc::new(RenewalSigner)),
    )
    .with_unary_timeout(std::time::Duration::from_secs(120))
    .with_clock_for_test(renewal_now)
    .with_retry_hooks_for_test(no_advance_retries, |_| {})
    .with_pending_observer(|event| {
        if matches!(event, PendingEvent::Waiting { .. }) {
            RENEWAL_TIME.fetch_add(190_000, Ordering::SeqCst);
        }
        true
    });
    assert_eq!(
        fixture
            .client
            .advance_refs(
                "refs/heads/main",
                RefWriteCondition::Missing,
                &[1; 32],
                "refs/mkit/packmap/main",
                RefWriteCondition::Missing,
                &[2; 32]
            )
            .unwrap(),
        AdvanceOutcome::Committed
    );
    let nonces = fixture.nonces.lock().unwrap();
    assert_eq!(nonces.len(), 2);
    assert_ne!(
        nonces[0], nonces[1],
        "the remaining 110 seconds cannot cover the configured 120 second unary attempt"
    );
}

#[test]
fn receipt_observer_can_reenter_the_same_transport() {
    const CHILD: &str = "CONNECT_RECEIPT_REENTRANCY_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .env(CHILD, "1")
            .args([
                "--exact",
                "receipt_observer_can_reenter_the_same_transport",
                "--nocapture",
            ])
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success(), "reentrant observer child failed");
                return;
            }
            if std::time::Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("receipt observer deadlocked while reentering the same transport");
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
    let fixture = Fixture::new(Some(generated::AdvanceOutcome::Committed), 0);
    let origin = fixture.client.origin().to_owned();
    let observed = Arc::new(AtomicUsize::new(0));
    let recorded = observed.clone();
    let transport = Arc::new_cyclic(|weak: &std::sync::Weak<ConnectTransport>| {
        let weak = weak.clone();
        ConnectTransport::connect_for_test(origin.parse().unwrap()).with_admission_receipt_observer(
            move |_| {
                let transport = weak.upgrade().unwrap();
                let _ = transport.upload_limits();
                let _ = transport.server_info();
                // The fixture has no ReadRef route. Its terminal response is
                // enough to prove nested HTTP dispatch can complete.
                assert!(transport.read_ref("refs/heads/main").is_err());
                recorded.fetch_add(1, Ordering::SeqCst);
            },
        )
    });
    assert_eq!(
        transport
            .advance_refs(
                "refs/heads/main",
                RefWriteCondition::Missing,
                &[1; 32],
                "refs/mkit/packmap/main",
                RefWriteCondition::Missing,
                &[2; 32],
            )
            .unwrap(),
        AdvanceOutcome::Committed
    );
    assert_eq!(observed.load(Ordering::SeqCst), 1);
}
