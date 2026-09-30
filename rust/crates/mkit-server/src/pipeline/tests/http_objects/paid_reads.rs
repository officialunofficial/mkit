//! Real Admission and durable read outcomes, independent of HTTP mounting.
use super::*;
use crate::http_objects::HttpReadRuntime;
use crate::rt::{BoxFuture, Sleep, Spawner};
use crate::store::codec::{AbortReason, PendingOp, ReservationV1};
use crate::timers::reservation_reconcile::ReservationReconcile;
use crate::timers::{TickBudget, TimerRegistry, run_due};

#[derive(Default)]
struct Tasks(Mutex<Vec<std::thread::JoinHandle<()>>>);
impl Spawner for Tasks {
    fn spawn(&self, fut: BoxFuture<'static, ()>) {
        self.0
            .lock()
            .unwrap()
            .push(std::thread::spawn(move || block_on(fut)));
    }
}
impl Tasks {
    fn join(&self) {
        for task in self.0.lock().unwrap().drain(..) {
            task.join().unwrap();
        }
    }
}
struct Timer;
impl Sleep for Timer {
    fn sleep(&self, duration: Duration) -> BoxFuture<'static, ()> {
        if duration == Duration::from_millis(10) {
            Box::pin(async {})
        } else {
            Box::pin(core::future::pending())
        }
    }
}
#[derive(Default)]
struct PaidAdmission {
    calls: Mutex<Vec<(u64, Vec<crate::pipeline::CredentialHeader>)>>,
    challenge: AtomicBool,
    next: AtomicU32,
}
impl Admission for Arc<PaidAdmission> {
    async fn admit(&self, input: &AdmissionInput<'_>) -> Result<AdmissionDecision, ServerError> {
        if input.op.procedure().is_write() {
            return Ok(AdmissionDecision::allow(vec![]));
        }
        assert_eq!(input.op.principal.kind(), "anonymous");
        assert!(input.op.auth.is_none() && input.op.write_grant.is_none());
        assert!(!input.creates_namespace && !input.creates_repo);
        assert_eq!(input.new_to_repo_bytes, Some(0));
        assert_eq!(input.pack_id, None);
        assert_eq!(input.idempotency_key, None);
        assert_eq!(input.audience, Some(AUDIENCE));
        assert!(matches!(
            input.op.procedure(),
            Procedure::HttpGetObject | Procedure::HttpGetRefPath
        ));
        self.calls
            .lock()
            .unwrap()
            .push((input.declared_bytes, input.credential_headers.to_vec()));
        if self.challenge.load(std::sync::atomic::Ordering::SeqCst) {
            Ok(AdmissionDecision::challenge(
                vec![Challenge {
                    scheme: "mpp".into(),
                    value: "pay".into(),
                }],
                "payment",
            )
            .with_response_header("WWW-Authenticate", "Payment realm=repo")
            .with_response_header("WWW-Authenticate", "Other realm=repo")
            .with_response_header("PAYMENT-REQUIRED", "request"))
        } else {
            let n = self.next.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(AdmissionDecision::allow(vec![])
                .with_reservation(format!("read-{n}"))
                .with_response_header("Payment-Receipt", "receipt"))
        }
    }
}
type PaidHooks = Hooks<OpenAuthorizer, Arc<PaidAdmission>>;
fn setup() -> (Fx<PaidHooks>, Data, Arc<PaidAdmission>, Arc<Tasks>) {
    let admission = Arc::new(PaidAdmission::default());
    let tasks = Arc::new(Tasks::default());
    let fx = fixture_with(
        Hooks {
            authorizer: OpenAuthorizer,
            admission: admission.clone(),
            pre_receive: NoPreReceive,
            receipts: NoReceipts,
            outcomes: NoOutcomes,
        },
        HttpObjectsConfig {
            admit_reads: true,
            ..http_cfg()
        },
    );
    let fx = with_seams(fx, |s| {
        s.read_runtime = Some(HttpReadRuntime {
            sleep: Arc::new(Timer),
            spawner: tasks.clone(),
        });
    });
    let d = data();
    fx.push("room", &d.refs(), d.head(), None);
    (fx, d, admission, tasks)
}
fn reservation(fx: &Fx<PaidHooks>, n: u32) -> ReservationV1 {
    let repo = RepoId {
        namespace: NamespaceKey::from_namespace(&Namespace::parse(&fx.namespace()).unwrap()),
        name: RepoName::new("room").unwrap(),
    };
    let partition = fx.pipe.shards.coordinator(&repo.namespace);
    let value = block_on(fx.pipe.meta.get(
        &partition,
        &keys::reservation(&format!("read-{n}")).unwrap(),
    ))
    .unwrap()
    .unwrap();
    codec::decode_reservation(&value).unwrap()
}
fn served(fx: &Fx<PaidHooks>, n: u32, object: Hash, bytes: u64) {
    assert!(
        matches!(reservation(fx, n), ReservationV1::ReadServed { object: actual, bytes_served, .. } if actual == object && bytes_served == bytes)
    );
}

#[test]
fn missing_runtime_and_failed_pending_write_never_return_content() {
    for missing_runtime in [false, true] {
        let (fx, d, admission, tasks) = setup();
        let fx = if missing_runtime {
            with_seams(fx, |s| s.read_runtime = None)
        } else {
            fx.pipe
                .meta
                .fail_next_apply
                .store(true, std::sync::atomic::Ordering::SeqCst);
            fx
        };
        let got = fx.get(&fx.object_url("room", &id(&d.small)));
        assert_eq!(got.status, 503);
        assert_eq!(got.header("Cache-Control"), Some("no-store"));
        assert!(got.header("ETag").is_none());
        assert_ne!(got.body, d.small_bytes);
        assert_eq!(
            admission.calls.lock().unwrap().len(),
            usize::from(!missing_runtime)
        );
        let repo = NamespaceKey::from_namespace(&Namespace::parse(&fx.namespace()).unwrap());
        let partition = fx.pipe.shards.coordinator(&repo);
        assert!(
            block_on(
                fx.pipe
                    .meta
                    .get(&partition, &keys::reservation("read-0").unwrap())
            )
            .unwrap()
            .is_none()
        );
        tasks.join();
    }
}

#[test]
fn paid_get_head_range_and_bypass_input_are_exact() {
    let (fx, d, admission, tasks) = setup();
    let path = fx.object_url("room", &id(&d.big));
    let got = fx.get(&path);
    assert_eq!(got.status, 200);
    assert_eq!(
        got.header("Cache-Control"),
        Some("private, max-age=31536000, immutable")
    );
    assert_eq!(got.header("Payment-Receipt"), Some("receipt"));
    served(&fx, 0, id(&d.big), d.big_bytes.len() as u64);
    assert_eq!(fx.get_with(&path, &[("range", "bytes=0-99")]).status, 206);
    served(&fx, 1, id(&d.big), 100);
    let got = read(fx.request("HEAD", &path, None, &[("range", "bytes=0-9")]));
    assert_eq!(got.status, 206);
    assert!(got.body.is_empty());
    assert_eq!(got.header("Content-Length"), Some("10"));
    served(&fx, 2, id(&d.big), 0);
    let etag = format!("\"{}\"", to_hex(&id(&d.big)));
    assert_eq!(
        fx.get_with(&path, &[("if-none-match", &etag)])
            .header("Cache-Control"),
        Some("private, max-age=31536000, immutable")
    );
    assert_eq!(
        fx.get_with(&path, &[("range", "bytes=99999999-")]).status,
        416
    );
    assert_eq!(
        admission
            .calls
            .lock()
            .unwrap()
            .iter()
            .map(|x| x.0)
            .collect::<Vec<_>>(),
        [d.big_bytes.len() as u64, 100, 10]
    );
    tasks.join();
}

#[test]
fn pending_is_durable_before_response_and_drop_retains_actual_bytes() {
    let (fx, d, _, tasks) = setup();
    *fx.pipe.blobs.reads.lock().unwrap() = Reads::Pieces;
    let path = fx.object_url("room", &id(&d.big));
    let response = fx.request("GET", &path, None, &[]);
    assert!(matches!(
        reservation(&fx, 0),
        ReservationV1::Pending {
            op: PendingOp::Read,
            ..
        }
    ));
    drop(response);
    tasks.join();
    assert!(matches!(
        reservation(&fx, 0),
        ReservationV1::Aborted {
            reason: AbortReason::Internal,
            ..
        }
    ));
    let HttpBody::Stream { mut stream, .. } = fx.request("GET", &path, None, &[]).body else {
        panic!()
    };
    let n = block_on(stream.next()).unwrap().unwrap().len();
    drop(stream);
    tasks.join();
    served(&fx, 1, id(&d.big), n as u64);
}

#[test]
fn opening_failure_and_short_source_settle_zero_and_partial_outcomes() {
    let (fx, d, _, tasks) = setup();
    let path = fx.object_url("room", &id(&d.big));
    *fx.pipe.blobs.reads.lock().unwrap() = Reads::Fails;
    assert_eq!(fx.get(&path).status, 503);
    assert!(matches!(
        reservation(&fx, 0),
        ReservationV1::Aborted {
            reason: AbortReason::Internal,
            ..
        }
    ));
    *fx.pipe.blobs.reads.lock().unwrap() = Reads::Short;
    let response = fx.request("GET", &path, None, &[]);
    assert_eq!(response.status, 200);
    let HttpBody::Stream { mut stream, .. } = response.body else {
        panic!()
    };
    assert_eq!(
        block_on(stream.next()).unwrap().unwrap().len(),
        d.big_bytes.len() - 1
    );
    assert!(block_on(stream.next()).unwrap().is_err());
    served(&fx, 1, id(&d.big), d.big_bytes.len() as u64 - 1);
    tasks.join();
}

#[test]
fn deadline_stops_before_next_piece_and_grace_protects_completion() {
    let (fx, d, _, tasks) = setup();
    *fx.pipe.blobs.reads.lock().unwrap() = Reads::Pieces;
    let HttpBody::Stream { mut stream, .. } = fx
        .request("GET", &fx.object_url("room", &id(&d.big)), None, &[])
        .body
    else {
        panic!()
    };
    let ReservationV1::Pending {
        created_at_ms,
        reconcile_at_ms,
        ..
    } = reservation(&fx, 0)
    else {
        panic!()
    };
    assert_eq!(reconcile_at_ms - created_at_ms, 360_000);
    let first = block_on(stream.next()).unwrap().unwrap().len();
    fx.clock
        .set(i64::try_from(created_at_ms + 300_000).unwrap());
    assert!(block_on(stream.next()).unwrap().is_err());
    assert!(block_on(stream.next()).is_none());
    served(&fx, 0, id(&d.big), first as u64);
    tasks.join();
}

#[test]
fn challenge_json_headers_and_head_have_no_success_metadata_or_state() {
    let (fx, d, admission, tasks) = setup();
    admission
        .challenge
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let path = fx.object_url("room", &id(&d.small));
    for method in ["GET", "HEAD"] {
        let got = read(fx.request(method, &path, None, &[]));
        assert_eq!(got.status, 402);
        assert_eq!(got.header("Cache-Control"), Some("no-store"));
        assert_eq!(got.header("Content-Type"), Some("application/json"));
        assert_eq!(
            got.headers
                .iter()
                .filter(|(n, _)| *n == "WWW-Authenticate")
                .count(),
            2
        );
        assert!(
            !got.headers
                .iter()
                .any(|(n, _)| n.starts_with("X-Mkit-") || *n == "ETag" || *n == "Content-Range")
        );
        if method == "GET" {
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&got.body).unwrap(),
                serde_json::json!({"challenges":[{"scheme":"mpp","value":"pay"}],"description":"payment"})
            );
        } else {
            assert!(got.body.is_empty());
        }
    }
    assert_eq!(admission.next.load(std::sync::atomic::Ordering::SeqCst), 0);
    tasks.join();
}

#[test]
fn http_credentials_enforce_bounds_and_redaction_before_admit() {
    let (mut fx, d, admission, tasks) = setup();
    fx.pipe.cfg.admission_credential_headers = vec!["X-Pay".into()];
    let path = fx.object_url("room", &id(&d.small));
    let long = "x".repeat(8193);
    for headers in [
        vec![("Payment-Authorization", "a,b")],
        vec![("PAYMENT-SIGNATURE", "a,b")],
        vec![("X-Pay", "a,b")],
        vec![
            ("Payment-Authorization", "a"),
            ("payment-authorization", "b"),
        ],
        vec![("PAYMENT-SIGNATURE", long.as_str())],
        vec![("X-Pay", "bad\n")],
    ] {
        assert_eq!(fx.get_with(&path, &headers).status, 403);
    }
    assert!(admission.calls.lock().unwrap().is_empty());
    assert_eq!(
        fx.get_with(
            &path,
            &[
                ("Authorization", "Bearer SECRET"),
                ("payment-authorization", "SECRET"),
                ("PAYMENT-SIGNATURE", "signature"),
                ("X-Pay", "extra")
            ]
        )
        .status,
        200
    );
    let calls = admission.calls.lock().unwrap();
    let headers = &calls[0].1;
    assert_eq!(headers.len(), 3);
    assert_eq!(headers[0].name, "payment-authorization");
    assert!(!format!("{headers:?}").contains("SECRET"));
    drop(calls);
    assert_eq!(
        fx.get_with(&path, &[("Authorization", "Payment abc==")])
            .status,
        200
    );
    assert_eq!(
        admission.calls.lock().unwrap()[1].1[0].value.expose(),
        "Payment abc=="
    );
    tasks.join();
}

#[test]
fn completion_and_reconcile_share_one_arbiter_and_retry_settlement_io() {
    for late in [false, true] {
        let (fx, d, _, tasks) = setup();
        let repo = NamespaceKey::from_namespace(&Namespace::parse(&fx.namespace()).unwrap());
        let partition = fx.pipe.shards.coordinator(&repo);
        let initial = block_on(fx.pipe.meta.get(&partition, &keys::outcome_backlog()))
            .unwrap()
            .map_or(0, |v| codec::decode_backlog(&v).unwrap().rows);
        *fx.pipe.blobs.reads.lock().unwrap() = Reads::Pieces;
        let HttpBody::Stream { mut stream, .. } = fx
            .request("GET", &fx.object_url("room", &id(&d.big)), None, &[])
            .body
        else {
            panic!()
        };
        let n = block_on(stream.next()).unwrap().unwrap().len();
        let ReservationV1::Pending {
            reconcile_at_ms, ..
        } = reservation(&fx, 0)
        else {
            panic!()
        };
        let at = reconcile_at_ms - u64::from(!late);
        fx.clock.set(i64::try_from(at).unwrap());
        let repo = NamespaceKey::from_namespace(&Namespace::parse(&fx.namespace()).unwrap());
        let partition = fx.pipe.shards.coordinator(&repo);
        let registry = TimerRegistry::new().register(ReservationReconcile);
        let tick = block_on(run_due(
            &fx.pipe.meta,
            &partition,
            &registry,
            fx.clock.as_ref(),
            at,
            &TickBudget::default(),
        ))
        .unwrap();
        assert_eq!(tick.fired, u32::from(late));
        if !late {
            fx.pipe
                .meta
                .fail_next_apply
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
        drop(stream);
        tasks.join();
        if late {
            assert!(matches!(
                reservation(&fx, 0),
                ReservationV1::Aborted {
                    reason: AbortReason::Abandoned,
                    ..
                }
            ));
        } else {
            served(&fx, 0, id(&d.big), n as u64);
        }
        let backlog = block_on(fx.pipe.meta.get(&partition, &keys::outcome_backlog()))
            .unwrap()
            .unwrap();
        assert_eq!(codec::decode_backlog(&backlog).unwrap().rows, initial + 1);
    }
}

#[test]
fn paid_private_ids_keep_the_token_lifetime_bound_and_head_zero_outcome() {
    let (mut fx, d, _, tasks) = setup();
    let tokens = crate::url_token::UrlTokenConfig::new(
        crate::url_token::UrlTokenKeys::new(zeroize::Zeroizing::new([13; 32]), vec![]).unwrap(),
    );
    fx.pipe.cfg.url_tokens = Some(tokens.clone());
    fx.pipe = fx.pipe.with_http_seams(|mut s| {
        s.tokens = Arc::new(tokens.clone());
        s
    });
    fx.make_private("room");
    let token = tokens
        .mint(
            AUDIENCE,
            &fx.identity("room"),
            &crate::url_token::UrlTarget::Object(id(&d.small)),
            0,
            fx.clock.now_ms(),
            60,
        )
        .unwrap();
    let path = fx.object_url("room", &id(&d.small));
    fx.clock.advance(1);
    let got = read(fx.request(
        "GET",
        &path,
        Some(&format!("token={}", token.expose())),
        &[],
    ));
    assert_eq!(got.status, 200);
    assert_eq!(
        got.header("Cache-Control"),
        Some("private, max-age=59, immutable")
    );
    served(&fx, 0, id(&d.small), d.small_bytes.len() as u64);
    let got = read(fx.request(
        "HEAD",
        &path,
        Some(&format!("token={}", token.expose())),
        &[],
    ));
    assert_eq!(got.status, 200);
    assert!(got.body.is_empty());
    served(&fx, 1, id(&d.small), 0);
    tasks.join();
}

#[derive(Default)]
struct RetrySink {
    fail: AtomicBool,
    seen: Mutex<Vec<crate::pipeline::Outcome>>,
}
impl OutcomeSink for RetrySink {
    async fn deliver(
        &self,
        outcome: &crate::pipeline::Outcome,
    ) -> Result<(), crate::pipeline::DeliveryError> {
        self.seen.lock().unwrap().push(outcome.clone());
        if self.fail.load(std::sync::atomic::Ordering::SeqCst) {
            Err(crate::pipeline::DeliveryError::new("retry", None))
        } else {
            Ok(())
        }
    }
}

#[test]
fn paid_outcome_survives_delivery_driver_restart_and_retry() {
    let (fx, d, _, tasks) = setup();
    assert_eq!(fx.get(&fx.object_url("room", &id(&d.small))).status, 200);
    tasks.join();
    let repo = fx.repo_id("room");
    let partition = fx.pipe.shards.coordinator(&repo.namespace);
    let sink = Arc::new(RetrySink::default());
    sink.fail.store(true, std::sync::atomic::Ordering::SeqCst);
    let fire = || {
        // Reconstruct the entire delivery driver, keeping only durable rows.
        let driver = crate::timers::outcome_delivery::OutcomeDelivery::new(
            sink.clone(),
            AUDIENCE.into(),
            fx.metrics.clone(),
            Arc::new(Timer),
        );
        let registry = TimerRegistry::new()
            .register(driver)
            .register(ReservationReconcile);
        block_on(run_due(
            &fx.pipe.meta,
            &partition,
            &registry,
            fx.clock.as_ref(),
            ms(fx.clock.now_ms()),
            &TickBudget::default(),
        ))
        .unwrap();
    };
    fire();
    let first = sink
        .seen
        .lock()
        .unwrap()
        .iter()
        .find(|o| o.reservation_id == "read-0")
        .unwrap()
        .clone();
    assert!(matches!(
        first.kind,
        crate::pipeline::OutcomeKind::ReadServed {
            bytes_served: 100,
            ..
        }
    ));
    assert!(
        block_on(
            fx.pipe
                .meta
                .get(&partition, &keys::reservation("read-0").unwrap())
        )
        .unwrap()
        .is_some()
    );
    sink.fail.store(false, std::sync::atomic::Ordering::SeqCst);
    fx.clock.advance(900_001);
    fire();
    let seen = sink.seen.lock().unwrap();
    let repeats: Vec<_> = seen
        .iter()
        .filter(|o| o.reservation_id == "read-0")
        .collect();
    assert_eq!(repeats, [&first, &first]);
    assert!(
        block_on(
            fx.pipe
                .meta
                .get(&partition, &keys::reservation("read-0").unwrap())
        )
        .unwrap()
        .is_none()
    );
}

#[test]
fn empty_get_is_settled_before_returning_even_if_adapter_never_polls() {
    let (fx, _, _, tasks) = setup();
    let response = fx.request("GET", &fx.ref_url("room", "main", "empty"), None, &[]);
    assert_eq!(response.status, 200);
    assert_eq!(response.header("Content-Length"), Some("0"));
    served(&fx, 0, id(&blob(b"")), 0);
    drop(response);
    tasks.join();
    served(&fx, 0, id(&blob(b"")), 0);
}

#[test]
fn simultaneous_completion_and_reconcile_commit_exactly_one_outcome() {
    let (mut fx, d, _, tasks) = setup();
    let barrier = Arc::new(std::sync::Barrier::new(2));
    Arc::get_mut(&mut fx.pipe.meta).unwrap().hook = Some(Box::new(move |_, _, batch| {
        for write in &batch.writes {
            if let Write::Put(key, value) = write
                && *key == keys::reservation("read-0").unwrap()
                && matches!(
                    codec::decode_reservation(value).unwrap(),
                    ReservationV1::ReadServed { .. } | ReservationV1::Aborted { .. }
                )
            {
                // Both contenders have planned from the same pending bytes
                // and counters before either backend commit can proceed.
                barrier.wait();
            }
        }
    }));
    *fx.pipe.blobs.reads.lock().unwrap() = Reads::Pieces;
    let HttpBody::Stream { mut stream, .. } = fx
        .request("GET", &fx.object_url("room", &id(&d.big)), None, &[])
        .body
    else {
        panic!()
    };
    let n = block_on(stream.next()).unwrap().unwrap().len();
    let ReservationV1::Pending {
        reconcile_at_ms, ..
    } = reservation(&fx, 0)
    else {
        panic!()
    };
    let partition = fx.pipe.shards.coordinator(&fx.repo_id("room").namespace);
    let initial = block_on(fx.pipe.meta.get(&partition, &keys::outcome_backlog()))
        .unwrap()
        .map_or(0, |v| codec::decode_backlog(&v).unwrap().rows);
    fx.clock.set(i64::try_from(reconcile_at_ms).unwrap());
    let meta = fx.pipe.meta.clone();
    let clock = fx.clock.clone();
    let p = partition.clone();
    let reconcile = std::thread::spawn(move || {
        let registry = TimerRegistry::new().register(ReservationReconcile);
        block_on(run_due(
            &meta,
            &p,
            &registry,
            clock.as_ref(),
            reconcile_at_ms,
            &TickBudget::default(),
        ))
        .unwrap();
    });
    drop(stream);
    tasks.join();
    reconcile.join().unwrap();
    match reservation(&fx, 0) {
        ReservationV1::ReadServed {
            object,
            bytes_served,
            ..
        } => assert_eq!((object, bytes_served), (id(&d.big), n as u64)),
        ReservationV1::Aborted { reason, .. } => assert_eq!(reason, AbortReason::Abandoned),
        other => panic!("unexpected outcome {other:?}"),
    }
    let backlog = block_on(fx.pipe.meta.get(&partition, &keys::outcome_backlog()))
        .unwrap()
        .unwrap();
    assert_eq!(codec::decode_backlog(&backlog).unwrap().rows, initial + 1);
}

#[test]
fn proof_get_head_share_admission_and_declare_encoded_bytes() {
    let (fx, d, admission, tasks) = setup();
    let proofs = Arc::new(Proofs(Mutex::default()));
    let fx = with_seams(fx, |s| s.proofs = proofs.clone());
    let path = fx.object_url("room", &id(&d.small));
    let query = format!("proof=1&commit={}&path=small.txt", to_hex(&d.head()));
    let got = read(fx.request(
        "GET",
        &path,
        Some(&query),
        &[("Range", "bytes=0-1"), ("payment-authorization", "paid")],
    ));
    assert_eq!(got.status, 200);
    let len = got.body.len() as u64;
    assert_eq!(got.header("Content-Length"), Some(len.to_string().as_str()));
    assert_eq!(got.header("Payment-Receipt"), Some("receipt"));
    assert_eq!(
        got.header("Cache-Control"),
        Some("private, max-age=31536000, immutable")
    );
    served(&fx, 0, id(&d.small), len);
    let head = read(fx.request("HEAD", &path, Some(&query), &[]));
    assert_eq!(head.status, 200);
    assert!(head.body.is_empty());
    assert_eq!(head.header("Content-Length"), got.header("Content-Length"));
    served(&fx, 1, id(&d.small), 0);
    assert_eq!(proofs.0.lock().unwrap().len(), 1); // HEAD never builds.
    let calls = admission.calls.lock().unwrap();
    assert_eq!(calls.iter().map(|c| c.0).collect::<Vec<_>>(), [len, len]);
    assert_eq!(calls[0].1.len(), 1);
    assert_eq!(calls[0].1[0].name, "payment-authorization");
    drop(calls);
    tasks.join();
}

#[test]
fn proof_challenge_denial_revalidation_caps_and_context_never_build() {
    let (mut fx, d, admission, tasks) = setup();
    let proofs = Arc::new(Proofs(Mutex::default()));
    fx = with_seams(fx, |s| s.proofs = proofs.clone());
    let path = fx.object_url("room", &id(&d.small));
    let query = format!("proof=1&commit={}&path=small.txt", to_hex(&d.head()));
    let etag = format!("\"{}.{}.object\"", to_hex(&d.head()), to_hex(&id(&d.small)));
    let response = read(fx.request("GET", &path, Some(&query), &[("if-none-match", &etag)]));
    assert_eq!(response.status, 304);
    assert_eq!(
        response.header("Cache-Control"),
        Some("private, max-age=31536000, immutable")
    );
    assert!(admission.calls.lock().unwrap().is_empty());
    for method in ["GET", "HEAD"] {
        admission
            .challenge
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let got = read(fx.request(method, &path, Some(&query), &[]));
        assert_eq!(got.status, 402);
        assert!(got.header("ETag").is_none());
        assert!(got.header("X-Mkit-Object").is_none());
    }
    admission
        .challenge
        .store(false, std::sync::atomic::Ordering::SeqCst);
    // Credential denial precedes Admission and proof construction.
    assert_eq!(
        read(fx.request(
            "GET",
            &path,
            Some(&query),
            &[("payment-authorization", "a,b")]
        ))
        .status,
        403
    );
    let calls = admission.calls.lock().unwrap().len();
    for suffix in ["&range=0-18446744073709551615", "&range=99999-99999"] {
        assert_eq!(
            read(fx.request("GET", &path, Some(&format!("{query}{suffix}")), &[])).status,
            416
        );
    }
    fx.pipe
        .cfg
        .http_objects
        .as_mut()
        .unwrap()
        .max_proof_bundle_bytes = 1;
    assert_eq!(
        read(fx.request("GET", &path, Some(&query), &[])).status,
        416
    );
    assert_eq!(
        read(fx.request(
            "GET",
            &path,
            Some(&query.replace("small.txt", "big.bin")),
            &[("if-none-match", "*")]
        ))
        .status,
        404
    );
    assert_eq!(admission.calls.lock().unwrap().len(), calls);
    assert_eq!(admission.next.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert!(proofs.0.lock().unwrap().is_empty());
    tasks.join();
}

struct FailedProof(bool);
impl ProofServer for FailedProof {
    fn build<'a>(
        &'a self,
        request: &'a PreparedProof,
        _: &'a mut dyn ProofSource,
    ) -> BoxFuture<'a, Result<Vec<u8>, ServerError>> {
        Box::pin(async move {
            if self.0 {
                Ok(vec![0; request.encoded_len as usize - 1])
            } else {
                Err(ServerError::unavailable("build failed"))
            }
        })
    }
}
#[test]
fn proof_build_failure_and_planned_length_mismatch_abort_reservation() {
    for short in [false, true] {
        let (fx, d, admission, tasks) = setup();
        let fx = with_seams(fx, |s| s.proofs = Arc::new(FailedProof(short)));
        let query = format!("proof=1&commit={}&path=small.txt", to_hex(&d.head()));
        let got = read(fx.request(
            "GET",
            &fx.object_url("room", &id(&d.small)),
            Some(&query),
            &[],
        ));
        assert_eq!(got.status, 503);
        assert!(matches!(
            reservation(&fx, 0),
            ReservationV1::Aborted {
                reason: AbortReason::Internal,
                ..
            }
        ));
        assert_eq!(admission.calls.lock().unwrap().len(), 1);
        tasks.join();
    }
}

#[test]
fn proof_drop_before_or_after_first_byte_settles_once() {
    for poll in [false, true] {
        let (fx, d, _, tasks) = setup();
        let fx = with_seams(fx, |s| s.proofs = Arc::new(Proofs(Mutex::default())));
        let query = format!("proof=1&commit={}&path=small.txt", to_hex(&d.head()));
        let got = fx.request(
            "GET",
            &fx.object_url("room", &id(&d.small)),
            Some(&query),
            &[],
        );
        assert!(matches!(reservation(&fx, 0), ReservationV1::Pending { .. }));
        let HttpBody::Stream { mut stream, .. } = got.body else {
            panic!("paid proof stream");
        };
        if poll {
            let bytes = block_on(stream.next()).unwrap().unwrap().len() as u64;
            drop(stream);
            tasks.join();
            served(&fx, 0, id(&d.small), bytes);
        } else {
            drop(stream);
            tasks.join();
            assert!(matches!(
                reservation(&fx, 0),
                ReservationV1::Aborted {
                    reason: AbortReason::Internal,
                    ..
                }
            ));
        }
    }
}
