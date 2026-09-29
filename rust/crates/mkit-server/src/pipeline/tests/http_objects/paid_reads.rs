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
        })
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
                ("Payment-Authorization", "SECRET"),
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
            .map(|v| codec::decode_backlog(&v).unwrap().rows)
            .unwrap_or(0);
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
