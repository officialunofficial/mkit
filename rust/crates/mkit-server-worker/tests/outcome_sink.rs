//! WP-3.5: the Worker's kind-8 sink seam, plan budget and timeout, plus the
//! CORS strings, repeated `WWW-Authenticate` and credential redaction of the
//! fetch adapter's host-testable parts.
#![allow(clippy::unwrap_used)]

use std::sync::{Arc, Mutex};

use mkit_server::pipeline::{DeliveryError, Outcome, OutcomeSink};
use mkit_server::store::codec::{self, AbortReason, ReservationV1};
use mkit_server::store::keys;
use mkit_server::store::outbox::{OutboxBuilder, Terminal};
use mkit_server::timers::{TickBudget, TimerRegistry, run_due};
use mkit_server::{
    Batch, BatchOutcome, ManualClock, ManualSleep, MemoryKv, NamespaceKey, NamespaceStore,
    Partition, Sleep,
};
use mkit_server_worker::adapter::{
    ConfigError, cors_allow_headers, cors_expose_headers, outcome_budget, response_header_plan,
    with_outcome_timers,
};
use mkit_server_worker::classes::ShardClass;

/// Records each call; fails or hangs on request.
#[derive(Clone, Default)]
struct Sink {
    calls: Arc<Mutex<Vec<String>>>,
    fail: bool,
    hang: bool,
}

impl OutcomeSink for Sink {
    async fn deliver(&self, outcome: &Outcome) -> Result<(), DeliveryError> {
        self.calls
            .lock()
            .unwrap()
            .push(outcome.reservation_id.clone());
        if self.hang {
            std::future::pending::<()>().await;
        }
        if self.fail {
            return Err(DeliveryError::new("sink down", None));
        }
        Ok(())
    }
}

fn partition() -> Partition {
    Partition::Namespace(NamespaceKey::deployment_default())
}

/// `rows` terminal outcomes, written in small batches (a batch has an op cap).
async fn seed(store: &MemoryKv, rows: usize) {
    let ids: Vec<String> = (0..rows).map(|i| format!("r{i:03}")).collect();
    for group in ids.chunks(4) {
        let os = store
            .get(&partition(), &keys::outbox_sequence())
            .await
            .unwrap();
        let oc = store
            .get(&partition(), &keys::outcome_backlog())
            .await
            .unwrap();
        let mut builder = OutboxBuilder::new(os.as_ref(), oc.as_ref()).unwrap();
        for id in group {
            builder.abort_direct(
                id,
                Terminal::new(ReservationV1::aborted(
                    "repo".into(),
                    100,
                    AbortReason::Unspecified,
                    String::new(),
                ))
                .unwrap(),
            );
        }
        let mut batch = Batch::new();
        builder
            .try_finish(&mut batch.preconditions, &mut batch.writes)
            .unwrap();
        assert_eq!(
            store.apply(&partition(), batch).await.unwrap(),
            BatchOutcome::Committed
        );
    }
}

fn registry(
    plan: Option<&str>,
    sink: Sink,
    sleep: Arc<dyn Sleep>,
) -> TimerRegistry<'static, MemoryKv> {
    with_outcome_timers(
        TimerRegistry::new(),
        ShardClass::RefStore,
        Ok::<_, ConfigError>("https://server.example".to_owned()),
        plan,
        sink,
        sleep,
        Arc::new(ManualClock::new(0)),
    )
}

async fn alarm(store: &MemoryKv, registry: &TimerRegistry<'static, MemoryKv>, now: u64) {
    run_due(
        store,
        &partition(),
        registry,
        &ManualClock::new(i64::try_from(now).unwrap()),
        now,
        &TickBudget::default(),
    )
    .await
    .unwrap();
}

async fn backlog(store: &MemoryKv) -> u64 {
    store
        .get(&partition(), &keys::outcome_backlog())
        .await
        .unwrap()
        .map_or(0, |v| codec::decode_backlog(&v).unwrap().rows)
}

#[tokio::test]
async fn a_capturing_sink_receives_the_outcomes_and_they_are_acknowledged() {
    let store = MemoryKv::default();
    seed(&store, 3).await;
    let sink = Sink::default();
    let registry = registry(Some("paid"), sink.clone(), Arc::new(ManualSleep::new()));
    alarm(&store, &registry, 200).await;
    assert_eq!(sink.calls.lock().unwrap().len(), 3);
    assert_eq!(backlog(&store).await, 0);
}

#[tokio::test]
async fn a_failing_sink_is_called_once_per_fire_and_loses_nothing() {
    let store = MemoryKv::default();
    seed(&store, 5).await;
    let sink = Sink {
        fail: true,
        ..Sink::default()
    };
    let registry = registry(Some("free"), sink.clone(), Arc::new(ManualSleep::new()));
    alarm(&store, &registry, 200).await;
    assert_eq!(sink.calls.lock().unwrap().len(), 1);
    assert_eq!(backlog(&store).await, 5);
}

#[tokio::test]
async fn a_hanging_sink_is_cut_by_the_timeout() {
    let store = MemoryKv::default();
    seed(&store, 2).await;
    let sink = Sink {
        hang: true,
        ..Sink::default()
    };
    let sleeper = ManualSleep::elapsed();
    let registry = registry(Some("free"), sink.clone(), Arc::new(sleeper.clone()));
    alarm(&store, &registry, 200).await;
    assert_eq!(sink.calls.lock().unwrap().len(), 1);
    assert_eq!(sleeper.requested(), [std::time::Duration::from_secs(5)]);
    assert_eq!(backlog(&store).await, 2);
}

#[tokio::test]
async fn free_plan_makes_at_most_eight_sink_calls_per_alarm() {
    let store = MemoryKv::default();
    seed(&store, 40).await;
    let sink = Sink::default();
    let registry = registry(Some("free"), sink.clone(), Arc::new(ManualSleep::new()));
    alarm(&store, &registry, 200).await;
    assert_eq!(sink.calls.lock().unwrap().len(), 8);
    // An unset or unknown plan is the Free budget.
    for plan in [None, Some("other")] {
        assert_eq!(outcome_budget(plan).sink_calls_per_alarm(), 8);
    }
    assert_eq!(outcome_budget(Some("free")).sink_calls_per_alarm(), 8);
    assert_eq!(outcome_budget(Some(" Paid ")).sink_calls_per_alarm(), 64);
}

#[test]
fn cors_strings_carry_the_payment_headers() {
    let allow = cors_allow_headers();
    for name in [
        "authorization",
        "payment-authorization",
        "payment-signature",
        "accept-payment",
        "x-signature",
        "content-type",
    ] {
        assert_eq!(
            allow.split(", ").filter(|have| *have == name).count(),
            1,
            "{name} in {allow}"
        );
    }
    let expose = cors_expose_headers();
    for name in [
        "WWW-Authenticate",
        "PAYMENT-REQUIRED",
        "Payment-Receipt",
        "PAYMENT-RESPONSE",
    ] {
        assert!(expose.split(", ").any(|have| have == name), "{expose}");
    }
}

#[test]
fn repeated_www_authenticate_is_appended_not_replaced() {
    let mut headers = http::HeaderMap::new();
    headers.insert("content-type", "application/json".parse().unwrap());
    headers.append("www-authenticate", "Payment id=\"a\"".parse().unwrap());
    headers.append("www-authenticate", "Payment id=\"b\"".parse().unwrap());
    headers.append("www-authenticate", "Bearer".parse().unwrap());
    let plan = response_header_plan(&headers);
    let wa: Vec<_> = plan
        .iter()
        .filter(|(name, _, _)| name == "www-authenticate")
        .collect();
    assert_eq!(wa.len(), 3);
    assert!(!wa[0].2, "the first value replaces the runtime default");
    assert!(wa[1].2 && wa[2].2, "later values append");
    let ct = plan
        .iter()
        .find(|(name, _, _)| name == "content-type")
        .unwrap();
    assert!(!ct.2);
}

#[tokio::test]
async fn content_shard_purge_drains_shared_wake_without_unknown_timer() {
    let store = MemoryKv::default();
    let p = mkit_server::store::content_shard(&[9; 32]);
    let request = mkit_server::purge::Request {
        purge_id: "content-purge".into(),
        audience: "https://server.example".into(),
        repository: "root/repo".into(),
        namespace: String::new(),
        trigger: mkit_server::purge::Trigger::Takedown,
        url_paths: Vec::new(),
        object_ids: Vec::new(),
        refs: Vec::new(),
    };
    store
        .apply(
            &p,
            mkit_server::purge::plan_enqueue(&request, 10, None, None).unwrap(),
        )
        .await
        .unwrap();
    let sink = Sink::default();
    let registry = with_outcome_timers(
        TimerRegistry::new(),
        ShardClass::ContentIndexShard,
        Ok("https://server.example".into()),
        Some("paid"),
        sink.clone(),
        Arc::new(ManualSleep::new()),
        Arc::new(ManualClock::new(10)),
    )
    .register(mkit_server::purge::PurgeDelivery::new(
        Arc::new(mkit_server::purge::NoLocalCache),
        None,
        mkit_server::purge::SliceBudget::new(16),
    ));
    let first = run_due(
        &store,
        &p,
        &registry,
        &ManualClock::new(10),
        10,
        &TickBudget::new(4, 4, 64, 1000),
    )
    .await
    .unwrap();
    assert_eq!((first.fired, first.unknown, first.scanned), (2, 0, 2));
    let second = run_due(
        &store,
        &p,
        &registry,
        &ManualClock::new(10000),
        10000,
        &TickBudget::new(4, 4, 64, 1000),
    )
    .await
    .unwrap();
    assert_eq!((second.fired, second.unknown, second.scanned), (1, 0, 1));
    assert!(
        store
            .get(&p, &keys::outcome_backlog())
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .scan(
                &p,
                &mkit_server::Key::new(b"w\0".to_vec()),
                &mkit_server::Key::new(b"w\x01".to_vec()),
                None,
                100
            )
            .await
            .unwrap()
            .entries
            .is_empty()
    );
    assert!(sink.calls.lock().unwrap().is_empty());
}
