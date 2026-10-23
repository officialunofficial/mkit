#![cfg(feature = "test-host")]

use mkit_server::{Batch, Clock, NamespaceKey, NamespaceStore, Partition};
use mkit_server_conformance::test_host::TestHost;
use mkit_server_conformance::wire::{
    Feature, Milestone, Profile, Verdict, WireAuth, WireTarget, run,
};

fn profile() -> Profile {
    Profile::new(WireAuth::AuthV2 {
        audience: String::new(),
        repository: "default".into(),
        seed: [0x5e; 32],
    })
}

#[tokio::test]
async fn valid_grants_admit_every_owner_scheme_in_single_and_d34() {
    for sharding_d34 in [false, true] {
        let mut p = profile();
        p.milestone = Milestone::M2;
        p.sharding_d34 = sharding_d34;
        p.features
            .extend([Feature::MultiRepo, Feature::Grants, Feature::Tickets]);
        let host = TestHost::start(p).await.unwrap();
        let target = WireTarget {
            base_url: host.base_url().parse().unwrap(),
            profile: host.profile().clone(),
        };
        let report = run(&target, Some("grants.valid_")).await;
        host.shutdown().await;
        assert!(!report.failed(), "{}", report.tap());
        for name in [
            "grants.valid_ed25519",
            "grants.valid_secp256k1_eip191",
            "grants.valid_webauthn_p256",
        ] {
            assert!(
                matches!(report.verdict(name), Some(Verdict::Pass(_))),
                "{}",
                report.tap()
            );
        }
    }
}

#[tokio::test]
async fn signed_read_capability_matches_config_without_manual_feature_derivation() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    for enabled in [false, true] {
        let mut p = profile();
        // Deliberately stale: start must normalize the profile before configuration.
        p.features.insert(Feature::SignedReads);
        p.sign_reads = enabled;
        let host = TestHost::start(p).await.unwrap();
        assert_eq!(host.profile().has(Feature::SignedReads), enabled);
        let mut socket =
            tokio::net::TcpStream::connect(host.base_url().strip_prefix("http://").unwrap())
                .await
                .unwrap();
        socket.write_all(b"GET /.well-known/mkit-url-token-keys.json HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").await.unwrap();
        let mut response = Vec::new();
        socket.read_to_end(&mut response).await.unwrap();
        host.shutdown().await;
        let response = String::from_utf8(response).unwrap();
        let status = if enabled {
            "HTTP/1.1 200"
        } else {
            "HTTP/1.1 404"
        };
        assert!(response.starts_with(status), "{response}");
    }
}

struct Hang;
impl mkit_server::pipeline::OutcomeSink for Hang {
    async fn deliver(
        &self,
        _: &mkit_server::pipeline::Outcome,
    ) -> Result<(), mkit_server::pipeline::DeliveryError> {
        futures::future::pending().await
    }
}

async fn queue_outcome(host: &TestHost) -> Partition {
    use mkit_server::store::adapter_spi::{codec, keys, outbox};
    let partition = Partition::Namespace(NamespaceKey::deployment_default());
    let prior = codec::encode_reservation(&codec::ReservationV1::Ticketed {
        ticket_id: [0x71; 32],
    });
    host.kv()
        .apply(
            &partition,
            Batch::new().put(
                keys::reservation("pending-sink").expect("valid queued-outcome fixture"),
                prior.clone(),
            ),
        )
        .await
        .expect("valid queued-outcome fixture");
    let terminal = outbox::Terminal::new(codec::ReservationV1::committed(
        "default".into(),
        u64::try_from(host.clock().now_ms()).expect("valid queued-outcome fixture"),
        0,
        0,
        0,
        Vec::new(),
        mkit_server::store::StoredProcedure::UpdateRef,
    ))
    .expect("valid queued-outcome fixture");
    let mut outbox = outbox::OutboxBuilder::new(None, None).expect("valid queued-outcome fixture");
    outbox.outcome("pending-sink", &prior, terminal);
    let mut batch = Batch::new();
    outbox
        .try_finish(&mut batch.preconditions, &mut batch.writes)
        .expect("valid queued-outcome fixture");
    host.kv()
        .apply(&partition, batch)
        .await
        .expect("valid queued-outcome fixture");
    host.clock().advance(10_000);
    partition
}

#[tokio::test]
async fn pending_outcome_sink_returns_a_bounded_error_and_retains_work() {
    use mkit_server::store::adapter_spi::{codec, keys};
    let host = TestHost::start(Profile::new(WireAuth::None)).await.unwrap();
    let partition = queue_outcome(&host).await;
    let (start, end) = keys::class_range(keys::TAG_TIMER);
    let before = host
        .kv()
        .scan(&partition, &start, &end, None, 10)
        .await
        .unwrap();
    let error = host
        .drain_core_timers_with_outcomes(
            &partition,
            &mkit_server::timers::TickBudget::new(128, 32, 512, 50),
            Hang,
        )
        .await
        .unwrap_err();
    assert!(error.to_string().contains("elapsed budget"), "{error}");
    let after = host
        .kv()
        .scan(&partition, &start, &end, None, 10)
        .await
        .unwrap();
    assert_eq!(
        before.entries, after.entries,
        "cancelled delivery lost its timer"
    );
    let backlog = host
        .kv()
        .get(&partition, &keys::outcome_backlog())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(codec::decode_backlog(&backlog).unwrap().rows, 1);
    host.shutdown().await;
}

struct DelayedOutcome(std::sync::Arc<std::sync::atomic::AtomicUsize>);
impl mkit_server::pipeline::OutcomeSink for DelayedOutcome {
    async fn deliver(
        &self,
        _: &mkit_server::pipeline::Outcome,
    ) -> Result<(), mkit_server::pipeline::DeliveryError> {
        let mut delay = core::pin::pin!(tokio::time::sleep(std::time::Duration::from_millis(100)));
        futures::future::poll_fn(|cx| {
            self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            core::future::Future::poll(delay.as_mut(), cx)
        })
        .await;
        Ok(())
    }
}

#[tokio::test]
async fn delayed_outcome_sink_is_driven_by_wakes_and_completes_within_tick_budget() {
    use mkit_server::store::adapter_spi::keys;
    let host = TestHost::start(Profile::new(WireAuth::None)).await.unwrap();
    let partition = queue_outcome(&host).await;
    let polls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    host.drain_core_timers_with_outcomes(
        &partition,
        &mkit_server::timers::TickBudget::new(128, 32, 512, 1000),
        DelayedOutcome(polls.clone()),
    )
    .await
    .unwrap();
    assert!(
        polls.load(std::sync::atomic::Ordering::Relaxed) < 16,
        "pending I/O was polled without a wake"
    );
    let (start, end) = keys::class_range(keys::TAG_TIMER);
    assert_eq!(
        host.kv()
            .scan(&partition, &start, &end, None, 10)
            .await
            .unwrap()
            .entries,
        [] as [(mkit_server::Key, mkit_server::Value); 0]
    );
    host.shutdown().await;
}
