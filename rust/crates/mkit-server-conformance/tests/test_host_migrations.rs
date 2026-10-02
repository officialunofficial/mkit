//! Protocol coverage retained when the native adapter is removed.
#![cfg(feature = "test-host")]

use std::sync::{Arc, OnceLock};

use mkit_server::pipeline::{Hooks, NoOutcomes, OutcomeSink};
use mkit_server::store::{Cursor, keys, watermark};
use mkit_server::timers::{TickBudget, registry::kinds};
use mkit_server::{Clock, NamespaceKey, NamespaceStore, Partition};
use mkit_server_conformance::stubs::hook::HookKey;
use mkit_server_conformance::stubs::mpp::{Mode, MppStub, Settings};
use mkit_server_conformance::test_host::{LoopbackHookChannel, TestHost};
use mkit_server_conformance::wire::{
    CASES, Feature, Milestone, Profile, Report, WireAuth, WireTarget, run,
};

fn profile() -> Profile {
    let mut profile = Profile::new(WireAuth::AuthV2 {
        audience: String::new(),
        repository: "default".into(),
        seed: [0x5e; 32],
    });
    profile.atomic_advance = true;
    profile.max_pack_bytes = 4 << 20;
    profile.features.insert(Feature::Tickets);
    profile
}

fn judge(report: &Report) {
    assert!(!report.failed(), "{}", report.tap());
    assert!(
        report.skips().is_empty(),
        "required cases skipped: {}",
        report.tap()
    );
    assert!(!report.passes().is_empty(), "no cases ran");
}

// The wire cases stay unchanged. This test-side driver polls their future
// alongside explicit core timer ticks; business time moves only to an eligible
// persisted timer. Long listing cases also follow the unchanged wire client's
// signing clock; their assertions concern paging, not timer timing.
async fn run_driven<O: OutcomeSink + Clone + 'static>(
    host: &TestHost,
    filter: &str,
    outcomes: O,
    stub: Option<&MppStub>,
) -> Report {
    let target = WireTarget {
        base_url: host.base_url().parse().expect("valid host origin"),
        profile: host.profile().clone(),
    };
    let driver = async {
        let client = reqwest::Client::builder()
            .no_proxy()
            .build()
            .expect("hook control client");
        let coordinator = Partition::Coordinator(NamespaceKey::deployment_default());
        let mut cursor: Option<Cursor> = None;
        loop {
            if filter.starts_with("list.") {
                let signed_at = mkit_server::SystemClock.now_ms();
                host.clock().set(host.clock().now_ms().max(signed_at));
            }
            let partitions = if host.profile().sharding_d34 {
                let page = watermark::active_shards(
                    host.kv().as_ref(),
                    &coordinator,
                    cursor.as_ref(),
                    256,
                )
                .await
                .expect("read active shards");
                cursor = page.next;
                page.shards
            } else {
                vec![Partition::Namespace(NamespaceKey::deployment_default())]
            };
            for partition in partitions {
                host.drain_core_timers_with_outcomes(
                    &partition,
                    &TickBudget::default(),
                    outcomes.clone(),
                )
                .await
                .expect("drain core timers");
                advance_due_work(host, &partition, filter, stub, &client).await;
            }
            tokio::task::yield_now().await;
        }
    };
    tokio::select! {
        report = run(&target, Some(filter)) => report,
        () = driver => unreachable!("timer driver returns only with the wire run"),
    }
}

async fn advance_due_work(
    host: &TestHost,
    partition: &Partition,
    filter: &str,
    stub: Option<&MppStub>,
    client: &reqwest::Client,
) {
    let (start, end) = keys::class_range(keys::TAG_TIMER);
    let page = host
        .kv()
        .scan(partition, &start, &end, None, 512)
        .await
        .expect("scan persisted timers");
    let now = u64::try_from(host.clock().now_ms()).expect("nonnegative clock");
    for (key, _) in page.entries {
        let Some(keys::ParsedKey::Timer {
            due_at_ms, kind, ..
        }) = keys::parse(&key)
        else {
            continue;
        };
        if due_at_ms <= now {
            continue;
        }
        let expire = filter == "outcomes.expired_ticket" && kind == kinds::TICKET_EXPIRY.get();
        let retry = if kind == kinds::OUTCOME_DELIVERY.get() {
            if let Some(stub) = stub {
                let bytes = client
                    .get(format!("{}/__stub/mode", stub.origin()))
                    .send()
                    .await
                    .expect("read hook mode")
                    .bytes()
                    .await
                    .expect("read hook control response");
                let settings: Settings = serde_json::from_slice(&bytes).expect("valid hook mode");
                settings.outcome == Some(Mode::Normal)
            } else {
                false
            }
        } else {
            false
        };
        if expire || retry {
            host.clock()
                .set(i64::try_from(due_at_ms).expect("timer within clock range"));
            return;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn admission_and_outcome_failures_run_the_existing_wire_cases() {
    let cases: Vec<_> = CASES
        .iter()
        .filter(|case| {
            case.name.starts_with("admission.")
                || case.name.starts_with("cors.")
                || case.name.starts_with("outcomes.")
        })
        .collect();
    for case in cases {
        let signer = mkit_server::hooks::HookSigner::new("migration", [0x37; 32].into()).unwrap();
        let stub = Arc::new(MppStub::start(vec![HookKey::new(
            "migration",
            signer.public_key(),
        )]));
        let mut profile = profile();
        profile.milestone = Milestone::M3;
        profile.backlog_cap = Some(16);
        profile.hook_stub = Some(stub.origin().parse().unwrap());
        profile.features.extend([
            Feature::Admission,
            Feature::HookStub,
            Feature::Timers,
            Feature::ShortTickets,
            Feature::BacklogCap,
        ]);
        let client = Arc::new(OnceLock::new());
        let for_factory = client.clone();
        let stub_for_factory = stub.clone();
        let host = TestHost::start_with_hooks_factory(profile, move |origin, clock| {
            let channel = LoopbackHookChannel::new(&stub_for_factory.origin())?;
            let client = Arc::new(
                mkit_server::hooks::HookClient::new(
                    channel,
                    origin,
                    Some(signer),
                    clock,
                    Arc::new(mkit_server::ManualSleep::new()),
                )
                .map_err(|error| error.to_string())?,
            );
            for_factory
                .set(client.clone())
                .map_err(|_| "hook client initialized twice".to_owned())?;
            Ok(Hooks {
                authorizer: mkit_server::pipeline::OpenAuthorizer,
                admission: mkit_server::hooks::RemoteAdmission::new(client.clone()),
                pre_receive: mkit_server::pipeline::NoPreReceive,
                receipts: mkit_server::pipeline::NoReceipts,
                outcomes: mkit_server::hooks::RemoteOutcomes::new(client),
            })
        })
        .await
        .unwrap();
        let sink = mkit_server::hooks::RemoteOutcomes::new(client.get().unwrap().clone());
        let report = run_driven(&host, case.name, sink, Some(stub.as_ref())).await;
        host.shutdown().await;
        judge(&report);
        assert!(
            stub.hook.calls().iter().all(|call| call.verified),
            "unsigned hook call in {}",
            case.name
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn large_listing_wire_cases_run_in_single_and_d34() {
    for sharding_d34 in [false, true] {
        let mut profile = profile();
        profile.milestone = Milestone::M1;
        profile.sharding_d34 = sharding_d34;
        profile.list_refs = 1_000;
        let host = TestHost::start(profile).await.unwrap();
        for case in ["list.paging_wire", "list.large_response_within_limit"] {
            let report = run_driven(&host, case, NoOutcomes, None).await;
            judge(&report);
        }
        host.shutdown().await;
    }
}

// Keep the existing ignored-lane name so the shared CI lane continues running
// this full-size HTTP proof after the native package is removed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "75,000 refs over HTTP: run by the ignored-lane profile"]
async fn listing_over_32_mib_pages_under_d34() {
    let mut profile = profile();
    profile.milestone = Milestone::M1;
    profile.sharding_d34 = true;
    profile.merge_paging_refs = 75_000;
    let host = TestHost::start(profile).await.unwrap();
    let report = run_driven(&host, "list.merge_paging_over_32_mib", NoOutcomes, None).await;
    host.shutdown().await;
    judge(&report);
}
