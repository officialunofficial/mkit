//! Protocol coverage retained when the reference deployment adapters are removed.
#![cfg(feature = "test-host")]

use std::sync::{Arc, OnceLock};

use mkit_server::pipeline::{Hooks, NoOutcomes, OutcomeSink};
use mkit_server::store::adapter_spi::{keys, watermark};
use mkit_server::timers::{TickBudget, registry::kinds};
use mkit_server::{Clock, NamespaceKey, NamespaceStore, Partition};
use mkit_server_conformance::stubs::hook::HookKey;
use mkit_server_conformance::stubs::mpp::{Mode, MppStub, Settings};
use mkit_server_conformance::test_host::{LoopbackHookChannel, TestHost};
use mkit_server_conformance::wire::{
    CASES, Feature, Milestone, Profile, QuotaLimits, Report, Verdict, WireAuth, WireTarget, run,
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
    println!("{}", report.tap());
    assert!(!report.failed(), "{}", report.tap());
    assert!(
        report.skips().is_empty(),
        "required cases skipped: {}",
        report.tap()
    );
    assert!(!report.passes().is_empty(), "no cases ran");
}

fn timer_namespaces(profile: &Profile) -> Vec<NamespaceKey> {
    if !profile.has(Feature::MultiRepo) {
        return vec![NamespaceKey::deployment_default()];
    }
    let mut namespaces = mkit_server_conformance::wire::multi_allowlist(profile);
    if profile.has(Feature::Grants) {
        namespaces.extend(mkit_server_conformance::wire::grant_owner_namespaces());
    }
    if let WireAuth::AuthV2 { repository, .. } = &profile.auth
        && let Some(namespace) = repository
            .split_once('/')
            .and_then(|(name, _)| mkit_core::repo_identity::Namespace::parse(name).ok())
    {
        namespaces.insert(namespace);
    }
    namespaces
        .iter()
        .map(NamespaceKey::from_namespace)
        .collect()
}

async fn timer_partitions(host: &TestHost, namespaces: &[NamespaceKey]) -> Vec<Partition> {
    use mkit_server::pipeline::ShardMap;
    let mut partitions = Vec::new();
    for namespace in namespaces {
        partitions.push(Partition::Namespace(namespace.clone()));
        if host.profile().sharding_d34 {
            let coordinator = Partition::Coordinator(namespace.clone());
            let mut cursor = None;
            loop {
                let page = watermark::active_shards(
                    host.kv().as_ref(),
                    &coordinator,
                    cursor.as_ref(),
                    256,
                )
                .await
                .expect("valid native fixture");
                for shard in &page.shards {
                    if let Partition::Ref { ns, repo, .. } = shard {
                        let repo = mkit_server::RepoId {
                            namespace: ns.clone(),
                            name: repo.clone(),
                        };
                        partitions
                            .extend(mkit_server::pipeline::D34Shards.ref_index_partitions(&repo));
                        partitions.extend(
                            mkit_server::pipeline::D34Shards.object_index_partitions(&repo),
                        );
                    }
                }
                partitions.extend(page.shards);
                cursor = page.next;
                if cursor.is_none() {
                    break;
                }
            }
            partitions.push(coordinator);
        }
    }
    partitions
}

// The wire cases stay unchanged. This test-side driver polls their future
// alongside explicit core timer ticks; business time moves only to an eligible
// persisted timer. Long listing cases also follow the unchanged wire client's
// signing clock; their assertions concern paging, not timer timing. Timer and
// growth cases follow real time without advancing a future persisted timer.
async fn run_driven<O: OutcomeSink + Clone + 'static>(
    host: &TestHost,
    filter: &str,
    outcomes: O,
    stub: Option<&MppStub>,
) -> Report {
    let mut profile = host.profile().clone();
    if filter == "lag.membership_window" || filter == "repo.d36_hint_reads_during_lag" {
        // These cases seed their own distinct repositories and drive the relay.
        profile.planted_membership = false;
    }
    let target = WireTarget {
        base_url: host.base_url().parse().expect("valid host origin"),
        profile,
    };
    let namespaces = timer_namespaces(host.profile());
    let driver = async {
        let client = reqwest::Client::builder()
            .no_proxy()
            .build()
            .expect("hook control client");
        let mut first_verifier = None;
        let mut saw_outcome_outage = false;
        let mut known_partitions = std::collections::BTreeSet::new();
        if host.profile().has(Feature::IndexedMode) {
            known_partitions.extend(mkit_server::store::content_shards());
        }
        loop {
            // Keep the one-second short ticket alive during backlog setup,
            // even on slow CI machines. The recovery phase below explicitly
            // drives its expiration after the wire case restores the sink.
            if !host.profile().has(Feature::IndexedAsync)
                && filter != "outcomes.backpressure_hook_down"
                // Multi grant/epoch fixtures synchronize at each request.
                && !(host.profile().has(Feature::MultiRepo) && host.profile().has(Feature::Grants))
            {
                let signed_at = mkit_server::SystemClock.now_ms();
                host.clock().set(host.clock().now_ms().max(signed_at));
            }
            // A partition's durable alarm outlives its coordinator lease row.
            // Remember discovered shards even after a lease sweep removes them.
            known_partitions.extend(timer_partitions(host, &namespaces).await);
            let partitions = known_partitions.clone();
            for partition in partitions {
                let (start, end) = keys::class_range(keys::TAG_TIMER);
                if host
                    .kv()
                    .scan(&partition, &start, &end, None, 1)
                    .await
                    .expect("timer head")
                    .entries
                    .is_empty()
                {
                    continue;
                }
                if host.profile().has(Feature::AdvanceHold) {
                    let (start, end) = keys::class_range(keys::TAG_TIMER);
                    let page = host
                        .kv()
                        .scan(&partition, &start, &end, None, 512)
                        .await
                        .expect("valid native fixture");
                    if page.entries.iter().any(|(key, _)| matches!(keys::parse(key), Some(keys::ParsedKey::Timer { kind, .. }) if kind == kinds::VERIFY.get())) {
                        // Model a verifier that starts slowly so the unchanged
                        // wire case observes a held advance and a concurrent read.
                        let seen = first_verifier.get_or_insert_with(tokio::time::Instant::now);
                        if seen.elapsed() < std::time::Duration::from_secs(3) { continue; }
                    }
                }
                host.drain_core_timers_with_outcomes(
                    &partition,
                    &TickBudget::default(),
                    outcomes.clone(),
                )
                .await
                .expect("drain core timers");
                advance_due_work(
                    host,
                    &partition,
                    filter,
                    stub,
                    &client,
                    &mut saw_outcome_outage,
                )
                .await;
            }
            if filter == "timers.fire_on_schedule" || filter.starts_with("growth.") {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            } else {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        }
    };
    // The verifier can spend a full bounded slice decoding on the driver
    // task. Keep the HTTP client and real-clock progression independently
    // scheduled so a held advance cannot block its concurrent read probe.
    let filter = filter.to_owned();
    let wire = tokio::spawn(async move { run(&target, Some(&filter)).await });
    let clock = host.clock().clone();
    let ticker = host.profile().has(Feature::IndexedAsync).then(|| {
        tokio::spawn(async move {
            loop {
                clock.set(clock.now_ms().max(mkit_server::SystemClock.now_ms()));
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
    });
    let report = tokio::select! {
        report = wire => report.expect("wire task panicked"),
        () = driver => unreachable!("timer driver returns only with the wire run"),
    };
    if let Some(ticker) = ticker {
        ticker.abort();
    }
    report
}

async fn advance_due_work(
    host: &TestHost,
    partition: &Partition,
    filter: &str,
    stub: Option<&MppStub>,
    client: &reqwest::Client,
    saw_outcome_outage: &mut bool,
) {
    let (start, end) = keys::class_range(keys::TAG_TIMER);
    let page = host
        .kv()
        .scan(partition, &start, &end, None, 512)
        .await
        .expect("scan persisted timers");
    let now = u64::try_from(host.clock().now_ms()).expect("nonnegative clock");
    let recovery = if let Some(stub) = stub {
        let bytes = client
            .get(format!("{}/__stub/mode", stub.origin()))
            .send()
            .await
            .expect("read hook mode")
            .bytes()
            .await
            .expect("read hook response");
        let settings: Settings = serde_json::from_slice(&bytes).expect("valid hook mode");
        if settings.outcome == Some(Mode::Down) {
            *saw_outcome_outage = true;
        }
        settings.outcome == Some(Mode::Normal)
            && (filter != "outcomes.backpressure_hook_down" || *saw_outcome_outage)
    } else {
        false
    };
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
        let expire = kind == kinds::TICKET_EXPIRY.get() && filter == "outcomes.expired_ticket";
        let retry = kind == kinds::OUTCOME_DELIVERY.get() && recovery;
        if expire || retry {
            host.clock()
                .set(i64::try_from(due_at_ms).expect("timer within clock range"));
            return;
        }
    }
}

// Make backlog setup take longer than the unchanged one-second ticket TTL.
// The explicit outage/recovery clock must keep this contract independent of
// the speed of the machine serving the HTTP requests.
fn slow_backlog_writes(app: axum::Router) -> axum::Router {
    app.layer(axum::middleware::from_fn(
        |request: axum::extract::Request, next: axum::middleware::Next| async move {
            if request.uri().path().ends_with("/UpdateRef") {
                tokio::time::sleep(std::time::Duration::from_millis(40)).await;
            }
            next.run(request).await
        },
    ))
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
        let signer = mkit_server::hooks::HookSigner::new("migration", [0x37; 32].into())
            .expect("valid native fixture");
        let stub = Arc::new(MppStub::start(vec![HookKey::new(
            "migration",
            signer.public_key(),
        )]));
        let mut profile = profile();
        profile.milestone = Milestone::M3;
        profile.backlog_cap = Some(16);
        profile.hook_stub = Some(stub.origin().parse().expect("valid native fixture"));
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
        let slow_backlog = case.name == "outcomes.backpressure_hook_down";
        let host = TestHost::start_with_test_layers(
            profile,
            move |origin, clock| {
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
            },
            |_| {},
            move |app| {
                if slow_backlog {
                    slow_backlog_writes(app)
                } else {
                    app
                }
            },
        )
        .await
        .expect("valid native fixture");
        let sink = mkit_server::hooks::RemoteOutcomes::new(
            client.get().expect("valid native fixture").clone(),
        );
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
        let host = TestHost::start(profile)
            .await
            .expect("valid native fixture");
        for case in ["list.paging_wire", "list.large_response_within_limit"] {
            let report = run_driven(&host, case, NoOutcomes, None).await;
            judge(&report);
        }
        host.shutdown().await;
    }
}

// Keep the existing ignored-lane name so the shared CI lane continues running
// this full-size HTTP proof after deployment adapters are removed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "75,000 refs over HTTP: run by the ignored-lane profile"]
async fn listing_over_32_mib_pages_under_d34() {
    let mut profile = profile();
    profile.milestone = Milestone::M1;
    profile.sharding_d34 = true;
    profile.merge_paging_refs = 75_000;
    let host = TestHost::start(profile)
        .await
        .expect("valid native fixture");
    let report = run_driven(&host, "list.merge_paging_over_32_mib", NoOutcomes, None).await;
    host.shutdown().await;
    judge(&report);
}

#[tokio::test]
async fn indexed_pending_verification_wire_case_runs_against_the_host() {
    let case = "indexed.pending_verification_unavailable";
    let mut profile = profile();
    let WireAuth::AuthV2 {
        audience,
        repository,
        seed,
    } = &mut profile.auth
    else {
        unreachable!("auth v2 profile");
    };
    let signer = mkit_server_conformance::wire::sign::Signer::derive(
        seed,
        &profile.run_id,
        &format!("{case}/main"),
        audience,
        repository,
    );
    *repository = format!("ed25519-{}/default", signer.public_key_hex());
    profile.milestone = Milestone::M4;
    profile.features.extend([
        Feature::Tickets,
        Feature::TestFaults,
        Feature::MultiRepo,
        Feature::IndexedMode,
    ]);
    let host = TestHost::start(profile)
        .await
        .expect("valid native fixture");
    let target = WireTarget {
        base_url: host.base_url().parse().expect("valid native fixture"),
        profile: host.profile().clone(),
    };
    let report = run(&target, Some(case)).await;
    host.shutdown().await;
    judge(&report);
    assert!(
        matches!(report.verdict(case), Some(Verdict::Pass(_))),
        "{}",
        report.tap()
    );
}

// Ticket pruning waits out signed replay expiry and grace twice on the real
// clock. The timer driver follows that clock without advancing future work.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn timer_and_ticket_pruning_wire_cases_run_against_the_host() {
    for case in [
        "timers.fire_on_schedule",
        "growth.tickets_and_outbox_pruned",
    ] {
        let mut profile = profile();
        profile.milestone = Milestone::M1;
        profile.quota = Some(QuotaLimits {
            window_ms: 5_000,
            max_ops: 1_000,
            max_bytes: 2 << 20,
        });
        profile
            .features
            .extend([Feature::TestFaults, Feature::Timers, Feature::ShortTickets]);
        let host = TestHost::start(profile)
            .await
            .expect("valid native fixture");
        let report = run_driven(&host, case, NoOutcomes, None).await;
        host.shutdown().await;
        judge(&report);
        assert!(
            matches!(report.verdict(case), Some(Verdict::Pass(_))),
            "{}",
            report.tap()
        );
    }
}

fn native_wire_profile(sharding_d34: bool) -> Profile {
    let mut p = profile();
    p.milestone = Milestone::M1;
    p.max_pack_bytes = 1 << 30;
    p.sharding_d34 = sharding_d34;
    p.list_refs = if sharding_d34 { 1_000 } else { 10_000 };
    p.features.extend([
        Feature::Health,
        Feature::StrictGzipAuth,
        Feature::Multipart,
        Feature::TestFaults,
        Feature::Timers,
    ]);
    if sharding_d34 {
        p.features.insert(Feature::EpochLeases);
    }
    p
}

// Run every compatible case selected by the former release/fault profiles.
// Configuration-dependent cases have dedicated tests below or in test_host.rs.
async fn native_profile(sharding_d34: bool) {
    let host = TestHost::start(native_wire_profile(sharding_d34))
        .await
        .expect("valid native fixture");
    for case in CASES
        .iter()
        .filter(|case| case.skip_reason(host.profile()).is_none())
    {
        if case.name == "list.merge_paging_over_32_mib"
            || (!sharding_d34
                && matches!(
                    case.name,
                    "lag.list_refs_window" | "list.large_response_within_limit"
                ))
        {
            continue;
        }
        let report = run_driven(&host, case.name, NoOutcomes, None).await;
        judge(&report);
    }
    host.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn native_single_wire_profile() {
    native_profile(false).await;
}

// Keep the full 10,000-ref Single fixture in its own default timeout window.
// Nextest reserves the run's threads so it does not compete with other suites.
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn native_single_large_listing() {
    let host = TestHost::start(native_wire_profile(false))
        .await
        .expect("valid native fixture");
    judge(&run_driven(&host, "list.large_response_within_limit", NoOutcomes, None).await);
    host.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn native_sharded_wire_profile() {
    native_profile(true).await;
}

fn multi_profile() -> Profile {
    let mut p = profile();
    p.milestone = Milestone::M2;
    p.sharding_d34 = true;
    p.features.extend([
        Feature::MultiRepo,
        Feature::NamespacePolicy,
        Feature::Grants,
        Feature::TestFaults,
        Feature::Timers,
        Feature::EpochLeases,
    ]);
    p
}

// These grant/epoch contracts sign statements against SystemClock, including
// a statement that expired one millisecond ago. Synchronize at the request
// boundary instead of racing a periodic timer driver; preserve explicit
// forward advances used by lease tests.
async fn start_multi_wall_clock_host() -> TestHost {
    let clock_slot = Arc::new(OnceLock::<Arc<mkit_server::ManualClock>>::new());
    let for_factory = clock_slot.clone();
    TestHost::start_with_test_layers(
        multi_profile(),
        move |_, clock| {
            for_factory
                .set(clock)
                .map_err(|_| "fixture clock initialized twice".to_owned())?;
            Ok(Hooks::new())
        },
        |_| {},
        move |app| {
            let clock = Arc::new(std::sync::Mutex::new(
                clock_slot.get().expect("fixture clock initialized").clone(),
            ));
            app.layer(axum::middleware::from_fn(
                move |request: axum::extract::Request, next: axum::middleware::Next| {
                    let clock = clock.clone();
                    async move {
                        {
                            let clock = clock.lock().expect("request clock mutex");
                            clock.set(clock.now_ms().max(mkit_server::SystemClock.now_ms()));
                        }
                        next.run(request).await
                    }
                },
            ))
        },
    )
    .await
    .expect("valid native fixture")
}

async fn multi_cases(prefixes: &[&str]) {
    let host = start_multi_wall_clock_host().await;
    for case in CASES.iter().filter(|case| {
        prefixes.iter().any(|prefix| case.name.starts_with(prefix))
            && case.skip_reason(host.profile()).is_none()
    }) {
        let report = if case.name == "repo.membership_read_your_writes" {
            // This case proves the deliberately undelivered fixture; no relay.
            run(
                &WireTarget {
                    base_url: host.base_url().parse().expect("valid native fixture"),
                    profile: host.profile().clone(),
                },
                Some(case.name),
            )
            .await
        } else {
            run_driven(&host, case.name, NoOutcomes, None).await
        };
        judge(&report);
    }
    host.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn native_epoch_expiration_uses_request_clock_without_background_ticks() {
    let host = start_multi_wall_clock_host().await;
    let target = WireTarget {
        base_url: host.base_url().parse().expect("valid native fixture"),
        profile: host.profile().clone(),
    };
    for _ in 0..5 {
        host.clock().set(mkit_server::SystemClock.now_ms() - 1_000);
        judge(&run(&target, Some("epochs.expired")).await);
    }
    host.shutdown().await;
}

macro_rules! multi_tests {
    ($($test:ident => [$($prefix:literal),*];)*) => {$(
        #[tokio::test(flavor = "multi_thread", worker_threads = 3)]
        async fn $test() { multi_cases(&[$($prefix),*]).await; }
    )*};
}

multi_tests! {
    native_grant_wire_cases => ["grants."];
    native_ref_scope_wire_cases => ["ref_scopes."];
    native_epoch_wire_cases => ["epochs."];
    native_epoch_lease_wire_cases => ["leases."];
    native_membership_lag_wire_cases => ["lag.", "repo.d36_hint_reads_during_lag"];
    native_multi_repository_wire_cases => ["repo.", "repository.", "policy.", "tickets.advance_other_repository", "tickets.advance_ticket_bindings", "info."];
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn indexed_published_source_runs_against_native_host() {
    let mut p = profile();
    p.milestone = Milestone::M4;
    p.sharding_d34 = true;
    p.features
        .extend([Feature::MultiRepo, Feature::IndexedMode]);
    let host = TestHost::start(p).await.expect("valid native fixture");
    let report = run_driven(&host, "indexed.from_published", NoOutcomes, None).await;
    judge(&report);
    host.shutdown().await;
}

struct FixtureAuthorizer;

impl mkit_server::pipeline::Authorizer for FixtureAuthorizer {
    async fn authorize(
        &self,
        operation: &mkit_server::Operation,
    ) -> Result<mkit_server::AuthzFacts, mkit_server::ServerError> {
        Ok(operation.authz.clone())
    }
}

#[derive(Clone)]
struct FixtureAdmission;

impl mkit_server::pipeline::Admission for FixtureAdmission {
    async fn admit(
        &self,
        input: &mkit_server::pipeline::AdmissionInput<'_>,
    ) -> Result<mkit_server::pipeline::AdmissionDecision, mkit_server::ServerError> {
        use mkit_server::pipeline::{AdmissionDecision, Challenge, DefaultAdmission};
        if input.op.procedure() == mkit_server::Procedure::BeginUpload && input.declared_bytes == 13
        {
            return Ok(AdmissionDecision::challenge(
                vec![Challenge {
                    scheme: "embedding-local".into(),
                    value: "fixture".into(),
                }],
                "local acceptance payment challenge",
            ));
        }
        let mut decision = DefaultAdmission.admit(input).await?;
        if input.op.procedure().is_write()
            && let Some(nonce) = input.idempotency_key
        {
            decision = decision.with_reservation(nonce);
        }
        Ok(decision)
    }
}

async fn scheduled_case(case: &str, hold: bool) {
    let mut p = profile();
    p.milestone = Milestone::M4;
    p.max_pack_bytes = 64 << 20;
    p.sharding_d34 = true;
    p.sign_reads = true;
    p.features.extend([
        Feature::MultiRepo,
        Feature::IndexedMode,
        Feature::IndexedAsync,
        Feature::HttpObjects,
        Feature::Timers,
    ]);
    if case == "indexed.async_verification_commits" || case == "fork.driver_probe" {
        p.features.insert(Feature::TestFaults);
    }
    if case == "fork.driver_probe" {
        p.features.insert(Feature::Fork);
    }
    if hold {
        p.features.insert(Feature::AdvanceHold);
    }
    let mut host = TestHost::start_with_hooks(
        p,
        Hooks {
            authorizer: FixtureAuthorizer,
            admission: FixtureAdmission,
            pre_receive: mkit_server::pipeline::NoPreReceive,
            receipts: mkit_server::pipeline::NoReceipts,
            outcomes: NoOutcomes,
        },
    )
    .await
    .expect("valid native fixture");
    let report = run_driven(&host, case, NoOutcomes, None).await;
    judge(&report);
    if case.starts_with("embedding.") {
        let Some(Verdict::Pass(Some(note))) = report.verdict(case) else {
            panic!("published fixture metadata absent");
        };
        let fields: std::collections::BTreeMap<_, _> = note
            .split_whitespace()
            .filter_map(|field| field.split_once('='))
            .collect();
        host.restart_with_default_hooks()
            .await
            .expect("restart published host");
        let response = reqwest::get(format!(
            "{}/{}/-/objects/{}",
            host.base_url(),
            fields["repository"],
            fields["extracted_blob"]
        ))
        .await
        .expect("published read after restart");
        assert_eq!(response.status(), http::StatusCode::OK);
        let expected: Vec<_> = (0..1 << 20)
            .map(|i| u8::try_from(((i * 17) ^ (i >> 9)) & 255).expect("fixture byte"))
            .collect();
        assert_eq!(response.bytes().await.expect("published bytes"), expected);
    }
    host.shutdown().await;
}

macro_rules! scheduled_tests {
    ($($test:ident => ($case:literal, $hold:literal);)*) => {$(
        #[tokio::test(flavor = "multi_thread", worker_threads = 3)]
        async fn $test() { scheduled_case($case, $hold).await; }
    )*};
}

scheduled_tests! {
    native_async_verification => ("indexed.async_verification_commits", false);
    native_async_verification_with_hold => ("indexed.async_verification_commits", true);
    native_small_scheduled_pack => ("indexed.small_pack_verification_commits", false);
    native_small_scheduled_pack_with_hold => ("indexed.small_pack_verification_commits", true);
    native_fork_driver => ("fork.driver_probe", false);
    native_reference_fixture => ("embedding.reference_fixture", false);
    native_public_fixture => ("embedding.public_fixture", false);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn namespace_quota_rollup_runs_over_native_http() {
    let mut p = profile();
    p.milestone = Milestone::M1;
    p.sharding_d34 = true;
    p.quota = Some(QuotaLimits {
        window_ms: 3_600_000,
        max_ops: 6,
        max_bytes: 2 << 20,
    });
    p.features
        .extend([Feature::MultiRepo, Feature::TestFaults, Feature::Timers]);
    let host = TestHost::start(p).await.expect("valid native fixture");
    let report = run_driven(&host, "quota.namespace_cap_after_rollup", NoOutcomes, None).await;
    judge(&report);
    host.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn native_replay_and_quota_pruning() {
    let mut p = profile();
    p.milestone = Milestone::M1;
    p.quota = Some(QuotaLimits {
        window_ms: 5_000,
        max_ops: 1_000,
        max_bytes: 2 << 20,
    });
    p.features.extend([Feature::TestFaults, Feature::Timers]);
    let host = TestHost::start(p).await.expect("valid native fixture");
    let report = run_driven(&host, "growth.replay_and_quota_pruned", NoOutcomes, None).await;
    judge(&report);
    host.shutdown().await;
}
