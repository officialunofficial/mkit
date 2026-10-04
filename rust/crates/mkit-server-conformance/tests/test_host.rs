#![cfg(feature = "test-host")]

use mkit_server::timers::{
    DueTimer, Fired, TickBudget, TimerCtx, TimerHandler, TimerKind, TimerRegistry,
};
use mkit_server::{
    Batch, BoxFuture, Clock, NamespaceKey, NamespaceStore, Partition, StoreError, Value,
};
use mkit_server_conformance::stubs::hook::{FakeHook, HookKey};
use mkit_server_conformance::test_host::LoopbackHookChannel;
use mkit_server_conformance::test_host::TestHost;
use mkit_server_conformance::wire::{
    Feature, Milestone, Profile, QuotaLimits, Verdict, WireAuth, WireTarget, run,
};

fn target(host: &TestHost) -> WireTarget {
    WireTarget {
        base_url: host.base_url().parse().expect("valid host origin"),
        profile: host.profile().clone(),
    }
}

fn auth_v2_profile() -> Profile {
    Profile::new(WireAuth::AuthV2 {
        audience: "http://placeholder.invalid".into(),
        repository: "default".into(),
        seed: [0x5e; 32],
    })
}

async fn send_http(host: &TestHost, request: &str) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let address = host.base_url().strip_prefix("http://").expect("HTTP host");
    let mut socket = tokio::net::TcpStream::connect(address)
        .await
        .expect("connect to host");
    socket
        .write_all(request.as_bytes())
        .await
        .expect("send request");
    let mut response = Vec::new();
    socket
        .read_to_end(&mut response)
        .await
        .expect("read response");
    String::from_utf8(response).expect("UTF-8 HTTP response")
}

struct DrainProbe;

impl TimerHandler<mkit_server::MemoryKv> for DrainProbe {
    fn kind(&self) -> TimerKind {
        TimerKind::new(0xf0)
    }

    fn fire<'a>(
        &'a self,
        _ctx: &'a TimerCtx<'a, mkit_server::MemoryKv>,
        _timer: &'a DueTimer,
    ) -> BoxFuture<'a, Result<Fired, StoreError>> {
        Box::pin(async { Ok(Fired::Done(Batch::new())) })
    }
}

#[tokio::test]
async fn reusable_host_runs_the_existing_wire_suite() {
    let mut profile = Profile::new(WireAuth::None);
    profile.milestone = Milestone::M1;
    profile.atomic_advance = true;
    profile.fresh_target = true;
    profile.max_pack_bytes = 4 << 20;
    profile.list_refs = 200;
    profile.derive_features();

    let host = TestHost::start(profile).await.unwrap();
    let report = run(&target(&host), None).await;

    assert!(!report.failed(), "wire suite failures:\n{}", report.tap());

    for name in ["info.shape_and_policy", "info.ignores_repository_header"] {
        assert!(
            matches!(report.verdict(name), Some(Verdict::Pass(_))),
            "{name} did not pass against the reusable test host: {:?}",
            report.verdict(name)
        );
    }
    host.shutdown().await;
}

#[tokio::test]
async fn auth_v2_profile_uses_the_allocated_loopback_origin_as_audience() {
    let profile = auth_v2_profile();

    let host = TestHost::start(profile).await.unwrap();
    let WireAuth::AuthV2 { audience, .. } = &host.profile().auth else {
        panic!("auth v2 profile was changed");
    };
    assert_eq!(audience, host.base_url());
    host.shutdown().await;
}

#[tokio::test]
async fn expired_ticket_cases_use_the_frozen_server_clock() {
    let mut profile = auth_v2_profile();
    profile.milestone = Milestone::M1;
    profile
        .features
        .extend([Feature::Tickets, Feature::TestFaults, Feature::ShortTickets]);
    profile.ticket_per_signer = 2;
    let host = TestHost::start(profile).await.unwrap();
    // Model a slow fixture setup without a wall-clock sleep in every CI run.
    host.clock().advance(-5_000);
    let target = target(&host);
    for name in [
        "tickets.advance_expired_ticket",
        "tickets.upload_pack_expired_token",
        "tickets.expiry_timer_frees_cap_slot",
    ] {
        let report = run(&target, Some(name)).await;
        assert!(
            matches!(report.verdict(name), Some(Verdict::Pass(_))),
            "{}",
            report.tap()
        );
    }
    host.shutdown().await;
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // One ordered wire scenario shares its host and timer state.
async fn ticketed_auth_v2_wire_cases_run_against_the_host() {
    let mut profile = auth_v2_profile();
    profile.milestone = Milestone::M1;
    profile.atomic_advance = true;
    profile.max_pack_bytes = 4 << 20;
    profile.list_refs = 200;
    profile.fresh_target = true;
    profile.ticket_per_signer = 4;
    profile.ticket_per_ref = 8;
    profile.features.insert(Feature::ShortTickets);
    profile.quota = Some(QuotaLimits {
        window_ms: 3_600_000,
        max_ops: 6,
        max_bytes: 2 << 20,
    });
    profile.features.insert(Feature::Tickets);
    profile.features.insert(Feature::TestFaults);
    profile.derive_features();

    let signer = mkit_server::hooks::HookSigner::new("contract-test", [0x37; 32].into()).unwrap();
    let hook = std::sync::Arc::new(FakeHook::start(vec![HookKey::new(
        "contract-test",
        signer.public_key(),
    )]));
    let hook_for_factory = hook.clone();
    let remote_client = std::sync::Arc::new(std::sync::OnceLock::new());
    let client_for_factory = remote_client.clone();
    let host = TestHost::start_with_hooks_factory(profile, move |server_origin, clock| {
        let channel = LoopbackHookChannel::new(&hook_for_factory.origin())?;
        let client = std::sync::Arc::new(
            mkit_server::hooks::HookClient::new(
                channel,
                server_origin,
                Some(signer),
                clock,
                std::sync::Arc::new(mkit_server::ManualSleep::new()),
            )
            .map_err(|error| error.to_string())?,
        );
        client_for_factory
            .set(client.clone())
            .map_err(|_| "hook client was already initialized".to_owned())?;
        Ok(mkit_server::pipeline::Hooks {
            authorizer: mkit_server::pipeline::OpenAuthorizer,
            admission: mkit_server::hooks::RemoteAdmission::new(client),
            pre_receive: mkit_server::pipeline::NoPreReceive,
            receipts: mkit_server::pipeline::NoReceipts,
            outcomes: mkit_server::pipeline::NoOutcomes,
        })
    })
    .await
    .unwrap();
    let report = run(&target(&host), Some("tickets.")).await;
    assert!(
        !report.failed(),
        "ticket wire suite failures:\n{}",
        report.tap()
    );

    for name in [
        "tickets.begin_upload_new",
        "tickets.begin_upload_idempotent",
        "tickets.begin_upload_caps",
        "tickets.begin_upload_packmap_refused",
        "tickets.upload_pack_ticketed",
        "tickets.upload_pack_bad_token",
        "tickets.upload_pack_expired_token",
        "tickets.advance_expired_ticket",
        "tickets.upload_pack_binding_denied",
        "tickets.expiry_timer_frees_cap_slot",
    ] {
        assert!(
            matches!(report.verdict(name), Some(Verdict::Pass(_))),
            "{name} did not pass against the reusable test host: {:?}; hook calls: {:?}",
            report.verdict(name),
            hook.calls()
        );
    }
    assert!(
        hook.calls()
            .iter()
            .any(|call| call.procedure == "Admit" && call.verified),
        "the fake hook did not verify a signed Admit request"
    );
    let partition = mkit_server::Partition::Namespace(NamespaceKey::deployment_default());
    let prior = mkit_server::store::adapter_spi::codec::encode_reservation(
        &mkit_server::store::adapter_spi::codec::ReservationV1::Ticketed {
            ticket_id: [0x71; 32],
        },
    );
    assert_eq!(
        host.kv()
            .apply(
                &partition,
                Batch::new().put(
                    mkit_server::store::adapter_spi::keys::reservation("test-host-outcome")
                        .unwrap(),
                    prior.clone(),
                ),
            )
            .await
            .unwrap(),
        mkit_server::BatchOutcome::Committed
    );
    let terminal = mkit_server::store::adapter_spi::outbox::Terminal::new(
        mkit_server::store::adapter_spi::codec::ReservationV1::committed(
            "default".into(),
            u64::try_from(host.clock().now_ms()).unwrap(),
            0,
            0,
            0,
            Vec::new(),
            mkit_server::store::StoredProcedure::UpdateRef,
        ),
    )
    .unwrap();
    let outbox_sequence = host
        .kv()
        .get(
            &partition,
            &mkit_server::store::adapter_spi::keys::outbox_sequence(),
        )
        .await
        .unwrap();
    let outcome_backlog = host
        .kv()
        .get(
            &partition,
            &mkit_server::store::adapter_spi::keys::outcome_backlog(),
        )
        .await
        .unwrap();
    let mut outbox = mkit_server::store::adapter_spi::outbox::OutboxBuilder::new(
        outbox_sequence.as_ref(),
        outcome_backlog.as_ref(),
    )
    .unwrap();
    outbox.outcome("test-host-outcome", &prior, terminal);
    let mut batch = Batch::new();
    outbox
        .try_finish(&mut batch.preconditions, &mut batch.writes)
        .unwrap();
    assert_eq!(
        host.kv().apply(&partition, batch).await.unwrap(),
        mkit_server::BatchOutcome::Committed
    );
    host.clock().advance(10_000);
    let timers = host
        .drain_core_timers_with_outcomes(
            &partition,
            &TickBudget::default(),
            mkit_server::hooks::RemoteOutcomes::new(remote_client.get().unwrap().clone()),
        )
        .await
        .unwrap();
    assert!(
        timers.fired > 0,
        "the core timer registry did not expire due upload tickets: {timers:?}"
    );
    assert!(
        hook.calls()
            .iter()
            .any(|call| call.procedure == "Outcome" && call.verified),
        "the core outcome timer did not deliver through the signed fake hook: {timers:?}; calls: {:?}",
        hook.calls()
    );
    host.shutdown().await;
}

/// One admission as the hook saw it: procedure, requested visibility, declared bytes.
type AdmissionSeen = (
    mkit_server::Procedure,
    Option<mkit_server::pipeline::RepoVisibility>,
    u64,
);

/// Records the operation each admission sees.
#[derive(Clone, Default)]
struct RecordedAdmission(std::sync::Arc<std::sync::Mutex<Vec<AdmissionSeen>>>);

impl mkit_server::pipeline::Admission for RecordedAdmission {
    async fn admit(
        &self,
        input: &mkit_server::pipeline::AdmissionInput<'_>,
    ) -> Result<mkit_server::pipeline::AdmissionDecision, mkit_server::ServerError> {
        let visibility = match &input.op.kind {
            mkit_server::OpKind::SetRepoVisibility { visibility } => Some(*visibility),
            _ => None,
        };
        self.0.lock().expect("admission log").push((
            input.op.procedure(),
            visibility,
            input.declared_bytes,
        ));
        mkit_server::pipeline::DefaultAdmission.admit(input).await
    }
}

/// An embedder's in-process hooks (the Worker's `serve_with` takes the same
/// `HookSet`) see `SetRepoVisibility` in both modes, with the requested
/// visibility and no declared bytes.
#[tokio::test]
async fn in_process_hooks_see_repository_visibility_changes_over_the_wire() {
    let mut profile = auth_v2_profile();
    profile.milestone = Milestone::M2;
    profile.atomic_advance = true;
    profile.sign_reads = true;
    profile.features.extend([
        Feature::MultiRepo,
        Feature::Grants,
        Feature::SignedReads,
        Feature::Tickets,
    ]);
    profile.derive_features();
    let admission = RecordedAdmission::default();
    let recorded = admission.0.clone();
    let host = TestHost::start_with_hooks_factory(profile, move |_, _| {
        Ok(mkit_server::pipeline::Hooks {
            authorizer: mkit_server::pipeline::OpenAuthorizer,
            admission,
            pre_receive: mkit_server::pipeline::NoPreReceive,
            receipts: mkit_server::pipeline::NoReceipts,
            outcomes: mkit_server::pipeline::NoOutcomes,
        })
    })
    .await
    .unwrap();
    for name in ["visibility.envelope_owner", "visibility.statement_ed25519"] {
        let report = run(&target(&host), Some(name)).await;
        assert!(
            matches!(report.verdict(name), Some(Verdict::Pass(_))),
            "{name}: {}",
            report.tap()
        );
    }
    let seen: Vec<_> = recorded
        .lock()
        .expect("admission log")
        .iter()
        .filter(|(procedure, _, _)| *procedure == mkit_server::Procedure::SetRepoVisibility)
        .copied()
        .collect();
    assert!(
        seen.len() >= 2
            && seen
                .iter()
                .all(|(_, visibility, bytes)| visibility.is_some() && *bytes == 0),
        "{seen:?}"
    );
    host.shutdown().await;
}

#[tokio::test]
async fn sharded_auth_v2_quota_cases_run_against_the_host() {
    let mut profile = auth_v2_profile();
    profile.sharding_d34 = true;
    profile.atomic_advance = true;
    profile.quota = Some(QuotaLimits {
        window_ms: 3_600_000,
        max_ops: 6,
        max_bytes: 2 << 20,
    });
    profile.derive_features();

    let host = TestHost::start(profile).await.unwrap();
    let report = run(&target(&host), Some("quota.")).await;

    for name in [
        "quota.ops_exhaustion_resource_exhausted",
        "quota.bytes_exhaustion_resource_exhausted",
        "quota.exhaustion_allocates_no_replay",
        "quota.replay_not_charged",
    ] {
        assert!(
            matches!(report.verdict(name), Some(Verdict::Pass(_))),
            "{name} did not pass against the sharded test host: {:?}",
            report.verdict(name)
        );
    }
    host.shutdown().await;
}

#[tokio::test]
async fn d34_multi_addressing_runs_membership_wire_cases_against_the_host() {
    let mut profile = auth_v2_profile();
    profile.milestone = Milestone::M1;
    profile.sharding_d34 = true;
    profile.atomic_advance = true;
    profile.features.insert(Feature::MultiRepo);
    profile.features.insert(Feature::Tickets);
    profile.derive_features();

    let host = TestHost::start(profile).await.unwrap();
    assert!(host.profile().sharding_d34);
    assert!(host.profile().planted_membership);

    for name in [
        "repo.isolation_packs",
        "repo.membership_read_your_writes",
        "repo.malformed_membership_hint_no_op",
        "repository.ticketed_upload_multi",
    ] {
        let report = run(&target(&host), Some(name)).await;
        assert!(
            matches!(report.verdict(name), Some(Verdict::Pass(_))),
            "{name} did not pass against the D34 Multi test host: {:?}",
            report.verdict(name)
        );
    }
    host.shutdown().await;
}

#[tokio::test]
async fn list_repos_wire_case_runs_with_single_and_d34_sharding() {
    for sharding_d34 in [false, true] {
        let mut profile = auth_v2_profile();
        profile.milestone = Milestone::M2;
        profile.sharding_d34 = sharding_d34;
        profile.atomic_advance = true;
        profile.sign_reads = true;
        profile.features.insert(Feature::MultiRepo);
        profile.features.insert(Feature::Tickets);
        profile.derive_features();
        let host = TestHost::start(profile).await.unwrap();
        let report = run(&target(&host), Some("repo.list_repos")).await;
        assert!(
            matches!(report.verdict("repo.list_repos"), Some(Verdict::Pass(_))),
            "{}",
            report.tap()
        );
        host.shutdown().await;
    }
}

/// Drive the same push/clone/fetch dispatch used by the `mkit` CLI against
/// the host's real HTTP Connect listener.
#[tokio::test]
#[allow(clippy::too_many_lines)] // Keep the complete CLI round trip and assertions together.
async fn cli_push_clone_and_fetch_work_against_the_in_process_host() {
    let seed = [0x4a; 32];
    let mut profile = Profile::new(WireAuth::AuthV2 {
        audience: "http://placeholder.invalid".into(),
        repository: "default".into(),
        seed,
    });
    profile.milestone = Milestone::M4;
    profile.atomic_advance = true;
    profile.fresh_target = true;
    profile.features.insert(Feature::MultiRepo);
    profile.features.insert(Feature::Tickets);
    profile.features.insert(Feature::HttpObjects);
    profile.derive_features();
    let host = TestHost::start(profile).await.unwrap();
    let base_url = host.base_url().to_owned();
    let run_id = host.profile().run_id.clone();

    let blob_id = tokio::task::spawn_blocking(move || {
        use mkit_cli::remote_dispatch::{PushControl, fetch_all, pull_all_with, push_branch_steps};
        use mkit_core::hash::Hash;
        use mkit_core::layout::RepoLayout;
        use mkit_core::object::{Blob, Commit, EntryMode, Identity, Object, Tree, TreeEntry};
        use mkit_core::protocol::RefWriteCondition;
        use mkit_core::sign::{KeyPair, sign_commit};
        use mkit_core::store::ObjectStore;
        use mkit_transport_connect::ConnectTransport;
        use mkit_transport_connect::EnvelopeSigner;

        struct ClientSigner(ed25519_dalek::SigningKey);
        impl EnvelopeSigner for ClientSigner {
            fn public_key_hex(&self) -> String {
                mkit_core::hash::to_hex_bytes(&self.0.verifying_key().to_bytes())
            }

            fn sign_hex(&self, message: &[u8; 32]) -> Result<String, String> {
                use ed25519_dalek::Signer as _;
                Ok(mkit_core::hash::to_hex_bytes(
                    &self.0.sign(message).to_bytes(),
                ))
            }
        }

        let source = tempfile::tempdir().unwrap();
        let source_layout = RepoLayout::single(source.path());
        ObjectStore::init(&source_layout).unwrap();
        mkit_core::refs::init(&source_layout).unwrap();
        let source_store = ObjectStore::open(&source_layout).unwrap();
        let key = KeyPair::from_seed([0x29; 32]);
        let bytes = b"host-backed cli flow".to_vec();
        let blob = Object::Blob(Blob { data: bytes });
        let blob_id = source_store
            .write(&mkit_core::serialize::serialize(&blob).unwrap())
            .unwrap();
        let tree = Object::Tree(Tree {
            entries: vec![TreeEntry {
                name: b"file.txt".to_vec(),
                mode: EntryMode::Blob,
                object_hash: blob_id,
            }],
        });
        let tree_id = source_store
            .write(&mkit_core::serialize::serialize(&tree).unwrap())
            .unwrap();
        let mut commit = Commit::new_unannotated(
            tree_id,
            Vec::new(),
            Identity::ed25519(key.public.0),
            key.public.0,
            b"host test commit".to_vec(),
            1_700_000_000,
            [0; 64],
        );
        commit.signature = sign_commit(&commit, &key).unwrap().0;
        let tip: Hash = source_store
            .write(&mkit_core::serialize::serialize(&Object::Commit(commit)).unwrap())
            .unwrap();
        mkit_core::refs::write_ref(&source_layout, "main", &tip).unwrap();

        let label = "repo.isolation_packs/repository-a";
        let mut signer_input = b"mkit-server-conformance signer\n".to_vec();
        signer_input.extend_from_slice(&seed);
        signer_input.extend_from_slice(run_id.as_bytes());
        signer_input.push(b'\n');
        signer_input.extend_from_slice(label.as_bytes());
        let signer_seed = mkit_core::hash::hash(&signer_input);
        let signer = ClientSigner(ed25519_dalek::SigningKey::from_bytes(&signer_seed));
        let namespace = format!("ed25519-{}", signer.public_key_hex());
        let client = ConnectTransport::connect_with_signer(
            &format!("mkit+{base_url}/{namespace}/default"),
            Some(std::sync::Arc::new(signer)),
        )
        .unwrap();
        push_branch_steps(
            &client,
            &source_store,
            "main",
            tip,
            RefWriteCondition::Missing,
            0,
            mkit_core::pack::MAX_TOTAL_PAYLOAD,
            &PushControl::default(),
            &mut |_| Ok(()),
        )
        .unwrap();

        let clone = tempfile::tempdir().unwrap();
        let clone_layout = RepoLayout::single(clone.path());
        ObjectStore::init(&clone_layout).unwrap();
        mkit_core::refs::init(&clone_layout).unwrap();
        pull_all_with(clone.path(), &client, "origin", Some("main"), true).unwrap();
        assert_eq!(
            mkit_core::refs::read_ref(&clone_layout, "main").unwrap(),
            Some(tip)
        );

        let fetched = tempfile::tempdir().unwrap();
        let fetched_layout = RepoLayout::single(fetched.path());
        ObjectStore::init(&fetched_layout).unwrap();
        mkit_core::refs::init(&fetched_layout).unwrap();
        fetch_all(fetched.path(), &client, "origin").unwrap();
        assert_eq!(
            mkit_core::refs::read_remote_ref(&fetched_layout, "origin", "main").unwrap(),
            Some(tip)
        );
        (blob_id, namespace)
    })
    .await
    .unwrap();

    let (blob_id, namespace) = blob_id;
    let object_path = format!(
        "/{namespace}/default/-/objects/{}",
        mkit_core::hash::to_hex_bytes(&blob_id)
    );
    let ranged = send_http(
        &host,
        &format!(
            "GET {object_path} HTTP/1.1\r\nHost: localhost\r\nRange: bytes=1-3\r\nIf-Range: \"{}\"\r\nConnection: close\r\n\r\n",
            mkit_core::hash::to_hex_bytes(&blob_id)
        ),
    )
    .await;
    assert!(ranged.starts_with("HTTP/1.1 206"), "{ranged}");
    assert!(
        ranged
            .to_ascii_lowercase()
            .contains("content-range: bytes 1-3/20"),
        "{ranged}"
    );
    assert!(ranged.ends_with("ost"), "{ranged}");
    let conditional = send_http(
        &host,
        &format!(
            "GET {object_path} HTTP/1.1\r\nHost: localhost\r\nIf-None-Match: \"{}\"\r\nConnection: close\r\n\r\n",
            mkit_core::hash::to_hex_bytes(&blob_id)
        ),
    )
    .await;
    assert!(conditional.starts_with("HTTP/1.1 304"), "{conditional}");
    let head = send_http(
        &host,
        &format!("HEAD {object_path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"),
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(head.split_once("\r\n\r\n").unwrap().1, "");

    host.shutdown().await;
}

#[tokio::test]
async fn explicit_timer_drain_waits_for_manual_clock_advance() {
    let host = TestHost::start(Profile::new(WireAuth::None)).await.unwrap();
    let partition = Partition::Namespace(NamespaceKey::deployment_default());
    let due_at = u64::try_from(host.clock().now_ms()).unwrap() + 1_000;
    let key = mkit_server::store::adapter_spi::keys::timer(due_at, 0xf0, b"test-host-probe");
    assert_eq!(
        host.kv()
            .apply(&partition, Batch::new().put(key, Value::default()))
            .await
            .unwrap(),
        mkit_server::BatchOutcome::Committed
    );
    let registry = TimerRegistry::new().register(DrainProbe);
    let budget = TickBudget::default();

    assert_eq!(
        host.drain_timers(&partition, &registry, &budget)
            .await
            .unwrap()
            .fired,
        0
    );
    host.clock().advance(1_000);
    assert_eq!(
        host.drain_timers(&partition, &registry, &budget)
            .await
            .unwrap()
            .fired,
        1
    );
    host.shutdown().await;
}

#[tokio::test]
async fn http_object_mount_uses_core_cors_and_options_behavior() {
    let mut profile = auth_v2_profile();
    profile.milestone = Milestone::M1;
    profile.features.insert(Feature::MultiRepo);
    profile.features.insert(Feature::Tickets);
    profile.features.insert(Feature::HttpObjects);
    profile.sign_reads = true;
    profile.derive_features();
    let host = TestHost::start(profile).await.unwrap();
    let response = send_http(
        &host,
        "OPTIONS /ns/repo/-/objects/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa HTTP/1.1\r\nHost: localhost\r\nOrigin: https://embedding.example\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(response.starts_with("HTTP/1.1 204"), "{response}");
    assert!(
        response
            .to_ascii_lowercase()
            .contains("access-control-allow-origin: *")
    );
    assert!(
        response
            .to_ascii_lowercase()
            .contains("access-control-allow-methods: get, head, options")
    );
    let get = send_http(
        &host,
        "GET /.well-known/mkit-url-token-keys.json HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(get.starts_with("HTTP/1.1 200"), "{get}");
    assert!(
        get.to_ascii_lowercase()
            .contains("content-type: application/json")
    );
    let head = send_http(
        &host,
        "HEAD /.well-known/mkit-url-token-keys.json HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(head.split_once("\r\n\r\n").unwrap().1, "");
    let WireAuth::AuthV2 {
        audience,
        repository,
        seed,
    } = &host.profile().auth
    else {
        panic!("HTTP object test requires auth v2");
    };
    let signer = mkit_server_conformance::wire::sign::Signer::derive(
        seed,
        &host.profile().run_id,
        "repo.isolation_packs/repository-a",
        audience,
        repository,
    );
    let namespace = format!("ed25519-{}", signer.public_key_hex());
    let object_path = format!("/{namespace}/{repository}/-/objects/{}", "a".repeat(64));
    let get = send_http(
        &host,
        &format!(
            "GET {object_path} HTTP/1.1\r\nHost: localhost\r\nRange: bytes=0-1\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    let head = send_http(
        &host,
        &format!("HEAD {object_path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"),
    )
    .await;
    assert!(get.starts_with("HTTP/1.1 404"), "{get}");
    assert!(head.starts_with("HTTP/1.1 404"), "{head}");
    assert_eq!(head.split_once("\r\n\r\n").unwrap().1, "");
    host.shutdown().await;
}
