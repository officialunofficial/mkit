#![cfg(feature = "test-host")]

use mkit_server::store::adapter_spi::{codec, keys};
use mkit_server::{Batch, NamespaceKey, NamespaceStore, Partition, RepoName};
use mkit_server_conformance::control::{self, ObservationQuery, Request, Response};
use mkit_server_conformance::test_host::{ControlledHost, TestHost};
use mkit_server_conformance::wire::{Feature, Profile, WireAuth};

fn profile() -> Profile {
    Profile::new(WireAuth::AuthV2 {
        audience: "http://placeholder.invalid".into(),
        repository: "default".into(),
        seed: [0x62; 32],
    })
}

async fn command(host: &ControlledHost, request: &Request) -> (u16, Vec<u8>) {
    let response = reqwest::Client::new()
        .post(format!("{}{}", host.base_url(), control::CONTROL_PATH))
        .header("content-type", "application/json")
        .body(serde_json::to_vec(request).expect("serialize control request"))
        .send()
        .await
        .expect("send loopback control request");
    (
        response.status().as_u16(),
        response
            .bytes()
            .await
            .expect("read control response")
            .to_vec(),
    )
}

#[tokio::test]
async fn controlled_host_negotiates_truthful_controls_and_pins_clock() {
    let host = ControlledHost::start(profile()).await.unwrap();
    let response = reqwest::get(format!("{}{}", host.base_url(), control::CAPABILITIES_PATH))
        .await
        .unwrap();
    let capabilities: control::Capabilities =
        serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
    assert_eq!(capabilities.version, control::VERSION);
    assert!(capabilities.controls.iter().any(|name| name == "observe"));
    assert!(capabilities.unsupported.contains_key("restart.kill"));
    assert!(
        !capabilities
            .controls
            .iter()
            .any(|name| name == "authority.bump")
    );
    let (status, body) = command(&host, &Request::PinClock { now_ms: 123 }).await;
    assert_eq!(status, 200);
    assert_eq!(
        serde_json::from_slice::<Response>(&body).unwrap().now_ms,
        Some(123)
    );
    let (status, body) = command(&host, &Request::AdvanceClock { delta_ms: 42 }).await;
    assert_eq!(status, 200);
    assert_eq!(
        serde_json::from_slice::<Response>(&body).unwrap().now_ms,
        Some(165)
    );
    assert_eq!(
        command(
            &host,
            &Request::Restart {
                mode: "kill".into()
            }
        )
        .await
        .0,
        501
    );
    host.shutdown().await;
}

#[tokio::test]
async fn controlled_host_atomic_typed_snapshot_survives_pipeline_restart() {
    let host = ControlledHost::start(profile()).await.unwrap();
    let repo = RepoName::new("default").unwrap();
    let head = "refs/heads/test-control";
    let packmap = mkit_attest::grant::head_packmap(head).unwrap();
    let partition = Partition::Namespace(NamespaceKey::deployment_default());
    host.kv()
        .apply(
            &partition,
            Batch::new()
                .put(
                    keys::ref_key(&repo, head),
                    codec::encode_ref_id(&[0x21; 32]),
                )
                .put(
                    keys::ref_key(&repo, &packmap),
                    codec::encode_ref_id(&[0x22; 32]),
                ),
        )
        .await
        .unwrap();
    let request = Request::Observe {
        query: ObservationQuery {
            repository: "default".into(),
            head: head.into(),
            ..ObservationQuery::default()
        },
    };
    let (status, before) = command(&host, &request).await;
    assert_eq!(status, 200);
    let before = serde_json::from_slice::<Response>(&before)
        .unwrap()
        .observation
        .unwrap();
    assert_eq!(before.head.as_deref(), Some("21".repeat(32).as_str()));
    assert_eq!(before.packmap.as_deref(), Some("22".repeat(32).as_str()));
    assert_eq!(
        command(
            &host,
            &Request::Restart {
                mode: "graceful".into()
            }
        )
        .await
        .0,
        200
    );
    let (status, after) = command(&host, &request).await;
    assert_eq!(status, 200);
    assert_eq!(
        serde_json::from_slice::<Response>(&after)
            .unwrap()
            .observation,
        Some(before)
    );
    host.shutdown().await;
}

#[tokio::test]
async fn controlled_host_authority_control_is_conditional_and_monotonic() {
    let mut profile = profile();
    profile.features.insert(Feature::MultiRepo);
    let host = ControlledHost::start(profile).await.unwrap();
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x31; 32]);
    let namespace = format!(
        "ed25519-{}",
        mkit_core::hash::to_hex(key.verifying_key().as_bytes())
    );
    for generation in [1, 2] {
        let (status, body) = command(
            &host,
            &Request::BumpAuthority {
                namespace: namespace.clone(),
            },
        )
        .await;
        assert_eq!(status, 200);
        assert_eq!(
            serde_json::from_slice::<Response>(&body)
                .unwrap()
                .generation,
            Some(generation)
        );
    }
    host.shutdown().await;
}

#[tokio::test]
async fn ordinary_test_host_does_not_mount_control_routes() {
    let host = TestHost::start(profile()).await.unwrap();
    let response = reqwest::get(format!("{}{}", host.base_url(), control::CAPABILITIES_PATH))
        .await
        .unwrap();
    assert!(!response.status().is_success());
    host.shutdown().await;
}

#[tokio::test]
async fn controlled_reference_host_runs_the_two_tier_acceptance_cases() {
    let mut profile = profile();
    let owner = ed25519_dalek::SigningKey::from_bytes(&[0x32; 32]);
    if let WireAuth::AuthV2 { repository, .. } = &mut profile.auth {
        *repository = format!(
            "ed25519-{}/conformance",
            mkit_core::hash::to_hex(owner.verifying_key().as_bytes())
        );
    }
    profile.atomic_advance = true;
    profile.quota = Some(mkit_server_conformance::wire::QuotaLimits {
        max_ops: 32,
        max_bytes: 1024 * 1024,
        window_ms: 3_600_000,
    });
    profile
        .features
        .extend([Feature::MultiRepo, Feature::Tickets]);
    profile.derive_features();
    let host = ControlledHost::start(profile).await.unwrap();
    let mut skips = std::collections::BTreeMap::from([(
        "acceptance.kill_recovery".into(),
        "reference host retains volatile memory across pipeline restart; process-kill persistence requires an external host".into(),
    )]);
    for (case, reason) in [
        (
            "fork.destination_gate_before_acceptance",
            "reference fork destination gate is not implemented",
        ),
        (
            "fork.failed_destination_inert",
            "reference fork destination gate and per-commit authority fence are not implemented",
        ),
        (
            "fork.acceptance_result_replay_outcome_atomic",
            "gated fork test binding awaits destination activation and advancing-commit fencing",
        ),
        (
            "fork.authority_at_acceptance",
            "reference guarded fork authority-fence binding is not yet implemented",
        ),
        (
            "fork.authority_each_progress_commit",
            "reference fork does not yet compare recorded authority facts at every advancing commit",
        ),
    ] {
        skips.insert(case.into(), reason.into());
    }
    for change in ["moved", "unpublished", "visibility_revoked", "denied"] {
        for phase in ["before_acceptance", "after_acceptance"] {
            skips.insert(
                format!("fork.source_{change}_{phase}"),
                "reference fork lacks a final source proof after all membership staging and before guarded acceptance".into(),
            );
        }
    }
    let target = mkit_server_conformance::wire::WireTarget {
        base_url: host.base_url().parse().unwrap(),
        profile: host.profile().clone(),
    };
    let report = mkit_server_conformance::controlled::run(&target, &skips, None).await;
    assert!(!report.failed(), "{}", report.tap());
    assert_eq!(
        report
            .cases
            .iter()
            .filter(|case| matches!(
                case.verdict,
                mkit_server_conformance::wire::Verdict::Pass(_)
            ))
            .count(),
        6
    );
    assert_eq!(
        report
            .cases
            .iter()
            .filter(|case| matches!(
                case.verdict,
                mkit_server_conformance::wire::Verdict::Skip(_)
            ))
            .count(),
        14
    );
    assert_eq!(
        report.cases.len(),
        mkit_server_conformance::controlled::CASES.len()
    );
    host.shutdown().await;
}
