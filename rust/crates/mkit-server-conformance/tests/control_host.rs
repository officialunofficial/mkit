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

/// The seven cases whose shared fixture publishes real verifiable objects:
/// real commit packs and packmap nodes through signed ticketed uploads.
const VERIFIED_CASES: &[&str] = &[
    "acceptance.before_acceptance_restart",
    "acceptance.after_durable_acceptance_restart",
    "acceptance.after_response_restart",
    "acceptance.kill_recovery",
    "recovery.uncertain_commit",
    "guard.authority_final_boundary",
    "replay.moves_and_generation",
];

fn kill_recovery_skip() -> std::collections::BTreeMap<String, String> {
    std::collections::BTreeMap::from([(
        "acceptance.kill_recovery".into(),
        "reference host retains volatile memory across pipeline restart; process-kill persistence requires an external host".into(),
    )])
}

fn authority_profile() -> Profile {
    let owner = ed25519_dalek::SigningKey::from_bytes(&[0x32; 32]);
    let mut profile = profile();
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
    profile
}

async fn run_verified_case(host: &ControlledHost, name: &str) {
    let target = mkit_server_conformance::wire::WireTarget {
        base_url: host.base_url().parse().expect("loopback base url parses"),
        profile: host.profile().clone(),
    };
    let report =
        mkit_server_conformance::controlled::run(&target, &kill_recovery_skip(), Some(name)).await;
    assert!(!report.failed(), "{name}: {}", report.tap());
    let verdict = report.verdict(name);
    if name == "acceptance.kill_recovery" {
        assert!(
            matches!(
                verdict,
                Some(mkit_server_conformance::wire::Verdict::Skip(_))
            ),
            "{name}: {}",
            report.tap()
        );
    } else {
        assert!(
            matches!(
                verdict,
                Some(mkit_server_conformance::wire::Verdict::Pass(_))
            ),
            "{name}: {}",
            report.tap()
        );
    }
}

#[tokio::test]
async fn controlled_reference_host_runs_the_two_tier_acceptance_cases() {
    let host = ControlledHost::start(authority_profile()).await.unwrap();
    let skips = kill_recovery_skip();
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
        23
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
        1
    );
    assert_eq!(
        report.cases.len(),
        mkit_server_conformance::controlled::CASES.len()
    );
    host.shutdown().await;
}

#[tokio::test]
async fn authority_setter_off_rejects_both_wire_rpcs() {
    let host = ControlledHost::start(profile()).await.unwrap();
    let target = mkit_server_conformance::wire::WireTarget {
        base_url: host.base_url().parse().unwrap(),
        profile: host.profile().clone(),
    };
    let report = mkit_server_conformance::controlled::run(
        &target,
        &std::collections::BTreeMap::default(),
        Some("authority.setter"),
    )
    .await;
    assert!(!report.failed(), "{}", report.tap());
    assert!(matches!(
        report.verdict("authority.setter_disabled"),
        Some(mkit_server_conformance::wire::Verdict::Pass(_))
    ));
    assert!(matches!(
        report.verdict("authority.setter_enabled"),
        Some(mkit_server_conformance::wire::Verdict::NotApplicable(_))
    ));
    host.shutdown().await;
}

#[tokio::test]
async fn undeclared_features_are_not_applicable_and_cannot_be_declared_skips() {
    let host = ControlledHost::start(profile()).await.unwrap();
    let target = mkit_server_conformance::wire::WireTarget {
        base_url: host.base_url().parse().unwrap(),
        profile: host.profile().clone(),
    };
    let report = mkit_server_conformance::controlled::run(
        &target,
        &std::collections::BTreeMap::default(),
        Some("guard.authority_final_boundary"),
    )
    .await;
    assert!(
        matches!(report.verdict("guard.authority_final_boundary"), Some(mkit_server_conformance::wire::Verdict::NotApplicable(reason)) if reason.contains("authority-fencing"))
    );
    let skips = std::collections::BTreeMap::from([(
        "guard.authority_final_boundary".into(),
        "absent feature".into(),
    )]);
    let report = mkit_server_conformance::controlled::run(
        &target,
        &skips,
        Some("guard.authority_final_boundary"),
    )
    .await;
    assert!(report.failed(), "{}", report.tap());
    host.shutdown().await;
}

#[tokio::test]
async fn authority_setter_disabled_case_detects_an_enabled_wire_setter() {
    let mut profile = profile();
    profile.features.insert(Feature::MultiRepo);
    let host = ControlledHost::start(profile).await.unwrap();
    let mut declared = host.profile().clone();
    declared.features.remove(&Feature::AuthoritySetter);
    let target = mkit_server_conformance::wire::WireTarget {
        base_url: host.base_url().parse().unwrap(),
        profile: declared,
    };
    let report = mkit_server_conformance::controlled::run(
        &target,
        &std::collections::BTreeMap::default(),
        Some("authority.setter_disabled"),
    )
    .await;
    assert!(report.failed(), "{}", report.tap());
    host.shutdown().await;
}

#[tokio::test]
async fn opaque_host_rejects_publication_controls_before_parameter_validation() {
    let host = ControlledHost::start(profile()).await.unwrap();
    let response = reqwest::get(format!("{}{}", host.base_url(), control::CAPABILITIES_PATH))
        .await
        .unwrap();
    let capabilities: control::Capabilities =
        serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
    for name in [
        "observe.publication",
        "publication.eligibility",
        "publication.drive",
    ] {
        assert!(capabilities.unsupported.contains_key(name));
        assert!(!capabilities.controls.iter().any(|control| control == name));
    }
    let snapshot = Request::Observe {
        query: ObservationQuery {
            repository: "default".into(),
            head: "refs/heads/unsupported-publication".into(),
            ..ObservationQuery::default()
        },
    };
    let (status, before) = command(&host, &snapshot).await;
    assert_eq!(status, 200);
    let before = serde_json::from_slice::<Response>(&before)
        .unwrap()
        .observation;
    let requests = [
        Request::ObservePublication {
            query: control::PublicationQuery {
                acceptance: ObservationQuery {
                    repository: "invalid/repository".into(),
                    head: "invalid head".into(),
                    packs: vec!["invalid pack".into()],
                    ..ObservationQuery::default()
                },
            },
        },
        Request::SetPublicationEligibility {
            repository: "invalid/repository".into(),
            head: "invalid head".into(),
            eligible: false,
        },
        Request::DrivePublication {
            repository: "invalid/repository".into(),
            head: "invalid head".into(),
        },
    ];
    let mut statuses = Vec::new();
    for request in requests {
        statuses.push(command(&host, &request).await.0);
    }
    assert_eq!(statuses, [501, 501, 501]);
    let (status, after) = command(&host, &snapshot).await;
    assert_eq!(status, 200);
    assert_eq!(
        serde_json::from_slice::<Response>(&after)
            .unwrap()
            .observation,
        before
    );
    host.shutdown().await;
}

#[tokio::test]
async fn indexed_reference_host_runs_the_seven_verified_cases() {
    let mut profile = authority_profile();
    profile.features.insert(Feature::IndexedMode);
    profile.derive_features();
    let host = ControlledHost::start(profile).await.unwrap();
    for name in VERIFIED_CASES {
        run_verified_case(&host, name).await;
    }
    host.shutdown().await;
}

#[tokio::test]
async fn withheld_ref_reservation_still_runs_the_verified_cases() {
    let host = ControlledHost::start_without_ref_reservation(authority_profile())
        .await
        .unwrap();
    let response = reqwest::get(format!("{}{}", host.base_url(), control::CAPABILITIES_PATH))
        .await
        .unwrap();
    let capabilities: control::Capabilities =
        serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
    assert!(
        capabilities
            .unsupported
            .contains_key("fixture.ref_reservation")
    );
    assert!(
        !capabilities
            .controls
            .iter()
            .any(|name| name == "fixture.ref_reservation")
    );
    for name in VERIFIED_CASES {
        run_verified_case(&host, name).await;
    }
    host.shutdown().await;
}
