#![cfg(feature = "test-host")]

use mkit_server_conformance::differential::{DiffStatus, DiffTarget, run};
use mkit_server_conformance::test_host::ControlledHost;
use mkit_server_conformance::wire::profile::QuotaLimits;
use mkit_server_conformance::wire::{Profile, WireAuth, WireTarget};

#[tokio::test]
async fn deterministic_decisions_match_between_native_reference_hosts() {
    let mut profile = Profile::new(WireAuth::AuthV2 {
        audience: "http://placeholder.invalid".into(),
        repository: "default".into(),
        seed: [0x45; 32],
    });
    profile.atomic_advance = true;
    profile.derive_features();
    let left = ControlledHost::start(profile.clone()).await.unwrap();
    let right = ControlledHost::start(profile).await.unwrap();
    let target = |host: &ControlledHost| DiffTarget {
        wire: WireTarget {
            base_url: host.base_url().parse().unwrap(),
            profile: host.profile().clone(),
        },
        control_url: host.base_url().parse().unwrap(),
    };
    let report = run(&target(&left), &target(&right)).await.unwrap();
    assert!(
        !report.failed(),
        "{}",
        serde_json::to_string_pretty(&report).unwrap()
    );
    assert_eq!(report.cases.len(), 4);
    assert!(
        report
            .cases
            .iter()
            .all(|case| case.status == DiffStatus::Matched)
    );
    left.shutdown().await;
    right.shutdown().await;
}

#[tokio::test]
async fn mutated_atomic_observation_fails_with_a_field_difference() {
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, Response};
    let mut profile = Profile::new(WireAuth::AuthV2 {
        audience: "http://placeholder.invalid".into(),
        repository: "default".into(),
        seed: [0x45; 32],
    });
    profile.atomic_advance = true;
    profile.derive_features();
    let left = ControlledHost::start(profile.clone()).await.unwrap();
    let right = ControlledHost::start(profile).await.unwrap();
    let upstream = right.base_url().to_owned();
    let router = axum::Router::new().fallback(move |request: Request<Body>| {
        let upstream = upstream.clone();
        async move {
            let (parts, body) = request.into_parts();
            let bytes = to_bytes(body, 1024 * 1024).await.unwrap();
            let mut request =
                reqwest::Client::new().request(parts.method, format!("{upstream}{}", parts.uri));
            for (name, value) in &parts.headers {
                if name != "host" && name != "content-length" {
                    request = request.header(name, value);
                }
            }
            let response = request.body(bytes).send().await.unwrap();
            let status = response.status();
            let content_type = response.headers().get("content-type").cloned();
            let mut bytes = response.bytes().await.unwrap().to_vec();
            if parts.uri.path() == mkit_server_conformance::control::CONTROL_PATH {
                let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                if let Some(reservations) = value
                    .get_mut("observation")
                    .and_then(|observation| observation.get_mut("reservations"))
                    .and_then(serde_json::Value::as_array_mut)
                {
                    for reservation in reservations {
                        if reservation["state"] == "committed" {
                            reservation["terminal_count"] = 2.into();
                        }
                    }
                }
                bytes = serde_json::to_vec(&value).unwrap();
            }
            let mut response = Response::builder().status(status);
            if let Some(content_type) = content_type {
                response = response.header("content-type", content_type);
            }
            response.body(Body::from(bytes)).unwrap()
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_url: url::Url = format!("http://{}", listener.local_addr().unwrap())
        .parse()
        .unwrap();
    let proxy = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    let target = |host: &ControlledHost| DiffTarget {
        wire: WireTarget {
            base_url: host.base_url().parse().unwrap(),
            profile: host.profile().clone(),
        },
        control_url: host.base_url().parse().unwrap(),
    };
    let mut candidate = target(&right);
    candidate.control_url = proxy_url;
    let report = run(&target(&left), &candidate).await.unwrap();
    assert!(report.failed());
    assert!(
        report.cases[0]
            .differences
            .iter()
            .any(|field| field.path == "/after/reservations/0/terminal_count")
    );
    proxy.abort();
    left.shutdown().await;
    right.shutdown().await;
}

#[tokio::test]
async fn deterministic_decisions_include_declared_quota_charges() {
    let mut profile = Profile::new(WireAuth::AuthV2 {
        audience: "http://placeholder.invalid".into(),
        repository: "default".into(),
        seed: [0x45; 32],
    });
    profile.quota = Some(QuotaLimits {
        max_ops: 32,
        max_bytes: 1_048_576,
        window_ms: 3_600_000,
    });
    profile.atomic_advance = true;
    profile.derive_features();
    let left = ControlledHost::start(profile.clone()).await.unwrap();
    let right = ControlledHost::start(profile).await.unwrap();
    let target = |host: &ControlledHost| DiffTarget {
        wire: WireTarget {
            base_url: host.base_url().parse().unwrap(),
            profile: host.profile().clone(),
        },
        control_url: host.base_url().parse().unwrap(),
    };
    let report = run(&target(&left), &target(&right)).await.unwrap();
    assert!(
        !report.failed(),
        "{}",
        serde_json::to_string_pretty(&report).unwrap()
    );
    assert!(
        report
            .cases
            .iter()
            .all(|case| case.status == DiffStatus::Matched)
    );
    left.shutdown().await;
    right.shutdown().await;
}

#[tokio::test]
async fn paired_cas_detects_a_matching_side_write_on_conflict() {
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, Response};
    use buffa::Message as _;
    use mkit_transport_connect::generated::AdvanceRefsRequest;
    use std::sync::{Arc, Mutex};
    let mut profile = Profile::new(WireAuth::AuthV2 {
        audience: "http://placeholder.invalid".into(),
        repository: "default".into(),
        seed: [0x45; 32],
    });
    profile.atomic_advance = true;
    profile.derive_features();
    let left = ControlledHost::start(profile.clone()).await.unwrap();
    let right = ControlledHost::start(profile).await.unwrap();
    let upstream = right.base_url().to_owned();
    let proposed = Arc::new(Mutex::new(None::<(String, String)>));
    let router = axum::Router::new().fallback(move |request: Request<Body>| {
        let upstream = upstream.clone();
        let proposed = proposed.clone();
        async move {
            let (parts, body) = request.into_parts();
            let bytes = to_bytes(body, 1024 * 1024).await.unwrap();
            if parts.uri.path() == "/mkit.transport.v1.TransportService/AdvanceRefs" {
                let request = AdvanceRefsRequest::decode_from_slice(&bytes).unwrap();
                // Simulate a server applying the side whose CAS matches even
                // though the paired operation reports a conflict. Retain the
                // proposal from the first stale-pair request across its replay.
                if request.ticket_ids.is_empty() {
                    let mut proposed = proposed.lock().unwrap();
                    if proposed.is_none() {
                        let field = if request.packmap_expected_id.as_deref() == Some(&[0x19; 32]) {
                            "head"
                        } else {
                            "packmap"
                        };
                        let id = if field == "head" {
                            request.head_new_id
                        } else {
                            request.packmap_new_id
                        }
                        .unwrap();
                        *proposed = Some((field.into(), mkit_core::hash::to_hex_bytes(&id)));
                    }
                }
            }
            let mut request =
                reqwest::Client::new().request(parts.method, format!("{upstream}{}", parts.uri));
            for (name, value) in &parts.headers {
                if name != "host" && name != "content-length" {
                    request = request.header(name, value);
                }
            }
            let response = request.body(bytes).send().await.unwrap();
            let status = response.status();
            let content_type = response.headers().get("content-type").cloned();
            let mut bytes = response.bytes().await.unwrap().to_vec();
            if parts.uri.path() == mkit_server_conformance::control::CONTROL_PATH {
                let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                if value["observation"].is_object()
                    && let Some((field, id)) = proposed.lock().unwrap().as_ref()
                {
                    value["observation"][field] = id.clone().into();
                }
                bytes = serde_json::to_vec(&value).unwrap();
            }
            let mut response = Response::builder().status(status);
            if let Some(content_type) = content_type {
                response = response.header("content-type", content_type);
            }
            response.body(Body::from(bytes)).unwrap()
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_url: url::Url = format!("http://{}", listener.local_addr().unwrap())
        .parse()
        .unwrap();
    let proxy = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    let target = |host: &ControlledHost| DiffTarget {
        wire: WireTarget {
            base_url: host.base_url().parse().unwrap(),
            profile: host.profile().clone(),
        },
        control_url: host.base_url().parse().unwrap(),
    };
    let mut candidate = target(&right);
    candidate.wire.base_url = proxy_url.clone();
    candidate.control_url = proxy_url;
    let report = run(&target(&left), &candidate).await.unwrap();
    assert!(
        report.failed(),
        "partial paired writes escaped the differential oracle"
    );
    proxy.abort();
    left.shutdown().await;
    right.shutdown().await;
}
