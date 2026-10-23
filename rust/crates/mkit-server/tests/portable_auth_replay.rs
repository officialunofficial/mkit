//! Shared semantic vectors pin the current reference behavior for portable hosts.

use mkit_core::hash::from_hex;
use mkit_core::protocol::AdvanceOutcome;
use mkit_server::{
    BeginUploadResult, Code, ReplayDecision, ReplayRecord, ReplayState, StoredRejection,
    StoredResult, UpdateRefResult, auth_v2, classify,
};
use serde_json::Value;

#[test]
fn shared_classifier_matrix_matches_reference_for_every_saved_result_shape() {
    let cases: Vec<Value> =
        serde_json::from_str(include_str!("../../../tests/golden/replay/classifier.json")).unwrap();
    let results = [
        StoredResult::UpdateRef(UpdateRefResult::Committed),
        StoredResult::UpdateRef(UpdateRefResult::Conflict { current: None }),
        StoredResult::UpdateRef(UpdateRefResult::Conflict {
            current: Some([3; 32]),
        }),
        StoredResult::AdvanceRefs(AdvanceOutcome::Committed),
        StoredResult::AdvanceRefs(AdvanceOutcome::PackmapConflict),
        StoredResult::AdvanceRefs(AdvanceOutcome::HeadConflict),
        StoredResult::BeginUpload(BeginUploadResult::AlreadyPresent),
        StoredResult::BeginUpload(BeginUploadResult::Ticket {
            id: [4; 32],
            part_size: 1,
            expires_at_ms: 1_000,
            token: vec![5, 6, 7],
        }),
        StoredResult::UploadPack,
        StoredResult::RepoVisibility,
        StoredResult::Fork,
    ];
    for case in cases {
        for saved in &results {
            let state = match case["state"].as_str().unwrap() {
                "absent" => None,
                "committed" => Some(ReplayState::Committed(saved.clone())),
                "rejected" => Some(ReplayState::Committed(StoredResult::Rejected(
                    StoredRejection::new(Code::NotFound, "saved refusal").unwrap(),
                ))),
                "resumable" => Some(ReplayState::InFlight { resumable: true }),
                "in_flight" => Some(ReplayState::InFlight { resumable: false }),
                _ => panic!("unknown fixture state"),
            };
            for expires_at_ms in [-1, 0, 1_000, i64::MAX] {
                let record = state.clone().map(|state| ReplayRecord {
                    fingerprint: [7; 32],
                    expires_at_ms,
                    state,
                });
                let fingerprint = if case["same_fingerprint"].as_bool().unwrap() {
                    [7; 32]
                } else {
                    [8; 32]
                };
                let actual = match classify(record.as_ref(), &fingerprint) {
                    ReplayDecision::New => "fresh",
                    ReplayDecision::Return(result) => {
                        let ReplayState::Committed(expected) = &record.as_ref().unwrap().state
                        else {
                            panic!("returned an in-flight result")
                        };
                        assert_eq!(&result, expected);
                        "recorded"
                    }
                    ReplayDecision::Resume => "resume",
                    ReplayDecision::RetryLater => "in_flight",
                    ReplayDecision::FingerprintMismatch => "conflict",
                };
                assert_eq!(actual, case["expected"].as_str().unwrap(), "{case}");
            }
        }
    }
}

#[test]
fn shared_permanent_code_fixture_matches_reference_allowlist() {
    let cases: Vec<Value> =
        serde_json::from_str(include_str!("../../../tests/golden/replay/codes.json")).unwrap();
    let codes = [
        Code::Canceled,
        Code::Unknown,
        Code::InvalidArgument,
        Code::DeadlineExceeded,
        Code::NotFound,
        Code::AlreadyExists,
        Code::PermissionDenied,
        Code::ResourceExhausted,
        Code::FailedPrecondition,
        Code::Aborted,
        Code::OutOfRange,
        Code::Unimplemented,
        Code::Internal,
        Code::Unavailable,
        Code::DataLoss,
        Code::Unauthenticated,
    ];
    assert_eq!(cases.len(), codes.len() + 1);
    for case in cases {
        let name = case["code"].as_str().unwrap();
        let expected = case["storable"].as_bool().unwrap();
        if let Some(code) = codes.iter().find(|code| code.as_str() == name) {
            assert_eq!(StoredRejection::is_storable(*code), expected, "{name}");
            assert_eq!(
                StoredRejection::new(*code, "saved refusal").is_some(),
                expected,
                "{name}"
            );
        } else {
            assert_eq!(name, "future_code");
            assert!(!expected);
        }
    }
}

fn fixture_headers(fixture: &Value) -> mkit_core::write_auth::Headers {
    let text = |name: &str| fixture[name].as_str().map(str::to_owned);
    mkit_core::write_auth::Headers {
        version: Some("2".into()),
        audience: text("audience"),
        repository: text("repository"),
        public_key: text("public_key"),
        signature: text("signature"),
        digest: text("body_digest"),
        commitment: text("commitment"),
        created_at: Some(
            fixture["created_at"]
                .as_i64()
                .expect("fixture creation time")
                .to_string(),
        ),
        expires_at: Some(
            fixture["expires_at"]
                .as_i64()
                .expect("fixture expiry time")
                .to_string(),
        ),
        idempotency_key: text("nonce"),
    }
}

#[test]
fn shared_auth_vectors_match_reference_signer_fingerprint_and_time() {
    let mut fixtures = vec![
        serde_json::from_str::<Value>(include_str!("../../../tests/golden/auth-v2/unary.json"))
            .unwrap(),
    ];
    fixtures.extend(
        serde_json::from_str::<Vec<Value>>(include_str!("../../../tests/golden/auth-v2/read.json"))
            .unwrap(),
    );
    fixtures.push(
        serde_json::from_str(include_str!("../../../tests/golden/auth-v2/part.json")).unwrap(),
    );
    for fixture in fixtures {
        let field = |name: &str| fixture[name].as_str().unwrap();
        let config = auth_v2::AuthV2Config::new(field("audience"), field("repository")).unwrap();
        let headers = fixture_headers(&fixture);
        let created = fixture["created_at"].as_i64().unwrap();
        let expires = fixture["expires_at"].as_i64().unwrap();
        let body = fixture["body"].as_str().map_or_else(
            || {
                fixture["body_hex"].as_str().map_or_else(Vec::new, |hex| {
                    hex.as_bytes()
                        .as_chunks::<2>()
                        .0
                        .iter()
                        .map(|pair| {
                            u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap()
                        })
                        .collect()
                })
            },
            |text| text.as_bytes().to_vec(),
        );
        for (now, accepted) in [
            (created - 30_001, false),
            (created - 30_000, true),
            (created, true),
            (expires, true),
            (expires + 1, false),
        ] {
            let result = if field("commitment").starts_with("part:") {
                auth_v2::verify_stream(&config, field("procedure"), now, &headers)
            } else {
                auth_v2::verify_unary(&config, field("procedure"), &body, now, &headers)
            };
            assert_eq!(result.is_ok(), accepted, "{} at {now}", field("procedure"));
            if let Ok(auth) = result {
                assert_eq!(auth.signer, from_hex(field("public_key")).unwrap());
                assert_eq!(auth.fingerprint, from_hex(field("signing_digest")).unwrap());
                assert_eq!(auth.created_at_ms, created);
                assert_eq!(auth.expires_at_ms, expires);
            }
        }
    }
}
