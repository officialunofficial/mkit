use super::*;
fn logic() -> Logic {
    Logic {
        secret: [17; 32],
        state: Mutex::default(),
        clock: Arc::new(|| 1_000_000),
    }
}
fn req() -> AdmitRequest {
    AdmitRequest {
        operation: proto::Operation {
            audience: Some("https://vcs.test".into()),
            repository: Some("default".into()),
            procedure: Some("/BeginUpload".into()),
            principal: proto::Principal {
                kind: Some(proto::__buffa::oneof::principal::Kind::Signer(
                    proto::Signer {
                        ed25519_public_key: Some(vec![8; 32]),
                        ..Default::default()
                    }
                    .into(),
                )),
                ..Default::default()
            }
            .into(),
            ..Default::default()
        }
        .into(),
        declared_bytes: Some(100),
        pack_id: Some(vec![9; 32]),
        ..Default::default()
    }
}
fn credential(logic: &Logic, req: &mut AdmitRequest) -> String {
    let Some(Decision::Challenge(c)) = logic.challenge(req, false, false).decision else {
        panic!()
    };
    let value = credential_for(c.challenges[0].value.as_deref().unwrap()).unwrap();
    req.credential_headers = vec![header("Authorization", value.clone())];
    value
}
fn result(reply: &Reply) -> AdmitResponse {
    serde_json::from_slice(&reply.body).unwrap()
}
#[test]
fn every_fingerprint_field_is_bound() {
    let logic = logic();
    let mut request = req();
    credential(&logic, &mut request);
    for field in 0..6 {
        let mut changed = request.clone();
        match field {
            0 => {
                changed.operation.get_or_insert_default().audience =
                    Some("https://other.test".into());
            }
            1 => changed.operation.get_or_insert_default().repository = Some("other".into()),
            2 => changed.operation.get_or_insert_default().procedure = Some("/UpdateRef".into()),
            3 => {
                changed.operation.get_or_insert_default().principal =
                    proto::Principal::default().into();
            }
            4 => changed.pack_id = Some(vec![10; 32]),
            _ => changed.declared_bytes = Some(101),
        }
        assert!(matches!(
            result(&logic.admit(changed, &mut State::default())).decision,
            Some(Decision::Deny(_))
        ));
    }
    let mut state = State::default();
    assert!(matches!(
        result(&logic.admit(request.clone(), &mut state)).decision,
        Some(Decision::Allow(_))
    ));
    assert!(matches!(
        result(&logic.admit(request, &mut state)).decision,
        Some(Decision::Deny(_))
    ));
}
#[test]
fn expiry_malformed_and_comma_credentials_are_refused() {
    let mut logic = logic();
    let mut request = req();
    let cred = credential(&logic, &mut request);
    logic.clock = Arc::new(|| 1_061_000);
    assert!(matches!(
        result(&logic.admit(request.clone(), &mut State::default())).decision,
        Some(Decision::Deny(_))
    ));
    for value in [
        "Payment !".to_owned(),
        format!("{cred}, other"),
        "Bearer secret".to_owned(),
    ] {
        request.credential_headers = vec![header("Authorization", value)];
        assert!(matches!(
            result(&logic.admit(request.clone(), &mut State::default())).decision,
            Some(Decision::Deny(_))
        ));
    }
}
#[test]
fn bearer_challenge_and_ledger_terminal_arbiter() {
    let logic = logic();
    let Some(Decision::Challenge(c)) = logic.challenge(&req(), true, false).decision else {
        panic!()
    };
    assert!(
        c.challenges[0]
            .value
            .as_deref()
            .unwrap()
            .contains("header=\"Payment-Authorization\"")
    );
    let outcome = proto::Outcome {
        reservation_id: Some("stub:1".into()),
        kind: Some(Kind::Committed(proto::Committed::default().into())),
        ..Default::default()
    };
    let request = OutcomeRequest {
        outcome: outcome.clone().into(),
        ..Default::default()
    };
    let mut state = State::default();
    assert_eq!(Logic::outcome(request.clone(), &mut state).status, 200);
    assert_eq!(Logic::outcome(request, &mut state).status, 200);
    let changed = proto::Outcome {
        kind: Some(Kind::Expired(proto::Expired::default().into())),
        ..outcome
    };
    assert_eq!(
        Logic::outcome(
            OutcomeRequest {
                outcome: changed.into(),
                ..Default::default()
            },
            &mut state
        )
        .status,
        409
    );
    assert_eq!(state.outcomes["stub:1"].acknowledged, 2);
}
#[test]
fn control_plane_cannot_bind_non_loopback() {
    assert!(std::panic::catch_unwind(|| MppStub::start_on("0.0.0.0:0", vec![], true)).is_err());
}
#[tokio::test]
async fn unsigned_only_when_explicitly_configured_and_control_is_redacted() {
    use crate::wire::client::{Client, UNARY_JSON};
    for unsigned in [false, true] {
        let stub = MppStub::start_on("127.0.0.1:0", vec![], unsigned);
        let client = Client::new(&stub.origin().parse().unwrap()).unwrap();
        let body = serde_json::to_vec(&req()).unwrap();
        let reply = client
            .post(&format!("{SERVICE}/Admit"), UNARY_JSON, &[], body)
            .await
            .unwrap();
        assert_eq!(reply.status, if unsigned { 200 } else { 401 });
        for path in ["/__stub/calls", "/__stub/outcomes"] {
            let reply = client.get(path).await.unwrap();
            assert_eq!(reply.status, 200);
            assert!(!String::from_utf8_lossy(&reply.body).contains("Payment "));
        }
    }
}
