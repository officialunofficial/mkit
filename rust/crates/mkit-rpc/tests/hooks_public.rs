//! Only public items are used, as in an external hook implementer's crate.
#![cfg(feature = "hooks")]
use buffa::Message;
use mkit_rpc::hooks::__buffa::oneof::{
    admit_response::Decision, authorize_response::Result as AuthResult, inspect_response::Verdict,
};
use mkit_rpc::hooks::*;
use std::{fs, path::Path};
fn fixture(name: &str) -> Vec<u8> {
    fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/golden/server-hooks")
            .join(name),
    )
    .unwrap()
}
fn decode<M: Message + serde::de::DeserializeOwned + serde::Serialize + PartialEq>(name: &str) {
    let bytes = fixture(name);
    let msg: M = serde_json::from_slice(&bytes).unwrap();
    let round = M::decode(&mut msg.encode_to_vec().as_slice()).unwrap();
    assert!(msg == round, "protobuf round trip: {name}");
    let json: M = serde_json::from_slice(&serde_json::to_vec(&msg).unwrap()).unwrap();
    assert!(msg == json, "JSON round trip: {name}");
    assert_eq!(
        serde_json::to_value(&round).unwrap(),
        serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
        "all golden fields survive protobuf decoding: {name}"
    );
}
#[test]
fn decode_every_golden_request() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/golden/server-hooks");
    let mut count = 0;
    for entry in fs::read_dir(dir).unwrap() {
        let name = entry.unwrap().file_name().into_string().unwrap();
        if !name.ends_with(".request.json") {
            continue;
        }
        match name.split('-').next().unwrap().split('.').next().unwrap() {
            "admit" => decode::<AdmitRequest>(&name),
            "authorize" => decode::<AuthorizeRequest>(&name),
            "inspect" => decode::<InspectRequest>(&name),
            "outcome" => decode::<OutcomeRequest>(&name),
            "event" => decode::<EventRequest>(&name),
            "cache" => decode::<CachePurgeRequest>(&name),
            _ => panic!("uncovered request: {name}"),
        }
        count += 1;
    }
    // SPEC-SERVER §20 includes visibility and repository-storage outcomes.
    assert_eq!(count, 18);
}
fn header(name: &str, value: &str) -> Header {
    Header {
        name: Some(name.into()),
        value: Some(value.into()),
        ..Default::default()
    }
}
fn deny(message: &str) -> Deny {
    Deny {
        code: Some("permission_denied".into()),
        message: Some(message.into()),
        ..Default::default()
    }
}
fn response(name: &str, msg: impl serde::Serialize) {
    let expected: serde_json::Value = serde_json::from_slice(&fixture(name)).unwrap();
    assert_eq!(
        serde_json::to_value(msg).unwrap(),
        expected,
        "response: {name}"
    );
}
#[test]
fn build_every_golden_response() {
    for (name, result) in [
        (
            "authorize-allow",
            AuthResult::Allow(AuthorizeAllow::default().into()),
        ),
        (
            "authorize-writer-view",
            AuthResult::Allow(
                AuthorizeAllow {
                    writer_view: Some(true),
                    ..Default::default()
                }
                .into(),
            ),
        ),
        (
            "authorize-deny",
            AuthResult::Deny(deny("This repository is read-only.").into()),
        ),
    ] {
        response(
            &format!("{name}.response.json"),
            AuthorizeResponse {
                result: Some(result),
                ..Default::default()
            },
        );
    }
    for (name, allow) in [
        (
            "admit-allow",
            AdmitAllow {
                reservation_id: Some("demo:upload-20260926-001".into()),
                response_headers: vec![
                    header("Payment-Receipt", "fake-example-receipt-not-valid"),
                    header("PAYMENT-RESPONSE", "fake-example-response-not-valid"),
                ],
                ..Default::default()
            },
        ),
        (
            "admit-allow-external-ref",
            AdmitAllow {
                reservation_id: Some("demo:upload-20260928-001".into()),
                external_ref: Some("contract:order-17".into()),
                ..Default::default()
            },
        ),
    ] {
        response(
            &format!("{name}.response.json"),
            AdmitResponse {
                decision: Some(Decision::Allow(allow.into())),
                ..Default::default()
            },
        );
    }
    response(
        "admit-deny.response.json",
        AdmitResponse {
            decision: Some(Decision::Deny(deny("Upload budget exceeded.").into())),
            ..Default::default()
        },
    );
    response("admit-challenge.response.json", AdmitResponse {decision: Some(Decision::Challenge(AdmitChallenge {
        challenges: vec![Challenge { scheme: Some("mpp".into()), value: Some("fake-example-challenge-not-valid".into()), ..Default::default()}],
        description: Some("Example upload payment required.".into()),
        response_headers: vec![header("WWW-Authenticate", r#"Payment id="fake-example-not-valid", method="tempo", intent="charge", request="fake-example-request-not-valid""#)],
        ..Default::default()
    }.into())), ..Default::default()});
    for (name, verdict, flagged_objects, takedown_reason) in [
        (
            "inspect-pass",
            Verdict::Pass(InspectPass::default().into()),
            vec![],
            None,
        ),
        (
            "inspect-defer",
            Verdict::Defer(
                InspectDefer {
                    retry_after_ms: Some(5000),
                    ..Default::default()
                }
                .into(),
            ),
            vec![],
            None,
        ),
        (
            "inspect-quarantine",
            Verdict::Quarantine(
                InspectQuarantine {
                    reason: Some("manual review required".into()),
                    ..Default::default()
                }
                .into(),
            ),
            vec![vec![0x11; 32]],
            None,
        ),
        (
            "inspect-reject-flagged",
            Verdict::Reject(deny("content policy hit").into()),
            vec![vec![0x22; 32]],
            Some("policy".into()),
        ),
    ] {
        response(
            &format!("{name}.response.json"),
            InspectResponse {
                verdict: Some(verdict),
                flagged_objects,
                takedown_reason,
                ..Default::default()
            },
        );
    }
    response("outcome.response.json", OutcomeResponse::default());
    response("event.response.json", EventResponse::default());
    response("cache-purge.response.json", CachePurgeResponse::default());
}
#[test]
fn verify_every_signature_vector_and_raw_body_binding() {
    let json: serde_json::Value = serde_json::from_slice(&fixture("signature.json")).unwrap();
    for vector in json["vectors"].as_array().unwrap() {
        let s = |name: &str| vector[name].as_str().unwrap();
        let created: i64 = s("created_at_ms").parse().unwrap();
        let verifier = HookVerifier::new(
            s("audience"),
            vec![VerifierKey::new(
                s("key_id"),
                hex::decode(s("public_key")).unwrap().try_into().unwrap(),
            )],
            move || created,
        )
        .with_replay_protection();
        let headers: Vec<_> = vector["headers"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str().unwrap()))
            .collect();
        let body = fixture(s("body_file"));
        assert!(verifier.verify(s("procedure"), &headers, &body).is_ok());
        assert_eq!(
            verifier.verify(s("procedure"), &headers, &body),
            Err(VerifyError::Replay)
        );
        let mut changed = body.clone();
        changed.push(b' ');
        assert_eq!(
            verifier.verify(s("procedure"), &headers, &changed),
            Err(VerifyError::Digest)
        );
        let seed: [u8; 32] = hex::decode(s("test_seed_hex")).unwrap().try_into().unwrap();
        let signer = HookSigner::new(s("key_id"), seed.into())
            .unwrap()
            .with_validity(std::time::Duration::from_millis(300_000))
            .unwrap();
        let nonce = hex::decode(s("nonce")).unwrap().try_into().unwrap();
        for (name, value) in signer
            .headers(s("audience"), s("procedure"), &body, created, &nonce)
            .unwrap()
        {
            assert_eq!(value, vector["headers"][name]);
        }
    }
}
