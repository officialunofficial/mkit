//! Unit tests for the remote-hook adapter: the golden vectors, mapping,
//! failure classification, redaction and the timeout seam. The pipeline-level
//! "fails closed and writes nothing" matrix lives in
//! `pipeline/tests/remote_hooks.rs`, which reuses [`MockChannel`].

use core::future::Future;
use core::time::Duration;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::Path;
use std::sync::{Arc, Mutex};

use ed25519_dalek::{Signature, SigningKey};
use futures_executor::block_on;
use mkit_core::hash::{from_hex, hash, to_hex};
use mkit_core::protocol::PackKey;
use mkit_core::refs::RefWriteCondition;
use serde::de::DeserializeOwned;
use zeroize::Zeroizing;

use super::proto::v1 as pb;
use super::*;
use crate::error::{Code, Redacted, ServerError};
use crate::op::{AuthzFacts, Commitment, GrantRef, OpKind, Operation, RefUpdate, VerifiedAuth};
use crate::pipeline::{
    Admission, AdmissionDecision, AdmissionInput, Authorizer, CredentialHeader, Outcome,
    OutcomeKind, OutcomeSink,
};
use crate::principal::Principal;
use crate::repo::{NamespaceKey, RepoId, RepoName};
use crate::rt::{Clock, ManualClock, ManualSleep};
use crate::store::codec::{AbortReason, OutcomeRef};

pub(crate) const NAMESPACE: &str =
    "ed25519-a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f0";
const SIGNER: [u8; 32] = [
    0xd0, 0x4a, 0xb2, 0x32, 0x74, 0x2b, 0xb4, 0xab, 0x3a, 0x13, 0x68, 0xbd, 0x46, 0x15, 0xe4, 0xe6,
    0xd0, 0x22, 0x4a, 0xb7, 0x1a, 0x01, 0x6b, 0xaf, 0x85, 0x20, 0xa3, 0x32, 0xc9, 0x77, 0x87, 0x37,
];
const HOOK_ORIGIN: &str = "https://hooks.example.test";
const SERVER_ORIGIN: &str = "https://vcs.example.test";
const CREDENTIAL: &str = "Payment fake-example-credential-not-valid";
const T: i64 = 1_790_424_000_000;

fn golden(name: &str) -> Vec<u8> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/golden/server-hooks");
    std::fs::read(dir.join(name)).unwrap()
}

fn decode<M: DeserializeOwned>(name: &str) -> M {
    serde_json::from_slice(&golden(name)).unwrap()
}

/// What a scripted channel does with its next call.
#[derive(Clone)]
pub(crate) enum Step {
    Reply(u16, Option<&'static str>, Vec<u8>),
    Fail(ChannelError),
    Hang,
}

impl Step {
    pub(crate) fn json(body: &str) -> Self {
        Self::Reply(200, Some("application/json"), body.as_bytes().to_vec())
    }
}

/// One request a channel received.
pub(crate) struct Seen {
    pub(crate) procedure: &'static str,
    pub(crate) headers: Vec<(&'static str, String)>,
    pub(crate) body: Vec<u8>,
    pub(crate) timeout: Duration,
    pub(crate) max_response_bytes: usize,
}

/// An in-memory channel that records requests and replays one scripted step.
pub(crate) struct MockChannel {
    audience: Option<&'static str>,
    isolated: bool,
    step: Mutex<Step>,
    pub(crate) seen: Mutex<Vec<Seen>>,
}

impl MockChannel {
    pub(crate) fn new(step: Step) -> Self {
        Self {
            audience: Some(HOOK_ORIGIN),
            isolated: false,
            step: Mutex::new(step),
            seen: Mutex::default(),
        }
    }
}

impl HookChannel for MockChannel {
    fn audience(&self) -> Option<&str> {
        self.audience
    }

    fn isolated(&self) -> bool {
        self.isolated
    }

    fn call(
        &self,
        request: HookRequest,
    ) -> impl Future<Output = Result<HookResponse, ChannelError>> + crate::rt::MaybeSend {
        self.seen.lock().unwrap().push(Seen {
            procedure: request.procedure,
            headers: request.headers.clone(),
            body: request.body.to_vec(),
            timeout: request.timeout,
            max_response_bytes: request.max_response_bytes,
        });
        let step = self.step.lock().unwrap().clone();
        async move {
            match step {
                Step::Reply(status, content_type, body) => Ok(HookResponse::new(
                    status,
                    content_type.map(str::to_owned),
                    body,
                )),
                Step::Fail(err) => Err(err),
                Step::Hang => core::future::pending().await,
            }
        }
    }
}

const SEED: [u8; 32] = [0x53; 32];

pub(crate) fn signer() -> HookSigner {
    HookSigner::new("test-hook-2026-09", Zeroizing::new(SEED)).unwrap()
}

/// A signed client over `channel`, its clock at the golden time and a sleeper
/// that never fires unless `sleep` says so.
pub(crate) fn client(channel: MockChannel, sleep: ManualSleep) -> Arc<HookClient<MockChannel>> {
    client_for(channel, sleep, SERVER_ORIGIN)
}

/// [`client`] for a server whose own origin is `origin`.
pub(crate) fn client_for(
    channel: MockChannel,
    sleep: ManualSleep,
    origin: &str,
) -> Arc<HookClient<MockChannel>> {
    let clock: Arc<dyn Clock> = Arc::new(ManualClock::new(T));
    Arc::new(HookClient::new(channel, origin, Some(signer()), clock, Arc::new(sleep)).unwrap())
}

pub(crate) fn channel_of(client: &HookClient<MockChannel>) -> &MockChannel {
    client.channel()
}

fn repo() -> RepoId {
    RepoId {
        namespace: NamespaceKey::from_stored(NAMESPACE.to_owned()),
        name: RepoName::new("payments-demo").unwrap(),
    }
}

fn granted_op(kind: OpKind, nonce: &str) -> Operation {
    let auth = VerifiedAuth {
        signer: SIGNER,
        replay_scope: [0; 32],
        fingerprint: [0; 32],
        nonce: nonce.repeat(32),
        commitment: Commitment::Body([0; 32]),
        expires_at_ms: 0,
    };
    let mut op = Operation::new(
        repo(),
        Principal::Signer { ed25519: SIGNER },
        Some(auth),
        kind,
    );
    op.authz = AuthzFacts {
        grant: Some(GrantRef {
            id: [0x44; 32],
            epoch: 7,
            presence_requirement: None,
        }),
        owner: false,
        ..Default::default()
    };
    op
}

fn update_op() -> Operation {
    granted_op(
        OpKind::UpdateRef(RefUpdate {
            name: "refs/heads/main".into(),
            condition: RefWriteCondition::Match([0x22; 32]),
            new: Some([0x33; 32]),
        }),
        "a2",
    )
}

fn begin_op() -> Operation {
    granted_op(
        OpKind::BeginUpload {
            ref_name: "refs/heads/main".into(),
            key: PackKey([0x55; 32]),
            bytes: 16_384,
        },
        "a1",
    )
}

fn admit_input<'a>(op: &'a Operation, credentials: &'a [CredentialHeader]) -> AdmissionInput<'a> {
    let mut input = AdmissionInput::new(op);
    input.declared_bytes = 16_384;
    input.pack_id = Some(PackKey([0x55; 32]));
    input.new_to_repo_bytes = Some(8_192);
    input.credential_headers = credentials;
    input
}

fn credentials() -> Vec<CredentialHeader> {
    vec![CredentialHeader::new(
        "Payment-Authorization",
        Redacted::new(CREDENTIAL),
    )]
}

fn value_of<M: serde::Serialize>(message: &M) -> serde_json::Value {
    serde_json::to_value(message).unwrap()
}

fn golden_value(name: &str) -> serde_json::Value {
    serde_json::from_slice(&golden(name)).unwrap()
}

fn outcome(reservation: &str, kind: OutcomeKind) -> Outcome {
    Outcome {
        reservation_id: reservation.to_owned(),
        audience: SERVER_ORIGIN.to_owned(),
        repository: format!("{NAMESPACE}/payments-demo"),
        occurred_unix_ms: 1_790_424_001_000,
        kind,
    }
}

fn unavailable(err: &ServerError) -> bool {
    err.code() == Code::Unavailable
}

// ---- signing ---------------------------------------------------------------

// The vectors go through `HookSigner::headers` directly, not a client call:
// their bodies are the pretty-printed golden text, which the client (compact
// JSON) never sends. `a_call_is_signed_over_its_exact_body_with_a_fresh_nonce_each_attempt`
// and its neighbours cover the requests the client really sends.
#[test]
fn every_signature_vector_reproduces_byte_for_byte() {
    let file: serde_json::Value = serde_json::from_slice(&golden("signature.json")).unwrap();
    let vectors = file["vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), 4);
    for vector in vectors {
        let text = |name: &str| vector[name].as_str().unwrap();
        let seed = from_hex(text("test_seed_hex")).unwrap();
        let signer = HookSigner::new(text("key_id"), Zeroizing::new(seed))
            .unwrap()
            .with_validity(MAX_VALIDITY)
            .unwrap();
        let mut nonce = [0u8; 32];
        for (byte, pair) in nonce.iter_mut().zip(text("nonce").as_bytes().chunks(2)) {
            *byte = u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap();
        }
        let headers = signer
            .headers(
                text("audience"),
                text("procedure"),
                text("body_utf8").as_bytes(),
                text("created_at_ms").parse().unwrap(),
                &nonce,
            )
            .unwrap();
        let got: BTreeMap<_, _> = headers
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v))
            .collect();
        let want: BTreeMap<_, _> = vector["headers"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_owned()))
            .collect();
        assert_eq!(got, want, "{}", text("procedure"));
        assert_eq!(got.len(), 8);
    }
}

#[test]
fn signer_refuses_a_bad_key_id_validity_and_clock() {
    let seed = || Zeroizing::new(SEED);
    for bad in ["", "has space", "new\nline", "ünï", &"k".repeat(65)] {
        assert_eq!(
            HookSigner::new(bad, seed()).unwrap_err(),
            SignerError::KeyId
        );
    }
    assert!(HookSigner::new("k".repeat(64), seed()).is_ok());
    assert!(HookSigner::new("A.b_c-9", seed()).is_ok());
    let ok = || HookSigner::new("k", seed()).unwrap();
    assert!(ok().with_validity(Duration::ZERO).is_err());
    assert_eq!(
        ok().with_validity(Duration::from_micros(500)).unwrap_err(),
        SignerError::Validity
    );
    assert!(
        ok().with_validity(MAX_VALIDITY + Duration::from_millis(1))
            .is_err()
    );
    assert!(ok().with_validity(Duration::from_millis(1)).is_ok());
    assert_eq!(
        ok().headers("https://a.test", "/p", b"", -1, &[0; 32])
            .unwrap_err(),
        SignerError::Clock
    );
    assert!(!format!("{:?}", ok()).contains("53"));
}

/// An independent §7.1 verifier over what the channel received.
fn verify(seen: &Seen) {
    let header = |name: &str| {
        let mut all = seen.headers.iter().filter(|(n, _)| *n == name);
        let value = all
            .next()
            .unwrap_or_else(|| panic!("missing {name}"))
            .1
            .clone();
        assert!(all.next().is_none(), "duplicate {name}");
        value
    };
    assert_eq!(header("X-Mkit-Hook-Version"), "1");
    assert_eq!(header("X-Mkit-Hook-Audience"), HOOK_ORIGIN);
    let digest = format!("body:{}", to_hex(&hash(&seen.body)));
    assert_eq!(header("X-Mkit-Hook-Digest"), digest);
    let (created, expires): (i64, i64) = (
        header("X-Mkit-Hook-Created-At").parse().unwrap(),
        header("X-Mkit-Hook-Expires-At").parse().unwrap(),
    );
    assert_eq!(created, T);
    assert!((1..=300_000).contains(&(expires - created)));
    let nonce = header("X-Mkit-Hook-Nonce");
    assert!(
        nonce.len() == 64
            && nonce
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    );
    let canonical = [
        "mkit-hook:v1",
        &header("X-Mkit-Hook-Key-Id"),
        HOOK_ORIGIN,
        seen.procedure,
        &digest,
        &created.to_string(),
        &expires.to_string(),
        &nonce,
    ]
    .join("\n");
    let signature = header("X-Mkit-Hook-Signature");
    assert_eq!(signature.len(), 128);
    let mut bytes = [0u8; 64];
    for (byte, pair) in bytes.iter_mut().zip(signature.as_bytes().chunks(2)) {
        *byte = u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap();
    }
    SigningKey::from_bytes(&SEED)
        .verifying_key()
        .verify_strict(&hash(canonical.as_bytes()), &Signature::from_bytes(&bytes))
        .unwrap();
    assert!(
        seen.headers
            .iter()
            .any(|(n, v)| *n == "Content-Type" && v == "application/json")
    );
    assert!(
        seen.headers
            .iter()
            .any(|(n, v)| *n == "Connect-Protocol-Version" && v == "1")
    );
}

#[test]
fn a_call_is_signed_over_its_exact_body_with_a_fresh_nonce_each_attempt() {
    let client = client(
        MockChannel::new(Step::json(r#"{"allow":{}}"#)),
        ManualSleep::new(),
    );
    let authorizer = RemoteAuthorizer::new(client.clone());
    let op = update_op();
    for _ in 0..2 {
        block_on(authorizer.authorize(&op)).unwrap();
    }
    let seen = channel_of(&client).seen.lock().unwrap();
    assert_eq!(seen.len(), 2);
    for request in seen.iter() {
        verify(request);
        assert_eq!(
            request.procedure,
            "/mkit.server.hooks.v1.HooksService/Authorize"
        );
        assert_eq!(request.timeout, DEFAULT_TIMEOUT);
        assert_eq!(request.max_response_bytes, 65_536);
    }
    let nonce = |i: usize| {
        seen[i]
            .headers
            .iter()
            .find(|(n, _)| *n == "X-Mkit-Hook-Nonce")
            .unwrap()
            .1
            .clone()
    };
    assert_ne!(nonce(0), nonce(1));
}

#[test]
fn an_unsigned_hook_is_refused_unless_the_channel_is_isolated() {
    let clock: Arc<dyn Clock> = Arc::new(ManualClock::new(T));
    let sleep = || Arc::new(ManualSleep::new());
    let plain = MockChannel::new(Step::Hang);
    let err = HookClient::new(plain, SERVER_ORIGIN, None, clock.clone(), sleep()).unwrap_err();
    assert_eq!(err, HookConfigError::SignerRequired);

    let mut binding = MockChannel::new(Step::json(r#"{"allow":{}}"#));
    binding.isolated = true;
    binding.audience = None;
    let unsigned =
        Arc::new(HookClient::new(binding, SERVER_ORIGIN, None, clock.clone(), sleep()).unwrap());
    block_on(RemoteAuthorizer::new(unsigned.clone()).authorize(&update_op())).unwrap();
    let seen = channel_of(&unsigned).seen.lock().unwrap();
    assert!(
        seen[0]
            .headers
            .iter()
            .all(|(n, _)| !n.starts_with("X-Mkit-Hook-"))
    );

    let mut named_binding = MockChannel::new(Step::Hang);
    named_binding.isolated = true;
    let err =
        HookClient::new(named_binding, SERVER_ORIGIN, None, clock.clone(), sleep()).unwrap_err();
    assert_eq!(err, HookConfigError::UnsignedOrigin);

    let mut nameless = MockChannel::new(Step::Hang);
    nameless.audience = None;
    let err = HookClient::new(
        nameless,
        SERVER_ORIGIN,
        Some(signer()),
        clock.clone(),
        sleep(),
    )
    .unwrap_err();
    assert_eq!(err, HookConfigError::ChannelAudience);
    let err = HookClient::new(
        MockChannel::new(Step::Hang),
        "not an origin",
        Some(signer()),
        clock,
        sleep(),
    )
    .unwrap_err();
    assert_eq!(err, HookConfigError::Audience("server"));
}

// ---- requests --------------------------------------------------------------

#[test]
fn encoded_requests_equal_the_golden_requests() {
    let op = update_op();
    let authorize = map::authorize_request(&op, SERVER_ORIGIN);
    assert_eq!(value_of(&authorize), golden_value("authorize.request.json"));
    assert!(authorize == decode::<pb::AuthorizeRequest>("authorize.request.json"));

    let op = begin_op();
    let creds = credentials();
    let admit = map::admit_request(&admit_input(&op, &creds), SERVER_ORIGIN);
    assert_eq!(value_of(&admit), golden_value("admit.request.json"));
    let first = map::admit_request(&admit_input(&op, &[]), SERVER_ORIGIN);
    assert_eq!(
        value_of(&first),
        golden_value("admit-first-attempt.request.json")
    );
    assert!(first == decode::<pb::AdmitRequest>("admit-first-attempt.request.json"));
}

#[test]
fn encoded_outcomes_equal_the_golden_outcomes() {
    let committed = outcome(
        "demo:upload-20260926-001",
        OutcomeKind::Committed {
            bytes_stored: 16_384,
            new_to_repo: 8_192,
            new_to_store: 4_096,
            refs: vec![
                OutcomeRef {
                    name: "refs/heads/main".into(),
                    new: Some([0x33; 32]),
                    deleted: false,
                },
                OutcomeRef {
                    name: "refs/mkit/packmap/main".into(),
                    new: Some([0x66; 32]),
                    deleted: false,
                },
            ],
        },
    );
    let cases = [
        ("outcome-committed.request.json", committed),
        (
            "outcome-aborted.request.json",
            outcome(
                "demo:write-20260926-001",
                OutcomeKind::Aborted {
                    reason: AbortReason::RefConflict,
                    detail: "The admitted UpdateRef lost its compare-and-swap.".into(),
                },
            ),
        ),
        (
            "outcome-abandoned.request.json",
            outcome(
                "demo:write-20260926-002",
                OutcomeKind::Aborted {
                    reason: AbortReason::Abandoned,
                    detail:
                        "Pending reservation had no apply result before authentication expired."
                            .into(),
                },
            ),
        ),
        (
            "outcome-expired.request.json",
            outcome("demo:upload-20260926-002", OutcomeKind::Expired),
        ),
        (
            "outcome-read-served.request.json",
            outcome(
                "demo:read-20260926-001",
                OutcomeKind::ReadServed {
                    object: [0x33; 32],
                    bytes_served: 8_192,
                },
            ),
        ),
    ];
    for (name, outcome) in cases {
        let request = map::outcome_request(&outcome);
        assert_eq!(value_of(&request), golden_value(name), "{name}");
        assert!(request == decode::<pb::OutcomeRequest>(name), "{name}");
    }
}

#[test]
fn a_single_deployment_sends_its_bare_repository_name() {
    let mut op = update_op();
    op.repo.namespace = NamespaceKey::deployment_default();
    let request = map::authorize_request(&op, SERVER_ORIGIN);
    assert_eq!(
        request.operation.repository.as_deref(),
        Some("payments-demo")
    );
}

// ---- responses -------------------------------------------------------------

#[test]
fn golden_responses_decode_to_the_expected_decisions() {
    let op = update_op();
    let facts = map::authorize_answer(decode("authorize-allow.response.json"), &op).unwrap();
    assert_eq!(facts, op.authz);
    let facts = map::authorize_answer(decode("authorize-writer-view.response.json"), &op).unwrap();
    assert_eq!(facts.caller_view, crate::op::CallerView::Writer);
    assert_eq!(
        (facts.owner, &facts.grant),
        (op.authz.owner, &op.authz.grant)
    );
    let err = map::authorize_answer(decode("authorize-deny.response.json"), &op).unwrap_err();
    assert_eq!(
        (err.code(), err.public_message()),
        (Code::PermissionDenied, "This repository is read-only.")
    );

    match map::admit_answer(decode("admit-allow.response.json")).unwrap() {
        AdmissionDecision::Allow {
            charges,
            reservation,
            response_headers,
            external_ref,
        } => {
            assert!(charges.is_empty());
            assert_eq!(reservation.as_deref(), Some("demo:upload-20260926-001"));
            assert_eq!(response_headers.len(), 2);
            assert_eq!(response_headers[0].0, "Payment-Receipt");
            assert_eq!(external_ref, None);
        }
        other => panic!("{other:?}"),
    }
    match map::admit_answer(decode("admit-allow-external-ref.response.json")).unwrap() {
        AdmissionDecision::Allow {
            reservation,
            external_ref,
            ..
        } => {
            assert_eq!(reservation.as_deref(), Some("demo:upload-20260928-001"));
            assert_eq!(external_ref.as_deref(), Some("contract:order-17"));
        }
        other => panic!("{other:?}"),
    }
    match map::admit_answer(decode("admit-challenge.response.json")).unwrap() {
        AdmissionDecision::Challenge {
            challenges,
            description,
            response_headers,
        } => {
            assert_eq!(
                (challenges.len(), challenges[0].scheme.as_str()),
                (1, "mpp")
            );
            assert_eq!(description, "Example upload payment required.");
            assert_eq!(response_headers[0].0, "WWW-Authenticate");
            crate::pipeline::validate_decision(&AdmissionDecision::Challenge {
                challenges,
                description,
                response_headers,
            })
            .unwrap();
        }
        other => panic!("{other:?}"),
    }
    match map::admit_answer(decode("admit-deny.response.json")).unwrap() {
        AdmissionDecision::Deny(err) => assert_eq!(err.public_message(), "Upload budget exceeded."),
        other => panic!("{other:?}"),
    }
}

#[test]
fn unknown_json_fields_are_ignored_and_an_absent_decision_is_not() {
    let json = r#"{"allow":{"reservationId":"r-1","futureField":[1,{"x":null}]},"other":true}"#;
    let parsed: pb::AdmitResponse = serde_json::from_str(json).unwrap();
    assert!(map::admit_answer(parsed).is_ok());
    let parsed: pb::AuthorizeResponse =
        serde_json::from_str(r#"{"newThing":1,"deny":{"code":"x","zzz":2}}"#).unwrap();
    let err = map::authorize_answer(parsed, &update_op()).unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied);
    // A decision naming two members is malformed, not "the first one".
    assert!(
        serde_json::from_str::<pb::AdmitResponse>(
            r#"{"allow":{"reservationId":"r"},"deny":{"code":"permission_denied"}}"#
        )
        .is_err()
    );
    for empty in ["{}", r#"{"futureOnly":1}"#] {
        let parsed: pb::AuthorizeResponse = serde_json::from_str(empty).unwrap();
        assert!(unavailable(
            &map::authorize_answer(parsed, &update_op()).unwrap_err()
        ));
        let parsed: pb::AdmitResponse = serde_json::from_str(empty).unwrap();
        assert!(unavailable(&map::admit_answer(parsed).unwrap_err()));
    }
}

#[test]
fn authorize_deny_codes_and_messages_are_sanitised() {
    let read = granted_op(
        OpKind::ReadRef {
            name: "refs/heads/main".into(),
        },
        "a3",
    );
    let write = update_op();
    let long = "x".repeat(513);
    let exact = "y".repeat(512);
    let cases: [(&str, &str, &Operation, Code, String); 9] = [
        (
            "permission_denied",
            "no",
            &write,
            Code::PermissionDenied,
            "no".into(),
        ),
        (
            "unauthenticated",
            "sign in",
            &write,
            Code::Unauthenticated,
            "sign in".into(),
        ),
        (
            "not_found",
            "hidden",
            &read,
            Code::NotFound,
            "hidden".into(),
        ),
        (
            "not_found",
            "hidden",
            &write,
            Code::PermissionDenied,
            "hidden".into(),
        ),
        (
            "internal",
            "boom",
            &read,
            Code::PermissionDenied,
            "boom".into(),
        ),
        (
            "",
            "empty code",
            &write,
            Code::PermissionDenied,
            "empty code".into(),
        ),
        (
            "permission_denied",
            &long,
            &write,
            Code::PermissionDenied,
            "permission denied".into(),
        ),
        (
            "permission_denied",
            &exact,
            &write,
            Code::PermissionDenied,
            exact.clone(),
        ),
        (
            "permission_denied",
            "bell\u{7}",
            &write,
            Code::PermissionDenied,
            "permission denied".into(),
        ),
    ];
    for (code, message, op, want_code, want_message) in cases {
        let response = pb::AuthorizeResponse {
            result: Some(pb::__buffa::oneof::authorize_response::Result::Deny(
                Box::new(pb::Deny {
                    code: Some(code.into()),
                    message: Some(message.into()),
                    ..Default::default()
                }),
            )),
            ..Default::default()
        };
        let err = map::authorize_answer(response, op).unwrap_err();
        assert_eq!(
            (err.code(), err.public_message()),
            (want_code, want_message.as_str()),
            "{code} {message}"
        );
    }
}

#[test]
fn an_admit_denial_is_permission_denied_whatever_its_code() {
    let response: pb::AdmitResponse =
        serde_json::from_str(r#"{"deny":{"code":"not_found","message":"line\nbreak"}}"#).unwrap();
    match map::admit_answer(response).unwrap() {
        AdmissionDecision::Deny(err) => {
            assert_eq!(
                (err.code(), err.public_message()),
                (Code::PermissionDenied, "admission denied")
            );
        }
        other => panic!("{other:?}"),
    }
}

// ---- failure classification ------------------------------------------------

fn admit_with(step: Step, sleep: ManualSleep) -> Result<AdmissionDecision, ServerError> {
    let admission = RemoteAdmission::new(client(MockChannel::new(step), sleep));
    let op = begin_op();
    let creds = credentials();
    block_on(admission.admit(&admit_input(&op, &creds)))
}

fn authorize_with(step: Step, sleep: ManualSleep) -> Result<AuthzFacts, ServerError> {
    let authorizer = RemoteAuthorizer::new(client(MockChannel::new(step), sleep));
    block_on(authorizer.authorize(&update_op()))
}

/// A valid allow of exactly `len` bytes, padded with an unknown field.
fn padded_allow(len: usize) -> String {
    let frame = r#"{"allow":{"reservationId":"r"},"pad":""}"#.len();
    format!(
        r#"{{"allow":{{"reservationId":"r"}},"pad":"{}"}}"#,
        "z".repeat(len - frame)
    )
}

#[test]
fn the_response_size_cap_is_exactly_64_kib() {
    let at_cap = padded_allow(MAX_RESPONSE_BYTES);
    assert_eq!(at_cap.len(), 65_536);
    assert!(authorize_with(Step::json(&at_cap), ManualSleep::new()).is_ok());
    assert!(admit_with(Step::json(&at_cap), ManualSleep::new()).is_ok());
    let over = padded_allow(MAX_RESPONSE_BYTES + 1);
    assert!(unavailable(
        &authorize_with(Step::json(&over), ManualSleep::new()).unwrap_err()
    ));
    assert!(unavailable(
        &admit_with(Step::json(&over), ManualSleep::new()).unwrap_err()
    ));
}

/// Every way a hook call can fail or answer unusably (SPEC-SERVER §8).
pub(crate) fn failure_steps() -> Vec<(&'static str, Step)> {
    // Otherwise a valid decision for both Authorize and Admit, so only the
    // size check can refuse it.
    let big = padded_allow(MAX_RESPONSE_BYTES + 1);
    vec![
        (
            "transport",
            Step::Fail(ChannelError::Transport(Redacted::new("reset"))),
        ),
        ("channel timeout", Step::Fail(ChannelError::Timeout)),
        ("too large", Step::Fail(ChannelError::TooLarge)),
        (
            "500",
            Step::Reply(500, Some("application/json"), br#"{"allow":{}}"#.to_vec()),
        ),
        (
            "404",
            Step::Reply(
                404,
                Some("application/json"),
                br#"{"code":"not_found"}"#.to_vec(),
            ),
        ),
        (
            "connect error",
            Step::Reply(
                403,
                Some("application/json"),
                br#"{"code":"permission_denied","message":"nope"}"#.to_vec(),
            ),
        ),
        (
            "3xx",
            Step::Reply(302, Some("application/json"), br#"{"allow":{}}"#.to_vec()),
        ),
        (
            "text/plain",
            Step::Reply(200, Some("text/plain"), br#"{"allow":{}}"#.to_vec()),
        ),
        (
            "no content type",
            Step::Reply(200, None, br#"{"allow":{}}"#.to_vec()),
        ),
        (
            "body over 64 KiB",
            Step::Reply(200, Some("application/json"), big.into_bytes()),
        ),
        ("malformed", Step::json("{")),
        ("empty body", Step::json("")),
        ("absent oneof", Step::json("{}")),
        ("wrong type", Step::json(r#"{"allow":7}"#)),
        (
            "duplicate oneof",
            Step::json(r#"{"allow":{"reservationId":"r"},"deny":{}}"#),
        ),
        ("hang", Step::Hang),
    ]
}

#[test]
fn every_authorize_failure_is_retryable_unavailable() {
    for (name, step) in failure_steps() {
        let err = authorize_with(step, ManualSleep::elapsed()).unwrap_err();
        assert!(unavailable(&err), "{name}: {err:?}");
    }
}

#[test]
fn every_admit_failure_and_invalid_response_is_retryable_unavailable() {
    for (name, step) in failure_steps().into_iter().chain(invalid_admit_steps()) {
        let err = admit_with(step, ManualSleep::elapsed()).unwrap_err();
        assert!(unavailable(&err), "{name}: {err:?}");
    }
}

fn header(name: &str, value: &str) -> String {
    format!(r#"{{"name":"{name}","value":"{value}"}}"#)
}

/// Admit answers that decode but break §6.6 or the remote rules.
#[allow(clippy::too_many_lines)] // One table of wire fixtures.
pub(crate) fn invalid_admit_steps() -> Vec<(&'static str, Step)> {
    let headers = |n: usize, name: &str| {
        (0..n)
            .map(|_| header(name, "v"))
            .collect::<Vec<_>>()
            .join(",")
    };
    let challenges = |n: usize| {
        (0..n)
            .map(|_| r#"{"scheme":"mpp","value":"v"}"#)
            .collect::<Vec<_>>()
            .join(",")
    };
    let allow = |extra: &str| Step::json(&format!(r#"{{"allow":{{{extra}}}}}"#));
    let challenge = |body: &str| Step::json(&format!(r#"{{"challenge":{{{body}}}}}"#));
    vec![
        ("allow without reservation", allow("")),
        (
            "allow with empty reservation",
            allow(r#""reservationId":"""#),
        ),
        ("s: reservation", allow(r#""reservationId":"s:synthetic""#)),
        (
            "reservation with a space",
            allow(r#""reservationId":"a b""#),
        ),
        (
            "reservation over 128",
            allow(&format!(r#""reservationId":"{}""#, "r".repeat(129))),
        ),
        (
            "9 headers",
            allow(&format!(
                r#""reservationId":"r","responseHeaders":[{}]"#,
                headers(9, "Payment-Receipt")
            )),
        ),
        (
            "2 receipt headers of one name",
            allow(&format!(
                r#""reservationId":"r","responseHeaders":[{}]"#,
                headers(2, "Payment-Receipt")
            )),
        ),
        (
            "disallowed header",
            allow(&format!(
                r#""reservationId":"r","responseHeaders":[{}]"#,
                header("Set-Cookie", "a=b")
            )),
        ),
        (
            "challenge header on allow",
            allow(&format!(
                r#""reservationId":"r","responseHeaders":[{}]"#,
                header("WWW-Authenticate", "x")
            )),
        ),
        (
            "external_ref over 256",
            allow(&format!(
                r#""reservationId":"r","externalRef":"{}""#,
                "e".repeat(257)
            )),
        ),
        (
            "external_ref with a space",
            allow(r#""reservationId":"r","externalRef":"a b""#),
        ),
        (
            "9 challenges",
            challenge(&format!(
                r#""challenges":[{}],"description":"d""#,
                challenges(9)
            )),
        ),
        (
            "no challenges",
            challenge(r#""challenges":[],"description":"d""#),
        ),
        (
            "bad scheme",
            challenge(r#""challenges":[{"scheme":"Bad Scheme","value":"v"}],"description":"d""#),
        ),
        (
            "description over 512",
            challenge(&format!(
                r#""challenges":[{{"scheme":"mpp","value":"v"}}],"description":"{}""#,
                "d".repeat(513)
            )),
        ),
        (
            "9 challenge headers",
            challenge(&format!(
                r#""challenges":[{{"scheme":"mpp","value":"v"}}],"description":"d","responseHeaders":[{}]"#,
                headers(9, "WWW-Authenticate")
            )),
        ),
        (
            "receipt header on challenge",
            challenge(&format!(
                r#""challenges":[{{"scheme":"mpp","value":"v"}}],"description":"d","responseHeaders":[{}]"#,
                header("Payment-Receipt", "x")
            )),
        ),
        (
            "header without a value",
            allow(r#""reservationId":"r","responseHeaders":[{"name":"Payment-Receipt"}]"#),
        ),
    ]
}

#[test]
fn a_timeout_through_the_sleep_seam_is_unavailable_and_carries_the_call_timeout() {
    let sleep = ManualSleep::elapsed();
    let client = client(MockChannel::new(Step::Hang), sleep.clone());
    let authorizer = RemoteAuthorizer::new(client.clone()).with_timeout(Duration::from_millis(250));
    assert!(unavailable(
        &block_on(authorizer.authorize(&update_op())).unwrap_err()
    ));
    assert_eq!(sleep.requested(), [Duration::from_millis(250)]);
    let seen = channel_of(&client).seen.lock().unwrap();
    assert_eq!(seen[0].timeout, Duration::from_millis(250));
}

#[test]
fn a_ready_answer_beats_a_timer_that_has_not_fired() {
    let admitted = admit_with(
        Step::json(r#"{"allow":{"reservationId":"r-1"}}"#),
        ManualSleep::new(),
    );
    assert!(matches!(admitted.unwrap(), AdmissionDecision::Allow { .. }));
}

#[test]
fn outcomes_ack_on_any_2xx_and_error_otherwise() {
    let sink = |step| RemoteOutcomes::new(client(MockChannel::new(step), ManualSleep::elapsed()));
    let row = outcome("r-1", OutcomeKind::Expired);
    for status in [200, 201, 204, 299] {
        let step = Step::Reply(status, Some("text/plain"), b"not json at all".to_vec());
        assert!(block_on(sink(step).deliver(&row)).is_ok(), "{status}");
    }
    assert!(block_on(sink(Step::Reply(200, None, Vec::new())).deliver(&row)).is_ok());
    for (name, step) in failure_steps() {
        let acked = matches!(&step, Step::Reply(s, ..) if (200..300).contains(s));
        let result = block_on(sink(step).deliver(&row));
        assert_eq!(result.is_ok(), acked, "{name}");
    }
    let err = block_on(sink(Step::Reply(503, None, Vec::new())).deliver(&row)).unwrap_err();
    assert_eq!(err.to_string(), "outcome delivery failed");
}

#[test]
fn the_outcome_response_golden_acknowledges_and_an_oversize_2xx_still_does() {
    let empty: pb::OutcomeResponse = decode("outcome.response.json");
    assert!(empty == pb::OutcomeResponse::default());
    let golden = String::from_utf8(golden("outcome.response.json")).unwrap();
    let sink = |step| RemoteOutcomes::new(client(MockChannel::new(step), ManualSleep::new()));
    let row = outcome("r-1", OutcomeKind::Expired);
    assert!(block_on(sink(Step::json(&golden)).deliver(&row)).is_ok());
    // A channel that hit its cap hands back the status and max + 1 bytes.
    let big = Step::Reply(
        200,
        Some("application/json"),
        vec![b' '; MAX_RESPONSE_BYTES + 1],
    );
    assert!(block_on(sink(big).deliver(&row)).is_ok());
}

#[test]
fn each_outcome_attempt_is_signed_afresh() {
    let client = client(MockChannel::new(Step::json("{}")), ManualSleep::new());
    let sink = RemoteOutcomes::new(client.clone());
    let row = outcome("r-1", OutcomeKind::Expired);
    for _ in 0..2 {
        block_on(sink.deliver(&row)).unwrap();
    }
    let seen = channel_of(&client).seen.lock().unwrap();
    assert_eq!(seen[0].body, seen[1].body);
    verify(&seen[0]);
    verify(&seen[1]);
    let nonce = |i: usize| {
        seen[i]
            .headers
            .iter()
            .find(|(n, _)| *n == "X-Mkit-Hook-Nonce")
            .unwrap()
            .1
            .clone()
    };
    assert_ne!(nonce(0), nonce(1));
}

// ---- redaction -------------------------------------------------------------

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<String>>);

struct Fields<'a>(&'a Mutex<String>);

impl tracing::field::Visit for Fields<'_> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn core::fmt::Debug) {
        let _ = write!(self.0.lock().unwrap(), "{}={value:?} ", field.name());
    }
}

impl tracing::Subscriber for Capture {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, attrs: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        attrs.record(&mut Fields(&self.0));
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, values: &tracing::span::Record<'_>) {
        values.record(&mut Fields(&self.0));
    }
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        let _ = write!(self.0.lock().unwrap(), "{} ", event.metadata().name());
        event.record(&mut Fields(&self.0));
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

#[test]
fn an_admit_round_trip_never_emits_the_credential() {
    let capture = Capture::default();
    let mut rendered = String::new();
    // With one live dispatcher, tracing registers a callsite against the
    // registering thread's own default, so another test thread that reaches a
    // callsite first would cache it as disabled for us. A second, idle
    // dispatcher makes every registration consult all of them.
    let _second = tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default());
    tracing::subscriber::with_default(capture.clone(), || {
        tracing::callsite::rebuild_interest_cache();
        let mut steps = failure_steps();
        steps.extend(invalid_admit_steps());
        steps.push(("allow", Step::json(r#"{"allow":{"reservationId":"r-1"}}"#)));
        steps.push(("challenge", Step::json(&format!(
            r#"{{"challenge":{{"challenges":[{{"scheme":"mpp","value":"v"}}],"description":"{CREDENTIAL}"}}}}"#
        ))));
        for (_, step) in steps {
            let client = client(MockChannel::new(step), ManualSleep::elapsed());
            let admission = RemoteAdmission::new(client.clone());
            let op = begin_op();
            let creds = credentials();
            let input = admit_input(&op, &creds);
            let outcome = block_on(admission.admit(&input));
            if let Err(err) = &outcome {
                write!(rendered, "{err:?} {err} {:?}", err.log_detail()).unwrap();
            }
            let seen = channel_of(&client).seen.lock().unwrap();
            // The credential really travelled in the request body...
            assert!(String::from_utf8_lossy(&seen[0].body).contains(CREDENTIAL));
            // ...and never in anything a log line or debug print could carry.
            write!(
                rendered,
                "{:?} {admission:?} {client:?}",
                HookRequest {
                    procedure: "p",
                    headers: vec![],
                    body: Zeroizing::new(seen[0].body.clone()),
                    timeout: DEFAULT_TIMEOUT,
                    max_response_bytes: 1,
                }
            )
            .unwrap();
        }
    });
    let logs = capture.0.lock().unwrap().clone();
    assert!(!logs.is_empty(), "the invalid-response paths log a warning");
    assert!(
        !logs.contains("fake-example-credential") && !rendered.contains("fake-example-credential")
    );
    assert!(!logs.contains("Payment-Authorization=") && !logs.contains("SECRET"));
}

#[test]
fn a_channel_error_keeps_its_text_out_of_display_and_debug() {
    let err = ChannelError::Transport(Redacted::new(
        "tls: Payment fake-example-credential-not-valid",
    ));
    assert!(!format!("{err} {err:?}").contains("credential"));
    let response = HookResponse::new(
        200,
        None,
        b"Payment fake-example-credential-not-valid".to_vec(),
    );
    assert!(!format!("{response:?}").contains("credential"));
}

#[test]
fn every_attempt_stamps_the_clock_and_a_source_failure_fails_closed() {
    struct Failing;
    impl NonceSource for Failing {
        fn fill(&self, _: &mut [u8; 32]) -> bool {
            false
        }
    }
    let clock = Arc::new(ManualClock::new(T));
    let dynamic: Arc<dyn Clock> = clock.clone();
    let channel = MockChannel::new(Step::json("{}"));
    let hook = HookClient::new(
        channel,
        SERVER_ORIGIN,
        Some(signer()),
        dynamic,
        Arc::new(ManualSleep::new()),
    )
    .unwrap()
    .with_nonce_source(Arc::new(Fixed([7; 32])));
    let hook = Arc::new(hook);
    let sink = RemoteOutcomes::new(hook.clone());
    let row = outcome("r-1", OutcomeKind::Expired);
    block_on(sink.deliver(&row)).unwrap();
    clock.advance(90_000);
    block_on(sink.deliver(&row)).unwrap();
    let created = |i: usize| -> i64 {
        let seen = channel_of(&hook).seen.lock().unwrap();
        seen[i]
            .headers
            .iter()
            .find(|(n, _)| *n == "X-Mkit-Hook-Created-At")
            .unwrap()
            .1
            .parse()
            .unwrap()
    };
    assert_eq!(created(1) - created(0), 90_000);

    let failing = HookClient::new(
        MockChannel::new(Step::json("{}")),
        SERVER_ORIGIN,
        Some(signer()),
        Arc::new(ManualClock::new(T)),
        Arc::new(ManualSleep::new()),
    )
    .unwrap()
    .with_nonce_source(Arc::new(Failing));
    let failing = Arc::new(failing);
    let err = block_on(RemoteAuthorizer::new(failing.clone()).authorize(&update_op())).unwrap_err();
    assert!(unavailable(&err));
    assert!(
        channel_of(&failing).seen.lock().unwrap().is_empty(),
        "nothing is sent unsigned"
    );
}

struct Fixed([u8; 32]);
impl NonceSource for Fixed {
    fn fill(&self, nonce: &mut [u8; 32]) -> bool {
        *nonce = self.0;
        true
    }
}

#[test]
fn plain_http_is_loopback_only_and_an_unsigned_channel_names_no_origin() {
    let clock: Arc<dyn Clock> = Arc::new(ManualClock::new(T));
    let with_origin = |origin: &'static str, signed: bool| {
        let mut channel = MockChannel::new(Step::Hang);
        channel.audience = Some(origin);
        channel.isolated = !signed;
        HookClient::new(
            channel,
            SERVER_ORIGIN,
            signed.then(signer),
            clock.clone(),
            Arc::new(ManualSleep::new()),
        )
        .map(|_| ())
    };
    for ok in [
        "https://hooks.example.test",
        "http://localhost:8787",
        "http://127.0.0.1:9000",
        "http://127.8.8.8",
        "http://[::1]:9000",
    ] {
        assert_eq!(with_origin(ok, true), Ok(()), "{ok}");
    }
    for bad in [
        "http://hooks.example.test",
        "http://10.0.0.1",
        "http://localhost.example.test",
        "http://128.0.0.1",
        "ftp://hooks.example.test",
        "https://Hooks.Example.test",
    ] {
        assert_eq!(
            with_origin(bad, true),
            Err(HookConfigError::Audience("hook")),
            "{bad}"
        );
    }
    // An unsigned channel is a service binding: it names no origin at all.
    assert_eq!(
        with_origin("https://hooks.example.test", false),
        Err(HookConfigError::UnsignedOrigin)
    );
}

#[test]
fn a_pipeline_audience_that_differs_from_the_adapters_is_refused() {
    let hook = client(
        MockChannel::new(Step::json(r#"{"allow":{"reservationId":"r"}}"#)),
        ManualSleep::new(),
    );
    let admission = RemoteAdmission::new(hook.clone());
    let op = begin_op();
    let mut input = admit_input(&op, &[]);
    input.audience = Some(SERVER_ORIGIN);
    assert!(block_on(admission.admit(&input)).is_ok());
    input.audience = Some("https://other.example.test");
    let err = block_on(admission.admit(&input)).unwrap_err();
    assert!(unavailable(&err));
    assert_eq!(channel_of(&hook).seen.lock().unwrap().len(), 1);
}

#[test]
fn the_repository_a_hook_sees_is_the_wire_identity() {
    use crate::repo::{Addressing, MultiAddressing};
    let mut op = update_op();
    let multi = Addressing::Multi(MultiAddressing::new());
    let wire = format!("{NAMESPACE}/payments-demo");
    let resolved = multi.resolve(Some(&wire), true).unwrap();
    op.repo = resolved.repo;
    assert_eq!(
        map::authorize_request(&op, SERVER_ORIGIN)
            .operation
            .repository,
        Some(resolved.identity)
    );

    let single = Addressing::Single {
        repo: RepoId {
            namespace: NamespaceKey::deployment_default(),
            name: RepoName::new("room-a").unwrap(),
        },
    };
    let resolved = single.resolve(Some("room-a"), true).unwrap();
    op.repo = resolved.repo;
    assert_eq!(
        map::authorize_request(&op, SERVER_ORIGIN)
            .operation
            .repository,
        Some(resolved.identity)
    );
}

#[test]
fn credentials_are_wiped_from_the_message_and_the_body_is_exactly_sized() {
    let op = begin_op();
    let creds = credentials();
    let mut request = map::admit_request(&admit_input(&op, &creds), SERVER_ORIGIN);
    let body = super::client::encode(&request).unwrap();
    assert_eq!(*body, serde_json::to_vec(&request).unwrap());
    assert_eq!(body.len(), body.capacity());
    assert!(String::from_utf8_lossy(&body).contains(CREDENTIAL));
    map::wipe(&mut request);
    assert!(
        request
            .credential_headers
            .iter()
            .all(|h| h.value.as_deref() == Some(""))
    );
    assert!(
        !serde_json::to_string(&request)
            .unwrap()
            .contains("fake-example-credential")
    );
}

#[test]
fn a_signed_read_sends_an_empty_idempotency_key_and_a_write_its_nonce() {
    let read = granted_op(
        OpKind::ReadRef {
            name: "refs/heads/main".into(),
        },
        "b3",
    );
    assert_eq!(
        map::authorize_request(&read, SERVER_ORIGIN)
            .operation
            .idempotency_key,
        None
    );
    let write = update_op();
    assert_eq!(
        map::authorize_request(&write, SERVER_ORIGIN)
            .operation
            .idempotency_key,
        Some("a2".repeat(32))
    );
}

#[test]
fn an_unknown_ssh_key_is_explicit_empty_bytes() {
    let mut op = update_op();
    op.principal = Principal::SshForcedCommand { key: None };
    let request = value_of(&map::authorize_request(&op, SERVER_ORIGIN));
    let key = &request["operation"]["principal"]["sshForcedCommand"];
    assert!(key.get("ed25519PublicKey").is_some(), "{request}");
}

#[test]
fn an_outcome_for_another_audience_is_not_delivered() {
    let hook = client(MockChannel::new(Step::json("{}")), ManualSleep::new());
    let sink = RemoteOutcomes::new(hook.clone());
    let mut row = outcome("r-1", OutcomeKind::Expired);
    row.audience = "https://other.example.test".to_owned();
    let err = block_on(sink.deliver(&row)).unwrap_err();
    assert_eq!(err.to_string(), "outcome delivery failed");
    assert!(channel_of(&hook).seen.lock().unwrap().is_empty());
    row.audience = SERVER_ORIGIN.to_owned();
    block_on(sink.deliver(&row)).unwrap();
}

#[test]
fn credentials_are_wiped_when_the_call_is_cancelled_or_unwinds() {
    use core::sync::atomic::{AtomicUsize, Ordering};
    struct Probe(Arc<AtomicUsize>);
    impl super::roles::Wipe for Probe {
        fn wipe(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    let wipes = Arc::new(AtomicUsize::new(0));
    // Dropped mid-call, on a future that never completes.
    let held = super::roles::WipeOnDrop(Probe(wipes.clone()));
    let mut call = Box::pin(async move {
        let _held = held;
        core::future::pending::<()>().await;
    });
    assert!(futures::FutureExt::now_or_never(&mut call).is_none());
    assert_eq!(wipes.load(Ordering::SeqCst), 0);
    drop(call);
    assert_eq!(wipes.load(Ordering::SeqCst), 1);
    // A panic unwinds through the guard.
    let inner = wipes.clone();
    let result = std::panic::catch_unwind(move || {
        let _held = super::roles::WipeOnDrop(Probe(inner));
        panic!("unwind");
    });
    assert!(result.is_err());
    assert_eq!(wipes.load(Ordering::SeqCst), 2);

    // And through the real adapter: a hung Admit dropped mid-call.
    let hook = client(MockChannel::new(Step::Hang), ManualSleep::new());
    let admission = RemoteAdmission::new(hook.clone());
    let op = begin_op();
    let creds = credentials();
    let input = admit_input(&op, &creds);
    let mut admit = Box::pin(admission.admit(&input));
    assert!(futures::FutureExt::now_or_never(&mut admit).is_none());
    drop(admit);
    assert_eq!(channel_of(&hook).seen.lock().unwrap().len(), 1);
}
