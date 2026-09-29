//! The remote-hook adapter driven through a memory pipeline (SPEC-SERVER §8):
//! every failure of a decision hook answers retryable `unavailable` and
//! writes nothing.
use super::*;
use crate::hooks::tests::{
    MockChannel, Step, channel_of, client_for, failure_steps, invalid_admit_steps,
};
use crate::hooks::{RemoteAdmission, RemoteAuthorizer};
use crate::rt::ManualSleep;

/// The hooks must name the origin the pipeline authenticates for.
fn client(channel: MockChannel, sleep: ManualSleep) -> Arc<crate::hooks::HookClient<MockChannel>> {
    client_for(channel, sleep, AUDIENCE)
}

fn env_with<H: HookSet>(hooks: H) -> Env<H> {
    let clock = clock();
    build(cfg(authv2()), Spy::new(store(&clock)), hooks, clock)
}

fn update_once<H: HookSet>(env: &Env<H>) -> Result<UpdateRefResult, ServerError> {
    let u = upd(HEAD, Missing, A);
    env.update(&Req::update(&key(7), 1, &u, T0), &u)
}

fn remote_authorizer(step: Step) -> Hooks<RemoteAuthorizer<MockChannel>> {
    Hooks {
        authorizer: RemoteAuthorizer::new(client(MockChannel::new(step), ManualSleep::elapsed())),
        admission: DefaultAdmission,
        pre_receive: NoPreReceive,
        receipts: NoReceipts,
        outcomes: NoOutcomes,
    }
}

fn remote_admission(step: Step) -> Hooks<OpenAuthorizer, RemoteAdmission<MockChannel>> {
    with_admission(RemoteAdmission::new(client(
        MockChannel::new(step),
        ManualSleep::elapsed(),
    )))
}

fn assert_unavailable_and_untouched<H: HookSet>(env: &Env<H>, what: &str) {
    let err = update_once(env).unwrap_err();
    assert_eq!(err.code(), Code::Unavailable, "{what}: {err:?}");
    assert!(
        err.http_status().is_none_or(|status| status != 402),
        "{what}"
    );
    assert!(env.batches().is_empty() && env.rows().is_empty(), "{what}");
}

#[test]
fn every_remote_authorize_failure_denies_unavailable_and_writes_nothing() {
    for (name, step) in failure_steps() {
        assert_unavailable_and_untouched(&env_with(remote_authorizer(step)), name);
    }
}

#[test]
fn every_remote_admit_failure_and_invalid_response_writes_nothing() {
    for (name, step) in failure_steps().into_iter().chain(invalid_admit_steps()) {
        assert_unavailable_and_untouched(&env_with(remote_admission(step)), name);
    }
}

#[test]
fn a_deliberate_remote_denial_is_a_decision_and_writes_nothing() {
    let deny = Step::json(r#"{"deny":{"code":"not_found","message":"Upload budget exceeded."}}"#);
    let env = env_with(remote_authorizer(deny.clone()));
    let err = update_once(&env).unwrap_err();
    assert_eq!(
        (err.code(), err.public_message()),
        (Code::PermissionDenied, "Upload budget exceeded.")
    );
    assert!(env.batches().is_empty() && env.rows().is_empty());

    let env = env_with(remote_admission(deny));
    let err = update_once(&env).unwrap_err();
    assert_eq!(
        (err.code(), err.http_status()),
        (Code::PermissionDenied, Some(403))
    );
    assert!(env.batches().is_empty() && env.rows().is_empty());
}

#[test]
fn a_remote_challenge_is_the_402_response_and_writes_nothing() {
    let challenge = Step::json(
        r#"{"challenge":{"challenges":[{"scheme":"mpp","value":"id=1"}],"description":"pay"}}"#,
    );
    let env = env_with(remote_admission(challenge));
    let err = update_once(&env).unwrap_err();
    assert_eq!(
        (err.code(), err.http_status()),
        (Code::PermissionDenied, Some(402))
    );
    assert!(env.batches().is_empty() && env.rows().is_empty());
}

#[test]
fn remote_allows_commit_and_record_the_hook_reservation() {
    let authorize = client(
        MockChannel::new(Step::json(r#"{"allow":{}}"#)),
        ManualSleep::new(),
    );
    let admit = client(
        MockChannel::new(Step::json(
            r#"{"allow":{"reservationId":"demo:remote-1","externalRef":"contract:1"}}"#,
        )),
        ManualSleep::new(),
    );
    let hooks = Hooks {
        authorizer: RemoteAuthorizer::new(authorize.clone()),
        admission: RemoteAdmission::new(admit.clone()),
        pre_receive: NoPreReceive,
        receipts: NoReceipts,
        outcomes: NoOutcomes,
    };
    let env = env_with(hooks);
    assert_eq!(update_once(&env).unwrap(), UpdateRefResult::Committed);
    let row = now(env
        .pipe
        .meta
        .get(&ns(), &keys::reservation("demo:remote-1").unwrap()))
    .unwrap()
    .unwrap();
    assert!(matches!(
        codec::decode_reservation(&row).unwrap(),
        codec::ReservationV1::Committed { .. }
    ));
    // Each hook was called once, at its own procedure.
    for (client, rpc) in [(&authorize, "Authorize"), (&admit, "Admit")] {
        let seen = channel_of(client).seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(
            seen[0].procedure,
            format!("/mkit.server.hooks.v1.HooksService/{rpc}")
        );
    }
}
