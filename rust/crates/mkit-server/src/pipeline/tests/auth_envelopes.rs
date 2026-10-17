use super::*;
use crate::error::Redacted;

#[test]
fn authv2_each_missing_envelope_header_fails_closed() {
    let env = env(authv2());
    for procedure in [
        Procedure::ReadRef,
        Procedure::ListRefs,
        Procedure::UpdateRef,
    ] {
        for name in crate::auth_v2::HEADER_NAMES {
            let mut request = Req::signed(&key(7), procedure, b"request", &nonce(70), T0);
            request.headers.retain(|(header, _)| *header != name);
            assert_eq!(
                code(env.auth(&request)),
                Code::Unauthenticated,
                "{procedure:?}: {name}"
            );
        }
    }
    assert!(env.rows().is_empty());
}

#[test]
fn authv2_each_duplicate_envelope_header_fails_closed() {
    let env = env(authv2());
    for procedure in [Procedure::ReadRef, Procedure::UpdateRef] {
        let request = Req::signed(&key(7), procedure, b"request", &nonce(71), T0);
        let lookup = |name: &str| {
            request
                .headers
                .iter()
                .find(|(header, _)| *header == name)
                .map(|(_, value)| value.clone())
        };
        for duplicate in crate::auth_v2::HEADER_NAMES {
            let values = |name: &str| {
                let value = lookup(name).unwrap();
                if name == duplicate {
                    vec![value.clone(), value]
                } else {
                    vec![value]
                }
            };
            let result = env.pipe.authenticate(&RequestMeta {
                procedure,
                header: &lookup,
                header_values: Some(&values),
                unary_body: Some(&request.body),
                transport_principal: None,
            });
            assert_eq!(
                code(result),
                Code::Unauthenticated,
                "{procedure:?}: {duplicate}"
            );
        }
    }
    assert!(env.rows().is_empty());
}

#[test]
fn authv2_saved_replay_never_extends_envelope_validity() {
    let env = env(authv2());
    let update = upd(HEAD, Missing, A);
    let request = Req::update(&key(7), 72, &update, T0);
    assert_eq!(
        env.update(&request, &update).unwrap(),
        UpdateRefResult::Committed
    );
    let rows = env.rows();
    let batches = env.batches().len();
    env.clock.set(T0 + 300_000);
    assert_eq!(
        env.update(&request, &update).unwrap(),
        UpdateRefResult::Committed
    );
    assert_eq!(env.batches().len(), batches);
    env.clock.set(T0 + 300_001);
    assert_eq!(code(env.update(&request, &update)), Code::Unauthenticated);
    assert_eq!(env.rows(), rows);
    assert_eq!(env.batches().len(), batches);
}

#[test]
fn every_trigger_alone_fails_on_reads_and_writes() {
    let env = env(authv2());
    for procedure in [
        Procedure::ReadRef,
        Procedure::ListRefs,
        Procedure::UpdateRef,
    ] {
        for name in mkit_primitives::auth::TRIGGER_HEADER_NAMES {
            for value in ["", "partial"] {
                assert_eq!(
                    code(env.auth(&Req::unsigned(procedure).header(name, value))),
                    Code::Unauthenticated
                );
            }
        }
    }
    assert!(env.rows().is_empty());
}

#[test]
fn unsigned_write_timestamps_preserve_authentication_modes() {
    let methods = [
        Procedure::UpdateRef,
        Procedure::AdvanceRefs,
        Procedure::BeginUpload,
        Procedure::UploadPack,
        Procedure::UploadPart,
        Procedure::CompleteUpload,
    ];
    for mode in [
        AuthMode::Open,
        AuthMode::Bearer {
            token: Redacted::new("token"),
        },
        AuthMode::TransportIdentity,
        authv2(),
    ] {
        let signed_mode = matches!(mode, AuthMode::AuthV2(_));
        let env = env(mode);
        for procedure in methods {
            let mut request = Req::unsigned(procedure)
                .header("x-repository", REPO)
                .header("idempotency-key", &nonce(73))
                .header("x-created-at", &T0.to_string())
                .header("x-expires-at", &(T0 + 300_000).to_string())
                .header("authorization", "Bearer token");
            request.principal = Some(Principal::Anonymous);
            let result = env.auth(&request);
            if signed_mode {
                assert_eq!(code(result), Code::Unauthenticated);
            } else {
                assert!(result.unwrap().auth.is_none());
            }
        }
        assert!(env.rows().is_empty());
    }
}

#[test]
fn raw_presence_cannot_disappear_through_a_lossy_getter() {
    let env = env(authv2());
    let request = Req::signed(&key(7), Procedure::ReadRef, b"body", &nonce(74), T0);
    for dropped in crate::auth_v2::HEADER_NAMES {
        let lookup = |name: &str| {
            (name != dropped)
                .then(|| {
                    request
                        .headers
                        .iter()
                        .find(|(n, _)| *n == name)
                        .map(|(_, v)| v.clone())
                })
                .flatten()
        };
        let values = |name: &str| {
            request
                .headers
                .iter()
                .filter(|(n, _)| *n == name)
                .map(|(_, v)| v.clone())
                .collect()
        };
        assert_eq!(
            code(env.pipe.authenticate(&RequestMeta {
                procedure: request.procedure,
                header: &lookup,
                header_values: Some(&values),
                unary_body: Some(&request.body),
                transport_principal: None,
            })),
            Code::Unauthenticated
        );
    }
    assert!(env.rows().is_empty());
}
