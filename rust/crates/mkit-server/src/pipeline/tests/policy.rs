//! STC §7.5 / SPEC-SERVER §6.2 composition and allocation regressions.
use super::*;
use crate::op::Creation;
use crate::repo::MultiAddressing;

#[derive(Clone)]
struct PolicyHook {
    deny: bool,
    seen: Arc<Mutex<Vec<Operation>>>,
}

impl Authorizer for PolicyHook {
    async fn authorize(&self, op: &Operation) -> Result<AuthzFacts, ServerError> {
        self.seen.lock().unwrap().push(op.clone());
        if self.deny {
            Err(ServerError::permission_denied("hook denial"))
        } else {
            // The hook cannot manufacture ownership or an M2 grant.
            Ok(AuthzFacts {
                owner: true,
                grant: None,
            })
        }
    }
}

#[derive(Clone, Default)]
struct PolicyAdmission(Arc<Mutex<Vec<AuthzFacts>>>);

impl Admission for PolicyAdmission {
    fn is_default(&self) -> bool {
        // This spy delegates its decision unchanged to DefaultAdmission.
        true
    }

    async fn admit(&self, input: &AdmissionInput<'_>) -> Result<AdmissionDecision, ServerError> {
        self.0.lock().unwrap().push(input.op.authz.clone());
        DefaultAdmission.admit(input).await
    }
}

fn policy_hooks(deny: bool) -> Hooks<PolicyHook, PolicyAdmission> {
    let defaults = Hooks::new();
    Hooks {
        authorizer: PolicyHook {
            deny,
            seen: Arc::default(),
        },
        admission: PolicyAdmission::default(),
        pre_receive: defaults.pre_receive,
        receipts: defaults.receipts,
        outcomes: defaults.outcomes,
    }
}

fn namespace_policy(kind: u8, namespace: &Namespace) -> NamespacePolicy {
    match kind {
        0 => NamespacePolicy::Allowlist([*namespace].into()),
        1 => NamespacePolicy::default(),
        _ => NamespacePolicy::Any {
            unsafe_without_admission: true,
        },
    }
}

fn policy_cfg(multi: bool, policy: NamespacePolicy) -> PipelineConfig {
    let addressing = if multi {
        Addressing::Multi(MultiAddressing::new().with_namespace_policy(policy))
    } else {
        Addressing::Single { repo: repo() }
    };
    let mut c = PipelineConfig::new(
        addressing,
        AuthMode::Open,
        cfg(AuthMode::Open).upload_limits,
    );
    c.write_quota = Some(DEFAULT_WRITE_QUOTA);
    c.sharding = Sharding::D34;
    c
}

/// Exercise stage 2 after authentication with each possible established
/// principal, including transport/SSH identities unavailable to HTTP signers.
#[test]
fn namespace_write_policy_matrix_denials_allocate_nothing() {
    let owner_key = [1; 32];
    let ed_namespace = Namespace::Ed25519(owner_key);
    let principals = [
        Principal::Signer { ed25519: owner_key },
        Principal::Signer { ed25519: [2; 32] },
        Principal::Anonymous,
        Principal::BearerHolder,
        Principal::Signer { ed25519: owner_key }, // Address namespace
        Principal::TransportPeer { ed25519: owner_key },
        Principal::SshForcedCommand {
            key: Some(owner_key),
        },
        Principal::SshForcedCommand { key: None },
    ];
    for multi in [false, true] {
        for policy_kind in 0..3 {
            for (index, principal) in principals.iter().enumerate() {
                let namespace = if index == 4 {
                    Namespace::Address([3; 20])
                } else {
                    ed_namespace
                };
                for (role, hook_denies) in [
                    (AuthorizerRole::Check, false),
                    (AuthorizerRole::Check, true),
                    (AuthorizerRole::Authority, false),
                    (AuthorizerRole::Authority, true),
                ] {
                    check_policy_case(
                        multi,
                        policy_kind,
                        principal,
                        namespace,
                        role,
                        hook_denies,
                        matches!(index, 0 | 5 | 6),
                    );
                }
            }
        }
    }
}

fn check_policy_case(
    multi: bool,
    policy_kind: u8,
    principal: &Principal,
    namespace: Namespace,
    role: AuthorizerRole,
    hook_denies: bool,
    owner: bool,
) {
    let mut c = policy_cfg(multi, namespace_policy(policy_kind, &namespace));
    c.authorizer_role = role;
    let clock = clock();
    let hooks = policy_hooks(hook_denies);
    let seen = hooks.authorizer.seen.clone();
    let admitted = hooks.admission.0.clone();
    let e = build(c, Spy::new(store(&clock)), hooks, clock);
    let identity = if multi {
        format!("{namespace}/{REPO}")
    } else {
        REPO.to_owned()
    };
    let mut auth = e
        .auth(&Req::unsigned(Procedure::UpdateRef).header("x-repository", &identity))
        .unwrap();
    auth.principal = principal.clone();
    // Supply a stage-0 verified envelope to exercise replay and quota
    // allocation alongside every principal combination.
    auth.auth = Some(VerifiedAuth {
        signer: [1; 32],
        replay_scope: [1; 32],
        fingerprint: [2; 32],
        nonce: nonce(1),
        commitment: crate::op::Commitment::Body(A),
        expires_at_ms: T0 + 300_000,
    });
    let namespace_passes = !multi || policy_kind != 1;
    let hook_called = namespace_passes && (!multi || owner || role == AuthorizerRole::Authority);
    let allowed = hook_called && !hook_denies;
    let result = now(e.pipe.update_ref(&auth, upd(HEAD, Any, A)));
    let context = format!(
        "multi={multi} policy={policy_kind} principal={principal:?} role={role:?} deny={hook_denies}"
    );
    assert_eq!(result.is_ok(), allowed, "{context}");
    assert_eq!(
        seen.lock().unwrap().len(),
        usize::from(hook_called),
        "{context}"
    );
    assert_eq!(
        admitted.lock().unwrap().len(),
        usize::from(allowed),
        "{context}"
    );
    if multi && hook_called {
        let observed = seen.lock().unwrap();
        assert_eq!(
            observed[0].authz,
            AuthzFacts { owner, grant: None },
            "{context}"
        );
    }
    if multi && allowed {
        assert_eq!(
            admitted.lock().unwrap()[0],
            AuthzFacts { owner, grant: None },
            "{context}"
        );
    }
    if !allowed {
        let err = result.unwrap_err();
        assert_eq!(err.code(), Code::PermissionDenied, "{context}");
        assert_eq!(
            err.public_message(),
            if hook_called {
                "hook denial"
            } else {
                "write not permitted"
            },
            "{context}"
        );
        assert!(e.pipe.meta.batches.lock().unwrap().is_empty(), "{context}");
        for p in [
            e.pipe.shards.coordinator(&auth.repo().repo.namespace),
            e.pipe.shards.ref_shard(&auth.repo().repo, HEAD),
        ] {
            assert_eq!(
                now(e.pipe.meta.inner.stats(&p)).unwrap().keys,
                Some(0),
                "{context}"
            );
        }
    }
}

fn construct<H: HookSet>(
    c: PipelineConfig,
    hooks: H,
) -> Result<Pipeline<MemoryBlobStore, MemoryKv, H>, ServerError> {
    Pipeline::new(
        MemoryBlobStore::default(),
        store(&clock()),
        hooks,
        c,
        clock(),
        Arc::new(crate::NoopMetrics),
    )
}

#[test]
fn startup_policy_refusals_and_accepted_counterparts() {
    let ns = Namespace::Ed25519([1; 32]);
    for (multi, write, expected) in [
        (
            false,
            WritePolicy::Owner,
            "write_policy owner needs multi-repository addressing",
        ),
        (
            true,
            WritePolicy::Open,
            "write_policy open is single-repository only (SPEC-TRANSPORT-CONNECT §7.5)",
        ),
    ] {
        let mut c = policy_cfg(multi, namespace_policy(0, &ns));
        c.write_policy = write;
        let err = construct(c, Hooks::new()).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert_eq!(err.public_message(), expected);
        assert!(construct(policy_cfg(multi, namespace_policy(0, &ns)), Hooks::new()).is_ok());
    }
    let any = NamespacePolicy::Any {
        unsafe_without_admission: false,
    };
    let err = construct(policy_cfg(true, any.clone()), Hooks::new()).unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);
    assert_eq!(
        err.public_message(),
        "namespace_policy any needs a non-default admission step, or the explicit unsafe override (D27)"
    );
    let mut admitted = policy_cfg(true, any);
    admitted.auth = authv2();
    admitted.ticket_keys =
        Some(crate::upload::token::TicketKeys::new(vec![("test".into(), [7; 32])]).unwrap());
    assert!(
        construct(
            admitted,
            with_admission(Fixed(AdmissionDecision::allow(vec![])))
        )
        .is_ok()
    );
    assert!(construct(policy_cfg(true, namespace_policy(2, &ns)), Hooks::new()).is_ok());
    let mut c = policy_cfg(true, namespace_policy(0, &ns));
    c.authorizer_role = AuthorizerRole::Authority;
    let err = construct(c.clone(), Hooks::new()).unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);
    assert_eq!(
        err.public_message(),
        "an authority authorizer must be a real authority source"
    );
    assert!(construct(c, policy_hooks(false)).is_ok());
    assert!(DefaultAdmission.is_default());
    assert!(OpenAuthorizer.is_open());
    assert!(PolicyAdmission::default().is_default());
    assert!(!policy_hooks(false).authorizer.is_open());
}

#[test]
fn defaults_and_advertised_namespace_policy() {
    let ns = Namespace::Ed25519([1; 32]);
    assert_eq!(MultiAddressing::new(), MultiAddressing::default());
    assert_eq!(
        MultiAddressing::new().namespace_policy,
        NamespacePolicy::default()
    );
    for (multi, kind, advertised, write) in [
        (false, 0, "single-repository", WritePolicy::Open),
        (true, 0, "allowlist", WritePolicy::Owner),
        (true, 1, "allowlist", WritePolicy::Owner),
        (true, 2, "any", WritePolicy::Owner),
    ] {
        let c = policy_cfg(multi, namespace_policy(kind, &ns));
        assert_eq!(c.advertised_namespace_policy(), advertised);
        assert_eq!(c.write_policy, write);
        assert_eq!(c.authorizer_role, AuthorizerRole::Check);
    }
}

#[test]
fn non_owner_denial_is_independent_of_repository_existence() {
    let namespace = Namespace::Ed25519([1; 32]);
    let clock = clock();
    let e = build(
        policy_cfg(true, namespace_policy(0, &namespace)),
        Spy::new(store(&clock)),
        policy_hooks(false),
        clock,
    );
    let mut denied = Vec::new();
    for exists in [false, true] {
        let identity = format!("{namespace}/{REPO}");
        let req = Req::unsigned(Procedure::UpdateRef).header("x-repository", &identity);
        let mut auth = e.auth(&req).unwrap();
        if exists {
            auth.principal = Principal::TransportPeer { ed25519: [1; 32] };
            now(e.pipe.update_ref(&auth, upd(HEAD, Any, A))).unwrap();
        }
        e.pipe.meta.batches.lock().unwrap().clear();
        auth.principal = Principal::Signer { ed25519: [2; 32] };
        let err = now(e.pipe.update_ref(&auth, upd(HEAD, Any, B))).unwrap_err();
        denied.push((err.code(), err.public_message().to_owned()));
        assert!(e.pipe.meta.batches.lock().unwrap().is_empty());
        let p = e.pipe.shards.ref_shard(&auth.repo().repo, HEAD);
        assert_eq!(
            now(e
                .pipe
                .meta
                .inner
                .get(&p, &keys::ref_key(&auth.repo().repo.name, HEAD)))
            .unwrap(),
            exists.then(|| codec::encode_ref_id(&A))
        );
    }
    assert_eq!(denied[0], denied[1]);
    assert_eq!(
        denied[0],
        (Code::PermissionDenied, "write not permitted".into())
    );
}

#[test]
fn reads_keep_hook_behavior_and_invalid_multi_namespace_is_internal() {
    let namespace = Namespace::Ed25519([1; 32]);
    let clock = clock();
    let e = build(
        policy_cfg(true, NamespacePolicy::default()),
        Spy::new(store(&clock)),
        policy_hooks(false),
        clock,
    );
    let mut op = Operation::new(
        repo(),
        Principal::Anonymous,
        None,
        OpKind::ReadRef { name: HEAD.into() },
    );
    assert!(now(e.pipe.authorize(&op)).is_ok());
    op.kind = OpKind::UpdateRef(upd(HEAD, Any, A));
    assert_eq!(
        now(e.pipe.authorize(&op)).unwrap_err().code(),
        Code::Internal
    );
    op.repo.namespace = NamespaceKey::from_namespace(&namespace);
    op.creation = Creation {
        namespace: true,
        repo: true,
    };
    assert_eq!(
        now(e.pipe.authorize(&op)).unwrap_err().public_message(),
        "write not permitted"
    );
}
