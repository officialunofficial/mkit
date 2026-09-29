//! Grant authorization before any allocation, over the real pipeline.

use super::*;
use crate::pipeline::tests::policy::{PolicyHook, policy_hooks};
use crate::repo::MultiAddressing;
use mkit_attest::grant::{
    AcceptedSchemes, Capabilities, Grant, OwnerScheme, RefScopes, RepoScope, SignedHeader,
};
use mkit_core::repo_identity::{Namespace, RepositoryIdentity};

pub(super) fn config(owner: &SigningKey, role: AuthorizerRole) -> PipelineConfig {
    let namespace = Namespace::Ed25519(*owner.verifying_key().as_bytes());
    let mut c = cfg(authv2());
    c.addressing = Addressing::Multi(
        MultiAddressing::new()
            .with_namespace_policy(NamespacePolicy::Allowlist([namespace].into())),
    );
    c.write_policy = WritePolicy::Owner;
    c.authorizer_role = role;
    c.grants = Some(
        GrantConfig::new(
            AUDIENCE,
            AcceptedSchemes::of(&[OwnerScheme::Ed25519]),
            vec![],
        )
        .unwrap(),
    );
    c
}

pub(super) fn repository(owner: &SigningKey) -> String {
    format!(
        "{}/{REPO}",
        Namespace::Ed25519(*owner.verifying_key().as_bytes())
    )
}

pub(super) fn grant(
    owner: &SigningKey,
    grantee: &SigningKey,
    mutate: impl FnOnce(&mut Grant),
) -> String {
    let repo = repository(owner);
    let mut grant = Grant {
        namespace: Namespace::Ed25519(*owner.verifying_key().as_bytes()),
        scope: RepoScope::Repository(RepositoryIdentity::parse(&repo).unwrap()),
        grantee: *grantee.verifying_key().as_bytes(),
        capabilities: Capabilities::Write,
        audiences: vec![AUDIENCE.into()],
        ref_scopes: Some(RefScopes::parse("refs/heads/main=cuf").unwrap()),
        epoch: 0,
        created_ms: T0 - 1000,
        expiry_ms: T0 + 100_000,
        nonce: [7; 32],
    };
    mutate(&mut grant);
    let statement = grant.encode().unwrap();
    let signature = owner.sign(&hash(&statement));
    SignedHeader {
        statement,
        scheme: OwnerScheme::Ed25519,
        blob: signature.to_bytes().to_vec(),
    }
    .encode()
    .unwrap()
}

pub(super) fn request(signer: &SigningKey, repo: &str, nonce: u32, header: Option<&str>) -> Req {
    let update = upd(HEAD, Any, A);
    let body = format!("{update:?}").into_bytes();
    let digest = to_hex(&hash(&body));
    let nonce = super::nonce(nonce);
    let op = SignedOp {
        context: AuthContext {
            audience: AUDIENCE,
            repository: repo,
        },
        procedure: Procedure::UpdateRef.connect_path(),
        commitment: &format!("body:{digest}"),
        created_at: T0,
        expires_at: T0 + 300_000,
        nonce: &nonce,
    };
    let signature = signer.sign(&op.digest().unwrap());
    let mut req = Req::unsigned(Procedure::UpdateRef);
    req.body = body;
    for (name, value) in [
        ("x-envelope-version", "2".to_owned()),
        ("x-audience", AUDIENCE.to_owned()),
        ("x-repository", repo.to_owned()),
        ("x-public-key", to_hex(signer.verifying_key().as_bytes())),
        ("x-signature", to_hex_bytes(&signature.to_bytes())),
        ("x-content-commitment", format!("body:{digest}")),
        ("x-digest", digest),
        ("x-created-at", T0.to_string()),
        ("x-expires-at", (T0 + 300_000).to_string()),
        ("idempotency-key", nonce),
    ] {
        req = req.header(name, &value);
    }
    if let Some(header) = header {
        req = req.header("x-write-grant", header);
    }
    req
}

pub(super) fn environment(
    owner: &SigningKey,
    role: AuthorizerRole,
    deny: bool,
) -> Env<Hooks<PolicyHook, super::policy::PolicyAdmission>> {
    environment_sharding(owner, role, deny, Sharding::Single)
}

pub(super) fn environment_sharding(
    owner: &SigningKey,
    role: AuthorizerRole,
    deny: bool,
    sharding: Sharding,
) -> Env<Hooks<PolicyHook, super::policy::PolicyAdmission>> {
    let clock = clock();
    let mut c = config(owner, role);
    c.sharding = sharding;
    build(c, Spy::new(store(&clock)), policy_hooks(deny), clock)
}

pub(super) fn assert_no_rows<H: HookSet>(e: &Env<H>, owner: &SigningKey) {
    assert!(e.pipe.meta.batches.lock().unwrap().is_empty());
    let repo = e
        .pipe
        .cfg
        .addressing
        .resolve(Some(&repository(owner)), true)
        .unwrap()
        .repo;
    for p in [
        e.pipe.shards.coordinator(&repo.namespace),
        e.pipe.shards.ref_shard(&repo, HEAD),
    ] {
        assert_eq!(now(e.pipe.meta.inner.stats(&p)).unwrap().keys, Some(0));
    }
}

#[test]
fn bad_grant_allocates_nothing_and_same_nonce_can_be_corrected() {
    let owner = key(1);
    let grantee = key(2);
    let repo = repository(&owner);
    let e = environment(&owner, AuthorizerRole::Check, false);
    let bad = grant(&owner, &grantee, |g| {
        g.audiences = vec!["https://other.example.test".into()];
    });
    let signed = request(&grantee, &repo, 1, Some(&bad));
    assert_eq!(
        e.update(&signed, &upd(HEAD, Any, A)).unwrap_err().code(),
        Code::PermissionDenied
    );
    assert_no_rows(&e, &owner);

    let good = grant(&owner, &grantee, |_| {});
    let corrected = request(&grantee, &repo, 1, Some(&good));
    assert!(e.update(&corrected, &upd(HEAD, Any, A)).is_ok());
    let seen = e.pipe.hooks.authorizer().seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert!(!seen[0].authz.owner);
    assert!(seen[0].authz.grant.is_some());
}

#[test]
fn grant_rejection_matrix_allocates_nothing() {
    let owner = key(1);
    let grantee = key(2);
    let repo = repository(&owner);
    let cases = [
        ("malformed", "malformed".to_owned()),
        (
            "audience",
            grant(&owner, &grantee, |g| {
                g.audiences = vec!["https://wrong.example".into()];
            }),
        ),
        (
            "scope",
            grant(&owner, &grantee, |g| {
                g.ref_scopes = Some(RefScopes::parse("refs/tags/*=cuf").unwrap());
            }),
        ),
        (
            "signer",
            grant(&owner, &grantee, |g| g.grantee = [0x44; 32]),
        ),
        (
            "capability",
            grant(&owner, &grantee, |g| {
                g.capabilities = Capabilities::Read;
                g.ref_scopes = None;
            }),
        ),
        ("epoch", grant(&owner, &grantee, |g| g.epoch = 1)),
        (
            "expired",
            grant(&owner, &grantee, |g| {
                g.created_ms = T0 - 60_000;
                g.expiry_ms = T0;
            }),
        ),
        (
            "future",
            grant(&owner, &grantee, |g| {
                g.created_ms = T0 + 30_001;
                g.expiry_ms = T0 + 90_001;
            }),
        ),
    ];
    for sharding in [Sharding::Single, Sharding::D34] {
        for (label, header) in &cases {
            let e = environment_sharding(&owner, AuthorizerRole::Check, false, sharding);
            let error = e
                .update(
                    &request(&grantee, &repo, 11, Some(header)),
                    &upd(HEAD, Any, A),
                )
                .unwrap_err();
            assert_eq!(error.code(), Code::PermissionDenied, "{sharding:?} {label}");
            assert_no_rows(&e, &owner);
        }
    }
}

#[test]
fn grant_created_at_lead_inclusive() {
    let owner = key(1);
    let grantee = key(2);
    let repo = repository(&owner);
    let header = grant(&owner, &grantee, |g| {
        g.created_ms = T0 + 30_000;
        g.expiry_ms = T0 + 90_000;
    });
    let e = environment(&owner, AuthorizerRole::Check, false);
    assert!(
        e.update(
            &request(&grantee, &repo, 12, Some(&header)),
            &upd(HEAD, Any, A)
        )
        .is_ok()
    );
}

#[test]
fn grant_only_path_and_hook_composition() {
    let owner = key(1);
    let grantee = key(2);
    let repo = repository(&owner);
    let valid = grant(&owner, &grantee, |_| {});
    let bad = "malformed";

    let e = environment(&owner, AuthorizerRole::Authority, false);
    assert_eq!(
        e.update(&request(&grantee, &repo, 2, Some(bad)), &upd(HEAD, Any, A))
            .unwrap_err()
            .code(),
        Code::PermissionDenied
    );
    assert_no_rows(&e, &owner);
    assert!(e.pipe.hooks.authorizer().seen.lock().unwrap().is_empty());

    let e = environment(&owner, AuthorizerRole::Check, false);
    assert_eq!(
        e.update(&request(&owner, &repo, 3, Some(bad)), &upd(HEAD, Any, A))
            .unwrap_err()
            .code(),
        Code::PermissionDenied
    );
    assert_no_rows(&e, &owner);
    assert!(
        e.update(&request(&owner, &repo, 3, None), &upd(HEAD, Any, A))
            .is_ok()
    );

    let e = environment(&owner, AuthorizerRole::Check, true);
    assert_eq!(
        e.update(
            &request(&grantee, &repo, 4, Some(&valid)),
            &upd(HEAD, Any, A)
        )
        .unwrap_err()
        .public_message(),
        "hook denial"
    );
    assert_no_rows(&e, &owner);
    let seen = e.pipe.hooks.authorizer().seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert!(!seen[0].authz.owner && seen[0].authz.grant.is_some());
}

#[cfg(feature = "test-faults")]
struct BumpAtAuthorize {
    store: Arc<MemoryKv>,
    partition: Partition,
    fired: AtomicBool,
}

#[cfg(feature = "test-faults")]
impl FaultHooks for BumpAtAuthorize {
    async fn at(
        &self,
        point: FaultPoint,
        _: &Operation,
        _: &TestDirectives,
    ) -> Result<(), ServerError> {
        if point == FaultPoint::AfterAuthorize && !self.fired.swap(true, Ordering::SeqCst) {
            self.store
                .apply(
                    &self.partition,
                    Batch::new().put(keys::grant_epoch(), codec::encode_u64(1)),
                )
                .await
                .unwrap();
        }
        Ok(())
    }
}

#[cfg(feature = "test-faults")]
#[test]
fn epoch_change_after_authorize_commits_no_write_state() {
    let owner = key(1);
    let grantee = key(2);
    let repo = repository(&owner);
    let valid = grant(&owner, &grantee, |_| {});
    for sharding in [Sharding::Single, Sharding::D34] {
        let Env {
            pipe,
            clock,
            metrics,
        } = environment_sharding(&owner, AuthorizerRole::Check, false, sharding);
        let resolved = pipe.cfg.addressing.resolve(Some(&repo), true).unwrap();
        let p = pipe.shards.coordinator(&resolved.repo.namespace);
        let store = pipe.meta.inner.clone();
        let pipe = pipe.with_faults(BumpAtAuthorize {
            store,
            partition: p.clone(),
            fired: AtomicBool::new(false),
        });
        let e = Env {
            pipe,
            clock,
            metrics,
        };
        let err = e
            .update(
                &request(&grantee, &repo, 10, Some(&valid)),
                &upd(HEAD, Any, A),
            )
            .unwrap_err();
        assert_eq!(err.code(), Code::PermissionDenied);
        assert_eq!(
            err.public_message(),
            "write grant epoch changed; re-authorize"
        );
        assert_eq!(
            now(e.pipe.meta.inner.get(&p, &keys::grant_epoch())).unwrap(),
            Some(codec::encode_u64(1))
        );
        assert_eq!(
            now(e.pipe.meta.inner.get(&p, &keys::epoch_lease())).unwrap(),
            None
        );
        let shard = e.pipe.shards.ref_shard(&resolved.repo, HEAD);
        assert_eq!(
            now(e.pipe.meta.inner.stats(&shard)).unwrap().keys,
            if sharding == Sharding::Single {
                Some(1)
            } else {
                Some(0)
            },
            "{sharding:?}"
        );
    }
}

fn k1_namespace(owner: &k256::ecdsa::SigningKey) -> Namespace {
    let point = owner.verifying_key().to_sec1_point(false);
    Namespace::Address(
        mkit_attest::eth::address_secp256k1(&point.as_bytes()[1..].try_into().unwrap()).unwrap(),
    )
}

fn k1_config(policy: NamespacePolicy) -> PipelineConfig {
    let mut c = cfg(authv2());
    c.addressing = Addressing::Multi(MultiAddressing::new().with_namespace_policy(policy));
    c.write_policy = WritePolicy::Owner;
    c.authorizer_role = AuthorizerRole::Check;
    c.grants = Some(
        GrantConfig::new(
            AUDIENCE,
            AcceptedSchemes::of(&[OwnerScheme::Ed25519, OwnerScheme::Secp256k1Eip191]),
            vec![],
        )
        .unwrap(),
    );
    c
}

fn k1_grant(owner: &k256::ecdsa::SigningKey, repo: &str, grantee: &SigningKey) -> String {
    let statement = Grant {
        namespace: k1_namespace(owner),
        scope: RepoScope::Repository(RepositoryIdentity::parse(repo).unwrap()),
        grantee: *grantee.verifying_key().as_bytes(),
        capabilities: Capabilities::Write,
        audiences: vec![AUDIENCE.into()],
        ref_scopes: Some(RefScopes::parse("refs/heads/main=cuf").unwrap()),
        epoch: 0,
        created_ms: T0 - 1000,
        expiry_ms: T0 + 100_000,
        nonce: [9; 32],
    }
    .encode()
    .unwrap();
    let (signature, recovery) =
        owner.sign_prehash_recoverable(&mkit_attest::eth::eip191_hash(&statement));
    let mut blob = signature.to_bytes().to_vec();
    blob.push(27 + recovery.to_byte());
    SignedHeader {
        statement,
        scheme: OwnerScheme::Secp256k1Eip191,
        blob,
    }
    .encode()
    .unwrap()
}

/// The `0x` path through the server: an allowlisted address namespace takes a
/// write only with a valid EIP-191 grant, and never under an `Any` policy.
#[test]
fn zero_x_namespace_takes_writes_only_through_an_eip191_grant() {
    let owner = k256::ecdsa::SigningKey::from_slice(&[0x21; 32]).unwrap();
    let namespace = k1_namespace(&owner);
    let repo = format!("{namespace}/{REPO}");
    let grantee = key(2);
    let header = k1_grant(&owner, &repo, &grantee);
    let allow = || {
        let clock = clock();
        build(
            k1_config(NamespacePolicy::Allowlist([namespace].into())),
            Spy::new(store(&clock)),
            policy_hooks(false),
            clock,
        )
    };

    let e = allow();
    assert!(
        e.update(
            &request(&grantee, &repo, 21, Some(&header)),
            &upd(HEAD, Any, A)
        )
        .is_ok()
    );
    let seen = e.pipe.hooks.authorizer().seen.lock().unwrap();
    assert!(!seen[0].authz.owner);
    assert!(seen[0].authz.grant.is_some());
    drop(seen);

    let e = allow();
    assert_eq!(
        e.update(&request(&grantee, &repo, 22, None), &upd(HEAD, Any, A))
            .unwrap_err()
            .code(),
        Code::PermissionDenied
    );
    assert!(e.pipe.meta.batches.lock().unwrap().is_empty());

    let clock = clock();
    let e = build(
        k1_config(NamespacePolicy::Any {
            unsafe_without_admission: true,
        }),
        Spy::new(store(&clock)),
        policy_hooks(false),
        clock,
    );
    assert_eq!(
        e.update(
            &request(&grantee, &repo, 23, Some(&header)),
            &upd(HEAD, Any, A)
        )
        .unwrap_err()
        .code(),
        Code::PermissionDenied
    );
    assert!(e.pipe.meta.batches.lock().unwrap().is_empty());
}

/// A grant header is ignored, unparsed, under Single addressing and `Open`.
#[test]
fn single_open_ignores_the_grant_header() {
    let clock = clock();
    let e = build(
        cfg(authv2()),
        Spy::new(store(&clock)),
        policy_hooks(false),
        clock,
    );
    assert!(
        e.update(
            &request(&key(2), REPO, 24, Some("malformed")),
            &upd(HEAD, Any, A)
        )
        .is_ok()
    );
}

/// Multi/Owner without a grant configuration denies any grant header.
#[test]
fn grant_header_without_grant_config_is_denied() {
    let owner = key(1);
    let grantee = key(2);
    let repo = repository(&owner);
    let clock = clock();
    let mut c = config(&owner, AuthorizerRole::Check);
    c.grants = None;
    let e = build(c, Spy::new(store(&clock)), policy_hooks(false), clock);
    let header = grant(&owner, &grantee, |_| {});
    let error = e
        .update(
            &request(&grantee, &repo, 25, Some(&header)),
            &upd(HEAD, Any, A),
        )
        .unwrap_err();
    assert_eq!(error.code(), Code::PermissionDenied);
    assert_no_rows(&e, &owner);
}
