//! Private-repository read authorization: the uniform `not_found`, the
//! §7 grant checks and the §9.3 decision over the coordinator's `rr`,
//! `rv` and `e` rows (SPEC-WRITE-GRANTS §9).

use super::grants::{config, environment, grant, repository};
use super::*;
use mkit_attest::grant::Capabilities;

const READS: [Procedure; 4] = [
    Procedure::ReadRef,
    Procedure::ListRefs,
    Procedure::PackExists,
    Procedure::DownloadPack,
];

fn repo_id<H: HookSet>(e: &Env<H>, owner: &SigningKey) -> RepoId {
    e.pipe
        .cfg
        .addressing
        .resolve(Some(&repository(owner)), true)
        .unwrap()
        .repo
}

fn put_repo<H: HookSet>(e: &Env<H>, repo: &RepoId, visibility: Option<codec::StoredVisibility>) {
    let mut batch = Batch::new().put(
        keys::repo_record(&repo.name),
        codec::encode_repo_record(&codec::RepoRecord {
            created_at_ms: u64::try_from(T0).unwrap(),
        }),
    );
    if let Some(visibility) = visibility {
        batch = batch.put(
            keys::repo_visibility(&repo.name),
            codec::encode_repo_visibility(&codec::RepoVisibilityV1 {
                visibility,
                last_created_ms: 0,
                last_statement_id: None,
            }),
        );
    }
    let p = e.pipe.shards.coordinator(&repo.namespace);
    assert_eq!(
        now(e.pipe.meta.inner.apply(&p, batch)).unwrap(),
        BatchOutcome::Committed
    );
}

fn put_epoch<H: HookSet>(e: &Env<H>, repo: &RepoId, epoch: u64) {
    let p = e.pipe.shards.coordinator(&repo.namespace);
    assert_eq!(
        now(e.pipe.meta.inner.apply(
            &p,
            Batch::new().put(keys::grant_epoch(), codec::encode_u64(epoch))
        ))
        .unwrap(),
        BatchOutcome::Committed
    );
}

fn signed_read(signer: &SigningKey, repo: &str, procedure: Procedure, grant: Option<&str>) -> Req {
    let req = Req::signed_for(signer, procedure, repo, b"r", &nonce(1), T0);
    match grant {
        Some(header) => req.header("x-write-grant", header),
        None => req,
    }
}

fn anonymous_read(repo: &str, procedure: Procedure) -> Req {
    Req::unsigned(procedure).header("x-repository", repo)
}

fn call<H: HookSet>(
    e: &Env<H>,
    a: &Authenticated,
    procedure: Procedure,
) -> Result<(), ServerError> {
    match procedure {
        Procedure::ReadRef => block_on(e.pipe.read_ref(a, HEAD)).map(drop),
        Procedure::ListRefs => block_on(e.pipe.list_refs(a, "refs/")).map(drop),
        Procedure::PackExists => block_on(e.pipe.pack_exists(a, PackKey::new(A))).map(drop),
        Procedure::DownloadPack => block_on(e.pipe.download(a, PackKey::new(A))).map(drop),
        _ => unreachable!(),
    }
}

fn try_read<H: HookSet>(e: &Env<H>, req: &Req, procedure: Procedure) -> Result<(), ServerError> {
    call(e, &e.auth(req).unwrap(), procedure)
}

fn assert_not_found(err: &ServerError, context: &str) {
    assert_eq!(err.code(), Code::NotFound, "{context}");
    assert_eq!(err.public_message(), "repository not found", "{context}");
    assert!(err.details().is_empty(), "{context}");
    assert!(err.headers().is_empty(), "{context}");
}

/// Served means either a result or an error downstream of the
/// repository's `not_found` (a private read never reaches the latter).
fn assert_served(result: Result<(), ServerError>, context: &str) {
    if let Err(err) = result {
        assert_ne!(err.public_message(), "repository not found", "{context}");
    }
}

#[derive(Clone)]
struct UnavailableAuthorizer;

impl Authorizer for UnavailableAuthorizer {
    async fn authorize(&self, _: &Operation) -> Result<AuthzFacts, ServerError> {
        Err(ServerError::unavailable("authorizer down"))
    }
}

#[derive(Clone)]
struct WriterView;

impl Authorizer for WriterView {
    async fn authorize(&self, _: &Operation) -> Result<AuthzFacts, ServerError> {
        Ok(AuthzFacts {
            caller_view: CallerView::Writer,
            ..AuthzFacts::default()
        })
    }
}

fn env_with<Az: Authorizer>(
    owner: &SigningKey,
    role: AuthorizerRole,
    authorizer: Az,
) -> Env<Hooks<Az>> {
    let defaults = Hooks::new();
    let hooks = Hooks {
        authorizer,
        admission: defaults.admission,
        pre_receive: defaults.pre_receive,
        receipts: defaults.receipts,
        outcomes: defaults.outcomes,
    };
    let clock = clock();
    build(config(owner, role), Spy::new(store(&clock)), hooks, clock)
}

#[test]
fn private_repository_reads_return_the_missing_repository_error() {
    let owner = key(1);
    let stranger = key(2);
    let repo = repository(&owner);
    let env = environment(&owner, AuthorizerRole::Check, false);
    let id = repo_id(&env, &owner);
    for procedure in READS {
        // Measure the missing-repository answer first.
        let missing = try_read(&env, &anonymous_read(&repo, procedure), procedure).unwrap_err();
        assert_not_found(&missing, "missing");
        // The repository exists and is private: anonymous and
        // unauthorized signed callers get byte-for-byte the same answer.
        put_repo(&env, &id, Some(codec::StoredVisibility::Private));
        for (label, req) in [
            ("anonymous", anonymous_read(&repo, procedure)),
            (
                "unauthorized",
                signed_read(&stranger, &repo, procedure, None),
            ),
        ] {
            let denied = try_read(&env, &req, procedure).unwrap_err();
            assert_eq!(
                (
                    denied.code(),
                    denied.public_message(),
                    denied.details(),
                    denied.headers(),
                    denied.http_status()
                ),
                (
                    missing.code(),
                    missing.public_message(),
                    missing.details(),
                    missing.headers(),
                    missing.http_status()
                ),
                "{procedure:?} {label}"
            );
        }
    }
}

#[test]
fn private_repository_reads_allow_authorized_callers() {
    let owner = key(1);
    let grantee = key(2);
    let stranger = key(3);
    let repo = repository(&owner);
    let env = environment(&owner, AuthorizerRole::Check, false);
    let id = repo_id(&env, &owner);
    put_repo(&env, &id, Some(codec::StoredVisibility::Private));
    let read_grant = grant(&owner, &grantee, |g| {
        g.capabilities = Capabilities::Read;
        g.ref_scopes = None;
    });
    let write_grant = grant(&owner, &stranger, |_| {});
    for procedure in READS {
        for (label, req) in [
            ("owner", signed_read(&owner, &repo, procedure, None)),
            (
                "read grant",
                signed_read(&grantee, &repo, procedure, Some(read_grant.as_str())),
            ),
        ] {
            assert_served(
                try_read(&env, &req, procedure),
                &format!("{procedure:?} {label}"),
            );
        }
        let err = try_read(
            &env,
            &signed_read(&stranger, &repo, procedure, Some(write_grant.as_str())),
            procedure,
        )
        .unwrap_err();
        assert_not_found(&err, "write-only grant");
    }
}

#[test]
fn private_read_grant_epoch_must_match_stored() {
    let owner = key(1);
    let grantee = key(2);
    let repo = repository(&owner);
    let env = environment(&owner, AuthorizerRole::Check, false);
    let id = repo_id(&env, &owner);
    put_repo(&env, &id, Some(codec::StoredVisibility::Private));
    put_epoch(&env, &id, 1);
    let read_grant = |epoch: u64| {
        grant(&owner, &grantee, |g| {
            g.capabilities = Capabilities::Read;
            g.ref_scopes = None;
            g.epoch = epoch;
        })
    };
    // The grant's epoch 0 does not match the stored epoch 1 (§7 step 11).
    let stale = read_grant(0);
    let err = try_read(
        &env,
        &signed_read(&grantee, &repo, Procedure::ReadRef, Some(stale.as_str())),
        Procedure::ReadRef,
    )
    .unwrap_err();
    assert_not_found(&err, "stale epoch");
    assert_served(
        try_read(
            &env,
            &signed_read(
                &grantee,
                &repo,
                Procedure::ReadRef,
                Some(read_grant(1).as_str()),
            ),
            Procedure::ReadRef,
        ),
        "matching epoch",
    );
}

#[test]
fn public_repository_reads_stay_public() {
    let owner = key(1);
    let stranger = key(2);
    let repo = repository(&owner);
    let env = environment(&owner, AuthorizerRole::Check, false);
    let id = repo_id(&env, &owner);
    for visibility in [None, Some(codec::StoredVisibility::Public)] {
        put_repo(&env, &id, visibility);
        for procedure in READS {
            assert_served(
                try_read(&env, &anonymous_read(&repo, procedure), procedure),
                &format!("{visibility:?} {procedure:?} anonymous"),
            );
            // A grant that fails verification only loses the caller its
            // classification; it never fails a public read.
            assert_served(
                try_read(
                    &env,
                    &signed_read(&stranger, &repo, procedure, Some("junk.header")),
                    procedure,
                ),
                &format!("{visibility:?} {procedure:?} bad grant"),
            );
        }
    }
}

#[test]
fn private_read_hook_errors_hide_the_repository() {
    let owner = key(1);
    let repo = repository(&owner);
    // The hook denies: the private read still reports `not_found`.
    let env = environment(&owner, AuthorizerRole::Check, true);
    let id = repo_id(&env, &owner);
    put_repo(&env, &id, Some(codec::StoredVisibility::Private));
    for procedure in READS {
        let err = try_read(
            &env,
            &signed_read(&owner, &repo, procedure, None),
            procedure,
        )
        .unwrap_err();
        assert_not_found(&err, "denied");
    }
    // The hook is `unavailable`: same answer, never the raw error.
    let env = env_with(&owner, AuthorizerRole::Check, UnavailableAuthorizer);
    let id = repo_id(&env, &owner);
    put_repo(&env, &id, Some(codec::StoredVisibility::Private));
    let err = try_read(
        &env,
        &signed_read(&owner, &repo, Procedure::ReadRef, None),
        Procedure::ReadRef,
    )
    .unwrap_err();
    assert_not_found(&err, "unavailable");
    // On a public repository the same hook error propagates unchanged
    // under the Check role.
    let p = env.pipe.shards.coordinator(&id.namespace);
    assert_eq!(
        now(env
            .pipe
            .meta
            .inner
            .apply(&p, Batch::new().delete(keys::repo_visibility(&id.name))))
        .unwrap(),
        BatchOutcome::Committed
    );
    let err = try_read(
        &env,
        &anonymous_read(&repo, Procedure::ReadRef),
        Procedure::ReadRef,
    )
    .unwrap_err();
    assert_eq!(err.code(), Code::Unavailable);
}

#[test]
fn authority_hook_can_authorize_a_private_read() {
    let owner = key(1);
    let stranger = key(2);
    let repo = repository(&owner);
    // Authority role: the hook's verdict grants the private read.
    let env = env_with(&owner, AuthorizerRole::Authority, WriterView);
    let id = repo_id(&env, &owner);
    put_repo(&env, &id, Some(codec::StoredVisibility::Private));
    assert_served(
        try_read(
            &env,
            &signed_read(&stranger, &repo, Procedure::ReadRef, None),
            Procedure::ReadRef,
        ),
        "authority allows",
    );
    // Check role: the same answer from the hook cannot authorize.
    let env = env_with(&owner, AuthorizerRole::Check, WriterView);
    let id = repo_id(&env, &owner);
    put_repo(&env, &id, Some(codec::StoredVisibility::Private));
    let err = try_read(
        &env,
        &signed_read(&stranger, &repo, Procedure::ReadRef, None),
        Procedure::ReadRef,
    )
    .unwrap_err();
    assert_not_found(&err, "check role");
}

#[test]
fn private_read_needs_no_hook_when_unsigned() {
    let owner = key(1);
    let repo = repository(&owner);
    let env = environment(&owner, AuthorizerRole::Check, false);
    let id = repo_id(&env, &owner);
    put_repo(&env, &id, Some(codec::StoredVisibility::Private));
    let err = try_read(
        &env,
        &anonymous_read(&repo, Procedure::ReadRef),
        Procedure::ReadRef,
    )
    .unwrap_err();
    assert_not_found(&err, "anonymous");
    // One coordinator `get_many` for `rr`, `rv` and `e`; no hook call and
    // no ref-shard read.
    assert_eq!(env.pipe.meta.ops(), ["get_many"]);
    assert_eq!(
        env.pipe.meta.seen(),
        [
            keys::repo_record(&id.name),
            keys::repo_visibility(&id.name),
            keys::grant_epoch(),
        ]
    );
    assert!(env.pipe.hooks.authorizer().seen.lock().unwrap().is_empty());
}

#[test]
fn repository_state_failure_is_unavailable_not_public() {
    let owner = key(1);
    let repo = repository(&owner);
    let clock = clock();
    let env = build(
        config(&owner, AuthorizerRole::Check),
        Spy::new(store(&clock)).failing_reads(),
        Hooks::new(),
        clock,
    );
    for procedure in READS {
        let err = try_read(&env, &anonymous_read(&repo, procedure), procedure).unwrap_err();
        assert_eq!(err.code(), Code::Unavailable, "{procedure:?}");
        assert_eq!(err.public_message(), "repository state unavailable");
    }
}

#[test]
fn visibility_row_without_repository_record_is_missing() {
    let owner = key(1);
    let repo = repository(&owner);
    let env = environment(&owner, AuthorizerRole::Check, false);
    let id = repo_id(&env, &owner);
    // `rv` alone does not make the repository exist, even for its owner.
    let p = env.pipe.shards.coordinator(&id.namespace);
    assert_eq!(
        now(env.pipe.meta.inner.apply(
            &p,
            Batch::new().put(
                keys::repo_visibility(&id.name),
                codec::encode_repo_visibility(&codec::RepoVisibilityV1 {
                    visibility: codec::StoredVisibility::Private,
                    last_created_ms: 0,
                    last_statement_id: None,
                }),
            ),
        ))
        .unwrap(),
        BatchOutcome::Committed
    );
    for procedure in READS {
        let err = try_read(
            &env,
            &signed_read(&owner, &repo, procedure, None),
            procedure,
        )
        .unwrap_err();
        assert_not_found(&err, "rv without rr");
    }
}
