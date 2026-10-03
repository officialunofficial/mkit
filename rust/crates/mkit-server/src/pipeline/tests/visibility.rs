//! Private-repository read authorization: the uniform `not_found`, the
//! §7 grant checks and the §9.3 decision over the coordinator's `rr`,
//! `rv` and `e` rows (SPEC-WRITE-GRANTS §9).

use super::grants::{config, environment, grant, repository, request};
use super::*;
use mkit_attest::grant::{
    Capabilities, OwnerScheme, SignedHeader, Visibility, VisibilityStatement,
};
use mkit_core::repo_identity::RepositoryIdentity;

const READS: [Procedure; 4] = [
    Procedure::ReadRef,
    Procedure::ListRefs,
    Procedure::PackExists,
    Procedure::DownloadPack,
];

pub(super) fn repo_id<H: HookSet>(e: &Env<H>, owner: &SigningKey) -> RepoId {
    e.pipe
        .cfg
        .addressing
        .resolve(Some(&repository(owner)), true)
        .unwrap()
        .repo
}

pub(super) fn put_repo<H: HookSet>(
    e: &Env<H>,
    repo: &RepoId,
    visibility: Option<codec::StoredVisibility>,
) {
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
                changed_ms: None,
            }),
        );
    }
    let p = e.pipe.shards.coordinator(&repo.namespace);
    assert_eq!(
        now(e.pipe.meta.inner.apply(&p, batch)).unwrap(),
        BatchOutcome::Committed
    );
}

pub(super) fn put_epoch<H: HookSet>(e: &Env<H>, repo: &RepoId, epoch: u64) {
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

pub(super) fn assert_not_found(err: &ServerError, context: &str) {
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
fn a_signed_read_writes_no_replay_rows() {
    // SPEC-WRITE-GRANTS §9.2: a signed read verifies in full but keeps no
    // replay ledger — no `p` or `px` row, ever.
    let owner = key(1);
    let repo = repository(&owner);
    let e = environment(&owner, AuthorizerRole::Check, false);
    let id = repo_id(&e, &owner);
    put_repo(&e, &id, Some(codec::StoredVisibility::Private));
    assert_eq!(e.count("p"), 0);
    assert_eq!(e.count("px"), 0);
    for procedure in READS {
        assert_served(
            try_read(&e, &signed_read(&owner, &repo, procedure, None), procedure),
            &format!("{procedure:?} owner"),
        );
    }
    assert_eq!(e.count("p"), 0);
    assert_eq!(e.count("px"), 0);
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
                    changed_ms: None,
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

// ----------------------------------------------------- SetRepoVisibility

pub(super) fn set<H: HookSet>(
    e: &Env<H>,
    req: &Req,
    mode: VisibilityRequest,
) -> Result<(), ServerError> {
    let a = e.auth(req).unwrap();
    block_on(e.pipe.set_repo_visibility(&a, mode))
}

pub(super) fn signed_visibility(signer: &SigningKey, repo: &str, n: u32, body: &[u8]) -> Req {
    Req::signed_for(
        signer,
        Procedure::SetRepoVisibility,
        repo,
        body,
        &nonce(n),
        T0,
    )
}

pub(super) fn unsigned_visibility(repo: &str) -> Req {
    Req::unsigned(Procedure::SetRepoVisibility).header("x-repository", repo)
}

/// The canonical `ed25519:<scheme>` signed header for a visibility
/// statement, and the statement id the `rv` row records.
pub(super) fn statement(
    owner: &SigningKey,
    repo: &str,
    visibility: Visibility,
    created_ms: i64,
    nonce: [u8; 32],
) -> (String, String) {
    let statement = VisibilityStatement {
        repository: RepositoryIdentity::parse(repo).unwrap(),
        visibility,
        audiences: vec![AUDIENCE.into()],
        created_ms,
        expiry_ms: created_ms + 60_000,
        nonce,
    };
    let id = to_hex(&statement.id().unwrap());
    let bytes = statement.encode().unwrap();
    let signature = owner.sign(&hash(&bytes));
    let header = SignedHeader {
        statement: bytes,
        scheme: OwnerScheme::Ed25519,
        blob: signature.to_bytes().to_vec(),
    }
    .encode()
    .unwrap();
    (header, id)
}

pub(super) fn stored_visibility_row<H: HookSet>(
    e: &Env<H>,
    id: &RepoId,
) -> codec::RepoVisibilityV1 {
    let p = e.pipe.shards.coordinator(&id.namespace);
    now(e.pipe.meta.inner.get(&p, &keys::repo_visibility(&id.name)))
        .unwrap()
        .map(|v| codec::decode_repo_visibility(&v).unwrap())
        .unwrap()
}

#[test]
fn envelope_owner_sets_private_and_reads_enforce_it() {
    let owner = key(1);
    let repo = repository(&owner);
    let e = environment(&owner, AuthorizerRole::Check, false);
    let id = repo_id(&e, &owner);
    put_repo(&e, &id, None);
    set(
        &e,
        &signed_visibility(&owner, &repo, 1, b"v"),
        VisibilityRequest::Envelope(Visibility::Private),
    )
    .unwrap();
    assert_eq!(
        stored_visibility_row(&e, &id).visibility,
        codec::StoredVisibility::Private
    );
    let err = try_read(
        &e,
        &anonymous_read(&repo, Procedure::ReadRef),
        Procedure::ReadRef,
    )
    .unwrap_err();
    assert_not_found(&err, "anonymous after private");
    assert_served(
        try_read(
            &e,
            &signed_read(&owner, &repo, Procedure::ReadRef, None),
            Procedure::ReadRef,
        ),
        "owner reads a private repo",
    );
}

#[test]
fn envelope_writes_rv_replay_and_expiry_index() {
    let owner = key(1);
    let repo = repository(&owner);
    let e = environment(&owner, AuthorizerRole::Check, false);
    let id = repo_id(&e, &owner);
    set(
        &e,
        &signed_visibility(&owner, &repo, 2, b"v"),
        VisibilityRequest::Envelope(Visibility::Private),
    )
    .unwrap();
    let batches = e.pipe.meta.batches.lock().unwrap();
    assert_eq!(batches.len(), 1);
    let puts: Vec<_> = batches[0]
        .writes
        .iter()
        .filter_map(|w| match w {
            Write::Put(k, _) => Some(k),
            Write::Delete(_) => None,
        })
        .collect();
    let classes: Vec<_> = puts.iter().map(|k| keys::parse(k)).collect();
    assert!(
        matches!(
            classes.as_slice(),
            [
                Some(keys::ParsedKey::RepoVisibility(_)),
                Some(keys::ParsedKey::Replay(_)),
                Some(keys::ParsedKey::ReplayExpiry { .. }),
            ]
        ),
        "{classes:?}"
    );
    drop(batches);
    // Nothing else: no `rr`/`rk` was written for the missing repository.
    let p = e.pipe.shards.coordinator(&id.namespace);
    assert_eq!(now(e.pipe.meta.inner.stats(&p)).unwrap().keys, Some(3));
    assert!(
        now(e.pipe.meta.inner.get(&p, &keys::repo_record(&id.name)))
            .unwrap()
            .is_none()
    );
}

#[test]
fn envelope_replay_returns_and_a_reused_nonce_rejects() {
    let owner = key(1);
    let repo = repository(&owner);
    let e = environment(&owner, AuthorizerRole::Check, false);
    let req = signed_visibility(&owner, &repo, 3, b"v");
    set(&e, &req, VisibilityRequest::Envelope(Visibility::Private)).unwrap();
    // The same nonce and body is the committed operation's answer.
    set(&e, &req, VisibilityRequest::Envelope(Visibility::Private)).unwrap();
    // The same nonce over a different body is a different operation.
    let err = set(
        &e,
        &signed_visibility(&owner, &repo, 3, b"w"),
        VisibilityRequest::Envelope(Visibility::Public),
    )
    .unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);
    assert_eq!(
        err.public_message(),
        "nonce reused for a different operation"
    );
}

#[test]
fn envelope_needs_the_owner_and_never_a_grant() {
    let owner = key(1);
    let stranger = key(2);
    let repo = repository(&owner);
    let e = environment(&owner, AuthorizerRole::Check, false);
    let err = set(
        &e,
        &signed_visibility(&stranger, &repo, 4, b"v"),
        VisibilityRequest::Envelope(Visibility::Private),
    )
    .unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied);
    assert_eq!(err.public_message(), "SetRepoVisibility not permitted");
    // A grant header never authorizes a visibility change.
    let header = grant(&owner, &stranger, |_| {});
    let req = signed_visibility(&owner, &repo, 5, b"v").header("x-write-grant", &header);
    let err = set(&e, &req, VisibilityRequest::Envelope(Visibility::Private)).unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied);
    assert_eq!(
        err.public_message(),
        "a grant never authorizes SetRepoVisibility"
    );
}

#[test]
fn statement_mode_keeps_the_newest_statement() {
    let owner = key(1);
    let repo = repository(&owner);
    let e = environment(&owner, AuthorizerRole::Check, false);
    let id = repo_id(&e, &owner);
    let (first, first_id) = statement(&owner, &repo, Visibility::Private, T0, [1; 32]);
    set(
        &e,
        &unsigned_visibility(&repo),
        VisibilityRequest::Statement(first.clone()),
    )
    .unwrap();
    let row = stored_visibility_row(&e, &id);
    assert_eq!(row.visibility, codec::StoredVisibility::Private);
    assert_eq!(row.last_created_ms, u64::try_from(T0).unwrap());
    assert_eq!(row.last_statement_id.as_deref(), Some(first_id.as_str()));
    let applies = e.pipe.meta.batches.lock().unwrap().len();
    // The identical statement is idempotent: Ok, no write.
    set(
        &e,
        &unsigned_visibility(&repo),
        VisibilityRequest::Statement(first),
    )
    .unwrap();
    assert_eq!(e.pipe.meta.batches.lock().unwrap().len(), applies);
    for (label, created, nonce) in [
        ("older", T0 - 1, [2; 32]),
        ("same created, other id", T0, [3; 32]),
    ] {
        let (stmt, _) = statement(&owner, &repo, Visibility::Public, created, nonce);
        let err = set(
            &e,
            &unsigned_visibility(&repo),
            VisibilityRequest::Statement(stmt),
        )
        .unwrap_err();
        assert_eq!(err.code(), Code::PermissionDenied, "{label}");
        assert_eq!(
            err.public_message(),
            "visibility statement rejected: not newer than the stored statement"
        );
    }
    let (newer, newer_id) = statement(&owner, &repo, Visibility::Public, T0 + 1, [4; 32]);
    set(
        &e,
        &unsigned_visibility(&repo),
        VisibilityRequest::Statement(newer),
    )
    .unwrap();
    let row = stored_visibility_row(&e, &id);
    assert_eq!(row.visibility, codec::StoredVisibility::Public);
    assert_eq!(row.last_created_ms, u64::try_from(T0).unwrap() + 1);
    assert_eq!(row.last_statement_id.as_deref(), Some(newer_id.as_str()));
}

#[test]
fn statement_mode_rejects_mismatch_oversize_and_signed_requests() {
    let owner = key(1);
    let repo = repository(&owner);
    let e = environment(&owner, AuthorizerRole::Check, false);
    // The statement names another repository than X-Repository.
    let (stmt, _) = statement(&owner, &repo, Visibility::Private, T0, [5; 32]);
    let other = format!(
        "{}/other-room",
        Namespace::Ed25519(*owner.verifying_key().as_bytes())
    );
    let err = set(
        &e,
        &unsigned_visibility(&other),
        VisibilityRequest::Statement(stmt),
    )
    .unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied);
    // Oversize is rejected before parsing.
    let err = set(
        &e,
        &unsigned_visibility(&repo),
        VisibilityRequest::Statement("x".repeat(mkit_attest::grant::MAX_GRANT_HEADER_BYTES + 1)),
    )
    .unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied);
    assert_eq!(
        err.public_message(),
        "visibility statement rejected: too long"
    );
    // A statement on a signed request is an argument error, not auth.
    let err = set(
        &e,
        &signed_visibility(&owner, &repo, 6, b"v"),
        VisibilityRequest::Statement("x".into()),
    )
    .unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);
}

#[test]
fn statement_mode_needs_owner_schemes() {
    let owner = key(1);
    let repo = repository(&owner);
    let clock = clock();
    let mut c = config(&owner, AuthorizerRole::Check);
    c.grants = None;
    let e = build(c, Spy::new(store(&clock)), Hooks::new(), clock);
    let (stmt, _) = statement(&owner, &repo, Visibility::Private, T0, [6; 32]);
    let err = set(
        &e,
        &unsigned_visibility(&repo),
        VisibilityRequest::Statement(stmt),
    )
    .unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied);
    assert_eq!(
        err.public_message(),
        "visibility statement rejected: no owner schemes configured"
    );
}

#[test]
fn envelope_mode_requires_a_signed_request() {
    let owner = key(1);
    let repo = repository(&owner);
    let e = environment(&owner, AuthorizerRole::Check, false);
    let err = set(
        &e,
        &unsigned_visibility(&repo),
        VisibilityRequest::Envelope(Visibility::Private),
    )
    .unwrap_err();
    assert_eq!(err.code(), Code::Unauthenticated);
}

#[test]
fn visibility_needs_a_visibility_deployment_and_served_namespace() {
    let owner = key(1);
    // Single addressing: no visibility at all.
    let clock = clock();
    let single = build(cfg(authv2()), Spy::new(store(&clock)), Hooks::new(), clock);
    let err = set(
        &single,
        &Req::signed(&owner, Procedure::SetRepoVisibility, b"v", &nonce(7), T0),
        VisibilityRequest::Envelope(Visibility::Private),
    )
    .unwrap_err();
    assert_eq!(err.code(), Code::FailedPrecondition);
    // A namespace outside the allowlist is not served.
    let e = environment(&owner, AuthorizerRole::Check, false);
    let stranger = key(2);
    let foreign = repository(&stranger);
    let err = set(
        &e,
        &signed_visibility(&stranger, &foreign, 8, b"v"),
        VisibilityRequest::Envelope(Visibility::Private),
    )
    .unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied);
    assert_eq!(err.public_message(), "namespace not served");
}

#[test]
fn visibility_on_a_missing_repo_gates_reads_once_created() {
    let owner = key(1);
    let repo = repository(&owner);
    let e = environment(&owner, AuthorizerRole::Check, false);
    let id = repo_id(&e, &owner);
    // `rv` writes alone never register the repository.
    set(
        &e,
        &signed_visibility(&owner, &repo, 9, b"v"),
        VisibilityRequest::Envelope(Visibility::Private),
    )
    .unwrap();
    let p = e.pipe.shards.coordinator(&id.namespace);
    assert!(
        now(e.pipe.meta.inner.get(&p, &keys::repo_record(&id.name)))
            .unwrap()
            .is_none()
    );
    // The first write creates `rr`; the repo is already private.
    e.update(&request(&owner, &repo, 10, None), &upd(HEAD, Any, A))
        .unwrap();
    assert!(
        now(e.pipe.meta.inner.get(&p, &keys::repo_record(&id.name)))
            .unwrap()
            .is_some()
    );
    let err = try_read(
        &e,
        &anonymous_read(&repo, Procedure::ReadRef),
        Procedure::ReadRef,
    )
    .unwrap_err();
    assert_not_found(&err, "anonymous");
    assert_served(
        try_read(
            &e,
            &signed_read(&owner, &repo, Procedure::ReadRef, None),
            Procedure::ReadRef,
        ),
        "owner",
    );
}

// ------------------------------------------------------- review fixes

/// Counts its calls and records the `caller_view` it was shown.
#[derive(Clone, Default)]
struct Counting {
    views: Arc<Mutex<Vec<CallerView>>>,
}

impl Counting {
    fn calls(&self) -> usize {
        self.views.lock().unwrap().len()
    }
}

impl Authorizer for Counting {
    async fn authorize(&self, op: &Operation) -> Result<AuthzFacts, ServerError> {
        self.views.lock().unwrap().push(op.authz.caller_view);
        Ok(AuthzFacts {
            caller_view: CallerView::Writer,
            ..AuthzFacts::default()
        })
    }
}

/// A hook error shaped like an admission challenge.
#[derive(Clone)]
struct PaymentShaped;

impl Authorizer for PaymentShaped {
    async fn authorize(&self, _: &Operation) -> Result<AuthzFacts, ServerError> {
        Err(ServerError::permission_denied("pay first")
            .with_http_status(402)
            .with_header("www-authenticate", "Payment realm=repo"))
    }
}

#[test]
fn a_payment_shaped_hook_error_never_leaks_on_reads_or_visibility() {
    let owner = key(1);
    let stranger = key(2);
    let repo = repository(&owner);
    let env = env_with(&owner, AuthorizerRole::Check, PaymentShaped);
    let id = repo_id(&env, &owner);
    // Private: the uniform `not_found`.
    put_repo(&env, &id, Some(codec::StoredVisibility::Private));
    let err = try_read(
        &env,
        &signed_read(&stranger, &repo, Procedure::ReadRef, None),
        Procedure::ReadRef,
    )
    .unwrap_err();
    assert_not_found(&err, "private");
    // Public under the Check role: the error propagates, stripped.
    put_repo(&env, &id, Some(codec::StoredVisibility::Public));
    let err = try_read(
        &env,
        &anonymous_read(&repo, Procedure::ReadRef),
        Procedure::ReadRef,
    )
    .unwrap_err();
    assert_ne!(err.http_status(), Some(402));
    assert!(err.headers().is_empty() && err.details().is_empty());
    // Envelope visibility consults the hook for a non-owner.
    let env = env_with(&owner, AuthorizerRole::Authority, PaymentShaped);
    let err = set(
        &env,
        &signed_visibility(&stranger, &repo, 21, b"v"),
        VisibilityRequest::Envelope(Visibility::Private),
    )
    .unwrap_err();
    assert_ne!(err.http_status(), Some(402));
    assert!(err.headers().is_empty() && err.details().is_empty());
}

#[test]
fn a_bad_grant_never_lets_the_authority_hook_authorize_a_private_read() {
    let owner = key(1);
    let grantee = key(2);
    let repo = repository(&owner);
    let env = env_with(&owner, AuthorizerRole::Authority, WriterView);
    let id = repo_id(&env, &owner);
    put_repo(&env, &id, Some(codec::StoredVisibility::Private));
    put_epoch(&env, &id, 1);
    let mut grants = vec![
        // Old epoch, expired and foreign-owner grants.
        grant(&owner, &grantee, |g| {
            g.capabilities = Capabilities::Read;
            g.ref_scopes = None;
            g.epoch = 0;
        }),
        grant(&owner, &grantee, |g| {
            g.capabilities = Capabilities::Read;
            g.ref_scopes = None;
            g.epoch = 1;
            g.expiry_ms = T0 - 1;
        }),
        grant(&key(3), &grantee, |g| {
            g.capabilities = Capabilities::Read;
            g.ref_scopes = None;
            g.epoch = 1;
        }),
    ];
    grants.push("junk.header".to_owned());
    for header in &grants {
        let err = try_read(
            &env,
            &signed_read(&grantee, &repo, Procedure::ReadRef, Some(header)),
            Procedure::ReadRef,
        )
        .unwrap_err();
        assert_not_found(&err, header);
    }
    // Without a grant the same hook authorizes.
    assert_served(
        try_read(
            &env,
            &signed_read(&grantee, &repo, Procedure::ReadRef, None),
            Procedure::ReadRef,
        ),
        "no grant",
    );
}

#[test]
fn an_expired_grant_loses_a_private_read_and_only_classifies_a_public_one() {
    let owner = key(1);
    let grantee = key(2);
    let repo = repository(&owner);
    let env = environment(&owner, AuthorizerRole::Check, false);
    let id = repo_id(&env, &owner);
    let expired = grant(&owner, &grantee, |g| {
        g.capabilities = Capabilities::Read;
        g.ref_scopes = None;
        g.expiry_ms = T0 - 1;
    });
    put_repo(&env, &id, Some(codec::StoredVisibility::Private));
    let err = try_read(
        &env,
        &signed_read(&grantee, &repo, Procedure::ReadRef, Some(&expired)),
        Procedure::ReadRef,
    )
    .unwrap_err();
    assert_not_found(&err, "expired, private");
    put_repo(&env, &id, None);
    let p = env.pipe.shards.coordinator(&id.namespace);
    now(env
        .pipe
        .meta
        .inner
        .apply(&p, Batch::new().delete(keys::repo_visibility(&id.name))))
    .unwrap();
    let a = env
        .auth(&signed_read(
            &grantee,
            &repo,
            Procedure::ReadRef,
            Some(&expired),
        ))
        .unwrap();
    let op = env
        .pipe
        .identify(&a, OpKind::ReadRef { name: HEAD.into() })
        .unwrap();
    let read = block_on(env.pipe.authorize_read(&op)).unwrap();
    assert_eq!(read.facts.caller_view, CallerView::Reader);
}

#[test]
fn a_missing_repository_pays_the_same_hook_round_trip_as_a_private_one() {
    let owner = key(1);
    let stranger = key(2);
    let repo = repository(&owner);
    let calls = |private: bool, signed: bool| {
        let counting = Counting::default();
        let env = env_with(&owner, AuthorizerRole::Authority, counting.clone());
        if private {
            let id = repo_id(&env, &owner);
            put_repo(&env, &id, Some(codec::StoredVisibility::Private));
        }
        let req = if signed {
            signed_read(&stranger, &repo, Procedure::ReadRef, None)
        } else {
            anonymous_read(&repo, Procedure::ReadRef)
        };
        let _ = try_read(&env, &req, Procedure::ReadRef);
        counting.calls()
    };
    assert_eq!(calls(false, true), 1);
    assert_eq!(calls(false, true), calls(true, true));
    assert_eq!(calls(false, false), calls(true, false));
}

#[test]
fn visibility_outside_multi_owner_auth_v2_is_failed_precondition() {
    let owner = key(1);
    let repo = repository(&owner);
    for auth in [
        AuthMode::Open,
        AuthMode::Bearer {
            token: crate::error::Redacted::new("t"),
        },
    ] {
        let e = env(auth);
        for mode in [
            VisibilityRequest::Envelope(Visibility::Private),
            VisibilityRequest::Statement("x".into()),
        ] {
            let a = e
                .auth(
                    &Req::unsigned(Procedure::SetRepoVisibility)
                        .header("authorization", "Bearer t"),
                )
                .unwrap();
            let err = block_on(e.pipe.set_repo_visibility(&a, mode)).unwrap_err();
            assert_eq!(err.code(), Code::FailedPrecondition);
        }
    }
    let _ = repo;
}

#[test]
fn a_grant_header_without_auth_v2_is_unauthenticated_everywhere() {
    for auth in [
        AuthMode::Open,
        AuthMode::Bearer {
            token: crate::error::Redacted::new("t"),
        },
    ] {
        let e = env(auth);
        let err = e
            .auth(
                &Req::unsigned(Procedure::ReadRef)
                    .header("authorization", "Bearer t")
                    .header("x-write-grant", "a.b.c"),
            )
            .unwrap_err();
        assert_eq!(err.code(), Code::Unauthenticated);
    }
}

#[test]
fn private_rows_are_enforced_whatever_the_auth_mode() {
    let owner = key(1);
    let repo = repository(&owner);
    let clock = clock();
    let mut c = config(&owner, AuthorizerRole::Check);
    c.auth = AuthMode::Open;
    c.grants = None;
    let env = build(c, Spy::new(store(&clock)), Hooks::new(), clock);
    let id = repo_id(&env, &owner);
    put_repo(&env, &id, Some(codec::StoredVisibility::Private));
    let err = try_read(
        &env,
        &anonymous_read(&repo, Procedure::ReadRef),
        Procedure::ReadRef,
    )
    .unwrap_err();
    assert_not_found(&err, "open sibling, private");
    put_repo(&env, &id, Some(codec::StoredVisibility::Public));
    assert_served(
        try_read(
            &env,
            &anonymous_read(&repo, Procedure::ReadRef),
            Procedure::ReadRef,
        ),
        "open sibling, public",
    );
}

#[test]
fn an_envelope_flip_cannot_be_undone_by_an_older_statement() {
    let owner = key(1);
    let repo = repository(&owner);
    let e = environment(&owner, AuthorizerRole::Check, false);
    let id = repo_id(&e, &owner);
    let (older, _) = statement(&owner, &repo, Visibility::Public, T0 - 1, [11; 32]);
    let (same, _) = statement(&owner, &repo, Visibility::Public, T0, [12; 32]);
    set(
        &e,
        &signed_visibility(&owner, &repo, 30, b"v"),
        VisibilityRequest::Envelope(Visibility::Private),
    )
    .unwrap();
    assert_eq!(
        stored_visibility_row(&e, &id).last_created_ms,
        u64::try_from(T0).unwrap()
    );
    for stmt in [older, same] {
        let err = set(
            &e,
            &unsigned_visibility(&repo),
            VisibilityRequest::Statement(stmt),
        )
        .unwrap_err();
        assert_eq!(err.code(), Code::PermissionDenied);
    }
    assert_eq!(
        stored_visibility_row(&e, &id).visibility,
        codec::StoredVisibility::Private
    );
}

#[test]
fn a_stale_identical_statement_retry_after_an_envelope_change_is_refused() {
    let owner = key(1);
    let repo = repository(&owner);
    let e = environment(&owner, AuthorizerRole::Check, false);
    let id = repo_id(&e, &owner);
    let (stmt, _) = statement(&owner, &repo, Visibility::Private, T0, [13; 32]);
    set(
        &e,
        &unsigned_visibility(&repo),
        VisibilityRequest::Statement(stmt.clone()),
    )
    .unwrap();
    set(
        &e,
        &signed_visibility(&owner, &repo, 31, b"v"),
        VisibilityRequest::Envelope(Visibility::Public),
    )
    .unwrap();
    let err = set(
        &e,
        &unsigned_visibility(&repo),
        VisibilityRequest::Statement(stmt),
    )
    .unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied);
    assert_eq!(
        stored_visibility_row(&e, &id).visibility,
        codec::StoredVisibility::Public
    );
}

#[test]
fn the_envelope_hook_sees_a_reader_until_it_decides() {
    let owner = key(1);
    let stranger = key(2);
    let repo = repository(&owner);
    let counting = Counting::default();
    let env = env_with(&owner, AuthorizerRole::Authority, counting.clone());
    set(
        &env,
        &signed_visibility(&stranger, &repo, 32, b"v"),
        VisibilityRequest::Envelope(Visibility::Private),
    )
    .unwrap();
    assert_eq!(*counting.views.lock().unwrap(), [CallerView::Reader]);
}

#[test]
fn a_visibility_request_debug_hides_the_statement() {
    let shown = format!(
        "{:?}",
        VisibilityRequest::Statement("secret.header.bytes".into())
    );
    assert!(!shown.contains("secret"), "{shown}");
}

#[test]
fn admin_owner_cannot_grant_private_repository_reads() {
    let owner = key(1);
    let grantee = key(2);
    let repo = repository(&owner);
    for sharding in [Sharding::Single, Sharding::D34] {
        let mut c = config(&owner, AuthorizerRole::Check);
        c.admin_keys = vec![*owner.verifying_key().as_bytes()];
        c.sharding = sharding;
        let clock = clock();
        let e = build(
            c,
            Spy::new(store(&clock)),
            super::policy::policy_hooks(false),
            clock,
        );
        let id = repo_id(&e, &owner);
        put_repo(&e, &id, Some(codec::StoredVisibility::Private));
        for capability in [Capabilities::Read, Capabilities::Write] {
            let delegated = grant(&owner, &grantee, |g| {
                if matches!(capability, Capabilities::Read) {
                    g.ref_scopes = None;
                }
                g.capabilities = capability;
            });
            for procedure in READS {
                let err = try_read(
                    &e,
                    &signed_read(&grantee, &repo, procedure, Some(&delegated)),
                    procedure,
                )
                .unwrap_err();
                assert_not_found(&err, "admin-owner private read grant");
            }
        }
    }
}

#[test]
fn admin_owner_cannot_sign_visibility_statements() {
    let owner = key(1);
    let repo = repository(&owner);
    for sharding in [Sharding::Single, Sharding::D34] {
        let mut c = config(&owner, AuthorizerRole::Check);
        c.admin_keys = vec![*owner.verifying_key().as_bytes()];
        c.sharding = sharding;
        let clock = clock();
        let e = build(
            c,
            Spy::new(store(&clock)),
            super::policy::policy_hooks(false),
            clock,
        );
        let id = repo_id(&e, &owner);
        put_repo(&e, &id, Some(codec::StoredVisibility::Private));
        let (signed, _) = statement(&owner, &repo, Visibility::Public, T0, [8; 32]);
        assert_eq!(
            set(
                &e,
                &unsigned_visibility(&repo),
                VisibilityRequest::Statement(signed)
            )
            .unwrap_err()
            .code(),
            Code::PermissionDenied,
            "{sharding:?}"
        );
        assert_eq!(
            stored_visibility_row(&e, &id).visibility,
            codec::StoredVisibility::Private
        );
    }
}

#[test]
fn deployment_default_visibility_is_resolved_for_every_connect_read() {
    let owner = key(1);
    for default in [Visibility::Public, Visibility::Private] {
        for explicit in [
            None,
            Some(codec::StoredVisibility::Public),
            Some(codec::StoredVisibility::Private),
        ] {
            let clock = clock();
            let mut c = config(&owner, AuthorizerRole::Check);
            c.default_repo_visibility = default;
            let e = build(
                c,
                Spy::new(store(&clock)),
                super::policy::policy_hooks(false),
                clock,
            );
            let repo = repository(&owner);
            let id = repo_id(&e, &owner);
            put_repo(&e, &id, explicit);
            let private = explicit.map_or(default == Visibility::Private, |v| {
                v == codec::StoredVisibility::Private
            });
            for procedure in READS {
                let result = try_read(&e, &anonymous_read(&repo, procedure), procedure);
                if private {
                    assert_not_found(&result.unwrap_err(), "deployment default");
                } else {
                    assert_served(result, "explicit or default public");
                }
            }
        }
    }
}
