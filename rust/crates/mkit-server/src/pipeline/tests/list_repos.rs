use super::grants::{config, grant, repository};
use super::*;

fn setup(sharding: Sharding, default: RepoVisibility) -> Env {
    let mut cfg = config(&key(1), AuthorizerRole::Check);
    cfg.sharding = sharding;
    cfg.default_repo_visibility = default;
    let clock = clock();
    build(cfg, Spy::new(store(&clock)), Hooks::new(), clock)
}

fn identity(name: &str) -> String {
    let owned = repository(&key(1));
    format!("{}/{name}", owned.split_once('/').unwrap().0)
}

fn request(procedure: Procedure, identity: &str, signer: Option<&SigningKey>) -> Req {
    match signer {
        Some(key) => Req::signed_for(key, procedure, identity, b"repos", &nonce(90), T0),
        None => Req::unsigned(procedure).header("x-repository", identity),
    }
}

fn create<H: HookSet>(e: &Env<H>, name: &str, number: u32) {
    let req = Req::signed_for(
        &key(1),
        Procedure::UpdateRef,
        &identity(name),
        b"repos",
        &nonce(number),
        T0,
    );
    let a = e.auth(&req).unwrap();
    assert!(matches!(
        block_on(e.pipe.update_ref(
            &a,
            RefUpdate {
                name: HEAD.into(),
                condition: Any,
                new: Some(A)
            }
        ))
        .unwrap(),
        UpdateRefResult::Committed
    ));
}

fn set<H: HookSet>(e: &Env<H>, name: &str, visibility: RepoVisibility, number: u32) {
    let req = Req::signed_for(
        &key(1),
        Procedure::SetRepoVisibility,
        &identity(name),
        b"repos",
        &nonce(number),
        T0,
    );
    let a = e.auth(&req).unwrap();
    block_on(
        e.pipe
            .set_repo_visibility(&a, VisibilityRequest::Envelope(visibility)),
    )
    .unwrap();
}

fn listing<H: HookSet>(
    e: &Env<H>,
    req: &Req,
    prefix: &str,
    size: u32,
    token: Option<&[u8]>,
) -> Result<RepoPage, ServerError> {
    let a = e.auth(req)?;
    block_on(e.pipe.list_repos_page(
        &a,
        identity("selector").split_once('/').unwrap().0,
        prefix,
        Some(size),
        token,
    ))
}

fn names(page: &RepoPage) -> Vec<&str> {
    page.repos.iter().map(|entry| entry.name.as_str()).collect()
}

fn full_creation_is_retryable(sharding: Sharding) {
    let mut cfg = config(&key(1), AuthorizerRole::Check);
    cfg.sharding = sharding;
    let clock = clock();
    let e = build(
        cfg,
        Spy::new(store(&clock).with_capacity_limit(0)),
        Hooks::new(),
        clock,
    );
    let req = request(Procedure::UpdateRef, &identity("new-repo"), Some(&key(1)));
    let a = e.auth(&req).unwrap();
    let error = block_on(e.pipe.update_ref(&a, upd(HEAD, Missing, A))).unwrap_err();
    assert_eq!(error.code(), Code::Unavailable);
    assert_eq!(error.public_message(), "storage partition full");
    assert_eq!(e.metrics.count(METRIC_PARTITION_FULL), 1);
    let coordinator = e.pipe.shards.coordinator(&a.repo().repo.namespace);
    assert_eq!(
        block_on(e.pipe.meta.stats(&coordinator)).unwrap().keys,
        Some(0)
    );
    let anon = request(Procedure::ListRepos, &identity("selector"), None);
    assert!(listing(&e, &anon, "", 100, None).unwrap().repos.is_empty());
}

#[test]
fn full_repository_creation_is_retryable() {
    full_creation_is_retryable(Sharding::Single);
}

#[test]
fn full_coordinator_lease_grant_is_retryable() {
    full_creation_is_retryable(Sharding::D34);
}

fn full_relay_lease_is_retryable(local_full: bool) {
    let mut cfg = config(&key(1), AuthorizerRole::Check);
    cfg.sharding = Sharding::D34;
    let clock = clock();
    let e = build(
        cfg,
        Spy::new(store(&clock).with_capacity_limit(if local_full { 4096 } else { 0 })),
        Hooks::new(),
        clock,
    );
    let req = request(Procedure::UpdateRef, &identity("new-repo"), Some(&key(1)));
    let a = e.auth(&req).unwrap();
    let repo = &a.repo().repo;
    if local_full {
        block_on(e.pipe.meta.inner.apply(
            &e.pipe.shards.ref_shard(repo, HEAD),
            Batch::new().put(Key::new(b"filler".to_vec()), Value::new(vec![0; 4089])),
        ))
        .unwrap();
    }
    let error = block_on(renew_for_relay(
        &e.pipe.meta,
        &e.pipe.meta,
        e.pipe.shards.as_ref(),
        e.clock.as_ref(),
        e.pipe.metrics.as_ref(),
        repo,
        &e.pipe.shards.ref_shard(repo, HEAD),
        &LeaseParams::from(&e.pipe.cfg),
    ))
    .unwrap_err();
    assert_eq!(error.code(), Code::Unavailable);
    assert_eq!(error.public_message(), "storage partition full");
    assert_eq!(e.metrics.count(METRIC_PARTITION_FULL), 1);
}

#[test]
fn full_relay_lease_grant_is_retryable() {
    full_relay_lease_is_retryable(false);
}

#[test]
fn full_relay_lease_install_is_retryable() {
    full_relay_lease_is_retryable(true);
}

#[test]
fn visibility_views_and_atomic_creation_work_in_single_and_d34() {
    for sharding in [Sharding::Single, Sharding::D34] {
        let mut e = setup(sharding, RepoVisibility::Public);
        set(&e, "a-private", RepoVisibility::Private, 1);
        set(&e, "c-public", RepoVisibility::Public, 2);
        let anon = request(Procedure::ListRepos, &identity("selector"), None);
        assert!(
            listing(&e, &anon, "", 100, None).unwrap().repos.is_empty(),
            "visibility must not register a repository"
        );
        for (number, name) in [(3, "a-private"), (4, "b-default"), (5, "c-public")] {
            create(&e, name, number);
        }
        let public = listing(&e, &anon, "", 100, None).unwrap();
        assert_eq!(names(&public), ["b-default", "c-public"]);
        let owner = request(Procedure::ListRepos, &identity("selector"), Some(&key(1)));
        let all = listing(&e, &owner, "", 100, None).unwrap();
        assert_eq!(names(&all), ["a-private", "b-default", "c-public"]);
        assert_eq!(all.repos[0].visibility, RepoVisibility::Private);
        let stranger = request(Procedure::ListRepos, &identity("selector"), Some(&key(2)));
        assert_eq!(
            names(&listing(&e, &stranger, "", 100, None).unwrap()),
            names(&public)
        );
        let read_grant = grant(&key(1), &key(2), |g| {
            g.capabilities = mkit_attest::grant::Capabilities::Read;
            g.ref_scopes = None;
        });
        let holder = stranger.header("x-write-grant", &read_grant);
        assert_eq!(
            names(&listing(&e, &holder, "", 100, None).unwrap()),
            names(&public)
        );
        set(&e, "b-default", RepoVisibility::Private, 6);
        assert_eq!(
            names(&listing(&e, &anon, "", 100, None).unwrap()),
            ["c-public"]
        );
        set(&e, "a-private", RepoVisibility::Public, 7);
        assert_eq!(
            names(&listing(&e, &anon, "", 100, None).unwrap()),
            ["a-private", "c-public"]
        );
        create(&e, "d-inherited", 8);
        e.pipe.cfg.default_repo_visibility = RepoVisibility::Private;
        assert_eq!(
            names(&listing(&e, &anon, "", 100, None).unwrap()),
            ["a-private", "c-public"]
        );
        assert_eq!(
            listing(&e, &owner, "d", 100, None).unwrap().repos[0].visibility,
            RepoVisibility::Private
        );
        for batch in e.pipe.meta.batches.lock().unwrap().iter() {
            batch.validate(&e.pipe.meta.capabilities()).unwrap();
        }
    }
}

#[test]
fn pagination_merges_both_visibility_prefixes_and_bounds_calls() {
    for sharding in [Sharding::Single, Sharding::D34] {
        let mut e = setup(sharding, RepoVisibility::Public);
        for i in 0..105 {
            let name = format!("repo-{i:03}");
            create(&e, &name, i + 1);
            if i % 2 == 0 {
                set(&e, &name, RepoVisibility::Public, i + 1000);
            }
        }
        let anon = request(Procedure::ListRepos, &identity("selector"), None);
        let before = e.pipe.meta.calls();
        let first = listing(&e, &anon, "repo-", 100, None).unwrap();
        assert_eq!(first.repos.len(), 100);
        assert_eq!(
            e.pipe.meta.calls() - before,
            2,
            "two coordinator scans, no per-repo reads"
        );
        let next = listing(&e, &anon, "repo-", 100, first.next.as_deref()).unwrap();
        assert_eq!(
            names(&next),
            ["repo-100", "repo-101", "repo-102", "repo-103", "repo-104"]
        );
        assert!(next.next.is_none());
        e.pipe.meta.scan_limit = Some(1);
        let before = e.pipe.meta.calls();
        let short = listing(&e, &anon, "repo-", 100, None).unwrap();
        assert_eq!(short, first);
        assert_eq!(e.pipe.meta.calls() - before, 102);
        let owner = request(Procedure::ListRepos, &identity("selector"), Some(&key(1)));
        let before = e.pipe.meta.calls();
        let full = listing(&e, &owner, "repo-", 100, None).unwrap();
        assert_eq!(names(&full), names(&first));
        assert_eq!(e.pipe.meta.calls() - before, 102);
        assert_eq!(
            names(&listing(&e, &anon, "repo-02", 100, None).unwrap()),
            (20..30).map(|i| format!("repo-{i:03}")).collect::<Vec<_>>()
        );
    }
}

#[test]
fn token_tampering_and_foreign_bindings_are_rejected() {
    let mut e = setup(Sharding::D34, RepoVisibility::Public);
    create(&e, "a", 1);
    create(&e, "b", 2);
    let anon = request(Procedure::ListRepos, &identity("selector"), None);
    let token = listing(&e, &anon, "", 1, None).unwrap().next.unwrap();
    for index in 0..token.len() {
        let mut forged = token.clone();
        forged[index] ^= 1;
        assert_eq!(
            listing(&e, &anon, "", 1, Some(&forged)).unwrap_err().code(),
            Code::InvalidArgument
        );
    }
    for bytes in [vec![], vec![1; 1000], token[..token.len() - 1].to_vec()] {
        assert_eq!(
            listing(&e, &anon, "", 1, Some(&bytes)).unwrap_err().code(),
            Code::InvalidArgument
        );
    }
    assert_eq!(
        listing(&e, &anon, "a", 1, Some(&token)).unwrap_err().code(),
        Code::InvalidArgument
    );
    let owner = request(Procedure::ListRepos, &identity("selector"), Some(&key(1)));
    assert_eq!(
        listing(&e, &owner, "", 1, Some(&token)).unwrap_err().code(),
        Code::InvalidArgument
    );
    e.pipe.cfg.default_repo_visibility = RepoVisibility::Private;
    assert_eq!(
        listing(&e, &anon, "", 1, Some(&token)).unwrap_err().code(),
        Code::InvalidArgument
    );
    assert_eq!(
        listing(&e, &anon, "", 101, None).unwrap_err().code(),
        Code::InvalidArgument
    );
    let wrong = request(Procedure::ReadRef, &identity("selector"), None);
    assert_eq!(
        listing(&e, &wrong, "", 1, None).unwrap_err().code(),
        Code::Unauthenticated
    );
}

#[test]
fn private_only_and_empty_namespaces_have_identical_public_pages_and_cost() {
    let e = setup(Sharding::D34, RepoVisibility::Private);
    let anon = request(Procedure::ListRepos, &identity("selector"), None);
    let before = e.pipe.meta.calls();
    let empty = listing(&e, &anon, "", 100, None).unwrap();
    let empty_calls = e.pipe.meta.calls() - before;
    for i in 0..150 {
        create(&e, &format!("hidden-{i:03}"), i + 1);
    }
    let before = e.pipe.meta.calls();
    assert_eq!(listing(&e, &anon, "", 100, None).unwrap(), empty);
    assert_eq!(e.pipe.meta.calls() - before, empty_calls);
    set(&e, "z-public", RepoVisibility::Public, 500);
    create(&e, "z-public", 501);
    assert_eq!(
        names(&listing(&e, &anon, "", 100, None).unwrap()),
        ["z-public"]
    );
}

struct ListingAuthority {
    selector: Option<&'static str>,
    writer: bool,
}

impl Authorizer for ListingAuthority {
    async fn authorize(&self, op: &Operation) -> Result<AuthzFacts, ServerError> {
        if !op.authz.owner
            && self
                .selector
                .is_some_and(|name| op.repo.name.as_str() != name)
        {
            return Err(ServerError::permission_denied("other repository"));
        }
        if matches!(op.kind, OpKind::ListRepos { .. }) {
            return Ok(AuthzFacts {
                caller_view: if self.writer {
                    CallerView::Writer
                } else {
                    CallerView::Reader
                },
                ..AuthzFacts::default()
            });
        }
        Ok(AuthzFacts::default())
    }
}

fn authority_hooks(selector: Option<&'static str>, writer: bool) -> Hooks<ListingAuthority> {
    let defaults = Hooks::new();
    Hooks {
        authorizer: ListingAuthority { selector, writer },
        admission: defaults.admission,
        pre_receive: defaults.pre_receive,
        receipts: defaults.receipts,
        outcomes: defaults.outcomes,
    }
}

#[test]
fn authority_full_listing_requires_opt_in_and_writer_view_while_grants_remain_public() {
    for sharding in [Sharding::Single, Sharding::D34] {
        for writer in [false, true] {
            let mut cfg = config(&key(1), AuthorizerRole::Authority);
            cfg.sharding = sharding;
            cfg.default_repo_visibility = RepoVisibility::Private;
            assert!(!cfg.list_repos_authority_full);
            let clock = clock();
            let mut e = build(
                cfg,
                Spy::new(store(&clock)),
                authority_hooks(None, writer),
                clock,
            );
            create(&e, "secret", 1);
            create(&e, "visible", 2);
            set(&e, "visible", RepoVisibility::Public, 3);
            let authority = request(Procedure::ListRepos, &identity("selector"), Some(&key(2)));
            assert_eq!(
                names(&listing(&e, &authority, "", 100, None).unwrap()),
                ["visible"]
            );
            e.pipe.cfg.list_repos_authority_full = true;
            assert_eq!(
                names(&listing(&e, &authority, "", 100, None).unwrap()),
                if writer {
                    vec!["secret", "visible"]
                } else {
                    vec!["visible"]
                }
            );
            let presented_grant =
                authority.header("x-write-grant", "invalid-but-irrelevant-to-listing");
            assert_eq!(
                names(&listing(&e, &presented_grant, "", 100, None).unwrap()),
                ["visible"]
            );
        }
    }
}

#[test]
fn repository_scoped_authority_allow_cannot_enumerate_private_names() {
    for opt_in in [false, true] {
        let mut cfg = config(&key(1), AuthorizerRole::Authority);
        cfg.default_repo_visibility = RepoVisibility::Private;
        cfg.list_repos_authority_full = opt_in;
        let clock = clock();
        let e = build(
            cfg,
            Spy::new(store(&clock)),
            authority_hooks(Some("x"), false),
            clock,
        );
        create(&e, "x", 1);
        create(&e, "secret", 2);
        let collaborator = request(Procedure::ListRepos, &identity("x"), Some(&key(2)));
        assert!(
            listing(&e, &collaborator, "", 100, None)
                .unwrap()
                .repos
                .is_empty()
        );
        let other_selector = request(Procedure::ListRepos, &identity("secret"), Some(&key(2)));
        assert!(
            listing(&e, &other_selector, "", 100, None)
                .unwrap()
                .repos
                .is_empty()
        );
        let owner = request(Procedure::ListRepos, &identity("x"), Some(&key(1)));
        assert_eq!(
            names(&listing(&e, &owner, "", 100, None).unwrap()),
            ["secret", "x"]
        );
    }
}

#[test]
fn empty_scan_pages_resume_before_merging_and_count_against_the_budget() {
    for sharding in [Sharding::Single, Sharding::D34] {
        let mut e = setup(sharding, RepoVisibility::Public);
        create(&e, "repo-a", 1);
        set(&e, "repo-a", RepoVisibility::Public, 2);
        create(&e, "repo-b", 3);
        e.pipe.meta.scan_page_hook = Some(Box::new(|start, after, page| {
            if after.is_none() {
                ScanPage {
                    entries: Vec::new(),
                    next: Some(crate::store::Cursor::new(start.as_bytes().to_vec())),
                }
            } else {
                page
            }
        }));
        let anon = request(Procedure::ListRepos, &identity("selector"), None);
        let before = e.pipe.meta.calls();
        let page = listing(&e, &anon, "repo-", 1, None).unwrap();
        assert_eq!(names(&page), ["repo-a"]);
        assert_eq!(e.pipe.meta.calls() - before, 4);
        let next = listing(&e, &anon, "repo-", 1, page.next.as_deref()).unwrap();
        assert_eq!(names(&next), ["repo-b"]);
        assert!(next.next.is_none());
        let owner = request(Procedure::ListRepos, &identity("selector"), Some(&key(1)));
        let before = e.pipe.meta.calls();
        assert_eq!(
            names(&listing(&e, &owner, "repo-", 100, None).unwrap()),
            ["repo-a", "repo-b"]
        );
        assert_eq!(e.pipe.meta.calls() - before, 3);
        // Arbitrarily many empty pages still advance through the gap before printable names.
        e.pipe.meta.scan_page_hook = Some(Box::new(|start, after, _| {
            let mut cursor =
                after.map_or_else(|| start.as_bytes().to_vec(), |c| c.as_bytes().to_vec());
            cursor.push(0);
            ScanPage {
                entries: Vec::new(),
                next: Some(crate::store::Cursor::new(cursor)),
            }
        }));
        for (req, expected_calls) in [(&anon, 102), (&owner, 101)] {
            let before = e.pipe.meta.calls();
            assert_eq!(
                listing(&e, req, "repo-", 100, None).unwrap_err().code(),
                Code::ResourceExhausted
            );
            assert_eq!(e.pipe.meta.calls() - before, expected_calls);
        }
    }
}

#[test]
fn creation_survives_three_visibility_conflicts_before_the_fourth_apply() {
    for sharding in [Sharding::Single, Sharding::D34] {
        let mut cfg = config(&key(1), AuthorizerRole::Check);
        cfg.sharding = sharding;
        let name = RepoName::new("racing").unwrap();
        let attempts = Arc::new(AtomicU32::new(0));
        let counter = attempts.clone();
        let clock = clock();
        let spy =
            Spy::new(store(&clock)).hook(move |kv, p, batch| {
                if batch.writes.iter().any(
                    |write| matches!(write, Write::Put(k, _) if *k == keys::repo_record(&name)),
                ) {
                    let attempt = counter.fetch_add(1, Ordering::SeqCst);
                    if attempt < 3 {
                        now(kv.apply(
                            p,
                            Batch::new().put(
                                keys::repo_visibility(&name),
                                codec::encode_repo_visibility(&codec::RepoVisibilityV1 {
                                    visibility: codec::StoredVisibility::Private,
                                    last_created_ms: u64::from(attempt),
                                    last_statement_id: None,
                                    changed_ms: None,
                                }),
                            ),
                        ))
                        .unwrap();
                    }
                }
            });
        let e = build(cfg, spy, Hooks::new(), clock);
        create(&e, "racing", 1);
        assert_eq!(attempts.load(Ordering::SeqCst), 4);
        let anon = request(Procedure::ListRepos, &identity("selector"), None);
        assert!(listing(&e, &anon, "", 100, None).unwrap().repos.is_empty());
    }
}

#[test]
fn creation_retries_if_visibility_changes_before_its_apply() {
    for sharding in [Sharding::Single, Sharding::D34] {
        let cfg = {
            let mut c = config(&key(1), AuthorizerRole::Check);
            c.sharding = sharding;
            c
        };
        let name = RepoName::new("racing").unwrap();
        let changed = Arc::new(AtomicBool::new(false));
        let once = changed.clone();
        let clock = clock();
        let spy =
            Spy::new(store(&clock)).hook(move |kv, p, batch| {
                if batch.writes.iter().any(
                    |write| matches!(write, Write::Put(k, _) if *k == keys::repo_record(&name)),
                ) && !once.swap(true, Ordering::SeqCst)
                {
                    now(kv.apply(
                        p,
                        Batch::new().put(
                            keys::repo_visibility(&name),
                            codec::encode_repo_visibility(&codec::RepoVisibilityV1 {
                                visibility: codec::StoredVisibility::Private,
                                last_created_ms: 0,
                                last_statement_id: None,
                                changed_ms: None,
                            }),
                        ),
                    ))
                    .unwrap();
                }
            });
        let e = build(cfg, spy, Hooks::new(), clock);
        create(&e, "racing", 1);
        assert!(changed.load(Ordering::SeqCst));
        let anon = request(Procedure::ListRepos, &identity("selector"), None);
        assert!(listing(&e, &anon, "", 100, None).unwrap().repos.is_empty());
    }
}

#[test]
fn visibility_retries_if_registration_changes_before_its_apply() {
    let name = RepoName::new("racing").unwrap();
    let once = Arc::new(AtomicBool::new(false));
    let clock = clock();
    let spy =
        Spy::new(store(&clock)).hook(move |kv, p, batch| {
            if batch.writes.iter().any(
                |write| matches!(write, Write::Put(k, _) if *k == keys::repo_visibility(&name)),
            ) && !once.swap(true, Ordering::SeqCst)
            {
                now(kv.apply(
                    p,
                    Batch::new()
                        .put(
                            keys::repo_record(&name),
                            codec::encode_repo_record(&codec::RepoRecord { created_at_ms: 0 }),
                        )
                        .put(keys::repo_listing(&name, false), Value::default()),
                ))
                .unwrap();
            }
        });
    let e = build(
        config(&key(1), AuthorizerRole::Check),
        spy,
        Hooks::new(),
        clock,
    );
    set(&e, "racing", RepoVisibility::Private, 1);
    let anon = request(Procedure::ListRepos, &identity("selector"), None);
    assert!(listing(&e, &anon, "", 100, None).unwrap().repos.is_empty());
}

#[test]
fn single_addressing_lists_its_configured_public_repository() {
    let e = env(AuthMode::Open);
    let a = e.auth(&Req::unsigned(Procedure::ListRepos)).unwrap();
    let page = block_on(e.pipe.list_repos_page(&a, "root", "room", Some(1), None)).unwrap();
    assert_eq!(names(&page), [REPO]);
    assert!(page.next.is_none());
}

#[test]
fn unsigned_grants_are_rejected_and_scan_failures_are_redacted() {
    let mut e = setup(Sharding::D34, RepoVisibility::Public);
    let anon = request(Procedure::ListRepos, &identity("selector"), None);
    let unsigned_grant = anon.clone().header("x-write-grant", "unsigned");
    assert_eq!(
        listing(&e, &unsigned_grant, "", 100, None)
            .unwrap_err()
            .code(),
        Code::Unauthenticated
    );
    e.pipe.meta.fail_reads = true;
    let error = listing(&e, &anon, "", 100, None).unwrap_err();
    assert_eq!(error.code(), Code::Unavailable);
    assert_eq!(error.public_message(), "repository listing unavailable");
}

#[test]
fn malformed_visibility_fails_closed_for_registry_listing() {
    let e = setup(Sharding::D34, RepoVisibility::Public);
    create(&e, "a", 1);
    let a = e
        .auth(&request(
            Procedure::ListRepos,
            &identity("selector"),
            Some(&key(1)),
        ))
        .unwrap();
    let partition = e.pipe.shards.coordinator(&a.repo().repo.namespace);
    block_on(e.pipe.meta.inner.apply(
        &partition,
        Batch::new().put(
            keys::repo_visibility(&RepoName::new("a").unwrap()),
            Value::new(b"invalid".to_vec()),
        ),
    ))
    .unwrap();
    let owner = request(Procedure::ListRepos, &identity("selector"), Some(&key(1)));
    assert_eq!(
        listing(&e, &owner, "", 100, None).unwrap_err().code(),
        Code::Unavailable
    );
}

#[test]
fn continuations_accept_retained_keys_and_reject_removed_keys() {
    use crate::upload::token::TicketKeys;
    let mut e = setup(Sharding::D34, RepoVisibility::Public);
    create(&e, "a", 1);
    create(&e, "b", 2);
    let anon = request(Procedure::ListRepos, &identity("selector"), None);
    let token = listing(&e, &anon, "", 1, None).unwrap().next.unwrap();
    e.pipe.cfg.ticket_keys =
        Some(TicketKeys::new(vec![("new".into(), [8; 32]), ("test".into(), [7; 32])]).unwrap());
    assert_eq!(
        names(&listing(&e, &anon, "", 1, Some(&token)).unwrap()),
        ["b"]
    );
    e.pipe.cfg.ticket_keys = Some(TicketKeys::new(vec![("new".into(), [8; 32])]).unwrap());
    assert_eq!(
        listing(&e, &anon, "", 1, Some(&token)).unwrap_err().code(),
        Code::InvalidArgument
    );
}

struct ListingDenial(bool);
impl Authorizer for ListingDenial {
    async fn authorize(&self, op: &Operation) -> Result<AuthzFacts, ServerError> {
        if matches!(op.kind, OpKind::ListRepos { .. }) {
            Err(if self.0 {
                ServerError::unavailable("hook unavailable")
            } else {
                ServerError::permission_denied("hook denial")
            })
        } else {
            Ok(AuthzFacts::default())
        }
    }
}

#[test]
fn check_denials_and_failures_reject_every_view_before_storage() {
    for sharding in [Sharding::Single, Sharding::D34] {
        for unavailable in [false, true] {
            let mut cfg = config(&key(1), AuthorizerRole::Check);
            cfg.sharding = sharding;
            cfg.default_repo_visibility = RepoVisibility::Public;
            let clock = clock();
            let defaults = Hooks::new();
            let hooks = Hooks {
                authorizer: ListingDenial(unavailable),
                admission: defaults.admission,
                pre_receive: defaults.pre_receive,
                receipts: defaults.receipts,
                outcomes: defaults.outcomes,
            };
            let e = build(cfg, Spy::new(store(&clock)), hooks, clock);
            create(&e, "public", 1);
            let read_grant = grant(&key(1), &key(2), |g| {
                g.capabilities = mkit_attest::grant::Capabilities::Read;
                g.ref_scopes = None;
            });
            for req in [
                request(Procedure::ListRepos, &identity("selector"), None),
                request(Procedure::ListRepos, &identity("selector"), Some(&key(1))),
                request(Procedure::ListRepos, &identity("selector"), Some(&key(2))),
                request(Procedure::ListRepos, &identity("selector"), Some(&key(2)))
                    .header("x-write-grant", &read_grant),
            ] {
                let before = e.pipe.meta.calls();
                assert_eq!(
                    listing(&e, &req, "", 100, None).unwrap_err().code(),
                    if unavailable {
                        Code::Unavailable
                    } else {
                        Code::PermissionDenied
                    }
                );
                assert_eq!(e.pipe.meta.calls(), before);
            }
        }
    }
}

#[test]
fn authority_denial_selects_public_but_failure_does_not_fail_open() {
    for unavailable in [false, true] {
        let mut cfg = config(&key(1), AuthorizerRole::Authority);
        cfg.default_repo_visibility = RepoVisibility::Private;
        let clock = clock();
        let defaults = Hooks::new();
        let hooks = Hooks {
            authorizer: ListingDenial(unavailable),
            admission: defaults.admission,
            pre_receive: defaults.pre_receive,
            receipts: defaults.receipts,
            outcomes: defaults.outcomes,
        };
        let e = build(cfg, Spy::new(store(&clock)), hooks, clock);
        create(&e, "secret", 1);
        create(&e, "visible", 2);
        set(&e, "visible", RepoVisibility::Public, 3);
        for signer in [key(1), key(2)] {
            let authority = request(Procedure::ListRepos, &identity("selector"), Some(&signer));
            let result = listing(&e, &authority, "", 100, None);
            if unavailable {
                assert_eq!(result.unwrap_err().code(), Code::Unavailable);
            } else {
                assert_eq!(names(&result.unwrap()), ["visible"]);
            }
        }
    }
}

#[test]
fn single_addressing_honors_read_denial_hooks() {
    let clock = clock();
    let e = build(
        cfg(AuthMode::Open),
        Spy::new(store(&clock)),
        super::policy::policy_hooks(true),
        clock,
    );
    let a = e.auth(&Req::unsigned(Procedure::ListRepos)).unwrap();
    assert_eq!(
        block_on(e.pipe.list_repos_page(&a, "root", "", None, None))
            .unwrap_err()
            .code(),
        Code::PermissionDenied
    );
}

fn full_env(configure: impl FnOnce(&mut PipelineConfig)) -> Env<Hooks> {
    let mut cfg = config(&key(1), AuthorizerRole::Check);
    cfg.sharding = Sharding::D34;
    configure(&mut cfg);
    let clock = clock();
    build(
        cfg,
        Spy::new(store(&clock).with_capacity_limit(0)),
        Hooks::new(),
        clock,
    )
}

fn assert_full(e: &Env<Hooks>, error: &ServerError) {
    assert_eq!(error.code(), Code::Unavailable);
    assert_eq!(error.public_message(), "storage partition full");
    assert_eq!(e.metrics.count(METRIC_PARTITION_FULL), 1);
}

#[test]
fn full_epoch_transition_is_retryable() {
    let e = full_env(|_| {});
    let ns = NamespaceKey::deployment_default();
    assert_full(&e, &block_on(e.pipe.bump_epoch(&ns, 1)).unwrap_err());
}

#[test]
fn full_pending_reservation_is_retryable() {
    let e = full_env(|_| {});
    let req = request(Procedure::UpdateRef, &identity("new-repo"), Some(&key(1)));
    let a = e.auth(&req).unwrap();
    let partition = e.pipe.shards.coordinator(&a.repo().repo.namespace);
    let error = block_on(e.pipe.record_pending(&a, &partition, "rid")).unwrap_err();
    assert_full(&e, &error);
}

#[test]
fn full_authority_activation_is_retryable() {
    let clock = clock();
    let mut cfg = config(&key(1), AuthorizerRole::Authority);
    cfg.addressing = Addressing::Multi(crate::MultiAddressing::new().with_namespace_policy(
        crate::policy::NamespacePolicy::Any {
            unsafe_without_admission: true,
        },
    ));
    cfg.write_policy = WritePolicy::Owner;
    cfg.authority_fence = Some(
        crate::authority::AuthorityFence::parse(&format!(
            "deployment {} {}",
            to_hex(&key(8).verifying_key().to_bytes()),
            mkit_core::repo_identity::Namespace::Address([0x11; 20]),
        ))
        .unwrap(),
    );
    let defaults = Hooks::new();
    let hooks = Hooks {
        authorizer: Granting,
        admission: defaults.admission,
        pre_receive: defaults.pre_receive,
        receipts: defaults.receipts,
        outcomes: defaults.outcomes,
    };
    let e = build(
        cfg,
        Spy::new(store(&clock).with_capacity_limit(0)),
        hooks,
        clock,
    );
    let ns = NamespaceKey::deployment_default();
    let error = block_on(e.pipe.ensure_authority_activation(&ns)).unwrap_err();
    assert_eq!(error.code(), Code::Unavailable);
    assert_eq!(error.public_message(), "storage partition full");
    assert_eq!(e.metrics.count(METRIC_PARTITION_FULL), 1);
}

#[test]
fn full_ticket_and_admission_batches_share_the_typed_apply() {
    // Ticket-outcome (advance) and HTTP read admission batches use the same helper.
    let e = full_env(|_| {});
    let p = e
        .pipe
        .shards
        .coordinator(&NamespaceKey::deployment_default());
    let error = block_on(e.pipe.apply_meta(
        &p,
        Batch::new().put(keys::namespace_record(), Value::new(vec![1])),
    ))
    .unwrap_err();
    assert_full(&e, &error);
}
