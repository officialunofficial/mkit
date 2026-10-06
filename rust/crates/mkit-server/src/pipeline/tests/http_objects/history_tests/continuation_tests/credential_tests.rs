//! Cross-request scope checks using independently authenticated requests.
use super::*;
use mkit_attest::grant::{AcceptedSchemes, OwnerScheme, RepoScope};

struct ScopeAuthority;
impl Authorizer for ScopeAuthority {
    async fn authorize(&self, op: &Operation) -> Result<AuthzFacts, ServerError> {
        // Only these fixture keys are accepted; both are real auth-v2 signers.
        if op.principal != Principal::Anonymous
            && ![key(7), key(56)]
                .iter()
                .any(|key| op.principal.ed25519() == Some(key.verifying_key().as_bytes()))
        {
            return Err(ServerError::permission_denied("unknown fixture signer"));
        }
        Ok(AuthzFacts {
            caller_view: CallerView::Writer,
            ..AuthzFacts::default()
        })
    }
}
type ScopeFx = Fx<Hooks<ScopeAuthority>>;

fn scope_fixture(denial: bool) -> (ScopeFx, Hash, Hash) {
    let defaults = Hooks::new();
    let hooks = Hooks {
        authorizer: ScopeAuthority,
        admission: defaults.admission,
        pre_receive: defaults.pre_receive,
        receipts: defaults.receipts,
        outcomes: defaults.outcomes,
    };
    let mut fx = fixture_tweaked(hooks, http_cfg(), |cfg| {
        cfg.authorizer_role = AuthorizerRole::Authority;
        cfg.admission_credential_headers = vec!["X-Access-Credential".into()];
        cfg.grants = Some(
            GrantConfig::new(
                AUDIENCE,
                AcceptedSchemes::of(&[OwnerScheme::Ed25519]),
                vec![],
            )
            .unwrap(),
        );
    });
    let root = tree(&[]);
    let base = commit(&root, &[], "base");
    let middle = commit(&root, &[&base], "middle");
    let head = commit(&root, &[&middle], "head");
    fx.push("room", &[&root, &base, &middle, &head], id(&head), None);
    fx.pipe.cfg.takedown_denial = denial;
    enable(&mut fx);
    (fx, id(&head), id(&middle))
}

fn scope_grant(fx: &ScopeFx, signer: &SigningKey, number: u8) -> String {
    crate::pipeline::tests::grants::grant(&fx.owner, signer, |grant| {
        grant.scope = RepoScope::Repository(
            mkit_core::repo_identity::RepositoryIdentity::parse(&fx.identity("room")).unwrap(),
        );
        grant.nonce = [number; 32];
    })
}

fn envelope(fx: &ScopeFx, signer: &SigningKey, audience: &str, created: i64) -> Req {
    let mut req = signed(
        signer,
        &fx.identity("room"),
        Procedure::ListRefs,
        fx.number(),
    );
    let commitment = format!("body:{}", to_hex(&hash(&req.body)));
    let nonce = nonce(fx.number());
    let identity = fx.identity("room");
    let op = SignedOp {
        context: AuthContext {
            audience,
            repository: &identity,
        },
        procedure: Procedure::ListRefs.connect_path(),
        commitment: &commitment,
        created_at: created,
        expires_at: created + 300_000,
        nonce: &nonce,
    };
    let signature = signer.sign(&op.digest().unwrap());
    req = req
        .header("x-audience", audience)
        .header("x-created-at", &created.to_string())
        .header("x-expires-at", &(created + 300_000).to_string())
        .header("idempotency-key", &nonce)
        .header("x-signature", &to_hex_bytes(&signature.to_bytes()));
    req
}

fn with_request(
    fx: &ScopeFx,
    req: Option<&Req>,
    test: impl FnOnce(ObjectReader<'_, SpyBlobs, Arc<Spy>, Hooks<ScopeAuthority>>),
) {
    let values = |name: &str| {
        req.into_iter()
            .flat_map(|req| &req.headers)
            .filter(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.clone())
            .collect::<Vec<_>>()
    };
    let lookup = |name: &str| values(name).first().cloned();
    let meta = RequestMeta {
        procedure: Procedure::ListRefs,
        header: &lookup,
        header_values: Some(&values),
        unary_body: req.map(|req| req.body.as_slice()),
        transport_principal: None,
    };
    let view = req.map_or(ReaderView::Public, |_| ReaderView::Owner(&meta));
    let reader = block_on(fx.pipe.object_reader(fx.repo_id("room"), view)).unwrap();
    test(reader);
}

fn issue(fx: &ScopeFx, req: Option<&Req>) -> HistoryContinuation {
    let mut token = None;
    with_request(fx, req, |reader| {
        token = block_on(reader.walk_history_page_in(&mut ReaderSession::default(), HEAD, None, 1))
            .unwrap()
            .unwrap()
            .next;
    });
    token.unwrap()
}

fn accepts_fresh(
    fx: &ScopeFx,
    req: Option<&Req>,
    token: &HistoryContinuation,
    head: Hash,
    cursor: Hash,
) {
    // Verification time also changes between requests; it is not stable scope.
    fx.clock.set(fx.clock.now_ms() + 1);
    with_request(fx, req, |reader| {
        let mut session = ReaderSession::default();
        let page = block_on(reader.walk_history_page_in(
            &mut session,
            HEAD,
            Some(token.token.expose()),
            1,
        ))
        .unwrap()
        .unwrap();
        assert_eq!(page.commits.len(), 1);
        assert_eq!(page.commits[0].id, cursor);
        assert_eq!(page.next.unwrap().expires_at_ms, token.expires_at_ms);
        assert!(session.used().storage_calls > 0);
        assert!(session.used().decoded_bytes > 0);
        assert!(session.used().output_bytes > 0);
        assert!(!session.proofs.contains(&head));
        assert!(
            !session.proofs.contains(&cursor),
            "paging evidence stays isolated"
        );
    });
}

fn rejects_scope(fx: &ScopeFx, req: Option<&Req>, token: &HistoryContinuation, cursor: Hash) {
    with_request(fx, req, |reader| {
        let mut session = ReaderSession::default();
        // Replay the same mismatch in one ledger: refusal never refunds work.
        for _ in 0..2 {
            let spent = session.used();
            let before = fx.calls.lock().unwrap().len();
            let keys_before = fx.pipe.meta.seen.lock().unwrap().len();
            let ops_before = fx.pipe.meta.ops.lock().unwrap().len();
            assert!(
                block_on(reader.walk_history_page_in(
                    &mut session,
                    HEAD,
                    Some(token.token.expose()),
                    1,
                ))
                .unwrap()
                .is_none(),
                "credential mismatch is uniform absence"
            );
            assert_eq!(
                fx.calls.lock().unwrap().len(),
                before,
                "no cursor blob HEAD/GET"
            );
            assert!(
                fx.pipe.meta.seen.lock().unwrap()[keys_before..]
                    .iter()
                    .all(|key| !key
                        .as_bytes()
                        .windows(cursor.len())
                        .any(|bytes| bytes == cursor)),
                "no cursor-key membership or location probe"
            );
            assert!(
                fx.pipe.meta.ops.lock().unwrap()[ops_before..]
                    .iter()
                    .all(|op| matches!(*op, "get" | "get_many")),
                "mismatch performs no index scan or apply"
            );
            assert!(session.used().decoded_bytes > spent.decoded_bytes);
            assert!(session.used().storage_calls >= spent.storage_calls);
            assert_eq!(session.used().output_bytes, spent.output_bytes);
            assert!(!session.proofs.contains(&cursor));
        }
        // Independently demonstrate B has permission to page this same ref.
        let page = block_on(reader.walk_history_page_in(&mut session, HEAD, None, 1))
            .unwrap()
            .unwrap();
        assert!(page.next.is_some());
        assert!(!session.proofs.contains(&cursor));
    });
}

#[test]
fn continuation_cross_credential_signers() {
    for denial in [false, true] {
        let (fx, head, cursor) = scope_fixture(denial);
        let other = key(56);
        let grant = scope_grant(&fx, &other, 1);
        let a = envelope(&fx, &fx.owner, AUDIENCE, T0);
        let fresh = envelope(&fx, &fx.owner, AUDIENCE, T0 - 1);
        let b = envelope(&fx, &other, AUDIENCE, T0).header("x-write-grant", &grant);
        let fresh_b = envelope(&fx, &other, AUDIENCE, T0 - 1).header("x-write-grant", &grant);
        let token = issue(&fx, Some(&a));
        accepts_fresh(&fx, Some(&fresh), &token, head, cursor);
        rejects_scope(&fx, Some(&b), &token, cursor);
        let token = issue(&fx, Some(&b));
        accepts_fresh(&fx, Some(&fresh_b), &token, head, cursor);
        rejects_scope(&fx, Some(&a), &token, cursor);
    }
}

#[test]
fn continuation_cross_credential_same_grant_signers() {
    for denial in [false, true] {
        let (fx, head, cursor) = scope_fixture(denial);
        let other = key(56);
        let grant = scope_grant(&fx, &other, 1);
        // On a public repo the Authority hook may classify the namespace owner
        // as Writer despite a grant naming someone else. The reader accepts
        // actual ownership for A and this same valid grant for B: only signer differs.
        for (a, b) in [(&fx.owner, &other), (&other, &fx.owner)] {
            let issued = envelope(&fx, a, AUDIENCE, T0).header("x-write-grant", &grant);
            let fresh = envelope(&fx, a, AUDIENCE, T0 - 1).header("x-write-grant", &grant);
            let changed = envelope(&fx, b, AUDIENCE, T0).header("x-write-grant", &grant);
            let token = issue(&fx, Some(&issued));
            accepts_fresh(&fx, Some(&fresh), &token, head, cursor);
            rejects_scope(&fx, Some(&changed), &token, cursor);
        }
    }
}

#[test]
fn continuation_cross_credential_no_grant_authority_cannot_construct_owner_reader() {
    for denial in [false, true] {
        for private in [false, true] {
            let (fx, _, _) = scope_fixture(denial);
            if private {
                fx.make_private("room");
            }
            for signer in [&fx.owner, &key(56)] {
                let req = envelope(&fx, signer, AUDIENCE, T0);
                let auth = fx.auth(&req);
                assert!(auth.write_grant.is_none());
                let op = fx
                    .pipe
                    .identify(
                        &auth,
                        OpKind::ListRefs {
                            prefix: "refs/".into(),
                        },
                    )
                    .unwrap();
                assert_eq!(
                    block_on(fx.pipe.authorize_read(&op))
                        .unwrap()
                        .facts
                        .caller_view,
                    CallerView::Writer
                );
                assert!(
                    !block_on(fx.pipe.list_refs(&auth, "refs/"))
                        .unwrap()
                        .is_empty()
                );
                let lookup = |name: &str| {
                    req.headers
                        .iter()
                        .find(|(n, _)| *n == name)
                        .map(|(_, v)| v.clone())
                };
                let meta = RequestMeta {
                    procedure: req.procedure,
                    header: &lookup,
                    header_values: None,
                    unary_body: Some(&req.body),
                    transport_principal: None,
                };
                let result = block_on(
                    fx.pipe
                        .object_reader(fx.repo_id("room"), ReaderView::Owner(&meta)),
                );
                if signer == &fx.owner {
                    assert!(result.is_ok());
                } else {
                    assert_eq!(result.err().unwrap().code(), Code::PermissionDenied);
                }
            }
        }
    }
}

#[test]
fn continuation_cross_credential_grants() {
    for denial in [false, true] {
        let (fx, head, cursor) = scope_fixture(denial);
        let grants = [
            scope_grant(&fx, &fx.owner, 1),
            scope_grant(&fx, &fx.owner, 2),
        ];
        for grant in [Some(&grants[0]), Some(&grants[1]), None] {
            let decorate = |req: Req| match grant {
                Some(g) => req.header("x-write-grant", g),
                None => req,
            };
            let a = decorate(envelope(&fx, &fx.owner, AUDIENCE, T0));
            let fresh = decorate(envelope(&fx, &fx.owner, AUDIENCE, T0 - 1));
            let token = issue(&fx, Some(&a));
            accepts_fresh(&fx, Some(&fresh), &token, head, cursor);
            for other in [Some(&grants[0]), Some(&grants[1]), None] {
                if other == grant {
                    continue;
                }
                let mut b = envelope(&fx, &fx.owner, AUDIENCE, T0);
                if let Some(g) = other {
                    b = b.header("x-write-grant", g);
                }
                rejects_scope(&fx, Some(&b), &token, cursor);
            }
        }
    }
}

#[test]
fn continuation_cross_credential_headers() {
    for denial in [false, true] {
        let (fx, head, cursor) = scope_fixture(denial);
        for name in [
            "payment-authorization",
            "payment-signature",
            "authorization",
            "x-access-credential",
        ] {
            let a = envelope(&fx, &fx.owner, AUDIENCE, T0).header(name, "credential-a");
            let fresh = envelope(&fx, &fx.owner, AUDIENCE, T0 - 1).header(name, "credential-a");
            let token = issue(&fx, Some(&a));
            accepts_fresh(&fx, Some(&fresh), &token, head, cursor);
            let b = envelope(&fx, &fx.owner, AUDIENCE, T0).header(name, "credential-b");
            rejects_scope(&fx, Some(&b), &token, cursor);
            // Multi-value capture must bind the full ordered list, not its first value.
            let mut b = envelope(&fx, &fx.owner, AUDIENCE, T0).header(name, "credential-a");
            b.headers.push((name, "credential-b".into()));
            rejects_scope(&fx, Some(&b), &token, cursor);
            let b = envelope(&fx, &fx.owner, AUDIENCE, T0);
            rejects_scope(&fx, Some(&b), &token, cursor);
        }
    }
}

#[test]
fn continuation_cross_credential_audience() {
    for denial in [false, true] {
        for owner in [false, true] {
            let (mut fx, head, cursor) = scope_fixture(denial);
            let a = envelope(&fx, &fx.owner, AUDIENCE, T0);
            let fresh = envelope(&fx, &fx.owner, AUDIENCE, T0 - 1);
            let token = issue(&fx, owner.then_some(&a));
            accepts_fresh(&fx, owner.then_some(&fresh), &token, head, cursor);
            let audience = "https://other.example.test";
            fx.pipe.cfg.auth = AuthMode::AuthV2(AuthV2Config::new(audience, REPO).unwrap());
            fx.pipe.cfg.grants = Some(
                GrantConfig::new(
                    audience,
                    AcceptedSchemes::of(&[OwnerScheme::Ed25519]),
                    vec![],
                )
                .unwrap(),
            );
            let b = envelope(&fx, &fx.owner, audience, T0);
            rejects_scope(&fx, owner.then_some(&b), &token, cursor);
            let fresh = envelope(&fx, &fx.owner, audience, T0 - 1);
            let token = issue(&fx, owner.then_some(&b));
            accepts_fresh(&fx, owner.then_some(&fresh), &token, head, cursor);
        }
    }
}

#[test]
fn continuation_cross_credential_anonymous_authenticated() {
    for denial in [false, true] {
        let (fx, head, cursor) = scope_fixture(denial);
        let a = envelope(&fx, &fx.owner, AUDIENCE, T0);
        let fresh = envelope(&fx, &fx.owner, AUDIENCE, T0 - 1);
        for owner in [false, true] {
            let token = issue(&fx, owner.then_some(&a));
            accepts_fresh(&fx, owner.then_some(&fresh), &token, head, cursor);
            rejects_scope(&fx, (!owner).then_some(&fresh), &token, cursor);
        }
    }
}
