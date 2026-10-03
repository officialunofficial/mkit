//! Stateless token verification must precede the only epoch read.
use super::*;
use crate::http_objects::TokenGate;
use crate::url_token::{Prechecked, TokenRejected, UrlTarget, UrlTokenConfig, UrlTokenKeys};
use zeroize::Zeroizing;

pub(super) fn tokens() -> UrlTokenConfig {
    UrlTokenConfig::new(UrlTokenKeys::new(Zeroizing::new([13; 32]), vec![]).unwrap())
}
fn setup() -> (Fx<Scripts>, Data, Arc<Scripted>, UrlTokenConfig) {
    let tokens = tokens();
    let az = Arc::new(Scripted::default());
    let fx = fixture_tweaked(scripted(&az), http_cfg(), |c| {
        c.url_tokens = Some(tokens.clone());
    });
    let d = data();
    fx.push("room", &d.refs(), d.head(), None);
    fx.make_private("room");
    az.seen.lock().unwrap().clear();
    (fx, d, az, tokens)
}
fn mint<H: HookSet>(fx: &Fx<H>, tokens: &UrlTokenConfig, target: &UrlTarget, epoch: u64) -> String {
    tokens
        .mint(
            AUDIENCE,
            &fx.identity("room"),
            target,
            epoch,
            fx.clock.now_ms(),
            60,
        )
        .unwrap()
        .expose()
        .to_owned()
}
fn with_token<H: HookSet>(
    fx: &Fx<H>,
    method: &str,
    path: &str,
    token: &str,
    headers: &[(&str, &str)],
) -> Got {
    read(fx.request(method, path, Some(&format!("token={token}")), headers))
}
fn reset<H: HookSet>(fx: &Fx<H>) {
    fx.pipe.meta.seen.lock().unwrap().clear();
}
fn epoch_read<H: HookSet>(fx: &Fx<H>) -> bool {
    fx.pipe.meta.seen().contains(&keys::grant_epoch())
}

struct OrderedGate {
    tokens: UrlTokenConfig,
    store: Arc<Spy>,
}
impl TokenGate for OrderedGate {
    fn precheck(&self, token: &crate::Redacted, now: i64) -> Result<Prechecked, TokenRejected> {
        assert!(
            self.store.seen().is_empty(),
            "precheck must precede rr/rv and all other stored reads"
        );
        self.tokens.precheck(token.expose(), now)
    }
    fn ttl_ms(&self) -> u64 {
        self.tokens.ttl_ms()
    }
}

#[test]
fn stateless_checks_precede_stored_epoch_and_valid_tokens_remain_anonymous() {
    let (fx, d, az, tokens) = setup();
    let gate = Arc::new(OrderedGate {
        tokens: tokens.clone(),
        store: fx.pipe.meta.clone(),
    });
    let fx = with_seams(fx, |s| s.tokens = gate);
    let target = UrlTarget::Object(id(&d.small));
    let path = fx.object_url("room", &id(&d.small));
    let valid = mint(&fx, &tokens, &target, 0);
    let wrong_target = mint(&fx, &tokens, &UrlTarget::Object([9; 32]), 0);
    let wrong_repo = tokens
        .mint(
            AUDIENCE,
            &fx.identity("elsewhere"),
            &target,
            0,
            fx.clock.now_ms(),
            60,
        )
        .unwrap();
    let wrong_audience = tokens
        .mint(
            "https://other.test",
            &fx.identity("room"),
            &target,
            0,
            fx.clock.now_ms(),
            60,
        )
        .unwrap();
    for token in [
        "garbage",
        wrong_target.as_str(),
        wrong_repo.expose(),
        wrong_audience.expose(),
    ] {
        reset(&fx);
        assert_uniform_404(&with_token(&fx, "GET", &path, token, &[]));
        assert!(!epoch_read(&fx));
        assert!(az.seen.lock().unwrap().is_empty());
        assert_eq!(
            fx.pipe.meta.seen(),
            [
                keys::repo_record(&RepoName::new("room").unwrap()),
                keys::repo_visibility(&RepoName::new("room").unwrap())
            ]
        );
    }
    reset(&fx);
    let got = with_token(&fx, "GET", &path, &valid, &[]);
    assert_eq!(got.status, 200);
    assert_eq!(got.body, d.small_bytes);
    assert!(epoch_read(&fx));
    assert_eq!(
        *az.seen.lock().unwrap(),
        [(Procedure::HttpGetObject, "anonymous")]
    );
    assert_eq!(
        got.header("Cache-Control"),
        Some("private, max-age=60, immutable")
    );
    // Proof selectors never change an object token target.
    reset(&fx);
    let proof = read(fx.request(
        "GET",
        &path,
        Some(&format!(
            "token={valid}&proof=1&commit={}&path=small.txt",
            to_hex(&d.head())
        )),
        &[],
    ));
    assert_eq!(proof.status, 416);
    assert!(epoch_read(&fx));
}

#[test]
fn missing_and_private_token_failures_have_identical_get_and_head_responses() {
    let (fx, d, _, tokens) = setup();
    let path = fx.object_url("room", &id(&d.small));
    let missing = fx.object_url("missing", &id(&d.small));
    let other = UrlTokenConfig::new(UrlTokenKeys::new(Zeroizing::new([14; 32]), vec![]).unwrap());
    let bad_key = mint(&fx, &other, &UrlTarget::Object(id(&d.small)), 0);
    let epoch = mint(&fx, &tokens, &UrlTarget::Object(id(&d.small)), 1);
    let valid = mint(&fx, &tokens, &UrlTarget::Object(id(&d.small)), 0);
    let mut bad_sig = valid.clone().into_bytes();
    let dot = bad_sig.iter().position(|b| *b == b'.').unwrap();
    bad_sig[dot + 1] = if bad_sig[dot + 1] == b'A' { b'B' } else { b'A' };
    let bad_sig = String::from_utf8(bad_sig).unwrap();
    for method in ["GET", "HEAD"] {
        let baseline = read(fx.request(method, &missing, None, &[]));
        for token in [
            None,
            Some("bad"),
            Some(bad_key.as_str()),
            Some(bad_sig.as_str()),
            Some(epoch.as_str()),
        ] {
            let got = match token {
                Some(token) => with_token(&fx, method, &path, token, &[]),
                None => read(fx.request(method, &path, None, &[])),
            };
            assert_eq!(
                (got.status, got.headers, got.body),
                (
                    baseline.status,
                    baseline.headers.clone(),
                    baseline.body.clone()
                )
            );
        }
    }
}

#[test]
fn public_repositories_ignore_even_valid_wrong_claims_and_never_read_epoch() {
    let (fx, d, _, tokens) = setup();
    let repo = fx.repo_id("room");
    block_on(fx.pipe.meta.inner.apply(
        &fx.pipe.shards.coordinator(&repo.namespace),
        Batch::new().delete(keys::repo_visibility(&repo.name)),
    ))
    .unwrap();
    let path = fx.object_url("room", &id(&d.small));
    let wrong = tokens
        .mint(
            "https://wrong.test",
            &fx.identity("missing"),
            &UrlTarget::Object([9; 32]),
            99,
            fx.clock.now_ms() - 61_000,
            60,
        )
        .unwrap();
    for token in ["bad", wrong.expose()] {
        reset(&fx);
        let got = with_token(&fx, "GET", &path, token, &[]);
        assert_eq!(got.status, 200);
        assert_eq!(got.header("Cache-Control"), Some(IMMUTABLE));
        assert!(!epoch_read(&fx));
    }
}

#[test]
fn private_cache_uses_floored_remaining_lifetime_and_304_preserves_it() {
    let (fx, d, _, tokens) = setup();
    let path = fx.object_url("room", &id(&d.small));
    let valid = mint(&fx, &tokens, &UrlTarget::Object(id(&d.small)), 0);
    fx.clock.advance(1);
    let etag = format!("\"{}\"", to_hex(&id(&d.small)));
    for (method, headers, status) in [
        ("GET", vec![], 200),
        ("HEAD", vec![], 200),
        ("GET", vec![("range", "bytes=0-9")], 206),
        ("GET", vec![("if-none-match", etag.as_str())], 304),
    ] {
        let got = with_token(&fx, method, &path, &valid, &headers);
        assert_eq!(got.status, status);
        assert_eq!(
            got.header("Cache-Control"),
            Some("private, max-age=59, immutable")
        );
    }
    fx.clock.advance(59_000);
    assert_eq!(
        with_token(&fx, "GET", &path, &valid, &[]).header("Cache-Control"),
        Some("private, max-age=0, immutable")
    );
    fx.clock.advance(999);
    reset(&fx);
    assert_uniform_404(&with_token(&fx, "GET", &path, &valid, &[]));
    assert!(!epoch_read(&fx));
}

#[test]
fn path_targets_include_root_and_reject_non_utf8_without_epoch_access() {
    let (fx, d, _, tokens) = setup();
    for (file, want) in [
        ("", serialize(&d.root).unwrap()),
        ("small.txt", d.small_bytes.clone()),
    ] {
        let target = UrlTarget::path(HEAD, file).unwrap();
        let valid = mint(&fx, &tokens, &target, 0);
        let path = fx.ref_url("room", "main", file);
        let got = with_token(&fx, "GET", &path, &valid, &[]);
        assert_eq!(got.status, 200);
        assert_eq!(got.body, want);
        assert_eq!(got.header("Cache-Control"), Some("private, no-cache"));
        assert_eq!(
            got.header("X-Mkit-Commit"),
            Some(to_hex(&d.head()).as_str())
        );
    }
    let valid = mint(
        &fx,
        &tokens,
        &UrlTarget::path(HEAD, "small.txt").unwrap(),
        0,
    );
    let escaped = fx.ref_url("room", "main", "small%2Etxt");
    assert_eq!(with_token(&fx, "GET", &escaped, &valid, &[]).status, 200);
    let non_utf8 = fx.ref_url("room", "main", "%FF");
    reset(&fx);
    assert_uniform_404(&with_token(&fx, "GET", &non_utf8, &valid, &[]));
    assert!(!epoch_read(&fx));
}

#[test]
fn token_does_not_bypass_authorizer_denials_or_storage_failures() {
    let (fx, d, az, tokens) = setup();
    let path = fx.object_url("room", &id(&d.small));
    let valid = mint(&fx, &tokens, &UrlTarget::Object(id(&d.small)), 0);
    for (code, status) in [
        (Code::PermissionDenied, 404),
        (Code::NotFound, 404),
        (Code::Unauthenticated, 404),
        (Code::Unavailable, 503),
        (Code::Internal, 503),
    ] {
        *az.verdict.lock().unwrap() = Some(code);
        let got = with_token(&fx, "GET", &path, &valid, &[]);
        assert_eq!(got.status, status);
        if status == 404 {
            assert_uniform_404(&got);
        }
    }
    assert_eq!(az.seen.lock().unwrap().len(), 5);
}

#[test]
fn lifetime_epoch_and_key_retirement_are_enforced_by_the_serving_path() {
    let (fx, d, _, tokens) = setup();
    let path = fx.object_url("room", &id(&d.small));
    let target = UrlTarget::Object(id(&d.small));
    let valid = mint(&fx, &tokens, &target, 0);
    let shorter = UrlTokenConfig::with_ttl_ms(
        UrlTokenKeys::new(Zeroizing::new([13; 32]), vec![]).unwrap(),
        30_000,
    )
    .unwrap();
    let fx = with_seams(fx, |s| s.tokens = Arc::new(shorter));
    reset(&fx);
    assert_uniform_404(&with_token(&fx, "GET", &path, &valid, &[]));
    assert!(!epoch_read(&fx));
    let retired_at_ms = u64::try_from(fx.clock.now_ms()).unwrap();
    let rotated = UrlTokenConfig::with_ttl_ms(
        UrlTokenKeys::new(
            Zeroizing::new([14; 32]),
            vec![crate::url_token::RetiredKey {
                public: key(13).verifying_key().to_bytes(),
                retired_at_ms,
            }],
        )
        .unwrap(),
        60_000,
    )
    .unwrap();
    let fx = with_seams(fx, |s| s.tokens = Arc::new(rotated));
    assert_eq!(with_token(&fx, "GET", &path, &valid, &[]).status, 200);
    let repo = fx.repo_id("room");
    block_on(fx.pipe.meta.inner.apply(
        &fx.pipe.shards.coordinator(&repo.namespace),
        Batch::new().put(keys::grant_epoch(), codec::encode_u64(1)),
    ))
    .unwrap();
    reset(&fx);
    assert_uniform_404(&with_token(&fx, "GET", &path, &valid, &[]));
    assert!(epoch_read(&fx));
    fx.clock.advance(60_000);
    reset(&fx);
    assert_uniform_404(&with_token(&fx, "GET", &path, &valid, &[]));
    assert!(!epoch_read(&fx));
}

#[test]
fn private_proofs_keep_token_bounded_immutable_or_ref_revalidation_policy() {
    let (fx, d, _, tokens) = setup();
    let fx = with_seams(fx, |s| s.proofs = Arc::new(Proofs(Mutex::default())));
    for (path, target, selector, cache) in [
        (
            fx.ref_url("room", "main", "small.txt"),
            UrlTarget::path(HEAD, "small.txt").unwrap(),
            String::new(),
            "private, no-cache",
        ),
        (
            fx.object_url("room", &id(&d.small)),
            UrlTarget::Object(id(&d.small)),
            format!("&commit={}&path=small.txt", to_hex(&d.head())),
            "private, max-age=60, immutable",
        ),
    ] {
        let valid = mint(&fx, &tokens, &target, 0);
        let got = read(fx.request(
            "GET",
            &path,
            Some(&format!("token={valid}&proof=1{selector}")),
            &[],
        ));
        assert_eq!(got.status, 200);
        assert_eq!(got.header("Cache-Control"), Some(cache));
    }
}

#[test]
fn all_retained_url_token_keys_are_separated_from_every_ticket_secret() {
    let fx = fixture();
    let mut cfg = fx.pipe.cfg.clone();
    cfg.url_tokens = Some(UrlTokenConfig::new(
        UrlTokenKeys::new(
            Zeroizing::new([13; 32]),
            vec![crate::url_token::RetiredKey {
                public: key(7).verifying_key().to_bytes(),
                retired_at_ms: u64::try_from(fx.clock.now_ms()).unwrap(),
            }],
        )
        .unwrap(),
    ));
    let error = Pipeline::new(
        fx.pipe.blobs.clone(),
        fx.pipe.meta.clone(),
        Hooks::new(),
        cfg,
        fx.clock.clone(),
        fx.metrics.clone(),
    )
    .unwrap_err();
    assert_eq!(
        error.public_message(),
        "the URL token key must differ from the upload ticket keys"
    );
}

#[test]
fn corrupt_epoch_fails_closed_after_binding_and_public_reads_ignore_it() {
    let (fx, d, _, tokens) = setup();
    let repo = fx.repo_id("room");
    let partition = fx.pipe.shards.coordinator(&repo.namespace);
    block_on(fx.pipe.meta.inner.apply(
        &partition,
        Batch::new().put(keys::grant_epoch(), Value::new(b"invalid epoch".to_vec())),
    ))
    .unwrap();
    let path = fx.object_url("room", &id(&d.small));
    let valid = mint(&fx, &tokens, &UrlTarget::Object(id(&d.small)), 0);
    assert_uniform_404(&with_token(&fx, "GET", &path, "bad", &[]));
    let got = with_token(&fx, "GET", &path, &valid, &[]);
    assert_eq!(got.status, 503);
    assert_eq!(got.header("Cache-Control"), Some("no-store"));
    assert_eq!(got.header("ETag"), None);
    block_on(fx.pipe.meta.inner.apply(
        &partition,
        Batch::new().delete(keys::repo_visibility(&repo.name)),
    ))
    .unwrap();
    reset(&fx);
    assert_eq!(with_token(&fx, "GET", &path, &valid, &[]).status, 200);
    assert!(!epoch_read(&fx));
}

#[test]
fn valid_private_url_tokens_and_proofs_cannot_expose_pending_content() {
    let tokens = tokens();
    let az = Arc::new(Scripted::default());
    let mut fx = fixture_tweaked(scripted(&az), http_cfg(), |c| {
        c.url_tokens = Some(tokens.clone());
    });
    fx.pipe = fx
        .pipe
        .with_publication_policy(Arc::new(super::super::indexed::InspectionPolicy(
            crate::store::publication::Clearance::Pending,
        )))
        .unwrap();
    let d = data();
    let mut writer = PackWriter::new_raw_only();
    for object in &d.all {
        writer
            .push_raw(id(object), &serialize(object).unwrap())
            .unwrap();
    }
    let pack = writer.finish().unwrap();
    let map = mkit_core::transfer::encode_packlist(None, &[hash(&pack)]).unwrap();
    let identity = fx.identity("room");
    let mut tickets = Vec::new();
    for bytes in [&pack, &map] {
        let req = signed(&fx.owner, &identity, Procedure::BeginUpload, fx.number());
        let BeginUploadResult::Ticket { id: ticket, .. } =
            block_on(
                fx.pipe
                    .begin_upload(&fx.auth(&req), HEAD, &hash(bytes), bytes.len() as u64),
            )
            .unwrap()
        else {
            panic!("ticket")
        };
        block_on(async {
            let mut sink = fx
                .pipe
                .blobs
                .begin(BlobKey::pack(hash(bytes)), bytes.len() as u64)
                .await
                .unwrap();
            sink.write(Bytes::copy_from_slice(bytes)).await.unwrap();
            sink.commit().await.unwrap();
            write_upload_marker(&fx.pipe.blobs, &ticket, &hash(bytes))
                .await
                .unwrap();
        });
        tickets.push(ticket);
    }
    let req = signed(&fx.owner, &identity, Procedure::AdvanceRefs, fx.number());
    assert_eq!(
        super::super::indexed::complete(|| block_on(fx.pipe.advance_refs_with_tickets(
            &fx.auth(&req),
            upd(HEAD, Missing, d.head()),
            upd(PACKMAP, Missing, hash(&map)),
            tickets.clone()
        )))
        .unwrap(),
        AdvanceOutcome::Committed
    );
    fx.make_private("room");
    let proofs = Arc::new(Proofs(Mutex::new(Vec::new())));
    let fx = with_seams(fx, |s| s.proofs = proofs.clone());
    for (path, target) in [
        (
            fx.object_url("room", &id(&d.small)),
            UrlTarget::Object(id(&d.small)),
        ),
        (
            fx.ref_url("room", "main", "small.txt"),
            UrlTarget::path(HEAD, "small.txt").unwrap(),
        ),
    ] {
        let token = mint(&fx, &tokens, &target, 0);
        for method in ["GET", "HEAD"] {
            assert_eq!(with_token(&fx, method, &path, &token, &[]).status, 404);
            let query = if matches!(target, UrlTarget::Object(_)) {
                format!(
                    "token={token}&proof=1&commit={}&path=small.txt",
                    to_hex(&d.head())
                )
            } else {
                format!("token={token}&proof=1")
            };
            assert_eq!(
                read(fx.request(method, &path, Some(&query), &[])).status,
                404
            );
        }
    }
    assert!(proofs.0.lock().unwrap().is_empty());
}

#[test]
fn private_ref_token_file_headers_do_not_change_binding_or_caching() {
    let (fx, d, _, tokens) = setup();
    let target = UrlTarget::Path {
        reference: HEAD.into(),
        path: "small.txt".into(),
    };
    let token = mint(&fx, &tokens, &target, 0);
    let path = fx.ref_url("room", "main", "small.txt");
    for method in ["GET", "HEAD"] {
        let got = with_token(&fx, method, &path, &token, &[]);
        assert_eq!(got.status, 200);
        assert_eq!(
            got.header("Content-Type"),
            Some("text/plain; charset=utf-8")
        );
        assert_eq!(
            got.header("Content-Disposition"),
            Some("inline; filename=\"small.txt\"; filename*=UTF-8''small.txt")
        );
        assert_eq!(got.header("Cache-Control"), Some("private, no-cache"));
        assert_eq!(
            got.body,
            if method == "HEAD" {
                vec![]
            } else {
                d.small_bytes.clone()
            }
        );
    }
    assert_uniform_404(&with_token(
        &fx,
        "GET",
        &fx.ref_url("room", "main", "big.bin"),
        &token,
        &[],
    ));
}

fn set_visibility<H: HookSet>(fx: &Fx<H>, visibility: crate::pipeline::RepoVisibility) {
    let req = signed(
        &fx.owner,
        &fx.identity("room"),
        Procedure::SetRepoVisibility,
        fx.number(),
    );
    block_on(
        fx.pipe
            .set_repo_visibility(&fx.auth(&req), VisibilityRequest::Envelope(visibility)),
    )
    .unwrap();
}

/// A token is a bearer read grant for the repository as it was private when
/// issued: a visibility change after issuance revokes it even though the
/// namespace epoch is untouched (SPEC-WRITE-GRANTS §9.4).
#[test]
fn tokens_issued_before_a_visibility_change_are_refused() {
    use crate::pipeline::RepoVisibility::{Private, Public};
    let (fx, d, _, tokens) = setup();
    let object = (
        fx.object_url("room", &id(&d.small)),
        UrlTarget::Object(id(&d.small)),
    );
    let by_ref = (
        fx.ref_url("room", "main", "small.txt"),
        UrlTarget::path(HEAD, "small.txt").unwrap(),
    );
    let serves = |fx: &Fx<Scripts>, token: &str, path: &str| {
        with_token(fx, "GET", path, token, &[]).status == 200
    };
    let mint_both = |fx: &Fx<Scripts>| {
        (
            mint(fx, &tokens, &object.1, 0),
            mint(fx, &tokens, &by_ref.1, 0),
        )
    };

    // Private -> public -> private revokes tokens issued while private.
    let (obj_a, ref_a) = mint_both(&fx);
    assert!(serves(&fx, &obj_a, &object.0) && serves(&fx, &ref_a, &by_ref.0));
    fx.clock.advance(1_000);
    set_visibility(&fx, Public);
    fx.clock.advance(1_000);
    set_visibility(&fx, Private);
    fx.clock.advance(1_000);
    assert!(!serves(&fx, &obj_a, &object.0), "object token survived");
    assert!(!serves(&fx, &ref_a, &by_ref.0), "ref token survived");

    // A token issued after the latest change works.
    let (obj_b, ref_b) = mint_both(&fx);
    assert!(serves(&fx, &obj_b, &object.0) && serves(&fx, &ref_b, &by_ref.0));

    // Public -> private revokes a token issued while public, and the
    // earlier private-era token again.
    fx.clock.advance(1_000);
    set_visibility(&fx, Public);
    fx.clock.advance(1_000);
    let (obj_c, ref_c) = mint_both(&fx);
    fx.clock.advance(1_000);
    set_visibility(&fx, Private);
    fx.clock.advance(1_000);
    for (token, path) in [
        (&obj_b, &object.0),
        (&ref_b, &by_ref.0),
        (&obj_c, &object.0),
        (&ref_c, &by_ref.0),
    ] {
        assert!(!serves(&fx, token, path));
    }
    let (obj_d, ref_d) = mint_both(&fx);
    assert!(serves(&fx, &obj_d, &object.0) && serves(&fx, &ref_d, &by_ref.0));
}

/// A repository with no stored visibility row has never changed
/// visibility: a token issued under the private default keeps serving.
#[test]
fn tokens_on_a_default_private_repository_without_a_row_keep_serving() {
    let tokens = tokens();
    let fx = fixture_tweaked(Hooks::new(), http_cfg(), |c| {
        c.default_repo_visibility = crate::pipeline::RepoVisibility::Private;
        c.url_tokens = Some(tokens.clone());
    });
    let d = data();
    fx.push("room", &d.refs(), d.head(), None);
    let token = mint(&fx, &tokens, &UrlTarget::Object(id(&d.small)), 0);
    let path = fx.object_url("room", &id(&d.small));
    assert_eq!(with_token(&fx, "GET", &path, &token, &[]).status, 200);
}

/// A visibility row stored before `changed_ms` existed still serves reads;
/// its `last_created_ms` stands in as the change time.
#[test]
fn legacy_visibility_row_without_a_change_time_uses_its_creation_time() {
    let (fx, d, _, tokens) = setup();
    let repo = fx.repo_id("room");
    let last_created = fx.clock.now_ms() + 5_000;
    let legacy = format!(
        "\x01{{\"visibility\":\"private\",\"last_created_ms\":{last_created},\"last_statement_id\":null}}"
    );
    block_on(fx.pipe.meta.inner.apply(
        &fx.pipe.shards.coordinator(&repo.namespace),
        Batch::new().put(
            keys::repo_visibility(&repo.name),
            crate::store::Value::new(legacy.into_bytes()),
        ),
    ))
    .unwrap();
    let path = fx.object_url("room", &id(&d.small));
    let target = UrlTarget::Object(id(&d.small));
    let before = mint(&fx, &tokens, &target, 0);
    fx.clock.set(last_created);
    let at = mint(&fx, &tokens, &target, 0);
    fx.clock.advance(1);
    let after = mint(&fx, &tokens, &target, 0);
    assert_eq!(with_token(&fx, "GET", &path, &before, &[]).status, 404);
    assert_eq!(with_token(&fx, "GET", &path, &at, &[]).status, 404);
    assert_eq!(with_token(&fx, "GET", &path, &after, &[]).status, 200);
}
