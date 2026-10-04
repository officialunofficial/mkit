//! Security decisions stay live while structural evidence is reused.
use super::*;
use crate::pipeline::{ReadLimits, ReaderSession, ReaderView};
use crate::store::{BorrowedStore, ContentIndex};

fn block(fx: &Fx, object: Hash) {
    block_on(ContentIndex::new(BorrowedStore(&fx.pipe.meta)).block(
        &object,
        &crate::store::BlockEntry::new("manual", T0 as u64),
        T0 as u64,
    ))
    .unwrap();
}

fn owner_meta<'a>(req: &'a Req, lookup: &'a dyn Fn(&str) -> Option<String>) -> RequestMeta<'a> {
    RequestMeta {
        procedure: req.procedure,
        header: lookup,
        header_values: None,
        unary_body: Some(&req.body),
        transport_principal: None,
    }
}

#[test]
fn warm_session_still_checks_target_pack_and_manifest_denial() {
    for blocked in ["target", "pack", "manifest"] {
        for writer in [false, true] {
            let fx = fixture();
            let d = data();
            let pack = fx.push("room", &d.refs(), d.head(), None);
            let req = signed(
                &fx.owner,
                &fx.identity("room"),
                Procedure::ListRefs,
                fx.number(),
            );
            let lookup = |name: &str| {
                req.headers
                    .iter()
                    .find(|(n, _)| *n == name)
                    .map(|(_, v)| v.clone())
            };
            let meta = owner_meta(&req, &lookup);
            let reader = block_on(fx.pipe.object_reader(
                fx.repo_id("room"),
                if writer {
                    ReaderView::Owner(&meta)
                } else {
                    ReaderView::Public
                },
            ))
            .unwrap();
            let mut session = ReaderSession::default();
            let target = if blocked == "manifest" {
                id(&d.chunks[0])
            } else {
                id(&d.small)
            };
            assert!(
                block_on(reader.read_canonical_in(&mut session, &[target])).unwrap()[0].is_some()
            );
            block(
                &fx,
                match blocked {
                    "target" => target,
                    "pack" => pack,
                    _ => id(&d.manifest),
                },
            );
            assert_eq!(
                block_on(reader.read_canonical_in(&mut session, &[target])).unwrap(),
                [None]
            );
            assert_eq!(
                block_on(reader.object_metadata_in(&mut session, &[target])).unwrap(),
                [None]
            );
        }
    }
}

#[test]
fn warm_session_still_checks_external_base_and_its_pack() {
    for pack_block in [false, true] {
        let fx = fixture();
        let base = blob(b"base payload");
        let old_root = tree(&[("base", EntryMode::Blob, &base)]);
        let old_head = commit(&old_root, &[], "old");
        let old_pack = fx.push("room", &[&base, &old_root, &old_head], id(&old_head), None);
        let derived = blob(b"derived payload");
        let root = tree(&[("derived", EntryMode::Blob, &derived)]);
        let head = commit(&root, &[], "derived");
        let mut pack = PackWriter::new();
        pack.push_delta(
            &id(&base),
            &mkit_core::delta::encode(&serialize(&base).unwrap(), &serialize(&derived).unwrap())
                .unwrap(),
        )
        .unwrap();
        for o in [&root, &head] {
            pack.push_raw(id(o), &serialize(o).unwrap()).unwrap();
        }
        assert_eq!(
            fx.push_pack(
                "room",
                &pack.finish().unwrap(),
                (HEAD, PACKMAP),
                id(&head),
                (Match(id(&old_head)), Match(old_pack))
            )
            .0,
            AdvanceOutcome::Committed
        );
        let reader = block_on(
            fx.pipe
                .object_reader(fx.repo_id("room"), ReaderView::Public),
        )
        .unwrap();
        let mut session = ReaderSession::default();
        assert!(
            block_on(reader.read_canonical_in(&mut session, &[id(&derived)])).unwrap()[0].is_some()
        );
        assert!(
            !session.proofs.contains(&id(&base)),
            "reconstruction is not a graph edge"
        );
        block(&fx, if pack_block { old_pack } else { id(&base) });
        assert_eq!(
            block_on(reader.read_canonical_in(&mut session, &[id(&derived)])).unwrap(),
            [None]
        );
        assert_eq!(
            block_on(reader.object_metadata_in(&mut session, &[id(&derived)])).unwrap(),
            [None]
        );
    }
}

#[test]
fn session_visibility_and_grant_revocation_are_live() {
    use mkit_attest::grant::{AcceptedSchemes, Capabilities, OwnerScheme, RepoScope};
    let fx = fixture_tweaked(Hooks::new(), http_cfg(), |cfg| {
        cfg.grants = Some(
            GrantConfig::new(
                AUDIENCE,
                AcceptedSchemes::of(&[OwnerScheme::Ed25519]),
                vec![],
            )
            .unwrap(),
        );
    });
    let d = data();
    fx.push("room", &d.refs(), d.head(), None);
    let public = block_on(
        fx.pipe
            .object_reader(fx.repo_id("room"), ReaderView::Public),
    )
    .unwrap();
    let mut session = ReaderSession::default();
    assert!(
        block_on(public.read_canonical_in(&mut session, &[id(&d.small)])).unwrap()[0].is_some()
    );
    fx.make_private("room");
    assert_eq!(
        block_on(public.read_canonical_in(&mut session, &[id(&d.small)])).unwrap(),
        [None]
    );
    let grantee = key(55);
    let header = super::super::grants::grant(&fx.owner, &grantee, |grant| {
        grant.capabilities = Capabilities::ReadWrite;
        grant.scope = RepoScope::Repository(
            mkit_core::repo_identity::RepositoryIdentity::parse(&fx.identity("room")).unwrap(),
        );
    });
    let req = signed(
        &grantee,
        &fx.identity("room"),
        Procedure::ListRefs,
        fx.number(),
    )
    .header("x-write-grant", &header);
    let lookup = |name: &str| {
        req.headers
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| v.clone())
    };
    let meta = owner_meta(&req, &lookup);
    let reader = block_on(
        fx.pipe
            .object_reader(fx.repo_id("room"), ReaderView::Owner(&meta)),
    )
    .unwrap();
    assert!(
        block_on(reader.read_canonical_in(&mut session, &[id(&d.small)])).unwrap()[0].is_some()
    );
    let spent = session.used();
    let repo = fx.repo_id("room");
    block_on(fx.pipe.meta.inner.apply(
        &fx.pipe.shards.coordinator(&repo.namespace),
        Batch::new().put(keys::grant_epoch(), codec::encode_u64(1)),
    ))
    .unwrap();
    assert!(block_on(reader.read_canonical_in(&mut session, &[id(&d.small)])).is_err());
    assert!(session.used().storage_calls > spent.storage_calls);
}

#[test]
fn captured_roots_expire_without_sliding_on_hits_or_child_expansion() {
    for delete in [false, true] {
        let mut cfg = http_cfg();
        cfg.reachability_lag_ms = 1000;
        let fx = fixture_with(Hooks::new(), cfg);
        let d = data();
        let pack = fx.push("room", &d.refs(), d.head(), None);
        let reader = block_on(
            fx.pipe
                .object_reader(fx.repo_id("room"), ReaderView::Public),
        )
        .unwrap();
        let mut session = ReaderSession::default();
        assert!(
            block_on(reader.read_canonical_in(&mut session, &[d.head()])).unwrap()[0].is_some()
        );
        let repo = fx.repo_id("room");
        let partition = fx.pipe.shards.ref_shard(&repo, HEAD);
        if delete {
            block_on(fx.pipe.meta.inner.apply(
                &partition,
                Batch::new().delete(keys::published_ref(&repo.name, HEAD)),
            ))
            .unwrap();
        } else {
            let (objects, _, head) = rewound();
            fx.push(
                "room",
                &objects.iter().collect::<Vec<_>>(),
                id(&head),
                Some((d.head(), pack)),
            );
        }
        fx.clock.advance(500);
        assert!(
            block_on(reader.read_canonical_in(&mut session, &[id(&d.root)])).unwrap()[0].is_some()
        );
        fx.clock.advance(499);
        assert!(
            block_on(reader.read_canonical_in(&mut session, &[id(&d.small)])).unwrap()[0].is_some()
        );
        fx.clock.advance(1);
        assert_eq!(
            block_on(reader.read_canonical_in(&mut session, &[id(&d.small)])).unwrap(),
            [None]
        );
    }
}

#[test]
fn explicit_request_deadline_is_not_reset_by_reader_changes() {
    let (fx, d) = published();
    let reader = block_on(
        fx.pipe
            .object_reader(fx.repo_id("room"), ReaderView::Public),
    )
    .unwrap();
    let mut session = ReaderSession::with_deadline(ReadLimits::default(), T0 as u64 + 10);
    assert!(block_on(reader.read_canonical_in(&mut session, &[d.head()])).unwrap()[0].is_some());
    let used = session.used();
    fx.clock.advance(10);
    let reader = block_on(
        fx.pipe
            .object_reader(fx.repo_id("room"), ReaderView::Public),
    )
    .unwrap();
    assert_eq!(
        block_on(reader.read_canonical_in(&mut session, &[d.head()]))
            .unwrap_err()
            .code(),
        Code::ResourceExhausted
    );
    assert!(session.used().storage_calls >= used.storage_calls);
    assert!(!session.proofs.contains(&d.head()));
}

#[test]
fn one_session_cannot_transfer_proofs_between_readers_repositories_or_backends() {
    let (fx, d) = published();
    let root = tree(&[]);
    let head = commit(&root, &[], "orphan");
    fx.push("other", &[&root, &head, &d.small], id(&head), None);
    let foreign = fixture();
    foreign.push("room", &[&root, &head, &d.small], id(&head), None);
    let mut session = ReaderSession::default();
    let reader = block_on(
        fx.pipe
            .object_reader(fx.repo_id("room"), ReaderView::Public),
    )
    .unwrap();
    assert!(
        block_on(reader.read_canonical_in(&mut session, &[id(&d.small)])).unwrap()[0].is_some()
    );
    let spent = session.used();
    let other = block_on(
        fx.pipe
            .object_reader(fx.repo_id("other"), ReaderView::Public),
    )
    .unwrap();
    assert_eq!(
        block_on(other.read_canonical_in(&mut session, &[id(&d.small)])).unwrap(),
        [None]
    );
    assert!(session.used().storage_calls > spent.storage_calls);
    assert!(
        block_on(reader.read_canonical_in(&mut session, &[id(&d.small)])).unwrap()[0].is_some()
    );
    let other = block_on(
        foreign
            .pipe
            .object_reader(foreign.repo_id("room"), ReaderView::Public),
    )
    .unwrap();
    assert_eq!(
        block_on(other.read_canonical_in(&mut session, &[id(&d.small)])).unwrap(),
        [None]
    );
    assert!(
        block_on(reader.read_canonical_in(&mut session, &[id(&d.small)])).unwrap()[0].is_some()
    );
    let mut other_namespace = fx.repo_id("room");
    other_namespace.namespace = crate::NamespaceKey::deployment_default();
    let other = block_on(fx.pipe.object_reader(other_namespace, ReaderView::Public)).unwrap();
    assert_eq!(
        block_on(other.read_canonical_in(&mut session, &[id(&d.small)])).unwrap(),
        [None]
    );
    // Extracted global bytes are not proof or membership in another repository.
    let other = block_on(
        fx.pipe
            .object_reader(fx.repo_id("other"), ReaderView::Public),
    )
    .unwrap();
    assert_eq!(
        block_on(other.read_canonical_in(&mut session, &[id(&d.big)])).unwrap(),
        [None]
    );
}

#[test]
fn writer_memo_never_authorizes_public_http_or_url_targets() {
    let mut fx = fixture_tweaked(Hooks::new(), http_cfg(), |cfg| {
        cfg.url_tokens = Some(super::private_tokens::tokens());
        cfg.takedown_denial = true;
    });
    fx.pipe = fx
        .pipe
        .with_publication_policy(Arc::new(super::super::indexed::InspectionPolicy(
            crate::store::publication::Clearance::Pending,
        )))
        .unwrap();
    let d = data();
    let pack = fx.push("room", &d.refs(), d.head(), None);
    let req = signed(
        &fx.owner,
        &fx.identity("room"),
        Procedure::ListRefs,
        fx.number(),
    );
    let lookup = |name: &str| {
        req.headers
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| v.clone())
    };
    let meta = owner_meta(&req, &lookup);
    let reader = block_on(
        fx.pipe
            .object_reader(fx.repo_id("room"), ReaderView::Owner(&meta)),
    )
    .unwrap();
    let mut session = ReaderSession::default();
    assert!(
        block_on(reader.read_canonical_in(&mut session, &[id(&d.small)])).unwrap()[0].is_some()
    );
    assert!(
        !block_on(
            fx.pipe
                .http_seams
                .as_ref()
                .unwrap()
                .reachability
                .known_reachable(&fx.repo_id("room"), &id(&d.small), T0 as u64)
        )
        .unwrap()
    );
    assert!(
        block_on(reader.issue_urls(
            &[
                UrlTarget::Object(id(&d.small)),
                UrlTarget::Path {
                    reference: HEAD.into(),
                    path: "small.txt".into()
                }
            ],
            300
        ))
        .unwrap()
        .iter()
        .all(Option::is_none)
    );
    assert_uniform_404(&fx.get(&fx.object_url("room", &id(&d.small))));
    let public = block_on(
        fx.pipe
            .object_reader(fx.repo_id("room"), ReaderView::Public),
    )
    .unwrap();
    assert_eq!(
        block_on(public.read_canonical_in(&mut session, &[id(&d.small)])).unwrap(),
        [None]
    );
    assert!(
        block_on(reader.read_canonical_in(&mut session, &[id(&d.small)])).unwrap()[0].is_some()
    );
    let repo = fx.repo_id("room");
    let partition = fx.pipe.shards.ref_shard(&repo, HEAD);
    let key = keys::membership(&repo.name, &pack);
    let mut witness = crate::store::publication::Witness::decode(
        &block_on(fx.pipe.meta.inner.get(&partition, &key))
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    witness.held = true;
    block_on(
        fx.pipe
            .meta
            .inner
            .apply(&partition, Batch::new().put(key, witness.encode())),
    )
    .unwrap();
    assert_eq!(
        block_on(reader.read_canonical_in(&mut session, &[id(&d.small)])).unwrap(),
        [None]
    );
}

struct ChangingStop(Arc<Mutex<Option<Hash>>>);
impl crate::http_objects::TakedownGate for ChangingStop {
    fn stops_descent(&self, _: &RepoId, id: &Hash) -> bool {
        self.0.lock().unwrap().as_ref() == Some(id)
    }
    fn check<'a>(
        &'a self,
        _: &'a RepoId,
        _: &'a Hash,
    ) -> crate::BoxFuture<'a, Result<crate::http_objects::TakedownVerdict, ServerError>> {
        Box::pin(async { Ok(crate::http_objects::TakedownVerdict::Clear) })
    }
}

#[test]
fn returned_objects_and_reused_ancestry_obey_current_custom_stops() {
    for stop_before in [false, true] {
        let (fx, d) = published();
        let stop = Arc::new(Mutex::new(if stop_before {
            Some(id(&d.root))
        } else {
            None
        }));
        let fx = Fx {
            pipe: fx.pipe.with_http_seams(|mut seams| {
                seams.takedown = Arc::new(ChangingStop(stop.clone()));
                seams
            }),
            ..fx
        };
        let reader = block_on(
            fx.pipe
                .object_reader(fx.repo_id("room"), ReaderView::Public),
        )
        .unwrap();
        let mut session = ReaderSession::default();
        assert!(
            block_on(reader.read_canonical_in(&mut session, &[id(&d.root)])).unwrap()[0].is_some()
        );
        if stop_before {
            assert!(!session.proofs.contains(&id(&d.small)));
        } else {
            assert!(session.proofs.contains(&id(&d.small)));
            *stop.lock().unwrap() = Some(id(&d.root));
        }
        assert_eq!(
            block_on(reader.read_canonical_in(&mut session, &[id(&d.small)])).unwrap(),
            [None]
        );
    }
}

#[test]
fn metadata_does_not_expand_queued_ancestors_or_read_requested_frames() {
    let (fx, d) = published();
    let reader = block_on(
        fx.pipe
            .object_reader(fx.repo_id("room"), ReaderView::Public),
    )
    .unwrap();
    let mut session = ReaderSession::default();
    assert!(block_on(reader.object_metadata_in(&mut session, &[d.head()])).unwrap()[0].is_some());
    assert!(!session.proofs.contains(&id(&d.root)));
    assert_eq!(
        block_on(reader.object_metadata_in(&mut session, &[id(&d.root), id(&d.small)])).unwrap()[1],
        None
    );
    assert!(!session.proofs.contains(&id(&d.small)));
}

#[test]
fn changed_verified_credential_scope_resets_roots_without_refunding_budgets() {
    use mkit_attest::grant::{AcceptedSchemes, Capabilities, OwnerScheme, RepoScope};
    let fx = fixture_tweaked(Hooks::new(), http_cfg(), |cfg| {
        cfg.grants = Some(
            GrantConfig::new(
                AUDIENCE,
                AcceptedSchemes::of(&[OwnerScheme::Ed25519]),
                vec![],
            )
            .unwrap(),
        );
    });
    let d = data();
    fx.push("room", &d.refs(), d.head(), None);
    let grantee = key(56);
    let grant = super::super::grants::grant(&fx.owner, &grantee, |grant| {
        grant.capabilities = Capabilities::ReadWrite;
        grant.scope = RepoScope::Repository(
            mkit_core::repo_identity::RepositoryIdentity::parse(&fx.identity("room")).unwrap(),
        );
    });
    let first = signed(
        &fx.owner,
        &fx.identity("room"),
        Procedure::ListRefs,
        fx.number(),
    );
    let second = signed(
        &grantee,
        &fx.identity("room"),
        Procedure::ListRefs,
        fx.number(),
    )
    .header("x-write-grant", &grant);
    let changed = AtomicBool::new(false);
    let lookup = |name: &str| {
        let req = if changed.load(Ordering::SeqCst) {
            &second
        } else {
            &first
        };
        req.headers
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| v.clone())
    };
    let meta = owner_meta(&first, &lookup);
    let reader = block_on(
        fx.pipe
            .object_reader(fx.repo_id("room"), ReaderView::Owner(&meta)),
    )
    .unwrap();
    let mut session = ReaderSession::default();
    assert!(
        block_on(reader.read_canonical_in(&mut session, &[id(&d.small)])).unwrap()[0].is_some()
    );
    let spent = session.used();
    let repo = fx.repo_id("room");
    block_on(fx.pipe.meta.inner.apply(
        &fx.pipe.shards.ref_shard(&repo, HEAD),
        Batch::new().delete(keys::ref_key(&repo.name, HEAD)),
    ))
    .unwrap();
    changed.store(true, Ordering::SeqCst);
    assert_eq!(
        block_on(reader.read_canonical_in(&mut session, &[id(&d.small)])).unwrap(),
        [None]
    );
    assert!(session.used().storage_calls > spent.storage_calls);
    assert_eq!(session.used().output_bytes, spent.output_bytes);
}

#[test]
fn foreign_remix_sources_are_not_child_proofs_even_when_stored_locally() {
    let fx = fixture();
    let d = data();
    fx.push("upstream", &d.refs(), d.head(), None);
    let root = tree(&[]);
    let signer = KeyPair::from_seed([9; 32]);
    let mut remix = mkit_core::object::Remix {
        tree_hash: id(&root),
        parents: Vec::new(),
        sources: vec![mkit_core::object::RemixSource {
            upstream_id: [0xcd; 32],
            commit_hash: d.head(),
        }],
        author: Identity::ed25519(signer.public.0),
        signer: signer.public.0,
        message: b"remix".to_vec(),
        timestamp: 43,
        signature: [0; 64],
    };
    remix.signature = mkit_core::sign::sign_remix(&remix, &signer).unwrap().0;
    let remix = Object::Remix(remix);
    let mut objects = d.refs();
    objects.extend([&root, &remix]);
    fx.push("room", &objects, id(&remix), None);
    let reader = block_on(
        fx.pipe
            .object_reader(fx.repo_id("room"), ReaderView::Public),
    )
    .unwrap();
    let mut session = ReaderSession::default();
    assert!(block_on(reader.read_canonical_in(&mut session, &[id(&remix)])).unwrap()[0].is_some());
    assert!(!session.proofs.contains(&d.head()));
    assert_eq!(
        block_on(reader.read_canonical_in(&mut session, &[d.head(), id(&d.big)])).unwrap(),
        [None, None]
    );
}

#[test]
fn fallback_walk_retains_decoded_edges_and_next_batch_skips_ref_enumeration() {
    let (fx, d) = published();
    let reader = block_on(
        fx.pipe
            .object_reader(fx.repo_id("room"), ReaderView::Public),
    )
    .unwrap();
    let mut session = ReaderSession::default();
    assert!(
        block_on(reader.read_canonical_in(&mut session, &[id(&d.small)])).unwrap()[0].is_some()
    );
    assert!(session.proofs.contains(&id(&d.root)));
    assert!(session.proofs.contains(&id(&d.dir)));
    let scanned = fx
        .pipe
        .meta
        .ops()
        .iter()
        .filter(|&&op| op == "scan")
        .count();
    assert!(block_on(reader.read_canonical_in(&mut session, &[id(&d.dir)])).unwrap()[0].is_some());
    // Only the new target's index lookup remains; no ref enumeration.
    assert_eq!(
        fx.pipe
            .meta
            .ops()
            .iter()
            .filter(|&&op| op == "scan")
            .count(),
        scanned + 1
    );
    let tips = session.proofs.tips.clone();
    assert_eq!(tips, Some(vec![d.head()]));
}

struct PauseTarget(Hash);
impl TakedownGate for PauseTarget {
    fn check<'a>(
        &'a self,
        _: &'a RepoId,
        leaf: &'a Hash,
    ) -> crate::BoxFuture<'a, Result<TakedownVerdict, ServerError>> {
        Box::pin(async move {
            if *leaf == self.0 {
                std::future::pending().await
            } else {
                Ok(TakedownVerdict::Clear)
            }
        })
    }
}

#[test]
fn cancelled_requested_load_never_publishes_undecoded_children() {
    let (fx, d) = published();
    let fx = Fx {
        pipe: fx.pipe.with_http_seams(|mut seams| {
            seams.takedown = Arc::new(PauseTarget(id(&d.manifest)));
            seams
        }),
        ..fx
    };
    let reader = block_on(
        fx.pipe
            .object_reader(fx.repo_id("room"), ReaderView::Public),
    )
    .unwrap();
    let mut session = ReaderSession::default();
    assert!(block_on(reader.read_canonical_in(&mut session, &[id(&d.root)])).unwrap()[0].is_some());
    assert!(session.proofs.contains(&id(&d.manifest)));
    assert!(!session.proofs.contains(&id(&d.chunks[0])));
    let before = session.used();
    let ids = [id(&d.manifest)];
    let mut future = Box::pin(reader.read_canonical_in(&mut session, &ids));
    assert!(
        block_on(std::future::poll_fn(|cx| std::task::Poll::Ready(
            future.as_mut().poll(cx)
        )))
        .is_pending()
    );
    drop(future);
    assert!(session.used().storage_calls > before.storage_calls);
    assert_eq!(session.used().output_bytes, before.output_bytes);
    assert!(!session.proofs.contains(&id(&d.chunks[0])));
}

#[test]
fn new_commits_need_a_new_session_and_public_orphans_stay_uniform_at_proof_caps() {
    let (fx, d) = published();
    let reader = block_on(
        fx.pipe
            .object_reader(fx.repo_id("room"), ReaderView::Public),
    )
    .unwrap();
    let mut session = ReaderSession::default();
    assert!(block_on(reader.read_canonical_in(&mut session, &[d.head()])).unwrap()[0].is_some());
    let head = commit(&d.root, &[&d.commit], "next");
    let repo = fx.repo_id("room");
    let partition = fx.pipe.shards.ref_shard(&repo, HEAD);
    let pack = block_on(crate::store::read::read_ref(
        &fx.pipe.meta,
        &partition,
        &repo.name,
        PACKMAP,
    ))
    .unwrap()
    .unwrap();
    fx.push("room", &[&head], id(&head), Some((d.head(), pack)));
    assert_eq!(
        block_on(reader.read_canonical_in(&mut session, &[id(&head)])).unwrap(),
        [None]
    );
    assert!(
        block_on(reader.read_canonical_in(&mut ReaderSession::default(), &[id(&head)])).unwrap()[0]
            .is_some()
    );

    let orphan = blob(b"orphan");
    let root = tree(&[]);
    let head = commit(&root, &[], "empty");
    fx.push("other", &[&root, &head, &orphan], id(&head), None);
    let reader = block_on(
        fx.pipe
            .object_reader(fx.repo_id("other"), ReaderView::Public),
    )
    .unwrap();
    for target in [id(&orphan), [93; 32]] {
        let mut session = ReaderSession::new(ReadLimits::new(8500, 0, u64::MAX, u64::MAX));
        assert_eq!(
            block_on(reader.read_canonical_in(&mut session, &[target])).unwrap(),
            [None]
        );
        assert!(!session.proofs.contains(&target));
        assert_eq!(
            block_on(reader.object_metadata_in(&mut session, &[target])).unwrap(),
            [None]
        );
    }
}
