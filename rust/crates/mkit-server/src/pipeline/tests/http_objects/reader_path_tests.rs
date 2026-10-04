//! Path-directed readers retain canonical traversal and URL authority rules.
use super::*;
use crate::pipeline::{ObjectReader, ReaderSession, ReaderView};
use std::collections::BTreeMap;

fn with_reader<T>(
    fx: &Fx,
    owner: bool,
    run: impl FnOnce(&ObjectReader<'_, SpyBlobs, Arc<Spy>, Hooks>) -> T,
) -> T {
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
    let meta = RequestMeta {
        procedure: req.procedure,
        header: &lookup,
        header_values: None,
        unary_body: Some(&req.body),
        transport_principal: None,
    };
    let reader = block_on(fx.pipe.object_reader(
        fx.repo_id("room"),
        if owner {
            ReaderView::Owner(&meta)
        } else {
            ReaderView::Public
        },
    ))
    .unwrap();
    run(&reader)
}

#[test]
fn canonical_path_type_symlink_and_grammar_matrix() {
    for denial in [false, true] {
        let mut fx = fixture_tweaked(Hooks::new(), http_cfg(), |c| c.takedown_denial = false);
        let d = data();
        fx.push("room", &d.refs(), d.head(), None);
        fx.pipe.cfg.takedown_denial = denial;
        for owner in [false, true] {
            with_reader(&fx, owner, |reader| {
                for (path, want) in [
                    ("", &d.root),
                    ("dir", &d.dir),
                    ("small.txt", &d.small),
                    ("big.bin", &d.big),
                    ("chunked.bin", &d.manifest),
                ] {
                    assert_eq!(
                        block_on(reader.read_path(HEAD, path)).unwrap(),
                        Some((id(want), serialize(want).unwrap())),
                        "{path}"
                    );
                }
                let (_, link) = block_on(reader.read_path(HEAD, "link")).unwrap().unwrap();
                assert_eq!(
                    mkit_core::serialize::deserialize(&link).unwrap(),
                    blob(b"small.txt")
                );
                for path in ["link/child", "small.txt/child", "dir/missing", "missing"] {
                    assert!(block_on(reader.read_path(HEAD, path)).unwrap().is_none());
                }
                for path in [
                    "../small.txt",
                    "dir/../small.txt",
                    "dir//inner.txt",
                    "/small.txt",
                    "dir/",
                    ".",
                    "x\0y",
                ] {
                    assert_eq!(
                        block_on(reader.read_path(HEAD, path)).unwrap_err().code(),
                        crate::Code::InvalidArgument
                    );
                }
                assert_eq!(
                    block_on(reader.read_path("refs/heads/../bad", ""))
                        .unwrap_err()
                        .code(),
                    crate::Code::InvalidArgument
                );
                assert!(
                    block_on(reader.read_path("refs/heads/missing", ""))
                        .unwrap()
                        .is_none()
                );
            });
        }
    }
}

#[test]
fn path_ref_type_matrix_and_bounded_tag_peeling() {
    for depth in [16, 17] {
        let (fx, d) = published();
        let signer = KeyPair::from_seed([9; 32]);
        let mut tags = Vec::new();
        let mut target = d.head();
        for n in 0..depth {
            let mut tag = Tag {
                target,
                target_type: if n == 0 {
                    ObjectType::Commit
                } else {
                    ObjectType::Tag
                },
                name: format!("v{n}").into_bytes(),
                tagger: Identity::ed25519(signer.public.0),
                signer: signer.public.0,
                message: b"path tag".to_vec(),
                timestamp: 1,
                signature: [0; 64],
            };
            tag.signature = mkit_core::sign::sign_tag(&tag, &signer).unwrap().0;
            let object = Object::Tag(tag);
            target = id(&object);
            tags.push(object);
        }
        assert_eq!(
            fx.push_ref(
                "room",
                &tags.iter().collect::<Vec<_>>(),
                (TAG_REF, TAG_PACKMAP),
                target,
                (Missing, Missing)
            )
            .0,
            AdvanceOutcome::Committed
        );
        for owner in [false, true] {
            with_reader(&fx, owner, |reader| {
                let answer = block_on(reader.read_path(TAG_REF, "small.txt")).unwrap();
                if depth == 16 {
                    assert_eq!(answer, Some((id(&d.small), serialize(&d.small).unwrap())));
                } else {
                    assert!(answer.is_none());
                }
            });
        }
        let repo = fx.repo_id("room");
        let partition = fx.pipe.shards.ref_shard(&repo, HEAD);
        for object in [&d.small, &d.root, &d.manifest] {
            block_on(
                fx.pipe.meta.inner.apply(
                    &partition,
                    Batch::new()
                        .put(
                            keys::ref_key(&repo.name, HEAD),
                            codec::encode_ref_id(&id(object)),
                        )
                        .put(
                            keys::published_ref(&repo.name, HEAD),
                            codec::encode_ref_id(&id(object)),
                        ),
                ),
            )
            .unwrap();
            for owner in [false, true] {
                with_reader(&fx, owner, |reader| {
                    assert!(block_on(reader.read_path(HEAD, "")).unwrap().is_none());
                });
            }
        }
    }
    let fx = fixture();
    let root = tree(&[]);
    let signer = KeyPair::from_seed([9; 32]);
    let mut remix = mkit_core::object::Remix {
        tree_hash: id(&root),
        parents: vec![],
        sources: vec![],
        author: Identity::ed25519(signer.public.0),
        signer: signer.public.0,
        message: b"path remix".to_vec(),
        timestamp: 1,
        signature: [0; 64],
    };
    remix.signature = mkit_core::sign::sign_remix(&remix, &signer).unwrap().0;
    let remix = Object::Remix(remix);
    fx.push("room", &[&root, &remix], id(&remix), None);
    for owner in [false, true] {
        with_reader(&fx, owner, |reader| {
            assert_eq!(
                block_on(reader.read_path(HEAD, "")).unwrap(),
                Some((id(&root), serialize(&root).unwrap()))
            );
        });
    }
}

#[test]
fn owner_path_proofs_do_not_broaden_exact_private_url_tokens() {
    let fx = fixture_tweaked(Hooks::new(), http_cfg(), |c| {
        c.url_tokens = Some(super::private_tokens::tokens());
    });
    let d = data();
    fx.push("room", &d.refs(), d.head(), None);
    fx.make_private("room");
    with_reader(&fx, true, |reader| {
        let mut session = ReaderSession::default();
        assert_eq!(
            block_on(reader.read_path_in(&mut session, HEAD, "small.txt")).unwrap(),
            Some((id(&d.small), serialize(&d.small).unwrap()))
        );
        let target = crate::url_token::UrlTarget::path(HEAD, "small.txt").unwrap();
        let token = block_on(reader.issue_urls(&[target], 60))
            .unwrap()
            .pop()
            .unwrap()
            .unwrap();
        let query = format!("token={}", token.expose());
        let good = read(fx.request(
            "GET",
            &fx.ref_url("room", "main", "small.txt"),
            Some(&query),
            &[],
        ));
        assert_eq!(good.status, 200);
        assert_eq!(good.body, d.small_bytes);
        for url in [
            fx.ref_url("room", "main", "link"),
            fx.ref_url("room", "main", "dir"),
            fx.object_url("room", &id(&d.small)),
        ] {
            assert_uniform_404(&read(fx.request("GET", &url, Some(&query), &[])));
        }
    });
    with_reader(&fx, false, |reader| {
        assert!(
            block_on(reader.read_path(HEAD, "small.txt"))
                .unwrap()
                .is_none()
        );
    });
}

#[test]
fn owner_path_uses_live_ref_without_authorizing_published_urls() {
    let fx = fixture_tweaked(Hooks::new(), http_cfg(), |c| {
        c.url_tokens = Some(super::private_tokens::tokens());
    });
    let d = data();
    fx.push("room", &d.refs(), d.head(), None);
    let repo = fx.repo_id("room");
    block_on(fx.pipe.meta.inner.apply(
        &fx.pipe.shards.ref_shard(&repo, HEAD),
        Batch::new().delete(keys::published_ref(&repo.name, HEAD)),
    ))
    .unwrap();
    with_reader(&fx, true, |reader| {
        assert_eq!(
            block_on(reader.read_path(HEAD, "small.txt")).unwrap(),
            Some((id(&d.small), serialize(&d.small).unwrap()))
        );
        let target = crate::url_token::UrlTarget::path(HEAD, "small.txt").unwrap();
        assert!(block_on(reader.issue_urls(&[target], 60)).unwrap()[0].is_none());
    });
    with_reader(&fx, false, |reader| {
        assert!(
            block_on(reader.read_path(HEAD, "small.txt"))
                .unwrap()
                .is_none()
        );
    });
}

#[test]
fn opt_in_batch_limit_preserves_defaults_url_cap_and_duplicate_output_accounting() {
    let fx = fixture_tweaked(Hooks::new(), http_cfg(), |c| {
        c.url_tokens = Some(super::private_tokens::tokens());
    });
    let d = data();
    fx.push("room", &d.refs(), d.head(), None);
    for owner in [false, true] {
        with_reader(&fx, owner, |reader| {
            assert_eq!(
                block_on(reader.read_canonical(&[d.head(); 17]))
                    .unwrap_err()
                    .code(),
                crate::Code::InvalidArgument
            );
        });
    }
    for invalid in [0, 46, usize::MAX] {
        let reader = block_on(
            fx.pipe
                .object_reader(fx.repo_id("room"), ReaderView::Public),
        )
        .unwrap();
        let before = fx.pipe.meta.calls();
        assert_eq!(
            reader.with_batch_limit(invalid).err().unwrap().code(),
            crate::Code::InvalidArgument
        );
        assert_eq!(fx.pipe.meta.calls(), before);
    }
    let reader = block_on(
        fx.pipe
            .object_reader(fx.repo_id("room"), ReaderView::Public),
    )
    .unwrap()
    .with_batch_limit(45)
    .unwrap();
    let ids: Vec<_> = [d.head(), id(&d.root), id(&d.small)]
        .into_iter()
        .cycle()
        .take(45)
        .collect();
    let canonical: BTreeMap<_, _> = [&d.commit, &d.root, &d.small]
        .into_iter()
        .map(|object| (id(object), serialize(object).unwrap()))
        .collect();
    let mut session = ReaderSession::default();
    assert_eq!(
        block_on(reader.read_canonical_in(&mut session, &ids)).unwrap(),
        ids.iter()
            .map(|id| Some(canonical[id].clone()))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        session.used().output_bytes,
        ids.iter().map(|id| canonical[id].len() as u64).sum::<u64>()
    );
    assert!(
        block_on(reader.object_metadata_in(&mut session, &ids))
            .unwrap()
            .iter()
            .all(Option::is_some)
    );
    let before = fx.pipe.meta.calls();
    assert_eq!(
        block_on(reader.read_canonical(&[d.head(); 46]))
            .unwrap_err()
            .code(),
        crate::Code::InvalidArgument
    );
    assert_eq!(
        block_on(reader.issue_urls(&vec![crate::url_token::UrlTarget::Object(d.head()); 17], 60))
            .unwrap_err()
            .code(),
        crate::Code::InvalidArgument
    );
    assert_eq!(fx.pipe.meta.calls(), before);
}
