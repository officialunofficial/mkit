//! Read results remain identical when an empty denial index is disabled.
use super::*;
use crate::pipeline::{ContinuedHistoryPage, HistoryPage, ObjectMetadata};
use crate::store::{BorrowedStore, ContentIndex};

#[derive(Debug, PartialEq, Eq)]
struct ReadResults {
    show: Vec<Option<Vec<u8>>>,
    metadata: Vec<Option<ObjectMetadata>>,
    log: HistoryPage,
    page: ContinuedHistoryPage,
    pack_visible: bool,
}

async fn results(shape: &Shape, owner: bool) -> ReadResults {
    let fx = &shape.fx;
    let request = signed(
        &fx.owner,
        &fx.identity("room"),
        Procedure::ListRefs,
        fx.number(),
    );
    let lookup = |name: &str| {
        request
            .headers
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| v.clone())
    };
    let meta = RequestMeta {
        procedure: request.procedure,
        header: &lookup,
        header_values: None,
        unary_body: Some(&request.body),
        transport_principal: None,
    };
    let reader = fx
        .pipe
        .object_reader(
            fx.repo_id("room"),
            if owner {
                ReaderView::Owner(&meta)
            } else {
                ReaderView::Public
            },
        )
        .await
        .unwrap();
    let mut session = ReaderSession::default();
    let mut show = reader
        .read_canonical_in(&mut session, &[shape.head])
        .await
        .unwrap();
    show.extend(
        reader
            .read_canonical_in(&mut session, &[shape.root])
            .await
            .unwrap(),
    );
    let metadata = reader
        .object_metadata_in(&mut session, &shape.files)
        .await
        .unwrap();
    let log = reader
        .walk_history_in(
            &mut ReaderSession::default(),
            HEAD,
            None,
            10,
            HistoryOptions {
                mode: HistoryMode::FirstParent,
                ..HistoryOptions::default()
            },
        )
        .await
        .unwrap()
        .unwrap();
    let page = reader
        .walk_history_page_in(&mut ReaderSession::default(), HEAD, None, 10)
        .await
        .unwrap()
        .unwrap();
    let request = if owner {
        signed(
            &fx.owner,
            &fx.identity("room"),
            Procedure::PackExists,
            fx.number(),
        )
    } else {
        Req::unsigned(Procedure::PackExists).header("x-repository", &fx.identity("room"))
    };
    let pack_visible = fx
        .pipe
        .pack_exists(
            &fx.auth(&request),
            PackKey::new(*shape.packs.last().unwrap()),
        )
        .await
        .unwrap();
    ReadResults {
        show,
        metadata,
        log,
        page,
        pack_visible,
    }
}

#[test]
fn denial_off_read_shapes_match_empty_denial_on_and_read_no_block_rows() {
    let mut history = shape(11, 2, false, |_| 1);
    for owner in [false, true] {
        history.fx.pipe.cfg.takedown_denial = false;
        history.fx.pipe.meta.seen.lock().unwrap().clear();
        let off = block_on(results(&history, owner));
        assert_no_denial_rows(&history.fx.pipe.meta.seen());
        assert!(off.show.iter().all(Option::is_some));
        assert!(off.metadata.iter().all(Option::is_some));
        assert_eq!(off.log.commits.len(), 10);
        assert_eq!(off.page.commits.len(), 10);
        assert!(off.pack_visible);

        history.fx.pipe.cfg.takedown_denial = true;
        let on = block_on(results(&history, owner));
        assert_eq!(off, on, "owner={owner}: mode changed visible read results");
    }
}

#[test]
fn pipeline_typed_read_modes_use_the_deployment_gate_for_live_denial() {
    use crate::reads::MemberReadLimits;
    for enabled in [false, true] {
        for pack_block in [false, true] {
            let fx = fixture_tweaked(Hooks::new(), http_cfg(), |cfg| {
                cfg.takedown_denial = enabled;
            });
            let d = data();
            let pack = fx.push("room", &d.refs(), d.head(), None);
            let repo = fx.repo_id("room");
            let target = id(&d.small);
            let reads = fx.pipe.read_access();
            let limits = MemberReadLimits {
                max_delta_depth: 32,
                max_decode_bytes: 1024,
            };
            fx.pipe.meta.seen.lock().unwrap().clear();
            let before = block_on(reads.locate_object(&repo, &target))
                .unwrap()
                .unwrap();
            assert!(!before.denied);
            assert_eq!(
                block_on(reads.locate_objects(&repo, &[target, target])).unwrap(),
                [Some(before), Some(before)]
            );
            let canonical =
                block_on(reads.read_member_canonical(&fx.pipe.blobs, &repo, target, limits))
                    .unwrap()
                    .unwrap();
            assert_eq!(canonical.bytes.as_ref(), serialize(&d.small).unwrap());
            if !enabled {
                assert_no_denial_rows(&fx.pipe.meta.seen());
            }
            block_on(ContentIndex::new(BorrowedStore(&fx.pipe.meta.inner)).block(
                &crate::takedown::DenialCapability::for_test(),
                &if pack_block { pack } else { target },
                &crate::store::BlockEntry::new("test stop", T0 as u64),
                T0 as u64,
            ))
            .unwrap();
            fx.pipe.meta.seen.lock().unwrap().clear();
            let current = block_on(reads.locate_object(&repo, &target))
                .unwrap()
                .unwrap();
            assert_eq!(current.denied, enabled);
            assert_eq!(
                block_on(reads.locate_objects(&repo, &[target, target])).unwrap(),
                [Some(current), Some(current)]
            );
            let after =
                block_on(reads.read_member_canonical(&fx.pipe.blobs, &repo, target, limits));
            if enabled {
                assert!(after.is_err());
                assert!(fx.pipe.meta.seen().contains(&keys::block(&target)));
                assert!(
                    fx.pipe
                        .meta
                        .seen()
                        .contains(&crate::takedown::denial::action_key(&target))
                );
            } else {
                assert_eq!(current, before);
                assert_eq!(after.unwrap(), Some(canonical));
                assert_no_denial_rows(&fx.pipe.meta.seen());
            }
        }
    }
}

fn typed_external_base(enabled: bool) -> (Fx, Hash, Hash, Object) {
    let fx = fixture_tweaked(Hooks::new(), http_cfg(), |cfg| {
        cfg.takedown_denial = enabled;
    });
    let base = blob(b"external base");
    let old_root = tree(&[("base", EntryMode::Blob, &base)]);
    let old_head = commit(&old_root, &[], "base");
    let old_pack = fx.push("room", &[&base, &old_root, &old_head], id(&old_head), None);
    let derived = blob(b"derived value");
    let root = tree(&[("derived", EntryMode::Blob, &derived)]);
    let head = commit(&root, &[], "derived");
    let mut writer = PackWriter::new();
    writer
        .push_delta(
            &id(&base),
            &mkit_core::delta::encode(&serialize(&base).unwrap(), &serialize(&derived).unwrap())
                .unwrap(),
        )
        .unwrap();
    for object in [&root, &head] {
        writer
            .push_raw(id(object), &serialize(object).unwrap())
            .unwrap();
    }
    assert_eq!(
        fx.push_pack(
            "room",
            &writer.finish().unwrap(),
            (HEAD, PACKMAP),
            id(&head),
            (Match(id(&old_head)), Match(old_pack))
        )
        .0,
        AdvanceOutcome::Committed
    );
    (fx, id(&base), old_pack, derived)
}

#[test]
fn pipeline_typed_read_modes_preserve_external_base_denial() {
    use crate::reads::MemberReadLimits;
    for enabled in [false, true] {
        for pack_block in [false, true] {
            let (fx, base, old_pack, derived) = typed_external_base(enabled);
            let reads = fx.pipe.read_access();
            let repo = fx.repo_id("room");
            let target = id(&derived);
            let limits = MemberReadLimits {
                max_delta_depth: 32,
                max_decode_bytes: 1024,
            };
            fx.pipe.meta.seen.lock().unwrap().clear();
            let before = block_on(reads.locate_object(&repo, &target)).unwrap();
            assert!(!before.unwrap().denied);
            assert_eq!(
                block_on(reads.locate_objects(&repo, &[target, target])).unwrap(),
                [before, before]
            );
            let canonical =
                block_on(reads.read_member_canonical(&fx.pipe.blobs, &repo, target, limits))
                    .unwrap()
                    .unwrap();
            assert_eq!(canonical.bytes.as_ref(), serialize(&derived).unwrap());
            if !enabled {
                assert_no_denial_rows(&fx.pipe.meta.seen());
            }
            block_on(ContentIndex::new(BorrowedStore(&fx.pipe.meta.inner)).block(
                &crate::takedown::DenialCapability::for_test(),
                &if pack_block { old_pack } else { base },
                &crate::store::BlockEntry::new("test stop", T0 as u64),
                T0 as u64,
            ))
            .unwrap();
            fx.pipe.meta.seen.lock().unwrap().clear();
            assert_eq!(
                block_on(reads.locate_object(&repo, &target)).unwrap(),
                before
            );
            assert_eq!(
                block_on(reads.locate_objects(&repo, &[target, target])).unwrap(),
                [before, before]
            );
            let after =
                block_on(reads.read_member_canonical(&fx.pipe.blobs, &repo, target, limits));
            if enabled {
                assert!(after.is_err());
                assert!(fx.pipe.meta.seen().contains(&keys::block(&base)));
                assert!(
                    fx.pipe
                        .meta
                        .seen()
                        .contains(&crate::takedown::denial::action_key(&base))
                );
            } else {
                assert_eq!(after.unwrap(), Some(canonical));
                assert_no_denial_rows(&fx.pipe.meta.seen());
            }
        }
    }
}
