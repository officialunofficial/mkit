//! Selected-ref reader sessions: one authoritative anchor pins every read.
use super::history_tests::{drain, in_view};
use super::*;
use crate::history_token::HistoryTokenConfig;
use crate::pipeline::read_proofs::{HistoryEdge, HistoryKind};
use crate::pipeline::{HistoryOptions, ReadLimits, ReaderSession};
use crate::store::publication::Publication;

fn simple_history<H: HookSet>(fx: &Fx<H>) -> (Object, Object, Object, Object, Hash) {
    let file = blob(b"selected file");
    let root = tree(&[("file", EntryMode::Blob, &file)]);
    let base = commit(&root, &[], "base");
    let head = commit(&root, &[&base], "head");
    let pack = fx.push("room", &[&file, &root, &base, &head], id(&head), None);
    drain(fx);
    (file, root, base, head, pack)
}

#[test]
fn selected_sessions_capture_one_ref_and_record_history_lineage() {
    for denial in [false, true] {
        let mut fx = fixture();
        fx.pipe.cfg.takedown_denial = denial;
        let (file, root, base, head, _) = simple_history(&fx);
        for writer in [false, true] {
            in_view(&fx, writer, |reader| {
                let reader = reader.with_selected_ref(HEAD).unwrap();
                let mut session = ReaderSession::default();
                let capture = block_on(reader.selected_capture_in(&mut session))
                    .unwrap()
                    .unwrap();
                assert_eq!(capture.tip(), id(&head));
                assert_eq!(capture.reference(), HEAD);
                let reads = block_on(reader.read_canonical_in(
                    &mut session,
                    &[id(&head), id(&root), id(&file), id(&base)],
                ))
                .unwrap();
                assert_eq!(
                    reads,
                    [&head, &root, &file, &base]
                        .iter()
                        .map(|o| Some(serialize(o).unwrap()))
                        .collect::<Vec<_>>()
                );
                let Object::Commit(base_commit) = &base else {
                    panic!("expected a commit");
                };
                let Object::Commit(head_commit) = &head else {
                    panic!("expected a commit");
                };
                let link = session.proofs.history_link(&id(&base)).unwrap();
                assert_eq!(link.edge, HistoryEdge::Parent);
                assert_eq!(link.predecessor, Some(id(&head)));
                assert_eq!(
                    link.decoded,
                    Some((HistoryKind::Commit, base_commit.timestamp))
                );
                let root_link = session.proofs.history_link(&id(&head)).unwrap();
                assert_eq!(root_link.edge, HistoryEdge::Root);
                assert_eq!(root_link.predecessor, None);
                assert_eq!(
                    root_link.decoded,
                    Some((HistoryKind::Commit, head_commit.timestamp))
                );
                // Content edges record no history link.
                assert!(session.proofs.history_link(&id(&root)).is_none());
                assert!(session.proofs.history_link(&id(&file)).is_none());
                // Metadata reads share the same immutable capture.
                let sizes =
                    block_on(reader.object_metadata_in(&mut session, &[id(&file), id(&base)]))
                        .unwrap();
                assert!(sizes.iter().all(Option::is_some));
                assert!(std::sync::Arc::ptr_eq(
                    session.proofs.checkpoint().unwrap(),
                    &capture.0,
                ));
            });
        }
    }
}

#[test]
fn a_tag_ref_binds_the_unpeeled_tag() {
    let fx = fixture();
    let d = data();
    fx.push("room", &d.refs(), d.head(), None);
    let signer = KeyPair::from_seed([9; 32]);
    let mut tag = Tag {
        target: d.head(),
        target_type: ObjectType::Commit,
        name: b"v1".to_vec(),
        tagger: Identity::ed25519(signer.public.0),
        signer: signer.public.0,
        message: b"tag".to_vec(),
        timestamp: 1,
        signature: [0; 64],
    };
    tag.signature = mkit_core::sign::sign_tag(&tag, &signer).unwrap().0;
    let tag = Object::Tag(tag);
    let (outcome, _) = fx.push_ref(
        "room",
        &[&tag],
        (TAG_REF, TAG_PACKMAP),
        id(&tag),
        (Missing, Missing),
    );
    assert_eq!(outcome, AdvanceOutcome::Committed);
    drain(&fx);
    for writer in [false, true] {
        in_view(&fx, writer, |reader| {
            let reader = reader.with_selected_ref(TAG_REF).unwrap();
            let mut session = ReaderSession::default();
            let capture = block_on(reader.selected_capture_in(&mut session))
                .unwrap()
                .unwrap();
            // The unpeeled anchor: the tag id, not the peeled commit.
            assert_eq!(capture.tip(), id(&tag));
            let reads = block_on(reader.read_canonical_in(&mut session, &[d.head()])).unwrap();
            assert_eq!(reads, vec![Some(serialize(&d.commit).unwrap())]);
            let link = session.proofs.history_link(&d.head()).unwrap();
            assert_eq!(link.edge, HistoryEdge::TagTarget);
            assert_eq!(link.predecessor, Some(id(&tag)));
        });
    }
}

#[test]
fn off_ref_objects_are_uniformly_absent_without_lookup() {
    for writer in [false, true] {
        let fx = fixture();
        let d = data();
        fx.push("room", &d.refs(), d.head(), None);
        // A second branch whose leaf is unreachable from the selected ref.
        let side_file = blob(b"only on the side branch");
        let side_root = tree(&[("side", EntryMode::Blob, &side_file)]);
        let side_head = commit(&side_root, &[], "side");
        let (outcome, _) = fx.push_ref(
            "room",
            &[&side_file, &side_root, &side_head],
            ("refs/heads/side", "refs/mkit/packmap/side"),
            id(&side_head),
            (Missing, Missing),
        );
        assert_eq!(outcome, AdvanceOutcome::Committed);
        drain(&fx);
        let needle = id(&side_file);
        in_view(&fx, writer, |reader| {
            let reader = reader.with_selected_ref(HEAD).unwrap();
            let mut session = ReaderSession::default();
            let before = fx.pipe.meta.seen().len();
            let reads = block_on(reader.read_canonical_in(&mut session, &[needle])).unwrap();
            assert_eq!(reads, vec![None]);
            assert!(
                !fx.pipe.meta.seen()[before..]
                    .iter()
                    .any(|key| key.as_bytes().windows(32).any(|w| w == needle.as_slice())),
                "an off-ref target is never located"
            );
        });
        // Control: an unscoped session proves the same target.
        in_view(&fx, writer, |reader| {
            let mut session = ReaderSession::default();
            let reads = block_on(reader.read_canonical_in(&mut session, &[needle])).unwrap();
            assert_eq!(reads, vec![Some(serialize(&side_file).unwrap())]);
        });
    }
}

#[test]
fn owner_and_public_selected_roots_differ_when_publication_lags() {
    let fx = fixture();
    let (_, root, _, head, head_pack) = simple_history(&fx);
    let second = commit(&root, &[&head], "second");
    fx.push(
        "room",
        &[&second],
        id(&second),
        Some((id(&head), head_pack)),
    );
    drain(&fx);
    // An uncleared advance leaves the published pair behind the live ref:
    // the owner's anchor is the live ref while the public anchor is the
    // ledger's published head.
    let repo = fx.repo_id("room");
    let shard = fx.pipe.shards.ref_shard(&repo, HEAD);
    let key = keys::publication(&repo.name, HEAD);
    let mut publication =
        Publication::decode(block_on(fx.pipe.meta.get(&shard, &key)).unwrap().as_ref()).unwrap();
    publication.value.head = Some(id(&head));
    publication.value.packmap = Some(head_pack);
    let batch = Batch::new().put(key, publication.encode().unwrap());
    assert_eq!(
        block_on(fx.pipe.meta.apply(&shard, batch)).unwrap(),
        BatchOutcome::Committed
    );
    in_view(&fx, true, |reader| {
        let reader = reader.with_selected_ref(HEAD).unwrap();
        let mut session = ReaderSession::default();
        let capture = block_on(reader.selected_capture_in(&mut session))
            .unwrap()
            .unwrap();
        assert_eq!(capture.tip(), id(&second));
    });
    in_view(&fx, false, |reader| {
        let reader = reader.with_selected_ref(HEAD).unwrap();
        let mut session = ReaderSession::default();
        let capture = block_on(reader.selected_capture_in(&mut session))
            .unwrap()
            .unwrap();
        assert_eq!(capture.tip(), id(&head));
    });
}

#[test]
fn a_missing_or_empty_ledger_is_uniformly_absent() {
    let fx = fixture();
    let (_, _, _, head, _) = simple_history(&fx);
    // A zero-sequence publication is the same absent state as no ledger.
    let repo = fx.repo_id("room");
    let shard = fx.pipe.shards.ref_shard(&repo, "refs/heads/zero");
    let batch = Batch::new()
        .put(
            keys::publication(&repo.name, "refs/heads/zero"),
            Publication::default().encode().unwrap(),
        )
        .put(
            keys::ref_key(&repo.name, "refs/heads/zero"),
            codec::encode_ref_id(&id(&head)),
        );
    assert_eq!(
        block_on(fx.pipe.meta.apply(&shard, batch)).unwrap(),
        BatchOutcome::Committed
    );
    for writer in [false, true] {
        for reference in ["refs/heads/missing", "refs/heads/zero"] {
            in_view(&fx, writer, |reader| {
                let reader = reader.with_selected_ref(reference).unwrap();
                let mut session = ReaderSession::default();
                assert!(
                    block_on(reader.selected_capture_in(&mut session))
                        .unwrap()
                        .is_none()
                );
                let reads = block_on(reader.read_canonical_in(&mut session, &[id(&head)])).unwrap();
                assert_eq!(reads, vec![None]);
            });
        }
    }
}

#[test]
fn stale_aba_and_expired_captures_are_refused() {
    for writer in [false, true] {
        let fx = fixture();
        let (_, root, _, head, head_pack) = simple_history(&fx);
        in_view(&fx, writer, |reader| {
            let reader = reader.with_selected_ref(HEAD).unwrap();
            let mut session = ReaderSession::default();
            let capture = block_on(reader.selected_capture_in(&mut session))
                .unwrap()
                .unwrap();
            assert!(block_on(reader.verify_checkpoint_in(&mut session, &capture)).unwrap());
            // A session that never captured holds no checkpoint at all.
            let mut empty = ReaderSession::default();
            assert!(!block_on(reader.verify_checkpoint_in(&mut empty, &capture)).unwrap());
            // ABA: advance and rewind to the same ref value; only the
            // publication ledger moved on.
            let second = commit(&root, &[&head], "second");
            let second_pack = fx.push(
                "room",
                &[&second],
                id(&second),
                Some((id(&head), head_pack)),
            );
            drain(&fx);
            let (outcome, _) = fx.push_ref(
                "room",
                &[&head],
                (HEAD, PACKMAP),
                id(&head),
                (Match(id(&second)), Match(second_pack)),
            );
            assert_eq!(outcome, AdvanceOutcome::Committed);
            drain(&fx);
            assert!(!block_on(reader.verify_checkpoint_in(&mut session, &capture)).unwrap());
            // A private -> public round trip changes only the security digest.
            let mut session = ReaderSession::default();
            let settled = block_on(reader.selected_capture_in(&mut session))
                .unwrap()
                .unwrap();
            assert!(block_on(reader.verify_checkpoint_in(&mut session, &settled)).unwrap());
            fx.make_private("room");
            set_visibility(&fx, codec::StoredVisibility::Public);
            assert!(!block_on(reader.verify_checkpoint_in(&mut session, &settled)).unwrap());
        });
        // Expiry drops the checkpoint; the next capture is a new handle.
        in_view(&fx, writer, |reader| {
            let reader = reader.with_selected_ref(HEAD).unwrap();
            let mut session = ReaderSession::default();
            let capture = block_on(reader.selected_capture_in(&mut session))
                .unwrap()
                .unwrap();
            fx.clock.advance(61_000);
            assert!(!block_on(reader.verify_checkpoint_in(&mut session, &capture)).unwrap());
            let recaptured = block_on(reader.selected_capture_in(&mut session))
                .unwrap()
                .unwrap();
            assert!(!std::sync::Arc::ptr_eq(&recaptured.0, &capture.0));
            assert!(block_on(reader.verify_checkpoint_in(&mut session, &recaptured)).unwrap());
        });
    }
}

#[test]
fn cross_reader_sessions_are_refused() {
    for writer in [false, true] {
        let fx = fixture();
        let (_, _, base, head, _) = simple_history(&fx);
        in_view(&fx, writer, |reader| {
            let a = reader.with_selected_ref(HEAD).unwrap();
            let mut session = ReaderSession::default();
            let capture = block_on(a.selected_capture_in(&mut session))
                .unwrap()
                .unwrap();
            in_view(&fx, writer, |other| {
                let b = other.with_selected_ref(HEAD).unwrap();
                // A different reader identity drops the memo entirely.
                assert!(!block_on(b.verify_checkpoint_in(&mut session, &capture)).unwrap());
                assert!(!block_on(a.verify_checkpoint_in(&mut session, &capture)).unwrap());
            });
        });
        // A session bound by the unscoped reader loses its proofs too.
        in_view(&fx, writer, |reader| {
            let mut session = ReaderSession::default();
            block_on(reader.read_canonical_in(&mut session, &[id(&head), id(&base)])).unwrap();
            assert!(session.proofs.contains(&id(&base)));
            assert!(session.proofs.checkpoint().is_none());
            let reader = reader.with_selected_ref(HEAD).unwrap();
            block_on(reader.selected_capture_in(&mut session))
                .unwrap()
                .unwrap();
            assert!(session.proofs.checkpoint().is_some());
            assert!(!session.proofs.contains(&id(&base)));
        });
    }
}

#[test]
fn helpers_cannot_change_capture_provenance() {
    for writer in [false, true] {
        let mut fx = fixture();
        enable(&mut fx);
        simple_history(&fx);
        in_view(&fx, writer, |reader| {
            let reader = reader.with_selected_ref(HEAD).unwrap();
            let mut session = ReaderSession::default();
            let capture = block_on(reader.selected_capture_in(&mut session))
                .unwrap()
                .unwrap();
            // The isolated continuation helper preserves the caller's memo.
            let page = block_on(reader.walk_history_page_in(&mut session, HEAD, None, 1))
                .unwrap()
                .unwrap();
            assert_eq!(page.commits.len(), 1);
            assert!(block_on(reader.verify_checkpoint_in(&mut session, &capture)).unwrap());
            // A helper's own capture replaces the memo and its checkpoint.
            let page = block_on(reader.walk_history_in(
                &mut session,
                HEAD,
                None,
                1,
                HistoryOptions::default(),
            ))
            .unwrap()
            .unwrap();
            assert_eq!(page.commits.len(), 1);
            assert!(!block_on(reader.verify_checkpoint_in(&mut session, &capture)).unwrap());
            // Helpers naming another ref are refused before any I/O.
            let ops = fx.pipe.meta.calls();
            let error = block_on(reader.walk_history_in(
                &mut session,
                "refs/heads/other",
                None,
                1,
                HistoryOptions::default(),
            ))
            .unwrap_err();
            assert_eq!(error.code(), Code::InvalidArgument);
            assert_eq!(fx.pipe.meta.calls(), ops);
        });
    }
    // Ref name validation performs no I/O.
    let fx = fixture();
    for bad in ["main", "", "refs/mkit/packmap/x"] {
        in_view(&fx, false, |reader| {
            let ops = fx.pipe.meta.calls();
            let error = reader.with_selected_ref(bad).err().unwrap();
            assert_eq!(error.code(), Code::InvalidArgument);
            assert_eq!(fx.pipe.meta.calls(), ops);
        });
    }
}

#[test]
fn declined_optional_expansion_admits_no_history_link() {
    for writer in [false, true] {
        // Two rows prove the tip; the parent edge's expansion is declined.
        let fx = fixture_with(
            Hooks::new(),
            HttpObjectsConfig {
                max_walk_objects: 2,
                ..http_cfg()
            },
        );
        let (_, _, base, head, _) = simple_history(&fx);
        in_view(&fx, writer, |reader| {
            let reader = reader.with_selected_ref(HEAD).unwrap();
            let mut session = ReaderSession::default();
            block_on(reader.selected_capture_in(&mut session))
                .unwrap()
                .unwrap();
            // The walk sees the parent at the tip's expansion, so the read
            // still follows existing semantics and serves it.
            let reads = block_on(reader.read_canonical_in(&mut session, &[id(&base)])).unwrap();
            assert_eq!(reads, vec![Some(serialize(&base).unwrap())]);
            // Expansion was declined: the parent row was never recorded.
            assert!(session.proofs.history_link(&id(&base)).is_none());
            let Object::Commit(head_commit) = &head else {
                panic!("expected a commit");
            };
            let link = session.proofs.history_link(&id(&head)).unwrap();
            assert_eq!(link.edge, HistoryEdge::Root);
            assert_eq!(
                link.decoded,
                Some((HistoryKind::Commit, head_commit.timestamp))
            );
        });
        // A stop-descent gate on the tip keeps its parent unproved.
        let fx = fixture();
        let (_, _, base, head, _) = simple_history(&fx);
        let gate = Arc::new(Takedown {
            verdict: Mutex::new(|| TakedownVerdict::Clear),
            stops: Some(id(&head)),
            seen: Mutex::new(Vec::new()),
        });
        let fx = with_seams(fx, |seams| seams.takedown = gate);
        in_view(&fx, writer, |reader| {
            let reader = reader.with_selected_ref(HEAD).unwrap();
            let mut session = ReaderSession::default();
            block_on(reader.selected_capture_in(&mut session))
                .unwrap()
                .unwrap();
            let reads =
                block_on(reader.read_canonical_in(&mut session, &[id(&head), id(&base)])).unwrap();
            assert_eq!(reads, vec![Some(serialize(&head).unwrap()), None]);
            assert!(session.proofs.history_link(&id(&base)).is_none());
        });
    }
}

#[test]
fn unscoped_sessions_record_no_lineage() {
    for writer in [false, true] {
        let fx = fixture();
        let (_, root, base, head, _) = simple_history(&fx);
        in_view(&fx, writer, |reader| {
            let mut session = ReaderSession::default();
            let reads = block_on(
                reader.read_canonical_in(&mut session, &[id(&head), id(&root), id(&base)]),
            )
            .unwrap();
            assert!(reads.iter().all(Option::is_some));
            assert!(session.proofs.checkpoint().is_none());
            assert!(session.proofs.history_link(&id(&base)).is_none());
            assert!(session.proofs.history_link(&id(&head)).is_none());
        });
    }
}

#[test]
fn capture_failures_map_like_session_reads() {
    // A refusal that lands after reader construction is typed for an owner
    // capture, never a silent absence; the public view stays absent.
    let az = Arc::new(Scripted::default());
    let fx = fixture_with(scripted(&az), http_cfg());
    simple_history(&fx);
    in_view(&fx, true, |reader| {
        let reader = reader.with_selected_ref(HEAD).unwrap();
        *az.verdict.lock().unwrap() = Some(Code::PermissionDenied);
        let mut session = ReaderSession::default();
        let error = block_on(reader.selected_capture_in(&mut session)).unwrap_err();
        assert_eq!(error.code(), Code::PermissionDenied);
    });
    in_view(&fx, false, |reader| {
        let reader = reader.with_selected_ref(HEAD).unwrap();
        let mut session = ReaderSession::default();
        assert!(
            block_on(reader.selected_capture_in(&mut session))
                .unwrap()
                .is_none()
        );
    });
    // A private repository is uniformly absent for a public capture too.
    let fx = fixture();
    simple_history(&fx);
    fx.make_private("room");
    in_view(&fx, false, |reader| {
        let reader = reader.with_selected_ref(HEAD).unwrap();
        let mut session = ReaderSession::default();
        assert!(
            block_on(reader.selected_capture_in(&mut session))
                .unwrap()
                .is_none()
        );
    });
}

#[test]
fn an_owner_sessions_capped_batch_is_typed_never_absent() {
    let fx = fixture();
    let (file, _, _, _, _) = simple_history(&fx);
    in_view(&fx, true, |reader| {
        let reader = reader.with_selected_ref(HEAD).unwrap();
        // Measure a capture plus one proved read. The second read reuses the
        // checkpoint and the memoized proof, so its own charge and the
        // denial prefetch consume three calls before the post-proof locate.
        let mut probe = ReaderSession::default();
        block_on(reader.selected_capture_in(&mut probe))
            .unwrap()
            .unwrap();
        let reads = block_on(reader.read_canonical_in(&mut probe, &[id(&file)])).unwrap();
        assert_eq!(reads, vec![Some(serialize(&file).unwrap())]);
        let spent = probe.used().storage_calls;
        let mut session =
            ReaderSession::new(ReadLimits::new(spent + 3, u64::MAX, u64::MAX, u64::MAX));
        block_on(reader.selected_capture_in(&mut session))
            .unwrap()
            .unwrap();
        assert!(
            block_on(reader.read_canonical_in(&mut session, &[id(&file)])).unwrap()[0].is_some()
        );
        // A capped locate is typed exhaustion for an owner, never `None`.
        let error = block_on(reader.read_canonical_in(&mut session, &[id(&file)])).unwrap_err();
        assert_eq!(error.code(), Code::ResourceExhausted);
    });
}

fn set_visibility(fx: &Fx, visibility: codec::StoredVisibility) {
    let repo = fx.repo_id("room");
    let batch = Batch::new().put(
        keys::repo_visibility(&repo.name),
        codec::encode_repo_visibility(&codec::RepoVisibilityV1 {
            visibility,
            last_created_ms: 0,
            last_statement_id: None,
            changed_ms: 7,
        }),
    );
    let partition = fx.pipe.shards.coordinator(&repo.namespace);
    assert_eq!(
        block_on(fx.pipe.meta.inner.apply(&partition, batch)).unwrap(),
        BatchOutcome::Committed
    );
}

fn enable<H: HookSet>(fx: &mut Fx<H>) {
    fx.pipe.cfg.history_tokens = Some(
        HistoryTokenConfig::new(
            zeroize::Zeroizing::new([101; 32]),
            "test-backend".into(),
            900_000,
        )
        .unwrap(),
    );
}
