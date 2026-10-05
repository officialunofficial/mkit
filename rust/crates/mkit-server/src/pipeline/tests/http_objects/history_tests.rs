//! Real indexed fixtures for bounded history and exact commit/path reads.
use super::*;
use crate::pipeline::{
    HistoryMode, HistoryOptions, ObjectReader, PathOptions, ReadLimits, ReaderSession, ReaderView,
};

fn in_view<H: HookSet>(
    fx: &Fx<H>,
    writer: bool,
    test: impl FnOnce(ObjectReader<'_, SpyBlobs, Arc<Spy>, H>),
) {
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
        if writer {
            ReaderView::Owner(&meta)
        } else {
            ReaderView::Public
        },
    ))
    .unwrap();
    test(reader);
}

fn drain(fx: &Fx) {
    let repo = fx.repo_id("room");
    let source = fx.pipe.shards.ref_shard(&repo, HEAD);
    let relay = crate::timers::TimerRegistry::new().register(crate::relay::RelayHandler {
        target: crate::store::BorrowedStore(&fx.pipe.meta),
        hook: crate::relay::NoHook,
        budget: crate::relay::RelayBudget::default(),
    });
    for _ in 0..128 {
        block_on(crate::timers::run_due(
            &fx.pipe.meta,
            &source,
            &relay,
            fx.clock.as_ref(),
            T0 as u64,
            &crate::timers::TickBudget::default(),
        ))
        .unwrap();
    }
}
fn history(
    h: usize,
    depth: usize,
    files: usize,
    denial: bool,
) -> (Fx, Vec<Object>, Hash, Vec<Vec<u8>>) {
    let mut fx = fixture_tweaked(Hooks::new(), http_cfg(), |cfg| {
        cfg.sharding = Sharding::D34;
        cfg.takedown_denial = false;
    });
    fx.pipe
        .meta
        .count_partition_scans
        .store(true, Ordering::SeqCst);
    let mut commits = Vec::new();
    let mut previous = None;
    let mut leaf = [0; 32];
    for n in 0..h {
        let mut objects = Vec::new();
        let mut sub = None;
        for d in (0..=depth).rev() {
            let mut entries = Vec::new();
            for f in 0..files {
                let file = blob(format!("change {n} level {d} file {f}").as_bytes());
                if n == 0 && d == depth && f == 0 {
                    leaf = id(&file);
                }
                entries.push(TreeEntry {
                    name: format!("f{f:03}").into_bytes(),
                    mode: EntryMode::Blob,
                    object_hash: id(&file),
                });
                objects.push(file);
            }
            if let Some(child) = sub {
                entries.push(TreeEntry {
                    name: b"sub".to_vec(),
                    mode: EntryMode::Tree,
                    object_hash: child,
                });
            }
            let root = Object::Tree(Tree { entries });
            sub = Some(id(&root));
            objects.push(root);
        }
        let head = commit(
            objects.last().unwrap(),
            &commits.last().into_iter().collect::<Vec<_>>(),
            &format!("change {n}"),
        );
        objects.push(head.clone());
        let pack = fx.push(
            "room",
            &objects.iter().collect::<Vec<_>>(),
            id(&head),
            previous,
        );
        drain(&fx);
        previous = Some((id(&head), pack));
        commits.push(head);
    }
    fx.pipe.cfg.takedown_denial = denial;
    let mut path = vec![b"sub".to_vec(); depth];
    path.push(b"f000".to_vec());
    (fx, commits, leaf, path)
}

fn get_count(fx: &Fx) -> usize {
    fx.calls
        .lock()
        .unwrap()
        .iter()
        .filter(|(op, _)| *op == "get")
        .count()
}
fn report(
    fx: &Fx,
    label: &str,
    units: u32,
    before_kv: u32,
    before_get: usize,
    directory_checks: u32,
) {
    let kv = fx.pipe.meta.calls() - before_kv;
    let gets = u32::try_from(get_count(fx) - before_get).unwrap();
    // Raw range reads map to HEAD + GET. Strong-directory first pages have
    // four waves at concurrency four, instead of sixteen serial waits.
    let physical = kv + 2 * gets;
    let rounds = physical.saturating_sub(12 * directory_checks);
    println!(
        "{label}: units={units}, KV={kv}, ranged_GET={gets}, physical_calls={physical}, modeled_rounds={rounds}, wait_30ms={:.2}s, wait_130ms={:.2}s",
        f64::from(rounds) * 0.03,
        f64::from(rounds) * 0.13
    );
}

#[test]
#[allow(clippy::too_many_lines)] // One fixture matrix across owner/public and denial modes.
fn history_counts_only_commit_decodes_and_old_path_fits_budget() {
    for denial in [false, true] {
        let (fx, commits, _, _) = history(31, 10, 27, denial);
        for writer in [false, true] {
            in_view(&fx, writer, |reader| {
                let mut session = ReaderSession::default();
                let (kv, gets, ops) = (
                    fx.pipe.meta.calls(),
                    get_count(&fx),
                    fx.pipe.meta.ops().len(),
                );
                let page = block_on(reader.walk_history_in(
                    &mut session,
                    HEAD,
                    None,
                    30,
                    HistoryOptions::default(),
                ))
                .unwrap()
                .unwrap();
                assert_eq!(page.commits.len(), 30);
                assert!(!page.complete);
                let canonical: Vec<_> = commits
                    .iter()
                    .rev()
                    .take(30)
                    .map(|o| serialize(o).unwrap())
                    .collect();
                assert_eq!(
                    page.commits
                        .iter()
                        .map(|c| &c.canonical)
                        .collect::<Vec<_>>(),
                    canonical.iter().collect::<Vec<_>>()
                );
                assert_eq!(
                    session.used().decoded_bytes,
                    canonical.iter().map(|c| c.len() as u64).sum::<u64>(),
                    "zero tree/blob decoding"
                );
                assert_eq!(
                    get_count(&fx) - gets,
                    60,
                    "two raw-range reads per commit, zero snapshot reads"
                );
                let scans = fx.pipe.meta.ops()[ops..]
                    .iter()
                    .filter(|&&op| op == "scan_many_index")
                    .count();
                assert!(scans <= if denial { 120 } else { 60 }, "{scans}");
                report(
                    &fx,
                    &format!("log30 owner={writer} denial={denial}"),
                    session.used().storage_calls,
                    kv,
                    gets,
                    if denial { 31 } else { 0 },
                );
                let mut session = ReaderSession::default();
                let (kv, gets) = (fx.pipe.meta.calls(), get_count(&fx));
                let target = id(&commits[10]);
                let found = block_on(reader.locate_commit_in(
                    &mut session,
                    HEAD,
                    target,
                    HistoryOptions::default(),
                ))
                .unwrap()
                .unwrap();
                assert_eq!(found.canonical, serialize(&commits[10]).unwrap());
                assert_eq!(get_count(&fx) - gets, 42);
                assert_eq!(
                    session.used().decoded_bytes,
                    commits[10..]
                        .iter()
                        .map(|c| serialize(c).unwrap().len() as u64)
                        .sum::<u64>()
                );
                report(
                    &fx,
                    &format!("lookup20 owner={writer} denial={denial}"),
                    session.used().storage_calls,
                    kv,
                    gets,
                    if denial { 21 } else { 0 },
                );
            });
        }
        // Twenty parents followed by ten directory edges plus a leaf.
        let (fx, commits, leaf, path) = history(21, 10, 27, denial);
        for (writer, include_witness) in
            [(false, false), (true, false), (false, true), (true, true)]
        {
            in_view(&fx, writer, |reader| {
                let mut session = ReaderSession::default();
                let (kv, gets, ops) = (
                    fx.pipe.meta.calls(),
                    get_count(&fx),
                    fx.pipe.meta.ops().len(),
                );
                let found = block_on(reader.read_commit_path_in(
                    &mut session,
                    HEAD,
                    id(&commits[0]),
                    &path,
                    Some(leaf),
                    PathOptions {
                        include_witness,
                        ..PathOptions::default()
                    },
                ))
                .unwrap()
                .unwrap();
                assert_eq!(found.id, leaf);
                assert_eq!(
                    id(&mkit_core::serialize::deserialize(&found.canonical).unwrap()),
                    leaf
                );
                assert!(
                    session.used().storage_calls <= 1_500,
                    "{}",
                    session.used().storage_calls
                );
                let scans = fx.pipe.meta.ops()[ops..]
                    .iter()
                    .filter(|&&op| op == "scan_many_index")
                    .count();
                let primary_scans = scans
                    - if denial {
                        33 + if include_witness { 13 } else { 0 }
                    } else {
                        0
                    };
                assert!(
                    primary_scans <= 35,
                    "{primary_scans} primary, {scans} total"
                );
                report(
                    &fx,
                    &format!(
                        "lookup20/path10 owner={writer} denial={denial} witness={include_witness}"
                    ),
                    session.used().storage_calls,
                    kv,
                    gets,
                    if denial {
                        33 + u32::from(include_witness)
                    } else {
                        0
                    },
                );
                let mut output_bytes = found.canonical.len() as u64;
                assert_eq!(found.witness.is_some(), include_witness);
                if let Some(witness) = &found.witness {
                    assert_eq!(witness.commit.id, id(&commits[0]));
                    assert_eq!(witness.commit.canonical, serialize(&commits[0]).unwrap());
                    assert_eq!(witness.trees.len(), path.len());
                    let Object::Commit(commit) = &commits[0] else {
                        panic!("commit")
                    };
                    let mut expected_tree = commit.tree_hash;
                    output_bytes += witness.commit.canonical.len() as u64;
                    for (ancestor, name) in witness.trees.iter().zip(&path) {
                        assert_eq!(ancestor.id, expected_tree);
                        let object =
                            mkit_core::serialize::deserialize(&ancestor.canonical).unwrap();
                        assert_eq!(id(&object), ancestor.id);
                        let Object::Tree(tree) = object else {
                            panic!("tree")
                        };
                        expected_tree = tree
                            .entries
                            .iter()
                            .find(|entry| entry.name == *name)
                            .unwrap()
                            .object_hash;
                        output_bytes += ancestor.canonical.len() as u64;
                    }
                    assert_eq!(expected_tree, leaf);
                }
                assert_eq!(session.used().output_bytes, output_bytes);
                let current = block_on(reader.read_canonical_in(&mut session, &[leaf])).unwrap()[0]
                    .take()
                    .unwrap();
                assert_eq!(current, found.canonical);
            });
        }
    }
}

#[test]
fn continued_start_is_parent_only_and_public_missing_matches_stored_orphan() {
    let (fx, commits, _, _) = history(61, 1, 2, true);
    let orphan = blob(b"orphan");
    let root = tree(&[("a", EntryMode::Blob, &orphan)]);
    let orphan_commit = commit(&root, &[], "unreachable");
    // A real stored orphan in a separate repository has no authority in room.
    fx.push(
        "other",
        &[&orphan, &root, &orphan_commit],
        id(&orphan_commit),
        None,
    );
    for writer in [false, true] {
        in_view(&fx, writer, |reader| {
            let mut session = ReaderSession::default();
            let gets = get_count(&fx);
            let page = block_on(reader.walk_history_in(
                &mut session,
                HEAD,
                Some(id(&commits[30])),
                30,
                HistoryOptions::default(),
            ))
            .unwrap()
            .unwrap();
            assert_eq!(
                page.commits.iter().map(|c| c.id).collect::<Vec<_>>(),
                commits[1..31].iter().rev().map(id).collect::<Vec<_>>()
            );
            assert_eq!(get_count(&fx) - gets, 120);
            let mut costs = Vec::new();
            for target in [id(&orphan_commit), [231; 32]] {
                let mut session = ReaderSession::default();
                assert!(
                    block_on(reader.locate_commit_in(
                        &mut session,
                        HEAD,
                        target,
                        HistoryOptions::default()
                    ))
                    .unwrap()
                    .is_none()
                );
                costs.push(session.used());
            }
            assert_eq!(costs[0], costs[1]);
        });
    }
}

#[test]
fn merge_modes_preserve_parent_order_deduplicate_and_refuse_fanout() {
    for denial in [false, true] {
        let mut fx = fixture();
        let root = tree(&[]);
        let base = commit(&root, &[], "base");
        let left = commit(&root, &[&base], "left");
        let right = commit(&root, &[&base], "right");
        let head = commit(&root, &[&left, &right], "merge");
        fx.push(
            "room",
            &[&root, &base, &left, &right, &head],
            id(&head),
            None,
        );
        fx.pipe.cfg.takedown_denial = denial;
        for writer in [false, true] {
            in_view(&fx, writer, |reader| {
                for (mode, expected) in [
                    (
                        HistoryMode::AllParents,
                        vec![id(&head), id(&left), id(&right), id(&base)],
                    ),
                    (
                        HistoryMode::FirstParent,
                        vec![id(&head), id(&left), id(&base)],
                    ),
                ] {
                    let options = HistoryOptions {
                        mode,
                        ..HistoryOptions::default()
                    };
                    let page = block_on(reader.walk_history_in(
                        &mut ReaderSession::default(),
                        HEAD,
                        None,
                        20,
                        options,
                    ))
                    .unwrap()
                    .unwrap();
                    assert_eq!(
                        page.commits.iter().map(|c| c.id).collect::<Vec<_>>(),
                        expected
                    );
                    assert!(page.complete);
                }
                let mut options = HistoryOptions {
                    max_frontier: 1,
                    ..HistoryOptions::default()
                };
                let result = block_on(reader.walk_history_in(
                    &mut ReaderSession::default(),
                    HEAD,
                    None,
                    20,
                    options,
                ));
                if writer {
                    assert_eq!(result.unwrap_err().code(), Code::ResourceExhausted);
                } else {
                    assert!(result.unwrap().is_none());
                }
                options.max_nodes = 1;
                assert_eq!(
                    block_on(reader.locate_commit_in(
                        &mut ReaderSession::default(),
                        HEAD,
                        id(&head),
                        options
                    ))
                    .unwrap()
                    .unwrap()
                    .id,
                    id(&head)
                );
            });
        }
    }
}

#[test]
#[allow(clippy::too_many_lines)] // Independent bounds and completion in the same merge fixture.
fn merge_visit_bounds_stops_and_redundant_parents() {
    for denial in [false, true] {
        let mut fx = fixture();
        let root = tree(&[]);
        let left = commit(&root, &[], "left");
        let right = commit(&root, &[&left], "right");
        let head = commit(&root, &[&left, &right], "merge");
        fx.push("room", &[&root, &left, &right, &head], id(&head), None);
        fx.pipe.cfg.takedown_denial = denial;
        for writer in [false, true] {
            in_view(&fx, writer, |reader| {
                let options = HistoryOptions {
                    max_nodes: 2,
                    max_frontier: 2,
                    ..HistoryOptions::default()
                };
                let mut session = ReaderSession::default();
                let gets = get_count(&fx);
                let found =
                    block_on(reader.locate_commit_in(&mut session, HEAD, id(&left), options))
                        .unwrap()
                        .unwrap();
                assert_eq!(found.id, id(&left));
                assert_eq!(get_count(&fx) - gets, 4, "exactly two visited commits");
                let mut session = ReaderSession::default();
                let result =
                    block_on(reader.locate_commit_in(&mut session, HEAD, id(&right), options));
                if writer {
                    assert_eq!(result.unwrap_err().code(), Code::ResourceExhausted);
                } else {
                    assert!(result.unwrap().is_none());
                }
                assert_eq!(session.used().output_bytes, 0);
                for limit in [3, 4] {
                    let page = block_on(reader.walk_history_in(
                        &mut ReaderSession::default(),
                        HEAD,
                        None,
                        limit,
                        HistoryOptions::default(),
                    ))
                    .unwrap()
                    .unwrap();
                    assert_eq!(
                        page.commits.iter().map(|c| c.id).collect::<Vec<_>>(),
                        vec![id(&head), id(&left), id(&right)]
                    );
                    assert!(page.complete, "all selected parents were consumed");
                }
            });
        }
        fx.pipe = fx.pipe.with_http_seams(|mut seams| {
            seams.takedown = Arc::new(StopGate {
                stop: id(&head),
                pause: None,
            });
            seams
        });
        for writer in [false, true] {
            in_view(&fx, writer, |reader| {
                let mut session = ReaderSession::default();
                let gets = get_count(&fx);
                let page = block_on(reader.walk_history_in(
                    &mut session,
                    HEAD,
                    None,
                    2,
                    HistoryOptions {
                        max_frontier: 1,
                        ..HistoryOptions::default()
                    },
                ))
                .unwrap()
                .unwrap();
                assert_eq!(page.commits.len(), 1);
                assert_eq!(page.commits[0].id, id(&head));
                assert!(page.complete);
                assert_eq!(get_count(&fx) - gets, 2, "stopped parents are never loaded");
                assert!(!session.proofs.contains(&id(&left)));
                assert!(!session.proofs.contains(&id(&right)));
            });
        }
    }
}

#[test]
#[allow(clippy::too_many_lines)] // One fixture matrix across owner/public and denial modes.
fn exact_names_modes_roots_symlinks_and_expected_ids() {
    for denial in [false, true] {
        let mut fx = fixture();
        let file = blob(b"payload");
        let link = blob(b"target");
        let child = tree(&[("target", EntryMode::Blob, &file)]);
        let root = Object::Tree(Tree {
            entries: vec![
                TreeEntry {
                    name: b"Case".to_vec(),
                    mode: EntryMode::Executable,
                    object_hash: id(&file),
                },
                TreeEntry {
                    name: b"bad".to_vec(),
                    mode: EntryMode::Tree,
                    object_hash: id(&file),
                },
                TreeEntry {
                    name: b"dir".to_vec(),
                    mode: EntryMode::Tree,
                    object_hash: id(&child),
                },
                TreeEntry {
                    name: b"link".to_vec(),
                    mode: EntryMode::Symlink,
                    object_hash: id(&link),
                },
                TreeEntry {
                    name: vec![0xff],
                    mode: EntryMode::Blob,
                    object_hash: id(&file),
                },
            ],
        });
        let head = commit(&root, &[], "paths");
        fx.push(
            "room",
            &[&file, &link, &child, &root, &head],
            id(&head),
            None,
        );
        fx.pipe.cfg.takedown_denial = denial;
        for writer in [false, true] {
            in_view(&fx, writer, |reader| {
                for (path, target, mode) in [
                    (vec![], &root, EntryMode::Tree),
                    (vec![b"Case".to_vec()], &file, EntryMode::Executable),
                    (vec![b"link".to_vec()], &link, EntryMode::Symlink),
                    (vec![vec![0xff]], &file, EntryMode::Blob),
                    (
                        vec![b"dir".to_vec(), b"target".to_vec()],
                        &file,
                        EntryMode::Blob,
                    ),
                ] {
                    let found = block_on(reader.read_commit_path_in(
                        &mut ReaderSession::default(),
                        HEAD,
                        id(&head),
                        &path,
                        Some(id(target)),
                        PathOptions::default(),
                    ))
                    .unwrap()
                    .unwrap();
                    assert_eq!(found.canonical, serialize(target).unwrap());
                    assert_eq!(found.mode, mode);
                }
                for path in [
                    vec![b"case".to_vec()],
                    vec![b"link".to_vec(), b"target".to_vec()],
                    vec![b"bad".to_vec()],
                    vec![b"Case".to_vec(), b"target".to_vec()],
                ] {
                    assert!(
                        block_on(reader.read_commit_path_in(
                            &mut ReaderSession::default(),
                            HEAD,
                            id(&head),
                            &path,
                            None,
                            PathOptions::default()
                        ))
                        .unwrap()
                        .is_none()
                    );
                }
                let gets = get_count(&fx);
                assert!(
                    block_on(reader.read_commit_path_in(
                        &mut ReaderSession::default(),
                        HEAD,
                        id(&head),
                        &[b"Case".to_vec()],
                        Some([232; 32]),
                        PathOptions::default()
                    ))
                    .unwrap()
                    .is_none()
                );
                assert_eq!(get_count(&fx) - gets, 4, "mismatched leaf was not loaded");
                assert_eq!(
                    block_on(reader.read_commit_path_in(
                        &mut ReaderSession::default(),
                        HEAD,
                        id(&head),
                        &[b"..".to_vec()],
                        None,
                        PathOptions::default()
                    ))
                    .unwrap_err()
                    .code(),
                    Code::InvalidArgument
                );
                let options = PathOptions {
                    max_depth: 0,
                    ..PathOptions::default()
                };
                let result = block_on(reader.read_commit_path_in(
                    &mut ReaderSession::default(),
                    HEAD,
                    id(&head),
                    &[b"Case".to_vec()],
                    None,
                    options,
                ));
                if writer {
                    assert_eq!(result.unwrap_err().code(), Code::ResourceExhausted);
                } else {
                    assert!(result.unwrap().is_none());
                }
            });
        }
    }
}

fn block_id(fx: &Fx, object: Hash) {
    block_on(
        crate::store::ContentIndex::new(crate::store::BorrowedStore(&fx.pipe.meta)).block(
            &object,
            &crate::store::BlockEntry::new("manual", T0 as u64),
            T0 as u64,
        ),
    )
    .unwrap();
}

#[test]
fn scope_pending_visibility_epoch_and_stops_remain_live() {
    for denial in [false, true] {
        let mut fx = fixture_tweaked(Hooks::new(), http_cfg(), |cfg| cfg.takedown_denial = true);
        fx.pipe = fx
            .pipe
            .with_publication_policy(Arc::new(super::super::indexed::InspectionPolicy(
                crate::store::publication::Clearance::Pending,
            )))
            .unwrap();
        let d = data();
        fx.push("room", &d.refs(), d.head(), None);
        fx.pipe.cfg.takedown_denial = denial;
        let mut session = ReaderSession::default();
        in_view(&fx, true, |reader| {
            assert!(
                block_on(reader.read_commit_path_in(
                    &mut session,
                    HEAD,
                    d.head(),
                    &[b"small.txt".to_vec()],
                    None,
                    PathOptions::default()
                ))
                .unwrap()
                .is_some()
            );
        });
        let spent = session.used();
        in_view(&fx, false, |reader| {
            assert!(
                block_on(reader.locate_commit_in(
                    &mut session,
                    HEAD,
                    d.head(),
                    HistoryOptions::default()
                ))
                .unwrap()
                .is_none()
            );
        });
        assert!(session.used().storage_calls > spent.storage_calls);
        assert!(!session.proofs.contains(&d.head()));

        let mut fx = fixture();
        fx.push("room", &d.refs(), d.head(), None);
        fx.pipe.cfg.takedown_denial = denial;
        in_view(&fx, false, |reader| {
            assert!(
                block_on(reader.locate_commit_in(
                    &mut session,
                    HEAD,
                    d.head(),
                    HistoryOptions::default()
                ))
                .unwrap()
                .is_some()
            );
            fx.make_private("room");
            assert!(
                block_on(reader.locate_commit_in(
                    &mut session,
                    HEAD,
                    d.head(),
                    HistoryOptions::default()
                ))
                .unwrap()
                .is_none()
            );
        });
        in_view(&fx, true, |reader| {
            assert!(
                block_on(reader.locate_commit_in(
                    &mut session,
                    HEAD,
                    d.head(),
                    HistoryOptions::default()
                ))
                .unwrap()
                .is_some()
            );
            let repo = fx.repo_id("room");
            block_on(fx.pipe.meta.inner.apply(
                &fx.pipe.shards.coordinator(&repo.namespace),
                Batch::new().put(keys::grant_epoch(), codec::encode_u64(1)),
            ))
            .unwrap();
            // Repository epochs revoke grants; direct owner authority remains valid.
            assert!(
                block_on(reader.locate_commit_in(
                    &mut session,
                    HEAD,
                    d.head(),
                    HistoryOptions::default()
                ))
                .unwrap()
                .is_some()
            );
        });
    }
}

#[test]
fn foreign_remix_sources_and_delta_bases_are_not_history_edges() {
    for denial in [false, true] {
        let mut fx = fixture();
        let root = tree(&[]);
        let orphan = commit(&root, &[], "orphan");
        let signer = KeyPair::from_seed([9; 32]);
        let mut remix = mkit_core::object::Remix {
            tree_hash: id(&root),
            parents: vec![],
            sources: vec![mkit_core::object::RemixSource {
                upstream_id: [99; 32],
                commit_hash: id(&orphan),
            }],
            author: Identity::ed25519(signer.public.0),
            signer: signer.public.0,
            message: b"remix".to_vec(),
            timestamp: 43,
            signature: [0; 64],
        };
        remix.signature = mkit_core::sign::sign_remix(&remix, &signer).unwrap().0;
        let remix = Object::Remix(remix);
        // Stored in the same pack/repo, but only mentioned as a foreign source.
        fx.push("room", &[&root, &orphan, &remix], id(&remix), None);
        fx.pipe.cfg.takedown_denial = denial;
        for writer in [false, true] {
            in_view(&fx, writer, |reader| {
                let mut costs = Vec::new();
                for target in [id(&orphan), [234; 32]] {
                    let mut session = ReaderSession::default();
                    assert!(
                        block_on(reader.locate_commit_in(
                            &mut session,
                            HEAD,
                            target,
                            HistoryOptions::default()
                        ))
                        .unwrap()
                        .is_none()
                    );
                    assert!(!session.proofs.contains(&id(&orphan)));
                    costs.push(session.used());
                }
                assert_eq!(costs[0], costs[1]);
            });
        }

        let mut fx = fixture();
        let base = commit(&root, &[], "delta base");
        let pack = fx.push("room", &[&root, &base], id(&base), None);
        let head = commit(&root, &[], "derived with no parent");
        let mut packed = PackWriter::new();
        packed
            .push_delta(
                &id(&base),
                &mkit_core::delta::encode(&serialize(&base).unwrap(), &serialize(&head).unwrap())
                    .unwrap(),
            )
            .unwrap();
        assert_eq!(
            fx.push_pack(
                "room",
                &packed.finish().unwrap(),
                (HEAD, PACKMAP),
                id(&head),
                (Match(id(&base)), Match(pack))
            )
            .0,
            AdvanceOutcome::Committed
        );
        fx.pipe.cfg.takedown_denial = denial;
        for writer in [false, true] {
            in_view(&fx, writer, |reader| {
                let mut session = ReaderSession::default();
                assert!(
                    block_on(reader.locate_commit_in(
                        &mut session,
                        HEAD,
                        id(&base),
                        HistoryOptions::default()
                    ))
                    .unwrap()
                    .is_none()
                );
                assert!(!session.proofs.contains(&id(&base)));
            });
        }
    }
}

struct StopGate {
    stop: Hash,
    pause: Option<Hash>,
}
impl TakedownGate for StopGate {
    fn stops_descent(&self, _: &RepoId, id: &Hash) -> bool {
        *id == self.stop
    }
    fn check<'a>(
        &'a self,
        _: &'a RepoId,
        id: &'a Hash,
    ) -> crate::BoxFuture<'a, Result<TakedownVerdict, ServerError>> {
        Box::pin(async move {
            if self.pause == Some(*id) {
                std::future::pending().await
            } else {
                Ok(TakedownVerdict::Clear)
            }
        })
    }
}

#[test]
#[allow(clippy::too_many_lines)] // One fixture matrix across owner/public and denial modes.
fn custom_stops_direct_denial_cancellation_and_spent_budgets() {
    for denial in [false, true] {
        for writer in [false, true] {
            let mut fx = fixture();
            let d = data();
            let pack = fx.push("room", &d.refs(), d.head(), None);
            fx.pipe.cfg.takedown_denial = denial;
            fx.pipe = fx.pipe.with_http_seams(|mut seams| {
                seams.takedown = Arc::new(StopGate {
                    stop: id(&d.root),
                    pause: None,
                });
                seams
            });
            in_view(&fx, writer, |reader| {
                assert!(
                    block_on(reader.read_commit_path_in(
                        &mut ReaderSession::default(),
                        HEAD,
                        d.head(),
                        &[b"small.txt".to_vec()],
                        None,
                        PathOptions::default()
                    ))
                    .unwrap()
                    .is_none()
                );
                assert!(
                    block_on(reader.read_commit_path_in(
                        &mut ReaderSession::default(),
                        HEAD,
                        d.head(),
                        &[],
                        None,
                        PathOptions::default()
                    ))
                    .unwrap()
                    .is_some(),
                    "stopped node itself can be read"
                );
                block_id(&fx, pack);
                assert!(
                    block_on(reader.locate_commit_in(
                        &mut ReaderSession::default(),
                        HEAD,
                        d.head(),
                        HistoryOptions::default()
                    ))
                    .unwrap()
                    .is_none()
                );
            });

            let mut fx = fixture();
            fx.push("room", &d.refs(), d.head(), None);
            fx.pipe.cfg.takedown_denial = denial;
            fx.pipe = fx.pipe.with_http_seams(|mut seams| {
                seams.takedown = Arc::new(StopGate {
                    stop: [240; 32],
                    pause: Some(id(&d.root)),
                });
                seams
            });
            in_view(&fx, writer, |reader| {
                let mut session = ReaderSession::default();
                let path = [b"small.txt".to_vec()];
                let mut future = Box::pin(reader.read_commit_path_in(
                    &mut session,
                    HEAD,
                    d.head(),
                    &path,
                    None,
                    PathOptions::default(),
                ));
                assert!(
                    block_on(std::future::poll_fn(|cx| std::task::Poll::Ready(
                        future.as_mut().poll(cx)
                    )))
                    .is_pending()
                );
                drop(future);
                assert!(session.used().storage_calls > 0);
                assert!(session.used().decoded_bytes > serialize(&d.commit).unwrap().len() as u64);
                assert_eq!(session.used().output_bytes, 0);
                assert!(!session.proofs.contains(&id(&d.small)));
            });
            let mut fx = fixture();
            fx.push("room", &d.refs(), d.head(), None);
            fx.pipe.cfg.takedown_denial = denial;
            in_view(&fx, writer, |reader| {
                let mut session =
                    ReaderSession::new(ReadLimits::new(10, 256 << 20, u64::MAX, 256 << 20));
                let result = block_on(reader.locate_commit_in(
                    &mut session,
                    HEAD,
                    d.head(),
                    HistoryOptions::default(),
                ));
                if writer {
                    assert_eq!(result.unwrap_err().code(), Code::ResourceExhausted);
                } else {
                    assert!(result.unwrap().is_none());
                }
                let spent = session.used();
                let _ = block_on(reader.locate_commit_in(
                    &mut session,
                    HEAD,
                    d.head(),
                    HistoryOptions::default(),
                ));
                assert!(session.used().storage_calls >= spent.storage_calls);
                assert_eq!(session.used().output_bytes, 0);
            });
        }
    }
}

#[test]
fn forged_parent_roles_and_corrupted_canonical_bytes_never_expand() {
    for denial in [false, true] {
        let mut fx = fixture();
        let file = blob(b"not a commit");
        let root = tree(&[("file", EntryMode::Blob, &file)]);
        let head = commit(&root, &[&root], "forged parent role");
        fx.push("room", &[&file, &root, &head], id(&head), None);
        fx.pipe.cfg.takedown_denial = denial;
        for writer in [false, true] {
            in_view(&fx, writer, |reader| {
                let mut session = ReaderSession::default();
                assert!(
                    block_on(reader.locate_commit_in(
                        &mut session,
                        HEAD,
                        id(&root),
                        HistoryOptions::default()
                    ))
                    .unwrap()
                    .is_none()
                );
                assert!(!session.proofs.contains(&id(&file)));
            });
        }
        let mut fx = fixture();
        let head = commit(&root, &[], "hash-checked bytes");
        let pack = fx.push("room", &[&file, &root, &head], id(&head), None);
        fx.pipe.cfg.takedown_denial = denial;
        let repo = fx.repo_id("room");
        let partition = fx.pipe.shards.object_index(&repo, &id(&head));
        let key = keys::object_index(&repo.name, &id(&head), &pack);
        let value = block_on(fx.pipe.meta.inner.get(&partition, &key))
            .unwrap()
            .unwrap();
        let mut row = codec::decode_object_index(&id(&head), &value).unwrap();
        row.frame_offset += 1;
        block_on(fx.pipe.meta.inner.apply(
            &partition,
            Batch::new().put(key, codec::encode_object_index(&id(&head), &row).unwrap()),
        ))
        .unwrap();
        for writer in [false, true] {
            in_view(&fx, writer, |reader| {
                let mut session = ReaderSession::default();
                assert_eq!(
                    block_on(reader.locate_commit_in(
                        &mut session,
                        HEAD,
                        id(&head),
                        HistoryOptions::default()
                    ))
                    .unwrap_err()
                    .code(),
                    Code::Unavailable
                );
                assert!(!session.proofs.contains(&id(&root)));
            });
        }
    }
}

struct ChangeAfterBody {
    target: Hash,
    change: Box<dyn Fn() -> crate::BoxFuture<'static, ()> + Send + Sync>,
}
impl TakedownGate for ChangeAfterBody {
    fn check<'a>(
        &'a self,
        _: &'a RepoId,
        id: &'a Hash,
    ) -> crate::BoxFuture<'a, Result<TakedownVerdict, ServerError>> {
        Box::pin(async move {
            if *id == self.target {
                (self.change)().await;
            }
            Ok(TakedownVerdict::Clear)
        })
    }
}
#[test]
#[allow(clippy::too_many_lines)] // One fixture matrix across owner/public and denial modes.
fn authority_and_pack_revocation_after_body_io_prevent_output() {
    for denial in [false, true] {
        for writer in [false, true] {
            let mut fx = fixture();
            let d = data();
            let pack = fx.push("room", &d.refs(), d.head(), None);
            fx.pipe.cfg.takedown_denial = denial;
            let store = fx.pipe.meta.clone();
            fx.pipe = fx.pipe.with_http_seams(|mut seams| {
                seams.takedown = Arc::new(ChangeAfterBody {
                    target: id(&d.small),
                    change: Box::new(move || {
                        let store = store.clone();
                        Box::pin(async move {
                            crate::store::ContentIndex::new(crate::store::BorrowedStore(&store))
                                .block(
                                    &pack,
                                    &crate::store::BlockEntry::new("revoked", T0 as u64),
                                    T0 as u64,
                                )
                                .await
                                .unwrap();
                        })
                    }),
                });
                seams
            });
            in_view(&fx, writer, |reader| {
                let mut session = ReaderSession::default();
                assert!(
                    block_on(reader.read_commit_path_in(
                        &mut session,
                        HEAD,
                        d.head(),
                        &[b"small.txt".to_vec()],
                        None,
                        PathOptions::default()
                    ))
                    .unwrap()
                    .is_none()
                );
                assert_eq!(session.used().output_bytes, 0);
            });
            let az = Arc::new(Scripted::default());
            let mut fx = fixture_with(scripted(&az), http_cfg());
            fx.push("room", &d.refs(), d.head(), None);
            fx.pipe.cfg.takedown_denial = denial;
            let store = fx.pipe.meta.clone();
            let repo = fx.repo_id("room");
            let coordinator = fx.pipe.shards.coordinator(&repo.namespace);
            fx.pipe = fx.pipe.with_http_seams(|mut seams| {
                seams.takedown = Arc::new(ChangeAfterBody {
                    target: id(&d.small),
                    change: Box::new(move || {
                        let (store, repo, coordinator, az) =
                            (store.clone(), repo.clone(), coordinator.clone(), az.clone());
                        Box::pin(async move {
                            if writer {
                                *az.verdict.lock().unwrap() = Some(Code::PermissionDenied);
                            } else {
                                store
                                    .inner
                                    .apply(
                                        &coordinator,
                                        Batch::new().put(
                                            keys::repo_visibility(&repo.name),
                                            codec::encode_repo_visibility(
                                                &codec::RepoVisibilityV1 {
                                                    visibility: codec::StoredVisibility::Private,
                                                    last_created_ms: 0,
                                                    last_statement_id: None,
                                                    changed_ms: 0,
                                                },
                                            ),
                                        ),
                                    )
                                    .await
                                    .unwrap();
                            }
                        })
                    }),
                });
                seams
            });
            in_view(&fx, writer, |reader| {
                let mut session = ReaderSession::default();
                let result = block_on(reader.read_commit_path_in(
                    &mut session,
                    HEAD,
                    d.head(),
                    &[b"small.txt".to_vec()],
                    None,
                    PathOptions::default(),
                ));
                if writer {
                    assert!(result.is_err());
                } else {
                    assert!(result.unwrap().is_none());
                }
                assert_eq!(session.used().output_bytes, 0);
            });
        }
    }
}

#[test]
fn retained_singleton_history_rechecks_after_unavailable_parent() {
    for denial in [false, true] {
        for writer in [false, true] {
            let mut fx = fixture();
            let root = tree(&[]);
            let parent = commit(&root, &[], "parent");
            let head = commit(&root, &[&parent], "head");
            let pack = fx.push("room", &[&root, &parent, &head], id(&head), None);
            fx.pipe.cfg.takedown_denial = denial;
            let store = fx.pipe.meta.clone();
            fx.pipe = fx.pipe.with_http_seams(|mut seams| {
                seams.takedown = Arc::new(ChangeAfterBody {
                    target: id(&parent),
                    change: Box::new(move || {
                        let store = store.clone();
                        Box::pin(async move {
                            crate::store::ContentIndex::new(crate::store::BorrowedStore(&store))
                                .block(
                                    &pack,
                                    &crate::store::BlockEntry::new("revoked", T0 as u64),
                                    T0 as u64,
                                )
                                .await
                                .unwrap();
                        })
                    }),
                });
                seams
            });
            in_view(&fx, writer, |reader| {
                let mut session = ReaderSession::default();
                let gets = get_count(&fx);
                assert!(
                    block_on(reader.walk_history_in(
                        &mut session,
                        HEAD,
                        None,
                        2,
                        HistoryOptions::default()
                    ))
                    .unwrap()
                    .is_none()
                );
                assert_eq!(
                    get_count(&fx) - gets,
                    4,
                    "head retained before parent revocation"
                );
                assert_eq!(session.used().output_bytes, 0);
                assert_eq!(
                    session.used().decoded_bytes,
                    (serialize(&head).unwrap().len() + serialize(&parent).unwrap().len()) as u64
                );
            });
        }
    }
}

#[test]
fn path_witness_rechecks_all_sources_and_reserves_all_output() {
    for denial in [false, true] {
        for writer in [false, true] {
            let mut fx = fixture();
            let d = data();
            let pack = fx.push("room", &d.refs(), d.head(), None);
            fx.pipe.cfg.takedown_denial = denial;
            let options = PathOptions {
                include_witness: true,
                ..PathOptions::default()
            };
            in_view(&fx, writer, |reader| {
                let leaf_bytes = serialize(&d.small).unwrap().len() as u64;
                let mut session =
                    ReaderSession::new(ReadLimits::new(8500, 256 << 20, u64::MAX, leaf_bytes));
                assert_eq!(
                    block_on(reader.read_commit_path_in(
                        &mut session,
                        HEAD,
                        d.head(),
                        &[b"small.txt".to_vec()],
                        None,
                        options
                    ))
                    .unwrap_err()
                    .code(),
                    Code::ResourceExhausted
                );
                assert_eq!(session.used().output_bytes, 0);
                let found = block_on(reader.read_commit_path_in(
                    &mut ReaderSession::default(),
                    HEAD,
                    d.head(),
                    &[],
                    None,
                    options,
                ))
                .unwrap()
                .unwrap();
                let witness = found.witness.unwrap();
                assert_eq!(witness.commit.id, d.head());
                assert!(witness.trees.is_empty());
                assert_eq!(found.mode, EntryMode::Tree);
            });
            let store = fx.pipe.meta.clone();
            let checks = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            fx.pipe = fx.pipe.with_http_seams(|mut seams| {
                seams.takedown = Arc::new(ChangeAfterBody {
                    target: id(&d.small),
                    change: Box::new(move || {
                        let (store, checks) = (store.clone(), checks.clone());
                        Box::pin(async move {
                            // Revoke at the witness boundary after the leaf's
                            // own live checks have completed.
                            if checks.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 1 {
                                crate::store::ContentIndex::new(crate::store::BorrowedStore(
                                    &store,
                                ))
                                .block(
                                    &pack,
                                    &crate::store::BlockEntry::new("revoked", T0 as u64),
                                    T0 as u64,
                                )
                                .await
                                .unwrap();
                            }
                        })
                    }),
                });
                seams
            });
            in_view(&fx, writer, |reader| {
                let mut session = ReaderSession::default();
                assert!(
                    block_on(reader.read_commit_path_in(
                        &mut session,
                        HEAD,
                        d.head(),
                        &[b"small.txt".to_vec()],
                        None,
                        options
                    ))
                    .unwrap()
                    .is_none()
                );
                assert_eq!(session.used().output_bytes, 0);
            });
        }
    }
}

#[test]
fn tags_and_output_are_independently_bounded() {
    for denial in [false, true] {
        let mut fx = fixture();
        let root = tree(&[]);
        let head = commit(&root, &[], "tag target");
        let signer = KeyPair::from_seed([9; 32]);
        let mut objects = vec![root.clone(), head.clone()];
        let mut target = id(&head);
        for n in 0..3 {
            let mut tag = Tag {
                target,
                target_type: if n == 0 {
                    ObjectType::Commit
                } else {
                    ObjectType::Tag
                },
                name: format!("tag{n}").into_bytes(),
                tagger: Identity::ed25519(signer.public.0),
                signer: signer.public.0,
                message: vec![],
                timestamp: 43,
                signature: [0; 64],
            };
            tag.signature = mkit_core::sign::sign_tag(&tag, &signer).unwrap().0;
            let tag = Object::Tag(tag);
            target = id(&tag);
            objects.push(tag);
        }
        fx.push("room", &objects.iter().collect::<Vec<_>>(), target, None);
        fx.pipe.cfg.takedown_denial = denial;
        for writer in [false, true] {
            in_view(&fx, writer, |reader| {
                let options = HistoryOptions {
                    max_tags: 3,
                    ..HistoryOptions::default()
                };
                assert_eq!(
                    block_on(reader.locate_commit_in(
                        &mut ReaderSession::default(),
                        HEAD,
                        id(&head),
                        options
                    ))
                    .unwrap()
                    .unwrap()
                    .id,
                    id(&head)
                );
                let options = HistoryOptions {
                    max_tags: 2,
                    ..options
                };
                let result = block_on(reader.locate_commit_in(
                    &mut ReaderSession::default(),
                    HEAD,
                    id(&head),
                    options,
                ));
                if writer {
                    assert_eq!(result.unwrap_err().code(), Code::ResourceExhausted);
                } else {
                    assert!(result.unwrap().is_none());
                }
                let mut session = ReaderSession::new(ReadLimits::new(8500, 256 << 20, u64::MAX, 1));
                assert_eq!(
                    block_on(reader.locate_commit_in(
                        &mut session,
                        HEAD,
                        id(&head),
                        HistoryOptions::default()
                    ))
                    .unwrap_err()
                    .code(),
                    Code::ResourceExhausted
                );
                assert_eq!(session.used().output_bytes, 0);
            });
        }
    }
}

#[test]
fn one_hundred_directory_edges_complete_with_independent_depth_cap() {
    for denial in [false, true] {
        let (fx, commits, leaf, path) = history(1, 100, 1, denial);
        for writer in [false, true] {
            in_view(&fx, writer, |reader| {
                let mut session = ReaderSession::default();
                let found = block_on(reader.read_commit_path_in(
                    &mut session,
                    HEAD,
                    id(&commits[0]),
                    &path,
                    Some(leaf),
                    PathOptions::default(),
                ))
                .unwrap()
                .unwrap();
                assert_eq!(found.id, leaf);
                assert!(session.used().storage_calls < 8500);
                let result = block_on(reader.read_commit_path_in(
                    &mut ReaderSession::default(),
                    HEAD,
                    id(&commits[0]),
                    &path,
                    Some(leaf),
                    PathOptions {
                        max_depth: 100,
                        ..PathOptions::default()
                    },
                ));
                if writer {
                    assert_eq!(result.unwrap_err().code(), Code::ResourceExhausted);
                } else {
                    assert!(result.unwrap().is_none());
                }
            });
        }
    }
}

#[test]
fn grant_epoch_revoked_after_body_is_rechecked_for_directed_path() {
    use mkit_attest::grant::{AcceptedSchemes, Capabilities, OwnerScheme, RepoScope};
    for denial in [false, true] {
        let mut fx = fixture_tweaked(Hooks::new(), http_cfg(), |cfg| {
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
        fx.pipe.cfg.takedown_denial = denial;
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
        let store = fx.pipe.meta.clone();
        let coordinator = fx.pipe.shards.coordinator(&fx.repo_id("room").namespace);
        fx.pipe = fx.pipe.with_http_seams(|mut seams| {
            seams.takedown = Arc::new(ChangeAfterBody {
                target: id(&d.small),
                change: Box::new(move || {
                    let (store, coordinator) = (store.clone(), coordinator.clone());
                    Box::pin(async move {
                        store
                            .inner
                            .apply(
                                &coordinator,
                                Batch::new().put(keys::grant_epoch(), codec::encode_u64(1)),
                            )
                            .await
                            .unwrap();
                    })
                }),
            });
            seams
        });
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
        let reader = block_on(
            fx.pipe
                .object_reader(fx.repo_id("room"), ReaderView::Owner(&meta)),
        )
        .unwrap();
        let mut session = ReaderSession::default();
        assert!(
            block_on(reader.read_commit_path_in(
                &mut session,
                HEAD,
                d.head(),
                &[b"small.txt".to_vec()],
                None,
                PathOptions::default()
            ))
            .is_err()
        );
        assert_eq!(session.used().output_bytes, 0);
        assert!(session.used().decoded_bytes > 0);
    }
}

#[test]
fn helper_decode_allowance_is_shared_across_all_skipped_ancestors() {
    for denial in [false, true] {
        let (mut fx, commits, _, _) = history(3, 0, 1, denial);
        let allowance = serialize(commits.last().unwrap()).unwrap().len() as u64;
        fx.pipe
            .cfg
            .http_objects
            .as_mut()
            .unwrap()
            .http_decode_budget = allowance;
        for writer in [false, true] {
            in_view(&fx, writer, |reader| {
                let mut session = ReaderSession::default();
                let result = block_on(reader.locate_commit_in(
                    &mut session,
                    HEAD,
                    id(&commits[0]),
                    HistoryOptions::default(),
                ));
                if writer {
                    assert_eq!(result.unwrap_err().code(), Code::ResourceExhausted);
                } else {
                    assert!(result.unwrap().is_none());
                }
                assert_eq!(session.used().decoded_bytes, allowance);
                assert_eq!(session.used().output_bytes, 0);
                assert!(session.used().storage_calls > 0);
            });
        }
    }
}

#[test]
fn directed_chunked_leaf_preserves_live_manifest_provenance() {
    for denial in [false, true] {
        let mut fx = fixture();
        let d = data();
        fx.push("room", &d.refs(), d.head(), None);
        fx.pipe.cfg.takedown_denial = denial;
        for writer in [false, true] {
            in_view(&fx, writer, |reader| {
                let mut session = ReaderSession::default();
                let found = block_on(reader.read_commit_path_in(
                    &mut session,
                    HEAD,
                    d.head(),
                    &[b"chunked.bin".to_vec()],
                    None,
                    PathOptions::default(),
                ))
                .unwrap()
                .unwrap();
                assert_eq!(found.canonical, serialize(&d.manifest).unwrap());
                assert!(session.proofs.contains(&id(&d.chunks[0])));
                let gets = get_count(&fx);
                let chunk = block_on(reader.read_canonical_in(&mut session, &[id(&d.chunks[0])]))
                    .unwrap()[0]
                    .take()
                    .unwrap();
                assert_eq!(chunk, serialize(&d.chunks[0]).unwrap());
                assert_eq!(
                    get_count(&fx) - gets,
                    2,
                    "no snapshot traversal to acquire a chunk"
                );
                block_id(&fx, id(&d.manifest));
                assert_eq!(
                    block_on(reader.read_canonical_in(&mut session, &[id(&d.chunks[0])])).unwrap(),
                    [None]
                );
            });
            // Each view starts with clear storage, rather than reusing denial
            // permission or graph evidence from the other view.
            block_on(
                crate::store::ContentIndex::new(crate::store::BorrowedStore(&fx.pipe.meta))
                    .unblock(&id(&d.manifest), T0 as u64),
            )
            .unwrap();
        }
    }
}

#[test]
fn selected_ref_evidence_does_not_narrow_later_general_id_reads() {
    for denial in [false, true] {
        let mut fx = fixture();
        let a = blob(b"main file");
        let ta = tree(&[("a", EntryMode::Blob, &a)]);
        let ca = commit(&ta, &[], "main");
        fx.push("room", &[&a, &ta, &ca], id(&ca), None);
        let b = blob(b"other branch");
        let tb = tree(&[("b", EntryMode::Blob, &b)]);
        let cb = commit(&tb, &[], "other");
        assert_eq!(
            fx.push_ref(
                "room",
                &[&b, &tb, &cb],
                (TAG_REF, TAG_PACKMAP),
                id(&cb),
                (Missing, Missing)
            )
            .0,
            AdvanceOutcome::Committed
        );
        fx.pipe.cfg.takedown_denial = denial;
        for writer in [false, true] {
            in_view(&fx, writer, |reader| {
                let mut session = ReaderSession::default();
                assert!(
                    block_on(reader.locate_commit_in(
                        &mut session,
                        HEAD,
                        id(&ca),
                        HistoryOptions::default()
                    ))
                    .unwrap()
                    .is_some()
                );
                let bytes = block_on(reader.read_canonical_in(&mut session, &[id(&b)])).unwrap()[0]
                    .take()
                    .unwrap();
                assert_eq!(bytes, serialize(&b).unwrap());
                // The history lookup still uses only its explicit selected ref,
                // even after a general read has proved another branch's graph.
                assert!(
                    block_on(reader.locate_commit_in(
                        &mut session,
                        HEAD,
                        id(&cb),
                        HistoryOptions::default()
                    ))
                    .unwrap()
                    .is_none()
                );
            });
        }
    }
}
