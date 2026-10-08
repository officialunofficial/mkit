//! All-parents timestamp-discovery continuations: an embedder drives page 1
//! through per-commit canonical reads on a selected-ref session, issuance
//! mints a sealed reducer snapshot with memo-only provenance, and fresh
//! readers redeem later pages without re-walking page 1.
use super::*;
use crate::history_token::ClaimState;
use crate::pipeline::{
    ContinuedHistoryOptions, ContinuedHistoryOrder, ContinuedHistoryPage, HistoryContinuationState,
    read_proofs::Checkpoint,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use mkit_core::history_order::{
    HistoryOrderError, ParentEdge, PendingCandidate, TimestampDiscovery, WalkStep,
};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};

fn ts_options() -> ContinuedHistoryOptions {
    ContinuedHistoryOptions {
        order: ContinuedHistoryOrder::TimestampDiscovery,
    }
}

fn object_timestamp(object: &Object) -> u64 {
    match object {
        Object::Commit(c) => c.timestamp,
        Object::Remix(r) => r.timestamp,
        _ => panic!("history lineage object"),
    }
}

fn object_parents(object: &Object) -> Vec<Hash> {
    match object {
        Object::Commit(c) => c.parents.clone(),
        Object::Remix(r) => r.parents.clone(),
        _ => panic!("history lineage object"),
    }
}

/// Commit objects by id plus the selected tip: 52 commits either way. With
/// `merge`, 39 mainline commits and every third one merges a side commit
/// parented two mainline commits back (13 side commits); side timestamps mix
/// keys equal to a mainline neighbour's with keys newer than the merge that
/// pulls them in.
fn commits_graph(merge: bool) -> (Fx, BTreeMap<Hash, Object>, Hash, Hash) {
    let fx = fixture_tweaked(Hooks::new(), http_cfg(), |cfg| {
        cfg.sharding = Sharding::D34;
        cfg.takedown_denial = false;
    });
    fx.pipe
        .meta
        .count_partition_scans
        .store(true, Ordering::SeqCst);
    let mut by_id: BTreeMap<Hash, Object> = BTreeMap::new();
    let mut objects: Vec<Object> = Vec::new();
    let mut mainline: Vec<Hash> = Vec::new();
    // 52 commit/remix objects in total: 39 mainline + 13 side with merges.
    let mainline_commits: u64 = if merge { 39 } else { 52 };
    for n in 0..mainline_commits {
        let file = blob(format!("main {n}").as_bytes());
        let root = tree(&[("f", EntryMode::Blob, &file)]);
        objects.extend([file, root.clone()]);
        by_id.insert(id(&root), root.clone());
        let mut parents: Vec<Hash> = mainline.last().copied().into_iter().collect();
        if merge && n >= 2 && n % 3 == 2 {
            let side_file = blob(format!("side {n}").as_bytes());
            let side_root = tree(&[("s", EntryMode::Blob, &side_file)]);
            let side_ts = match n % 9 {
                2 => 100 + n * 10 + 5,
                5 => 100 + (n - 1) * 10,
                _ => 100 + n * 10 - 7,
            };
            let side = commit_at(
                &side_root,
                &[&by_id[&mainline[usize::try_from(n).unwrap() - 2]]],
                &format!("side {n}"),
                side_ts,
            );
            parents.push(id(&side));
            objects.extend([side_file, side_root, side.clone()]);
            by_id.insert(id(&side), side);
        }
        let parent_refs: Vec<&Object> = parents.iter().map(|p| &by_id[p]).collect();
        let head = commit_at(&root, &parent_refs, &format!("main {n}"), 100 + n * 10);
        mainline.push(id(&head));
        objects.push(head.clone());
        by_id.insert(id(&head), head);
    }
    let tip = *mainline.last().unwrap();
    let all: Vec<&Object> = objects.iter().collect();
    let pack = fx.push("room", &all, tip, None);
    drain(&fx);
    (fx, by_id, tip, pack)
}

/// `roots` parentless commits below one octopus commit below the tip.
fn octopus_graph(roots: usize) -> (Fx, BTreeMap<Hash, Object>, Hash) {
    let fx = fixture_tweaked(Hooks::new(), http_cfg(), |cfg| {
        cfg.sharding = Sharding::D34;
        cfg.takedown_denial = false;
    });
    fx.pipe
        .meta
        .count_partition_scans
        .store(true, Ordering::SeqCst);
    let mut by_id: BTreeMap<Hash, Object> = BTreeMap::new();
    let mut objects: Vec<Object> = Vec::new();
    let mut root_ids = Vec::new();
    for n in 0..roots {
        let file = blob(format!("root {n}").as_bytes());
        let root = tree(&[("f", EntryMode::Blob, &file)]);
        let head = commit_at(&root, &[], &format!("root {n}"), n as u64);
        objects.extend([file, root, head.clone()]);
        by_id.insert(id(&head), head.clone());
        root_ids.push(id(&head));
    }
    let file = blob(b"octopus");
    let root = tree(&[("f", EntryMode::Blob, &file)]);
    let parent_refs: Vec<&Object> = root_ids.iter().map(|p| &by_id[p]).collect();
    let octopus = commit_at(&root, &parent_refs, "octopus", roots as u64);
    objects.extend([file, root, octopus.clone()]);
    by_id.insert(id(&octopus), octopus.clone());
    let file = blob(b"tip");
    let root = tree(&[("f", EntryMode::Blob, &file)]);
    let tip = commit_at(&root, &[&octopus], "tip", roots as u64 + 1);
    let tip_id = id(&tip);
    objects.extend([file, root, tip.clone()]);
    by_id.insert(tip_id, tip);
    let all: Vec<&Object> = objects.iter().collect();
    fx.push("room", &all, tip_id, None);
    drain(&fx);
    (fx, by_id, tip_id)
}

/// `drain`, but for a non-HEAD ref's shard: ref updates on `reference` queue
/// their own membership work there.
fn drain_ref<H: HookSet>(fx: &Fx<H>, reference: &str) {
    let repo = fx.repo_id("room");
    let source = fx.pipe.shards.ref_shard(&repo, reference);
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

/// A 12-commit mainline with one merge, ref-anchored by an annotated tag:
/// the tag ref's target — and so the capture checkpoint's tip — is the
/// unpeeled tag id. Returns the tag id and the peeled commit.
fn tagged_graph() -> (Fx, BTreeMap<Hash, Object>, Hash, Hash) {
    let fx = fixture_tweaked(Hooks::new(), http_cfg(), |cfg| {
        cfg.sharding = Sharding::D34;
        cfg.takedown_denial = false;
    });
    fx.pipe
        .meta
        .count_partition_scans
        .store(true, Ordering::SeqCst);
    let mut by_id: BTreeMap<Hash, Object> = BTreeMap::new();
    let mut objects: Vec<Object> = Vec::new();
    let mut mainline: Vec<Hash> = Vec::new();
    for n in 0..12u64 {
        let file = blob(format!("main {n}").as_bytes());
        let root = tree(&[("f", EntryMode::Blob, &file)]);
        objects.extend([file, root.clone()]);
        by_id.insert(id(&root), root.clone());
        let mut parents: Vec<Hash> = mainline.last().copied().into_iter().collect();
        if n == 5 {
            let side_file = blob(b"side".as_slice());
            let side_root = tree(&[("s", EntryMode::Blob, &side_file)]);
            let side = commit_at(
                &side_root,
                &[&by_id[&mainline[3]]],
                "side",
                100 + n * 10 + 5,
            );
            parents.push(id(&side));
            objects.extend([side_file, side_root, side.clone()]);
            by_id.insert(id(&side), side);
        }
        let parent_refs: Vec<&Object> = parents.iter().map(|p| &by_id[p]).collect();
        let head = commit_at(&root, &parent_refs, &format!("main {n}"), 100 + n * 10);
        mainline.push(id(&head));
        objects.push(head.clone());
        by_id.insert(id(&head), head);
    }
    let tip = *mainline.last().unwrap();
    let all: Vec<&Object> = objects.iter().collect();
    fx.push("room", &all, tip, None);
    drain(&fx);
    let signer = KeyPair::from_seed([9; 32]);
    let mut tag = Tag {
        target: tip,
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
    drain_ref(&fx, TAG_REF);
    (fx, by_id, id(&tag), tip)
}

/// The single-run reducer over the fixture graph: the served order both the
/// embedder's page 1 and every redeemed page must concatenate to.
fn reference_order(by_id: &BTreeMap<Hash, Object>, tip: Hash) -> Vec<Hash> {
    let mut walk = TimestampDiscovery::new();
    walk.push(PendingCandidate {
        id: tip,
        timestamp: None,
    })
    .unwrap();
    let mut order = Vec::new();
    loop {
        match walk.step().unwrap() {
            WalkStep::Done => break,
            WalkStep::NeedTimestamp(id) => {
                walk.provide_timestamp(id, object_timestamp(&by_id[&id]))
                    .unwrap();
            }
            WalkStep::Emit(id) => {
                order.push(id);
                let edges: Vec<ParentEdge> = object_parents(&by_id[&id])
                    .iter()
                    .map(|p| ParentEdge {
                        id: *p,
                        timestamp: None,
                        enqueue: true,
                    })
                    .collect();
                walk.emit(&edges).unwrap();
            }
            _ => panic!("canonical walk step"),
        }
    }
    order
}

/// Replay one page's server-side drive of `walk`: the distinct object ids the
/// page loads (emitted plus hydrated-for-keys).
fn page_loads(
    walk: &TimestampDiscovery,
    by_id: &BTreeMap<Hash, Object>,
    limit: usize,
) -> BTreeSet<Hash> {
    let mut walk = walk.clone();
    let mut loaded = BTreeSet::new();
    let mut emitted = 0;
    loop {
        if emitted >= limit {
            break;
        }
        // Mirror resume_timestamp: a key already known on a pending slot is
        // carried onto a re-enqueued duplicate without another load.
        let known: BTreeMap<Hash, u64> = walk
            .pending()
            .iter()
            .filter_map(|candidate| candidate.timestamp.map(|t| (candidate.id, t)))
            .collect();
        match walk.step().unwrap() {
            WalkStep::Done => break,
            WalkStep::NeedTimestamp(_) => {
                for candidate in walk.pending().to_vec() {
                    if candidate.timestamp.is_none() {
                        loaded.insert(candidate.id);
                        walk.provide_timestamp(
                            candidate.id,
                            object_timestamp(&by_id[&candidate.id]),
                        )
                        .unwrap();
                    }
                }
            }
            WalkStep::Emit(id) => {
                loaded.insert(id);
                let cached = loaded.clone();
                let edges: Vec<ParentEdge> = object_parents(&by_id[&id])
                    .iter()
                    .map(|p| ParentEdge {
                        id: *p,
                        timestamp: cached
                            .contains(p)
                            .then(|| object_timestamp(&by_id[p]))
                            .or_else(|| known.get(p).copied()),
                        enqueue: true,
                    })
                    .collect();
                walk.emit(&edges).unwrap();
                emitted += 1;
            }
            _ => panic!("canonical walk step"),
        }
    }
    loaded
}

/// The embedder's page-1 loop on one selected reader/session: capture, seed,
/// and serve `size` emissions by per-commit canonical reads. With `hydrate`,
/// every still-unknown pending key is read and provided before issuance
/// (the KNOWN variant); otherwise issuance sees untouched keys (UNKNOWN).
/// Returns the page-1 commits and the issued continuation, if any.
fn embedder_page_one(
    fx: &Fx,
    writer: bool,
    size: usize,
    hydrate: bool,
) -> (Vec<(Hash, Vec<u8>)>, Option<HistoryContinuation>) {
    let mut commits = Vec::new();
    let mut issued = None;
    in_view(fx, writer, |reader| {
        let reader = reader.with_selected_ref(HEAD).unwrap();
        let mut session = ReaderSession::default();
        let checkpoint = block_on(reader.selected_capture_in(&mut session))
            .unwrap()
            .unwrap();
        let mut walk = TimestampDiscovery::new();
        walk.push(PendingCandidate {
            id: checkpoint.tip(),
            timestamp: None,
        })
        .unwrap();
        while commits.len() < size {
            match walk.step().unwrap() {
                WalkStep::Done => break,
                WalkStep::NeedTimestamp(need) => {
                    let bytes = block_on(reader.read_canonical_in(&mut session, &[need]))
                        .unwrap()
                        .pop()
                        .flatten()
                        .unwrap();
                    let object = mkit_core::serialize::deserialize(&bytes).unwrap();
                    walk.provide_timestamp(need, object_timestamp(&object))
                        .unwrap();
                }
                WalkStep::Emit(id) => {
                    let bytes = block_on(reader.read_canonical_in(&mut session, &[id]))
                        .unwrap()
                        .pop()
                        .flatten()
                        .unwrap_or_else(|| panic!("emit {id:?} unreadable (writer={writer})"));
                    let object = mkit_core::serialize::deserialize(&bytes).unwrap();
                    let edges: Vec<ParentEdge> = object_parents(&object)
                        .iter()
                        .map(|p| ParentEdge {
                            id: *p,
                            timestamp: None,
                            enqueue: true,
                        })
                        .collect();
                    walk.emit(&edges).unwrap();
                    commits.push((id, bytes));
                }
                _ => panic!("canonical walk step"),
            }
        }
        if hydrate {
            loop {
                let unknown: Vec<Hash> = walk
                    .pending()
                    .iter()
                    .filter(|c| c.timestamp.is_none())
                    .map(|c| c.id)
                    .collect();
                if unknown.is_empty() {
                    break;
                }
                for id in unknown {
                    let bytes = block_on(reader.read_canonical_in(&mut session, &[id]))
                        .unwrap()
                        .pop()
                        .flatten()
                        .unwrap();
                    let object = mkit_core::serialize::deserialize(&bytes).unwrap();
                    walk.provide_timestamp(id, object_timestamp(&object))
                        .unwrap();
                }
            }
        }
        issued = block_on(reader.issue_history_continuation_in(
            &mut session,
            &HistoryContinuationState { checkpoint, walk },
        ))
        .unwrap();
    });
    (commits, issued)
}

/// The sealed reducer snapshot an issued token carries.
fn token_walk<H: HookSet>(fx: &Fx<H>, token: &HistoryContinuation) -> TimestampDiscovery {
    let claims = fx
        .pipe
        .cfg
        .history_tokens
        .as_ref()
        .unwrap()
        .verify(token.token.expose())
        .unwrap();
    match claims.state {
        ClaimState::TimestampDiscovery(walk) => walk,
        ClaimState::FirstParent => panic!("expected a timestamp snapshot"),
    }
}

/// One redeemed timestamp page on a fresh reader/session. With `latency`,
/// runs on a paused Tokio clock under the read probe and returns modeled
/// rounds, KV calls, blob GETs and the op names seen.
fn redeem_page(
    fx: &Fx,
    writer: bool,
    reference: &str,
    token: &HistoryContinuation,
    size: usize,
    latency: Option<u32>,
    by_id: &BTreeMap<Hash, Object>,
) -> (Option<ContinuedHistoryPage>, Option<(f64, u32, usize)>) {
    use crate::store::read_probe::{self, Config};
    let (kv, gets) = (fx.pipe.meta.calls(), get_count(fx));
    let op_start = fx.pipe.meta.ops().len();
    fx.pipe.meta.touched.lock().unwrap().clear();
    let mut page = None;
    in_view(fx, writer, |reader| {
        let mut session = ReaderSession::default();
        let result;
        if let Some(latency) = latency {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .start_paused(true)
                .build()
                .unwrap();
            fx.pipe
                .meta
                .latency_ms
                .store(u64::from(latency), Ordering::SeqCst);
            fx.pipe
                .blobs
                .latency_ms
                .store(u64::from(latency * 2), Ordering::SeqCst);
            let trace = Arc::new(Mutex::new(Vec::new()));
            let start = runtime.block_on(async { tokio::time::Instant::now() });
            result = runtime.block_on(read_probe::run(
                Config {
                    concurrency: crate::store::read_io::PARALLELISM,
                    trace: trace.clone(),
                },
                reader.walk_history_page_with_options_in(
                    &mut session,
                    reference,
                    Some(token.token.expose()),
                    size,
                    ts_options(),
                ),
            ));
            let elapsed = runtime.block_on(async { tokio::time::Instant::now() - start });
            fx.pipe.meta.latency_ms.store(0, Ordering::SeqCst);
            fx.pipe.blobs.latency_ms.store(0, Ordering::SeqCst);
            let kv_calls = fx.pipe.meta.calls() - kv;
            let range_gets = get_count(fx) - gets;
            let physical = kv_calls + 2 * u32::try_from(range_gets).unwrap();
            let traced: u32 = trace
                .lock()
                .unwrap()
                .iter()
                .map(|event| {
                    u32::try_from((event.end - event.start).as_millis() / u128::from(latency))
                        .unwrap()
                })
                .sum();
            let untraced = physical.saturating_sub(traced);
            let wait = elapsed.as_secs_f64() + f64::from(untraced) * f64::from(latency) / 1000.0;
            let rounds = wait * 1000.0 / f64::from(latency);
            let loaded = page_loads(&token_walk(fx, token), by_id, size);
            assert_eq!(
                range_gets,
                loaded.len() * 2,
                "page loads only its emitted and hydrated objects"
            );
            page = Some((result.unwrap(), Some((rounds, kv_calls, range_gets))));
        } else {
            result = block_on(reader.walk_history_page_with_options_in(
                &mut session,
                reference,
                Some(token.token.expose()),
                size,
                ts_options(),
            ));
            page = Some((result.unwrap(), None));
        }
    });
    let ops = fx.pipe.meta.ops()[op_start..].to_vec();
    assert!(
        !ops.contains(&"scan"),
        "a redeemed page never scans one range at a time"
    );
    let touched = fx.pipe.meta.touched.lock().unwrap().clone();
    assert!(
        !touched.iter().any(|p| p.kind() == "ref_index"),
        "a redeemed page never touches the all-ref index (reader_tips)"
    );
    page.unwrap()
}

#[test]
#[allow(clippy::too_many_lines)] // One fixture x variant x view matrix.
fn timestamp_pages_match_reducer_and_stay_bounded() {
    for merge in [false, true] {
        let (mut fx, by_id, tip, _) = commits_graph(merge);
        assert_eq!(
            by_id
                .values()
                .filter(|o| matches!(o, Object::Commit(_) | Object::Remix(_)))
                .count(),
            52,
            "fixture is 52 commits (merge={merge})"
        );
        enable(&mut fx);
        let expected: Vec<(Hash, Vec<u8>)> = reference_order(&by_id, tip)
            .into_iter()
            .map(|id| (id, serialize(&by_id[&id]).unwrap()))
            .collect();
        for hydrate in [false, true] {
            for denial in [false, true] {
                fx.pipe.cfg.takedown_denial = denial;
                for writer in [false, true] {
                    let label = format!(
                        "ts-page merge={merge} hydrate={hydrate} owner={writer} denial={denial}"
                    );
                    let (page_one, issued) = embedder_page_one(&fx, writer, 10, hydrate);
                    let token = issued.expect("an incomplete walk issues");
                    let expiry = token.expires_at_ms;
                    let mut all = page_one;
                    let mut token = token;
                    let mut page_number = 1;
                    loop {
                        page_number += 1;
                        let measure = matches!(page_number, 2 | 3);
                        let (page, measured) = redeem_page(
                            &fx,
                            writer,
                            HEAD,
                            &token,
                            10,
                            measure.then_some(50),
                            &by_id,
                        );
                        let page = page.unwrap();
                        if let Some((rounds, kv, gets)) = measured {
                            println!(
                                "{label} page={page_number}: rounds={rounds:.0} KV={kv} GET={gets}"
                            );
                            assert!(rounds <= 400.0, "{label} page {page_number}: {rounds}");
                        }
                        for commit in &page.commits {
                            all.push((commit.id, commit.canonical.clone()));
                        }
                        match page.next {
                            Some(next) => {
                                assert_eq!(next.expires_at_ms, expiry, "expiry never extends");
                                token = next;
                            }
                            None => break,
                        }
                    }
                    assert_eq!(
                        all, expected,
                        "{label}: concatenated ids and canonical bytes match the reducer order"
                    );
                }
            }
        }
    }
}

/// A ref whose target is an annotated tag: the capture checkpoint's tip is
/// the unpeeled tag, so the embedder's page-1 loop peels to the commit — a
/// `TagTarget` memo edge — before seeding the walk. Issuance's typed witness
/// then roots the pending lineage at the tag, and redeemed pages match a
/// reference walk seeded at the peeled commit.
#[test]
#[allow(clippy::too_many_lines)] // One peel, page-1 and redeem loop per view.
fn tag_anchored_ref_pages_from_the_peeled_commit() {
    for writer in [false, true] {
        let (mut fx, by_id, tag_id, peeled) = tagged_graph();
        enable(&mut fx);
        let expected: Vec<(Hash, Vec<u8>)> = reference_order(&by_id, peeled)
            .into_iter()
            .map(|id| (id, serialize(&by_id[&id]).unwrap()))
            .collect();
        let mut page_one = Vec::new();
        let mut issued = None;
        in_view(&fx, writer, |reader| {
            let reader = reader.with_selected_ref(TAG_REF).unwrap();
            let mut session = ReaderSession::default();
            let checkpoint = block_on(reader.selected_capture_in(&mut session))
                .unwrap()
                .unwrap();
            assert_eq!(
                checkpoint.tip(),
                tag_id,
                "the capture anchors the unpeeled tag"
            );
            // Peel to the commit/remix before seeding, bounded like the
            // server's own tag peel.
            let mut seed = checkpoint.tip();
            for _ in 0..16 {
                let bytes = block_on(reader.read_canonical_in(&mut session, &[seed]))
                    .unwrap()
                    .pop()
                    .flatten()
                    .unwrap();
                let Object::Tag(tag) = mkit_core::serialize::deserialize(&bytes).unwrap() else {
                    break;
                };
                seed = tag.target;
            }
            assert_eq!(seed, peeled);
            let mut walk = TimestampDiscovery::new();
            walk.push(PendingCandidate {
                id: seed,
                timestamp: None,
            })
            .unwrap();
            while page_one.len() < 3 {
                match walk.step().unwrap() {
                    WalkStep::Done => break,
                    WalkStep::NeedTimestamp(need) => {
                        let bytes = block_on(reader.read_canonical_in(&mut session, &[need]))
                            .unwrap()
                            .pop()
                            .flatten()
                            .unwrap();
                        let object = mkit_core::serialize::deserialize(&bytes).unwrap();
                        walk.provide_timestamp(need, object_timestamp(&object))
                            .unwrap();
                    }
                    WalkStep::Emit(id) => {
                        let bytes = block_on(reader.read_canonical_in(&mut session, &[id]))
                            .unwrap()
                            .pop()
                            .flatten()
                            .unwrap();
                        let object = mkit_core::serialize::deserialize(&bytes).unwrap();
                        let edges: Vec<ParentEdge> = object_parents(&object)
                            .iter()
                            .map(|p| ParentEdge {
                                id: *p,
                                timestamp: None,
                                enqueue: true,
                            })
                            .collect();
                        walk.emit(&edges).unwrap();
                        page_one.push((id, bytes));
                    }
                    _ => panic!("canonical walk step"),
                }
            }
            issued = block_on(reader.issue_history_continuation_in(
                &mut session,
                &HistoryContinuationState { checkpoint, walk },
            ))
            .unwrap();
        });
        let mut token = issued.expect("an incomplete walk on a tag ref issues");
        let mut all = page_one;
        loop {
            let (page, _) = redeem_page(&fx, writer, TAG_REF, &token, 10, None, &by_id);
            let page = page.unwrap();
            for commit in &page.commits {
                all.push((commit.id, commit.canonical.clone()));
            }
            match page.next {
                Some(next) => token = next,
                None => break,
            }
        }
        assert_eq!(
            all, expected,
            "owner={writer}: concatenated ids and canonical bytes match the peeled walk"
        );
    }
}

/// Drive page-1 size `size` on a fresh selected session (appending `extra`
/// fabricated edges to the final emission's parent list), apply `edit` —
/// which may read, mutate or replace the walk and the checkpoint — and issue.
fn issue_after(
    fx: &Fx,
    writer: bool,
    size: usize,
    extra: &[Hash],
    edit: impl FnOnce(
        &ObjectReader<'_, SpyBlobs, Arc<Spy>, Hooks>,
        &mut ReaderSession,
        &mut TimestampDiscovery,
        &mut crate::pipeline::CaptureCheckpoint,
    ),
) -> Result<Option<HistoryContinuation>, crate::ServerError> {
    let mut result = Err(ServerError::unavailable("unset"));
    in_view(fx, writer, |reader| {
        let reader = reader.with_selected_ref(HEAD).unwrap();
        let mut session = ReaderSession::default();
        let mut checkpoint = block_on(reader.selected_capture_in(&mut session))
            .unwrap()
            .unwrap();
        let mut walk = TimestampDiscovery::new();
        walk.push(PendingCandidate {
            id: checkpoint.tip(),
            timestamp: None,
        })
        .unwrap();
        let mut emitted = 0;
        while emitted < size {
            match walk.step().unwrap() {
                WalkStep::Done => break,
                WalkStep::NeedTimestamp(need) => {
                    let bytes = block_on(reader.read_canonical_in(&mut session, &[need]))
                        .unwrap()
                        .pop()
                        .flatten()
                        .unwrap();
                    let object = mkit_core::serialize::deserialize(&bytes).unwrap();
                    walk.provide_timestamp(need, object_timestamp(&object))
                        .unwrap();
                }
                WalkStep::Emit(id) => {
                    let bytes = block_on(reader.read_canonical_in(&mut session, &[id]))
                        .unwrap()
                        .pop()
                        .flatten()
                        .unwrap_or_else(|| panic!("emit {id:?} unreadable (writer={writer})"));
                    let object = mkit_core::serialize::deserialize(&bytes).unwrap();
                    let mut edges: Vec<ParentEdge> = object_parents(&object)
                        .iter()
                        .map(|p| ParentEdge {
                            id: *p,
                            timestamp: None,
                            enqueue: true,
                        })
                        .collect();
                    if emitted + 1 == size {
                        edges.extend(extra.iter().map(|e| ParentEdge {
                            id: *e,
                            timestamp: None,
                            enqueue: true,
                        }));
                    }
                    walk.emit(&edges).unwrap();
                    emitted += 1;
                }
                _ => panic!("canonical walk step"),
            }
        }
        edit(&reader, &mut session, &mut walk, &mut checkpoint);
        result = block_on(reader.issue_history_continuation_in(
            &mut session,
            &HistoryContinuationState { checkpoint, walk },
        ));
    });
    result
}

#[test]
fn issuance_makes_no_object_or_storage_proof_calls() {
    for writer in [false, true] {
        let (mut fx, ..) = commits_graph(true);
        enable(&mut fx);
        in_view(&fx, writer, |reader| {
            let reader = reader.with_selected_ref(HEAD).unwrap();
            let mut session = ReaderSession::default();
            let checkpoint = block_on(reader.selected_capture_in(&mut session))
                .unwrap()
                .unwrap();
            let mut walk = TimestampDiscovery::new();
            walk.push(PendingCandidate {
                id: checkpoint.tip(),
                timestamp: None,
            })
            .unwrap();
            // Emit three commits; the pending set then holds real memo rows.
            let mut emitted = 0;
            while emitted < 3 {
                match walk.step().unwrap() {
                    WalkStep::NeedTimestamp(need) => {
                        let bytes = block_on(reader.read_canonical_in(&mut session, &[need]))
                            .unwrap()
                            .pop()
                            .flatten()
                            .unwrap();
                        let object = mkit_core::serialize::deserialize(&bytes).unwrap();
                        walk.provide_timestamp(need, object_timestamp(&object))
                            .unwrap();
                    }
                    WalkStep::Emit(id) => {
                        let bytes = block_on(reader.read_canonical_in(&mut session, &[id]))
                            .unwrap()
                            .pop()
                            .flatten()
                            .unwrap();
                        let object = mkit_core::serialize::deserialize(&bytes).unwrap();
                        let edges: Vec<ParentEdge> = object_parents(&object)
                            .iter()
                            .map(|p| ParentEdge {
                                id: *p,
                                timestamp: None,
                                enqueue: true,
                            })
                            .collect();
                        walk.emit(&edges).unwrap();
                        emitted += 1;
                    }
                    _ => break,
                }
            }
            let (gets, kv, decoded) = (
                get_count(&fx),
                fx.pipe.meta.calls(),
                session.used().decoded_bytes,
            );
            fx.pipe.meta.touched.lock().unwrap().clear();
            let token = block_on(reader.issue_history_continuation_in(
                &mut session,
                &HistoryContinuationState { checkpoint, walk },
            ))
            .unwrap()
            .unwrap();
            assert_eq!(get_count(&fx) - gets, 0, "issuance performs no blob GETs");
            // Anchor + security + credential-scope reads at the opening fence,
            // the write-free guarded apply and the security + anchor +
            // credential reads at the closing fence.
            assert_eq!(
                fx.pipe.meta.calls() - kv,
                7,
                "issuance's only reads are fences"
            );
            let kinds: BTreeSet<&'static str> = fx
                .pipe
                .meta
                .touched
                .lock()
                .unwrap()
                .iter()
                .map(crate::Partition::kind)
                .collect();
            assert!(
                kinds.iter().all(|k| matches!(*k, "ref" | "coordinator")),
                "issuance touches only the ref shard and coordinator: {kinds:?}"
            );
            assert_eq!(
                session.used().decoded_bytes,
                decoded,
                "issuance decodes nothing beyond the minted token"
            );
            assert!(token.expires_at_ms > 0);
        });
    }
}

#[test]
#[allow(clippy::too_many_lines)] // Every refusal variant shares the harness.
fn issuance_refusals() {
    for writer in [false, true] {
        let (mut fx, by_id, tip, _) = commits_graph(false);
        enable(&mut fx);
        // A pending id never read carries no memo row: the emitted tip's edge
        // list gains a fabricated candidate.
        let fake = [9; 32];
        let result = issue_after(&fx, writer, 1, &[fake], |_, _, _, _| {});
        assert!(result.unwrap().is_none(), "unproven pending id refuses");
        // A pending id whose supplied key disagrees with the memo: the real
        // first parent is provided a timestamp that is not its own.
        let parent = object_parents(&by_id[&tip])[0];
        let wrong = object_timestamp(&by_id[&parent]) + 1;
        let result = issue_after(&fx, writer, 1, &[], |reader, session, walk, _| {
            // Decode the parent so the memo carries its true key, then hand
            // the reducer a different one.
            let bytes = block_on(reader.read_canonical_in(session, &[parent]))
                .unwrap()
                .pop()
                .flatten()
                .unwrap();
            let _ = bytes;
            walk.provide_timestamp(parent, wrong).unwrap();
        });
        assert!(
            result.unwrap().is_none(),
            "a mismatched supplied key refuses"
        );
        // A pending id present only as a tree content edge has no history
        // role: the fixture grafts an orphan commit id into the tip's tree.
        let fx2 = fixture_tweaked(Hooks::new(), http_cfg(), |cfg| {
            cfg.sharding = Sharding::D34;
            cfg.takedown_denial = false;
        });
        fx2.pipe
            .meta
            .count_partition_scans
            .store(true, Ordering::SeqCst);
        let (mut fx, tree_with_orphan, orphan, tip_obj, pack2) = {
            let file = blob(b"orphan");
            let orphan_root = tree(&[("f", EntryMode::Blob, &file)]);
            let orphan = commit_at(&orphan_root, &[], "orphan", 9_999);
            // A chain of commits; the tip's tree names the orphan as content.
            let mut objects = vec![file, orphan_root.clone(), orphan.clone()];
            let mut previous = None;
            let mut last_tree = None;
            for n in 0..5u64 {
                let leaf = blob(format!("chain {n}").as_bytes());
                let mut entries = vec![("f", EntryMode::Blob, &leaf)];
                if n == 4 {
                    entries.push(("o", EntryMode::Blob, &orphan));
                }
                let root = tree(&entries);
                let parents: Vec<&Object> = previous.iter().collect();
                let head = commit_at(&root, &parents, &format!("c{n}"), n);
                objects.extend([leaf, root.clone(), head.clone()]);
                last_tree = Some(root);
                previous = Some(head);
            }
            let tip_obj = previous.unwrap();
            let all: Vec<&Object> = objects.iter().collect();
            let pack2 = fx2.push("room", &all, id(&tip_obj), None);
            drain(&fx2);
            (fx2, last_tree.unwrap(), orphan, tip_obj, pack2)
        };
        enable(&mut fx);
        // Pending id that exists only as a tree-edge child row.
        let result = issue_after(&fx, writer, 1, &[id(&orphan)], |reader, session, _, _| {
            // Reading the tip's tree records the orphan as a content-edge
            // child row; it still carries no history role.
            assert!(
                block_on(reader.read_canonical_in(session, &[id(&tree_with_orphan)])).unwrap()[0]
                    .is_some()
            );
        });
        assert!(
            result.unwrap().is_none(),
            "a pending content-edge id refuses"
        );
        // An emitted id that is only a tree content edge refuses even when the
        // row itself decodes: it was never a history link. The fabricated
        // pending edge keeps the walk incomplete so issuance reaches the
        // emitted-id check.
        let result = issue_after(&fx, writer, 0, &[], |reader, session, walk, checkpoint| {
            assert!(
                block_on(reader.read_canonical_in(session, &[checkpoint.tip()])).unwrap()[0]
                    .is_some()
            );
            assert!(
                block_on(reader.read_canonical_in(session, &[id(&tree_with_orphan)])).unwrap()[0]
                    .is_some()
            );
            *walk = TimestampDiscovery::new();
            walk.push(PendingCandidate {
                id: id(&orphan),
                timestamp: None,
            })
            .unwrap();
            assert!(matches!(walk.step().unwrap(), WalkStep::Emit(_)));
            // Two enqueued parents activate dedup so the emitted set records
            // the orphan; a single-parent emit would leave it unrecorded.
            walk.emit(&[
                ParentEdge {
                    id: checkpoint.tip(),
                    timestamp: None,
                    enqueue: true,
                },
                ParentEdge {
                    id: checkpoint.tip(),
                    timestamp: None,
                    enqueue: true,
                },
            ])
            .unwrap();
        });
        assert!(
            result.unwrap().is_none(),
            "an emitted content-edge id refuses"
        );
        // A checkpoint captured by a different session of the same reader is
        // not this session's live capture.
        let result = issue_after(&fx, writer, 1, &[], |reader, _, _, checkpoint| {
            let mut other = ReaderSession::default();
            *checkpoint = block_on(reader.selected_capture_in(&mut other))
                .unwrap()
                .unwrap();
        });
        assert!(result.unwrap().is_none(), "a foreign checkpoint refuses");
        // A ref moved between capture and issuance refuses.
        let result = issue_after(&fx, writer, 1, &[], |_, _, _, _| {
            let leaf = blob(b"issuance ref change");
            let root = tree(&[("f", EntryMode::Blob, &leaf)]);
            let head = commit_at(&root, &[&tip_obj], "moved", 9_000_001);
            fx.push(
                "room",
                &[&leaf, &root, &head],
                id(&head),
                Some((id(&tip_obj), pack2)),
            );
            drain(&fx);
        });
        assert!(result.unwrap().is_none(), "a changed ref refuses");
        // A checkpoint past the memo expiry is stale.
        let result = issue_after(&fx, writer, 1, &[], |_, _, _, _| {
            fx.clock
                .advance(i64::try_from(http_cfg().reachability_lag_ms).unwrap() + 1);
        });
        assert!(result.unwrap().is_none(), "a stale checkpoint refuses");
        // An outstanding selected candidate is invalid input, not absence:
        // hydrate the pending key, step to the selection and stop before
        // `emit` clears it.
        let result = issue_after(&fx, writer, 1, &[], |reader, session, walk, _| {
            let next = walk.pending()[0].id;
            let bytes = block_on(reader.read_canonical_in(session, &[next]))
                .unwrap()
                .pop()
                .flatten()
                .unwrap();
            let object = mkit_core::serialize::deserialize(&bytes).unwrap();
            walk.provide_timestamp(next, object_timestamp(&object))
                .unwrap();
            match walk.step().unwrap() {
                WalkStep::Emit(_) => {}
                _ => panic!("expected a selected candidate"),
            }
            assert!(walk.selected().is_some());
        });
        match result {
            Err(error) => assert_eq!(error.code(), Code::InvalidArgument),
            Ok(_) => panic!("an outstanding selected candidate is invalid"),
        }
        // An unsealed walk — pushed but never emitted — is invalid input.
        let result = issue_after(&fx, writer, 0, &[], |_, _, _, _| {});
        match result {
            Err(error) => assert_eq!(error.code(), Code::InvalidArgument),
            Ok(_) => panic!("an unsealed walk is invalid"),
        }
        // Issuance on an unselected reader is invalid input.
        in_view(&fx, writer, |reader| {
            let mut session = ReaderSession::default();
            let mut walk = TimestampDiscovery::new();
            walk.push(PendingCandidate {
                id: [7; 32],
                timestamp: None,
            })
            .unwrap();
            let checkpoint = CaptureCheckpoint(Arc::new(Checkpoint {
                reference: HEAD.into(),
                tip: [7; 32],
                publication: Publication::default(),
                raw: Vec::new(),
                security: [0; 32],
                expires: u64::MAX,
            }));
            let error = block_on(reader.issue_history_continuation_in(
                &mut session,
                &HistoryContinuationState { checkpoint, walk },
            ))
            .unwrap_err();
            assert_eq!(error.code(), Code::InvalidArgument);
        });
    }
}

/// Redeem `token` on a fresh reader/session; assert uniform absence and that
/// no object body was fetched.
fn reject_ts<H: HookSet>(fx: &Fx<H>, writer: bool, token: &str) {
    in_view(fx, writer, |reader| {
        let before = get_count(fx);
        assert!(
            block_on(reader.walk_history_page_with_options_in(
                &mut ReaderSession::default(),
                HEAD,
                Some(token),
                10,
                ts_options(),
            ))
            .unwrap()
            .is_none()
        );
        assert_eq!(
            before,
            get_count(fx),
            "invalid structural evidence performs no object I/O"
        );
    });
}

#[test]
#[allow(clippy::too_many_lines)] // Every refusal variant shares the harness.
fn timestamp_redemption_refusals_are_uniform_and_free_of_object_io() {
    for denial in [false, true] {
        let (mut fx, by_id, tip, pack) = commits_graph(false);
        fx.pipe.cfg.takedown_denial = denial;
        enable(&mut fx);
        let mut current_head = by_id[&tip].clone();
        let mut current_pack = pack;
        for writer in [false, true] {
            let (_, issued) = embedder_page_one(&fx, writer, 10, false);
            let token = issued.unwrap();
            // Wrong view: an owner-minted token refuses on a public reader and
            // vice versa.
            reject_ts(&fx, !writer, token.token.expose());
            let config = fx.pipe.cfg.history_tokens.as_ref().unwrap();
            for dimension in 0..4 {
                let mut c = config.verify(token.token.expose()).unwrap();
                match dimension {
                    0 => c.repository = "other".into(),
                    1 => c.namespace = "other".into(),
                    2 => c.reference = "refs/heads/other".into(),
                    _ => c.realm = "other-backend".into(),
                }
                reject_ts(&fx, writer, &config.mint(&c).unwrap());
            }
            // A tampered token byte fails the MAC.
            let mut edited = token.token.expose().as_bytes().to_vec();
            edited[10] = if edited[10] == b'A' { b'B' } else { b'A' };
            reject_ts(&fx, writer, core::str::from_utf8(&edited).unwrap());
            // Order mismatch in both directions.
            reject_ts(&fx, writer, first(&fx, writer, 1).token.expose());
            in_view(&fx, writer, |reader| {
                assert!(
                    block_on(reader.walk_history_page_in(
                        &mut ReaderSession::default(),
                        HEAD,
                        Some(token.token.expose()),
                        10,
                    ))
                    .unwrap()
                    .is_none(),
                    "a timestamp token refuses first-parent redemption"
                );
            });
            // A hand-built version-1 JSON token under the old v1 derived-key
            // MAC is not a v2 token and never redeems.
            let zero = vec![0u8; 32];
            let one = vec![1u8; 32];
            let payload = serde_json::json!({
                "version": 1,
                "purpose": "mkit-history-continuation:v1",
                "realm": "test-backend",
                "namespace": config.verify(token.token.expose()).unwrap().namespace,
                "repository": "room",
                "reference": HEAD,
                "writer": writer,
                "credential": zero,
                "anchor": one.clone(),
                "security": one.clone(),
                "issued": 1,
                "expires": u64::MAX,
                "cursor": one.clone(),
                "ancestry": [one],
            });
            let bytes = serde_json::to_vec(&payload).unwrap();
            let key = blake3::derive_key("mkit-history-continuation:v1", &[101; 32]);
            let mac = blake3::keyed_hash(&key, &bytes);
            let v1 = format!(
                "{}.{}",
                URL_SAFE_NO_PAD.encode(&bytes),
                URL_SAFE_NO_PAD.encode(mac.as_bytes())
            );
            reject_ts(&fx, writer, &v1);
            // Replay within the same scope and expiry reruns live checks and
            // returns the same page.
            let mut replayed = None;
            for _ in 0..2 {
                let before = get_count(&fx);
                let mut this = None;
                in_view(&fx, writer, |reader| {
                    this = Some(
                        block_on(reader.walk_history_page_with_options_in(
                            &mut ReaderSession::default(),
                            HEAD,
                            Some(token.token.expose()),
                            10,
                            ts_options(),
                        ))
                        .unwrap()
                        .unwrap(),
                    );
                });
                let this = this.unwrap();
                assert!(get_count(&fx) > before, "replay reruns live checks");
                if let Some(previous) = &replayed {
                    assert_eq!(&this, previous, "replay serves the same page");
                }
                replayed = Some(this);
            }
            // A ref change after issuance invalidates the token.
            let leaf = blob(format!("changed head {writer}").as_bytes());
            let root = tree(&[("f", EntryMode::Blob, &leaf)]);
            let head = commit_at(&root, &[&current_head], "changed", 999_999);
            fx.pipe.cfg.takedown_denial = false; // Same fixture construction as commits_graph.
            current_pack = fx.push(
                "room",
                &[&leaf, &root, &head],
                id(&head),
                Some((id(&current_head), current_pack)),
            );
            fx.pipe.cfg.takedown_denial = denial;
            current_head = head;
            drain(&fx);
            reject_ts(&fx, writer, token.token.expose());
        }
    }
}

#[test]
fn timestamp_seed_window_is_closed() {
    let (mut fx, _by_id, _tip, _) = commits_graph(false);
    enable(&mut fx);
    let (_, issued) = embedder_page_one(&fx, false, 3, false);
    let mut walk = token_walk(&fx, &issued.unwrap());
    // A decoded snapshot is sealed: reseeding after the first emission is
    // refused, never silently accepted.
    assert_eq!(
        walk.push(PendingCandidate {
            id: [9; 32],
            timestamp: None,
        }),
        Err(HistoryOrderError::WalkStarted)
    );
}

#[test]
fn timestamp_frontier_cap_is_typed_in_both_views() {
    // One octopus commit over 257 roots overflows the reducer frontier when
    // the redeemed page emits it.
    let (mut fx, ..) = octopus_graph(257);
    enable(&mut fx);
    for writer in [false, true] {
        let (_, issued) = embedder_page_one(&fx, writer, 1, false);
        let token = issued.unwrap();
        in_view(&fx, writer, |reader| {
            let error = block_on(reader.walk_history_page_with_options_in(
                &mut ReaderSession::default(),
                HEAD,
                Some(token.token.expose()),
                10,
                ts_options(),
            ))
            .unwrap_err();
            assert_eq!(
                error.history_state_limit(),
                Some(crate::HistoryStateLimit::Frontier),
                "owner={writer}"
            );
        });
    }
}

#[test]
fn timestamp_cancel_discards_imported_proofs() {
    for writer in [false, true] {
        let (mut fx, by_id, tip, _) = commits_graph(false);
        enable(&mut fx);
        let expected = reference_order(&by_id, tip);
        let (_, issued) = embedder_page_one(&fx, writer, 3, false);
        let token = issued.unwrap();
        let cursor = expected[3];
        let paused = Arc::new(AtomicBool::new(true));
        let fx = with_seams(fx, |seams| {
            seams.takedown = Arc::new(PauseCursor {
                cursor,
                paused: paused.clone(),
            });
        });
        in_view(&fx, writer, |reader| {
            let mut session = ReaderSession::default();
            {
                let mut future = Box::pin(reader.walk_history_page_with_options_in(
                    &mut session,
                    HEAD,
                    Some(token.token.expose()),
                    10,
                    ts_options(),
                ));
                let waker = std::task::Waker::noop();
                let mut context = std::task::Context::from_waker(waker);
                assert!(std::future::Future::poll(future.as_mut(), &mut context).is_pending());
            }
            assert!(!session.proofs.contains(&cursor));
            let spent = session.used().storage_calls;
            assert!(spent > 0);
            paused.store(false, Ordering::SeqCst);
            assert!(
                block_on(reader.read_canonical_in(&mut session, &[cursor])).unwrap()[0].is_some()
            );
            assert!(session.used().storage_calls > spent);
        });
    }
}
