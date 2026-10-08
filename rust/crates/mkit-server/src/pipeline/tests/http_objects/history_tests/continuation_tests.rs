mod credential_tests;
mod timestamp_tests;
use super::*;
use crate::history_token::HistoryTokenConfig;
use crate::pipeline::HistoryContinuation;
use crate::store::publication::Publication;

fn changing_history(length: usize) -> (Fx, Vec<Object>) {
    if length <= 300 {
        let (fx, commits, _, _) = history(length, 2, 4, false);
        return (fx, commits);
    }
    // Two commits per real upload keep fixture construction within the existing
    // write quota. Reader budgets and every current serving check are unchanged.
    let (fx, _, _, _) = history(0, 2, 4, false);
    let mut commits = Vec::new();
    let mut previous = None;
    for group in (0..length).step_by(2) {
        let mut objects = Vec::new();
        for n in group..(group + 2).min(length) {
            let file = blob(format!("changing snapshot {n}").as_bytes());
            let sub = tree(&[("file", EntryMode::Blob, &file)]);
            let root = tree(&[("sub", EntryMode::Tree, &sub)]);
            let head = commit(
                &root,
                &commits.last().into_iter().collect::<Vec<_>>(),
                &format!("change {n}"),
            );
            objects.extend([file, sub, root, head.clone()]);
            commits.push(head);
        }
        let head = id(commits.last().unwrap());
        let pack = fx.push("room", &objects.iter().collect::<Vec<_>>(), head, previous);
        drain(&fx);
        previous = Some((head, pack));
    }
    (fx, commits)
}

#[test]
fn continuation_selected_ref_overhead_is_bounded_independently_of_cursor_depth() {
    for denial in [false, true] {
        let (mut fx, _, _, _) = history(61, 1, 2, denial);
        enable(&mut fx);
        for writer in [false, true] {
            let mut baseline = 0;
            in_view(&fx, writer, |reader| {
                let kv = fx.pipe.meta.calls();
                block_on(reader.walk_history_in(
                    &mut ReaderSession::default(),
                    HEAD,
                    None,
                    30,
                    HistoryOptions {
                        mode: HistoryMode::FirstParent,
                        ..HistoryOptions::default()
                    },
                ))
                .unwrap()
                .unwrap();
                baseline = fx.pipe.meta.calls() - kv;
            });
            let token = first(&fx, writer, 30);
            in_view(&fx, writer, |reader| {
                let kv = fx.pipe.meta.calls();
                let page = block_on(reader.walk_history_page_in(
                    &mut ReaderSession::default(),
                    HEAD,
                    Some(token.token.expose()),
                    30,
                ))
                .unwrap()
                .unwrap();
                assert_eq!(page.commits.len(), 30);
                let overhead = fx.pipe.meta.calls() - kv - baseline;
                println!(
                    "continuation-validation owner={writer} denial={denial}: added physical calls/rounds={overhead}"
                );
                assert!(overhead <= 8, "{overhead}");
            });
        }
    }
}

#[test]
fn continuation_authorizer_refusal_is_live_and_uniform() {
    for denial in [false, true] {
        let az = Arc::new(Scripted::default());
        let mut fx = fixture_tweaked(scripted(&az), http_cfg(), |cfg| {
            cfg.takedown_denial = denial;
        });
        let root = tree(&[]);
        let base = commit(&root, &[], "base");
        let head = commit(&root, &[&base], "head");
        fx.push("room", &[&root, &base, &head], id(&head), None);
        enable(&mut fx);
        for writer in [false, true] {
            let token = first(&fx, writer, 1);
            // Construct the owner reader while authority is valid, then revoke
            // it before redemption; public readers do not pre-authorize.
            in_view(&fx, writer, |reader| {
                *az.verdict.lock().unwrap() = Some(Code::PermissionDenied);
                assert!(
                    block_on(reader.walk_history_page_in(
                        &mut ReaderSession::default(),
                        HEAD,
                        Some(token.token.expose()),
                        1
                    ))
                    .unwrap()
                    .is_none()
                );
                *az.verdict.lock().unwrap() = None;
            });
        }
    }
}

#[test]
fn continuation_detects_authoritative_ref_changes_after_body_and_before_relay() {
    for denial in [false, true] {
        for writer in [false, true] {
            let (mut fx, commits, _, _) = history(3, 1, 2, denial);
            enable(&mut fx);
            let token = first(&fx, writer, 1);
            let repo = fx.repo_id("room");
            let shard = fx.pipe.shards.ref_shard(&repo, HEAD);
            let storage = fx.pipe.meta.clone();
            let fx = with_seams(fx, |seams| {
                seams.takedown = Arc::new(ChangeAfterBody {
                    target: id(&commits[1]),
                    change: Box::new(move || {
                        let (storage, repo, shard) = (storage.clone(), repo.clone(), shard.clone());
                        Box::pin(async move {
                            let key = keys::publication(&repo.name, HEAD);
                            let raw = storage.inner.get(&shard, &key).await.unwrap();
                            let mut row = Publication::decode(raw.as_ref()).unwrap();
                            row.sequence += 1;
                            storage
                                .inner
                                .apply(&shard, Batch::new().put(key, row.encode().unwrap()))
                                .await
                                .unwrap();
                        })
                    }),
                });
            });
            in_view(&fx, writer, |reader| {
                assert!(
                    block_on(reader.walk_history_page_in(
                        &mut ReaderSession::default(),
                        HEAD,
                        Some(token.token.expose()),
                        1
                    ))
                    .unwrap()
                    .is_none()
                );
            });

            let (mut fx, commits, _, _) = history(3, 1, 2, denial);
            enable(&mut fx);
            let token = first(&fx, writer, 1);
            let file = blob(b"new snapshot");
            let root = tree(&[("file", EntryMode::Blob, &file)]);
            let head = commit(&root, &[commits.last().unwrap()], "append");
            let repo = fx.repo_id("room");
            let shard = fx.pipe.shards.ref_shard(&repo, HEAD);
            let pack = block_on(
                fx.pipe
                    .meta
                    .get(&shard, &keys::ref_key(&repo.name, PACKMAP)),
            )
            .unwrap()
            .unwrap();
            // Advance authoritative state, leaving asynchronous projections undrained.
            fx.pipe.cfg.takedown_denial = false; // Same fixture construction as `history`.
            fx.push(
                "room",
                &[&file, &root, &head],
                id(&head),
                Some((
                    id(commits.last().unwrap()),
                    codec::decode_ref_id(&pack).unwrap(),
                )),
            );
            fx.pipe.cfg.takedown_denial = denial;
            reject(&fx, writer, token.token.expose());
            drain(&fx);
            reject(&fx, writer, token.token.expose());
        }
    }
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
fn first<H: HookSet>(fx: &Fx<H>, writer: bool, limit: usize) -> HistoryContinuation {
    let mut result = None;
    in_view(fx, writer, |reader| {
        result =
            block_on(reader.walk_history_page_in(&mut ReaderSession::default(), HEAD, None, limit))
                .unwrap()
                .unwrap()
                .next;
    });
    result.unwrap()
}
fn reject<H: HookSet>(fx: &Fx<H>, writer: bool, token: &str) {
    in_view(fx, writer, |reader| {
        let before = get_count(fx);
        assert!(
            block_on(reader.walk_history_page_in(
                &mut ReaderSession::default(),
                HEAD,
                Some(token),
                1
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
fn continuation_pages_complete_changing_history_without_cursor_walk() {
    let (mut fx, commits) = changing_history(40);
    enable(&mut fx);
    for denial in [false, true] {
        fx.pipe.cfg.takedown_denial = denial;
        for writer in [false, true] {
            for size in [7, 10] {
                for latency in [30, 130] {
                    measured_pages(&fx, &commits, size, writer, latency);
                }
            }
        }
    }
}

#[test]
#[ignore = "full real-upload fixture runs explicitly in the ignored CI lane"]
fn continuation_pages_complete_long_changing_histories_without_cursor_walk() {
    for length in [201, 302] {
        let (mut fx, commits) = changing_history(length);
        enable(&mut fx);
        for denial in [false, true] {
            fx.pipe.cfg.takedown_denial = denial;
            for writer in [false, true] {
                for size in [30, 100] {
                    for latency in [30, 130] {
                        measured_pages(&fx, &commits, size, writer, latency);
                    }
                }
            }
        }
    }
}

#[allow(clippy::too_many_lines)] // Real pages with virtual RPC latency, canonical and accounting checks.
fn measured_pages(fx: &Fx, commits: &[Object], size: usize, writer: bool, latency: u32) {
    use crate::store::read_probe::{self, Config};
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .start_paused(true)
        .build()
        .unwrap();
    let mut continuation: Option<HistoryContinuation> = None;
    let mut output = Vec::new();
    let mut page_number = 0;
    let mut expiry = None;
    loop {
        page_number += 1;
        let (kv, gets) = (fx.pipe.meta.calls(), get_count(fx));
        in_view(fx, writer, |reader| {
            let trace = Arc::new(Mutex::new(Vec::new()));
            fx.pipe
                .meta
                .latency_ms
                .store(u64::from(latency), Ordering::SeqCst);
            // The Workers adapter issues one GET for a bounded range. The doubled
            // delay (a HEAD then a GET) is a conservative model; set
            // MKIT_BENCH_RANGED_HEAD for a single delay.
            let blob_latency = if std::env::var_os("MKIT_BENCH_RANGED_HEAD").is_some() {
                latency
            } else {
                latency * 2
            };
            fx.pipe
                .blobs
                .latency_ms
                .store(u64::from(blob_latency), Ordering::SeqCst);
            let mut session = ReaderSession::default();
            let start = runtime.block_on(async { tokio::time::Instant::now() });
            let page = runtime
                .block_on(read_probe::run(
                    Config {
                        concurrency: crate::store::read_io::PARALLELISM,
                        trace: trace.clone(),
                    },
                    reader.walk_history_page_in(
                        &mut session,
                        HEAD,
                        continuation.as_ref().map(|c| c.token.expose()),
                        size,
                    ),
                ))
                .unwrap()
                .unwrap();
            let elapsed = runtime.block_on(async { tokio::time::Instant::now() - start });
            fx.pipe.meta.latency_ms.store(0, Ordering::SeqCst);
            fx.pipe.blobs.latency_ms.store(0, Ordering::SeqCst);
            let range_gets = u32::try_from(get_count(fx) - gets).unwrap();
            assert_eq!(
                usize::try_from(range_gets).unwrap(),
                page.commits.len() * 2,
                "only requested commits are loaded; no history/tree walk"
            );
            assert!(session.used().storage_calls <= OBJECT_READER_CALLS);
            let canonical_bytes = page
                .commits
                .iter()
                .map(|c| c.canonical.len() as u64)
                .sum::<u64>();
            let token_bytes = continuation
                .as_ref()
                .map_or(0, |c| c.token.expose().len() as u64);
            assert_eq!(session.used().decoded_bytes, canonical_bytes + token_bytes);
            for returned in &page.commits {
                let expected = &commits[commits.len() - 1 - output.len()];
                assert_eq!(returned.id, id(expected));
                assert_eq!(returned.canonical, serialize(expected).unwrap());
                output.push(returned.id);
            }
            let kv_calls = fx.pipe.meta.calls() - kv;
            let physical = kv_calls + 2 * range_gets;
            // Construction runs before the probe and guarded applies are
            // immediate in this fixture. Both are serial physical calls.
            let traced_rpcs = trace
                .lock()
                .unwrap()
                .iter()
                .map(|event| {
                    u32::try_from((event.end - event.start).as_millis() / u128::from(latency))
                        .unwrap()
                })
                .sum::<u32>();
            let untraced = physical.checked_sub(traced_rpcs).unwrap();
            let wait = elapsed.as_secs_f64() + f64::from(untraced) * f64::from(latency) / 1000.0;
            let rounds = wait * 1000.0 / f64::from(latency);
            println!(
                "continuation length={} size={size} page={page_number} owner={writer} denial={} latency_ms={latency}: units={}, KV={kv_calls}, ranged_GET={range_gets}, physical_calls={physical}, modeled_rounds={rounds:.2}, virtual_wait={wait:.3}s",
                commits.len(),
                fx.pipe.cfg.takedown_denial,
                session.used().storage_calls
            );
            if let Some(next) = &page.next {
                assert_eq!(
                    *expiry.get_or_insert(next.expires_at_ms),
                    next.expires_at_ms
                );
            }
            continuation = page.next;
        });
        if continuation.is_none() {
            break;
        }
    }
    assert_eq!(output, commits.iter().rev().map(id).collect::<Vec<_>>());
    assert_eq!(page_number, commits.len().div_ceil(size));
}

#[test]
fn continuation_replay_serves_same_page_and_reruns_live_checks() {
    for denial in [false, true] {
        for writer in [false, true] {
            for block_source in [false, true] {
                let az = Arc::new(Scripted::default());
                let mut fx = fixture_tweaked(scripted(&az), http_cfg(), |cfg| {
                    cfg.takedown_denial = denial;
                });
                let root = tree(&[]);
                let base = commit(&root, &[], "base");
                let middle = commit(&root, &[&base], "middle");
                let head = commit(&root, &[&middle], "head");
                let pack = fx.push("room", &[&root, &base, &middle, &head], id(&head), None);
                enable(&mut fx);
                let token = first(&fx, writer, 1);
                let copied = token.token.expose().to_owned();
                let guards = Arc::new(AtomicU32::new(0));
                let observed = guards.clone();
                Arc::get_mut(&mut fx.pipe.meta).unwrap().hook =
                    Some(Box::new(move |_, _, batch| {
                        assert!(
                            batch.writes.is_empty(),
                            "redemption allocates no paging rows"
                        );
                        observed.fetch_add(1, Ordering::SeqCst);
                    }));
                let mut expected = None;
                let mut measured = None;
                for supplied in [token.token.expose(), copied.as_str()] {
                    let before = (
                        fx.pipe.meta.calls(),
                        get_count(&fx),
                        az.seen.lock().unwrap().len(),
                    );
                    in_view(&fx, writer, |reader| {
                        let page = block_on(reader.walk_history_page_in(
                            &mut ReaderSession::default(),
                            HEAD,
                            Some(supplied),
                            1,
                        ))
                        .unwrap()
                        .unwrap();
                        assert_eq!(page.commits[0].id, id(&middle));
                        assert_eq!(
                            page.next.as_ref().unwrap().expires_at_ms,
                            token.expires_at_ms
                        );
                        if let Some(previous) = &expected {
                            assert_eq!(&page, previous);
                        }
                        expected = Some(page);
                    });
                    let current = (
                        fx.pipe.meta.calls() - before.0,
                        get_count(&fx) - before.1,
                        az.seen.lock().unwrap().len() - before.2,
                    );
                    assert_eq!(current.1, 2, "replay reloads only its requested commit");
                    assert!(current.2 > 0, "replay reauthorizes");
                    if let Some(previous) = measured {
                        assert_eq!(current, previous, "replay repeats all physical/live checks");
                    }
                    measured = Some(current);
                }
                assert_eq!(guards.load(Ordering::SeqCst), 2);
                if block_source {
                    block_on(
                        crate::store::ContentIndex::new(crate::store::BorrowedStore(
                            &fx.pipe.meta.inner,
                        ))
                        .block(
                            &pack,
                            &crate::store::BlockEntry::new("replay", T0 as u64),
                            T0 as u64,
                        ),
                    )
                    .unwrap();
                }
                in_view(&fx, writer, |reader| {
                    if !block_source {
                        *az.verdict.lock().unwrap() = Some(Code::PermissionDenied);
                    }
                    assert!(
                        block_on(reader.walk_history_page_in(
                            &mut ReaderSession::default(),
                            HEAD,
                            Some(&copied),
                            1,
                        ))
                        .unwrap()
                        .is_none(),
                        "replay does not retain source or authority clearance"
                    );
                });
            }
        }
    }
}

#[test]
fn continuation_scope_mac_and_corrupt_state_fail_uniformly() {
    for denial in [false, true] {
        let (mut fx, _, _, _) = history(4, 1, 2, denial);
        enable(&mut fx);
        for writer in [false, true] {
            let token = first(&fx, writer, 1);
            reject(&fx, !writer, token.token.expose());
            let mut edited = token.token.expose().as_bytes().to_vec();
            edited[10] = if edited[10] == b'A' { b'B' } else { b'A' };
            reject(&fx, writer, core::str::from_utf8(&edited).unwrap());
            for dimension in 0..7 {
                let config = fx.pipe.cfg.history_tokens.as_ref().unwrap();
                let mut c = config.verify(token.token.expose()).unwrap();
                match dimension {
                    0 => c.repository = "other".into(),
                    1 => c.namespace = "other".into(),
                    2 => c.realm = "other-backend".into(),
                    3 => c.credential = [0; 32],
                    // 4 mints under a foreign purpose below; a version-2
                    // payload MAC'd by the wrong domain fails verify.
                    5 => {
                        // Duplicated authenticated node: the witness id repeats.
                        let id = c.witness[0].id;
                        c.witness.push(crate::history_token::WitnessNode {
                            id,
                            predecessor: Some(0),
                        });
                    }
                    6 => {
                        // A second root: only the first witness node may have
                        // no predecessor.
                        c.witness.push(crate::history_token::WitnessNode {
                            id: [9; 32],
                            predecessor: None,
                        });
                    }
                    _ => {}
                }
                let minted = if dimension == 4 {
                    config
                        .mint_purpose_test(&c, crate::url_token::DOMAIN)
                        .unwrap()
                } else {
                    config.mint(&c).unwrap()
                };
                reject(&fx, writer, &minted);
            }
        }
    }
}

#[test]
fn continuation_root_and_authority_boundaries_invalidate_both_views() {
    for denial in [false, true] {
        for writer in [false, true] {
            for change in 0..12 {
                let (mut fx, commits, _, _) = history(3, 1, 2, denial);
                enable(&mut fx);
                let token = first(&fx, writer, 1);
                let repo = fx.repo_id("room");
                let shard = fx.pipe.shards.ref_shard(&repo, HEAD);
                let coordinator = fx.pipe.shards.coordinator(&repo.namespace);
                let key = keys::publication(&repo.name, HEAD);
                let raw = block_on(fx.pipe.meta.get(&shard, &key)).unwrap();
                let mut publication = Publication::decode(raw.as_ref()).unwrap();
                let mut batch = Batch::new();
                match change {
                    0 => {
                        // append, retaining the same value to exercise conservative invalidation
                        publication.sequence += 1;
                        batch = batch.put(key, publication.encode().unwrap());
                    }
                    1 => {
                        // rewind
                        publication.sequence += 1;
                        publication.value.head = Some(id(&commits[0]));
                        batch = batch.put(key, publication.encode().unwrap()).put(
                            keys::ref_key(&repo.name, HEAD),
                            codec::encode_ref_id(&id(&commits[0])),
                        );
                    }
                    2 => {
                        // delete/recreate with identical anchor (ABA)
                        publication.sequence += 2;
                        publication.boundary = publication.sequence - 1;
                        publication.published = publication.sequence;
                        batch = batch.put(key, publication.encode().unwrap());
                    }
                    3 => {
                        // authoritative anchor replacement
                        publication.value.head = Some([253; 32]);
                        batch = batch.put(key, publication.encode().unwrap()).put(
                            keys::ref_key(&repo.name, HEAD),
                            codec::encode_ref_id(&[253; 32]),
                        );
                    }
                    4 => {
                        // late publication delivery/prefix change
                        publication.published = publication.published.saturating_sub(1);
                        batch = batch.put(key, publication.encode().unwrap());
                    }
                    5 => {
                        // incomplete root capture
                        batch = batch.delete(key);
                    }
                    6 => {
                        // membership incarnation change
                        publication.generation += 1;
                        batch = batch.put(key, publication.encode().unwrap());
                    }
                    7 => {
                        // fixed expiry reached between requests
                        fx.clock.set(i64::try_from(token.expires_at_ms).unwrap());
                    }
                    8 => {
                        // rotation immediately retires all existing MACs
                        fx.pipe.cfg.history_tokens = Some(
                            HistoryTokenConfig::new(
                                zeroize::Zeroizing::new([102; 32]),
                                "test-backend".into(),
                                900_000,
                            )
                            .unwrap(),
                        );
                    }
                    9 => {
                        block_on(fx.pipe.meta.apply(
                            &coordinator,
                            Batch::new().put(keys::grant_epoch(), codec::encode_u64(1)),
                        ))
                        .unwrap();
                    }
                    10 => {
                        block_on(fx.pipe.meta.apply(
                            &coordinator,
                            Batch::new().put(
                                keys::repo_visibility(&repo.name),
                                codec::encode_repo_visibility(&codec::RepoVisibilityV1 {
                                    visibility: codec::StoredVisibility::Private,
                                    changed_ms: T0 as u64 + 1,
                                    last_created_ms: 0,
                                    last_statement_id: None,
                                }),
                            ),
                        ))
                        .unwrap();
                    }
                    11 => {
                        block_on(fx.pipe.meta.apply(
                            &coordinator,
                            Batch::new().put(keys::authority_generation(), codec::encode_u64(1)),
                        ))
                        .unwrap();
                    }
                    _ => unreachable!(),
                }
                block_on(fx.pipe.meta.apply(&shard, batch)).unwrap();
                reject(&fx, writer, token.token.expose());
            }
        }
    }
}

#[test]
fn continuation_rechecks_custom_ancestry_stops_and_current_cursor_denial() {
    for denial in [false, true] {
        for writer in [false, true] {
            let (mut fx, commits, _, _) = history(4, 1, 2, denial);
            enable(&mut fx);
            let token = first(&fx, writer, 2);
            let fx = with_seams(fx, |seams| {
                seams.takedown = Arc::new(Takedown {
                    stops: Some(id(&commits[3])),
                    verdict: Mutex::new(|| TakedownVerdict::Clear),
                    seen: Mutex::new(Vec::new()),
                });
            });
            reject(&fx, writer, token.token.expose());
            let (mut fx, commits, _, _) = history(4, 1, 2, denial);
            enable(&mut fx);
            let token = first(&fx, writer, 2);
            let fx = with_seams(fx, |seams| {
                seams.takedown = Arc::new(Takedown {
                    stops: None,
                    verdict: Mutex::new(|| TakedownVerdict::NotFound),
                    seen: Mutex::new(Vec::new()),
                });
            });
            in_view(&fx, writer, |reader| {
                assert!(
                    block_on(reader.walk_history_page_in(
                        &mut ReaderSession::default(),
                        HEAD,
                        Some(token.token.expose()),
                        1
                    ))
                    .unwrap()
                    .is_none()
                );
            });
            assert_eq!(commits.len(), 4);
        }
    }
}

#[test]
fn continuation_closing_reads_precede_live_authorizer_and_source_checks() {
    for denial in [false, true] {
        for writer in [false, true] {
            for block_source in [false, true] {
                let az = Arc::new(Scripted::default());
                let mut fx = fixture_tweaked(scripted(&az), http_cfg(), |cfg| {
                    cfg.takedown_denial = denial;
                });
                let root = tree(&[]);
                let base = commit(&root, &[], "base");
                let middle = commit(&root, &[&base], "middle");
                let head = commit(&root, &[&middle], "head");
                let pack = fx.push("room", &[&root, &base, &middle, &head], id(&head), None);
                enable(&mut fx);
                let token = first(&fx, writer, 1);
                let repo = fx.repo_id("room");
                let publication = keys::publication(&repo.name, HEAD);
                let reads = Arc::new(AtomicU32::new(0));
                let seen = reads.clone();
                let az = az.clone();
                Arc::get_mut(&mut fx.pipe.meta).unwrap().read_many_hook =
                    Some(Box::new(move |store, _, keys| {
                        if keys.contains(&publication) && seen.fetch_add(1, Ordering::SeqCst) == 1 {
                            if block_source {
                                now(crate::store::ContentIndex::new(crate::store::BorrowedStore(
                                    store,
                                ))
                                .block(
                                    &pack,
                                    &crate::store::BlockEntry::new("closed", T0 as u64),
                                    T0 as u64,
                                ))
                                .unwrap();
                            } else {
                                *az.verdict.lock().unwrap() = Some(Code::PermissionDenied);
                            }
                        }
                    }));
                in_view(&fx, writer, |reader| {
                    assert!(
                        block_on(reader.walk_history_page_in(
                            &mut ReaderSession::default(),
                            HEAD,
                            Some(token.token.expose()),
                            1
                        ))
                        .unwrap()
                        .is_none()
                    );
                });
                assert_eq!(reads.load(Ordering::SeqCst), 2);
            }
        }
    }
}

#[test]
fn continuation_expiry_during_redemption_is_uniform() {
    for denial in [false, true] {
        for writer in [false, true] {
            let (mut fx, commits, _, _) = history(3, 1, 2, denial);
            enable(&mut fx);
            let token = first(&fx, writer, 1);
            let clock = fx.clock.clone();
            let expiry = token.expires_at_ms;
            let fx = with_seams(fx, |seams| {
                seams.takedown = Arc::new(ChangeAfterBody {
                    target: id(&commits[1]),
                    change: Box::new(move || {
                        let clock = clock.clone();
                        Box::pin(async move {
                            clock.set(i64::try_from(expiry).unwrap());
                        })
                    }),
                });
            });
            in_view(&fx, writer, |reader| {
                assert!(
                    block_on(reader.walk_history_page_in(
                        &mut ReaderSession::default(),
                        HEAD,
                        Some(token.token.expose()),
                        1,
                    ))
                    .unwrap()
                    .is_none()
                );
            });
        }
    }
}

#[test]
fn continuation_failed_anchor_does_not_leave_same_session_proofs() {
    for denial in [false, true] {
        for writer in [false, true] {
            let (mut fx, commits, _, _) = history(3, 1, 2, denial);
            enable(&mut fx);
            let token = first(&fx, writer, 1);
            let repo = fx.repo_id("room");
            let shard = fx.pipe.shards.ref_shard(&repo, HEAD);
            let store = fx.pipe.meta.clone();
            let old_tip = id(&commits[0]);
            let cursor = id(&commits[1]);
            let fx = with_seams(fx, |seams| {
                seams.takedown = Arc::new(ChangeAfterBody {
                    target: cursor,
                    change: Box::new(move || {
                        let (store, repo, shard) = (store.clone(), repo.clone(), shard.clone());
                        Box::pin(async move {
                            let key = keys::publication(&repo.name, HEAD);
                            let raw = store.inner.get(&shard, &key).await.unwrap();
                            let mut publication = Publication::decode(raw.as_ref()).unwrap();
                            publication.sequence += 1;
                            publication.value.head = Some(old_tip);
                            store
                                .inner
                                .apply(
                                    &shard,
                                    Batch::new().put(key, publication.encode().unwrap()).put(
                                        keys::ref_key(&repo.name, HEAD),
                                        codec::encode_ref_id(&old_tip),
                                    ),
                                )
                                .await
                                .unwrap();
                        })
                    }),
                });
            });
            in_view(&fx, writer, |reader| {
                let mut session = ReaderSession::default();
                assert!(
                    block_on(reader.walk_history_page_in(
                        &mut session,
                        HEAD,
                        Some(token.token.expose()),
                        1
                    ))
                    .unwrap()
                    .is_none()
                );
                assert!(!session.proofs.contains(&cursor));
                assert!(session.used().storage_calls > 0);
                // Drop lagging listing roots as well, so a fresh ordinary read
                // cannot legally rediscover the old cursor through projections.
                let repo = fx.repo_id("room");
                for partition in fx.pipe.shards.ref_index_partitions(&repo) {
                    now(fx.pipe.meta.inner.apply(
                        &partition,
                        Batch::new()
                            .delete(keys::ref_key(&repo.name, HEAD))
                            .delete(keys::ref_index_key(&repo.name, HEAD))
                            .delete(keys::published_ref(&repo.name, HEAD))
                            .delete(keys::published_index(&repo.name, HEAD)),
                    ))
                    .unwrap();
                }
                assert!(
                    block_on(reader.read_canonical_in(&mut session, &[cursor])).unwrap()[0]
                        .is_none()
                );
            });
        }
    }
}

struct PauseCursor {
    cursor: Hash,
    paused: Arc<AtomicBool>,
}
impl TakedownGate for PauseCursor {
    fn check<'a>(
        &'a self,
        _: &'a RepoId,
        id: &'a Hash,
    ) -> crate::BoxFuture<'a, Result<TakedownVerdict, ServerError>> {
        Box::pin(async move {
            if *id == self.cursor && self.paused.load(Ordering::SeqCst) {
                std::future::pending::<()>().await;
            }
            Ok(TakedownVerdict::Clear)
        })
    }
}

#[test]
fn continuation_cancel_discards_imported_proofs() {
    for writer in [false, true] {
        let (mut fx, commits, _, _) = history(3, 1, 2, false);
        enable(&mut fx);
        let token = first(&fx, writer, 1);
        let cursor = id(&commits[1]);
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
                let mut future = Box::pin(reader.walk_history_page_in(
                    &mut session,
                    HEAD,
                    Some(token.token.expose()),
                    1,
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

#[test]
fn continuation_visibility_revision_fences_same_clock_aba() {
    for writer in [false, true] {
        let (mut fx, _, _, _) = history(3, 1, 2, false);
        enable(&mut fx);
        let repo = fx.repo_id("room");
        let coordinator = fx.pipe.shards.coordinator(&repo.namespace);
        set_visibility(&fx, mkit_attest::grant::Visibility::Public);
        let raw = block_on(
            fx.pipe
                .meta
                .get(&coordinator, &keys::repo_visibility(&repo.name)),
        )
        .unwrap();
        let token = first(&fx, writer, 1);
        let config = fx.pipe.cfg.history_tokens.take();
        set_visibility(&fx, mkit_attest::grant::Visibility::Private);
        set_visibility(&fx, mkit_attest::grant::Visibility::Public);
        assert_eq!(
            raw,
            block_on(
                fx.pipe
                    .meta
                    .get(&coordinator, &keys::repo_visibility(&repo.name))
            )
            .unwrap()
        );
        assert_eq!(
            block_on(
                fx.pipe
                    .meta
                    .get(&coordinator, &keys::repo_visibility_revision(&repo.name))
            )
            .unwrap(),
            Some(codec::encode_u64(3))
        );
        fx.pipe.cfg.history_tokens = config;
        reject(&fx, writer, token.token.expose());
    }
}

fn set_visibility<H: HookSet>(fx: &Fx<H>, visibility: mkit_attest::grant::Visibility) {
    let req = signed(
        &fx.owner,
        &fx.identity("room"),
        Procedure::SetRepoVisibility,
        fx.number(),
    );
    block_on(fx.pipe.set_repo_visibility(
        &fx.auth(&req),
        crate::pipeline::VisibilityRequest::Envelope(visibility),
    ))
    .unwrap();
}

#[test]
fn continuation_ref_change_after_acceptance_cut_invalidates_successor() {
    for writer in [false, true] {
        let (mut fx, commits, _, _) = history(4, 1, 2, false);
        enable(&mut fx);
        let token = first(&fx, writer, 1);
        let repo = fx.repo_id("room");
        let shard = fx.pipe.shards.ref_shard(&repo, HEAD);
        let store = fx.pipe.meta.clone();
        let checks = Arc::new(AtomicU32::new(0));
        let count = checks.clone();
        let fx = with_seams(fx, |seams| {
            seams.takedown = Arc::new(ChangeAfterBody {
                target: id(&commits[2]),
                change: Box::new(move || {
                    let (store, repo, shard, count) =
                        (store.clone(), repo.clone(), shard.clone(), count.clone());
                    Box::pin(async move {
                        // Body validation is first; final serving validation is
                        // second, after the write-free guard and closing reads.
                        if count.fetch_add(1, Ordering::SeqCst) == 1 {
                            let key = keys::publication(&repo.name, HEAD);
                            let raw = store.inner.get(&shard, &key).await.unwrap();
                            let mut publication = Publication::decode(raw.as_ref()).unwrap();
                            publication.sequence += 1;
                            store
                                .inner
                                .apply(&shard, Batch::new().put(key, publication.encode().unwrap()))
                                .await
                                .unwrap();
                        }
                    })
                }),
            });
        });
        let mut next = None;
        in_view(&fx, writer, |reader| {
            next = block_on(reader.walk_history_page_in(
                &mut ReaderSession::default(),
                HEAD,
                Some(token.token.expose()),
                1,
            ))
            .unwrap()
            .unwrap()
            .next;
        });
        assert_eq!(checks.load(Ordering::SeqCst), 2);
        reject(&fx, writer, next.unwrap().token.expose());
    }
}

#[test]
fn continuation_visibility_activation_rejects_a_preplanned_unfenced_write() {
    let (mut fx, _, _, _) = history(3, 1, 2, false);
    let repo = fx.repo_id("room");
    let coordinator = fx.pipe.shards.coordinator(&repo.namespace);
    let mut stale = Batch::new().put(
        keys::repo_visibility(&repo.name),
        codec::encode_repo_visibility(&codec::RepoVisibilityV1 {
            visibility: codec::StoredVisibility::Private,
            changed_ms: T0 as u64,
            last_created_ms: T0 as u64,
            last_statement_id: None,
        }),
    );
    block_on(
        fx.pipe
            .plan_listing_visibility(&coordinator, &repo, &mut stale),
    )
    .unwrap();
    enable(&mut fx);
    let token = first(&fx, false, 1);
    assert!(matches!(
        block_on(fx.pipe.meta.apply(&coordinator, stale)).unwrap(),
        BatchOutcome::PreconditionFailed { .. }
    ));
    in_view(&fx, false, |reader| {
        assert!(
            block_on(reader.walk_history_page_in(
                &mut ReaderSession::default(),
                HEAD,
                Some(token.token.expose()),
                1
            ))
            .unwrap()
            .is_some()
        );
    });
}

#[test]
fn continuation_expiry_with_a_settled_metadata_cap_is_uniform() {
    for denial in [false, true] {
        for writer in [false, true] {
            let (mut fx, _, _, _) = history(3, 1, 2, denial);
            enable(&mut fx);
            let token = first(&fx, writer, 1);
            let repo = fx.repo_id("room");
            let visibility = keys::repo_visibility(&repo.name);
            let expiry = token.expires_at_ms;
            let clock = fx.clock.clone();
            let mut session = ReaderSession::default();
            let budget = session.io.calls.clone();
            let reads = Arc::new(AtomicU32::new(0));
            let seen = reads.clone();
            Arc::get_mut(&mut fx.pipe.meta).unwrap().read_many_hook =
                Some(Box::new(move |_, _, keys| {
                    if keys.contains(&visibility)
                        && keys.contains(&keys::repo_visibility_revision(&repo.name))
                        && seen.fetch_add(1, Ordering::SeqCst) == 1
                    {
                        // The last security read returns normally; the next anchor
                        // read fails its shared ledger before backend dispatch.
                        clock.set(i64::try_from(expiry).unwrap());
                        budget
                            .charge_many(OBJECT_READER_CALLS - budget.used())
                            .unwrap();
                    }
                }));
            in_view(&fx, writer, |reader| {
                assert!(
                    block_on(reader.walk_history_page_in(
                        &mut session,
                        HEAD,
                        Some(token.token.expose()),
                        1
                    ))
                    .unwrap()
                    .is_none()
                );
            });
            assert_eq!(reads.load(Ordering::SeqCst), 2);
            assert_eq!(session.used().storage_calls, OBJECT_READER_CALLS);
            assert!(!session.proofs.contains(&token_cursor(&fx, &token)));
        }
    }
}

fn token_cursor<H: HookSet>(fx: &Fx<H>, token: &HistoryContinuation) -> Hash {
    fx.pipe
        .cfg
        .history_tokens
        .as_ref()
        .unwrap()
        .verify(token.token.expose())
        .unwrap()
        .witness
        .last()
        .unwrap()
        .id
}

#[test]
fn continuation_restored_proofs_respect_a_shorter_inherited_deadline() {
    let first = Arc::new(());
    let mut saved = crate::pipeline::read_proofs::ReadProofs::default();
    let long = HttpObjectsConfig {
        read_deadline: std::time::Duration::from_secs(10),
        reachability_lag_ms: 10_000,
        ..http_cfg()
    };
    saved.bind(&first, None, 0, &long).unwrap();
    saved.capture_selected(Some([1; 32]));
    let mut temporary = saved.isolated();
    let mut short = long;
    short.read_deadline = std::time::Duration::from_secs(1);
    temporary.bind(&Arc::new(()), None, 100, &short).unwrap();
    saved.inherit_deadline(&temporary);
    // Returning to the original context before its shortened deadline keeps
    // evidence, but an operation ending beyond that deadline must refuse.
    saved.bind(&first, None, 500, &long).unwrap();
    assert!(saved.contains(&[1; 32]));
    assert!(saved.current(1_000));
    assert!(!saved.current(2_000));
}
