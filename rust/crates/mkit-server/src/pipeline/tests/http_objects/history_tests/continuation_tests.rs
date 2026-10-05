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
fn continuation_pages_complete_long_changing_histories_without_cursor_walk() {
    for length in [201, 302] {
        // Distinct files and nested trees in every snapshot, real indexed packs.
        let (mut fx, commits) = changing_history(length);
        enable(&mut fx);
        for denial in [false, true] {
            fx.pipe.cfg.takedown_denial = denial;
            for writer in [false, true] {
                for size in [30, 100] {
                    let mut continuation: Option<HistoryContinuation> = None;
                    let mut output = Vec::new();
                    let mut page_number = 0;
                    let mut expiry = None;
                    loop {
                        page_number += 1;
                        let measured_before = (fx.pipe.meta.calls(), get_count(&fx));
                        in_view(&fx, writer, |reader| {
                            let (kv, gets) = measured_before;
                            let mut session = ReaderSession::default();
                            let page = block_on(reader.walk_history_page_in(
                                &mut session,
                                HEAD,
                                continuation.as_ref().map(|c| c.token.expose()),
                                size,
                            ))
                            .unwrap()
                            .unwrap();
                            assert_eq!(
                                get_count(&fx) - gets,
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
                                let expected = &commits[length - 1 - output.len()];
                                assert_eq!(returned.id, id(expected));
                                assert_eq!(returned.canonical, serialize(expected).unwrap());
                                output.push(returned.id);
                            }
                            report(
                                &fx,
                                &format!(
                                    "continuation length={length} size={size} page={page_number} owner={writer} denial={denial}"
                                ),
                                session.used().storage_calls,
                                kv,
                                gets,
                                if denial {
                                    u32::try_from(page.commits.len() + 1).unwrap()
                                } else {
                                    0
                                },
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
                    assert_eq!(page_number, length.div_ceil(size));
                }
            }
        }
    }
}

#[test]
fn continuation_scope_mac_replay_and_corrupt_state_fail_uniformly() {
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
                    4 => c.purpose = "mkit-url-token:v1".into(),
                    5 => c.ancestry.push(c.cursor), // cyclic/duplicated authenticated state
                    6 => c.ancestry.clear(),
                    _ => unreachable!(),
                }
                reject(&fx, writer, &config.mint(&c).unwrap());
            }
            let copied = token.token.expose().to_owned();
            // The copy wins at most once in its original scope. Both the copied
            // MAC and the original fail after that atomic redemption.
            in_view(&fx, writer, |reader| {
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
            reject(&fx, writer, token.token.expose());
            reject(&fx, writer, &copied);
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
