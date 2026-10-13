//! Cross-request storage-cache probes use fresh reader sessions for every read.
use super::*;
use crate::store::{
    BorrowedStore, CacheConfig, CachingBlobStore, CachingNamespaceStore, ContentIndex,
    MemoryImmutableCache,
};
use std::time::Duration;
mod trace;
use trace::{TraceBlobs, TraceKv};

type CachedPipe<H = Hooks> = Pipeline<
    CachingBlobStore<TraceBlobs, MemoryImmutableCache>,
    CachingNamespaceStore<TraceKv, MemoryImmutableCache>,
    H,
>;

fn cached<H: HookSet>(shape: &Shape, hooks: H) -> CachedPipe<H> {
    let fx = &shape.fx;
    let cache =
        MemoryImmutableCache::new(16 * 1024 * 1024, Duration::from_mins(1), fx.clock.clone());
    let config = CacheConfig::new(
        "read-probe",
        Arc::new(crate::ManualSleep::new()),
        Duration::from_millis(10),
    )
    .unwrap();
    let trace = trace::new();
    Pipeline::new(
        CachingBlobStore::new(
            TraceBlobs {
                inner: fx.pipe.blobs.clone(),
                trace: trace.clone(),
            },
            cache.clone(),
            config.clone(),
        ),
        CachingNamespaceStore::new(
            TraceKv {
                inner: fx.pipe.meta.clone(),
                trace,
            },
            cache,
            config,
        ),
        hooks,
        fx.pipe.cfg.clone(),
        fx.clock.clone(),
        fx.metrics.clone(),
    )
    .unwrap()
}

/// Populate actual immutable entries, rather than merely warming session proofs.
fn warm_packs<H: HookSet>(shape: &Shape, pipe: &CachedPipe<H>) {
    for pack in &shape.packs {
        assert!(
            block_on(pipe.blobs.get(&BlobKey::pack(*pack), None))
                .unwrap()
                .is_some()
        );
    }
}

#[test]
fn embedder_read_shapes_immutable_cache_warm_repeat() {
    let mut history = shape(11, 8, true, |_| 1);
    for denial in [false, true] {
        history.fx.pipe.cfg.takedown_denial = denial;
        for owner in [false, true] {
            for op in [Op::Show { sizes: true }, Op::Log(10), Op::GetReadGate] {
                // Compare repeats on both paths; selected capture may initialize rj.
                let _ = measure(&history, owner, op);
                let before = measure(&history, owner, op);
                let pipe = cached(&history, Hooks::new());
                let _ = measure_on(&history, &pipe, owner, op, LATENCY, None, false);
                trace::clear(&pipe);
                let warm = measure_on(&history, &pipe, owner, op, LATENCY, None, false);
                trace::print(&pipe, owner, denial, op, "repeat");
                // Namespace rows are Live: no KV savings are claimed or expected.
                assert_eq!(warm.1, before.1);
                println!(
                    "IMMUTABLE_CACHE_REPEAT denial={denial} owner={owner} op={op:?} rounds_before={:.0} rounds_warm={:.0} KV_before={} KV_warm={} GET_before={} GET_warm={} KV_saved={} GET_saved={}",
                    before.0,
                    warm.0,
                    before.1,
                    warm.1,
                    before.2,
                    warm.2,
                    i64::from(before.1) - i64::from(warm.1),
                    i64::try_from(before.2).unwrap() - i64::try_from(warm.2).unwrap(),
                );
                // A backend may have whole packs from an earlier full-pack download.
                warm_packs(&history, &pipe);
                trace::clear(&pipe);
                let preloaded = measure_on(&history, &pipe, owner, op, LATENCY, None, false);
                trace::print(&pipe, owner, denial, op, "full-pack-preload");
                assert_eq!(preloaded.1, before.1);
                println!(
                    "IMMUTABLE_CACHE_FULL_PACK_WARM denial={denial} owner={owner} op={op:?} KV={} GET={}",
                    preloaded.1, preloaded.2,
                );
            }
        }
    }
}

/// The same three shapes, returning uniform absence instead of asserting presence.
async fn present<B: MultipartBlobStore, N: NamespaceStore + Clone + 'static, H: HookSet>(
    shape: &Shape,
    pipe: &Pipeline<B, N, H>,
    owner: bool,
    op: Op,
) -> Result<bool, ServerError> {
    let fx = &shape.fx;
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
    let reader = pipe
        .object_reader(
            fx.repo_id("room"),
            if owner {
                ReaderView::Owner(&meta)
            } else {
                ReaderView::Public
            },
        )
        .await?;
    let mut session = ReaderSession::default();
    match op {
        Op::Show { .. } => {
            let head = reader
                .read_canonical_in(&mut session, &[shape.head])
                .await?;
            if head[0].is_none() {
                return Ok(false);
            }
            let root = reader
                .read_canonical_in(&mut session, &[shape.root])
                .await?;
            Ok(root[0].is_some())
        }
        Op::Log(count) => Ok(reader
            .walk_history_in(
                &mut session,
                HEAD,
                None,
                count,
                HistoryOptions {
                    mode: HistoryMode::FirstParent,
                    ..HistoryOptions::default()
                },
            )
            .await?
            .is_some_and(|page| !page.commits.is_empty())),
        Op::GetReadGate => {
            let reader = reader.with_selected_ref(HEAD)?;
            let Some(capture) = reader.selected_capture_in(&mut session).await? else {
                return Ok(false);
            };
            Ok(reader
                .read_canonical_in(&mut session, &[capture.tip()])
                .await?[0]
                .is_some())
        }
        _ => unreachable!("security regression uses Show, Log and GetReadGate"),
    }
}

#[test]
fn immutable_cache_warm_show_log_gate_keep_denial_live() {
    for denial in [false, true] {
        for owner in [false, true] {
            let mut history = shape(11, 2, false, |_| 1);
            history.fx.pipe.cfg.takedown_denial = denial;
            let pipe = cached(&history, Hooks::new());
            warm_packs(&history, &pipe);
            let operations = [Op::Show { sizes: false }, Op::Log(10), Op::GetReadGate];
            for op in operations {
                assert!(block_on(present(&history, &pipe, owner, op)).unwrap());
            }
            block_on(
                ContentIndex::new(BorrowedStore(&history.fx.pipe.meta)).block(
                    &history.head,
                    &crate::store::BlockEntry::new("manual", T0 as u64),
                    T0 as u64,
                ),
            )
            .unwrap();
            for op in operations {
                assert!(
                    !block_on(present(&history, &pipe, owner, op)).unwrap(),
                    "{op:?}"
                );
            }
        }
    }
}

#[test]
fn immutable_cache_warm_show_log_gate_keep_visibility_live() {
    let history = shape(11, 2, false, |_| 1);
    let pipe = cached(&history, Hooks::new());
    warm_packs(&history, &pipe);
    let operations = [Op::Show { sizes: false }, Op::Log(10), Op::GetReadGate];
    for op in operations {
        assert!(block_on(present(&history, &pipe, false, op)).unwrap());
    }
    history.fx.make_private("room");
    for op in operations {
        assert!(
            !block_on(present(&history, &pipe, false, op)).unwrap(),
            "{op:?}"
        );
        assert!(
            block_on(present(&history, &pipe, true, op)).unwrap(),
            "{op:?}"
        );
    }
}

#[test]
fn immutable_cache_warm_show_log_gate_keep_authorization_live() {
    let history = shape(11, 2, false, |_| 1);
    let az = Arc::new(Scripted::default());
    let pipe = cached(&history, scripted(&az));
    let raw = Pipeline::new(
        history.fx.pipe.blobs.clone(),
        history.fx.pipe.meta.clone(),
        scripted(&az),
        history.fx.pipe.cfg.clone(),
        history.fx.clock.clone(),
        history.fx.metrics.clone(),
    )
    .unwrap();
    warm_packs(&history, &pipe);
    let operations = [Op::Show { sizes: false }, Op::Log(10), Op::GetReadGate];
    for op in operations {
        assert!(block_on(present(&history, &pipe, false, op)).unwrap());
    }
    *az.verdict.lock().unwrap() = Some(Code::PermissionDenied);
    for op in operations {
        let expected = block_on(present(&history, &raw, false, op));
        let calls = az.seen.lock().unwrap().len();
        let actual = block_on(present(&history, &pipe, false, op));
        match (expected, actual) {
            (Ok(false), Ok(false)) => {}
            (Err(expected), Err(actual)) => {
                assert_eq!(actual.code(), expected.code(), "{op:?}");
                assert!(matches!(
                    actual.code(),
                    Code::PermissionDenied | Code::NotFound
                ));
            }
            outcomes => panic!("{op:?} changed authorization denial: {outcomes:?}"),
        }
        assert!(
            az.seen.lock().unwrap().len() > calls,
            "{op:?} skipped authorizer"
        );
    }
}

#[test]
fn immutable_cache_warm_readers_see_ref_moves_immediately() {
    let mut history = shape(11, 2, false, |_| 1);
    let pipe = cached(&history, Hooks::new());
    warm_packs(&history, &pipe);
    for op in [Op::Show { sizes: false }, Op::Log(10), Op::GetReadGate] {
        assert!(block_on(present(&history, &pipe, false, op)).unwrap());
    }
    let bytes =
        block_on(pipe.object_reader(history.fx.repo_id("room"), ReaderView::Public)).unwrap();
    let canonical = block_on(bytes.read_canonical(&[history.head, history.root])).unwrap();
    let head = mkit_core::serialize::deserialize(canonical[0].as_ref().unwrap()).unwrap();
    let root = mkit_core::serialize::deserialize(canonical[1].as_ref().unwrap()).unwrap();
    let next = commit(&root, &[&head], "next");
    let previous = history.packs.last().copied().unwrap();
    history
        .fx
        .push("room", &[&next], id(&next), Some((history.head, previous)));
    drain(&history.fx);
    history.head = id(&next);
    // Each read starts a new session on the same cache and observes current ref state.
    for op in [Op::Show { sizes: false }, Op::Log(10), Op::GetReadGate] {
        block_on(run(
            &history,
            &pipe,
            false,
            op,
            &mut ReaderSession::default(),
        ))
        .unwrap();
    }
    let reader =
        block_on(pipe.object_reader(history.fx.repo_id("room"), ReaderView::Public)).unwrap();
    let page = block_on(reader.walk_history_in(
        &mut ReaderSession::default(),
        HEAD,
        None,
        10,
        HistoryOptions::default(),
    ))
    .unwrap()
    .unwrap();
    assert_eq!(page.commits[0].id, history.head);
}
