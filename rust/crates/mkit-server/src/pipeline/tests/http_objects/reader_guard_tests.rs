//! Batched guards retain the storage/response boundary for both reader views.
use super::*;
use crate::pipeline::{ReaderSession, ReaderView};
use futures::FutureExt as _;
use std::sync::atomic::{AtomicBool, AtomicUsize};

fn queued_stop(fx: &Fx, target: Hash) -> MemoryKv {
    let source = MemoryKv::with_clock(fx.clock.clone());
    let row = codec::RelayV1 {
        at_ms: T0 as u64,
        target: crate::store::content_shard(&target),
        puts: vec![(
            keys::block(&target),
            codec::encode_block_entry(&crate::store::BlockEntry::new("alarm stop", T0 as u64)),
        )],
        deletes: Vec::new(),
    };
    block_on(crate::relay::commit_relay_rows(
        &source,
        &ns(),
        &[row],
        T0 as u64,
        T0 as u64 + 1000,
        None,
    ))
    .unwrap();
    source
}

#[test]
fn concurrent_relay_alarm_and_guard_fault_keep_the_stop_durable_and_reads_closed() {
    for global_proofs in [false, true] {
        let mut fx = fixture_tweaked(Hooks::new(), http_cfg(), |c| c.takedown_denial = false);
        let leaf = blob(&vec![7; 2048]);
        let root = tree(&[("leaf", EntryMode::Blob, &leaf)]);
        let head = commit(&root, &[], "alarm race");
        fx.push("room", &[&leaf, &root, &head], id(&head), None);
        fx.pipe.cfg.takedown_denial = global_proofs;
        let target = id(&leaf);
        let armed = Arc::new(AtomicBool::new(false));
        let hook_armed = armed.clone();
        let spy = Arc::get_mut(&mut fx.pipe.meta).unwrap();
        spy.yields = true;
        spy.read_many_hook = Some(Box::new(move |store, _, keys| {
            if keys.contains(&keys::block(&target)) && hook_armed.swap(false, Ordering::SeqCst) {
                store
                    .apply(
                        &crate::store::content_shard(&target),
                        Batch::new().put(keys::block(&target), Value::new(vec![255])),
                    )
                    .now_or_never()
                    .unwrap()
                    .unwrap();
            }
        }));
        let reader = block_on(
            fx.pipe
                .object_reader(fx.repo_id("room"), ReaderView::Public),
        )
        .unwrap();
        let mut session = ReaderSession::default();
        for parent in [id(&head), id(&root)] {
            assert!(
                block_on(reader.read_canonical_in(&mut session, &[parent])).unwrap()[0].is_some()
            );
        }
        let source = queued_stop(&fx, target);
        let registry = crate::timers::TimerRegistry::new().register(crate::relay::RelayHandler {
            target: crate::store::BorrowedStore(fx.pipe.meta.as_ref()),
            hook: crate::relay::NoHook,
            budget: crate::relay::RelayBudget::default(),
        });
        let tick = crate::timers::TickBudget::default();
        fx.pipe.meta.fail_next_apply.store(true, Ordering::SeqCst);
        armed.store(true, Ordering::SeqCst);
        let ids = [target];
        let (read, alarm) = block_on(futures::future::join(
            reader.read_canonical_in(&mut session, &ids),
            crate::timers::run_due(
                &source,
                &ns(),
                &registry,
                fx.clock.as_ref(),
                T0 as u64,
                &tick,
            ),
        ));
        assert_eq!(read.unwrap_err().code(), crate::Code::Unavailable);
        let alarm = alarm.unwrap();
        assert_eq!(alarm.fired, 1);
        assert!(!fx.pipe.meta.fail_next_apply.load(Ordering::SeqCst));
        assert!(
            block_on(source.get(&ns(), &keys::relay(1)))
                .unwrap()
                .is_some(),
            "a failed target apply cannot consume the durable stop"
        );
        let retry = alarm
            .next_wake_ms
            .expect("failed relay retains a retry timer");
        fx.clock.set(i64::try_from(retry).unwrap());
        let alarm = block_on(crate::timers::run_due(
            &source,
            &ns(),
            &registry,
            fx.clock.as_ref(),
            retry,
            &tick,
        ))
        .unwrap();
        assert_eq!(alarm.fired, 1);
        assert!(
            block_on(source.get(&ns(), &keys::relay(1)))
                .unwrap()
                .is_none()
        );
        fx.clear_calls();
        assert_eq!(
            block_on(reader.read_canonical_in(&mut session, &ids)).unwrap(),
            [None]
        );
        assert!(
            fx.calls.lock().unwrap().is_empty(),
            "a delivered stop precedes blob access"
        );
    }
}

#[test]
fn target_and_pack_blocks_at_the_final_wave_hide_canonical_and_metadata_outputs() {
    for denial in [false, true] {
        for pack_block in [false, true] {
            for sizes_only in [false, true] {
                for writer in [false, true] {
                    let mut fx = fixture_tweaked(Hooks::new(), http_cfg(), |c| {
                        c.takedown_denial = denial;
                    });
                    let leaf = blob(b"guarded leaf");
                    let root = tree(&[("leaf", EntryMode::Blob, &leaf)]);
                    let head = commit(&root, &[], "guard boundary");
                    let pack = fx.push("room", &[&leaf, &root, &head], id(&head), None);
                    let target = id(&leaf);
                    let blocked = if pack_block { pack } else { target };
                    let armed = Arc::new(AtomicBool::new(false));
                    let reads = Arc::new(AtomicUsize::new(0));
                    let (hook_armed, hook_reads) = (armed.clone(), reads.clone());
                    Arc::get_mut(&mut fx.pipe.meta).unwrap().read_many_hook =
                        Some(Box::new(move |store, _, keys| {
                            if hook_armed.load(Ordering::SeqCst)
                                && keys.contains(&keys::block(&blocked))
                                && hook_reads.fetch_add(1, Ordering::SeqCst) == 1
                            {
                                store
                                    .apply(
                                        &crate::store::content_shard(&blocked),
                                        Batch::new().put(
                                            keys::block(&blocked),
                                            codec::encode_block_entry(
                                                &crate::store::BlockEntry::new(
                                                    "concurrent stop",
                                                    T0 as u64,
                                                ),
                                            ),
                                        ),
                                    )
                                    .now_or_never()
                                    .expect("memory store writes are immediate")
                                    .unwrap();
                            }
                        }));
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
                    let mut session = ReaderSession::default();
                    for parent in [id(&head), id(&root)] {
                        assert!(
                            block_on(reader.read_canonical_in(&mut session, &[parent])).unwrap()[0]
                                .is_some()
                        );
                    }
                    fx.clear_calls();
                    armed.store(true, Ordering::SeqCst);
                    if sizes_only {
                        assert_eq!(
                            block_on(reader.object_metadata_in(&mut session, &[target, target]))
                                .unwrap(),
                            [None, None]
                        );
                        assert!(fx.calls.lock().unwrap().is_empty());
                    } else {
                        assert_eq!(
                            block_on(reader.read_canonical_in(&mut session, &[target, target]))
                                .unwrap(),
                            [None, None]
                        );
                        assert!(
                            !fx.calls.lock().unwrap().is_empty(),
                            "stop arrives after raw loading"
                        );
                    }
                    assert_eq!(reads.load(Ordering::SeqCst), 2);
                }
            }
        }
    }
}

#[test]
fn an_external_base_stop_after_reconstruction_is_checked_at_the_final_boundary() {
    for denial in [false, true] {
        for pack_block in [false, true] {
            let mut fx = fixture_tweaked(Hooks::new(), http_cfg(), |c| c.takedown_denial = false);
            let base = blob(b"base payload");
            let old_root = tree(&[("base", EntryMode::Blob, &base)]);
            let old_head = commit(&old_root, &[], "base");
            let old_pack = fx.push("room", &[&base, &old_root, &old_head], id(&old_head), None);
            let derived = blob(b"derived payload");
            let root = tree(&[("derived", EntryMode::Blob, &derived)]);
            let head = commit(&root, &[], "delta");
            let mut pack = PackWriter::new();
            pack.push_delta(
                &id(&base),
                &mkit_core::delta::encode(
                    &serialize(&base).unwrap(),
                    &serialize(&derived).unwrap(),
                )
                .unwrap(),
            )
            .unwrap();
            for object in [&root, &head] {
                pack.push_raw(id(object), &serialize(object).unwrap())
                    .unwrap();
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
            fx.pipe.cfg.takedown_denial = denial;
            let target = id(&derived);
            let stopped = if pack_block { old_pack } else { id(&base) };
            let armed = Arc::new(AtomicBool::new(false));
            let reads = Arc::new(AtomicUsize::new(0));
            let (hook_armed, hook_reads) = (armed.clone(), reads.clone());
            Arc::get_mut(&mut fx.pipe.meta).unwrap().read_many_hook =
                Some(Box::new(move |store, _, keys| {
                    if hook_armed.load(Ordering::SeqCst)
                        && keys.contains(&keys::block(&target))
                        && hook_reads.fetch_add(1, Ordering::SeqCst) == 1
                    {
                        store
                            .apply(
                                &crate::store::content_shard(&stopped),
                                Batch::new().put(
                                    keys::block(&stopped),
                                    codec::encode_block_entry(&crate::store::BlockEntry::new(
                                        "base stop",
                                        T0 as u64,
                                    )),
                                ),
                            )
                            .now_or_never()
                            .unwrap()
                            .unwrap();
                    }
                }));
            let reader = block_on(
                fx.pipe
                    .object_reader(fx.repo_id("room"), ReaderView::Public),
            )
            .unwrap();
            let mut session = ReaderSession::default();
            for parent in [id(&head), id(&root)] {
                assert!(
                    block_on(reader.read_canonical_in(&mut session, &[parent])).unwrap()[0]
                        .is_some()
                );
            }
            fx.clear_calls();
            armed.store(true, Ordering::SeqCst);
            assert_eq!(
                block_on(reader.read_canonical_in(&mut session, &[target])).unwrap(),
                [None]
            );
            assert_eq!(reads.load(Ordering::SeqCst), 2);
            assert!(
                !fx.blob_calls(BlobKey::pack(old_pack)).is_empty(),
                "base loaded before final guard"
            );
        }
    }
}

#[test]
fn global_proof_switch_only_controls_directory_reads_not_live_block_guards() {
    for global_proofs in [false, true] {
        for metadata_only in [false, true] {
            let mut fx = fixture_tweaked(Hooks::new(), http_cfg(), |c| c.takedown_denial = false);
            let leaf = blob(b"mode guard");
            let root = tree(&[("leaf", EntryMode::Blob, &leaf)]);
            let head = commit(&root, &[], "mode guard");
            let pack = fx.push("room", &[&leaf, &root, &head], id(&head), None);
            fx.pipe.cfg.takedown_denial = global_proofs;
            let target = id(&leaf);
            let target_reads = Arc::new(AtomicUsize::new(0));
            let directory_pages = Arc::new(AtomicUsize::new(0));
            let reads = target_reads.clone();
            let pages = directory_pages.clone();
            let spy = Arc::get_mut(&mut fx.pipe.meta).unwrap();
            spy.read_many_hook = Some(Box::new(move |_, _, keys| {
                if keys.contains(&keys::block(&target)) {
                    assert!(keys.contains(&crate::takedown::denial::action_key(&target)));
                    reads.fetch_add(1, Ordering::SeqCst);
                }
            }));
            spy.scan_page_hook = Some(Box::new(move |start, _, page| {
                if start
                    .as_bytes()
                    .starts_with(b"b\0\xffdenial-descriptor-directory\0")
                {
                    pages.fetch_add(1, Ordering::SeqCst);
                }
                page
            }));
            let reader = block_on(
                fx.pipe
                    .object_reader(fx.repo_id("room"), ReaderView::Public),
            )
            .unwrap();
            let mut session = ReaderSession::default();
            for parent in [id(&head), id(&root)] {
                assert!(
                    block_on(reader.read_canonical_in(&mut session, &[parent])).unwrap()[0]
                        .is_some()
                );
            }
            target_reads.store(0, Ordering::SeqCst);
            directory_pages.store(0, Ordering::SeqCst);
            for _ in 0..2 {
                if metadata_only {
                    assert!(
                        block_on(reader.object_metadata_in(&mut session, &[target])).unwrap()[0]
                            .is_some()
                    );
                } else {
                    assert_eq!(
                        block_on(reader.read_canonical_in(&mut session, &[target])).unwrap(),
                        [Some(serialize(&leaf).unwrap())]
                    );
                }
            }
            assert_eq!(target_reads.load(Ordering::SeqCst), 4);
            assert_eq!(
                directory_pages.load(Ordering::SeqCst),
                if global_proofs { 32 } else { 0 },
                "an empty directory is read strongly on each enabled operation"
            );
            block_on(fx.pipe.meta.inner.apply(
                &crate::store::content_shard(&target),
                Batch::new().put(keys::block(&target), Value::new(vec![255])),
            ))
            .unwrap();
            let error = if metadata_only {
                block_on(reader.object_metadata_in(&mut session, &[target])).unwrap_err()
            } else {
                block_on(reader.read_canonical_in(&mut session, &[target])).unwrap_err()
            };
            assert_eq!(error.code(), crate::Code::Unavailable);
            assert!(target_reads.load(Ordering::SeqCst) > 4);
            // The pack guard is still part of every clean operation in both modes.
            assert!(
                fx.pipe
                    .meta
                    .seen
                    .lock()
                    .unwrap()
                    .contains(&keys::block(&pack))
            );
        }
    }
}
