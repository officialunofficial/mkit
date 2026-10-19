//! Published reads must retain their authorization checks before validators.
use super::*;

#[test]
#[allow(clippy::too_many_lines)] // Real reader surfaces at both sides of the clearance deadline.
fn clearance_hold_race_reader_exposure_before_and_after_deadline() {
    use crate::rt::Clock;
    use crate::store::outbox::OutboxBuilder;
    use crate::store::publication::{self, Advance, Clearance, Pair, Witness};
    use crate::timers::{DueTimer, Fired, TimerCtx, TimerHandler, registry::kinds};

    // Extend the timer reproducer with real packs, indexes and public readers.
    // Also cover a hold committed after clearance, without changing hold tests.
    for (hold_before_apply, coherent_gate) in
        [(true, false), (false, false), (true, true), (false, true)]
    {
        let mut fx = fixture_tweaked(Hooks::new(), http_cfg(), |cfg| {
            cfg.sharding = Sharding::D34;
            cfg.takedown_denial = true;
        });
        let stopped = Arc::new(AtomicBool::new(false));
        fx.pipe = fx
            .pipe
            .with_publication_policy(Arc::new(ServingStop(stopped.clone())))
            .unwrap();
        let d = data();
        fx.push("room", &d.refs(), d.head(), None);
        super::history_tests::drain(&fx);
        let repo = fx.repo_id("room");
        let main_source = fx.pipe.shards.ref_shard(&repo, HEAD);
        let race_ref = "refs/heads/race";
        let source = fx.pipe.shards.ref_shard(&repo, race_ref);
        let located = block_on(crate::indexed::resolve::locate_split(
            &fx.pipe.meta,
            fx.pipe.shards.as_ref(),
            &repo,
            &[d.head()],
            fx.metrics.as_ref(),
        ))
        .unwrap()[&d.head()]
            .as_ref()
            .unwrap()
            .unwrap();
        let pack = located.pack;
        let anonymous = |procedure| {
            fx.auth(&Req::unsigned(procedure).header("x-repository", &fx.identity("room")))
        };
        assert!(
            block_on(
                fx.pipe
                    .pack_exists(&anonymous(Procedure::PackExists), PackKey(pack))
            )
            .unwrap()
        );
        assert!(
            block_on(
                fx.pipe
                    .download(&anonymous(Procedure::DownloadPack), PackKey(pack))
            )
            .is_ok()
        );
        for object in [&d.small, &d.big, &d.manifest] {
            assert_eq!(fx.get(&fx.object_url("room", &id(object))).status, 200);
        }
        let original = block_on(publication::read(
            &fx.pipe.meta,
            &main_source,
            &repo.name,
            HEAD,
        ))
        .unwrap();
        let advance = Advance {
            sequence: 1,
            generation: original.generation,
            value: Pair {
                head: Some(d.head()),
                packmap: original.value.packmap,
            },
            additions: vec![],
            dependencies: vec![pack],
            external_bases: vec![],
            obligations: vec![],
            state: Clearance::Pending,
            operation: [49; 32],
        };
        let outbox_rows = block_on(
            fx.pipe
                .meta
                .get_many(&source, &[keys::outbox_sequence(), keys::outcome_backlog()]),
        )
        .unwrap();
        let mut outbox =
            OutboxBuilder::new(outbox_rows[0].as_ref(), outbox_rows[1].as_ref()).unwrap();
        let mut batch = Batch::new();
        publication::append(
            &repo,
            race_ref,
            &source,
            fx.pipe.shards.as_ref(),
            None,
            advance,
            false,
            &mut batch.preconditions,
            &mut batch.writes,
            &mut outbox,
        )
        .unwrap();
        outbox
            .try_finish(&mut batch.preconditions, &mut batch.writes)
            .unwrap();
        assert_eq!(
            block_on(fx.pipe.meta.inner.apply(&source, batch)).unwrap(),
            BatchOutcome::Committed
        );
        let advance_key = keys::advance(&repo.name, race_ref, 1);
        let timer_key = keys::timer(0, kinds::PUBLICATION_RECHECK.get(), advance_key.as_bytes());
        let timer = DueTimer {
            due_at_ms: 0,
            kind: kinds::PUBLICATION_RECHECK,
            reference: advance_key.into_bytes(),
            value: block_on(fx.pipe.meta.get(&source, &timer_key))
                .unwrap()
                .unwrap(),
        };
        let now = u64::try_from(fx.clock.now_ms()).unwrap();
        let ctx = TimerCtx {
            store: &fx.pipe.meta,
            partition: &source,
            now_ms: now,
            continuation_deadline_ms: None,
        };
        let handler =
            crate::timers::publication_recheck::PublicationRecheck::new(fx.pipe.meta.clone());
        let Fired::Done(batch) = block_on(handler.fire(&ctx, &timer)).unwrap() else {
            panic!("visible supplier must produce a clearance plan");
        };
        assert!(
            batch
                .preconditions
                .contains(&Precondition::NotAfter(now + 10_000))
        );
        let batch = batch
            .require(Precondition::Equals(timer_key.clone(), timer.value))
            .delete(timer_key);
        let hold = || {
            // A configured inspector must install this live gate before the hold.
            // The witness-only cases separately probe an incoherent projection.
            if coherent_gate {
                stopped.store(true, Ordering::SeqCst);
            }
            let partition = fx.pipe.shards.membership(&repo, &BlobKey::pack(pack));
            assert_ne!(partition, source);
            let key = keys::published_member(&repo.name, &pack);
            let raw = block_on(fx.pipe.meta.get(&partition, &key))
                .unwrap()
                .unwrap();
            let mut witness = Witness::decode(&raw).unwrap();
            witness.held = true;
            assert_eq!(
                block_on(
                    fx.pipe
                        .meta
                        .inner
                        .apply(&partition, Batch::new().put(key, witness.encode()))
                )
                .unwrap(),
                BatchOutcome::Committed
            );
        };
        if hold_before_apply {
            hold();
        }
        assert_eq!(
            block_on(fx.pipe.meta.inner.apply(&source, batch)).unwrap(),
            BatchOutcome::Committed
        );
        if !hold_before_apply {
            hold();
        }
        let registry = crate::timers::TimerRegistry::new().register(crate::relay::RelayHandler {
            target: crate::store::BorrowedStore(&fx.pipe.meta),
            hook: crate::relay::NoHook,
            budget: crate::relay::RelayBudget::default(),
        });
        for _ in 0..8 {
            block_on(crate::timers::run_due(
                &fx.pipe.meta,
                &source,
                &registry,
                fx.clock.as_ref(),
                now,
                &crate::timers::TickBudget::default(),
            ))
            .unwrap();
        }
        for elapsed in [0, 10_001] {
            fx.clock.set(i64::try_from(now + elapsed).unwrap());
            let anonymous = |procedure| {
                fx.auth(&Req::unsigned(procedure).header("x-repository", &fx.identity("room")))
            };
            let exists = block_on(
                fx.pipe
                    .pack_exists(&anonymous(Procedure::PackExists), PackKey(pack)),
            )
            .unwrap();
            assert!(!exists);
            let download = block_on(
                fx.pipe
                    .download(&anonymous(Procedure::DownloadPack), PackKey(pack)),
            )
            .err()
            .unwrap();
            assert_eq!(download.code(), Code::NotFound);
            let hinted = |procedure| {
                fx.auth(
                    &Req::unsigned(procedure)
                        .header("x-repository", &fx.identity("room"))
                        .header("x-mkit-ref", HEAD),
                )
            };
            let hinted_exists = block_on(
                fx.pipe
                    .pack_exists(&hinted(Procedure::PackExists), PackKey(pack)),
            )
            .unwrap();
            let hinted_download = block_on(
                fx.pipe
                    .download(&hinted(Procedure::DownloadPack), PackKey(pack)),
            );
            let hinted_served = if let Ok(mut stream) = hinted_download {
                let bytes = block_on(async {
                    let mut bytes = Vec::new();
                    while let Some(chunk) = stream.chunks.next().await {
                        bytes.extend_from_slice(&chunk.unwrap().data);
                    }
                    bytes
                });
                assert_eq!(hash(&bytes), pack);
                true
            } else {
                false
            };
            assert_eq!(hinted_exists, !coherent_gate);
            assert_eq!(hinted_served, !coherent_gate);
            // Inline, extracted and chunked object sources all remain filtered.
            for object in [&d.small, &d.big, &d.manifest] {
                assert_eq!(fx.get(&fx.object_url("room", &id(object))).status, 404);
            }
            assert_eq!(fx.get(&fx.ref_url("room", "race", "small.txt")).status, 404);
            let head =
                block_on(fx.pipe.read_ref(&anonymous(Procedure::ReadRef), race_ref)).unwrap();
            assert_eq!(head, Some(d.head()));
            let refs = block_on(fx.pipe.list_refs(&anonymous(Procedure::ListRefs), "")).unwrap();
            assert_eq!(
                refs.iter().find(|entry| entry.name == race_ref).unwrap().id,
                d.head()
            );
            eprintln!(
                "hold_before_apply={hold_before_apply} coherent_gate={coherent_gate} elapsed={elapsed}: PackExists=false DownloadPack=not_found hinted_exists={hinted_exists} hinted_bytes={hinted_served} object_reads=404 ReadRef=head ListRefs=head"
            );
        }
    }
}

fn counters(fx: Fx) -> (Fx, Arc<Admit>) {
    let admission = Arc::new(Admit {
        seen: Mutex::default(),
        ended: Arc::default(),
        challenge: false,
    });
    let fx = with_seams(fx, |s| s.admission = admission.clone());
    (fx, admission)
}

fn same_response(got: &Got, expected: &Got) {
    assert_eq!(
        (got.status, &got.headers, &got.body),
        (expected.status, &expected.headers, &expected.body)
    );
}

#[test]
fn ref_reads_never_fall_back_to_a_live_value() {
    let (fx, d) = published();
    let repo = fx.repo_id("room");
    let partition = fx.pipe.shards.ref_shard(&repo, HEAD);
    block_on(fx.pipe.meta.inner.apply(
        &partition,
        Batch::new().put(
            keys::ref_key(&repo.name, HEAD),
            codec::encode_ref_id(&[99; 32]),
        ),
    ))
    .unwrap();
    let (fx, admission) = counters(fx);
    let path = fx.ref_url("room", "main", "small.txt");
    let got = read(fx.request("GET", &path, None, &[]));
    assert_eq!(got.status, 200);
    assert_eq!(
        got.header("X-Mkit-Commit"),
        Some(to_hex(&d.head()).as_str())
    );
    admission.seen.lock().unwrap().clear();
    block_on(fx.pipe.meta.inner.apply(
        &partition,
        Batch::new().delete(keys::published_ref(&repo.name, HEAD)),
    ))
    .unwrap();
    for method in ["GET", "HEAD"] {
        let missing = read(fx.request(method, &fx.object_url("room", &[98; 32]), None, &[]));
        let got = read(fx.request(method, &path, None, &[("if-none-match", "*")]));
        same_response(&got, &missing);
    }
    assert!(admission.seen.lock().unwrap().is_empty());
}

#[test]
fn held_membership_overrides_warm_validators_before_admission() {
    let (fx, d) = published();
    let path = fx.object_url("room", &id(&d.small));
    assert_eq!(fx.get(&path).status, 200);
    let repo = fx.repo_id("room");
    let located = block_on(crate::indexed::resolve::locate_split(
        &fx.pipe.meta,
        fx.pipe.shards.as_ref(),
        &repo,
        &[d.head()],
        fx.metrics.as_ref(),
    ))
    .unwrap()[&d.head()]
        .as_ref()
        .unwrap()
        .unwrap();
    let partition = fx.pipe.shards.ref_shard(&repo, HEAD);
    let key = keys::membership(&repo.name, &located.pack);
    let value = block_on(fx.pipe.meta.get(&partition, &key))
        .unwrap()
        .unwrap();
    let mut witness = crate::store::publication::Witness::decode(&value).unwrap();
    // Simulate the upstream authority's held witness.
    witness.held = true;
    block_on(
        fx.pipe
            .meta
            .inner
            .apply(&partition, Batch::new().put(key, witness.encode())),
    )
    .unwrap();
    let (fx, admission) = counters(fx);
    for method in ["GET", "HEAD"] {
        let missing = read(fx.request(method, &fx.object_url("room", &[99; 32]), None, &[]));
        for url in [&path, &fx.ref_url("room", "main", "small.txt")] {
            let got = read(fx.request(method, url, None, &[("if-none-match", "*")]));
            same_response(&got, &missing);
        }
    }
    assert!(admission.seen.lock().unwrap().is_empty());
}
