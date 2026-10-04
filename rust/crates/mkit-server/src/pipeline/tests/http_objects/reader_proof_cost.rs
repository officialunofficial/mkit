use super::*;
use crate::pipeline::{ReadLimits, ReaderSession, ReaderView};

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

fn build(h: usize, depth: usize, files: usize, denial: bool) -> (Fx, Vec<Vec<Hash>>, Vec<Hash>) {
    let mut fx = fixture_tweaked(Hooks::new(), http_cfg(), |cfg| {
        cfg.sharding = Sharding::D34;
        cfg.takedown_denial = false;
    });
    fx.pipe
        .meta
        .count_partition_scans
        .store(true, Ordering::SeqCst);
    let mut parent: Option<Object> = None;
    let mut previous = None;
    let mut levels = Vec::new();
    let mut heads = Vec::new();
    for n in 0..h {
        let mut objects = Vec::new();
        let mut level_ids = vec![Vec::new(); depth + 2];
        let mut sub: Option<Object> = None;
        for d in (0..=depth).rev() {
            let mut entries = Vec::new();
            for f in 0..files {
                let o = blob(format!("commit {n} level {d} file {f}").as_bytes());
                entries.push(TreeEntry {
                    name: format!("f{f:03}.txt").into_bytes(),
                    mode: EntryMode::Blob,
                    object_hash: id(&o),
                });
                level_ids[depth + 1].push(id(&o));
                objects.push(o);
            }
            if let Some(child) = sub {
                entries.push(TreeEntry {
                    name: b"sub".to_vec(),
                    mode: EntryMode::Tree,
                    object_hash: id(&child),
                });
            }
            let t = Object::Tree(Tree { entries });
            level_ids[d].push(id(&t));
            objects.push(t.clone());
            sub = Some(t);
        }
        let c = commit(
            sub.as_ref().unwrap(),
            &parent.iter().collect::<Vec<_>>(),
            &format!("change {n}"),
        );
        objects.push(c.clone());
        heads.push(id(&c));
        let pack = fx.push(
            "room",
            &objects.iter().collect::<Vec<_>>(),
            id(&c),
            previous,
        );
        drain(&fx);
        previous = Some((id(&c), pack));
        parent = Some(c);
        levels = level_ids;
    }
    levels.insert(0, vec![*heads.last().unwrap()]);
    fx.pipe.cfg.takedown_denial = denial;
    (fx, levels, heads)
}

#[derive(Debug)]
struct Measurement {
    calls: u32,
    scans: usize,
    answers: Vec<Option<Vec<u8>>>,
}

fn measure(fx: &Fx, levels: &[Vec<Hash>], memo: bool) -> Measurement {
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
    let before = fx.pipe.meta.calls();
    let op_start = fx.pipe.meta.ops().len();
    let blob_start = fx.calls.lock().unwrap().len();
    let mut session = ReaderSession::new(ReadLimits::new(8500, 256 << 20, u64::MAX, 256 << 20));
    let reader = block_on(
        fx.pipe
            .object_reader(fx.repo_id("room"), ReaderView::Owner(&meta)),
    )
    .unwrap();
    let mut answers = Vec::new();
    for level in levels {
        for batch in level.chunks(16) {
            // The one-call API is the unchanged main proof path. Keeping the same
            // reader includes constructor authorization exactly once in both runs.
            answers.extend(
                block_on(async {
                    if memo {
                        reader.read_canonical_in(&mut session, batch).await
                    } else {
                        reader.read_canonical(batch).await
                    }
                })
                .unwrap(),
            );
        }
    }
    assert!(answers.iter().all(Option::is_some));
    for (answer, expected) in answers.iter().zip(levels.iter().flatten()) {
        assert_eq!(&hash(answer.as_ref().unwrap()), expected);
    }
    Measurement {
        calls: fx.pipe.meta.calls() - before
            + u32::try_from(fx.calls.lock().unwrap().len() - blob_start).unwrap(),
        scans: fx.pipe.meta.ops()[op_start..]
            .iter()
            .filter(|&&op| op == "scan_many_index")
            .count(),
        answers,
    }
}

#[test]
fn level_reads_and_log_reuse_proofs_with_identical_output() {
    let (fx, levels, _) = build(3, 4, 4, false);
    let before = measure(&fx, &levels, false);
    let after = measure(&fx, &levels, true);
    assert_eq!(after.answers.len(), 26);
    assert_eq!(before.answers, after.answers);
    println!(
        "26-object owner: calls {} -> {}, index scans {} -> {}",
        before.calls, after.calls, before.scans, after.scans
    );
    assert!(after.calls <= 450 && after.scans <= 30, "{after:?}");
    let (fx, _, heads) = build(10, 4, 4, true);
    let log: Vec<_> = heads.into_iter().rev().map(|head| vec![head]).collect();
    let before = measure(&fx, &log, false);
    let after = measure(&fx, &log, true);
    assert_eq!(before.answers, after.answers);
    println!(
        "10-commit owner log with denial: calls {} -> {}, index scans {} -> {}",
        before.calls, after.calls, before.scans, after.scans
    );
    assert!(after.calls <= 500, "{after:?}");
}

#[test]
fn one_hundred_parents_fit_the_unchanged_session_allowance() {
    let (fx, _, heads) = build(100, 4, 4, true);
    let log: Vec<_> = heads.into_iter().rev().map(|head| vec![head]).collect();
    let after = measure(&fx, &log, true);
    assert_eq!(after.answers.len(), 100);
    println!(
        "100-commit owner log with denial: {} calls, {} index scans",
        after.calls, after.scans
    );
}
