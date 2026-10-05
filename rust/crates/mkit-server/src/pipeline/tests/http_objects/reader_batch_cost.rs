use super::*;
use crate::pipeline::{ReadLimits, ReaderSession, ReaderView};
use std::collections::BTreeMap;

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

type Levels = Vec<Vec<Hash>>;
type Canonical = BTreeMap<Hash, Vec<u8>>;

fn build(
    h: usize,
    depth: usize,
    files: usize,
    denial: bool,
) -> (Fx, Vec<Levels>, Vec<Hash>, Canonical) {
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
    let mut snapshots = Vec::new();
    let mut canonical = BTreeMap::new();
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
        level_ids.insert(0, vec![*heads.last().unwrap()]);
        snapshots.push(level_ids);
        for object in &objects {
            canonical.insert(id(object), serialize(object).unwrap());
        }
    }
    fx.pipe.cfg.takedown_denial = denial;
    (fx, snapshots, heads, canonical)
}

#[derive(Debug)]
struct Cost {
    scans: usize,
    used: ReadLimits,
    objects: usize,
    elapsed: std::time::Duration,
}
async fn measure(
    fx: &Fx,
    levels: &[Vec<Hash>],
    expected: &BTreeMap<Hash, Vec<u8>>,
    metadata: bool,
    public: bool,
) -> Cost {
    try_measure(fx, levels, expected, metadata, public)
        .await
        .unwrap()
}
async fn try_measure(
    fx: &Fx,
    levels: &[Vec<Hash>],
    expected: &BTreeMap<Hash, Vec<u8>>,
    metadata: bool,
    public: bool,
) -> Result<Cost, crate::ServerError> {
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
    let op_start = fx.pipe.meta.ops().len();
    let start = std::time::Instant::now();
    let reader = fx
        .pipe
        .object_reader(
            fx.repo_id("room"),
            if public {
                ReaderView::Public
            } else {
                ReaderView::Owner(&meta)
            },
        )
        .await?;
    let mut session = ReaderSession::default();
    let mut objects = 0;
    for (level, ids) in levels.iter().enumerate() {
        for batch in ids.chunks(16) {
            if metadata && level + 1 == levels.len() {
                let before = fx.calls.lock().unwrap().len();
                for (id, answer) in batch
                    .iter()
                    .zip(reader.object_metadata_in(&mut session, batch).await?)
                {
                    assert_eq!(answer.unwrap().canonical_len, expected[id].len() as u64);
                    objects += 1;
                }
                assert_eq!(
                    before,
                    fx.calls.lock().unwrap().len(),
                    "sizes must not fetch leaf bodies"
                );
            } else {
                for (id, answer) in batch
                    .iter()
                    .zip(reader.read_canonical_in(&mut session, batch).await?)
                {
                    assert_eq!(answer.as_ref(), Some(&expected[id]));
                    objects += 1;
                }
            }
        }
    }
    Ok(Cost {
        scans: fx.pipe.meta.ops()[op_start..]
            .iter()
            .filter(|&&op| op == "scan_many_index")
            .count(),
        used: session.used(),
        objects,
        elapsed: start.elapsed(),
    })
}
fn gate(cost: &Cost, objects: usize, scans: usize, calls: u32) {
    println!("{cost:?}");
    assert_eq!(cost.objects, objects);
    assert!(
        cost.scans <= scans && cost.used.storage_calls <= calls,
        "{cost:?}"
    );
}
#[test]
fn completed_denial_enabled_workloads_fit_the_evaluation_envelope() {
    for history in [1, 3, 10] {
        let (fx, snapshots, _, expected) = build(history, 4, 4, true);
        gate(
            &block_on(measure(
                &fx,
                snapshots.last().unwrap(),
                &expected,
                false,
                false,
            )),
            26,
            30,
            650,
        );
        gate(
            &block_on(measure(
                &fx,
                snapshots.last().unwrap(),
                &expected,
                false,
                true,
            )),
            26,
            30,
            650,
        );
    }
    let (fx, snapshots, _, expected) = build(3, 10, 27, true);
    let levels = snapshots.last().unwrap();
    gate(
        &block_on(measure(&fx, &levels[..12], &expected, false, false)),
        12,
        16,
        500,
    );
    gate(
        &block_on(measure(&fx, levels, &expected, true, false)),
        309,
        320,
        4000,
    );
    gate(
        &block_on(measure(&fx, levels, &expected, false, false)),
        309,
        320,
        4500,
    );
    let diff: Vec<_> = snapshots[1..]
        .iter()
        .flat_map(|levels| levels.iter().cloned())
        .collect();
    gate(
        &block_on(measure(&fx, &diff, &expected, false, false)),
        618,
        640,
        7000,
    );
    let (fx, _, heads, expected) = build(100, 10, 27, true);
    let log: Vec<_> = heads.into_iter().rev().map(|id| vec![id]).collect();
    gate(
        &block_on(measure(&fx, &log, &expected, false, false)),
        100,
        110,
        4000,
    );
}
fn timed_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap()
}
fn inject_latency(fx: &Fx) {
    let latency = crate::store::read_probe::latency_ms();
    fx.pipe.meta.latency_ms.store(latency, Ordering::SeqCst);
    fx.pipe.blobs.latency_ms.store(latency, Ordering::SeqCst);
}
fn report_p95(name: &str, mut samples: Vec<std::time::Duration>, seconds: u64) -> bool {
    samples.sort();
    let p95 = *samples.last().unwrap(); // Nearest-rank p95 of three local samples.
    println!(
        "{name}: local p95 {p95:?}; {:.0} latency-equivalent critical-path rounds; limit {seconds} s",
        p95.as_secs_f64() / 0.030
    );
    p95 <= std::time::Duration::from_secs(seconds)
}
#[test]
fn informational_latency_for_large_canonical_fixtures() {
    let (fx, snapshots, _, expected) = build(3, 10, 27, true);
    inject_latency(&fx);
    let runtime = timed_runtime();
    let diff: Vec<_> = snapshots[1..]
        .iter()
        .flat_map(|levels| levels.iter().cloned())
        .collect();
    for (name, levels, metadata, objects, scans, calls, seconds) in [
        (
            "show",
            snapshots.last().unwrap().as_slice(),
            true,
            309,
            320,
            4000,
            10,
        ),
        ("diff", diff.as_slice(), false, 618, 640, 7000, 15),
    ] {
        let mut samples = Vec::new();
        for sample in 1..=3 {
            let cost = runtime.block_on(measure(&fx, levels, &expected, metadata, false));
            println!("{name} sample {sample}: {cost:?}");
            gate(&cost, objects, scans, calls);
            samples.push(cost.elapsed);
        }
        let _ = report_p95(name, samples, seconds);
    }
    let mut samples = Vec::new();
    for sample in 1..=3 {
        let elapsed = runtime.block_on(timed_deep_cat(&fx, &snapshots, &expected));
        println!("deep cat sample {sample}: {elapsed:?}");
        samples.push(elapsed);
    }
    let _ = report_p95("deep cat", samples, 10);
}
async fn timed_deep_cat(
    fx: &Fx,
    snapshots: &[Vec<Vec<Hash>>],
    expected: &BTreeMap<Hash, Vec<u8>>,
) -> std::time::Duration {
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
    let before = fx.pipe.meta.ops().len();
    let start = std::time::Instant::now();
    let reader = fx
        .pipe
        .object_reader(fx.repo_id("room"), ReaderView::Owner(&meta))
        .await
        .unwrap();
    let mut session = ReaderSession::default();
    let path = format!("{}f000.txt", "sub/".repeat(10));
    let (id, bytes) = reader
        .read_path_in(&mut session, HEAD, &path)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(id, snapshots.last().unwrap().last().unwrap()[0]);
    assert_eq!(bytes, expected[&id]);
    let scans = fx.pipe.meta.ops()[before..]
        .iter()
        .filter(|&&op| op == "scan_many_index")
        .count();
    assert!(scans <= 16 && session.used().storage_calls <= 550);
    println!("deep cat: {scans} scans, {:?}", session.used());
    start.elapsed()
}
#[test]
fn cold_owner_path_uses_only_the_selected_ten_level_path() {
    let (fx, snapshots, _, expected) = build(3, 10, 27, true);
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
    let reader = block_on(
        fx.pipe
            .object_reader(fx.repo_id("room"), ReaderView::Owner(&meta)),
    )
    .unwrap();
    let mut session = ReaderSession::default();
    let before = fx.pipe.meta.ops().len();
    let path = format!("{}f000.txt", "sub/".repeat(10));
    let (id, bytes) = block_on(reader.read_path_in(&mut session, HEAD, &path))
        .unwrap()
        .unwrap();
    assert_eq!(id, snapshots.last().unwrap().last().unwrap()[0]);
    assert_eq!(bytes, expected[&id]);
    let scans = fx.pipe.meta.ops()[before..]
        .iter()
        .filter(|&&op| op == "scan_many_index")
        .count();
    println!("deep cat: {scans} scans, {:?}", session.used());
    assert!(scans <= 16 && session.used().storage_calls <= 550);
    assert!(block_on(reader.read_path(HEAD, "../f000.txt")).is_err());
    assert!(
        block_on(reader.read_path(HEAD, "sub/missing"))
            .unwrap()
            .is_none()
    );
}
