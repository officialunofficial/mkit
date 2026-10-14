//! Sequential-round probe for embedder-shaped reads. Reports rounds, not a
//! latency gate: every storage call costs one virtual latency unit, run on a
//! paused clock under the production shared concurrency limiter, so
//! `rounds = virtual elapsed / latency` is the critical path through the
//! dependent chain. A ranged blob read is one call (set
//! `MKIT_BENCH_RANGED_HEAD` to model the earlier HEAD-then-GET pair). Print
//! the table with `--nocapture`.
use super::history_tests::{drain, get_count};
use super::*;
use crate::history_token::HistoryTokenConfig;
use crate::pipeline::{
    HistoryMode, HistoryOptions, ObjectReader, PathOptions, ReaderSession, ReaderView,
};
use crate::store::read_probe::{self, Config};
use std::collections::BTreeSet;

const LATENCY: u32 = 30;

#[derive(Clone, Copy, Debug)]
enum Op {
    Show { sizes: bool },
    Cat,
    ListRefs,
    GetReadGate,
    BeforeGetReadGate,
    Log(usize),
    Page1(usize),
    CanonicalLog(usize),
    SelectedLog(usize),
}

struct Shape {
    fx: Fx,
    head: Hash,
    commits: usize,
    root: Hash,
    dir: Option<Hash>,
    files: Vec<Hash>,
    path: Vec<Vec<u8>>,
    packs: Vec<Hash>,
}

/// `commits` linear commits over `files` root files (plus one nested file when
/// `nested`); in commit `n`, files below `changed(n)` take new content.
fn shape(commits: usize, files: usize, nested: bool, changed: impl Fn(usize) -> usize) -> Shape {
    let mut fx = fixture_tweaked(Hooks::new(), http_cfg(), |cfg| {
        cfg.sharding = Sharding::D34;
        cfg.takedown_denial = false;
    });
    fx.pipe
        .meta
        .count_partition_scans
        .store(true, Ordering::SeqCst);
    fx.pipe.cfg.history_tokens = Some(
        HistoryTokenConfig::new(
            zeroize::Zeroizing::new([101; 32]),
            "test-backend".into(),
            900_000,
        )
        .unwrap(),
    );
    let mut seen = BTreeSet::new();
    let mut packs = Vec::new();
    let (mut previous, mut parent) = (None, None);
    let mut last = None;
    for n in 0..commits {
        let mut objects = Vec::new();
        let names: Vec<String> = (0..files).map(|f| format!("f{f:03}")).collect();
        let blobs: Vec<Object> = (0..files)
            .map(|f| blob(format!("file {f} v{}", if f < changed(n) { n } else { 0 }).as_bytes()))
            .collect();
        let nested_blob = blob(b"nested leaf");
        let dir = tree(&[("leaf", EntryMode::Blob, &nested_blob)]);
        // Entries are byte-sorted: "dir" precedes "f000".
        let mut entries: Vec<(&str, EntryMode, &Object)> = Vec::new();
        if nested {
            entries.push(("dir", EntryMode::Tree, &dir));
        }
        entries.extend(
            names
                .iter()
                .zip(&blobs)
                .map(|(name, object)| (name.as_str(), EntryMode::Blob, object)),
        );
        let root = tree(&entries);
        let head = commit(&root, &parent.iter().collect::<Vec<_>>(), &format!("c{n}"));
        objects.extend(blobs.iter().cloned());
        if nested {
            objects.extend([nested_blob.clone(), dir.clone()]);
        }
        objects.extend([root.clone(), head.clone()]);
        let fresh: Vec<&Object> = objects.iter().filter(|o| seen.insert(id(o))).collect();
        let pack = fx.push("room", &fresh, id(&head), previous);
        packs.push(pack);
        drain(&fx);
        previous = Some((id(&head), pack));
        parent = Some(head.clone());
        let mut file_ids: Vec<Hash> = blobs.iter().map(id).collect();
        if nested {
            file_ids.push(id(&nested_blob));
        }
        last = Some(Shape {
            fx: fixture(),
            head: id(&head),
            commits: n + 1,
            root: id(&root),
            dir: nested.then(|| id(&dir)),
            files: file_ids,
            path: vec![b"dir".to_vec(), b"leaf".to_vec()],
            packs: Vec::new(),
        });
    }
    let mut shape = last.unwrap();
    shape.fx = fx;
    shape.packs = packs;
    shape
}

#[allow(clippy::too_many_lines)] // One probe driver covering every shape.
async fn run(
    shape: &Shape,
    owner: bool,
    op: Op,
    session: &mut ReaderSession,
) -> Result<(), crate::ServerError> {
    let fx = &shape.fx;
    let procedure = if matches!(op, Op::GetReadGate | Op::BeforeGetReadGate) {
        Procedure::PackExists
    } else {
        Procedure::ListRefs
    };
    let req = signed(&fx.owner, &fx.identity("room"), procedure, fx.number());
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
    if matches!(op, Op::ListRefs | Op::GetReadGate | Op::BeforeGetReadGate) {
        let request = if owner {
            req
        } else {
            Req::unsigned(procedure).header("x-repository", &fx.identity("room"))
        };
        let auth = fx.auth(&request);
        if matches!(op, Op::GetReadGate | Op::BeforeGetReadGate) {
            let key = PackKey::new(*shape.packs.last().unwrap());
            let visible = if matches!(op, Op::BeforeGetReadGate) {
                before_get_read_gate(fx, &auth, key).await?
            } else {
                fx.pipe.pack_exists(&auth, key).await?
            };
            assert!(visible);
        } else {
            let refs = fx.pipe.list_refs(&auth, "").await?;
            assert!(!refs.is_empty());
        }
        return Ok(());
    }
    let reader = fx
        .pipe
        .object_reader(
            fx.repo_id("room"),
            if owner {
                ReaderView::Owner(&meta)
            } else {
                ReaderView::Public
            },
        )
        .await?;
    match op {
        Op::Show { sizes } => {
            let mut levels = vec![vec![shape.head], vec![shape.root]];
            levels.extend(shape.dir.map(|dir| vec![dir]));
            for ids in levels {
                let answers = reader.read_canonical_in(session, &ids).await?;
                assert!(answers.iter().all(Option::is_some));
            }
            if sizes {
                let answers = reader.object_metadata_in(session, &shape.files).await?;
                assert!(answers.iter().all(Option::is_some));
            }
        }
        Op::ListRefs | Op::GetReadGate | Op::BeforeGetReadGate => unreachable!(),
        Op::Cat => {
            let read = reader
                .read_commit_path_in(
                    session,
                    HEAD,
                    shape.head,
                    &shape.path,
                    None,
                    PathOptions::default(),
                )
                .await?;
            assert!(read.is_some());
        }
        Op::Log(count) => {
            let page = reader
                .walk_history_in(
                    session,
                    HEAD,
                    None,
                    count,
                    HistoryOptions {
                        mode: HistoryMode::FirstParent,
                        ..HistoryOptions::default()
                    },
                )
                .await?
                .unwrap();
            assert_eq!(page.commits.len(), count.min(shape.commits));
        }
        Op::Page1(size) => {
            let page = reader
                .walk_history_page_in(session, HEAD, None, size)
                .await?
                .unwrap();
            assert_eq!(page.commits.len(), size.min(shape.commits));
        }
        Op::CanonicalLog(count) => canonical_log(&reader, session, shape.head, count).await?,
        Op::SelectedLog(count) => {
            let reader = reader.with_selected_ref(HEAD)?;
            let checkpoint = reader.selected_capture_in(session).await?.unwrap();
            assert_eq!(checkpoint.tip(), shape.head);
            canonical_log(&reader, session, checkpoint.tip(), count).await?;
        }
    }
    Ok(())
}

/// The embedder's page-1 loop: walk first parents through canonical reads.
async fn canonical_log(
    reader: &ObjectReader<'_, SpyBlobs, Arc<Spy>, Hooks>,
    session: &mut ReaderSession,
    head: Hash,
    count: usize,
) -> Result<(), crate::ServerError> {
    let mut current = head;
    for _ in 0..count {
        let bytes = reader
            .read_canonical_in(session, &[current])
            .await?
            .into_iter()
            .next()
            .flatten()
            .unwrap();
        let Object::Commit(commit) = mkit_core::serialize::deserialize(&bytes).unwrap() else {
            panic!("expected a commit");
        };
        current = commit.parents[0];
    }
    Ok(())
}

/// Rounds, KV calls and blob GETs of one operation.
fn measure(shape: &Shape, owner: bool, op: Op) -> (f64, u32, usize) {
    measure_latency(shape, owner, op, LATENCY, None, false)
}
fn measure_latency(
    shape: &Shape,
    owner: bool,
    op: Op,
    latency: u32,
    cold: Option<u64>,
    warm_packs: bool,
) -> (f64, u32, usize) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .start_paused(true)
        .build()
        .unwrap();
    let fx = &shape.fx;
    let (kv, gets) = (fx.pipe.meta.calls(), get_count(fx));
    fx.pipe.meta.touched.lock().unwrap().clear();
    fx.pipe.meta.seen.lock().unwrap().clear();
    fx.pipe
        .meta
        .latency_ms
        .store(u64::from(latency), Ordering::SeqCst);
    fx.pipe
        .blobs
        .latency_ms
        .store(u64::from(latency), Ordering::SeqCst);
    let trace = Arc::new(Mutex::new(Vec::new()));
    let mut session = ReaderSession::default();
    let start = runtime.block_on(async { tokio::time::Instant::now() });
    let operation = read_probe::run(
        Config {
            concurrency: crate::store::read_io::PARALLELISM,
            trace: trace.clone(),
        },
        Box::pin(run(shape, owner, op, &mut session)),
    );
    let warm_partitions = if warm_packs {
        shape
            .packs
            .iter()
            .map(crate::store::content_shard)
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let operation = async {
        if let Some(milliseconds) = cold {
            read_probe::run_cold(milliseconds, &warm_partitions, operation).await
        } else {
            operation.await
        }
    };
    runtime.block_on(operation).unwrap();
    if !fx.pipe.cfg.takedown_denial && !matches!(op, Op::BeforeGetReadGate) {
        assert_no_denial_rows(&fx.pipe.meta.seen());
    }
    let elapsed = runtime.block_on(async { tokio::time::Instant::now() - start });
    fx.pipe.meta.latency_ms.store(0, Ordering::SeqCst);
    fx.pipe.blobs.latency_ms.store(0, Ordering::SeqCst);
    let rounds = elapsed.as_secs_f64() * 1000.0 / f64::from(latency);
    let partitions: BTreeSet<Partition> = fx
        .pipe
        .meta
        .touched
        .lock()
        .unwrap()
        .iter()
        .cloned()
        .collect();
    let mut by_kind = std::collections::BTreeMap::<&str, usize>::new();
    for partition in &partitions {
        *by_kind.entry(partition.kind()).or_default() += 1;
    }
    if let Some(cold) = cold {
        println!(
            "COLD_LOG owner={owner} op={op:?} source_packs_warm={warm_packs} warm_ms={latency} cold_ms={cold} elapsed_ms={} KV={} GET={}",
            elapsed.as_millis(),
            fx.pipe.meta.calls() - kv,
            get_count(fx) - gets
        );
    } else {
        println!(
            "READ_ROUNDS denial={} owner={owner} op={op:?} rounds={rounds:.0} KV={} GET={} partitions={} by_kind={by_kind:?} phases={}",
            fx.pipe.cfg.takedown_denial,
            fx.pipe.meta.calls() - kv,
            get_count(fx) - gets,
            partitions.len(),
            read_probe::summary(&trace.lock().unwrap())
        );
    }
    println!(
        "READ_LEDGER op={op:?} session_calls={} remaining={}",
        session.io.calls.used(),
        session.io.calls.remaining()
    );
    (rounds, fx.pipe.meta.calls() - kv, get_count(fx) - gets)
}

/// Rounds of a public reader with takedown denial off, on the baseline this
/// probe was written against, and the ceilings the shapes must stay under. The
/// ceilings are a regression guard with slack, not a latency promise: a ranged
/// blob read counts as one call here.
const BASELINE: [(&str, u32); 5] = [
    ("A1 show with sizes", 59),
    ("A2 cat", 46),
    ("B1 show", 47),
    ("B2 log of 5", 54),
    ("C1 log of 50", 621),
];
const CEILING: [u32; 5] = [38, 34, 30, 38, 420];

// Measured before this change on the same runtime, in denial/view/operation order.
// No row may increase KV calls.
const MEASURED_BASELINE: [[(u32, u32); 13]; 4] = [
    [
        (34, 68),
        (30, 38),
        (24, 37),
        (25, 56),
        (34, 52),
        (42, 64),
        (80, 124),
        (84, 129),
        (4, 17),
        (380, 603),
        (383, 607),
        (73, 86),
        (73, 73),
    ],
    [
        (31, 69),
        (31, 39),
        (22, 38),
        (24, 57),
        (35, 53),
        (43, 65),
        (81, 125),
        (84, 129),
        (4, 17),
        (381, 604),
        (384, 608),
        (64, 87),
        (74, 74),
    ],
    [
        (49, 135),
        (50, 114),
        (36, 88),
        (36, 106),
        (60, 156),
        (73, 190),
        (139, 360),
        (142, 364),
        (4, 17),
        (659, 1719),
        (662, 1723),
        (113, 256),
        (113, 243),
    ],
    [
        (46, 136),
        (51, 115),
        (34, 89),
        (35, 107),
        (61, 157),
        (74, 191),
        (140, 361),
        (143, 365),
        (4, 17),
        (660, 1720),
        (663, 1724),
        (104, 257),
        (114, 244),
    ],
];

#[test]
fn embedder_read_shapes_report_rounds() {
    let mut a = shape(1, 8, true, |_| 8);
    let mut b = shape(4, 6, false, |n| n);
    let mut c = shape(52, 2, false, |_| 1);
    for denial in [false, true] {
        for shape in [&mut a, &mut b, &mut c] {
            shape.fx.pipe.cfg.takedown_denial = denial;
        }
        for owner in [false, true] {
            let baseline = &MEASURED_BASELINE[usize::from(denial) * 2 + usize::from(owner)];
            let mut guarded = Vec::new();
            for (row, (shape, op, guard)) in [
                (&a, Op::Show { sizes: true }, true),
                (&a, Op::Cat, true),
                (&a, Op::Show { sizes: false }, false),
                (&b, Op::Show { sizes: true }, true),
                (&b, Op::Log(5), true),
                (&c, Op::Log(5), false),
                (&c, Op::Log(10), false),
                (&c, Op::Page1(10), false),
                (&c, Op::ListRefs, false),
                (&c, Op::Log(50), true),
                (&c, Op::Page1(50), false),
                (&c, Op::CanonicalLog(10), false),
                (&c, Op::SelectedLog(10), false),
            ]
            .into_iter()
            .enumerate()
            {
                let (rounds, kv, _) = measure(shape, owner, op);
                let (old_rounds, old_kv) = baseline[row];
                if std::env::var_os("MKIT_BENCH_RANGED_HEAD").is_none() {
                    assert!(
                        rounds.round() <= f64::from(old_rounds),
                        "{op:?}: rounds increased from {old_rounds} to {rounds}"
                    );
                }
                if denial && std::env::var_os("MKIT_BENCH_RANGED_HEAD").is_none() {
                    assert!(
                        (rounds.round() - f64::from(old_rounds)).abs() < f64::EPSILON,
                        "{op:?}: denial-on rounds changed"
                    );
                    assert_eq!(kv, old_kv, "{op:?}: denial-on KV calls changed");
                }
                assert!(
                    kv <= old_kv,
                    "{op:?}: KV calls increased from {old_kv} to {kv}"
                );
                println!(
                    "ROUND_DELTA denial={denial} owner={owner} row={row} op={op:?} rounds_before={old_rounds} rounds_after={rounds:.0} KV_before={old_kv} KV_after={kv} KV_delta={}",
                    i64::from(kv) - i64::from(old_kv)
                );
                if guard {
                    guarded.push(rounds);
                }
            }
            let (rounds, kv, _) = measure(&c, owner, Op::GetReadGate);
            if !denial {
                let (before_rounds, before_kv, _) = measure(&c, owner, Op::BeforeGetReadGate);
                assert!((before_rounds - rounds - 1.0).abs() < f64::EPSILON);
                assert_eq!(before_kv, kv + 1);
                println!(
                    "ROUND_DELTA denial={denial} owner={owner} op=GetReadGate rounds_before={before_rounds:.0} rounds_after={rounds:.0} KV_before={before_kv} KV_after={kv}"
                );
            }
            if !denial && !owner && std::env::var_os("MKIT_BENCH_RANGED_HEAD").is_none() {
                for ((name, baseline), (rounds, ceiling)) in
                    BASELINE.iter().zip(guarded.iter().zip(CEILING))
                {
                    assert!(
                        *rounds <= f64::from(ceiling),
                        "{name}: {rounds} rounds, ceiling {ceiling} (baseline {baseline})"
                    );
                }
            }
        }
    }
}

/// Reports the modeled cold first-touch cost of the unchanged serial Log walk.
#[test]
fn first_parent_log_models_cold_first_touches() {
    let history = shape(11, 2, false, |_| 1);
    measure(&history, false, Op::Page1(1));
    for cold in [300, 500] {
        for warm_packs in [false, true] {
            for op in [Op::Log(10), Op::Page1(10)] {
                let (rounds, _, _) =
                    measure_latency(&history, false, op, 50, Some(cold), warm_packs);
                assert!(rounds > 0.0);
            }
        }
    }
}

#[path = "denial_off_reads.rs"]
mod denial_off_reads;

/// Exact block/action rows, excluding the descriptor directories and chunk pages.
pub(super) fn assert_no_denial_rows(seen: &[Key]) {
    for key in seen {
        let bytes = key.as_bytes();
        assert!(
            !(bytes.starts_with(b"b\0")
                && (bytes.len() == 34 || (bytes.len() == 42 && bytes.ends_with(b"\0actions")))),
            "denial disabled read a block or action row: {key:?}"
        );
    }
}

/// Empty-denial-index model of the former pack-serving gate. Restore its unconditional
/// block/action lookup at the membership-to-blob boundary; all other work uses
/// the same production helpers as the current gate. This runs only with denial
/// disabled, so the restored lookup is exactly one sequential KV round.
async fn before_get_read_gate(
    fx: &Fx,
    auth: &Authenticated,
    key: PackKey,
) -> Result<bool, ServerError> {
    assert!(!fx.pipe.cfg.takedown_denial);
    let op = fx.pipe.identify(auth, OpKind::PackExists { key })?;
    let authorized = fx.pipe.authorize_read(&op).await?;
    if !fx
        .pipe
        .pack_is_member(auth, &key, authorized.facts.caller_view)
        .await?
    {
        return Ok(false);
    }
    crate::takedown::denial::require_clear(&fx.pipe.meta, &key.0).await?;
    Ok(fx.pipe.blobs.head(&key.into()).await.unwrap().is_some())
}
