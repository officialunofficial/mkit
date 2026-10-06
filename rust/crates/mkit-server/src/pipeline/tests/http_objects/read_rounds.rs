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
use crate::pipeline::{HistoryMode, HistoryOptions, PathOptions, ReaderSession, ReaderView};
use crate::store::read_probe::{self, Config};
use std::collections::BTreeSet;

const LATENCY: u32 = 30;

#[derive(Clone, Copy, Debug)]
enum Op {
    Show { sizes: bool },
    Cat,
    Log(usize),
    Page1(usize),
}

struct Shape {
    fx: Fx,
    head: Hash,
    commits: usize,
    root: Hash,
    dir: Option<Hash>,
    files: Vec<Hash>,
    path: Vec<Vec<u8>>,
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
        });
    }
    let mut shape = last.unwrap();
    shape.fx = fx;
    shape
}

async fn run(
    shape: &Shape,
    owner: bool,
    op: Op,
    session: &mut ReaderSession,
) -> Result<(), crate::ServerError> {
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
    }
    Ok(())
}

/// Rounds, KV calls and blob GETs of one operation.
fn measure(shape: &Shape, owner: bool, op: Op) -> (f64, u32, usize) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .start_paused(true)
        .build()
        .unwrap();
    let fx = &shape.fx;
    let (kv, gets) = (fx.pipe.meta.calls(), get_count(fx));
    fx.pipe.meta.touched.lock().unwrap().clear();
    fx.pipe
        .meta
        .latency_ms
        .store(u64::from(LATENCY), Ordering::SeqCst);
    fx.pipe
        .blobs
        .latency_ms
        .store(u64::from(LATENCY), Ordering::SeqCst);
    let trace = Arc::new(Mutex::new(Vec::new()));
    let mut session = ReaderSession::default();
    let start = runtime.block_on(async { tokio::time::Instant::now() });
    runtime
        .block_on(read_probe::run(
            Config {
                concurrency: crate::store::read_io::PARALLELISM,
                trace: trace.clone(),
            },
            run(shape, owner, op, &mut session),
        ))
        .unwrap();
    let elapsed = runtime.block_on(async { tokio::time::Instant::now() - start });
    fx.pipe.meta.latency_ms.store(0, Ordering::SeqCst);
    fx.pipe.blobs.latency_ms.store(0, Ordering::SeqCst);
    let rounds = elapsed.as_secs_f64() * 1000.0 / f64::from(LATENCY);
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
    println!(
        "READ_ROUNDS denial={} owner={owner} op={op:?} rounds={rounds:.0} KV={} GET={} partitions={} by_kind={by_kind:?} phases={}",
        fx.pipe.cfg.takedown_denial,
        fx.pipe.meta.calls() - kv,
        get_count(fx) - gets,
        partitions.len(),
        read_probe::summary(&trace.lock().unwrap())
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
            let mut guarded = Vec::new();
            for (shape, op, guard) in [
                (&a, Op::Show { sizes: true }, true),
                (&a, Op::Cat, true),
                (&a, Op::Show { sizes: false }, false),
                (&b, Op::Show { sizes: true }, true),
                (&b, Op::Log(5), true),
                (&c, Op::Log(5), false),
                (&c, Op::Log(10), false),
                (&c, Op::Log(50), true),
                (&c, Op::Page1(50), false),
            ] {
                let (rounds, ..) = measure(shape, owner, op);
                if guard {
                    guarded.push(rounds);
                }
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
