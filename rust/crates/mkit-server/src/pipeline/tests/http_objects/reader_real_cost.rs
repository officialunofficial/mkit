//! Embedder-shaped latency probes. They deliberately do not assert a latency gate.
use super::*;
use crate::pipeline::{ReadLimits, ReaderSession, ReaderView};
use crate::store::read_probe::{self, Config};
use std::collections::{BTreeMap, BTreeSet};
const BASELINE: bool = false;

struct Snapshot {
    head: Hash,
    levels: Vec<Vec<Hash>>,
    leaf: Hash,
}
struct Fixture {
    fx: Fx,
    snapshots: Vec<Snapshot>,
    expected: BTreeMap<Hash, Vec<u8>>,
}
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
fn fixture_shape(history: usize, levels: usize, files: usize, branches: usize) -> Fixture {
    let mut fx = fixture_tweaked(Hooks::new(), http_cfg(), |cfg| {
        cfg.sharding = Sharding::D34;
        cfg.takedown_denial = false;
    });
    fx.pipe
        .meta
        .count_partition_scans
        .store(true, Ordering::SeqCst);
    let mut expected = BTreeMap::new();
    let mut snapshots = Vec::new();
    let mut parent = None;
    let mut previous = None;
    for n in 0..history {
        let mut objects = Vec::new();
        let mut ids = vec![Vec::new(); levels];
        let mut root_entries = Vec::new();
        let mut first_leaf = None;
        for branch in 0..branches {
            let mut child = None;
            for level in (1..levels).rev() {
                let entries = if level + 1 == levels {
                    (0..files / branches + usize::from(branch < files % branches))
                        .map(|f| {
                            let object = blob(
                                format!(
                                    "branch {branch} change {} file {f}",
                                    if branch == 0 { n } else { 0 }
                                )
                                .as_bytes(),
                            );
                            let hash = id(&object);
                            if branch == 0 && f == 0 {
                                first_leaf = Some(hash);
                            }
                            objects.push(object);
                            TreeEntry {
                                name: format!("f{f:03}.txt").into_bytes(),
                                mode: EntryMode::Blob,
                                object_hash: hash,
                            }
                        })
                        .collect()
                } else {
                    vec![TreeEntry {
                        name: b"sub".to_vec(),
                        mode: EntryMode::Tree,
                        object_hash: child.unwrap(),
                    }]
                };
                let tree = Object::Tree(Tree { entries });
                let hash = id(&tree);
                ids[level].push(hash);
                objects.push(tree);
                child = Some(hash);
            }
            root_entries.push(TreeEntry {
                name: format!("b{branch:02}").into_bytes(),
                mode: EntryMode::Tree,
                object_hash: child.unwrap(),
            });
        }
        let tree = Object::Tree(Tree {
            entries: root_entries,
        });
        ids[0].push(id(&tree));
        objects.push(tree.clone());
        let commit = commit(
            &tree,
            &parent.iter().collect::<Vec<_>>(),
            &format!("change {n}"),
        );
        let head = id(&commit);
        objects.push(commit.clone());
        let new: Vec<_> = objects
            .iter()
            .filter(|o| !expected.contains_key(&id(o)))
            .collect();
        let pack = fx.push("room", &new, head, previous);
        drain(&fx);
        previous = Some((head, pack));
        parent = Some(commit);
        snapshots.push(Snapshot {
            head,
            levels: ids,
            leaf: first_leaf.unwrap(),
        });
        for object in objects {
            expected.insert(id(&object), serialize(&object).unwrap());
        }
    }
    fx.pipe.cfg.takedown_denial = std::env::var_os("MKIT_BENCH_DENIAL_ON").is_some();
    let latency = crate::store::read_probe::latency_ms();
    fx.pipe.meta.latency_ms.store(latency, Ordering::SeqCst);
    fx.pipe.blobs.latency_ms.store(latency, Ordering::SeqCst);
    Fixture {
        fx,
        snapshots,
        expected,
    }
}
#[derive(Clone, Copy)]
enum Work {
    Show,
    Diff(usize),
    Log(usize, usize),
    Cat,
}
#[derive(Default, Debug)]
struct Stats {
    diff_tree_ms: Option<f64>,
    diff_tree_model_ms: Option<f64>,
    metadata_model_ms: Option<f64>,
    canonical: usize,
    metadata: usize,
    canonical_batches: usize,
    metadata_batches: usize,
}
async fn read_ids(
    reader: &crate::pipeline::ObjectReader<'_, SpyBlobs, Arc<Spy>, Hooks>,
    session: &mut ReaderSession,
    ids: &[Hash],
    limit: usize,
    expected: &BTreeMap<Hash, Vec<u8>>,
    stats: &mut Stats,
) -> Result<BTreeMap<Hash, Object>, crate::ServerError> {
    let mut objects = BTreeMap::new();
    for batch in ids.chunks(limit) {
        stats.canonical_batches += 1;
        let answers = reader.read_canonical_in(session, batch).await?;
        for (id, bytes) in batch.iter().zip(answers) {
            let bytes =
                bytes.ok_or_else(|| crate::ServerError::unavailable("expected object absent"))?;
            assert_eq!(bytes, expected[id]);
            objects.insert(*id, mkit_core::serialize::deserialize(&bytes).unwrap());
            stats.canonical += 1;
        }
    }
    Ok(objects)
}
async fn cat_driver(
    f: &Fixture,
    reader: &crate::pipeline::ObjectReader<'_, SpyBlobs, Arc<Spy>, Hooks>,
    session: &mut ReaderSession,
) -> Result<(), crate::ServerError> {
    let path = format!("b00/{}f000.txt", "sub/".repeat(9));
    let (hash, bytes) = reader
        .read_path_in(session, HEAD, &path)
        .await?
        .ok_or_else(|| crate::ServerError::unavailable("expected path absent"))?;
    assert_eq!(hash, f.snapshots.last().unwrap().leaf);
    assert_eq!(bytes, f.expected[&hash]);
    Ok(())
}
#[allow(clippy::too_many_lines)] // One exact-data driver for the four embedder workload shapes.
async fn perform(
    f: &Fixture,
    work: Work,
    limit: usize,
) -> (Result<(), crate::ServerError>, Stats, ReadLimits) {
    let fx = &f.fx;
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
    let mut session = ReaderSession::default();
    let mut stats = Stats::default();
    let result = async {
        let reader = fx
            .pipe
            .object_reader(fx.repo_id("room"), ReaderView::Owner(&meta))
            .await?
            .with_batch_limit(limit)?;
        let newest = f.snapshots.last().unwrap();
        match work {
            Work::Cat => {
                cat_driver(f, &reader, &mut session).await?;
                stats.canonical = 1;
            }
            Work::Log(offset, count) => {
                let mut pending = vec![f.snapshots[f.snapshots.len() - 1 - offset].head];
                let mut seen = BTreeSet::new();
                let mut returned = 0;
                while !pending.is_empty() && returned < count {
                    pending.retain(|id| seen.insert(*id));
                    pending.truncate(count - returned);
                    let objects = read_ids(
                        &reader,
                        &mut session,
                        &pending,
                        limit,
                        &f.expected,
                        &mut stats,
                    )
                    .await?;
                    pending.clear();
                    for object in objects.values() {
                        let Object::Commit(c) = object else {
                            panic!("log expected commits")
                        };
                        pending.extend(c.parents.iter().copied().filter(|id| !seen.contains(id)));
                        returned += 1;
                    }
                }
                assert_eq!(returned, count);
            }
            Work::Diff(distance) => {
                // Resolve the older commit by actual parent edges; no snapshot tree/file prefetch.
                let mut current = newest.head;
                let mut endpoints = Vec::new();
                for step in 0..=distance {
                    let objects = read_ids(
                        &reader,
                        &mut session,
                        &[current],
                        limit,
                        &f.expected,
                        &mut stats,
                    )
                    .await?;
                    let Object::Commit(c) = &objects[&current] else {
                        panic!("expected commit")
                    };
                    if step == 0 || step == distance {
                        endpoints.push(c.tree_hash);
                    }
                    if step < distance {
                        current = c.parents[0];
                    }
                }
                let tree_start = std::time::Instant::now();
                let tree_model_start = tokio::time::Instant::now();
                let mut pairs = vec![(endpoints[0], endpoints[1])];
                while !pairs.is_empty() {
                    let unique: BTreeSet<_> = pairs.iter().flat_map(|(a, b)| [*a, *b]).collect();
                    let objects = read_ids(
                        &reader,
                        &mut session,
                        &unique.into_iter().collect::<Vec<_>>(),
                        limit,
                        &f.expected,
                        &mut stats,
                    )
                    .await?;
                    let mut next = Vec::new();
                    for (a, b) in pairs {
                        let (Object::Tree(a), Object::Tree(b)) = (&objects[&a], &objects[&b])
                        else {
                            panic!("expected tree pair")
                        };
                        let old: BTreeMap<_, _> = b.entries.iter().map(|e| (&e.name, e)).collect();
                        for entry in &a.entries {
                            if entry.mode != EntryMode::Tree {
                                continue;
                            }
                            if let Some(other) = old.get(&entry.name)
                                && other.mode == EntryMode::Tree
                                && entry.object_hash != other.object_hash
                            {
                                next.push((entry.object_hash, other.object_hash));
                            }
                        }
                    }
                    pairs = next;
                }
                stats.diff_tree_ms = Some(tree_start.elapsed().as_secs_f64() * 1000.0);
                stats.diff_tree_model_ms = Some(tree_model_start.elapsed().as_secs_f64() * 1000.0);
                assert_eq!(stats.canonical, distance + 1 + 8);
                assert_eq!(stats.metadata, 0);
            }
            Work::Show => {
                read_ids(
                    &reader,
                    &mut session,
                    &[newest.head],
                    limit,
                    &f.expected,
                    &mut stats,
                )
                .await?;
                let mut files = BTreeSet::new();
                for ids in &newest.levels {
                    let objects =
                        read_ids(&reader, &mut session, ids, limit, &f.expected, &mut stats)
                            .await?;
                    for object in objects.values() {
                        let Object::Tree(tree) = object else {
                            panic!("expected tree")
                        };
                        files.extend(
                            tree.entries
                                .iter()
                                .filter(|e| e.mode != EntryMode::Tree)
                                .map(|e| e.object_hash),
                        );
                    }
                }
                let files: Vec<_> = files.into_iter().collect();
                if matches!(work, Work::Show) {
                    let metadata_start = tokio::time::Instant::now();
                    for batch in files.chunks(limit) {
                        stats.metadata_batches += 1;
                        for (hash, answer) in batch
                            .iter()
                            .zip(reader.object_metadata_in(&mut session, batch).await?)
                        {
                            let answer = answer.ok_or_else(|| {
                                crate::ServerError::unavailable("expected metadata absent")
                            })?;
                            assert_eq!(answer.canonical_len, f.expected[hash].len() as u64);
                            assert_eq!(
                                answer.logical_len,
                                Some(f.expected[hash].len() as u64 - 10)
                            );
                            stats.metadata += 1;
                        }
                    }
                    stats.metadata_model_ms = Some(metadata_start.elapsed().as_secs_f64() * 1000.0);
                }
            }
        }
        Ok(())
    }
    .await;
    (result, stats, session.used())
}
async fn sample(
    f: &Fixture,
    work: Work,
    name: &str,
    ids: usize,
    concurrency: usize,
    sample: usize,
    virtual_time: bool,
) {
    let trace = Arc::new(Mutex::new(Vec::new()));
    let config = Config {
        concurrency,
        trace: trace.clone(),
    };
    let start = std::time::Instant::now();
    let (result, stats, used) = Box::pin(read_probe::run(config, perform(f, work, ids))).await;
    let elapsed = start.elapsed();
    let trace = trace.lock().unwrap();
    let model_ms = trace
        .iter()
        .map(|e| e.end)
        .max()
        .zip(trace.iter().map(|e| e.start).min())
        .map_or(0., |(end, start)| (end - start).as_secs_f64() * 1000.);
    println!(
        "REAL_COST {}",
        serde_json::json!({"baseline":BASELINE,"denial":f.fx.pipe.cfg.takedown_denial,"name":name,"ids":ids,"concurrency":concurrency,"sample":sample,"virtual":virtual_time,"elapsed_ms":elapsed.as_secs_f64()*1000.,"model_ms":model_ms,"result":result.as_ref().err().map(|e| format!("{:?}: {}",e.code(),e.public_message())),"canonical":stats.canonical,"metadata":stats.metadata,"diff_tree_ms":stats.diff_tree_ms,"diff_tree_model_ms":stats.diff_tree_model_ms,"metadata_model_ms":stats.metadata_model_ms,"canonical_batches":stats.canonical_batches,"metadata_batches":stats.metadata_batches,"ledger":used.storage_calls,"decoded":used.decoded_bytes,"encoded":used.encoded_bytes,"phases":read_probe::summary(&trace)})
    );
    if !matches!(work, Work::Log(_, count) if count > 30) {
        result.expect("accepted measured workload must complete successfully");
    }
}
fn measure_matrix(ids: usize, concurrency: usize) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    let virtual_runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .start_paused(true)
        .build()
        .unwrap();
    let mut fixtures = vec![
        (
            "show_h3",
            fixture_shape(3, 5, 300, 4),
            vec![("show_h3".to_string(), Work::Show)],
        ),
        (
            "show_h16",
            fixture_shape(16, 5, 300, 4),
            vec![("show_h16".to_string(), Work::Show)],
        ),
        (
            "diff",
            fixture_shape(17, 4, 300, 4),
            vec![("diff_16_apart".to_string(), Work::Diff(16))],
        ),
        (
            "cat",
            fixture_shape(3, 11, 300, 4),
            vec![("deep_cat".to_string(), Work::Cat)],
        ),
        (
            "log",
            fixture_shape(100, 5, 300, 4),
            vec![
                ("log100_page1".to_string(), Work::Log(0, 100)),
                ("log30_page1".to_string(), Work::Log(0, 30)),
            ],
        ),
    ];
    let only = std::env::var("MKIT_BENCH_ONLY").ok();
    if let Some(only) = only {
        for (_, _, cases) in &mut fixtures {
            cases.retain(|(name, _)| only.split(',').any(|filter| name.contains(filter)));
        }
    }
    for (_, fixture, cases) in &fixtures {
        for (name, work) in cases {
            virtual_runtime.block_on(sample(fixture, *work, name, ids, concurrency, 0, true));
        }
    }
    if std::env::var_os("MKIT_BENCH_VIRTUAL_ONLY").is_some() {
        return;
    }
    runtime.block_on(async {
        if std::env::var_os("MKIT_BENCH_SEQUENTIAL").is_some() {
            for (_, fixture, cases) in &fixtures {
                for (name, work) in cases {
                    for run in 1..=3 {
                        sample(fixture, *work, name, ids, concurrency, run, false).await;
                    }
                }
            }
            return;
        }
        let mut jobs = Vec::new();
        for (_, fixture, cases) in &fixtures {
            for (name, work) in cases {
                for run in 1..=3 {
                    jobs.push(sample(fixture, *work, name, ids, concurrency, run, false));
                }
            }
        }
        futures::future::join_all(jobs).await;
    });
}
#[test]
fn measure_16_6() {
    measure_matrix(16, 6);
}
#[test]
fn measure_16_16() {
    measure_matrix(16, 16);
}
#[test]
fn measure_16_32() {
    measure_matrix(16, 32);
}
#[test]
fn measure_45_6() {
    measure_matrix(45, 6);
}
#[test]
fn measure_45_16() {
    measure_matrix(45, 16);
}
#[test]
fn measure_45_32() {
    measure_matrix(45, 32);
}
