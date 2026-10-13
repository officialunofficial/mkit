//! Multi-writer ref compare-and-swap contention.
//!
//! Every writer loops `read_ref` then `update_ref(Match(old), new)` until it
//! lands `OPS` advances. Reports advances/s, attempts per advance and the
//! p50/p99/max latency of one landed advance (retries included). After each
//! run the (old, new) edges are checked to form one linear chain, so a lost
//! update fails the run.
//!
//! Env: `CAS_OPS` (advances per writer, default per backend), `CAS_THREADS`
//! (comma list), `CAS_BACKENDS` (comma list of memory,file,local).

use mkit_core::hash::{Hash, hash};
use mkit_core::layout::RepoLayout;
use mkit_core::protocol::Transport;
use mkit_core::refs::{self, RefError, RefWriteCondition};
use mkit_transport_file::FileTransport;
use mkit_transport_memory::MemoryTransport;
use std::collections::HashMap;
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

type Cas = dyn Fn(&Hash, &Hash) -> bool + Send + Sync; // true = landed, false = conflict
type Read = dyn Fn() -> Option<Hash> + Send + Sync;

struct Backend {
    name: &'static str,
    default_ops: usize,
    /// `fresh(ref_name)` seeds the ref and returns read/cas closures.
    fresh: Box<dyn Fn(&str, &Hash) -> (Arc<Read>, Arc<Cas>, Box<dyn std::any::Any>)>,
}

#[derive(Clone, Copy)]
enum Policy {
    Spin,
    Backoff,
}

struct Result_ {
    secs: f64,
    attempts: u64,
    lat: Vec<Duration>,
    edges: Vec<(Hash, Hash)>,
}

fn run(
    read: Arc<Read>,
    cas: Arc<Cas>,
    threads: usize,
    ops: usize,
    policy: Policy,
    distinct: bool,
    names: &[String],
    mk: &dyn Fn(&str) -> (Arc<Read>, Arc<Cas>),
) -> Result_ {
    let barrier = Arc::new(Barrier::new(threads + 1));
    let mut handles = Vec::new();
    for t in 0..threads {
        let (read, cas) = if distinct {
            mk(&names[t])
        } else {
            (read.clone(), cas.clone())
        };
        let barrier = barrier.clone();
        handles.push(std::thread::spawn(move || {
            let mut lat = Vec::with_capacity(ops);
            let mut edges = Vec::with_capacity(ops);
            let mut attempts = 0u64;
            let mut rng = 0x9E37_79B9_7F4A_7C15u64 ^ (t as u64 + 1);
            barrier.wait();
            for i in 0..ops {
                let start = Instant::now();
                let mut fails = 0u32;
                loop {
                    attempts += 1;
                    let old = read().expect("seeded ref");
                    let mut buf = [0u8; 48];
                    buf[..32].copy_from_slice(&old);
                    buf[32..40].copy_from_slice(&(t as u64).to_le_bytes());
                    buf[40..].copy_from_slice(&(i as u64).to_le_bytes());
                    let new = hash(&buf);
                    if cas(&old, &new) {
                        edges.push((old, new));
                        break;
                    }
                    fails += 1;
                    if let Policy::Backoff = policy {
                        rng ^= rng << 13;
                        rng ^= rng >> 7;
                        rng ^= rng << 17;
                        let cap_us = 20u64 << fails.min(8);
                        std::thread::sleep(Duration::from_micros(rng % cap_us));
                    }
                }
                lat.push(start.elapsed());
            }
            (attempts, lat, edges)
        }));
    }
    barrier.wait();
    let t0 = Instant::now();
    let mut attempts = 0;
    let mut lat = Vec::new();
    let mut edges = Vec::new();
    for h in handles {
        let (a, l, e) = h.join().unwrap();
        attempts += a;
        lat.extend(l);
        edges.extend(e);
    }
    Result_ { secs: t0.elapsed().as_secs_f64(), attempts, lat, edges }
}

fn check_chain(seed: &Hash, edges: &[(Hash, Hash)], expect: usize) {
    let mut next: HashMap<Hash, Hash> = HashMap::new();
    for (o, n) in edges {
        assert!(next.insert(*o, *n).is_none(), "lost update: two writers advanced the same old value");
    }
    let (mut cur, mut len) = (*seed, 0);
    while let Some(n) = next.get(&cur) {
        cur = *n;
        len += 1;
    }
    assert_eq!(len, expect, "chain broken");
}

fn pct(v: &mut [Duration], p: f64) -> Duration {
    v.sort_unstable();
    v[(((v.len() - 1) as f64) * p) as usize]
}

fn main() {
    let env_list = |k: &str| std::env::var(k).ok().map(|s| s.split(',').map(str::to_owned).collect::<Vec<_>>());
    let threads: Vec<usize> = env_list("CAS_THREADS")
        .map(|v| v.iter().map(|s| s.parse().unwrap()).collect())
        .unwrap_or_else(|| vec![1, 2, 4, 8, 16, 32]);
    let want = env_list("CAS_BACKENDS").unwrap_or_else(|| vec!["memory".into(), "file".into(), "local".into()]);
    let ops_env: Option<usize> = std::env::var("CAS_OPS").ok().map(|s| s.parse().unwrap());

    let backends: Vec<Backend> = vec![
        Backend {
            name: "memory",
            default_ops: 5_000,
            fresh: Box::new(|name, seed| {
                let t = Arc::new(MemoryTransport::new());
                t.update_ref(name, RefWriteCondition::Missing, seed).unwrap();
                let (n1, n2) = (name.to_owned(), name.to_owned());
                let (t1, t2) = (t.clone(), t.clone());
                (
                    Arc::new(move || t1.read_ref(&n1).unwrap()),
                    Arc::new(move |o, n| t2.update_ref(&n2, RefWriteCondition::Match(*o), n).is_ok()),
                    Box::new(t),
                )
            }),
        },
        Backend {
            name: "file",
            default_ops: 150,
            fresh: Box::new(|name, seed| {
                let dir = tempfile::tempdir().unwrap();
                let t = Arc::new(FileTransport::new(dir.path()));
                t.update_ref(name, RefWriteCondition::Missing, seed).unwrap();
                let (n1, n2) = (name.to_owned(), name.to_owned());
                let (t1, t2) = (t.clone(), t.clone());
                (
                    Arc::new(move || t1.read_ref(&n1).unwrap()),
                    Arc::new(move |o, n| t2.update_ref(&n2, RefWriteCondition::Match(*o), n).is_ok()),
                    Box::new((t, dir)),
                )
            }),
        },
        Backend {
            name: "local",
            default_ops: 150,
            fresh: Box::new(|name, seed| {
                let dir = tempfile::tempdir().unwrap();
                let layout = Arc::new(RepoLayout::single(dir.path()));
                refs::init(&layout).unwrap();
                refs::update_ref(&layout, name, RefWriteCondition::Missing, seed).unwrap();
                let (n1, n2) = (name.to_owned(), name.to_owned());
                let (l1, l2) = (layout.clone(), layout.clone());
                (
                    Arc::new(move || refs::read_ref(&l1, &n1).unwrap()),
                    Arc::new(move |o, n| match refs::update_ref(&l2, &n2, RefWriteCondition::Match(*o), n) {
                        Ok(()) => true,
                        Err(RefError::Conflict(_)) => false,
                        Err(e) => panic!("local update_ref: {e}"),
                    }),
                    Box::new((layout, dir)),
                )
            }),
        },
    ];

    println!(
        "{:<7} {:<9} {:<8} {:>4} {:>10} {:>9} {:>10} {:>10} {:>10}",
        "backend", "scenario", "policy", "thr", "adv/s", "att/adv", "p50", "p99", "max"
    );
    for b in backends.iter().filter(|b| want.iter().any(|w| w == b.name)) {
        let ops = ops_env.unwrap_or(b.default_ops);
        for &thr in &threads {
            for (scenario, distinct, policy) in [
                ("one-ref", false, Policy::Spin),
                ("one-ref", false, Policy::Backoff),
                ("own-ref", true, Policy::Spin),
            ] {
                if distinct && thr == 1 {
                    continue;
                }
                let seed = hash(b"seed");
                let names: Vec<String> = (0..thr).map(|i| format!("agent-{i}")).collect();
                // For own-ref every writer gets its own ref in one shared store.
                let (read, cas, _keep) = (b.fresh)("agent-0", &seed);
                let mk_state = std::sync::Mutex::new(Vec::<(Arc<Read>, Arc<Cas>)>::new());
                let _ = &mk_state;
                // own-ref uses fresh store per ref: simplest honest isolation
                // (no shared lock), so it measures the uncontended ceiling.
                let mk = |n: &str| {
                    let (r, c, keep) = (b.fresh)(n, &seed);
                    std::mem::forget(keep);
                    (r, c)
                };
                let mut r = run(read, cas, thr, ops, policy, distinct, &names, &mk);
                let total = thr * ops;
                if !distinct {
                    check_chain(&seed, &r.edges, total);
                }
                println!(
                    "{:<7} {:<9} {:<8} {:>4} {:>10.0} {:>9.2} {:>10.1?} {:>10.1?} {:>10.1?}",
                    b.name,
                    scenario,
                    match policy { Policy::Spin => "spin", Policy::Backoff => "backoff" },
                    thr,
                    total as f64 / r.secs,
                    r.attempts as f64 / total as f64,
                    pct(&mut r.lat, 0.50),
                    pct(&mut r.lat, 0.99),
                    pct(&mut r.lat, 1.0),
                );
            }
        }
    }
}
