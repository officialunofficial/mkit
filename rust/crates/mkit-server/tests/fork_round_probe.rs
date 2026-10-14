//! Storage calls and serial rounds of one fork, per phase.
//!
//! Every call sleeps 30 ms of virtual time and the store reports a known read
//! allowance (as the Workers store does), so calls of one wave overlap and
//! elapsed time divided by 30 ms is the number of serial rounds. The source
//! has two commits (four packs: two data packs and two packmap nodes).
//! The expected tables pin the shape of the fork; a change that moves a
//! number is a change to how many storage rounds a fork costs.
#![cfg(feature = "memory")]
#![allow(clippy::unwrap_used, clippy::too_many_lines)]
mod fork_support;
use fork_support::*;
use mkit_attest::grant::Visibility;
use mkit_core::hash::hash;
use mkit_server::{
    RepoId, RepoName,
    budget::SliceBudget,
    fork::{ForkEnv, ForkLimits, ForkPlan, ForkRequest, ForkSpec},
    store::adapter_spi::keys,
};
use std::fmt::Write as _;
use std::sync::atomic::Ordering;
use tokio::time::Instant;

const ROUND_MS: u64 = 30;

/// Calls and serial rounds, by phase.
#[derive(Debug, Default, PartialEq, Eq)]
struct Table {
    /// `plan_bytes` before admission.
    plan_bytes: (u64, u64),
    /// `start_with`.
    start: (u64, u64),
    /// Each job phase, in order of first appearance.
    phases: Vec<(String, u64, u64)>,
}

impl Table {
    fn render(&self) -> String {
        let mut out = format!(
            "plan_bytes {}/{} start {}/{}",
            self.plan_bytes.0, self.plan_bytes.1, self.start.0, self.start.1
        );
        for (phase, calls, rounds) in &self.phases {
            let _ = write!(out, " {phase} {calls}/{rounds}");
        }
        out
    }
}

async fn source(files: u32, denial: bool) -> Source {
    let mut source = Source::build_full("source", files, 0, |mut c| {
        c.takedown_denial = denial;
        c
    })
    .await;
    // A second commit on the same tree.
    let (bytes, head) = commit_pack(source.tree, vec![source.head], b"second");
    let pack = hash(&bytes);
    let map = source.packmap;
    source.packmap = source.push(bytes, head, Some(map), &[pack]).await;
    source.head = head;
    source
}

fn rounds(elapsed: std::time::Duration) -> u64 {
    u64::try_from(elapsed.as_millis()).unwrap() / ROUND_MS
}

/// The engine, phase by phase: the pre-admission plan, the start and every
/// job commit, as a request drives them.
async fn engine(files: u32, denial: bool) -> Table {
    let source = source(files, denial).await;
    let dest = RepoId {
        namespace: source.repo.namespace.clone(),
        name: RepoName::new("forked").unwrap(),
    };
    let spec = ForkSpec {
        source: source.repo.clone(),
        source_ref: "refs/heads/main".into(),
        expected_tip: source.head,
        dest: dest.clone(),
        dest_visibility: Visibility::Public,
    };
    let env = ForkEnv {
        store: &source.store,
        shards: source.shards.as_ref(),
        clock: source.clock.as_ref(),
        takedown_denial: denial,
        extract_min_bytes: Some(65_536),
        limits: ForkLimits::default(),
    };
    source.store.sleep_ms.store(ROUND_MS, Ordering::SeqCst);
    source.store.waves.store(true, Ordering::SeqCst);
    *source.store.mark_key.lock().unwrap() = Some(keys::fork_job(&dest.name));
    let mut table = Table::default();

    let (c0, t0) = (source.store.calls(), Instant::now());
    let planned = plan(&env, &spec).await;
    let (c1, t1) = (source.store.calls(), Instant::now());
    table.plan_bytes = (c1 - c0, rounds(t1 - t0));
    source.store.marks.lock().unwrap().clear();
    start(&env, &spec, planned).await;
    let (c2, t2) = (source.store.calls(), Instant::now());
    table.start = (c2 - c1, rounds(t2 - t1));
    let first = mkit_server::fork::read_job(&source.store, source.shards.as_ref(), &dest)
        .await
        .unwrap()
        .unwrap()
        .0;

    let mut slices = 0;
    loop {
        slices += 1;
        let report = mkit_server::fork::step(&env, &dest, &SliceBudget::new(600))
            .await
            .unwrap();
        if report.job.finished() || slices > 50 {
            assert!(report.job.failure.is_none(), "{:?}", report.job.failure);
            break;
        }
    }
    let marks = source.store.marks.lock().unwrap().clone();
    let (mut last_calls, mut last_at) = (c2, t2);
    let mut current = format!("{:?}", first.phase);
    for (calls, bytes, at) in marks {
        let after = format!(
            "{:?}",
            mkit_server::fork::decode_job(&mkit_server::Value::new(bytes))
                .unwrap()
                .phase
        );
        let (dc, dr) = (calls - last_calls, rounds(at - last_at));
        match table.phases.iter_mut().find(|p| p.0 == current) {
            Some(row) => {
                row.1 += dc;
                row.2 += dr;
            }
            None => table.phases.push((current.clone(), dc, dr)),
        }
        current = after;
        (last_calls, last_at) = (calls, at);
    }
    table
}

/// The whole fork through the pipeline: prelude, admission, start and the
/// request's one slice. Calls, rounds, and whether the slice finished the fork.
async fn pipeline(files: u32, denial: bool) -> (u64, u64, bool) {
    let source = source(files, denial).await;
    let dest = source.at("forked");
    let request = ForkRequest {
        source: source.repo.clone(),
        source_ref: "refs/heads/main".into(),
        expected_tip: source.head,
        dest_visibility: Visibility::Public,
    };
    source.store.sleep_ms.store(ROUND_MS, Ordering::SeqCst);
    source.store.waves.store(true, Ordering::SeqCst);
    let (calls, at) = (source.store.calls(), Instant::now());
    let auth = dest.authenticate_body(mkit_server::Procedure::Fork, 77, &request.canonical_body());
    let finished = Box::pin(source.pipe.fork_repo(&auth, request))
        .await
        .is_ok();
    (
        source.store.calls() - calls,
        rounds(Instant::now() - at),
        finished,
    )
}

async fn plan(env: &ForkEnv<'_, Counting>, spec: &ForkSpec) -> Option<ForkPlan> {
    mkit_server::fork::plan_fork(env, spec).await.unwrap()
}
async fn start(env: &ForkEnv<'_, Counting>, spec: &ForkSpec, planned: Option<ForkPlan>) {
    mkit_server::fork::start_planned(env, spec, None, None, planned)
        .await
        .unwrap();
}

macro_rules! probe {
    ($(#[$meta:meta])* $name:ident, $files:expr, $denial:expr, $engine:expr, $request:expr) => {
        $(#[$meta])*
        #[tokio::test(start_paused = true)]
        async fn $name() {
            let table = engine($files, $denial).await;
            let (calls, rounds, finished) = pipeline($files, $denial).await;
            let request = format!("{calls}/{rounds} finished={finished}");
            println!(
                "PROBE {} | {} | fork_repo {request}",
                stringify!($name),
                table.render()
            );
            assert_eq!(table.render(), $engine);
            assert_eq!(request, $request);
        }
    };
}

// Entries read "calls/serial rounds". `fork_repo` adds the pipeline's own
// prelude to the engine's phases. Before the round cuts (a fork that plans
// twice, walks without denial, and publishes one pack at a time):
//
//   500 files,   denial off: plan_bytes 13/13 start 37/11 Plan 15/15 Trees 8/8
//     Walk 14/13 Register 52/13 Copy 35/35 Count 3/3 Publish 38/25
//     fork_repo 221/142
//   3,000 files, denial off: the same but Copy 112/112; fork_repo 298/219
//   500 files,   denial on:  plan_bytes 89/41 start 37/11 Plan 91/43 Trees 8/8
//     Walk 14/13 Register 52/13 Copy 35/35 Count 3/3 Publish 190/81
//     fork_repo 525/254
//   3,000 files, denial on:  the same but Copy 117/117; fork_repo 352/190, cut
//     at the request's one slice (unfinished)
//
// With denial off, 142 becomes 75 rounds and 219 becomes 81: the carried
// plan skips the in-job Plan and the denial-off Walk, and copy index rows
// issue in holder waves rather than serially. With denial on the job keeps
// its Walk but copy still waves: 254 becomes 186 and 289 becomes 192, so
// the 3,000-file fork now finishes inside the request's one slice.
probe!(
    files_500_denial_off,
    500,
    false,
    "plan_bytes 13/10 start 37/11 Trees 8/8 Register 52/13 Copy 35/9 Count 3/3 Publish 38/15",
    "192/75 finished=true"
);
probe!(
    files_3000_denial_off,
    3_000,
    false,
    "plan_bytes 13/10 start 37/11 Trees 8/8 Register 52/13 Copy 58/15 Count 3/3 Publish 38/15",
    "215/81 finished=true"
);
probe!(
    files_500_denial_on,
    500,
    true,
    "plan_bytes 89/41 start 37/11 Trees 9/9 Walk 14/13 Register 52/13 Copy 35/9 Count 3/3 Publish 190/81",
    "435/186 finished=true"
);
probe!(
    #[ignore = "large fork fixture; exercised by the ignored-lane CI profile"]
    files_3000_denial_on,
    3_000,
    true,
    "plan_bytes 89/41 start 37/11 Trees 9/9 Walk 14/13 Register 52/13 Copy 58/15 Count 3/3 Publish 190/81",
    "458/192 finished=true"
);
