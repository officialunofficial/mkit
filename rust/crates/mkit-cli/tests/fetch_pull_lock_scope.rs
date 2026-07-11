//! Issue #642 — narrow `pull_all`/`fetch_all`'s repo-lock hold to the
//! ref-publish window instead of the whole network transfer, without
//! reopening the #267 GC-prune race.
//!
//! Four things are under test:
//!
//! 1. [`fetch_all_does_not_hold_repo_lock_during_pack_download`] and
//!    [`pull_all_does_not_hold_repo_lock_during_pack_download`] prove the
//!    lock is free while a pack is in flight over the network — the bug
//!    this issue fixes. Run against the pre-#642 code, these fail (the
//!    lock-probe times out because the whole transfer holds the lock).
//! 2. [`gc_blocks_while_repo_lock_held_mid_fetch_critical_section`] proves
//!    the mechanism the narrowed design leans on for safety: a concurrent
//!    `gc --grace-secs 0` cannot make progress while the SAME lock a
//!    fetch/pull holds across its local-write + ref-publish window
//!    (`packmap::apply_fetched_chain`) is held.
//! 3. [`fetch_objects_survive_a_grace_zero_gc_run_during_the_unlocked_download_phase`]
//!    exercises the issue's literal testing decision: an aggressive
//!    concurrent `gc --grace-secs 0` running purely during the (now
//!    unlocked) download window must never corrupt the eventual fetch.
//! 4. [`concurrent_fetch_and_aggressive_gc_never_lose_fetched_objects`] is
//!    a soak test mirroring `lock_contention.rs`'s
//!    `publisher_vs_gc_never_corrupts` (the original #267 regression test)
//!    but for `fetch` instead of `tag -a`, driving the real subprocesses
//!    against a `mkit+file://` remote over many iterations.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

mod common;

use std::fs;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::Duration;

use common::{Repo, check_invariants};
use mkit_cli::remote_dispatch::{fetch_all, pull_all, push_all};
use mkit_core::hash::Hash;
use mkit_core::layout::RepoLayout;
use mkit_core::ops::reachable_objects;
use mkit_core::protocol::{PackKey, RefWriteCondition, Transport, TransportResult};
use mkit_core::refs::{self, Ref};
use mkit_core::store::ObjectStore;
use mkit_transport_file::FileTransport;
use mkit_transport_memory::MemoryTransport;

/// Delegates to [`common::mkit_env`] for the full isolation every other
/// suite gets (`XDG_CONFIG_HOME` + `HOME` + `EDITOR`/`VISUAL`/`GIT_EDITOR`
/// all pointed at a throwaway dir, stdin closed) — found missing here
/// during the epic-#634 code review: this file previously hand-rolled its
/// own `run_in` that set only `XDG_CONFIG_HOME`, leaving the developer's
/// real `$EDITOR`/`$HOME` reachable by any code path in these tests that
/// happens to need them (e.g. an uncommitted `commit` falling through to
/// interactive message composition would have spawned the real editor).
fn run_in(cwd: &std::path::Path, args: &[&str]) -> std::process::Output {
    let xdg = tempfile::tempdir().expect("xdg tempdir");
    let out = common::mkit_env(cwd, xdg.path(), args, &[]);
    drop(xdg);
    out
}

fn init_repo(dir: &std::path::Path) {
    assert!(run_in(dir, &["init"]).status.success());
    assert!(run_in(dir, &["keygen"]).status.success());
}

fn commit_all(dir: &std::path::Path, msg: &str) {
    assert!(run_in(dir, &["add", "."]).status.success());
    let out = run_in(dir, &["commit", "-m", msg]);
    assert!(out.status.success(), "commit failed: {out:?}");
}

// ---------------------------------------------------------------------------
// A rendezvous gate: lets a test thread learn exactly when a fetch/pull has
// entered the network pack-download phase, and hold it there until the test
// is done probing the repo lock.
// ---------------------------------------------------------------------------

struct Gate {
    started: (Mutex<bool>, Condvar),
    release: (Mutex<bool>, Condvar),
}

impl Gate {
    fn new() -> Self {
        Self {
            started: (Mutex::new(false), Condvar::new()),
            release: (Mutex::new(false), Condvar::new()),
        }
    }

    /// Called from inside `download_pack`: signal that the network phase
    /// has been entered, then block until [`Self::release`] is called.
    fn enter_and_wait(&self) {
        {
            let (lock, cvar) = &self.started;
            *lock.lock().unwrap() = true;
            cvar.notify_all();
        }
        let (lock, cvar) = &self.release;
        let mut released = lock.lock().unwrap();
        while !*released {
            released = cvar.wait(released).unwrap();
        }
    }

    /// Block the calling (test) thread until [`Self::enter_and_wait`] has
    /// been entered, up to `timeout`. Returns `false` on timeout.
    fn wait_started(&self, timeout: Duration) -> bool {
        let (lock, cvar) = &self.started;
        let guard = lock.lock().unwrap();
        let (guard, _) = cvar
            .wait_timeout_while(guard, timeout, |started| !*started)
            .unwrap();
        *guard
    }

    /// Let a blocked [`Self::enter_and_wait`] call proceed.
    fn release(&self) {
        let (lock, cvar) = &self.release;
        *lock.lock().unwrap() = true;
        cvar.notify_all();
    }
}

/// Wraps [`MemoryTransport`], routing every real pack download through
/// [`Gate::enter_and_wait`] so a test can pause a fetch/pull exactly while
/// it is in the network phase. Packlist chain-node downloads
/// (`download_blob`) are explicitly delegated straight to `inner` —
/// bypassing the gate — so only genuine pack transfers (the slow part a
/// WAN fetch spends its time on) trip it, mirroring `download_pack`'s
/// unconditional-vs-pack distinction already established by
/// `applied_packs_fetch.rs`'s `CountingTransport`.
struct BlockingTransport {
    inner: MemoryTransport,
    gate: Arc<Gate>,
}

impl Transport for BlockingTransport {
    fn upload_pack(&self, bytes: &[u8], key: &PackKey) -> TransportResult<()> {
        self.inner.upload_pack(bytes, key)
    }

    fn download_pack(&self, key: &PackKey) -> TransportResult<Vec<u8>> {
        self.gate.enter_and_wait();
        self.inner.download_pack(key)
    }

    fn pack_exists(&self, key: &PackKey) -> TransportResult<bool> {
        self.inner.pack_exists(key)
    }

    fn upload_blob(&self, bytes: &[u8], key: &PackKey) -> TransportResult<()> {
        self.inner.upload_blob(bytes, key)
    }

    fn download_blob(&self, key: &PackKey) -> TransportResult<Vec<u8>> {
        self.inner.download_blob(key)
    }

    fn update_ref(
        &self,
        name: &str,
        condition: RefWriteCondition,
        hash: &Hash,
    ) -> TransportResult<()> {
        self.inner.update_ref(name, condition, hash)
    }

    fn read_ref(&self, name: &str) -> TransportResult<Option<Hash>> {
        self.inner.read_ref(name)
    }

    fn list_refs(&self, prefix: &str) -> TransportResult<Vec<Ref>> {
        self.inner.list_refs(prefix)
    }
}

/// Probe whether the repo lock at `layout` is free right now. The timeout
/// is generous (well under the 5s default a real contended acquire would
/// need) to absorb scheduling jitter on a loaded machine — a free lock
/// still returns almost immediately; this only guards against a false
/// failure when the *lock itself* isn't the bottleneck, e.g. a shared
/// build machine under heavy concurrent CI/test load. It stays far short
/// of `DEFAULT_TIMEOUT` (5s) so a genuinely held lock (the pre-#642 bug)
/// still fails the probe well before that budget elapses.
fn lock_is_free(layout: &RepoLayout) -> bool {
    mkit_core::repo_lock::acquire(
        layout.worktree_state_dir(),
        mkit_cli::commands::WORKTREE_LOCK,
        Duration::from_secs(2),
    )
    .is_ok()
}

// ---------------------------------------------------------------------------
// 1. The lock must be free during the network download phase.
// ---------------------------------------------------------------------------

#[test]
fn fetch_all_does_not_hold_repo_lock_during_pack_download() {
    let alice = tempfile::tempdir().unwrap();
    let bob = tempfile::tempdir().unwrap();
    init_repo(alice.path());
    init_repo(bob.path());

    fs::write(alice.path().join("a.txt"), b"v1").unwrap();
    commit_all(alice.path(), "c1");

    let plain = MemoryTransport::new();
    push_all(alice.path(), &plain).expect("push");

    let gate = Arc::new(Gate::new());
    let tx = BlockingTransport {
        inner: plain,
        gate: gate.clone(),
    };
    let bob_layout = RepoLayout::single(bob.path());
    let bob_path = bob.path();

    // Never assert while `gate` might still be blocking the spawned fetch:
    // `thread::scope` joins spawned threads before propagating a panic, so
    // panicking here first (pre-fix, where the lock probe times out) would
    // deadlock the whole test instead of failing it. Collect every outcome
    // first, unconditionally release + join, THEN assert.
    let (started, lock_was_free, fetch_result) = thread::scope(|s| {
        let handle = s.spawn(|| fetch_all(bob_path, &tx, "default"));

        let started = gate.wait_started(Duration::from_secs(5));
        let lock_was_free = started && lock_is_free(&bob_layout);

        gate.release();
        let fetch_result = handle.join().expect("fetch thread panicked");
        (started, lock_was_free, fetch_result)
    });

    assert!(
        started,
        "fetch never reached the pack-download phase — test setup is broken"
    );
    assert!(
        lock_was_free,
        "#642: the repo lock must be free while a fetch's pack download is in \
         flight; a probe acquire timed out, meaning the lock is still held \
         across the network transfer"
    );
    let n = fetch_result.expect("fetch must succeed");
    assert_eq!(n, 1, "expected exactly one branch fetched");

    let remote_tip = refs::read_remote_ref(&bob_layout, "default", "main")
        .unwrap()
        .expect("remote-tracking ref must be published");
    let bob_store = ObjectStore::open(&bob_layout).unwrap();
    reachable_objects(&bob_store, &remote_tip)
        .expect("every object reachable from the published tip must be present");
}

#[test]
fn pull_all_does_not_hold_repo_lock_during_pack_download() {
    let alice = tempfile::tempdir().unwrap();
    let bob = tempfile::tempdir().unwrap();
    init_repo(alice.path());
    init_repo(bob.path());

    fs::write(alice.path().join("a.txt"), b"v1").unwrap();
    commit_all(alice.path(), "c1");

    let plain = MemoryTransport::new();
    push_all(alice.path(), &plain).expect("push");

    let gate = Arc::new(Gate::new());
    let tx = BlockingTransport {
        inner: plain,
        gate: gate.clone(),
    };
    let bob_layout = RepoLayout::single(bob.path());
    let bob_path = bob.path();

    // See the fetch-side test above for why every outcome is collected
    // before any assertion: panicking with `gate` still held would deadlock
    // `thread::scope`'s join instead of failing the test.
    let (started, lock_was_free, pull_result) = thread::scope(|s| {
        let handle = s.spawn(|| pull_all(bob_path, &tx, "default", None));

        let started = gate.wait_started(Duration::from_secs(5));
        let lock_was_free = started && lock_is_free(&bob_layout);

        gate.release();
        let pull_result = handle.join().expect("pull thread panicked");
        (started, lock_was_free, pull_result)
    });

    assert!(
        started,
        "pull never reached the pack-download phase — test setup is broken"
    );
    assert!(
        lock_was_free,
        "#642: the repo lock must be free while a pull's pack download is in \
         flight; a probe acquire timed out, meaning the lock is still held \
         across the network transfer"
    );
    let n = pull_result.expect("pull must succeed");
    assert_eq!(n, 1, "expected exactly one branch fetched");

    // Fast-forward landed: bob's local `main` now matches alice's tip.
    let alice_main = fs::read_to_string(alice.path().join(".mkit/refs/heads/main")).unwrap();
    let bob_main = fs::read_to_string(bob.path().join(".mkit/refs/heads/main")).unwrap();
    assert_eq!(alice_main.trim(), bob_main.trim());
}

// ---------------------------------------------------------------------------
// 2. The mechanism the narrowed design leans on: gc cannot run while the
//    SAME lock a fetch/pull's critical section holds is held.
// ---------------------------------------------------------------------------

#[test]
fn gc_blocks_while_repo_lock_held_mid_fetch_critical_section() {
    // `packmap::apply_fetched_chain` holds the repo lock continuously from
    // the first object it unpacks through the caller's ref publish (#642).
    // Simulate being inside that window by holding the same lock directly,
    // and confirm a concurrent `gc --grace-secs 0` cannot proceed until it
    // is released — the invariant (#267) the narrowed lock design depends
    // on: gc can never observe a downloaded-but-not-yet-referenced object.
    let repo = Repo::new();
    repo.commit_file("base.txt", b"base\n", "base");
    let layout = RepoLayout::single(repo.path());

    let lock = mkit_core::repo_lock::acquire_default(
        layout.worktree_state_dir(),
        mkit_cli::commands::WORKTREE_LOCK,
    )
    .expect("acquire lock (simulating a fetch/pull's held critical section)");

    thread::scope(|s| {
        let handle = s.spawn(|| repo.run(&["gc", "--grace-secs", "0"]));

        thread::sleep(Duration::from_millis(500));
        assert!(
            !handle.is_finished(),
            "gc must still be blocked by the held repo lock after 500ms"
        );

        drop(lock);

        let out = handle.join().expect("gc thread panicked");
        assert!(
            out.status.success(),
            "gc must succeed once the lock is released: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    });

    check_invariants(repo.path(), "post-gc-after-lock-release").unwrap();
}

// ---------------------------------------------------------------------------
// 3. A grace-zero gc running purely during the unlocked download window
//    must never corrupt the eventual fetch (the issue's literal testing
//    decision).
// ---------------------------------------------------------------------------

#[test]
fn fetch_objects_survive_a_grace_zero_gc_run_during_the_unlocked_download_phase() {
    let alice = tempfile::tempdir().unwrap();
    let bob = tempfile::tempdir().unwrap();
    init_repo(alice.path());
    init_repo(bob.path());

    fs::write(alice.path().join("a.txt"), b"v1").unwrap();
    commit_all(alice.path(), "c1");

    let plain = MemoryTransport::new();
    push_all(alice.path(), &plain).expect("push");

    let gate = Arc::new(Gate::new());
    let tx = BlockingTransport {
        inner: plain,
        gate: gate.clone(),
    };
    let bob_layout = RepoLayout::single(bob.path());
    let bob_path = bob.path();

    // As above: collect outcomes before asserting, so a failure can't leave
    // `gate` blocking the spawned fetch forever inside `thread::scope`'s join.
    let (started, gc_out, fetch_result) = thread::scope(|s| {
        let handle = s.spawn(|| fetch_all(bob_path, &tx, "default"));

        let started = gate.wait_started(Duration::from_secs(5));

        // An aggressive concurrent gc while the download is in flight and
        // no repo lock is held: at this point the download hasn't unpacked
        // anything yet, so there's nothing new to prune — this must be
        // completely harmless, and the gc itself must succeed cleanly.
        let gc_out = started.then(|| run_in(bob_path, &["gc", "--grace-secs", "0"]));

        gate.release();
        let fetch_result = handle.join().expect("fetch thread panicked");
        (started, gc_out, fetch_result)
    });

    assert!(
        started,
        "fetch never reached the pack-download phase — test setup is broken"
    );
    let gc_out = gc_out.expect("gc must have run");
    assert!(
        gc_out.status.success(),
        "a concurrent gc during the unlocked download phase must succeed cleanly: {}",
        String::from_utf8_lossy(&gc_out.stderr)
    );
    let n = fetch_result.expect("fetch must succeed");
    assert_eq!(n, 1);

    let remote_tip = refs::read_remote_ref(&bob_layout, "default", "main")
        .unwrap()
        .expect("remote-tracking ref must be published");
    let bob_store = ObjectStore::open(&bob_layout).unwrap();
    reachable_objects(&bob_store, &remote_tip).expect(
        "every object reachable from the published tip must have survived the concurrent gc",
    );
}

// ---------------------------------------------------------------------------
// 4. Soak test mirroring lock_contention.rs's `publisher_vs_gc_never_corrupts`
//    (#267), for `fetch` instead of `tag -a`.
// ---------------------------------------------------------------------------

/// Every worker must end either applied (0) or lock-busy (75, TEMPFAIL) — no
/// other exit code, no panic. Mirrors `lock_contention.rs`'s
/// `assert_lock_outcome`.
fn assert_lock_outcome(out: &std::process::Output, who: &str) {
    const TEMPFAIL: i32 = 75;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("panicked") && !stderr.contains("RUST_BACKTRACE"),
        "{who}: panic in stderr: {stderr}"
    );
    match out.status.code() {
        Some(0 | TEMPFAIL) => {}
        other => panic!("{who}: unexpected exit {other:?}; stderr: {stderr}"),
    }
}

#[test]
fn concurrent_fetch_and_aggressive_gc_never_lose_fetched_objects() {
    let alice = tempfile::tempdir().unwrap();
    init_repo(alice.path());

    let bob = Repo::new();
    let remote = tempfile::tempdir().unwrap();
    let url = format!("mkit+file://{}", remote.path().display());
    bob.ok(&["remote", "add", "origin", &url]);

    let file_tx = FileTransport::new(remote.path());

    let iters = 15;
    for k in 0..iters {
        fs::write(alice.path().join(format!("f{k}.txt")), format!("v{k}")).unwrap();
        commit_all(alice.path(), &format!("c{k}"));
        push_all(alice.path(), &file_tx).expect("push");

        thread::scope(|s| {
            let bob_ref = &bob;
            let t_fetch = s.spawn(move || bob_ref.run(&["fetch", "origin"]));
            let t_gc = s.spawn(move || bob_ref.run(&["gc", "--grace-secs", "0"]));
            assert_lock_outcome(&t_fetch.join().unwrap(), &format!("fetch/{k}"));
            assert_lock_outcome(&t_gc.join().unwrap(), &format!("gc/{k}"));
        });

        check_invariants(bob.path(), &format!("fetch-vs-gc/{k}")).unwrap();

        // If the tracking ref moved this iteration, its closure must be
        // fully intact — the #267 race this narrowed lock must still
        // close.
        let bob_layout = RepoLayout::single(bob.path());
        if let Some(tip) = refs::read_remote_ref(&bob_layout, "origin", "main").unwrap() {
            let bob_store = ObjectStore::open(&bob_layout).unwrap();
            reachable_objects(&bob_store, &tip).unwrap_or_else(|e| {
                panic!("iteration {k}: tracking tip's closure incomplete: {e}")
            });
        }
    }
}
