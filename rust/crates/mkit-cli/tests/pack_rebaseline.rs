//! Periodic re-baseline integration tests (#406).
//!
//! `push_branch` bounds a branch's packlist chain depth: once a push would
//! grow the chain past `MKIT_PACK_REBASELINE_DEPTH` (default 64, see
//! `remote_dispatch::packmap::rebaseline_depth`), it resets the chain to a
//! single self-contained node instead of appending to it. This is a
//! storage/transfer-encoding change only — every commit keeps its hash and
//! stays checkout-able (see issue #406's "does NOT squash history" note).
//!
//! ## Env-var injection without `std::env::set_var`
//!
//! `rebaseline_depth()` reads `MKIT_PACK_REBASELINE_DEPTH` from the
//! process environment. `std::env::set_var` is banned by
//! `clippy::disallowed_methods` in this repo (races other threads on
//! POSIX), so the depth-threshold tests below spawn the real `mkit`
//! binary and set the var on the child `Command` — never on this test
//! process — following the same pattern `push_named_remote.rs` already
//! uses for a real, URL-reachable `mkit+file://` remote.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::process::{Command, Output};
use std::sync::Mutex;

use mkit_cli::remote_dispatch::{DispatchError, fetch_all, pull_all, push_all, push_branch};
use mkit_core::hash::Hash;
use mkit_core::layout::RepoLayout;
use mkit_core::object::Object;
use mkit_core::pack::delta_base_hashes;
use mkit_core::protocol::{PackKey, RefWriteCondition, Transport, TransportResult};
use mkit_core::refs::{self, Ref};
use mkit_core::store::ObjectStore;
use mkit_core::transfer::{self, PackListNode};
use mkit_transport_file::FileTransport;
use mkit_transport_memory::MemoryTransport;

fn mkit_bin() -> &'static str {
    env!("CARGO_BIN_EXE_mkit")
}

/// Spawn the real `mkit` binary, isolated from the developer's real
/// `XDG_CONFIG_HOME`. `extra_env` carries any additional vars a specific
/// invocation needs (namely `MKIT_PACK_REBASELINE_DEPTH`).
fn run_in(cwd: &Path, args: &[&str], extra_env: &[(&str, &str)]) -> Output {
    let xdg = tempfile::tempdir().expect("xdg tempdir");
    let mut cmd = Command::new(mkit_bin());
    cmd.args(args)
        .current_dir(cwd)
        .env("XDG_CONFIG_HOME", xdg.path());
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("spawn mkit");
    drop(xdg);
    out
}

fn init_repo(dir: &Path) {
    assert!(run_in(dir, &["init"], &[]).status.success());
    assert!(run_in(dir, &["keygen"], &[]).status.success());
}

fn commit_file(dir: &Path, name: &str, content: &[u8], msg: &str) {
    fs::write(dir.join(name), content).unwrap();
    assert!(run_in(dir, &["add", name], &[]).status.success());
    let out = run_in(dir, &["commit", "-m", msg], &[]);
    assert!(out.status.success(), "commit failed: {out:?}");
}

fn head_hash(dir: &Path) -> Hash {
    refs::read_ref(&RepoLayout::single(dir), "main")
        .unwrap()
        .unwrap()
}

fn file_url(dir: &Path) -> String {
    format!("mkit+file://{}", dir.display())
}

/// Walk `<remote>`'s packlist chain for `branch` newest-first via the
/// public [`Transport`] verbs (`read_ref` + `download_blob`), exactly the
/// way the push/fetch paths do — so the test never has to assume anything
/// about a transport's on-disk layout.
fn packmap_chain(tx: &dyn Transport, branch: &str) -> Vec<PackListNode> {
    let mut nodes = Vec::new();
    let mut cursor = tx.read_ref(&format!("refs/mkit/packmap/{branch}")).unwrap();
    while let Some(key) = cursor {
        let bytes = tx.download_blob(&PackKey::from_hash(key)).unwrap();
        let node = transfer::decode_packlist(&bytes).unwrap();
        cursor = node.prev;
        nodes.push(node);
    }
    nodes
}

/// `true` if every pack referenced anywhere in `chain` carries zero delta
/// entries (i.e. every pack in the chain is self-contained / all-raw).
fn chain_is_all_raw(tx: &dyn Transport, chain: &[PackListNode]) -> bool {
    chain.iter().flat_map(|n| &n.packs).all(|pack_key| {
        let bytes = tx.download_pack(&PackKey::from_hash(*pack_key)).unwrap();
        delta_base_hashes(&bytes).unwrap().is_empty()
    })
}

fn all_ancestor_commit_hashes(store: &ObjectStore, tip: Hash) -> HashSet<Hash> {
    let mut out = HashSet::new();
    let mut stack = vec![tip];
    while let Some(h) = stack.pop() {
        if !out.insert(h) {
            continue;
        }
        if let Object::Commit(c) = store.read_object(&h).unwrap() {
            stack.extend(c.parents);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Depth-threshold behaviour, driven through the real binary against a
// `mkit+file://` remote (env-var injection via subprocess, see module docs).
// ---------------------------------------------------------------------------

/// Fix for mkit #521: `mkit+file://` (`FileTransport`) uses the DEFAULT,
/// non-transactional `advance_refs` (packmap-then-head) — it does not
/// override [`Transport::supports_atomic_advance`], so it inherits `false`.
/// A proactive re-baseline reset writes a fresh node with `prev = None`,
/// which is NOT a superset of the prior chain (unlike an ordinary append);
/// committing one while losing the paired head CAS would strand the
/// (unmoved) head pointing at a commit the packmap can no longer
/// reconstruct. So even after 4 pushes cross the depth-3 threshold, the
/// chain on a non-atomic transport must keep appending — never reset — and
/// the remote must stay fully clonable throughout.
///
/// This supersedes the pre-#521 version of this test (which asserted the
/// opposite: that the chain collapses to one self-contained node here).
/// That assertion described exactly the unsafe behavior #521 closes: on a
/// non-atomic transport, a divergent push racing at this same depth
/// threshold could commit a packmap reset, lose the head CAS, and leave
/// the remote with a head pointing at an unreconstructable closure (see
/// `RemoteMissingObject`). The re-baseline mechanism itself is still
/// covered — on the transactional path — by
/// `divergent_push_that_would_rebaseline_blocks_then_retry_stays_clonable`
/// below, which uses `AtomicTransport`.
#[test]
fn four_pushes_at_depth_3_over_a_non_atomic_transport_never_reset() {
    let alice = tempfile::tempdir().unwrap();
    init_repo(alice.path());
    let remote = tempfile::tempdir().unwrap();
    let url = file_url(remote.path());
    assert!(
        run_in(alice.path(), &["remote", "add", &url], &[])
            .status
            .success()
    );

    let mut tips = Vec::new();
    for i in 0..4u32 {
        commit_file(
            alice.path(),
            "f.txt",
            i.to_string().as_bytes(),
            &format!("c{i}"),
        );
        tips.push(head_hash(alice.path()));
        let out = run_in(
            alice.path(),
            &["push"],
            &[("MKIT_PACK_REBASELINE_DEPTH", "3")],
        );
        assert!(out.status.success(), "push {i} failed: {out:?}");
    }
    let final_tip = *tips.last().unwrap();

    let tx = FileTransport::new(remote.path());
    let chain = packmap_chain(&tx, "main");
    assert_eq!(
        chain.len(),
        4,
        "a non-atomic transport must never reset the chain, even past the \
         re-baseline threshold — it must keep appending, one node per push"
    );
    // `packmap_chain` walks newest-first: every node but the oldest must
    // chain to a `Some` prev, i.e. no reset (`prev = None`) happened
    // partway through the chain.
    for (idx, node) in chain.iter().enumerate() {
        if idx + 1 < chain.len() {
            assert!(
                node.prev.is_some(),
                "node {idx} unexpectedly reset to prev = None on a non-atomic transport"
            );
        }
    }
    assert_eq!(
        tx.read_ref("refs/heads/main").unwrap(),
        Some(final_tip),
        "head must resolve to the latest tip"
    );

    // The remote stays clonable, and a fresh clone reconstructs every
    // commit with unchanged hashes.
    let dest = tempfile::tempdir().unwrap();
    let out = run_in(dest.path(), &["clone", &url, "bob"], &[]);
    assert!(out.status.success(), "clone failed: {out:?}");
    let bob = dest.path().join("bob");
    assert_eq!(head_hash(&bob), final_tip);
    let bob_store = ObjectStore::open(&RepoLayout::single(&bob)).unwrap();
    let ancestry = all_ancestor_commit_hashes(&bob_store, final_tip);
    for tip in &tips {
        assert!(
            ancestry.contains(tip),
            "commit {tip:?} missing from the reconstructed history"
        );
    }
    assert_eq!(ancestry.len(), 4, "all 4 commits, and only those, present");
    assert_eq!(fs::read(bob.join("f.txt")).unwrap(), b"3");
}

#[test]
fn two_pushes_below_depth_3_threshold_keep_two_nodes() {
    let alice = tempfile::tempdir().unwrap();
    init_repo(alice.path());
    let remote = tempfile::tempdir().unwrap();
    let url = file_url(remote.path());
    assert!(
        run_in(alice.path(), &["remote", "add", &url], &[])
            .status
            .success()
    );

    for i in 0..2u32 {
        commit_file(
            alice.path(),
            "f.txt",
            i.to_string().as_bytes(),
            &format!("c{i}"),
        );
        let out = run_in(
            alice.path(),
            &["push"],
            &[("MKIT_PACK_REBASELINE_DEPTH", "3")],
        );
        assert!(out.status.success(), "push {i} failed: {out:?}");
    }

    let tx = FileTransport::new(remote.path());
    let chain = packmap_chain(&tx, "main");
    assert_eq!(
        chain.len(),
        2,
        "no premature reset while the chain is still below the threshold"
    );
}

#[test]
fn depth_zero_disables_rebaseline() {
    let alice = tempfile::tempdir().unwrap();
    init_repo(alice.path());
    let remote = tempfile::tempdir().unwrap();
    let url = file_url(remote.path());
    assert!(
        run_in(alice.path(), &["remote", "add", &url], &[])
            .status
            .success()
    );

    for i in 0..4u32 {
        commit_file(
            alice.path(),
            "f.txt",
            i.to_string().as_bytes(),
            &format!("c{i}"),
        );
        let out = run_in(
            alice.path(),
            &["push"],
            &[("MKIT_PACK_REBASELINE_DEPTH", "0")],
        );
        assert!(out.status.success(), "push {i} failed: {out:?}");
    }

    let tx = FileTransport::new(remote.path());
    let chain = packmap_chain(&tx, "main");
    assert_eq!(
        chain.len(),
        4,
        "MKIT_PACK_REBASELINE_DEPTH=0 must disable re-baselining"
    );
}

// ---------------------------------------------------------------------------
// Concurrency: a divergent push whose depth check WOULD re-baseline.
// ---------------------------------------------------------------------------

/// A [`MemoryTransport`] wrapper with a genuinely atomic `advance_refs`:
/// both preconditions are checked under one lock before either ref is
/// written, so a losing push never commits half of a two-ref advance.
/// This models the transactional advance #408 provides on production
/// remotes (native HTTP + makechain's `/refs/advance`).
///
/// The plain default `advance_refs` (used by [`MemoryTransport`] /
/// [`FileTransport`] and exercised by the other tests in this file and in
/// `push_delta.rs`) commits packmap-then-head sequentially; that is
/// documented as safe when a losing head race still leaves an *appended*
/// (superset) packmap. #406's re-baseline reset (`prev = None`) breaks
/// that assumption for a torn write — which is exactly the production
/// hazard #408's atomic advance exists to close — so this specific test
/// needs the real atomic contract to be meaningful rather than incidental
/// to the non-transactional fallback's commit order.
struct AtomicTransport {
    inner: MemoryTransport,
    lock: Mutex<()>,
}

impl AtomicTransport {
    fn new() -> Self {
        Self {
            inner: MemoryTransport::new(),
            lock: Mutex::new(()),
        }
    }
}

fn condition_holds(condition: RefWriteCondition, current: Option<Hash>) -> bool {
    match condition {
        RefWriteCondition::Any => true,
        RefWriteCondition::Missing => current.is_none(),
        RefWriteCondition::Match(h) => current == Some(h),
    }
}

impl Transport for AtomicTransport {
    fn upload_pack(&self, bytes: &[u8], key: &PackKey) -> TransportResult<()> {
        self.inner.upload_pack(bytes, key)
    }
    fn download_pack(&self, key: &PackKey) -> TransportResult<Vec<u8>> {
        self.inner.download_pack(key)
    }
    fn pack_exists(&self, key: &PackKey) -> TransportResult<bool> {
        self.inner.pack_exists(key)
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
    fn advance_refs(
        &self,
        head_ref: &str,
        head_condition: RefWriteCondition,
        head_value: &Hash,
        packmap_ref: &str,
        packmap_condition: RefWriteCondition,
        packmap_value: &Hash,
    ) -> TransportResult<mkit_core::protocol::AdvanceOutcome> {
        use mkit_core::protocol::AdvanceOutcome;
        let _guard = self.lock.lock().unwrap();
        if !condition_holds(packmap_condition, self.inner.read_ref(packmap_ref)?) {
            return Ok(AdvanceOutcome::PackmapConflict);
        }
        if !condition_holds(head_condition, self.inner.read_ref(head_ref)?) {
            return Ok(AdvanceOutcome::HeadConflict);
        }
        self.inner
            .update_ref(packmap_ref, packmap_condition, packmap_value)?;
        self.inner
            .update_ref(head_ref, head_condition, head_value)?;
        Ok(AdvanceOutcome::Committed)
    }

    // This transport's `advance_refs` above genuinely commits the head +
    // packmap write as one indivisible transaction (both preconditions
    // checked under one lock before either write lands), which is exactly
    // the contract `Transport::supports_atomic_advance` gates the
    // pack-chain re-baseline reset on (mkit #521): declaring it here is
    // what lets `divergent_push_that_would_rebaseline_blocks_then_retry_stays_clonable`
    // below still exercise the re-baseline path at all.
    fn supports_atomic_advance(&self) -> bool {
        true
    }
}

#[test]
#[allow(clippy::too_many_lines)] // one scenario: race, blocked re-baseline, retry, re-clone
fn divergent_push_that_would_rebaseline_blocks_then_retry_stays_clonable() {
    // Reaches the DEFAULT re-baseline threshold (64) with 64 real
    // appending pushes rather than overriding MKIT_PACK_REBASELINE_DEPTH —
    // this test drives `push_branch` in-process (like the existing
    // divergent-push tests in push_delta.rs) to control the exact CAS
    // race, and there is no policy-compliant way to inject an env var into
    // this test's own process (see module docs).
    let alice = tempfile::tempdir().unwrap();
    let bob = tempfile::tempdir().unwrap();
    init_repo(alice.path());
    init_repo(bob.path());

    fs::write(alice.path().join("f.txt"), b"0").unwrap();
    assert!(
        run_in(alice.path(), &["add", "f.txt"], &[])
            .status
            .success()
    );
    assert!(
        run_in(alice.path(), &["commit", "-m", "base"], &[])
            .status
            .success()
    );

    let tx = AtomicTransport::new();
    push_all(alice.path(), &tx).expect("alice base push");
    pull_all(bob.path(), &tx, "default").expect("bob clones base");
    let shared_tip = head_hash(alice.path());

    // The base push above already contributed the chain's first node,
    // so 63 more plain appending pushes reach depth 64 exactly (not 65 —
    // the 65th push is the one that would itself re-baseline).
    for i in 1..=63u32 {
        fs::write(alice.path().join("f.txt"), i.to_string()).unwrap();
        assert!(
            run_in(alice.path(), &["add", "f.txt"], &[])
                .status
                .success()
        );
        assert!(
            run_in(alice.path(), &["commit", "-m", &format!("alice-{i}")], &[])
                .status
                .success()
        );
        push_all(alice.path(), &tx).unwrap_or_else(|e| panic!("push alice-{i}: {e}"));
    }
    let alice_tip = head_hash(alice.path());
    assert_eq!(packmap_chain(&tx, "main").len(), 64);

    // bob, still at the shared base, races with a stale expectation. The
    // remote's current depth (64) means this push, if it reached the
    // packmap CAS, WOULD re-baseline (64 + 1 > 64).
    fs::write(bob.path().join("f.txt"), b"bob-divergent").unwrap();
    assert!(run_in(bob.path(), &["add", "f.txt"], &[]).status.success());
    assert!(
        run_in(bob.path(), &["commit", "-m", "bob-divergent"], &[])
            .status
            .success()
    );
    let bob_tip = head_hash(bob.path());
    let bob_store = ObjectStore::open(&RepoLayout::single(bob.path())).unwrap();

    let err = push_branch(
        &tx,
        &bob_store,
        "main",
        bob_tip,
        RefWriteCondition::Match(shared_tip),
    )
    .unwrap_err();
    assert!(
        matches!(err, DispatchError::NonFastForwardPush { .. }),
        "expected NonFastForwardPush, got {err:?}"
    );

    // The remote must be untouched: the atomic advance never let bob's
    // would-be re-baseline reset land without also winning the head CAS.
    assert_eq!(tx.read_ref("refs/heads/main").unwrap(), Some(alice_tip));
    assert_eq!(packmap_chain(&tx, "main").len(), 64);
    let carol = tempfile::tempdir().unwrap();
    init_repo(carol.path());
    pull_all(carol.path(), &tx, "default")
        .expect("remote must stay clonable after the loser's blocked re-baseline");
    assert_eq!(fs::read(carol.path().join("f.txt")).unwrap(), b"63");

    // The loser retries: fast-forward onto alice's tip, recommit, push
    // again. The chain is still at depth 64, so this retry ALSO decides to
    // re-baseline — and this time it wins the head CAS outright (nothing
    // else moved the head), collapsing the chain to one self-contained
    // node covering the full merged history.
    fetch_all(bob.path(), &tx, "default").expect("bob's retry fetch");
    let alice_hex = mkit_core::to_hex(&alice_tip);
    let out = run_in(bob.path(), &["reset", "--hard", "-f", &alice_hex], &[]);
    assert!(out.status.success(), "bob reset onto alice's tip: {out:?}");
    fs::write(bob.path().join("f.txt"), b"bob-retry").unwrap();
    assert!(run_in(bob.path(), &["add", "f.txt"], &[]).status.success());
    assert!(
        run_in(bob.path(), &["commit", "-m", "bob-retry"], &[])
            .status
            .success()
    );
    let bob_retry_tip = head_hash(bob.path());
    let bob_store2 = ObjectStore::open(&RepoLayout::single(bob.path())).unwrap();
    push_branch(
        &tx,
        &bob_store2,
        "main",
        bob_retry_tip,
        RefWriteCondition::Match(alice_tip),
    )
    .expect("bob's retry push should succeed");

    assert_eq!(tx.read_ref("refs/heads/main").unwrap(), Some(bob_retry_tip));
    let chain = packmap_chain(&tx, "main");
    assert_eq!(chain.len(), 1, "retry re-baseline collapses the chain");
    assert!(chain_is_all_raw(&tx, &chain));

    // Still clonable, with the full merged history (alice's base + 63
    // appending commits, plus bob's retried commit) present and
    // hash-verified.
    let dave = tempfile::tempdir().unwrap();
    init_repo(dave.path());
    pull_all(dave.path(), &tx, "default").expect("clone after the retry re-baseline");
    assert_eq!(fs::read(dave.path().join("f.txt")).unwrap(), b"bob-retry");
    let dave_tip = head_hash(dave.path());
    assert_eq!(dave_tip, bob_retry_tip);
    let dave_store = ObjectStore::open(&RepoLayout::single(dave.path())).unwrap();
    let ancestry = all_ancestor_commit_hashes(&dave_store, dave_tip);
    assert_eq!(
        ancestry.len(),
        65,
        "base + 63 alice commits + bob's retry commit"
    );
    for h in &ancestry {
        let bytes = dave_store
            .read(h)
            .expect("object present and hash-verified");
        assert_eq!(
            mkit_core::serialize::deserialize(&bytes)
                .unwrap()
                .id()
                .unwrap(),
            *h
        );
    }
}

/// mkit #521 (force-push safety): a force push (`RefWriteCondition::Any`)
/// that reaches the re-baseline threshold on an ATOMIC transport must still
/// NOT reset the chain — it must append.
///
/// A force push's `Any` head condition makes even an atomic `advance_refs`
/// fall back to the ordered two-PUT path (packmap PUT then head PUT), on
/// which a committed reset (`prev = None`, not a superset of the prior chain)
/// followed by a lost/crashed head PUT would strand the head at a closure the
/// reset can no longer reconstruct → `RemoteMissingObject` for every fetcher.
/// So `push_branch`'s depth gate excludes `Any` and takes the safe append
/// path here, even though the transport reports `supports_atomic_advance()`.
/// The CAS/`Match`-conditioned re-baseline (exercised by
/// `divergent_push_that_would_rebaseline_blocks_then_retry_stays_clonable`)
/// is deliberately left untouched and stays green.
#[test]
#[allow(clippy::too_many_lines)] // one scenario: build to threshold, force-push, re-clone
fn force_push_at_threshold_appends_and_never_resets() {
    let alice = tempfile::tempdir().unwrap();
    init_repo(alice.path());

    fs::write(alice.path().join("f.txt"), b"0").unwrap();
    assert!(
        run_in(alice.path(), &["add", "f.txt"], &[])
            .status
            .success()
    );
    assert!(
        run_in(alice.path(), &["commit", "-m", "base"], &[])
            .status
            .success()
    );

    let tx = AtomicTransport::new();
    push_all(alice.path(), &tx).expect("alice base push");

    // Base push = the chain's first node; 63 more plain appending pushes
    // reach depth 64 exactly — the depth at which the NEXT push would itself
    // re-baseline (64 + 1 > 64 with the default threshold).
    for i in 1..=63u32 {
        fs::write(alice.path().join("f.txt"), i.to_string()).unwrap();
        assert!(
            run_in(alice.path(), &["add", "f.txt"], &[])
                .status
                .success()
        );
        assert!(
            run_in(alice.path(), &["commit", "-m", &format!("alice-{i}")], &[])
                .status
                .success()
        );
        push_all(alice.path(), &tx).unwrap_or_else(|e| panic!("push alice-{i}: {e}"));
    }
    assert_eq!(packmap_chain(&tx, "main").len(), 64);

    // A FORCE push (unconditional `Any` head condition) of a new
    // fast-forward commit. The chain sits at depth 64, so a CAS-conditioned
    // push would re-baseline here — but `Any` forces the ordered advance
    // path, so this must append instead.
    fs::write(alice.path().join("f.txt"), b"forced").unwrap();
    assert!(
        run_in(alice.path(), &["add", "f.txt"], &[])
            .status
            .success()
    );
    assert!(
        run_in(alice.path(), &["commit", "-m", "forced"], &[])
            .status
            .success()
    );
    let forced_tip = head_hash(alice.path());
    let store = ObjectStore::open(&RepoLayout::single(alice.path())).unwrap();
    push_branch(&tx, &store, "main", forced_tip, RefWriteCondition::Any)
        .expect("force push at threshold should append, not reset");

    // Appended, not reset: the chain grew to 65 and its NEWEST node still
    // chains to a `Some` prev (a re-baseline would leave one lone
    // `prev = None` node, i.e. `chain.len() == 1`). `packmap_chain` walks
    // newest-first, so `chain[0]` is that newest node.
    let chain = packmap_chain(&tx, "main");
    assert_eq!(
        chain.len(),
        65,
        "a force push at the threshold must append (65 nodes), not reset to a single node"
    );
    assert!(
        chain[0].prev.is_some(),
        "newest node reset to prev = None — a re-baseline leaked through on an `Any` force push"
    );
    assert_eq!(tx.read_ref("refs/heads/main").unwrap(), Some(forced_tip));

    // The remote stays clonable with the full 65-commit history intact.
    let bob = tempfile::tempdir().unwrap();
    init_repo(bob.path());
    pull_all(bob.path(), &tx, "default").expect("clone after the force-push append");
    assert_eq!(fs::read(bob.path().join("f.txt")).unwrap(), b"forced");
    assert_eq!(head_hash(bob.path()), forced_tip);
    let bob_store = ObjectStore::open(&RepoLayout::single(bob.path())).unwrap();
    let ancestry = all_ancestor_commit_hashes(&bob_store, forced_tip);
    assert_eq!(
        ancestry.len(),
        65,
        "base + 63 appending commits + the forced commit"
    );
}
