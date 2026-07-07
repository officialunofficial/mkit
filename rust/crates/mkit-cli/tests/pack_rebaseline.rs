//! Periodic re-baseline integration tests (#406).
//!
//! `push_branch` bounds a branch's packlist chain depth: once a push would
//! grow the chain past the re-baseline threshold (default 64, see
//! `remote_dispatch::packmap::rebaseline_depth`), it resets the chain to a
//! single self-contained node instead of appending to it. This is a
//! storage/transfer-encoding change only — every commit keeps its hash and
//! stays checkout-able (see issue #406's "does NOT squash history" note).
//!
//! ## Injecting a small threshold (#547)
//!
//! Two seams, one per kind of test:
//!
//! * The depth-threshold tests exercise the CLI's env-var knob
//!   (`MKIT_PACK_REBASELINE_DEPTH`) end-to-end. `std::env::set_var` is
//!   banned by `clippy::disallowed_methods` in this repo (races other
//!   threads on POSIX), so they spawn the real `mkit` binary through the
//!   shared harness's env-capable runner (`common::mkit_env`) and set the
//!   var on the child `Command` — never on this test process.
//! * The concurrency tests drive `push_branch_with_depth` in-process (they
//!   need to control the exact CAS race, like the divergent-push tests in
//!   `push_delta.rs`) with an explicit small threshold — instead of
//!   reaching the default threshold (64) with ~64 real pushes.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

mod common;

use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::sync::Mutex;

use common::Repo;
use mkit_cli::remote_dispatch::{
    DispatchError, fetch_all, pull_all, push_all, push_branch_with_depth,
};
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

/// The small threshold the in-process concurrency tests inject via
/// `push_branch_with_depth` (#547) — reachable with a handful of pushes,
/// unlike the default 64.
const TEST_DEPTH: usize = 3;

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
    let alice = Repo::new();
    let remote = tempfile::tempdir().unwrap();
    let url = file_url(remote.path());
    alice.ok(&["remote", "add", &url]);

    let mut tips = Vec::new();
    for i in 0..4u32 {
        alice.commit_file("f.txt", i.to_string().as_bytes(), &format!("c{i}"));
        tips.push(head_hash(alice.path()));
        alice.ok_env(&["push"], &[("MKIT_PACK_REBASELINE_DEPTH", "3")]);
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
    let xdg = tempfile::tempdir().unwrap();
    let out = common::mkit(dest.path(), xdg.path(), &["clone", &url, "bob"]);
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
    let alice = Repo::new();
    let remote = tempfile::tempdir().unwrap();
    let url = file_url(remote.path());
    alice.ok(&["remote", "add", &url]);

    for i in 0..2u32 {
        alice.commit_file("f.txt", i.to_string().as_bytes(), &format!("c{i}"));
        alice.ok_env(&["push"], &[("MKIT_PACK_REBASELINE_DEPTH", "3")]);
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
    let alice = Repo::new();
    let remote = tempfile::tempdir().unwrap();
    let url = file_url(remote.path());
    alice.ok(&["remote", "add", &url]);

    for i in 0..4u32 {
        alice.commit_file("f.txt", i.to_string().as_bytes(), &format!("c{i}"));
        alice.ok_env(&["push"], &[("MKIT_PACK_REBASELINE_DEPTH", "0")]);
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

/// `TEST_DEPTH - 1` plain appending pushes of successive `f.txt` contents
/// (`"1"`, `"2"`, …) on top of an already-pushed base commit, growing the
/// remote's chain for `main` to exactly [`TEST_DEPTH`] nodes — the depth at
/// which the NEXT push would itself re-baseline
/// (`TEST_DEPTH + 1 > TEST_DEPTH`). Returns the final tip.
///
/// These build-up pushes go through the ordinary [`push_all`] (default
/// threshold): they sit far below it, so they append — only the decisive
/// push under test injects [`TEST_DEPTH`] via `push_branch_with_depth`.
fn grow_chain_to_test_depth(alice: &Repo, tx: &dyn Transport) -> Hash {
    for i in 1..TEST_DEPTH {
        alice.commit_file("f.txt", i.to_string().as_bytes(), &format!("alice-{i}"));
        push_all(alice.path(), tx).unwrap_or_else(|e| panic!("push alice-{i}: {e}"));
    }
    assert_eq!(packmap_chain(tx, "main").len(), TEST_DEPTH);
    head_hash(alice.path())
}

#[test]
#[allow(clippy::too_many_lines)] // one scenario: race, blocked re-baseline, retry, re-clone
fn divergent_push_that_would_rebaseline_blocks_then_retry_stays_clonable() {
    // Drives `push_branch_with_depth` in-process (like the existing
    // divergent-push tests in push_delta.rs) to control the exact CAS
    // race, at an injected small threshold (#547) instead of reaching the
    // default one with ~64 real pushes.
    let alice = Repo::new();
    let bob = Repo::new();

    let tx = AtomicTransport::new();
    alice.commit_file("f.txt", b"0", "base");
    push_all(alice.path(), &tx).expect("alice base push");
    pull_all(bob.path(), &tx, "default").expect("bob clones base");
    let shared_tip = head_hash(alice.path());

    // The base push above already contributed the chain's first node;
    // grow to TEST_DEPTH exactly (the next push is the one that would
    // itself re-baseline).
    let alice_tip = grow_chain_to_test_depth(&alice, &tx);

    // bob, still at the shared base, races with a stale expectation. The
    // remote's current depth (TEST_DEPTH) means this push, if it reached
    // the packmap CAS, WOULD re-baseline (TEST_DEPTH + 1 > TEST_DEPTH).
    bob.commit_file("f.txt", b"bob-divergent", "bob-divergent");
    let bob_tip = head_hash(bob.path());
    let bob_store = ObjectStore::open(&RepoLayout::single(bob.path())).unwrap();

    let err = push_branch_with_depth(
        &tx,
        &bob_store,
        "main",
        bob_tip,
        RefWriteCondition::Match(shared_tip),
        TEST_DEPTH,
    )
    .unwrap_err();
    assert!(
        matches!(err, DispatchError::NonFastForwardPush { .. }),
        "expected NonFastForwardPush, got {err:?}"
    );

    // The remote must be untouched: the atomic advance never let bob's
    // would-be re-baseline reset land without also winning the head CAS.
    assert_eq!(tx.read_ref("refs/heads/main").unwrap(), Some(alice_tip));
    assert_eq!(packmap_chain(&tx, "main").len(), TEST_DEPTH);
    let carol = Repo::new();
    pull_all(carol.path(), &tx, "default")
        .expect("remote must stay clonable after the loser's blocked re-baseline");
    assert_eq!(
        fs::read(carol.path().join("f.txt")).unwrap(),
        (TEST_DEPTH - 1).to_string().as_bytes()
    );

    // The loser retries: fast-forward onto alice's tip, recommit, push
    // again. The chain is still at TEST_DEPTH, so this retry ALSO decides
    // to re-baseline — and this time it wins the head CAS outright (nothing
    // else moved the head), collapsing the chain to one self-contained
    // node covering the full merged history.
    fetch_all(bob.path(), &tx, "default").expect("bob's retry fetch");
    let alice_hex = mkit_core::to_hex(&alice_tip);
    bob.ok(&["reset", "--hard", "-f", &alice_hex]);
    bob.commit_file("f.txt", b"bob-retry", "bob-retry");
    let bob_retry_tip = head_hash(bob.path());
    let bob_store2 = ObjectStore::open(&RepoLayout::single(bob.path())).unwrap();
    push_branch_with_depth(
        &tx,
        &bob_store2,
        "main",
        bob_retry_tip,
        RefWriteCondition::Match(alice_tip),
        TEST_DEPTH,
    )
    .expect("bob's retry push should succeed");

    assert_eq!(tx.read_ref("refs/heads/main").unwrap(), Some(bob_retry_tip));
    let chain = packmap_chain(&tx, "main");
    assert_eq!(chain.len(), 1, "retry re-baseline collapses the chain");
    assert!(chain_is_all_raw(&tx, &chain));

    // Still clonable, with the full merged history (alice's base +
    // TEST_DEPTH - 1 appending commits, plus bob's retried commit) present
    // and hash-verified.
    let dave = Repo::new();
    pull_all(dave.path(), &tx, "default").expect("clone after the retry re-baseline");
    assert_eq!(fs::read(dave.path().join("f.txt")).unwrap(), b"bob-retry");
    let dave_tip = head_hash(dave.path());
    assert_eq!(dave_tip, bob_retry_tip);
    let dave_store = ObjectStore::open(&RepoLayout::single(dave.path())).unwrap();
    let ancestry = all_ancestor_commit_hashes(&dave_store, dave_tip);
    assert_eq!(
        ancestry.len(),
        TEST_DEPTH + 1,
        "base + {} alice commits + bob's retry commit",
        TEST_DEPTH - 1
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
fn force_push_at_threshold_appends_and_never_resets() {
    let alice = Repo::new();
    let tx = AtomicTransport::new();
    alice.commit_file("f.txt", b"0", "base");
    push_all(alice.path(), &tx).expect("alice base push");
    grow_chain_to_test_depth(&alice, &tx);

    // A FORCE push (unconditional `Any` head condition) of a new
    // fast-forward commit. The chain sits at TEST_DEPTH, so a
    // CAS-conditioned push would re-baseline here — but `Any` forces the
    // ordered advance path, so this must append instead.
    alice.commit_file("f.txt", b"forced", "forced");
    let forced_tip = head_hash(alice.path());
    let store = ObjectStore::open(&RepoLayout::single(alice.path())).unwrap();
    push_branch_with_depth(
        &tx,
        &store,
        "main",
        forced_tip,
        RefWriteCondition::Any,
        TEST_DEPTH,
    )
    .expect("force push at threshold should append, not reset");

    // Appended, not reset: the chain grew to TEST_DEPTH + 1 and its NEWEST
    // node still chains to a `Some` prev (a re-baseline would leave one
    // lone `prev = None` node, i.e. `chain.len() == 1`). `packmap_chain`
    // walks newest-first, so `chain[0]` is that newest node.
    let chain = packmap_chain(&tx, "main");
    assert_eq!(
        chain.len(),
        TEST_DEPTH + 1,
        "a force push at the threshold must append, not reset to a single node"
    );
    assert!(
        chain[0].prev.is_some(),
        "newest node reset to prev = None — a re-baseline leaked through on an `Any` force push"
    );
    assert_eq!(tx.read_ref("refs/heads/main").unwrap(), Some(forced_tip));

    // The remote stays clonable with the full history intact.
    let bob = Repo::new();
    pull_all(bob.path(), &tx, "default").expect("clone after the force-push append");
    assert_eq!(fs::read(bob.path().join("f.txt")).unwrap(), b"forced");
    assert_eq!(head_hash(bob.path()), forced_tip);
    let bob_store = ObjectStore::open(&RepoLayout::single(bob.path())).unwrap();
    let ancestry = all_ancestor_commit_hashes(&bob_store, forced_tip);
    assert_eq!(
        ancestry.len(),
        TEST_DEPTH + 1,
        "base + {} appending commits + the forced commit",
        TEST_DEPTH - 1
    );
}
