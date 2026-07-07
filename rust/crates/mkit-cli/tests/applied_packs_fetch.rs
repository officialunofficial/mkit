//! Issue #409: fetch-side applied-pack record.
//!
//! Verifies, via a counting transport wrapper around the in-process
//! `MemoryTransport`, that a steady-state fetch skips packs already
//! recorded as applied (downloading zero packs when the remote chain
//! hasn't grown, and exactly the new pack when it has), and that the
//! self-heal path recovers if the local object store is wiped out-of-band
//! while the applied-packs record survives.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

use mkit_cli::remote_dispatch::{DispatchError, fetch_all, push_all};
use mkit_core::hash::{self, Hash};
use mkit_core::layout::RepoLayout;
use mkit_core::ops::reachable_objects;
use mkit_core::protocol::{PackKey, RefWriteCondition, Transport, TransportResult};
use mkit_core::refs::{self, Ref};
use mkit_core::store::ObjectStore;
use mkit_core::transfer;
use mkit_transport_file::FileTransport;
use mkit_transport_memory::MemoryTransport;

fn mkit_bin() -> &'static str {
    env!("CARGO_BIN_EXE_mkit")
}

fn run_in(cwd: &Path, args: &[&str]) -> std::process::Output {
    let xdg = tempfile::tempdir().expect("xdg tempdir");
    let out = Command::new(mkit_bin())
        .args(args)
        .current_dir(cwd)
        .env("XDG_CONFIG_HOME", xdg.path())
        .output()
        .expect("spawn mkit");
    drop(xdg);
    assert!(
        out.status.success(),
        "mkit {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

fn init_repo(dir: &Path) {
    run_in(dir, &["init"]);
    run_in(dir, &["keygen"]);
}

fn commit_all(dir: &Path, msg: &str) {
    run_in(dir, &["add", "."]);
    run_in(dir, &["commit", "-m", msg]);
}

/// Counts calls to `download_pack` specifically (NOT `download_blob`, which
/// the packlist chain-node walk uses and which stays unconditional per the
/// #409 spec) so tests can assert exactly how many *pack* bodies were
/// pulled over the wire on a given fetch. Everything else delegates to an
/// inner [`MemoryTransport`].
struct CountingTransport {
    inner: MemoryTransport,
    pack_downloads: AtomicUsize,
}

impl CountingTransport {
    fn new() -> Self {
        Self {
            inner: MemoryTransport::new(),
            pack_downloads: AtomicUsize::new(0),
        }
    }

    /// Read-and-reset the pack-download counter.
    fn take_pack_downloads(&self) -> usize {
        self.pack_downloads.swap(0, Ordering::SeqCst)
    }
}

impl Transport for CountingTransport {
    fn upload_pack(&self, bytes: &[u8], key: &PackKey) -> TransportResult<()> {
        self.inner.upload_pack(bytes, key)
    }

    fn download_pack(&self, key: &PackKey) -> TransportResult<Vec<u8>> {
        self.pack_downloads.fetch_add(1, Ordering::SeqCst);
        self.inner.download_pack(key)
    }

    fn pack_exists(&self, key: &PackKey) -> TransportResult<bool> {
        self.inner.pack_exists(key)
    }

    // Explicitly delegated (rather than left to the trait's default, which
    // would route through `Self::download_pack`/`Self::upload_pack` and
    // inflate the pack counter with chain-node blob traffic): the packlist
    // chain walk is unconditional by design (#409) and must never count
    // against the pack-download assertions below.
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

#[test]
fn steady_state_fetch_skips_already_applied_packs() {
    let alice = tempfile::tempdir().unwrap();
    let bob = tempfile::tempdir().unwrap();
    init_repo(alice.path());
    init_repo(bob.path());

    let tx = CountingTransport::new();

    // Two pushes from alice BEFORE bob ever fetches, so bob's first fetch
    // walks a two-pack chain.
    fs::write(alice.path().join("a.txt"), b"v1").unwrap();
    commit_all(alice.path(), "c1");
    push_all(alice.path(), &tx).expect("push 1");

    fs::write(alice.path().join("a.txt"), b"v2").unwrap();
    commit_all(alice.path(), "c2");
    push_all(alice.path(), &tx).expect("push 2");

    // Fetch 1: pulls the whole (two-pack) chain. Reset the counter — this
    // test only asserts about the *steady-state* fetches that follow.
    fetch_all(bob.path(), &tx, "default").expect("fetch 1");
    let first_fetch_downloads = tx.take_pack_downloads();
    assert!(
        first_fetch_downloads >= 1,
        "first fetch must download at least one pack, got {first_fetch_downloads}"
    );

    // Fetch 2: nothing changed on the remote since fetch 1 — every pack in
    // the chain is already recorded as applied, so this must download ZERO
    // packs (the whole point of #409).
    fetch_all(bob.path(), &tx, "default").expect("fetch 2 (steady state)");
    assert_eq!(
        tx.take_pack_downloads(),
        0,
        "a fetch with no new remote packs must download zero packs"
    );

    // Push a third time from alice: exactly one new pack enters the chain.
    fs::write(alice.path().join("a.txt"), b"v3").unwrap();
    commit_all(alice.path(), "c3");
    push_all(alice.path(), &tx).expect("push 3");

    // Fetch 3: must download exactly the one new pack, skipping every
    // earlier pack in the chain.
    fetch_all(bob.path(), &tx, "default").expect("fetch 3");
    assert_eq!(
        tx.take_pack_downloads(),
        1,
        "a fetch with exactly one new remote pack must download exactly one pack"
    );

    // Sanity: bob's remote-tracking ref actually landed on alice's latest
    // tip (fetch never checks out the working tree, so we assert via the
    // ref rather than reading a working-tree file).
    let alice_tip = refs::read_ref(&RepoLayout::single(alice.path()), "main")
        .unwrap()
        .unwrap();
    let bob_tracking_tip =
        refs::read_remote_ref(&RepoLayout::single(bob.path()), "default", "main")
            .unwrap()
            .unwrap();
    assert_eq!(alice_tip, bob_tracking_tip);
}

#[test]
fn self_heal_recovers_when_object_store_is_wiped_but_record_survives() {
    let alice = tempfile::tempdir().unwrap();
    let bob = tempfile::tempdir().unwrap();
    init_repo(alice.path());
    init_repo(bob.path());

    let tx = CountingTransport::new();

    fs::write(alice.path().join("a.txt"), b"alpha").unwrap();
    fs::create_dir_all(alice.path().join("src")).unwrap();
    fs::write(alice.path().join("src/main.rs"), b"fn main() {}\n").unwrap();
    commit_all(alice.path(), "c1");
    push_all(alice.path(), &tx).expect("push");

    // Populates bob's object store AND the applied-packs record.
    fetch_all(bob.path(), &tx, "default").expect("initial fetch");
    assert!(tx.take_pack_downloads() >= 1);

    // Wipe bob's object store contents out-of-band, but keep the
    // applied-packs record — exactly the staleness scenario the self-heal
    // path exists for.
    let bob_mkit = bob.path().join(".mkit");
    let objects_dir = bob_mkit.join("objects");
    assert!(objects_dir.is_dir(), "precondition: objects dir exists");
    fs::remove_dir_all(&objects_dir).unwrap();
    fs::create_dir_all(&objects_dir).unwrap();
    assert!(
        bob_mkit.join("applied-packs").join("default").exists(),
        "precondition: applied-packs record must survive the wipe"
    );

    // Fetch again: without self-heal this would skip every pack (they're
    // all still "recorded applied") yet find no objects, and blow up
    // downstream. With self-heal it must succeed by clearing the stale
    // record and re-downloading everything.
    fetch_all(bob.path(), &tx, "default").expect("fetch must self-heal, not fail");
    assert!(
        tx.take_pack_downloads() >= 1,
        "the self-heal retry must re-download the pack(s)"
    );

    // Every object reachable from bob's remote-tracking tip must be back.
    let bob_layout = RepoLayout::single(bob.path());
    let bob_store = ObjectStore::open(&bob_layout).unwrap();
    let remote_tip = refs::read_remote_ref(&bob_layout, "default", "main")
        .unwrap()
        .unwrap();
    let closure: HashSet<_> = reachable_objects(&bob_store, &remote_tip)
        .unwrap()
        .into_iter()
        .collect();
    assert!(
        closure.len() >= 4,
        "closure must include >= commit+tree+2 blobs after self-heal, got {}",
        closure.len()
    );

    // A subsequent steady-state fetch is back to normal: zero downloads.
    fetch_all(bob.path(), &tx, "default").expect("post-heal fetch");
    assert_eq!(
        tx.take_pack_downloads(),
        0,
        "after self-heal, the record must be accurate again"
    );
}

/// Walk `branch`'s packmap chain on `tx` and collect every pack digest it
/// references, independent of the fetch path under test — used to compute
/// an expected set to compare the applied-packs record against.
fn packmap_chain_packs(tx: &dyn Transport, branch: &str) -> HashSet<Hash> {
    let mut out = HashSet::new();
    let mut cursor = tx.read_ref(&format!("refs/mkit/packmap/{branch}")).unwrap();
    while let Some(key) = cursor {
        let bytes = tx.download_blob(&PackKey::from_hash(key)).unwrap();
        let node = transfer::decode_packlist(&bytes).unwrap();
        out.extend(node.packs.iter().copied());
        cursor = node.prev;
    }
    out
}

/// Parse an applied-packs record file's contents (one lowercase 64-hex
/// digest per line, per the module's on-disk format) into a set of digests.
fn parse_record(path: &Path) -> HashSet<Hash> {
    fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|line| {
            hash::from_hex(line).unwrap_or_else(|e| panic!("malformed record line {line:?}: {e}"))
        })
        .collect()
}

#[test]
fn multi_branch_fetch_persists_the_union_of_every_branchs_pack_digests() {
    let alice = tempfile::tempdir().unwrap();
    init_repo(alice.path());

    // Three branches off the same initial tip, each with its own distinct
    // commit — so each branch's push is a distinct, non-overlapping pack.
    fs::write(alice.path().join("main.txt"), b"main").unwrap();
    commit_all(alice.path(), "c-main");

    run_in(alice.path(), &["switch", "-c", "bbb"]);
    fs::write(alice.path().join("bbb.txt"), b"bbb").unwrap();
    commit_all(alice.path(), "c-bbb");

    run_in(alice.path(), &["switch", "main"]);
    run_in(alice.path(), &["switch", "-c", "ccc"]);
    fs::write(alice.path().join("ccc.txt"), b"ccc").unwrap();
    commit_all(alice.path(), "c-ccc");

    let remote = tempfile::tempdir().unwrap();
    let tx = FileTransport::new(remote.path());
    push_all(alice.path(), &tx).expect("push all three branches");

    // Independently compute, straight off the remote's packmap chains, the
    // union of every pack digest across all three branches — the baseline
    // the applied-packs record must match after a single fetch.
    let mut expected = HashSet::new();
    for branch in ["main", "bbb", "ccc"] {
        expected.extend(packmap_chain_packs(&tx, branch));
    }
    assert_eq!(
        expected.len(),
        3,
        "sanity: each of the 3 branches must contribute exactly one distinct pack"
    );

    let bob = tempfile::tempdir().unwrap();
    init_repo(bob.path());
    let n = fetch_all(bob.path(), &tx, "default").expect("single fetch across all branches");
    assert_eq!(n, 3, "fetch must report all three branches");

    let record_path = bob.path().join(".mkit/applied-packs/default");
    let got = parse_record(&record_path);
    assert_eq!(
        got, expected,
        "the applied-packs record after one fetch must contain the union of \
         all three branches' pack digests"
    );
}

#[test]
fn cross_branch_fetch_persists_progress_before_a_later_branchs_failure_propagates() {
    let alice = tempfile::tempdir().unwrap();
    init_repo(alice.path());

    // An initial commit on "main" gives `switch -c` a HEAD to branch from;
    // "main" itself is deleted below so the remote only ever advertises
    // "aaa" and "zzz".
    fs::write(alice.path().join("seed.txt"), b"seed").unwrap();
    commit_all(alice.path(), "c-seed");

    // "aaa" sorts before "zzz" in `FileTransport::list_refs` (it sorts by
    // name), so `fetch_all` is guaranteed to process "aaa" first.
    run_in(alice.path(), &["switch", "-c", "aaa"]);
    fs::write(alice.path().join("aaa.txt"), b"aaa").unwrap();
    commit_all(alice.path(), "c-aaa");

    run_in(alice.path(), &["switch", "main"]);
    run_in(alice.path(), &["switch", "-c", "zzz"]);
    fs::write(alice.path().join("zzz.txt"), b"zzz").unwrap();
    commit_all(alice.path(), "c-zzz");

    // Delete "main" (current branch is "zzz", so this is allowed) so the
    // remote only ever advertises "aaa" and "zzz" — nothing else can
    // succeed between them and mask the assertion below.
    run_in(alice.path(), &["branch", "-D", "main"]);

    let remote = tempfile::tempdir().unwrap();
    let tx = FileTransport::new(remote.path());
    push_all(alice.path(), &tx).expect("push aaa and zzz");

    // Confirm the ordering assumption the test relies on.
    let names: Vec<String> = tx
        .list_refs("refs/heads/")
        .unwrap()
        .into_iter()
        .map(|r| r.name)
        .collect();
    let aaa_pos = names.iter().position(|n| n == "aaa");
    let zzz_pos = names.iter().position(|n| n == "zzz");
    assert!(
        aaa_pos.is_some() && zzz_pos.is_some() && aaa_pos < zzz_pos,
        "precondition: list_refs must return aaa before zzz, got {names:?}"
    );

    // Baseline: the pack(s) a successful fetch of "aaa" alone would apply.
    let aaa_packs = packmap_chain_packs(&tx, "aaa");
    assert!(!aaa_packs.is_empty());

    // Delete the remote's packmap ref for "zzz" only — its branch head ref
    // stays advertised, so `fetch_all` still lists it, but resolving its
    // packmap now returns `None`, which is `DispatchError::PackmapMissing`.
    let zzz_packmap_path = remote.path().join("refs/mkit/packmap/zzz");
    assert!(
        zzz_packmap_path.exists(),
        "precondition: zzz's packmap ref exists on the remote"
    );
    fs::remove_file(&zzz_packmap_path).unwrap();

    let bob = tempfile::tempdir().unwrap();
    init_repo(bob.path());
    let err = fetch_all(bob.path(), &tx, "default")
        .expect_err("zzz's missing packmap must fail the whole fetch");
    assert!(
        matches!(&err, DispatchError::PackmapMissing(name) if name == "zzz"),
        "expected PackmapMissing(\"zzz\"), got {err:?}"
    );

    // Despite the fetch failing on "zzz", the single end-of-fetch persist
    // must still have durably recorded the packs applied for "aaa" (which
    // was processed first, by construction).
    let record_path = bob.path().join(".mkit/applied-packs/default");
    assert!(
        record_path.exists(),
        "the applied-packs record must have been persisted despite the later failure"
    );
    let got = parse_record(&record_path);
    assert_eq!(
        got, aaa_packs,
        "the record must contain exactly aaa's applied packs after the failed fetch"
    );
}

/// Build a repo with three branches — each contributing one distinct pack —
/// pushed to a fresh file-transport remote, and return that remote's
/// tempdir. Shared setup for the load-once / persist-once counting tests
/// below (#546), which drive the fetch through the CLI binary so the
/// warning lines the applied-packs cache emits on injected I/O failures can
/// be counted on the subprocess's stderr.
#[cfg(unix)]
fn three_branch_file_remote() -> tempfile::TempDir {
    let alice = tempfile::tempdir().unwrap();
    init_repo(alice.path());

    fs::write(alice.path().join("main.txt"), b"main").unwrap();
    commit_all(alice.path(), "c-main");

    run_in(alice.path(), &["switch", "-c", "bbb"]);
    fs::write(alice.path().join("bbb.txt"), b"bbb").unwrap();
    commit_all(alice.path(), "c-bbb");

    run_in(alice.path(), &["switch", "main"]);
    run_in(alice.path(), &["switch", "-c", "ccc"]);
    fs::write(alice.path().join("ccc.txt"), b"ccc").unwrap();
    commit_all(alice.path(), "c-ccc");

    let remote = tempfile::tempdir().unwrap();
    push_all(alice.path(), &FileTransport::new(remote.path())).expect("push all three branches");
    remote
}

/// #546 acceptance: the applied-packs record is loaded exactly ONCE per
/// fetch, not once per branch. Every `AppliedPacks::load` that hits an
/// unreadable record emits exactly one "could not read applied-packs
/// record" warning (and nothing else does), so an unreadable record turns
/// the subprocess's stderr into a load counter: a three-branch fetch under
/// the old per-branch lifecycle printed it three times; the hoisted
/// lifecycle must print it exactly once. Doubles as a non-fatal-cache-I/O
/// check — the fetch itself must still succeed.
#[cfg(unix)]
#[test]
fn multi_branch_fetch_loads_the_record_exactly_once() {
    use std::os::unix::fs::PermissionsExt;

    let remote = three_branch_file_remote();
    let url = format!("mkit+file://{}", remote.path().display());

    let bob = tempfile::tempdir().unwrap();
    init_repo(bob.path());
    run_in(bob.path(), &["remote", "add", "origin", &url]);

    // Pre-create an UNREADABLE record so every load attempt fails (and
    // warns) deterministically.
    let record_dir = bob.path().join(".mkit").join("applied-packs");
    fs::create_dir_all(&record_dir).unwrap();
    let record_path = record_dir.join("origin");
    fs::write(&record_path, b"").unwrap();
    fs::set_permissions(&record_path, fs::Permissions::from_mode(0o000)).unwrap();
    if fs::read(&record_path).is_ok() {
        // Permission bits aren't enforced for this user (e.g. running as
        // root) — the failure injection can't work, so skip.
        eprintln!("skipping: permission denial is not enforced in this environment");
        return;
    }

    // Non-fatal cache I/O: `run_in` asserts the fetch SUCCEEDS despite the
    // unreadable record.
    let out = run_in(bob.path(), &["fetch", "origin"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        stderr
            .matches("could not read applied-packs record")
            .count(),
        1,
        "a three-branch fetch must load the applied-packs record exactly once, \
         not once per branch; stderr:\n{stderr}"
    );
    // The end-of-fetch persist replaces the unreadable file via the atomic
    // tmp+rename (which needs only directory write permission), so it must
    // NOT have warned.
    assert_eq!(
        stderr
            .matches("could not persist applied-packs record")
            .count(),
        0,
        "the single persist over the unreadable record must succeed; stderr:\n{stderr}"
    );
    // All three branches were still fetched.
    for branch in ["main", "bbb", "ccc"] {
        assert!(
            refs::read_remote_ref(&RepoLayout::single(bob.path()), "origin", branch)
                .unwrap()
                .is_some(),
            "branch '{branch}' must have been fetched despite the cache read failure"
        );
    }
}

/// #546 acceptance: the applied-packs record is persisted at most ONCE per
/// fetch, not once per branch. Mirror of the load-counting test above: a
/// read-only `applied-packs/` directory makes every persist attempt fail at
/// tmp-file creation with exactly one "could not persist applied-packs
/// record" warning, so stderr counts persist attempts — one, not three.
/// The load stays clean (the record file is simply absent), and the fetch
/// itself must still succeed (non-fatal cache I/O).
#[cfg(unix)]
#[test]
fn multi_branch_fetch_persists_the_record_at_most_once() {
    use std::os::unix::fs::PermissionsExt;

    let remote = three_branch_file_remote();
    let url = format!("mkit+file://{}", remote.path().display());

    let bob = tempfile::tempdir().unwrap();
    init_repo(bob.path());
    run_in(bob.path(), &["remote", "add", "origin", &url]);

    // Pre-create the applied-packs DIRECTORY read-only: the record file is
    // absent (a clean, warning-free empty load) but any persist fails to
    // create its sibling tmp file.
    let record_dir = bob.path().join(".mkit").join("applied-packs");
    fs::create_dir_all(&record_dir).unwrap();
    fs::set_permissions(&record_dir, fs::Permissions::from_mode(0o555)).unwrap();
    if fs::write(record_dir.join("probe"), b"").is_ok() {
        // Permission bits aren't enforced for this user (e.g. running as
        // root) — the failure injection can't work, so skip.
        fs::remove_file(record_dir.join("probe")).unwrap();
        fs::set_permissions(&record_dir, fs::Permissions::from_mode(0o755)).unwrap();
        eprintln!("skipping: permission denial is not enforced in this environment");
        return;
    }

    // Non-fatal cache I/O: `run_in` asserts the fetch SUCCEEDS despite the
    // unwritable record directory.
    let out = run_in(bob.path(), &["fetch", "origin"]);

    // Restore permissions first so the tempdir is cleanable even if an
    // assertion below fails.
    fs::set_permissions(&record_dir, fs::Permissions::from_mode(0o755)).unwrap();

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        stderr
            .matches("could not persist applied-packs record")
            .count(),
        1,
        "a three-branch fetch must persist the applied-packs record exactly once, \
         not once per branch; stderr:\n{stderr}"
    );
    assert_eq!(
        stderr
            .matches("could not read applied-packs record")
            .count(),
        0,
        "an absent record file is a clean empty load, never a warning; stderr:\n{stderr}"
    );
    // All three branches were still fetched.
    for branch in ["main", "bbb", "ccc"] {
        assert!(
            refs::read_remote_ref(&RepoLayout::single(bob.path()), "origin", branch)
                .unwrap()
                .is_some(),
            "branch '{branch}' must have been fetched despite the cache write failure"
        );
    }
}
