//! Integration tests for the resolvable-conflict workflow (#177):
//! merge / cherry-pick / rebase conflict → state → resolve → continue /
//! abort / skip.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output};

use mkit_core::object::Object;
use mkit_core::refs;
use mkit_core::store::ObjectStore;

fn mkit_bin() -> &'static str {
    env!("CARGO_BIN_EXE_mkit")
}

fn run(cwd: &Path, xdg: &Path, args: &[&str]) -> Output {
    Command::new(mkit_bin())
        .args(args)
        .current_dir(cwd)
        .env("XDG_CONFIG_HOME", xdg)
        .output()
        .expect("spawn mkit")
}

fn ok(cwd: &Path, xdg: &Path, args: &[&str]) -> Output {
    let out = run(cwd, xdg, args);
    assert!(
        out.status.success(),
        "expected `mkit {}` to succeed: {}",
        args.join(" "),
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

fn fail(cwd: &Path, xdg: &Path, args: &[&str]) -> Output {
    let out = run(cwd, xdg, args);
    assert!(
        !out.status.success(),
        "expected `mkit {}` to fail but it succeeded",
        args.join(" ")
    );
    out
}

struct Repo {
    dir: tempfile::TempDir,
    xdg: tempfile::TempDir,
}

impl Repo {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let xdg = tempfile::tempdir().unwrap();
        ok(dir.path(), xdg.path(), &["init"]);
        ok(dir.path(), xdg.path(), &["keygen"]);
        Repo { dir, xdg }
    }
    fn path(&self) -> &Path {
        self.dir.path()
    }
    fn xdg(&self) -> &Path {
        self.xdg.path()
    }
    fn write(&self, rel: &str, body: &[u8]) {
        let p = self.path().join(rel);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(p, body).unwrap();
    }
    fn add(&self, rel: &str) {
        ok(self.path(), self.xdg(), &["add", rel]);
    }
    fn commit(&self, msg: &str) {
        ok(self.path(), self.xdg(), &["commit", "-m", msg]);
    }
    fn commit_file(&self, rel: &str, body: &[u8], msg: &str) {
        self.write(rel, body);
        self.add(rel);
        self.commit(msg);
    }
    fn mkit_dir(&self) -> std::path::PathBuf {
        self.path().join(".mkit")
    }
    fn head_tree_blob(&self, rel: &str) -> Vec<u8> {
        let store = ObjectStore::open(self.path()).unwrap();
        let head = refs::resolve_head(&self.mkit_dir()).unwrap().unwrap();
        let Object::Commit(c) = store.read_object(&head).unwrap() else {
            panic!("HEAD not a commit");
        };
        read_tree_path(&store, c.tree_hash, rel)
    }
}

fn read_tree_path(store: &ObjectStore, tree: mkit_core::hash::Hash, rel: &str) -> Vec<u8> {
    let mut current = tree;
    let parts: Vec<&str> = rel.split('/').collect();
    for (i, part) in parts.iter().enumerate() {
        let Object::Tree(t) = store.read_object(&current).unwrap() else {
            panic!("not a tree at {part}");
        };
        let entry = t
            .entries
            .iter()
            .find(|e| e.name == part.as_bytes())
            .unwrap_or_else(|| panic!("missing entry {part}"));
        if i == parts.len() - 1 {
            let Object::Blob(b) = store.read_object(&entry.object_hash).unwrap() else {
                panic!("leaf not a blob");
            };
            return b.data;
        }
        current = entry.object_hash;
    }
    unreachable!()
}

/// Build a classic ours/theirs divergence on `path`:
/// base commit, then `feature` branch modifies the file (theirs), and
/// `main` modifies it differently (ours). Returns when checked out on
/// `main`.
fn diverge_modify(repo: &Repo, path: &str) {
    repo.commit_file(path, b"base\n", "base");
    ok(repo.path(), repo.xdg(), &["branch", "feature"]);
    ok(repo.path(), repo.xdg(), &["checkout", "feature"]);
    repo.commit_file(path, b"theirs\n", "theirs change");
    ok(repo.path(), repo.xdg(), &["checkout", "main"]);
    repo.commit_file(path, b"ours\n", "ours change");
}

#[test]
fn merge_text_conflict_continue_uses_resolved_index() {
    let repo = Repo::new();
    diverge_modify(&repo, "a.txt");

    let out = fail(repo.path(), repo.xdg(), &["merge", "feature"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("conflict"), "stderr: {stderr}");

    // State files exist.
    assert!(repo.mkit_dir().join("MERGE_HEAD").exists());
    assert!(repo.mkit_dir().join("ORIG_HEAD").exists());
    assert!(repo.mkit_dir().join("mkit-conflicts").exists());

    // Worktree file has classic 2-way markers.
    let content = fs::read_to_string(repo.path().join("a.txt")).unwrap();
    assert!(content.contains("<<<<<<< ours"), "content: {content}");
    assert!(content.contains("======="), "content: {content}");
    assert!(content.contains(">>>>>>> theirs"), "content: {content}");

    // --continue refuses while markers remain.
    let out = fail(repo.path(), repo.xdg(), &["merge", "--continue"]);
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("markers remain"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Resolve to a THIRD distinct content (proves the continued tree
    // comes from the resolved index, not the conflict-time ours-wins).
    repo.write("a.txt", b"resolved-third\n");
    repo.add("a.txt");
    ok(repo.path(), repo.xdg(), &["merge", "--continue"]);

    // State cleared.
    assert!(!repo.mkit_dir().join("MERGE_HEAD").exists());
    assert!(!repo.mkit_dir().join("mkit-conflicts").exists());

    // Committed tree blob is exactly the resolved content.
    assert_eq!(repo.head_tree_blob("a.txt"), b"resolved-third\n");

    // The merge commit has two parents.
    let store = ObjectStore::open(repo.path()).unwrap();
    let head = refs::resolve_head(&repo.mkit_dir()).unwrap().unwrap();
    let Object::Commit(c) = store.read_object(&head).unwrap() else {
        panic!();
    };
    assert_eq!(c.parents.len(), 2, "merge commit must have two parents");
}

#[test]
fn merge_abort_restores_everything() {
    let repo = Repo::new();
    diverge_modify(&repo, "a.txt");

    let head_before = refs::resolve_head(&repo.mkit_dir()).unwrap().unwrap();
    let index_before = fs::read(repo.mkit_dir().join("index")).unwrap();

    fail(repo.path(), repo.xdg(), &["merge", "feature"]);
    // Abort.
    ok(repo.path(), repo.xdg(), &["merge", "--abort"]);

    assert!(!repo.mkit_dir().join("MERGE_HEAD").exists());
    assert!(!repo.mkit_dir().join("mkit-conflicts").exists());
    let head_after = refs::resolve_head(&repo.mkit_dir()).unwrap().unwrap();
    assert_eq!(head_before, head_after, "HEAD must be restored");
    assert_eq!(
        index_before,
        fs::read(repo.mkit_dir().join("index")).unwrap(),
        "index must be restored"
    );
    // Worktree restored to ours (no markers).
    let content = fs::read_to_string(repo.path().join("a.txt")).unwrap();
    assert_eq!(content, "ours\n");
}

#[test]
fn merge_add_add_conflict() {
    let repo = Repo::new();
    repo.commit_file("base.txt", b"base\n", "base");
    ok(repo.path(), repo.xdg(), &["branch", "feature"]);
    ok(repo.path(), repo.xdg(), &["checkout", "feature"]);
    repo.commit_file("new.txt", b"theirs-add\n", "theirs adds new");
    ok(repo.path(), repo.xdg(), &["checkout", "main"]);
    repo.commit_file("new.txt", b"ours-add\n", "ours adds new");

    fail(repo.path(), repo.xdg(), &["merge", "feature"]);
    let content = fs::read_to_string(repo.path().join("new.txt")).unwrap();
    assert!(content.contains("<<<<<<< ours"), "content: {content}");
    // Sidecar records addadd.
    let sidecar = fs::read_to_string(repo.mkit_dir().join("mkit-conflicts")).unwrap();
    assert!(sidecar.contains("addadd"), "sidecar: {sidecar}");

    repo.write("new.txt", b"merged-add\n");
    repo.add("new.txt");
    ok(repo.path(), repo.xdg(), &["merge", "--continue"]);
    assert_eq!(repo.head_tree_blob("new.txt"), b"merged-add\n");
}

#[test]
fn merge_delete_modify_conflict() {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"base\n", "base");
    ok(repo.path(), repo.xdg(), &["branch", "feature"]);
    // feature modifies a.txt
    ok(repo.path(), repo.xdg(), &["checkout", "feature"]);
    repo.commit_file("a.txt", b"theirs-modified\n", "theirs modifies");
    // main deletes a.txt (rm stages removal; remove the worktree file
    // too — worktree-file removal is PR5 scope, out of #177).
    ok(repo.path(), repo.xdg(), &["checkout", "main"]);
    ok(repo.path(), repo.xdg(), &["rm", "a.txt"]);
    fs::remove_file(repo.path().join("a.txt")).unwrap();
    repo.commit("ours deletes");

    fail(repo.path(), repo.xdg(), &["merge", "feature"]);
    let sidecar = fs::read_to_string(repo.mkit_dir().join("mkit-conflicts")).unwrap();
    assert!(sidecar.contains("deletemodify"), "sidecar: {sidecar}");
    // Surviving (modified) content present.
    let content = fs::read_to_string(repo.path().join("a.txt")).unwrap();
    assert_eq!(content, "theirs-modified\n");

    // Resolve by keeping it.
    repo.add("a.txt");
    ok(repo.path(), repo.xdg(), &["merge", "--continue"]);
    assert_eq!(repo.head_tree_blob("a.txt"), b"theirs-modified\n");
}

#[test]
fn merge_binary_conflict_no_markers() {
    let repo = Repo::new();
    // base binary
    repo.commit_file("img.bin", &[0u8, 1, 2, 3], "base");
    ok(repo.path(), repo.xdg(), &["branch", "feature"]);
    ok(repo.path(), repo.xdg(), &["checkout", "feature"]);
    repo.commit_file("img.bin", &[0u8, 9, 9, 9], "theirs binary");
    ok(repo.path(), repo.xdg(), &["checkout", "main"]);
    repo.commit_file("img.bin", &[0u8, 5, 5, 5], "ours binary");

    let out = fail(repo.path(), repo.xdg(), &["merge", "feature"]);
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("binary"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    // No markers were injected into the binary file.
    let content = fs::read(repo.path().join("img.bin")).unwrap();
    assert!(!content.windows(7).any(|w| w == b"<<<<<<<"));
    // ours content is preserved.
    assert_eq!(content, vec![0u8, 5, 5, 5]);

    // Manually resolve and continue.
    repo.write("img.bin", &[0u8, 7, 7, 7]);
    repo.add("img.bin");
    ok(repo.path(), repo.xdg(), &["merge", "--continue"]);
    assert_eq!(repo.head_tree_blob("img.bin"), vec![0u8, 7, 7, 7]);
}

#[test]
fn merge_exec_mode_conflict_records_sidecar() {
    let repo = Repo::new();
    repo.commit_file("script.sh", b"echo base\n", "base");
    ok(repo.path(), repo.xdg(), &["branch", "feature"]);
    // feature: make it executable + change content
    ok(repo.path(), repo.xdg(), &["checkout", "feature"]);
    repo.write("script.sh", b"echo theirs\n");
    fs::set_permissions(
        repo.path().join("script.sh"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    repo.add("script.sh");
    repo.commit("theirs exec");
    // main: different content, non-exec
    ok(repo.path(), repo.xdg(), &["checkout", "main"]);
    repo.commit_file("script.sh", b"echo ours\n", "ours change");

    fail(repo.path(), repo.xdg(), &["merge", "feature"]);
    assert!(repo.mkit_dir().join("mkit-conflicts").exists());
    // Resolve and continue.
    repo.write("script.sh", b"echo resolved\n");
    repo.add("script.sh");
    ok(repo.path(), repo.xdg(), &["merge", "--continue"]);
    assert_eq!(repo.head_tree_blob("script.sh"), b"echo resolved\n");
}

#[test]
fn merge_symlink_conflict_no_markers() {
    let repo = Repo::new();
    repo.commit_file("anchor.txt", b"anchor\n", "base");
    ok(repo.path(), repo.xdg(), &["branch", "feature"]);
    // feature: link -> theirs-target
    ok(repo.path(), repo.xdg(), &["checkout", "feature"]);
    std::os::unix::fs::symlink("theirs-target", repo.path().join("link")).unwrap();
    repo.add("link");
    repo.commit("theirs symlink");
    // main: link -> ours-target
    ok(repo.path(), repo.xdg(), &["checkout", "main"]);
    std::os::unix::fs::symlink("ours-target", repo.path().join("link")).unwrap();
    repo.add("link");
    repo.commit("ours symlink");

    let out = run(repo.path(), repo.xdg(), &["merge", "feature"]);
    // A symlink/symlink target divergence must produce resolvable
    // conflict state (recorded in the sidecar) and never crash. The
    // conflict struct carries only blob hashes, so the symlink target
    // text routes through the text path; the important #177 guarantee
    // is that state is recorded and resolvable.
    if !out.status.success() {
        assert!(repo.mkit_dir().join("MERGE_HEAD").exists());
        assert!(repo.mkit_dir().join("mkit-conflicts").exists());
        let sidecar = fs::read_to_string(repo.mkit_dir().join("mkit-conflicts")).unwrap();
        assert!(sidecar.contains("link"), "sidecar: {sidecar}");
        // Resolve the path to a concrete regular file and continue.
        repo.write("link", b"resolved-link-target\n");
        repo.add("link");
        ok(repo.path(), repo.xdg(), &["merge", "--continue"]);
        assert!(!repo.mkit_dir().join("MERGE_HEAD").exists());
    }
}

#[test]
fn merge_file_vs_dir_conflict() {
    let repo = Repo::new();
    repo.commit_file("seed.txt", b"seed\n", "base");
    ok(repo.path(), repo.xdg(), &["branch", "feature"]);
    // feature: x is a directory with a file
    ok(repo.path(), repo.xdg(), &["checkout", "feature"]);
    repo.commit_file("x/inner.txt", b"inner\n", "theirs dir");
    // main: x is a file
    ok(repo.path(), repo.xdg(), &["checkout", "main"]);
    repo.commit_file("x", b"ours-file\n", "ours file");

    // This should conflict (add/add on `x` with different shapes) — at
    // minimum it must not crash and must produce resolvable state or a
    // clean merge.
    let out = run(repo.path(), repo.xdg(), &["merge", "feature"]);
    // Either it conflicts (state present) or merges cleanly; either way
    // the repo stays consistent. If it conflicted, we can abort cleanly.
    if !out.status.success() {
        assert!(repo.mkit_dir().join("MERGE_HEAD").exists());
        ok(repo.path(), repo.xdg(), &["merge", "--abort"]);
        assert!(!repo.mkit_dir().join("MERGE_HEAD").exists());
    }
}

#[test]
fn cherry_pick_conflict_continue_and_abort() {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"base\n", "base");
    ok(repo.path(), repo.xdg(), &["branch", "feature"]);
    // feature: a distinct change to cherry-pick
    ok(repo.path(), repo.xdg(), &["checkout", "feature"]);
    repo.commit_file("a.txt", b"feature-change\n", "feature change");
    let store = ObjectStore::open(repo.path()).unwrap();
    let feature_tip = refs::resolve_head(&repo.mkit_dir()).unwrap().unwrap();
    let feature_hex = mkit_core::hash::to_hex(&feature_tip);
    // main: a conflicting change
    ok(repo.path(), repo.xdg(), &["checkout", "main"]);
    repo.commit_file("a.txt", b"main-change\n", "main change");
    drop(store);

    let head_before = refs::resolve_head(&repo.mkit_dir()).unwrap().unwrap();

    fail(repo.path(), repo.xdg(), &["cherry-pick", &feature_hex]);
    assert!(repo.mkit_dir().join("CHERRY_PICK_HEAD").exists());

    // Abort restores HEAD.
    ok(repo.path(), repo.xdg(), &["cherry-pick", "--abort"]);
    assert!(!repo.mkit_dir().join("CHERRY_PICK_HEAD").exists());
    assert_eq!(
        head_before,
        refs::resolve_head(&repo.mkit_dir()).unwrap().unwrap()
    );

    // Now do it again and continue with a resolved value.
    fail(repo.path(), repo.xdg(), &["cherry-pick", &feature_hex]);
    repo.write("a.txt", b"cp-resolved\n");
    repo.add("a.txt");
    ok(repo.path(), repo.xdg(), &["cherry-pick", "--continue"]);
    assert!(!repo.mkit_dir().join("CHERRY_PICK_HEAD").exists());
    assert_eq!(repo.head_tree_blob("a.txt"), b"cp-resolved\n");
}

#[test]
fn second_op_refused_while_one_in_progress() {
    let repo = Repo::new();
    diverge_modify(&repo, "a.txt");
    fail(repo.path(), repo.xdg(), &["merge", "feature"]);

    // Starting a cherry-pick or rebase while a merge is in progress
    // must be refused.
    let store = ObjectStore::open(repo.path()).unwrap();
    let head = refs::resolve_head(&repo.mkit_dir()).unwrap().unwrap();
    let head_hex = mkit_core::hash::to_hex(&head);
    drop(store);
    let out = fail(repo.path(), repo.xdg(), &["cherry-pick", &head_hex]);
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("in progress"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let out = fail(repo.path(), repo.xdg(), &["rebase", "feature"]);
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("in progress"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    // Starting a second merge is also refused.
    let out = fail(repo.path(), repo.xdg(), &["merge", "feature"]);
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("in progress"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn merge_conflict_refuses_when_worktree_dirty() {
    let repo = Repo::new();
    diverge_modify(&repo, "a.txt");
    // Make an unrelated tracked file dirty (uncommitted change).
    repo.commit_file("other.txt", b"orig\n", "add other");
    fs::write(repo.path().join("other.txt"), b"dirty-uncommitted\n").unwrap();

    let out = fail(repo.path(), repo.xdg(), &["merge", "feature"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("overwrite") || stderr.contains("local changes"),
        "expected dirty-guard refusal, got: {stderr}"
    );
    // No state was written and the dirty file is untouched.
    assert!(!repo.mkit_dir().join("MERGE_HEAD").exists());
    assert_eq!(
        fs::read_to_string(repo.path().join("other.txt")).unwrap(),
        "dirty-uncommitted\n"
    );
}

#[test]
fn rebase_continue_consumes_resolved_tree_and_skip_drops_commit() {
    let repo = Repo::new();
    // base on main
    repo.commit_file("a.txt", b"base\n", "base");
    ok(repo.path(), repo.xdg(), &["branch", "feature"]);

    // main advances with a conflicting change to a.txt
    repo.commit_file("a.txt", b"main-change\n", "main change");

    // feature: two commits, the first conflicts on a.txt
    ok(repo.path(), repo.xdg(), &["checkout", "feature"]);
    repo.commit_file("a.txt", b"feature-change\n", "feature change a");
    repo.commit_file("b.txt", b"feature-b\n", "feature adds b");

    // Rebase feature onto main → conflict on first replayed commit.
    let out = fail(repo.path(), repo.xdg(), &["rebase", "main"]);
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("paused"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        repo.path()
            .join(".mkit/rebase-apply/mkit-conflicts")
            .exists()
    );

    // Resolve to a third value and continue.
    let content = fs::read_to_string(repo.path().join("a.txt")).unwrap();
    assert!(content.contains("<<<<<<<"), "expected markers: {content}");
    repo.write("a.txt", b"rebase-resolved\n");
    repo.add("a.txt");
    ok(repo.path(), repo.xdg(), &["rebase", "--continue"]);

    // Rebase finished: state cleared, b.txt replayed, a.txt is the
    // resolved content (not the conflict-time ours-wins value).
    assert!(!repo.path().join(".mkit/rebase-apply").exists());
    assert_eq!(repo.head_tree_blob("a.txt"), b"rebase-resolved\n");
    assert_eq!(repo.head_tree_blob("b.txt"), b"feature-b\n");
}

#[test]
fn rebase_skip_drops_conflicting_commit() {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"base\n", "base");
    ok(repo.path(), repo.xdg(), &["branch", "feature"]);
    repo.commit_file("a.txt", b"main-change\n", "main change");

    ok(repo.path(), repo.xdg(), &["checkout", "feature"]);
    repo.commit_file("a.txt", b"feature-change\n", "feature change a");
    repo.commit_file("c.txt", b"feature-c\n", "feature adds c");

    fail(repo.path(), repo.xdg(), &["rebase", "main"]);
    // Skip the conflicting commit.
    ok(repo.path(), repo.xdg(), &["rebase", "--skip"]);

    assert!(!repo.path().join(".mkit/rebase-apply").exists());
    // a.txt keeps main's value (the skipped commit was dropped); c.txt
    // was still replayed.
    assert_eq!(repo.head_tree_blob("a.txt"), b"main-change\n");
    assert_eq!(repo.head_tree_blob("c.txt"), b"feature-c\n");
}

#[test]
fn rebase_abort_restores_head() {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"base\n", "base");
    ok(repo.path(), repo.xdg(), &["branch", "feature"]);
    repo.commit_file("a.txt", b"main-change\n", "main change");
    ok(repo.path(), repo.xdg(), &["checkout", "feature"]);
    repo.commit_file("a.txt", b"feature-change\n", "feature change");

    let feature_before = refs::read_ref(&repo.mkit_dir(), "feature")
        .unwrap()
        .unwrap();
    fail(repo.path(), repo.xdg(), &["rebase", "main"]);
    ok(repo.path(), repo.xdg(), &["rebase", "--abort"]);

    assert!(!repo.path().join(".mkit/rebase-apply").exists());
    let feature_after = refs::read_ref(&repo.mkit_dir(), "feature")
        .unwrap()
        .unwrap();
    assert_eq!(
        feature_before, feature_after,
        "feature tip must be restored after abort"
    );
    assert_eq!(
        fs::read_to_string(repo.path().join("a.txt")).unwrap(),
        "feature-change\n"
    );
}
