//! Regression tests for #214: a conflict resolved via `--continue` must
//! preserve the ours-side executable bit and symlink mode instead of
//! silently demoting the path to a plain blob.
//!
//! The conflict materialiser stages the ours-side into the index with
//! its real `EntryMode` (carried on the merge `Conflict`), so a plain
//! `--continue` (without re-`add`ing) commits a tree that still records
//! the exec/symlink mode. For symlink conflicts the worktree path is a
//! real symlink, not a regular file holding the target text.

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output};

use mkit_core::object::{EntryMode, Object};
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
    /// Read the committed `EntryMode` for a top-level path in HEAD's tree.
    fn head_tree_mode(&self, name: &str) -> EntryMode {
        let store = ObjectStore::open(self.path()).unwrap();
        let head = refs::resolve_head(&self.mkit_dir()).unwrap().unwrap();
        let Object::Commit(c) = store.read_object(&head).unwrap() else {
            panic!("HEAD not a commit");
        };
        let Object::Tree(t) = store.read_object(&c.tree_hash).unwrap() else {
            panic!("tree not a tree");
        };
        t.entries
            .iter()
            .find(|e| e.name == name.as_bytes())
            .unwrap_or_else(|| panic!("missing entry {name}"))
            .mode
    }
}

/// #214 + #269: an executable ours-side that conflicts with a non-exec
/// theirs must stay executable through `--continue`. The user resolves
/// the content, restores the exec bit, and stages it; both the
/// resolved content (#269: an edited resolution must not be silently
/// dropped) and the executable mode (#214) survive the commit.
#[test]
fn merge_continue_preserves_ours_exec_bit() {
    let repo = Repo::new();
    repo.commit_file("script.sh", b"echo base\n", "base");
    ok(repo.path(), repo.xdg(), &["branch", "feature"]);

    // theirs: non-exec content change.
    ok(repo.path(), repo.xdg(), &["checkout", "feature"]);
    repo.commit_file("script.sh", b"echo theirs\n", "theirs change");

    // ours: executable + different content.
    ok(repo.path(), repo.xdg(), &["checkout", "main"]);
    repo.write("script.sh", b"echo ours\n");
    fs::set_permissions(
        repo.path().join("script.sh"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    repo.add("script.sh");
    repo.commit("ours exec change");

    // Sanity: ours committed an Executable entry.
    assert_eq!(repo.head_tree_mode("script.sh"), EntryMode::Executable);

    fail(repo.path(), repo.xdg(), &["merge", "feature"]);

    // Resolve the content, restore the exec bit (the rewrite reset perms),
    // and stage it. #269: an edited resolution must be staged —
    // `--continue` refuses an unstaged edit rather than silently committing
    // the stale staged content.
    repo.write("script.sh", b"echo resolved\n");
    fs::set_permissions(
        repo.path().join("script.sh"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    repo.add("script.sh");
    ok(repo.path(), repo.xdg(), &["merge", "--continue"]);

    assert_eq!(
        repo.head_tree_mode("script.sh"),
        EntryMode::Executable,
        "exec bit must survive merge --continue (#214)"
    );
    assert_eq!(
        fs::read(repo.path().join("script.sh")).unwrap(),
        b"echo resolved\n",
        "the resolved content must be committed, not the stale staged ours (#269)"
    );
}

/// #214: a symlink/symlink conflict must materialise a REAL symlink in
/// the worktree (not a regular file holding the target text), and
/// `--continue` must commit the path with `Symlink` mode.
#[test]
fn merge_continue_preserves_symlink_mode() {
    let repo = Repo::new();
    repo.commit_file("anchor.txt", b"anchor\n", "base");
    ok(repo.path(), repo.xdg(), &["branch", "feature"]);

    // theirs: link -> theirs-target.
    ok(repo.path(), repo.xdg(), &["checkout", "feature"]);
    std::os::unix::fs::symlink("theirs-target", repo.path().join("link")).unwrap();
    repo.add("link");
    repo.commit("theirs symlink");

    // ours: link -> ours-target.
    ok(repo.path(), repo.xdg(), &["checkout", "main"]);
    std::os::unix::fs::symlink("ours-target", repo.path().join("link")).unwrap();
    repo.add("link");
    repo.commit("ours symlink");
    assert_eq!(repo.head_tree_mode("link"), EntryMode::Symlink);

    fail(repo.path(), repo.xdg(), &["merge", "feature"]);

    // The materialised conflict path must be a real symlink pointing at
    // the ours-side target — NOT a regular file containing the text.
    let meta = fs::symlink_metadata(repo.path().join("link")).unwrap();
    assert!(
        meta.file_type().is_symlink(),
        "conflict symlink must be materialised as a real symlink (#214)"
    );
    let target = fs::read_link(repo.path().join("link")).unwrap();
    assert_eq!(target.to_str().unwrap(), "ours-target");

    // Continue without re-adding: the staged ours-side Symlink mode is
    // committed.
    ok(repo.path(), repo.xdg(), &["merge", "--continue"]);
    assert_eq!(
        repo.head_tree_mode("link"),
        EntryMode::Symlink,
        "symlink mode must survive merge --continue (#214)"
    );
}
