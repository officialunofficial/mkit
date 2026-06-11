//! End-to-end suite for `mkit git import` / `fetch` / `pull`
//! (feature `git-bridge`), driving real `mkit` + `git` binaries
//! through the SPEC-GIT-IMPORT journeys: fresh-clone import,
//! incremental pull, native-merge integration, force-push handling,
//! key pinning, the origin guard, and the dispatch matrix.
#![cfg(feature = "git-bridge")]

mod common;

use common::Repo;
use mkit_core::object::Object;
use mkit_core::refs;
use mkit_core::store::ObjectStore;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

fn git_available() -> bool {
    Command::new("git")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

fn mkit_bin() -> &'static str {
    env!("CARGO_BIN_EXE_mkit")
}

fn mkit_in(cwd: &Path, xdg: &Path, args: &[&str]) -> Output {
    Command::new(mkit_bin())
        .args(args)
        .current_dir(cwd)
        .env("XDG_CONFIG_HOME", xdg)
        .env("HOME", xdg)
        .env("EDITOR", "true")
        .stdin(Stdio::null())
        .output()
        .expect("spawn mkit")
}

fn git_in(dir: &Path, args: &[&str]) -> Output {
    Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .env("GIT_AUTHOR_NAME", "Up Stream")
        .env("GIT_AUTHOR_EMAIL", "up@example.com")
        .env("GIT_COMMITTER_NAME", "Up Stream")
        .env("GIT_COMMITTER_EMAIL", "up@example.com")
        .env("GIT_AUTHOR_DATE", "1700000000 +0000")
        .env("GIT_COMMITTER_DATE", "1700000000 +0000")
        .output()
        .expect("spawn git")
}

fn git_ok(dir: &Path, args: &[&str]) {
    let out = git_in(dir, args);
    assert!(out.status.success(), "git {args:?}: {out:?}");
}

/// A scratch area with a real git upstream (2 commits + annotated tag).
struct Fixture {
    root: tempfile::TempDir,
    xdg: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let f = Fixture {
            root: tempfile::tempdir().unwrap(),
            xdg: tempfile::tempdir().unwrap(),
        };
        let up = f.upstream();
        std::fs::create_dir_all(&up).unwrap();
        git_ok(&up, &["init", "--quiet", "--initial-branch=main", "."]);
        std::fs::write(up.join("a.txt"), "hello\n").unwrap();
        git_ok(&up, &["add", "a.txt"]);
        git_ok(&up, &["commit", "--quiet", "-m", "upstream first"]);
        std::fs::write(up.join("b.txt"), "world\n").unwrap();
        git_ok(&up, &["add", "b.txt"]);
        git_ok(&up, &["commit", "--quiet", "-m", "upstream second"]);
        git_ok(&up, &["tag", "-a", "v1", "-m", "release"]);
        f
    }

    fn upstream(&self) -> PathBuf {
        self.root.path().join("upstream")
    }

    fn fork(&self) -> PathBuf {
        self.root.path().join("fork")
    }

    fn mkit(&self, cwd: &Path, args: &[&str]) -> Output {
        mkit_in(cwd, self.xdg.path(), args)
    }

    fn mkit_ok(&self, cwd: &Path, args: &[&str]) -> Output {
        let out = self.mkit(cwd, args);
        assert!(
            out.status.success(),
            "mkit {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        out
    }

    /// Fresh-clone import into `fork/`.
    fn import(&self) -> PathBuf {
        let up = self.upstream();
        self.mkit_ok(
            self.root.path(),
            &["git", "import", up.to_str().unwrap(), "fork"],
        );
        self.fork()
    }
}

#[test]
fn fresh_clone_imports_checks_out_and_verifies() {
    if !git_available() {
        return;
    }
    let f = Fixture::new();
    let fork = f.import();

    // Worktree checked out from the upstream default branch.
    assert!(fork.join("a.txt").exists() && fork.join("b.txt").exists());

    // History is ordinary mkit: readable upstream author, verify ok.
    let out = f.mkit_ok(&fork, &["log", "-n", "1"]);
    let log = String::from_utf8_lossy(&out.stdout);
    assert!(
        log.contains("Author: Up Stream <up@example.com>"),
        "log: {log}"
    );
    f.mkit_ok(&fork, &["verify", "HEAD"]);

    // Tag imported as an mkit tag object on refs/tags/v1.
    let mkit_dir = fork.join(".mkit");
    let tag = refs::read_tag(&mkit_dir, "v1").unwrap().unwrap();
    let store = ObjectStore::open(&fork).unwrap();
    assert!(matches!(store.read_object(&tag), Ok(Object::Tag(_))));

    // Tracking ref exists and the dedicated import key was pinned.
    assert!(
        refs::read_remote_ref(&mkit_dir, "upstream", "main")
            .unwrap()
            .is_some()
    );
    assert!(mkit_dir.join("keys/git-import.key").exists());
    assert!(mkit_dir.join("git/upstream/source").exists());
}

#[test]
fn pull_ff_divergence_and_native_merge_loop() {
    if !git_available() {
        return;
    }
    let f = Fixture::new();
    let fork = f.import();
    f.mkit_ok(&fork, &["keygen"]);

    // Clean FF when local hasn't diverged.
    let up = f.upstream();
    std::fs::write(up.join("c.txt"), "c\n").unwrap();
    git_ok(&up, &["add", "c.txt"]);
    git_ok(&up, &["commit", "--quiet", "-m", "upstream third"]);
    let out = f.mkit_ok(&fork, &["git", "pull"]);
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("fast-forwarded 'main'"),
        "{out:?}"
    );
    assert!(fork.join("c.txt").exists());

    // Diverge locally, advance upstream → pull refuses with the hint,
    // native merge integrates.
    std::fs::write(fork.join("local.txt"), "l\n").unwrap();
    f.mkit_ok(&fork, &["add", "local.txt"]);
    f.mkit_ok(&fork, &["commit", "-m", "local work"]);
    std::fs::write(up.join("d.txt"), "d\n").unwrap();
    git_ok(&up, &["add", "d.txt"]);
    git_ok(&up, &["commit", "--quiet", "-m", "upstream fourth"]);
    let out = f.mkit(&fork, &["git", "pull"]);
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("mkit merge upstream/main"),
        "{out:?}"
    );
    f.mkit_ok(&fork, &["merge", "upstream/main"]);
    assert!(fork.join("d.txt").exists() && fork.join("local.txt").exists());
}

#[test]
fn upstream_force_push_warns_and_rewinds_tracking_ref() {
    if !git_available() {
        return;
    }
    let f = Fixture::new();
    let fork = f.import();
    let up = f.upstream();
    git_ok(&up, &["reset", "--hard", "--quiet", "HEAD~1"]);
    std::fs::write(up.join("rewritten.txt"), "r\n").unwrap();
    git_ok(&up, &["add", "rewritten.txt"]);
    git_ok(&up, &["commit", "--quiet", "-m", "rewritten history"]);

    let out = f.mkit_ok(&fork, &["git", "fetch"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("force-pushed") && stderr.contains("rewound"),
        "stderr: {stderr}"
    );
}

#[test]
fn import_key_is_pinned_against_other_keys() {
    if !git_available() {
        return;
    }
    let f = Fixture::new();
    let fork = f.import();

    // A different key for the same state refuses with guidance.
    let other = f.root.path().join("other.key");
    let kp = mkit_core::sign::KeyPair::from_seed([9u8; 32]);
    mkit_core::sign::save_key(&other, &kp).unwrap();
    let out = f.mkit(&fork, &["git", "fetch", "--key", other.to_str().unwrap()]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("pinned to importer key") && stderr.contains("designated-importer")
            || stderr.contains("Designated-importer"),
        "stderr: {stderr}"
    );
}

#[test]
fn origin_guard_blocks_plain_export_and_source_binding_holds() {
    if !git_available() {
        return;
    }
    let f = Fixture::new();
    let fork = f.import();
    f.mkit_ok(&fork, &["keygen"]);

    // Plain export toward the imported-from upstream: refused.
    let up = f.upstream();
    let out = f.mkit(&fork, &["git", "export", up.to_str().unwrap()]);
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("recorded git-import source"),
        "{out:?}"
    );
    // Equivalent spelling (trailing slash) is also caught.
    let spelled = format!("{}/", up.display());
    let out = f.mkit(&fork, &["git", "export", &spelled]);
    assert!(!out.status.success(), "canonical identity must match");

    // Same remote-name, different source: refused.
    let other = f.root.path().join("other-upstream");
    std::fs::create_dir_all(&other).unwrap();
    git_ok(&other, &["init", "--quiet", "--initial-branch=main", "."]);
    let out = f.mkit(&fork, &["git", "import", other.to_str().unwrap()]);
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("use a different --remote-name"),
        "{out:?}"
    );

    // Export to a THIRD repo (a new mirror) still works.
    let mirror = f.root.path().join("mirror");
    f.mkit_ok(&fork, &["git", "export", mirror.to_str().unwrap()]);
}

#[test]
fn native_commands_refuse_git_bridge_remotes() {
    if !git_available() {
        return;
    }
    let r = Repo::new();
    r.commit_file("a.txt", b"a\n", "base");
    r.ok(&["remote", "add", "ghub", "git+https://github.com/org/repo"]);
    for cmd in [&["push", "ghub"][..], &["fetch", "ghub"], &["pull", "ghub"]] {
        let out = r.run(cmd);
        assert!(!out.status.success(), "{cmd:?} must refuse");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("git-bridge remote") || stderr.contains("mkit git"),
            "{cmd:?}: {stderr}"
        );
    }
}

#[test]
fn reimport_is_noop_and_fresh_state_is_deterministic() {
    if !git_available() {
        return;
    }
    let f = Fixture::new();
    let fork = f.import();
    let mkit_dir = fork.join(".mkit");
    let head1 = refs::read_remote_ref(&mkit_dir, "upstream", "main")
        .unwrap()
        .unwrap();

    // No upstream change: fetch is a no-op on the tracking ref.
    f.mkit_ok(&fork, &["git", "fetch"]);
    assert_eq!(
        refs::read_remote_ref(&mkit_dir, "upstream", "main")
            .unwrap()
            .unwrap(),
        head1
    );

    // Wipe map + staging (keep the pinned key), re-fetch: same hashes.
    std::fs::remove_file(mkit_dir.join("git/upstream/map")).unwrap();
    std::fs::remove_dir_all(mkit_dir.join("git/upstream/repo.git")).unwrap();
    // Also clear recorded ref state so everything re-translates.
    std::fs::remove_file(mkit_dir.join("git/upstream/refs-import")).unwrap();
    let up = f.upstream();
    f.mkit_ok(&fork, &["git", "import", up.to_str().unwrap()]);
    assert_eq!(
        refs::read_remote_ref(&mkit_dir, "upstream", "main")
            .unwrap()
            .unwrap(),
        head1,
        "same key + same upstream must reproduce identical hashes"
    );
}

#[test]
fn crash_marker_discards_map_and_recovers() {
    if !git_available() {
        return;
    }
    let f = Fixture::new();
    let fork = f.import();
    let mkit_dir = fork.join(".mkit");
    let state = mkit_dir.join("git/upstream");
    let head1 = refs::read_remote_ref(&mkit_dir, "upstream", "main")
        .unwrap()
        .unwrap();

    // Simulate a crashed session: marker present, map possibly stale.
    std::fs::write(state.join("importing"), b"").unwrap();
    std::fs::remove_file(state.join("refs-import")).unwrap();
    let out = f.mkit_ok(&fork, &["git", "fetch"]);
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("rebuilding the map cache"),
        "{out:?}"
    );
    assert!(!state.join("importing").exists(), "marker cleared");
    assert_eq!(
        refs::read_remote_ref(&mkit_dir, "upstream", "main")
            .unwrap()
            .unwrap(),
        head1
    );
}

/// `git` stdout (trimmed) or panic — for rev-parse style queries.
fn git_stdout(dir: &Path, args: &[&str]) -> String {
    let out = git_in(dir, args);
    assert!(out.status.success(), "git {args:?}: {out:?}");
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

#[test]
fn passthrough_export_creates_prable_fork() {
    if !git_available() {
        return;
    }
    let f = Fixture::new();
    let fork = f.import();
    f.mkit_ok(&fork, &["keygen"]);
    std::fs::write(fork.join("local.txt"), "l\n").unwrap();
    f.mkit_ok(&fork, &["add", "local.txt"]);
    f.mkit_ok(&fork, &["commit", "-m", "local work"]);

    // A GitHub-fork stand-in: a bare clone of the upstream.
    let up = f.upstream();
    let forkgit = f.root.path().join("forkgit");
    git_ok(
        f.root.path(),
        &[
            "clone",
            "--bare",
            "--quiet",
            up.to_str().unwrap(),
            "forkgit",
        ],
    );

    f.mkit_ok(
        &fork,
        &[
            "git",
            "export",
            "--passthrough",
            "--remote-name",
            "upstream",
            forkgit.to_str().unwrap(),
        ],
    );

    // SHA-sharing (SPEC-GIT-BRIDGE §14.1): the fork's main sits
    // DIRECTLY on the original upstream commits — merge-base with the
    // upstream tip is the upstream tip, so a PR diff is just the
    // native work.
    let up_tip = git_stdout(&up, &["rev-parse", "HEAD"]);
    assert_eq!(git_stdout(&forkgit, &["rev-parse", "main^"]), up_tip);
    assert_eq!(
        git_stdout(&forkgit, &["merge-base", "main", &up_tip]),
        up_tip
    );
    // Tags pass through byte-identical.
    assert_eq!(
        git_stdout(&forkgit, &["rev-parse", "v1"]),
        git_stdout(&up, &["rev-parse", "v1"])
    );
    // Everything pushed is well-formed git.
    git_ok(&forkgit, &["fsck", "--strict"]);

    // Attestation scoping (§11): only the bridge-translated head gets
    // a translation claim — passthrough objects keep their
    // git-import/v1 provenance.
    let tree = git_stdout(&forkgit, &["ls-tree", "refs/mkit/attestations"]);
    assert_eq!(tree.lines().count(), 1, "one translated head:\n{tree}");

    // The import mirror's own ref namespaces stay untouched: the
    // export staged under refs/mkit-export/, not refs/heads/.
    let staging = fork.join(".mkit/git/upstream/repo.git");
    assert_eq!(
        git_stdout(&staging, &["rev-parse", "refs/heads/main"]),
        up_tip
    );
}

#[test]
fn passthrough_requires_import_state_and_locks_direction() {
    if !git_available() {
        return;
    }
    let f = Fixture::new();
    let fork = f.import();
    f.mkit_ok(&fork, &["keygen"]);
    let dest = f.root.path().join("dest.git");

    // No import state under that name → refused with guidance.
    let out = f.mkit(
        &fork,
        &[
            "git",
            "export",
            "--passthrough",
            "--remote-name",
            "nope",
            dest.to_str().unwrap(),
        ],
    );
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("requires import state"),
        "{out:?}"
    );

    // Fork the real import state, then plain export under the same
    // name: direction conflict.
    let up = f.upstream();
    let forkgit = f.root.path().join("forkgit");
    git_ok(
        f.root.path(),
        &[
            "clone",
            "--bare",
            "--quiet",
            up.to_str().unwrap(),
            "forkgit",
        ],
    );
    f.mkit_ok(
        &fork,
        &[
            "git",
            "export",
            "--passthrough",
            "--remote-name",
            "upstream",
            forkgit.to_str().unwrap(),
        ],
    );
    let out = f.mkit(
        &fork,
        &[
            "git",
            "export",
            "--remote-name",
            "upstream",
            forkgit.to_str().unwrap(),
        ],
    );
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("direction"),
        "{out:?}"
    );
}

#[test]
fn fetch_after_fork_keeps_import_tracking_clean() {
    if !git_available() {
        return;
    }
    let f = Fixture::new();
    let fork = f.import();
    f.mkit_ok(&fork, &["keygen"]);
    std::fs::write(fork.join("local.txt"), "l\n").unwrap();
    f.mkit_ok(&fork, &["add", "local.txt"]);
    f.mkit_ok(&fork, &["commit", "-m", "local work"]);
    let up = f.upstream();
    let forkgit = f.root.path().join("forkgit");
    git_ok(
        f.root.path(),
        &[
            "clone",
            "--bare",
            "--quiet",
            up.to_str().unwrap(),
            "forkgit",
        ],
    );
    f.mkit_ok(
        &fork,
        &[
            "git",
            "export",
            "--passthrough",
            "--remote-name",
            "upstream",
            forkgit.to_str().unwrap(),
        ],
    );

    // Upstream advances; fetch through the SAME (now fork) state dir
    // must track it without a spurious force-push warning — the
    // export leases and the import tracking state are separate files.
    std::fs::write(up.join("e.txt"), "e\n").unwrap();
    git_ok(&up, &["add", "e.txt"]);
    git_ok(&up, &["commit", "--quiet", "-m", "upstream fifth"]);
    let out = f.mkit_ok(&fork, &["git", "fetch"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("force-pushed"),
        "clean FF advance misread as a force-push: {stderr}"
    );
    // The tracking ref moved to the new upstream tip (translated).
    let log = f.mkit_ok(&fork, &["log", "-n", "1", "upstream/main"]);
    assert!(
        String::from_utf8_lossy(&log.stdout).contains("upstream fifth"),
        "{log:?}"
    );

    // And a second passthrough export still pushes cleanly (the fork
    // didn't move; recorded leases hold).
    f.mkit_ok(
        &fork,
        &[
            "git",
            "export",
            "--passthrough",
            "--remote-name",
            "upstream",
            forkgit.to_str().unwrap(),
        ],
    );
}
