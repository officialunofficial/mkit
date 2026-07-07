//! End-to-end suite for `mkit git import` / `fetch` / `pull`
//! (feature `git-bridge`), driving real `mkit` + `git` binaries
//! through the SPEC-GIT-IMPORT journeys: fresh-clone import,
//! incremental pull, native-merge integration, force-push handling,
//! key pinning, the origin guard, and the dispatch matrix.
#![cfg(feature = "git-bridge")]
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

mod common;

use common::Repo;
use mkit_core::layout::RepoLayout;
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
    let layout = RepoLayout::single(&fork);
    let tag = refs::read_tag(&layout, "v1").unwrap().unwrap();
    let store = ObjectStore::open(&layout).unwrap();
    assert!(matches!(store.read_object(&tag), Ok(Object::Tag(_))));

    // Tracking ref exists and the dedicated import key was pinned.
    assert!(
        refs::read_remote_ref(&layout, "upstream", "main")
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
    let layout = RepoLayout::single(&fork);
    let before = refs::read_remote_ref(&layout, "upstream", "main")
        .unwrap()
        .unwrap();
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
    // The warning must come WITH the rewind, not instead of it.
    let after = refs::read_remote_ref(&layout, "upstream", "main")
        .unwrap()
        .unwrap();
    assert_ne!(after, before, "tracking ref rewound to the new history");
    let log = f.mkit_ok(&fork, &["log", "-n", "1", "upstream/main"]);
    assert!(
        String::from_utf8_lossy(&log.stdout).contains("rewritten history"),
        "{log:?}"
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
        stderr.contains("pinned to importer key"),
        "stderr: {stderr}"
    );
    assert!(
        stderr.contains("Designated-importer model"),
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
    let layout = RepoLayout::single(&fork);
    let head1 = refs::read_remote_ref(&layout, "upstream", "main")
        .unwrap()
        .unwrap();

    // No upstream change: fetch is a no-op on the tracking ref.
    f.mkit_ok(&fork, &["git", "fetch"]);
    assert_eq!(
        refs::read_remote_ref(&layout, "upstream", "main")
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
        refs::read_remote_ref(&layout, "upstream", "main")
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
    let layout = RepoLayout::single(&fork);
    let state = mkit_dir.join("git/upstream");
    let head1 = refs::read_remote_ref(&layout, "upstream", "main")
        .unwrap()
        .unwrap();

    // Simulate a crashed session: marker present, map possibly stale.
    // Recovery must discard BOTH the map and the recorded ref state —
    // stale recorded tips would otherwise short-circuit the rebuild
    // and leave the map empty (poisoning a later passthrough export).
    std::fs::write(state.join("importing"), b"").unwrap();
    let out = f.mkit_ok(&fork, &["git", "fetch"]);
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("rebuilding the map cache"),
        "{out:?}"
    );
    assert!(!state.join("importing").exists(), "marker cleared");
    assert_eq!(
        refs::read_remote_ref(&layout, "upstream", "main")
            .unwrap()
            .unwrap(),
        head1,
        "full re-translation reproduces identical hashes"
    );
    // The map cache was actually rebuilt (non-empty), so fork-mode
    // export after a crash still passes imported objects through.
    let map = std::fs::read_to_string(state.join("map")).unwrap();
    assert!(map.lines().count() > 0, "map rebuilt, not left empty");
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
fn passthrough_refuses_to_move_an_existing_remote_tag() {
    // SPEC-GIT-BRIDGE fork-mode export never moves an existing tag: if
    // `refs/tags/<name>` already exists on the destination at a
    // different object than what this export would push, the whole
    // export must refuse (exit USAGE) before issuing any push, and the
    // remote's tag must stay exactly where it was.
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

    // Move the destination's v1 tag to point at the FIRST upstream
    // commit instead of the second — a real divergence from what this
    // export would push (tags otherwise pass through byte-identical,
    // per `passthrough_export_creates_prable_fork`).
    let first_commit = git_stdout(&up, &["rev-parse", "HEAD^"]);
    git_ok(&forkgit, &["update-ref", "refs/tags/v1", &first_commit]);
    let moved_tag = git_stdout(&forkgit, &["rev-parse", "refs/tags/v1"]);
    assert_eq!(moved_tag, first_commit);

    let out = f.mkit(
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
    assert!(!out.status.success());
    assert_eq!(
        out.status.code(),
        Some(64),
        "fork-mode tag-move must exit USAGE (64): {out:?}"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("refs/tags/v1") && stderr.contains("never moves an existing tag"),
        "expected the fork-mode tag-move diagnostic, got: {stderr}"
    );

    // The remote is unchanged: the tag is still at the first commit,
    // and `main` never received the local commit either (the whole
    // export refuses atomically, before any push).
    assert_eq!(
        git_stdout(&forkgit, &["rev-parse", "refs/tags/v1"]),
        first_commit,
        "remote tag must be untouched by the refused export"
    );
    let up_tip = git_stdout(&up, &["rev-parse", "HEAD"]);
    assert_eq!(
        git_stdout(&forkgit, &["rev-parse", "main"]),
        up_tip,
        "remote main must be untouched by the refused export"
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

#[test]
fn verify_status_and_fork_audit() {
    if !git_available() {
        return;
    }
    let f = Fixture::new();
    let fork = f.import();
    f.mkit_ok(&fork, &["keygen"]);

    // Import-direction verify: every imported object vouched.
    let out = f.mkit_ok(&fork, &["git", "verify"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("ok:") && stderr.contains("imported-vouched"),
        "{stderr}"
    );

    // Status shows the import state.
    let out = f.mkit_ok(&fork, &["git", "status"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("upstream  direction=import")
            && stdout.contains("importer key:")
            && stdout.contains("tracking refs/heads/main")
            && stdout.contains("staging: ok"),
        "{stdout}"
    );

    // Fork it (local commit + passthrough export), then full audit.
    std::fs::write(fork.join("local.txt"), "l\n").unwrap();
    f.mkit_ok(&fork, &["add", "local.txt"]);
    f.mkit_ok(&fork, &["commit", "-m", "local work"]);
    let up = f.upstream();
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
    let forkgit = f.root.path().join("forkgit");
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
    let out = f.mkit_ok(&fork, &["git", "verify", "--fork-audit"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("ok:")
            && stderr.contains("bridge-translated")
            && stderr.contains("content-derived"),
        "{stderr}"
    );
    let out = f.mkit_ok(&fork, &["git", "status"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("direction=fork") && stdout.contains("exported refs/heads/main"),
        "{stdout}"
    );

    // Tamper with retained raw bytes → verify must fail loudly.
    let raw_root = fork.join(".mkit/git/upstream/raw");
    let bucket = std::fs::read_dir(&raw_root)
        .unwrap()
        .next()
        .unwrap()
        .unwrap();
    let victim = std::fs::read_dir(bucket.path())
        .unwrap()
        .next()
        .unwrap()
        .unwrap();
    std::fs::write(victim.path(), b"blob 5\0junk\n").unwrap();
    let out = f.mkit(&fork, &["git", "verify"]);
    assert!(!out.status.success(), "tampered raw bytes must fail verify");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("FAIL") && stderr.contains("DIFFERENT sha1"),
        "{stderr}"
    );
}

#[test]
fn format_patch_output_applies_with_git_am() {
    if !git_available() {
        return;
    }
    let f = Fixture::new();
    let fork = f.import();
    f.mkit_ok(&fork, &["keygen"]);
    std::fs::write(fork.join("feature.txt"), "one\n").unwrap();
    f.mkit_ok(&fork, &["add", "feature.txt"]);
    f.mkit_ok(&fork, &["commit", "-m", "Add feature file"]);
    std::fs::write(fork.join("feature.txt"), "one\ntwo\n").unwrap();
    f.mkit_ok(&fork, &["add", "feature.txt"]);
    f.mkit_ok(
        &fork,
        &["commit", "-m", "Extend feature file\n\nWith a body line."],
    );

    let patches = f.root.path().join("patches");
    let out = f.mkit_ok(
        &fork,
        &[
            "git",
            "format-patch",
            "upstream/main..HEAD",
            "-o",
            patches.to_str().unwrap(),
        ],
    );
    let listing = String::from_utf8_lossy(&out.stdout);
    assert!(
        listing.contains("0001-Add-feature-file.patch")
            && listing.contains("0002-Extend-feature-file.patch"),
        "{listing}"
    );

    // The patches apply onto a plain git clone of the upstream.
    let up = f.upstream();
    git_ok(
        f.root.path(),
        &["clone", "--quiet", up.to_str().unwrap(), "contrib"],
    );
    let contrib = f.root.path().join("contrib");
    let p1 = patches.join("0001-Add-feature-file.patch");
    let p2 = patches.join("0002-Extend-feature-file.patch");
    git_ok(
        &contrib,
        &["am", p1.to_str().unwrap(), p2.to_str().unwrap()],
    );
    assert_eq!(
        std::fs::read_to_string(contrib.join("feature.txt")).unwrap(),
        "one\ntwo\n"
    );
    let log = git_in(&contrib, &["log", "--format=%s", "-n", "2"]);
    let subjects = String::from_utf8_lossy(&log.stdout);
    assert!(
        subjects.contains("Extend feature file") && subjects.contains("Add feature file"),
        "{subjects}"
    );
}

#[test]
fn passthrough_cannot_target_another_states_import_source() {
    if !git_available() {
        return;
    }
    let f = Fixture::new();
    let fork = f.import();
    f.mkit_ok(&fork, &["keygen"]);

    // A second, unrelated git upstream imported under another name.
    let second = f.root.path().join("second");
    std::fs::create_dir_all(&second).unwrap();
    git_ok(&second, &["init", "--quiet", "--initial-branch=main", "."]);
    std::fs::write(second.join("s.txt"), "s\n").unwrap();
    git_ok(&second, &["add", "s.txt"]);
    git_ok(&second, &["commit", "--quiet", "-m", "second upstream"]);
    f.mkit_ok(
        &fork,
        &[
            "git",
            "import",
            second.to_str().unwrap(),
            "--remote-name",
            "second",
        ],
    );

    // Passthrough through state 'upstream' toward state 'second's
    // source: 'upstream's map knows nothing of second's objects, so
    // this is a disconnected re-translation — the guard must refuse.
    let out = f.mkit(
        &fork,
        &[
            "git",
            "export",
            "--passthrough",
            "--remote-name",
            "upstream",
            second.to_str().unwrap(),
        ],
    );
    assert!(!out.status.success(), "cross-state passthrough must refuse");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("recorded git-import source"), "{stderr}");
    // And the refusal left no side effects on the dest binding.
    assert!(!fork.join(".mkit/git/upstream/dest").exists());
}

#[test]
fn format_patch_refuses_binary_changes() {
    if !git_available() {
        return;
    }
    let f = Fixture::new();
    let fork = f.import();
    f.mkit_ok(&fork, &["keygen"]);
    std::fs::write(fork.join("blob.bin"), [0u8, 159, 146, 150, 0, 1, 2]).unwrap();
    f.mkit_ok(&fork, &["add", "blob.bin"]);
    f.mkit_ok(&fork, &["commit", "-m", "Add binary blob"]);

    let out = f.mkit(
        &fork,
        &["git", "format-patch", "upstream/main..HEAD", "--stdout"],
    );
    assert!(!out.status.success(), "binary change must refuse");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("blob.bin") && stderr.contains("binary"),
        "{stderr}"
    );
}

#[test]
fn upstream_branch_deletion_prunes_tracking_ref() {
    if !git_available() {
        return;
    }
    let f = Fixture::new();
    let up = f.upstream();
    git_ok(&up, &["branch", "feature"]);
    let fork = f.import();
    let layout = RepoLayout::single(&fork);
    assert!(
        refs::read_remote_ref(&layout, "upstream", "feature")
            .unwrap()
            .is_some(),
        "feature tracked after import"
    );

    git_ok(&up, &["branch", "-D", "feature"]);
    let out = f.mkit_ok(&fork, &["git", "fetch"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("upstream deleted") && stderr.contains("feature"),
        "{stderr}"
    );
    assert!(
        refs::read_remote_ref(&layout, "upstream", "feature")
            .unwrap()
            .is_none(),
        "tracking ref pruned"
    );
}

#[test]
fn sha256_upstream_refuses() {
    if !git_available() {
        return;
    }
    let f = Fixture::new();
    let up256 = f.root.path().join("up256");
    std::fs::create_dir_all(&up256).unwrap();
    let probe = git_in(
        &up256,
        &[
            "init",
            "--quiet",
            "--object-format=sha256",
            "--initial-branch=main",
            ".",
        ],
    );
    if !probe.status.success() {
        return; // git too old for sha256 repos — vector not producible
    }
    std::fs::write(up256.join("a.txt"), "a\n").unwrap();
    git_ok(&up256, &["add", "a.txt"]);
    git_ok(&up256, &["commit", "--quiet", "-m", "sha256 commit"]);

    let out = f.mkit(
        f.root.path(),
        &["git", "import", up256.to_str().unwrap(), "fork256"],
    );
    assert!(!out.status.success(), "sha256 upstream must refuse");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("SHA-256"),
        "{out:?}"
    );
}

#[test]
fn import_spec_version_mismatch_refuses() {
    if !git_available() {
        return;
    }
    let f = Fixture::new();
    let fork = f.import();
    std::fs::write(fork.join(".mkit/git/upstream/import-spec"), "999\n").unwrap();
    let out = f.mkit(&fork, &["git", "fetch"]);
    assert!(!out.status.success(), "spec mismatch must refuse");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("import-spec 999") && stderr.contains("new --remote-name"),
        "{stderr}"
    );
}

#[test]
fn lightweight_tag_imports_as_bare_ref() {
    if !git_available() {
        return;
    }
    let f = Fixture::new();
    let up = f.upstream();
    git_ok(&up, &["tag", "lw"]); // lightweight: points straight at the commit
    let fork = f.import();
    let layout = RepoLayout::single(&fork);
    let lw = refs::read_tag(&layout, "lw").unwrap().unwrap();
    // Lightweight tag = bare ref at the commit twin: identical to the
    // branch head, with no tag object in between.
    let head = refs::read_remote_ref(&layout, "upstream", "main")
        .unwrap()
        .unwrap();
    assert_eq!(lw, head, "bare ref, no synthesized tag object");
    // The annotated fixture tag still points at a tag object instead.
    let v1 = refs::read_tag(&layout, "v1").unwrap().unwrap();
    assert_ne!(v1, head);
}

#[test]
fn mixed_import_skips_refused_ref_and_keeps_the_rest() {
    if !git_available() {
        return;
    }
    let f = Fixture::new();
    let up = f.upstream();
    // A branch whose tree adds a gitlink (submodule) — spec'd refusal.
    git_ok(&up, &["checkout", "--quiet", "-b", "with-submodule"]);
    let out = git_in(
        &up,
        &[
            "-c",
            "protocol.file.allow=always",
            "submodule",
            "add",
            "--quiet",
            up.to_str().unwrap(),
            "sub",
        ],
    );
    assert!(out.status.success(), "submodule add: {out:?}");
    git_ok(&up, &["commit", "--quiet", "-m", "add submodule"]);
    git_ok(&up, &["checkout", "--quiet", "main"]);

    let out = f.mkit_ok(
        f.root.path(),
        &["git", "import", up.to_str().unwrap(), "fork"],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("skipping refs/heads/with-submodule") && stderr.contains("submodule"),
        "{stderr}"
    );
    let layout = RepoLayout::single(f.fork());
    assert!(
        refs::read_remote_ref(&layout, "upstream", "main")
            .unwrap()
            .is_some(),
        "healthy ref imported despite the refusal"
    );
    assert!(
        refs::read_remote_ref(&layout, "upstream", "with-submodule")
            .unwrap()
            .is_none(),
        "refused ref left untracked"
    );
    // And the partially-translated shared history did not poison the
    // map: verify walks the recorded refs clean.
    f.mkit_ok(&f.fork(), &["git", "verify"]);
}

#[test]
fn remote_rename_moves_and_remove_keeps_bridge_state() {
    if !git_available() {
        return;
    }
    let f = Fixture::new();
    let fork = f.import();
    let up = f.upstream();
    let mkit_dir = fork.join(".mkit");
    // Bind the bridge state name to a configured remote of the same name.
    f.mkit_ok(
        &fork,
        &[
            "remote",
            "add",
            "upstream",
            &format!("git+file://{}", up.display()),
        ],
    );
    assert!(mkit_dir.join("git/upstream/source").exists());

    f.mkit_ok(&fork, &["remote", "rename", "upstream", "origin-git"]);
    assert!(
        mkit_dir.join("git/origin-git/source").exists(),
        "bridge state moved with the remote"
    );
    assert!(!mkit_dir.join("git/upstream").exists());

    let out = f.mkit_ok(&fork, &["remote", "remove", "origin-git"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        mkit_dir.join("git/origin-git/source").exists(),
        "bridge state retained on remove (audit evidence)"
    );
    assert!(
        stderr.contains("git/origin-git"),
        "remove names the retained path: {stderr}"
    );
}

#[test]
fn upstream_tag_deletion_keeps_local_tag() {
    if !git_available() {
        return;
    }
    let f = Fixture::new();
    let fork = f.import();
    let up = f.upstream();
    git_ok(&up, &["tag", "-d", "v1"]);
    f.mkit_ok(&fork, &["git", "fetch"]);
    assert!(
        refs::read_tag(&RepoLayout::single(&fork), "v1")
            .unwrap()
            .is_some(),
        "tags are kept on upstream deletion (no --prune-tags)"
    );
}

#[test]
fn locally_moved_tag_is_not_clobbered_by_fetch() {
    if !git_available() {
        return;
    }
    let f = Fixture::new();
    let fork = f.import();
    f.mkit_ok(&fork, &["keygen"]);
    let layout = RepoLayout::single(&fork);
    let imported_v1 = refs::read_tag(&layout, "v1").unwrap().unwrap();

    // Move v1 locally to the branch head (delete + recreate).
    f.mkit_ok(&fork, &["tag", "-d", "v1"]);
    f.mkit_ok(&fork, &["tag", "v1", "HEAD"]);
    let moved = refs::read_tag(&layout, "v1").unwrap().unwrap();
    assert_ne!(moved, imported_v1);

    let out = f.mkit_ok(&fork, &["git", "fetch"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("not updating tag 'v1'"),
        "warn on skipped tag: {stderr}"
    );
    assert_eq!(
        refs::read_tag(&layout, "v1").unwrap().unwrap(),
        moved,
        "locally-moved tag survives fetch"
    );
}

#[test]
fn format_patch_skips_merges_with_warning() {
    if !git_available() {
        return;
    }
    let f = Fixture::new();
    let fork = f.import();
    f.mkit_ok(&fork, &["keygen"]);
    // Build a local merge: branch off, commit on both sides, merge.
    f.mkit_ok(&fork, &["branch", "side"]);
    std::fs::write(fork.join("main.txt"), "m\n").unwrap();
    f.mkit_ok(&fork, &["add", "main.txt"]);
    f.mkit_ok(&fork, &["commit", "-m", "Main work"]);
    f.mkit_ok(&fork, &["checkout", "side"]);
    std::fs::write(fork.join("side.txt"), "s\n").unwrap();
    f.mkit_ok(&fork, &["add", "side.txt"]);
    f.mkit_ok(&fork, &["commit", "-m", "Side work"]);
    f.mkit_ok(&fork, &["checkout", "main"]);
    f.mkit_ok(&fork, &["merge", "side"]);

    let out = f.mkit_ok(
        &fork,
        &["git", "format-patch", "upstream/main..HEAD", "--stdout"],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("merge commit(s) skipped"),
        "merge-skip warning: {stderr}"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Main work") && stdout.contains("Side work"));
}

#[test]
fn duplicate_import_state_for_same_upstream_refuses() {
    if !git_available() {
        return;
    }
    let f = Fixture::new();
    let fork = f.import();
    let up = f.upstream();
    let out = f.mkit(
        &fork,
        &[
            "git",
            "import",
            up.to_str().unwrap(),
            "--remote-name",
            "dup",
        ],
    );
    assert!(!out.status.success(), "duplicate state must refuse");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("already imported as state 'upstream'"),
        "{stderr}"
    );
}

#[test]
fn dash_prefixed_url_refuses() {
    // The argument-injection guard: an option-shaped URL must be
    // refused by mkit's OWN validate_url (USAGE, with its diagnostic)
    // before any git argv is built. `--` forces the dash-prefixed
    // value through clap so the failure can only come from mkit's
    // guard, not clap's unknown-flag error. No git or fixture needed —
    // the guard fires before anything touches a repository.
    let cwd = tempfile::tempdir().unwrap();
    let xdg = tempfile::tempdir().unwrap();
    let out = mkit_in(
        cwd.path(),
        xdg.path(),
        &["git", "import", "--", "--upload-pack=/bin/echo", "fork"],
    );
    assert_eq!(
        out.status.code(),
        Some(64),
        "dash-prefixed URL must exit USAGE (64): {out:?}"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("is not a valid git URL or path"),
        "expected mkit's URL guard diagnostic, got: {stderr}"
    );
}

#[test]
fn passthrough_refuses_non_fast_forward_push() {
    if !git_available() {
        return;
    }
    let f = Fixture::new();
    let fork = f.import();
    f.mkit_ok(&fork, &["keygen"]);
    std::fs::write(fork.join("local.txt"), "l\n").unwrap();
    f.mkit_ok(&fork, &["add", "local.txt"]);
    f.mkit_ok(&fork, &["commit", "-m", "local work"]);

    // The "fork" advanced past what we imported (stand-in for an
    // upstream that moved, or a fork pushed to from elsewhere).
    let up = f.upstream();
    git_ok(
        f.root.path(),
        &["clone", "--quiet", up.to_str().unwrap(), "forkwt"],
    );
    let forkwt = f.root.path().join("forkwt");
    std::fs::write(forkwt.join("remote.txt"), "r\n").unwrap();
    git_ok(&forkwt, &["add", "remote.txt"]);
    git_ok(&forkwt, &["commit", "--quiet", "-m", "remote-side work"]);
    git_ok(
        f.root.path(),
        &["clone", "--bare", "--quiet", "forkwt", "forkgit"],
    );
    let forkgit = f.root.path().join("forkgit");

    let out = f.mkit(
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
    assert!(
        !out.status.success(),
        "non-FF passthrough must refuse, not rewind"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("not integrated") || stderr.contains("has commits this repo has not"),
        "{stderr}"
    );
    // The fork was not touched.
    let tip = git_in(&forkgit, &["log", "--format=%s", "-n", "1"]);
    assert!(
        String::from_utf8_lossy(&tip.stdout).contains("remote-side work"),
        "{tip:?}"
    );
}

#[test]
fn divergence_probe_refuses_second_key_over_same_content() {
    if !git_available() {
        return;
    }
    let f = Fixture::new();
    let fork = f.import();
    // Wipe ALL bridge state (bindings, key pin, map) but keep the
    // store: only the §6.1 content probe stands between this repo and
    // a second, divergent import of the same upstream.
    std::fs::remove_dir_all(fork.join(".mkit/git/upstream")).unwrap();
    let other = f.root.path().join("other.key");
    let kp = mkit_core::sign::KeyPair::from_seed([7u8; 32]);
    mkit_core::sign::save_key(&other, &kp).unwrap();

    let up = f.upstream();
    let out = f.mkit(
        &fork,
        &[
            "git",
            "import",
            up.to_str().unwrap(),
            "--key",
            other.to_str().unwrap(),
        ],
    );
    assert!(!out.status.success(), "content probe must refuse");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("already imported here under key"),
        "{stderr}"
    );
}

#[test]
fn state_dir_lock_blocks_concurrent_bridge_operation() {
    if !git_available() {
        return;
    }
    let f = Fixture::new();
    let fork = f.import();
    // Hold the per-state lock the way a concurrent process would.
    let lock = mkit_core::repo_lock::acquire_default(&fork.join(".mkit"), "git-upstream.lock")
        .expect("acquire test lock");
    let out = f.mkit(&fork, &["git", "fetch"]);
    drop(lock);
    assert!(!out.status.success(), "locked state must refuse");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("busy"), "{stderr}");
    // Released: the next fetch goes through.
    f.mkit_ok(&fork, &["git", "fetch"]);
}

#[test]
fn dash_and_empty_urls_refuse_before_reaching_git() {
    if !git_available() {
        return;
    }
    let f = Fixture::new();
    // `--` hands the option-shaped string through clap to OUR guard —
    // exactly the form scripts use with untrusted URLs.
    let out = f.mkit(
        f.root.path(),
        &["git", "import", "--", "--upload-pack=/bin/echo", "fork"],
    );
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("is not a valid git URL or path"),
        "{out:?}"
    );
    // The refusal fired before any target was created.
    assert!(!f.fork().exists(), "no half-created clone target");

    // Export-side twin guards (dash + empty).
    let fork = f.import();
    f.mkit_ok(&fork, &["keygen"]);
    let out = f.mkit(&fork, &["git", "export", "--", "--receive-pack=/bin/echo"]);
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("is not a valid git URL or path"),
        "{out:?}"
    );
    let out = f.mkit(&fork, &["git", "export", ""]);
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("empty git URL"),
        "{out:?}"
    );
    assert!(
        !fork.join("HEAD").exists(),
        "no bare-repo files scattered into the worktree"
    );
}

#[test]
fn import_attestation_predicate_pins_locator_and_source() {
    if !git_available() {
        return;
    }
    let f = Fixture::new();
    let fork = f.import();
    let layout = RepoLayout::single(&fork);
    let head = refs::read_remote_ref(&layout, "upstream", "main")
        .unwrap()
        .unwrap();
    let paths = mkit_attest::store::list(&layout, &head).unwrap();
    assert!(
        !paths.is_empty(),
        "git-import/v1 attestation minted per head"
    );
    let env = mkit_attest::store::load(&paths[0]).unwrap();
    let payload = String::from_utf8_lossy(&env.payload).into_owned();
    let up_tip = git_stdout(&f.upstream(), &["rev-parse", "HEAD"]);
    assert!(
        payload.contains("git-import/v1")
            && payload.contains(&up_tip)
            && payload.contains("\"schemaVersion\":1"),
        "{payload}"
    );
    // §5: refName/subject carry the FULL MKIT ref, not the upstream's.
    assert!(payload.contains("refs/remotes/upstream/main"), "{payload}");
}

#[test]
fn fork_export_succeeds_after_upstream_advance_and_merge() {
    if !git_available() {
        return;
    }
    let f = Fixture::new();
    // A BARE central upstream that both mkit and third parties push
    // to — the §14.2-sanctioned export-to-upstream path, where the
    // recorded lease goes stale the moment anyone else lands work.
    let up = f.upstream();
    git_ok(
        f.root.path(),
        &[
            "clone",
            "--bare",
            "--quiet",
            up.to_str().unwrap(),
            "central",
        ],
    );
    let central = f.root.path().join("central");
    f.mkit_ok(
        f.root.path(),
        &[
            "git",
            "import",
            central.to_str().unwrap(),
            "fork",
            "--remote-name",
            "central",
        ],
    );
    let fork = f.fork();
    f.mkit_ok(&fork, &["keygen"]);
    std::fs::write(fork.join("local.txt"), "l\n").unwrap();
    f.mkit_ok(&fork, &["add", "local.txt"]);
    f.mkit_ok(&fork, &["commit", "-m", "local work"]);
    f.mkit_ok(
        &fork,
        &[
            "git",
            "export",
            "--passthrough",
            "--remote-name",
            "central",
            central.to_str().unwrap(),
        ],
    );

    // Third-party work lands on central: the recorded lease is stale.
    git_ok(
        f.root.path(),
        &["clone", "--quiet", central.to_str().unwrap(), "third"],
    );
    let third = f.root.path().join("third");
    std::fs::write(third.join("t.txt"), "t\n").unwrap();
    git_ok(&third, &["add", "t.txt"]);
    git_ok(&third, &["commit", "--quiet", "-m", "third-party work"]);
    git_ok(&third, &["push", "--quiet", "origin", "main"]);

    // The prescribed remediation must work end to end: fetch,
    // integrate natively, re-export (fresh observation = the lease).
    f.mkit_ok(&fork, &["git", "fetch", "--remote-name", "central"]);
    f.mkit_ok(&fork, &["merge", "central/main"]);
    f.mkit_ok(
        &fork,
        &[
            "git",
            "export",
            "--passthrough",
            "--remote-name",
            "central",
            central.to_str().unwrap(),
        ],
    );
    let subjects = git_stdout(&central, &["log", "--format=%s", "-n", "4", "main"]);
    assert!(
        subjects.contains("third-party work") && subjects.contains("local work"),
        "{subjects}"
    );
}

#[test]
fn triangular_fork_can_also_export_to_its_own_upstream() {
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
    let forkgit = f.root.path().join("forkgit");
    // First passthrough goes to the personal fork…
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
    // …and the SAME state can still push to the upstream itself (the
    // §14.2-sanctioned path; dest is not a binding in fork mode). The
    // upstream is non-bare with main checked out, so push a side
    // branch (what a PR-style contribution looks like anyway).
    f.mkit_ok(&fork, &["branch", "contrib"]);
    f.mkit_ok(
        &fork,
        &[
            "git",
            "export",
            "--passthrough",
            "--remote-name",
            "upstream",
            "--ref",
            "refs/heads/contrib",
            up.to_str().unwrap(),
        ],
    );
    let subjects = git_stdout(&up, &["log", "--format=%s", "-n", "1", "contrib"]);
    assert!(subjects.contains("local work"), "{subjects}");
}

#[test]
fn bad_first_url_does_not_wedge_the_state_name() {
    if !git_available() {
        return;
    }
    let f = Fixture::new();
    let missing = f.root.path().join("nope-does-not-exist");
    let out = f.mkit(
        f.root.path(),
        &["git", "import", missing.to_str().unwrap(), "fork"],
    );
    assert!(!out.status.success(), "clone of a missing path fails");
    assert!(
        !f.fork().exists(),
        "failed fresh clone cleans up the target it created"
    );
    // Retry with the REAL upstream into the same target: must succeed
    // without any manual cleanup.
    let up = f.upstream();
    f.mkit_ok(
        f.root.path(),
        &["git", "import", up.to_str().unwrap(), "fork"],
    );
}

#[test]
fn oversized_tag_name_skips_per_ref() {
    if !git_available() {
        return;
    }
    let f = Fixture::new();
    let up = f.upstream();
    // Hand-craft an annotated tag whose name is over the 4096-byte
    // cap; the REF name stays short.
    let commit = git_stdout(&up, &["rev-parse", "HEAD"]);
    let long = "a".repeat(5000);
    let body = format!("object {commit}\ntype commit\ntag {long}\ntagger T <t@x> 5 +0000\n\nbig\n");
    let tmp = f.root.path().join("tagbody");
    std::fs::write(&tmp, body).unwrap();
    let out = git_in(
        &up,
        &[
            "hash-object",
            "-t",
            "tag",
            "--literally",
            "-w",
            tmp.to_str().unwrap(),
        ],
    );
    assert!(out.status.success(), "{out:?}");
    let tag_id = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    git_ok(&up, &["update-ref", "refs/tags/evil", &tag_id]);

    let out = f.mkit_ok(
        f.root.path(),
        &["git", "import", up.to_str().unwrap(), "fork"],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("skipping refs/tags/evil"),
        "per-ref skip, not whole-run abort: {stderr}"
    );
    // Healthy refs imported fine.
    let layout = RepoLayout::single(f.fork());
    assert!(
        refs::read_remote_ref(&layout, "upstream", "main")
            .unwrap()
            .is_some()
    );
    assert!(refs::read_tag(&layout, "v1").unwrap().is_some());
}

#[test]
fn map_only_loss_rebuilds_even_with_unchanged_refs() {
    if !git_available() {
        return;
    }
    let f = Fixture::new();
    let fork = f.import();
    let state = fork.join(".mkit/git/upstream");
    // Delete ONLY the map — no crash marker, upstream unchanged. The
    // disposable-cache contract says the next run rebuilds it; the
    // unchanged-ref short-circuit must not leave it empty (a later
    // passthrough export would re-translate imported history).
    std::fs::remove_file(state.join("map")).unwrap();
    let out = f.mkit_ok(&fork, &["git", "fetch"]);
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("rebuilding"),
        "{out:?}"
    );
    let map = std::fs::read_to_string(state.join("map")).unwrap();
    assert!(map.lines().count() > 0, "map rebuilt");
}

#[test]
fn corrupt_direction_stamp_refuses_instead_of_rebinding() {
    if !git_available() {
        return;
    }
    let f = Fixture::new();
    let fork = f.import();
    std::fs::write(fork.join(".mkit/git/upstream/direction"), "garbage\n").unwrap();
    let out = f.mkit(&fork, &["git", "fetch"]);
    assert!(!out.status.success(), "corrupt binding must refuse");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("corrupt"),
        "{out:?}"
    );
}

#[test]
fn partially_corrupt_map_triggers_full_rebuild() {
    if !git_available() {
        return;
    }
    let f = Fixture::new();
    let fork = f.import();
    let state = fork.join(".mkit/git/upstream");
    // Corrupt the middle of the map but leave valid lines: surviving
    // lines are not evidence the rest exists — the cache must rebuild.
    let map = std::fs::read_to_string(state.join("map")).unwrap();
    let lines: Vec<&str> = map.lines().collect();
    assert!(lines.len() > 2);
    let mangled = format!(
        "{}\nGARBAGE not-a-line\n{}\n",
        lines[0],
        lines[lines.len() - 1]
    );
    std::fs::write(state.join("map"), mangled).unwrap();
    let out = f.mkit_ok(&fork, &["git", "fetch"]);
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("rebuilding"),
        "{out:?}"
    );
    let rebuilt = std::fs::read_to_string(state.join("map")).unwrap();
    assert_eq!(
        rebuilt.lines().count(),
        lines.len(),
        "every mapping recovered"
    );
}

#[test]
fn format_patch_escapes_mbox_splitting_body_lines() {
    if !git_available() {
        return;
    }
    let f = Fixture::new();
    let fork = f.import();
    f.mkit_ok(&fork, &["keygen"]);
    std::fs::write(fork.join("f.txt"), "x\n").unwrap();
    f.mkit_ok(&fork, &["add", "f.txt"]);
    f.mkit_ok(
        &fork,
        &[
            "commit",
            "-m",
            "Tricky body\n\nFrom 1234567890abcdef1234567890abcdef12345678 Mon Sep 17 00:00:00 2001\nFrom the start this stays verbatim.",
        ],
    );
    let out = f.mkit_ok(
        &fork,
        &["git", "format-patch", "upstream/main..HEAD", "--stdout"],
    );
    let mbox = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        mbox.contains(">From 1234567890abcdef"),
        "date-shaped line escaped: {mbox}"
    );
    assert!(
        mbox.contains("\nFrom the start this stays verbatim."),
        "harmless line untouched: {mbox}"
    );

    // And the whole thing applies cleanly where git's own unescaped
    // output would fail mailsplit.
    let up = f.upstream();
    git_ok(
        f.root.path(),
        &["clone", "--quiet", up.to_str().unwrap(), "amtest"],
    );
    let amtest = f.root.path().join("amtest");
    let patch = f.root.path().join("tricky.mbox");
    std::fs::write(&patch, mbox).unwrap();
    git_ok(&amtest, &["am", patch.to_str().unwrap()]);
    let log = git_in(&amtest, &["log", "-1", "--format=%B"]);
    assert!(
        String::from_utf8_lossy(&log.stdout).contains("Tricky body"),
        "{log:?}"
    );
}

#[test]
fn failed_clone_keeps_preexisting_empty_target_dir() {
    if !git_available() {
        return;
    }
    let f = Fixture::new();
    let target = f.root.path().join("preexisting");
    std::fs::create_dir_all(&target).unwrap();
    let missing = f.root.path().join("nope-missing");
    let out = f.mkit(
        f.root.path(),
        &["git", "import", missing.to_str().unwrap(), "preexisting"],
    );
    assert!(!out.status.success());
    assert!(
        target.is_dir(),
        "a directory this run did not create must survive"
    );
    assert_eq!(
        std::fs::read_dir(&target).unwrap().count(),
        0,
        "but this run's contents are cleaned out"
    );
}

#[test]
fn map_tail_truncation_at_line_boundary_rebuilds() {
    if !git_available() {
        return;
    }
    let f = Fixture::new();
    let fork = f.import();
    let state = fork.join(".mkit/git/upstream");
    // Drop the LAST line (ref tips are appended last): the file still
    // parses cleanly, so only the tip-presence check can catch it.
    let map = std::fs::read_to_string(state.join("map")).unwrap();
    let lines: Vec<&str> = map.lines().collect();
    let mut truncated = lines[..lines.len() - 1].join("\n");
    truncated.push('\n');
    std::fs::write(state.join("map"), truncated).unwrap();
    let out = f.mkit_ok(&fork, &["git", "fetch"]);
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("rebuilding"),
        "{out:?}"
    );
    let rebuilt = std::fs::read_to_string(state.join("map")).unwrap();
    assert_eq!(rebuilt.lines().count(), lines.len(), "tail recovered");
}
