//! Integration tests for the CLI-WIRE commands (9 subcommands).
//!
//! Each command gets at least one happy-path and one error-path test.
//! We spawn the real `mkit` binary so full argv → dispatch → library
//! path is exercised.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::fs;
use std::path::Path;
use std::process::Command;

fn mkit_bin() -> &'static str {
    env!("CARGO_BIN_EXE_mkit")
}

fn run_in(cwd: &Path, args: &[&str]) -> std::process::Output {
    // Empty XDG_CONFIG_HOME per call so the developer's real user
    // config does not bleed into tests.
    let xdg = tempfile::tempdir().expect("xdg tempdir");
    let out = Command::new(mkit_bin())
        .args(args)
        .current_dir(cwd)
        .env("XDG_CONFIG_HOME", xdg.path())
        .output()
        .expect("spawn mkit");
    drop(xdg);
    out
}

fn init_repo(td: &Path) {
    assert!(run_in(td, &["init"]).status.success());
    // we removed auto-keygen on `mkit commit`.
    assert!(run_in(td, &["keygen"]).status.success());
}

fn make_commit(td: &Path, file: &str, body: &[u8], msg: &str) {
    fs::write(td.join(file), body).unwrap();
    assert!(run_in(td, &["add", file]).status.success());
    let out = run_in(td, &["commit", "-m", msg]);
    assert!(out.status.success(), "commit failed: {out:?}");
}

fn head_hash(td: &Path) -> String {
    ref_hash(td, "main")
}

fn ref_hash(td: &Path, branch: &str) -> String {
    fs::read_to_string(td.join(".mkit/refs/heads").join(branch))
        .unwrap()
        .trim()
        .to_string()
}

// ---------- clone ---------------------------------------------------------

#[test]
fn clone_errors_on_missing_url() {
    let td = tempfile::tempdir().unwrap();
    let out = run_in(td.path(), &["clone"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.to_lowercase().contains("usage"),
        "expected usage diagnostic on stderr, got: {stderr}"
    );
}

#[test]
fn clone_from_file_url_roundtrips() {
    // FileTransport expects a bare-ish layout with `refs/heads/...` and
    // `packs/...` directly under its root URL — NOT the in-repo `.mkit/`
    // layout. We set up a bare directory, push alice's refs into it,
    // then clone from the bare URL.
    let alice = tempfile::tempdir().unwrap();
    init_repo(alice.path());
    make_commit(alice.path(), "a.txt", b"hi from alice\n", "first");

    let bare = tempfile::tempdir().unwrap();
    let url = format!("mkit+file://{}", bare.path().display());
    // Publish alice's main ref into the bare remote.
    assert!(
        run_in(alice.path(), &["remote", "add", &url])
            .status
            .success()
    );
    let out = run_in(alice.path(), &["push"]);
    assert!(out.status.success(), "push failed: {out:?}");

    let parent = tempfile::tempdir().unwrap();
    let out = Command::new(mkit_bin())
        .args(["clone", &url, "bob"])
        .current_dir(parent.path())
        .output()
        .expect("spawn");
    assert!(out.status.success(), "clone failed: {out:?}");
    let bob = parent.path().join("bob");
    assert!(bob.join(".mkit/refs/heads/main").is_file());
    assert_eq!(
        fs::read_to_string(alice.path().join(".mkit/refs/heads/main"))
            .unwrap()
            .trim(),
        fs::read_to_string(bob.join(".mkit/refs/heads/main"))
            .unwrap()
            .trim(),
    );
}

// ---------- merge ---------------------------------------------------------

#[test]
fn merge_errors_on_missing_branch() {
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    let out = run_in(td.path(), &["merge", "nope"]);
    assert!(!out.status.success());
}

#[test]
fn merge_fast_forwards_when_current_is_ancestor() {
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    make_commit(td.path(), "a.txt", b"1\n", "c1");
    let c1 = head_hash(td.path());
    assert!(run_in(td.path(), &["branch", "feature"]).status.success());
    // Advance feature ahead of main.
    assert!(run_in(td.path(), &["checkout", "feature"]).status.success());
    make_commit(td.path(), "a.txt", b"2\n", "c2");
    // Go back to main — main still at c1 — and merge feature (ff).
    assert!(run_in(td.path(), &["checkout", "main"]).status.success());
    // Only assert merge ran; check it claims fast-forward.
    let out = run_in(td.path(), &["merge", "feature"]);
    assert!(out.status.success(), "merge failed: {out:?}");
    // Confirmation prose now lives on stderr.
    let stderr = String::from_utf8(out.stderr).unwrap();
    let lower = stderr.to_lowercase();
    assert!(
        lower.contains("fast-forward") || lower.contains("up to date"),
        "unexpected merge output: {stderr}"
    );
    // main should have moved off c1.
    assert_ne!(head_hash(td.path()), c1);
}

#[test]
fn merge_preserves_ignored_untracked_files() {
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    make_commit(td.path(), "a.txt", b"1\n", "c1");
    assert!(run_in(td.path(), &["branch", "feature"]).status.success());
    assert!(run_in(td.path(), &["checkout", "feature"]).status.success());
    make_commit(td.path(), "a.txt", b"2\n", "c2");
    assert!(run_in(td.path(), &["checkout", "main"]).status.success());

    fs::write(td.path().join(".mkitignore"), "local.txt\n").unwrap();
    fs::write(td.path().join("local.txt"), b"local only\n").unwrap();

    let out = run_in(td.path(), &["merge", "feature"]);
    assert!(out.status.success(), "merge failed: {out:?}");
    assert_eq!(
        fs::read(td.path().join("local.txt")).unwrap(),
        b"local only\n"
    );
    assert_eq!(
        fs::read_to_string(td.path().join(".mkitignore")).unwrap(),
        "local.txt\n"
    );
}

// ---------- cherry-pick ---------------------------------------------------

#[test]
fn cherry_pick_errors_on_bad_hash() {
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    let out = run_in(td.path(), &["cherry-pick", "not-a-hash"]);
    assert!(!out.status.success());
}

#[test]
fn cherry_pick_restores_worktree_and_advances_ref() {
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    make_commit(td.path(), "base.txt", b"base\n", "base");
    assert!(run_in(td.path(), &["branch", "feature"]).status.success());
    assert!(run_in(td.path(), &["checkout", "feature"]).status.success());
    make_commit(td.path(), "picked.txt", b"picked\n", "picked");
    let picked = ref_hash(td.path(), "feature");
    assert!(run_in(td.path(), &["checkout", "main"]).status.success());
    let main_before = head_hash(td.path());

    let out = run_in(td.path(), &["cherry-pick", &picked]);
    assert!(out.status.success(), "cherry-pick failed: {out:?}");
    assert_eq!(fs::read(td.path().join("picked.txt")).unwrap(), b"picked\n");
    assert_ne!(head_hash(td.path()), main_before);
}

// ---------- rebase --------------------------------------------------------

#[test]
fn rebase_errors_when_no_rebase_in_progress() {
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    let out = run_in(td.path(), &["rebase", "--continue"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("no rebase in progress"));
}

#[test]
fn rebase_onto_same_head_is_noop() {
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    make_commit(td.path(), "a.txt", b"1\n", "c1");
    // Create a feature branch at HEAD and rebase onto it — nothing to replay.
    assert!(run_in(td.path(), &["branch", "feature"]).status.success());
    let out = run_in(td.path(), &["rebase", "feature"]);
    assert!(out.status.success(), "rebase failed: {out:?}");
    // Confirmation prose lives on stderr.
    let stderr = String::from_utf8(out.stderr).unwrap();
    let lower = stderr.to_lowercase();
    assert!(
        lower.contains("rebased") || lower.contains("up to date"),
        "unexpected rebase output: {stderr}"
    );
}

#[test]
fn rebase_abort_restores_original_branch_ref_and_worktree() {
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    make_commit(td.path(), "a.txt", b"base\n", "base");
    assert!(run_in(td.path(), &["branch", "feature"]).status.success());

    assert!(run_in(td.path(), &["checkout", "feature"]).status.success());
    make_commit(td.path(), "a.txt", b"feature\n", "feature change");
    let feature_before = ref_hash(td.path(), "feature");

    assert!(run_in(td.path(), &["checkout", "main"]).status.success());
    make_commit(td.path(), "a.txt", b"main\n", "main change");

    assert!(run_in(td.path(), &["checkout", "feature"]).status.success());
    let rebase = run_in(td.path(), &["rebase", "main"]);
    assert!(!rebase.status.success(), "rebase should pause on conflict");
    assert!(td.path().join(".mkit/rebase-apply").exists());

    let abort = run_in(td.path(), &["rebase", "--abort"]);
    assert!(abort.status.success(), "abort failed: {abort:?}");
    assert_eq!(ref_hash(td.path(), "feature"), feature_before);
    assert_eq!(fs::read(td.path().join("a.txt")).unwrap(), b"feature\n");
    assert!(!td.path().join(".mkit/rebase-apply").exists());
}

// ---------- bisect --------------------------------------------------------

#[test]
fn bisect_errors_on_unknown_subcommand() {
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    let out = run_in(td.path(), &["bisect", "wat"]);
    assert!(!out.status.success());
}

#[test]
fn bisect_start_creates_state_file() {
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    make_commit(td.path(), "a.txt", b"1\n", "c1");
    let out = run_in(td.path(), &["bisect", "start"]);
    assert!(out.status.success(), "bisect start failed: {out:?}");
    assert!(td.path().join(".mkit/bisect").is_file());
    // Clean up so the repo can be dropped cleanly.
    assert!(run_in(td.path(), &["bisect", "reset"]).status.success());
}

// ---------- stash ---------------------------------------------------------

#[test]
fn stash_list_on_empty_repo_prints_none_marker() {
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    let out = run_in(td.path(), &["stash", "list"]);
    assert!(out.status.success(), "stash list failed: {out:?}");
    // Empty stash listing → empty stdout; the "(no stash entries)"
    // marker is human-readable diagnostic on stderr.
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.is_empty(),
        "empty stash list must produce empty stdout: {stdout:?}"
    );
    // git prints nothing at all for an empty stash list — match that.
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.is_empty(),
        "empty stash list must be silent (git-shaped): {stderr:?}"
    );
}

#[test]
fn stash_show_returns_tempfail_placeholder() {
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    let out = run_in(td.path(), &["stash", "show"]);
    assert!(!out.status.success());
}

// ---------- blame ---------------------------------------------------------

#[test]
fn blame_errors_on_missing_file() {
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    make_commit(td.path(), "real.txt", b"x\n", "r1");
    let out = run_in(td.path(), &["blame", "nope.txt"]);
    assert!(!out.status.success());
}

#[test]
fn blame_on_single_commit_attributes_every_line_to_it() {
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    make_commit(td.path(), "f.txt", b"one\ntwo\nthree\n", "first");
    let out = run_in(td.path(), &["blame", "f.txt"]);
    assert!(out.status.success(), "blame failed: {out:?}");
    let stdout = String::from_utf8(out.stdout).unwrap();
    // Three lines, each with short_hash \t <line_num> \t <text>.
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 3, "expected 3 blame lines, got {stdout:?}");
    assert!(lines[0].ends_with("\tone"));
    assert!(lines[1].ends_with("\ttwo"));
    assert!(lines[2].ends_with("\tthree"));
    // Short hash is 12 hex chars.
    let first_short: &str = lines[0].split('\t').next().unwrap();
    assert_eq!(first_short.len(), 12);
    assert!(first_short.chars().all(|c| c.is_ascii_hexdigit()));
}

// ---------- serve ---------------------------------------------------------

#[test]
fn serve_errors_on_missing_path() {
    // `mkit serve` without a path should fail with a usage error.
    // Clap renders "Usage:" (capital U) in its error output; match
    // case-insensitively so the test isn't tied to clap's exact
    // formatting.
    let td = tempfile::tempdir().unwrap();
    let out = run_in(td.path(), &["serve"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.to_lowercase().contains("usage"),
        "expected usage diagnostic on stderr, got: {stderr}"
    );
}

#[test]
fn serve_rejects_bad_handshake_and_exits() {
    use std::io::Write;
    use std::process::Stdio;

    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());

    let mut child = Command::new(mkit_bin())
        .args(["serve", td.path().to_str().unwrap()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn serve");

    // Send a single frame with the wrong opcode (should be OP_HELLO = 0x00).
    // Frame = [op=0x01][len=0u32].
    let frame = [0x01, 0, 0, 0, 0];
    child.stdin.as_mut().unwrap().write_all(&frame).unwrap();
    drop(child.stdin.take());
    let out = child.wait_with_output().expect("wait serve");
    // The server responds with STATUS_ERROR and exits — exit code is
    // PROTOCOL_ERROR (76).
    assert!(!out.status.success(), "serve should reject bad handshake");
}

// ---------- sparse-checkout ----------------------------------------------

#[test]
fn sparse_checkout_set_without_patterns_errors() {
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    let out = run_in(td.path(), &["sparse-checkout", "set"]);
    assert!(!out.status.success());
}

#[test]
fn sparse_checkout_roundtrips_patterns() {
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    make_commit(td.path(), "a.txt", b"x\n", "c1");
    assert!(
        run_in(td.path(), &["sparse-checkout", "set", "a.txt"])
            .status
            .success()
    );
    let out = run_in(td.path(), &["sparse-checkout", "list"]);
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("a.txt"));
    assert!(
        run_in(td.path(), &["sparse-checkout", "disable"])
            .status
            .success()
    );
}

#[test]
fn sparse_checkout_set_refuses_dirty_tracked_file_inside_sparse_set() {
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    make_commit(td.path(), "a.txt", b"v1\n", "c1");

    fs::write(td.path().join("a.txt"), b"local edit\n").unwrap();
    let out = run_in(td.path(), &["sparse-checkout", "set", "a.txt"]);

    assert!(!out.status.success(), "sparse set should fail: {out:?}");
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("restore would overwrite local changes"));
    assert_eq!(fs::read(td.path().join("a.txt")).unwrap(), b"local edit\n");
    assert!(!td.path().join(".mkit/sparse-checkout").exists());
}

#[test]
fn sparse_checkout_set_allows_dirty_tracked_file_outside_sparse_set() {
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    fs::write(td.path().join("a.txt"), b"a\n").unwrap();
    fs::write(td.path().join("b.txt"), b"b\n").unwrap();
    assert!(run_in(td.path(), &["add", "."]).status.success());
    assert!(run_in(td.path(), &["commit", "-m", "c1"]).status.success());

    fs::write(td.path().join("b.txt"), b"local b\n").unwrap();
    let out = run_in(td.path(), &["sparse-checkout", "set", "a.txt"]);

    assert!(out.status.success(), "sparse set failed: {out:?}");
    assert_eq!(fs::read(td.path().join("b.txt")).unwrap(), b"local b\n");
    assert_eq!(
        fs::read_to_string(td.path().join(".mkit/sparse-checkout")).unwrap(),
        "a.txt\n"
    );
}

#[test]
fn sparse_checkout_disable_refuses_untracked_file_that_full_restore_would_remove() {
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    make_commit(td.path(), "a.txt", b"a\n", "c1");
    assert!(
        run_in(td.path(), &["sparse-checkout", "set", "a.txt"])
            .status
            .success()
    );

    fs::write(td.path().join("notes.txt"), b"local notes\n").unwrap();
    let out = run_in(td.path(), &["sparse-checkout", "disable"]);

    assert!(!out.status.success(), "sparse disable should fail: {out:?}");
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("restore would remove untracked path"));
    assert_eq!(
        fs::read(td.path().join("notes.txt")).unwrap(),
        b"local notes\n"
    );
    assert_eq!(
        fs::read_to_string(td.path().join(".mkit/sparse-checkout")).unwrap(),
        "a.txt\n"
    );
}

// ---------- diff (revision resolver, #207) -------------------------------

#[test]
fn diff_head_tilde_one_shows_second_commit_change() {
    // PR-B / #207: `mkit diff HEAD~1` must resolve the revision to its
    // tree and emit a real diff against the worktree (which mirrors the
    // tip), NOT silently treat `HEAD~1` as a pathspec and exit empty.
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    make_commit(td.path(), "a.txt", b"one\n", "c1");
    make_commit(td.path(), "b.txt", b"two\n", "c2");

    let out = run_in(td.path(), &["diff", "HEAD~1"]);
    assert!(out.status.success(), "diff HEAD~1 failed: {out:?}");
    let stdout = String::from_utf8(out.stdout).unwrap();
    // The worktree (== HEAD == c2) differs from HEAD~1 (== c1) by b.txt.
    assert!(
        stdout.contains("b.txt"),
        "expected b.txt in diff HEAD~1 output, got: {stdout:?}"
    );
}

#[test]
fn diff_branch_ref_resolves_and_diffs() {
    // `mkit diff <branch>` resolves the branch tip to its tree.
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    make_commit(td.path(), "a.txt", b"one\n", "c1");
    assert!(run_in(td.path(), &["branch", "base"]).status.success());
    make_commit(td.path(), "b.txt", b"two\n", "c2");

    let out = run_in(td.path(), &["diff", "base"]);
    assert!(out.status.success(), "diff base failed: {out:?}");
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.contains("b.txt"),
        "expected b.txt in diff base output, got: {stdout:?}"
    );
}

#[test]
fn diff_bad_revision_errors_not_silent_empty() {
    // A hash-shaped arg that resolves to nothing is a hard error (#207),
    // not a silent empty diff.
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    make_commit(td.path(), "a.txt", b"one\n", "c1");

    let bogus = "ab".repeat(32);
    let out = run_in(td.path(), &["diff", &bogus]);
    assert!(!out.status.success(), "bad revision should fail: {out:?}");
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.to_lowercase().contains("revision"),
        "expected a revision diagnostic, got: {stderr}"
    );
}

#[test]
fn diff_staged_with_revision_is_usage_error() {
    // #223: `--staged` already fixes HEAD vs index; an explicit revision
    // is contradictory.
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    make_commit(td.path(), "a.txt", b"one\n", "c1");

    let out = run_in(td.path(), &["diff", "--staged", "HEAD"]);
    assert!(!out.status.success(), "--staged HEAD should fail: {out:?}");
}

// ---------- branch / tag ref-write safety (#206) -------------------------

#[test]
fn branch_create_collision_is_rejected() {
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    make_commit(td.path(), "a.txt", b"one\n", "c1");
    assert!(run_in(td.path(), &["branch", "feature"]).status.success());

    let out = run_in(td.path(), &["branch", "feature"]);
    assert!(
        !out.status.success(),
        "duplicate branch should fail: {out:?}"
    );
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("already exists"),
        "expected collision diagnostic, got: {stderr}"
    );
}

#[test]
fn branch_delete_current_is_rejected() {
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    make_commit(td.path(), "a.txt", b"one\n", "c1");
    // HEAD points at `main`; deleting it must be refused.
    let out = run_in(td.path(), &["branch", "-d", "main"]);
    assert!(
        !out.status.success(),
        "deleting current branch should fail: {out:?}"
    );
}

#[test]
fn tag_create_collision_is_rejected() {
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    make_commit(td.path(), "a.txt", b"one\n", "c1");
    assert!(run_in(td.path(), &["tag", "v1"]).status.success());

    let out = run_in(td.path(), &["tag", "v1"]);
    assert!(!out.status.success(), "duplicate tag should fail: {out:?}");
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("already exists"),
        "expected collision diagnostic, got: {stderr}"
    );
}
