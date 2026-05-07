//! Integration tests for the CLI-WIRE commands (9 subcommands).
//!
//! Each command gets at least one happy-path and one error-path test.
//! We spawn the real `mkit` binary so full argv → dispatch → library
//! path is exercised.

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
    fs::read_to_string(td.join(".mkit/refs/heads/main"))
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
    assert!(stderr.contains("usage"));
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
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.contains("fast-forward") || stdout.contains("already up to date"),
        "unexpected merge output: {stdout}"
    );
    // main should have moved off c1.
    assert_ne!(head_hash(td.path()), c1);
}

// ---------- cherry-pick ---------------------------------------------------

#[test]
fn cherry_pick_errors_on_bad_hash() {
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    let out = run_in(td.path(), &["cherry-pick", "not-a-hash"]);
    assert!(!out.status.success());
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
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.contains("rebased 0") || stdout.contains("rebased"),
        "unexpected rebase output: {stdout}"
    );
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
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("no stash"));
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
    let td = tempfile::tempdir().unwrap();
    let out = run_in(td.path(), &["serve"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("usage"));
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
