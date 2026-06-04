//! #260 Part 2b — the history-rewriting commands (`commit --amend`,
//! `reset`, `rebase`) must record the superseded tip in
//! `.mkit/recovery-log` so `mkit gc` keeps it recoverable. Spawns the
//! real binary and asserts the old tip's full hash lands in the log.

use std::fs;
use std::path::Path;
use std::process::Command;

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
    out
}

/// Fresh repo with a signing key; returns the canonicalized root (so
/// signed commits don't trip the macOS `/var` symlink).
fn init_repo() -> tempfile::TempDir {
    let td = tempfile::tempdir().unwrap();
    // Canonicalize in place by reopening through the resolved path is not
    // possible with TempDir; instead operate on the canonical path.
    assert!(run_in(td.path(), &["init"]).status.success());
    assert!(run_in(td.path(), &["keygen"]).status.success());
    td
}

fn commit(root: &Path, name: &str, content: &[u8], msg: &str) {
    fs::write(root.join(name), content).unwrap();
    assert!(run_in(root, &["add", name]).status.success(), "add {name}");
    assert!(
        run_in(root, &["commit", "-m", msg]).status.success(),
        "commit {msg}"
    );
}

/// Full 64-hex tip of `refs/heads/main`.
fn main_tip(root: &Path) -> String {
    fs::read_to_string(root.join(".mkit/refs/heads/main"))
        .expect("read main ref")
        .trim()
        .to_owned()
}

fn recovery_log(root: &Path) -> String {
    fs::read_to_string(root.join(".mkit/recovery-log")).unwrap_or_default()
}

#[test]
fn amend_records_superseded_head() {
    let td = init_repo();
    let root = td.path();
    commit(root, "a.txt", b"one\n", "one");
    let old = main_tip(root);

    assert!(
        run_in(root, &["commit", "--amend", "-m", "one-amended"])
            .status
            .success(),
        "amend"
    );

    let log = recovery_log(root);
    assert!(
        log.contains(&old),
        "amend must record the superseded HEAD {old} in the recovery log; got:\n{log}"
    );
    assert!(
        log.contains("\tamend\t"),
        "op token should be `amend`: {log}"
    );
    // The amended commit replaced HEAD, so the recorded tip is no longer
    // the branch tip.
    assert_ne!(main_tip(root), old, "amend should have moved the branch");
}

#[test]
fn reset_records_superseded_tip() {
    let td = init_repo();
    let root = td.path();
    commit(root, "a.txt", b"one\n", "one");
    commit(root, "b.txt", b"two\n", "two");
    let superseded = main_tip(root); // tip at "two"

    assert!(
        run_in(root, &["reset", "--soft", "HEAD~1"])
            .status
            .success(),
        "reset --soft HEAD~1"
    );

    let log = recovery_log(root);
    assert!(
        log.contains(&superseded),
        "reset must record the superseded tip {superseded}; got:\n{log}"
    );
    assert!(
        log.contains("\treset\t"),
        "op token should be `reset`: {log}"
    );
}

#[test]
fn noop_reset_records_nothing() {
    let td = init_repo();
    let root = td.path();
    commit(root, "a.txt", b"one\n", "one");
    // reset to the current tip — no supersession, nothing to record.
    assert!(run_in(root, &["reset", "--soft", "HEAD"]).status.success());
    assert!(
        recovery_log(root).is_empty(),
        "a no-op reset must not write a recovery entry"
    );
}

#[test]
fn reset_aborts_and_does_not_move_a_corrupt_current_ref() {
    let td = init_repo();
    let root = td.path();
    commit(root, "a.txt", b"one\n", "one");
    let c1 = main_tip(root); // valid full hash, used as explicit target
    commit(root, "b.txt", b"two\n", "two");

    // Corrupt the current branch ref. `resolve_head` then errors, so
    // reset must abort BEFORE move_head clobbers it unlogged.
    let main_ref = root.join(".mkit/refs/heads/main");
    fs::write(&main_ref, b"not-a-valid-ref\n").unwrap();

    let out = run_in(root, &["reset", "--soft", &c1]);
    assert!(
        !out.status.success(),
        "reset must fail closed on an unreadable current ref"
    );
    assert_eq!(
        fs::read_to_string(&main_ref).unwrap().trim(),
        "not-a-valid-ref",
        "the corrupt ref must NOT be moved"
    );
    assert!(
        recovery_log(root).is_empty(),
        "no recovery entry should be written when reset aborts"
    );
}

#[test]
fn rebase_records_original_tip() {
    let td = init_repo();
    let root = td.path();
    // main: base -> a
    commit(root, "base.txt", b"base\n", "base");
    assert!(run_in(root, &["branch", "feature"]).status.success());
    commit(root, "a.txt", b"a\n", "on-main");

    // feature: base -> b
    assert!(run_in(root, &["checkout", "feature"]).status.success());
    commit(root, "b.txt", b"b\n", "on-feature");
    let feature_orig = main_tip_of(root, "feature");

    // Rebase feature onto main (non-conflicting; different files).
    let out = run_in(root, &["rebase", "main"]);
    assert!(out.status.success(), "rebase: {out:?}");

    let log = recovery_log(root);
    assert!(
        log.contains(&feature_orig),
        "rebase must record the original feature tip {feature_orig}; got:\n{log}"
    );
    assert!(
        log.contains("\trebase\t"),
        "op token should be `rebase`: {log}"
    );
}

fn main_tip_of(root: &Path, branch: &str) -> String {
    fs::read_to_string(root.join(format!(".mkit/refs/heads/{branch}")))
        .expect("read branch ref")
        .trim()
        .to_owned()
}
