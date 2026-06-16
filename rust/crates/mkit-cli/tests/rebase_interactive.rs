//! `mkit rebase -i` — interactive rebase: reorder / drop / reword / squash
//! / fixup.
//!
//! Drives the command with a stub `$EDITOR` that transforms the todo file
//! (and, for reword/squash, writes the new/combined commit message on the
//! later editor invocation), keyed by the `$OP`/`$MSG` env vars.

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output};

fn mkit_bin() -> &'static str {
    env!("CARGO_BIN_EXE_mkit")
}

/// A stub editor that branches on the file it is handed:
/// - a rebase todo (detected by the `# Rebase` header) → apply `$OP`
/// - anything else (a reword message seed) → overwrite with `$MSG`
///
/// `$OP` values operate on commits whose subjects are single letters
/// `A`/`B`/`C` (the fixtures below), so the transformations are portable
/// shell with no `tac`/`sed -i`.
fn editor_script() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("todo-editor.sh");
    let script = r#"#!/bin/sh
f="$1"
if grep -q '^# Rebase' "$f"; then
    a=$(grep ' A$' "$f")
    b=$(grep ' B$' "$f")
    c=$(grep ' C$' "$f")
    case "$OP" in
        noop) : ;;
        reverse)
            { printf '%s\n' "$c"; printf '%s\n' "$b"; printf '%s\n' "$a"; } > "$f" ;;
        drop_b)
            grep -v ' B$' "$f" > "$f.tmp" && mv "$f.tmp" "$f" ;;
        reword_b)
            { printf '%s\n' "$a"; printf '%s\n' "$b" | sed 's/^pick/reword/'; printf '%s\n' "$c"; } > "$f" ;;
        squash_b)
            { printf '%s\n' "$a"; printf '%s\n' "$b" | sed 's/^pick/squash/'; printf '%s\n' "$c"; } > "$f" ;;
        fixup_b)
            { printf '%s\n' "$a"; printf '%s\n' "$b" | sed 's/^pick/fixup/'; printf '%s\n' "$c"; } > "$f" ;;
        squash_first)
            { printf '%s\n' "$a" | sed 's/^pick/squash/'; printf '%s\n' "$b"; printf '%s\n' "$c"; } > "$f" ;;
        drop_all)
            : > "$f" ;;
    esac
else
    printf '%s' "${MSG:-edited}" > "$f"
fi
"#;
    fs::write(&path, script).unwrap();
    let mut perms = fs::metadata(&path).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&path, perms).unwrap();
    (dir, path)
}

struct Repo {
    _td: tempfile::TempDir,
    _xdg: tempfile::TempDir,
    path: std::path::PathBuf,
    xdg: std::path::PathBuf,
}

fn run(repo: &Repo, args: &[&str]) -> Output {
    Command::new(mkit_bin())
        .args(args)
        .current_dir(&repo.path)
        .env("XDG_CONFIG_HOME", &repo.xdg)
        .output()
        .expect("spawn mkit")
}

fn ok(repo: &Repo, args: &[&str]) -> Output {
    let out = run(repo, args);
    assert!(
        out.status.success(),
        "mkit {:?} failed: {}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

/// `mkit rebase -i <onto>` driven by the stub editor under operation `op`
/// (and reword message `msg`).
fn rebase_i(repo: &Repo, onto: &str, script: &Path, op: &str, msg: &str) -> Output {
    Command::new(mkit_bin())
        .args(["rebase", "-i", onto])
        .current_dir(&repo.path)
        .env("XDG_CONFIG_HOME", &repo.xdg)
        .env("EDITOR", script)
        .env_remove("GIT_EDITOR")
        .env_remove("VISUAL")
        .env("OP", op)
        .env("MSG", msg)
        .output()
        .expect("spawn mkit rebase -i")
}

/// `mkit rebase --continue` with the stub editor wired up (the squash
/// combined-message editor runs during continue).
fn rebase_continue(repo: &Repo, script: &Path, msg: &str) -> Output {
    Command::new(mkit_bin())
        .args(["rebase", "--continue"])
        .current_dir(&repo.path)
        .env("XDG_CONFIG_HOME", &repo.xdg)
        .env("EDITOR", script)
        .env_remove("GIT_EDITOR")
        .env_remove("VISUAL")
        .env("MSG", msg)
        .output()
        .expect("spawn mkit rebase --continue")
}

fn commit(repo: &Repo, file: &str, content: &str, msg: &str) {
    fs::write(repo.path.join(file), content).unwrap();
    ok(repo, &["add", "."]);
    ok(repo, &["commit", "-m", msg]);
}

/// Subjects of the current branch's log, newest-first.
fn log_subjects(repo: &Repo) -> Vec<String> {
    let out = ok(repo, &["log", "--oneline"]);
    String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .map(|l| {
            l.split_once(' ')
                .map_or(String::new(), |(_, s)| s.to_string())
        })
        .collect()
}

/// main = base (c0); feature = base -> A -> B -> C, checked out.
fn setup() -> Repo {
    let td = tempfile::tempdir().unwrap();
    let xdg = tempfile::tempdir().unwrap();
    let repo = Repo {
        path: td.path().to_path_buf(),
        xdg: xdg.path().to_path_buf(),
        _td: td,
        _xdg: xdg,
    };
    ok(&repo, &["init"]);
    ok(&repo, &["keygen"]);
    commit(&repo, "base.txt", "base", "base");
    ok(&repo, &["branch", "feature"]);
    ok(&repo, &["checkout", "feature"]);
    commit(&repo, "a.txt", "A", "A");
    commit(&repo, "b.txt", "B", "B");
    commit(&repo, "c.txt", "C", "C");
    repo
}

#[test]
fn rebase_i_noop_preserves_order() {
    let repo = setup();
    let (_d, script) = editor_script();
    let out = rebase_i(&repo, "main", &script, "noop", "");
    assert!(
        out.status.success(),
        "noop rebase -i failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(log_subjects(&repo), vec!["C", "B", "A", "base"]);
}

#[test]
fn rebase_i_reorder_reverses_commits() {
    let repo = setup();
    let (_d, script) = editor_script();
    // Apply order C, B, A → HEAD is A, newest-first log: A, B, C.
    let out = rebase_i(&repo, "main", &script, "reverse", "");
    assert!(out.status.success());
    assert_eq!(log_subjects(&repo), vec!["A", "B", "C", "base"]);
    // All three files still present (reordering disjoint changes).
    for f in ["a.txt", "b.txt", "c.txt"] {
        assert!(repo.path.join(f).exists(), "{f} missing after reorder");
    }
}

#[test]
fn rebase_i_drop_removes_commit() {
    let repo = setup();
    let (_d, script) = editor_script();
    let out = rebase_i(&repo, "main", &script, "drop_b", "");
    assert!(out.status.success());
    assert_eq!(log_subjects(&repo), vec!["C", "A", "base"]);
    assert!(
        !repo.path.join("b.txt").exists(),
        "dropped commit's file should be gone"
    );
}

#[test]
fn rebase_i_reword_changes_message() {
    let repo = setup();
    let (_d, script) = editor_script();
    let out = rebase_i(&repo, "main", &script, "reword_b", "B-reworded");
    assert!(
        out.status.success(),
        "reword rebase -i failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(log_subjects(&repo), vec!["C", "B-reworded", "A", "base"]);
    // Content is untouched by a reword.
    assert!(repo.path.join("b.txt").exists());
}

#[test]
fn rebase_i_squash_folds_into_previous_and_combines_message() {
    let repo = setup();
    let (_d, script) = editor_script();
    // pick A, squash B into A, pick C. The squash opens the combined-message
    // editor; the stub writes MSG. Result: base -> AB(squashed) -> C.
    let out = rebase_i(&repo, "main", &script, "squash_b", "A and B squashed");
    assert!(
        out.status.success(),
        "squash rebase -i failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        log_subjects(&repo),
        vec!["C", "A and B squashed", "base"],
        "B should be folded into A with a combined message"
    );
    // The squashed commit still carries B's changes.
    assert!(
        repo.path.join("a.txt").exists(),
        "a.txt missing after squash"
    );
    assert!(
        repo.path.join("b.txt").exists(),
        "b.txt missing after squash"
    );
    assert!(repo.path.join("c.txt").exists());
}

#[test]
fn rebase_i_fixup_folds_into_previous_keeping_message() {
    let repo = setup();
    let (_d, script) = editor_script();
    // pick A, fixup B into A, pick C. Fixup keeps A's message and opens no
    // editor. Result: base -> A(+B's changes) -> C.
    let out = rebase_i(&repo, "main", &script, "fixup_b", "");
    assert!(
        out.status.success(),
        "fixup rebase -i failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        log_subjects(&repo),
        vec!["C", "A", "base"],
        "fixup should keep A's message and discard B's"
    );
    assert!(
        repo.path.join("b.txt").exists(),
        "b.txt missing after fixup"
    );
}

/// The danger-zone path: a `squash` whose replay conflicts must pause, and
/// `--continue` must build the *folded* commit (parent = the kept commit's
/// parent = `onto`, combined message) from the resolved tree — not a plain
/// child of HEAD. Scenario: `A` touches a different file (clean pick onto
/// `main`), then `B` edits `f.txt` where `main` also edited it, so only the
/// `squash B` step collides.
#[test]
fn rebase_i_squash_with_conflict_then_continue() {
    let td = tempfile::tempdir().unwrap();
    let xdg = tempfile::tempdir().unwrap();
    let repo = Repo {
        path: td.path().to_path_buf(),
        xdg: xdg.path().to_path_buf(),
        _td: td,
        _xdg: xdg,
    };
    ok(&repo, &["init"]);
    ok(&repo, &["keygen"]);
    commit(&repo, "f.txt", "x\ny\n", "base");
    ok(&repo, &["branch", "feature"]);
    ok(&repo, &["checkout", "feature"]);
    commit(&repo, "a.txt", "from A\n", "A"); // different file → clean pick
    commit(&repo, "f.txt", "B-line\ny\n", "B"); // edits f.txt line 1
    ok(&repo, &["checkout", "main"]);
    commit(&repo, "f.txt", "MAIN-line\ny\n", "M"); // also edits f.txt line 1
    ok(&repo, &["checkout", "feature"]);

    let (_d, script) = editor_script();
    // pick A (other file, clean onto M) then squash B (f.txt line 1 collides).
    let out = rebase_i(&repo, "main", &script, "squash_b", "A+B squashed");
    assert!(
        !out.status.success(),
        "squash should pause on the line-1 conflict"
    );
    assert!(
        repo.path.join(".mkit/rebase-apply").exists(),
        "a paused rebase should leave in-progress state"
    );

    // Resolve and continue. The squash's combined-message editor runs here.
    fs::write(repo.path.join("f.txt"), "RESOLVED\nfrom main+B\n").unwrap();
    ok(&repo, &["add", "f.txt"]);
    let cont = rebase_continue(&repo, &script, "A+B squashed");
    assert!(
        cont.status.success(),
        "rebase --continue after squash conflict failed: {}",
        String::from_utf8_lossy(&cont.stderr)
    );

    // feature = base -> M -> (A+B squashed); the fold's parent is `onto` (M),
    // not the throwaway picked-A commit.
    assert_eq!(log_subjects(&repo), vec!["A+B squashed", "M", "base"]);
    assert_eq!(
        fs::read_to_string(repo.path.join("f.txt")).unwrap(),
        "RESOLVED\nfrom main+B\n",
        "the resolved tree should be committed"
    );
    // A's file survives the fold (it was part of the kept commit).
    assert!(
        repo.path.join("a.txt").exists(),
        "a.txt lost in the squash fold"
    );
    assert!(!repo.path.join(".mkit/rebase-apply").exists());
}

#[test]
fn rebase_i_squash_as_first_line_is_rejected_without_mutating() {
    let repo = setup();
    let before = log_subjects(&repo);
    let (_d, script) = editor_script();
    // Marking the first line `squash` has nothing to fold into.
    let out = rebase_i(&repo, "main", &script, "squash_first", "");
    assert!(!out.status.success(), "a leading squash must be rejected");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("first commit"),
        "expected a 'first commit' rejection, got: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // Rejected before any mutation.
    assert_eq!(log_subjects(&repo), before);
    assert!(!repo.path.join(".mkit/rebase-apply").exists());
}

/// `rebase -i <onto>` when the current branch is *behind* `onto` (an
/// ancestor of it) must fast-forward the branch to `onto`, like
/// non-interactive rebase — not early-return as a noop.
#[test]
fn rebase_i_fast_forwards_when_behind() {
    let td = tempfile::tempdir().unwrap();
    let xdg = tempfile::tempdir().unwrap();
    let repo = Repo {
        path: td.path().to_path_buf(),
        xdg: xdg.path().to_path_buf(),
        _td: td,
        _xdg: xdg,
    };
    ok(&repo, &["init"]);
    ok(&repo, &["keygen"]);
    // main = base -> A; feature branches at base (one commit behind main).
    commit(&repo, "base.txt", "base", "base");
    ok(&repo, &["branch", "feature"]);
    commit(&repo, "a.txt", "A", "A"); // advances main to A
    ok(&repo, &["checkout", "feature"]);
    assert_eq!(log_subjects(&repo), vec!["base"]);

    let (_d, script) = editor_script();
    let out = rebase_i(&repo, "main", &script, "noop", "");
    assert!(
        out.status.success(),
        "rebase -i when behind failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // feature fast-forwarded to main (base -> A).
    assert_eq!(log_subjects(&repo), vec!["A", "base"]);
    assert!(repo.path.join("a.txt").exists());
}

#[test]
fn rebase_i_drop_all_resets_to_base() {
    let repo = setup();
    let (_d, script) = editor_script();
    let out = rebase_i(&repo, "main", &script, "drop_all", "");
    assert!(
        out.status.success(),
        "drop-all rebase -i failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // Dropping every commit resets feature to the base.
    assert_eq!(log_subjects(&repo), vec!["base"]);
    for f in ["a.txt", "b.txt", "c.txt"] {
        assert!(!repo.path.join(f).exists(), "{f} should be gone");
    }
}

// ---------- revspec targets (the onto argument is resolved through the
// shared revspec resolver, not a literal ref read) ------------------------

/// Non-interactive `rebase HEAD~n` works: the positional argument
/// accepts any revspec, not just a branch name. (Regression: this used
/// to fail with `read ref: invalid ref name 'HEAD~3'`.)
#[test]
fn rebase_accepts_head_relative_revspec() {
    let repo = setup();
    // On feature (base -> A -> B -> C): HEAD~3 == base == main.
    let out = run(&repo, &["rebase", "HEAD~3"]);
    assert!(
        out.status.success(),
        "rebase HEAD~3 failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("rebased 3 commit(s)"),
        "expected a 3-commit replay, got: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(log_subjects(&repo), vec!["C", "B", "A", "base"]);
}

/// Non-interactive `rebase <short-hash>` works.
#[test]
fn rebase_accepts_short_hash_revspec() {
    let repo = setup();
    let main_hash = fs::read_to_string(repo.path.join(".mkit/refs/heads/main")).unwrap();
    let short = &main_hash.trim()[..12];
    let out = run(&repo, &["rebase", short]);
    assert!(
        out.status.success(),
        "rebase {short} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("rebased 3 commit(s)"),
        "expected a 3-commit replay, got: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(log_subjects(&repo), vec!["C", "B", "A", "base"]);
}

/// `rebase -i HEAD~n` works (the interactive flag goes through the same
/// resolution).
#[test]
fn rebase_i_accepts_head_relative_revspec() {
    let repo = setup();
    let (_d, script) = editor_script();
    // HEAD~2 == A; replay B and C onto it unchanged.
    let out = rebase_i(&repo, "HEAD~2", &script, "noop", "");
    assert!(
        out.status.success(),
        "rebase -i HEAD~2 failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("rebased 2 commit(s)"),
        "expected a 2-commit replay, got: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(log_subjects(&repo), vec!["C", "B", "A", "base"]);
}

/// An unknown revspec is still rejected before any mutation.
#[test]
fn rebase_rejects_unknown_revspec() {
    let repo = setup();
    let before = log_subjects(&repo);
    let out = run(&repo, &["rebase", "nosuchref~2"]);
    assert!(!out.status.success(), "unknown revspec should fail");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("no such commit"),
        "expected a resolver error, got: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(log_subjects(&repo), before);
    assert!(!repo.path.join(".mkit/rebase-apply").exists());
}
