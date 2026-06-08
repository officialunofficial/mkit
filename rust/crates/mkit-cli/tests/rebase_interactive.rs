//! `mkit rebase -i` — interactive rebase: reorder / drop / reword.
//!
//! Drives the command with a stub `$EDITOR` that transforms the todo file
//! (and, for reword, writes the new commit message on the second editor
//! invocation). squash/fixup are deferred (#291) and rejected here.

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
fn rebase_i_squash_is_rejected_without_mutating() {
    let repo = setup();
    let before = log_subjects(&repo);
    let (_d, script) = editor_script();
    let out = rebase_i(&repo, "main", &script, "squash_b", "");
    assert!(
        !out.status.success(),
        "squash must be rejected (deferred to #291)"
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("not yet supported"),
        "expected a 'not yet supported' message"
    );
    // No mutation: branch and HEAD unchanged, no rebase-apply dir left.
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
