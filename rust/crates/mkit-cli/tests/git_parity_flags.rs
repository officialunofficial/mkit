//! Integration coverage for the git-UX parity flags added alongside the
//! parity-matrix sweep: `commit -F`, two-parent `merge --no-commit`,
//! `cherry-pick -n`/`-m`, `merge -m`, `branch` ancestry filters,
//! `show --stat`, `diff --merge-base`, `stash@{N}`, and case-insensitive
//! `config` keys. Each asserts the git-shaped behavior end to end.

mod common;

use std::process::Output;

use common::Repo;

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Count `parent <hash>` lines in a commit object's `cat-file -p` output.
fn parent_count(repo: &Repo, rev: &str) -> usize {
    let out = repo.ok(&["cat-file", "-p", rev]);
    stdout(&out)
        .lines()
        .filter(|l| l.starts_with("parent "))
        .count()
}

/// A base commit, then `feature` (adds `b.txt`) and `main` (adds `c.txt`)
/// touch *different* files, so a merge is clean (no conflict). Leaves the
/// repo checked out on `main`.
fn clean_diverge(repo: &Repo) {
    repo.commit_file("a.txt", b"base\n", "base");
    repo.ok(&["branch", "feature"]);
    repo.ok(&["checkout", "feature"]);
    repo.commit_file("b.txt", b"feat\n", "feat");
    repo.ok(&["checkout", "main"]);
    repo.commit_file("c.txt", b"main\n", "main2");
}

#[test]
fn config_keys_are_case_insensitive() {
    let repo = Repo::new();
    // Mixed-case set, lowercase read — git-compatible.
    repo.ok(&["config", "User.Name", "Ada"]);
    assert_eq!(stdout(&repo.ok(&["config", "user.name"])).trim(), "Ada");
    repo.ok(&["config", "USER.EMAIL", "ada@example.com"]);
    assert_eq!(
        stdout(&repo.ok(&["config", "user.email"])).trim(),
        "ada@example.com"
    );
}

#[test]
fn config_case_variant_cannot_bypass_forbidden_key_guard() {
    // `user.identity` is repo-forbidden; a case variant must route to
    // user scope, never the per-repo layer (that would be a spoof vector).
    // The key is lowercased BEFORE the REPO_FORBIDDEN_KEYS check, so the
    // mixed-case spelling is caught by the same guard.
    let repo = Repo::new();
    let ident = format!("ed25519:{}", "ab".repeat(32));
    repo.ok(&["config", "User.Identity", &ident]);
    let cfg = std::fs::read_to_string(repo.mkit_dir().join("config")).unwrap_or_default();
    assert!(
        !cfg.to_lowercase().contains("identity"),
        "case-variant user.identity leaked into the per-repo config: {cfg}"
    );
}

#[test]
fn commit_dash_f_reads_message_from_file() {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"v1\n", "first");
    repo.write("a.txt", b"v2\n");
    repo.ok(&["add", "a.txt"]);
    repo.write("MSG", b"message from -F\n");
    repo.ok(&["commit", "-F", "MSG"]);
    let log = stdout(&repo.ok(&["log", "--oneline"]));
    assert!(
        log.lines().next().unwrap_or("").contains("message from -F"),
        "log subject did not come from -F file: {log}"
    );
}

#[test]
fn merge_no_commit_then_commit_records_two_parents() {
    let repo = Repo::new();
    clean_diverge(&repo);
    let head_before = stdout(&repo.ok(&["rev-parse", "HEAD"]));

    let out = repo.ok(&["merge", "--no-commit", "feature"]);
    let msg = String::from_utf8_lossy(&out.stderr);
    assert!(
        msg.contains("stopped before committing"),
        "unexpected merge --no-commit message: {msg}"
    );
    // HEAD has NOT moved yet.
    assert_eq!(stdout(&repo.ok(&["rev-parse", "HEAD"])), head_before);
    // The merged-in file is materialised.
    assert!(repo.path().join("b.txt").exists());

    // Finishing with `mkit commit` records a two-parent merge commit.
    repo.ok(&["commit", "-m", "Merge feature"]);
    assert_eq!(parent_count(&repo, "HEAD"), 2);
    assert_ne!(stdout(&repo.ok(&["rev-parse", "HEAD"])), head_before);
}

#[test]
fn merge_continue_also_finishes_a_no_commit_merge() {
    let repo = Repo::new();
    clean_diverge(&repo);
    repo.ok(&["merge", "--no-commit", "feature"]);
    // The existing `--continue` path must still finalize it (two parents).
    repo.ok(&["merge", "--continue"]);
    assert_eq!(parent_count(&repo, "HEAD"), 2);
}

#[test]
fn merge_dash_m_overrides_message() {
    let repo = Repo::new();
    clean_diverge(&repo);
    repo.ok(&["merge", "-m", "custom merge subject", "feature"]);
    let log = stdout(&repo.ok(&["log", "--oneline"]));
    assert!(
        log.contains("custom merge subject"),
        "merge -m message not used: {log}"
    );
}

#[test]
fn cherry_pick_no_commit_stages_without_committing() {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"base\n", "base");
    repo.ok(&["branch", "feature"]);
    repo.ok(&["checkout", "feature"]);
    repo.commit_file("d.txt", b"picked\n", "add d");
    let pick = stdout(&repo.ok(&["rev-parse", "HEAD"]));
    let pick = pick.trim();
    repo.ok(&["checkout", "main"]);
    let head_before = stdout(&repo.ok(&["rev-parse", "HEAD"]));

    repo.ok(&["cherry-pick", "-n", pick]);
    // HEAD unchanged, but the picked file is staged into the worktree.
    assert_eq!(stdout(&repo.ok(&["rev-parse", "HEAD"])), head_before);
    assert!(repo.path().join("d.txt").exists());

    // Finishing yields an ordinary single-parent commit.
    repo.ok(&["commit", "-m", "took d"]);
    assert_eq!(parent_count(&repo, "HEAD"), 1);
}

#[test]
fn cherry_pick_dash_m_overrides_message() {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"base\n", "base");
    repo.ok(&["branch", "feature"]);
    repo.ok(&["checkout", "feature"]);
    repo.commit_file("d.txt", b"x\n", "original subject");
    let pick = stdout(&repo.ok(&["rev-parse", "HEAD"]));
    let pick = pick.trim();
    repo.ok(&["checkout", "main"]);
    repo.ok(&["cherry-pick", "-m", "renamed subject", pick]);
    let log = stdout(&repo.ok(&["log", "--oneline"]));
    assert!(
        log.lines().next().unwrap_or("").contains("renamed subject"),
        "cherry-pick -m message not used: {log}"
    );
}

#[test]
fn branch_contains_and_merged_filter_by_ancestry() {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"base\n", "base");
    repo.ok(&["branch", "feature"]); // feature stays at base
    repo.commit_file("a.txt", b"more\n", "c1"); // main advances
    let c1 = stdout(&repo.ok(&["rev-parse", "HEAD"]));
    let c1 = c1.trim();

    // Only main contains c1.
    let contains = stdout(&repo.ok(&["branch", "--contains", c1]));
    assert!(contains.contains("main"), "expected main: {contains}");
    assert!(
        !contains.contains("feature"),
        "feature should not contain c1: {contains}"
    );

    // Both branches are merged into HEAD (feature's tip is an ancestor).
    let merged = stdout(&repo.ok(&["branch", "--merged"]));
    assert!(merged.contains("main") && merged.contains("feature"));

    // --no-merged HEAD excludes everything reachable from HEAD.
    let no_merged = stdout(&repo.ok(&["branch", "--no-merged"]));
    assert!(
        !no_merged.contains("feature") && !no_merged.contains("main"),
        "nothing should be unmerged: {no_merged}"
    );
}

#[test]
fn show_stat_renders_diffstat() {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"l1\nl2\n", "base");
    let out = repo.ok(&["show", "--stat", "HEAD"]);
    let s = stdout(&out);
    assert!(s.contains("a.txt"), "stat missing file: {s}");
    assert!(s.contains("file changed"), "stat missing summary: {s}");
    // Not the full patch — no hunk header.
    assert!(!s.contains("@@"), "show --stat should omit the patch: {s}");
}

#[test]
fn diff_merge_base_two_revs() {
    let repo = Repo::new();
    clean_diverge(&repo); // merge-base(feature,main) == base; main added c.txt
    let out = repo.ok(&["diff", "--merge-base", "feature", "main", "--name-only"]);
    let names = stdout(&out);
    assert!(
        names.contains("c.txt"),
        "merge-base diff should show main's added file: {names}"
    );
}

#[test]
fn stash_accepts_stash_at_brace_syntax() {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"base\n", "base");
    repo.write("a.txt", b"dirty1\n");
    repo.ok(&["stash"]);
    repo.write("a.txt", b"dirty2\n");
    repo.ok(&["stash", "save", "-m", "second"]);

    let list = stdout(&repo.ok(&["stash", "list"]));
    assert!(list.contains("stash@{0}") && list.contains("stash@{1}"));

    // Pop the older entry by its git-style reference.
    repo.ok(&["stash", "pop", "stash@{1}"]);

    // A malformed reference is a clean usage error, not a panic.
    let bad = repo.run(&["stash", "show", "stash@{nope}"]);
    assert!(!bad.status.success());
}
