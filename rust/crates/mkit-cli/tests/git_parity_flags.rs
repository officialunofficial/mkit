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

/// Resolve a revision to its full object id.
fn rev(repo: &Repo, r: &str) -> String {
    stdout(&repo.ok(&["rev-parse", r])).trim().to_string()
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
fn cherry_pick_m_is_mainline_selection_not_a_message() {
    // git's `cherry-pick -m` is `--mainline <parent-number>`, NOT a message
    // override. Verify the git semantics: required for a merge, rejected for
    // a non-merge, and that a valid mainline picks that parent's diff.
    let repo = Repo::new();
    repo.commit_file("a.txt", b"base\n", "c0");
    repo.ok(&["branch", "feature"]);
    repo.ok(&["checkout", "feature"]);
    repo.commit_file("b.txt", b"feat\n", "fb");
    repo.ok(&["checkout", "main"]);
    repo.commit_file("c.txt", b"main\n", "mc");
    let mc = rev(&repo, "HEAD");

    // Build a real merge commit M on `feature` (parents: fb, mc).
    repo.ok(&["checkout", "feature"]);
    repo.ok(&["merge", "main", "-m", "merge main into feature"]);
    assert_eq!(parent_count(&repo, "HEAD"), 2, "M must be a merge");
    let m = rev(&repo, "HEAD");

    repo.ok(&["checkout", "main"]);

    // `-m` on a NON-merge commit is rejected (git: "not a merge").
    let out = repo.run(&["cherry-pick", "-m", "1", &mc]);
    assert!(!out.status.success(), "-m on a non-merge must fail");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("not a merge"),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Cherry-picking the MERGE without `-m` is refused (git: needs mainline).
    let out = repo.run(&["cherry-pick", &m]);
    assert!(!out.status.success(), "merge pick without -m must fail");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("mainline"),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // `-m 2` selects parent 2 (mc) as the base: M's diff vs mc adds b.txt,
    // which `main` lacks → a clean pick. (A string like "msg" would be a
    // value-parse error, proving `-m` is numeric mainline selection.)
    assert!(!repo.path().join("b.txt").exists());
    let out = repo.run(&["cherry-pick", "-m", "2", &m]);
    assert!(
        out.status.success(),
        "cherry-pick -m 2 <merge> should succeed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(repo.path().join("b.txt").exists(), "mainline 2 should add b.txt");

    // A non-numeric `-m` is a clean value error, not a silent message.
    let out = repo.run(&["cherry-pick", "-m", "notanumber", &m]);
    assert!(!out.status.success(), "non-numeric -m must be a usage error");
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

#[test]
fn stash_pop_index_restores_staged_state() {
    // Stage v2 but leave v3 in the worktree, so staged != worktree.
    let repo = Repo::new();
    repo.commit_file("a.txt", b"v1\n", "c0");
    repo.write("a.txt", b"v2\n");
    repo.ok(&["add", "a.txt"]);
    repo.write("a.txt", b"v3\n");
    repo.ok(&["stash"]);
    // Worktree was reset to HEAD.
    assert_eq!(std::fs::read(repo.path().join("a.txt")).unwrap(), b"v1\n");

    repo.ok(&["stash", "pop", "--index"]);
    // Worktree restored to v3...
    assert_eq!(std::fs::read(repo.path().join("a.txt")).unwrap(), b"v3\n");
    // ...and the staged state (v1 -> v2) is back in the index.
    let staged = stdout(&repo.ok(&["diff", "--staged"]));
    assert!(
        staged.contains("+v2") && staged.contains("-v1"),
        "--index should restore the staged state: {staged}"
    );
}

#[test]
fn stash_pop_index_preserves_staged_deletion() {
    // The index snapshot is the serialized index, not a tree, so a purely
    // STAGED deletion (`mkit rm`) survives `pop --index` as a staged deletion
    // (a tree round-trip would silently drop it).
    let repo = Repo::new();
    repo.commit_file("a.txt", b"a\n", "c0");
    repo.write("b.txt", b"b\n");
    repo.ok(&["add", "b.txt"]);
    repo.ok(&["commit", "-m", "add b"]);

    repo.ok(&["rm", "b.txt"]); // stage a deletion
    repo.ok(&["stash"]);
    assert!(repo.path().join("b.txt").exists(), "save reset the worktree");

    repo.ok(&["stash", "pop", "--index"]);
    assert!(!repo.path().join("b.txt").exists(), "worktree deletion restored");
    let status = stdout(&repo.ok(&["status", "--porcelain"]));
    assert!(
        status.contains("D  b.txt"),
        "the staged deletion must survive --index (not become unstaged): {status}"
    );
}

#[test]
fn stash_pop_without_index_leaves_index_unstaged() {
    // Without --index, only the worktree is restored — the staged snapshot
    // is not re-applied (mkit's existing default behavior).
    let repo = Repo::new();
    repo.commit_file("a.txt", b"v1\n", "c0");
    repo.write("a.txt", b"v2\n");
    repo.ok(&["add", "a.txt"]);
    repo.write("a.txt", b"v3\n");
    repo.ok(&["stash"]);

    repo.ok(&["stash", "pop"]);
    assert_eq!(std::fs::read(repo.path().join("a.txt")).unwrap(), b"v3\n");
    // The v1 -> v2 staging is NOT restored to the index.
    let staged = stdout(&repo.ok(&["diff", "--staged"]));
    assert!(
        !staged.contains("+v2"),
        "staged state must not be restored without --index: {staged}"
    );
}

#[test]
fn branch_list_filters_by_glob_pattern() {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"base\n", "base");
    repo.ok(&["branch", "feature/login"]);
    repo.ok(&["branch", "feature/signup"]);
    repo.ok(&["branch", "release"]);

    // `*` spans `/`, so `feature/*` matches the path-like names only.
    let feat = stdout(&repo.ok(&["branch", "--list", "feature/*"]));
    assert!(feat.contains("feature/login") && feat.contains("feature/signup"));
    assert!(!feat.contains("release"), "release leaked: {feat}");
    assert!(!feat.contains("main"), "main leaked: {feat}");

    // Exact name — the `git branch --list <name>` existence-test idiom.
    let one = stdout(&repo.ok(&["branch", "--list", "release"]));
    assert!(one.contains("release"));
    assert!(!one.contains("feature"), "pattern over-matched: {one}");

    // Bare `--list` still lists everything.
    let all = stdout(&repo.ok(&["branch", "--list"]));
    assert!(all.contains("main") && all.contains("release") && all.contains("feature/login"));

    // A pattern combines with an ancestry filter (AND). `--contains` takes a
    // required value (HEAD), leaving the glob as a positional pattern; every
    // branch contains HEAD here, so only the glob narrows the result.
    let combo = stdout(&repo.ok(&["branch", "--contains", "HEAD", "feature/log*"]));
    assert!(combo.contains("feature/login"));
    assert!(!combo.contains("feature/signup") && !combo.contains("release"));
}

#[test]
fn config_preserves_remote_subsection_case_across_reload() {
    // `remote.<name>` subsection names are case-sensitive in git; reloading
    // the config file must not lowercase them, or a named remote added with
    // a capitalized name would be lost.
    let repo = Repo::new();
    repo.commit_file("a.txt", b"x\n", "c0");
    repo.ok(&["remote", "add", "Origin", "mkit+file:///tmp/xyz"]);
    // A fresh `mkit remote` process re-parses .mkit/config.
    let listed = stdout(&repo.ok(&["remote"]));
    assert!(
        listed.contains("Origin"),
        "remote subsection name was lowercased on reload: {listed}"
    );
}

#[test]
fn config_file_keys_are_case_insensitive() {
    // A hand-edited config file with a mixed-case key must resolve like its
    // canonical lowercase form (git semantics) — not just keys set via the
    // `config` command.
    let repo = Repo::new();
    let cfg_path = repo.mkit_dir().join("config");
    let mut body = std::fs::read_to_string(&cfg_path).unwrap_or_default();
    body.push_str("\nUser.Name = Zoe\n");
    std::fs::write(&cfg_path, body).unwrap();
    assert_eq!(stdout(&repo.ok(&["config", "user.name"])).trim(), "Zoe");
}

#[test]
fn cherry_pick_n_on_conflict_is_refused_cleanly() {
    // `-n` on a conflicting pick is refused BEFORE anything is written:
    // HEAD doesn't move, no sequencer state is left, and — crucially — no
    // conflict markers are materialized (which `mkit commit` couldn't guard
    // and the user could otherwise commit).
    let repo = Repo::new();
    repo.commit_file("a.txt", b"base\n", "c0");
    repo.ok(&["branch", "feature"]);
    repo.ok(&["checkout", "feature"]);
    repo.commit_file("a.txt", b"theirs\n", "feat");
    let pick = rev(&repo, "HEAD");
    repo.ok(&["checkout", "main"]);
    repo.commit_file("a.txt", b"ours\n", "main2");
    let head_before = rev(&repo, "HEAD");

    let out = repo.run(&["cherry-pick", "-n", &pick]);
    assert!(!out.status.success(), "a conflicting -n pick must be refused");
    assert_eq!(rev(&repo, "HEAD"), head_before, "-n must not move HEAD");

    // The worktree was left untouched — no `<<<<<<<` markers to accidentally
    // `mkit add` + commit.
    let body = std::fs::read(repo.path().join("a.txt")).unwrap();
    assert_eq!(body, b"ours\n", "worktree must be untouched on a refused -n pick");
    assert!(
        !String::from_utf8_lossy(&body).contains("<<<<<<<"),
        "no conflict markers should be materialized"
    );

    // Nothing is in progress.
    let cont = repo.run(&["cherry-pick", "--continue"]);
    assert!(!cont.status.success());
    assert!(
        String::from_utf8_lossy(&cont.stderr).contains("no cherry-pick in progress"),
        "a refused -n pick must leave no resumable state: {}",
        String::from_utf8_lossy(&cont.stderr)
    );
}

#[test]
fn merge_no_commit_empty_result_can_still_commit() {
    // A merge whose result is an empty tree (both sides deleted everything)
    // must still be committable as a two-parent merge — the empty-index gate
    // is skipped while a merge is in progress.
    let repo = Repo::new();
    repo.commit_file("a.txt", b"base\n", "c0");
    repo.ok(&["branch", "feature"]);
    repo.ok(&["checkout", "feature"]);
    repo.ok(&["rm", "a.txt"]);
    repo.ok(&["commit", "-m", "feature deletes a"]);
    repo.ok(&["checkout", "main"]);
    repo.ok(&["rm", "a.txt"]);
    repo.ok(&["commit", "-m", "main deletes a"]);

    // Both sides deleted a.txt → clean merge to an empty tree.
    repo.ok(&["merge", "--no-commit", "feature"]);
    let out = repo.run(&["commit", "-m", "empty merge"]);
    assert!(
        out.status.success(),
        "empty-result merge must be committable: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(parent_count(&repo, "HEAD"), 2, "must be a two-parent merge");
}

#[test]
fn merge_no_commit_finish_uses_orig_base_as_first_parent() {
    // The finishing commit must record the merge's recorded base
    // (`ORIG_HEAD`) as parent[0] and `MERGE_HEAD` as parent[1] — matching
    // `merge --continue`, regardless of the live HEAD.
    let repo = Repo::new();
    clean_diverge(&repo); // on `main`; main added c.txt, feature added b.txt
    let main_before = rev(&repo, "HEAD");
    let feature = rev(&repo, "feature");

    repo.ok(&["merge", "--no-commit", "feature"]);
    repo.ok(&["commit", "-m", "merge feature"]);

    let body = stdout(&repo.ok(&["cat-file", "-p", "HEAD"]));
    let parents: Vec<&str> = body
        .lines()
        .filter_map(|l| l.strip_prefix("parent "))
        .collect();
    assert_eq!(parents.len(), 2, "merge commit must have two parents: {body}");
    assert_eq!(parents[0], main_before, "parent[0] must be the merge base");
    assert_eq!(parents[1], feature, "parent[1] must be MERGE_HEAD (feature)");
}

#[test]
fn branch_contains_defaults_to_head() {
    // Bare `--contains` / `--no-contains` default to HEAD, like git.
    let repo = Repo::new();
    repo.commit_file("a.txt", b"base\n", "c0");
    repo.ok(&["branch", "feature"]); // feature stays at base
    repo.commit_file("a.txt", b"more\n", "c1"); // main (HEAD) advances

    // `--contains` (no arg) == `--contains HEAD`: only main contains HEAD.
    let contains = stdout(&repo.ok(&["branch", "--contains"]));
    assert!(contains.contains("main") && !contains.contains("feature"), "{contains}");
    // `--no-contains` (no arg): branches NOT containing HEAD → feature only.
    let no_contains = stdout(&repo.ok(&["branch", "--no-contains"]));
    assert!(no_contains.contains("feature") && !no_contains.contains("main"), "{no_contains}");
}

#[test]
fn rebase_replays_a_branch_containing_a_merge_commit() {
    // Regression: core cherry-pick rejects a merge without a mainline, so a
    // rebase whose range includes a merge commit must replay it (first-parent)
    // rather than failing mid-rebase.
    let repo = Repo::new();
    repo.commit_file("a.txt", b"base\n", "c0");
    repo.ok(&["branch", "topic"]);
    repo.ok(&["checkout", "topic"]);
    repo.commit_file("t.txt", b"t\n", "A");
    // `side` branches at A, then BOTH diverge so the merge is a real 3-way
    // merge (not a fast-forward).
    repo.ok(&["branch", "side"]);
    repo.ok(&["checkout", "side"]);
    repo.commit_file("s.txt", b"s\n", "S");
    repo.ok(&["checkout", "topic"]);
    repo.commit_file("t1.txt", b"t1\n", "A2"); // topic diverges from side
    repo.ok(&["merge", "side"]); // 3-way merge → merge commit M on topic
    assert_eq!(parent_count(&repo, "HEAD"), 2, "topic tip should be a merge");
    repo.commit_file("t2.txt", b"t2\n", "B");
    // Advance main, then rebase topic onto it.
    repo.ok(&["checkout", "main"]);
    repo.commit_file("m.txt", b"m\n", "c1");
    repo.ok(&["checkout", "topic"]);

    let out = repo.run(&["rebase", "main"]);
    assert!(
        out.status.success(),
        "rebase of a branch containing a merge must succeed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // All files land: base a.txt, the new base's m.txt, topic's t.txt/t1.txt,
    // s.txt (the merge replayed via its first parent adds it), and t2.txt.
    for f in ["a.txt", "m.txt", "t.txt", "t1.txt", "s.txt", "t2.txt"] {
        assert!(repo.path().join(f).exists(), "missing {f} after rebase");
    }
}

#[test]
fn diff_merge_base_typo_second_rev_errors() {
    // A typo'd second revision must error, not silently degrade to a pathspec
    // filter that emits an empty diff.
    let repo = Repo::new();
    clean_diverge(&repo); // `feature` and `main` exist
    let out = repo.run(&["diff", "--merge-base", "feature", "mian", "--name-only"]);
    assert!(
        !out.status.success(),
        "an unresolvable 2nd revision must fail, not exit 0: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("bad revision"),
        "expected a bad-revision error: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}
