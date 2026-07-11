//! `mkit log --author`/`--grep`/`--since`/`--until`/`--no-merges`/
//! `--first-parent` (#712) — commit-history filtering against a fixture
//! with mixed authors, mixed messages, and a real merge commit.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

mod common;

use std::process::Output;

use common::Repo;

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// The `--oneline` subjects (titles), newest-first.
fn subjects(repo: &Repo, extra: &[&str]) -> Vec<String> {
    let mut args = vec!["log", "--oneline"];
    args.extend_from_slice(extra);
    stdout(&repo.ok(&args))
        .lines()
        .map(|l| {
            l.split_once(' ')
                .map_or(String::new(), |(_, t)| t.to_string())
        })
        .collect()
}

/// A base commit (Alice), a `feature` branch (Bob) that touches a
/// different file, and a clean merge of `feature` back into `main` — mixed
/// authors, mixed messages, and one real 2-parent commit for
/// `--no-merges`/`--first-parent`. History (oldest to newest):
///
/// 1. `alice: base import` (Alice, adds `a.txt`)
/// 2. `bob: widget fix` (Bob, on `feature`, adds `b.txt`)
/// 3. `alice: gadget tweak` (Alice, on `main`, adds `c.txt`)
/// 4. `merge feature into main` (default identity, 2 parents)
fn repo_with_mixed_history() -> Repo {
    let repo = Repo::new();
    repo.write("a.txt", b"base\n");
    repo.ok(&["add", "a.txt"]);
    repo.ok(&[
        "commit",
        "--author",
        "opaque:Alice",
        "-m",
        "alice: base import",
    ]);
    repo.ok(&["branch", "feature"]);
    repo.ok(&["checkout", "feature"]);
    repo.write("b.txt", b"feat\n");
    repo.ok(&["add", "b.txt"]);
    repo.ok(&["commit", "--author", "opaque:Bob", "-m", "bob: widget fix"]);
    repo.ok(&["checkout", "main"]);
    repo.write("c.txt", b"main\n");
    repo.ok(&["add", "c.txt"]);
    repo.ok(&[
        "commit",
        "--author",
        "opaque:Alice",
        "-m",
        "alice: gadget tweak",
    ]);
    repo.ok(&["merge", "-m", "merge feature into main", "feature"]);
    repo
}

#[test]
fn author_filters_by_substring_against_both_identity_forms() {
    let repo = repo_with_mixed_history();
    assert_eq!(
        subjects(&repo, &["--author", "Alice"]),
        vec!["alice: gadget tweak", "alice: base import"]
    );
    assert_eq!(
        subjects(&repo, &["--author", "Bob"]),
        vec!["bob: widget fix"]
    );
    assert!(subjects(&repo, &["--author", "Nobody"]).is_empty());
}

#[test]
fn grep_filters_by_message_substring() {
    let repo = repo_with_mixed_history();
    assert_eq!(
        subjects(&repo, &["--grep", "widget"]),
        vec!["bob: widget fix"]
    );
    assert_eq!(
        subjects(&repo, &["--grep", "gadget"]),
        vec!["alice: gadget tweak"]
    );
    assert!(subjects(&repo, &["--grep", "nonexistent"]).is_empty());
}

#[test]
fn since_and_until_bound_the_commit_timestamp() {
    let repo = repo_with_mixed_history();
    // Boundary values (far future / far past) avoid clock-skew flakiness
    // from asserting an exact "now" cutoff.
    assert!(
        subjects(&repo, &["--since", "@9999999999"]).is_empty(),
        "a since-the-far-future bound should exclude every commit"
    );
    assert!(
        subjects(&repo, &["--until", "@1"]).is_empty(),
        "an until-near-epoch bound should exclude every commit"
    );
    assert_eq!(subjects(&repo, &["--since", "@0"]).len(), 4);
    assert_eq!(subjects(&repo, &["--since", "yesterday"]).len(), 4);
}

#[test]
fn since_rejects_an_unparsable_date() {
    let repo = Repo::new();
    let out = repo.run(&["log", "--since", "not-a-date"]);
    assert!(
        !out.status.success(),
        "expected `log --since not-a-date` to fail"
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("--since"),
        "error should name the offending flag: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn no_merges_hides_the_merge_commit_but_still_walks_through_it() {
    let repo = repo_with_mixed_history();
    assert_eq!(subjects(&repo, &[]).len(), 4);

    let filtered = subjects(&repo, &["--no-merges"]);
    assert_eq!(filtered.len(), 3);
    assert!(!filtered.iter().any(|s| s == "merge feature into main"));
    // Bob's commit, reached only through the merge's second parent, is
    // still walked — `--no-merges` only hides the merge commit itself.
    assert!(filtered.iter().any(|s| s == "bob: widget fix"));
}

#[test]
fn first_parent_never_enters_the_merged_side_branch() {
    let repo = repo_with_mixed_history();
    let filtered = subjects(&repo, &["--first-parent"]);
    assert_eq!(filtered.len(), 3); // merge + alice's two commits
    assert!(filtered.iter().any(|s| s == "merge feature into main"));
    assert!(
        !filtered.iter().any(|s| s == "bob: widget fix"),
        "--first-parent must never walk into a merged side branch: {filtered:?}"
    );
}

#[test]
fn limit_applies_after_filtering_not_before() {
    let repo = repo_with_mixed_history();
    // The newest commit overall is the merge; `-n 1` with `--author Alice`
    // must still land on Alice's newest commit, not the merge (which -n
    // would pick if it capped the raw walk before filtering).
    assert_eq!(
        subjects(&repo, &["--author", "Alice", "-n", "1"]),
        vec!["alice: gadget tweak"]
    );
}
