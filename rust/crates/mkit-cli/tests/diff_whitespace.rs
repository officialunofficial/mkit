//! `mkit diff -w`/`-b`/`-U<n>` (#712) — whitespace-insensitive comparison
//! and context-line control.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

mod common;

use std::process::Output;

use common::Repo;

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Does the patch for `path` contain a hunk (`@@ …`) at all? False means
/// the file is reported as changed (still gets a `diff --git` header,
/// since the blob hash differs) but the hunk body is empty — every line
/// compared equal under the active whitespace mode.
fn has_hunk_for(diff_out: &str, path: &str) -> bool {
    let marker = format!("diff --git a/{path} b/{path}");
    let Some(start) = diff_out.find(&marker) else {
        panic!("no `diff --git` header for {path} in:\n{diff_out}");
    };
    let rest = &diff_out[start + marker.len()..];
    let end = rest.find("diff --git").unwrap_or(rest.len());
    rest[..end].contains("@@")
}

fn setup_whitespace_repo() -> Repo {
    let repo = Repo::new();
    // `nospace.txt`: the changed line goes from having a space to having
    // none — `-w` ignores this entirely, `-b` does NOT (a line with
    // whitespace where the other side has none still differs under -b).
    repo.commit_file("nospace.txt", b"head\nfoo(a, b)\ntail\n", "base");
    repo.write("nospace.txt", b"head\nfoo(a,b)\ntail\n");
    // `amount.txt`: the changed line only has a different *amount* of
    // whitespace at the same spot — both `-w` and `-b` ignore this.
    repo.commit_file("amount.txt", b"head\nfoo(a,   b)\ntail\n", "base2");
    repo.write("amount.txt", b"head\nfoo(a, b)\ntail\n");
    repo.ok(&["add", "nospace.txt", "amount.txt"]);
    repo
}

#[test]
fn default_shows_hunks_for_any_whitespace_change() {
    let repo = setup_whitespace_repo();
    let out = stdout(&repo.ok(&["diff"]));
    assert!(has_hunk_for(&out, "nospace.txt"));
    assert!(has_hunk_for(&out, "amount.txt"));
}

#[test]
fn dash_w_ignores_all_whitespace() {
    let repo = setup_whitespace_repo();
    let out = stdout(&repo.ok(&["diff", "-w"]));
    assert!(!has_hunk_for(&out, "nospace.txt"));
    assert!(!has_hunk_for(&out, "amount.txt"));
    // Long-flag spelling behaves identically.
    let out2 = stdout(&repo.ok(&["diff", "--ignore-all-space"]));
    assert!(!has_hunk_for(&out2, "nospace.txt"));
}

#[test]
fn dash_b_ignores_only_amount_changes() {
    let repo = setup_whitespace_repo();
    let out = stdout(&repo.ok(&["diff", "-b"]));
    // A line with whitespace where the other side has none still differs.
    assert!(has_hunk_for(&out, "nospace.txt"));
    // Differing amounts of (present-on-both-sides) whitespace compare equal.
    assert!(!has_hunk_for(&out, "amount.txt"));
    let out2 = stdout(&repo.ok(&["diff", "--ignore-space-change"]));
    assert!(has_hunk_for(&out2, "nospace.txt"));
    assert!(!has_hunk_for(&out2, "amount.txt"));
}

#[test]
fn dash_w_wins_when_both_given() {
    let repo = setup_whitespace_repo();
    let out = stdout(&repo.ok(&["diff", "-w", "-b"]));
    assert!(!has_hunk_for(&out, "nospace.txt"));
    assert!(!has_hunk_for(&out, "amount.txt"));
}

/// Count context lines (unprefixed by `+`/`-`, and not a `\ No newline…`
/// marker) inside `path`'s hunk body.
fn context_line_count(diff_out: &str, path: &str) -> usize {
    let marker = format!("diff --git a/{path} b/{path}");
    let start = diff_out
        .find(&marker)
        .unwrap_or_else(|| panic!("no header for {path}"));
    let rest = &diff_out[start + marker.len()..];
    let end = rest.find("diff --git").unwrap_or(rest.len());
    rest[..end]
        .lines()
        .skip_while(|l| !l.starts_with("@@"))
        .skip(1) // the @@ header itself
        .filter(|l| l.starts_with(' '))
        .count()
}

fn setup_context_repo() -> Repo {
    let repo = Repo::new();
    let lines: Vec<String> = (1..=10).map(|n| format!("l{n}")).collect();
    let mut before = lines.join("\n");
    before.push('\n');
    repo.commit_file("ctx.txt", before.as_bytes(), "base");
    let mut after_lines = lines;
    after_lines[4] = "l5-changed".to_string(); // 0-based index 4 = l5
    let mut after = after_lines.join("\n");
    after.push('\n');
    repo.write("ctx.txt", after.as_bytes());
    repo.ok(&["add", "ctx.txt"]);
    repo
}

#[test]
fn default_context_is_three_lines_each_side() {
    let repo = setup_context_repo();
    let out = stdout(&repo.ok(&["diff"]));
    // 3 lines of context before (l2,l3,l4) + 3 after (l6,l7,l8) = 6,
    // bounded by the file having enough lines on both sides.
    assert_eq!(context_line_count(&out, "ctx.txt"), 6);
}

#[test]
fn dash_u_one_shows_one_line_of_context_each_side() {
    let repo = setup_context_repo();
    let out = stdout(&repo.ok(&["diff", "-U1"]));
    assert_eq!(context_line_count(&out, "ctx.txt"), 2);
    let out2 = stdout(&repo.ok(&["diff", "--unified=1"]));
    assert_eq!(context_line_count(&out2, "ctx.txt"), 2);
}

#[test]
fn dash_u_zero_shows_no_context() {
    let repo = setup_context_repo();
    let out = stdout(&repo.ok(&["diff", "-U0"]));
    assert_eq!(context_line_count(&out, "ctx.txt"), 0);
    // The changed line itself is still there (removed + added).
    assert!(out.contains("-l5\n"));
    assert!(out.contains("+l5-changed\n"));
}
