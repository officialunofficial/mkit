//! Integration tests for PR-H4: `mkit reflog` (read-only, #231) and
//! `mkit commit --amend` (#232).
//!
//! These spawn the built `mkit` binary so they exercise the real CLI
//! dispatch, signing, and ref-history paths end-to-end. The
//! journal-specific assertions are gated behind `--features
//! history-mmr`; the rest run in every build.

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

fn mkit_bin() -> &'static str {
    env!("CARGO_BIN_EXE_mkit")
}

fn run(cwd: &Path, args: &[&str]) -> Output {
    let xdg = tempfile::tempdir().expect("xdg");
    let out = Command::new(mkit_bin())
        .args(args)
        .current_dir(cwd)
        .env("XDG_CONFIG_HOME", xdg.path())
        .output()
        .expect("spawn mkit");
    drop(xdg);
    out
}

fn ok(cwd: &Path, args: &[&str]) -> Output {
    let out = run(cwd, args);
    assert!(
        out.status.success(),
        "mkit {:?} failed: stdout={} stderr={}",
        args,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    out
}

fn init_repo() -> tempfile::TempDir {
    let td = tempfile::tempdir().unwrap();
    ok(td.path(), &["init"]);
    ok(td.path(), &["keygen"]);
    td
}

fn write_file(root: &Path, rel: &str, body: &str) {
    let path = root.join(rel);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, body).unwrap();
}

fn commit_file(root: &Path, rel: &str, body: &str, msg: &str) {
    write_file(root, rel, body);
    ok(root, &["add", rel]);
    ok(root, &["commit", "-m", msg]);
}

/// First JSONL record from `mkit log --format=json` (= current HEAD).
/// Returns the raw line.
fn head_log_json(root: &Path) -> String {
    let out = ok(root, &["log", "--format=json"]);
    let s = String::from_utf8(out.stdout).unwrap();
    s.lines().next().expect("at least one commit").to_owned()
}

/// Crude field extractor for the flat JSON log/reflog records — no JSON
/// dep in the test harness. Pulls the string value of `"key":"..."`.
fn json_str_field(line: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\":\"");
    let start = line.find(&needle)? + needle.len();
    let rest = &line[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_owned())
}

fn head_hash(root: &Path) -> String {
    json_str_field(&head_log_json(root), "hash").expect("hash field")
}

// ------------------------------------------------------------------
// reflog (#231)
// ------------------------------------------------------------------

#[test]
fn reflog_lists_branch_chain_newest_first() {
    let td = init_repo();
    let root = td.path();

    commit_file(root, "a.txt", "a\n", "first");
    commit_file(root, "b.txt", "b\n", "second");
    commit_file(root, "c.txt", "c\n", "third");

    let out = ok(root, &["reflog"]);
    let text = String::from_utf8(out.stdout).unwrap();
    // Entry lines (skip the optional `# journal:` summary, which only
    // appears on history-mmr builds).
    let entries: Vec<&str> = text
        .lines()
        .filter(|l| !l.starts_with('#'))
        .filter(|l| !l.is_empty())
        .collect();
    assert_eq!(
        entries.len(),
        3,
        "three commits → three reflog entries:\n{text}"
    );
    // Newest first: @{0} = third, @{2} = first.
    assert!(
        entries[0].contains("main@{0}"),
        "first line: {}",
        entries[0]
    );
    assert!(entries[0].contains("third"), "first line: {}", entries[0]);
    assert!(entries[1].contains("main@{1}"));
    assert!(entries[1].contains("second"));
    assert!(entries[2].contains("main@{2}"));
    assert!(entries[2].contains("first"));
}

#[test]
fn reflog_json_emits_one_record_per_entry() {
    let td = init_repo();
    let root = td.path();
    commit_file(root, "a.txt", "a\n", "first");
    commit_file(root, "b.txt", "b\n", "second");

    let out = ok(root, &["reflog", "--format=json"]);
    let text = String::from_utf8(out.stdout).unwrap();
    let lines: Vec<&str> = text.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(lines.len(), 2, "two entries → two JSONL records:\n{text}");
    assert!(lines[0].contains("\"selector\":\"main@{0}\""));
    assert!(lines[0].contains("\"index\":0"));
    assert!(lines[0].contains("\"title\":\"second\""));
    assert!(json_str_field(lines[0], "hash").is_some());
    // `journaled` is present on every record (bool on history-mmr
    // builds, null otherwise).
    assert!(lines[0].contains("\"journaled\":"));
}

#[test]
fn reflog_honors_n_limit() {
    let td = init_repo();
    let root = td.path();
    commit_file(root, "a.txt", "a\n", "first");
    commit_file(root, "b.txt", "b\n", "second");
    commit_file(root, "c.txt", "c\n", "third");

    let out = ok(root, &["reflog", "--format=json", "-n", "1"]);
    let text = String::from_utf8(out.stdout).unwrap();
    let lines: Vec<&str> = text.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(lines.len(), 1, "-n 1 caps at one entry:\n{text}");
    assert!(lines[0].contains("\"title\":\"third\""));
}

#[test]
fn reflog_explicit_branch_arg() {
    let td = init_repo();
    let root = td.path();
    commit_file(root, "a.txt", "a\n", "first");
    ok(root, &["branch", "side"]);
    // `side` was created at HEAD; its history shows the same one commit.
    let out = ok(root, &["reflog", "side", "--format=json"]);
    let text = String::from_utf8(out.stdout).unwrap();
    let lines: Vec<&str> = text.lines().filter(|l| !l.is_empty()).collect();
    assert!(!lines.is_empty(), "side branch must have history:\n{text}");
    assert!(lines[0].contains("\"selector\":\"side@{0}\""));
}

#[test]
fn reflog_is_read_only() {
    // Running reflog must not change HEAD or the tip.
    let td = init_repo();
    let root = td.path();
    commit_file(root, "a.txt", "a\n", "first");
    commit_file(root, "b.txt", "b\n", "second");
    let before = head_hash(root);
    ok(root, &["reflog"]);
    ok(root, &["reflog", "--format=json"]);
    ok(root, &["reflog", "main"]);
    let after = head_hash(root);
    assert_eq!(before, after, "reflog must not move HEAD");
}

#[test]
fn reflog_no_commits_yet_is_clean() {
    let td = init_repo();
    let root = td.path();
    // No commits: reflog exits 0 and prints no entry lines.
    let out = ok(root, &["reflog"]);
    let text = String::from_utf8(out.stdout).unwrap();
    let entries: Vec<&str> = text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .collect();
    assert!(entries.is_empty(), "no commits → no entries:\n{text}");
}

// ------------------------------------------------------------------
// commit --amend (#232)
// ------------------------------------------------------------------

#[test]
fn amend_replaces_head_keeping_parent() {
    let td = init_repo();
    let root = td.path();
    commit_file(root, "a.txt", "a\n", "first");
    let first = head_hash(root);
    commit_file(root, "b.txt", "b\n", "second");
    let second = head_hash(root);
    let second_line = head_log_json(root);
    let second_parents = parents_of(&second_line);
    assert_eq!(
        second_parents,
        vec![first.clone()],
        "sanity: second's parent is first"
    );

    // Amend the message of the current commit.
    ok(root, &["commit", "--amend", "-m", "second (amended)"]);
    let amended = head_hash(root);
    let amended_line = head_log_json(root);

    assert_ne!(amended, second, "amend must produce a new hash");
    assert_eq!(
        parents_of(&amended_line),
        vec![first.clone()],
        "amended commit's parent must be the ORIGINAL parent, not the superseded commit"
    );
    assert_eq!(
        json_str_field(&amended_line, "title").as_deref(),
        Some("second (amended)"),
        "amend -m must replace the message"
    );

    // Branch moved to the amended commit; superseded commit is gone from
    // the reachable log.
    let log = ok(root, &["log", "--format=json"]);
    let log_text = String::from_utf8(log.stdout).unwrap();
    assert!(
        !log_text.contains(&second),
        "superseded commit must drop out of the reachable log"
    );
    assert_eq!(
        log_text.lines().filter(|l| !l.is_empty()).count(),
        2,
        "log shows amended + first only"
    );

    // The superseded commit object still exists on disk (unreachable
    // until gc) — `mkit cat` can still read it.
    let cat = run(root, &["cat", &second]);
    assert!(
        cat.status.success(),
        "superseded commit object should still exist on disk (gc reclaims it later)"
    );
}

#[test]
fn amend_signature_verifies() {
    let td = init_repo();
    let root = td.path();
    commit_file(root, "a.txt", "a\n", "first");
    commit_file(root, "b.txt", "b\n", "second");
    ok(root, &["commit", "--amend", "-m", "amended"]);
    let amended = head_hash(root);
    // `mkit verify <hash>` must accept the re-signed amended commit.
    ok(root, &["verify", &amended]);
}

#[test]
fn amend_reuses_message_when_no_dash_m() {
    let td = init_repo();
    let root = td.path();
    commit_file(root, "a.txt", "a\n", "keep this message");
    // Stage a new change, then amend without -m: message is reused, no
    // editor launched (the test sets no $EDITOR).
    write_file(root, "a.txt", "a changed\n");
    ok(root, &["add", "a.txt"]);
    ok(root, &["commit", "--amend"]);
    let line = head_log_json(root);
    assert_eq!(
        json_str_field(&line, "title").as_deref(),
        Some("keep this message"),
        "amend without -m reuses the previous message"
    );
}

#[test]
fn amend_with_no_commit_errors() {
    let td = init_repo();
    let root = td.path();
    write_file(root, "a.txt", "a\n");
    ok(root, &["add", "a.txt"]);
    // No commit exists yet → nothing to amend.
    let out = run(root, &["commit", "--amend", "-m", "x"]);
    assert!(!out.status.success(), "amend with no HEAD commit must fail");
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("nothing to amend"),
        "expected 'nothing to amend' error, got: {stderr}"
    );
}

/// Extract the `parents` array (list of 64-hex hashes) from a flat log
/// JSON record.
fn parents_of(line: &str) -> Vec<String> {
    let start = line.find("\"parents\":[").expect("parents key") + "\"parents\":[".len();
    let rest = &line[start..];
    let end = rest.find(']').expect("parents close");
    let inner = &rest[..end];
    inner
        .split(',')
        .map(|s| s.trim_matches('"'))
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

// ------------------------------------------------------------------
// Journal cross-check (history-mmr only)
// ------------------------------------------------------------------

/// On a history-mmr build, reflog prints the recorded-advance summary
/// and marks every reachable entry `[journaled]` (verified against the
/// MMR root), and amend records its move in the journal.
#[cfg(feature = "history-mmr")]
#[test]
fn reflog_journal_cross_check_marks_entries_journaled() {
    let td = init_repo();
    let root = td.path();
    commit_file(root, "a.txt", "a\n", "first");
    commit_file(root, "b.txt", "b\n", "second");

    let out = ok(root, &["reflog"]);
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(
        text.lines().any(|l| l.starts_with("# journal:")),
        "history-mmr build must print the journal summary:\n{text}"
    );
    assert!(
        text.contains("recorded advance(s) on 'main'"),
        "summary must name the branch:\n{text}"
    );
    // Both reachable entries verify against the journaled MMR root.
    let marked = text.lines().filter(|l| l.contains("[journaled]")).count();
    assert_eq!(marked, 2, "both entries must verify as journaled:\n{text}");
}

/// The journal cross-check is rewrite-robust: after `--amend`, the
/// reachable chain ({amended, first}) both verify as journaled, even
/// though the journal now carries three leaves (first, superseded
/// second, amended) and the reachable chain length no longer matches
/// the leaf count.
#[cfg(feature = "history-mmr")]
#[test]
fn reflog_cross_check_survives_amend() {
    let td = init_repo();
    let root = td.path();
    commit_file(root, "a.txt", "a\n", "first");
    commit_file(root, "b.txt", "b\n", "second");
    ok(root, &["commit", "--amend", "-m", "second (amended)"]);

    let out = ok(root, &["reflog"]);
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(
        text.contains("3 recorded advance(s)"),
        "journal must show three advances after amend:\n{text}"
    );
    let entries: Vec<&str> = text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .collect();
    assert_eq!(
        entries.len(),
        2,
        "reachable chain is amended + first:\n{text}"
    );
    // Both reachable commits were journaled at some leaf → both marked.
    let marked = text.lines().filter(|l| l.contains("[journaled]")).count();
    assert_eq!(
        marked, 2,
        "both reachable commits must verify as journaled after amend:\n{text}"
    );
    assert!(
        !text.contains("[NOT in journal]"),
        "no reachable commit should be flagged missing:\n{text}"
    );
}

#[cfg(feature = "history-mmr")]
#[test]
fn amend_advance_is_recorded_in_journal() {
    use std::sync::Arc;

    use mkit_core::history::{CommitHistory, TokioExecutor};

    let td = init_repo();
    let root = td.path();
    commit_file(root, "a.txt", "a\n", "first");
    commit_file(root, "b.txt", "b\n", "second");
    // 2 commits → 2 recorded advances so far.
    ok(root, &["commit", "--amend", "-m", "amended"]);
    // amend moves the branch via write_ref_recording_history → 3rd
    // recorded advance.
    let mkit = root.join(mkit_core::MKIT_DIR);
    let exec = Arc::new(TokioExecutor::new().expect("tokio runtime"));
    let history = CommitHistory::open_at(exec, &mkit, "main").expect("reopen journal");
    assert_eq!(
        history.len(),
        3,
        "two commits + one amend must record three advances in the journal"
    );
}
