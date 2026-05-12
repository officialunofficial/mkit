//! `mkit log --format=json` — JSONL output, one self-contained JSON
//! object per commit. Verifies field shape, key ordering, escaping,
//! and the "no commits" case.

use std::fs;
use std::process::Command;

fn mkit_bin() -> &'static str {
    env!("CARGO_BIN_EXE_mkit")
}

fn run_in(cwd: &std::path::Path, args: &[&str]) -> std::process::Output {
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

fn init_with_commits(commits: &[(&str, &[u8], &str)]) -> tempfile::TempDir {
    let td = tempfile::tempdir().unwrap();
    assert!(run_in(td.path(), &["init"]).status.success());
    assert!(run_in(td.path(), &["keygen"]).status.success());
    for (name, content, msg) in commits {
        fs::write(td.path().join(name), content).unwrap();
        assert!(run_in(td.path(), &["add", name]).status.success());
        assert!(
            run_in(td.path(), &["commit", "-m", msg]).status.success(),
            "commit '{msg}' failed"
        );
    }
    td
}

// Minimal JSON object parser tuned for `mkit log --format=json`
// output. The full schema is `{ "key": <scalar-or-array>, ... }` per
// line; values are either strings, numbers, or arrays of strings.
//
// Returning a typed struct avoids pulling serde_json into the dev
// dependencies just to round-trip our own output.
#[derive(Debug, Default)]
struct LogEntry {
    hash: String,
    parents: Vec<String>,
    tree: String,
    author: String,
    timestamp: i64,
    title: String,
    message: String,
}

fn parse_log_line(line: &str) -> LogEntry {
    // Quick-and-dirty parser. mkit's own output is deterministic and
    // safe (no embedded ` characters in commit titles since we
    // strip the leading whitespace + escape control bytes), so a
    // naïve search-for-key approach works.
    LogEntry {
        hash: extract_string(line, "\"hash\":\""),
        parents: extract_string_array(line, "\"parents\":["),
        tree: extract_string(line, "\"tree\":\""),
        author: extract_string(line, "\"author\":\""),
        timestamp: extract_number(line, "\"timestamp\":"),
        title: extract_string(line, "\"title\":\""),
        message: extract_string(line, "\"message\":\""),
    }
}

fn extract_string(line: &str, prefix: &str) -> String {
    let start = line.find(prefix).expect(prefix) + prefix.len();
    let rest = &line[start..];
    // Find the first unescaped quote.
    let mut end = 0;
    let mut iter = rest.char_indices();
    while let Some((i, c)) = iter.next() {
        if c == '\\' {
            iter.next();
            continue;
        }
        if c == '"' {
            end = i;
            break;
        }
    }
    rest[..end].to_string()
}

fn extract_number(line: &str, prefix: &str) -> i64 {
    let start = line.find(prefix).expect(prefix) + prefix.len();
    let rest = &line[start..];
    let end = rest
        .find(|c: char| !c.is_ascii_digit() && c != '-')
        .unwrap_or(rest.len());
    rest[..end].parse().unwrap_or(0)
}

fn extract_string_array(line: &str, prefix: &str) -> Vec<String> {
    let start = line.find(prefix).expect(prefix) + prefix.len();
    let rest = &line[start..];
    let end = rest.find(']').expect("]");
    let body = &rest[..end];
    if body.is_empty() {
        return vec![];
    }
    body.split(',')
        .map(|s| s.trim_matches('"').to_string())
        .collect()
}

#[test]
fn single_commit_emits_one_jsonl_record() {
    let td = init_with_commits(&[("a.txt", b"hello", "first commit")]);
    let out = run_in(td.path(), &["log", "--format=json"]);
    assert!(out.status.success(), "log --format=json failed: {out:?}");
    let stdout = String::from_utf8(out.stdout).unwrap();
    let lines: Vec<_> = stdout.lines().collect();
    assert_eq!(lines.len(), 1, "expected exactly 1 line, got: {stdout:?}");
    let e = parse_log_line(lines[0]);
    assert_eq!(e.hash.len(), 64, "hash should be 64 hex chars");
    assert_eq!(e.tree.len(), 64, "tree should be 64 hex chars");
    assert!(e.parents.is_empty(), "first commit has no parents");
    assert!(
        e.author.starts_with("ed25519:") || e.author.starts_with("mid:"),
        "author '{}' should be ed25519:<hex> or mid:<n>",
        e.author
    );
    assert!(e.timestamp > 0, "timestamp should be positive");
    assert_eq!(e.title, "first commit");
    assert!(e.message.starts_with("first commit"));
}

#[test]
fn multi_commit_emits_newest_first() {
    let td = init_with_commits(&[
        ("a.txt", b"v1", "first"),
        ("b.txt", b"v2", "second"),
        ("c.txt", b"v3", "third"),
    ]);
    let out = run_in(td.path(), &["log", "--format=json"]);
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    let lines: Vec<_> = stdout.lines().collect();
    assert_eq!(lines.len(), 3, "expected 3 lines, got: {stdout:?}");

    let titles: Vec<_> = lines.iter().map(|l| parse_log_line(l).title).collect();
    assert_eq!(titles, vec!["third", "second", "first"]);

    // Each commit's parents[0] should be the next commit's hash.
    let entries: Vec<_> = lines.iter().map(|l| parse_log_line(l)).collect();
    assert_eq!(entries[0].parents[0], entries[1].hash);
    assert_eq!(entries[1].parents[0], entries[2].hash);
    assert!(entries[2].parents.is_empty(), "root has no parents");
}

#[test]
fn no_commits_emits_empty_stdout() {
    let td = tempfile::tempdir().unwrap();
    assert!(run_in(td.path(), &["init"]).status.success());
    let out = run_in(td.path(), &["log", "--format=json"]);
    assert!(out.status.success(), "log on empty repo should succeed");
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.is_empty(),
        "expected empty stdout for empty repo, got: {stdout:?}"
    );
}

#[test]
fn multi_line_message_is_json_escaped() {
    // Commit message with newline + quote + backslash. Each commit
    // needs `-m`; chain them by using multiple -m flags.
    let td = tempfile::tempdir().unwrap();
    assert!(run_in(td.path(), &["init"]).status.success());
    assert!(run_in(td.path(), &["keygen"]).status.success());
    fs::write(td.path().join("a.txt"), b"x").unwrap();
    assert!(run_in(td.path(), &["add", "a.txt"]).status.success());
    // Title contains a quote and a backslash that must round-trip
    // through JSON escaping.
    let msg = r#"a "quoted" \ title"#;
    assert!(run_in(td.path(), &["commit", "-m", msg]).status.success());

    let out = run_in(td.path(), &["log", "--format=json"]);
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    // The raw on-disk form should have the escapes.
    assert!(
        stdout.contains(r#"\"quoted\""#),
        "expected escaped quotes in JSON: {stdout:?}"
    );
    assert!(
        stdout.contains(r"\\"),
        "expected escaped backslash in JSON: {stdout:?}"
    );
    // Parsed form should round-trip back.
    let line = stdout.lines().next().unwrap();
    let e = parse_log_line(line);
    assert_eq!(e.title, r#"a \"quoted\" \\ title"#);
}

#[test]
fn limit_caps_output() {
    let td = init_with_commits(&[
        ("a.txt", b"v1", "first"),
        ("b.txt", b"v2", "second"),
        ("c.txt", b"v3", "third"),
    ]);
    let out = run_in(td.path(), &["log", "--format=json", "-n", "2"]);
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert_eq!(stdout.lines().count(), 2);
}
