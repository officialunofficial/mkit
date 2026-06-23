//! `--format=json` on blame / branch / remote / config.
//!
//! These tests pin the schemas as machine-readable contracts. The
//! parser is intentionally naïve: mkit's own output is deterministic
//! (we emit keys in a known order, escape control bytes, never embed
//! raw quotes in hashes / branch names), so a search-for-key approach
//! suffices and we avoid pulling `serde_json` into the dev deps.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

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

fn init_with_commit(content: &[u8]) -> tempfile::TempDir {
    let td = tempfile::tempdir().unwrap();
    assert!(run_in(td.path(), &["init"]).status.success());
    assert!(run_in(td.path(), &["keygen"]).status.success());
    fs::write(td.path().join("a.txt"), content).unwrap();
    assert!(run_in(td.path(), &["add", "a.txt"]).status.success());
    assert!(
        run_in(td.path(), &["commit", "-m", "initial"])
            .status
            .success()
    );
    td
}

fn extract_string(line: &str, prefix: &str) -> String {
    let start = line.find(prefix).expect(prefix) + prefix.len();
    let rest = &line[start..];
    let mut iter = rest.char_indices();
    let mut end = 0;
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

// -----------------------------------------------------------------------
// branch
// -----------------------------------------------------------------------

#[test]
fn branch_json_lists_current_and_other_branches() {
    let td = init_with_commit(b"hello");
    assert!(run_in(td.path(), &["branch", "feature"]).status.success());
    let out = run_in(td.path(), &["branch", "--format=json"]);
    assert!(out.status.success(), "branch failed: {out:?}");
    let stdout = String::from_utf8(out.stdout).unwrap();
    let lines: Vec<_> = stdout.lines().collect();
    assert_eq!(lines.len(), 2, "expected 2 branches, got: {stdout:?}");
    // One of the two should be current=true (main), the other false.
    let trues = lines
        .iter()
        .filter(|l| l.contains("\"current\":true"))
        .count();
    let falses = lines
        .iter()
        .filter(|l| l.contains("\"current\":false"))
        .count();
    assert_eq!(trues, 1, "expected exactly one current=true: {stdout:?}");
    assert_eq!(falses, 1, "expected exactly one current=false: {stdout:?}");
    for line in &lines {
        let hash = extract_string(line, "\"hash\":\"");
        assert_eq!(hash.len(), 64, "hash should be 64 hex: {line:?}");
    }
}

// -----------------------------------------------------------------------
// remote
// -----------------------------------------------------------------------

#[test]
fn remote_json_emits_empty_stdout_when_unset() {
    let td = init_with_commit(b"hello");
    let out = run_in(td.path(), &["remote", "--format=json"]);
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.is_empty(),
        "unconfigured remote should produce empty stdout, got: {stdout:?}"
    );
}

#[test]
fn remote_json_emits_url_and_transport_when_set() {
    let td = init_with_commit(b"hello");
    assert!(
        run_in(td.path(), &["remote", "add", "mkit+file:///tmp/example"])
            .status
            .success()
    );
    let out = run_in(td.path(), &["remote", "--format=json"]);
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.contains("\"url\":\"mkit+file:///tmp/example\""),
        "missing url: {stdout:?}"
    );
    assert!(
        stdout.contains("\"transport\":\"file\""),
        "missing transport: {stdout:?}"
    );
}

// -----------------------------------------------------------------------
// config
// -----------------------------------------------------------------------

#[test]
fn config_json_show_all_emits_flat_object_with_known_keys() {
    let td = init_with_commit(b"hello");
    let out = run_in(td.path(), &["config", "--format=json"]);
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    // Single-line flat object.
    assert_eq!(
        stdout.lines().count(),
        1,
        "config --format=json should emit one line, got: {stdout:?}"
    );
    // Spot-check a few documented keys.
    for key in [
        "user.identity",
        "default_branch",
        "remote_endpoint",
        "ssh.strict_host_key_checking",
    ] {
        let needle = format!("\"{key}\":");
        assert!(
            stdout.contains(&needle),
            "config json missing key '{key}': {stdout:?}"
        );
    }
}

#[test]
fn config_json_show_one_emits_single_key_object() {
    let td = init_with_commit(b"hello");
    let out = run_in(td.path(), &["config", "default_branch", "--format=json"]);
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.contains("\"default_branch\":\"main\""),
        "expected default_branch=main in: {stdout:?}"
    );
}

// -----------------------------------------------------------------------
// blame
// -----------------------------------------------------------------------

#[test]
fn blame_json_emits_one_record_per_line() {
    let td = init_with_commit(b"line one\nline two\nline three\n");
    let out = run_in(td.path(), &["blame", "--format=json", "a.txt"]);
    assert!(out.status.success(), "blame failed: {out:?}");
    let stdout = String::from_utf8(out.stdout).unwrap();
    let lines: Vec<_> = stdout.lines().collect();
    assert_eq!(lines.len(), 3, "expected 3 records, got: {stdout:?}");

    for (i, line) in lines.iter().enumerate() {
        let expected_lineno = format!("\"line_num\":{}", i + 1);
        assert!(
            line.contains(&expected_lineno),
            "missing line_num {} in: {line:?}",
            i + 1
        );
        let hash = extract_string(line, "\"hash\":\"");
        assert_eq!(hash.len(), 64);
        let author = extract_string(line, "\"author\":\"");
        assert!(
            author.starts_with("ed25519:") || author.starts_with("mid:"),
            "unexpected author '{author}' in: {line:?}"
        );
    }
    // Each line's text should appear in the corresponding record.
    assert!(lines[0].contains("\"text\":\"line one\""));
    assert!(lines[1].contains("\"text\":\"line two\""));
    assert!(lines[2].contains("\"text\":\"line three\""));
}
