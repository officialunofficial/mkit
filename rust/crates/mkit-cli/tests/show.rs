//! `mkit show [<object>...]` — display objects.
//!
//! Structural / byte-exact checks (no git needed): commit header shape +
//! diff, blob contents, tree listing, tag peeling, default-to-HEAD, and the
//! unknown-object error. The diff body's byte-parity with `git show` is
//! covered by the differential harness.

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
        "mkit {:?} failed: {}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

fn stdout(out: &Output) -> String {
    String::from_utf8(out.stdout.clone()).expect("utf-8 stdout")
}

fn init_repo() -> tempfile::TempDir {
    let td = tempfile::tempdir().unwrap();
    ok(td.path(), &["init"]);
    ok(td.path(), &["keygen"]);
    td
}

/// Two commits: f.txt v1 then v2 (so HEAD has a real diff vs its parent).
fn two_commits(p: &Path) {
    fs::write(p.join("f.txt"), "line1\nline2\nline3\n").unwrap();
    ok(p, &["add", "."]);
    ok(p, &["commit", "-m", "first commit"]);
    fs::write(p.join("f.txt"), "line1\nCHANGED\nline3\nline4\n").unwrap();
    ok(p, &["add", "."]);
    ok(p, &["commit", "-m", "second commit"]);
}

fn tree_of_head(p: &Path) -> String {
    // `cat` takes a raw hash, so resolve HEAD via rev-parse first.
    let commit = stdout(&ok(p, &["rev-parse", "HEAD"])).trim().to_string();
    let body = stdout(&ok(p, &["cat", &commit]));
    body.lines()
        .find_map(|l| l.strip_prefix("tree ").map(|s| s.trim().to_string()))
        .expect("tree line in commit body")
}

/// The blob hash for `file` at HEAD, via `ls-tree`. Each line is
/// `<mode> <type> <hash>\t<name>`.
fn blob_of_head(p: &Path, file: &str) -> String {
    let body = stdout(&ok(p, &["ls-tree", "HEAD"]));
    body.lines()
        .find_map(|l| {
            let (meta, name) = l.split_once('\t')?;
            if name != file {
                return None;
            }
            meta.split_whitespace().nth(2).map(str::to_string) // <hash>
        })
        .unwrap_or_else(|| panic!("missing {file} in ls-tree: {body}"))
}

#[test]
fn show_head_renders_commit_header_and_diff() {
    let td = init_repo();
    let p = td.path();
    two_commits(p);

    let out = stdout(&ok(p, &["show", "HEAD"]));
    // git-shaped header (mkit identity/hash divergence aside).
    assert!(
        out.starts_with("commit "),
        "should start with `commit <hash>`: {out}"
    );
    assert!(out.contains("\nAuthor: "), "missing Author line: {out}");
    assert!(out.contains("\nDate:   "), "missing Date line: {out}");
    assert!(
        out.contains("\n    second commit\n"),
        "message should be indented four spaces: {out}"
    );
    // Diff body vs the first parent.
    assert!(
        out.contains("diff --git a/f.txt b/f.txt"),
        "missing diff header: {out}"
    );
    assert!(out.contains("+CHANGED"), "missing added line: {out}");
    assert!(out.contains("-line2"), "missing removed line: {out}");
}

#[test]
fn show_with_no_argument_defaults_to_head() {
    let td = init_repo();
    let p = td.path();
    two_commits(p);
    assert_eq!(
        ok(p, &["show"]).stdout,
        ok(p, &["show", "HEAD"]).stdout,
        "bare `show` should equal `show HEAD`"
    );
}

#[test]
fn show_blob_prints_raw_contents() {
    let td = init_repo();
    let p = td.path();
    two_commits(p);
    let blob = blob_of_head(p, "f.txt");
    let out = ok(p, &["show", &blob]);
    assert_eq!(
        out.stdout, b"line1\nCHANGED\nline3\nline4\n",
        "blob show should print exact contents"
    );
}

#[test]
fn show_tree_lists_entries() {
    let td = init_repo();
    let p = td.path();
    two_commits(p);
    let tree = tree_of_head(p);
    let out = stdout(&ok(p, &["show", &tree]));
    assert!(
        out.lines()
            .any(|l| l.starts_with("100644 blob ") && l.ends_with("\tf.txt")),
        "tree listing should have an ls-tree-style f.txt line: {out}"
    );
}

#[test]
fn show_root_commit_shows_all_added() {
    let td = init_repo();
    let p = td.path();
    two_commits(p);
    let out = stdout(&ok(p, &["show", "HEAD~1"]));
    assert!(out.starts_with("commit "), "root commit header: {out}");
    assert!(
        out.contains("new file mode 100644"),
        "root commit should show the file as newly added: {out}"
    );
    assert!(out.contains("+line1"), "missing added content: {out}");
    // No parent ⇒ nothing is shown as removed.
    assert!(
        !out.contains("\n-line"),
        "root commit must not show removed lines: {out}"
    );
}

#[test]
fn show_annotated_tag_then_target() {
    let td = init_repo();
    let p = td.path();
    two_commits(p);
    ok(p, &["tag", "-a", "v1.0.0", "-m", "release one"]);

    let out = stdout(&ok(p, &["show", "v1.0.0"]));
    assert!(out.starts_with("tag v1.0.0"), "tag header: {out}");
    assert!(out.contains("\nTagger: "), "missing Tagger line: {out}");
    assert!(out.contains("release one"), "missing tag message: {out}");
    // Then the peeled target commit.
    assert!(
        out.contains("\ncommit "),
        "tag show should include the peeled commit: {out}"
    );
    assert!(
        out.contains("diff --git a/f.txt b/f.txt"),
        "tag show should include the target commit's diff: {out}"
    );
}

#[test]
fn show_unknown_object_errors() {
    let td = init_repo();
    let p = td.path();
    two_commits(p);
    let out = run(p, &["show", "does-not-exist"]);
    assert!(!out.status.success(), "show of an unknown object must fail");
}
