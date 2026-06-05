//! Read-only plumbing — `rev-parse` / `cat-file` / `ls-tree` / `show-ref`
//! (#251, Phase 3). Covers the mkit-specific paths the differential
//! harness can't compare (abbreviated BLAKE3 ids, repo-root path, `-z`).

use std::fs;
use std::path::Path;
use std::process::Output;

fn mkit_bin() -> &'static str {
    env!("CARGO_BIN_EXE_mkit")
}

fn run_in(cwd: &Path, xdg: &Path, args: &[&str]) -> Output {
    std::process::Command::new(mkit_bin())
        .args(args)
        .current_dir(cwd)
        .env("XDG_CONFIG_HOME", xdg)
        .output()
        .expect("spawn mkit")
}

fn repo() -> (tempfile::TempDir, tempfile::TempDir) {
    let td = tempfile::tempdir().unwrap();
    let xdg = tempfile::tempdir().unwrap();
    let (root, x) = (td.path(), xdg.path());
    assert!(run_in(root, x, &["init"]).status.success());
    assert!(run_in(root, x, &["keygen"]).status.success());
    fs::write(root.join("file.txt"), b"hello\n").unwrap();
    fs::create_dir(root.join("sub")).unwrap();
    fs::write(root.join("sub/inner.txt"), b"nested\n").unwrap();
    assert!(run_in(root, x, &["add", "."]).status.success());
    assert!(run_in(root, x, &["commit", "-m", "init"]).status.success());
    (td, xdg)
}

fn out_str(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).trim().to_string()
}

#[test]
fn rev_parse_full_short_and_abbrev_ref() {
    let (td, xdg) = repo();
    let (root, x) = (td.path(), xdg.path());

    let full = out_str(&run_in(root, x, &["rev-parse", "HEAD"]));
    assert_eq!(full.len(), 64, "full id is 64-hex: {full:?}");
    assert!(full.chars().all(|c| c.is_ascii_hexdigit()));

    let short = out_str(&run_in(root, x, &["rev-parse", "--short", "HEAD"]));
    assert_eq!(short.len(), 7, "default --short is 7 chars: {short:?}");
    assert!(full.starts_with(&short), "short is a prefix of full");

    let short10 = out_str(&run_in(root, x, &["rev-parse", "--short=10", "HEAD"]));
    assert_eq!(short10.len(), 10);

    assert_eq!(
        out_str(&run_in(root, x, &["rev-parse", "--abbrev-ref", "HEAD"])),
        "main"
    );
}

#[test]
fn rev_parse_show_toplevel_is_repo_root() {
    let (td, xdg) = repo();
    let (root, x) = (td.path(), xdg.path());
    // Run from a subdirectory; --show-toplevel still finds the root.
    let out = run_in(&root.join("sub"), x, &["rev-parse", "--show-toplevel"]);
    assert!(out.status.success(), "show-toplevel failed: {out:?}");
    let printed = out_str(&out);
    let canon = fs::canonicalize(root).unwrap();
    assert_eq!(
        fs::canonicalize(&printed).unwrap(),
        canon,
        "show-toplevel should print the repo root"
    );
}

#[test]
fn rev_parse_bad_revision_errors() {
    let (td, xdg) = repo();
    let (root, x) = (td.path(), xdg.path());
    let out = run_in(root, x, &["rev-parse", "no-such-ref"]);
    assert!(!out.status.success(), "bad rev must error: {out:?}");
}

#[test]
fn cat_file_type_of_commit_and_tree() {
    let (td, xdg) = repo();
    let (root, x) = (td.path(), xdg.path());
    assert_eq!(
        out_str(&run_in(root, x, &["cat-file", "-t", "HEAD"])),
        "commit"
    );
    // A blob's type via its hash extracted from ls-tree.
    let ls = out_str(&run_in(root, x, &["ls-tree", "HEAD"]));
    let blob = ls
        .lines()
        .find(|l| l.ends_with("file.txt"))
        .and_then(|l| l.split_whitespace().nth(2))
        .unwrap()
        .to_string();
    assert_eq!(
        out_str(&run_in(root, x, &["cat-file", "-t", &blob])),
        "blob"
    );
    assert_eq!(out_str(&run_in(root, x, &["cat-file", "-s", &blob])), "6");
}

#[test]
fn cat_file_requires_a_flag() {
    let (td, xdg) = repo();
    let (root, x) = (td.path(), xdg.path());
    let out = run_in(root, x, &["cat-file", "HEAD"]);
    assert!(
        !out.status.success(),
        "cat-file without -t/-s/-p must error: {out:?}"
    );
}

#[test]
fn ls_tree_z_is_nul_terminated_and_recurses() {
    let (td, xdg) = repo();
    let (root, x) = (td.path(), xdg.path());
    let out = run_in(root, x, &["ls-tree", "-r", "-z", "HEAD"]);
    assert!(out.status.success(), "ls-tree -rz failed: {out:?}");
    let raw = String::from_utf8_lossy(&out.stdout);
    assert!(raw.ends_with('\0'), "records are NUL-terminated: {raw:?}");
    assert!(!raw.contains('\n'), "no newlines in -z output: {raw:?}");
    assert!(
        raw.contains("sub/inner.txt\0"),
        "recursed path present: {raw:?}"
    );
}

#[test]
fn show_ref_heads_and_tags_filter() {
    let (td, xdg) = repo();
    let (root, x) = (td.path(), xdg.path());
    assert!(run_in(root, x, &["tag", "v1"]).status.success());

    let all = out_str(&run_in(root, x, &["show-ref"]));
    assert!(all.contains("refs/heads/main"), "all: {all:?}");
    assert!(all.contains("refs/tags/v1"), "all: {all:?}");

    let heads = out_str(&run_in(root, x, &["show-ref", "--heads"]));
    assert!(
        heads.contains("refs/heads/main") && !heads.contains("refs/tags/"),
        "heads: {heads:?}"
    );

    let tags = out_str(&run_in(root, x, &["show-ref", "--tags"]));
    assert!(
        tags.contains("refs/tags/v1") && !tags.contains("refs/heads/"),
        "tags: {tags:?}"
    );
}
