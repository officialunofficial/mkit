//! `mkit add -p` — interactive hunk staging.
//!
//! Drives the command with piped stdin (the hunk answers) and verifies the
//! staged result by committing and reading back the committed blob, or by
//! inspecting `diff --cached`. The hunk-selection + patch-apply algorithm
//! itself is unit-tested in `mkit-core` (`enumerate_hunks` /
//! `apply_hunks_subset`); these tests pin the CLI wiring: base selection,
//! per-hunk prompting, partial-blob staging, and the refusals.

use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

fn mkit_bin() -> &'static str {
    env!("CARGO_BIN_EXE_mkit")
}

/// Run `mkit` with `stdin` piped in and an isolated XDG home.
fn run_stdin(cwd: &Path, args: &[&str], stdin: &[u8]) -> Output {
    let xdg = tempfile::tempdir().expect("xdg");
    let mut child = Command::new(mkit_bin())
        .args(args)
        .current_dir(cwd)
        .env("XDG_CONFIG_HOME", xdg.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn mkit");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(stdin)
        .expect("write stdin");
    let out = child.wait_with_output().expect("output");
    drop(xdg);
    out
}

fn run(cwd: &Path, args: &[&str]) -> Output {
    run_stdin(cwd, args, b"")
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

fn init_repo() -> tempfile::TempDir {
    let td = tempfile::tempdir().unwrap();
    ok(td.path(), &["init"]);
    ok(td.path(), &["keygen"]);
    td
}

/// 14 lines so edits at line 2 and line 13 form two distinct hunks.
const V1: &str = "l1\nl2\nl3\nl4\nl5\nl6\nl7\nl8\nl9\nl10\nl11\nl12\nl13\nl14\n";
const V2: &str = "l1\nL2\nl3\nl4\nl5\nl6\nl7\nl8\nl9\nl10\nl11\nl12\nL13\nl14\n";

fn head_commit(cwd: &Path) -> String {
    fs::read_to_string(cwd.join(".mkit/refs/heads/main"))
        .unwrap()
        .trim()
        .to_string()
}

fn tree_of_commit(cwd: &Path, commit: &str) -> String {
    let body = String::from_utf8(ok(cwd, &["cat", commit]).stdout).unwrap();
    for line in body.lines() {
        if let Some(rest) = line.strip_prefix("tree ") {
            return rest.trim().to_string();
        }
    }
    panic!("no tree line: {body}");
}

/// Content of the committed blob for `file` at HEAD.
fn head_blob_body(cwd: &Path, file: &str) -> String {
    let commit = head_commit(cwd);
    let tree = tree_of_commit(cwd, &commit);
    let body = String::from_utf8(ok(cwd, &["cat", &tree]).stdout).unwrap();
    let hash = body
        .lines()
        .find_map(|line| {
            let mut p = line.split_whitespace();
            let _mode = p.next()?;
            let hash = p.next()?;
            let name = p.next()?;
            (name == file).then_some(hash.to_string())
        })
        .unwrap_or_else(|| panic!("missing {file}: {body}"));
    String::from_utf8(ok(cwd, &["cat", &hash]).stdout).unwrap()
}

fn commit_v1(p: &Path) {
    fs::write(p.join("f.txt"), V1).unwrap();
    ok(p, &["add", "."]);
    ok(p, &["commit", "-m", "v1"]);
    fs::write(p.join("f.txt"), V2).unwrap();
}

#[test]
fn stage_first_hunk_only() {
    let td = init_repo();
    let p = td.path();
    commit_v1(p);

    // y = stage hunk 1 (line 2 -> L2); n = skip hunk 2 (line 13 stays l13).
    let out = run_stdin(p, &["add", "-p", "f.txt"], b"y\nn\n");
    assert!(
        out.status.success(),
        "add -p failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    ok(p, &["commit", "-m", "partial"]);

    let committed = head_blob_body(p, "f.txt");
    assert_eq!(
        committed, "l1\nL2\nl3\nl4\nl5\nl6\nl7\nl8\nl9\nl10\nl11\nl12\nl13\nl14\n",
        "only the first hunk should be staged+committed"
    );
}

#[test]
fn stage_second_hunk_only() {
    let td = init_repo();
    let p = td.path();
    commit_v1(p);

    // n = skip hunk 1; y = stage hunk 2 (line 13 -> L13).
    let out = run_stdin(p, &["add", "-p", "f.txt"], b"n\ny\n");
    assert!(out.status.success());
    ok(p, &["commit", "-m", "partial"]);

    assert_eq!(
        head_blob_body(p, "f.txt"),
        "l1\nl2\nl3\nl4\nl5\nl6\nl7\nl8\nl9\nl10\nl11\nl12\nL13\nl14\n",
        "only the second hunk should be staged"
    );
}

#[test]
fn answer_a_stages_all_remaining_hunks() {
    let td = init_repo();
    let p = td.path();
    commit_v1(p);

    // `a` on the first hunk stages it and all later hunks.
    let out = run_stdin(p, &["add", "-p", "f.txt"], b"a\n");
    assert!(out.status.success());
    ok(p, &["commit", "-m", "all"]);

    assert_eq!(
        head_blob_body(p, "f.txt"),
        V2,
        "`a` should stage everything"
    );
}

#[test]
fn answer_d_stages_nothing() {
    let td = init_repo();
    let p = td.path();
    commit_v1(p);

    // `d` on the first hunk skips it and all later hunks → nothing staged.
    let out = run_stdin(p, &["add", "-p", "f.txt"], b"d\n");
    assert!(out.status.success());

    // diff --cached (index vs HEAD) must be empty: nothing was staged.
    let cached = ok(p, &["diff", "--cached"]);
    assert!(
        cached.stdout.is_empty(),
        "nothing should be staged after `d`: {}",
        String::from_utf8_lossy(&cached.stdout)
    );
}

#[test]
fn quit_stages_already_selected_hunks() {
    let td = init_repo();
    let p = td.path();
    commit_v1(p);

    // y = stage hunk 1; q = quit before answering hunk 2.
    let out = run_stdin(p, &["add", "-p", "f.txt"], b"y\nq\n");
    assert!(out.status.success());
    ok(p, &["commit", "-m", "partial-quit"]);

    assert_eq!(
        head_blob_body(p, "f.txt"),
        "l1\nL2\nl3\nl4\nl5\nl6\nl7\nl8\nl9\nl10\nl11\nl12\nl13\nl14\n",
        "quit should keep the hunk staged before it"
    );
}

#[test]
fn new_file_can_be_partially_staged() {
    let td = init_repo();
    let p = td.path();
    // Need a HEAD so commit works; seed with an unrelated file.
    fs::write(p.join("seed.txt"), b"seed\n").unwrap();
    ok(p, &["add", "."]);
    ok(p, &["commit", "-m", "seed"]);

    // A brand-new untracked file: base is empty, so the whole content is one
    // added hunk. Stage it with `y`.
    fs::write(p.join("new.txt"), "alpha\nbeta\n").unwrap();
    let out = run_stdin(p, &["add", "-p", "new.txt"], b"y\n");
    assert!(
        out.status.success(),
        "add -p new file failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    ok(p, &["commit", "-m", "add new"]);
    assert_eq!(head_blob_body(p, "new.txt"), "alpha\nbeta\n");
}

#[test]
fn binary_file_is_skipped_not_errored() {
    let td = init_repo();
    let p = td.path();
    fs::write(p.join("seed.txt"), b"seed\n").unwrap();
    ok(p, &["add", "."]);
    ok(p, &["commit", "-m", "seed"]);

    // A file with a NUL byte is binary by git's heuristic.
    fs::write(p.join("bin.dat"), b"abc\0def\n").unwrap();
    let out = run_stdin(p, &["add", "-p", "bin.dat"], b"y\n");
    assert!(
        out.status.success(),
        "binary -p should exit 0 (skip), not error"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("binary"),
        "expected a binary-skip message, got: {stderr}"
    );
    // Nothing staged.
    let cached = ok(p, &["diff", "--cached"]);
    assert!(cached.stdout.is_empty(), "binary file must not be staged");
}

#[test]
fn patch_requires_paths() {
    let td = init_repo();
    let p = td.path();
    let out = run(p, &["add", "-p"]);
    assert!(!out.status.success(), "-p with no paths must fail");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("requires"),
        "expected a 'requires paths' message"
    );
}

#[test]
fn patch_conflicts_with_all() {
    let td = init_repo();
    let p = td.path();
    let out = run(p, &["add", "-p", "-A"]);
    assert!(!out.status.success(), "-p with -A must fail");
}

#[test]
fn patch_refuses_ignored_path_without_force() {
    let td = init_repo();
    let p = td.path();
    fs::write(p.join(".mkitignore"), b"secret.txt\n").unwrap();
    fs::write(p.join("secret.txt"), "topsecret\n").unwrap();

    // Without -f, an ignored untracked path must be refused (matching `add`).
    let out = run_stdin(p, &["add", "-p", "secret.txt"], b"y\n");
    assert!(
        !out.status.success(),
        "add -p of an ignored path must be refused without -f"
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("ignored"),
        "expected an 'ignored' refusal message"
    );
}

#[test]
fn patch_stages_ignored_path_with_force() {
    let td = init_repo();
    let p = td.path();
    fs::write(p.join("seed.txt"), b"seed\n").unwrap();
    ok(p, &["add", "."]);
    ok(p, &["commit", "-m", "seed"]);

    fs::write(p.join(".mkitignore"), b"secret.txt\n").unwrap();
    fs::write(p.join("secret.txt"), "topsecret\n").unwrap();

    // With -f, the ignored path can be patched in.
    let out = run_stdin(p, &["add", "-p", "-f", "secret.txt"], b"y\n");
    assert!(
        out.status.success(),
        "add -p -f of an ignored path should succeed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    ok(p, &["commit", "-m", "force ignored"]);
    assert_eq!(head_blob_body(p, "secret.txt"), "topsecret\n");
}

#[cfg(unix)]
#[test]
fn patch_refuses_path_escaping_through_symlinked_parent() {
    use std::os::unix::fs::symlink;
    let td = init_repo();
    let p = td.path();
    // A repo symlink pointing at an external directory.
    let external = tempfile::tempdir().unwrap();
    fs::write(external.path().join("file.txt"), "external secret\n").unwrap();
    symlink(external.path(), p.join("link_out")).unwrap();

    // `link_out/file.txt` is lexically in-repo but resolves outside; refuse.
    let out = run_stdin(p, &["add", "-p", "link_out/file.txt"], b"y\n");
    assert!(
        !out.status.success(),
        "add -p must refuse a path escaping via a symlinked parent"
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("outside repository"),
        "expected an 'outside repository' refusal, got: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[cfg(unix)]
#[test]
fn plain_add_refuses_path_escaping_through_symlinked_parent() {
    use std::os::unix::fs::symlink;
    let td = init_repo();
    let p = td.path();
    let external = tempfile::tempdir().unwrap();
    fs::write(external.path().join("file.txt"), "external secret\n").unwrap();
    symlink(external.path(), p.join("link_out")).unwrap();

    // The same guard applies to plain `add` of an explicit escaping path.
    let out = run(p, &["add", "link_out/file.txt"]);
    assert!(
        !out.status.success(),
        "add must refuse a path escaping via a symlinked parent"
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("outside repository"),
        "expected an 'outside repository' refusal, got: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[cfg(unix)]
#[test]
fn patch_refuses_symlink() {
    use std::os::unix::fs::symlink;
    let td = init_repo();
    let p = td.path();
    fs::write(p.join("target.txt"), b"data\n").unwrap();
    symlink("target.txt", p.join("link")).unwrap();
    let out = run_stdin(p, &["add", "-p", "link"], b"y\n");
    assert!(!out.status.success(), "-p on a symlink must be refused");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("regular files only"),
        "expected a regular-files-only message"
    );
}
