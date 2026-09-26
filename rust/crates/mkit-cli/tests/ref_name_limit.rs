//! SPEC-REFS §3's 512-byte ref-name bound, end to end through the real
//! binary. A new branch name must leave `refs/heads/<b>` and
//! `refs/mkit/packmap/<b>` within it (494 bytes), and a new tag
//! `refs/tags/<t>` (502 bytes); longer ones are refused with a message
//! naming the limit. A branch over the bound that predates it keeps the
//! repository usable: it is listed, `mkit branch -m`/`-D` get rid of it,
//! and a push of it names the limit.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Output;

fn run_in(cwd: &Path, xdg: &Path, args: &[&str]) -> Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_mkit"))
        .args(args)
        .current_dir(cwd)
        .env("XDG_CONFIG_HOME", xdg)
        .output()
        .expect("spawn mkit")
}

/// A repo with a key and one commit on the default branch.
fn repo() -> (tempfile::TempDir, tempfile::TempDir) {
    let td = tempfile::tempdir().unwrap();
    let xdg = tempfile::tempdir().unwrap();
    let x = xdg.path();
    assert!(run_in(td.path(), x, &["init"]).status.success());
    assert!(run_in(td.path(), x, &["keygen"]).status.success());
    fs::write(td.path().join("a.txt"), b"hello\n").unwrap();
    assert!(run_in(td.path(), x, &["add", "."]).status.success());
    assert!(
        run_in(td.path(), x, &["commit", "-m", "initial"])
            .status
            .success()
    );
    (td, xdg)
}

/// A name of `len` bytes, in 100-byte segments of `c`.
fn long_name(len: usize, c: char) -> String {
    let mut name = String::new();
    while name.len() < len {
        if !name.is_empty() {
            name.push('/');
        }
        let seg = (len - name.len()).min(100);
        name.push_str(&c.to_string().repeat(seg));
    }
    name
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn branches(root: &Path, x: &Path) -> String {
    String::from_utf8_lossy(&run_in(root, x, &["branch"]).stdout).into_owned()
}

/// Plant a branch file the way a pre-bound mkit wrote it.
fn plant_branch(root: &Path, name: &str) -> PathBuf {
    let heads = root.join(".mkit/refs/heads");
    let main = fs::read_dir(&heads)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.is_file())
        .unwrap();
    let tip = fs::read(&main).unwrap();
    let path = name.split('/').fold(heads, |p, s| p.join(s));
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, &tip).unwrap();
    path
}

#[test]
fn new_branch_over_494_or_tag_over_502_bytes_is_refused_naming_the_limit() {
    let (td, xdg) = repo();
    let (root, x) = (td.path(), xdg.path());
    let branch = long_name(495, 'b');
    for args in [vec!["branch", &branch], vec!["switch", "-c", &branch]] {
        let out = run_in(root, x, &args);
        assert!(!out.status.success(), "{:?} must fail", args[0]);
        let err = stderr(&out);
        assert!(
            err.contains("branch name too long (495 bytes; at most 494")
                && err.contains("refs/mkit/packmap/<name>"),
            "{:?}: the message names the limit and why: {err}",
            args[0]
        );
    }
    let tag = long_name(503, 't');
    let out = run_in(root, x, &["tag", &tag]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("tag name too long (503 bytes; at most 502"),
        "{}",
        stderr(&out)
    );
    // At the bounds exactly, both are created.
    let out = run_in(root, x, &["tag", &long_name(502, 't')]);
    assert!(out.status.success(), "{}", stderr(&out));
    let out = run_in(root, x, &["branch", &long_name(494, 'b')]);
    assert!(out.status.success(), "{}", stderr(&out));
}

#[test]
fn branch_of_494_bytes_pushes_over_mkit_file() {
    let (td, xdg) = repo();
    let (root, x) = (td.path(), xdg.path());
    let branch = long_name(494, 'p');
    assert!(run_in(root, x, &["branch", &branch]).status.success());
    let bare = tempfile::tempdir().unwrap();
    let url = format!("mkit+file://{}", bare.path().display());
    assert!(
        run_in(root, x, &["remote", "add", "origin", &url])
            .status
            .success()
    );
    let out = run_in(root, x, &["push", "origin", "--all"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let pushed = format!("refs/heads/{branch}")
        .split('/')
        .fold(bare.path().to_path_buf(), |p, s| p.join(s));
    assert!(pushed.is_file(), "the remote holds refs/heads/<494 bytes>");
}

#[test]
fn existing_branch_over_the_bound_is_usable_but_not_pushable() {
    let (td, xdg) = repo();
    let (root, x) = (td.path(), xdg.path());
    // 500 bytes: fits 512 locally, but refs/mkit/packmap/<b> is 518.
    let old = long_name(500, 'o');
    plant_branch(root, &old);
    assert!(branches(root, x).contains(&old));
    let log = run_in(root, x, &["log", "--oneline", &old]);
    assert!(log.status.success(), "it still resolves: {}", stderr(&log));
    let bare = tempfile::tempdir().unwrap();
    let url = format!("mkit+file://{}", bare.path().display());
    assert!(
        run_in(root, x, &["remote", "add", "origin", &url])
            .status
            .success()
    );
    let out = run_in(root, x, &["push", "origin", "--all"]);
    assert!(!out.status.success(), "a push of it fails");
    assert!(
        stderr(&out).contains("ref name too long (518 bytes; at most 512"),
        "the push error names the limit: {}",
        stderr(&out)
    );

    // Rename it to a legal name...
    let out = run_in(root, x, &["branch", "-m", &old, "rescued"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let listed = branches(root, x);
    assert!(
        listed.contains("rescued") && !listed.contains(&old),
        "{listed}"
    );

    // ...or delete it; even one over 512 bytes.
    let over = long_name(600, 'z');
    plant_branch(root, &over);
    assert!(branches(root, x).contains(&over));
    let out = run_in(root, x, &["branch", "-D", &over]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(!branches(root, x).contains(&over));
}
