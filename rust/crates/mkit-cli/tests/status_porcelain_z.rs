//! #249: `mkit status -z` emits NUL-terminated, raw (unquoted)
//! records, and default porcelain C-style-quotes special-byte paths.

#![cfg(unix)]
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::fs;
use std::path::Path;
use std::process::Command;

fn mkit_bin() -> &'static str {
    env!("CARGO_BIN_EXE_mkit")
}

fn run_in(cwd: &Path, args: &[&str]) -> std::process::Output {
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

fn init_repo() -> tempfile::TempDir {
    let td = tempfile::tempdir().unwrap();
    assert!(run_in(td.path(), &["init"]).status.success());
    assert!(run_in(td.path(), &["keygen"]).status.success());
    td
}

#[test]
fn dash_z_is_nul_terminated_and_unquoted() {
    let td = init_repo();
    let root = td.path();
    // A path with a tab — git/mkit quote it in default porcelain, but
    // `-z` must emit it raw.
    let name = "a\tb.txt";
    fs::write(root.join(name), b"x\n").unwrap();

    let out = run_in(root, &["status", "-z"]);
    assert!(out.status.success(), "status -z: {out:?}");
    // Raw path, no quoting, NUL-terminated, no trailing newline.
    assert_eq!(out.stdout, format!("?? {name}\0").into_bytes());
}

#[test]
fn default_porcelain_c_quotes_special_paths() {
    let td = init_repo();
    let root = td.path();
    fs::write(root.join("a\tb.txt"), b"x\n").unwrap();

    let out = run_in(root, &["status", "--porcelain"]);
    assert!(out.status.success(), "status --porcelain: {out:?}");
    assert_eq!(
        String::from_utf8(out.stdout).unwrap(),
        "?? \"a\\tb.txt\"\n",
        "special-byte paths must be C-style quoted in default porcelain"
    );
}

#[test]
fn plain_paths_are_not_quoted() {
    let td = init_repo();
    let root = td.path();
    // A space is "plain" for git porcelain — must NOT be quoted.
    fs::write(root.join("with space.txt"), b"x\n").unwrap();
    let out = run_in(root, &["status", "--porcelain"]);
    assert_eq!(
        String::from_utf8(out.stdout).unwrap(),
        "?? with space.txt\n",
        "spaces are not special; path stays unquoted"
    );
}
