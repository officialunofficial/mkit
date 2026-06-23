//! `mkit commit` without `-m` must spawn `$EDITOR` on a tempfile and
//! use the resulting message. We use a shell-script-style editor that
//! overwrites the file with a canned message.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::fs;
use std::process::Command;

fn mkit_bin() -> &'static str {
    env!("CARGO_BIN_EXE_mkit")
}

/// Write a POSIX shell script that, when invoked with one argument
/// (the tempfile path), writes `payload` to that path. Marks the
/// script executable and returns its path. The [`tempfile::TempDir`]
/// the script lives in is returned so the caller keeps it alive.
fn write_editor_script(payload: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("fake-editor.sh");
    let script = format!("#!/bin/sh\nprintf '%s' \"{payload}\" > \"$1\"\n");
    fs::write(&path, script).unwrap();
    let mut perms = fs::metadata(&path).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&path, perms).unwrap();
    (dir, path)
}

#[test]
fn commit_without_message_honours_editor_env_var() {
    if cfg!(windows) {
        return;
    }

    let td = tempfile::tempdir().unwrap();
    let xdg = tempfile::tempdir().unwrap();
    Command::new(mkit_bin())
        .args(["init"])
        .current_dir(td.path())
        .env("XDG_CONFIG_HOME", xdg.path())
        .status()
        .unwrap();
    // we removed auto-keygen on `mkit commit`.
    Command::new(mkit_bin())
        .args(["keygen"])
        .current_dir(td.path())
        .env("XDG_CONFIG_HOME", xdg.path())
        .status()
        .unwrap();
    fs::write(td.path().join("hello.txt"), b"hi\n").unwrap();
    Command::new(mkit_bin())
        .args(["add", "."])
        .current_dir(td.path())
        .env("XDG_CONFIG_HOME", xdg.path())
        .status()
        .unwrap();

    let (_script_dir, script) = write_editor_script("commit-from-editor");
    let out = Command::new(mkit_bin())
        .args(["commit"])
        .current_dir(td.path())
        .env("XDG_CONFIG_HOME", xdg.path())
        .env("EDITOR", script.as_os_str())
        .env_remove("GIT_EDITOR")
        .env_remove("VISUAL")
        .output()
        .expect("spawn mkit commit");
    assert!(
        out.status.success(),
        "commit failed: stdout={}, stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    // Confirmation line `committed <hash> (<title>)` lives on stderr.
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("commit-from-editor"),
        "commit message from $EDITOR not reflected in output, got: {stderr}"
    );
}

#[test]
fn commit_without_message_and_empty_editor_output_aborts() {
    if cfg!(windows) {
        return;
    }

    let td = tempfile::tempdir().unwrap();
    let xdg = tempfile::tempdir().unwrap();
    Command::new(mkit_bin())
        .args(["init"])
        .current_dir(td.path())
        .env("XDG_CONFIG_HOME", xdg.path())
        .status()
        .unwrap();
    Command::new(mkit_bin())
        .args(["keygen"])
        .current_dir(td.path())
        .env("XDG_CONFIG_HOME", xdg.path())
        .status()
        .unwrap();
    fs::write(td.path().join("f.txt"), b"x").unwrap();
    Command::new(mkit_bin())
        .args(["add", "."])
        .current_dir(td.path())
        .env("XDG_CONFIG_HOME", xdg.path())
        .status()
        .unwrap();

    // Editor that truncates the tempfile to empty (`: > "$1"`).
    let (_script_dir, script) = write_editor_script("");
    let out = Command::new(mkit_bin())
        .args(["commit"])
        .current_dir(td.path())
        .env("XDG_CONFIG_HOME", xdg.path())
        .env("EDITOR", script.as_os_str())
        .env_remove("GIT_EDITOR")
        .env_remove("VISUAL")
        .output()
        .expect("spawn mkit commit");
    assert!(
        !out.status.success(),
        "empty message must abort, but exit code was zero"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("empty") || stderr.contains("abort"),
        "expected an 'empty' / 'abort' diagnostic, got: {stderr}"
    );
}
