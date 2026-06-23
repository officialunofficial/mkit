//! CLI-surface coverage for the `durability.objects` escape hatch
//! (SPEC-OBJECTS §10.1). The key is honored by the object-store sync
//! policy, so it must also be settable and showable through `mkit
//! config` — regression for the review finding that
//! `mkit config durability.objects per-object` exited 78 with
//! "unknown config key".
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

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

fn fresh_repo() -> tempfile::TempDir {
    let td = tempfile::tempdir().unwrap();
    let out = run_in(td.path(), &["init"]);
    assert!(
        out.status.success(),
        "mkit init failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    td
}

#[test]
fn durability_objects_set_and_show() {
    let td = fresh_repo();

    // Set the strict per-object schedule.
    let set = run_in(td.path(), &["config", "durability.objects", "per-object"]);
    assert!(
        set.status.success(),
        "set should succeed; stderr=\n{}",
        String::from_utf8_lossy(&set.stderr)
    );

    // Show it back.
    let show = run_in(td.path(), &["config", "durability.objects"]);
    assert!(show.status.success(), "show should succeed");
    let value = String::from_utf8(show.stdout).unwrap();
    assert_eq!(value.trim(), "per-object");
}

#[test]
fn durability_objects_rejects_bogus_value() {
    let td = fresh_repo();

    let out = run_in(td.path(), &["config", "durability.objects", "sometimes"]);
    assert!(
        !out.status.success(),
        "a bogus durability value must be rejected, not silently accepted"
    );
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("durability.objects"),
        "error should name the key; got:\n{stderr}"
    );
}
