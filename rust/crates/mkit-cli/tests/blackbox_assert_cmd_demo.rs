//! Demonstrates `assert_cmd` + `predicates` + `assert_fs`'s fluent
//! black-box API as a pattern reference for new tests, alongside (not
//! replacing) the existing `Repo` builder in `tests/common/mod.rs`.
//!
//! `Repo` already covers the "sandboxed temp-dir + fixed signing key +
//! run a command" role `cargo-test-support`'s `project()` builder plays
//! for cargo's own testsuite — reach for it first, especially for
//! anything needing the invariant battery or the conflict/fault-injection
//! builders. Reach for `assert_cmd` when a test is simple enough that its
//! fluent `.assert().success().stdout(predicate!(...))` chain reads more
//! directly than a manual `Output` + `assert!` pair.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use assert_cmd::Command;
use assert_fs::TempDir;
use assert_fs::prelude::*;
use predicates::prelude::*;

fn mkit_in(dir: &TempDir) -> Command {
    let mut cmd = Command::cargo_bin("mkit").unwrap();
    cmd.current_dir(dir)
        .env("XDG_CONFIG_HOME", dir.path())
        .env("HOME", dir.path())
        .env("EDITOR", "true")
        .env("VISUAL", "true")
        .env("GIT_EDITOR", "true");
    cmd
}

#[test]
fn init_keygen_add_commit_flow_via_assert_cmd() {
    let dir = TempDir::new().unwrap();

    mkit_in(&dir)
        .arg("init")
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "initialized empty mkit repository",
        ));

    mkit_in(&dir).arg("keygen").assert().success();

    dir.child("README.md").write_str("hello\n").unwrap();

    mkit_in(&dir).args(["add", "README.md"]).assert().success();

    mkit_in(&dir)
        .args(["commit", "-m", "assert_cmd demo commit"])
        .assert()
        .success()
        .stderr(predicate::str::contains("assert_cmd demo commit"));

    // `log --oneline` should now show exactly one commit with our message.
    mkit_in(&dir)
        .args(["log", "--oneline"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("assert_cmd demo commit")
                .and(predicate::function(|s: &str| s.lines().count() == 1)),
        );
}
