//! Snapshot test for `mkit help` — every documented subcommand in
//! `docs/CLI.md` must appear in the help text.

use std::process::Command;

fn mkit_bin() -> &'static str {
    env!("CARGO_BIN_EXE_mkit")
}

/// The canonical subcommand list per `docs/CLI.md`. Keep in sync with
/// the CLI reference when adding commands.
const DOCUMENTED_SUBCOMMANDS: &[&str] = &[
    "init",
    "add",
    "rm",
    "status",
    "diff",
    "stash",
    "sparse-checkout",
    "commit",
    "log",
    "blame",
    "verify",
    "cat",
    "hash",
    "tree",
    "branch",
    "checkout",
    "tag",
    "merge",
    "cherry-pick",
    "rebase",
    "bisect",
    "remote",
    "clone",
    "fetch",
    "pull",
    "push",
    "serve",
    "keygen",
    "config",
    "version",
];

#[test]
fn help_lists_every_documented_subcommand() {
    let output = Command::new(mkit_bin())
        .arg("help")
        .output()
        .expect("spawn `mkit help`");
    assert!(output.status.success(), "`mkit help` must exit 0");
    let text = String::from_utf8(output.stdout).expect("stdout is utf-8");
    for cmd in DOCUMENTED_SUBCOMMANDS {
        assert!(
            text.contains(cmd),
            "`mkit help` output is missing documented subcommand '{cmd}'"
        );
    }
}

#[test]
fn dash_dash_help_goes_to_stdout() {
    let output = Command::new(mkit_bin())
        .arg("--help")
        .output()
        .expect("spawn `mkit --help`");
    assert!(output.status.success(), "`mkit --help` must exit 0");
    assert!(!output.stdout.is_empty(), "stdout empty");
    assert!(output.stderr.is_empty(), "stderr should be empty on --help");
}

#[test]
fn unknown_subcommand_exits_usage() {
    let output = Command::new(mkit_bin())
        .arg("definitely-nonsense")
        .output()
        .expect("spawn");
    assert_eq!(
        output.status.code(),
        Some(64),
        "unknown command must exit 64 (sysexits EX_USAGE)"
    );
}
