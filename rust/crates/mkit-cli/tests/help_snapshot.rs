//! Snapshot test for `mkit help` — every documented subcommand in
//! `docs/CLI.md` must appear in the help text.
//!
//! These tests also assert man-page and shell-completion coverage of
//! the documented subcommand list, so a new command can't silently ship
//! without being added to `man/mkit.1` and `completions/mkit.{bash,zsh,
//! fish}` (the drift that #219 fixed for `pack-shard`).

use std::path::PathBuf;
use std::process::Command;

fn mkit_bin() -> &'static str {
    env!("CARGO_BIN_EXE_mkit")
}

/// Repository root, three levels up from this crate
/// (`rust/crates/mkit-cli`).
fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("..")
}

fn read_repo_file(rel: &str) -> String {
    let path = repo_root().join(rel);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {} ({}): {e}", rel, path.display()))
}

/// The canonical subcommand list per `docs/CLI.md`. Keep in sync with
/// the CLI reference when adding commands.
const DOCUMENTED_SUBCOMMANDS: &[&str] = &[
    "init",
    "add",
    "rm",
    "mv",
    "restore",
    "reset",
    "status",
    "diff",
    "stash",
    "sparse-checkout",
    "pack-shard",
    "commit",
    "log",
    "reflog",
    "blame",
    "verify",
    "cat",
    "cat-file",
    "hash",
    "tree",
    "ls-tree",
    "ls-files",
    "rev-parse",
    "show-ref",
    "for-each-ref",
    "symbolic-ref",
    "update-ref",
    "branch",
    "checkout",
    "clean",
    "tag",
    "merge",
    "cherry-pick",
    "revert",
    "rebase",
    "bisect",
    "gc",
    "remote",
    "clone",
    "fetch",
    "pull",
    "push",
    "serve",
    "key",
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
fn man_page_documents_every_subcommand() {
    let man = read_repo_file("man/mkit.1");
    for cmd in DOCUMENTED_SUBCOMMANDS {
        // The man page enumerates subcommands as mdoc `Cm <name>`
        // macros (either `.It Cm <name>` for the leading entry or
        // `Cm <name>` after a comma for grouped entries like
        // `.Cm pull , Cm fetch`). Match the macro plus a delimiter so a
        // prefix can't satisfy a longer command name by accident.
        let documented = man.lines().any(|line| {
            line.match_indices(&format!("Cm {cmd}")).any(|(idx, m)| {
                let after = &line[idx + m.len()..];
                after.is_empty() || after.starts_with([' ', ',', '\t'])
            })
        });
        assert!(
            documented,
            "man/mkit.1 is missing documented subcommand '{cmd}' (expected a `Cm {cmd}` macro)"
        );
    }
}

#[test]
fn completions_cover_every_subcommand() {
    for (file, name) in [
        ("completions/mkit.bash", "bash"),
        ("completions/mkit.zsh", "zsh"),
        ("completions/mkit.fish", "fish"),
    ] {
        let text = read_repo_file(file);
        for cmd in DOCUMENTED_SUBCOMMANDS {
            assert!(
                text.contains(cmd),
                "{name} completion ({file}) is missing documented subcommand '{cmd}'"
            );
        }
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

/// Snapshot of `mkit --help` output. Reviewable diffs via
/// `cargo insta review`; raw assertions on a 30+ subcommand list
/// produce noisy diffs that nobody reads.
#[test]
fn help_output_snapshot() {
    let output = Command::new(mkit_bin())
        .arg("--help")
        .output()
        .expect("spawn `mkit --help`");
    let stdout = String::from_utf8(output.stdout).expect("utf-8");
    insta::assert_snapshot!("mkit_dash_help", stdout);
}

/// Snapshot of `mkit version`. Pins the format (key=value pairs,
/// trailing newline) so any drift in the version-emitter shows up as
/// a reviewable diff instead of a `contains("0.")` regex.
#[test]
fn version_output_snapshot() {
    let output = Command::new(mkit_bin())
        .arg("version")
        .output()
        .expect("spawn `mkit version`");
    let stdout = String::from_utf8(output.stdout).expect("utf-8");
    // Mask the version string so a `Cargo.toml` version bump doesn't
    // re-break the snapshot — we want shape-stability, not number-
    // stability.
    insta::with_settings!({filters => vec![
        (r"\d+\.\d+\.\d+(-[A-Za-z0-9._-]+)?", "[VERSION]"),
    ]}, {
        insta::assert_snapshot!("mkit_version", stdout);
    });
}
