//! `mkit` CLI crate, exposed as a library so integration tests can
//! drive commands in-process.
//!
//! The binary is `src/main.rs`; everything else is a module here so
//! unit tests and integration tests can link without shelling out.
//! `mkit-cli` is explicitly `publish = false` — it is monorepo-internal
//! plumbing, not a stable API.

// `deny` rather than `forbid` so the (currently single) `getpwuid_r`
// home-dir lookup in `config::home_dir_for_euid` can call libc. That
// function defeats the `HOME=/` parent-process trick when validating
// an absolute `signing_key` path: env-derived home would admit every
// path; passwd-derived home is bound to the same uid the file-mode
// checks use. All other modules remain effectively `forbid`'d via
// review; new `unsafe` sites need both an `#[allow]` opt-in and a
// SAFETY comment on the block.
#![deny(unsafe_code)]

pub mod clap_shim;
pub mod cli;
pub mod commands;
pub mod config;
pub mod editor;
pub mod exit;
pub mod format;
pub mod remote_dispatch;
pub mod signal;
pub mod term;

use std::io::Write;

/// Dispatch a single argv invocation. Takes the full argv including
/// `argv[0]`. Returns the exit code the binary should pass to
/// `std::process::exit`.
///
/// All I/O goes through stdout/stderr so integration tests either
/// spawn the binary (full end-to-end) or drive this entry point
/// directly (in-process, faster). We keep this function small and
/// dispatch-only so the command modules remain easy to snapshot.
#[must_use]
pub fn dispatch(argv: &[String]) -> u8 {
    if argv.len() < 2 {
        print_usage_stderr();
        return exit::USAGE;
    }
    let cmd = &argv[1];
    let rest: Vec<String> = argv.iter().skip(2).cloned().collect();

    match cmd.as_str() {
        "-h" | "--help" | "help" => {
            let mut stdout = std::io::stdout().lock();
            let _ = stdout.write_all(cli::HELP_TEXT.as_bytes());
            exit::OK
        }
        "version" => {
            let mut stdout = std::io::stdout().lock();
            // Byte-exact `"mkit <X.Y.Z>\n"` — pinned by the snapshot
            // test in tests/version_snapshot.rs AND by Homebrew /
            // Scoop shell asserts. Any refactor that widens this must
            // update docs/CLI.md and ship a 1.0 major bump.
            let _ = writeln!(stdout, "mkit {}", cli::CLI_VERSION);
            exit::OK
        }
        "init" => commands::init::run(&rest),
        "keygen" => commands::keygen::run(&rest),
        "hash" => commands::hash_cmd::run(&rest),
        "cat" => commands::cat::run(&rest),
        "tree" => commands::tree::run(&rest),
        "add" => commands::add::run(&rest),
        "rm" => commands::rm::run(&rest),
        "status" => commands::status::run(&rest),
        "commit" => commands::commit::run(&rest),
        "log" => commands::log::run(&rest),
        "branch" => commands::branch::run(&rest),
        "tag" => commands::tag::run(&rest),
        "checkout" => commands::checkout::run(&rest),
        "diff" => commands::diff::run(&rest),
        "verify" => commands::verify::run(&rest),
        "attest" => commands::attest::run(&rest),
        "verify-attest" => commands::verify_attest::run(&rest),
        "config" => commands::config_cmd::run(&rest),
        "remote" => commands::remote::run(&rest),
        "push" => commands::push::run(&rest),
        "pull" => commands::pull::run(&rest),
        "fetch" => commands::fetch::run(&rest),
        "clone" => commands::clone::run(&rest),
        "merge" => commands::merge::run(&rest),
        "cherry-pick" => commands::cherry_pick::run(&rest),
        "rebase" => commands::rebase::run(&rest),
        "bisect" => commands::bisect::run(&rest),
        "stash" => commands::stash::run(&rest),
        "blame" => commands::blame::run(&rest),
        "serve" => commands::serve::run(&rest),
        "sparse-checkout" => commands::sparse_checkout::run(&rest),
        other => {
            let mut stderr = std::io::stderr().lock();
            let _ = writeln!(
                stderr,
                "error: unknown command '{other}' (run 'mkit --help' for a list of commands)"
            );
            exit::USAGE
        }
    }
}

fn print_usage_stderr() {
    let mut stderr = std::io::stderr().lock();
    let _ = stderr.write_all(cli::HELP_TEXT.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_version_returns_ok() {
        // Even without a repo, `version` should succeed.
        let argv = vec!["mkit".to_string(), "version".to_string()];
        assert_eq!(dispatch(&argv), exit::OK);
    }

    #[test]
    fn dispatch_unknown_command_returns_usage() {
        let argv = vec!["mkit".to_string(), "definitely-not-a-command".to_string()];
        assert_eq!(dispatch(&argv), exit::USAGE);
    }

    #[test]
    fn dispatch_bare_binary_returns_usage() {
        let argv = vec!["mkit".to_string()];
        assert_eq!(dispatch(&argv), exit::USAGE);
    }
}
