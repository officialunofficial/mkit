#![doc = include_str!("../README.md")]
//!
//! `mkit` CLI crate, exposed as a library so integration tests can
//! drive commands in-process.
//!
//! The binary is `src/main.rs`; everything else is a module here so
//! unit tests and integration tests can link without shelling out.
//! `mkit-cli` IS published to crates.io so `cargo install mkit-cli`
//! works, but its library surface (`mkit_cli::…`) is unstable, exists
//! only for in-process testing, and is deliberately excluded from
//! `cargo-semver-checks` — do not depend on it as a stable API.

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
#[cfg(feature = "sparse-checkout")]
pub mod sparse_cache;
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
#[allow(clippy::too_many_lines)] // flat command-dispatch match; splitting it would only hurt readability
pub fn dispatch(argv: &[String]) -> u8 {
    // Consume leading global flags (`-C <path>`, `-c <key>=<val>`, and the
    // accepted-as-no-op pager flags) BEFORE resolving the subcommand, so
    // they apply to every command and to repo discovery — like git.
    let (cmd_idx, overrides) = match parse_global_flags(argv) {
        Ok(parsed) => parsed,
        Err(code) => return code,
    };
    config::set_cli_overrides(overrides);

    if cmd_idx >= argv.len() {
        print_usage_stderr();
        return exit::USAGE;
    }
    let cmd = &argv[cmd_idx];
    let rest: Vec<String> = argv.iter().skip(cmd_idx + 1).cloned().collect();

    match cmd.as_str() {
        "-h" | "--help" | "help" => {
            let mut stdout = std::io::stdout().lock();
            let _ = stdout.write_all(cli::HELP_TEXT.as_bytes());
            exit::OK
        }
        "version" | "--version" | "-V" => {
            let mut stdout = std::io::stdout().lock();
            // Byte-exact `"mkit <X.Y.Z>\n"` — pinned by the snapshot
            // test in tests/version_snapshot.rs AND by Homebrew /
            // Scoop shell asserts. Any refactor that widens this must
            // update docs/CLI.md and ship a 1.0 major bump. The
            // top-level `--version`/`-V` flags are aliases of the
            // `version` subcommand (git-parity, #248) and emit the same
            // canonical string.
            let _ = writeln!(stdout, "mkit {}", cli::CLI_VERSION);
            exit::OK
        }
        "init" => commands::init::run(&rest),
        "key" => commands::key::run(&rest),
        "keygen" => commands::keygen::run(&rest),
        "hash" => commands::hash_cmd::run(&rest),
        "cat" => commands::cat::run(&rest),
        "cat-file" => commands::cat_file::run(&rest),
        "ls-tree" => commands::ls_tree::run(&rest),
        "ls-files" => commands::ls_files::run(&rest),
        "rev-parse" => commands::rev_parse::run(&rest),
        "show" => commands::show::run(&rest),
        "show-ref" => commands::show_ref::run(&rest),
        "for-each-ref" => commands::for_each_ref::run(&rest),
        "symbolic-ref" => commands::symbolic_ref::run(&rest),
        "update-ref" => commands::update_ref::run(&rest),
        "tree" => commands::tree::run(&rest),
        "add" => commands::add::run(&rest),
        "rm" => commands::rm::run(&rest),
        "mv" => commands::mv::run(&rest),
        "restore" => commands::restore::run(&rest),
        "reset" => commands::reset::run(&rest),
        "status" => commands::status::run(&rest),
        "commit" => commands::commit::run(&rest),
        "log" => commands::log::run(&rest),
        "reflog" => commands::reflog::run(&rest),
        "branch" => commands::branch::run(&rest),
        "tag" => commands::tag::run(&rest),
        "checkout" => commands::checkout::run(&rest),
        "switch" => commands::switch::run(&rest),
        "merge-base" => commands::merge_base::run(&rest),
        "rev-list" => commands::rev_list::run(&rest),
        "clean" => commands::clean::run(&rest),
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
        "mcp" => commands::mcp::run(&rest),
        "merge" => commands::merge::run(&rest),
        "cherry-pick" => commands::cherry_pick::run(&rest),
        "revert" => commands::revert::run(&rest),
        "rebase" => commands::rebase::run(&rest),
        "bisect" => commands::bisect::run(&rest),
        "gc" => commands::gc::run(&rest),
        "stash" => commands::stash::run(&rest),
        "worktree" => commands::worktree::run(&rest),
        "blame" => commands::blame::run(&rest),
        "self" => commands::self_update::run(&rest),
        "serve" => commands::serve::run(&rest),
        #[cfg(feature = "git-bridge")]
        "git" => commands::git::run(&rest),
        #[cfg(not(feature = "git-bridge"))]
        "git" => {
            let mut stderr = std::io::stderr().lock();
            let _ = writeln!(
                stderr,
                "error: the git bridge is not compiled into this binary; \
                 rebuild with `--features git-bridge` (see docs/specs/SPEC-GIT-BRIDGE.md)"
            );
            exit::UNAVAILABLE
        }
        "sparse-checkout" => commands::sparse_checkout::run(&rest),
        #[cfg(feature = "pack-shards")]
        "pack-shard" => commands::pack_shard::run(&rest),
        #[cfg(not(feature = "pack-shards"))]
        "pack-shard" => {
            // `pack-shard` is advertised in HELP_TEXT as a feature-gated
            // command; mirror the `git` fallback so an advertised-but-
            // disabled command fails with a clear "not compiled in"
            // message rather than a misleading "unknown command".
            let mut stderr = std::io::stderr().lock();
            let _ = writeln!(
                stderr,
                "error: pack-shard is not compiled into this binary; \
                 rebuild with `--features pack-shards`"
            );
            exit::UNAVAILABLE
        }
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

/// Consume the leading global flags from `argv` (after `argv[0]`):
/// `-C <path>` / `-C<path>` changes directory (repeatable, relative
/// resolution like git), `-c <key>=<val>` / `-c<key>=<val>` records a
/// one-shot config override, and `--no-pager` / `-P` / `--paginate` are
/// accepted as no-ops (mkit never paginates). Returns the index of the
/// subcommand token and the collected overrides, or an exit code on a
/// malformed flag / failed `chdir`.
fn parse_global_flags(argv: &[String]) -> Result<(usize, Vec<(String, String)>), u8> {
    let mut i = 1; // skip argv[0]
    let mut overrides: Vec<(String, String)> = Vec::new();
    while i < argv.len() {
        let arg = argv[i].as_str();
        if arg == "-C" {
            let Some(path) = argv.get(i + 1) else {
                return Err(global_flag_err("option `-C` requires a path"));
            };
            chdir(path)?;
            i += 2;
        } else if let Some(path) = arg.strip_prefix("-C").filter(|p| !p.is_empty()) {
            chdir(path)?;
            i += 1;
        } else if arg == "-c" {
            let Some(kv) = argv.get(i + 1) else {
                return Err(global_flag_err("option `-c` requires <key>=<value>"));
            };
            overrides.push(split_config_override(kv)?);
            i += 2;
        } else if let Some(kv) = arg.strip_prefix("-c").filter(|kv| !kv.is_empty()) {
            overrides.push(split_config_override(kv)?);
            i += 1;
        } else if matches!(arg, "--no-pager" | "-P" | "--paginate") {
            // mkit never paginates; accept the flags so defensive
            // `mkit --no-pager log` doesn't error out.
            i += 1;
        } else {
            break;
        }
    }
    Ok((i, overrides))
}

/// `chdir` for `-C`, resolving relative paths against the current dir
/// (repeatable `-C` composes, like git).
fn chdir(path: &str) -> Result<(), u8> {
    std::env::set_current_dir(path).map_err(|e| {
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(stderr, "error: cannot change to '{path}': {e}");
        exit::NOINPUT
    })
}

/// Split a `-c key=value` argument; the value may itself contain `=`.
fn split_config_override(kv: &str) -> Result<(String, String), u8> {
    match kv.split_once('=') {
        Some((k, v)) if !k.is_empty() => Ok((k.to_string(), v.to_string())),
        _ => Err(global_flag_err(
            "option `-c` expects <key>=<value> (e.g. -c user.email=ci@example.com)",
        )),
    }
}

fn global_flag_err(msg: &str) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "error: {msg}");
    exit::USAGE
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
