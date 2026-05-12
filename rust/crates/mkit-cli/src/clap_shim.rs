//! Bridge between clap-derive command structs and mkit's sysexits
//! contract.
//!
//! mkit's top-level dispatcher in `lib.rs` hands each subcommand a
//! `&[String]` of remaining argv and expects a `u8` exit code back.
//! When a subcommand opts into clap-derive parsing, it gets two
//! choices about how to handle parse errors:
//!
//! 1. Map the error kind to the correct sysexit (USAGE for missing
//!    args, DATAERR for invalid values, etc.) so shell scripts that
//!    do `mkit foo … || handle` see the right code.
//! 2. Print the error to stderr in clap's standard format so users
//!    see consistent diagnostics across commands.
//!
//! This module does both. The typical migrated command looks like:
//!
//! ```ignore
//! use crate::clap_shim;
//! use clap::Parser;
//!
//! #[derive(Parser, Debug)]
//! struct Opts {
//!     #[arg(short, long)]
//!     verbose: bool,
//! }
//!
//! pub fn run(args: &[String]) -> u8 {
//!     let opts = match clap_shim::parse::<Opts>("mkit my-cmd", args) {
//!         Ok(o) => o,
//!         Err(code) => return code,
//!     };
//!     // ...real work using `opts`
//! }
//! ```
//!
//! ## Exit-code mapping
//!
//! | clap `ErrorKind`             | mkit exit code |
//! |------------------------------|----------------|
//! | `InvalidValue`               | `DATAERR` (65) |
//! | `ValueValidation`            | `DATAERR` (65) |
//! | `Io`                         | `NOINPUT` (66) |
//! | `DisplayHelp`                | `OK` (0)       |
//! | `DisplayVersion`             | `OK` (0)       |
//! | everything else (missing arg, unknown flag, …) | `USAGE` (64) |
//!
//! Help / version requests are NOT treated as errors — clap prints
//! them and we exit 0.

use std::io::Write;

use clap::Parser;
use clap::error::ErrorKind;

use crate::exit;

/// Parse `args` (everything after `argv[1]` from the dispatcher) into
/// `P`. On success, returns the parsed struct. On error, prints
/// clap's formatted diagnostic to stdout (for help/version) or
/// stderr (for usage / value errors) and returns the matching
/// sysexits code so the caller can `return` it.
///
/// `bin_name` is what clap prefixes errors with — usually
/// `"mkit <subcommand>"` so a user typo like
/// `mkit commit --bogus` reads cleanly:
///
/// ```text
/// error: unexpected argument '--bogus' found
///   tip: a similar argument exists: '--all'
/// usage: mkit commit [OPTIONS]
/// ```
pub fn parse<P: Parser>(bin_name: &str, args: &[String]) -> Result<P, u8> {
    // Prepend the bin name so clap's diagnostics show the right
    // prefix. Clap expects argv[0] to be the program name.
    let mut full: Vec<String> = Vec::with_capacity(args.len() + 1);
    full.push(bin_name.to_owned());
    full.extend(args.iter().cloned());

    match P::try_parse_from(full) {
        Ok(p) => Ok(p),
        Err(e) => Err(report_clap_error(&e)),
    }
}

/// Write a clap error to the appropriate stream and return the
/// matching sysexits code. Public so commands that hand-roll their
/// own `clap::Command` (rather than using the derive form) can reuse
/// the mapping.
#[must_use]
pub fn report_clap_error(e: &clap::Error) -> u8 {
    // Help and version are not actually errors — clap models them
    // this way so callers can hook into the formatting. Print to
    // stdout (that's the conventional location for `--help`) and
    // exit OK.
    match e.kind() {
        ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => {
            let mut stdout = std::io::stdout().lock();
            let _ = stdout.write_all(e.render().to_string().as_bytes());
            return exit::OK;
        }
        _ => {}
    }
    // Everything else is a real diagnostic — render to stderr.
    let mut stderr = std::io::stderr().lock();
    let _ = stderr.write_all(e.render().to_string().as_bytes());
    map_clap_error_kind(e.kind())
}

/// Map a `clap::ErrorKind` to a mkit sysexit. Kept as a small
/// freestanding function so unit tests can pin the mapping without
/// running clap.
#[must_use]
pub fn map_clap_error_kind(kind: ErrorKind) -> u8 {
    match kind {
        // "Value present but wrong shape" — `--commit not-a-hash`,
        // `--limit not-a-number`. The argument was structurally
        // there, the data was malformed.
        ErrorKind::InvalidValue | ErrorKind::ValueValidation => exit::DATAERR,

        // I/O error while parsing (e.g. failed to read stdin for a
        // value).
        ErrorKind::Io => exit::NOINPUT,

        // Format error during error rendering — should not happen on
        // any user-reachable path.
        ErrorKind::Format => exit::GENERAL_ERROR,

        // Everything else is "argument-shape problem" — wrong
        // subcommand, missing required arg, unknown flag, too many
        // values, etc. Help/version are special-cased in
        // [`report_clap_error`]; if they reach this mapper they
        // weren't intercepted, so route to USAGE defensively.
        _ => exit::USAGE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser, Debug)]
    #[command(no_binary_name = false)]
    struct DummyOpts {
        #[arg(short, long)]
        flag: bool,
        #[arg(short = 'n', long, value_parser = clap::value_parser!(u32))]
        count: Option<u32>,
    }

    #[test]
    fn unknown_flag_is_usage() {
        let res: Result<DummyOpts, _> = parse("mkit test", &["--bogus".to_string()]);
        assert_eq!(res.unwrap_err(), exit::USAGE);
    }

    #[test]
    fn invalid_value_is_dataerr() {
        let res: Result<DummyOpts, _> = parse(
            "mkit test",
            &["--count".to_string(), "not-a-number".to_string()],
        );
        assert_eq!(res.unwrap_err(), exit::DATAERR);
    }

    #[test]
    fn valid_parse_succeeds() {
        let res: Result<DummyOpts, _> = parse(
            "mkit test",
            &["--flag".to_string(), "-n".to_string(), "42".to_string()],
        );
        let opts = res.expect("should parse");
        assert!(opts.flag);
        assert_eq!(opts.count, Some(42));
    }

    #[test]
    fn no_args_parses_with_defaults() {
        let res: Result<DummyOpts, _> = parse("mkit test", &[]);
        let opts = res.expect("should parse with defaults");
        assert!(!opts.flag);
        assert_eq!(opts.count, None);
    }

    #[test]
    fn mapping_table() {
        assert_eq!(map_clap_error_kind(ErrorKind::InvalidValue), exit::DATAERR);
        assert_eq!(
            map_clap_error_kind(ErrorKind::ValueValidation),
            exit::DATAERR
        );
        assert_eq!(map_clap_error_kind(ErrorKind::Io), exit::NOINPUT);
        assert_eq!(
            map_clap_error_kind(ErrorKind::MissingRequiredArgument),
            exit::USAGE
        );
        assert_eq!(map_clap_error_kind(ErrorKind::UnknownArgument), exit::USAGE);
        assert_eq!(
            map_clap_error_kind(ErrorKind::InvalidSubcommand),
            exit::USAGE
        );
    }
}
