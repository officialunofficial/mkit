//! `mkit` — CLI binary entry point.
//!
//! The dispatch itself lives in `mkit_cli::dispatch` so integration
//! tests can drive the same code path in-process without spawning a
//! subprocess.

use std::process::ExitCode;

use mkit_cli::{dispatch, signal};

fn main() -> ExitCode {
    signal::install();
    let argv: Vec<String> = std::env::args().collect();
    let code = dispatch(&argv);
    ExitCode::from(code)
}
