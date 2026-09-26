//! `mkit-server`: the long-running native mkit server (PRD §5.1, D31).
//!
//! ```text
//! mkit-server serve --listen <ADDR> --repo-root <DIR> [...]
//! mkit-server version
//! ```
//!
//! See the crate README for the operator guide.

use std::process::ExitCode;

use clap::{Parser, Subcommand};
use mkit_server_native::config::{ServeArgs, UNSAFE_BANNER, resolve};
use mkit_server_native::telemetry::{DEFAULT_FILTER, init_tracing};
use mkit_server_native::{Shutdown, exit, server, shutdown_signal};

#[derive(Debug, Parser)]
#[command(name = "mkit-server", version, about = "The mkit server")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

/// Operator commands. Later ones slot in here (`grant ...` in WP-2.12,
/// `admin ...` in WP-5.11b).
#[derive(Debug, Subcommand)]
enum Command {
    /// Serve `mkit.transport.v1` over HTTP (terminate TLS at a reverse
    /// proxy).
    Serve(Box<ServeArgs>),
    /// Print the version.
    Version,
}

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => {
            // `--help` and `--version` print to stdout and succeed.
            let code = if e.use_stderr() {
                exit::USAGE
            } else {
                exit::OK
            };
            let _ = e.print();
            return ExitCode::from(code);
        }
    };
    ExitCode::from(match cli.command {
        Command::Version => {
            println!("mkit-server {}", env!("CARGO_PKG_VERSION"));
            exit::OK
        }
        Command::Serve(args) => serve(&args),
    })
}

fn serve(args: &ServeArgs) -> u8 {
    let env = |name: &str| std::env::var(name).ok();
    let cfg = match resolve(args, &env) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("{e}");
            return e.code;
        }
    };
    if cfg.is_open() {
        eprintln!("{UNSAFE_BANNER}");
    }
    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| DEFAULT_FILTER.to_owned());
    if let Err(e) = init_tracing(cfg.log_format, &filter) {
        eprintln!("mkit-server serve: {e}");
        return exit::CONFIG_ERROR;
    }
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            eprintln!("mkit-server serve: failed to start the async runtime: {e}");
            return exit::UNAVAILABLE;
        }
    };
    // Locks first, outside the runtime: they outlive it (below).
    let (router, locks) = match server::open(&cfg) {
        Ok(opened) => opened.into_parts(),
        Err(e) => {
            eprintln!("{e}");
            return e.code;
        }
    };
    let result = runtime.block_on(async {
        let shutdown = Shutdown::new();
        let trigger = shutdown.clone();
        tokio::spawn(async move {
            shutdown_signal().await;
            trigger.trigger();
        });
        server::serve_router(&cfg, router, shutdown).await
    });
    // Let store calls still running on the blocking pool (an abandoned
    // request's `SQLite` commit) finish before the root's locks go, so no
    // other process can take the root under them.
    runtime.shutdown_timeout(cfg.serve.grace);
    drop(locks);
    match result {
        Ok(()) => exit::OK,
        Err(e) => {
            eprintln!("{e}");
            e.code
        }
    }
}
