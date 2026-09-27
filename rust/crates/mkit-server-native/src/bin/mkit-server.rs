//! `mkit-server`: the long-running native mkit server (PRD §5.1, D31).
//!
//! ```text
//! mkit-server serve [--listen <ADDR>] [--listen-enc <ADDR>] --repo-root <DIR> [...]
//! mkit-server version
//! mkit-server backup --meta sqlite:<PATH> --out <FILE>
//! ```
//!
//! See the crate README for the operator guide.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};
use mkit_server::sql::SqlConn;
use mkit_server_native::config::{MetaArg, ServeArgs, resolve};
use mkit_server_native::telemetry::{DEFAULT_FILTER, init_tracing};
use mkit_server_native::{RusqliteConn, Shutdown, exit, server, shutdown_signal};

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
    /// proxy), `mkit+enc://` clients over the encrypted listener, or both.
    Serve(Box<ServeArgs>),
    /// Print the version.
    Version,
    /// Write a consistent physical `SQLite` backup while the server runs.
    Backup(BackupArgs),
}

#[derive(Debug, Args)]
struct BackupArgs {
    /// Existing `SQLite` metadata database: sqlite:<PATH>.
    #[arg(long)]
    meta: MetaArg,
    /// New output file; any existing path is refused.
    #[arg(long)]
    out: PathBuf,
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
        Command::Backup(args) => backup(&args),
    })
}

fn backup(args: &BackupArgs) -> u8 {
    match write_backup(args) {
        Ok(size) => {
            println!("{} ({size} bytes)", args.out.display());
            exit::OK
        }
        Err((code, error)) => {
            eprintln!("mkit-server backup: {error}");
            code
        }
    }
}

fn write_backup(args: &BackupArgs) -> Result<u64, (u8, String)> {
    let MetaArg::Sqlite(source) = &args.meta else {
        return Err((exit::USAGE, "--meta must be sqlite:<PATH>".to_owned()));
    };
    match std::fs::symlink_metadata(&args.out) {
        Ok(_) => {
            return Err((
                exit::USAGE,
                format!("--out {} already exists", args.out.display()),
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err((
                exit::USAGE,
                format!("--out {}: {error}", args.out.display()),
            ));
        }
    }
    if !source.is_file() {
        return Err((
            exit::NOINPUT,
            format!(
                "--meta sqlite:{} is not an existing database file",
                source.display()
            ),
        ));
    }
    let dest = args
        .out
        .to_str()
        .ok_or_else(|| (exit::USAGE, "--out must be a UTF-8 path".to_owned()))?;
    let fail = |error: String| (exit::UNAVAILABLE, error);
    // A separate WAL connection reads a consistent snapshot without
    // acquiring the server's root locks or stopping its writers.
    let conn = RusqliteConn::open(source).map_err(|error| fail(error.to_string()))?;
    conn.backup_to(dest)
        .map_err(|error| fail(error.to_string()))?;
    std::fs::metadata(&args.out)
        .map(|metadata| metadata.len())
        .map_err(|error| fail(error.to_string()))
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
    for banner in cfg.banners() {
        eprintln!("{banner}");
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
    let (services, locks) = match server::open(&cfg) {
        Ok(opened) => opened.into_parts(),
        Err(e) => {
            eprintln!("{e}");
            return e.code;
        }
    };
    #[cfg(feature = "enc")]
    if let (Some(opts), Some(service)) = (&cfg.enc, &services.enc) {
        eprintln!(
            "{}",
            mkit_server_native::enc::announcement(opts.listen, &service.key)
        );
    }
    let result = runtime.block_on(async {
        let shutdown = Shutdown::new();
        let trigger = shutdown.clone();
        tokio::spawn(async move {
            shutdown_signal().await;
            trigger.trigger();
        });
        server::serve_services(&cfg, services, shutdown).await
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
