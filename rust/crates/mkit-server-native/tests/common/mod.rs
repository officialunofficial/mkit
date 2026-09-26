//! Shared by the native server's integration tests: temp roots, flag
//! parsing, serving a router on loopback, and judging wire reports.

#![allow(dead_code)] // each test binary uses a subset

use std::path::Path;

use clap::Parser;
use mkit_server_conformance::wire::{CASES, Report, Verdict};
use mkit_server_native::config::{ConfigError, ServeArgs, ServeConfig, resolve};
use mkit_server_native::{Shutdown, serve};

/// `mkit-server serve`'s flags, parsed as the binary parses them.
#[derive(Debug, Parser)]
struct Serve {
    #[command(flatten)]
    args: ServeArgs,
}

/// Parse `flags` (without the `serve` word).
pub(crate) fn args(flags: &[&str]) -> ServeArgs {
    Serve::try_parse_from(std::iter::once("serve").chain(flags.iter().copied()))
        .unwrap()
        .args
}

/// [`resolve`] with the environment `env` (name, value) pairs only.
pub(crate) fn resolve_with(
    flags: &[&str],
    env: &[(&str, &str)],
) -> Result<ServeConfig, ConfigError> {
    let lookup = |name: &str| {
        env.iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| (*v).to_owned())
    };
    resolve(&args(flags), &lookup)
}

/// A served root: a temp dir holding `.mkit`.
pub(crate) fn repo_root() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join(".mkit")).unwrap();
    dir
}

/// `path` as a flag value.
pub(crate) fn s(path: &Path) -> &str {
    path.to_str().unwrap()
}

/// `127.0.0.1:0` and its `http://` origin.
pub(crate) async fn listener() -> (tokio::net::TcpListener, String) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    (listener, origin)
}

/// Serve `router` on `listener` in the background until `shutdown`.
pub(crate) fn spawn_serve(
    listener: tokio::net::TcpListener,
    router: axum::Router,
    shutdown: &Shutdown,
) -> tokio::task::JoinHandle<std::io::Result<()>> {
    let shutdown = shutdown.clone();
    tokio::spawn(serve(
        listener,
        router,
        shutdown,
        std::time::Duration::from_secs(10),
    ))
}

/// Pass iff every failed case is listed in `divergences`, and every listed
/// case names a real case and does not pass (mkit-server-conformance's
/// baseline rule).
pub(crate) fn judge(report: &Report, divergences: &[(&str, &str)]) {
    let tap = report.tap();
    eprintln!("{tap}");
    for (name, why) in divergences {
        assert!(
            CASES.iter().any(|c| c.name == *name),
            "divergence `{name}` names no case"
        );
        assert!(!why.is_empty(), "divergence `{name}` has no justification");
        assert!(
            !matches!(report.verdict(name), Some(Verdict::Pass(_))),
            "divergence `{name}` passes now: remove it from the list\n{tap}"
        );
    }
    let unexpected: Vec<_> = report
        .failures()
        .into_iter()
        .filter(|f| !divergences.iter().any(|(n, _)| n == f))
        .collect();
    assert!(
        unexpected.is_empty(),
        "unexpected failures {unexpected:?}\n{tap}"
    );
}
