//! `mkit-server serve`: open the stores a [`ServeConfig`] names, hold the
//! serve lock, and serve the router until shutdown.

use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write as _};
use std::path::Path;
use std::sync::Arc;

use mkit_core::protocol::Transport as _;
use mkit_core::repo_lock::{self, RepoLock};
use mkit_server::fs::{FsBlobStore, FsLayoutStore, META_MARKER};
use mkit_server::pipeline::{Hooks, Pipeline};
use mkit_server::sql::SqlKvStore;
use mkit_server::{Addressing, BlobStore, NamespaceStore, RepoId, StoreError, SystemClock};
use mkit_transport_file::{FileTransport, sync_dir};
use tokio::net::TcpListener;

use crate::config::{ConfigError, MetaChoice, ServeConfig};
use crate::shutdown::{Shutdown, serve};
use crate::telemetry::MetricsBridge;
use crate::{Blocking, RusqliteConn, build_router, exit};

/// The lock a live server holds shared under `<root>/.mkit`, so local
/// worktree commands and `gc` can tell the root is served (the literal
/// `mkit-cli`'s `commands::SERVE_LOCK` uses; `docs/INVARIANTS.md`).
pub const SERVE_LOCK: &str = "serve.lock";

/// What the marker at [`META_MARKER`] holds.
const MARKER_CONTENT: &[u8] = b"sqlite\n";

/// A server ready to bind: its router, and the serve lock it holds until
/// dropped.
#[derive(Debug)]
pub struct Opened {
    /// The router over the configured stores.
    pub router: axum::Router,
    _lock: RepoLock,
}

fn config_error(what: &str, e: impl std::fmt::Display) -> ConfigError {
    ConfigError::new(
        exit::CONFIG_ERROR,
        format!("mkit-server serve: {what}: {e}"),
    )
}

/// Refuse a root whose refs live in files (R-81), then mark it as served
/// with `SQLite` metadata, so `FsLayoutStore::open` refuses it from now on.
///
/// # Errors
/// `CONFIG_ERROR` when the root holds ref files, carries a marker this
/// binary does not write, or the marker cannot be written.
pub fn claim_root_for_sqlite(root: &Path) -> Result<(), ConfigError> {
    let refs = FileTransport::new(root)
        .list_refs("")
        .map_err(|e| config_error("listing the root's ref files", e))?;
    if !refs.is_empty() {
        return Err(ConfigError::new(
            exit::CONFIG_ERROR,
            format!(
                "mkit-server serve: repo root {} already holds file-based refs (used by 'mkit \
                 serve' and local mkit commands); --meta sqlite would keep a second, diverging \
                 copy of the refs. Serve this root with --meta fs-layout, or point --repo-root \
                 at a root without file refs.",
                root.display()
            ),
        ));
    }
    let marker = root.join(META_MARKER);
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&marker)
    {
        Ok(mut file) => {
            file.write_all(MARKER_CONTENT)
                .and_then(|()| file.sync_all())
                .map_err(|e| config_error("writing the meta marker", e))?;
            if let Some(dir) = marker.parent() {
                sync_dir(dir).map_err(|e| config_error("syncing the meta marker", e))?;
            }
            Ok(())
        }
        Err(e) if e.kind() == ErrorKind::AlreadyExists => match fs::read(&marker) {
            Ok(bytes) if bytes == MARKER_CONTENT => Ok(()),
            Ok(_) => Err(ConfigError::new(
                exit::CONFIG_ERROR,
                format!(
                    "mkit-server serve: {} holds an unknown metadata marker",
                    marker.display()
                ),
            )),
            Err(e) => Err(config_error("reading the meta marker", e)),
        },
        Err(e) => Err(config_error("writing the meta marker", e)),
    }
}

/// The pipeline over `blobs` and `meta`, as a router.
fn router<B, N>(blobs: B, meta: N, cfg: &ServeConfig) -> Result<axum::Router, ConfigError>
where
    B: BlobStore + 'static,
    N: NamespaceStore + 'static,
{
    let pipeline = Pipeline::new(
        blobs,
        meta,
        Hooks::new(),
        cfg.pipeline.clone(),
        Arc::new(SystemClock),
        Arc::new(MetricsBridge),
    )
    .map_err(|e| config_error("pipeline", e))?
    // One process owns the root's metadata: serialize each partition's
    // writes here rather than race them through re-plans.
    .with_write_gate();
    Ok(build_router(Arc::new(pipeline), &cfg.router))
}

fn store_error(what: &str, e: StoreError) -> ConfigError {
    config_error(what, e)
}

/// Take the serve lock, check and mark the root for its metadata choice,
/// and open the stores (FS blobs under the root; `FsLayoutStore` or
/// `SQLite` metadata).
///
/// # Errors
/// `TEMPFAIL` when the serve lock is not granted in time; `CONFIG_ERROR`
/// for a root whose refs live elsewhere (R-81) or a store that does not
/// open.
pub fn open(cfg: &ServeConfig) -> Result<Opened, ConfigError> {
    let lock = repo_lock::acquire_shared(
        &cfg.repo_root.join(".mkit"),
        SERVE_LOCK,
        repo_lock::DEFAULT_TIMEOUT,
    )
    .map_err(|e| {
        ConfigError::new(
            exit::TEMPFAIL,
            format!("mkit-server serve: serve lock: {e}"),
        )
    })?;
    let Addressing::Single { repo } = &cfg.pipeline.addressing else {
        return Err(config_error(
            "addressing",
            "only single-repo addressing is served",
        ));
    };
    let repo: &RepoId = repo;
    let blobs = Blocking::new(FsBlobStore::new(&cfg.repo_root));
    let router = match &cfg.meta {
        MetaChoice::FsLayout => {
            let meta = FsLayoutStore::open(&cfg.repo_root, repo)
                .map_err(|e| store_error("--meta fs-layout", e))?;
            router(blobs, Blocking::new(meta), cfg)?
        }
        MetaChoice::Sqlite { path, capacity } => {
            claim_root_for_sqlite(&cfg.repo_root)?;
            let conn = RusqliteConn::open(path)
                .map_err(|e| store_error("--meta sqlite", StoreError::from(e)))?;
            let meta = SqlKvStore::open_with_capacity(conn, *capacity)
                .map_err(|e| store_error("--meta sqlite", e))?;
            router(blobs, Blocking::new(meta), cfg)?
        }
    };
    Ok(Opened {
        router,
        _lock: lock,
    })
}

/// [`open`], bind [`ServeConfig::listen`], and serve until `shutdown`
/// triggers and in-flight requests drain (at most
/// [`ServeConfig::shutdown_grace`]). The serve lock is released last.
///
/// # Errors
/// [`open`]'s errors; `UNAVAILABLE` when the address cannot be bound or
/// the listener fails.
pub async fn run(cfg: &ServeConfig, shutdown: Shutdown) -> Result<(), ConfigError> {
    let opened = open(cfg)?;
    let listener = TcpListener::bind(cfg.listen).await.map_err(|e| {
        ConfigError::new(
            exit::UNAVAILABLE,
            format!("mkit-server serve: bind {}: {e}", cfg.listen),
        )
    })?;
    let addr = listener
        .local_addr()
        .map_or_else(|_| cfg.listen.to_string(), |a| a.to_string());
    tracing::info!(%addr, root = %cfg.repo_root.display(), meta = ?cfg.meta, "listening");
    serve(listener, opened.router, shutdown, cfg.shutdown_grace)
        .await
        .map_err(|e| ConfigError::new(exit::UNAVAILABLE, format!("mkit-server serve: {e}")))?;
    tracing::info!("stopped");
    Ok(())
}
