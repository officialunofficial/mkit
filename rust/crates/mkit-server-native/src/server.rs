//! `mkit-server serve`: take the root's locks, open the stores a
//! [`ServeConfig`] names, and serve the router until shutdown.

use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use mkit_core::protocol::Transport as _;
use mkit_core::repo_lock::{self, LockError, RepoLock};
use mkit_server::fs::{FsBlobStore, FsLayoutStore, META_MARKER};
use mkit_server::pipeline::{Hooks, Pipeline};
use mkit_server::sql::{SqlConn, SqlError, SqlKvStore, SqlValue, TxFn};
use mkit_server::{Addressing, BlobStore, NamespaceStore, RepoId, StoreError, SystemClock};
use mkit_transport_file::{FileTransport, sync_dir};
use tokio::net::TcpListener;

use crate::config::{ConfigError, MetaChoice, ServeConfig};
use crate::telemetry::MetricsBridge;
use crate::{Blocking, RusqliteConn, Shutdown, build_router, exit, serve};

/// The lock every live server holds **shared** under `<root>/.mkit`, so
/// local worktree commands and `gc` can tell the root is served (the
/// literal `mkit-cli`'s `commands::SERVE_LOCK` uses; `docs/INVARIANTS.md`).
/// `mkit serve` over ssh holds it too, and they coexist.
pub const SERVE_LOCK: &str = "serve.lock";

/// The lock one `mkit-server` holds **exclusively** under `<root>/.mkit`
/// for its lifetime: one server process per root, because its write gate
/// and caches are per process.
pub const SERVER_LOCK: &str = "server.lock";

/// The first line of the marker at [`META_MARKER`].
const MARKER_HEADER: &str = "mkit-server-meta 1";

/// The native server's own table in the `SQLite` file, outside the schema
/// shared with Durable Objects: the root id this database belongs to.
const ROOT_TABLE: &str = "CREATE TABLE IF NOT EXISTS mkit_server_root \
     (id INTEGER PRIMARY KEY CHECK (id = 1), root_id TEXT NOT NULL)";

/// The locks a running server holds on its root; they release on drop.
#[derive(Debug)]
pub struct ServerLocks {
    _server: RepoLock,
    _serve: RepoLock,
}

/// A server ready to bind: its router, and the root's locks.
#[derive(Debug)]
pub struct Opened {
    /// The router over the configured stores.
    pub router: axum::Router,
    locks: ServerLocks,
}

impl Opened {
    /// The router, and the locks to hold until the runtime that serves it
    /// has shut down (so no store call is still running on its blocking
    /// pool when another process may take the root).
    #[must_use = "the locks release when dropped"]
    pub fn into_parts(self) -> (axum::Router, ServerLocks) {
        (self.router, self.locks)
    }
}

fn config_error(what: &str, e: impl std::fmt::Display) -> ConfigError {
    ConfigError::new(
        exit::CONFIG_ERROR,
        format!("mkit-server serve: {what}: {e}"),
    )
}

/// What the marker binds: the root's id and its database.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Marker {
    root_id: String,
    db: PathBuf,
}

impl Marker {
    fn render(&self) -> String {
        format!(
            "{MARKER_HEADER}\nroot-id {}\nsqlite {}\n",
            self.root_id,
            self.db.display()
        )
    }

    fn parse(text: &str) -> Option<Self> {
        let mut lines = text.lines();
        if lines.next()? != MARKER_HEADER {
            return None;
        }
        let root_id = lines.next()?.strip_prefix("root-id ")?.to_owned();
        let db = PathBuf::from(lines.next()?.strip_prefix("sqlite ")?);
        let valid = root_id.len() == 32 && root_id.bytes().all(|b| b.is_ascii_hexdigit());
        (valid && lines.next().is_none()).then_some(Self { root_id, db })
    }
}

fn new_root_id() -> Result<String, ConfigError> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|e| config_error("generating a root id", e))?;
    Ok(mkit_core::hash::to_hex_bytes(&bytes))
}

/// Claim `root` for the `SQLite` database `db` (canonical) and return the
/// root's id (R-81). Under the root's ref lock, so no ref file can appear
/// in between: refuse a root that holds ref files; then read the marker,
/// which must name `db`, or write a new one with a fresh root id. From then
/// on every `FileTransport` ref write and `FsLayoutStore::open` refuse the
/// root.
///
/// # Errors
/// `CONFIG_ERROR` when the root holds ref files, is bound to another
/// database, carries a marker this binary does not read, or the marker
/// cannot be read or written.
pub fn claim_root_for_sqlite(root: &Path, db: &Path) -> Result<String, ConfigError> {
    let tx = FileTransport::new(root);
    tx.with_ref_lock(|_| claim_locked(&tx, root, db))
        .map_err(|e| config_error("taking the root's ref lock", e))?
}

fn claim_locked(tx: &FileTransport, root: &Path, db: &Path) -> Result<String, ConfigError> {
    let refs = tx
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
    let path = root.join(META_MARKER);
    match fs::read(&path) {
        Ok(bytes) => {
            let marker = std::str::from_utf8(&bytes)
                .ok()
                .and_then(Marker::parse)
                .ok_or_else(|| {
                    config_error(
                        "the root's meta marker",
                        format!("{} is not a marker this binary reads", path.display()),
                    )
                })?;
            if marker.db != db {
                rebind_moved(&path, &marker, db, root)?;
            }
            Ok(marker.root_id)
        }
        Err(e) if e.kind() == ErrorKind::NotFound => {
            let marker = Marker {
                root_id: new_root_id()?,
                db: db.to_owned(),
            };
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .map_err(|e| config_error("writing the meta marker", e))?;
            file.write_all(marker.render().as_bytes())
                .and_then(|()| file.sync_all())
                .map_err(|e| config_error("writing the meta marker", e))?;
            if let Some(dir) = path.parent() {
                sync_dir(dir).map_err(|e| config_error("syncing the meta marker", e))?;
            }
            Ok(marker.root_id)
        }
        Err(e) => Err(config_error("reading the meta marker", e)),
    }
}

/// The root id stored in the existing database `db`, if it has one. Never
/// creates the file.
fn stored_root_id(db: &Path) -> Result<Option<String>, ConfigError> {
    if !db.is_file() {
        return Ok(None);
    }
    let conn =
        RusqliteConn::open(db).map_err(|e| config_error("--meta sqlite", StoreError::from(e)))?;
    // No table: a database that was never bound.
    let Ok(rows) = conn.query("SELECT root_id FROM mkit_server_root WHERE id = 1", &[]) else {
        return Ok(None);
    };
    Ok(match rows.first().and_then(|row| row.first()) {
        Some(SqlValue::Text(id)) => Some(id.clone()),
        _ => None,
    })
}

/// The marker names another database than `db`. If `db` carries the
/// marker's root id, the root (or its database) moved: record the new path
/// in the marker, atomically, under the ref lock the caller holds.
/// Otherwise `db` is not this root's database, and the root is refused.
fn rebind_moved(path: &Path, marker: &Marker, db: &Path, root: &Path) -> Result<(), ConfigError> {
    let stored = stored_root_id(db)?;
    if stored.as_deref() == Some(marker.root_id.as_str()) {
        tracing::info!(
            from = %marker.db.display(),
            to = %db.display(),
            "the root's database moved; re-binding the marker"
        );
        let moved = Marker {
            root_id: marker.root_id.clone(),
            db: db.to_owned(),
        };
        let tmp = mkit_transport_file::temp_path(path)
            .map_err(|e| config_error("re-binding the meta marker", e))?;
        let write = || -> std::io::Result<()> {
            let mut file = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
            file.write_all(moved.render().as_bytes())?;
            file.sync_all()?;
            fs::rename(&tmp, path)?;
            if let Some(dir) = path.parent() {
                sync_dir(dir)?;
            }
            Ok(())
        };
        return write().map_err(|e| {
            let _ = fs::remove_file(&tmp);
            config_error("re-binding the meta marker", e)
        });
    }
    let found = match stored {
        Some(other) => format!("it belongs to another root (root id {other})"),
        None if db.exists() => "it carries no root binding".to_owned(),
        None => "it does not exist".to_owned(),
    };
    Err(ConfigError::new(
        exit::CONFIG_ERROR,
        format!(
            "mkit-server serve: repo root {} is bound to the database {} (root id {}, marker \
             {}), but --meta names {}, which is not this root's database: {found}. Point \
             --meta at this root's database; if you moved the root or its database, pass its \
             new path and the marker is re-bound automatically.",
            root.display(),
            marker.db.display(),
            marker.root_id,
            path.display(),
            db.display(),
        ),
    ))
}

/// How the database stands against the root claiming it.
enum Binding {
    Same,
    Other(String),
    UnboundWithData,
}

/// Bind the database on `conn` to `root_id`, or check that it is. A new
/// (empty) database adopts the id: the marker is always written first, so
/// a crash between the two only leaves an empty database to adopt.
///
/// # Errors
/// `CONFIG_ERROR` when the database belongs to another root, or holds
/// metadata but no root binding.
pub fn bind_database(conn: &RusqliteConn, root_id: &str, db: &Path) -> Result<(), ConfigError> {
    let id = root_id.to_owned();
    let check: TxFn<RusqliteConn, Binding> = Box::new(move |c: RusqliteConn| {
        c.exec(ROOT_TABLE, &[])?;
        let rows = c.query("SELECT root_id FROM mkit_server_root WHERE id = 1", &[])?;
        match rows.first().and_then(|row| row.first()) {
            Some(SqlValue::Text(bound)) if *bound == id => Ok(Binding::Same),
            Some(SqlValue::Text(bound)) => Ok(Binding::Other(bound.clone())),
            Some(_) => Err(SqlError::Corrupt("root binding is not text")),
            None => {
                if !c.query("SELECT 1 FROM kv LIMIT 1", &[])?.is_empty() {
                    return Ok(Binding::UnboundWithData);
                }
                c.exec(
                    "INSERT INTO mkit_server_root (id, root_id) VALUES (1, ?1)",
                    &[SqlValue::Text(id)],
                )?;
                Ok(Binding::Same)
            }
        }
    });
    let binding = conn
        .transaction(check)
        .map_err(|e| config_error("--meta sqlite", StoreError::from(e)))?;
    let refuse = |why: String| {
        Err(ConfigError::new(
            exit::CONFIG_ERROR,
            format!("mkit-server serve: --meta sqlite:{}: {why}", db.display()),
        ))
    };
    match binding {
        Binding::Same => Ok(()),
        Binding::Other(bound) => refuse(format!(
            "the database belongs to another served root (root id {bound}; this root's is \
             {root_id}). Two roots cannot share one database: give each its own file."
        )),
        Binding::UnboundWithData => refuse(
            "the database holds metadata but no root binding, so it was not created for this \
             root. Point --meta at this root's database."
                .to_owned(),
        ),
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
    // One process owns the root's metadata (the exclusive server lock):
    // serialize each partition's writes here rather than race them
    // through re-plans.
    .with_write_gate();
    Ok(build_router(Arc::new(pipeline), &cfg.router))
}

/// Take the root's locks: [`SERVER_LOCK`] exclusively (one server per
/// root), then [`SERVE_LOCK`] shared.
fn lock_root(root: &Path) -> Result<ServerLocks, ConfigError> {
    let dot_mkit = root.join(".mkit");
    let server =
        repo_lock::acquire(&dot_mkit, SERVER_LOCK, Duration::ZERO).map_err(|e| match e {
            LockError::Busy(_) => ConfigError::new(
                exit::CONFIG_ERROR,
                format!(
                    "mkit-server serve: another mkit-server already serves {} (it holds {}); run \
                 one server per root",
                    root.display(),
                    dot_mkit.join(SERVER_LOCK).display()
                ),
            ),
            other => ConfigError::new(
                exit::TEMPFAIL,
                format!("mkit-server serve: server lock: {other}"),
            ),
        })?;
    let serve = repo_lock::acquire_shared(&dot_mkit, SERVE_LOCK, repo_lock::DEFAULT_TIMEOUT)
        .map_err(|e| {
            ConfigError::new(
                exit::TEMPFAIL,
                format!("mkit-server serve: serve lock: {e}"),
            )
        })?;
    Ok(ServerLocks {
        _server: server,
        _serve: serve,
    })
}

/// Take the root's locks, check and bind the root for its metadata
/// choice, and open the stores (FS blobs under the root; `FsLayoutStore`
/// or `SQLite` metadata). Needs no async runtime.
///
/// # Errors
/// `CONFIG_ERROR` for a root another server holds, a root whose refs live
/// elsewhere or that is bound to another database (R-81), or a store that
/// does not open; `TEMPFAIL` when the serve lock is not granted in time.
pub fn open(cfg: &ServeConfig) -> Result<Opened, ConfigError> {
    let locks = lock_root(&cfg.repo_root)?;
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
                .map_err(|e| config_error("--meta fs-layout", e))?;
            router(blobs, Blocking::new(meta), cfg)?
        }
        MetaChoice::Sqlite { path, capacity } => {
            let root_id = claim_root_for_sqlite(&cfg.repo_root, path)?;
            let conn = RusqliteConn::open(path)
                .map_err(|e| config_error("--meta sqlite", StoreError::from(e)))?;
            let meta = SqlKvStore::open_with_capacity(conn.clone(), *capacity)
                .map_err(|e| config_error("--meta sqlite", e))?;
            bind_database(&conn, &root_id, path)?;
            router(blobs, Blocking::new(meta), cfg)?
        }
    };
    Ok(Opened { router, locks })
}

/// Bind [`ServeConfig::listen`] and serve `router` until `shutdown`
/// triggers and in-flight requests drain (see [`crate::serve`]).
///
/// # Errors
/// `UNAVAILABLE` when the address cannot be bound or the listener fails.
pub async fn serve_router(
    cfg: &ServeConfig,
    router: axum::Router,
    shutdown: Shutdown,
) -> Result<(), ConfigError> {
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
    serve(listener, router, shutdown, &cfg.serve)
        .await
        .map_err(|e| ConfigError::new(exit::UNAVAILABLE, format!("mkit-server serve: {e}")))?;
    tracing::info!("stopped");
    Ok(())
}

/// [`open`], then [`serve_router`]; the locks are released on return. The
/// binary instead holds them until its runtime has shut down.
///
/// # Errors
/// As [`open`] and [`serve_router`].
pub async fn run(cfg: &ServeConfig, shutdown: Shutdown) -> Result<(), ConfigError> {
    let (router, _locks) = open(cfg)?.into_parts();
    serve_router(cfg, router, shutdown).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marker_round_trips_and_rejects_junk() {
        let marker = Marker {
            root_id: "0123456789abcdef0123456789abcdef".to_owned(),
            db: PathBuf::from("/srv/mkit/meta.sqlite3"),
        };
        assert_eq!(Marker::parse(&marker.render()), Some(marker));
        for junk in [
            "sqlite\n",
            "",
            "mkit-server-meta 1\nroot-id xyz\nsqlite /a\n",
            "mkit-server-meta 1\nroot-id 0123456789abcdef0123456789abcdef\n",
            "mkit-server-meta 1\nroot-id 0123456789abcdef0123456789abcdef\nsqlite /a\nextra\n",
        ] {
            assert_eq!(Marker::parse(junk), None, "{junk:?}");
        }
    }
}
