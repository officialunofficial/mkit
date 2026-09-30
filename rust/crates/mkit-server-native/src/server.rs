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
use mkit_server::pipeline::{HookSet, Hooks, OutcomeSink, Pipeline, Sharding};
use mkit_server::sql::{SqlConn, SqlError, SqlKvStore, SqlValue, TxFn};
use mkit_server::timers::outcome_delivery::OutcomeDelivery;
use mkit_server::{Addressing, MultipartBlobStore, NamespaceStore, StoreError, SystemClock};
use mkit_transport_file::{FileTransport, sync_dir};
use tokio::net::TcpListener;

use crate::config::{BlobChoice, ConfigError, MetaChoice, ServeConfig};
use crate::pressure::PressureMonitor;
use crate::telemetry::MetricsBridge;
use crate::timers::{TimerDriver, TimerNotifying, TimerStore, TokioSleep};
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

/// The native server's record of the metadata routing (`--sharding`) the
/// database was written with. Switching it on an existing database would
/// read refs from other partitions and hide every existing ref (R-93).
const SHARDING_TABLE: &str = "CREATE TABLE IF NOT EXISTS mkit_server_sharding \
     (id INTEGER PRIMARY KEY CHECK (id = 1), mode TEXT NOT NULL)";

/// The locks a running server holds on its root; they release on drop.
#[derive(Debug)]
pub struct ServerLocks {
    _server: RepoLock,
    _serve: RepoLock,
}

/// What a server serves over its stores: the HTTP router and, when
/// configured, the enc listener's service. Both run one pipeline's stores,
/// hooks and write gate.
#[derive(Debug)]
pub struct Services {
    /// Separate default-off operator router.
    pub admin: Option<axum::Router>,
    /// The router over the configured stores (served only with
    /// [`ServeConfig::listen`]).
    pub router: axum::Router,
    /// The enc listener's key and session function, with
    /// `ServeConfig::enc`.
    #[cfg(feature = "enc")]
    pub enc: Option<crate::enc::EncService>,
    /// Prepared `SQLite` timer driver, started by [`serve_services`].
    pub timers: Option<TimerDriver>,
    /// Physical database pressure monitor, absent for filesystem metadata.
    pub pressure: Option<PressureMonitor>,
}

/// A server ready to bind: its services, and the root's locks.
#[derive(Debug)]
pub struct Opened {
    /// Separate default-off operator router.
    pub admin: Option<axum::Router>,
    /// The router over the configured stores.
    pub router: axum::Router,
    /// The enc listener's service, when configured.
    #[cfg(feature = "enc")]
    pub enc: Option<crate::enc::EncService>,
    /// Prepared timer driver; absent for filesystem metadata.
    pub timers: Option<TimerDriver>,
    /// Prepared physical database pressure monitor.
    pub pressure: Option<PressureMonitor>,
    locks: ServerLocks,
}

impl Opened {
    /// The services, and the locks to hold until the runtime that serves
    /// them has shut down (so no store call is still running on its
    /// blocking pool when another process may take the root).
    #[must_use = "the locks release when dropped"]
    pub fn into_parts(self) -> (Services, ServerLocks) {
        let services = Services {
            admin: self.admin,
            router: self.router,
            #[cfg(feature = "enc")]
            enc: self.enc,
            timers: self.timers,
            pressure: self.pressure,
        };
        (services, self.locks)
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
    // Only a real move re-binds: the recorded database must be gone. If it
    // still exists (or cannot be checked), `db` is a stale copy, an old
    // backup or a mistyped path, and serving it would roll the refs and the
    // replay ledger back.
    match fs::symlink_metadata(&marker.db) {
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Ok(_) => {
            return Err(ConfigError::new(
                exit::CONFIG_ERROR,
                format!(
                    "mkit-server serve: repo root {} is bound to the database {}, which still \
                     exists, but --meta names {}. That looks like a stale copy (an old backup) \
                     or a wrong path, and serving it would roll the refs back. Pass --meta \
                     sqlite:{}; to restore a backup, stop the server and move the backup over \
                     that file.",
                    root.display(),
                    marker.db.display(),
                    db.display(),
                    marker.db.display()
                ),
            ));
        }
        Err(e) => {
            return Err(config_error(
                &format!(
                    "checking the root's recorded database {} before re-binding to {}",
                    marker.db.display(),
                    db.display()
                ),
                e,
            ));
        }
    }
    let stored = stored_root_id(db)?;
    if stored.as_deref() == Some(marker.root_id.as_str()) {
        tracing::warn!(
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

/// `--sharding` spelling of `mode`.
fn sharding_name(mode: Sharding) -> &'static str {
    match mode {
        Sharding::D34 => "d34",
        _ => "single",
    }
}

/// Record the database's routing on first use, or check that it matches.
/// A database that already holds metadata but no record predates
/// `--sharding` and was written `single`.
///
/// # Errors
/// `CONFIG_ERROR` when the database was written with another `--sharding`,
/// or its record is unreadable.
pub fn bind_sharding(conn: &RusqliteConn, mode: Sharding, db: &Path) -> Result<(), ConfigError> {
    let wanted = sharding_name(mode);
    let check: TxFn<RusqliteConn, String> = Box::new(move |c: RusqliteConn| {
        c.exec(SHARDING_TABLE, &[])?;
        let rows = c.query("SELECT mode FROM mkit_server_sharding WHERE id = 1", &[])?;
        match rows.first().and_then(|row| row.first()) {
            Some(SqlValue::Text(stored)) => Ok(stored.clone()),
            Some(_) => Err(SqlError::Corrupt("sharding record is not text")),
            None => {
                let has_data = !c.query("SELECT 1 FROM kv LIMIT 1", &[])?.is_empty();
                let stored = if has_data { "single" } else { wanted };
                c.exec(
                    "INSERT INTO mkit_server_sharding (id, mode) VALUES (1, ?1)",
                    &[SqlValue::Text(stored.to_owned())],
                )?;
                Ok(stored.to_owned())
            }
        }
    });
    let stored = conn
        .transaction(check)
        .map_err(|e| config_error("--meta sqlite", StoreError::from(e)))?;
    if stored == wanted {
        return Ok(());
    }
    Err(ConfigError::new(
        exit::CONFIG_ERROR,
        format!(
            "mkit-server serve: --meta sqlite:{}: the database was written with --sharding \
             {stored}, but this server was started with --sharding {wanted} (the default with \
             --meta sqlite is d34, or single for --addressing multi with --listen-enc). Changing an existing database's sharding would hide its refs \
             and is never done silently: start with --sharding {stored}.",
            db.display()
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

/// The pipeline over `blobs` and `meta` as a router and, with an enc
/// listener, the enc service over its `TransportIdentity` sibling (same
/// stores, same write gate).
fn build_services<B, N, H>(
    blobs: B,
    meta: N,
    cfg: &ServeConfig,
    hooks: H,
) -> Result<Services, ConfigError>
where
    B: MultipartBlobStore + Clone + 'static,
    N: NamespaceStore + Clone + 'static,
    H: HookSet + Clone + 'static,
{
    #[cfg(all(feature = "http-objects", feature = "hooks"))]
    if let Some(settings) = &cfg.hooks {
        crate::http_mount::check_other_keys(
            cfg.pipeline.url_tokens.as_ref(),
            &[settings.public_key()?],
        )?;
    }
    #[cfg(feature = "hooks")]
    if let (Some(retrieval), Some(settings)) = (&cfg.pipeline.scanner_retrieval, &cfg.hooks) {
        settings.check_scanner_keys(retrieval)?;
    }
    let mut pipeline_config = cfg.pipeline.clone();
    if let Some(purge) = pipeline_config.purge.take() {
        pipeline_config.purge = Some(purge.with_audit(Arc::new(
            mkit_server::admin::SystemAudit::new(
                meta.clone(),
                crate::admin::partition(pipeline_config.sharding),
            ),
        )));
    }
    let pipeline = Pipeline::new(
        blobs,
        meta.clone(),
        hooks,
        pipeline_config.clone(),
        Arc::new(SystemClock),
        Arc::new(MetricsBridge),
    )
    .map_err(|e| config_error("pipeline", e))?
    // One process owns the root's metadata (the exclusive server lock):
    // serialize each partition's writes here rather than race them
    // through re-plans.
    .with_write_gate();
    #[cfg(feature = "hooks")]
    let pipeline = if let Some(settings) = cfg.hooks.as_ref().filter(|s| !s.inspect.is_empty()) {
        let built = crate::hooks::build::build(Some(settings), &outcome_audience(cfg))?;
        let inspectors = built
            .inspectors
            .into_iter()
            .map(|inspector| {
                Arc::new(inspector) as Arc<dyn mkit_server::pipeline::inspection::ContentInspector>
            })
            .collect();
        pipeline
            .with_inspectors(inspectors, settings.inspect_batch_max_objects)
            .map_err(|e| config_error("inspection", e))?
    } else {
        pipeline
    };
    #[cfg(feature = "enc")]
    let enc = match &cfg.enc {
        Some(opts) => {
            let sibling = pipeline
                .with_auth(mkit_server::pipeline::AuthMode::TransportIdentity)
                .map_err(|e| config_error("pipeline", e))?;
            let key = crate::enc::load_server_key(&opts.server_key)?;
            if let Some(retrieval) = &cfg.pipeline.scanner_retrieval {
                crate::scanner_retrieval::check_enc_key(retrieval, &key)?;
            }
            #[cfg(feature = "http-objects")]
            {
                use commonware_cryptography::Signer as _;
                let public = <[u8; 32]>::try_from(key.public_key().as_ref())
                    .map_err(|_| config_error("enc key", "invalid public key"))?;
                crate::http_mount::check_other_keys(cfg.pipeline.url_tokens.as_ref(), &[public])?;
            }
            if let Some(admin) = &cfg.admin {
                use commonware_cryptography::Signer as _;
                let public = <[u8; 32]>::try_from(key.public_key().as_ref())
                    .map_err(|e| config_error("enc key", e))?;
                admin
                    .config
                    .check_separation(&[public])
                    .map_err(|e| config_error("admin key", e))?;
            }
            // The enc key may be created on first run, so this is the first
            // place its public half is known (SPEC-SERVER §7.1).
            #[cfg(feature = "hooks")]
            if let Some(settings) = &cfg.hooks {
                crate::hooks::build::check_enc_separation(settings, &key)?;
            }
            let session = crate::enc::session_fn(
                Arc::new(sibling),
                opts.repository.clone(),
                opts.idle_timeout,
            );
            Some(crate::enc::EncService { key, session })
        }
        None => None,
    };
    Ok(Services {
        admin: cfg
            .admin
            .as_ref()
            .map(|settings| crate::admin::router(meta, settings, &pipeline_config)),
        router: build_router(Arc::new(pipeline), &cfg.router),
        #[cfg(feature = "enc")]
        enc,
        timers: None,
        pressure: None,
    })
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
    #[cfg(feature = "hooks")]
    {
        let built = crate::hooks::build::build(cfg.hooks.as_ref(), &outcome_audience(cfg))?;
        let mut options = SinkOptions::default();
        if let Some(settings) = &cfg.hooks {
            // The kind-8 sink call is bounded by the hook timeout, or a
            // timeout above the 5 s default would be cut short.
            options.timeout = settings.timeout;
        }
        open_inner(
            cfg,
            built.hooks,
            Delivery {
                sink: built.sink,
                real: built.remote_sink,
                options,
            },
        )
    }
    #[cfg(not(feature = "hooks"))]
    open_inner(
        cfg,
        Hooks::new(),
        Delivery {
            sink: mkit_server::pipeline::NoOutcomes,
            real: false,
            options: SinkOptions::default(),
        },
    )
}

/// Kind-8 delivery bounds for [`open_with_sink`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SinkOptions {
    /// Bound on one sink call.
    pub timeout: Duration,
    /// Rows examined (and so sink calls attempted) per fire.
    pub max_rows: usize,
}

impl Default for SinkOptions {
    fn default() -> Self {
        Self {
            timeout: mkit_server::timers::outcome_delivery::DEFAULT_SINK_TIMEOUT,
            max_rows: mkit_server::timers::outcome_delivery::DEFAULT_MAX_ROWS,
        }
    }
}

/// The sink and its bounds as they travel through `open`.
struct Delivery<O> {
    sink: O,
    /// A caller-supplied sink, not the local acknowledger.
    real: bool,
    options: SinkOptions,
}

/// [`open`], delivering terminal outcomes (kind 8) to `sink` instead of
/// acknowledging them locally. For embedders: the binary builds its sink
/// from `--hook-outcome-url` (see [`open`]).
/// Each call is bounded by `options.timeout` (default 5 s) and a fire also by
/// twice that in wall-clock time, a failure or timeout ends the fire and
/// retries with backoff, and the shutdown drain (`--shutdown-drain-secs`) delivers what is due before
/// exit. A sink that names the server's audience (a `RemoteOutcomes` client's
/// `server_audience`) must take it from [`outcome_audience`].
///
/// # Errors
/// As [`open`], and `CONFIG_ERROR` for `--meta fs-layout`, which has no
/// timer driver to deliver from.
pub fn open_with_sink<O: OutcomeSink + 'static>(
    cfg: &ServeConfig,
    sink: O,
    options: SinkOptions,
) -> Result<Opened, ConfigError> {
    open_with(cfg, Hooks::new(), sink, options)
}

/// [`open_with_sink`] with the pipeline's hooks supplied too, for embedders
/// that run their own authorizer or admission. `cfg`'s remote-hook flags
/// (`--hook-*-url`) are refused here: the hooks come from the arguments, and
/// two sources for one stage would be ambiguous.
///
/// # Errors
/// As [`open_with_sink`], and `CONFIG_ERROR` when `cfg` configures remote hooks.
pub fn open_with<H, O>(
    cfg: &ServeConfig,
    hooks: H,
    sink: O,
    options: SinkOptions,
) -> Result<Opened, ConfigError>
where
    H: HookSet + Clone + 'static,
    O: OutcomeSink + 'static,
{
    #[cfg(feature = "hooks")]
    if cfg
        .hooks
        .as_ref()
        .is_some_and(crate::hooks::config::HookSettings::any)
    {
        return Err(config_error(
            "--hook-*-url",
            "remote hooks cannot be combined with hooks or a sink supplied by the embedder              (open_with, open_with_sink): each stage would have two sources",
        ));
    }
    open_inner(
        cfg,
        hooks,
        Delivery {
            sink,
            real: true,
            options,
        },
    )
}

/// The audience stamped on delivered outcomes: the auth-v2 audience, empty
/// without auth v2. Derive a hook client's `server_audience` from this same
/// value (R-162).
#[must_use]
pub fn outcome_audience(cfg: &ServeConfig) -> String {
    match &cfg.pipeline.auth {
        mkit_server::pipeline::AuthMode::AuthV2(config) => config.audience().to_owned(),
        _ => String::new(),
    }
}

fn open_inner<H, O>(
    cfg: &ServeConfig,
    hooks: H,
    delivery: Delivery<O>,
) -> Result<Opened, ConfigError>
where
    H: HookSet + Clone + 'static,
    O: OutcomeSink + 'static,
{
    let locks = lock_root(&cfg.repo_root)?;
    let services = match &cfg.blob {
        BlobChoice::Fs => {
            let blobs = FsBlobStore::new(&cfg.repo_root);
            let swept = blobs
                .sweep_stale_uploads(Duration::from_hours(168))
                .map_err(|e| config_error("sweeping filesystem uploads", e))?;
            if swept > 0 {
                tracing::warn!(swept, "removed stale filesystem uploads");
            }
            with_meta(
                Blocking::new(blobs),
                &cfg.pipeline.addressing,
                cfg,
                hooks,
                delivery,
            )?
        }
        #[cfg(feature = "s3")]
        BlobChoice::S3 {
            config,
            spool_max_bytes,
        } => with_meta(
            open_s3(config, *spool_max_bytes, cfg)?,
            &cfg.pipeline.addressing,
            cfg,
            hooks,
            delivery,
        )?,
    };
    Ok(Opened {
        admin: services.admin,
        router: services.router,
        #[cfg(feature = "enc")]
        enc: services.enc,
        timers: services.timers,
        pressure: services.pressure,
        locks,
    })
}

/// The services over `blobs` and the metadata store `cfg` names. The
/// fs-layout store names its one repository from the addressing; `SQLite`
/// serves every namespace's partitions.
fn with_meta<B, H, O>(
    blobs: B,
    addressing: &Addressing,
    cfg: &ServeConfig,
    hooks: H,
    delivery: Delivery<O>,
) -> Result<Services, ConfigError>
where
    B: MultipartBlobStore + Clone + 'static,
    H: HookSet + Clone + 'static,
    O: OutcomeSink + 'static,
{
    match &cfg.meta {
        MetaChoice::FsLayout => {
            if delivery.real {
                return Err(config_error(
                    "--meta fs-layout",
                    "outcome delivery needs the timer driver, which fs-layout metadata does \
                     not have; use --meta sqlite:<PATH>",
                ));
            }
            // `resolve` already refuses this combination; keep it a
            // config error rather than a panic if a config arrives
            // without going through it.
            let Addressing::Single { repo } = addressing else {
                return Err(config_error(
                    "--meta fs-layout",
                    "fs-layout metadata serves one repository; multi addressing needs \
                     --meta sqlite:<PATH>",
                ));
            };
            let meta = FsLayoutStore::open(&cfg.repo_root, repo)
                .map_err(|e| config_error("--meta fs-layout", e))?;
            build_services(blobs, Blocking::new(meta), cfg, hooks)
        }
        MetaChoice::Sqlite { path, capacity } => {
            let root_id = claim_root_for_sqlite(&cfg.repo_root, path)?;
            let conn = RusqliteConn::open(path)
                .map_err(|e| config_error("--meta sqlite", StoreError::from(e)))?;
            let meta = SqlKvStore::open_with_capacity(conn.clone(), *capacity)
                .map_err(|e| config_error("--meta sqlite", e))?;
            bind_database(&conn, &root_id, path)?;
            bind_sharding(&conn, cfg.pipeline.sharding, path)?;
            let meta = Blocking::new(TimerNotifying::new(meta));
            let Delivery { sink, options, .. } = delivery;
            let outcomes = OutcomeDelivery::new(
                sink,
                outcome_audience(cfg),
                Arc::new(MetricsBridge),
                Arc::new(TokioSleep),
            )
            .with_sink_timeout(options.timeout)
            .with_max_rows(options.max_rows)
            .with_clock(Arc::new(SystemClock));
            let registry = sqlite_timer_registry_with_audit(
                blobs.clone(),
                meta.clone(),
                outcomes,
                crate::admin::partition(cfg.pipeline.sharding),
            );
            #[cfg(feature = "hooks")]
            let registry = if let Some(sink) =
                crate::purge::build(cfg.hooks.as_ref(), &outcome_audience(cfg))?
            {
                registry.register(crate::purge::NativeDelivery::new(sink))
            } else {
                registry
            };
            let driver = TimerDriver::new(meta.clone(), registry, Arc::new(SystemClock));
            let mut services = build_services(blobs, meta, cfg, hooks)?;
            services.timers = Some(driver);
            services.pressure = Some(PressureMonitor::new(conn, *capacity));
            Ok(services)
        }
    }
}

/// The exact timer registry installed by the native `SQLite` server.
///
/// Kinds 8 and 9 run for every partition of the one store. Delivery goes to
/// `sink` (`NoOutcomes` acknowledges locally); `audience` is the canonical
/// origin stamped on delivered outcomes (empty without auth v2).
pub fn sqlite_timer_registry<B, O>(
    blobs: B,
    meta: TimerStore,
    audience: String,
    sink: O,
) -> mkit_server::timers::TimerRegistry<'static, TimerStore>
where
    B: MultipartBlobStore + Clone + 'static,
    O: OutcomeSink + 'static,
{
    let delivery = OutcomeDelivery::new(
        sink,
        audience,
        Arc::new(MetricsBridge),
        Arc::new(TokioSleep),
    )
    .with_clock(Arc::new(SystemClock));
    sqlite_timer_registry_with(blobs, meta, delivery)
}

/// [`sqlite_timer_registry`] with a caller-built kind-8 driver, for a
/// different sink timeout or row budget.
pub fn sqlite_timer_registry_with<B, O>(
    blobs: B,
    meta: TimerStore,
    delivery: OutcomeDelivery<O>,
) -> mkit_server::timers::TimerRegistry<'static, TimerStore>
where
    B: MultipartBlobStore + Clone + 'static,
    O: OutcomeSink + 'static,
{
    sqlite_timer_registry_with_audit(
        blobs,
        meta,
        delivery,
        crate::admin::partition(Sharding::Single),
    )
}

fn sqlite_timer_registry_with_audit<B, O>(
    blobs: B,
    meta: TimerStore,
    delivery: OutcomeDelivery<O>,
    root: mkit_server::Partition,
) -> mkit_server::timers::TimerRegistry<'static, TimerStore>
where
    B: MultipartBlobStore + Clone + 'static,
    O: OutcomeSink + 'static,
{
    let registry = mkit_server::timers::TimerRegistry::new()
        .register(mkit_server::timers::ticket_expiry::TicketExpiry { blobs })
        .register(
            mkit_server::timers::lease_sweep::LeaseSweep::new(meta.clone())
                .with_metrics(Arc::new(MetricsBridge)),
        )
        .register(mkit_server::relay::RelayHandler {
            target: meta.clone(),
            hook: mkit_server::admin::AuditRelayHook::new(meta.clone(), root),
            budget: mkit_server::relay::RelayBudget::default(),
        })
        .register(delivery)
        .register(mkit_server::timers::reservation_reconcile::ReservationReconcile)
        .register(
            mkit_server::timers::publication_recheck::PublicationRecheck {
                target: meta.clone(),
            },
        )
        .register(mkit_server::timers::quota_rollup::QuotaRollup {
            coordinator: meta,
            metrics: MetricsBridge,
        });
    #[cfg(feature = "test-faults")]
    let registry = registry.register(mkit_server::timers::test_kind::TestTimer);
    registry
}

/// The directory under `<root>/.mkit` where S3 uploads spool: on the
/// served root's volume, not a possibly RAM-backed system temp directory.
/// Spool files are unnamed; leftovers of a crash are swept at startup.
#[cfg(feature = "s3")]
pub const S3_SPOOL_DIR: &str = "server-spool";

/// The S3 blob store, spooling under [`S3_SPOOL_DIR`] within its budget
/// and capped at the pack limit. Runs under the root's exclusive
/// `server.lock`, so the spool directory's leftovers are a crashed
/// server's, and are swept.
#[cfg(feature = "s3")]
fn open_s3(
    s3: &crate::s3::S3Config,
    spool_max_bytes: u64,
    cfg: &ServeConfig,
) -> Result<crate::S3BlobStore, ConfigError> {
    let spool = cfg.repo_root.join(".mkit").join(S3_SPOOL_DIR);
    fs::create_dir_all(&spool).map_err(|e| config_error("creating the S3 upload spool", e))?;
    let swept = crate::s3::sweep_spool_dir(&spool)
        .map_err(|e| config_error("sweeping the S3 upload spool", e))?;
    if swept > 0 {
        tracing::warn!(swept, "removed spool files a crashed server left");
    }
    if s3.endpoint.scheme() == "http" && !s3.endpoint_is_loopback() {
        tracing::warn!(
            endpoint = %s3.endpoint,
            "--s3-allow-insecure-http: pack bytes cross the network in cleartext"
        );
    }
    Ok(crate::S3BlobStore::new(s3.clone(), Arc::new(SystemClock))
        .map_err(|e| config_error("--blob s3", e))?
        .with_spool_dir(spool)
        .with_spool_max_bytes(spool_max_bytes)
        .with_max_bytes(cfg.pipeline.upload_limits.max_total_bytes))
}

async fn bind(addr: std::net::SocketAddr, flag: &str) -> Result<TcpListener, ConfigError> {
    TcpListener::bind(addr).await.map_err(|e| {
        ConfigError::new(
            exit::UNAVAILABLE,
            format!("mkit-server serve: {flag} {addr}: bind: {e}"),
        )
    })
}

/// Bind the configured listeners, then serve `services` on them until
/// `shutdown` triggers and in-flight requests and sessions drain (see
/// [`crate::serve`] and `enc::serve`). Both listeners share the runtime and
/// the shutdown signal; one that fails triggers it, so the other drains too.
///
/// # Errors
/// `UNAVAILABLE` when an address cannot be bound or a listener fails.
pub async fn serve_services(
    cfg: &ServeConfig,
    services: Services,
    shutdown: Shutdown,
) -> Result<(), ConfigError> {
    let http = match cfg.listen {
        Some(addr) => Some(bind(addr, "--listen").await?),
        None => None,
    };
    let admin = match (&cfg.admin, services.admin) {
        (Some(settings), Some(router)) => {
            Some((bind(settings.listen, "--admin-listen").await?, router))
        }
        _ => None,
    };
    #[cfg(feature = "enc")]
    let enc = match (&cfg.enc, services.enc) {
        (Some(opts), Some(service)) => Some((bind(opts.listen, "--listen-enc").await?, service)),
        _ => None,
    };
    // The driver stops on its own switch, after the listeners drain, so an
    // outcome committed by a draining request is still delivered.
    let timer_stop = Shutdown::new();
    let timer_task = match services.timers {
        Some(driver) => Some(
            driver
                .start_with_drain(timer_stop.clone(), cfg.shutdown_drain)
                .await
                .map_err(|e| config_error("timer directory", e))?,
        ),
        None => None,
    };
    let pressure_task = services
        .pressure
        .map(|monitor| monitor.start(shutdown.clone()));
    let root = cfg.repo_root.display();
    let stop_on_error = |result: Result<(), ConfigError>| {
        if result.is_err() {
            shutdown.trigger();
        }
        result
    };
    let router = services.router;
    let http_run = async {
        let Some(listener) = http else {
            return Ok(());
        };
        let addr = listener.local_addr().map(|a| a.to_string());
        let addr = addr.unwrap_or_default();
        tracing::info!(%addr, %root, meta = ?cfg.meta, blob = %cfg.blob, "listening");
        serve(listener, router, shutdown.clone(), &cfg.serve)
            .await
            .map_err(|e| ConfigError::new(exit::UNAVAILABLE, format!("mkit-server serve: {e}")))
    };
    let admin_run = async {
        let Some((listener, router)) = admin else {
            return Ok(());
        };
        serve(listener, router, shutdown.clone(), &cfg.serve)
            .await
            .map_err(|e| config_error("admin listener", e))
    };
    #[cfg(feature = "enc")]
    let enc_run = async {
        let (Some(opts), Some((listener, service))) = (&cfg.enc, enc) else {
            return Ok(());
        };
        let addr = listener.local_addr().map(|a| a.to_string());
        let addr = addr.unwrap_or_default();
        let pubkey = crate::enc::public_key_hex(&service.key);
        tracing::info!(%addr, %pubkey, %root, meta = ?cfg.meta, blob = %cfg.blob, "enc listening");
        crate::enc::serve(listener, service, opts, shutdown.clone())
            .await
            .map_err(|e| {
                ConfigError::new(
                    exit::UNAVAILABLE,
                    format!("mkit-server serve: --listen-enc: {e}"),
                )
            })
    };
    #[cfg(not(feature = "enc"))]
    let enc_run = async { Ok(()) };
    let (http_result, enc_result, admin_result) = tokio::join!(
        async { stop_on_error(http_run.await) },
        async { stop_on_error(enc_run.await) },
        async { stop_on_error(admin_run.await) }
    );
    shutdown.trigger();
    timer_stop.trigger();
    if let Some(task) = timer_task {
        task.await.map_err(|e| config_error("timer driver", e))?;
    }
    if let Some(task) = pressure_task {
        task.await
            .map_err(|e| config_error("storage pressure monitor", e))?;
    }
    tracing::info!("stopped");
    http_result.and(enc_result).and(admin_result)
}

/// [`open`], then [`serve_services`]; the locks are released on return.
/// The binary instead holds them until its runtime has shut down.
///
/// # Errors
/// As [`open`] and [`serve_services`].
pub async fn run(cfg: &ServeConfig, shutdown: Shutdown) -> Result<(), ConfigError> {
    let (services, _locks) = open(cfg)?.into_parts();
    serve_services(cfg, services, shutdown).await
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

    fn database(dir: &Path, name: &str) -> (RusqliteConn, PathBuf) {
        let path = dir.join(name);
        let conn = RusqliteConn::open(&path).unwrap();
        SqlKvStore::open(conn.clone()).unwrap();
        (conn, path)
    }

    #[test]
    fn sharding_is_recorded_once_and_mismatches_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        for (first, other) in [
            (Sharding::Single, Sharding::D34),
            (Sharding::D34, Sharding::Single),
        ] {
            let (conn, path) = database(dir.path(), &format!("{}.sqlite3", sharding_name(first)));
            bind_sharding(&conn, first, &path).unwrap();
            bind_sharding(&conn, first, &path).unwrap();
            let refused = bind_sharding(&conn, other, &path).unwrap_err();
            assert_eq!(refused.code, exit::CONFIG_ERROR);
            assert!(
                refused.message.contains("--sharding"),
                "{}",
                refused.message
            );
        }
    }

    #[test]
    fn a_database_with_data_but_no_record_was_written_single() {
        let dir = tempfile::tempdir().unwrap();
        let (conn, path) = database(dir.path(), "legacy.sqlite3");
        conn.exec(
            "INSERT INTO kv (part, key, value) VALUES (?1, ?2, ?3)",
            &[
                SqlValue::Blob(b"nroot\0".to_vec()),
                SqlValue::Blob(b"r\0x".to_vec()),
                SqlValue::Blob(vec![0; 32]),
            ],
        )
        .unwrap();
        let refused = bind_sharding(&conn, Sharding::D34, &path).unwrap_err();
        assert_eq!(refused.code, exit::CONFIG_ERROR);
        assert!(
            refused.message.contains("start with --sharding single")
                && !refused.message.contains("no migration yet"),
            "{}",
            refused.message
        );
        bind_sharding(&conn, Sharding::Single, &path).unwrap();
    }
}
