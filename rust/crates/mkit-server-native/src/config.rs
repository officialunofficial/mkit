//! `mkit-server serve`'s flags and their fail-closed resolution into a
//! [`ServeConfig`].

use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use clap::{Args, ValueEnum};
use http::HeaderValue;
use mkit_server::auth_v2::AuthV2Config;
use mkit_server::pipeline::{AuthMode, PipelineConfig};
use mkit_server::sql::Capacity;
use mkit_server::upload::UploadLimits;
use mkit_server::{Addressing, NamespaceKey, Redacted, RepoId, RepoName};

use crate::ServeOptions;
use crate::exit;
use crate::layers::body_limit_for;
use crate::router::{CorsPolicy, RouterOptions};

/// The bearer token's environment variable: the one `mkit serve --http`
/// reads and the `mkit+https://` client sends (SPEC-TRANSPORT §5.2).
pub const TOKEN_ENV: &str = "MKIT_API_TOKEN";

/// Pins every served root under a directory, as for `mkit serve`.
pub const SERVE_ROOT_ENV: &str = "MKIT_SERVE_ROOT";

/// Default `--repository`.
pub const DEFAULT_REPOSITORY: &str = "default";

/// Default `--sqlite-max-bytes`: the hard cap of the `SQLite` metadata
/// file (8 GiB).
pub const DEFAULT_SQLITE_MAX_BYTES: u64 = 8 << 30;

/// Where the metadata (refs, and under auth v2 the replay ledger and quota)
/// lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetaArg {
    /// Ref files under the served root, shared with `mkit serve` and local
    /// `mkit` commands (`FsLayoutStore`). Refs only: bearer or open auth.
    FsLayout,
    /// A `SQLite` database file (`sqlite:<PATH>`).
    Sqlite(PathBuf),
}

impl FromStr for MetaArg {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        if s == "fs-layout" {
            return Ok(Self::FsLayout);
        }
        match s.strip_prefix("sqlite:") {
            Some(path) if !path.is_empty() => Ok(Self::Sqlite(PathBuf::from(path))),
            _ => Err(format!("expected fs-layout or sqlite:<PATH>, got {s:?}")),
        }
    }
}

/// `--auth`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum AuthArg {
    /// A shared `Authorization: Bearer <token>` on every RPC.
    Bearer,
    /// Auth v2 signed writes, with the replay ledger and write quota.
    #[value(name = "auth-v2")]
    AuthV2,
}

/// `--log-format`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum)]
pub enum LogFormat {
    /// Human-readable lines.
    #[default]
    Text,
    /// One JSON object per event.
    Json,
}

/// `mkit-server serve`'s flags. Secrets never go on the command line: the
/// bearer token comes from `--bearer-token-file` or `MKIT_API_TOKEN`.
#[derive(Debug, Clone, Args)]
#[allow(clippy::struct_excessive_bools)]
pub struct ServeArgs {
    /// Address to listen on, e.g. `127.0.0.1:8080`. Plaintext HTTP/1.1 and
    /// h2c: terminate TLS at a reverse proxy.
    #[arg(long, value_name = "ADDR")]
    pub listen: SocketAddr,
    /// The served root: a directory holding `.mkit`. Packs live in
    /// `<DIR>/packs`, file refs in `<DIR>/refs`.
    #[arg(long, value_name = "DIR")]
    pub repo_root: PathBuf,
    /// `fs-layout` (ref files, shared with `mkit serve`; the default for
    /// bearer and unsafe auth) or `sqlite:<PATH>` (required for auth v2).
    #[arg(long, value_name = "fs-layout|sqlite:<PATH>")]
    pub meta: Option<MetaArg>,
    /// How writes authenticate: `bearer` (the default when a token is
    /// configured) or `auth-v2` (signed writes; needs `--audience`).
    #[arg(long, value_enum)]
    pub auth: Option<AuthArg>,
    /// Development only: accept any caller with no authentication.
    #[arg(long)]
    pub unsafe_allow_any_peer: bool,
    /// A file holding the bearer token (one trailing newline is ignored).
    /// Without it, `MKIT_API_TOKEN` is read.
    #[arg(long, value_name = "PATH")]
    pub bearer_token_file: Option<PathBuf>,
    /// Auth v2: the deployment's canonical origin, byte for byte as
    /// clients sign it (e.g. `https://vcs.example`).
    #[arg(long, value_name = "ORIGIN")]
    pub audience: Option<String>,
    /// The repository identity served (and signed for under auth v2).
    #[arg(long, value_name = "ID", default_value = DEFAULT_REPOSITORY)]
    pub repository: String,
    /// Largest pack an upload may declare (default 4 GiB).
    #[arg(long, value_name = "N")]
    pub max_pack_bytes: Option<u64>,
    /// Deadline of a unary RPC.
    #[arg(long, value_name = "SECS", default_value_t = 30)]
    pub unary_timeout_secs: u64,
    /// Deadline of an `UploadPack` or `DownloadPack` stream.
    #[arg(long, value_name = "SECS", default_value_t = 3600)]
    pub stream_timeout_secs: u64,
    /// Requests served at once, each until its response body ends; excess
    /// requests wait. Keep it below tokio's blocking-pool size (512).
    #[arg(long, value_name = "N", default_value_t = 256)]
    pub max_concurrency: usize,
    /// How long a request waits for a slot before it is shed (HTTP 503,
    /// Connect `unavailable`); 0 sheds at once.
    #[arg(long, value_name = "SECS", default_value_t = 5)]
    pub queue_timeout_secs: u64,
    /// How long a client may take to send its request headers.
    #[arg(long, value_name = "SECS", default_value_t = 10)]
    pub header_read_timeout_secs: u64,
    /// Connections open at once; further clients wait in the accept
    /// backlog.
    #[arg(long, value_name = "N", default_value_t = 1024)]
    pub max_connections: usize,
    /// An origin browsers may call from (repeatable); `*` allows any.
    #[arg(long, value_name = "ORIGIN")]
    pub cors_allow_origin: Vec<String>,
    /// How long in-flight requests may run after SIGINT/SIGTERM before they
    /// are dropped.
    #[arg(long, value_name = "SECS", default_value_t = 30)]
    pub shutdown_grace_secs: u64,
    /// `SQLite` metadata: the database's hard size cap. Writes that add data
    /// stop at a reserve below it; reads and pruning keep working.
    #[arg(long, value_name = "N", default_value_t = DEFAULT_SQLITE_MAX_BYTES)]
    pub sqlite_max_bytes: u64,
    /// Log line format.
    #[arg(long, value_enum, default_value_t = LogFormat::Text)]
    pub log_format: LogFormat,
}

/// Why `serve` refuses to start: the message for stderr and the exit code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError {
    /// An [`exit`] code.
    pub code: u8,
    /// What to tell the operator.
    pub message: String,
}

impl ConfigError {
    pub(crate) fn new(code: u8, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ConfigError {}

/// The metadata store to open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetaChoice {
    /// `FsLayoutStore` over the served root.
    FsLayout,
    /// `SqlKvStore` over this file, capped by `capacity`.
    Sqlite {
        /// The database file, canonical (its directory resolved), as the
        /// root's marker records it.
        path: PathBuf,
        /// Its size cap.
        capacity: Capacity,
    },
}

/// A resolved, validated `serve` configuration.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ServeConfig {
    /// Where to listen.
    pub listen: SocketAddr,
    /// The canonical served root.
    pub repo_root: PathBuf,
    /// The metadata store.
    pub meta: MetaChoice,
    /// The pipeline's settings (auth, addressing, limits, quota).
    pub pipeline: PipelineConfig,
    /// The router's layers.
    pub router: RouterOptions,
    /// The listener: connection cap, header-read timeout, HTTP/2
    /// keepalive and the shutdown grace period.
    pub serve: ServeOptions,
    /// Log line format.
    pub log_format: LogFormat,
}

impl ServeConfig {
    /// Whether every caller is accepted unauthenticated
    /// (`--unsafe-allow-any-peer`).
    #[must_use]
    pub fn is_open(&self) -> bool {
        matches!(self.pipeline.auth, AuthMode::Open)
    }
}

/// The banner `--unsafe-allow-any-peer` prints, as `mkit serve --http`
/// printed it.
pub const UNSAFE_BANNER: &str = "\
============================================================
WARNING: mkit-server serve --unsafe-allow-any-peer
This HTTP listener accepts ANY caller with NO authentication.
Every RPC — including ref writes and pack uploads — is open.
Use this only for local development, NEVER in production.
============================================================";

const PREFIX: &str = "mkit-server serve";

/// The auth mode the flags choose, fail-closed as `mkit serve --http`
/// (`serve/http.rs`): a token and the unsafe flag exclude each other, an
/// empty token is refused, and with neither nothing binds.
fn resolve_auth(
    args: &ServeArgs,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<AuthMode, ConfigError> {
    let token = match &args.bearer_token_file {
        Some(path) => Some(read_token(path)?),
        None => env(TOKEN_ENV),
    };
    let usage = |m: String| Err(ConfigError::new(exit::USAGE, m));
    match (args.auth, token, args.unsafe_allow_any_peer) {
        (_, Some(_), true) => usage(format!(
            "{PREFIX}: --bearer-token-file (or {TOKEN_ENV}) and --unsafe-allow-any-peer are \
             mutually exclusive"
        )),
        (Some(_), None, true) => usage(format!(
            "{PREFIX}: --auth and --unsafe-allow-any-peer are mutually exclusive"
        )),
        (None, None, true) => Ok(AuthMode::Open),
        (Some(AuthArg::AuthV2), Some(_), false) => usage(format!(
            "{PREFIX}: a bearer token (--bearer-token-file or {TOKEN_ENV}) cannot be combined \
             with --auth auth-v2"
        )),
        (Some(AuthArg::AuthV2), None, false) => {
            let Some(audience) = &args.audience else {
                return usage(format!(
                    "{PREFIX}: --auth auth-v2 requires --audience <ORIGIN>"
                ));
            };
            AuthV2Config::new(audience.clone(), args.repository.clone())
                .map(AuthMode::AuthV2)
                .map_err(|e| {
                    ConfigError::new(
                        exit::CONFIG_ERROR,
                        format!("{PREFIX}: --audience {audience:?}: {e}"),
                    )
                })
        }
        (_, Some(token), false) if token.is_empty() => Err(ConfigError::new(
            exit::CONFIG_ERROR,
            format!("{PREFIX}: bearer token MUST NOT be empty; refusing to bind"),
        )),
        (_, Some(token), false) => Ok(AuthMode::Bearer {
            token: Redacted::new(token),
        }),
        (_, None, false) => Err(ConfigError::new(
            exit::CONFIG_ERROR,
            format!(
                "{PREFIX}: refusing to bind without a bearer token.\n\
                 Pass --bearer-token-file <PATH> (or set {TOKEN_ENV}) to require it on every \
                 RPC, --auth auth-v2 to require signed writes, or --unsafe-allow-any-peer to \
                 accept any caller (development only)."
            ),
        )),
    }
}

/// The token in `path`, without one trailing newline. On Unix the file
/// must be a regular file (not a symlink) readable by its owner only.
fn read_token(path: &Path) -> Result<String, ConfigError> {
    check_secret_file(path)?;
    let text = std::fs::read_to_string(path).map_err(|e| {
        ConfigError::new(
            exit::CONFIG_ERROR,
            format!(
                "{PREFIX}: cannot read --bearer-token-file {}: {e}",
                path.display()
            ),
        )
    })?;
    let text = text.strip_suffix('\n').unwrap_or(&text);
    Ok(text.strip_suffix('\r').unwrap_or(text).to_owned())
}

/// Refuse a secret file that is a symlink, not a regular file, or (on
/// Unix) readable or writable by group or others.
fn check_secret_file(path: &Path) -> Result<(), ConfigError> {
    let refuse = |why: String| {
        Err(ConfigError::new(
            exit::CONFIG_ERROR,
            format!("{PREFIX}: --bearer-token-file {}: {why}", path.display()),
        ))
    };
    let meta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) => return refuse(e.to_string()),
    };
    if meta.file_type().is_symlink() {
        return refuse("is a symlink; point the flag at the file itself".to_owned());
    }
    if !meta.is_file() {
        return refuse("is not a regular file".to_owned());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return refuse(format!(
                "is accessible by group or others (mode {mode:o}); run `chmod 600 {}`",
                path.display()
            ));
        }
    }
    Ok(())
}

/// `path` with its directory resolved, as the marker records it: the same
/// database named relatively from another directory, or through a
/// symlinked directory, gets the same path.
fn canonical_db_path(path: &Path) -> Result<PathBuf, ConfigError> {
    let fail = |why: &str| {
        ConfigError::new(
            exit::CONFIG_ERROR,
            format!("{PREFIX}: --meta sqlite:{}: {why}", path.display()),
        )
    };
    let name = path.file_name().ok_or_else(|| fail("names no file"))?;
    let dir = match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    };
    let dir = std::fs::canonicalize(dir).map_err(|e| fail(&format!("its directory: {e}")))?;
    let canonical = dir.join(name);
    if canonical.to_str().is_none_or(|s| s.contains(['\n', '\r'])) {
        return Err(fail("the path must be UTF-8 without line breaks"));
    }
    Ok(canonical)
}

/// Resolve `path` as `mkit serve` resolves its root
/// (`mkit-cli` `serve::resolve_repo_path`): it must exist (`NOINPUT`), be a
/// directory holding `.mkit` (`DATAERR`), and lie under
/// `MKIT_SERVE_ROOT` when that is set (`NOPERM`).
///
/// # Errors
/// As above, with a message naming the path.
pub fn resolve_repo_root(
    path: &Path,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<PathBuf, ConfigError> {
    let shown = path.display();
    let resolved = std::fs::canonicalize(path).map_err(|e| {
        ConfigError::new(exit::NOINPUT, format!("{PREFIX}: --repo-root {shown}: {e}"))
    })?;
    if !resolved.is_dir() || !resolved.join(".mkit").is_dir() {
        return Err(ConfigError::new(
            exit::DATAERR,
            format!("{PREFIX}: --repo-root {shown} is not a directory holding .mkit"),
        ));
    }
    if let Some(root) = env(SERVE_ROOT_ENV) {
        let outside = || {
            ConfigError::new(
                exit::NOPERM,
                format!("{PREFIX}: --repo-root {shown} lies outside {SERVE_ROOT_ENV}"),
            )
        };
        let pinned = std::fs::canonicalize(&root).map_err(|_| outside())?;
        if !resolved.starts_with(&pinned) {
            return Err(outside());
        }
    }
    Ok(resolved)
}

fn cors_policy(origins: &[String]) -> Result<CorsPolicy, ConfigError> {
    if origins.is_empty() {
        return Ok(CorsPolicy::Disabled);
    }
    if origins.iter().any(|o| o == "*") {
        return Ok(CorsPolicy::AllowAny);
    }
    origins
        .iter()
        .map(|o| {
            HeaderValue::from_str(o).map_err(|_| {
                ConfigError::new(
                    exit::USAGE,
                    format!("{PREFIX}: --cors-allow-origin {o:?} is not a header value"),
                )
            })
        })
        .collect::<Result<_, _>>()
        .map(CorsPolicy::AllowOrigins)
}

/// Resolve `args`, reading environment variables through `env`. Nothing
/// is opened or written: [`crate::server::open`] does that.
///
/// # Errors
/// A [`ConfigError`] with its exit code: see [`exit`].
pub fn resolve(
    args: &ServeArgs,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<ServeConfig, ConfigError> {
    let usage = |m: &str| ConfigError::new(exit::USAGE, format!("{PREFIX}: {m}"));
    if args.max_concurrency == 0 || args.max_connections == 0 {
        return Err(usage(
            "--max-concurrency and --max-connections must be at least 1",
        ));
    }
    if args.header_read_timeout_secs == 0 {
        return Err(usage("--header-read-timeout-secs must be at least 1"));
    }
    if args.unary_timeout_secs == 0 || args.stream_timeout_secs == 0 {
        return Err(usage("timeouts must be at least 1 second"));
    }
    let auth = resolve_auth(args, env)?;
    let meta = match (&args.meta, &auth) {
        (Some(MetaArg::Sqlite(path)), _) => MetaChoice::Sqlite {
            path: canonical_db_path(path)?,
            capacity: Capacity::new(args.sqlite_max_bytes),
        },
        (_, AuthMode::AuthV2(_)) => {
            return Err(ConfigError::new(
                exit::CONFIG_ERROR,
                format!(
                    "{PREFIX}: --auth auth-v2 requires --meta sqlite:<PATH>: the replay ledger \
                     and write quota need a transactional store, which the fs-layout ref \
                     files are not"
                ),
            ));
        }
        (Some(MetaArg::FsLayout) | None, _) => MetaChoice::FsLayout,
    };
    let repo_root = resolve_repo_root(&args.repo_root, env)?;
    let name = RepoName::new(args.repository.clone())
        .map_err(|_| usage(&format!("--repository {:?} is invalid", args.repository)))?;
    let repo = RepoId {
        namespace: NamespaceKey::deployment_default(),
        name,
    };
    let max_pack = args
        .max_pack_bytes
        .unwrap_or(mkit_core::protocol::PACK_BODY_LIMIT);
    let limits = UploadLimits {
        max_total_bytes: max_pack,
        max_chunks: u32::MAX,
    };
    // `new` sets the default write quota for auth v2 only.
    let pipeline = PipelineConfig::new(Addressing::Single { repo }, auth, limits);
    let router = RouterOptions {
        unary_timeout: Duration::from_secs(args.unary_timeout_secs),
        stream_timeout: Duration::from_secs(args.stream_timeout_secs),
        max_concurrency: args.max_concurrency,
        queue_timeout: Duration::from_secs(args.queue_timeout_secs),
        max_body_bytes: body_limit_for(max_pack),
        cors: cors_policy(&args.cors_allow_origin)?,
        redactor: pipeline.redactor.clone(),
        ..RouterOptions::default()
    };
    Ok(ServeConfig {
        listen: args.listen,
        repo_root,
        meta,
        pipeline,
        router,
        serve: ServeOptions {
            grace: Duration::from_secs(args.shutdown_grace_secs),
            header_read_timeout: Duration::from_secs(args.header_read_timeout_secs),
            max_connections: args.max_connections,
            ..ServeOptions::default()
        },
        log_format: args.log_format,
    })
}
