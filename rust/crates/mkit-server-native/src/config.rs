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

/// Where the packs live (`--blob`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlobArg {
    /// Files under the served root, `<DIR>/packs/<64-hex>`.
    Fs,
    /// An S3-compatible bucket (`s3://<BUCKET>[/<PREFIX>]`).
    S3 {
        /// The bucket.
        bucket: String,
        /// The key prefix, without a trailing `/`.
        prefix: Option<String>,
    },
}

impl FromStr for BlobArg {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        if s == "fs" {
            return Ok(Self::Fs);
        }
        let Some(rest) = s.strip_prefix("s3://") else {
            return Err(format!(
                "expected fs or s3://<BUCKET>[/<PREFIX>], got {s:?}"
            ));
        };
        let rest = rest.strip_suffix('/').unwrap_or(rest);
        let (bucket, prefix) = match rest.split_once('/') {
            Some((bucket, prefix)) => (bucket, Some(prefix.to_owned())),
            None => (rest, None),
        };
        if bucket.is_empty() {
            return Err(format!("{s:?} names no bucket"));
        }
        Ok(Self::S3 {
            bucket: bucket.to_owned(),
            prefix,
        })
    }
}

/// The S3 access key id's environment variable: the one the
/// `mkit+s3://` client transport reads (`SPEC-CONFIG-SECURITY`).
pub const S3_ACCESS_KEY_ENV: &str = "MKIT_R2_ACCESS_KEY_ID";
/// The S3 secret access key's environment variable.
pub const S3_SECRET_KEY_ENV: &str = "MKIT_R2_SECRET_ACCESS_KEY";
/// The AWS-standard fallback for [`S3_ACCESS_KEY_ENV`].
pub const AWS_ACCESS_KEY_ENV: &str = "AWS_ACCESS_KEY_ID";
/// The AWS-standard fallback for [`S3_SECRET_KEY_ENV`].
pub const AWS_SECRET_KEY_ENV: &str = "AWS_SECRET_ACCESS_KEY";
/// Temporary AWS credentials, which the signer cannot send.
pub const AWS_SESSION_TOKEN_ENV: &str = "AWS_SESSION_TOKEN";

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
    /// Where packs live: `fs` (`<DIR>/packs`) or `s3://<BUCKET>[/<PREFIX>]`,
    /// an S3-compatible bucket that honors `If-None-Match: *` (needs
    /// `--s3-endpoint`, `--meta sqlite:<PATH>`, and credentials from
    /// `MKIT_R2_ACCESS_KEY_ID`/`MKIT_R2_SECRET_ACCESS_KEY`, the `AWS_*`
    /// pair, or `--s3-credentials-file`).
    #[arg(long, value_name = "fs|s3://BUCKET[/PREFIX]", default_value = "fs")]
    pub blob: BlobArg,
    /// The S3 API origin, e.g. `https://<account>.r2.cloudflarestorage.com`
    /// (no path: buckets are addressed path-style).
    #[arg(long, value_name = "URL")]
    pub s3_endpoint: Option<String>,
    /// The region S3 requests are signed for (`auto` for R2).
    #[arg(long, value_name = "REGION", default_value = "auto")]
    pub s3_region: String,
    /// A file of `KEY=VALUE` lines setting the S3 credential variables
    /// (owner-only, as `--bearer-token-file`); the environment is then not
    /// read for them.
    #[arg(long, value_name = "PATH")]
    pub s3_credentials_file: Option<PathBuf>,
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
    /// Close a connection (HTTP/2 or HTTP/1.1 keep-alive) that has had no
    /// request in flight for this long.
    #[arg(long, value_name = "SECS", default_value_t = 60)]
    pub idle_timeout_secs: u64,
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

/// The blob store to open. `Debug` redacts the S3 secret key.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum BlobChoice {
    /// `FsBlobStore` under the served root.
    Fs,
    /// `S3BlobStore` over this bucket.
    #[cfg(feature = "s3")]
    S3(Box<crate::s3::S3Config>),
}

impl fmt::Display for BlobChoice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fs => f.write_str("fs"),
            #[cfg(feature = "s3")]
            Self::S3(cfg) => {
                write!(f, "s3://{}", cfg.bucket)?;
                if let Some(prefix) = &cfg.prefix {
                    write!(f, "/{prefix}")?;
                }
                write!(f, " at {}", cfg.endpoint)
            }
        }
    }
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
    /// The blob store.
    pub blob: BlobChoice,
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

/// The token in `path`, without one trailing newline. The file is opened
/// once, without following a symlink (`O_NOFOLLOW`, and `O_NONBLOCK` so a
/// FIFO cannot stall startup), and the checks run on the open handle
/// (`fstat`): it must be a regular file, on Unix readable by its owner
/// only. Nothing can swap the file between the check and the read.
fn read_token(path: &Path) -> Result<String, ConfigError> {
    let text = read_secret_file(path, "--bearer-token-file", TOKEN_ENV)?;
    let text = text.strip_suffix('\n').unwrap_or(&text);
    Ok(text.strip_suffix('\r').unwrap_or(text).to_owned())
}

/// The whole of the secret file `path`, given by `flag`, opened and checked
/// as described at [`read_token`]; `env_hint` names the environment
/// alternative. Error messages never quote its contents.
fn read_secret_file(path: &Path, flag: &str, env_hint: &str) -> Result<String, ConfigError> {
    use std::io::Read as _;

    let refuse = |why: String| {
        ConfigError::new(
            exit::CONFIG_ERROR,
            format!("{PREFIX}: {flag} {}: {why}", path.display()),
        )
    };
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let mut file = options.open(path).map_err(|e| {
        #[cfg(unix)]
        if e.raw_os_error() == Some(libc::ELOOP) {
            return refuse(format!(
                "is a symlink; point the flag at the file itself, or pass a symlinked secret \
                 mount (e.g. Kubernetes) through {env_hint}"
            ));
        }
        refuse(e.to_string())
    })?;
    let meta = file.metadata().map_err(|e| refuse(e.to_string()))?;
    if !meta.is_file() {
        return Err(refuse("is not a regular file".to_owned()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(refuse(format!(
                "is accessible by group or others (mode {mode:o}); run `chmod 600 {}`",
                path.display()
            )));
        }
    }
    let mut text = String::new();
    file.read_to_string(&mut text)
        .map_err(|e| refuse(format!("cannot read it: {e}")))?;
    Ok(text)
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

/// The blob store `--blob` names, with its S3 settings checked.
fn resolve_blob(
    args: &ServeArgs,
    meta: &MetaChoice,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<BlobChoice, ConfigError> {
    let usage = |m: &str| ConfigError::new(exit::USAGE, format!("{PREFIX}: {m}"));
    let (bucket, prefix) = match &args.blob {
        BlobArg::Fs => {
            if args.s3_endpoint.is_some() || args.s3_credentials_file.is_some() {
                return Err(usage(
                    "--s3-endpoint and --s3-credentials-file need --blob s3://<BUCKET>",
                ));
            }
            return Ok(BlobChoice::Fs);
        }
        BlobArg::S3 { bucket, prefix } => (bucket, prefix),
    };
    if *meta == MetaChoice::FsLayout {
        return Err(ConfigError::new(
            exit::CONFIG_ERROR,
            format!(
                "{PREFIX}: --blob s3 requires --meta sqlite:<PATH>: fs-layout ref files are \
                 shared with local mkit commands, which read packs from <DIR>/packs"
            ),
        ));
    }
    s3_choice(args, bucket, prefix.as_deref(), env)
}

#[cfg(not(feature = "s3"))]
fn s3_choice(
    _args: &ServeArgs,
    _bucket: &str,
    _prefix: Option<&str>,
    _env: &dyn Fn(&str) -> Option<String>,
) -> Result<BlobChoice, ConfigError> {
    Err(ConfigError::new(
        exit::CONFIG_ERROR,
        format!("{PREFIX}: --blob s3: this mkit-server was built without the `s3` feature"),
    ))
}

#[cfg(feature = "s3")]
fn s3_choice(
    args: &ServeArgs,
    bucket: &str,
    prefix: Option<&str>,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<BlobChoice, ConfigError> {
    let invalid = |m: String| ConfigError::new(exit::CONFIG_ERROR, format!("{PREFIX}: {m}"));
    let Some(endpoint) = &args.s3_endpoint else {
        return Err(ConfigError::new(
            exit::USAGE,
            format!("{PREFIX}: --blob s3://… requires --s3-endpoint <URL>"),
        ));
    };
    let endpoint: url::Url = endpoint
        .parse()
        .map_err(|e| invalid(format!("--s3-endpoint {endpoint:?}: {e}")))?;
    let (access_key_id, secret_access_key) = s3_credentials(args, env)?;
    let cfg = crate::s3::S3Config {
        endpoint,
        bucket: bucket.to_owned(),
        prefix: prefix.map(str::to_owned),
        credentials: crate::s3::Credentials {
            access_key_id,
            secret_access_key,
            region: args.s3_region.clone(),
        },
    };
    cfg.validate()
        .map_err(|e| invalid(format!("--blob s3: {e}")))?;
    Ok(BlobChoice::S3(Box::new(cfg)))
}

/// The S3 access key pair: from `--s3-credentials-file` if given, else the
/// environment; [`S3_ACCESS_KEY_ENV`]/[`S3_SECRET_KEY_ENV`] first, then
/// the `AWS_*` pair. A pair is taken whole from one source. Temporary AWS
/// credentials are refused: the signer does not send
/// `x-amz-security-token`. Never taken from the command line.
#[cfg(feature = "s3")]
fn s3_credentials(
    args: &ServeArgs,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<(String, String), ConfigError> {
    let refuse = |m: String| ConfigError::new(exit::CONFIG_ERROR, format!("{PREFIX}: {m}"));
    let file_vars = match &args.s3_credentials_file {
        Some(path) => Some(parse_env_file(path)?),
        None => None,
    };
    let lookup = |name: &str| match &file_vars {
        Some(vars) => vars.get(name).cloned(),
        None => env(name),
    };
    let source = match &args.s3_credentials_file {
        Some(path) => format!("--s3-credentials-file {}", path.display()),
        None => "the environment".to_owned(),
    };
    for (id, secret) in [
        (S3_ACCESS_KEY_ENV, S3_SECRET_KEY_ENV),
        (AWS_ACCESS_KEY_ENV, AWS_SECRET_KEY_ENV),
    ] {
        match (lookup(id), lookup(secret)) {
            (None, None) => {}
            (Some(id_value), Some(secret_value)) => {
                if id_value.is_empty() || secret_value.is_empty() {
                    return Err(refuse(format!("{id} and {secret} in {source} are empty")));
                }
                if id == AWS_ACCESS_KEY_ENV && lookup(AWS_SESSION_TOKEN_ENV).is_some() {
                    return Err(refuse(format!(
                        "{source} sets {AWS_SESSION_TOKEN_ENV}: temporary credentials are not \
                         supported; use a long-lived access key"
                    )));
                }
                return Ok((id_value, secret_value));
            }
            _ => {
                return Err(refuse(format!(
                    "{source} sets only one of {id} and {secret}"
                )));
            }
        }
    }
    Err(refuse(format!(
        "--blob s3 needs credentials: set {S3_ACCESS_KEY_ENV} and {S3_SECRET_KEY_ENV} (or \
         {AWS_ACCESS_KEY_ENV} and {AWS_SECRET_KEY_ENV}) in {source}"
    )))
}

/// The `KEY=VALUE` lines of the secret file `path` (systemd
/// `EnvironmentFile` syntax: blank lines and `#` comments skipped, an
/// optional `export `, values optionally in matching quotes). Errors name
/// the line number, never its contents.
#[cfg(feature = "s3")]
fn parse_env_file(path: &Path) -> Result<std::collections::HashMap<String, String>, ConfigError> {
    let text = read_secret_file(
        path,
        "--s3-credentials-file",
        &format!("{S3_ACCESS_KEY_ENV}/{S3_SECRET_KEY_ENV}"),
    )?;
    let mut vars = std::collections::HashMap::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((name, value)) = line.split_once('=') else {
            return Err(ConfigError::new(
                exit::CONFIG_ERROR,
                format!(
                    "{PREFIX}: --s3-credentials-file {}: line {} is not KEY=VALUE",
                    path.display(),
                    n + 1
                ),
            ));
        };
        let value = value.trim();
        let unquoted = ['"', '\'']
            .iter()
            .find_map(|q| value.strip_prefix(*q)?.strip_suffix(*q))
            .unwrap_or(value);
        vars.insert(name.trim().to_owned(), unquoted.to_owned());
    }
    Ok(vars)
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
    if args.header_read_timeout_secs == 0 || args.idle_timeout_secs == 0 {
        return Err(usage(
            "--header-read-timeout-secs and --idle-timeout-secs must be at least 1",
        ));
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
    let blob = resolve_blob(args, &meta, env)?;
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
        blob,
        pipeline,
        router,
        serve: ServeOptions {
            grace: Duration::from_secs(args.shutdown_grace_secs),
            header_read_timeout: Duration::from_secs(args.header_read_timeout_secs),
            max_connections: args.max_connections,
            idle_timeout: Duration::from_secs(args.idle_timeout_secs),
            ..ServeOptions::default()
        },
        log_format: args.log_format,
    })
}
