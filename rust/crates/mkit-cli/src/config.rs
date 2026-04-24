//! `.mkit/config` parser / writer and XDG path helpers.
//!
//! On-disk format: `key = value`, one per line, lines starting with `#`
//! ignored. User-facing short-hand values for `user.identity`:
//! `ed25519:<hex>`, `mid:<u64>`, or raw `[kind][len][bytes]` hex.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use thiserror::Error;

pub const CONFIG_FILE: &str = ".mkit/config";
pub const DEFAULT_SIGNING_KEY: &str = ".mkit/keys/default.key";
pub const DEFAULT_BRANCH: &str = "main";

/// Full in-memory representation of `.mkit/config`. All fields default
/// to empty / documented defaults; readers that want a known-good
/// default file should call [`read_or_default`].
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

/// Read `<root>/.mkit/config`. If the file is missing, returns a
/// defaulted `Config`. Malformed lines are tolerated (skipped) — the
/// CLI has to cope with hand-edited files.
pub fn read_or_default(root: &Path) -> Result<Config, ConfigError> {
    let path = root.join(CONFIG_FILE);
    let text = match fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Config::with_defaults()),
        Err(e) => return Err(e.into()),
    };
    let mut cfg = Config::with_defaults();
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let key = k.trim();
        let val = v.trim().to_owned();
        match key {
            "user.identity" => cfg.user_identity = val,
            "signing_key" => cfg.signing_key = val,
            "default_branch" => cfg.default_branch = val,
            "remote_endpoint" => cfg.remote_endpoint = val,
            "remote_bucket" => cfg.remote_bucket = val,
            "remote_type" => cfg.remote_type = val,
            "ssh.strict_host_key_checking" => cfg.ssh_strict_host_key_checking = val,
            "ssh.user_known_hosts_file" => cfg.ssh_user_known_hosts_file = val,
            "ssh.identity_file" => cfg.ssh_identity_file = val,
            // Legacy keys — silently ignored so 0.1.x configs keep working.
            "author_mid" | "project_id" | "network" => {}
            _ if key.ends_with("_url") => {} // legacy keys retired upstream
            _ => {}                          // unknown keys: tolerate on read
        }
    }
    Ok(cfg)
}

/// Write the given `Config` to `<root>/.mkit/config` atomically. Only
/// non-empty fields are serialised so a fresh repo's config file stays
/// minimal.
pub fn write(root: &Path, cfg: &Config) -> Result<(), ConfigError> {
    let path = root.join(CONFIG_FILE);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut out = String::new();
    for (k, v) in [
        ("user.identity", cfg.user_identity.as_str()),
        ("signing_key", cfg.signing_key.as_str()),
        ("default_branch", cfg.default_branch.as_str()),
        ("remote_endpoint", cfg.remote_endpoint.as_str()),
        ("remote_bucket", cfg.remote_bucket.as_str()),
        ("remote_type", cfg.remote_type.as_str()),
        (
            "ssh.strict_host_key_checking",
            cfg.ssh_strict_host_key_checking.as_str(),
        ),
        (
            "ssh.user_known_hosts_file",
            cfg.ssh_user_known_hosts_file.as_str(),
        ),
        ("ssh.identity_file", cfg.ssh_identity_file.as_str()),
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
    // Raw hex — validate shape (kind + 2 len bytes + payload).
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

    #[test]
    fn read_default_when_missing() {
        let td = TempDir::new().unwrap();
        let cfg = read_or_default(td.path()).unwrap();
        assert_eq!(cfg.signing_key, DEFAULT_SIGNING_KEY);
        assert_eq!(cfg.default_branch, DEFAULT_BRANCH);
        assert!(cfg.remote_endpoint.is_empty());
    }

    #[test]
    fn roundtrip_config() {
        let td = TempDir::new().unwrap();
        fs::create_dir_all(td.path().join(".mkit")).unwrap();
        let mut cfg = Config::with_defaults();
        cfg.remote_endpoint = "/tmp/mirror".into();
        cfg.remote_type = "file".into();
        write(td.path(), &cfg).unwrap();
        let back = read_or_default(td.path()).unwrap();
        assert_eq!(back.remote_endpoint, "/tmp/mirror");
        assert_eq!(back.remote_type, "file");
    }

    #[test]
    fn expand_user_identity_ed25519() {
        let hex = "11".repeat(32);
        let out = expand_user_identity(&format!("ed25519:{hex}")).unwrap();
        // 0x01 + LE len(32=0x20,0x00) + 32 bytes -> 3+32=35 bytes -> 70 hex
        assert_eq!(out.len(), 70);
        assert!(out.starts_with("012000"));
    }

    #[test]
    fn expand_user_identity_mid() {
        let out = expand_user_identity("mid:42").unwrap();
        // 0x03 + LE(8=0x08,0x00) + 8 bytes LE(42)
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
    fn legacy_keys_are_ignored() {
        let td = TempDir::new().unwrap();
        fs::create_dir_all(td.path().join(".mkit")).unwrap();
        fs::write(
            td.path().join(CONFIG_FILE),
            "project_id = xyz\nauthor_mid = 5\nsigning_key = /keys/x\n",
        )
        .unwrap();
        let cfg = read_or_default(td.path()).unwrap();
        assert_eq!(cfg.signing_key, "/keys/x");
    }
}
