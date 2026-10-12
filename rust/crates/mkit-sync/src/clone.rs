//! Cloning: create a repository whose config names a remote, then pull.

use std::io::Write as _;
use std::path::Path;

use mkit_core::layout::{DiscoverError, RepoLayout};
use mkit_core::refs::{self, RefError};
use mkit_core::store::{ObjectStore, StoreError};

use crate::SyncOptions;
use crate::error::SyncError;
use crate::observer::SyncObserver;
use crate::pull::{PullReport, pull};
use crate::source::RemoteSource;

/// The name of the implicit flat remote, spelled `remote_endpoint` /
/// `remote_type` in the repository config.
pub const DEFAULT_REMOTE_NAME: &str = "default";

/// The branch a new repository's config names as its default.
const DEFAULT_BRANCH: &str = "main";

/// The remote a clone records in the new repository's config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloneRemote {
    /// The remote's name. [`DEFAULT_REMOTE_NAME`] selects the flat
    /// `remote_endpoint` / `remote_type` keys; any other name becomes a
    /// `remote.<name>.url` / `.type` entry. The caller validates the name and
    /// the URL (no control characters, a legal ref name).
    pub name: String,
    pub url: String,
    /// The transport kind (`file`, `http`, `s3`, `ssh`, ...), empty if unknown.
    pub kind: String,
}

/// Why preparing the clone destination failed.
#[derive(Debug, thiserror::Error)]
pub enum CloneInitError {
    #[error("create {path}: {source}")]
    CreateDir {
        path: String,
        source: std::io::Error,
    },
    #[error("worktree discovery: {0}")]
    Discover(#[from] DiscoverError),
    #[error("already a mkit repository")]
    AlreadyInitialized,
    /// The remote name, URL or kind cannot be written to the config safely.
    #[error("invalid remote: {0}")]
    InvalidRemote(String),
    #[error("init: {0}")]
    Store(StoreError),
    #[error("refs init: {0}")]
    Refs(RefError),
    #[error("write config: I/O: {0}")]
    WriteConfig(std::io::Error),
}

/// Create `dir`, initialise an empty repository in it and write its config
/// with `remote` recorded. Nothing is fetched. A failure leaves whatever was
/// created so far in place, exactly like a failed `git clone`.
pub fn init_clone_dir(dir: &Path, remote: &CloneRemote) -> Result<RepoLayout, CloneInitError> {
    validate_remote(remote)?;
    std::fs::create_dir_all(dir).map_err(|source| CloneInitError::CreateDir {
        path: dir.display().to_string(),
        source,
    })?;
    let layout = mkit_core::layout::discover(dir)?;
    match ObjectStore::init(&layout) {
        Ok(_) => {}
        Err(StoreError::AlreadyInitialized) => return Err(CloneInitError::AlreadyInitialized),
        Err(e) => return Err(CloneInitError::Store(e)),
    }
    refs::init(&layout).map_err(CloneInitError::Refs)?;
    write_config(&layout, remote).map_err(CloneInitError::WriteConfig)?;
    Ok(layout)
}

/// Refuse values that would corrupt or inject into the config file, before
/// anything is created. The config is `key = value` lines written raw, so a
/// control character in any value would add lines of the caller's choosing.
fn validate_remote(remote: &CloneRemote) -> Result<(), CloneInitError> {
    let invalid = |what: &str| Err(CloneInitError::InvalidRemote(what.to_owned()));
    for (what, value) in [
        ("name", &remote.name),
        ("url", &remote.url),
        ("kind", &remote.kind),
    ] {
        if value.chars().any(char::is_control) {
            return invalid(&format!("{what} contains control characters"));
        }
    }
    if remote.name != DEFAULT_REMOTE_NAME
        && (!refs::validate_ref_name(&remote.name) || remote.name.contains('.'))
    {
        return invalid("name must be `default` or a dot-free ref-safe name");
    }
    Ok(())
}

/// Render the repository config a clone writes.
fn render_config(remote: &CloneRemote) -> String {
    use std::fmt::Write as _;
    let (url_key, kind_key) = if remote.name == DEFAULT_REMOTE_NAME {
        ("remote_endpoint".to_owned(), "remote_type".to_owned())
    } else {
        (
            format!("remote.{}.url", remote.name),
            format!("remote.{}.type", remote.name),
        )
    };
    let mut out = format!("default_branch = {DEFAULT_BRANCH}\n");
    if !remote.url.is_empty() {
        let _ = writeln!(out, "{url_key} = {}", remote.url);
    }
    if !remote.kind.is_empty() {
        let _ = writeln!(out, "{kind_key} = {}", remote.kind);
    }
    out
}

/// Atomic replace: write a sibling temp file then rename over the target, so
/// a crash mid-write can never leave a truncated config.
fn write_config(layout: &RepoLayout, remote: &CloneRemote) -> std::io::Result<()> {
    let path = layout.config_file();
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;
    let mut tmp = tempfile::Builder::new()
        .prefix(".config.")
        .tempfile_in(parent)?;
    tmp.write_all(render_config(remote).as_bytes())?;
    tmp.flush()?;
    tmp.persist(&path).map_err(|e| e.error)?;
    Ok(())
}

/// What a clone did.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CloneReport {
    pub layout_root: std::path::PathBuf,
    pub pull: PullReport,
}

/// Why a clone failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CloneError {
    #[error(transparent)]
    Init(#[from] CloneInitError),
    #[error(transparent)]
    Sync(#[from] SyncError),
}

/// Initialise `dir` and pull the remote into it: [`init_clone_dir`] followed
/// by [`pull`], with the new remote's name as the tracking namespace.
pub fn clone(
    dir: &Path,
    source: &dyn RemoteSource,
    remote: &CloneRemote,
    options: &SyncOptions,
    observer: &dyn SyncObserver,
) -> Result<CloneReport, CloneError> {
    let layout = init_clone_dir(dir, remote)?;
    let report = pull(dir, source, &remote.name, options, observer)?;
    Ok(CloneReport {
        layout_root: layout.worktree_root().to_path_buf(),
        pull: report,
    })
}
