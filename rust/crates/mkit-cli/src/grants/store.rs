//! The user grant store (WP-2.13, R-155).
//!
//! One file per grant at `$XDG_CONFIG_HOME/mkit/grants/<grant id hex>.grant`,
//! holding the raw SPEC-WRITE-GRANTS §4.2 header value and nothing else;
//! everything else is derived by parsing. The directory is 0700 and each file
//! 0600, written atomically. The store is never repository-scoped: its
//! location comes from the XDG base directory alone, and it never reads a
//! repository path.
//!
//! Grants are not secret (§12: disclosing one is harmless), but a planted
//! file could steer grant selection, so every file is re-parsed and its owner
//! signature re-verified on load. A bad file costs one warning and is skipped.

use std::ffi::OsString;
use std::fs;
use std::io::{self, Read as _, Write as _};
use std::path::{Path, PathBuf};

use mkit_attest::grant::{Grant, OwnerScheme, RelyingParty};
use mkit_core::hash::to_hex_bytes;

use super::{HeaderError, verify_grant_header};

/// Most files the store loads.
pub const MAX_STORE_FILES: usize = 1024;
/// Largest file the store loads. A header is at most 8,192 bytes; this bound
/// leaves room for nothing else.
pub const MAX_STORE_FILE_BYTES: u64 = 16 * 1024;
const EXTENSION: &str = "grant";

/// A grant read back from the store, already verified.
#[derive(Debug, Clone)]
pub struct StoredGrant {
    pub id: [u8; 32],
    pub header: String,
    pub grant: Grant,
    pub scheme: OwnerScheme,
}

/// The result of loading the store: what verified, and one warning per
/// problem.
#[derive(Debug, Default)]
pub struct LoadReport {
    pub grants: Vec<StoredGrant>,
    pub warnings: Vec<String>,
}

/// What [`GrantStore::add`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddOutcome {
    Added,
    AlreadyStored,
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("grant store {path}: {source}")]
    Io { path: PathBuf, source: io::Error },
    #[error("{0}")]
    Rejected(#[from] HeaderError),
    #[error("{0}")]
    Unsafe(String),
    #[error(
        "the grant store already holds {MAX_STORE_FILES} grants; remove some with `mkit grant revoke --prune` or delete files under {0}"
    )]
    Full(PathBuf),
}

/// The user grant store.
#[derive(Debug, Clone)]
pub struct GrantStore {
    dir: PathBuf,
}

impl GrantStore {
    /// The store beside the user config. Derived from the XDG base directory
    /// only, so no repository configuration can relocate it.
    #[must_use]
    pub fn default_location() -> PathBuf {
        crate::config::xdg_config_home().join("mkit").join("grants")
    }

    #[must_use]
    pub fn open_default() -> Self {
        Self::at(Self::default_location())
    }

    #[must_use]
    pub fn at(dir: PathBuf) -> Self {
        Self { dir }
    }

    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Load and verify every grant, within the store bounds.
    #[must_use]
    pub fn load(&self, rps: &[RelyingParty]) -> LoadReport {
        self.load_bounded(rps, MAX_STORE_FILES, MAX_STORE_FILE_BYTES)
    }

    pub(crate) fn load_bounded(
        &self,
        rps: &[RelyingParty],
        max_files: usize,
        max_bytes: u64,
    ) -> LoadReport {
        let mut report = LoadReport::default();
        let meta = match fs::symlink_metadata(&self.dir) {
            Ok(meta) => meta,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return report,
            Err(e) => {
                report.warnings.push(format!(
                    "cannot read grant store {}: {e}",
                    self.dir.display()
                ));
                return report;
            }
        };
        if !meta.is_dir() {
            report.warnings.push(format!(
                "grant store {} is not a directory; ignoring it",
                self.dir.display()
            ));
            return report;
        }
        if let Some(problem) = writable_by_others(&meta) {
            report.warnings.push(format!(
                "refusing to load grant store {}: {problem}",
                self.dir.display()
            ));
            return report;
        }
        let mut names: Vec<OsString> = match fs::read_dir(&self.dir) {
            Ok(entries) => entries
                .filter_map(Result::ok)
                .map(|entry| entry.file_name())
                .filter(|name| Path::new(name).extension().is_some_and(|e| e == EXTENSION))
                .collect(),
            Err(e) => {
                report.warnings.push(format!(
                    "cannot list grant store {}: {e}",
                    self.dir.display()
                ));
                return report;
            }
        };
        names.sort();
        if names.len() > max_files {
            report.warnings.push(format!(
                "grant store {} holds {} grant files; loading the first {max_files} and skipping {}",
                self.dir.display(),
                names.len(),
                names.len() - max_files
            ));
            names.truncate(max_files);
        }
        for name in names {
            let path = self.dir.join(&name);
            match read_verified(&path, &name, rps, max_bytes) {
                Ok(grant) => report.grants.push(grant),
                Err(reason) => report
                    .warnings
                    .push(format!("skipping {}: {reason}", path.display())),
            }
        }
        report
    }

    /// Verify `header` and store it. Adding a grant that is already stored
    /// (same grant id, §3.4) changes nothing.
    ///
    /// # Errors
    /// The verifier's rule, an unsafe store directory, a full store, or I/O.
    pub fn add(&self, header: &str, rps: &[RelyingParty]) -> Result<AddOutcome, StoreError> {
        let verified = verify_grant_header(header, rps)?;
        self.ensure_dir()?;
        let path = self.dir.join(file_name(&verified.id));
        if let Ok(existing) = read_verified(
            &path,
            path.file_name().unwrap_or_default(),
            rps,
            MAX_STORE_FILE_BYTES,
        ) && existing.id == verified.id
        {
            return Ok(AddOutcome::AlreadyStored);
        }
        if !path.exists() && self.count_files() >= MAX_STORE_FILES {
            return Err(StoreError::Full(self.dir.clone()));
        }
        self.write_atomic(&path, header.as_bytes())?;
        Ok(AddOutcome::Added)
    }

    /// Delete the grant with `id`, if stored.
    ///
    /// # Errors
    /// I/O other than the file being absent.
    pub fn remove(&self, id: &[u8; 32]) -> Result<bool, StoreError> {
        let path = self.dir.join(file_name(id));
        match fs::remove_file(&path) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(source) => Err(StoreError::Io { path, source }),
        }
    }

    fn count_files(&self) -> usize {
        fs::read_dir(&self.dir).map_or(0, |entries| {
            entries
                .filter_map(Result::ok)
                .filter(|e| {
                    Path::new(&e.file_name())
                        .extension()
                        .is_some_and(|x| x == EXTENSION)
                })
                .count()
        })
    }

    fn ensure_dir(&self) -> Result<(), StoreError> {
        let io_err = |source| StoreError::Io {
            path: self.dir.clone(),
            source,
        };
        match fs::symlink_metadata(&self.dir) {
            Ok(meta) => {
                if !meta.is_dir() {
                    return Err(StoreError::Unsafe(format!(
                        "{} exists and is not a directory",
                        self.dir.display()
                    )));
                }
                if let Some(problem) = writable_by_others(&meta) {
                    return Err(StoreError::Unsafe(format!(
                        "refusing to use grant store {}: {problem}",
                        self.dir.display()
                    )));
                }
                Ok(())
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                if let Some(parent) = self.dir.parent() {
                    fs::create_dir_all(parent).map_err(io_err)?;
                }
                create_private_dir(&self.dir).map_err(io_err)
            }
            Err(e) => Err(io_err(e)),
        }
    }

    fn write_atomic(&self, path: &Path, bytes: &[u8]) -> Result<(), StoreError> {
        let io_err = |source| StoreError::Io {
            path: path.to_path_buf(),
            source,
        };
        // `NamedTempFile` creates the file 0600 and the rename is atomic, so
        // a reader sees the old state or the whole new file.
        let mut tmp = tempfile::NamedTempFile::new_in(&self.dir).map_err(io_err)?;
        tmp.write_all(bytes).map_err(io_err)?;
        tmp.as_file().sync_all().map_err(io_err)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            tmp.as_file()
                .set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(io_err)?;
        }
        tmp.persist(path).map_err(|e| io_err(e.error))?;
        if let Ok(dir) = fs::File::open(&self.dir) {
            let _ = dir.sync_all();
        }
        Ok(())
    }
}

fn file_name(id: &[u8; 32]) -> String {
    format!("{}.{EXTENSION}", to_hex_bytes(id))
}

fn read_verified(
    path: &Path,
    name: &std::ffi::OsStr,
    rps: &[RelyingParty],
    max_bytes: u64,
) -> Result<StoredGrant, String> {
    let meta = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !meta.file_type().is_file() {
        return Err("not a regular file".to_owned());
    }
    if meta.len() > max_bytes {
        return Err(format!("larger than {max_bytes} bytes"));
    }
    let mut bytes = Vec::new();
    fs::File::open(path)
        .and_then(|file| file.take(max_bytes + 1).read_to_end(&mut bytes))
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > max_bytes {
        return Err(format!("larger than {max_bytes} bytes"));
    }
    let header = String::from_utf8(bytes).map_err(|_| "not UTF-8".to_owned())?;
    let verified = verify_grant_header(&header, rps).map_err(|e| e.to_string())?;
    if Path::new(name).file_stem().and_then(|s| s.to_str()) != Some(&to_hex_bytes(&verified.id)) {
        return Err("file name is not the grant id".to_owned());
    }
    Ok(StoredGrant {
        id: verified.id,
        header,
        grant: verified.grant,
        scheme: verified.scheme,
    })
}

#[cfg(unix)]
fn create_private_dir(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt as _;
    fs::DirBuilder::new().mode(0o700).create(path)
}

#[cfg(not(unix))]
fn create_private_dir(path: &Path) -> io::Result<()> {
    fs::create_dir(path)
}

#[cfg(unix)]
fn writable_by_others(meta: &fs::Metadata) -> Option<&'static str> {
    use std::os::unix::fs::PermissionsExt as _;
    (meta.permissions().mode() & 0o022 != 0).then_some("it is group- or world-writable")
}

#[cfg(not(unix))]
fn writable_by_others(_meta: &fs::Metadata) -> Option<&'static str> {
    None
}

#[cfg(test)]
mod tests {
    use super::super::testutil::signed_grant;
    use super::*;

    const AUDIENCE: &str = "https://git.example.com";

    fn store() -> (tempfile::TempDir, GrantStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = GrantStore::at(dir.path().join("mkit").join("grants"));
        (dir, store)
    }

    fn id_of(header: &str) -> [u8; 32] {
        verify_grant_header(header, &[]).unwrap().id
    }

    #[test]
    fn add_then_load_round_trips_and_stores_only_the_header() {
        let (_tmp, store) = store();
        let header = signed_grant(1, 1, 0, AUDIENCE);
        assert_eq!(store.add(&header, &[]).unwrap(), AddOutcome::Added);
        let file = store.dir().join(file_name(&id_of(&header)));
        assert_eq!(fs::read_to_string(&file).unwrap(), header);
        let report = store.load(&[]);
        assert!(report.warnings.is_empty(), "{:?}", report.warnings);
        assert_eq!(report.grants.len(), 1);
        assert_eq!(report.grants[0].header, header);
        assert_eq!(report.grants[0].id, id_of(&header));
        // Nothing but the grant is left behind, temp files included.
        assert_eq!(fs::read_dir(store.dir()).unwrap().count(), 1);
    }

    #[test]
    fn adding_the_same_grant_id_twice_changes_nothing() {
        let (_tmp, store) = store();
        let header = signed_grant(1, 1, 0, AUDIENCE);
        assert_eq!(store.add(&header, &[]).unwrap(), AddOutcome::Added);
        let file = store.dir().join(file_name(&id_of(&header)));
        let before = fs::metadata(&file).unwrap().modified().unwrap();
        assert_eq!(store.add(&header, &[]).unwrap(), AddOutcome::AlreadyStored);
        assert_eq!(fs::metadata(&file).unwrap().modified().unwrap(), before);
        assert_eq!(store.load(&[]).grants.len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn directory_is_0700_and_files_are_0600() {
        use std::os::unix::fs::PermissionsExt as _;
        let (_tmp, store) = store();
        let header = signed_grant(1, 1, 0, AUDIENCE);
        store.add(&header, &[]).unwrap();
        let dir_mode = fs::metadata(store.dir()).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700);
        let file = store.dir().join(file_name(&id_of(&header)));
        assert_eq!(
            fs::metadata(file).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn a_tampered_or_forged_file_is_skipped_with_one_warning() {
        let (_tmp, store) = store();
        let good = signed_grant(1, 1, 0, AUDIENCE);
        let victim = signed_grant(1, 2, 0, AUDIENCE);
        store.add(&good, &[]).unwrap();
        store.add(&victim, &[]).unwrap();
        // Flip one byte of the signed statement in place.
        let path = store.dir().join(file_name(&id_of(&victim)));
        let mut bytes = fs::read(&path).unwrap();
        bytes[10] = if bytes[10] == b'A' { b'B' } else { b'A' };
        fs::write(&path, &bytes).unwrap();
        // A file whose name isn't its grant id (a copy planted under another name).
        fs::write(
            store.dir().join(format!("{}.grant", "00".repeat(32))),
            &good,
        )
        .unwrap();
        // Garbage, and a non-grant file that must be ignored silently.
        fs::write(
            store.dir().join(format!("{}.grant", "11".repeat(32))),
            b"not a header",
        )
        .unwrap();
        fs::write(store.dir().join("notes.txt"), b"ignored").unwrap();
        let report = store.load(&[]);
        assert_eq!(report.grants.len(), 1);
        assert_eq!(report.grants[0].header, good);
        assert_eq!(report.warnings.len(), 3, "{:?}", report.warnings);
        assert!(report.warnings.iter().all(|w| w.starts_with("skipping ")));
    }

    #[test]
    fn oversize_files_are_skipped_and_reported() {
        let (_tmp, store) = store();
        store.add(&signed_grant(1, 1, 0, AUDIENCE), &[]).unwrap();
        let big = store.dir().join(format!("{}.grant", "22".repeat(32)));
        fs::write(
            &big,
            vec![b'a'; usize::try_from(MAX_STORE_FILE_BYTES).unwrap() + 1],
        )
        .unwrap();
        let report = store.load(&[]);
        assert_eq!(report.grants.len(), 1);
        assert_eq!(report.warnings.len(), 1);
        assert!(
            report.warnings[0].contains("larger than"),
            "{:?}",
            report.warnings
        );
    }

    #[test]
    fn the_file_count_bound_holds() {
        let (_tmp, store) = store();
        for nonce in 1..=3 {
            store
                .add(&signed_grant(1, nonce, 0, AUDIENCE), &[])
                .unwrap();
        }
        let report = store.load_bounded(&[], 2, MAX_STORE_FILE_BYTES);
        assert_eq!(report.grants.len(), 2);
        assert_eq!(report.warnings.len(), 1);
        assert!(
            report.warnings[0].contains("skipping 1"),
            "{:?}",
            report.warnings
        );
        // The advertised bounds are the specified ones.
        assert_eq!(MAX_STORE_FILES, 1024);
        assert_eq!(MAX_STORE_FILE_BYTES, 16 * 1024);
    }

    #[cfg(unix)]
    #[test]
    fn a_group_writable_store_is_refused() {
        use std::os::unix::fs::PermissionsExt as _;
        let (_tmp, store) = store();
        store.add(&signed_grant(1, 1, 0, AUDIENCE), &[]).unwrap();
        fs::set_permissions(store.dir(), fs::Permissions::from_mode(0o770)).unwrap();
        let report = store.load(&[]);
        assert!(report.grants.is_empty());
        assert!(report.warnings[0].contains("group- or world-writable"));
        assert!(matches!(
            store.add(&signed_grant(1, 2, 0, AUDIENCE), &[]),
            Err(StoreError::Unsafe(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_grant_file_is_not_followed() {
        let (_tmp, store) = store();
        let header = signed_grant(1, 1, 0, AUDIENCE);
        store.add(&header, &[]).unwrap();
        let real = store.dir().join(file_name(&id_of(&header)));
        let target = store.dir().parent().unwrap().join("elsewhere");
        fs::rename(&real, &target).unwrap();
        std::os::unix::fs::symlink(&target, &real).unwrap();
        let report = store.load(&[]);
        assert!(report.grants.is_empty());
        assert!(report.warnings[0].contains("not a regular file"));
    }

    #[test]
    fn a_webauthn_grant_is_refused_without_a_pinned_relying_party() {
        let (_tmp, store) = store();
        let mut signed =
            mkit_attest::grant::SignedHeader::parse(&signed_grant(1, 1, 0, AUDIENCE)).unwrap();
        signed.scheme = mkit_attest::grant::OwnerScheme::WebAuthnP256;
        let header = signed.encode().unwrap();
        let error = store.add(&header, &[]).unwrap_err().to_string();
        assert!(error.contains("pinned relying party"), "{error}");
        assert!(!store.dir().exists() || store.load(&[]).grants.is_empty());
    }

    #[test]
    fn a_rejected_add_stores_nothing_and_names_the_rule() {
        let (_tmp, store) = store();
        let mut signed =
            mkit_attest::grant::SignedHeader::parse(&signed_grant(1, 1, 0, AUDIENCE)).unwrap();
        signed.blob[0] ^= 1;
        let error = store
            .add(&signed.encode().unwrap(), &[])
            .unwrap_err()
            .to_string();
        assert_eq!(error, "bad signature");
        assert!(!store.dir().exists());
    }

    #[test]
    fn remove_deletes_the_file() {
        let (_tmp, store) = store();
        let header = signed_grant(1, 1, 0, AUDIENCE);
        store.add(&header, &[]).unwrap();
        assert!(store.remove(&id_of(&header)).unwrap());
        assert!(!store.remove(&id_of(&header)).unwrap());
        assert!(store.load(&[]).grants.is_empty());
    }

    #[test]
    fn the_default_location_ignores_the_repository() {
        // It is derived from the XDG base directory alone: no argument, no
        // config field and no repository path can move it.
        let path = GrantStore::default_location();
        assert!(path.ends_with("mkit/grants"), "{}", path.display());
    }
}
