//! Crash-atomic key-file write machinery for the software keystore.
//!
//! Writes go through a synced temp file plus an atomic `rename`/`hard_link`
//! so a partial write can never install a corrupt record. On unix the path
//! is additionally guarded against symlink traversal, ownership confusion,
//! and lax directory permissions; a portable fallback covers other targets.

use std::path::{Path, PathBuf};

use crate::encrypted_record::KeyProtector;
use crate::{Algorithm, Error, KeyLabel, Result};

#[derive(Debug)]
pub(super) struct KeyFileWriteError {
    error: Error,
    record_may_exist: bool,
}

impl KeyFileWriteError {
    pub(super) fn before_record_install(error: Error) -> Self {
        Self {
            error,
            record_may_exist: false,
        }
    }

    pub(super) fn after_record_install(error: Error) -> Self {
        Self {
            error,
            record_may_exist: true,
        }
    }
}

pub(super) fn cleanup_new_dek_after_write_failure(
    protector: &dyn KeyProtector,
    wrapped_dek: &[u8],
    error: KeyFileWriteError,
) -> Error {
    if !error.record_may_exist {
        let _ = protector.delete_wrapped_dek(wrapped_dek);
    }
    error.error
}

pub(super) fn write_key_file(
    root: &Path,
    path: &Path,
    label: &str,
    algorithm: Algorithm,
    bytes: &[u8],
    overwrite: bool,
) -> std::result::Result<(), KeyFileWriteError> {
    #[cfg(unix)]
    return write_key_file_unix(root, path, label, algorithm, bytes, overwrite);

    #[cfg(not(unix))]
    {
        let _ = root;
        write_key_file_portable(path, label, algorithm, bytes, overwrite)
    }
}

#[cfg(unix)]
fn write_key_file_unix(
    root: &Path,
    path: &Path,
    label: &str,
    algorithm: Algorithm,
    bytes: &[u8],
    overwrite: bool,
) -> std::result::Result<(), KeyFileWriteError> {
    use std::os::unix::fs::MetadataExt as _;

    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    ensure_no_symlink_path(root, parent).map_err(KeyFileWriteError::before_record_install)?;
    std::fs::create_dir_all(parent)
        .map_err(|error| Error::Io(format!("mkdir {}: {error}", parent.display())))
        .map_err(KeyFileWriteError::before_record_install)?;
    set_private_dir_permissions(root).map_err(KeyFileWriteError::before_record_install)?;
    ensure_owned_by_euid(root).map_err(KeyFileWriteError::before_record_install)?;
    if parent != root {
        set_private_dir_permissions(parent).map_err(KeyFileWriteError::before_record_install)?;
        ensure_owned_by_euid(parent).map_err(KeyFileWriteError::before_record_install)?;
    }

    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(KeyFileWriteError::before_record_install(Error::Io(
                format!("keystore path is a symlink: {}", path.display()),
            )));
        }
        Ok(metadata) => {
            if !overwrite {
                return Err(KeyFileWriteError::before_record_install(
                    Error::KeyAlreadyExists {
                        label: KeyLabel::new(label)
                            .map_err(KeyFileWriteError::before_record_install)?,
                        algorithm,
                    },
                ));
            }
            if metadata.uid() != euid() {
                return Err(KeyFileWriteError::before_record_install(
                    Error::AccessDenied(format!(
                        "existing key file is owned by uid {}, expected {}: {}",
                        metadata.uid(),
                        euid(),
                        path.display()
                    )),
                ));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(KeyFileWriteError::before_record_install(Error::Io(
                format!("lstat {}: {error}", path.display()),
            )));
        }
    }

    let filename = path
        .file_name()
        .ok_or_else(|| Error::Io(format!("path has no filename: {}", path.display())))
        .map_err(KeyFileWriteError::before_record_install)?;
    let tmp_path = create_synced_tmp_key_file(parent, filename, bytes)
        .map_err(KeyFileWriteError::before_record_install)?;

    if overwrite {
        if let Err(error) = std::fs::rename(&tmp_path, path) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(KeyFileWriteError::before_record_install(Error::Io(
                format!("rename {}: {error}", path.display()),
            )));
        }
    } else if let Err(error) = std::fs::hard_link(&tmp_path, path) {
        let _ = std::fs::remove_file(&tmp_path);
        return if error.kind() == std::io::ErrorKind::AlreadyExists {
            Err(KeyFileWriteError::before_record_install(
                Error::KeyAlreadyExists {
                    label: KeyLabel::new(label)
                        .map_err(KeyFileWriteError::before_record_install)?,
                    algorithm,
                },
            ))
        } else {
            Err(KeyFileWriteError::before_record_install(Error::Io(
                format!("link {}: {error}", path.display()),
            )))
        };
    } else if let Err(error) = std::fs::remove_file(&tmp_path) {
        return Err(KeyFileWriteError::after_record_install(Error::Io(format!(
            "unlink tmp {}: {error}",
            tmp_path.display()
        ))));
    }

    let dir = std::fs::File::open(parent)
        .map_err(|error| Error::Io(format!("open dir for fsync: {error}")))
        .map_err(KeyFileWriteError::after_record_install)?;
    dir.sync_all()
        .map_err(|error| Error::Io(format!("fsync dir: {error}")))
        .map_err(KeyFileWriteError::after_record_install)
}

#[cfg(unix)]
fn create_synced_tmp_key_file(
    parent: &Path,
    filename: &std::ffi::OsStr,
    bytes: &[u8],
) -> Result<PathBuf> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let mut tmp_path = temp_key_file_path(parent, filename, 0);
    for attempt in 0..16u8 {
        if attempt > 0 {
            tmp_path = temp_key_file_path(parent, filename, attempt);
        }
        let mut file = match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW)
            .mode(0o600)
            .open(&tmp_path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(Error::Io(format!(
                    "open tmp {}: {error}",
                    tmp_path.display()
                )));
            }
        };
        if let Err(error) = file.write_all(bytes) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(Error::Io(format!(
                "write tmp {}: {error}",
                tmp_path.display()
            )));
        }
        if let Err(error) = file.sync_all() {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(Error::Io(format!(
                "fsync tmp {}: {error}",
                tmp_path.display()
            )));
        }
        drop(file);
        return Ok(tmp_path);
    }
    Err(Error::Io(format!(
        "could not create unique temp file under {}",
        parent.display()
    )))
}

#[cfg(unix)]
fn temp_key_file_path(parent: &Path, filename: &std::ffi::OsStr, attempt: u8) -> PathBuf {
    if attempt == 0 {
        parent.join(format!(
            ".{}.tmp.{}",
            filename.to_string_lossy(),
            std::process::id()
        ))
    } else {
        parent.join(format!(
            ".{}.tmp.{}.{}",
            filename.to_string_lossy(),
            std::process::id(),
            attempt
        ))
    }
}

#[cfg(unix)]
pub(super) fn ensure_no_symlink_path(root: &Path, path: &Path) -> Result<()> {
    let mut current = Some(path);
    while let Some(candidate) = current {
        if !candidate.starts_with(root) {
            break;
        }
        match std::fs::symlink_metadata(candidate) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(Error::Io(format!(
                    "keystore path is a symlink: {}",
                    candidate.display()
                )));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(Error::Io(format!("lstat {}: {error}", candidate.display()))),
        }
        if candidate == root {
            break;
        }
        current = candidate.parent();
    }
    Ok(())
}

#[cfg(unix)]
pub(super) fn ensure_owned_by_euid(path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = std::fs::metadata(path)
        .map_err(|error| Error::Io(format!("metadata {}: {error}", path.display())))?;
    let actual = metadata.uid();
    let expected = euid();
    if actual == expected {
        Ok(())
    } else {
        Err(Error::AccessDenied(format!(
            "keystore path is owned by uid {actual}, expected {expected}: {}",
            path.display()
        )))
    }
}

#[cfg(unix)]
pub(super) fn set_private_dir_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .map_err(|error| Error::Io(format!("chmod {}: {error}", path.display())))
}

#[cfg(unix)]
fn euid() -> u32 {
    mkit_core::sign::effective_uid()
}

#[cfg(not(unix))]
fn write_key_file_portable(
    path: &Path,
    label: &str,
    algorithm: Algorithm,
    bytes: &[u8],
    overwrite: bool,
) -> std::result::Result<(), KeyFileWriteError> {
    use std::io::Write as _;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| Error::Io(format!("mkdir {}: {error}", parent.display())))
            .map_err(KeyFileWriteError::before_record_install)?;
    }
    if overwrite {
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let filename = path
            .file_name()
            .ok_or_else(|| Error::Io(format!("path has no filename: {}", path.display())))
            .map_err(KeyFileWriteError::before_record_install)?;
        let (tmp_path, mut file) = create_synced_tmp_key_file_portable(parent, filename)
            .map_err(KeyFileWriteError::before_record_install)?;
        file.write_all(bytes)
            .map_err(|error| Error::Io(format!("write tmp {}: {error}", tmp_path.display())))
            .map_err(KeyFileWriteError::before_record_install)?;
        file.sync_all()
            .map_err(|error| Error::Io(format!("fsync tmp {}: {error}", tmp_path.display())))
            .map_err(KeyFileWriteError::before_record_install)?;
        drop(file);
        if let Err(error) = std::fs::rename(&tmp_path, path) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(KeyFileWriteError::before_record_install(Error::Io(
                format!("rename {}: {error}", path.display()),
            )));
        }
        Ok(())
    } else {
        write_key_file_portable_create_new(path, label, algorithm, bytes)
    }
}

#[cfg(not(unix))]
fn write_key_file_portable_create_new(
    path: &Path,
    label: &str,
    algorithm: Algorithm,
    bytes: &[u8],
) -> std::result::Result<(), KeyFileWriteError> {
    use std::io::Write as _;

    let mut file = match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(KeyFileWriteError::before_record_install(
                Error::KeyAlreadyExists {
                    label: KeyLabel::new(label)
                        .map_err(KeyFileWriteError::before_record_install)?,
                    algorithm,
                },
            ));
        }
        Err(error) => {
            return Err(KeyFileWriteError::before_record_install(Error::Io(
                format!("open {}: {error}", path.display()),
            )));
        }
    };
    if let Err(error) = file.write_all(bytes) {
        let removed = std::fs::remove_file(path).is_ok();
        let error = Error::Io(format!("write {}: {error}", path.display()));
        return Err(if removed {
            KeyFileWriteError::before_record_install(error)
        } else {
            KeyFileWriteError::after_record_install(error)
        });
    }
    if let Err(error) = file.sync_all() {
        let removed = std::fs::remove_file(path).is_ok();
        let error = Error::Io(format!("fsync {}: {error}", path.display()));
        return Err(if removed {
            KeyFileWriteError::before_record_install(error)
        } else {
            KeyFileWriteError::after_record_install(error)
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn create_synced_tmp_key_file_portable(
    parent: &Path,
    filename: &std::ffi::OsStr,
) -> Result<(PathBuf, std::fs::File)> {
    for attempt in 0..16u8 {
        let tmp_path = if attempt == 0 {
            parent.join(format!(
                ".{}.tmp.{}",
                filename.to_string_lossy(),
                std::process::id()
            ))
        } else {
            parent.join(format!(
                ".{}.tmp.{}.{}",
                filename.to_string_lossy(),
                std::process::id(),
                attempt
            ))
        };
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)
        {
            Ok(file) => return Ok((tmp_path, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(Error::Io(format!(
                    "open tmp {}: {error}",
                    tmp_path.display()
                )));
            }
        }
    }
    Err(Error::Io(format!(
        "could not create unique temp file under {}",
        parent.display()
    )))
}
