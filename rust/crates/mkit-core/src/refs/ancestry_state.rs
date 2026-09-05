//! Small history-publication metadata shared with feature-disabled GC/writers.
//! The MMR implementation is optional; pending roots and invalidation are not.

use std::collections::BTreeSet;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use super::{RefError, RefResult};
use crate::hash::{self, Hash};

pub(crate) const DIRECTORY: &str = "history-v1";
const MAX_TRANSACTION: u64 = 8192;

pub(crate) fn branch_dir(common: &Path, full_ref: &str) -> PathBuf {
    common
        .join(DIRECTORY)
        .join("branches")
        .join(hash::to_hex(&hash::hash(full_ref.as_bytes())))
}

/// Read a metadata file with a hard bound even if it grows after stat.
pub(crate) fn read_bounded(path: &Path, limit: u64) -> io::Result<Option<Vec<u8>>> {
    let file = match fs::File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "history metadata exceeds limit",
        ));
    }
    Ok(Some(bytes))
}

/// A durable intent, independent of MMR storage or the history feature flag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Transaction {
    pub repository: Hash,
    pub full_ref: String,
    pub previous: Option<Hash>,
    pub previous_generation: Option<Hash>,
    pub target: Hash,
    pub generation: Hash,
}

impl Transaction {
    #[cfg(feature = "history-mmr")]
    pub(crate) fn encode(&self) -> Vec<u8> {
        let optional = |h: Option<Hash>| h.map_or_else(|| "-".into(), |h| hash::to_hex(&h));
        let mut text = format!(
            "mkit-history-transaction-v1\n{}\n{}\n{}\n{}\n{}\n{}\n",
            hash::to_hex(&self.repository),
            self.full_ref,
            optional(self.previous),
            optional(self.previous_generation),
            hash::to_hex(&self.target),
            hash::to_hex(&self.generation)
        );
        text.push_str(&hash::to_hex(&hash::hash(text.as_bytes())));
        text.push('\n');
        text.into_bytes()
    }

    pub(crate) fn read(dir: &Path) -> RefResult<Option<Self>> {
        let Some(bytes) = read_bounded(&dir.join("transaction"), MAX_TRANSACTION)? else {
            return Ok(None);
        };
        let malformed = || RefError::InvalidRef("corrupt pending history transaction".into());
        let raw = std::str::from_utf8(&bytes).map_err(|_| malformed())?;
        let lines: Vec<_> = raw.split('\n').collect();
        if lines.len() != 9 || lines[0] != "mkit-history-transaction-v1" || !lines[8].is_empty() {
            return Err(malformed());
        }
        let parse_hash = |text: &str| -> RefResult<Hash> {
            let h = hash::from_hex(text).map_err(|_| malformed())?;
            if hash::to_hex(&h) != text {
                return Err(malformed());
            }
            Ok(h)
        };
        let optional = |text: &str| -> RefResult<Option<Hash>> {
            if text == "-" {
                Ok(None)
            } else {
                parse_hash(text).map(Some)
            }
        };
        let checksum_start = bytes.len().checked_sub(65).ok_or_else(malformed)?;
        if parse_hash(lines[7])? != hash::hash(&bytes[..checksum_start])
            || !lines[2].starts_with("refs/heads/")
            || !super::validate_ref_name(lines[2])
        {
            return Err(malformed());
        }
        Ok(Some(Self {
            repository: parse_hash(lines[1])?,
            full_ref: lines[2].to_owned(),
            previous: optional(lines[3])?,
            previous_generation: optional(lines[4])?,
            target: parse_hash(lines[5])?,
            generation: parse_hash(lines[6])?,
        }))
    }
}

/// Raw writers cannot step over an unfinished history transaction. A completed
/// raw mutation invalidates the pointer, so a delete/recreate or ABA rewrite
/// cannot revive an earlier incarnation's descriptor.
pub(crate) fn invalidate(common: &Path, full_ref: &str) -> RefResult<()> {
    let dir = branch_dir(common, full_ref);
    if Transaction::read(&dir)?.is_some() {
        return Err(RefError::InvalidRef(
            "pending history publication; retry with history-mmr enabled to recover".into(),
        ));
    }
    remove_synced(&dir.join("current"))?;
    Ok(())
}

pub(crate) fn remove_synced(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => crate::atomic::sync_dir(path.parent().expect("metadata has parent")),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

pub(crate) fn pending_roots(common: &Path) -> RefResult<BTreeSet<Hash>> {
    let mut roots = BTreeSet::new();
    let entries = match fs::read_dir(common.join(DIRECTORY).join("branches")) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(roots),
        Err(e) => return Err(e.into()),
    };
    for entry in entries {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            return Err(RefError::InvalidRef(
                "unexpected file in history branches".into(),
            ));
        }
        if let Some(tx) = Transaction::read(&entry.path())? {
            if branch_dir(common, &tx.full_ref) != entry.path() {
                return Err(RefError::InvalidRef(
                    "history transaction names a different branch".into(),
                ));
            }
            if let Some(h) = tx.previous {
                roots.insert(h);
            }
            roots.insert(tx.target);
        }
    }
    Ok(roots)
}
