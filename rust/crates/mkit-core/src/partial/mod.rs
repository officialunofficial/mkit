//! Portable, authenticated selected-file snapshots.
//!
//! Verification establishes integrity and selected-only materialization. It
//! does not establish signer identity trust, host permission, or full closure.

mod bundle;
mod collector;
mod limits;
mod overlay;
mod update;
mod verify;

use crate::object::TreeEntry;

pub use bundle::{PartialObject, PartialSnapshotBundle};
pub use limits::PartialLimits;
pub use overlay::{FileReplacement, PreparedPartialEdit, prepare_partial_commit, replace_files};
pub use update::{PartialUpdate, export_partial_update};
pub use verify::{
    PartialCoverage, SelectedFile, VerifiedPartialSnapshot, VerifiedTree, build_partial_snapshot,
    verify_partial_snapshot,
};

/// A repository-relative path represented by exact UTF-8 component bytes.
pub type PartialPath = Vec<Vec<u8>>;

/// Errors from partial snapshot production, decoding, and verification.
#[derive(Debug, thiserror::Error)]
pub enum PartialError {
    #[error("partial snapshot version {0} is unsupported")]
    UnsupportedVersion(u8),
    #[error("partial snapshot bytes are not canonical")]
    NonCanonical,
    #[error("bundle base does not match the independently expected base")]
    BaseMismatch,
    #[error("bundle selection does not match the independently expected selection")]
    SelectionMismatch,
    #[error("the bundle lacks required materialization bytes")]
    InsufficientWitness,
    #[error("an authenticated edge points to the wrong object type")]
    WrongObjectType,
    #[error("the base commit/remix signature is invalid")]
    InvalidSignature,
    #[error("chunked file metadata or occurrence lengths are invalid")]
    InvalidChunkLayout,
    #[error("a requested path does not exist in the authenticated trees")]
    IncompleteSelection,
    #[error("the selected path names an unsupported partial operation")]
    UnsupportedPartialOperation,
    #[error("authenticated tree witnesses exceed the configured bound")]
    WitnessTooLarge,
    #[error("selected data or encoded input exceeds the configured workspace bound")]
    WorkspaceTooLarge,
    #[error("validation count/depth budget exceeded")]
    ValidationBudgetExceeded,
    #[error("the replacement batch does not change any selected file")]
    NoChanges,
    #[error("the signed commit does not exactly match the prepared unsigned commit")]
    CommitMismatch,
    #[error("the partial update exceeds its configured bound")]
    SubmissionTooLarge,
    #[error("the partial update pack is malformed or not raw-only")]
    InvalidUpdatePack,
    #[error("selected path does not satisfy the partial-workspace profile")]
    InvalidPath,
    #[error(transparent)]
    Source(#[from] crate::store::StoreError),
}

pub(crate) fn validate_paths(
    paths: &[PartialPath],
    limits: &PartialLimits,
) -> Result<(), PartialError> {
    if paths.is_empty() || paths.len() > limits.max_selected_paths {
        return Err(PartialError::ValidationBudgetExceeded);
    }
    let mut prior: Option<Vec<u8>> = None;
    let mut aggregate = 0usize;
    for path in paths {
        if path.is_empty() || path.len() > limits.max_path_depth {
            return Err(PartialError::InvalidPath);
        }
        let mut joined = Vec::new();
        for (index, component) in path.iter().enumerate() {
            let text = std::str::from_utf8(component).map_err(|_| PartialError::InvalidPath)?;
            if component.len() > limits.max_component_bytes
                || !TreeEntry::validate_name(component)
                || text.chars().any(char::is_control)
                || (index == 0 && component.eq_ignore_ascii_case(b".mkit-scoped"))
            {
                return Err(PartialError::InvalidPath);
            }
            if index != 0 {
                joined.push(b'/');
            }
            joined.extend_from_slice(component);
        }
        if joined.len() > limits.max_path_bytes
            || prior.as_ref().is_some_and(|previous| previous >= &joined)
        {
            return Err(PartialError::InvalidPath);
        }
        aggregate = aggregate
            .checked_add(joined.len())
            .ok_or(PartialError::WorkspaceTooLarge)?;
        if aggregate > limits.max_total_path_bytes {
            return Err(PartialError::WorkspaceTooLarge);
        }
        prior = Some(joined);
    }
    Ok(())
}
