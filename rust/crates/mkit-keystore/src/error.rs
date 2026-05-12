//! Structured keystore errors.

use crate::{Algorithm, KeySelector};

/// Result alias for keystore operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Keystore operation failure.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The selected backend is unavailable in this environment.
    #[error("keystore backend unavailable: {0}")]
    BackendUnavailable(String),
    /// The backend does not support the requested algorithm.
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(Algorithm),
    /// The backend does not support the requested operation.
    #[error("unsupported operation: {0}")]
    UnsupportedOperation(&'static str),
    /// The backend cannot honor the requested key attributes.
    #[error("unsupported key attributes: {0}")]
    UnsupportedAttributes(String),
    /// The provided key label is invalid.
    #[error("invalid key label {label:?}: {reason}")]
    InvalidLabel { label: String, reason: &'static str },
    /// A key with the selected `(label, algorithm)` already exists.
    #[error("key already exists: label={label:?} algorithm={algorithm}")]
    KeyAlreadyExists { label: String, algorithm: Algorithm },
    /// The selected key was not found.
    #[error("key not found: {0:?}")]
    KeyNotFound(KeySelector),
    /// A label-only selector matched more than one key.
    #[error("ambiguous key selector: {0:?}")]
    AmbiguousKeySelector(KeySelector),
    /// The key exists but cannot be exported.
    #[error("key is not extractable: {0:?}")]
    NotExtractable(KeySelector),
    /// Secret bytes are malformed or invalid for the selected algorithm.
    #[error("invalid key material for {algorithm}: {reason}")]
    InvalidKeyMaterial {
        /// Algorithm whose material failed validation.
        algorithm: Algorithm,
        /// Human-readable reason safe to display.
        reason: String,
    },
    /// Authentication or user presence is required before retrying.
    #[error("authentication required: {0}")]
    AuthenticationRequired(String),
    /// The user declined a backend prompt.
    #[error("user declined keystore operation")]
    UserDeclined,
    /// The backend operation timed out.
    #[error("keystore operation timed out")]
    TimedOut,
    /// Backend I/O failed.
    #[error("keystore I/O failure: {0}")]
    Io(String),
    /// Backend access was denied.
    #[error("keystore access denied: {0}")]
    AccessDenied(String),
    /// Serialization or encoding failed.
    #[error("keystore encoding failure: {0}")]
    Encoding(String),
    /// Internal invariant failure.
    #[error("internal keystore error: {0}")]
    Internal(String),
}
