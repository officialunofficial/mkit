//! Structured keystore errors.

use core::fmt;

use crate::{Algorithm, KeyLabel, KeySelector};

/// Result alias for keystore operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Keystore operation failure.
#[derive(Debug)]
pub enum Error {
    /// The selected backend is unavailable in this environment.
    BackendUnavailable(String),
    /// The backend does not support the requested algorithm.
    UnsupportedAlgorithm(Algorithm),
    /// The backend does not support the requested operation.
    UnsupportedOperation(&'static str),
    /// The backend cannot honor the requested key attributes.
    UnsupportedAttributes(String),
    /// The provided key label is invalid.
    /// The raw invalid label is retained for Debug/detail diagnostics only.
    InvalidLabel { label: String, reason: &'static str },
    /// A key with the selected `(label, algorithm)` already exists.
    KeyAlreadyExists {
        label: KeyLabel,
        algorithm: Algorithm,
    },
    /// The selected key was not found.
    KeyNotFound(KeySelector),
    /// A label-only selector matched more than one key.
    AmbiguousKeySelector(KeySelector),
    /// The key exists but cannot be exported.
    NotExtractable(KeySelector),
    /// Secret bytes are malformed or invalid for the selected algorithm.
    InvalidKeyMaterial {
        /// Algorithm whose material failed validation.
        algorithm: Algorithm,
        /// Human-readable reason safe to display.
        reason: String,
    },
    /// Authentication or user presence is required before retrying.
    AuthenticationRequired(String),
    /// The user declined a backend prompt.
    UserDeclined,
    /// The backend operation timed out.
    TimedOut,
    /// Backend I/O failed.
    Io(String),
    /// Backend access was denied.
    AccessDenied(String),
    /// A software key record's data-encryption key is sealed by a
    /// different protector than the one used to open it.
    ///
    /// Protector identifiers are not sensitive — unlike paths and
    /// labels — so both are surfaced verbatim. These name the
    /// *software-record DEK protector* (e.g. the OS keychain wrapping
    /// the software keystore's DEK), **not** a signing-key backend, so
    /// the message deliberately does not prescribe a `key.backend` or
    /// `<backend>:<label>` change — those route to a different store
    /// that does not hold this record.
    ProtectorMismatch {
        /// Protector the record was sealed with.
        required: String,
        /// Protector that was used to open it.
        got: String,
    },
    /// Serialization or encoding failed.
    Encoding(String),
    /// Internal invariant failure.
    Internal(String),
}

impl Error {
    /// Developer-oriented diagnostic containing full structured details.
    #[must_use]
    pub fn detail(&self) -> String {
        format!("{self:?}")
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BackendUnavailable(_) => {
                f.write_str("keystore backend unavailable: no usable protector or session")
            }
            Self::UnsupportedAlgorithm(algorithm) => {
                write!(f, "unsupported algorithm: {algorithm}")
            }
            Self::UnsupportedOperation(operation) => {
                write!(f, "unsupported operation: {operation}")
            }
            Self::UnsupportedAttributes(message) => {
                write!(f, "unsupported key attributes: {message}")
            }
            Self::InvalidLabel { reason, .. } => write!(f, "invalid key label: {reason}"),
            Self::KeyAlreadyExists { algorithm, .. } => {
                write!(f, "key already exists for algorithm {algorithm}")
            }
            Self::KeyNotFound(selector) => match selector.algorithm() {
                Some(algorithm) => write!(f, "key not found for algorithm {algorithm}"),
                None => f.write_str("key not found"),
            },
            Self::AmbiguousKeySelector(selector) => match selector.algorithm() {
                Some(algorithm) => write!(f, "ambiguous key selector for algorithm {algorithm}"),
                None => f.write_str("ambiguous key selector"),
            },
            Self::NotExtractable(selector) => match selector.algorithm() {
                Some(algorithm) => write!(f, "key is not extractable for algorithm {algorithm}"),
                None => f.write_str("key is not extractable"),
            },
            Self::InvalidKeyMaterial { algorithm, reason } => {
                write!(f, "invalid key material for {algorithm}: {reason}")
            }
            Self::AuthenticationRequired(_) => f.write_str("authentication required"),
            Self::UserDeclined => f.write_str("user declined keystore operation"),
            Self::TimedOut => f.write_str("keystore operation timed out"),
            Self::Io(_) => f.write_str("keystore I/O failure during storage operation"),
            Self::AccessDenied(_) => f.write_str("keystore access denied by backend policy"),
            Self::ProtectorMismatch { required, got } => write!(
                f,
                "software key record is sealed with the `{required}` protector but was opened with the `{got}` protector — its encrypted data-encryption key can only be unwrapped by the protector that sealed it"
            ),
            Self::Encoding(_) => f.write_str("keystore encoding failure while processing key data"),
            Self::Internal(_) => f.write_str("internal keystore invariant failure"),
        }
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{KeyLabel, KeySelector};

    #[test]
    fn display_redacts_labels_and_paths() {
        let unavailable = Error::BackendUnavailable(
            "systemd-creds decrypt /Users/alice/private/key.cred: denied".into(),
        );
        assert_eq!(
            unavailable.to_string(),
            "keystore backend unavailable: no usable protector or session"
        );
        assert!(unavailable.detail().contains("/Users/alice/private"));

        let invalid = Error::InvalidLabel {
            label: "secret-release-key".into(),
            reason: "must not contain path separators",
        };
        assert!(!invalid.to_string().contains("secret-release-key"));
        assert!(invalid.detail().contains("secret-release-key"));

        let exists = Error::KeyAlreadyExists {
            label: KeyLabel::new("prod-signing").unwrap(),
            algorithm: Algorithm::Ed25519,
        };
        assert!(!exists.to_string().contains("prod-signing"));

        let missing = Error::KeyNotFound(KeySelector::new("prod-signing", None).unwrap());
        assert!(!missing.to_string().contains("prod-signing"));

        let io = Error::Io("read /Users/alice/.local/share/mkit/keys/prod.key: denied".into());
        assert_eq!(
            io.to_string(),
            "keystore I/O failure during storage operation"
        );
        assert!(!io.to_string().contains("/Users/alice"));
        assert!(io.detail().contains("/Users/alice"));

        let internal = Error::Internal("label prod-signing under /tmp/private".into());
        assert_eq!(internal.to_string(), "internal keystore invariant failure");

        let auth = Error::AuthenticationRequired(
            "backend prompt for label prod-signing at /Users/alice/keyring failed".into(),
        );
        assert_eq!(auth.to_string(), "authentication required");
        assert!(!auth.to_string().contains("prod-signing"));
        assert!(!auth.to_string().contains("/Users/alice"));
        assert!(auth.detail().contains("prod-signing"));
    }

    #[test]
    fn protector_mismatch_names_both_protectors() {
        let mismatch = Error::ProtectorMismatch {
            required: "macos-keychain".into(),
            got: "software".into(),
        };
        let message = mismatch.to_string();
        // Protector identifiers are not sensitive — surface both so the
        // user can see which protector sealed the record and which one
        // tried to open it.
        assert!(message.contains("macos-keychain"));
        assert!(message.contains("software"));
        assert!(message.contains("protector"));
    }

    #[test]
    fn protector_mismatch_does_not_prescribe_signing_backend_routing() {
        // `required`/`got` are software-record DEK protector ids, not
        // signing-key backends. The message must not steer users toward
        // `key.backend = …` (only drives `mkit key` defaults) or a
        // `<backend>:<label>` ref, which route to a different store that
        // does not hold this record.
        let mismatch = Error::ProtectorMismatch {
            required: "macos-keychain".into(),
            got: "software".into(),
        };
        let message = mismatch.to_string();
        assert!(!message.contains("key.backend"));
        assert!(!message.contains(":<label>"));
    }

    #[test]
    fn protector_mismatch_does_not_leak_labels_or_paths() {
        // Even though protectors are surfaced, the variant carries no
        // label/path channel, so it cannot leak one.
        let mismatch = Error::ProtectorMismatch {
            required: "macos-keychain".into(),
            got: "software".into(),
        };
        let message = mismatch.to_string();
        assert!(!message.contains("prod-signing"));
        assert!(!message.contains('/'));
    }
}
