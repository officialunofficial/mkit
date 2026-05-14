//! Public keystore API types.

use core::fmt;
use core::str::FromStr;

use zeroize::Zeroizing;

use crate::{Error, Result};

/// Signing algorithm supported by mkit keystores.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Algorithm {
    /// Ed25519 using raw 32-byte seed material.
    Ed25519,
    /// secp256k1 ECDSA using raw 32-byte scalar material.
    Secp256k1,
    /// P-256 ECDSA using raw 32-byte scalar material.
    P256,
}

impl Algorithm {
    /// Canonical lowercase string form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ed25519 => "ed25519",
            Self::Secp256k1 => "secp256k1",
            Self::P256 => "p256",
        }
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Algorithm {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "ed25519" => Ok(Self::Ed25519),
            "secp256k1" => Ok(Self::Secp256k1),
            "p256" => Ok(Self::P256),
            other => Err(Error::Encoding(format!("unknown algorithm: {other}"))),
        }
    }
}

#[cfg(feature = "attest")]
impl From<mkit_attest::Algorithm> for Algorithm {
    fn from(value: mkit_attest::Algorithm) -> Self {
        match value {
            mkit_attest::Algorithm::Ed25519 => Self::Ed25519,
            mkit_attest::Algorithm::Secp256k1 => Self::Secp256k1,
            mkit_attest::Algorithm::P256 => Self::P256,
        }
    }
}

#[cfg(feature = "attest")]
impl From<Algorithm> for mkit_attest::Algorithm {
    fn from(value: Algorithm) -> Self {
        match value {
            Algorithm::Ed25519 => Self::Ed25519,
            Algorithm::Secp256k1 => Self::Secp256k1,
            Algorithm::P256 => Self::P256,
        }
    }
}

/// Requested and reported key attributes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyAttrs {
    /// Whether the backend may export secret material.
    pub extractable: bool,
    /// Whether the backend should require per-operation user presence.
    pub require_user_presence: bool,
    /// Whether the key should be bound to this device.
    pub device_bound: bool,
}

impl Default for KeyAttrs {
    /// Default software-backend attributes are extractable because software-style
    /// storage decrypts into process memory; stronger backends advertise
    /// non-extractability through [`Capabilities::supports_non_extractable`].
    fn default() -> Self {
        Self {
            extractable: true,
            require_user_presence: false,
            device_bound: false,
        }
    }
}

/// Backend family identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum BackendKind {
    /// User-scoped software compatibility backend.
    Software,
    /// User-scoped raw-file compatibility backend.
    SoftwareRaw,
    /// macOS Keychain backend.
    MacosKeychain,
    /// Windows Credential Manager or CNG backend.
    WindowsCredentialManager,
    /// Linux Secret Service backend.
    LinuxSecretService,
    /// systemd-creds backend.
    SystemdCreds,
    /// YubiKey-backed signer.
    YubiKey,
    /// External signer bridge.
    External,
    /// Cloud KMS signer.
    Cloud,
    /// In-memory backend for tests and WASM-like integrations.
    Memory,
}

impl BackendKind {
    /// Canonical lowercase key-reference token.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Software => "software",
            Self::SoftwareRaw => "software-raw",
            Self::MacosKeychain => "macos-keychain",
            Self::WindowsCredentialManager => "windows-credential",
            Self::LinuxSecretService => "linux-secret-service",
            Self::SystemdCreds => "systemd-creds",
            Self::YubiKey => "yubikey",
            Self::External => "external",
            Self::Cloud => "cloud",
            Self::Memory => "memory",
        }
    }
}

impl fmt::Display for BackendKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for BackendKind {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "software" => Ok(Self::Software),
            "software-raw" => Ok(Self::SoftwareRaw),
            "macos-keychain" => Ok(Self::MacosKeychain),
            "windows-credential" => Ok(Self::WindowsCredentialManager),
            "linux-secret-service" => Ok(Self::LinuxSecretService),
            "systemd-creds" => Ok(Self::SystemdCreds),
            "yubikey" => Ok(Self::YubiKey),
            "external" => Ok(Self::External),
            "cloud" => Ok(Self::Cloud),
            "memory" => Ok(Self::Memory),
            other => Err(Error::BackendUnavailable(format!(
                "unknown backend: {other}"
            ))),
        }
    }
}

/// Runtime capabilities for one backend instance.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Capabilities {
    /// Backend family.
    pub backend: BackendKind,
    /// Supported algorithms.
    pub algorithms: Vec<Algorithm>,
    /// Whether the backend can generate keys.
    pub can_generate: bool,
    /// Whether the backend can import secret material.
    pub can_import: bool,
    /// Whether the backend can export secret material.
    pub can_export: bool,
    /// Whether the backend can delete keys.
    pub can_delete: bool,
    /// Whether the backend can list visible keys.
    pub supports_listing: bool,
    /// Whether the backend can require user presence.
    pub supports_user_presence: bool,
    /// Whether the backend can bind keys to this device.
    pub supports_device_bound: bool,
    /// Whether the backend can keep keys non-extractable.
    pub supports_non_extractable: bool,
}

/// Public metadata for a key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyMetadata {
    /// Backend-local label.
    pub(crate) label: String,
    /// Backend family.
    pub backend: BackendKind,
    /// Signing algorithm.
    pub algorithm: Algorithm,
    /// Encoded public key bytes.
    pub public_key: Vec<u8>,
    /// Canonical key ID.
    pub(crate) keyid: String,
    /// Whether this key can be exported.
    pub extractable: bool,
    /// Whether signing requires user presence.
    pub require_user_presence: bool,
    /// Whether this key is device-bound.
    pub device_bound: bool,
}

impl KeyMetadata {
    /// Backend-local label.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Backend family.
    #[must_use]
    pub const fn backend(&self) -> BackendKind {
        self.backend
    }

    /// Signing algorithm.
    #[must_use]
    pub const fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// Canonical key ID.
    #[must_use]
    pub fn keyid(&self) -> &str {
        &self.keyid
    }
}

/// Secret 32-byte key material.
pub struct SecretKey {
    /// Algorithm the bytes belong to.
    pub(crate) algorithm: Algorithm,
    bytes: Zeroizing<[u8; 32]>,
}

impl SecretKey {
    /// Wrap secret bytes for an algorithm.
    #[must_use]
    pub fn new(algorithm: Algorithm, bytes: [u8; 32]) -> Self {
        Self {
            algorithm,
            bytes: Zeroizing::new(bytes),
        }
    }

    /// Wrap zeroizing secret bytes for an algorithm.
    #[must_use]
    pub fn from_zeroizing(algorithm: Algorithm, bytes: Zeroizing<[u8; 32]>) -> Self {
        Self { algorithm, bytes }
    }

    /// Secret key algorithm.
    #[must_use]
    pub const fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// Expose secret bytes by reference.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Consume the wrapper and return zeroizing secret bytes.
    #[must_use]
    pub fn into_bytes(self) -> Zeroizing<[u8; 32]> {
        self.bytes
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretKey")
            .field("algorithm", &self.algorithm)
            .field("bytes", &"<redacted>")
            .finish()
    }
}

/// Selector for read, export, and deletion operations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeySelector {
    /// Backend-local label.
    pub(crate) label: String,
    /// Optional algorithm disambiguator.
    pub algorithm: Option<Algorithm>,
}

impl KeySelector {
    /// Build a selector after validating its label.
    pub fn new(label: impl Into<String>, algorithm: Option<Algorithm>) -> Result<Self> {
        let label = label.into();
        validate_label(&label)?;
        Ok(Self { label, algorithm })
    }

    /// Backend-local label.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Optional algorithm disambiguator.
    #[must_use]
    pub const fn algorithm(&self) -> Option<Algorithm> {
        self.algorithm
    }
}

/// Parsed `<backend>:<label>` key reference.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyRef {
    /// Backend family.
    pub backend: BackendKind,
    /// Backend-local label.
    pub(crate) label: String,
}

impl KeyRef {
    /// Create a key reference after validating the label.
    pub fn new(backend: BackendKind, label: impl Into<String>) -> Result<Self> {
        let label = label.into();
        validate_label(&label)?;
        validate_key_ref_label(&label)?;
        Ok(Self { backend, label })
    }

    /// Backend family.
    #[must_use]
    pub const fn backend(&self) -> BackendKind {
        self.backend
    }

    /// Backend-local label.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }
}

impl fmt::Display for KeyRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.backend, self.label)
    }
}

impl FromStr for KeyRef {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let Some((backend, label)) = s.split_once(':') else {
            return Err(Error::Encoding("key ref must be <backend>:<label>".into()));
        };
        if label.contains(':') {
            return Err(Error::InvalidLabel {
                label: label.into(),
                reason: "must not contain ':'",
            });
        }
        Self::new(backend.parse()?, label)
    }
}

/// Options for key generation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GenerateOptions {
    /// Replace an existing `(label, algorithm)` if present.
    pub overwrite: bool,
}

/// Options for key import.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ImportOptions {
    /// Replace an existing `(label, algorithm)` if present.
    pub overwrite: bool,
}

/// Validate a backend-local label.
pub fn validate_label(label: &str) -> Result<()> {
    if label.is_empty() {
        return Err(Error::InvalidLabel {
            label: label.into(),
            reason: "must not be empty",
        });
    }
    if label.trim() != label {
        return Err(Error::InvalidLabel {
            label: label.into(),
            reason: "must not have leading or trailing whitespace",
        });
    }
    if label.len() > 255 {
        return Err(Error::InvalidLabel {
            label: label.into(),
            reason: "must be at most 255 bytes",
        });
    }
    if label.contains(':') {
        return Err(Error::InvalidLabel {
            label: label.into(),
            reason: "must not contain ':'",
        });
    }
    if label.contains('/') || label.contains('\\') {
        return Err(Error::InvalidLabel {
            label: label.into(),
            reason: "must not contain path separators",
        });
    }
    if label.chars().any(char::is_control) {
        return Err(Error::InvalidLabel {
            label: label.into(),
            reason: "must not contain control characters",
        });
    }
    Ok(())
}

fn validate_key_ref_label(label: &str) -> Result<()> {
    if label.chars().any(|c| {
        matches!(
            c,
            '$' | '~' | '*' | '?' | '[' | ']' | '{' | '}' | ';' | '&' | '|' | '`' | '\'' | '"'
        )
    }) {
        return Err(Error::InvalidLabel {
            label: label.into(),
            reason: "must not contain shell or environment-expansion characters",
        });
    }
    Ok(())
}
