//! Bridge error taxonomy.
//!
//! [`Refusal`] is the closed set of *policy* refusals from
//! SPEC-GIT-BRIDGE (§4, §6.2, §7.1, §8, §12.1): the object or ref is
//! valid mkit data that the v1 mapping deliberately does not
//! translate. Everything else is a hard error.

use mkit_core::Hash;
use mkit_core::hash::to_hex;
use std::fmt;

/// A deliberate, spec'd refusal to translate (actionable; per-ref
/// granularity is the caller's job).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// Remix objects are not translated in v1 (SPEC-GIT-BRIDGE §8).
    Remix { object: Hash },
    /// Fixed-size chunked-blob manifests have no exact inverse
    /// (SPEC-GIT-BRIDGE §4).
    FixedSizeChunking { object: Hash, chunk_size: u32 },
    /// Content-defined manifest a conformant mkit writer cannot have
    /// produced (≤ threshold total size, or boundaries that differ
    /// from the pinned `FastCDC` output) — it would not round-trip
    /// (SPEC-GIT-BRIDGE §4).
    NonCanonicalChunking { object: Hash, detail: &'static str },
    /// Commit/tag timestamp exceeds `i64::MAX` (SPEC-GIT-BRIDGE §6.2).
    TimestampOverflow { object: Hash, timestamp: u64 },
    /// Tag object name contains bytes outside the mkit ref grammar
    /// (SPEC-GIT-BRIDGE §7.1).
    TagName { object: Hash },
    /// Ref name is mkit-legal but git-illegal (SPEC-GIT-BRIDGE §12.1).
    RefName { name: String, reason: &'static str },
    /// Object prologue carries a schema version this mapping does not
    /// cover (SPEC-GIT-BRIDGE §1.2).
    SchemaVersion { object: Hash },
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Remix { object } => write!(
                f,
                "remix object {} is not translatable in bridge v1 (SPEC-GIT-BRIDGE §8)",
                to_hex(object)
            ),
            Self::FixedSizeChunking { object, chunk_size } => write!(
                f,
                "chunked blob {} uses fixed-size chunking ({chunk_size}); only \
                 content-defined manifests translate (SPEC-GIT-BRIDGE §4)",
                to_hex(object)
            ),
            Self::NonCanonicalChunking { object, detail } => write!(
                f,
                "chunked blob {} cannot have been produced by a conformant \
                 mkit writer ({detail}); refusing a non-round-trippable \
                 translation (SPEC-GIT-BRIDGE §4)",
                to_hex(object)
            ),
            Self::TimestampOverflow { object, timestamp } => write!(
                f,
                "object {} timestamp {timestamp} exceeds the git-representable range",
                to_hex(object)
            ),
            Self::TagName { object } => write!(
                f,
                "tag object {} has a name outside the mkit ref grammar; \
                 it cannot ride in a git tag header",
                to_hex(object)
            ),
            Self::RefName { name, reason } => {
                write!(f, "ref {name:?} is not a legal git ref name ({reason})")
            }
            Self::SchemaVersion { object } => write!(
                f,
                "object {} has a schema_version other than 1; bridge v1 maps schema 1 only",
                to_hex(object)
            ),
        }
    }
}

/// Unified bridge error.
#[derive(Debug)]
pub enum BridgeError {
    /// A spec'd policy refusal (see [`Refusal`]).
    Refused(Refusal),
    /// Reading or decoding a source mkit object failed.
    Source(String),
    /// Reconstruction input is not a bridge-emitted git object
    /// (missing/duplicate/unknown `mkit-*` headers, malformed body,
    /// non-bridge mode bytes, …).
    NotBridgeObject(String),
    /// Reconstructed bytes failed an integrity check (BLAKE3 linkage
    /// or round-trip mismatch).
    Integrity(String),
    /// Filesystem error from the loose-object writer or map cache.
    Io(std::io::Error),
}

impl fmt::Display for BridgeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused(r) => write!(f, "refused: {r}"),
            Self::Source(m) => write!(f, "source object: {m}"),
            Self::NotBridgeObject(m) => write!(f, "not a bridge-emitted git object: {m}"),
            Self::Integrity(m) => write!(f, "integrity: {m}"),
            Self::Io(e) => write!(f, "io: {e}"),
        }
    }
}

impl std::error::Error for BridgeError {}

impl From<std::io::Error> for BridgeError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<Refusal> for BridgeError {
    fn from(r: Refusal) -> Self {
        Self::Refused(r)
    }
}
