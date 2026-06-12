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
#[non_exhaustive]
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
    /// Import: submodule gitlink entry (SPEC-GIT-IMPORT §3.3). The
    /// `object` is the zero-padded git tree sha1.
    Gitlink { object: Hash, path: String },
    /// Import: git tree-entry name mkit cannot store (SPEC-OBJECTS
    /// §4.1 deserialize-time rules).
    TreeEntryName { object: Hash, name: String },
    /// Import: a git tree mode outside the pinned §3.3 table.
    UnknownTreeMode { object: Hash, mode: String },
    /// Import: a historic mode would normalize, but the state dir is
    /// fork-mode (normalization breaks shared-SHA passthrough).
    NormalizedModeInFork { object: Hash, mode: String },
    /// Import: pre-1970 git timestamp (mkit timestamps are u64).
    NegativeTimestamp { object: Hash, timestamp: i64 },
    /// Import: structurally unparsable git object (SPEC-GIT-IMPORT
    /// §3.2/§3.5 — refused per-ref, never coerced).
    Unparsable { object: Hash, detail: String },
    /// Import: blob over the 1 GiB per-file cap (SPEC-GIT-IMPORT §3.1).
    BlobTooLarge { object: Hash, size: u64 },
    /// Import: git tree with more entries than mkit's decode cap —
    /// storing it would poison a signed object the store can never
    /// read back (SPEC-GIT-IMPORT §3.3).
    TooManyTreeEntries { object: Hash, count: usize },
    /// Import: a tree entry's git mode contradicts the actual kind of
    /// the object it names (e.g. mode 100644 → a commit). git tools
    /// barely tolerate these; mkit's object model cannot represent
    /// them (SPEC-GIT-IMPORT §3.3).
    TreeEntryKind { object: Hash, name: String },
    /// Import: the translated object cannot serialize under
    /// SPEC-OBJECTS caps (oversize payload, illegal field) — refused
    /// per-ref rather than failing the whole run.
    Unrepresentable { object: Hash, detail: String },
    /// Import: more than 1000 parents (`MAX_PARENTS`).
    TooManyParents { object: Hash },
    /// Import: author/tagger identity payload empty or over 4096.
    AuthorPayload { object: Hash },
    /// Import: tag→tag chain beyond the pinned depth (16).
    TagChain { object: Hash },
    /// Import: duplicate entry names after re-sorting to mkit order
    /// (git-representable as file+dir of one name; undecodable here).
    DuplicateTreeEntry { object: Hash },
    /// Import: tree nesting beyond `MAX_TREE_DEPTH` (128).
    TreeTooDeep { object: Hash },
}

impl fmt::Display for Refusal {
    #[allow(clippy::too_many_lines)] // one arm per refusal; flat by design
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
            Self::Gitlink { object, path } => write!(
                f,
                "git tree {} contains a submodule gitlink at {path:?}; submodules are out \
                 of scope (vendor the submodule, or exclude this ref) — SPEC-GIT-IMPORT §3.3",
                &to_hex(object)[..40]
            ),
            Self::TreeEntryName { object, name } => write!(
                f,
                "git tree {} entry {name:?} is not a storable mkit name (SPEC-OBJECTS §4.1); \
                 rename it upstream or exclude this ref",
                &to_hex(object)[..40]
            ),
            Self::UnknownTreeMode { object, mode } => write!(
                f,
                "git tree {} carries mode {mode} outside the import mapping (SPEC-GIT-IMPORT §3.3)",
                &to_hex(object)[..40]
            ),
            Self::NormalizedModeInFork { object, mode } => write!(
                f,
                "git tree {} carries historic mode {mode}, which would normalize lossily; \
                 this state dir is fork-mode, where normalized trees cannot reproduce their \
                 original sha1 — refusing (SPEC-GIT-IMPORT §3.3)",
                &to_hex(object)[..40]
            ),
            Self::Unparsable { object, detail } => write!(
                f,
                "git object {} is structurally unparsable ({detail}); refused per SPEC-GIT-IMPORT §3.2",
                to_hex(object)
            ),
            Self::TooManyTreeEntries { object, count } => write!(
                f,
                "git tree {} has {count} entries, over mkit's decode cap (SPEC-GIT-IMPORT §3.3)",
                to_hex(object)
            ),
            Self::TreeEntryKind { object, name } => write!(
                f,
                "git tree {} entry {name:?} names an object of a kind its mode contradicts (SPEC-GIT-IMPORT §3.3)",
                to_hex(object)
            ),
            Self::Unrepresentable { object, detail } => write!(
                f,
                "git object {} does not serialize under SPEC-OBJECTS ({detail}); refused per SPEC-GIT-IMPORT §3",
                to_hex(object)
            ),
            Self::BlobTooLarge { object, size } => write!(
                f,
                "git blob {} is {size} bytes, over the 1 GiB per-file cap (SPEC-GIT-IMPORT §3.1)",
                to_hex(object)
            ),
            Self::NegativeTimestamp { object, timestamp } => write!(
                f,
                "git object {} has pre-1970 timestamp {timestamp}; mkit timestamps are unsigned",
                &to_hex(object)[..40]
            ),
            Self::TooManyParents { object } => write!(
                f,
                "git commit {} has more than 1000 parents (MAX_PARENTS)",
                &to_hex(object)[..40]
            ),
            Self::AuthorPayload { object } => write!(
                f,
                "git object {} has an author/tagger identity that is empty or over 4096 bytes",
                &to_hex(object)[..40]
            ),
            Self::TagChain { object } => write!(
                f,
                "git tag {} heads a tag chain deeper than 16; refusing (SPEC-GIT-IMPORT §3.4)",
                &to_hex(object)[..40]
            ),
            Self::DuplicateTreeEntry { object } => write!(
                f,
                "git tree {} contains entries whose names collide byte-equal in mkit \
                 order (e.g. a file and a directory of one name); refusing",
                &to_hex(object)[..40]
            ),
            Self::TreeTooDeep { object } => write!(
                f,
                "git tree {} nests deeper than 128 levels; refusing (matches mkit's \
                 MAX_TREE_DEPTH defense)",
                &to_hex(object)[..40]
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
