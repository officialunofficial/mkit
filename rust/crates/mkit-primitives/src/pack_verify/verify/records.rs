//! Fixed-layout evidence record codecs for the verify indexes.
//!
//! Records are opaque page payloads; every codec round-trips byte-exactly and
//! refuses unknown versions, tags, and trailing data. Nothing in a record
//! grants verification authority: interpretation belongs to the sealed
//! [`super::super::VerifiedPack`] and its committed roots.
use crate::{
    closure::{EdgeKind, ObjectEdge},
    codec::{Budget, Cursor, failure},
    error::{Failure, FailureCode},
    evidence::{
        MemberFact, PackSource, PageCommitment, PageKind, ProofReference, RepositoryId, Revision,
        SourceBinding,
    },
};
use mkit_core::{hash::Hash, object::ObjectType};

/// Encoded object-record length.
pub const OBJECT_BYTES: usize = 120;
/// Encoded occurrence-record length.
pub const OCCURRENCE_BYTES: usize = 179;
/// Encoded ordinal-record length.
pub const ORDINAL_BYTES: usize = 42;
/// Encoded head-record length.
pub const HEAD_BYTES: usize = 99;
/// Encoded edge dependency-record length.
pub const EDGE_BYTES: usize = 93;
/// Encoded external dependency-record length.
pub const EXTERNAL_BYTES: usize = 289;

fn invalid() -> Failure {
    failure(FailureCode::InvalidEvidence)
}

fn kind_byte(kind: ObjectType) -> u8 {
    kind as u8
}

fn kind_from(byte: u8) -> Result<ObjectType, Failure> {
    match byte {
        0x01 => Ok(ObjectType::Blob),
        0x02 => Ok(ObjectType::Tree),
        0x03 => Ok(ObjectType::Commit),
        0x04 => Ok(ObjectType::Remix),
        0x05 => Ok(ObjectType::ChunkedBlob),
        0x07 => Ok(ObjectType::Tag),
        _ => Err(invalid()),
    }
}

fn put_kind(byte: &mut u8, kind: Option<ObjectType>) {
    *byte = kind.map_or(0, kind_byte);
}

fn bool_from(cursor: &mut Cursor<'_, '_>) -> Result<bool, Failure> {
    match cursor.byte()? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(invalid()),
    }
}

/// Per-object signature outcome; unsigned kinds record `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Signature {
    /// Kind carries no signature.
    None,
    /// Embedded signature verified against its embedded signer.
    Valid,
    /// Embedded signature failed; provisional evidence only, never sealed.
    Invalid,
}

impl Signature {
    fn byte(self) -> u8 {
        match self {
            Self::None => 0,
            Self::Valid => 1,
            Self::Invalid => 2,
        }
    }
    fn from(byte: u8) -> Result<Self, Failure> {
        match byte {
            0 => Ok(Self::None),
            1 => Ok(Self::Valid),
            2 => Ok(Self::Invalid),
            _ => Err(invalid()),
        }
    }
}

/// Signature domain recorded for diagnosis; `0` when `signature` is `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Domain {
    /// Unsigned.
    None,
    /// Commit signature domain.
    Commit,
    /// Remix signature domain.
    Remix,
    /// Tag signature domain.
    Tag,
}

impl Domain {
    fn byte(self) -> u8 {
        match self {
            Self::None => 0,
            Self::Commit => 1,
            Self::Remix => 2,
            Self::Tag => 3,
        }
    }
    fn from(byte: u8) -> Result<Self, Failure> {
        match byte {
            0 => Ok(Self::None),
            1 => Ok(Self::Commit),
            2 => Ok(Self::Remix),
            3 => Ok(Self::Tag),
            _ => Err(invalid()),
        }
    }
    /// Domain a signed kind uses; unsigned kinds return `None`.
    #[must_use]
    pub fn for_kind(kind: ObjectType) -> Self {
        match kind {
            ObjectType::Commit => Self::Commit,
            ObjectType::Remix => Self::Remix,
            ObjectType::Tag => Self::Tag,
            _ => Self::None,
        }
    }
}

/// One distinct object, keyed by type-dependent object id. A duplicate
/// occurrence never rewrites this record; its evidence lives in the
/// occurrence sequence under the same object identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectRecord {
    /// Canonical object kind.
    pub kind: ObjectType,
    /// Exact canonical byte length.
    pub canonical_len: u64,
    /// Wire ordinal of the first (owning) occurrence.
    pub first_ordinal: u64,
    /// Effective delta depth: `0` raw, else base depth plus one.
    pub delta_depth: u32,
    /// Signature outcome for this object.
    pub signature: Signature,
    /// Signature domain, `None` when unsigned.
    pub domain: Domain,
    /// Signer embedded in the object, zero when unsigned.
    pub signer: Hash,
    /// Domain digest over the object's signing bytes, zero when unsigned.
    pub signing_digest: Hash,
    /// Ordinal of this object's first dependency-sequence record.
    pub dep_start: u64,
    /// Number of dependency-sequence records owned by this object.
    pub dep_count: u64,
    /// Chunked-blob manifest total reconstructed size, zero otherwise.
    pub chunk_total: u64,
    /// Chunked-blob manifest chunk count, zero otherwise.
    pub chunk_count: u64,
}

impl ObjectRecord {
    /// Canonical fixed encoding.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(OBJECT_BYTES);
        out.push(1u8);
        out.push(kind_byte(self.kind));
        out.extend_from_slice(&self.canonical_len.to_le_bytes());
        out.extend_from_slice(&self.first_ordinal.to_le_bytes());
        out.extend_from_slice(&self.delta_depth.to_le_bytes());
        out.push(self.signature.byte());
        out.push(self.domain.byte());
        out.extend_from_slice(&self.signer);
        out.extend_from_slice(&self.signing_digest);
        out.extend_from_slice(&self.dep_start.to_le_bytes());
        out.extend_from_slice(&self.dep_count.to_le_bytes());
        out.extend_from_slice(&self.chunk_total.to_le_bytes());
        out.extend_from_slice(&self.chunk_count.to_le_bytes());
        debug_assert_eq!(out.len(), OBJECT_BYTES);
        out
    }

    /// Strict decode of one record.
    ///
    /// # Errors
    /// Wrong version, unknown kind/signature/domain bytes, wrong length,
    /// inconsistent signature facts.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Failure> {
        if bytes.len() != OBJECT_BYTES {
            return Err(invalid());
        }
        let mut budget = Budget::new(64, 0);
        let mut cursor = Cursor::new(bytes, &mut budget);
        if cursor.byte()? != 1 {
            return Err(invalid());
        }
        let record = Self {
            kind: kind_from(cursor.byte()?)?,
            canonical_len: cursor.u64()?,
            first_ordinal: cursor.u64()?,
            delta_depth: cursor.u32()?,
            signature: Signature::from(cursor.byte()?)?,
            domain: Domain::from(cursor.byte()?)?,
            signer: cursor.array()?,
            signing_digest: cursor.array()?,
            dep_start: cursor.u64()?,
            dep_count: cursor.u64()?,
            chunk_total: cursor.u64()?,
            chunk_count: cursor.u64()?,
        };
        cursor.finish()?;
        if (record.domain == Domain::None) != (record.signature == Signature::None)
            || record.domain != Domain::for_kind(record.kind)
            || (record.kind != ObjectType::ChunkedBlob
                && (record.chunk_total != 0 || record.chunk_count != 0))
            || (record.signature == Signature::None
                && (record.signer != [0; 32] || record.signing_digest != [0; 32]))
        {
            return Err(invalid());
        }
        Ok(record)
    }
}

/// One wire-order occurrence. `first` marks the owning occurrence that wrote
/// the object record; every occurrence repeats the object facts so a page
/// alone carries the entry's verified outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OccurrenceRecord {
    /// Object identity.
    pub object: Hash,
    /// Canonical object kind.
    pub kind: ObjectType,
    /// Exact canonical byte length.
    pub canonical_len: u64,
    /// Complete frame offset in the source pack.
    pub frame_offset: u64,
    /// Complete frame length in the source pack.
    pub frame_len: u64,
    /// Encoded frame type (`0x00`, `0x02`, `0x03`, `0x04`).
    pub wire_type: u8,
    /// `true` when the entry decoded through a delta.
    pub from_delta: bool,
    /// Referenced delta base id, or zero when `from_delta` is false.
    pub delta_base: Hash,
    /// Effective delta depth for this occurrence.
    pub delta_depth: u32,
    /// Signature outcome.
    pub signature: Signature,
    /// Whether this occurrence owns the object record.
    pub first: bool,
    /// Signature domain, `None` when unsigned.
    pub domain: Domain,
    /// Signer embedded in the object, zero when unsigned.
    pub signer: Hash,
    /// Domain digest over the object's signing bytes, zero when unsigned.
    pub signing_digest: Hash,
    /// Ordinal of this occurrence's first external dependency record.
    pub ext_start: u64,
    /// Number of external dependency records this occurrence consumed.
    pub ext_count: u64,
}

impl OccurrenceRecord {
    /// Canonical fixed encoding.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(OCCURRENCE_BYTES);
        out.push(1u8);
        out.extend_from_slice(&self.object);
        out.push(kind_byte(self.kind));
        out.extend_from_slice(&self.canonical_len.to_le_bytes());
        out.extend_from_slice(&self.frame_offset.to_le_bytes());
        out.extend_from_slice(&self.frame_len.to_le_bytes());
        out.push(self.wire_type);
        out.push(u8::from(self.from_delta));
        out.extend_from_slice(&self.delta_base);
        out.extend_from_slice(&self.delta_depth.to_le_bytes());
        out.push(self.signature.byte());
        out.push(u8::from(self.first));
        out.push(self.domain.byte());
        out.extend_from_slice(&self.signer);
        out.extend_from_slice(&self.signing_digest);
        out.extend_from_slice(&self.ext_start.to_le_bytes());
        out.extend_from_slice(&self.ext_count.to_le_bytes());
        debug_assert_eq!(out.len(), OCCURRENCE_BYTES);
        out
    }

    /// Strict decode of one record.
    ///
    /// # Errors
    /// Wrong version, unknown fields, wrong length, inconsistent flags.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Failure> {
        if bytes.len() != OCCURRENCE_BYTES {
            return Err(invalid());
        }
        let mut budget = Budget::new(64, 0);
        let mut cursor = Cursor::new(bytes, &mut budget);
        if cursor.byte()? != 1 {
            return Err(invalid());
        }
        let record = Self {
            object: cursor.array()?,
            kind: kind_from(cursor.byte()?)?,
            canonical_len: cursor.u64()?,
            frame_offset: cursor.u64()?,
            frame_len: cursor.u64()?,
            wire_type: cursor.byte()?,
            from_delta: bool_from(&mut cursor)?,
            delta_base: cursor.array()?,
            delta_depth: cursor.u32()?,
            signature: Signature::from(cursor.byte()?)?,
            first: bool_from(&mut cursor)?,
            domain: Domain::from(cursor.byte()?)?,
            signer: cursor.array()?,
            signing_digest: cursor.array()?,
            ext_start: cursor.u64()?,
            ext_count: cursor.u64()?,
        };
        cursor.finish()?;
        if !matches!(record.wire_type, 0x00 | 0x02 | 0x03 | 0x04)
            || (record.domain == Domain::None) != (record.signature == Signature::None)
            || record.domain != Domain::for_kind(record.kind)
            || (!record.from_delta && record.delta_base != [0; 32])
            || (record.signature == Signature::None
                && (record.signer != [0; 32] || record.signing_digest != [0; 32]))
            || (record.from_delta && record.delta_depth == 0)
            || (!record.from_delta && record.delta_depth != 0)
        {
            return Err(invalid());
        }
        Ok(record)
    }
}

/// One distinct object in first-occurrence order. The ordinal sequence lets a
/// consumer enumerate the object set positionally under one committed root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OrdinalRecord {
    /// Object identity.
    pub object: Hash,
    /// Canonical object kind.
    pub kind: ObjectType,
    /// Exact canonical byte length.
    pub canonical_len: u64,
}

impl OrdinalRecord {
    /// Canonical fixed encoding.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ORDINAL_BYTES);
        out.push(1u8);
        out.extend_from_slice(&self.object);
        out.push(kind_byte(self.kind));
        out.extend_from_slice(&self.canonical_len.to_le_bytes());
        debug_assert_eq!(out.len(), ORDINAL_BYTES);
        out
    }

    /// Strict decode of one record.
    ///
    /// # Errors
    /// Wrong version, unknown kind bytes, wrong length.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Failure> {
        if bytes.len() != ORDINAL_BYTES {
            return Err(invalid());
        }
        let mut budget = Budget::new(48, 0);
        let mut cursor = Cursor::new(bytes, &mut budget);
        if cursor.byte()? != 1 {
            return Err(invalid());
        }
        let record = Self {
            object: cursor.array()?,
            kind: kind_from(cursor.byte()?)?,
            canonical_len: cursor.u64()?,
        };
        cursor.finish()?;
        Ok(record)
    }
}

/// Ordered dependency evidence: object edges, or an external-base fact a
/// delta consumed. Tags distinguish the two layouts.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DependencyRecord {
    /// A direct reference of the object at its first occurrence.
    Edge {
        /// Referencing object id.
        subject: Hash,
        /// Subject's first-occurrence ordinal.
        subject_ordinal: u64,
        /// The extracted reference.
        edge: ObjectEdge,
    },
    /// A repository-scoped verified-member fact supplying a delta base.
    External {
        /// Wire ordinal of the delta entry that consumed the base.
        consumed_ordinal: u64,
        /// Object the consuming entry produced.
        child: Hash,
        /// The authenticated membership fact.
        fact: MemberFact,
    },
}

fn edge_kind_byte(kind: EdgeKind) -> u8 {
    match kind {
        EdgeKind::TreeEntry => 0,
        EdgeKind::Tree => 1,
        EdgeKind::Parent => 2,
        EdgeKind::Chunk => 3,
        EdgeKind::TagTarget => 4,
    }
}

fn edge_kind_from(byte: u8) -> Result<EdgeKind, Failure> {
    match byte {
        0 => Ok(EdgeKind::TreeEntry),
        1 => Ok(EdgeKind::Tree),
        2 => Ok(EdgeKind::Parent),
        3 => Ok(EdgeKind::Chunk),
        4 => Ok(EdgeKind::TagTarget),
        _ => Err(invalid()),
    }
}

impl DependencyRecord {
    /// Canonical encoding; edge records are [`EDGE_BYTES`], external records
    /// [`EXTERNAL_BYTES`].
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::Edge {
                subject,
                subject_ordinal,
                edge,
            } => {
                let mut out = Vec::with_capacity(EDGE_BYTES);
                out.push(1u8);
                out.push(1u8);
                out.extend_from_slice(subject);
                out.extend_from_slice(&subject_ordinal.to_le_bytes());
                out.extend_from_slice(&edge.target);
                out.push(edge_kind_byte(edge.kind));
                out.extend_from_slice(&edge.ordinal.to_le_bytes());
                let flags = u8::from(edge.expected_kind.is_some())
                    | (u8::from(edge.expected_len.is_some()) << 1);
                out.push(flags);
                let mut expected_kind = 0u8;
                put_kind(&mut expected_kind, edge.expected_kind);
                out.push(expected_kind);
                out.extend_from_slice(&edge.expected_len.unwrap_or(0).to_le_bytes());
                debug_assert_eq!(out.len(), EDGE_BYTES);
                out
            }
            Self::External {
                consumed_ordinal,
                child,
                fact,
            } => {
                let mut out = Vec::with_capacity(EXTERNAL_BYTES);
                out.push(1u8);
                out.push(2u8);
                out.extend_from_slice(&consumed_ordinal.to_le_bytes());
                out.extend_from_slice(child);
                out.extend_from_slice(&fact.repository.0);
                out.extend_from_slice(&fact.incarnation.0);
                out.extend_from_slice(&fact.object);
                out.push(kind_byte(fact.kind));
                out.extend_from_slice(&fact.canonical_len.to_le_bytes());
                out.extend_from_slice(&fact.supplier.id);
                out.extend_from_slice(&fact.supplier.len.to_le_bytes());
                out.extend_from_slice(&fact.supplier.binding.0);
                out.extend_from_slice(&fact.canonical_binding.0);
                out.extend_from_slice(&fact.revision.0);
                out.extend_from_slice(&fact.delta_depth.to_le_bytes());
                out.push(u8::from(fact.published));
                out.push(u8::from(fact.held));
                debug_assert_eq!(out.len(), EXTERNAL_BYTES);
                out
            }
        }
    }

    /// Strict decode of one record; the tag selects the layout.
    ///
    /// # Errors
    /// Wrong version/tag, unknown kind bytes, wrong length.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Failure> {
        if bytes.len() < 2 {
            return Err(invalid());
        }
        let mut budget = Budget::new(128, 0);
        let mut cursor = Cursor::new(bytes, &mut budget);
        if cursor.byte()? != 1 {
            return Err(invalid());
        }
        let record = match cursor.byte()? {
            1 => {
                if bytes.len() != EDGE_BYTES {
                    return Err(invalid());
                }
                let subject = cursor.array()?;
                let subject_ordinal = cursor.u64()?;
                let target = cursor.array()?;
                let kind = edge_kind_from(cursor.byte()?)?;
                let ordinal = cursor.u64()?;
                let flags = cursor.byte()?;
                if flags & !0b11 != 0 {
                    return Err(invalid());
                }
                let expected_kind_byte = cursor.byte()?;
                let expected_len_value = cursor.u64()?;
                let expected_kind = if flags & 0b01 != 0 {
                    Some(kind_from(expected_kind_byte)?)
                } else {
                    if expected_kind_byte != 0 {
                        return Err(invalid());
                    }
                    None
                };
                let expected_len = if flags & 0b10 != 0 {
                    Some(expected_len_value)
                } else {
                    if expected_len_value != 0 {
                        return Err(invalid());
                    }
                    None
                };
                Self::Edge {
                    subject,
                    subject_ordinal,
                    edge: ObjectEdge {
                        target,
                        kind,
                        ordinal,
                        expected_kind,
                        expected_len,
                    },
                }
            }
            2 => {
                if bytes.len() != EXTERNAL_BYTES {
                    return Err(invalid());
                }
                let consumed_ordinal = cursor.u64()?;
                let child = cursor.array()?;
                Self::External {
                    consumed_ordinal,
                    child,
                    fact: MemberFact {
                        repository: RepositoryId(cursor.array()?),
                        incarnation: Revision(cursor.array()?),
                        object: cursor.array()?,
                        kind: kind_from(cursor.byte()?)?,
                        canonical_len: cursor.u64()?,
                        supplier: PackSource {
                            id: cursor.array()?,
                            len: cursor.u64()?,
                            binding: SourceBinding(cursor.array()?),
                        },
                        canonical_binding: SourceBinding(cursor.array()?),
                        revision: Revision(cursor.array()?),
                        delta_depth: cursor.u32()?,
                        published: bool_from(&mut cursor)?,
                        held: bool_from(&mut cursor)?,
                    },
                }
            }
            _ => return Err(invalid()),
        };
        cursor.finish()?;
        Ok(record)
    }
}

/// An immutable head-candidate fact. The proof fields locate the owning
/// object record inside the committed object index; the consumer supplies
/// the verified object-set root when constructing a [`ProofReference`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeadRecord {
    /// Candidate object id.
    pub object: Hash,
    /// Verified kind; closure decides whether it is an allowed head.
    pub kind: ObjectType,
    /// Owning occurrence ordinal.
    pub occurrence_ordinal: u64,
    /// Object-index leaf page containing the object record.
    pub page: PageCommitment,
    /// Record position within that page.
    pub ordinal_in_page: u64,
}

impl HeadRecord {
    /// The authenticated lookup a consumer completes under the verified
    /// object-set root.
    #[must_use]
    pub fn reference(&self, root: Hash) -> ProofReference {
        ProofReference {
            root,
            page: self.page,
            ordinal: self.ordinal_in_page,
        }
    }

    /// Canonical fixed encoding.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEAD_BYTES);
        out.push(1u8);
        out.extend_from_slice(&self.object);
        out.push(kind_byte(self.kind));
        out.extend_from_slice(&self.occurrence_ordinal.to_le_bytes());
        out.extend_from_slice(&self.page.digest);
        out.push(crate::evidence::pages::kind_byte(self.page.kind));
        out.extend_from_slice(&self.page.len.to_le_bytes());
        out.extend_from_slice(&self.page.items.to_le_bytes());
        out.extend_from_slice(&self.ordinal_in_page.to_le_bytes());
        debug_assert_eq!(out.len(), HEAD_BYTES);
        out
    }

    /// Strict decode of one record.
    ///
    /// # Errors
    /// Wrong version, unknown kind bytes, wrong length, non-Object pages.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Failure> {
        if bytes.len() != HEAD_BYTES {
            return Err(invalid());
        }
        let mut budget = Budget::new(64, 0);
        let mut cursor = Cursor::new(bytes, &mut budget);
        if cursor.byte()? != 1 {
            return Err(invalid());
        }
        let record = Self {
            object: cursor.array()?,
            kind: kind_from(cursor.byte()?)?,
            occurrence_ordinal: cursor.u64()?,
            page: PageCommitment {
                digest: cursor.array()?,
                kind: match cursor.byte()? {
                    0 => PageKind::Objects,
                    _ => return Err(invalid()),
                },
                len: cursor.u64()?,
                items: cursor.u64()?,
            },
            ordinal_in_page: cursor.u64()?,
        };
        cursor.finish()?;
        if record.ordinal_in_page >= record.page.items {
            return Err(invalid());
        }
        Ok(record)
    }
}
