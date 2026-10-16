//! Authenticated linked output pages. Decoding authenticates bytes, not authority.

use super::EdgeKind;
use crate::{
    error::{BoundedDetail, Failure, FailureCode, Location},
    evidence::{
        MemberFact, PackSource, PageCommitment, PageKind, RepositoryId, Revision, SourceBinding,
    },
    pack_verify::EvidenceSequence,
};
use mkit_core::{
    hash::{Hash, ZERO, domain_digest},
    object::ObjectType,
};

const WITNESS_DOMAIN: &[u8] = b"mkit-closure-witness:v1";
const MISSING_DOMAIN: &[u8] = b"mkit-closure-missing:v1";

/// Finite caller allowances for one authenticated output page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageDecodeCfg {
    /// Maximum encoded bytes, checked before hashing or parsing.
    pub max_bytes: u64,
    /// Maximum missing-edge reasons allocated for one object.
    pub max_reasons: u64,
    /// Maximum work units: encoded bytes plus decoded reason records.
    pub max_work: u64,
}
/// One relied-on membership observation, preserving its supplier and bindings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessPage {
    /// Previous witness page, if any.
    pub previous: Option<PageCommitment>,
    /// Host-supplied membership fact; page decoding grants no authority.
    pub fact: MemberFact,
}
/// One occurrence requiring a missing object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct MissingReason {
    /// Source object, or absent for an advanced head.
    pub source: Option<Hash>,
    /// Edge role, or absent for an advanced head.
    pub kind: Option<EdgeKind>,
    /// Reference occurrence ordinal.
    pub ordinal: u64,
}
/// One missing ID and its bounded occurrence reasons.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissingObject {
    /// Missing canonical identity.
    pub object: Hash,
    /// Complete reasons recorded for this identity.
    pub reasons: Vec<MissingReason>,
}
/// One linked missing-object page. Links traverse IDs in ascending order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissingPage {
    /// Previous page, containing the next larger ID, if any.
    pub previous: Option<PageCommitment>,
    /// Missing identity and reasons.
    pub missing: MissingObject,
}
/// Complete committed missing set; construction belongs to the walker.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct MissingSet {
    root: Option<PageCommitment>,
    sequence: EvidenceSequence,
}
impl MissingSet {
    /// First page to acquire. An empty set has no page.
    #[must_use]
    pub const fn root(&self) -> Option<PageCommitment> {
        self.root
    }
    /// Exact committed sequence; an empty sequence uses the zero root sentinel.
    #[must_use]
    pub const fn sequence(&self) -> EvidenceSequence {
        self.sequence
    }
    /// Exact number of missing identities, never a truncated count.
    #[must_use]
    pub const fn count(&self) -> u64 {
        self.sequence.count
    }
    pub(super) fn seal(root: Option<PageCommitment>, count: u64) -> Self {
        Self {
            root,
            sequence: EvidenceSequence {
                root: root.map_or(ZERO, |page| page.digest),
                count,
            },
        }
    }
}

/// Authenticate a local visited-state page without resuming or constructing evidence.
///
/// # Errors
/// Returns `ResourceLimit` for explicit byte/work allowances and `InvalidResponse`
/// for authentication or strict current-version state grammar failures. The
/// immutable format additionally caps state pages at 1,024 bytes.
pub fn validate_state_page(
    page: PageCommitment,
    bytes: &[u8],
    cfg: PageDecodeCfg,
) -> Result<(), Failure> {
    let _input = authenticate(page, bytes, cfg, b"mkit-closure-state:v1")?;
    super::journal::validate_bytes(bytes)
}

/// Encode one membership witness, retaining all supplied fields.
///
/// # Errors
/// Returns `ResourceLimit` on allocation failure or `InvalidResponse` for an
/// invalid previous-page commitment.
pub fn encode_witness(
    previous: Option<PageCommitment>,
    fact: &MemberFact,
) -> Result<(PageCommitment, Vec<u8>), Failure> {
    let mut out = start(previous, 400)?;
    out.extend_from_slice(&fact.repository.0);
    out.extend_from_slice(&fact.incarnation.0);
    out.extend_from_slice(&fact.object);
    out.push(fact.kind as u8);
    out.extend_from_slice(&fact.canonical_len.to_le_bytes());
    out.extend_from_slice(&fact.supplier.id);
    out.extend_from_slice(&fact.supplier.len.to_le_bytes());
    out.extend_from_slice(&fact.supplier.binding.0);
    out.extend_from_slice(&fact.canonical_binding.0);
    out.extend_from_slice(&fact.revision.0);
    out.extend_from_slice(&fact.delta_depth.to_le_bytes());
    out.push(u8::from(fact.published));
    out.push(u8::from(fact.held));
    Ok(finish(WITNESS_DOMAIN, out))
}
/// Authenticate and decode precisely one witness page.
///
/// # Errors
/// Returns `ResourceLimit` for caller allowance exhaustion and `InvalidResponse`
/// for authentication, framing, reserved-tag, or trailing-byte failures.
pub fn decode_witness(
    page: PageCommitment,
    bytes: &[u8],
    cfg: PageDecodeCfg,
) -> Result<WitnessPage, Failure> {
    let mut input = authenticate(page, bytes, cfg, WITNESS_DOMAIN)?;
    let previous = input.header()?;
    let fact = MemberFact {
        repository: RepositoryId(input.take()?),
        incarnation: Revision(input.take()?),
        object: input.take()?,
        kind: input.kind()?,
        canonical_len: input.number()?,
        supplier: PackSource {
            id: input.take()?,
            len: input.number()?,
            binding: SourceBinding(input.take()?),
        },
        canonical_binding: SourceBinding(input.take()?),
        revision: Revision(input.take()?),
        delta_depth: u32::from_le_bytes(input.take()?),
        published: input.boolean()?,
        held: input.boolean()?,
    };
    input.end()?;
    Ok(WitnessPage { previous, fact })
}
/// Encode one missing identity. The walker bounds reasons before calling this.
///
/// # Errors
/// Returns `ResourceLimit` for size overflow or allocation failure and
/// `InvalidResponse` for an invalid previous-page commitment.
pub fn encode_missing(
    previous: Option<PageCommitment>,
    missing: &MissingObject,
) -> Result<(PageCommitment, Vec<u8>), Failure> {
    if missing.reasons.is_empty()
        || missing.reasons.windows(2).any(|pair| pair[0] >= pair[1])
        || missing.reasons.iter().any(|r| {
            r.source.is_some() != r.kind.is_some() || (r.source.is_none() && r.ordinal != 0)
        })
    {
        return Err(invalid());
    }
    let capacity = missing
        .reasons
        .len()
        .checked_mul(43)
        .and_then(|n| n.checked_add(82))
        .ok_or_else(resource)?;
    let mut out = start(previous, capacity)?;
    out.extend_from_slice(&missing.object);
    out.extend_from_slice(&(missing.reasons.len() as u64).to_le_bytes());
    for reason in &missing.reasons {
        out.push(u8::from(reason.source.is_some()));
        if let Some(source) = reason.source {
            out.extend_from_slice(&source);
        }
        out.push(match reason.kind {
            None => 0,
            Some(EdgeKind::TreeEntry) => 1,
            Some(EdgeKind::Tree) => 2,
            Some(EdgeKind::Parent) => 3,
            Some(EdgeKind::Chunk) => 4,
            Some(EdgeKind::TagTarget) => 5,
        });
        out.extend_from_slice(&reason.ordinal.to_le_bytes());
    }
    Ok(finish(MISSING_DOMAIN, out))
}
/// Authenticate and decode one missing-object page with bounded allocation.
///
/// # Errors
/// Returns `ResourceLimit` for byte, reason, work, or allocation exhaustion;
/// returns `InvalidResponse` for authentication or strict grammar failures.
pub fn decode_missing(
    page: PageCommitment,
    bytes: &[u8],
    cfg: PageDecodeCfg,
) -> Result<MissingPage, Failure> {
    let mut input = authenticate(page, bytes, cfg, MISSING_DOMAIN)?;
    let previous = input.header()?;
    let object = input.take()?;
    let count = input.number()?;
    if count == 0 {
        return Err(invalid());
    }
    if count > cfg.max_reasons
        || (bytes.len() as u64)
            .checked_add(count)
            .is_none_or(|work| work > cfg.max_work)
    {
        return Err(resource());
    }
    // Check the minimum wire extent before a platform-sized conversion so a
    // forged count has the same refusal on 32-bit and 64-bit hosts.
    if count > ((bytes.len() - input.position) / 10) as u64 {
        return Err(invalid());
    }
    let count = usize::try_from(count).map_err(|_| resource())?;
    let mut reasons = Vec::new();
    reasons.try_reserve_exact(count).map_err(|_| resource())?;
    for _ in 0..count {
        let source = if input.boolean()? {
            Some(input.take()?)
        } else {
            None
        };
        let kind = match input.byte()? {
            0 => None,
            1 => Some(EdgeKind::TreeEntry),
            2 => Some(EdgeKind::Tree),
            3 => Some(EdgeKind::Parent),
            4 => Some(EdgeKind::Chunk),
            5 => Some(EdgeKind::TagTarget),
            _ => return Err(invalid()),
        };
        let reason = MissingReason {
            source,
            kind,
            ordinal: input.number()?,
        };
        if reason.source.is_some() != reason.kind.is_some()
            || (reason.source.is_none() && reason.ordinal != 0)
            || reasons.last().is_some_and(|last| last >= &reason)
        {
            return Err(invalid());
        }
        reasons.push(reason);
    }
    input.end()?;
    Ok(MissingPage {
        previous,
        missing: MissingObject { object, reasons },
    })
}

fn invalid() -> Failure {
    failure(FailureCode::InvalidResponse)
}
fn resource() -> Failure {
    failure(FailureCode::ResourceLimit)
}
fn failure(code: FailureCode) -> Failure {
    Failure {
        code,
        location: Location::default(),
        detail: BoundedDetail::None,
    }
}
fn valid(page: PageCommitment) -> Result<(), Failure> {
    if page.kind != PageKind::Closure || page.items != 1 || page.len == 0 {
        return Err(invalid());
    }
    Ok(())
}
fn start(previous: Option<PageCommitment>, capacity: usize) -> Result<Vec<u8>, Failure> {
    let mut out = Vec::new();
    out.try_reserve_exact(capacity).map_err(|_| resource())?;
    out.push(1);
    out.push(u8::from(previous.is_some()));
    if let Some(page) = previous {
        valid(page)?;
        out.extend_from_slice(&page.digest);
        out.extend_from_slice(&page.len.to_le_bytes());
    }
    Ok(out)
}
fn finish(domain: &[u8], bytes: Vec<u8>) -> (PageCommitment, Vec<u8>) {
    (
        PageCommitment {
            digest: domain_digest(domain, &bytes),
            kind: PageKind::Closure,
            len: bytes.len() as u64,
            items: 1,
        },
        bytes,
    )
}
fn authenticate<'a>(
    page: PageCommitment,
    bytes: &'a [u8],
    cfg: PageDecodeCfg,
    domain: &[u8],
) -> Result<Cursor<'a>, Failure> {
    if bytes.len() as u64 > cfg.max_bytes || bytes.len() as u64 > cfg.max_work {
        return Err(resource());
    }
    valid(page)?;
    if page.len != bytes.len() as u64 || page.digest != domain_digest(domain, bytes) {
        return Err(invalid());
    }
    Ok(Cursor { bytes, position: 0 })
}
// Grammar: version=1, previous=(0|1,digest:32,len:le64), followed by either
// MemberFact fields in declaration order or object:32,count:le64,reasons.
// Each reason is source=(0|1,hash:32),kind=(0..5),ordinal:le64.
struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}
impl Cursor<'_> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N], Failure> {
        let end = self.position.checked_add(N).ok_or_else(invalid)?;
        let slice = self.bytes.get(self.position..end).ok_or_else(invalid)?;
        let mut value = [0; N];
        value.copy_from_slice(slice);
        self.position = end;
        Ok(value)
    }
    fn byte(&mut self) -> Result<u8, Failure> {
        Ok(self.take::<1>()?[0])
    }
    fn number(&mut self) -> Result<u64, Failure> {
        Ok(u64::from_le_bytes(self.take()?))
    }
    fn boolean(&mut self) -> Result<bool, Failure> {
        match self.byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(invalid()),
        }
    }
    fn kind(&mut self) -> Result<ObjectType, Failure> {
        match self.byte()? {
            1 => Ok(ObjectType::Blob),
            2 => Ok(ObjectType::Tree),
            3 => Ok(ObjectType::Commit),
            4 => Ok(ObjectType::Remix),
            5 => Ok(ObjectType::ChunkedBlob),
            6 => Ok(ObjectType::Delta),
            7 => Ok(ObjectType::Tag),
            _ => Err(invalid()),
        }
    }
    fn header(&mut self) -> Result<Option<PageCommitment>, Failure> {
        if self.byte()? != 1 {
            return Err(invalid());
        }
        if !self.boolean()? {
            return Ok(None);
        }
        let page = PageCommitment {
            digest: self.take()?,
            kind: PageKind::Closure,
            len: self.number()?,
            items: 1,
        };
        valid(page)?;
        Ok(Some(page))
    }
    fn end(&self) -> Result<(), Failure> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(invalid())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const CFG: PageDecodeCfg = PageDecodeCfg {
        max_bytes: 1024,
        max_reasons: 10,
        max_work: 2048,
    };
    fn fact() -> MemberFact {
        MemberFact {
            repository: RepositoryId([1; 32]),
            incarnation: Revision([2; 32]),
            object: [3; 32],
            kind: ObjectType::Blob,
            canonical_len: 90,
            supplier: PackSource {
                id: [4; 32],
                len: 100,
                binding: SourceBinding([5; 32]),
            },
            canonical_binding: SourceBinding([6; 32]),
            revision: Revision([7; 32]),
            delta_depth: 8,
            published: true,
            held: false,
        }
    }
    fn missing() -> MissingObject {
        MissingObject {
            object: [9; 32],
            reasons: vec![
                MissingReason {
                    source: None,
                    kind: None,
                    ordinal: 0,
                },
                MissingReason {
                    source: Some([8; 32]),
                    kind: Some(EdgeKind::Chunk),
                    ordinal: 3,
                },
            ],
        }
    }
    #[test]
    fn roundtrips_preserve_all_fields_and_links() {
        let (first, bytes) = encode_witness(None, &fact()).unwrap();
        assert_eq!(
            decode_witness(first, &bytes, CFG).unwrap(),
            WitnessPage {
                previous: None,
                fact: fact()
            }
        );
        let (page, bytes) = encode_witness(Some(first), &fact()).unwrap();
        assert_eq!(
            decode_witness(page, &bytes, CFG).unwrap().previous,
            Some(first)
        );
        let (page, bytes) = encode_missing(Some(first), &missing()).unwrap();
        assert_eq!(
            decode_missing(page, &bytes, CFG).unwrap(),
            MissingPage {
                previous: Some(first),
                missing: missing()
            }
        );
        let set = MissingSet::seal(Some(page), 1);
        assert_eq!(set.root(), Some(page));
        assert_eq!(set.count(), 1);
        assert_eq!(MissingSet::seal(None, 0).sequence().root, ZERO);
    }
    #[test]
    fn caps_are_exact_and_work_includes_reasons() {
        let (page, bytes) = encode_missing(None, &missing()).unwrap();
        let exact = PageDecodeCfg {
            max_bytes: page.len,
            max_reasons: 2,
            max_work: page.len + 2,
        };
        assert!(decode_missing(page, &bytes, exact).is_ok());
        for cfg in [
            PageDecodeCfg {
                max_bytes: page.len - 1,
                ..exact
            },
            PageDecodeCfg {
                max_reasons: 1,
                ..exact
            },
            PageDecodeCfg {
                max_work: page.len + 1,
                ..exact
            },
        ] {
            assert_eq!(
                decode_missing(page, &bytes, cfg).unwrap_err().code,
                FailureCode::ResourceLimit
            );
        }
    }
    #[test]
    fn duplicate_unordered_and_contradictory_missing_reasons_refuse() {
        let valid = missing();
        for reasons in [
            vec![valid.reasons[0], valid.reasons[0]],
            vec![valid.reasons[1], valid.reasons[0]],
            vec![MissingReason {
                source: None,
                kind: Some(EdgeKind::Chunk),
                ordinal: 0,
            }],
            vec![MissingReason {
                source: Some([1; 32]),
                kind: None,
                ordinal: 0,
            }],
            vec![MissingReason {
                source: None,
                kind: None,
                ordinal: 1,
            }],
        ] {
            assert_eq!(
                encode_missing(
                    None,
                    &MissingObject {
                        object: valid.object,
                        reasons
                    }
                )
                .unwrap_err()
                .code,
                FailureCode::InvalidResponse
            );
        }
        let (_, mut bytes) = encode_missing(None, &valid).unwrap();
        // The first head ordinal begins after header, ID, count and two tags.
        bytes[44] = 1;
        let (page, bytes) = finish(MISSING_DOMAIN, bytes);
        assert_eq!(
            decode_missing(page, &bytes, CFG).unwrap_err().code,
            FailureCode::InvalidResponse
        );
    }
    #[test]
    fn strict_authenticated_grammar_and_commitments() {
        let (_, bytes) = encode_witness(None, &fact()).unwrap();
        for end in 0..bytes.len() {
            let (page, part) = finish(WITNESS_DOMAIN, bytes[..end].to_vec());
            assert!(decode_witness(page, &part, CFG).is_err());
        }
        let mut suffix = bytes.clone();
        suffix.push(0);
        let (page, suffix) = finish(WITNESS_DOMAIN, suffix);
        assert!(decode_witness(page, &suffix, CFG).is_err());
        for offset in [0, 1, 98, bytes.len() - 2, bytes.len() - 1] {
            let mut bad = bytes.clone();
            bad[offset] = 255;
            let (page, bad) = finish(WITNESS_DOMAIN, bad);
            assert!(decode_witness(page, &bad, CFG).is_err());
        }
        let (mut page, bytes) = encode_missing(None, &missing()).unwrap();
        page.digest[0] ^= 1;
        assert!(decode_missing(page, &bytes, CFG).is_err());
        let (page, bytes) = encode_missing(None, &missing()).unwrap();
        assert!(decode_witness(page, &bytes, CFG).is_err());
        for end in 0..bytes.len() {
            let (page, part) = finish(MISSING_DOMAIN, bytes[..end].to_vec());
            assert!(decode_missing(page, &part, CFG).is_err());
        }
        let mut bad = bytes.clone();
        bad[43] = 255;
        let (page, bad) = finish(MISSING_DOMAIN, bad);
        assert!(decode_missing(page, &bad, CFG).is_err());
    }
}
