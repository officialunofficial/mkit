//! Bounded canonical pages. Structural decoding alone does not authenticate a root.
use super::{
    PackSource, PageCommitment, PageKind, ProfileId, RepositoryId, RulesetBinding, RulesetId,
    SourceBinding,
};
use crate::{
    codec::{Budget, Cursor, failure},
    error::{Failure, FailureCode},
    limits::EvidenceLimits,
};
use mkit_core::hash::Hash;

/// Current normative indexed ruleset, independent of crate and format versions.
pub const INDEXED_RULESET: RulesetId = RulesetId(1);
/// Maximum records or children in one encoded page.
pub const PAGE_FANOUT: u16 = 16;
/// Largest encoded page in this format.
pub const MAX_PAGE_BYTES: u64 = 1 << 20;
pub(crate) const HEADER_BYTES: u64 = 123;
/// Cursor takes [`PageView::decode`] spends on the fixed header.
const HEADER_TAKES: u64 = 13;
pub(crate) const PAGE_DOMAIN: &[u8] = b"mkit-evidence-page:v1";

/// Owned canonical page bytes; construction grants no verification authority.
#[derive(Debug)]
#[must_use]
pub struct EncodedPage {
    bytes: Vec<u8>,
    commitment: PageCommitment,
}

impl EncodedPage {
    /// Canonical bytes charged to the producer until retained or released.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Commitment binding bytes, role, encoded length, and immediate item count.
    #[must_use]
    pub const fn commitment(&self) -> PageCommitment {
        self.commitment
    }
    /// Moves the canonical bytes out so a cache can own them without a copy.
    pub(crate) fn into_parts(self) -> (Vec<u8>, PageCommitment) {
        (self.bytes, self.commitment)
    }
}

/// Encodes a strictly ordered leaf with explicit finite allocation/work limits.
///
/// # Errors
/// Refuses oversized values/pages, invalid bindings or duplicate/out-of-order
/// keys, work exhaustion, and allocation failure before returning any page.
pub fn encode_leaf(
    binding: EvidenceBinding,
    kind: PageKind,
    records: &[LeafRecord<'_>],
    limits: EvidenceLimits,
) -> Result<EncodedPage, Failure> {
    let count = u16::try_from(records.len()).map_err(|_| failure(FailureCode::ResourceLimit))?;
    if count > PAGE_FANOUT {
        return Err(failure(FailureCode::ResourceLimit));
    }
    let mut len = HEADER_BYTES;
    let mut prior = None;
    for record in records {
        if prior.is_some_and(|key| key >= record.key) {
            return Err(failure(FailureCode::InvalidEvidence));
        }
        prior = Some(record.key);
        let bytes =
            u64::try_from(record.value.len()).map_err(|_| failure(FailureCode::ResourceLimit))?;
        if bytes > limits.value_bytes || bytes > u64::from(u32::MAX) {
            return Err(failure(FailureCode::ResourceLimit));
        }
        len = len
            .checked_add(36)
            .and_then(|n| n.checked_add(bytes))
            .ok_or_else(|| failure(FailureCode::ResourceLimit))?;
    }
    if len > limits.page_bytes.min(MAX_PAGE_BYTES) {
        return Err(failure(FailureCode::ResourceLimit));
    }
    let mut budget = Budget::new(limits.work, limits.allocated_bytes);
    budget.charge(len, len)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(usize::try_from(len).map_err(|_| failure(FailureCode::ResourceLimit))?)
        .map_err(|_| failure(FailureCode::ResourceLimit))?;
    bytes.extend_from_slice(b"MKEP");
    bytes.extend_from_slice(&1_u16.to_le_bytes());
    bytes.extend_from_slice(&binding.repository.0);
    bytes.extend_from_slice(&binding.source.id);
    bytes.extend_from_slice(&binding.source.len.to_le_bytes());
    bytes.extend_from_slice(&binding.source.binding.0);
    bytes.extend_from_slice(&binding.ruleset.ruleset.0.to_le_bytes());
    bytes.push(1);
    bytes.push(kind_byte(kind));
    bytes.push(0);
    bytes.extend_from_slice(&count.to_le_bytes());
    bytes.extend_from_slice(
        &u32::try_from(len - HEADER_BYTES)
            .map_err(|_| failure(FailureCode::ResourceLimit))?
            .to_le_bytes(),
    );
    for record in records {
        bytes.extend_from_slice(&record.key);
        bytes.extend_from_slice(
            &u32::try_from(record.value.len())
                .map_err(|_| failure(FailureCode::ResourceLimit))?
                .to_le_bytes(),
        );
        bytes.extend_from_slice(record.value);
    }
    let page = PageView::decode(&bytes, binding, limits, &mut budget)?;
    budget.charge(len, 0)?;
    let commitment = page.commitment();
    Ok(EncodedPage { bytes, commitment })
}

/// A child following an internal page's first child.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BranchChild {
    /// Inclusive lower bound of this child's key interval.
    pub separator: Hash,
    /// Content commitment to a nonempty page of the same kind.
    pub child: PageCommitment,
}

/// Encodes an internal page in the existing canonical page grammar.
///
/// Child commitments describe structure, not verified contents. A complete
/// authenticated path additionally checks each child's height and key interval.
///
/// # Errors
/// Refuses invalid heights, ordering, child geometry or bindings, and finite
/// work, byte, or allocation limits before returning any page.
pub fn encode_internal(
    binding: EvidenceBinding,
    kind: PageKind,
    height: u8,
    first: PageCommitment,
    rest: &[BranchChild],
    limits: EvidenceLimits,
) -> Result<EncodedPage, Failure> {
    if !(1..=32).contains(&height) {
        return Err(failure(FailureCode::InvalidEvidence));
    }
    if rest.len() >= usize::from(PAGE_FANOUT) {
        return Err(failure(FailureCode::ResourceLimit));
    }
    let mut previous = None;
    for child in rest {
        if previous.is_some_and(|key| key >= child.separator) {
            return Err(failure(FailureCode::InvalidEvidence));
        }
        previous = Some(child.separator);
    }
    for child in core::iter::once(first).chain(rest.iter().map(|entry| entry.child)) {
        if child.kind != kind
            || !(1..=u64::from(PAGE_FANOUT)).contains(&child.items)
            || !(HEADER_BYTES..=limits.page_bytes.min(MAX_PAGE_BYTES)).contains(&child.len)
        {
            return Err(failure(FailureCode::InvalidEvidence));
        }
    }
    // Fan-out admission above bounds these conversions and all arithmetic.
    let count = u16::try_from(rest.len() + 1).map_err(|_| failure(FailureCode::ResourceLimit))?;
    let payload_len = 49 + u32::from(count - 1) * 81;
    let len = HEADER_BYTES + u64::from(payload_len);
    if len > limits.page_bytes.min(MAX_PAGE_BYTES) {
        return Err(failure(FailureCode::ResourceLimit));
    }
    let mut budget = Budget::new(limits.work, limits.allocated_bytes);
    budget.charge(len, len)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(usize::try_from(len).map_err(|_| failure(FailureCode::ResourceLimit))?)
        .map_err(|_| failure(FailureCode::ResourceLimit))?;
    bytes.extend_from_slice(b"MKEP");
    bytes.extend_from_slice(&1_u16.to_le_bytes());
    bytes.extend_from_slice(&binding.repository.0);
    bytes.extend_from_slice(&binding.source.id);
    bytes.extend_from_slice(&binding.source.len.to_le_bytes());
    bytes.extend_from_slice(&binding.source.binding.0);
    bytes.extend_from_slice(&binding.ruleset.ruleset.0.to_le_bytes());
    bytes.push(1);
    bytes.push(kind_byte(kind));
    bytes.push(height);
    bytes.extend_from_slice(&count.to_le_bytes());
    bytes.extend_from_slice(&payload_len.to_le_bytes());
    write_commitment(&mut bytes, first);
    for child in rest {
        bytes.extend_from_slice(&child.separator);
        write_commitment(&mut bytes, child.child);
    }
    let page = PageView::decode(&bytes, binding, limits, &mut budget)?;
    budget.charge(len, 0)?;
    let commitment = page.commitment();
    Ok(EncodedPage { bytes, commitment })
}

fn write_commitment(bytes: &mut Vec<u8>, child: PageCommitment) {
    bytes.extend_from_slice(&child.digest);
    bytes.push(kind_byte(child.kind));
    bytes.extend_from_slice(&child.len.to_le_bytes());
    bytes.extend_from_slice(&child.items.to_le_bytes());
}

/// Context committed by every page in a verification run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EvidenceBinding {
    /// Immutable complete pack source.
    pub source: PackSource,
    /// Repository in which external facts are scoped.
    pub repository: RepositoryId,
    /// Normative ruleset and semantic profile.
    pub ruleset: RulesetBinding,
}

/// A borrowed leaf record. Its value's owning module defines its semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeafRecord<'a> {
    /// Lexicographically ordered key; occurrence keys encode an ordinal in big-endian form.
    pub key: Hash,
    /// Bounded semantic payload, without an implicit verification claim.
    pub value: &'a [u8],
}

/// Iterator over at most sixteen structurally validated leaf records.
#[derive(Debug, Clone)]
pub struct LeafRecords<'a> {
    bytes: &'a [u8],
    left: u16,
}

impl<'a> Iterator for LeafRecords<'a> {
    type Item = LeafRecord<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.left == 0 {
            return None;
        }
        let key = self.bytes.get(..32)?.try_into().ok()?;
        let len = u32::from_le_bytes(self.bytes.get(32..36)?.try_into().ok()?);
        let end = 36_usize.checked_add(usize::try_from(len).ok()?)?;
        let value = self.bytes.get(36..end)?;
        self.bytes = self.bytes.get(end..)?;
        self.left -= 1;
        Some(LeafRecord { key, value })
    }
}

/// Validated structure borrowed from immutable caller-owned bytes.
///
/// Decoding checks binding, shape, and bounds. A caller must also authenticate
/// the content commitment before treating lookup as evidence under a root.
#[derive(Debug, Clone, Copy)]
pub struct PageView<'a> {
    bytes: &'a [u8],
    binding: EvidenceBinding,
    kind: PageKind,
    height: u8,
    items: u16,
    payload: &'a [u8],
}

pub(crate) fn kind_byte(kind: PageKind) -> u8 {
    match kind {
        PageKind::Objects => 0,
        PageKind::Occurrences => 1,
        PageKind::Dependencies => 2,
        PageKind::Closure => 3,
        PageKind::Heads => 4,
        PageKind::Ordinals => 5,
    }
}

pub(crate) fn read_kind(cursor: &mut Cursor<'_, '_>) -> Result<PageKind, Failure> {
    match cursor.byte()? {
        0 => Ok(PageKind::Objects),
        1 => Ok(PageKind::Occurrences),
        2 => Ok(PageKind::Dependencies),
        3 => Ok(PageKind::Closure),
        4 => Ok(PageKind::Heads),
        5 => Ok(PageKind::Ordinals),
        _ => Err(failure(FailureCode::InvalidEvidence)),
    }
}

pub(crate) fn read_binding(cursor: &mut Cursor<'_, '_>) -> Result<EvidenceBinding, Failure> {
    let repository = RepositoryId(cursor.array()?);
    let source = PackSource {
        id: cursor.array()?,
        len: cursor.u64()?,
        binding: SourceBinding(cursor.array()?),
    };
    let ruleset = RulesetId(cursor.u32()?);
    if ruleset != INDEXED_RULESET || cursor.byte()? != 1 {
        return Err(failure(FailureCode::UnsupportedRuleset));
    }
    if source.len < 44 {
        return Err(failure(FailureCode::InvalidEvidence));
    }
    Ok(EvidenceBinding {
        source,
        repository,
        ruleset: RulesetBinding {
            ruleset,
            profile: ProfileId::Indexed,
        },
    })
}

pub(crate) fn read_commitment(cursor: &mut Cursor<'_, '_>) -> Result<PageCommitment, Failure> {
    Ok(PageCommitment {
        digest: cursor.array()?,
        kind: read_kind(cursor)?,
        len: cursor.u64()?,
        items: cursor.u64()?,
    })
}

impl<'a> PageView<'a> {
    /// Computes the source-bound canonical page commitment.
    #[must_use]
    pub fn commitment(&self) -> PageCommitment {
        PageCommitment {
            digest: mkit_core::hash::domain_digest(PAGE_DOMAIN, self.bytes),
            kind: self.kind,
            len: self.bytes.len() as u64,
            items: u64::from(self.items),
        }
    }

    pub(crate) fn authenticate(
        &self,
        expected: PageCommitment,
        budget: &mut Budget,
    ) -> Result<(), Failure> {
        budget.charge(self.bytes.len() as u64, 0)?;
        if self.commitment() != expected {
            return Err(failure(FailureCode::EvidenceMismatch));
        }
        Ok(())
    }
    /// Same charge and role checks as [`Self::authenticate`] for bytes whose
    /// digest the caller already established; the digest is not recomputed.
    pub(crate) fn authenticate_resident(
        &self,
        expected: PageCommitment,
        budget: &mut Budget,
    ) -> Result<(), Failure> {
        budget.charge(self.bytes.len() as u64, 0)?;
        if self.kind != expected.kind
            || self.bytes.len() as u64 != expected.len
            || u64::from(self.items) != expected.items
        {
            return Err(failure(FailureCode::EvidenceMismatch));
        }
        Ok(())
    }
    /// Decodes a page whose payload an earlier [`Self::decode`] already
    /// validated: it checks the header and binding, skips the per-record pass,
    /// and charges `budget` exactly what [`Self::decode`] would have charged
    /// (debug builds also run the full decode).
    /// Only for bytes that already passed [`Self::decode`] (the driver's cache
    /// holds nothing else); the accessors parse the payload they return but
    /// do not repeat the ordering and geometry checks.
    pub(crate) fn decode_resident(
        bytes: &'a [u8],
        expected: EvidenceBinding,
        limits: EvidenceLimits,
        budget: &mut Budget,
    ) -> Result<Self, Failure> {
        let len = u64::try_from(bytes.len()).map_err(|_| failure(FailureCode::ResourceLimit))?;
        if len > limits.page_bytes.min(MAX_PAGE_BYTES) {
            return Err(failure(FailureCode::ResourceLimit));
        }
        // The header is read against a scratch budget; the real one is charged
        // the exact total below.
        let mut scratch = Budget::new(u64::MAX, 0);
        let mut cursor = Cursor::new(bytes, &mut scratch);
        if cursor.array::<4>()? != *b"MKEP" {
            return Err(failure(FailureCode::InvalidEvidence));
        }
        if cursor.u16()? != 1 {
            return Err(failure(FailureCode::UnsupportedEvidenceVersion));
        }
        if read_binding(&mut cursor)? != expected {
            return Err(failure(FailureCode::SourceChanged));
        }
        let kind = read_kind(&mut cursor)?;
        let height = cursor.byte()?;
        let items = cursor.u16()?;
        if height > 32 || items > PAGE_FANOUT || (height > 0 && items == 0) {
            return Err(failure(FailureCode::InvalidEvidence));
        }
        let payload_len = u64::from(cursor.u32()?);
        let payload = cursor.take(payload_len)?;
        cursor.finish()?;
        // One take per header field, then per record: key, length and value
        // for a leaf; separator and the four commitment fields for a branch.
        let items_work = u64::from(items);
        let body = if height == 0 {
            3 * items_work
        } else {
            5 * items_work - 1
        };
        budget.charge(len + HEADER_TAKES + body, 0)?;
        debug_assert!(
            Self::decode(
                bytes,
                expected,
                limits,
                &mut Budget::new(u64::MAX, u64::MAX)
            )
            .is_ok(),
            "resident page failed full validation"
        );
        Ok(Self {
            bytes,
            binding: expected,
            kind,
            height,
            items,
            payload,
        })
    }

    /// Decodes one complete canonical page under a finite shared operation budget.
    ///
    /// # Errors
    /// Refuses unsupported versions/rulesets, changed context, invalid ordering
    /// or geometry, trailing/truncated data, and exhausted limits.
    pub fn from_bytes(
        bytes: &'a [u8],
        expected: EvidenceBinding,
        limits: EvidenceLimits,
    ) -> Result<Self, Failure> {
        let mut budget = Budget::new(limits.work, limits.allocated_bytes);
        Self::decode(bytes, expected, limits, &mut budget)
    }

    pub(crate) fn decode(
        bytes: &'a [u8],
        expected: EvidenceBinding,
        limits: EvidenceLimits,
        budget: &mut Budget,
    ) -> Result<Self, Failure> {
        let len = u64::try_from(bytes.len()).map_err(|_| failure(FailureCode::ResourceLimit))?;
        if len > limits.page_bytes.min(MAX_PAGE_BYTES) {
            return Err(failure(FailureCode::ResourceLimit));
        }
        budget.charge(len, 0)?;
        let mut cursor = Cursor::new(bytes, budget);
        if cursor.array::<4>()? != *b"MKEP" {
            return Err(failure(FailureCode::InvalidEvidence));
        }
        if cursor.u16()? != 1 {
            return Err(failure(FailureCode::UnsupportedEvidenceVersion));
        }
        let binding = read_binding(&mut cursor)?;
        if binding != expected {
            return Err(failure(FailureCode::SourceChanged));
        }
        let kind = read_kind(&mut cursor)?;
        let height = cursor.byte()?;
        let items = cursor.u16()?;
        if height > 32 || items > PAGE_FANOUT || (height > 0 && items == 0) {
            return Err(failure(FailureCode::InvalidEvidence));
        }
        let payload_len = u64::from(cursor.u32()?);
        let payload = cursor.take(payload_len)?;
        cursor.finish()?;
        let mut contents = Cursor::new(payload, budget);
        if height == 0 {
            let mut prior = None;
            for _ in 0..items {
                let key: Hash = contents.array()?;
                if prior.is_some_and(|previous| previous >= key) {
                    return Err(failure(FailureCode::InvalidEvidence));
                }
                prior = Some(key);
                let value_len = u64::from(contents.u32()?);
                if value_len > limits.value_bytes {
                    return Err(failure(FailureCode::ResourceLimit));
                }
                contents.take(value_len)?;
            }
        } else {
            let mut prior = None;
            for index in 0..items {
                if index != 0 {
                    let separator: Hash = contents.array()?;
                    if prior.is_some_and(|previous| previous >= separator) {
                        return Err(failure(FailureCode::InvalidEvidence));
                    }
                    prior = Some(separator);
                }
                let child = read_commitment(&mut contents)?;
                if child.kind != kind
                    || child.items == 0
                    || child.items > u64::from(PAGE_FANOUT)
                    || !(HEADER_BYTES..=limits.page_bytes.min(MAX_PAGE_BYTES)).contains(&child.len)
                {
                    return Err(failure(FailureCode::InvalidEvidence));
                }
            }
        }
        contents.finish()?;
        Ok(Self {
            bytes,
            binding,
            kind,
            height,
            items,
            payload,
        })
    }

    /// Encoded bytes, still owned by the caller.
    #[must_use]
    pub const fn encoded(&self) -> &'a [u8] {
        self.bytes
    }
    /// Exact source/repository/ruleset binding.
    #[must_use]
    pub const fn binding(&self) -> EvidenceBinding {
        self.binding
    }
    /// Committed semantic role.
    #[must_use]
    pub const fn kind(&self) -> PageKind {
        self.kind
    }
    /// Zero for a leaf; child height is exactly one smaller for a branch.
    #[must_use]
    pub const fn height(&self) -> u8 {
        self.height
    }
    /// Number of leaf records or immediate children.
    #[must_use]
    pub const fn items(&self) -> u16 {
        self.items
    }

    /// Iterates validated leaf records without allocating.
    ///
    /// # Errors
    /// Returns `InvalidEvidence` for an internal node. A branch is never
    /// interpreted as an empty leaf or a proof of absence.
    pub fn records(&self) -> Result<LeafRecords<'a>, Failure> {
        if self.height != 0 {
            return Err(failure(FailureCode::InvalidEvidence));
        }
        Ok(LeafRecords {
            bytes: self.payload,
            left: self.items,
        })
    }

    pub(crate) fn route(
        &self,
        key: Hash,
        inherited_lower: Option<Hash>,
        inherited_upper: Option<Hash>,
        budget: &mut Budget,
    ) -> Result<Route, Failure> {
        if self.height == 0 {
            return Err(failure(FailureCode::InvalidEvidence));
        }
        let mut cursor = Cursor::new(self.payload, budget);
        let mut child = read_commitment(&mut cursor)?;
        let mut lower = None;
        let mut result = None;
        for _ in 1..self.items {
            let separator = cursor.array()?;
            // Validate every separator, including siblings outside the chosen
            // route. Otherwise a malformed nested branch could prove absence.
            if inherited_lower.is_some_and(|low| separator < low)
                || inherited_upper.is_some_and(|high| separator >= high)
            {
                return Err(failure(FailureCode::InvalidEvidence));
            }
            let next = read_commitment(&mut cursor)?;
            if result.is_none() && key < separator {
                result = Some(Route {
                    child,
                    lower,
                    upper: Some(separator),
                });
            }
            if result.is_none() {
                child = next;
                lower = Some(separator);
            }
        }
        cursor.finish()?;
        Ok(result.unwrap_or(Route {
            child,
            lower,
            upper: None,
        }))
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Route {
    pub(crate) child: PageCommitment,
    pub(crate) lower: Option<Hash>,
    pub(crate) upper: Option<Hash>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use mkit_core::hash;

    fn binding() -> EvidenceBinding {
        let mut empty = b"MKIT\x01\0\0\0\0\0\0\0".to_vec();
        empty.extend_from_slice(&hash::hash(&empty));
        EvidenceBinding {
            source: PackSource {
                id: hash::hash(&empty),
                len: 44,
                binding: SourceBinding([7; 32]),
            },
            repository: RepositoryId([9; 32]),
            ruleset: RulesetBinding {
                ruleset: INDEXED_RULESET,
                profile: ProfileId::Indexed,
            },
        }
    }

    #[test]
    fn resident_decode_charges_exactly_what_a_full_decode_charges() {
        let limits = EvidenceLimits::indexed();
        let values: Vec<Vec<u8>> = (0..16_u8).map(|n| vec![n; 7 * usize::from(n)]).collect();
        let mut pages = vec![EMPTY.to_vec()];
        let mut leaves = Vec::new();
        for count in 1..=16_usize {
            let records: Vec<LeafRecord<'_>> = (0..count)
                .map(|n| LeafRecord {
                    key: [u8::try_from(n).unwrap() + 1; 32],
                    value: &values[n],
                })
                .collect();
            let leaf = encode_leaf(binding(), PageKind::Objects, &records, limits).unwrap();
            leaves.push(leaf.commitment());
            pages.push(leaf.into_parts().0);
        }
        for count in 1..=15_usize {
            let rest: Vec<BranchChild> = (1..=count)
                .map(|n| BranchChild {
                    separator: [u8::try_from(n).unwrap(); 32],
                    child: leaves[n],
                })
                .collect();
            let page =
                encode_internal(binding(), PageKind::Objects, 1, leaves[0], &rest, limits).unwrap();
            pages.push(page.into_parts().0);
        }
        for bytes in &pages {
            let (mut full, mut resident) = (
                Budget::new(limits.work, limits.allocated_bytes),
                Budget::new(limits.work, limits.allocated_bytes),
            );
            let a = PageView::decode(bytes, binding(), limits, &mut full).unwrap();
            let b = PageView::decode_resident(bytes, binding(), limits, &mut resident).unwrap();
            assert_eq!(full.remaining(), resident.remaining());
            assert_eq!((a.kind(), a.height(), a.items()), (b.kind(), b.height(), b.items()));
        }
    }

    #[test]
    fn resident_decode_and_authentication_refuse_what_decode_refuses() {
        let limits = EvidenceLimits::indexed();
        let mut other = binding();
        other.repository = RepositoryId([1; 32]);
        for (bytes, expected, code) in [
            (EMPTY.to_vec(), other, FailureCode::SourceChanged),
            (EMPTY[..EMPTY.len() - 1].to_vec(), binding(), FailureCode::UnexpectedEof),
        ] {
            let full = PageView::decode(&bytes, expected, limits, &mut Budget::new(1 << 20, 0));
            assert_eq!(full.unwrap_err().code, code);
            let resident =
                PageView::decode_resident(&bytes, expected, limits, &mut Budget::new(1 << 20, 0));
            assert_eq!(resident.unwrap_err().code, code);
        }
        let mut budget = Budget::new(1 << 20, 0);
        let view = PageView::decode(EMPTY, binding(), limits, &mut budget).unwrap();
        let wrong = view.commitment();
        for mutate in [
            |c: &mut PageCommitment| c.kind = PageKind::Heads,
            |c: &mut PageCommitment| c.len += 1,
            |c: &mut PageCommitment| c.items += 1,
        ] {
            let mut expected = wrong;
            mutate(&mut expected);
            assert_eq!(
                view.authenticate_resident(expected, &mut budget).unwrap_err().code,
                FailureCode::EvidenceMismatch
            );
        }
        assert!(view.authenticate_resident(view.commitment(), &mut budget).is_ok());
    }

    const EMPTY: &[u8] = include_bytes!("../../fixtures/evidence/page-empty.bin");

    #[test]
    fn empty_page_is_canonical_and_every_truncated_prefix_refuses() {
        let page = PageView::from_bytes(EMPTY, binding(), EvidenceLimits::indexed()).unwrap();
        assert_eq!(page.binding(), binding());
        assert_eq!(page.kind(), PageKind::Objects);
        assert_eq!((page.height(), page.items()), (0, 0));
        assert_eq!(page.encoded(), EMPTY);
        assert_eq!(page.records().unwrap().count(), 0);
        for end in 0..EMPTY.len() {
            assert!(
                PageView::from_bytes(&EMPTY[..end], binding(), EvidenceLimits::indexed()).is_err()
            );
        }
        let mut trailing = EMPTY.to_vec();
        trailing.push(0);
        assert_eq!(
            PageView::from_bytes(&trailing, binding(), EvidenceLimits::indexed())
                .unwrap_err()
                .code,
            FailureCode::TrailingData
        );
        assert_eq!(HEADER_BYTES, u64::try_from(EMPTY.len()).unwrap());
        assert_eq!(kind_byte(PageKind::Closure), 3);
        assert_eq!(kind_byte(PageKind::Heads), 4);
        assert_eq!(kind_byte(PageKind::Ordinals), 5);
    }

    #[test]
    fn unsupported_and_changed_context_refuse_before_leaf_use() {
        for (offset, value, code) in [
            (4, 2, FailureCode::UnsupportedEvidenceVersion),
            (110, 2, FailureCode::UnsupportedRuleset),
            (114, 2, FailureCode::UnsupportedRuleset),
            (6, 8, FailureCode::SourceChanged),
            (115, 6, FailureCode::InvalidEvidence),
            (116, 33, FailureCode::InvalidEvidence),
            (117, 17, FailureCode::InvalidEvidence),
        ] {
            let mut bytes = EMPTY.to_vec();
            bytes[offset] = value;
            assert_eq!(
                PageView::from_bytes(&bytes, binding(), EvidenceLimits::indexed())
                    .unwrap_err()
                    .code,
                code
            );
        }
        let limits = EvidenceLimits {
            page_bytes: HEADER_BYTES - 1,
            ..EvidenceLimits::indexed()
        };
        assert_eq!(
            PageView::from_bytes(EMPTY, binding(), limits)
                .unwrap_err()
                .code,
            FailureCode::ResourceLimit
        );
    }

    #[test]
    fn duplicate_keys_and_nested_work_do_not_reset_limits() {
        let mut duplicate = EMPTY.to_vec();
        let record = [[0; 32].as_slice(), &0_u32.to_le_bytes()].concat();
        duplicate[117..119].copy_from_slice(&2_u16.to_le_bytes());
        duplicate[119..123].copy_from_slice(&72_u32.to_le_bytes());
        duplicate.extend_from_slice(&record);
        duplicate.extend_from_slice(&record);
        assert_eq!(
            PageView::from_bytes(&duplicate, binding(), EvidenceLimits::indexed())
                .unwrap_err()
                .code,
            FailureCode::InvalidEvidence
        );
        let mut budget = Budget::new(150, 0);
        PageView::decode(EMPTY, binding(), EvidenceLimits::indexed(), &mut budget).unwrap();
        assert_eq!(
            PageView::decode(EMPTY, binding(), EvidenceLimits::indexed(), &mut budget)
                .unwrap_err()
                .code,
            FailureCode::ResourceLimit
        );
    }

    #[test]
    fn internal_routing_preserves_exclusive_upper_bounds_and_never_reports_absence() {
        let mut bytes = EMPTY.to_vec();
        bytes[116] = 1;
        bytes[117..119].copy_from_slice(&2_u16.to_le_bytes());
        bytes[119..123].copy_from_slice(&130_u32.to_le_bytes());
        for child in 1..=2 {
            if child == 2 {
                bytes.extend_from_slice(&[5; 32]);
            }
            bytes.extend_from_slice(&[child; 32]);
            bytes.push(0);
            bytes.extend_from_slice(&HEADER_BYTES.to_le_bytes());
            bytes.extend_from_slice(&1_u64.to_le_bytes());
        }
        let page = PageView::from_bytes(&bytes, binding(), EvidenceLimits::indexed()).unwrap();
        assert!(page.records().is_err());
        let mut budget = Budget::new(100, 0);
        let left = page.route([4; 32], None, None, &mut budget).unwrap();
        assert_eq!(left.child.digest, [1; 32]);
        assert_eq!((left.lower, left.upper), (None, Some([5; 32])));
        let right = page.route([5; 32], None, None, &mut budget).unwrap();
        assert_eq!(right.child.digest, [2; 32]);
        assert_eq!((right.lower, right.upper), (Some([5; 32]), None));
        bytes[usize::try_from(HEADER_BYTES).unwrap() + 32] = 1;
        assert_eq!(
            PageView::from_bytes(&bytes, binding(), EvidenceLimits::indexed())
                .unwrap_err()
                .code,
            FailureCode::InvalidEvidence
        );
    }
    #[test]
    fn internal_encoder_is_bounded_before_allocation_and_preserves_canonical_bytes() {
        let (child, next) = branch_children();
        let page = encode_internal(
            binding(),
            PageKind::Objects,
            1,
            child,
            &[next],
            EvidenceLimits::indexed(),
        )
        .unwrap();
        let mut expected = EMPTY.to_vec();
        expected[116] = 1;
        expected[117..119].copy_from_slice(&2_u16.to_le_bytes());
        expected[119..123].copy_from_slice(&130_u32.to_le_bytes());
        write_commitment(&mut expected, child);
        expected.extend_from_slice(&next.separator);
        write_commitment(&mut expected, next.child);
        assert_eq!(page.bytes(), expected);
        assert_eq!(
            page.commitment(),
            PageView::from_bytes(&expected, binding(), EvidenceLimits::indexed())
                .unwrap()
                .commitment()
        );
        let len = page.bytes().len() as u64;
        for limits in [
            EvidenceLimits {
                allocated_bytes: len - 1,
                ..EvidenceLimits::indexed()
            },
            EvidenceLimits {
                page_bytes: len - 1,
                ..EvidenceLimits::indexed()
            },
            EvidenceLimits {
                work: len,
                ..EvidenceLimits::indexed()
            },
        ] {
            assert_eq!(
                encode_internal(binding(), PageKind::Objects, 1, child, &[next], limits)
                    .unwrap_err()
                    .code,
                FailureCode::ResourceLimit
            );
        }
        assert!(
            encode_internal(
                binding(),
                PageKind::Objects,
                1,
                child,
                &[next],
                EvidenceLimits {
                    allocated_bytes: len,
                    ..EvidenceLimits::indexed()
                }
            )
            .is_ok()
        );
    }

    fn branch_children() -> (PageCommitment, BranchChild) {
        let child = PageCommitment {
            digest: [1; 32],
            kind: PageKind::Objects,
            len: HEADER_BYTES + 36,
            items: 1,
        };
        let next = BranchChild {
            separator: [5; 32],
            child: PageCommitment {
                digest: [2; 32],
                ..child
            },
        };
        (child, next)
    }

    #[test]
    fn internal_encoder_refuses_invalid_geometry_and_ordering() {
        let (child, next) = branch_children();
        for (height, first, rest, code) in [
            (0, child, vec![next], FailureCode::InvalidEvidence),
            (33, child, vec![next], FailureCode::InvalidEvidence),
            (
                1,
                PageCommitment { items: 0, ..child },
                vec![next],
                FailureCode::InvalidEvidence,
            ),
            (
                1,
                PageCommitment {
                    kind: PageKind::Closure,
                    ..child
                },
                vec![next],
                FailureCode::InvalidEvidence,
            ),
            (1, child, vec![next, next], FailureCode::InvalidEvidence),
            (1, child, vec![next; 16], FailureCode::ResourceLimit),
        ] {
            assert_eq!(
                encode_internal(
                    binding(),
                    PageKind::Objects,
                    height,
                    first,
                    &rest,
                    EvidenceLimits::indexed()
                )
                .unwrap_err()
                .code,
                code
            );
        }
    }
}
