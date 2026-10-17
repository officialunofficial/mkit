//! Root-to-leaf membership and nonmembership authentication without allocation.
use super::PageCommitment;
use super::pages::{EvidenceBinding, PageView, read_commitment};
use crate::{
    codec::{Budget, Cursor, failure},
    error::{Failure, FailureCode},
    limits::EvidenceLimits,
};
use mkit_core::hash::Hash;

/// An authenticated result under one exact root, source, and queried key.
/// It establishes the encoded leaf value, not that value's application meaning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub struct Lookup<'a> {
    root: PageCommitment,
    binding: EvidenceBinding,
    key: Hash,
    value: Option<&'a [u8]>,
}

impl<'a> Lookup<'a> {
    /// Exact root under which the lookup was authenticated.
    #[must_use]
    pub const fn root(&self) -> PageCommitment {
        self.root
    }
    /// Exact immutable source and ruleset context.
    #[must_use]
    pub const fn binding(&self) -> EvidenceBinding {
        self.binding
    }
    /// Query identity; absence is meaningful only for this key.
    #[must_use]
    pub const fn key(&self) -> Hash {
        self.key
    }
    /// Present semantic bytes, or authenticated absence at the routed leaf.
    #[must_use]
    pub const fn value(&self) -> Option<&'a [u8]> {
        self.value
    }
}

/// Authenticates a complete portable path to the correctly routed leaf.
///
/// The encoded path and returned value borrow caller-owned input. This call
/// allocates nothing and shares one finite work budget across every page.
/// Missing pages cannot establish absence.
///
/// # Errors
/// Refuses wrong roots/bindings, missing or misrouted pages, noncanonical
/// encodings, unsupported versions, height/interval disagreements, and limits.
pub fn verify_path(
    bytes: &[u8],
    binding: EvidenceBinding,
    root: PageCommitment,
    query: Hash,
    limits: EvidenceLimits,
) -> Result<Lookup<'_>, Failure> {
    let len = u64::try_from(bytes.len()).map_err(|_| failure(FailureCode::ResourceLimit))?;
    if len > limits.proof_bytes {
        return Err(failure(FailureCode::ResourceLimit));
    }
    let mut budget = Budget::new(limits.work, limits.allocated_bytes);
    budget.charge(len, 0)?;
    let mut input = Cursor::new(bytes, &mut budget);
    if input.array::<4>()? != *b"MKPF" {
        return Err(failure(FailureCode::InvalidEvidence));
    }
    if input.u16()? != 1 {
        return Err(failure(FailureCode::UnsupportedEvidenceVersion));
    }
    if read_commitment(&mut input)? != root || input.array::<32>()? != query {
        return Err(failure(FailureCode::EvidenceMismatch));
    }
    let count = input.u16()?;
    if u32::from(count) > limits.proof_pages {
        return Err(failure(FailureCode::ResourceLimit));
    }
    if count == 0 || count > 33 {
        return Err(failure(FailureCode::InvalidEvidence));
    }
    // Only fixed path framing is read here. Each nested page below borrows the
    // same original buffer and budget without retaining decoded ancestors.
    let body = input.take(
        len.checked_sub(89)
            .ok_or_else(|| failure(FailureCode::UnexpectedEof))?,
    )?;
    input.finish()?;
    let mut remaining = body;
    let mut expected = root;
    let mut expected_height = None;
    let mut lower = None;
    let mut upper = None;
    for ordinal in 0..count {
        let mut framing = Cursor::new(remaining, &mut budget);
        let page_len = u64::from(framing.u32()?);
        let page_bytes = framing.take(page_len)?;
        let used = usize::try_from(page_len)
            .ok()
            .and_then(|n| n.checked_add(4))
            .ok_or_else(|| failure(FailureCode::ResourceLimit))?;
        remaining = remaining
            .get(used..)
            .ok_or_else(|| failure(FailureCode::UnexpectedEof))?;
        let page = PageView::decode(page_bytes, binding, limits, &mut budget)?;
        page.authenticate(expected, &mut budget)?;
        if expected_height.is_some_and(|height| page.height() != height) {
            return Err(failure(FailureCode::InvalidEvidence));
        }
        if page.height() == 0 {
            if ordinal + 1 != count || !remaining.is_empty() {
                return Err(failure(FailureCode::TrailingData));
            }
            let mut value = None;
            for record in page.records()? {
                if lower.is_some_and(|low| record.key < low)
                    || upper.is_some_and(|high| record.key >= high)
                {
                    return Err(failure(FailureCode::InvalidEvidence));
                }
                if record.key == query {
                    value = Some(record.value);
                }
            }
            return Ok(Lookup {
                root,
                binding,
                key: query,
                value,
            });
        }
        let route = page.route(query, lower, upper, &mut budget)?;
        if route
            .lower
            .is_some_and(|low| lower.is_some_and(|bound| low < bound))
            || route
                .upper
                .is_some_and(|high| upper.is_some_and(|bound| high > bound))
        {
            return Err(failure(FailureCode::InvalidEvidence));
        }
        if let Some(low) = route.lower {
            lower = Some(low);
        }
        if let Some(high) = route.upper {
            upper = Some(high);
        }
        expected = route.child;
        expected_height = page.height().checked_sub(1);
    }
    Err(failure(FailureCode::UnavailableInput))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::{
        PackSource, ProfileId, RepositoryId, RulesetBinding, SourceBinding,
        pages::{INDEXED_RULESET, LeafRecord, encode_leaf},
    };
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

    fn proof(page: &[u8], root: PageCommitment, query: Hash) -> Vec<u8> {
        let mut bytes = b"MKPF\x01\0".to_vec();
        bytes.extend_from_slice(&root.digest);
        bytes.push(super::super::pages::kind_byte(root.kind));
        bytes.extend_from_slice(&root.len.to_le_bytes());
        bytes.extend_from_slice(&root.items.to_le_bytes());
        bytes.extend_from_slice(&query);
        bytes.extend_from_slice(&1_u16.to_le_bytes());
        bytes.extend_from_slice(&u32::try_from(page.len()).unwrap().to_le_bytes());
        bytes.extend_from_slice(page);
        bytes
    }

    #[test]
    fn pinned_empty_root_proves_absence_and_missing_page_never_does() {
        let bytes = include_bytes!("../../fixtures/evidence/proof-empty.bin");
        let page = encode_leaf(
            binding(),
            super::super::PageKind::Objects,
            &[],
            EvidenceLimits::indexed(),
        )
        .unwrap();
        assert_eq!(proof(page.bytes(), page.commitment(), [5; 32]), bytes);
        let lookup = verify_path(
            bytes,
            binding(),
            page.commitment(),
            [5; 32],
            EvidenceLimits::indexed(),
        )
        .unwrap();
        assert_eq!(lookup.value(), None);
        assert_eq!(lookup.root(), page.commitment());
        assert_eq!(lookup.binding(), binding());
        assert_eq!(lookup.key(), [5; 32]);
        for end in 0..bytes.len() {
            assert!(
                verify_path(
                    &bytes[..end],
                    binding(),
                    page.commitment(),
                    [5; 32],
                    EvidenceLimits::indexed()
                )
                .is_err()
            );
        }
        let mut corrupted = bytes.to_vec();
        *corrupted.last_mut().unwrap() = 1;
        assert!(
            verify_path(
                &corrupted,
                binding(),
                page.commitment(),
                [5; 32],
                EvidenceLimits::indexed()
            )
            .is_err()
        );
        assert!(
            verify_path(
                bytes,
                binding(),
                page.commitment(),
                [6; 32],
                EvidenceLimits::indexed()
            )
            .is_err()
        );
    }

    #[test]
    fn inclusion_and_before_between_after_absence_are_exactly_keyed() {
        let records = [
            LeafRecord {
                key: [3; 32],
                value: b"first",
            },
            LeafRecord {
                key: [7; 32],
                value: b"last",
            },
        ];
        let page = encode_leaf(
            binding(),
            super::super::PageKind::Objects,
            &records,
            EvidenceLimits::indexed(),
        )
        .unwrap();
        for (key, expected) in [
            (2, None),
            (3, Some(b"first".as_slice())),
            (5, None),
            (7, Some(b"last".as_slice())),
            (8, None),
        ] {
            let bytes = proof(page.bytes(), page.commitment(), [key; 32]);
            assert_eq!(
                verify_path(
                    &bytes,
                    binding(),
                    page.commitment(),
                    [key; 32],
                    EvidenceLimits::indexed()
                )
                .unwrap()
                .value(),
                expected
            );
        }
    }
    fn path(pages: &[&[u8]], root: PageCommitment, query: Hash) -> Vec<u8> {
        let mut bytes = proof(pages[0], root, query);
        bytes[87..89].copy_from_slice(&u16::try_from(pages.len()).unwrap().to_le_bytes());
        for page in &pages[1..] {
            bytes.extend_from_slice(&u32::try_from(page.len()).unwrap().to_le_bytes());
            bytes.extend_from_slice(page);
        }
        bytes
    }

    fn leaf(keys: &[u8]) -> super::super::pages::EncodedPage {
        let records: Vec<_> = keys
            .iter()
            .map(|key| LeafRecord {
                key: [*key; 32],
                value: b"value",
            })
            .collect();
        encode_leaf(
            binding(),
            super::super::PageKind::Objects,
            &records,
            EvidenceLimits::indexed(),
        )
        .unwrap()
    }

    fn branch(
        height: u8,
        first: PageCommitment,
        rest: &[(u8, PageCommitment)],
    ) -> super::super::pages::EncodedPage {
        let children: Vec<_> = rest
            .iter()
            .map(|(key, child)| super::super::pages::BranchChild {
                separator: [*key; 32],
                child: *child,
            })
            .collect();
        super::super::pages::encode_internal(
            binding(),
            super::super::PageKind::Objects,
            height,
            first,
            &children,
            EvidenceLimits::indexed(),
        )
        .unwrap()
    }

    #[test]
    fn multilevel_paths_prove_membership_and_absence_with_no_allocation_budget() {
        let a = leaf(&[2, 4]);
        let b = leaf(&[7, 9]);
        let c = leaf(&[12, 16]);
        let left = branch(1, a.commitment(), &[(6, b.commitment())]);
        let right = branch(1, c.commitment(), &[]);
        let root = branch(2, left.commitment(), &[(10, right.commitment())]);
        let limits = EvidenceLimits {
            allocated_bytes: 0,
            ..EvidenceLimits::indexed()
        };
        for key in [0, 2, 3, 4, 5, 6, 7, 9, 10, 12, 16, 17] {
            let (middle, last) = if key >= 10 {
                (&right, &c)
            } else if key >= 6 {
                (&left, &b)
            } else {
                (&left, &a)
            };
            let bytes = path(
                &[root.bytes(), middle.bytes(), last.bytes()],
                root.commitment(),
                [key; 32],
            );
            let found =
                verify_path(&bytes, binding(), root.commitment(), [key; 32], limits).unwrap();
            assert_eq!(
                found.value(),
                [2, 4, 7, 9, 12, 16]
                    .contains(&key)
                    .then_some(b"value".as_slice())
            );
        }
        let missing = path(&[root.bytes(), left.bytes()], root.commitment(), [3; 32]);
        assert_eq!(
            verify_path(&missing, binding(), root.commitment(), [3; 32], limits)
                .unwrap_err()
                .code,
            FailureCode::UnavailableInput
        );
        let wrong = path(
            &[root.bytes(), left.bytes(), b.bytes()],
            root.commitment(),
            [3; 32],
        );
        assert_eq!(
            verify_path(&wrong, binding(), root.commitment(), [3; 32], limits)
                .unwrap_err()
                .code,
            FailureCode::EvidenceMismatch
        );
        let bytes = path(
            &[root.bytes(), left.bytes(), a.bytes()],
            root.commitment(),
            [3; 32],
        );
        for bounded in [
            EvidenceLimits {
                proof_pages: 2,
                ..limits
            },
            EvidenceLimits {
                proof_bytes: bytes.len() as u64 - 1,
                ..limits
            },
            EvidenceLimits {
                work: bytes.len() as u64,
                ..limits
            },
        ] {
            assert_eq!(
                verify_path(&bytes, binding(), root.commitment(), [3; 32], bounded)
                    .unwrap_err()
                    .code,
                FailureCode::ResourceLimit
            );
        }
    }

    #[test]
    fn every_nested_separator_respects_inherited_interval_even_off_route() {
        for (query, separators, nested_on_right) in [
            (2, [3, 11], false),
            (15, [1, 14], true),
            (2, [3, 10], false),
        ] {
            let selected = leaf(&[query]);
            let nested = branch(
                1,
                selected.commitment(),
                &[
                    (separators[0], selected.commitment()),
                    (separators[1], selected.commitment()),
                ],
            );
            let sibling = branch(1, selected.commitment(), &[]);
            let root = if nested_on_right {
                branch(2, sibling.commitment(), &[(10, nested.commitment())])
            } else {
                branch(2, nested.commitment(), &[(10, sibling.commitment())])
            };
            let bytes = path(
                &[root.bytes(), nested.bytes(), selected.bytes()],
                root.commitment(),
                [query; 32],
            );
            // The selected child is valid: only an unselected separator violates
            // the inherited bound. Child commitments deliberately coincide.
            assert_eq!(
                verify_path(
                    &bytes,
                    binding(),
                    root.commitment(),
                    [query; 32],
                    EvidenceLimits::indexed()
                )
                .unwrap_err()
                .code,
                FailureCode::InvalidEvidence
            );
        }
    }

    #[test]
    fn authenticated_wrong_height_and_out_of_interval_leaf_refuse() {
        let outside = leaf(&[11]);
        let sibling = leaf(&[15]);
        let root = branch(1, outside.commitment(), &[(10, sibling.commitment())]);
        let bytes = path(&[root.bytes(), outside.bytes()], root.commitment(), [2; 32]);
        assert_eq!(
            verify_path(
                &bytes,
                binding(),
                root.commitment(),
                [2; 32],
                EvidenceLimits::indexed()
            )
            .unwrap_err()
            .code,
            FailureCode::InvalidEvidence
        );
        let wrong_height = branch(2, outside.commitment(), &[]);
        let bytes = path(
            &[wrong_height.bytes(), outside.bytes()],
            wrong_height.commitment(),
            [11; 32],
        );
        assert_eq!(
            verify_path(
                &bytes,
                binding(),
                wrong_height.commitment(),
                [11; 32],
                EvidenceLimits::indexed()
            )
            .unwrap_err()
            .code,
            FailureCode::InvalidEvidence
        );
    }
}
