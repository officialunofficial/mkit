//! BLAKE3 subtree hashing for resumable part uploads
//! (SPEC-TRANSPORT-CONNECT §7.6).
//!
//! A pack of more than `part_size` bytes uploads in parts. Every part but the
//! last is exactly `part_size` bytes (a power of two of at least
//! [`MIN_PART_SIZE`]); the last is the non-empty rest. Part `i` covers pack
//! bytes from `i × part_size`, and its commitment carries the BLAKE3 chaining
//! value of those bytes as a non-root subtree at that offset. The server
//! merges the part chaining values by BLAKE3's left-balanced tree rule into
//! the root, which is the pack id ([`crate::hash::hash`] of the whole pack).
//!
//! This module is pure and wasm-safe. Every `blake3::hazmat` precondition
//! holds by construction: [`PartPlan`] validates the geometry, and
//! [`PartHasher`] rejects an overrun before it reaches `Hasher::update`, so no
//! caller input can reach a hazmat assertion.

use crate::hash::Hash;
use crate::write_auth::PartCommitment;
use blake3::hazmat::{self, HasherExt, Mode};

/// Smallest legal part size (SPEC-TRANSPORT-CONNECT §7.6).
pub const MIN_PART_SIZE: u64 = 8 * 1024 * 1024;

/// A BLAKE3 non-root chaining value.
pub type ChainingValue = [u8; 32];

/// A part geometry or part stream that violates SPEC-TRANSPORT-CONNECT §7.6.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PartError {
    /// `part_size` is not a power of two.
    #[error("part size is not a power of two")]
    PartSizeNotPowerOfTwo,
    /// `part_size` is below [`MIN_PART_SIZE`].
    #[error("part size is below the minimum")]
    PartSizeTooSmall,
    /// The pack fits one part, so it uploads with `UploadPack`, never parts.
    #[error("pack fits one part; upload it whole")]
    NotMultipart,
    /// The upload needs more parts than allowed.
    #[error("too many parts")]
    TooManyParts,
    /// A part index at or beyond the part count.
    #[error("part index out of range")]
    IndexOutOfRange,
    /// More bytes than the part's expected length.
    #[error("part data exceeds the part length")]
    Overrun,
    /// Fewer bytes than the part's expected length.
    #[error("part data is shorter than the part length")]
    LengthMismatch,
    /// A merge given a chaining value count other than the part count.
    #[error("wrong number of part chaining values")]
    WrongPartCount,
}

/// Validated part geometry for one multi-part upload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PartPlan {
    total: u64,
    part_size: u64,
    count: u32,
}

impl PartPlan {
    /// Validate the geometry of a `total`-byte pack split into `part_size`
    /// parts.
    ///
    /// # Errors
    /// [`PartError::PartSizeNotPowerOfTwo`], [`PartError::PartSizeTooSmall`],
    /// [`PartError::NotMultipart`] when `total <= part_size`, and
    /// [`PartError::TooManyParts`] when more than `max_parts` parts are needed.
    pub fn new(total: u64, part_size: u64, max_parts: u32) -> Result<Self, PartError> {
        if !part_size.is_power_of_two() {
            return Err(PartError::PartSizeNotPowerOfTwo);
        }
        if part_size < MIN_PART_SIZE {
            return Err(PartError::PartSizeTooSmall);
        }
        Self::build(total, part_size, max_parts)
    }

    /// Test-only geometry: any power-of-two `part_size` of at least one BLAKE3
    /// chunk, for fast vectors and property tests.
    #[cfg(test)]
    pub(crate) fn new_small(total: u64, part_size: u64) -> Result<Self, PartError> {
        if !part_size.is_power_of_two() {
            return Err(PartError::PartSizeNotPowerOfTwo);
        }
        if part_size < blake3::CHUNK_LEN as u64 {
            return Err(PartError::PartSizeTooSmall);
        }
        Self::build(total, part_size, u32::MAX)
    }

    fn build(total: u64, part_size: u64, max_parts: u32) -> Result<Self, PartError> {
        if total <= part_size {
            return Err(PartError::NotMultipart);
        }
        let count =
            u32::try_from(total.div_ceil(part_size)).map_err(|_| PartError::TooManyParts)?;
        if count > max_parts {
            return Err(PartError::TooManyParts);
        }
        // Every part-range end, `count × part_size`, must fit u64; this also
        // keeps every range length within `left_subtree_len`'s domain.
        u64::from(count)
            .checked_mul(part_size)
            .ok_or(PartError::TooManyParts)?;
        Ok(Self {
            total,
            part_size,
            count,
        })
    }

    /// Number of parts.
    #[must_use]
    pub fn count(&self) -> u32 {
        self.count
    }

    /// Size of every part but the last.
    #[must_use]
    pub fn part_size(&self) -> u64 {
        self.part_size
    }

    /// Pack byte count.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.total
    }

    /// Byte offset of part `index` in the pack: `index × part_size`.
    ///
    /// # Errors
    /// [`PartError::IndexOutOfRange`] for `index >= count()`.
    pub fn offset(&self, index: u32) -> Result<u64, PartError> {
        if index >= self.count {
            return Err(PartError::IndexOutOfRange);
        }
        // Cannot overflow: index < count, so the offset is below `total`.
        u64::from(index)
            .checked_mul(self.part_size)
            .ok_or(PartError::IndexOutOfRange)
    }

    /// Byte count of part `index`: `part_size`, or the non-empty remainder
    /// for the last part.
    ///
    /// # Errors
    /// [`PartError::IndexOutOfRange`] for `index >= count()`.
    pub fn expected_len(&self, index: u32) -> Result<u64, PartError> {
        Ok((self.total - self.offset(index)?).min(self.part_size))
    }

    /// Check a `part:` commitment against this plan (SPEC-TRANSPORT-CONNECT
    /// §7.6): the index is in range, and the length is `part_size` for every
    /// part but the last, and the remainder for the last.
    ///
    /// # Errors
    /// [`PartError::IndexOutOfRange`] or [`PartError::LengthMismatch`].
    pub fn check(&self, commitment: &PartCommitment) -> Result<(), PartError> {
        if commitment.len == self.expected_len(commitment.index)? {
            Ok(())
        } else {
            Err(PartError::LengthMismatch)
        }
    }

    /// Byte count of the parts `lo..hi` (`lo < hi <= count`).
    fn range_len(&self, lo: u32, hi: u32) -> u64 {
        let end = (u64::from(hi) * self.part_size).min(self.total);
        end - u64::from(lo) * self.part_size
    }
}

/// Streams one part's bytes into its non-root subtree chaining value.
///
/// The hasher never holds more than BLAKE3's own bounded state, whatever the
/// part size.
#[derive(Debug, Clone)]
pub struct PartHasher {
    hasher: blake3::Hasher,
    expected: u64,
    seen: u64,
}

impl PartHasher {
    /// Start hashing part `index` of `plan`.
    ///
    /// # Errors
    /// [`PartError::IndexOutOfRange`] for `index >= plan.count()`.
    pub fn new(plan: &PartPlan, index: u32) -> Result<Self, PartError> {
        let offset = plan.offset(index)?;
        let expected = plan.expected_len(index)?;
        let mut hasher = blake3::Hasher::new();
        // The offset is a multiple of a power-of-two part size of at least
        // one chunk, and no input has been accepted yet.
        hasher.set_input_offset(offset);
        Ok(Self {
            hasher,
            expected,
            seen: 0,
        })
    }

    /// Absorb the next bytes of the part.
    ///
    /// # Errors
    /// [`PartError::Overrun`] if the part would exceed its expected length.
    /// The check runs before any byte is hashed, so the state is unchanged
    /// on error.
    pub fn update(&mut self, data: &[u8]) -> Result<(), PartError> {
        let len = u64::try_from(data.len()).map_err(|_| PartError::Overrun)?;
        if len > self.expected - self.seen {
            return Err(PartError::Overrun);
        }
        // `expected <= part_size <= max_subtree_len(offset)`, so hazmat's
        // subtree-overrun assertion cannot fire.
        self.hasher.update(data);
        self.seen += len;
        Ok(())
    }

    /// Finish the part and return its chaining value.
    ///
    /// # Errors
    /// [`PartError::LengthMismatch`] unless exactly the expected length was
    /// seen.
    pub fn finalize(self) -> Result<ChainingValue, PartError> {
        if self.seen != self.expected {
            return Err(PartError::LengthMismatch);
        }
        // `seen == expected >= 1`, so the subtree is never empty.
        Ok(self.hasher.finalize_non_root())
    }
}

/// The chaining value of part `index`, hashed in one call.
///
/// # Errors
/// [`PartError::IndexOutOfRange`], [`PartError::Overrun`] or
/// [`PartError::LengthMismatch`].
pub fn part_subtree_cv(
    plan: &PartPlan,
    index: u32,
    bytes: &[u8],
) -> Result<ChainingValue, PartError> {
    let mut hasher = PartHasher::new(plan, index)?;
    hasher.update(bytes)?;
    hasher.finalize()
}

/// Merge the part chaining values `cvs`, in index order, into the root hash,
/// which is the pack id.
///
/// A range of parts of byte length `L` splits at `left_subtree_len(L)`,
/// always a part boundary: it is the largest power of two below `L`, and
/// `L > part_size`. Only the top merge is a root.
///
/// # Errors
/// [`PartError::WrongPartCount`] unless `cvs.len() == plan.count()`.
pub fn merge_to_root(plan: &PartPlan, cvs: &[ChainingValue]) -> Result<Hash, PartError> {
    if u32::try_from(cvs.len()) != Ok(plan.count) {
        return Err(PartError::WrongPartCount);
    }
    // `count >= 2` by construction (`NotMultipart`), so the root is a parent.
    let mid = split(plan, 0, plan.count);
    let left = merge_range(plan, cvs, 0, mid);
    let right = merge_range(plan, cvs, mid, plan.count);
    Ok(*hazmat::merge_subtrees_root(&left, &right, Mode::Hash).as_bytes())
}

/// The first part of the right subtree of parts `lo..hi` (`hi - lo >= 2`).
fn split(plan: &PartPlan, lo: u32, hi: u32) -> u32 {
    // The range spans more than one part, so its length exceeds
    // `part_size >= CHUNK_LEN`, as `left_subtree_len` requires; the result
    // is a multiple of `part_size` strictly below the range length.
    let left_parts = hazmat::left_subtree_len(plan.range_len(lo, hi)) / plan.part_size;
    // `left_parts < hi - lo`, which fits u32.
    lo + u32::try_from(left_parts).unwrap_or(hi - lo - 1)
}

fn merge_range(plan: &PartPlan, cvs: &[ChainingValue], lo: u32, hi: u32) -> ChainingValue {
    if hi - lo == 1 {
        return cvs[lo as usize];
    }
    let mid = split(plan, lo, hi);
    hazmat::merge_subtrees_non_root(
        &merge_range(plan, cvs, lo, mid),
        &merge_range(plan, cvs, mid, hi),
        Mode::Hash,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const MIB: u64 = 1024 * 1024;

    fn us(n: u64) -> usize {
        usize::try_from(n).unwrap()
    }

    /// The BLAKE3 test-vector input rule: `byte[i] = i % 251`.
    fn input(len: u64) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    fn cvs(plan: &PartPlan, data: &[u8]) -> Vec<ChainingValue> {
        (0..plan.count())
            .map(|i| {
                let start = us(plan.offset(i).unwrap());
                let end = start + us(plan.expected_len(i).unwrap());
                part_subtree_cv(plan, i, &data[start..end]).unwrap()
            })
            .collect()
    }

    #[test]
    fn plan_rejects_part_size_not_power_of_two() {
        for size in [0, 9 * MIB, 12 * MIB, MIN_PART_SIZE + 1, u64::MAX] {
            assert_eq!(
                PartPlan::new(u64::MAX, size, u32::MAX),
                Err(PartError::PartSizeNotPowerOfTwo),
                "{size}"
            );
        }
    }

    #[test]
    fn plan_rejects_small_part_size() {
        for size in [1, 1024, 4 * MIB, MIN_PART_SIZE / 2] {
            assert_eq!(
                PartPlan::new(64 * MIB, size, u32::MAX),
                Err(PartError::PartSizeTooSmall),
                "{size}"
            );
        }
    }

    #[test]
    fn plan_rejects_single_part_packs() {
        for total in [0, 1, MIN_PART_SIZE - 1, MIN_PART_SIZE] {
            assert_eq!(
                PartPlan::new(total, MIN_PART_SIZE, u32::MAX),
                Err(PartError::NotMultipart),
                "{total}"
            );
        }
        let plan = PartPlan::new(MIN_PART_SIZE + 1, MIN_PART_SIZE, 2).unwrap();
        assert_eq!((plan.count(), plan.total()), (2, MIN_PART_SIZE + 1));
        assert_eq!(plan.part_size(), MIN_PART_SIZE);
    }

    #[test]
    fn plan_rejects_too_many_parts() {
        assert_eq!(
            PartPlan::new(3 * MIN_PART_SIZE, MIN_PART_SIZE, 2),
            Err(PartError::TooManyParts)
        );
        assert_eq!(
            PartPlan::new(MIN_PART_SIZE + 1, MIN_PART_SIZE, 0),
            Err(PartError::TooManyParts)
        );
        PartPlan::new(3 * MIN_PART_SIZE, MIN_PART_SIZE, 3).unwrap();
        // u64::MAX / 8 MiB parts do not fit u32.
        assert_eq!(
            PartPlan::new(u64::MAX, MIN_PART_SIZE, u32::MAX),
            Err(PartError::TooManyParts)
        );
    }

    #[test]
    fn plan_arithmetic_near_u64_max() {
        // `count × part_size` would overflow u64: rejected, never a panic in
        // `range_len` or `left_subtree_len`.
        for (total, part_size, max_parts) in [
            (u64::MAX, 1 << 63, u32::MAX),
            (u64::MAX, 1 << 51, 10_000),
            (u64::MAX - (1 << 51) + 2, 1 << 51, 10_000),
        ] {
            assert_eq!(
                PartPlan::new(total, part_size, max_parts),
                Err(PartError::TooManyParts),
                "{total} {part_size}"
            );
        }
        // The largest plans whose last range end still fits.
        let top = 1 << 62;
        let plan = PartPlan::new(u64::MAX - top, top, u32::MAX).unwrap();
        assert_eq!(plan.count(), 3);
        assert_eq!(plan.offset(2), Ok(2 * top));
        assert_eq!(plan.expected_len(2), Ok(top - 1));
        assert_eq!(plan.offset(3), Err(PartError::IndexOutOfRange));
        let hasher = PartHasher::new(&plan, 2).unwrap();
        assert_eq!(hasher.finalize(), Err(PartError::LengthMismatch));
        assert!(merge_to_root(&plan, &[[0; 32]; 3]).is_ok());
        let plan = PartPlan::new(u64::MAX - (1 << 51) + 1, 1 << 51, 10_000).unwrap();
        assert_eq!(plan.count(), 8191);
        assert!(merge_to_root(&plan, &vec![[0; 32]; 8191]).is_ok());
    }

    #[test]
    fn plan_checks_part_commitments() {
        let plan = PartPlan::new(2 * MIN_PART_SIZE + 5, MIN_PART_SIZE, 3).unwrap();
        let part = |index, len| PartCommitment {
            ticket: [0x5a; 32],
            index,
            subtree: [0xcd; 32],
            len,
        };
        assert_eq!(plan.check(&part(0, MIN_PART_SIZE)), Ok(()));
        assert_eq!(plan.check(&part(1, MIN_PART_SIZE)), Ok(()));
        assert_eq!(plan.check(&part(2, 5)), Ok(()));
        for (index, len) in [
            (0, MIN_PART_SIZE - 1),
            (1, MIN_PART_SIZE + 1),
            (1, 5),
            (2, 4),
            (2, 6),
            (2, MIN_PART_SIZE),
        ] {
            assert_eq!(
                plan.check(&part(index, len)),
                Err(PartError::LengthMismatch),
                "{index} {len}"
            );
        }
        for index in [3, u32::MAX] {
            assert_eq!(plan.check(&part(index, 5)), Err(PartError::IndexOutOfRange));
        }
    }

    #[test]
    fn expected_len_last_part_is_remainder() {
        let plan = PartPlan::new(4 * MIN_PART_SIZE + 5, MIN_PART_SIZE, 5).unwrap();
        assert_eq!(plan.count(), 5);
        for i in 0..4 {
            assert_eq!(plan.expected_len(i), Ok(MIN_PART_SIZE));
            assert_eq!(plan.offset(i), Ok(u64::from(i) * MIN_PART_SIZE));
        }
        assert_eq!(plan.expected_len(4), Ok(5));
        let exact = PartPlan::new(2 * MIN_PART_SIZE, MIN_PART_SIZE, 2).unwrap();
        assert_eq!(exact.expected_len(1), Ok(MIN_PART_SIZE));
    }

    #[test]
    fn index_out_of_range() {
        let plan = PartPlan::new(2 * MIN_PART_SIZE, MIN_PART_SIZE, 2).unwrap();
        for index in [2, 3, u32::MAX] {
            assert_eq!(plan.offset(index), Err(PartError::IndexOutOfRange));
            assert_eq!(plan.expected_len(index), Err(PartError::IndexOutOfRange));
            assert_eq!(
                PartHasher::new(&plan, index).unwrap_err(),
                PartError::IndexOutOfRange
            );
        }
    }

    #[test]
    fn hasher_overrun_is_error_not_panic() {
        let plan = PartPlan::new_small(5 * 1024 + 7, 1024).unwrap();
        for index in 0..plan.count() {
            let expected = us(plan.expected_len(index).unwrap());
            let good = part_subtree_cv(&plan, index, &vec![7; expected]).unwrap();
            // One call.
            assert_eq!(
                part_subtree_cv(&plan, index, &vec![7; expected + 1]),
                Err(PartError::Overrun)
            );
            // Two calls: the second overruns and leaves the state unchanged.
            let mut hasher = PartHasher::new(&plan, index).unwrap();
            hasher.update(&vec![7; expected]).unwrap();
            assert_eq!(hasher.update(&[7]), Err(PartError::Overrun));
            assert_eq!(hasher.finalize(), Ok(good));
        }
        // An 8 MiB part at a non-zero offset: hazmat would assert here.
        let plan = PartPlan::new(3 * MIN_PART_SIZE, MIN_PART_SIZE, 3).unwrap();
        let mut hasher = PartHasher::new(&plan, 1).unwrap();
        hasher.update(&vec![0; us(MIN_PART_SIZE)]).unwrap();
        assert_eq!(hasher.update(&[0]), Err(PartError::Overrun));
    }

    #[test]
    fn hasher_short_is_length_mismatch() {
        let plan = PartPlan::new_small(3 * 1024 + 1, 1024).unwrap();
        for index in 0..plan.count() {
            let expected = us(plan.expected_len(index).unwrap());
            assert_eq!(
                part_subtree_cv(&plan, index, &vec![1; expected - 1]),
                Err(PartError::LengthMismatch)
            );
            assert_eq!(
                PartHasher::new(&plan, index).unwrap().finalize(),
                Err(PartError::LengthMismatch)
            );
        }
    }

    #[test]
    fn merge_rejects_wrong_count() {
        let plan = PartPlan::new_small(3 * 1024, 1024).unwrap();
        let data = input(plan.total());
        let mut all = cvs(&plan, &data);
        assert_eq!(
            merge_to_root(&plan, &all[..2]),
            Err(PartError::WrongPartCount)
        );
        assert_eq!(merge_to_root(&plan, &[]), Err(PartError::WrongPartCount));
        all.push(all[0]);
        assert_eq!(merge_to_root(&plan, &all), Err(PartError::WrongPartCount));
    }

    #[test]
    fn swapped_cvs_do_not_match_root() {
        let plan = PartPlan::new_small(4 * 1024, 1024).unwrap();
        let data = input(plan.total());
        let mut all = cvs(&plan, &data);
        assert_eq!(merge_to_root(&plan, &all), Ok(crate::hash::hash(&data)));
        all.swap(1, 2);
        assert_ne!(merge_to_root(&plan, &all), Ok(crate::hash::hash(&data)));
    }

    #[test]
    fn part_cv_is_offset_bound() {
        // The same bytes at a different index hash differently.
        let plan = PartPlan::new_small(3 * 1024, 1024).unwrap();
        let bytes = [9; 1024];
        let a = part_subtree_cv(&plan, 0, &bytes).unwrap();
        let b = part_subtree_cv(&plan, 1, &bytes).unwrap();
        assert_ne!(a, b);
    }

    /// Every small-geometry vector in the committed fixture, through this
    /// module's own `new_small` path (the integration test cannot reach it).
    #[test]
    fn small_geometry_goldens_match_module() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/golden/uploads/subtree-merge.json"
        ))
        .unwrap();
        let mut checked = 0;
        for vector in fixture["vectors"].as_array().unwrap() {
            if vector["test_geometry"] != serde_json::Value::Bool(true) {
                continue;
            }
            let plan = PartPlan::new_small(
                vector["total"].as_u64().unwrap(),
                vector["part_size"].as_u64().unwrap(),
            )
            .unwrap();
            let data = input(plan.total());
            let all = cvs(&plan, &data);
            let parts = vector["parts"].as_array().unwrap();
            assert_eq!(parts.len(), all.len());
            for (part, cv) in parts.iter().zip(&all) {
                assert_eq!(part["cv"].as_str().unwrap(), crate::hash::to_hex(cv));
            }
            let root = merge_to_root(&plan, &all).unwrap();
            assert_eq!(vector["root"].as_str().unwrap(), crate::hash::to_hex(&root));
            checked += 1;
        }
        assert!(checked >= 6, "expected the small-geometry vectors");
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn streaming_split_equals_one_shot(
            exp in 10u32..=14,
            extra in 1u64..=40_000,
            index_seed in any::<u32>(),
            cuts in proptest::collection::vec(any::<u16>(), 0..8),
        ) {
            let part_size = 1u64 << exp;
            let plan = PartPlan::new_small(part_size + extra, part_size).unwrap();
            let index = index_seed % plan.count();
            let data = input(plan.total());
            let start = us(plan.offset(index).unwrap());
            let part = &data[start..start + us(plan.expected_len(index).unwrap())];
            let one_shot = part_subtree_cv(&plan, index, part).unwrap();
            let mut points: Vec<usize> = cuts.iter().map(|c| usize::from(*c) % (part.len() + 1)).collect();
            points.sort_unstable();
            let mut hasher = PartHasher::new(&plan, index).unwrap();
            let mut last = 0;
            for point in points.into_iter().chain([part.len()]) {
                hasher.update(&part[last..point]).unwrap();
                last = point;
            }
            prop_assert_eq!(hasher.finalize().unwrap(), one_shot);
        }

        #[test]
        fn merge_matches_blake3_hash_small_geometry(
            exp in 10u32..=16,
            parts in 2u64..=20,
            short in any::<u64>(),
        ) {
            let part_size = 1u64 << exp;
            // `parts` parts, the last between 1 and `part_size` bytes.
            let total = (parts - 1) * part_size + 1 + short % part_size;
            let plan = PartPlan::new_small(total, part_size).unwrap();
            prop_assert_eq!(u64::from(plan.count()), parts);
            let data = input(total);
            let root = merge_to_root(&plan, &cvs(&plan, &data)).unwrap();
            prop_assert_eq!(root, crate::hash::hash(&data));
        }

        #[test]
        fn arbitrary_geometry_never_panics(
            total in any::<u64>(),
            part_size in prop_oneof![any::<u64>(), (0u32..64).prop_map(|e| 1u64 << e)],
            max_parts in any::<u32>(),
            index in any::<u32>(),
        ) {
            if let Ok(plan) = PartPlan::new(total, part_size, max_parts) {
                prop_assert!(plan.count() >= 2 && plan.count() <= max_parts);
                let _ = plan.offset(index);
                let _ = plan.expected_len(index);
                if let Ok(mut hasher) = PartHasher::new(&plan, index) {
                    let _ = hasher.update(&[0; 3]);
                    let _ = hasher.finalize();
                }
                let _ = plan.check(&PartCommitment {
                    ticket: [0; 32],
                    index,
                    subtree: [0; 32],
                    len: total % 97,
                });
                // Reach `range_len`/`left_subtree_len` on every small plan.
                if plan.count() <= 64 {
                    let cvs = vec![[0; 32]; plan.count() as usize];
                    prop_assert!(merge_to_root(&plan, &cvs).is_ok());
                }
                let _ = merge_to_root(&plan, &[[0; 32]; 3]);
            }
        }
    }
}
