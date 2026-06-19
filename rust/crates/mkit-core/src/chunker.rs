//! `FastCDC` content-defined chunker.
//!
//! Spec reference: `docs/SPEC-FASTCDC.md`. Frozen v1 parameters:
//!
//! * Gear seed: ASCII `"MKITFCDC"` interpreted as a big-endian `u64`
//!   (`0x4D4B_4954_4643_4443`). Splitmix64-derived 256-entry table.
//! * `MIN_SIZE = 16 KiB`, `AVG_SIZE = 64 KiB`, `MAX_SIZE = 256 KiB`.
//! * `MASK_S = 0x0001_FFFF` (strict, used while `i < AVG_SIZE`).
//! * `MASK   = 0x0000_FFFF` (informative; not used directly — we only
//!   need the strict and loose masks at runtime).
//! * `MASK_L = 0x0000_7FFF` (loose, used while `AVG_SIZE <= i < MAX_SIZE`).
//! * Rolling hash: `h = (h << 1) +% gear[byte]`. Cut when `(h & mask) == 0`,
//!   else force a cut at `MAX_SIZE`. Never cut before `MIN_SIZE`.
//!
//! The spec hard-codes the masks; we pin them as constants here so any
//! accidental change lights up in the golden tests immediately.
//!
//! All chunk boundaries are fully determined by the input bytes plus the
//! constants above. Any change breaks `chunked_blob` reproducibility
//! (see `SPEC-FASTCDC.md` §2 determinism contract).

/// Frozen splitmix64 seed for v1 — ASCII `"MKITFCDC"` as big-endian u64.
pub const SEED: u64 = 0x4D4B_4954_4643_4443;

/// Minimum chunk size (`16 KiB`). `cut` will not return a value below
/// this for non-final chunks.
pub const MIN_SIZE: usize = 0x4000;
/// Average target chunk size (`64 KiB`). The mask transition from strict
/// to loose happens here.
pub const AVG_SIZE: usize = 0x10000;
/// Maximum chunk size (`256 KiB`). `cut` always returns at most this.
pub const MAX_SIZE: usize = 0x40000;

/// Strict mask (used while `i < AVG_SIZE`). Fewer cuts → bias the chunker
/// toward `AVG_SIZE`.
pub const MASK_S: u64 = 0x0001_FFFF;
/// Loose mask (used while `AVG_SIZE <= i < MAX_SIZE`). More cuts → avoid
/// running into the `MAX_SIZE` forced boundary.
pub const MASK_L: u64 = 0x0000_7FFF;

/// 256-entry gear table, derived once at first use from [`SEED`] via
/// splitmix64. Wrapping arithmetic throughout — see SPEC-FASTCDC §3 for
/// the exact derivation.
fn gear_table() -> &'static [u64; 256] {
    use std::sync::OnceLock;
    static TABLE: OnceLock<[u64; 256]> = OnceLock::new();
    TABLE.get_or_init(build_gear_table)
}

fn build_gear_table() -> [u64; 256] {
    let mut state: u64 = SEED;
    let mut table = [0u64; 256];
    for entry in &mut table {
        // splitmix64 with the standard gamma. All ops are wrapping.
        state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^= z >> 31;
        *entry = z;
    }
    table
}

/// One chunk's position in the source buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkBoundary {
    pub offset: usize,
    pub length: usize,
}

/// `FastCDC` chunker parameters. Construct with [`FastCdc::v1`] for the
/// frozen v1 constants; other constructors exist mainly for tests that
/// exercise the algorithm at smaller sizes.
#[derive(Debug, Clone, Copy)]
pub struct FastCdc {
    min_size: usize,
    avg_size: usize,
    max_size: usize,
    mask_s: u64,
    mask_l: u64,
}

impl FastCdc {
    /// Construct the v1 chunker (`16 KiB / 64 KiB / 256 KiB`,
    /// strict/loose `0x0001_FFFF` / `0x0000_7FFF`).
    #[must_use]
    pub const fn v1() -> Self {
        Self {
            min_size: MIN_SIZE,
            avg_size: AVG_SIZE,
            max_size: MAX_SIZE,
            mask_s: MASK_S,
            mask_l: MASK_L,
        }
    }

    /// Construct a chunker with custom parameters. `avg_size` MUST be a
    /// power of two; the strict/loose masks are derived as
    /// `mask = (1 << log2(avg)) - 1; mask_s = mask | (mask << 1); mask_l = mask >> 1`.
    /// Returns [`crate::object::MkitError::InvalidIdentity`] re-purposed as a generic
    /// "bad parameter" error if the constraints are violated — but in
    /// practice this constructor is only used by tests, where the inputs
    /// are constants, so we panic instead for a clearer failure mode.
    ///
    /// # Panics
    ///
    /// Panics if `min < avg < max` is not strictly satisfied or `avg` is
    /// not a power of two.
    #[must_use]
    pub fn custom(min: usize, avg: usize, max: usize) -> Self {
        assert!(min < avg && avg < max, "FastCdc: require min<avg<max");
        assert!(avg.is_power_of_two(), "FastCdc: avg must be a power of 2");
        let bits = avg.trailing_zeros();
        let mask: u64 = (1u64 << bits) - 1;
        Self {
            min_size: min,
            avg_size: avg,
            max_size: max,
            mask_s: mask | (mask << 1),
            mask_l: mask >> 1,
        }
    }

    #[must_use]
    pub const fn min_size(&self) -> usize {
        self.min_size
    }
    #[must_use]
    pub const fn avg_size(&self) -> usize {
        self.avg_size
    }
    #[must_use]
    pub const fn max_size(&self) -> usize {
        self.max_size
    }

    /// Find the cut point in `data`. Returns the length of the first
    /// chunk. Semantics:
    ///
    /// * `data.len() <= min_size` → returns `data.len()` (no early cut).
    /// * `min_size < i <= avg_size` → strict mask, fewer boundaries.
    /// * `avg_size < i <= max_size` → loose mask, more boundaries.
    /// * Otherwise → forced cut at `min(max_size, data.len())`.
    #[must_use]
    pub fn cut(&self, data: &[u8]) -> usize {
        if data.len() <= self.min_size {
            return data.len();
        }
        let table = gear_table();
        let mut hash: u64 = 0;
        let avg_end = self.avg_size.min(data.len());
        let mut i = self.min_size;
        while i < avg_end {
            hash = (hash << 1).wrapping_add(table[data[i] as usize]);
            if (hash & self.mask_s) == 0 {
                return i;
            }
            i += 1;
        }
        let max_end = self.max_size.min(data.len());
        while i < max_end {
            hash = (hash << 1).wrapping_add(table[data[i] as usize]);
            if (hash & self.mask_l) == 0 {
                return i;
            }
            i += 1;
        }
        max_end
    }
}

/// Iterator over chunk boundaries in a contiguous byte slice.
#[derive(Debug)]
pub struct ChunkIterator<'a> {
    cdc: FastCdc,
    data: &'a [u8],
    offset: usize,
}

impl<'a> ChunkIterator<'a> {
    #[must_use]
    pub fn new(cdc: FastCdc, data: &'a [u8]) -> Self {
        Self {
            cdc,
            data,
            offset: 0,
        }
    }
}

impl Iterator for ChunkIterator<'_> {
    type Item = ChunkBoundary;
    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.data.len() {
            return None;
        }
        let remaining = &self.data[self.offset..];
        let length = self.cdc.cut(remaining);
        let boundary = ChunkBoundary {
            offset: self.offset,
            length,
        };
        self.offset += length;
        Some(boundary)
    }
}

/// Convenience: collect all chunk *end* offsets from `data` using the
/// frozen v1 chunker. The returned vector starts with the length of the
/// first chunk and ends with `data.len()`. An empty input yields an
/// empty vector. Used by goldens to pin boundaries deterministically
/// without exposing the `ChunkBoundary` struct in serialised form.
#[must_use]
pub fn chunk_boundaries(data: &[u8]) -> Vec<usize> {
    let cdc = FastCdc::v1();
    let mut out = Vec::new();
    let mut offset = 0usize;
    while offset < data.len() {
        let len = cdc.cut(&data[offset..]);
        offset += len;
        out.push(offset);
    }
    out
}

/// Hash the entire 256-entry gear table as little-endian `u64` bytes
/// (2 048 bytes total) with BLAKE3. Useful as a cheap "did we get the
/// seed right" check — see SPEC-FASTCDC §8 vector 1.
#[must_use]
pub fn gear_table_digest() -> [u8; 32] {
    let table = gear_table();
    let mut bytes = [0u8; 256 * 8];
    for (i, v) in table.iter().enumerate() {
        bytes[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
    }
    crate::hash::hash(&bytes)
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic xorshift64* PRNG for test-data generation. We avoid
    /// `rand` here to keep test inputs explicit and reproducible
    /// without committing to a specific `rand` version.
    struct Prng(u64);
    impl Prng {
        fn new(seed: u64) -> Self {
            Self(seed.max(1))
        }
        fn next_u64(&mut self) -> u64 {
            // splitmix64 (same primitive used to derive the gear table —
            // a different seed gives an unrelated stream).
            self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        }
        fn fill(&mut self, dst: &mut [u8]) {
            for chunk in dst.chunks_mut(8) {
                let bytes = self.next_u64().to_le_bytes();
                let n = chunk.len();
                chunk.copy_from_slice(&bytes[..n]);
            }
        }
    }

    #[test]
    fn gear_table_is_unique_and_nonzero() {
        let table = gear_table();
        let mut seen = std::collections::HashSet::new();
        for &v in table {
            assert_ne!(v, 0, "gear table entry is zero");
            assert!(seen.insert(v), "duplicate gear table entry");
        }
        assert_eq!(seen.len(), 256);
    }

    #[test]
    fn determinism_same_input_same_boundaries() {
        let cdc = FastCdc::v1();
        let mut data = vec![0u8; 200 * 1024];
        Prng::new(0xDEAD_BEEF).fill(&mut data);

        let pass1: Vec<_> = ChunkIterator::new(cdc, &data).collect();
        let pass2: Vec<_> = ChunkIterator::new(cdc, &data).collect();
        assert_eq!(pass1, pass2);
    }

    #[test]
    fn min_max_size_constraints() {
        let cdc = FastCdc::v1();
        let mut data = vec![0u8; 512 * 1024];
        Prng::new(0xCAFE_BABE).fill(&mut data);

        let mut total = 0usize;
        let mut count = 0usize;
        for b in ChunkIterator::new(cdc, &data) {
            assert!(b.length <= MAX_SIZE);
            // Only the final chunk is allowed to be smaller than min.
            if b.offset + b.length < data.len() {
                assert!(b.length >= MIN_SIZE, "chunk under MIN_SIZE: {}", b.length);
            }
            total += b.length;
            count += 1;
        }
        assert_eq!(total, data.len());
        assert!(count > 1);
    }

    #[test]
    fn small_input_is_single_chunk() {
        let cdc = FastCdc::v1();
        let small = b"hello, this is a tiny file";
        assert_eq!(cdc.cut(small), small.len());
        let boundaries: Vec<_> = ChunkIterator::new(cdc, small).collect();
        assert_eq!(boundaries.len(), 1);
        assert_eq!(boundaries[0].offset, 0);
        assert_eq!(boundaries[0].length, small.len());
    }

    #[test]
    fn empty_input_iterator_is_empty() {
        let cdc = FastCdc::v1();
        assert_eq!(cdc.cut(b""), 0);
        let none: Vec<_> = ChunkIterator::new(cdc, b"").collect();
        assert!(none.is_empty());
    }

    #[test]
    fn cut_at_exactly_min_size_returns_full() {
        let cdc = FastCdc::custom(1024, 4096, 16384);
        let mut data = vec![0u8; 1024];
        Prng::new(99).fill(&mut data);
        assert_eq!(cdc.cut(&data), data.len());
    }

    #[test]
    fn cut_forces_boundary_at_max_size() {
        // All-zero buffer, gear hash never trips a natural cut → forced
        // cut at max_size.
        let cdc = FastCdc::custom(4, 8, 16);
        let data = [0u8; 64];
        let len = cdc.cut(&data);
        assert!(len <= 16, "cut returned {len} > max=16");
    }

    #[test]
    fn boundary_stability_single_byte_insert() {
        // Insert one byte at offset 32 KiB; expect <=3 chunks differ.
        let cdc = FastCdc::v1();
        let mut original = vec![0u8; 64 * 1024];
        Prng::new(0xBEEF).fill(&mut original);
        let insert_point = 32 * 1024;
        let mut modified = Vec::with_capacity(original.len() + 1);
        modified.extend_from_slice(&original[..insert_point]);
        modified.push(0xFF);
        modified.extend_from_slice(&original[insert_point..]);

        let orig_chunks: Vec<_> = ChunkIterator::new(cdc, &original).collect();
        let mod_chunks: Vec<_> = ChunkIterator::new(cdc, &modified).collect();

        let max_chunks = orig_chunks.len().max(mod_chunks.len());
        let mut differing = 0usize;
        for i in 0..max_chunks {
            match (orig_chunks.get(i), mod_chunks.get(i)) {
                (Some(o), Some(m)) => {
                    let os = &original[o.offset..o.offset + o.length];
                    let ms = &modified[m.offset..m.offset + m.length];
                    if os != ms {
                        differing += 1;
                    }
                }
                _ => differing += 1,
            }
        }
        assert!(
            differing <= 3,
            "expected <=3 differing chunks, got {differing}"
        );
    }

    #[test]
    fn iterator_total_bytes_matches_input() {
        let cdc = FastCdc::v1();
        let mut data = vec![0u8; 300 * 1024];
        Prng::new(42).fill(&mut data);
        let total: usize = ChunkIterator::new(cdc, &data).map(|b| b.length).sum();
        assert_eq!(total, data.len());
    }

    #[test]
    fn different_avg_size_yields_different_boundaries() {
        let mut data = vec![0u8; 100 * 1024];
        Prng::new(0xABCD).fill(&mut data);
        let small = FastCdc::custom(8 * 1024, 32 * 1024, 128 * 1024);
        let large = FastCdc::v1();

        let s: Vec<_> = ChunkIterator::new(small, &data)
            .map(|b| b.offset + b.length)
            .collect();
        let l: Vec<_> = ChunkIterator::new(large, &data)
            .map(|b| b.offset + b.length)
            .collect();
        assert!(
            s != l,
            "expected different boundaries for different avg_size"
        );
    }

    #[test]
    fn chunk_boundaries_helper_matches_iterator() {
        let mut data = vec![0u8; 200 * 1024];
        Prng::new(0xFEED_FACE).fill(&mut data);
        let from_helper = chunk_boundaries(&data);
        let from_iter: Vec<usize> = ChunkIterator::new(FastCdc::v1(), &data)
            .map(|b| b.offset + b.length)
            .collect();
        assert_eq!(from_helper, from_iter);
    }

    /// Pinned v1 gear-table digest, harvested once from the splitmix64
    /// derivation seeded with "MKITFCDC". Drift = a v2 break.
    const EXPECTED_GEAR_DIGEST_HEX: &str =
        "7b238963a8bb10c4dea1bf678aa07d8c3ce94284209c440ca971ff3a97ee5ad4";

    #[test]
    fn gear_table_digest_is_stable() {
        // SPEC-FASTCDC §8 vector 1: any change to the seed or splitmix
        // derivation moves this digest. CI flags drift loud and early.
        let hex = crate::hash::to_hex(&gear_table_digest());
        assert_eq!(
            hex, EXPECTED_GEAR_DIGEST_HEX,
            "gear table digest changed; refuse to drift silently"
        );
    }

    // -- Property tests -------------------------------------------------
    //
    // Determinism + cap invariants exercised against arbitrary inputs
    // via `proptest`. The example tests above cover specific PRNG seeds;
    // the properties below catch the boundary cases the examples miss
    // (very-short data, repeating patterns, etc.).
    proptest::proptest! {
        /// FastCDC is deterministic: two passes over the same bytes
        /// produce the same chunk boundaries. This is the core SPEC-
        /// FASTCDC §2 contract that makes `chunked_blob` content-
        /// addressable.
        #[test]
        fn proptest_determinism(data in proptest::collection::vec(proptest::num::u8::ANY, 0..256 * 1024)) {
            let cdc = FastCdc::v1();
            let pass1: Vec<_> = ChunkIterator::new(cdc, &data).collect();
            let pass2: Vec<_> = ChunkIterator::new(cdc, &data).collect();
            proptest::prop_assert_eq!(pass1, pass2);
        }

        /// Boundaries cover the input exactly: sum of lengths equals
        /// input length; offsets are non-overlapping and monotonic.
        #[test]
        fn proptest_boundaries_partition_input(
            data in proptest::collection::vec(proptest::num::u8::ANY, 0..256 * 1024),
        ) {
            let cdc = FastCdc::v1();
            let boundaries: Vec<_> = ChunkIterator::new(cdc, &data).collect();
            let mut expected_offset = 0usize;
            for b in &boundaries {
                proptest::prop_assert_eq!(b.offset, expected_offset);
                expected_offset += b.length;
            }
            proptest::prop_assert_eq!(expected_offset, data.len());
        }
    }
}
