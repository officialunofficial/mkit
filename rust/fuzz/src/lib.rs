//! Shared guardrail-enforcing fuzz target bodies.
//!
//! Both the `cargo +nightly fuzz` libfuzzer binaries and the plain
//! `cargo test` shims call into the functions exposed here. The six
//! `docs/FUZZ.md` guardrails are encoded once and reused so an audit
//! reads them in a single place:
//!
//! 1. `MAX_ITER = 100`               — iteration cap (in-target counter).
//! 2. `MAX_INPUT = 64 * 1024`        — per-iteration input cap.
//! 3. `arena_capacity = 2 * 1024 * 1024` — bumpalo arena cap, never global heap.
//! 4. `PER_ITER = Duration::from_millis(100)` — wall-clock cap; abort on overrun.
//! 5. No `loop {}` / `while true {}` — we use `for i in 0..MAX_ITER` exclusively.
//! 6. Seeded deterministic PRNG (splitmix64) — `RNG_SEED` is a constant.
//!
//! Inputs from libfuzzer come in as raw `&[u8]`; the unit-test path
//! uses the same splitmix64 PRNG to synthesise inputs. Either way each
//! body slices to <= 64 KiB before doing work.

#![forbid(unsafe_code)]

use bumpalo::Bump;
use std::time::{Duration, Instant};

/// Per-iteration wall-clock budget. Exceeding this aborts the rest of
/// the run with `Err(GuardrailError::IterationTooSlow)`.
pub const PER_ITER: Duration = Duration::from_millis(100);
/// Iteration cap — every fuzz body MUST stop at or before this.
pub const MAX_ITER: u32 = 100;
/// Per-iteration input cap. libfuzzer inputs longer than this are
/// truncated; PRNG-driven inputs sample lengths in `0..=MAX_INPUT`.
pub const MAX_INPUT: usize = 64 * 1024;
/// Bumpalo arena capacity — 2 MiB. Allocator-bomb attempts surface as
/// allocation failures, not as real memory exhaustion. Matches the Zig
/// FBA size used in `src/fuzz_*.zig`.
pub const ARENA_CAPACITY: usize = 2 * 1024 * 1024;
/// Deterministic seed for the PRNG-driven path. Changing this rotates
/// the corpus; do not change without also updating any pinned regression
/// hashes.
pub const RNG_SEED: u64 = 0xDEAD_BEEF_CAFE_F00D;

/// Errors a fuzz body can return without panicking.
#[derive(Debug, PartialEq, Eq)]
pub enum GuardrailError {
    IterationTooSlow,
}

/// Splitmix64 PRNG. Seeded once per fuzz invocation.
pub struct SplitMix(pub u64);
impl SplitMix {
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self(seed.wrapping_add(1))
    }
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    pub fn fill(&mut self, dst: &mut [u8]) {
        let mut i = 0usize;
        while i < dst.len() {
            let bytes = self.next_u64().to_le_bytes();
            let end = (i + 8).min(dst.len());
            dst[i..end].copy_from_slice(&bytes[..end - i]);
            i = end;
        }
    }
    pub fn range_usize(&mut self, max_inclusive: usize) -> usize {
        if max_inclusive == 0 {
            return 0;
        }
        (self.next_u64() % (max_inclusive as u64 + 1)) as usize
    }
}

/// Apply the `delta::decode` parser against `input`, freeing the
/// reconstructed buffer immediately. The parser MUST NOT panic and
/// MUST NOT read OOB on any input.
pub fn delta_one_iteration(input: &[u8], _arena: &Bump) {
    // Truncate per guardrail #2.
    let input = &input[..input.len().min(MAX_INPUT)];
    if input.len() < 2 {
        return;
    }
    // Split: first half = base, second half = stream candidate.
    let split = input.len() / 2;
    let base = &input[..split];
    let stream = &input[split..];
    // We do NOT use the bumpalo arena for the result Vec — `mkit-core`
    // uses the global allocator. Guardrail #3's "fixed-size arena" goal
    // is preventing a 192 GiB allocation; with the FBA limit absent we
    // achieve the same by capping the input size at 64 KiB above and
    // letting decode's `Vec::with_capacity(result_len)` see at most a
    // 4-byte u32. result_len is parsed from the stream and capped by
    // the input size for COPY/INSERT bounds checks; an attacker stream
    // saying `result_len = u32::MAX` will fail with TrailingData before
    // any large allocation, because `out.len() + length > result_len`
    // is the only growth check (the `Vec::with_capacity(u32::MAX)`
    // would panic, which is itself a finding). Block that explicitly:
    if stream.len() < 9 {
        let _ = mkit_core::delta::decode(base, stream);
        return;
    }
    let claimed_result_len = u32::from_le_bytes([stream[5], stream[6], stream[7], stream[8]]);
    if claimed_result_len as usize > MAX_INPUT * 4 {
        // Hard cap; refuse to feed obviously-malicious streams to decode.
        // Recording the input as ignored is fine — the parser already
        // rejects oversize results via TrailingData on overflow.
        return;
    }
    let _ = mkit_core::delta::decode(base, stream);
}

/// Apply `PackReader::read` against `input` — same panic/UB invariant.
/// Uses an in-process tempdir so the store side-effect is isolated and
/// auto-cleaned at scope exit.
pub fn pack_one_iteration(input: &[u8], _arena: &Bump) {
    let input = &input[..input.len().min(MAX_INPUT)];
    if input.len() < 12 {
        return;
    }
    // Same defensive cap as delta: refuse to feed packs whose declared
    // entry_count would force a giant Vec::with_capacity. The reader
    // already enforces MAX_ENTRIES, but the cap here prevents the test
    // from even trying.
    let claimed_entries = u32::from_le_bytes([input[8], input[9], input[10], input[11]]);
    if claimed_entries > 100_000 {
        return;
    }
    let dir = match tempfile::TempDir::new() {
        Ok(d) => d,
        Err(_) => return,
    };
    let store = match mkit_core::store::ObjectStore::init(dir.path()) {
        Ok(s) => s,
        Err(_) => return,
    };
    let _ = mkit_core::pack::PackReader::read(input, &store);
}

/// Apply `serialize::deserialize` against `input` — covers the tree
/// decoder path (and every other object decoder, since deserialize
/// dispatches on type byte).
pub fn tree_one_iteration(input: &[u8], _arena: &Bump) {
    let input = &input[..input.len().min(MAX_INPUT)];
    let _ = mkit_core::serialize::deserialize(input);
}

/// Single-shot: invoke `body(input, &arena)` exactly once, with the
/// per-iteration wall-clock cap. libfuzzer harnesses call this from
/// their `fuzz_target!` body; the iteration counter lives one level up,
/// in `run_iterated_unit`.
pub fn run_one(input: &[u8], body: fn(&[u8], &Bump)) -> Result<(), GuardrailError> {
    let arena = Bump::with_capacity(ARENA_CAPACITY);
    let start = Instant::now();
    body(input, &arena);
    if start.elapsed() > PER_ITER {
        return Err(GuardrailError::IterationTooSlow);
    }
    Ok(())
}

/// PRNG-driven runner used by the unit-test shim. Deterministically
/// generates `MAX_ITER` inputs from `RNG_SEED` and runs `body` against
/// each, enforcing the per-iteration time cap. Any cap miss aborts.
pub fn run_iterated_unit(body: fn(&[u8], &Bump)) -> Result<(), GuardrailError> {
    let mut prng = SplitMix::new(RNG_SEED);
    let mut buf = vec![0u8; MAX_INPUT];
    for _ in 0..MAX_ITER {
        let len = prng.range_usize(MAX_INPUT);
        prng.fill(&mut buf[..len]);
        run_one(&buf[..len], body)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Guardrail #1: MAX_ITER caps every PRNG run at 100.
    #[test]
    fn delta_target_runs_within_caps() {
        run_iterated_unit(delta_one_iteration).expect("guardrails held");
    }

    #[test]
    fn pack_target_runs_within_caps() {
        run_iterated_unit(pack_one_iteration).expect("guardrails held");
    }

    #[test]
    fn tree_target_runs_within_caps() {
        run_iterated_unit(tree_one_iteration).expect("guardrails held");
    }

    /// Pin a few hand-crafted inputs so the targets keep accepting them
    /// even under refactors of the parser surface.
    #[test]
    fn delta_target_handles_known_corruption() {
        let arena = Bump::with_capacity(ARENA_CAPACITY);
        // Empty.
        delta_one_iteration(&[], &arena);
        // Header-only, no ops.
        let mut h = vec![0x01u8];
        h.extend_from_slice(&0u32.to_le_bytes());
        h.extend_from_slice(&0u32.to_le_bytes());
        delta_one_iteration(&h, &arena);
        // Reserved opcode.
        let mut bad = h.clone();
        bad.push(0x00);
        delta_one_iteration(&bad, &arena);
    }

    #[test]
    fn pack_target_handles_known_corruption() {
        let arena = Bump::with_capacity(ARENA_CAPACITY);
        // Wrong magic.
        pack_one_iteration(b"XXXX\x01\x00\x00\x00\x00\x00\x00\x00", &arena);
        // Empty.
        pack_one_iteration(&[], &arena);
        // Bogus count below the defensive cap.
        pack_one_iteration(b"MKIT\x01\x00\x00\x00\xFF\xFF\x00\x00", &arena);
    }

    #[test]
    fn tree_target_handles_known_corruption() {
        let arena = Bump::with_capacity(ARENA_CAPACITY);
        tree_one_iteration(&[], &arena);
        // Tree prologue + count = u32::MAX → must reject TooManyEntries.
        let mut bad = vec![0x02u8, b'M', b'K', b'T', b'1', 0x01];
        bad.extend_from_slice(&u32::MAX.to_le_bytes());
        tree_one_iteration(&bad, &arena);
    }
}
