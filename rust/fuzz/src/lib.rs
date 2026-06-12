//! Shared guardrail-enforcing fuzz target bodies.
//!
//! Both the `cargo +nightly fuzz` libfuzzer binaries and the plain
//! `cargo test` shims call into the functions exposed here. The six
//! `docs/FUZZ.md` guardrails are encoded once and reused so an audit
//! reads them in a single place:
//!
//! 1. `MAX_ITER = 100`               — iteration cap (in-target counter).
//! 2. `MAX_INPUT = 64 * 1024`        — per-iteration input cap.
//! 3. **Bounded allocations** — the input cap above plus per-op output
//!    caps inside `mkit-core` (`delta::decode` caps initial capacity,
//!    `pack::PackReader` enforces `MAX_ENTRIES` and `MAX_PAYLOAD`)
//!    keep the worst-case heap to ~1 MiB per iteration. Defensive
//!    pre-checks in the harness refuse obviously-malicious headers
//!    before invoking core.
//! 4. `PER_ITER = Duration::from_millis(100)` — wall-clock cap; abort on overrun.
//! 5. No `loop {}` / `while true {}` — we use `for i in 0..MAX_ITER` exclusively.
//! 6. Seeded deterministic PRNG (splitmix64) — `RNG_SEED` is a constant.
//!
//! Inputs from libfuzzer come in as raw `&[u8]`; the unit-test path
//! uses the same splitmix64 PRNG to synthesise inputs. Either way each
//! body slices to <= 64 KiB before doing work.

#![forbid(unsafe_code)]

use std::time::{Duration, Instant};

/// Per-iteration wall-clock budget. Exceeding this aborts the rest of
/// the run with `Err(GuardrailError::IterationTooSlow)`.
pub const PER_ITER: Duration = Duration::from_millis(100);
/// Iteration cap — every fuzz body MUST stop at or before this.
pub const MAX_ITER: u32 = 100;
/// Per-iteration input cap. libfuzzer inputs longer than this are
/// truncated; PRNG-driven inputs sample lengths in `0..=MAX_INPUT`.
pub const MAX_INPUT: usize = 64 * 1024;
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
pub fn delta_one_iteration(input: &[u8]) {
    // Truncate per guardrail #2.
    let input = &input[..input.len().min(MAX_INPUT)];
    if input.len() < 2 {
        return;
    }
    // Split: first half = base, second half = stream candidate.
    let split = input.len() / 2;
    let base = &input[..split];
    let stream = &input[split..];
    // Defensive pre-check on the stream header. `delta::decode` already
    // caps the initial `Vec::with_capacity` against stream length, but
    // we also refuse obviously-malicious declared-result-lengths here
    // so the fuzz loop makes progress on more interesting inputs per
    // unit of CPU (`MAX_INPUT * 4` matches the practical ceiling the
    // decoder can reach from a 64 KiB stream).
    if stream.len() < 9 {
        let _ = mkit_core::delta::decode(base, stream);
        return;
    }
    let claimed_result_len = u32::from_le_bytes([stream[5], stream[6], stream[7], stream[8]]);
    if claimed_result_len as usize > MAX_INPUT * 4 {
        return;
    }
    let _ = mkit_core::delta::decode(base, stream);
}

/// Apply `PackReader::read` against `input` — same panic/UB invariant.
/// Uses an in-process tempdir so the store side-effect is isolated and
/// auto-cleaned at scope exit.
pub fn pack_one_iteration(input: &[u8]) {
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
pub fn tree_one_iteration(input: &[u8]) {
    let input = &input[..input.len().min(MAX_INPUT)];
    let _ = mkit_core::serialize::deserialize(input);
}

/// Apply the git-bridge import parsers against `input` — the
/// untrusted-input boundary of `mkit git import` (SPEC-GIT-IMPORT §2).
/// These accept arbitrary upstream bytes, so they must never panic,
/// over-allocate, or hang on adversarial input.
pub fn git_commit_parse_one_iteration(input: &[u8]) {
    let input = &input[..input.len().min(MAX_INPUT)];
    if let Ok(c) = mkit_git_bridge::gitparse::parse_commit(input) {
        // Real invariant: the identity is a slice of the input, so it
        // can never exceed the input length.
        assert!(c.author.identity.len() <= input.len());
    }
}

/// Apply the git tag parser against `input`.
pub fn git_tag_parse_one_iteration(input: &[u8]) {
    let input = &input[..input.len().min(MAX_INPUT)];
    let _ = mkit_git_bridge::gitparse::parse_tag(input);
}

/// Apply the git tree parser + mode classifier against `input`.
pub fn git_tree_parse_one_iteration(input: &[u8]) {
    let input = &input[..input.len().min(MAX_INPUT)];
    if let Ok(entries) = mkit_git_bridge::gitparse::parse_tree(input) {
        for e in entries {
            let _ = mkit_git_bridge::gitparse::map_mode(&e.mode);
        }
    }
}

/// Apply the encrypted software-key record decoder against `input`.
pub fn software_key_record_one_iteration(input: &[u8]) {
    let input = &input[..input.len().min(MAX_INPUT)];
    let _ = mkit_keystore::fuzz_decode_software_key_record(input);
}

/// Fuzz the mkit-rpc wire decoders. Two properties per iteration:
///
/// 1. **Decode never panics.** Both protocol roots (`SignerFrame`,
///    `SshFrame`) are decoded from the raw input, through the
///    production decode caps (`frame_decode_options`) and the bare
///    decoder. Any input may fail to decode; none may panic.
/// 2. **Wire roundtrip.** The input entropy drives
///    `arbitrary::Arbitrary` to build structurally valid frames
///    (mkit-rpc's `arbitrary` feature, from buffa
///    `generate_arbitrary` codegen); encode → decode → re-encode must
///    reproduce the same wire bytes. (Value equality would not hold:
///    an `Arbitrary` open-enum `Unknown(v)` for a known wire value `v`
///    is canonicalized to `Known(_)` on decode, yet both encode to the
///    same bytes.)
pub fn rpc_decode_one_iteration(input: &[u8]) {
    use arbitrary::Arbitrary;
    use buffa::Message;
    use mkit_rpc::mkit::rpc::v1::signer::SignerFrame;
    use mkit_rpc::mkit::rpc::v1::ssh::SshFrame;

    let input = &input[..input.len().min(MAX_INPUT)];

    let _ = mkit_rpc::frame_decode_options().decode_from_slice::<SignerFrame>(input);
    let _ = mkit_rpc::frame_decode_options().decode_from_slice::<SshFrame>(input);
    let _ = SignerFrame::decode_from_slice(input);
    let _ = SshFrame::decode_from_slice(input);

    // Wire-level roundtrip, NOT value-level: `Arbitrary` can build an
    // open-enum field as `EnumValue::Unknown(v)` for a `v` that IS a
    // known wire value, which the decoder canonicalizes back to
    // `Known(_)` — so `frame == decoded` legitimately diverges. The
    // property that must hold is that re-encoding the decoded message
    // reproduces the same bytes (both representations encode `v`
    // identically).
    let mut u = arbitrary::Unstructured::new(input);
    if let Ok(frame) = SignerFrame::arbitrary(&mut u) {
        let bytes = frame.encode_to_vec();
        let decoded = SignerFrame::decode_from_slice(&bytes).expect("re-decode SignerFrame");
        assert_eq!(bytes, decoded.encode_to_vec(), "SignerFrame wire roundtrip diverged");
    }
    if let Ok(frame) = SshFrame::arbitrary(&mut u) {
        let bytes = frame.encode_to_vec();
        let decoded = SshFrame::decode_from_slice(&bytes).expect("re-decode SshFrame");
        assert_eq!(bytes, decoded.encode_to_vec(), "SshFrame wire roundtrip diverged");
    }
}

/// Single-shot: invoke `body(input)` exactly once, with the
/// per-iteration wall-clock cap. libfuzzer harnesses call this from
/// their `fuzz_target!` body; the iteration counter lives one level up,
/// in `run_iterated_unit`.
pub fn run_one(input: &[u8], body: fn(&[u8])) -> Result<(), GuardrailError> {
    let start = Instant::now();
    body(input);
    if start.elapsed() > PER_ITER {
        return Err(GuardrailError::IterationTooSlow);
    }
    Ok(())
}

/// PRNG-driven runner used by the unit-test shim. Deterministically
/// generates `MAX_ITER` inputs from `RNG_SEED` and runs `body` against
/// each, enforcing the per-iteration time cap. Any cap miss aborts.
pub fn run_iterated_unit(body: fn(&[u8])) -> Result<(), GuardrailError> {
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

    #[test]
    fn unit_git_commit_parse() {
        run_iterated_unit(git_commit_parse_one_iteration).unwrap();
        // Fixed structured cases: valid, truncated, continuation-heavy.
        for case in [
            &b"tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\nauthor A <a@x> 5 +0000\ncommitter A <a@x> 5 +0000\n\nm"[..],
            b"tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\nauthor",
            b"gpgsig x\n a\n b\n c\n\nm",
        ] {
            run_one(case, git_commit_parse_one_iteration).unwrap();
        }
    }

    #[test]
    fn unit_git_tag_parse() {
        run_iterated_unit(git_tag_parse_one_iteration).unwrap();
        for case in [
            &b"object ce013625030ba8dba906f756967f9e9ca394464a\ntype commit\ntag v1\n\nm"[..],
            b"object zz\ntype commit\ntag v1\n\nm",
            b"\n\n",
        ] {
            run_one(case, git_tag_parse_one_iteration).unwrap();
        }
    }

    #[test]
    fn unit_git_tree_parse() {
        run_iterated_unit(git_tree_parse_one_iteration).unwrap();
        let mut entry = b"100644 a\x00".to_vec();
        entry.extend_from_slice(&[9u8; 20]);
        for case in [&entry[..], b"160000 sub\x00short", b"77 x"] {
            run_one(case, git_tree_parse_one_iteration).unwrap();
        }
    }

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

    #[test]
    fn software_key_record_target_runs_within_caps() {
        run_iterated_unit(software_key_record_one_iteration).expect("guardrails held");
    }

    #[test]
    fn rpc_decode_target_runs_within_caps() {
        run_iterated_unit(rpc_decode_one_iteration).expect("guardrails held");
    }

    /// Pin a few hand-crafted inputs so the targets keep accepting them
    /// even under refactors of the parser surface.
    #[test]
    fn delta_target_handles_known_corruption() {
        // Empty.
        delta_one_iteration(&[]);
        // Header-only, no ops.
        let mut h = vec![0x01u8];
        h.extend_from_slice(&0u32.to_le_bytes());
        h.extend_from_slice(&0u32.to_le_bytes());
        delta_one_iteration(&h);
        // Reserved opcode.
        let mut bad = h.clone();
        bad.push(0x00);
        delta_one_iteration(&bad);
    }

    #[test]
    fn pack_target_handles_known_corruption() {
        // Wrong magic.
        pack_one_iteration(b"XXXX\x01\x00\x00\x00\x00\x00\x00\x00");
        // Empty.
        pack_one_iteration(&[]);
        // Bogus count below the defensive cap.
        pack_one_iteration(b"MKIT\x01\x00\x00\x00\xFF\xFF\x00\x00");
    }

    #[test]
    fn tree_target_handles_known_corruption() {
        tree_one_iteration(&[]);
        // Tree prologue + count = u32::MAX → must reject TooManyEntries.
        let mut bad = vec![0x02u8, b'M', b'K', b'T', b'1', 0x01];
        bad.extend_from_slice(&u32::MAX.to_le_bytes());
        tree_one_iteration(&bad);
    }

    #[test]
    fn software_key_record_target_handles_fixed_cases() {
        let valid = hex_to_bytes(
            "4d4b49544b53563101010104000000746573742000000024242424242424242424242424242424242424242424242424242424242424240e000000656432353531393a737461626c651800000022222222222222222222222222222222222222222222222220000000f9fffde0ffe7e285b5bcb4b4b4c7dbd2c0c3d5c6d1b3b4b4b4d0d1d2d5c1d8c030000000c125a54e1efba6d6a70f5689ff3be3a070d5819657dcb8a6220934a533a21b67791eb2cb0db7cbdd4815ce51b3ea5ae0",
        );
        software_key_record_one_iteration(&valid);
        software_key_record_one_iteration(&[]);
        software_key_record_one_iteration(b"MKITKSV1\x01\x01\x01");
        let mut bad = b"MKITKSV1".to_vec();
        bad.extend_from_slice(&[1, 1, 1]);
        bad.extend_from_slice(&u32::MAX.to_le_bytes());
        software_key_record_one_iteration(&bad);
    }

    #[test]
    fn rpc_decode_target_handles_fixed_cases() {
        use buffa::Message;
        use mkit_rpc::mkit::rpc::v1::signer::{SignerFrame, signer_frame};

        // Empty and truncated inputs.
        rpc_decode_one_iteration(&[]);
        rpc_decode_one_iteration(&[0x0A]);
        // A valid encoded frame must decode (and roundtrip) cleanly.
        let frame = mkit_rpc::signer_error_frame(
            mkit_rpc::mkit::rpc::v1::ErrorCode::Internal,
            "fuzz fixed case",
        );
        rpc_decode_one_iteration(&frame.encode_to_vec());
        // Field-1 tag with an absurd length prefix — classic truncation.
        rpc_decode_one_iteration(&[0x0A, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F]);
        // Suppress unused-import warning for the oneof module while
        // keeping the import for future fixed cases.
        let _: Option<signer_frame::Body> = SignerFrame::default().body;
    }

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        assert_eq!(hex.len() % 2, 0);
        (0..hex.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).expect("hex byte"))
            .collect()
    }
}
