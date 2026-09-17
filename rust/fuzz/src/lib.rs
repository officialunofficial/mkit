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
//! 6. Seeded deterministic PRNG — `RNG_SEED` is a constant. Most targets
//!    use splitmix64 (`run_iterated_unit`); the `rpc_decode` pilot drives
//!    the body through commonware-invariants `minifuzz`, whose ChaCha8
//!    sampler is seeded with the same `RNG_SEED` via `with_seed`, so it is
//!    likewise deterministic and reproducible (see its `#[test]`).
//!
//! Inputs from libfuzzer come in as raw `&[u8]`; the unit-test path
//! synthesises inputs from the seeded PRNG (splitmix64, or minifuzz's
//! ChaCha8 sampler for `rpc_decode`). Either way each body slices to
//! <= 64 KiB before doing work.

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

/// Shared pre-check for [`pack_one_iteration`] / [`pack_one_iteration_with_store`]:
/// truncate per guardrail #2 and refuse to feed packs whose declared
/// `entry_count` would force a giant `Vec::with_capacity` (the reader
/// already enforces `MAX_ENTRIES`, but the cap here prevents the test
/// from even trying). Returns `None` when the iteration should be
/// skipped.
fn pack_validated_input(input: &[u8]) -> Option<&[u8]> {
    let input = &input[..input.len().min(MAX_INPUT)];
    if input.len() < 12 {
        return None;
    }
    let claimed_entries = u32::from_le_bytes([input[8], input[9], input[10], input[11]]);
    if claimed_entries > 100_000 {
        return None;
    }
    Some(input)
}

/// Apply `PackReader::read` against `input` — same panic/UB invariant.
/// Uses an in-process tempdir so the store side-effect is isolated and
/// auto-cleaned at scope exit. Real libfuzzer / `fuzz_target!` runs call
/// this directly, where per-call isolation matters; the unit-test loop
/// uses [`pack_one_iteration_with_store`] instead to reuse one store
/// across all `MAX_ITER` iterations (#505 PR 5/5).
pub fn pack_one_iteration(input: &[u8]) {
    let Some(input) = pack_validated_input(input) else {
        return;
    };
    let dir = match tempfile::TempDir::new() {
        Ok(d) => d,
        Err(_) => return,
    };
    let layout = mkit_core::layout::RepoLayout::single(dir.path());
    let store = match mkit_core::store::ObjectStore::init(&layout) {
        Ok(s) => s,
        Err(_) => return,
    };
    let _ = mkit_core::pack::PackReader::read(input, &store);
}

/// As [`pack_one_iteration`], but against a caller-provided store
/// instead of a fresh tempdir. Lets the unit-test loop amortize the
/// tempdir + `ObjectStore::init` cost across all `MAX_ITER` iterations
/// instead of paying for 100 real filesystem inits per `cargo test`
/// invocation (#505 PR 5/5).
pub fn pack_one_iteration_with_store(input: &[u8], store: &mkit_core::store::ObjectStore) {
    let Some(input) = pack_validated_input(input) else {
        return;
    };
    let _ = mkit_core::pack::PackReader::read(input, store);
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
        assert_eq!(
            bytes,
            decoded.encode_to_vec(),
            "SignerFrame wire roundtrip diverged"
        );
    }
    if let Ok(frame) = SshFrame::arbitrary(&mut u) {
        let bytes = frame.encode_to_vec();
        let decoded = SshFrame::decode_from_slice(&bytes).expect("re-decode SshFrame");
        assert_eq!(
            bytes,
            decoded.encode_to_vec(),
            "SshFrame wire roundtrip diverged"
        );
    }
}

/// Decode a packlist node from untrusted bytes — the
/// `Transport::download_blob` boundary of the delta-push discovery chain
/// (transfer.rs, now backed by `commonware-codec`). It accepts arbitrary
/// remote bytes, so it must never panic, over-allocate, or hang. When a
/// blob decodes, re-encoding it MUST reproduce a blob that decodes to the
/// same node (encode∘decode stability over the codec body).
pub fn merkle_packlist_one_iteration(input: &[u8]) {
    let input = &input[..input.len().min(MAX_INPUT)];
    if let Ok(node) = mkit_core::transfer::decode_packlist(input)
        && let Ok(re) = mkit_core::transfer::encode_packlist(node.prev, &node.packs)
    {
        assert_eq!(
            mkit_core::transfer::decode_packlist(&re),
            Ok(node),
            "packlist re-encode must round-trip"
        );
    }
}

/// Exercise merkle object identity and inclusion-proof verification on
/// arbitrary input. Building an id must never panic and always yields 32
/// bytes; a freshly built proof must verify; and `verify_*` over
/// adversarial proof bytes must reject cleanly (never panic).
pub fn merkle_proof_one_iteration(input: &[u8]) {
    use mkit_core::merkle;
    use mkit_core::object::{ChunkedBlob, EntryMode, Tree, TreeEntry};
    let input = &input[..input.len().min(MAX_INPUT)];

    // Build a ChunkedBlob from up to 64 chunk ids carved from `input`.
    let chunks: Vec<[u8; 32]> = input
        .chunks(32)
        .take(64)
        .map(|c| {
            let mut h = [0u8; 32];
            h[..c.len()].copy_from_slice(c);
            h
        })
        .collect();
    let cb = ChunkedBlob {
        total_size: input.len() as u64,
        chunk_size: 0,
        chunks: chunks.clone(),
    };
    let cid = merkle::compute_chunked_id(&cb);
    assert_eq!(cid.len(), 32);
    if !chunks.is_empty() {
        // position 0 is the meta leaf; chunk i is at position i+1.
        let pos = (input.first().copied().unwrap_or(0) as usize % chunks.len()) as u32 + 1;
        if let Ok(proof) = merkle::build_chunk_proof(&cb, pos) {
            merkle::verify_chunk(&cid, &chunks[(pos - 1) as usize], pos, &proof)
                .expect("freshly built chunk proof must verify");
        }
        // Adversarial proof bytes / position must reject without panicking.
        // `input` is arbitrary fuzzer bytes, not necessarily a valid encoded
        // `Proof`; decode it first (bounded) and only pass a successfully
        // decoded proof to `verify_chunk` — a decode failure is itself a
        // clean rejection.
        if let Ok(proof) = merkle::Proof::decode(input, 1) {
            let _ = merkle::verify_chunk(&cid, &chunks[0], 0, &proof);
        }
    }

    // A Tree from the same bytes (one entry, name derived from input).
    let tree = Tree {
        entries: vec![TreeEntry {
            name: if input.is_empty() {
                b"x".to_vec()
            } else {
                vec![input[0].max(1)]
            },
            mode: EntryMode::Blob,
            object_hash: chunks.first().copied().unwrap_or([0u8; 32]),
        }],
    };
    let tid = merkle::compute_tree_id(&tree);
    assert_eq!(tid.len(), 32);
    if let Ok(p) = merkle::build_tree_entry_proof(&tree, 0) {
        merkle::verify_tree_entry(&tid, &tree.entries[0], 0, &p)
            .expect("freshly built tree proof must verify");
    }
    // Adversarial proof bytes must reject without panicking (see the
    // chunk-proof comment above for why we decode first).
    if let Ok(p) = merkle::Proof::decode(input, 1) {
        let _ = merkle::verify_tree_entry(&tid, &tree.entries[0], 0, &p);
    }
}

/// Decode a partial-disclosure bundle (issue #1015 verifier kit PR 2,
/// SPEC-DISCLOSURE) from arbitrary input against a fixed dummy commit id.
/// `verify::verify_disclosure` decodes the bundle before ever comparing
/// against the caller's id, so this exercises the decoder's bounds
/// (oversize bundle, bad magic/version, over-cap `Vec`/`Proof` lengths,
/// trailing bytes) on adversarial bytes: it must never panic, and must
/// never allocate based on an unvalidated length.
pub fn disclosure_decode_one_iteration(input: &[u8]) {
    let input = &input[..input.len().min(MAX_INPUT)];
    let commit_id = [0u8; 32];
    let _ = mkit_core::verify::verify_disclosure(&commit_id, input);
}

/// A small native `ObjectStore`-backed fixture for
/// [`verify_disclosure_one_iteration`]: one committed file, disclosed as
/// a real `Selector::Object` bundle. Built once by
/// [`build_disclosure_fixture`] and reused across all iterations of the
/// unit-test loop via [`run_iterated_unit_with`]; real libfuzzer runs
/// build a fresh one per call for isolation (mirrors
/// [`pack_one_iteration`] vs [`pack_one_iteration_with_store`]).
pub struct DisclosureFixture {
    _dir: tempfile::TempDir,
    commit_id: [u8; 32],
    good_bundle: Vec<u8>,
}

/// Build a [`DisclosureFixture`]. Never fails in practice (every step is
/// a fixed, valid construction over fixed bytes); panics only on a
/// genuine environment failure (no writable temp dir), same posture as
/// [`pack_one_iteration_with_store`]'s `ObjectStore::init`.
pub fn build_disclosure_fixture() -> DisclosureFixture {
    use mkit_core::hash::ZERO;
    use mkit_core::layout::RepoLayout;
    use mkit_core::object::{Commit, EntryMode, Identity, Object, Tree, TreeEntry};
    use mkit_core::sign::{KeyPair, sign_commit};
    use mkit_core::store::ObjectStore;
    use mkit_core::verify::{self, Selector};
    use mkit_core::worktree::store_file_object;

    let dir = tempfile::TempDir::new().expect("tempdir");
    let store = ObjectStore::init(&RepoLayout::single(dir.path())).expect("store init");
    let blob_id =
        store_file_object(&store, b"disclosure fuzz fixture content").expect("store file");
    let tree = Tree {
        entries: vec![TreeEntry {
            name: b"f.txt".to_vec(),
            mode: EntryMode::Blob,
            object_hash: blob_id,
        }],
    };
    let tree_hash = store
        .write(&mkit_core::serialize::serialize(&Object::Tree(tree)).expect("serialize tree"))
        .expect("write tree");
    let kp = KeyPair::from_seed([0x42; 32]);
    let mut commit = Commit {
        tree_hash,
        parents: vec![],
        author: Identity::ed25519(kp.public.0),
        signer: kp.public.0,
        message: b"disclosure fuzz fixture".to_vec(),
        timestamp: 1,
        message_hash: ZERO,
        content_digest: ZERO,
        signature: [0u8; 64],
    };
    commit.signature = sign_commit(&commit, &kp).expect("sign commit").0;
    let commit_bytes =
        mkit_core::serialize::serialize(&Object::Commit(commit)).expect("serialize commit");
    let commit_id = store.write(&commit_bytes).expect("write commit");
    let good_bundle = verify::build_disclosure(&store, &commit_id, &[b"f.txt"], Selector::Object)
        .expect("build disclosure");
    DisclosureFixture {
        _dir: dir,
        commit_id,
        good_bundle,
    }
}

/// Exercise `verify::verify_disclosure` against a real fixture. Three
/// properties per iteration: (1) the freshly built bundle MUST verify;
/// (2) an input-driven single-byte mutation of that bundle MUST reject
/// cleanly (never panic) — mutating one byte of a genuine bundle can
/// never happen to re-verify unless the mutation lands in a truly
/// don't-care byte, which `verify_disclosure`'s exhaustive checks (id,
/// hash, every proof, every Bao slice) leave essentially none of; (3)
/// raw fuzzer bytes verified directly against the fixture's real commit
/// id must never panic.
pub fn verify_disclosure_one_iteration(input: &[u8]) {
    let fixture = build_disclosure_fixture();
    verify_disclosure_one_iteration_with(input, &fixture);
}

/// As [`verify_disclosure_one_iteration`], but against a caller-provided
/// [`DisclosureFixture`] instead of building a fresh one — lets the
/// unit-test loop amortize the tempdir/store/signing cost across all
/// `MAX_ITER` iterations.
pub fn verify_disclosure_one_iteration_with(input: &[u8], fixture: &DisclosureFixture) {
    use mkit_core::verify;

    let input = &input[..input.len().min(MAX_INPUT)];

    let disclosed = verify::verify_disclosure(&fixture.commit_id, &fixture.good_bundle)
        .expect("freshly built disclosure must verify");
    // Builder fills `inner_root` from the parent tree; verify wrap-checks
    // it then requires the proof fold to equal the declared field. Re-check
    // the wrap of every authenticated root here so a builder/verifier
    // disagreement cannot slip through a successful round-trip.
    use mkit_core::merkle::{self, ObjectKind};
    if let Some(root) = disclosed.step_inner_roots.first() {
        assert_eq!(
            merkle::wrap_id(ObjectKind::Tree, root),
            disclosed.tree_hash,
            "step 0 inner_root must wrap to tree_hash"
        );
    }
    if let Some(root) = disclosed.chunk_inner_root {
        assert_eq!(
            merkle::wrap_id(ObjectKind::ChunkedBlob, &root),
            disclosed.leaf_id,
            "chunk inner_root must wrap to the leaf ChunkedBlob id"
        );
    }

    if !fixture.good_bundle.is_empty() && input.len() >= 2 {
        let mut mutated = fixture.good_bundle.clone();
        let pos = usize::from(input[0]) % mutated.len();
        let flip = input[1].max(1); // guaranteed non-zero XOR
        mutated[pos] ^= flip;
        let _ = verify::verify_disclosure(&fixture.commit_id, &mutated);
    }

    let _ = verify::verify_disclosure(&fixture.commit_id, input);
}

/// Valid `MKWB` fixture reused by the bounded partial-workspace target.
pub struct PartialWorkspaceFixture {
    _dir: tempfile::TempDir,
    base: [u8; 32],
    paths: Vec<mkit_core::PartialPath>,
    bundle: Vec<u8>,
}

pub fn build_partial_workspace_fixture() -> PartialWorkspaceFixture {
    use mkit_core::hash::ZERO;
    use mkit_core::layout::RepoLayout;
    use mkit_core::object::{Commit, EntryMode, Identity, Object, Tree, TreeEntry};
    use mkit_core::sign::{KeyPair, sign_commit};
    use mkit_core::store::ObjectStore;
    use mkit_core::worktree::store_file_object;

    let dir = tempfile::TempDir::new().expect("tempdir");
    let store = ObjectStore::init(&RepoLayout::single(dir.path())).expect("store init");
    let blob = store_file_object(&store, b"partial workspace fuzz fixture").expect("file");
    let tree = Tree {
        entries: vec![TreeEntry {
            name: b"f.txt".to_vec(),
            mode: EntryMode::Blob,
            object_hash: blob,
        }],
    };
    let tree = store
        .write(&mkit_core::serialize(&Object::Tree(tree)).expect("tree bytes"))
        .expect("tree");
    let key = KeyPair::from_seed([0x24; 32]);
    let mut commit = Commit {
        tree_hash: tree,
        parents: Vec::new(),
        author: Identity::ed25519(key.public.0),
        signer: key.public.0,
        message: b"partial workspace fuzz fixture".to_vec(),
        timestamp: 1,
        message_hash: ZERO,
        content_digest: ZERO,
        signature: [0; 64],
    };
    commit.signature = sign_commit(&commit, &key).expect("sign").0;
    let base = store
        .write(&mkit_core::serialize(&Object::Commit(commit)).expect("commit bytes"))
        .expect("commit");
    let paths = vec![vec![b"f.txt".to_vec()]];
    let bundle = mkit_core::build_partial_snapshot(
        &store,
        base,
        &paths,
        &mkit_core::PartialLimits::default(),
    )
    .expect("partial bundle")
    .encode(&mkit_core::PartialLimits::default())
    .expect("encode partial bundle");
    PartialWorkspaceFixture {
        _dir: dir,
        base,
        paths,
        bundle,
    }
}

/// Verify a valid bundle, a deliberately invalid full-range mutation, and
/// arbitrary untrusted bytes. All decode allocations are bounded by
/// `PartialLimits`.
pub fn partial_workspace_one_iteration(input: &[u8]) {
    let fixture = build_partial_workspace_fixture();
    partial_workspace_one_iteration_with(input, &fixture);
}

pub fn partial_workspace_one_iteration_with(input: &[u8], fixture: &PartialWorkspaceFixture) {
    let input = &input[..input.len().min(MAX_INPUT)];
    let limits = mkit_core::PartialLimits::default();
    mkit_core::verify_partial_snapshot(fixture.base, &fixture.paths, &fixture.bundle, &limits)
        .expect("fresh partial fixture verifies");
    if input.len() >= 9 {
        let mut mutated = fixture.bundle.clone();
        let selector = u64::from_le_bytes(input[..8].try_into().expect("eight-byte selector"));
        let position = (selector % mutated.len() as u64) as usize;
        mutated[position] ^= input[8].max(1);
        // The trailing byte makes rejection unconditional even if a mutation
        // happens to transform one valid field encoding into another.
        mutated.push(0);
        assert!(
            mkit_core::verify_partial_snapshot(fixture.base, &fixture.paths, &mutated, &limits)
                .is_err()
        );
    }
    let _ = mkit_core::verify_partial_snapshot(fixture.base, &fixture.paths, input, &limits);
}

/// Verified selected-file fixture reused by the bounded replacement-overlay target.
pub struct PartialOverlayFixture {
    verified: mkit_core::VerifiedPartialSnapshot,
    original_root: [u8; 32],
    untouched: mkit_core::TreeEntry,
}

pub fn build_partial_overlay_fixture() -> PartialOverlayFixture {
    use mkit_core::hash::ZERO;
    use mkit_core::layout::RepoLayout;
    use mkit_core::object::{Commit, EntryMode, Identity, Object, Tree, TreeEntry};
    use mkit_core::sign::{KeyPair, sign_commit};
    use mkit_core::store::ObjectStore;
    use mkit_core::worktree::store_file_object;

    let dir = tempfile::TempDir::new().expect("tempdir");
    let store = ObjectStore::init(&RepoLayout::single(dir.path())).expect("store init");
    let first = store_file_object(&store, b"first").expect("first file");
    let second = store_file_object(&store, b"second").expect("second file");
    let hidden = store_file_object(&store, b"unselected").expect("hidden file");
    let untouched = TreeEntry {
        name: b"hidden.txt".to_vec(),
        mode: EntryMode::Blob,
        object_hash: hidden,
    };
    let tree = Tree {
        entries: vec![
            TreeEntry {
                name: b"f.txt".to_vec(),
                mode: EntryMode::Blob,
                object_hash: first,
            },
            TreeEntry {
                name: b"g.txt".to_vec(),
                mode: EntryMode::Executable,
                object_hash: second,
            },
            untouched.clone(),
        ],
    };
    let original_root = store
        .write(&mkit_core::serialize(&Object::Tree(tree)).expect("tree bytes"))
        .expect("tree");
    let key = KeyPair::from_seed([0x42; 32]);
    let mut commit = Commit {
        tree_hash: original_root,
        parents: Vec::new(),
        author: Identity::ed25519(key.public.0),
        signer: key.public.0,
        message: b"partial overlay fuzz fixture".to_vec(),
        timestamp: 1,
        message_hash: ZERO,
        content_digest: ZERO,
        signature: [0; 64],
    };
    commit.signature = sign_commit(&commit, &key).expect("sign").0;
    let base = store
        .write(&mkit_core::serialize(&Object::Commit(commit)).expect("commit bytes"))
        .expect("commit");
    let paths = vec![vec![b"f.txt".to_vec()], vec![b"g.txt".to_vec()]];
    let limits = mkit_core::PartialLimits::default();
    let bundle = mkit_core::build_partial_snapshot(&store, base, &paths, &limits)
        .expect("partial bundle")
        .encode(&limits)
        .expect("encode partial bundle");
    let verified = mkit_core::verify_partial_snapshot(base, &paths, &bundle, &limits)
        .expect("verify partial bundle");
    PartialOverlayFixture {
        verified,
        original_root,
        untouched,
    }
}

/// Exercise bounded structured replacement batches against the public overlay API.
/// A generated batch may be valid or invalid. Successful batches must be
/// deterministic, preserve the unselected entry triple and file modes, and emit
/// canonical produced objects under their type-dependent ids.
pub fn partial_overlay_one_iteration(input: &[u8]) {
    let fixture = build_partial_overlay_fixture();
    partial_overlay_one_iteration_with(input, &fixture);
}

pub fn partial_overlay_one_iteration_with(input: &[u8], fixture: &PartialOverlayFixture) {
    let limits = mkit_core::PartialLimits {
        max_selected_file_bytes: 4 * 1024,
        max_total_selected_bytes: 8 * 1024,
        max_changed_paths: 4,
        ..mkit_core::PartialLimits::default()
    };
    let _ = partial_overlay_one_iteration_with_limits(input, fixture, &limits);
}

fn partial_overlay_one_iteration_with_limits(
    input: &[u8],
    fixture: &PartialOverlayFixture,
    limits: &mkit_core::PartialLimits,
) -> Result<(), mkit_core::PartialError> {
    use mkit_core::object::{EntryMode, Object, id_from_object};
    use mkit_core::replace_files;

    let input = &input[..input.len().min(MAX_INPUT)];
    let replacements = overlay_replacements(input);
    let prepared = replace_files(&fixture.verified, &replacements, limits)?;
    let replay = replace_files(&fixture.verified, &replacements, limits)
        .expect("a successful overlay must replay successfully");
    assert_eq!(prepared.root_id(), replay.root_id());
    assert_eq!(
        prepared.produced_objects().collect::<Vec<_>>(),
        replay.produced_objects().collect::<Vec<_>>(),
        "overlay output must be deterministic"
    );

    let changed = prepared.changed_paths().collect::<Vec<_>>();
    assert!(!changed.is_empty());
    assert!(changed.windows(2).all(|pair| pair[0] < pair[1]));
    assert!(changed.iter().all(|path| {
        path.as_slice() == [b"f.txt".to_vec()] || path.as_slice() == [b"g.txt".to_vec()]
    }));

    let mut rebuilt_root = None;
    for (id, bytes) in prepared.produced_objects() {
        let object = mkit_core::deserialize(bytes).expect("produced object must decode");
        assert_eq!(*id, id_from_object(&object, bytes));
        assert_eq!(
            bytes,
            mkit_core::serialize(&object).expect("canonical object")
        );
        if id == prepared.root_id() {
            rebuilt_root = Some(object);
        }
    }
    let Some(Object::Tree(root)) = rebuilt_root else {
        panic!("successful overlay must emit its rebuilt root Tree");
    };
    assert_ne!(*prepared.root_id(), fixture.original_root);
    assert!(root.entries.contains(&fixture.untouched));
    for entry in &root.entries {
        if entry.name == b"f.txt" {
            assert_eq!(entry.mode, EntryMode::Blob);
        } else if entry.name == b"g.txt" {
            assert_eq!(entry.mode, EntryMode::Executable);
        }
    }
    Ok(())
}

fn overlay_replacements(input: &[u8]) -> Vec<mkit_core::FileReplacement> {
    use mkit_core::FileReplacement;

    let Some((&count, mut rest)) = input.split_first() else {
        return Vec::new();
    };
    let mut replacements = Vec::with_capacity(usize::from(count % 5));
    for _ in 0..count % 5 {
        if rest.len() < 2 {
            break;
        }
        let destination = overlay_path(rest[0]);
        let kind = rest[1];
        rest = &rest[2..];
        if kind & 1 == 0 {
            if rest.len() < 2 {
                break;
            }
            let declared = usize::from(u16::from_le_bytes([rest[0], rest[1]])) % 4097;
            rest = &rest[2..];
            let take = declared.min(rest.len());
            replacements.push(FileReplacement::bytes(destination, rest[..take].to_vec()));
            rest = &rest[take..];
        } else {
            let Some((&source, tail)) = rest.split_first() else {
                break;
            };
            replacements.push(FileReplacement::reuse_selected(
                destination,
                overlay_path(source),
            ));
            rest = tail;
        }
    }
    replacements
}

fn overlay_path(selector: u8) -> mkit_core::PartialPath {
    match selector % 4 {
        0 => vec![b"f.txt".to_vec()],
        1 => vec![b"g.txt".to_vec()],
        2 => vec![b"hidden.txt".to_vec()],
        _ => vec![b"missing.txt".to_vec()],
    }
}

/// Store-less pack iterator: never panics on adversarial bytes. When
/// `PackReader::read` accepts a pack, `PackEntries::new` accepts it too
/// and yields `raw_count + delta_count` items.
pub fn pack_entries_one_iteration(input: &[u8]) {
    let Some(input) = pack_validated_input(input) else {
        return;
    };
    let parsed = mkit_core::pack::PackEntries::new(input);
    if let Ok(entries) = parsed {
        let mut n = 0usize;
        for item in entries {
            match item {
                Ok(_) => n += 1,
                Err(_) => break,
            }
        }
        let _ = n;
    }

    let dir = match tempfile::TempDir::new() {
        Ok(d) => d,
        Err(_) => return,
    };
    let layout = mkit_core::layout::RepoLayout::single(dir.path());
    let store = match mkit_core::store::ObjectStore::init(&layout) {
        Ok(s) => s,
        Err(_) => return,
    };
    if let Ok(report) = mkit_core::pack::PackReader::read(input, &store) {
        let entries = mkit_core::pack::PackEntries::new(input)
            .expect("PackReader-accepted pack must parse as PackEntries");
        let got = entries.filter(|e| e.is_ok()).count();
        assert_eq!(
            got,
            (report.raw_count + report.delta_count) as usize,
            "PackEntries must yield one item per PackReader-stored entry"
        );
    }
}

/// A tiny native fixture for [`verify_closure_one_iteration`]: one
/// committed file, exported as a snapshot closure.
pub struct ClosureFixture {
    _dir: tempfile::TempDir,
    store: mkit_core::store::ObjectStore,
    root: [u8; 32],
    manifest: Vec<u8>,
    packs: Vec<Vec<u8>>,
}

/// Build a [`ClosureFixture`]. Panics only on a genuine environment
/// failure (no writable temp dir).
pub fn build_closure_fixture() -> ClosureFixture {
    use mkit_core::ClosureMode;
    use mkit_core::hash::ZERO;
    use mkit_core::layout::RepoLayout;
    use mkit_core::object::{Commit, EntryMode, Identity, Object, Tree, TreeEntry};
    use mkit_core::sign::{KeyPair, sign_commit};
    use mkit_core::store::ObjectStore;
    use mkit_core::verify::export_closure;
    use mkit_core::worktree::store_file_object;

    let dir = tempfile::TempDir::new().expect("tempdir");
    let store = ObjectStore::init(&RepoLayout::single(dir.path())).expect("store init");
    let blob_id = store_file_object(&store, b"closure fuzz fixture").expect("store file");
    let tree = Tree {
        entries: vec![TreeEntry {
            name: b"f.txt".to_vec(),
            mode: EntryMode::Blob,
            object_hash: blob_id,
        }],
    };
    let tree_hash = store
        .write(&mkit_core::serialize::serialize(&Object::Tree(tree)).expect("serialize tree"))
        .expect("write tree");
    let kp = KeyPair::from_seed([0x43; 32]);
    let mut commit = Commit {
        tree_hash,
        parents: vec![],
        author: Identity::ed25519(kp.public.0),
        signer: kp.public.0,
        message: b"closure fuzz fixture".to_vec(),
        timestamp: 1,
        message_hash: ZERO,
        content_digest: ZERO,
        signature: [0u8; 64],
    };
    commit.signature = sign_commit(&commit, &kp).expect("sign commit").0;
    let commit_bytes =
        mkit_core::serialize::serialize(&Object::Commit(commit)).expect("serialize commit");
    let root = store.write(&commit_bytes).expect("write commit");
    let export = export_closure(&store, &root, ClosureMode::Snapshot).expect("export closure");
    ClosureFixture {
        _dir: dir,
        store,
        root,
        manifest: export.manifest,
        packs: export.packs,
    }
}

/// Never panics. A freshly exported closure MUST verify; a mutated
/// manifest or pack MUST reject cleanly; raw input as a pack MUST not
/// panic.
pub fn verify_closure_one_iteration(input: &[u8]) {
    let fixture = build_closure_fixture();
    verify_closure_one_iteration_with(input, &fixture);
}

/// As [`verify_closure_one_iteration`], amortizing fixture construction.
pub fn verify_closure_one_iteration_with(input: &[u8], fixture: &ClosureFixture) {
    use mkit_core::verify;

    let input = &input[..input.len().min(MAX_INPUT)];
    let pack_refs: Vec<&[u8]> = fixture.packs.iter().map(Vec::as_slice).collect();
    verify::verify_closure_manifest(&fixture.root, &fixture.manifest, &pack_refs)
        .expect("freshly exported closure must verify")
        .is_complete()
        .then_some(())
        .expect("freshly exported closure must be complete");

    let mut objects = Vec::new();
    for pack in &fixture.packs {
        for entry in
            mkit_core::pack::PackEntries::new(pack).expect("freshly exported closure must parse")
        {
            let mkit_core::pack::PackEntry::Raw { bytes } =
                entry.expect("freshly exported closure entries must parse")
            else {
                panic!("freshly exported closure must be raw-only");
            };
            objects.push(bytes.into_owned());
        }
    }
    let map_report = verify::verify_closure(
        &fixture.root,
        mkit_core::ClosureMode::Snapshot,
        objects.iter().map(Vec::as_slice),
    )
    .expect("freshly exported closure map path must verify");
    let store_report = verify::verify_closure_store(
        &fixture.store,
        &fixture.root,
        mkit_core::ClosureMode::Snapshot,
    )
    .expect("freshly exported closure store path must verify");
    assert_eq!(map_report.missing, store_report.missing);
    assert_eq!(map_report.verified, store_report.verified);
    assert_eq!(map_report.is_complete(), store_report.is_complete());

    if !fixture.manifest.is_empty() && input.len() >= 2 {
        let mut mutated = fixture.manifest.clone();
        let pos = usize::from(input[0]) % mutated.len();
        mutated[pos] ^= input[1].max(1);
        let _ = verify::verify_closure_manifest(&fixture.root, &mutated, &pack_refs);
    }
    let _ = verify::verify_closure(&fixture.root, mkit_core::ClosureMode::Snapshot, [input]);
    let _ = mkit_core::pack::PackEntries::new(input);

    // Feed raw fuzzer input directly as closure pack buffers (not wrapped
    // in valid PackEntries framing), both whole and split into two, so the
    // profile/framing checks in verify_closure_packs and
    // verify_closure_manifest see adversarial bytes a legitimate exporter
    // could never produce. Any `Ok` report must still be internally
    // consistent.
    let single_pack: [&[u8]; 1] = [input];
    if let Ok(report) = verify::verify_closure_packs(
        &fixture.root,
        mkit_core::ClosureMode::Snapshot,
        &single_pack,
    ) {
        assert_closure_report_consistent(&report);
    }
    if let Ok(report) =
        verify::verify_closure_manifest(&fixture.root, &fixture.manifest, &single_pack)
    {
        assert_closure_report_consistent(&report);
    }

    let mid = input.len() / 2;
    let split_pack: [&[u8]; 2] = [&input[..mid], &input[mid..]];
    if let Ok(report) =
        verify::verify_closure_packs(&fixture.root, mkit_core::ClosureMode::Snapshot, &split_pack)
    {
        assert_closure_report_consistent(&report);
    }
    if let Ok(report) =
        verify::verify_closure_manifest(&fixture.root, &fixture.manifest, &split_pack)
    {
        assert_closure_report_consistent(&report);
    }
}

/// `is_complete()` must imply no `missing`/`corrupt` entries, for any
/// report produced from adversarial pack bytes.
fn assert_closure_report_consistent(report: &mkit_core::verify::ClosureReport) {
    if report.is_complete() {
        assert!(
            report.missing.is_empty(),
            "complete report has missing entries"
        );
        assert!(
            report.corrupt.is_empty(),
            "complete report has corrupt entries"
        );
    }
}

/// Exercise the sparse-checkout build/verify pair on arbitrary input.
/// `build_sparse` must never panic; a freshly built delivery must
/// verify; and `verify_sparse` over adversarial proof/manifest bytes
/// (garbage bitmap, wrong-length bitmap, mismatched filter) must
/// reject cleanly — never panic. `mkit-core`'s `sparse-checkout`
/// feature is enabled unconditionally on this crate's dependency (see
/// `Cargo.toml`), so this needs no feature gate of its own.
pub fn sparse_verify_one_iteration(input: &[u8]) {
    use mkit_core::object::{EntryMode, Tree, TreeEntry};
    use mkit_core::sparse::{SparseProof, build_sparse, verify_sparse};
    use std::path::PathBuf;

    let input = &input[..input.len().min(MAX_INPUT)];
    if input.is_empty() {
        return;
    }

    // A small tree (<= 32 lex-sorted two-letter-named entries) whose
    // object hashes are carved from `input`.
    let n = usize::from(input[0]) % 32 + 1;
    let mut entries = Vec::with_capacity(n);
    for i in 0..n {
        let a = b'a' + u8::try_from(i / 26).unwrap_or(0);
        let b = b'a' + u8::try_from(i % 26).unwrap_or(0);
        let mut hash = [0u8; 32];
        let start = (i * 7) % input.len();
        for (j, byte) in hash.iter_mut().enumerate() {
            *byte = input[(start + j) % input.len()];
        }
        entries.push(TreeEntry {
            name: vec![a, b],
            mode: EntryMode::Blob,
            object_hash: hash,
        });
    }
    let tree = Tree { entries };

    // A filter selecting a pseudo-random subset of the same two-letter
    // names, so it sometimes matches and sometimes doesn't.
    let filter_count = input
        .get(1)
        .copied()
        .map_or(0, |b| usize::from(b) % (n + 1));
    let mut filter = Vec::with_capacity(filter_count);
    for i in 0..filter_count {
        let a = b'a' + u8::try_from(i / 26).unwrap_or(0);
        let b = b'a' + u8::try_from(i % 26).unwrap_or(0);
        filter.push(PathBuf::from(format!("{}{}", a as char, b as char)));
    }

    let Ok(mut response) = build_sparse(&tree, &filter) else {
        return;
    };
    let root = mkit_core::sparse::tree_hash(&tree);
    assert!(
        verify_sparse(&root, &filter, &response).is_ok(),
        "fresh witness must verify"
    );
    let honest = response.proof.clone();
    response.proof = SparseProof {
        tree_bytes: input.to_vec(),
    };
    let _ = verify_sparse(&root, &filter, &response);
    response.proof = honest;
    response.proof.tree_bytes.pop();
    let _ = verify_sparse(&root, &filter, &response);
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

/// As [`run_iterated_unit`], but threads a caller-owned `state: &T`
/// through to `body` on every iteration instead of requiring `body` to
/// build its own per-call state (#505 PR 5/5) — used by the pack target
/// to reuse one tempdir/store across all `MAX_ITER` iterations.
pub fn run_iterated_unit_with<T>(state: &T, body: fn(&[u8], &T)) -> Result<(), GuardrailError> {
    let mut prng = SplitMix::new(RNG_SEED);
    let mut buf = vec![0u8; MAX_INPUT];
    for _ in 0..MAX_ITER {
        let len = prng.range_usize(MAX_INPUT);
        prng.fill(&mut buf[..len]);
        let start = Instant::now();
        body(&buf[..len], state);
        if start.elapsed() > PER_ITER {
            return Err(GuardrailError::IterationTooSlow);
        }
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
        // #505 PR 5/5: one tempdir/store reused across all MAX_ITER
        // iterations instead of 100 real filesystem inits — the
        // per-iteration isolation `pack_one_iteration` gives real
        // libfuzzer runs isn't needed by this deterministic PRNG-driven
        // loop, which only cares whether the reader panics/UB's.
        let dir = tempfile::TempDir::new().expect("tempdir");
        let store =
            mkit_core::store::ObjectStore::init(&mkit_core::layout::RepoLayout::single(dir.path()))
                .expect("store init");
        run_iterated_unit_with(&store, pack_one_iteration_with_store).expect("guardrails held");
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
    fn merkle_packlist_target_runs_within_caps() {
        run_iterated_unit(merkle_packlist_one_iteration).expect("guardrails held");
        // A couple of explicit boundary cases.
        for case in [&b""[..], &b"MKPL\x01"[..], &[0xFF; 64]] {
            run_one(case, merkle_packlist_one_iteration).expect("guardrails held");
        }
    }

    #[test]
    fn merkle_proof_target_runs_within_caps() {
        run_iterated_unit(merkle_proof_one_iteration).expect("guardrails held");
        for case in [&b""[..], &[0u8; 32][..], &[0xAB; 200][..]] {
            run_one(case, merkle_proof_one_iteration).expect("guardrails held");
        }
    }

    #[test]
    fn disclosure_decode_target_runs_within_caps() {
        run_iterated_unit(disclosure_decode_one_iteration).expect("guardrails held");
        for case in [&b""[..], b"MKDP\x01", &[0xFF; 64][..]] {
            run_one(case, disclosure_decode_one_iteration).expect("guardrails held");
        }
    }

    #[test]
    fn pack_entries_target_runs_within_caps() {
        run_iterated_unit(pack_entries_one_iteration).expect("guardrails held");
        for case in [
            &b""[..],
            b"MKIT\x01\x00\x00\x00\x00\x00\x00\x00",
            &[0xFF; 64][..],
        ] {
            run_one(case, pack_entries_one_iteration).expect("guardrails held");
        }
    }

    #[test]
    fn verify_closure_target_runs_within_caps() {
        let fixture = build_closure_fixture();
        run_iterated_unit_with(&fixture, verify_closure_one_iteration_with)
            .expect("guardrails held");
        for case in [&b""[..], &[0u8; 32][..], &[0xAB; 200][..]] {
            let start = std::time::Instant::now();
            verify_closure_one_iteration_with(case, &fixture);
            assert!(start.elapsed() <= PER_ITER, "iteration exceeded PER_ITER");
        }
    }

    #[test]
    fn verify_disclosure_target_runs_within_caps() {
        // Amortize the tempdir/store/signing cost across all MAX_ITER
        // iterations, same rationale as the pack target above.
        let fixture = build_disclosure_fixture();
        run_iterated_unit_with(&fixture, verify_disclosure_one_iteration_with)
            .expect("guardrails held");
        for case in [&b""[..], &[0u8; 32][..], &[0xAB; 200][..]] {
            let start = std::time::Instant::now();
            verify_disclosure_one_iteration_with(case, &fixture);
            assert!(start.elapsed() <= PER_ITER, "iteration exceeded PER_ITER");
        }
    }

    #[test]
    fn partial_workspace_target_runs_within_caps() {
        let fixture = build_partial_workspace_fixture();
        run_iterated_unit_with(&fixture, partial_workspace_one_iteration_with)
            .expect("guardrails held");
        for case in [&b""[..], b"MKWB\x01", &[0xFF; 64][..]] {
            let start = std::time::Instant::now();
            partial_workspace_one_iteration_with(case, &fixture);
            assert!(start.elapsed() <= PER_ITER, "iteration exceeded PER_ITER");
        }
    }

    #[test]
    fn partial_workspace_mutation_rejects_beyond_first_256_bytes() {
        let fixture = build_partial_workspace_fixture();
        assert!(fixture.bundle.len() > 256);
        let position = fixture.bundle.len() - 1;
        let mut input = [0u8; 9];
        input[..8].copy_from_slice(&(position as u64).to_le_bytes());
        input[8] = 1;
        partial_workspace_one_iteration_with(&input, &fixture);
    }

    #[test]
    fn partial_overlay_target_runs_within_caps() {
        let fixture = build_partial_overlay_fixture();
        run_iterated_unit_with(&fixture, partial_overlay_one_iteration_with)
            .expect("guardrails held");
        for case in [
            &b""[..],
            &b"\x01\x00\x00\x03\x00new"[..],
            &b"\x01\x00\x01\x01"[..],
            &b"\x02\x00\x00\x01\x00a\x00\x00\x01\x00b"[..],
        ] {
            let start = std::time::Instant::now();
            partial_overlay_one_iteration_with(case, &fixture);
            assert!(start.elapsed() <= PER_ITER, "iteration exceeded PER_ITER");
        }
    }

    #[test]
    fn partial_overlay_fixed_case_reaches_aggregate_content_bound() {
        let fixture = build_partial_overlay_fixture();
        let payload = vec![0xA5; 4 * 1024];
        let mut input = vec![2, 0, 0, 0, 16];
        input.extend_from_slice(&payload);
        input.extend_from_slice(&[1, 0, 0, 16]);
        input.extend_from_slice(&payload);
        let exact = mkit_core::PartialLimits {
            max_selected_file_bytes: 4 * 1024,
            max_total_selected_bytes: 8 * 1024,
            max_changed_paths: 2,
            ..mkit_core::PartialLimits::V1
        };
        assert!(partial_overlay_one_iteration_with_limits(&input, &fixture, &exact).is_ok());
        let one_short = mkit_core::PartialLimits {
            max_total_selected_bytes: exact.max_total_selected_bytes - 1,
            ..exact
        };
        assert!(matches!(
            partial_overlay_one_iteration_with_limits(&input, &fixture, &one_short),
            Err(mkit_core::PartialError::WorkspaceTooLarge)
        ));
    }

    #[test]
    fn sparse_verify_target_runs_within_caps() {
        run_iterated_unit(sparse_verify_one_iteration).expect("guardrails held");
        for case in [&b""[..], &[0u8; 32][..], &[0xFF; 64][..], &[0x01; 512][..]] {
            run_one(case, sparse_verify_one_iteration).expect("guardrails held");
        }
    }

    /// Pilot migration to `minifuzz` (commonware-invariants) — the same
    /// in-process harness upstream commonware uses for its in-tree
    /// property tests. Replaces the bespoke splitmix64 loop
    /// (`run_iterated_unit`) for this one target while honouring the
    /// FUZZ.md guardrails: `with_search_limit(MAX_ITER)` caps iterations
    /// (#1), `with_seed(RNG_SEED)` keeps the run deterministic (#6), and
    /// the body truncates each input to `MAX_INPUT` and applies the
    /// per-iteration wall-clock cap (#2, #4) via `run_one`. minifuzz's
    /// mutational sampler caps its buffer at 8 KiB, so inputs stay well
    /// under the 64 KiB ceiling. On failure it prints a
    /// `MINIFUZZ_BRANCH = 0x...` token; replay it with
    /// `Builder::default().with_reproduce("0x...")`.
    #[test]
    fn rpc_decode_target_runs_within_caps() {
        commonware_invariants::minifuzz::Builder::default()
            .with_search_limit(u64::from(MAX_ITER))
            .with_seed(RNG_SEED)
            .test(|u| {
                let take = u.len().min(MAX_INPUT);
                let input = u.bytes(take)?;
                run_one(input, rpc_decode_one_iteration).expect("guardrails held");
                Ok(())
            });
        // minifuzz's mutational sampler tops out near 8 KiB, so on its own
        // it would not exercise the 8 KiB–64 KiB regime the old splitmix
        // loop covered (large-frame length-prefix handling near the
        // MAX_INPUT cap). Preserve that explicitly with a deterministic
        // large-input sweep up to 64 KiB, seeded from the same RNG_SEED so
        // failures still reproduce.
        let mut prng = SplitMix::new(RNG_SEED);
        let mut buf = vec![0u8; MAX_INPUT];
        for len in [4096usize, 16_384, 49_152, MAX_INPUT] {
            prng.fill(&mut buf[..len]);
            run_one(&buf[..len], rpc_decode_one_iteration).expect("guardrails held");
        }
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
