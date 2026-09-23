# Fuzzing

mkit ships a small number of **bounded property tests** that exercise the
binary parsers from adversarial inputs. They live in the `mkit-fuzz`
crate at `rust/fuzz/` and run in two modes:

- `cd rust && cargo test --manifest-path fuzz/Cargo.toml` &mdash; plain unit-test
  harness over the target bodies; stable Rust, no extra tooling. CI runs
  this.
- `cd rust/fuzz && cargo +nightly fuzz run <target>` &mdash; libfuzzer-sys
  harness for coverage-guided runs. Same target bodies, same
  guardrails.

The property-test approach is deliberate: an earlier attempt that ran
inputs through a page-backed allocator ballooned to hundreds of GiB on a
pathological corpus. Everything in this document exists to prevent that
from recurring.

## What is fuzzed

| Target file                    | Target function             |
| ------------------------------ | --------------------------- |
| `fuzz_targets/delta.rs`        | `delta::decode`             |
| `fuzz_targets/pack.rs`         | `pack::PackReader::read`    |
| `fuzz_targets/tree.rs`         | `serialize::deserialize`    |
| `fuzz_targets/software_key_record.rs` | `EncryptedKeyRecord::decode` |
| `fuzz_targets/git_commit_parse.rs` | `mkit-git-bridge gitparse::parse_commit` (untrusted upstream bytes, SPEC-GIT-IMPORT §2) |
| `fuzz_targets/git_tag_parse.rs` | `mkit-git-bridge gitparse::parse_tag` |
| `fuzz_targets/git_tree_parse.rs` | `mkit-git-bridge gitparse::parse_tree` plus `map_mode` |
| `fuzz_targets/rpc_decode.rs`   | `SignerFrame` / `SshFrame` wire decode (never panics) plus `Arbitrary`-driven encode/decode roundtrip |
| `fuzz_targets/sparse_verify.rs` | `sparse::build_sparse` / `sparse::verify_sparse` (never panics on adversarial manifest/proof bytes) |
| `fuzz_targets/merkle_proof.rs` | `merkle::compute_{tree,chunked}_id` / `merkle::Proof::decode` / `merkle::verify_tree_entry` / `merkle::verify_chunk` (never panics; a freshly built proof verifies; adversarial proof bytes reject cleanly, whether at decode or at verify) |
| `fuzz_targets/merkle_packlist.rs` | `transfer::decode_packlist` / `transfer::encode_packlist` (never panics; a decoded node re-encodes and re-decodes to the same node) |
| `fuzz_targets/disclosure_decode.rs` | `verify::verify_disclosure` decode path (issue #1015 verifier kit PR 2, SPEC-DISCLOSURE) — never panics on adversarial bundle bytes, regardless of the commit id checked against; every `Vec`/`Proof` length is bounded before allocation |
| `fuzz_targets/verify_disclosure.rs` | `verify::verify_disclosure` / `verify::build_disclosure` (never panics; a freshly built bundle over a real `ObjectStore` fixture verifies; a mutated bundle rejects cleanly) |
| `fuzz_targets/pack_entries.rs` | `pack::PackEntries` (never panics on adversarial pack bytes; a pack `PackReader::read` accepts also parses as `PackEntries` with the same entry count) |
| `fuzz_targets/bounded_inspection.rs` | keyed raw-v1 pack ranges and bounded canonical Snapshot-object identification (no panic or out-of-range borrowed payload) |
| `fuzz_targets/snapshot_walk.rs` | bounded complete-Snapshot Tree/manifest transitions over authenticated small facts (cursor, depth, width, length, and accounting bounds) |
| `fuzz_targets/staged_update.rs` | borrowed MKWU v1 carrier/key validation and ordered canonical inventory, with an unconditional committed-valid lane and bounded malformed bytes |
| `fuzz_targets/verify_closure.rs` | `verify::verify_closure` / `verify::verify_closure_packs` / `verify::verify_closure_manifest` / `verify::export_closure` (never panics; a freshly exported snapshot closure verifies; a mutated manifest rejects cleanly; raw adversarial bytes fed directly as pack buffers — whole and split into two — to `verify_closure_packs`/`verify_closure_manifest` never panic and any `Ok` report is internally consistent) |
| `fuzz_targets/partial_workspace.rs` | `partial::verify_partial_snapshot` (fresh `MKWB` bundle verifies; a full-range byte mutation plus a guaranteed trailing byte rejects; arbitrary bytes remain bounded and never panic; nested counts and byte lengths are bounded before allocation) |
| `fuzz_targets/partial_overlay.rs` | `partial::replace_files` (bounded structured replacement/reuse batches may succeed or reject; every success replays deterministically, preserves unselected entry triples and selected modes, and emits canonical objects under their type-dependent ids; a hand-built two-destination case accepts the exact aggregate-content bound and rejects the same input when that bound is lowered by one byte) |
| `fuzz_targets/hosted_grant.rs` | standalone `mkit-hosting-policy::decode` / `verify_signature` (bounded malformed MKHG input; every accepted envelope re-encodes byte-identically) |

Targets that exercise crate-private parser surfaces should expose a minimal
`#[cfg(feature = "fuzzing")]` wrapper from that crate and enable the feature in
`rust/fuzz/Cargo.toml`, as `software_key_record` does for `mkit-keystore`.

## What is **not** fuzzed (deferred)

- **`restore` (symlink resolution)** &mdash; the file-system side-effect
  surface made it too easy to accidentally create symlink cycles.
  Revisit once a virtual-FS shim exists to sandbox the target.
- **SSH / URL parser wire decoding** &mdash; covered by crate-level unit
  tests for now.

## Invariants per target

All targets share the same base invariants:

- No panic.
- No out-of-memory that is not an explicit `Vec::with_capacity`-caught
  allocation failure at the parser boundary.
- Every iteration completes in under 100 ms of wall-clock.

Target-specific invariants:

- **Packfile**: declared entry count plus declared entry lengths are
  bounds-checked against the actual input length *before* the parser
  allocates the entries vector. The most important regression case is
  "pack header claims count = 9 999 999, body is 0 bytes": the parser
  must reject before pre-allocating any large structure.
- **Tree**: every `TreeEntry.name` accepted by the parser is
  non-empty, contains no path separators and no NUL bytes, is not `.`
  or `..`, and is at most 255 bytes. Every mode is one of the defined
  enumerated values.
- **Delta**: a `COPY` instruction's `offset + length` stays within the
  base slice; a truncated `COPY` header or `INSERT` literal produces
  `DeltaCorrupt`; opcode `0x00` is always rejected.
- **Partial overlay**: inputs describe at most four complete-byte or
  verified-representation reuse operations. Each byte payload is at most
  4 KiB, and the whole batch is at most 8 KiB. Invalid, duplicate,
  unselected, and all-no-op batches may reject. A successful batch must
  replay to the same root and object set, keep every unselected entry triple
  unchanged, preserve regular/executable modes, and emit canonical objects.

## How to run

```sh
cd rust
cargo test --manifest-path fuzz/Cargo.toml
```

That runs the target bodies as ordinary unit tests with a seeded
PRNG &mdash; ~30 cases total, each wall-clock capped so a regression that
introduces an accidental loop aborts rather than hanging CI.

For coverage-guided runs (nightly toolchain required):

```sh
cd rust/fuzz
cargo +nightly fuzz run delta
cargo +nightly fuzz run pack
cargo +nightly fuzz run tree
cargo +nightly fuzz run software_key_record
cargo +nightly fuzz run rpc_decode
cargo +nightly fuzz run partial_overlay
```

## In-process minifuzz (`rpc_decode` pilot)

The default in-process harness is a bespoke splitmix64 loop
(`run_iterated_unit` in `src/lib.rs`). The `rpc_decode` target's unit
test instead drives the shared body through
[`minifuzz`](https://docs.rs/commonware-invariants) &mdash; the same
in-process property-test harness upstream commonware uses for its own
in-tree tests. It is a mutational fuzzer (smarter than uniform-random
bytes) yet still a plain `#[test]` on stable, and on failure prints a
`MINIFUZZ_BRANCH = 0x...` token that replays the exact case via
`Builder::default().with_reproduce("0x...")`.

`commonware-invariants` is a **dev-dependency only** (pinned to the
commonware train fixed in `rust/Cargo.toml`, `2026.9.x` as of this revision); the libfuzzer binaries never link it. The
same six guardrails apply: `with_search_limit(MAX_ITER)` caps iterations,
`with_seed(RNG_SEED)` keeps the run deterministic, and the body still
truncates to `MAX_INPUT` and runs under the per-iteration wall-clock cap.
This is a pilot &mdash; the other targets stay on the splitmix loop until the
pattern proves out (`commonware-invariants` is alpha upstream).

## Guardrails (non-negotiable)

Every target body must satisfy all six:

1. **At most 100 iterations per invocation.**
2. **Every iteration's input is at most 64 KiB.**
3. **Bounded allocations.** Input cap (2) plus per-op output caps inside
   `mkit-core` keep the worst-case heap under ~1 MiB per iteration:
   - `delta::decode` caps its initial `Vec::with_capacity` at
     `result_len.min(base.len() + 2 * stream.len())` so a 9-byte
     stream claiming `result_len = u32::MAX` cannot pre-allocate 4 GiB.
   - `pack::PackReader` enforces `MAX_ENTRIES = 10_000_000` and
     `MAX_PAYLOAD = 4 GiB` with count × entry-frame-length lower-bound
     checks against the input slice before any `Vec::with_capacity`.
   - `software_key_record` truncates each input to 64 KiB before calling
     `EncryptedKeyRecord::decode`. The decoder's cursor checks every
     length-prefixed field against the remaining input before copying, so
     allocation is bounded by bytes already present in the capped input rather
     than by untrusted declared lengths.
   - The harness adds defensive pre-checks
     (`claimed_result_len > MAX_INPUT * 4`,
     `claimed_entries > 100_000`) that short-circuit before calling
     into core, so the most pathological inputs don't even reach the
     parsers.
4. **Every iteration is timed; if it takes more than 100 ms the test
   aborts the remainder.**
5. **No `loop {}` or `while true {}` without a bounded iteration
   counter.**
6. **Seeded deterministic PRNG.** Inputs are synthesized from a fixed
   `u64` seed (`RNG_SEED`) so any failure reproduces exactly. Most targets
   use a splitmix64 PRNG (`run_iterated_unit`); the `rpc_decode` pilot
   drives the body through `minifuzz`, whose ChaCha8 sampler is seeded with
   the same constant via `with_seed` &mdash; also deterministic &mdash; plus a
   splitmix64 large-input sweep so the 8 KiB–64 KiB range stays covered
   (see the [In-process minifuzz](#in-process-minifuzz-rpc_decode-pilot)
   section).

## Known limitations

- PRNG-driven coverage is shallow &mdash; 100 iterations of random bytes
  will not find bugs that require deeply structured input. The fixed
  seed cases exist to cover the structurally interesting shapes
  (oversize counts, truncated headers, invalid modes, etc.) that
  random bytes rarely hit. Coverage-guided `cargo fuzz` runs fill in
  the rest.
- Most parser targets check only for no panic and no runaway. The partial
  overlay target adds deterministic replay, canonical-object, mode, and
  untouched-triple invariants, but it does not compare against an independent
  overlay implementation.

## Adding a new target

Use this checklist before landing a new target:

- [ ] Pick a parser with a clear input → output contract.
- [ ] Add the target body to `rust/fuzz/src/lib.rs` as a `pub fn
      run_<name>(rng_seed: u64)` that enforces the six guardrails.
- [ ] Add a libfuzzer shim under `fuzz_targets/<name>.rs` calling the
      same body.
- [ ] Add a `#[test]` shim that invokes the body with fixed seeds.
- [ ] Add at least three hand-crafted fixed-seed cases: the happy path,
      one structural malformation, and one bounds-stress case
      (oversize-count / oversize-length style).

If you cannot satisfy the guardrails, do not land the target &mdash; leave
a note in this file explaining why it was deferred.
