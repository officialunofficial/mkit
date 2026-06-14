# Fuzzing

mkit ships a small number of **bounded property tests** that exercise the
binary parsers from adversarial inputs. They live in the `mkit-fuzz`
crate at `rust/fuzz/` and run in two modes:

- `cd rust && cargo test --manifest-path fuzz/Cargo.toml` — plain unit-test
  harness over the target bodies; stable Rust, no extra tooling. CI runs
  this.
- `cd rust/fuzz && cargo +nightly fuzz run <target>` — libfuzzer-sys
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
| `fuzz_targets/pack.rs`         | `pack::PackReader::unpack`  |
| `fuzz_targets/tree.rs`         | `serialize::deserialize`    |
| `fuzz_targets/software_key_record.rs` | `EncryptedKeyRecord::decode` |
| `fuzz_targets/git_commit_parse.rs` | `mkit-git-bridge gitparse::parse_commit` (untrusted upstream bytes, SPEC-GIT-IMPORT §2) |
| `fuzz_targets/git_tag_parse.rs` | `mkit-git-bridge gitparse::parse_tag` |
| `fuzz_targets/git_tree_parse.rs` | `mkit-git-bridge gitparse::parse_tree` + `map_mode` |
| `fuzz_targets/rpc_decode.rs`   | `SignerFrame` / `SshFrame` wire decode (never panics) + `Arbitrary`-driven encode/decode roundtrip |

Targets that exercise crate-private parser surfaces should expose a minimal
`#[cfg(feature = "fuzzing")]` wrapper from that crate and enable the feature in
`rust/fuzz/Cargo.toml`, as `software_key_record` does for `mkit-keystore`.

## What is **not** fuzzed (deferred)

- **`restore` (symlink resolution)** — the file-system side-effect
  surface made it too easy to accidentally create symlink cycles.
  Revisit once we have a virtual-FS shim to sandbox the target.
- **SSH / URL parser wire decoding** — covered by crate-level unit
  tests for now.

## Invariants per target

All targets share the same base invariants:

- No panic.
- No out-of-memory that is not an explicit `Vec::with_capacity`-caught
  allocation failure at the parser boundary.
- Every iteration completes in under 100 ms of wall-clock.

Target-specific invariants:

- **Packfile**: declared entry count + declared entry lengths are
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

## How to run

```sh
cd rust
cargo test --manifest-path fuzz/Cargo.toml
```

That runs the target bodies as ordinary unit tests with a seeded
PRNG — ~30 cases total, each wall-clock capped so a regression that
introduces an accidental loop aborts rather than hanging CI.

For coverage-guided runs (nightly toolchain required):

```sh
cd rust/fuzz
cargo +nightly fuzz run delta
cargo +nightly fuzz run pack
cargo +nightly fuzz run tree
cargo +nightly fuzz run software_key_record
cargo +nightly fuzz run rpc_decode
```

## In-process minifuzz (`rpc_decode` pilot)

The default in-process harness is a bespoke splitmix64 loop
(`run_iterated_unit` in `src/lib.rs`). The `rpc_decode` target's unit
test instead drives the shared body through
[`minifuzz`](https://docs.rs/commonware-invariants) — the same
in-process property-test harness upstream commonware uses for its own
in-tree tests. It is a mutational fuzzer (smarter than uniform-random
bytes) yet still a plain `#[test]` on stable, and on failure prints a
`MINIFUZZ_BRANCH = 0x...` token that replays the exact case via
`Builder::default().with_reproduce("0x...")`.

`commonware-invariants` is a **dev-dependency only** (pinned to the
commonware 2026.5.x train); the libfuzzer binaries never link it. The
same six guardrails apply: `with_search_limit(MAX_ITER)` caps iterations,
`with_seed(RNG_SEED)` keeps the run deterministic, and the body still
truncates to `MAX_INPUT` and runs under the per-iteration wall-clock cap.
This is a pilot — the other targets stay on the splitmix loop until the
pattern proves out (`commonware-invariants` is ALPHA upstream).

## Guardrails (NON-NEGOTIABLE)

Every target body must satisfy all six:

1. **At most 100 iterations per invocation.**
2. **Every iteration's input is at most 64 KiB.**
3. **Bounded allocations.** Input cap (2) + per-op output caps inside
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
6. **Seeded deterministic PRNG.** Inputs are synthesised from a fixed
   `u64` seed (`RNG_SEED`) so any failure reproduces exactly. Most targets
   use a splitmix64 PRNG (`run_iterated_unit`); the `rpc_decode` pilot
   drives the body through `minifuzz`, whose ChaCha8 sampler is seeded with
   the same constant via `with_seed` — also deterministic — plus a
   splitmix64 large-input sweep so the 8 KiB–64 KiB range stays covered
   (see the [In-process minifuzz](#in-process-minifuzz-rpc_decode-pilot)
   section).

## Known limitations

- PRNG-driven coverage is shallow — 100 iterations of random bytes
  will not find bugs that require deeply structured input. The fixed
  seed cases exist to cover the structurally interesting shapes
  (oversize counts, truncated headers, invalid modes, etc.) that
  random bytes rarely hit. Coverage-guided `cargo fuzz` runs fill in
  the rest.
- Fuzz outputs are only checked for "no panic, no runaway". We do not
  diff against a reference decoder.

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

If you cannot satisfy the guardrails, do not land the target — leave
a note in this file explaining why it was deferred.
