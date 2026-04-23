# Fuzzing

mkit ships a small number of **bounded property tests** that exercise the
binary parsers from adversarial inputs. They run as part of the default
`zig build test` step — no separate fuzz harness, no external tooling.

The property-test approach is deliberate: a previous attempt at coverage
used `std.testing.fuzz` with `std.heap.page_allocator` and, under a
`--fuzz`-style corpus run, allocated 192 GB and wedged the machine.
Everything in this document exists to prevent that recurring.

## What is fuzzed

| File                   | Target                                    |
| ---------------------- | ----------------------------------------- |
| `src/fuzz_packfile.zig`| `packfile.unpack`                         |
| `src/fuzz_tree.zig`    | `serialize.deserialize` (tree objects)    |
| `src/fuzz_delta.zig`   | `delta.applyDelta`                        |

## What is **not** fuzzed (deferred)

- **`restore` (symlink resolution)** — the file-system side-effect surface
  made it too easy to accidentally create symlink cycles. Revisit once we
  have a virtual-FS shim to sandbox the target.
- **SSH / URL parser wire decoding** — the SSH stack has just landed; we
  keep the seam clean until it stabilises.

## Invariants per target

All three targets share the same base invariants:

- No panic, no `unreachable`, no infinite loop.
- No out-of-memory that is not an explicit `error.OutOfMemory` from the
  target's own allocator. (The harness pins every run to a
  `FixedBufferAllocator` backed by a 2 MiB static buffer — see below.)
- Every iteration completes in under 100 ms of wall-clock.

Target-specific invariants:

- **Packfile**: declared entry count + declared entry lengths are
  bounds-checked against the actual input length *before* the parser
  allocates the entries array. The most important regression test is
  "pack header claims count = 9 999 999, body is 0 bytes": the parser
  must reject or the FBA must return `OutOfMemory` — neither is allowed
  to reserve real memory.
- **Tree**: every `TreeEntry.name` accepted by the parser is non-empty,
  contains no path separators and no NUL bytes, is not `.` or `..`, and
  is at most 255 bytes. Every mode is one of the four enumerated values.
- **Delta**: a `COPY` instruction's `offset + length` stays within the
  base slice; a truncated `COPY` header or `INSERT` literal produces
  `error.DeltaCorrupt`; opcode `0x00` is always rejected.

## How to run

```sh
DEVELOPER_DIR=/Library/Developer/CommandLineTools zig build test
```

That includes the fuzz tests automatically. They add ~30 tests total,
complete in well under a second combined, and each one is wall-clock
capped so a regression that introduces an accidental loop aborts instead
of hanging CI.

Deeper fuzz runs (millions of iterations, per-target corpora, coverage
feedback) are intentionally **out of scope** for the bounded-property
harnesses in this directory. When we add a dedicated fuzz step, each
target here gains a matching `fuzz_<name>` build step and moves its body
into a function callable from both `zig build test` and the fuzz runner.

## Guardrails (NON-NEGOTIABLE)

Every fuzz test block in this repo must satisfy all six:

1. **At most 100 iterations per test block.**
2. **Every iteration's input is at most 64 KiB.**
3. **Every iteration runs under a `std.heap.FixedBufferAllocator` backed by a
   2 MiB static `[2 * 1024 * 1024]u8` buffer.** Never `std.testing.allocator`,
   never `std.heap.page_allocator` inside a fuzz body.
4. **Every iteration is timed; if it takes more than 100 ms the test
   aborts the remainder** via `return error.FuzzIterationTooSlow`.
5. **No `while (true)` without a bounded iteration counter.**
6. **No `std.testing.fuzz`.** We drive inputs synchronously from
   `std.Random.DefaultPrng` seeded with a fixed `u64` so failures
   reproduce exactly. The standard-library fuzz harness was the original
   source of the memory bomb; staying out of it is the whole point.

## Known limitations

- The 2 MiB FBA cap means bugs that only manifest above 2 MiB of
  allocation are not caught here. If you suspect such a bug, write a
  dedicated test with a larger allocator outside the fuzz file.
- PRNG-driven coverage is shallow — 100 iterations of random bytes will
  not find bugs that require deeply structured input. The fixed seed
  cases exist to cover the structurally interesting shapes (oversize
  counts, truncated headers, invalid modes, etc.) that random bytes
  rarely hit.
- Fuzz outputs are only checked for "no panic, no runaway". We do not
  diff against a reference decoder.

## Adding a new target

Use this checklist before you land a new `src/fuzz_<name>.zig`:

- [ ] Target is already compiled into the default `zig build test`
  binary. (If not, wire it through `src/lib.zig` first.)
- [ ] The fuzz file declares a static `fba_buf: [2 * 1024 * 1024]u8`.
- [ ] Every `test` block allocates from
  `std.heap.FixedBufferAllocator.init(&fba_buf).allocator()`.
- [ ] Every iteration takes its input from a seeded
  `std.Random.DefaultPrng`, **never** from `std.testing.fuzz`.
- [ ] Every iteration caps input length at 64 KiB (or less).
- [ ] Every iteration is wrapped in a `start = std.time.nanoTimestamp()`
  / elapsed check, with `return error.FuzzIterationTooSlow` on breach.
- [ ] The outer loop has an explicit iteration cap of at most 100.
- [ ] Add an export in `src/lib.zig` (`pub const fuzz_<name> = ...`) and
  a matching `_ = fuzz_<name>;` inside the top-level `test` block.
- [ ] Add at least three hand-crafted fixed-seed cases: the happy path,
  one structural malformation, and one bounds-stress case
  (oversize-count / oversize-length style).

If you cannot satisfy the guardrails, do not land the target — leave
a note in this file explaining why it was deferred.
