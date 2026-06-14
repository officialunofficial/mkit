# Profiling

mkit's performance work has two complementary tools:

- **Benchmarks** (`rust/benches/`, criterion) answer *how fast* a path is
  and guard against regressions. See [`scripts/bench-vs-git.sh`](../scripts/bench-vs-git.sh)
  for the end-to-end-vs-git suite behind the performance page.
- **Sampling profiles** (this document) answer *where the time goes*
  inside a real run — which functions and source lines the CPU actually
  spends time in, with inline stacks.

For sampled profiles we use [`samply`](https://github.com/mstange/samply),
a cross-platform (macOS / Linux / Windows) sampling profiler that records
to the [Firefox Profiler](https://profiler.firefox.com/) UI. It needs no
`perf`/root on macOS and integrates cleanly with Rust debug info.

## Install

```sh
cargo install samply
```

## The `profiling` cargo profile

A profiler can only attribute samples to functions if the binary carries
symbols and debug info. mkit's `release` profile sets `strip = "symbols"`
(good for shipping, useless for profiling), so a dedicated profile lives
in `rust/Cargo.toml`:

```toml
[profile.profiling]
inherits = "release"   # codegen-units = 1, lto = "thin" — representative
debug = true           # line tables → inline stacks + source view
strip = false          # keep symbols
```

Always profile this profile, **not** `--release` (unreadable) and **not**
`dev` (unrepresentative — no optimisation).

## Profile the CLI

The wrapper script builds with `--profile profiling` and records:

```sh
# scripts/profile.sh [-- <mkit args>]
scripts/profile.sh -- commit -m "msg"
scripts/profile.sh -- pack create
```

Equivalently, by hand:

```sh
cd rust
cargo build --profile profiling -p mkit-cli
samply record ./target/profiling/mkit commit -m "msg"
```

`samply record` runs the program to completion, then opens the Firefox
Profiler in your browser with the recorded profile loaded.

## Profile a benchmark

To drill into one of the criterion suites (`hashing`, `sign_verify`,
`object_commit`, `pack_create`):

```sh
scripts/profile.sh --bench pack_create
```

By hand, build the bench binary with the profiling profile and record it
running its measurement loop:

```sh
cd rust
cargo build --profile profiling -p mkit-benches --bench pack_create
samply record ./target/profiling/<hashed-bench-binary> --bench
```

(The wrapper resolves the hashed artifact path from cargo's JSON output.)

## Reading a profile

- The **Call Tree** and **Flame Graph** tabs show where wall-clock samples
  landed. Invert the call tree to find self-heavy leaf functions.
- **Double-click a function** to open the source view and see which lines
  were sampled, and how often.
- samply samples per-thread at 1000 Hz (1 ms) by default; short runs need
  a loop or a larger workload to gather enough samples — prefer profiling
  a bench or a non-trivial repository over a single tiny command.

## Platform notes

- **macOS** — works out of the box.
- **Linux** — samply uses `perf_event`. If recording fails with a
  permission error, samply prints the exact `sysctl` to lower
  `kernel.perf_event_paranoid` (or run under `sudo`).

## Why not in CI

Sampling profiles are interactive artifacts for investigation, not a
pass/fail gate — the criterion benches and `scripts/bench-vs-git.sh` cover
regression tracking. Capture a profile when a bench moves and you want to
know *why*.
