# Profiling

mkit's performance work has two complementary tools:

- **Benchmarks** (`rust/benches/`, criterion) answer *how fast* a path is
  and guard against regressions. See [`scripts/bench-vs-git.sh`](../scripts/bench-vs-git.sh)
  for the end-to-end-vs-git suite behind the performance page.
- **Sampling profiles** (this document) answer *where the time goes*
  inside a real run &mdash; which functions and source lines the CPU actually
  spends time in, with inline stacks.

Sampled profiles use [`samply`](https://github.com/mstange/samply),
a cross-platform (Linux/macOS/Windows) sampling profiler that records
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
`dev` (unrepresentative &mdash; no optimization).

### Representative codegen vs. readable stacks

There is a real tradeoff here. `inherits = "release"` keeps `lto = "thin"`
plus `codegen-units = 1`, which makes the *numbers* representative of a
shipped binary &mdash; but that aggressive cross-crate inlining **collapses the
call stack**, so a sampling profiler will mis-attribute self-time to the
wrong function (for example, allocator/format frames showing up under `blake3`, or
a phantom `format!` hotspot that does not exist). Trust hot-*path* shape,
not exact per-function percentages, when profiling the default profile.

When you need accurate **function-level** attribution, rebuild the same
profile with LTO off and more codegen units &mdash; distinct frames, still
optimized:

```sh
CARGO_PROFILE_PROFILING_LTO=false \
CARGO_PROFILE_PROFILING_CODEGEN_UNITS=16 \
  cargo build --profile profiling -p mkit-cli
```

The two views are complementary: LTO-on for "is the total time
representative?", LTO-off for "which function is hot?". A discrepancy
between them is usually an inlining artifact, not a real regression.

## Profile the CLI

The wrapper script builds with `--profile profiling` and records:

```sh
# scripts/profile.sh [--features <list>] [-- <mkit args>]
scripts/profile.sh -- add .
scripts/profile.sh -- commit -m "msg"
```

(The CLI is dominated by `add` / `commit`; there is no top-level `pack`
command &mdash; pack assembly is exercised via the `pack_create` bench below.)

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
`object_commit`, `pack_create`, `store_write`, and the feature-gated
`pack_shard_transfer` &mdash; see `rust/benches/Cargo.toml` for the full list):

```sh
scripts/profile.sh --bench pack_create
# Feature-gated bench: forward the cargo feature to the build.
scripts/profile.sh --bench pack_shard_transfer --features pack-shards
```

By hand, build the bench binary with the profiling profile and record it
running its measurement loop. Cargo emits bench executables under
`target/<profile>/deps/` with a content hash suffix, so resolve the path
from cargo's JSON rather than guessing it:

```sh
cd rust
cargo build --profile profiling -p mkit-benches --bench pack_create \
  --message-format=json \
  | python3 -c 'import sys,json; print(next(o["executable"] for l in sys.stdin if (o:=json.loads(l)).get("executable") and o.get("target",{}).get("name")=="pack_create"))'
samply record ./target/profiling/deps/pack_create-<hash> --bench
```

(The wrapper does exactly this JSON resolution, so it works under a custom
`CARGO_TARGET_DIR` too.)

## Reading a profile

- The **Call Tree** and **Flame Graph** tabs show where wall-clock samples
  landed. Invert the call tree to find self-heavy leaf functions.
- **Double-click a function** to open the source view and see which lines
  were sampled, and how often.
- samply samples per-thread at 1000 Hz (1 ms) by default; short runs need
  a loop or a larger workload to gather enough samples &mdash; prefer profiling
  a bench or a non-trivial repository over a single tiny command.

## Platform notes

- **macOS** &mdash; works out of the box.
- **Linux** &mdash; samply uses `perf_event`. If recording fails with a
  permission error, lower the `perf_event_paranoid` knob for your session
  (least privilege) rather than running the profiler as root:

  ```sh
  # Temporary, until reboot — samply prints this exact command on failure.
  sudo sysctl kernel.perf_event_paranoid=1
  ```

  **Do not** `sudo scripts/profile.sh` / `sudo samply record`: that runs
  freshly built local code and writes profile/build artifacts as root,
  which can leave root-owned files in your worktree. Adjust the sysctl (or
  grant `CAP_PERFMON` to the samply binary) and run the profiler as your
  normal user.

## Why not in CI

Sampling profiles are interactive artifacts for investigation, not a
pass/fail gate &mdash; the criterion benches and `scripts/bench-vs-git.sh` cover
regression tracking. Capture a profile when a bench moves and you want to
know *why*.
