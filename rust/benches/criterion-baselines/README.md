# Criterion baselines

This directory is the tracked snapshot of the criterion "committed"
baseline (`target/criterion/**/committed/`) that
`.github/workflows/bench-nightly.yml` compares every nightly run
against. `rust/target/` (including `target/criterion/`) is gitignored
build output, so this is the one place those numbers survive between
commits.

Only the small stats files criterion writes per benchmark are tracked
— `estimates.json`, `sample.json`, `tukey.json`, `benchmark.json` —
never the `report/` HTML+SVG bundle criterion also generates (that's
regenerable, and would bloat the repo with charts nobody reads from
git history).

## Regenerating the baseline

Do this deliberately, after confirming a perf change is real and
accepted (not to silence a nightly failure) — and on an otherwise
idle machine; these are absolute wall-clock numbers:

```sh
cd rust
cargo bench -p mkit-benches \
  --bench hashing --bench sign_verify \
  --bench object_commit --bench pack_create \
  -- --save-baseline committed
cd ..
scripts/bench-baseline.sh save
git add rust/benches/criterion-baselines
```

`pack_shard_transfer` and `store_write` are intentionally excluded,
matching the README's explicit-target reproduce command (PR #604):
`pack_shard_transfer` is feature-gated (`--features pack-shards`) and
its own Cargo.toml comment already says "not gated on in CI", and
`store_write`'s flush-schedule comparison is machine/filesystem
dependent by design (its interesting signal is the
per-object-vs-batch ratio, not the absolute number a baseline would
pin).

## Tolerance

`.github/workflows/bench-nightly.yml` runs
`cargo run -p mkit-benches --bin check-regressions` after comparing
against this baseline (`-- --baseline committed`), which fails the job
when any benchmark's mean wall-clock time regressed by more than 25%
(`MKIT_BENCH_TOLERANCE`, overridable). This is a tier-3 absolute
wall-clock guard (see issue #609): nightly-with-tolerance, never
PR-blocking. A red nightly run is a signal to investigate — profile
with `docs/PROFILING.md`'s workflow — not a gate on anything else.
