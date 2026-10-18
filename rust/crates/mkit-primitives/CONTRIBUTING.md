# Contributing to primitives

Follow the [repository guide](../../../CONTRIBUTING.md). Keep input acquisition,
clocks, storage, and atomic commits in the host. Reuse core wire implementations.

Each module owns a labeled section in **src/lib.rs**, the single `FailureCode`
enum in **src/error.rs**, and **fixtures/manifest.toml**. Append only inside your
module section; coordinate additions that cross ownership boundaries. Keep
trusted constructors module-private. No public helper may forge trusted artifacts.
Append new failure codes inside the same module section of the single
`fixtures/error/failure-codes.txt` registry and update its manifest digest.
Existing codes are stable within a ruleset and cannot be repurposed.

Every public item inherits its module's ALPHA annotation. New decoders require
explicit finite configurations, cumulative budgets, portable byte fixtures,
malformed cases, and a fuzz target with stable seed replay in the same change.
Register semantic fixtures for in-memory decisions without inventing encodings.
CI reads fixtures and rejects changed, missing, or orphan files; it never regenerates them.
Regeneration requires a reviewed format change or demonstrated generator defect,
with version and restart consequences documented.

Use fixed seeds and source identities. Limit Cargo and nextest to three jobs.
Run targeted checks through `just cargo-cached`. Full suites run in CI.
The stability inventory checks the compiler-resolved public API under every
backend configuration, including inherited annotations and re-exports.
Minimum-level builds reject dependencies on APIs below the selected level.

`cargo fmt` does not discover macro-declared modules. Run
`python3 scripts/fmt-primitives.py --check` from the repository root as well.

Releases are independent of the workspace train; see "Publishing
`mkit-primitives`" in `docs/RELEASE.md`. Record user-visible changes under
`## [Unreleased]` in `CHANGELOG.md`; an API break needs the next `0.x` minor.
Run `just check-primitives-release` and `just check-primitives-consumer`
before changing packaged files, fixtures or the manifest.
