# Changelog

All notable changes to `mkit-primitives` are documented here. The crate is
versioned independently of the mkit workspace release train and follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Every public API is
ALPHA: a `0.1.x` patch stays API compatible, and an intentional break requires
the next `0.x` minor, an entry here, and a new consumer-check fixture. Wire,
checkpoint and evidence format versions are tracked separately from the crate
version and never reinterpret existing protocol bytes.

Release preparation renames `## [Unreleased]` content to
`## [X.Y.Z] - YYYY-MM-DD`; `scripts/publish-primitives.py guard` refuses a tag
without that dated section.

## [Unreleased]

Initial public contract (0.1.0, not yet published).

### Added

- `Guarded<WriteDecision>::with_acceptance_basis` attaches repository-scoped
  acceptance guards to plain ref writes with exact pack coverage, duplicate
  elimination, contradiction checks and completeness auditing. Existing request
  constructors and decisions without an attachment are unchanged.

- Bounded sans-IO pack framing and all-entry verification with entry-boundary
  checkpoints, authenticated evidence pages and paths, optional caller-owned
  compute scheduling, and a strict versioned checkpoint envelope.
- Bounded closure walking, including resulting-pair coverage with local
  resumable progress.
- Guarded ref, publication, fork acceptance, activation, ticketed-advance,
  reservation-settlement and clearance decisions, with refusal-only guards.
- A sealed `AcceptanceBasis` (from sealed artifacts, decoded evidence, or an
  explicit host attestation) that ticketed acceptance requires and whose typed
  guards the decision adds; `Guarded::into_lowering`; `ClosureWalker::new` takes
  the sealed `VerifiedPack`; and a `synthetic-artifacts` feature for consumer tests.
- Portable auth-v2 validation, upload-claims binding and replay classification.
- A versioned `AcceptanceEvidence` envelope with strict bounded decoding, a
  canonical digest and independent head-signature rechecking.
- Portable byte and semantic fixtures under `fixtures/`, consumed by an
  out-of-tree check that builds this crate from its packaged form.

### Changed

- Reuse authenticated decoded objects-index leaves under a bounded optional
  resident reservation. Page emission, work charges, refusal precedence,
  compute determinism and checkpoint encoding stay unchanged.

- `ComputeConfig` adds `min_job_bytes` and becomes non-exhaustive. Construct it
  with `ComputeConfig::new(max_jobs)` and optionally call
  `.with_min_job_bytes(bytes)`. Raw entries below the default 64 KiB threshold
  decode inline; zero preserves all-entry dispatch. Delta scheduling, evidence,
  work charges, refusals, and encoded formats are unchanged.

### Compatibility

- Depends on the `mkit-core` release declared in `Cargo.toml`. Before
  publishing, that requirement must name a published core release containing
  every core API the crate uses.
- Features: `pack-ruzstd` (default, pure Rust) and `pack-zstd` (native).
  `std` on native and `wasm32-unknown-unknown`; no `no_std` promise.
