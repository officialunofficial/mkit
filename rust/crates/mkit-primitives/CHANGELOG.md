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

- Bounded sans-IO pack framing and all-entry verification with entry-boundary
  checkpoints, authenticated evidence pages and paths, optional caller-owned
  compute scheduling, and a strict versioned checkpoint envelope.
- Bounded closure walking, including resulting-pair coverage with local
  resumable progress.
- Guarded ref, publication, fork acceptance, activation, ticketed-advance,
  reservation-settlement and clearance decisions, with refusal-only guards.
- Portable auth-v2 validation, upload-claims binding and replay classification.
- A versioned `AcceptanceEvidence` envelope with strict bounded decoding, a
  canonical digest and independent head-signature rechecking.
- Portable byte and semantic fixtures under `fixtures/`, consumed by an
  out-of-tree check that builds this crate from its packaged form.

### Compatibility

- Depends on the `mkit-core` release declared in `Cargo.toml`. Before
  publishing, that requirement must name a published core release containing
  every core API the crate uses.
- Features: `pack-ruzstd` (default, pure Rust) and `pack-zstd` (native).
  `std` on native and `wasm32-unknown-unknown`; no `no_std` promise.
