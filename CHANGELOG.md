# Changelog

All notable changes to mkit are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-04-27

### Wire/Signature break

- **`sign::domain_digest` now includes a 2-byte little-endian length
  prefix** in front of the domain label, so the hash input is
  `len_le16(domain) || domain || signing_bytes` instead of
  `domain || signing_bytes`. Closes a latent ambiguity where two
  distinct `(domain, signing_bytes)` splits could in principle
  produce identical hash input (finding H4). Commit and remix
  signatures produced by v0.1.0 **will NOT verify under this
  change**, and vice versa. Ship this in a coordinated release —
  there are no shipped artefacts to migrate, but downstream signers
  and pre-built test vectors must be regenerated.
- Golden signing hashes (`rust/crates/mkit-core/tests/golden_sign.rs`
  `signing_hashes_are_stable`) were re-pinned for the new digest
  shape.
- DSSE envelope `Sig`-bearing structure unchanged; external-signer
  Protocol v1.1 adds an *optional* `webauthn` field that v1
  verifiers ignore.

### Added

- Multi-algorithm signing foundation: Ed25519 + secp256k1 + P-256
  (`mkit-attest::Algorithm`, COSE-aligned IDs −19 / −47 / −7), with
  algorithm-agnostic signer trait + verifier dispatch ([#65](https://github.com/officialunofficial/mkit/pull/65), [#67](https://github.com/officialunofficial/mkit/pull/67)).
- `mkit attest` and `mkit verify-attest` CLI subcommands, plus
  `[attest]` config block and signer factory ([#66](https://github.com/officialunofficial/mkit/pull/66)).
- Multi-signature DSSE envelope emission via `--additional-signer`
  (with `args=` clause for argv pass-through) ([#67](https://github.com/officialunofficial/mkit/pull/67), [#69](https://github.com/officialunofficial/mkit/pull/69)).
- `mkit keygen --algorithm {ed25519|secp256k1|p256}` with
  `--print-pubkey` and `--force` flags ([#67](https://github.com/officialunofficial/mkit/pull/67)).
- External-signer Protocol v1 — formal spec at
  `docs/SPEC-EXTERNAL-SIGNER.md` ([#66](https://github.com/officialunofficial/mkit/pull/66)).
- External-signer Protocol v1.1 — WebAuthn wrapping extension
  (`docs/SPEC-EXTERNAL-SIGNER.md` §14) plus
  `mkit_attest::webauthn::verify_webauthn_wrapping` helper ([#71](https://github.com/officialunofficial/mkit/pull/71)).
- Reference signer `mkit-sign-file` — file-backed Rust binary, the
  conformance baseline for the protocol ([#66](https://github.com/officialunofficial/mkit/pull/66)).
- Reference signer `mkit-sign-se` — Apple Secure Enclave (Swift /
  CryptoKit, P-256) ([#68](https://github.com/officialunofficial/mkit/pull/68)).
- Reference signer `mkit-sign-tpm` — Linux/Windows TPM 2.0 (Rust +
  `tss-esapi`, P-256, behind `tpm2` feature) ([#70](https://github.com/officialunofficial/mkit/pull/70)).
- Reference signer `mkit-sign-ctap` — FIDO2 / WebAuthn roaming
  authenticator (Rust + `ctap-hid-fido2`, Protocol v1.1) ([#71](https://github.com/officialunofficial/mkit/pull/71)).
- `mkit-wasm` crate — WASM bindings for browser / Cloudflare Worker
  consumers, with a multi-algorithm attestation demo site ([#73](https://github.com/officialunofficial/mkit/pull/73)).
- `--external-signer-arg` CLI flag, `attest.external_signer_args`
  config key, and `args=` clause on `--additional-signer` for
  passing argv to subprocess signers ([#69](https://github.com/officialunofficial/mkit/pull/69)).
- Config schema: `attest.secp256k1_key_path`,
  `attest.p256_key_path`, and `[[trust_root]]` table ([#66](https://github.com/officialunofficial/mkit/pull/66)).

### Changed

- `Signer` trait now requires an `algorithm()` method; all in-tree
  implementations updated ([#65](https://github.com/officialunofficial/mkit/pull/65)).
- `verify::TrustRoot` enum gained `Secp256k1PubKeySec1` and
  `P256PubKeySec1` variants ([#65](https://github.com/officialunofficial/mkit/pull/65), [#66](https://github.com/officialunofficial/mkit/pull/66)).
- `ExternalSigner::new()` rejects relative paths (finding H2) ([#63](https://github.com/officialunofficial/mkit/pull/63)).

### Security

Sixteen findings from the comprehensive security review, plus one
post-review external-signer conformance bug ([#63](https://github.com/officialunofficial/mkit/pull/63), [#69](https://github.com/officialunofficial/mkit/pull/69)):

- Critical / wire-shape: `serve` path containment + per-connection
  byte budget (A1, A14); case-insensitive `.mkit` / `.git` rejection
  in tree entries + restore sweep (B2, B3); bounded attacker-
  controlled allocations in delta / index / stash / blame parsers
  (G5, G11, G12, G13); SHA-pinned third-party CI actions (Z4).
- Important: transport hardening — file path-escape guard, SSH
  encoder strictness, HTTP loopback-only + body cap (E7, E8, E9);
  ref-name validation rejects `.lock` suffix and `HEAD` as branch
  (D6); signal-handler `install` documented + `is_shutdown` exposed
  (H1); `ExternalSigner::new` rejects relative paths (H2);
  key-file permissions set on `File` handle, not path (H3); JCS
  predicate full-parse instead of `{...}` boundary scan (H5);
  `repo_lock` distinguishes invalid name from bad length (H6);
  `delta::encode` returns `Result` on `>u32` lengths (H8).
- Hygiene: `.gitignore` patterns for keys / secrets (H7).
- Bugfix: `ExternalSigner` now includes the `algorithm` field per
  SPEC-EXTERNAL-SIGNER §3 — broke conformance with reference
  signers since the protocol shipped ([#69](https://github.com/officialunofficial/mkit/pull/69)).

### Fixed

- `mkit-sign-file` integration test tolerates `BrokenPipe` on stdin
  write — race observed on Linux ([#82](https://github.com/officialunofficial/mkit/pull/82)).
- Various `rustfmt` and `clippy` fixups across the multi-algorithm,
  Secure-Enclave, TPM, and CTAP signer integrations.

## [0.1.0] — 2026-04-24

Initial release.

### Added

- **Content-addressed object store.** BLAKE3-named raw objects stored
  at `.mkit/objects/<dd>/<hex62>`. Atomic writes (temp-file + fsync +
  rename + parent-dir fsync on Unix). Hash verify-on-read. 1 GiB cap
  per object. Idempotent: identical bytes → identical path.
- **Object format v1.** Six object types with a shared prologue
  `[type][MKT1][schema_version=0x01]`: `blob`, `tree`, `commit`,
  `remix`, `chunked_blob`, `delta`. All little-endian, `u64`
  timestamps. Full wire contract documented in `docs/SPEC-OBJECTS.md`.
- **Content-defined chunking (FastCDC v1).** Frozen seed `MKITFCDC`,
  three-mask (`0x1FFFF` / `0xFFFF` / `0x7FFF`) boundary selection,
  16 KiB / 64 KiB / 256 KiB parameter set. Documented in
  `docs/SPEC-FASTCDC.md`.
- **Delta encoding.** Minimal COPY/INSERT instruction stream per
  `docs/SPEC-DELTA.md`. Decoder is attacker-tolerant: result-length
  pre-allocation is bounded against the stream size, so a 9-byte
  header claiming `result_len = u32::MAX` cannot trigger a 4 GiB
  allocation.
- **Packfile format.** `MKIT` magic + version 1 + BLAKE3 trailer,
  base-before-delta ordering, ≤10M entries / ≤4 GiB payload caps.
  Documented in `docs/SPEC-PACKFILE.md`.
- **Refs + index + worktree.** 65-byte ref wire (lowercase hex64 +
  `\n`), CAS variants `any` / `missing` / `match(H)`. Index magic
  `MKIX`, atomic writes. `.mkitignore` glob matcher. Repo lock via
  `std::fs::File::lock_exclusive`. Symlinks pointing outside the repo
  root are rejected during worktree traversal.
- **High-level history ops.** `diff`, `graph`, `merge`,
  `cherry_pick`, `rebase` (with `--abort` / `--continue`), `bisect`
  (with `skip` exclusion set), `blame`, `stash` (save / list / pop /
  drop / show), `restore` (including sparse patterns and full
  worktree materialization).
- **Ed25519 signing (SPEC-SIGNING).** Domain-prefixed BLAKE3 digests:
  `BLAKE3("mkit.commit\x00" ‖ signing_bytes)` and
  `BLAKE3("mkit.remix\x00" ‖ signing_bytes)`. `verify_strict` /
  ZIP-215 semantics — rejects non-canonical `R`, high-`s`, and
  non-canonical public-key encodings so all honest verifiers reach
  the same verdict on a given signature. RFC 8032 known-answer test.
  Keys live at `.mkit/keys/default.key` as the raw 32-byte seed,
  mode 0600 enforced on Unix.
- **Native attestation subsystem (`mkit-attest`).**
  - RFC 8785 JCS canonical-JSON encoder (hand-rolled; the spec's
    member-sort and escape rules don't round-trip through
    `serde_json`).
  - in-toto v1 Statement encoder with commit-subject binding.
  - DSSE envelope encode/decode + PAE builder.
    `attestationId = BLAKE3(envelope_bytes)` (no trailing newline
    — preserves the content-addressing invariant).
  - Signer trait with three implementations: `repo-key` (Ed25519 via
    the commit-signing key), `external` (JSON-over-stdin/stdout
    subprocess for KMS / HSM delegation), `sigstore` (scaffold; full
    Rekor / Fulcio walk to follow).
  - Trust-root registry + per-signature verification; attestation
    store at `.mkit/attestations/<commit-hex>/<keyid-hex>.dsse.json`.
- **Protocol + transports.** Seven-verb `Transport` trait
  (`upload_pack`, `download_pack`, `pack_exists`, `write_ref`,
  `update_ref`, `read_ref`, `list_refs`) with a shared error
  taxonomy, SSH wire framing (`OP_HELLO` first frame, 16 MiB payload
  cap), and retry backoff (5 attempts, 1–300 s exponential).
  Implementations for:
  - `mkit+memory://` — HashMap-backed, for tests.
  - `mkit+file://` — local filesystem, atomic CAS on POSIX via
    `link(2)` for the `Missing` variant.
  - `mkit+http://` / `mkit+https://` — reqwest + rustls, blocking.
    Bearer `MKIT_API_TOKEN` auth, `If-Match` / `If-None-Match` CAS,
    429 / 5xx retried via the shared backoff.
  - `mkit+s3://` — hand-rolled AWS SigV4 signer + R2 endpoints.
    MD5-of-wire ETag CAS. Creds from `MKIT_R2_ACCESS_KEY_ID` /
    `MKIT_R2_SECRET_ACCESS_KEY`.
  - `mkit+ssh://` — delegates host-key checking, `~/.ssh/config`,
    agent integration, and `ProxyCommand` to the system `ssh(1)` via
    `std::process::Command`. No async runtime, no bundled SSH crypto.
- **CLI.** 30 subcommands wired from `mkit-cli` to the library crates:
  `init`, `keygen`, `hash`, `cat`, `tree`, `add`, `rm`, `status`,
  `commit` (with `$EDITOR` / `$GIT_EDITOR` template fallback and a
  `--author` override), `log`, `branch`, `tag`, `checkout` (with
  worktree materialization), `diff`, `verify`, `config`, `remote`,
  `push` / `pull` / `fetch` (transfer full reachable object set, not
  just ref pointers), `clone`, `merge`, `cherry-pick`, `rebase`,
  `bisect`, `stash`, `blame`, `serve`, `sparse-checkout`, `version`,
  `help`. `mkit version` emits exactly `mkit <X.Y.Z>\n` — snapshot
  tested and a CI step asserts the byte-exact contract on every push.
- **Bounded fuzz harnesses.** `cargo-fuzz`-compatible targets for
  `delta::decode`, `pack::PackReader::read`, and
  `serialize::deserialize`. Six guardrails per `docs/FUZZ.md`: ≤100
  iterations, ≤64 KiB input, bounded per-op allocations, 100 ms
  per-iteration wall-clock cap, no unbounded loops, seeded PRNG.
- **Supply chain.** CI matrix on ubuntu-latest + macos-latest:
  `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
  `cargo test --workspace --locked`, rename gate
  (`scripts/verify-rename.sh`), and a `mkit version` byte-exact
  assertion. Weekly `cargo audit` + `cargo deny` (advisories, license
  allow-list, wildcards, sources). Two-pass reproducible-build smoke
  test (SHA256 diff under `-C codegen-units=1 -C strip=symbols`).
  Release workflow cross-compiles four targets (aarch64-apple-darwin,
  x86_64-apple-darwin via cross, x86_64-unknown-linux-gnu,
  aarch64-unknown-linux-gnu), cosign keyless OIDC signatures, and a
  CycloneDX SBOM.

[Unreleased]: https://github.com/officialunofficial/mkit/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/officialunofficial/mkit/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/officialunofficial/mkit/releases/tag/v0.1.0
