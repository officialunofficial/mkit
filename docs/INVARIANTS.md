# Invariants

Properties that must always hold across the mkit monorepo, outside any
single crate or spec. Each entry states the invariant, why it matters, and
what breaks when it is violated. A regression test enforces each one; find
it by the file path listed under "Enforced by".

## Git audit establishes correspondence without a signing key

**Always:** imported graph edges and translated unsigned fields are derived
from retained Git bytes and checked under the pinned public key. A head's
provenance claim must match its exact subject, ref, source and versions.

**Because:** valid signatures on unrelated twins do not authenticate a mutable
Git-to-mkit mapping cache.

**If violated:** swapped mappings or unrelated attestations can pass an audit.

**Enforced by:** `rust/crates/mkit-cli/tests/git_import_integration.rs` mapping
swap, unrelated attestation and private-key removal regressions; the full
45-test integration suite passes. Golden translated bytes remain unchanged.

## File equality survives valid representation changes

**Always:** different file object IDs compare by verified byte streams; modes
remain separate. Restaging identical content keeps the staged ID only when its
representation is valid for the new entry type; symlink targets use a single
Blob. Chunk failures remain errors, including after the first differing byte.

**Because:** an inline Blob, fixed-size manifest and CDC manifest may describe
the same bytes with different immutable object identities.

**If violated:** clean worktrees appear modified, restaging changes identity,
and merge or overwrite decisions depend on chunk boundaries. Retaining a chunked
file object for a symlink produces an index that cannot be committed.

**Enforced by:** core `worktree::blob::equality_tests`,
`ops::diff::tests::equal_content_different_chunk_layout_is_clean`, and
`rust/crates/mkit-cli/tests/content_representation_integration.rs`. Comparison
holds at most one chunk per side plus manifests; rename fingerprints are
memoized for one diff and confirmed by byte comparison.

## Requested transport identities are checked before effects

**Always:** fetched packs and metadata match their requested keys; shard
manifests name the requested pack before reconstruction. Sparse selections are
derived from canonical Tree witnesses verified against independently known IDs.

**Because:** internally valid content can still be a substituted response.

**If violated:** transports can publish unrequested objects or incomplete paths.

**Enforced by:** packmap substitution tests, HTTP/S3 shard suites, core sparse
v2 mutation/completeness tests and `rust/tests/golden/sparse/response_v2.bin`.

## Shard worker bounds do not delay an available quorum

**Always:** HTTP and S3 shard downloads collect completed responses while
admitting workers under the shared process-wide limit. Reaching quorum or the
failure threshold cancels outstanding work without waiting for redundant shards.

**Because:** bounded worker admission can otherwise block the collector even
after enough shard responses have arrived to reconstruct the pack.

**If violated:** slow redundant requests delay successful downloads until their
network timeouts expire.

**Enforced by:** HTTP and S3 `shard_quorum_does_not_wait_for_extra_worker_slots`
regressions, which gate redundant responses until after the quorum returns.

## Every ref mutation participates in its lock protocol

**Always:** local Any, Missing, Match and deletion take the same full-ref guard.
The order is registry, worktrees, history, then ref mutation locks; peers within
a class use canonical order. File transport serializes all condition variants
within its separate transport lock domain.
Ref lock filenames use a fixed-length digest of the complete ref identity,
including its namespace, so valid long ref names remain writable.

**Because:** an unconditional writer can invalidate a conditional writer's
observation just as another CAS writer can.

**If violated:** reported successful updates lose writes or expose invalid
history publication states.

**Enforced by:** core refs and file-transport contention regressions, CLI
history lifecycle and publication retry tests, and core long-ref mutation and
lock-identity regressions.

## History evidence binds ancestry, generation and context

**Always:** a trusted proof describes the canonical first-parent chain for the
expected repository, ref, tip and generation. Pending durable intents pin both
previous and target tips as GC roots even without the history feature enabled.

**Because:** a mutation journal is not an ancestry proof, and publication spans
multiple durable files.

**If violated:** rewinds, resets, ABA or interrupted writes can issue misleading
proofs or let GC remove objects needed to recover.

**Enforced by:** `history/ancestry.rs` chain/context/generation and six-boundary
failure tests, and core GC intent-root tests. Current descriptors establish
local trust only; snapshots/reconstruction cost O(chain length), capped at one
million leaves. Only canonical ancestry snapshots are supported.

## Staging selections are durable; stat caches are disposable

**Always:** current index data preserves path, mode, staged object and deletion
intent. Only checksummed v3 is accepted. Unknown, empty or corrupt index data
stops operations that rely on staging, including GC; it is never converted or
rebuilt from working files.

**Because:** HEAD and the working file cannot reconstruct a partial selection.

**If violated:** recovery silently replaces staged A with working B or garbage
collect the only copy of staged content.

**Enforced by:** current index checksum/round-trip and unsupported-version
rejection tests, current golden fixtures, and GC no-sweep-on-corruption coverage.

## Authenticated write effects and replay state commit together

**Always:** auth v2 verifies configured audience, decoded repository, procedure,
content commitment, times and nonce before effects. Retries keep their operation
identity. SQLite adapters commit mutable effects, quota and replay response in
one transaction; immutable publication records a recoverable reservation first.
New quota- or rate-limited operations pass admission before allocating a replay
record; rejection leaves replay storage unchanged. Existing reservations and
saved results remain retryable without another quota charge.

**Because:** signature validity alone cannot prevent cross-service replay or
repeating an effect after a crash.

**If violated:** a captured request can move a ref back, toggle a reaction twice,
restore an old name or charge duplicate upload quota.
Reserving rejected operations also lets throttled authors keep growing replay
storage after exhausting their write budget.

**Enforced by:** shared core canonical/context tests; Connect retry tests;
actual local Workers regressions in `apps/{repo-worker,vcs-worker,keys-worker}/tests/`;
quota and rate admission in `apps/mkit-worker-common/tests/quota_ledger.mjs`;
web/spammer envelope tests. Keys failure injection after name and result writes
rolls back both; saved results survive a full Worker restart. Production builds
omit `test-faults`. Only auth v2 is accepted. Names use SQLite exclusively.

## External signer capabilities precede signing material

**Always:** the external signer returns compatible protocol, algorithm,
message-size and interaction capabilities before receiving SignRequest bytes.
The request uses a supported key form selected from that response, including
opaque handles for hardware signers with a configured default key.
All subprocess I/O retains frame and wall-clock bounds.

**Because:** advertising capabilities after signing cannot enforce them.

**If violated:** an incompatible signer can perform a request before rejection.

**Enforced by:** external signer no-sign-on-incompatible-handshake regressions,
opaque-handle request-frame and unsupported-key-form regressions, PIN/timeout
subprocess tests and the bundled file signer's end-to-end test.

## Dependabot ecosystem matches the lockfile format

**Always:** every directory with its own lockfile has a `.github/dependabot.yml`
update entry whose `package-ecosystem` matches that lockfile's format
(`cargo` for `Cargo.lock`, `bun` for `bun.lock`, `npm` for `package-lock.json`).
Every composite GitHub Action under `.github/actions/*/action.yml` has its
own `github-actions` entry, because a `directory: "/"` entry only scans
`.github/workflows/`.

**Because:** Dependabot edits only the manifest for the ecosystem it thinks
it is running. An `npm` entry pointed at a `bun`-only directory edits
`package.json` but never touches `bun.lock`. CI installs with
`bun install --frozen-lockfile`, which rejects a manifest whose lockfile did
not change with it.

**If violated:** every PR Dependabot opens for that directory fails CI on
the frozen-lockfile install step and gets closed unmerged, silently, on a
recurring weekly schedule. See `apps/web`'s Dependabot PRs #921, #922, #923,
#931, and #934 — all closed unmerged for exactly this reason before this
invariant was enforced.

**Enforced by:** `scripts/check-dependabot-coverage.sh`, run by the
"Meta: actionlint" workflow on any change to `.github/dependabot.yml`,
`.github/workflows/**`, or `.github/actions/**`.

## Single crypto-stack version across workspaces

**Always:** `ed25519-dalek` and `sha2` are pinned to the same
Cargo-semver-compatible version (for a `0.y.z` crate, `y` is the breaking
component; for `x.y.z` with `x >= 1`, `x` is) in every Cargo workspace that
declares them: `rust/`, `contrib/signers/`, and the `apps/*-worker`
standalone packages.

**Because:** several crates independently re-verify signatures/digests the
same byte-for-byte way another crate already does — `mkit-wasm`'s raw
Ed25519 exports vs. `mkit-core::sign`, and every `apps/*-worker`'s
write-envelope strict-verify vs. `mkit-core`'s own `verify_strict` call —
and the golden-vector and cross-impl-parity tests (e.g.
`mkit-wasm::ed25519::cross_impl_parity_with_dalek`,
`mkit-keystore`'s `*_matches_golden_vectors`) assert that stays true. A
drifted major/breaking version of the same crypto crate across workspaces
can silently diverge in wire-visible behavior (ed25519-dalek 2->3 dropped
the `std` feature and moved error types to `core::error::Error`; a future
bump could change verification semantics) with nothing forcing every
workspace to move together.

**If violated:** nothing fails to compile — each workspace has its own
lockfile, so two incompatible versions of the same crypto crate can coexist
silently. A behavior difference between them (a stricter/laxer signature
check, a different digest padding) would only surface as a hard-to-trace
cross-service inconsistency, not a build error.

**Enforced by:** `scripts/check-crypto-stack-version.sh`, run by the
"Meta: crypto-stack version" workflow on any change to a `Cargo.toml` under
`rust/`, `contrib/signers/`, or `apps/`.

## A live `mkit serve` is detectable by local worktree commands

**Always:** every live server process on a root holds a **shared** kernel
lock (`mkit_core::repo_lock::acquire_shared`) on `<common_dir>/serve.lock`
for its entire lifetime: `mkit serve <path>` (stdin SSH-frame, its only
mode) and `mkit-server serve --repo-root <path>` (HTTP and `mkit+enc://`
listeners; it also holds `<common_dir>/server.lock` exclusively, so one
`mkit-server` serves a root at a time). Every command that acquires `worktree.lock`
or `worktrees.lock` (`mkit-cli`'s `acquire_worktree_lock` /
`acquire_worktrees_registry_lock`) immediately probes that same
`serve.lock` non-blocking-exclusive (`mkit_core::repo_lock::probe_exclusive`)
and, if it finds the lock busy, prints a warning to stderr naming the
served root before proceeding. The one exclusive holder: at startup
`mkit serve` tries `serve.lock` exclusively without waiting, and only
while it holds it (no other server is up) sweeps the temp files crashed
uploads left in `packs/` (`.<hex>.tmp.<pid>.<seq>`, at least an hour
old), then takes it shared as above.

**Because:** `mkit-transport-file`'s only lock (`<root>/.mkit/refs/.lock`)
serializes file-transport instances against *each other*, not against
local worktree mutation or `gc` (SPEC-CONCURRENCY §3.1). Running `mkit
gc` or a worktree-mutating command directly against a root a live `mkit
serve` is also operating on is unsupported and uncoordinated; without
this invariant, nothing distinguishes that misuse from an ordinary,
safe invocation, and the failure (a `gc` sweep racing a concurrent
push's object write, or a lost ref update) surfaces only as
after-the-fact corruption with no diagnostic pointing at the cause.

**If violated:** a `gc` can silently sweep objects a concurrent `mkit
serve` client just uploaded, or a local commit/checkout can silently
lose a race against a client push — both without any warning ever
appearing, leaving an operator no reason to suspect the concurrent-serve
misconfiguration until data is already gone. This is detection only,
not coordination: a direct `mkit push mkit+file:///path` (bypassing
`mkit serve`) and a `serve` that starts *during* an already-in-flight
local critical section both remain undetected — see SPEC-CONCURRENCY
§3.1 for the full statement of what this warning does and does not
cover.

**Enforced by:** `mkit-cli/tests/serve_guard.rs`;
`mkit-server-native/tests/server_basics.rs`
(`serve_lock_is_held_while_running`).

## Single commonware release train across every manifest and lockfile

**Always:** every `commonware-<name>` dependency — in `rust/Cargo.toml`,
every `rust/crates/*/Cargo.toml`, `rust/fuzz/Cargo.toml`,
`contrib/signers/Cargo.toml`, and the `apps/*-worker` manifests — pins the
exact same version string (e.g. `=2026.9.0`, not merely a compatible
range), AND every `Cargo.lock` in those same trees that contains a
`commonware-*` package resolves to that same version.

**Because:** the commonware crates (`-storage`, `-cryptography`,
`-runtime`, `-coding`, `-codec`, `-parallel`, `-utils`, `-stream`,
`-invariants`) ship as one coordinated release; mkit's on-disk formats
(the ancestry MMB, the BLS threshold derivation) and wire
compatibility depend on the exact same version being linked everywhere a
crate touches them. A manifest bump without a matching `cargo update` in
every workspace leaves the *text* aligned while the *lockfile* — what
actually gets compiled — stays on the old train, silently defeating the
single-version intent this file's `check_crate` (ed25519-dalek/sha2)
already establishes.

**If violated:** nothing fails to compile — each workspace has its own
lockfile, so `rust/` can be on `2026.9.0` while `contrib/signers/` is still
locked to `2026.7.1`, undetected until an on-disk format or golden-vector
test run against the stale workspace disagrees with one run against the
bumped one.

**Enforced by:** `scripts/check-crypto-stack-version.sh`'s
`check_commonware_family`, run by the "Meta: crypto-stack version"
workflow (trigger paths include `**/Cargo.lock` under `rust/`,
`contrib/signers/`, and `apps/*`, not just `Cargo.toml`).

## commonware `Strategy` cannot be spied on from outside commonware-parallel

**Always:** `crates/mkit-core/src/pack_shard.rs`'s test suite does not
attempt to assert that a caller-supplied `commonware_parallel::Strategy`
was *invoked* by the encode/decode core (only that a real, non-default
strategy compiles against the generic entry points and round-trips
correctly — see `round_trip_with_explicit_parallel_strategy`).

**Because:** commonware-parallel 2026.9.0 made `Strategy` impossible to
implement from outside the `commonware-parallel` crate itself:
`Strategy::manual` must return a `Manual<Self>`, and `Manual`'s fields are
private with no public constructor left (`Manual::new` was removed). The
`CountingStrategy` spy this test module used to define — an `impl
Strategy` that counted `fold_init` calls to prove the supplied strategy
was genuinely exercised, not merely accepted and discarded — can no
longer be written.

**If violated:** re-adding an external `impl Strategy` (e.g. to restore
the invocation-count assertion) will not compile against the pinned
commonware-parallel train; if it is somehow worked around, treat the
resulting test as unable to prove what its name claims.

**Enforced by:** `crates/mkit-core/src/pack_shard.rs`'s
`round_trip_with_explicit_parallel_strategy` (compiles + round-trips a
real `Rayon` strategy) as the remaining guard; the comment block above it
records why the invocation-count assertion cannot be rebuilt.

## Windows is not a build, test, or release target

**Always:** no workflow, action, `justfile` recipe, crate manifest, or
installer targets Windows — no `windows-latest` / `pc-windows-msvc` CI
runner, no `backend-windows-credential` / `windows-credential` keystore
feature, no `install.ps1` or Scoop packaging, and no
`[target.'cfg(windows)'.dependencies]` stanza in any `Cargo.toml`.
`BackendKind` has no Windows Credential Manager variant.

**Because:** commonware-runtime 2026.9.0's storage-sync path calls
`libc::sync()` on every non-Linux target (`rust/crates/mkit-transport-enc`
depends on `commonware-runtime` unconditionally, and `mkit-core`'s
dev-dependencies pull it in
too) — `libc::sync()` does not exist on `x86_64-pc-windows-msvc`, so the
workspace and its test suite no longer build there. Maintaining a Windows
CI/release leg that cannot actually build or test the workspace would ship
an untested binary, so Windows was dropped as a supported target (MKIT-6)
rather than worked around. Windows users run mkit under WSL, which uses
the Linux binary.

**If violated:** a reintroduced Windows CI leg goes red on every PR (the
workspace fails to build there); a reintroduced Windows release leg ships
a binary no test ever exercised; a reintroduced
`backend-windows-credential` feature reopens a semver-breaking
`BackendKind` variant on a published crate (`mkit-keystore`) without the
required major bump.

**Enforced by:** `scripts/check-no-windows-target.sh`, run by the
"Meta: actionlint" workflow on any change to the CI workflows, `justfile`,
crate manifests, `install.sh`, or the web app's installer-staging scripts.
`mkit-keystore`'s `windows_credential_backend_name_is_not_recognized` test
(`crates/mkit-keystore/src/lib.rs`) pins that `"windows-credential"` is an
unrecognized `BackendKind`/`KeyRef` backend string, not a fail-closed one.

## wasm32 dependency graphs contain no C-toolchain crates

**Always:** the `wasm32-unknown-unknown` normal-dependency graphs of
`mkit-wasm`, `apps/repo-worker`, `mkit-server`, `mkit-server-worker` and
`apps/vcs-worker` contain none of `blst`,
`zstd-sys`, `commonware-runtime` or `commonware-storage`; `mkit-wasm`'s also
contains no `tokio`. Each crate depends on `mkit-core` with
`default-features = false`, which keeps `pack-zstd` (and so `zstd-sys`) out.
The same holds for `mkit-core` built with `--no-default-features
--features pack-ruzstd`, the pure-Rust decode-only zstd backend a Workers
build uses to read v2 packs: that graph must contain `ruzstd` and none of
the crates above. `mkit-wasm` stays raw-only (SPEC-DISCLOSURE §7.2), so
its graph must not contain `ruzstd` either until it opts in.

**Because:** none of those crates build for `wasm32-unknown-unknown`.
`mkit-wasm` ships to browsers, `apps/repo-worker` runs on Cloudflare
Workers, and `mkit-server` is the runtime-agnostic core that the Workers
server adapter builds on (PRD MKIT-29 §5.1). Cargo unifies features per
dependency graph, so one manifest line that re-enables a default feature
silently pulls a C library into every wasm build downstream.

**If violated:** the wasm32 builds fail, often only in a later, slower CI
job (wasm-pack, `worker-build`), or on a machine without the C toolchain
the native build happened to have. For `mkit-server`, a Workers deployment
could no longer build the server at all.

**Enforced by:** `scripts/check-wasm-dep-graph.sh` (a `cargo tree` check
per crate, including the `mkit-core` `pack-ruzstd` graph, which must
contain `ruzstd`) and the `cargo check --target wasm32-unknown-unknown`
steps for `mkit-wasm` and `mkit-server` (and the wasm32 build of
`mkit-server-worker`), all run by `just ci-scripts` (part of `just ci`);
cloudbuild/ci.yaml runs the script and the `mkit-server*` wasm32 builds
on `main` and PRs to it (WP-M0-20).

## The default `mkit` CLI is server-free

**Always:** the normal dependency graph of `mkit-cli` with its default
features, on every target, contains no `axum`, `mkit-server-native`,
`rusqlite` or `libsqlite3-sys`; it enables no hyper `server` feature, no
hyper-util `server*` feature and no connectrpc `server` or `axum` feature;
and it has `mkit-server` (the engine of `mkit serve`) with only the `ssh`
and `fs` features. `mkit serve` builds no async runtime: it runs the ssh
session under `futures::executor::block_on`, and its code names no tokio.
tokio itself is allowed: it is the runtime of the Connect and reqwest
*clients* in the default graph, and `mkit-server` uses only `tokio::sync`.

**Because:** the CLI is what every user installs (`cargo install
mkit-cli`, the release archives). The HTTP and `mkit+enc://` servers, the
`SQLite` metadata store and their dependencies belong to the separate
`mkit-server` binary (PRD MKIT-29, decision Q1). A server stack in the CLI
graph grows the published crate's supply chain, its build time and its
binary, and invites serving code paths the CLI was never reviewed for.

**If violated:** the published `mkit` compiles an HTTP server, a C
`SQLite` build or a second async stack that no CLI command needs; the
release check (`scripts/check-release-artifact-features.sh`) then fails
only at release time, where this check fails at the PR.

**Enforced by:** `scripts/check-cli-baseline.sh` (a `cargo tree` model of
the graph plus a grep of `commands/serve/`), run by `just ci-scripts`
(part of `just ci`), `just ci-server` and cloudbuild/ci.yaml; the release build's real compiler artifacts are
checked by `scripts/check-release-artifact-features.sh` against
`scripts/release/mkit-packages.golden`.

## Every storage backend passes the storage-contract suite

**Always:** every `NamespaceStore` and `BlobStore` a server can be deployed
on passes `mkit-server-conformance`'s storage suite (`storage_suite!`),
including the durability cases (`dur.*`: cancellation mid-apply,
crash/restart without shutdown, portable export/import) and the `NotAfter`
commit-deadline cases (`kv.not_after_*`), and declares each case it skips,
for a capability the backend lacks (`StoreCapabilities`, or a reopen that
an in-memory `SQLite` database cannot do). A declared skip that starts
passing, or an undeclared one, fails the run.

**Because:** `mkit-server`'s pipeline is written once against the storage
traits (PRD MKIT-29 §5.1) and trusts their contract: an atomic batch, a
missed deadline that writes nothing, a crash that leaves either the old or
the new state. A backend that bends one of these on a single path
(a partial batch on `SQLITE_FULL`, a blob visible before its final chunk)
corrupts refs or quota only in the deployment that uses it, where no
pipeline test looks.

**If violated:** a ref update half-applies or survives its own deadline,
replay or quota rows diverge from the effects they guard, or an upload is
readable before it is complete, on one backend only.

**Enforced by:** one test binary per backend in
`rust/crates/mkit-server-conformance/tests/`: `memory_backends.rs`
(full-capability and `RefsOnly` memory stores, `MemoryBlobStore`),
`fs_backends.rs` (`FsLayoutStore`, `FsBlobStore`), `sqlite_backends.rs`
(`SqlKvStore` over `RusqliteConn`, file and in-memory) and
`s3_backends.rs` (`S3BlobStore` against the in-repo fake S3); the Workers
stores (`DoNamespaceStore` over a simulated Durable Object, `R2BlobStore`)
in `rust/crates/mkit-server-worker/tests/conformance.rs`. The suite's own
mutation tests (`suite_selftest.rs`) prove each case fails the store bug it
targets. All run in the workspace nextest (`just ci`, cloudbuild/ci.yaml).
Simulated Durable Objects cannot show placement, Cloudflare's limits or
point-in-time recovery; the M1 staging runs (WP-1.20) cover those.

## M1 Connect surfaces remain explicit stubs until implementation

**Always:** until their implementing WPs land, the four new discovery and
upload RPCs return `unimplemented` ("not implemented yet"). Ref deletion,
advance ticket ids, upload ticket tokens and ref-list continuation tokens
are rejected before validation or pipeline writes. `page_size` is ignored
and listings end with an empty `next_page_token`.

**Because:** the new RPC paths currently bypass authentication because
`Procedure::from_connect_path` does not recognise them. WP-1.9 and WP-1.11
must add authenticated procedures before enabling upload behavior;
WP-1.6 must make discovery explicit while keeping it public by spec §2.1.

**If violated:** a new field can silently invoke legacy behavior, or an
unauthenticated upload handler can mutate state.

**Enforced by:** `mkit-server/tests/connect_dispatch.rs`'s `m1_*` tests
and the TODO and SECURITY comments in `connect/service.rs`. Implementing
WPs replace the relevant stub assertions with their behavior and auth tests.

## The native server and the reference Worker pass the black-box wire suite

**Always:** every `mkit.transport.v1` server mkit ships passes
`mkit-server-conformance`'s wire suite (`mkit-server-conformance wire`)
over the network, with no divergences (a divergence must be declared with
its justification in the test, and fails the test once the case passes):
`mkit-server` on FS + `.mkit` layout (bearer), FS + SQLite and S3 + SQLite
(auth v2), both in-process and as the real binary, and `apps/vcs-worker`
under `wrangler dev`. The suite speaks raw Connect with its own client, so
it checks the wire, not mkit's client library.

**Because:** the servers share one pipeline, but each binding (axum,
Workers fetch, the storage adapters) can still change status codes,
compression, streaming or limits on its own. "Nothing changes on the wire"
(PRD MKIT-29 §8, M0 exit) is only checkable against a fixed, black-box
suite; a client that happens to tolerate a change would hide it.

**If violated:** a deployment answers with a different error code, drops a
precondition or a limit, or buffers a stream where the spec requires it to
stream, and existing clients or third-party implementations break against
one server only.

**Enforced by:** `rust/crates/mkit-server-native/tests/wire_fs_layout_bearer.rs`,
`wire_fs_sqlite.rs`, `wire_s3_sqlite.rs` and `wire_binary.rs` (the
spawned binary), and `rust/crates/mkit-server-conformance/tests/baseline_pipeline_memory.rs`
(the pipeline over memory stores, plus store mutants each case must catch),
in the workspace nextest (`just ci`, `just ci-server`, cloudbuild/ci.yaml);
`scripts/vcs-worker-conformance.sh` for `apps/vcs-worker`, run by
`.github/workflows/workers.yml`'s `vcs-worker-conformance` job (main and
PRs to main only; during the MKIT-29 epic it runs locally at each
milestone boundary).

## Both zstd backends accept exactly one frame per entry

**Always:** a `0x03`/`0x04` entry's payload after `uncompressed_len` is
exactly one RFC 8878 Zstandard frame (SPEC-PACKFILE §3.3). The C backend
(`pack-zstd`) and the pure-Rust backend (`pack-ruzstd`) both reject a
skippable or legacy frame magic, a second concatenated frame and any
trailing byte, with `PackError::ZstdDecompress`. Both apply the same §3.3
bomb guards (claim ≤ `MAX_RAW_OBJECT_SIZE` before decoding, output bounded
to the claim, exact length re-check). The pure-Rust path does not
pre-allocate the claim and reads out at most `claim + 1` bytes, but a
frame that decodes to its claim peaks at about 3× the claim (C: about
1×): ruzstd's ring buffer rounds up to a power of two and holds up to one
window of pending output, and `read_to_end` grows the output by doubling
(a 512 MiB claim measured about 1.55 GiB RSS). A decoded-size budget set
by the caller is WP-4.8a's. The pure-Rust path also
checks what `ruzstd` skips and the C decoder enforces: the declared
content size against the claim and the decoded length, the content
checksum, the reserved descriptor and sequence-mode bits, and the
block-size bound for windows under 128 KiB. When both features are on,
the C decoder serves reads.

**Because:** a pack must mean the same objects on the native server (C)
and a Workers isolate (`ruzstd`). A frame one runtime accepts and the
other rejects splits pushes, fetches and indexed state between them.

**If violated:** a push accepted on one runtime is rejected on the other,
or a runtime decodes bytes the spec forbids (a second frame's content).

The hand-written frame parsing assembles header fields in `u64`, never
`usize`, so it behaves the same on 32-bit wasm32 as on 64-bit native.

**Residual divergence (documented, not closed):** the two decoders agree
on every frame an encoder produces (differential proptest over
`PackWriter` output, C-encoded fixtures) and on the curated adversarial
table. On *malformed* frames they do not fully agree. Fail-closed on
`pack-ruzstd` (it rejects, C accepts): frames declaring a window above
`max(claim, 8 MiB)`, windowed frames under 128 KiB whose output exceeds
the window (legal for raw blocks and for multi-block frames), and
corrupt entropy-coded sections the C one-shot decoder tolerates. Fail-open
(it accepts, C rejects) and both-accept-different-bytes cases also exist
for a small share of corrupted frames, in Huffman/FSE table internals
that no cheap check reaches; the reference `zstd` CLI rejects those
frames too. Over 850k mutated frames: 134 accepted only by `pack-ruzstd`,
2,580 accepted only by C, 4 accepted by both with different bytes, no
panics. The WP-4.1 brief called the first class "not tolerable"; it is
accepted as this documented residual because no consumer enables
`pack-ruzstd` yet and object ids are content-derived. Integrity is
unaffected: decoded bytes must parse as a canonical object and are stored
under their own content id, so no runtime can accept wrong content under
a given id. The divergence can only change which objects, if any, a
crafted pack yields on each runtime.

**Consumers MUST:** a server that accepts a pushed pack through
`pack-ruzstd` MUST NOT serve that pack's `0x03`/`0x04` frames verbatim to
other clients unless the reference (C) decoder decodes them to the same
bytes the server indexed (both decoders can accept a frame yet produce
different bytes). Otherwise it MUST serve server-derived bytes instead:
raw v1 entries, or frames the server re-encoded itself. No consumer may assume two runtimes derive the same
object set from the same client-supplied compressed frames. Owners:
WP-4.7 (indexed ingestion) and WP-4.8 (Workers verification), which
enable `pack-ruzstd` first.

**Enforced by:** `mkit_core::pack::zstd_tests` (`c_backend_enforces_one_frame`,
`ruzstd_enforces_one_frame`, `ruzstd_rejects_claims_before_or_at_the_cap`,
`ruzstd_rejects_huge_window_frame`,
`ruzstd_decodes_4_and_5_byte_literals_headers`,
`ruzstd_enforces_reserved_bits_and_block_size`, and under
`--all-features` the differential `backends_agree_on_adversarial_frames`,
`backends_agree_on_bit_flipped_frames`,
`backends_agree_on_reserved_sequence_mode_bits`,
`window_divergences_are_fail_closed`,
`backends_agree_on_committed_v2_fixtures` and
`ruzstd_matches_c_on_writer_output`), plus
`golden_pack::pack_v2_fixtures::pack_v2_fixtures_decode_without_c_zstd`
over `rust/tests/golden/pack-v2/`, the `pack-ruzstd`-only nextest run in
`just ci`, and `scripts/wasm-ruzstd-check.sh` (the same fixtures decoded
on a real wasm32 target by `mkit-core-wasm-check`, in `just ci-scripts`).

## Hosted workspaces separate public projects from owner execution

**Always:** workspace files and signed versions are public; conversation messages,
current task details, and PTY access require the owner's session. Writes require
an exact, unexpired auth-v2 signature. The browser uses a saved PRF passkey identity;
its signing seed never leaves the browser. The server holds a separate agent key
whose owner-signed grant must remain valid for new execution and version publication.

**Because:** public remixing must not disclose private prompts or give visitors
shell access under another person's delegated identity.

**If violated:** a public link can leak conversations or execute commands without
owner authorization; replaying a request can affect an unrelated later task.

**Enforced by:** `apps/workspace-worker/src/auth.test.ts`,
`apps/workspace-worker/src/workspace.integration.test.ts`, and the workspace client
identity tests under `apps/web/src/components/workspace/`.

## Hosted task completion publishes a recoverable signed version

**Always:** only a completed, currently authorized agent task publishes its new
signed version with its completed status and saved conversation snapshot. Failed
or cancelled tasks retain captured draft files without claiming completion.
Captures cannot overwrite another workspace generation. A worker restart does
not replay shell commands whose outcome is uncertain.

**Because:** the browser can close while the agent works, and container lifetime
is independent of the project's durable files and versions.

**If violated:** users lose completed work, see a completed task with no version,
or execute a command twice during recovery.

**Enforced by:** `apps/workspace-worker/src/workspace-state.test.ts`,
`apps/workspace-worker/src/workspace-runner.test.ts`, and
`apps/workspace-worker/src/sandbox-files.test.ts`.

## Browser login and signing authority have separate lifetimes

**Always:** one shared session query and Account region represent login on every page. A refresh can preserve the HttpOnly login cookie, but cannot recover or persist a signing seed. Locking signing preserves the login; sign-out revokes the server session and clears private query and mutation caches. Workspace reads remain disabled during logout, and late responses cannot replace another identity's state. Workspace activation never issues a login cookie.

**Because:** page navigation and cache reuse must not change identity or revive access after sign-out. Public recovery metadata is safe to persist; signing keys and private workspace state are not.

**Enforced by:** `apps/web/src/components/auth-provider.test.tsx`, workspace query/editor tests, `apps/workspace-worker/src/browser-session.test.ts`, workspace integration tests, and `bun run verify:auth` in `apps/web`.

## A workspace version saves one coherent project state

**Always:** a batch save checks every draft's expected file hash before publishing any edit or version. A conflict preserves browser edits and requires explicit review against current content. Terminal working changes and accepted drafts become one named version. Restore appends a new version and retains saved history.

**Because:** a project version must not silently combine stale edits or leave half a batch applied.

**Enforced by:** workspace worker version-edit integration tests, file-editor conflict tests, and workspace save orchestration tests.

## Browser drafts belong to the authenticated session

**Always:** drafts stay in memory, survive route remounts and signing locks, and clear on logout or session replacement. Explicit logout asks before discarding drafts. Current file query keys include content hashes so terminal captures cannot leave cached contents stale.

**Enforced by:** workspace draft-store, Account, auth-provider, and workspace query tests.

## BMT inclusion-proof bytes and sibling selection match commonware exactly

**Always:** `mkit_core::merkle::Proof`'s wire bytes (`u32 BE leaf_count ‖
varint(n) ‖ n × 32-byte digest`) and its level-major, self-duplicate- and
already-proven-sibling-omitting selection rule are byte-identical to
`commonware_storage::bmt::Proof` at the pinned `2026.9.0` train, for
single, range, and multi-leaf proofs alike — both directions: mkit
decodes and accepts upstream's proof bytes, and upstream decodes and
accepts mkit's.

**Because:** SPEC-MERKLE-OBJECTS §5.7 makes this byte-identity a
normative compatibility promise, so a commonware-based verifier (for
example, makechain) can decode and verify an mkit proof with the
upstream type directly, applying only mkit's outer type-domain wrap
(`wrap_id`) on top. mkit cannot depend on `commonware-storage`'s `bmt`
module directly for this (it drags in `commonware-cryptography`'s
unconditional `blst` C dependency, which does not build for
`wasm32-unknown-unknown` — see `merkle.rs`'s module docs and issue
#843), so the construction is vendored and the byte-identity claim has
no compiler to enforce it.

**If violated:** a proof mkit produces would fail to decode, or would
decode but fail to verify, against an otherwise-correct commonware-based
verifier (and vice versa) — silently breaking cross-implementation
verification with no local test failure, since every mkit-only
round-trip test would still pass.

**Enforced by:** `mkit_core::merkle::tests::proofs_match_commonware`
(native-only, dev-dependency on `commonware-storage`/`commonware-cryptography`),
which builds many randomised trees and single/range/multi position sets,
asserts mkit's encoded bytes equal upstream's `commonware_codec::Encode`
output, cross-decodes each side's bytes with the other's type, and
confirms both verifiers reject a mutated proof (flipped sibling byte,
dropped/added sibling, wrong `leaf_count`).

## Disclosure verification is against object ids only

**Always:** every check `mkit_core::verify` performs — a path step, a
chunk, a byte range — is stated against an authenticated object id
(a commit id, a step's `child_id`, a `ChunkedBlob`/chunk id). A v2
bundle carries a bare inner root on each step and chunk header; that
field is wrap-checked against the trusted id (`domain_digest(TYPE_DOMAIN,
inner_root) == expected_id`) **before** it is used for anything, then
cross-checked against the proof fold. No verification step ever treats
a bare inner root, a caller-claimed path string, or an unauthenticated
length/offset as a trust anchor.

**Because:** an inner root is not type-distinct (SPEC-MERKLE-OBJECTS §2),
so accepting one directly would let a `Tree` proof pass for a
`ChunkedBlob` id or vice versa; and a caller-claimed path or offset that
was never itself checked against a proof is exactly the kind of
unauthenticated metadata a disclosure bundle exists to replace with a
proof.

**If violated:** a verifier could be tricked into accepting content at
the wrong path, or into reporting an offset/length nothing in the bundle
actually proves — silently, since the disclosed bytes themselves might
still be genuine content from *somewhere* in the repository, just not at
the claimed location.

**Enforced by:** `mkit_core::verify::tests` (`verify_path_rejects_*`,
`verify_chunk_with_meta_bounds`, `commit_id_mismatch_is_rejected`) and
`rust/tests/golden/disclosure/`'s negative vectors (swapped steps, a
wrong-position proof, a forged `ChunkedBlob` meta pair) — SPEC-DISCLOSURE
§4 states this as a numbered MUST at every dispatch point.

## Declared disclosure inner roots wrap and match the proof fold

**Always:** for every v2 disclosure `Step` and chunk header,
`domain_digest(TYPE_DOMAIN, inner_root)` equals the parent Tree id or
ChunkedBlob leaf id, and the proof folds to exactly that declared
`inner_root`. Version byte `1` is rejected.

**Because:** a commonware-native verifier runs upstream
`verify_element_inclusion` / `verify_multi_inclusion` against the
declared root. Without wrap-check-first, a prover could substitute any
tree whose proof verifies against a forged root. Without the fold
cross-check, a bundle could declare a wrap-correct root while attaching
a proof built for a different tree.

**If violated:** an external verifier that trusted the field would
accept content from the wrong tree, or mkit and a commonware-native
verifier would disagree on the same bundle.

**Enforced by:** `rust/crates/mkit-core/tests/native_commonware_disclosure.rs`
(every accept golden verified with only bundle fields, upstream
`commonware_storage::bmt::Proof`, and `hash::domain_digest`; the three
v2 negatives fail at wrap or upstream verify) and
`rust/tests/golden/disclosure/neg_inner_root_forged.*`,
`neg_inner_root_fold_mismatch.*`, `neg_bundle_version_1.*`.

## Disclosed absolute offsets require a complete length-proof set

**Always:** `DisclosedPayload::Range::absolute_offset` is `Some(...)`
only when either the leaf is a plain `Blob` (nothing to sum) or the
disclosed chunk is index 0 (nothing precedes it), or `chunk_len_proofs`
verifiably covers exactly the index set `0..index` with no gaps and no
duplicates. Any other shape of `chunk_len_proofs` — a gap, a duplicate,
an index `>= index`, or one entry that fails to verify — is a typed
[`VerifyError::IncompleteLengthProofSet`], never a silent `None`. A
*non-empty* `chunk_len_proofs` on a chunk-index-0 range, or on a plain
`Blob` leaf, has nothing preceding it to describe and is rejected
outright as `VerifyError::UnexpectedLengthProofs`, never silently
ignored either.

**Because:** a partial or malformed length-proof set does not sum to a
value that means anything; treating it as "absent" (`None`) rather than
rejecting it outright would let a caller silently miss that an absolute
offset was *claimed but not actually provable*, rather than being told
plainly that the request failed. The chunk-0/plain-`Blob` case is the
same principle at its edge: an entry that describes nothing real is not
merely irrelevant, it is evidence of a malformed or lying builder.

**If violated:** an application relying on `absolute_offset` for, say,
byte-accurate DA-layer indexing could be handed a value derived from an
incomplete sum — or worse, silently receive `None` for a bundle that
*looked* like it was trying to prove one, masking a builder bug or a
malicious short-fill.

**Enforced by:** `mkit_core::verify::tests::incomplete_length_proof_set_is_rejected`
and `rust/tests/golden/disclosure/neg_incomplete_length_proof_set.*`;
`mkit_core::verify::tests::len_proofs_on_chunk0_are_rejected` and
`rust/tests/golden/disclosure/neg_len_proofs_on_chunk0.*` (SPEC-DISCLOSURE §4/§4.1).

## Closure walks share one `children` function

**Always:** every reachability walk &mdash; store-backed
`reachable_objects` / `reachable_closure` / `reachable_snapshot`, the
store-less `verify_closure` BFS, the pull-based `verify_closure_streaming`
walk, push verification (`verify_push`), and push/fetch pack planning &mdash; takes
its edges from `ops::graph::children(obj, mode)`. The verifiers
(`verify_closure*` and `verify_push`) share one BFS, `verify::closure::walk`;
none keeps a walker of its own. Snapshot mode omits
commit/remix parents; history mode includes them; remix `sources` and
`Delta.base_hash` are never followed.

**Because:** a snapshot-vs-history disagreement, or a walker that
followed foreign remix sources, would let two "closures of the same
commit" disagree on the object set, so a DA-layer verifier and a push
could not be checking the same thing.

**If violated:** a history export verified in snapshot mode (or the
reverse) would silently drop or invent objects, and a wasm verifier
walking a hand-rolled map would accept a different set than
`reachable_objects`.

**Enforced by:** `mkit_core::ops::graph::tests::children_snapshot_omits_parents_history_includes_them`,
`reachable_snapshot_excludes_parent_commit`,
`mkit_core::verify::closure::tests::history_on_snapshot_reports_parent_missing`
/ `snapshot_on_history_reports_parent_unreferenced`, and
`mkit_core::verify::push::tests::history_vs_snapshot` /
`remix_sources_never_followed`.

## Streaming closure verification reads only reachable objects, each once

**Always:** `verify_closure_streaming` and `verify_push` queue and fetch each visited id at
most once (so repeated references do not grow the queue), fetch no id outside the selected snapshot/history closure, and drops an
object's bytes after extracting its child ids; it reports
`unreferenced_checked = false` because it cannot enumerate objects it never
requested.

**Because:** local closure verification must scale with the checked closure,
not with the size of the repository's unrelated object store, while a
duplicate or out-of-closure fetch would defeat the source's bounded,
pull-based contract.

**If violated:** a large local store can turn a small closure check into an
O(store-size) memory operation, or a buggy mode walk can silently inspect
foreign/unreachable objects and misrepresent what was verified.

**Enforced by:**
`mkit_core::verify::closure::tests::streaming_fetches_each_reachable_object_once_and_only`,
which uses a counting source that panics on unknown ids and checks the exact
snapshot/history fetch sets, and
`mkit_core::verify::push::tests::each_object_fetched_once_across_multiple_tips`
and `mkit_core::verify::closure::tests::repeated_child_ids_are_queued_once`.

## Push verification and delta bases resolve only within the pushing repository

**Always:** `verify_push` reads objects only through the `ObjectSource` its
caller supplies, and stops only at ids the caller's `known` accepts; a
`known` id is neither fetched nor descended. A server supplies a source
limited to the pushing repository's members plus the pushed objects, and
`known` holds only for objects whose whole closure (in the walk's mode) was
already verified in that repository. Every fetched object is re-hashed, and
every commit, remix and tag has its signature checked
(`sign::verify_object_signature`), before any ref moves. Likewise a delta's
external base comes only from the `pack::DeltaBaseSource` the decoder is
given: the local `ObjectStore` on a client, the repository's membership on a
server, never a global content store. A source that does not have a base
and a source that may not serve it give the same `DeltaBaseMissing` error;
an unverified source's bytes are re-derived, so a wrong object is never
used as a base.

A `known` tip is skipped whole, including the commit/remix/tag type check
`verify_push` applies to every fetched tip. Callers MUST type-check known
tips themselves (from their index) before moving a ref to one.

`decode_entries_with` is bounded by the caller's `DecodeLimits`: every
`0x03`/`0x04` claim and every delta's declared result length is charged
before it is materialised, and every external base from the
`DeltaBaseSource` as it is fetched. An entry or external base stays
resident only until the last delta that names it; an external base's
charge is then credited back. The budget is per call: a server sizes it
from its isolate limit and decode concurrency. `PackReader::read` has no
such budget (tracked separately).

**Because:** PRD §6.5 forbids existence oracles. If a push could close its
history, or resolve a delta, over objects held only by another repository or
the global store, the push's success would reveal that some other repository
holds those objects, and the repository would reference objects it never
held. A `known` that meant "exists somewhere" would skip verification of
content this repository never checked.

**If violated:** a pusher could probe for private content by pushing deltas
or commits over guessed ids, or land a ref whose history includes unverified,
unsigned or foreign objects.

**Enforced by:** `mkit_core::verify::push::tests` (`frontier_stop` and
`known_tip_is_noop`, whose source panics on any fetch past the frontier;
`unsigned_commit_rejected`, `forged_tag_rejected`, `remix_signature_checked`,
`wrong_bytes_for_id_is_corrupt`) and `mkit_core::pack::tests`
(`external_base_outside_source_is_delta_base_missing`,
`untrusted_source_returning_wrong_bytes_is_rejected`,
`decode_with_no_external_bases_matches_reader`,
`delta_bomb_is_rejected_before_any_delta_is_applied`,
`compressed_claims_are_charged_before_decompression`,
`external_bases_are_charged_against_the_budget`). The server-side wiring and
the cross-repository uniform-error conformance test belong to WP-4.7.

## Closure profile is raw-only

**Always:** a closure pack is SPEC-PACKFILE v1 with only `0x00` entries.
`PackWriter::new_raw_only` never compresses and rejects deltas.
`verify_closure_packs` treats any delta or compressed entry as
`VerifyError::ClosureProfileViolation` after a type scan that does not
decompress.

**Because:** `mkit-wasm` builds `mkit-core` with `default-features =
false` (no zstd). A compressed or delta pack would be unreadable there,
so the profile that a wasm verifier consumes has to be raw-only by
construction.

**If violated:** a native exporter could emit a v2 pack that a wasm
verifier rejects (or, without the type scan, tries to decompress and
hits the `pack-zstd` stub), splitting the verifier kit into two
incompatible carriers. The type scan still runs first when a build has
the `pack-ruzstd` decoder, so a compressed entry is a profile violation
there too, not a decoded object.

**Enforced by:** `mkit_core::pack::tests::raw_only_writer_emits_v1_raw_for_compressible_payload`,
`raw_only_writer_rejects_deltas`,
`mkit_core::verify::closure::tests::delta_pack_is_profile_violation`,
and `rust/tests/golden/closure/neg_delta_entry.*` /
`neg_compressed_entry.*`, and
`golden_pack::pack_v2_fixtures::closure_profile_still_rejects_compressed_entries`
(every feature combination, including a frame corrupted past decoding).
