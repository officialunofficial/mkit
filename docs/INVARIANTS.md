# Invariants

Properties that must always hold across the mkit monorepo, outside any
single crate or spec. Each entry states the invariant, why it matters, and
what breaks when it is violated. A regression test enforces each one; find
it by the file path listed under "Enforced by".

## Ticketed pushes bind uploaded bytes to one paired advance

**Always:** a Connect push opens a signed ticket for each pack that needs one,
uploads that ticket's bytes, and commits at most seven distinct ticket ids in
an advance pairing `refs/heads/<branch>` with `refs/mkit/packmap/<branch>`.
Only the current data packs and current MKPL node contribute ids. Multipart
receipts are durable before the next part begins and remain until the advance
commits. An ambiguous advance retry retains its nonce until the envelope
lapses; polling renews before the worst-case retry ladder could cross expiry.

**Because:** a stale node ticket, early receipt deletion, or changed nonce
could make an otherwise complete push fail or replay a committed write.

**If violated:** a push can strand content, publish an incomplete closure, or
lose resumability after interruption.

**Enforced by:** `mkit-transport-connect/src/client.rs` ticket mapping, part
store and poll loop; `mkit-cli/src/remote_dispatch/packmap.rs` current commit
set; Connect client wire and CLI receipt-store tests; native FS end-to-end
ticketed upload and resume tests.

## Grant revocation fences every leased ref shard

**Always:** a grant epoch change reports success only after every leased
ref shard has acknowledged the new epoch or its old lease has expired.
Each granted write checks its epoch at authorization and again in its
atomic ref-shard apply, including after a failed apply is replanned.

**Because:** an owner must be able to treat a completed epoch update as
revocation of every older grant, even when a write was already in flight.

**If violated:** a stale grantee can commit after revocation has completed.

**Enforced by:** `rust/crates/mkit-server-native/tests/epoch_leases.rs`
on memory and SQLite, and the grant-epoch and ref-scope wire suites.

## ListRefs pages make bounded forward progress

**Always:** a nonterminal ListRefs page contains at least one ref, its token
binds the repository and normalized prefix to the last emitted full name,
and every encoded page is at most 2 MiB. A failed bucket scan fails the
entire page with `unavailable`.

**Because:** clients reject repeated tokens and nonincreasing names; an
unbounded response exceeds the Connect client message limit.

**If violated:** a client loops or drops refs, or a partial merge appears to
be a complete listing.

**Enforced by:** `pipeline::list` property and large-list tests, the
`connect_dispatch` paging wire test, and the Connect encoded-length guard.

## Storage receipts attest recorded state without exposing inspection

**Always:** a storage receipt binds a committed live advance or lease change
to its issue-time terms and deployment role key. An advance receipt contains
only the writer's ref and consumed-ticket facts, never publication, hold, inspection,
or cross-repository physical-storage facts. Replays and later fetches return
the same signed bytes.

**Because:** changing the claim after commit defeats audit evidence, while
publication or physical-storage details can expose inspection decisions or
other repositories' holdings.

**If violated:** a writer can use receipts to evade detection, infer another
repository's packs, or receive contradictory evidence for one operation.

**Enforced by:** `rust/crates/mkit-server/tests/golden_receipts.rs` pins the
format, subject and key-window checks. Runtime issuance, replay and field
exclusion are specified in SPEC-SERVER §15 and await WP-5.8 implementation
and conformance coverage.

## Ticketed UploadPack writes no business metadata and requires a marker

**Always:** a ticketed UploadPack verifies the signed pack commitment and
ticket before reading bytes, streams the complete pack through a verifying
blob sink, and writes a content-addressed marker in the upload-marker
namespace after the pack commit. Only bounded authoritative generation/mode
reads are permitted; it writes no metadata row and makes no quota charge,
replay reservation, authorization, admission or `pre_receive` call.

**Because:** the marker proves that a holder of this ticket supplied and
verified these pack bytes. WP-1.10 requires it with the pack blob before
consuming the ticket, even when another repository already stored the pack.

**If violated:** an advance could attach a globally present pack without an
upload, or a ticketed stream could create business metadata or bypass revocation.

**Enforced by:** `mkit-server` pipeline tests `ticketed_upload_no_metadata_and_marker`,
`ticketed_upload_failures_leave_no_marker`, and `upload::marker::tests::golden_upload_marker_v1`;
`mkit-server-native` tests `ticketed_memory_all_layouts_touch_no_metadata`
and `ticketed_sqlite_all_layouts_touch_no_metadata` (including concurrent uploads);
wire cases `tickets.upload_pack_ticketed` and `repository.ticketed_upload_multi`.

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
record; admission rejection leaves replay storage unchanged. Permanent built-in
ref policy denials commit a guarded replay rejection, preserving a concurrent
winner; membership lag (`unavailable`) answers remain unstored. Existing
reservations and saved results remain retryable without another quota charge.

**Because:** signature validity alone cannot prevent cross-service replay or
repeating an effect after a crash.

**If violated:** a captured request can move a ref back, toggle a reaction twice,
restore an old name or charge duplicate upload quota.
Reserving rejected operations also lets throttled authors keep growing replay
storage after exhausting their write budget.

**Enforced by:** `mkit-server` ref policy permanent-denial, lag-retry and
concurrent replay winner tests; shared core canonical/context tests; Connect retry tests;
actual local Workers regressions in `apps/{repo-worker,vcs-worker,keys-worker}/tests/`;
quota and rate admission in `apps/mkit-worker-common/tests/quota_ledger.mjs`;
web/spammer envelope tests. Keys failure injection after name and result writes
rolls back both; saved results survive a full Worker restart. Production builds
omit `test-faults`. Only auth v2 is accepted. Names use SQLite exclusively.

## Namespace quota charges and rollups

**Always:** an admitted default-quota write charges its fixed-window namespace
counter in the same batch as its write and signer charge. A ref shard guards its
local `qs` counter; a coordinator or Single partition guards its exact `qt`
total. The kind-5 rollup applies only the increase since that source's guarded
`qc` cumulative value, or re-baselines a decreased restored contribution, then installs an unguarded local `qv` view. A new shard seeds `qv` from the coordinator total read with its lease. A missing or
stale view permits writes only up to the local exact cap and increments a
fallback metric. Replays and admission-free ticket answers charge neither.

**Because:** a retry or crash after the coordinator apply must not count the
same shard usage twice, and a view refresh must not force every write to
re-plan. With scheduled rollups succeeding, the local estimate can lag other
active shards by at most their admission rate times three 60-second intervals (3R).

**If violated:** an author can exceed the namespace cap without a bounded
delay, or a retry double-charges and locks out valid writes.

**Enforced by:** `quota.rs` fixed-window math and batch planner, guarded
`timers::quota_rollup`, and the memory-store rollup/denial/rollover tests.

## Pending verification preserves the advance identity

**Always:** a typed pending `AdvanceRefs` response causes a clamped poll, not
a retry-ladder step. Every attempt keeps the same nonce, timestamps and
signature while the envelope remains valid; before the next poll it is renewed
when less than 30 s of validity remains (or the unary timeout, if longer). An
ambiguous retry retains its identity until the envelope actually lapses.
Polling ends before the consumed ticket expires.

**Because:** a pending answer is never stored for replay, and the next attempt
must observe verification progress without changing the logical operation.

**If violated:** an advance can fail after the ordinary retry ladder, use an
expired signature, or keep polling after its ticket is invalid.

**Enforced by:** `ConnectTransport::advance_refs_with_deadline` and its pending
response, renewal and deadline tests. The caller's real ticket deadline is
pending WP-1.17; until then the helper uses the seven-day maximum lifetime.

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
or `worktrees.lock` immediately probes that same `serve.lock`
non-blocking-exclusive (`mkit_core::repo_lock::probe_exclusive`) and, if it
finds the lock busy, prints a warning to stderr naming the served root
before proceeding. Most commands do this through `mkit-cli`'s
`acquire_worktree_lock` / `acquire_worktrees_registry_lock`; the paths
that take `worktree.lock` directly (the `fetch`/`pull` phases in
`remote_dispatch` and `status`'s index refresh) call the same
`warn_if_served` probe (SPEC-CONCURRENCY §3.1). The one exclusive holder: at startup
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
cover. Detection does not make a concurrent `gc` safe: SPEC-GC
("Concurrent writers and the grace window") states the condition a
writer outside gc's lock set must meet, which a dedup hit on an old
unreachable object does not meet today.

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

## M2 Connect surfaces remain explicit stubs until implementation

**Always:** `GetGrantEpoch`, `SetGrantEpoch`, `SetRepoVisibility` and
`IssueObjectUrl` return `unimplemented` ("not implemented yet") until
WP-2.8, WP-2.9 and WP-2.11 implement them. They write no state.

**Because:** their paths currently bypass auth-v2 `Procedure` dispatch.
WP-2.8 keeps both namespace epoch RPCs outside that path permanently, by
spec §5.3 (`grant_epoch_paths_are_permanently_outside_procedure`).
WP-2.9 and WP-2.11 must add mode-specific and signed-read authorization
before enabling their repository RPCs.

**If violated:** an unauthenticated repository RPC can mutate state or mint a token.

**Enforced by:** `mkit-server/tests/connect_dispatch.rs`'s `m2_*` tests
and the TODO and SECURITY comments in `connect/service.rs`. Implementing
WPs replace their stub assertions with behavior and auth tests.

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
to the claim, exact length re-check). Both paths reserve output fallibly
without zero-filling the claim; unpack charges the resident budget first.
The pure-Rust path reads out at most `claim + 1` bytes and never grows the
reserved output. Its separate decoder ring rounds up to a power of two
and holds up to one window of pending output, outside the owned-payload
resident cap and the window reader's carry/output budget. The pure-Rust path also
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

## MKDS spans bind every chunk to one authenticated byte range

**Always:** an accepted MKDS container has one trusted commit, authenticated
path and leaf, a complete preceding length-proof set, and consecutive chunk
bundles. Its absolute boundaries come from verified canonical Blob content
lengths. The requested range starts in the first included chunk and ends in
the last, with no unnecessary last chunk. A malformed container returns its
first SPEC-DISCLOSURE §8.2 reason and no partial output bytes. A range-proof
builder checks untrusted boundary hints against the chunk bytes it reads and
does not read a chunk after the span.

**Because:** a chunk-size marker or unchecked hint is not a proof of a content
boundary, and combining individually valid bundles from different contexts
would not authenticate their concatenation as one requested range.

**If violated:** a caller can receive bytes at the wrong absolute offset or
from the wrong leaf, or accept an incomplete range as a valid disclosure.

**Enforced by:** `mkit_core::verify::span` and its unit tests,
`rust/crates/mkit-core/tests/golden_http_objects.rs` product/reference parity
and builder byte-identity checks, and `rust/crates/mkit-wasm/tests/verify.rs`
(WP-4.14a; SPEC-DISCLOSURE §8 and SPEC-HTTP-OBJECTS §5.2).

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
from its isolate limit and decode concurrency. `PackReader::read` instead
uses the separate peak resident cap below. Compressed and delta claims
accumulate under `DecodeLimits`; resident reservations are released on
last use. `ObjectStore` base admission charges before allocation through
the provided `DeltaBaseSource` method; existing sources default to charging
the bytes returned by `base()`.

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

## Windowed pack entries stay provisional until complete verification

**Always:** `pack::window` yields the same entry values as `PackEntries` when
resource limits do not bind, and returns `Done` only after framing, the trailer,
and any expected whole-pack id pass. Drivers discard all staged entries on
any error, including entries yielded before a checkpoint.

**Binding.** `Done` means every entry yielded across the whole run chain (the original run and every resume
through its cursors) is an entry, in order, of the one pack whose bytes hash to the verified pack id: the trailer,
and `expected_pack_id` when set. A cursor from pack A used on a source that yields different bytes for any
not-yet-verified range fails with `PackfileCorrupted`, never `Done`. The reader does not re-read ranges it has
already verified. **Keeping the source immutable across resumes is the caller's job** (informative: WP-4.8 binds
R2 range reads to the object's etag). A source whose already-verified prefix changed after verification can still
reach `Done`, but only with entries of the verified pack.

A `None` checkpoint means keep the previous cursor. After a boundary-state `None` (the trailer phase), resuming re-reads at most one window plus the trailer; after a mid-entry `None`, it re-reads every window the unfinished entry spans.

**Because:** a streaming trailer check occurs after entries have been delivered;
completed-window CVs and the lazy current-window prefix commitment bind the
entries staged across resumes without re-reading completed ranges.

**If violated:** malformed packs or mismatched cursor/source pairs can publish
partially verified data.

**Enforced by:** `rust/crates/mkit-core/src/pack/window/tests.rs` differential,
resume, cursor-binding, released-window, resource-budget, and trailer-split tests;
the `mkit-core-wasm-check` v2 differential harness. Caller staging rollback and
source immutability remain obligations of WP-4.7/4.8; the core reader does not store objects.

## Pack exclusions preserve surviving objects and delta bases

**Always:** a pack rewrite drops every excluded entry and rawifies a surviving
delta only when its direct base is excluded. Surviving bytes and entry order
are preserved; an unchanged pack keeps its original bytes. Rewrites use the
existing `DecodeLimits` charged-payload accounting; the caller supplies
repository-scoped bases.

**Because:** deleting a delta base otherwise makes retained objects undecodable;
transitive rawification adds size without improving decodability.

**If violated:** a takedown can corrupt unrelated objects or reveal external
object membership.

**Enforced by:** `pack::rewrite::tests` (128 property cases, chains of depth 1–5,
external bases, duplicates, compressed fixtures and budget/error checks), plus
`mkit-core-wasm-check/tests/pack_rewrite.rs` and the hostile-length wasm harness.

## Repository addressing binds authentication and storage routing

**Always:** stage 0 validates `X-Repository` with the shared identity grammar
and stores its resolved identity on `Authenticated`. Every operation routes
refs and replay state through `ShardMap` using that repository. Multi ref reads
require a ref row in the named repository; Multi pack RPCs return
`unimplemented` before blob access until repository membership exists.

**Because:** ref keys contain only the repository name; namespace partitions
provide isolation, and global blob presence would reveal another repository's
contents. Auth v2 must bind the signature and replay scope to the routed identity.

**If violated:** a request can observe or mutate another repository's refs,
reuse its replay result, or learn whether it holds particular content.

**Enforced by:** server `repo::tests` (the BLAKE3-pinned repository grammar),
`pipeline::tests::single_repository_header_rules_preserve_04_requests_and_fail_at_stage_zero`,
native `tests/repository_routing.rs` over memory and SQLite (including the
same repository name in different namespaces and shared nonces), and the
conformance `repo.*` wire cases. Namespace authorization is WP-1.5; pack
membership is WP-1.10; WP-1.22 moved existence to the coordinator repository registry.

## Branch shards preserve atomic advances and registered repository state

**Always:** D34 accepts only matching `refs/heads/<x>` and
`refs/mkit/packmap/<x>` for `AdvanceRefs`, before storage or replay access,
and commits their effects and replay state in one ref partition. Multi writes
observe creation after replay lookup and commit coordinator registration only
after authorization and admission allow them, before committing refs. A
ref-shard repo-known marker is written with the ref batch.

**Because:** a store batch cannot span partitions. Registration before refs
makes a crash leave an empty registered repository; marker caching preserves
the two-call steady write path. Admission observations can race, while
`Operation::created` reports only creation actually committed by this write.

**If violated:** advances lose atomicity, challenges create repository state,
replays reach creation hooks, or committed refs become unreadable as an
unregistered repository.

**Enforced by:** pipeline pairing tests with the call-counting store and
native `tests/d34_creation.rs` over memory and SQLite in both sharding
modes; D34 mapping golden and property tests pin co-location and fixed fan-outs.

## Timer effects share the row's atomicity boundary

**Always:** a timer handler's batch commits in its timer partition only after
checking the original row value, together with deleting or rescheduling the row.
Unknown timer kinds remain stored. Native committed timer Puts notify inside the
blocking task, even if the awaiting request is canceled.

**Because:** alarm redelivery and concurrent ticks must not duplicate effects;
cancellation must not hide a durable timer from the native driver.

**If violated:** effects can run twice or a committed timer can remain asleep.

**Enforced by:** `mkit-server/src/timers/tests.rs` race and atomicity tests,
`mkit-server-native/tests/timers.rs`, and the worker's pure alarm tests.

## Worker shard classes reject foreign partition kinds

**Always:** each Durable Object class accepts only its assigned partition kinds
before dispatching a store call. RepoIndexShard serves both repo and ref indexes.

**Because:** the wire carries the partition, so a class must check the request's
kind rather than trusting its caller's binding selection.

**If violated:** an incorrectly routed request can write into a foreign class.

**Enforced by:** `mkit-server-worker::ns_object::serve_reply` and the full
class/partition cross-product in `mkit-server-worker/tests/stores.rs`.

## Worker timer ticks retain alarms scheduled while awaiting I/O

**Always:** after running due timers, the alarm handler re-reads the current
alarm and retains the earlier of it and the tick's next wake. With default
storage options and no intervening I/O, Cloudflare input gates protect this
final read/write sequence from request delivery.

**Because:** `getAlarm` returns null during an alarm handler unless `setAlarm`
has been called since it started. A timer Apply interleaved while a handler
awaits non-storage I/O may install a new alarm.

**If violated:** the final tick reschedule or delete can overwrite that alarm,
delaying or stranding a newly inserted timer.

**Enforced by:** `NsObject::alarm`, `alarm_after_tick_with_current`, and its host
regression tests. Gate semantics follow [Cloudflare's glossary](https://developers.cloudflare.com/durable-objects/reference/glossary/)
and [storage transaction documentation](https://developers.cloudflare.com/durable-objects/api/sqlite-storage-api/#transaction);
the null behavior is documented in [the alarms API](https://developers.cloudflare.com/durable-objects/api/alarms/#getalarm).

## Worker deployment sharding is bound before serving RPCs

**Always:** a Worker isolate validates its configured sharding (`SHARDING`,
default `d34`) against `sm 00` in the root RefStore before serving RPCs. An
unmarked root with rows is single, so it answers 503 until `SHARDING=single` is
pinned: there is no single to D34 migration (R-123). The native server's
`bind_sharding` makes the same choice: a recorded or unmarked-with-data `single`
database under the `d34` default (`--meta sqlite`) is `CONFIG_ERROR`, telling
the operator to pass `--sharding single`.
Each cold request runs its own check with its own store handle. The thread-local
`RefCell<Option<Settled>>` caches only plain definitive data: success, mismatch
or corruption. No future, promise or request handle crosses request contexts.
Storage failures remain request-local and are retried by the next request.
The cache is keyed by mode and jurisdiction; a changed key drops the cache and
re-checks storage. A failed Absent uses its atomic observation; an absent
observation or an undecodable marker refuses as corruption.

**Because:** changing partition routing over existing data hides its refs;
[Workers continuations](https://developers.cloudflare.com/workers/configuration/compatibility-flags/#handle-cross-request-promise-resolution-correctly)
remain tied to their original request context; a transient backend
outage must not permanently poison an isolate.

**If violated:** cold requests can hang, deployments can appear empty, or a
brief outage can strand all subsequent requests.

**Enforced by:** `sharding_guard::{Settled, check_mode}`, the adapter's isolate-local
cache, host interleaving/error/config regression tests, and 30 concurrent cold
health checks before every Worker conformance phase. At most 3 DO calls per
request arriving before the first definitive result is cached; 0 afterwards;
never more than one check per request.

## Epoch lease acknowledgements describe durable shard state

**Always:** outside a declared recovery hold-off, `ls.acked_epoch = n` only if
the shard's `el` durably holds epoch at least n, or every older-epoch write is
already past its backend deadline.
Live renewals preserve acknowledgement. Revocation pushes even to an absent
`el`, guards the observed shard value, then acknowledges in a separate guarded
coordinator batch. Every D34 ref batch guards `el` and starts with
`NotAfter(min(plan_time + MAX_APPLY_WINDOW, expires - margin, replay cap))`.
Creation and lease registration commit together only after authorization and
admission. D34 creates coordinator `nr`/`rr` records even with Single addressing,
so every leased shard has the records its guards and `config_version` require.
The Single sharding path continues reading and guarding `e` directly.
Safety requires `lease_margin_ms` to exceed the maximum skew between every
pipeline instance clock (grant, renewal and revoke), the sweep driver clock,
and every backend clock; this deployment assumption is documented, not checked
by `Pipeline::new`.

During declared recovery, a rebuilt missing `ls` row may acknowledge the current
epoch before a surviving old `el` is replaced. The persistent `lr` hold-off
prevents completion for `epoch_lease + margin`, so every surviving old write's
deadline has passed before revocation can complete.

**Because:** a coordinator acknowledgement before shard installation could
report completion while a delayed old-epoch batch can still commit. Expiry
alone is safe only because the storage backend checks its own clock atomically.

**If violated:** a revoked grant can mutate a ref after revocation completes,
or denied/challenged requests can allocate lease state.

**Enforced by:** `pipeline/lease.rs`, `pipeline/revocation.rs`, the pure write
planner, and native `tests/epoch_leases.rs` on memory and SQLite. The Rust
interleaving property test covers the protocol model; pipeline regressions
protect the implementation. `LeaseSweep` guards expired coordinator rows and
moves its timer atomically with each renewal. Recovery is declared with the
persistent `lr` marker; restore/rebuild procedures MUST call
`mark_lease_table_recovered` before serving writes (WP-1.29). Completion waits
`epoch_lease + margin` after that marker, independent of namespace creation time.

## Namespace and write policy decide before allocation and never read existence

**Always:** Multi writes pass the namespace policy and owner/authority policy
in the authorize stage, after replay lookup and creation observations, before
admission or any quota, reservation, replay, namespace or repository allocation.
Built-in policy never reads creation facts or repository existence. Namespace
and non-owner denials have the same public `permission_denied` message,
"write not permitted". Namespace denial never calls the authorizer. Authorize
and Admit both see the established owner and grant facts; authority hooks still
run for owners and may deny them. Single deployments retain open write behavior.

**Because:** unauthorized writes must not disclose repository existence or
allowlist contents, allocate state, or bypass a deployment namespace boundary.

**If violated:** denied callers can create storage state or infer other tenants'
repositories; an authority Allow can bypass a namespace restriction.

**Enforced by:** `Pipeline::new` validates policy combinations and D27 using
wasm-safe provided trait methods. `Pipeline::authorize` enforces STC §7.5 and
SPEC-SERVER §6.2. `pipeline::tests::policy` covers the policy/principal/hook matrix,
startup refusals, identical existing/missing repository denials, and empty
coordinator/ref shards after every denial. Wire `policy.*` cases pin owner,
non-owner and allowlist behavior. Grants and private reads remain M2.

## Ticket, reservation and outbox rows keep exactly one outcome per reservation

**Always:** a ticket has a reservation-derived id and a unique guarded `o` row.
Only a still-Ticketed or Pending row can become terminal. Directly admitted
writes first record Pending, then replace it with Committed or Aborted under
an equality guard; BeginUpload replaces Pending with Ticketed. A pending
apply's deadline precedes its reconcile timer, so a late apply cannot commit
after an Aborted(ABANDONED) replacement. Consumption commits its outcome
with ref publication and local membership; a missing pack with a present upload
marker records `Aborted(PACK_MISSING)` in a separate guarded batch before the
advance fails. A missing marker leaves the ticket open. Terminal outcomes stay
durable until acknowledgement, which deletes their delivery index and subtracts
the exact stored key/value byte count. Shared counters and sequence/backlog
values are guarded once per batch. A zero-to-positive backlog transition adds
one kind-8 delivery kick; delivery may repeat but never drops an unacked row.
A positive backlog keeps exactly one kind-8 row. Delivery decides completion
from the same backlog snapshot its acknowledgment batch guards; concurrent
appends either retain a rescheduled timer or fail that guard for re-planning.

**Because:** consumption and expiry race; delivery may repeat or crash. An
unguarded replacement could record two outcomes, erase a replacement ticket's
index or lose membership while publishing refs.

**If violated:** settlement can repeat, committed packs can disappear from
repository membership, and backlog/caps can undercount durable obligations.

**Enforced by:** `mkit-server/src/store/{tickets,outbox}.rs` pure planner tests,
strict `store/codec.rs` decodes, and `mkit-server-conformance/src/storage/kv_cases.rs`
creation, atomic publication, stale-ticket and acknowledgement cases over memory
and SQLite. WP-1.10 exercises consumption and the defensive abort over native
memory/SQLite and wire cases; the kind-2 expiry handler closes tickets with
one guarded `Expired` row and best-effort session abort. WP-3.3 enforces guarded
Pending reservations, ReadServed, reconciliation and backlog limits.
WP-3.13 corrects the kind-8 acknowledgment/completion window from #1219;
regular `timers/outcome_delivery.rs` regressions cover appends before and
after the guarded fresh read and complete empty-backlog acknowledgment.
## Relay delivery advances durable per-source watermarks before source cleanup

**Always:** relay rows for a source/target pair apply in sequence order. Each
batch guards the target's `rh` and advances it atomically with the row upserts,
deletes, and pre-delivery hook effects. Duplicates never apply a target batch. Source
cleanup guards each encoded row; draining the timer guards the originally
observed `os`, so a same-millisecond writer cannot lose its wake-up. Writers
stamp and chunk rows, and commit an immediate kind-3 timer with their outbox.
Target watermarks and the one `rs 00` scan row per source are never pruned;
watermarks are bounded by source shards.

**Always:** a key that is ever relay-deleted has exactly one producer. Its
source `os` sequence orders every upsert and delete. Identical upserts from
several producers remain valid for never-deleted keys, including object-index
`i` rows (R-130).

**Because:** one target `rh` per source deduplicates rows, but cannot order
conflicting operations from distinct sources on a deleted key.

**If violated:** a delayed upsert can resurrect a deleted ref-index row.

**Enforced by:** D34 ref-index routing from one ref shard, the disjoint
put/delete relay codec and outbox validation, and ordered relay delivery tests.

**Always:** during an active relay scan cycle, every undelivered row whose
sequence is at or below the durable cursor has a target in the cycle's
sorted, deduplicated blocked set. That set holds at most 32 targets. A cycle
ending at its observed `os` ignores newer rows until the next cycle. The
source atomically guards its previous scan state and commits the new state
with any queue-row deletions; a guard conflict retries. Reaching the cycle
end or the blocked-set cap starts the next fire at the head. Thus a target's
later row cannot advance `rh` past its earlier undelivered row: an earlier
row before the cursor blocks the target, and one after it is scanned first.
Only delivery failure blocks a target; reaching `max_targets` pauses before
the next target and resumes there on the next fire. Blocked targets are
retried at each cycle start. While fewer than `MAX_BLOCKED_TARGETS`
distinct failing targets precede it, every healthy target is eventually
delivered: every fire that sees a deliverable row delivers at least one,
delivered rows (including those past the checkpoint) are deleted in the
same guarded checkpoint, and fires that deliver nothing back off. No
closed-form fire bound is claimed; the relay throughput regressions pin
fire counts for representative schedules. A row appended mid-cycle waits
for the current cycle to finish. This can exceed `RELAY_LAG_BOUND_MS` in time;
WP-1.23c's `namespace_relay_watermark` must tolerate it. A target's later
row is never retried while its earlier row remains undelivered.
At the SQL soft capacity limit, only a valid, guarded `rs` checkpoint, with
any relay-row deletions, or a guarded kind-3 relay timer reschedule may use
the reserved space; ordinary puts still fail. The timer exception preserves
immediate rescheduling after progress on a full shard; without it the runner
would wait for the 5-second retry backoff.

**Because:** target delivery and source cleanup cannot share a transaction.
A crash, overlapping timer fires, or a concurrent writer can occur between them.
Source-head scans alone would indefinitely hide a healthy target behind more
than one fire's inspection cap of permanently failing rows.

**If violated:** re-delivery overwrites newer index values, hook effects detach
from their membership writes, or newly queued rows lose their relay timer.
Restoring an older source requires raising `os` above every target's `rh` for
that source or re-keying it (R-102; WP-1.29).

**Enforced by:** `mkit-server/src/relay/tests.rs` crash, contention, ordering,
chunk-limit and wake-up tests; native SQLite driver and soft-limit checkpoint
tests; Worker Loopback host
tests. Worker RefShard registration uses
plan-specific fire caps and two target calls per target per fire, including
chunking and contention. Fires inspect up to four times their row delivery
budget, persist bounded cycle progress in `rs 00`, and revisit blocked targets
at the next cycle. A healthy target is reached when fewer than 32 distinct
failing targets precede it; beyond the cap, the cycle resets. Corruption stops
delivery after its decodable prefix. Coordinator watermarks follow in WP-1.23c;
writers in WP-1.9/1.10.

## Object-index visibility follows repository membership (writer gate pending)

**Always:** an `i` row is visible only while its pack has an `m` row in the
same repository. For indexed advances, every index row of a consumed pack
MUST be delivered before the advance commits membership and refs. Until
delivery finishes, the advance returns `PendingVerification` without a replay
result. Identical upserts from several sources may target the same index key.
An index value MUST be a pure function of (pack bytes, entry), so every
producer writes identical bytes (R-130). §13 GC removes index rows whose
membership is absent and whose pack has no live ticket; WP-5.3a owns this
pass. Until it lands, the per-id row cap bounds orphan damage.

**Because:** relay lag can exceed the §9.4 window. Early index rows are safe
only while membership keeps them invisible; committing membership first could
make a later miss look permanent.

**If violated:** closure, delta-base checks, object serving or takedown can
miss a member or use an object from another repository.

**Enforced by:** `store::index` repository-scoped lookups and conformance
cases enforce the read-side membership join and isolation. WP-4.7 and WP-4.8
must enforce the delivery-before-advance gate in their production writers.
See R-130.

## Pack reads consult only the named repository's membership

**Always:** Multi PackExists and DownloadPack authorize and check repository
existence, then consult the repository's membership index before opening a
blob. An optional X-Mkit-Ref checks only the same repository's ref shard;
invalid, unserved, unknown or overlong hints never cause a public error.
The hint is outside the auth v2 canonical string. Single reads treat stored
packs as members. M1 has no quarantined view; later visibility checks must
constrain both index and hinted answers to the caller's permitted view.

**Because:** blobs may be shared globally, and index relay can lag a write.

**If violated:** pack reads expose another repository's content or make
malformed hints an existence oracle.

**Enforced by:** store::read::is_member, pipeline pack reads and bounded hint
parsing, unit call-count/isolation tests and Multi wire membership cases.


## Every relay source is covered by an epoch lease

**Always:** a production batch that appends relay rows carries an epoch lease
on its source shard. Only ref shards are relay sources. The test-only `TestTimer`
kind may append a ref-index delete without a lease: it is compiled out of
release builds and can fire after the lease expires. A new relay source class
requires its own coordinator watermark design before it can append rows.
This binds WP-1.10 (#1188), 4.7, 4.8, 4.10, 5.3b, 5.6 and 5.7b. The namespace
watermark bounds every undelivered relay row's **commit time** from below;
consumers compare it against `T + MAX_APPLY_WINDOW + margin`.

**Because:** the coordinator keeps an `ls` row until the source outbox drains.
Without a lease, a new row could appear after the coordinator removed the
source, and the namespace minimum could pass an undelivered commit.

**If violated:** GC or takedown could complete before a relay row arrives.

**Enforced by:** lease guarded ref writes (including `AdvanceRefs`), the D34
apply-loop relay guard, `LeaseSweep` source scans, and real-path watermark
property tests. A new shard's first report can be stale-low, so the namespace
result can decrease even without recovery. It remains unavailable after
recovery until reconciliation.

## Fresh restore preserves epoch and relay safety

**Always:** logical restore imports into a newly empty store supplied by its
caller. It imports the root
sharding marker before other partitions, raises each restored namespace epoch
to `max(snapshot epoch + 2^32, --epoch-at-least)`, refusing overflow, and marks every
restored coordinator lease table recovered before traffic. It drops backup
state, kind-4 timers, old lease-sweep timers, reconciliation markers and relay
scan state. It resets imported `ls` maxima to zero and seeds expired `ls`
rows with sweep timers for restored ref shards that have relay backlog.
Before importing, it reads every
source `os` and every supplied target `rh[source]`. It discards restored
ref-shard epoch leases, forcing the first write to renew against the raised
coordinator epoch. For each source it sets
`floor = max(snapshot os, max supplied rh[source])`, re-keys each relay row
from `seq` to `seq + floor`, and sets `os` to `snapshot os + floor`, refusing
overflow.

**Because:** a Fresh target contains only supplied or explicitly reconstructed
partitions. A target
absent from the set has no high-water mark. Every restored relay row and the
source's next sequence therefore exceed every target's `rh[source]`. Missing
sources are refused or reconstructed at the supplied watermark; missing
coordinators require an explicit epoch floor and are marked recovered.
Relay rows carry upserts and deletes (R-134). Redelivering a row is
idempotent under `rh` ordering and the single-producer rule for relay-deleted
keys; gaps are harmless because delivery compares sequences only with `rh`.
The epoch jump prevents a grant issued and revoked after the snapshot from
becoming valid again. Owners must re-issue grants after restore. Already
delivered rows cannot be replayed from an older target's snapshot; index and
membership reconciliation is required before GA (R-116).

**If violated:** relay delivery can skip a required update, a restored grant
can regain authority through an unexpired old shard lease, or revocation can
complete while an old lease remains effective.

**Enforced by:** the native CLI refuses an existing database;
`mkit-server/src/store/restore.rs` checks every supplied target partition and
validates and transforms the supplied set before import. Tests
`missing_source_is_refused_or_reconstructed_above_target_watermark`,
`missing_coordinator_requires_both_flags_and_is_recovered_before_ref`,
`epoch_floor_and_overflow`, `older_target_cannot_recover_already_delivered_rows`,
and `fresh_restore_orders_root_and_rewrites_recovery_epoch_and_relay` enforce
the memory invariants; native `export_restore_roundtrip_and_usage_refusals`
enforces Fresh refusal and SQLite import.
`mkit-server/src/relay/deliver.rs` guards target upserts and `rh` together.
In-place and Merge restore require another proof and are deferred to WP-5.11b.

## Deployment discovery is public and repository-independent

**Always:** GetServerInfo is unauthenticated, never resolves a repository and
never reads the store. Its response depends only on deployment configuration,
hook defaults and store capabilities, with the upload threshold zero for
Multi addressing or admission. The one exception is the Worker's
deployment-wide sharding guard (R-94), which runs before every RPC, this one
included: until an isolate has settled the guard, a cold GetServerInfo may
read the root marker, and a deployment whose marker mismatches answers
`unavailable` instead of advertising capabilities it would then refuse. The
guard is deployment-wide, so this never depends on a repository.

**Because:** clients need capabilities before authenticating, and discovery
must never expose whether a repository exists (STC §2.1).

**If violated:** clients cannot discover bearer deployments or malformed and
unknown identities become a repository existence oracle.

**Enforced by:** pipeline `tests::info`, Connect dispatch discovery tests,
native `server_hardening` bearer/concurrency regression and wire cases
`info.shape_and_policy` and `info.ignores_repository_header` on Single, Multi,
native binary and Worker runners.

## Client repository addressing and capabilities remain stable

**Always:** the Connect client validates the literal remote path without repairing
its spelling and sends the resulting identity on every RPC. Signed writes bind
that same value. A transport caches its first capability discovery outcome and
claims atomic advance only for a validated v2 advertisement with an explicit
true value. Ref hints never enter the signed canonical string.

**Because:** routing must agree with authentication, and a push must not reset a
packmap based on an unsupported or changing atomicity assumption.

**If violated:** a client can address an unintended repository or strand a head
behind a packmap reset that was not committed atomically.

**Enforced by:** Connect `client::tests::url_identity_table_preserves_literal_paths`,
`envelope::tests::parity`, `tests/v2_client.rs` discovery and paging regressions,
and CLI `tests/remote_dispatch_connect.rs` header capture.

## Pack unpack bounds owned payload residency

**Always:** unpack charges decompressed payloads, delta targets and cached store
bases before allocation against `max(2 × MAX_RAW_OBJECT_SIZE, 16 × pack_len)`.
Raw wire payloads stay borrowed; a base is released after its final delta use.
Decompression writes into reserved capacity without initializing the claimed
size first. Raw staging skips positions after its earliest permanent failure;
transient worker admission failures are retried strictly in pack order.
Framing arithmetic rejects out-of-bounds lengths on native and wasm32 hosts.

**Because:** authenticated or malicious packs must not exhaust memory through
entry decompression or retained delta targets.

**If violated:** fetch, clone, pull or wasm pack verification can deny service.

**Enforced by:** `pack::tests` resident-peak, bomb, retention-equivalence and
maximum-wire-length regressions; live wasm framing tests in
`apps/web/src/lib/mkit.test.ts`.

## Inspection clearance bounds every reader surface (specified, implementation pending)

**Always:** readers and anonymous callers see only published ref values and
published repository membership. Every newly reachable file object and every
file entry in a pack added by an advance is covered by the configured
inspection obligations or the explicit unavailable-publish policy. A later
pass cannot skip an earlier held or pending advance. A reused pack from
another pending advance cannot satisfy published membership, even through
`X-Mkit-Ref`. Held content is absent to every caller until release or
takedown replacement; this includes all added content for a hold without
flagged ids. Every advance after the published pointer through the live
value remains a GC root in any clearance state; a hit and its replacement
packs remain rooted through takedown.

**Because:** whole-pack downloads, HTTP, URL tokens, snapshots and caches must
not expose uninspected or uncleared content, including surplus pack entries.

**If violated:** a reader can bypass quarantine through an alternate serving
surface or another ref that reuses pending content.

**Enforced by:** normative SPEC-SERVER §§10–11.
Runtime enforcement and behavioral conformance remain for WP-5.4/5.5/5.13;
the current goldens verify the additive hook wire contract only.

## Takedown denial precedes rewrites (specified, implementation pending)

**Always:** a global blocklist write stops extracted and HTTP serving at
once. Until a repository's takedown completes, chunks of its blocked
manifest are also unservable, although chunks are not blocklisted.
Every pack read proves that the pack contains no blocked id or such
chunk and is not superseded, or answers absent. HTTP reachability does
not descend through a blocked or tombstoned manifest. The serving stop
is immediate, independent of holder discovery; the sweep does not
impose a deployment-wide pack outage. Every blocklist check gating a
membership, index, or holder write is at or after its `plan_time`.
After the cut at takedown time plus `MAX_APPLY_WINDOW + margin`, each
namespace's relay watermark passes the cut before its sweep reads it.
No replacement or preserved bytes become a serving or delta-base source until
that repository's guarded rewrite and ref-value substitution complete. Live,
published and retained intermediate values, membership and ref-addition records
all name the same replacement packmap after membership becomes visible
and then ref values are substituted. A hit resolves on its repository's
completion; the safety-cut sweep and watermark govern completion.

**Because:** a lagging index or an intermediate advance can otherwise serve
blocked bytes or resurrect a removed pack after a later publication.

**If violated:** a reader or writer can recover taken-down content, or a
replacement corrupts an unrelated branch's closure.

**Enforced by:** normative SPEC-SERVER §14 and the redaction wire goldens.
Runtime enforcement remains for the takedown, rewrite, and serving WPs.

## Admin authority and audit continuity (launch foundations)

**Always:** administrative effects require a valid `mkit-admin:v1` signature
from a key whose deployment-wide roles permit the procedure. A `RENEWAL` or
`POLICY` change cannot bring lease-derived suspension or deletion earlier
than the configured minimum notice through any `SetLease` action, and can
always extend a lease, even while an override suspends the repository. A nonce cannot authorize
different request bytes, and a repeated long-running operation id cannot
start a second action. Every authenticated result and automatic redaction,
release, waiver or purge appends one gapless hash-chained audit entry.
Unauthenticated attempts never enter the durable log. Pruning preserves a
checkpoint through the longest active preservation retention.

**Because:** lease-only billing authority must not grant moderation power,
and operators need verifiable evidence of changes that affect serving or
preserved bytes.

**If violated:** a replay or wrong-role key changes protected content, or a
missing audit segment conceals an administrative action.

**Enforced by:** `mkit-server/src/admin` authentication, replay ledger and audit
export, default-off native/Worker mounts, and the existing source relay/root
apply extension. Automatic purge intent, kind-11 timer and audit event commit
with the triggering state change; audit append, dedup receipt and watermark
commit together after source commit. Purge delivery does not await audit.
Manual purge, review, leases, takedown and pruning consumers remain later work.

## BeginUpload decisions and replay share the write batch

**Always:** BeginUpload authorizes before returning a live ticket or membership
result. Those results skip admission and quota but persist a replay record.
A new ticket, its counters, expiry timer, Ticketed reservation, quota and replay
commit in the target ref shard's one guarded batch. D34 uses the common epoch
lease stages, el guard and capped deadline. Replay stores the complete token.

**Because:** repeat operations must allocate neither extra reservations nor cap
slots, and a retry must still return identical token bytes after consumption or
key rotation. Membership decisions in Multi may consult only the local repo row.

**If violated:** a denied request allocates state, racing opens exceed the caps,
retries charge admission again, or token results disappear with ticket rows.

**Enforced by:** `mkit-server/tests/golden_ticket_token.rs`
(`golden_ticket_token_v1`), `mkit-server/tests/begin_upload_codec.rs`, native
`tests/begin_upload.rs` (`lifecycle_*`, `caps_*`, `race_*`, `rejected_*`) over
memory and SQLite (Single and D34), and the wire `tickets.*` cases.
Kind-2 ticket expiry closes unconsumed tickets; admission Pending/Aborted
reconciliation and terminal outcome delivery belong to WP-3.3.

## Ticketed advance publishes only completed uploads

**Always:** a ticketed advance checks the ticket row's repository, head ref,
signer and expiry, then the ticket-specific upload marker and pack blob. It
skips admission. A typed ref conflict preserves every ticket; a successful
advance closes each ticket and writes exactly one committed outcome and local
membership in the same guarded batch. The upload marker is checked before the
pack so a globally present pack cannot satisfy another ticket.

**Because:** an upload ticket alone does not prove bytes arrived, and a ref
conflict must remain correctable while the ticket is live.

**If violated:** a repository could claim another upload's pack, lose its
payment outcome, or strand usable tickets after a CAS conflict.

**Enforced by:** `mkit-server/src/pipeline/advance.rs`, native ticket advance
flow/race tests, and `mkit-server-conformance` ticket wire cases.

## Multipart completion authenticates every part before publication

**Always:** UploadPart verifies the ticket, signed commitment and geometry
before storing bytes. A part counts only after its subtree value matches.
CompleteUpload verifies every receipt, total length and merged BLAKE3 root
before making the pack visible. Both paths bypass metadata and admission;
success writes a content-addressed marker in the upload-marker namespace.

**Because:** an unauthenticated or incomplete part must not replace a good
part, publish a pack or create repository membership.

**If violated:** a forged receipt can publish unverified content, or an
upload can bypass BeginUpload's authorization and admission.

**Enforced by:** `upload::receipt::tests`, `pipeline::parts::tests`, and `pipeline::tests::begin_parts` (WP-1.11a).

## Filesystem multipart staging is separate from pack visibility

**Always:** a filesystem part appears under `server-uploads/<ticket-id>/<index>-<cv>` only after its subtree CV verifies. An invalid re-upload leaves the prior verified part intact. A durable per-index pointer selects the current verified file, so a crash during replacement preserves either the old or new receipt. Completion streams the selected part files through the verifying pack sink, so only an exact total and BLAKE3 root can publish a pack. A missing or stale part tag is invalid while the session exists; a completed session reports `SessionGone`. Sessions older than seven days plus one hour, measured from meta mtime, are swept at startup without touching younger sessions. FS part upload and completion each keep peak live heap growth below one quarter of an 8 MiB part in the shared suite; the memory reference backend buffers parts.

**Because:** receipts must identify durable, verified part bytes while crashes and retries cannot make incomplete bytes visible as packs.

**If violated:** a stale receipt could select replaced bytes, or a crash could expose a partial pack or discard a live session.

**Enforced by:** `mkit-server-conformance/src/storage/multipart.rs` on memory, FS, R2 and S3; `mkit-server/src/fs/tests.rs` ticket-layout, restart and seven-day sweep tests; `Feature::Multipart` wire cases on memory, native FS + SQLite, native S3 + SQLite, and Worker R2.

## Object-store multipart staging cannot publish unverified bytes

**Always:** R2 and S3 stage parts under CV-keyed `server-uploads/<ticket-id>/<index>-<cv>` objects. A part becomes visible only after its subtree CV verifies. R2 re-hashes the assembled stream and withholds the final byte of the conditional pack put until the full root verifies. S3 streams each staged part through a subtree hash immediately before completion, then pins each `UploadPartCopy` to the ETag observed on that GET; the ETag identifies the object version, never proves integrity. A failed hash or copy precondition publishes no pack. Successful completion and abort remove session meta before parts, so concurrent completion sees `SessionGone`. Bucket lifecycle rules expire `server-uploads/` after eight days.

**Because:** staged objects can change between upload and completion, while abandoned sessions must not persist indefinitely.

**If violated:** a corrupted or replaced part can publish a pack whose bytes do not match its BLAKE3 root, or a stale session can remain available to another completion.

**Enforced by:** the shared multipart suite on R2 and S3, corrupted-at-rest completion tests, conditional-copy FakeS3 tests, and the R2/S3 lifecycle runbook.

## Storage pressure observes physical capacity after commit

**Always:** Worker pressure samples use the local physical database size only
following a committed batch containing a put, before alarm I/O. Native SQLite
samples the database-wide physical size every 60 seconds and stops on shutdown.
Alerts use the put soft limit, 70%/90% thresholds and five-point hysteresis;
per-instance ten-minute limits survive clearing and re-entry. Only the highest
active severity emits. Counters and gauges are never sampled; Worker latency
observations are sampled once per hundred calls across the isolate.

**Because:** logical row bytes do not measure the physical storage cap, and
pre-commit or unsampled latency logging can mislead or overwhelm operators.

**If violated:** capacity exhaustion becomes invisible, or repeated writes
flood logs while operators need the critical alert.

**Enforced by:** `telemetry/pressure.rs` pure transition tests, Worker
`ns_object::PressureStore` and `tests/stores.rs` over the DO SQL shim,
console sink/subscriber tests, and native `pressure.rs` shutdown/size-task tests.

## Connect read authentication is scoped to one attempt

**Always:** a Connect client with a signer signs each repository read over
the exact HTTP request body, including streaming-request framing. Each retry
has fresh identity headers. Writes retain their logical-operation nonce, and
the grant header stays outside the signed canonical string. Discovery and
grant-epoch RPCs are never signed; grant-epoch RPCs carry no repository.

**Because:** read authentication selects the writer or private-reader view,
while replay protection applies only to writes. A grant is selected locally
and may change without changing the authenticated operation.

**If violated:** a private read can become anonymous, a retry can use an
expired identity, or a write can silently mint a new nonce.

**Enforced by:** the Connect procedure classification and envelope tests,
client retry tests, and `mkit_core::write_auth::verify_headers` checks over
captured request bodies.

## Implicit transport-identity membership is session-bound

**Always:** implicit (transport-identity) membership is granted only for
packs uploaded and verified in the same session and repository; the
packmap check only refuses. A session's pending set holds at most seven
distinct packs, dies with the session, and is consumed by that session's
next packmap write. A packmap is refused when its node's `prev` is
neither absent nor the packmap value the write replaces, so the
ssh/enc consuming write never adds a new non-member (values written
over Connect are not chain-validated, so this guarantee covers values
written over ssh/enc); it is also refused when its node or a listed pack is
neither pending nor already a member of the bound repository (a pending
packlist listed as a pack is refused: a packlist is a node, not a
pack), or when it lists more than 1,024 packs; the check never adds
membership for a pack it merely names, and no reservation or outcome
rows are created — there is no reservation to keep one outcome per.

**Because:** ssh and enc clients cannot carry signed upload tickets, so
the transport binds them to the session instead. Letting the packmap
check grant membership, or letting pending state outlive a session,
would let a client claim packs it never uploaded — the membership
oracle a ticket's signature otherwise prevents.

**If violated:** a writer could publish packmaps naming packs it did not
upload, minting membership without possession and breaking repository
isolation across sessions and repositories.

**Enforced by:** `mkit-server/src/pipeline/mod.rs`
`check_implicit_packmap` and `update_packmap_consuming` unit tests,
`mkit-server/src/ssh/tests.rs` pending/consume/reconnect/isolation
cases, `mkit-cli/tests/serve_golden.rs` session-3 wire goldens, and
`mkit-server-native/tests/enc_listener.rs` bound-repository cases.

## Private repositories are indistinguishable from missing ones

**Always:** an unauthorized read of a private repository answers the same
`not_found` — code, message, details and headers — as a missing
repository, from `ServerError::repository_not_found()`. A signed read
verifies its envelope in full before any repository lookup and never
creates or consumes a replay record.

**Because:** SPEC-WRITE-GRANTS §9.2/§9.3; private repositories must not be
enumerable, and reads must not spend replay capacity.

**If violated:** private repository existence leaks through an error
difference, or reads consume replay capacity.

**Enforced by:** `pipeline::authorize_read` and `policy::read::decide`;
the pipeline `private_repository_reads_return_the_missing_repository_error`
and `a_signed_read_writes_no_replay_rows` tests; the connect_dispatch and
wire `reads.private_not_found_byte_identical` cases.


## Scheduled verification checkpoints retain closure authority

**Always:** a scheduled job's guarded checkpoint and the deletion of a child
satisfied by a member pack commit together. The checkpoint retains that pack
for the consuming advance's membership recheck. Only a completed decode may
emit index rows, and Verified follows delivery and extraction. Rebuilding job
rows cannot downgrade an already Verified pack.

**Because:** a crash between deleting a child and recording its member would
lose the evidence needed to catch GC or generation changes. Async verification
must retain the same repository authority as inline verification.

**If violated:** an advance can accept an open closure, or storage damage can
turn a monotone verification result into a contradictory persisted rejection.

**Enforced by:** `mkit-server/src/indexed/job.rs` atomic closure checkpoints and
state guards; the job-driver crash sweeps, satisfying-member removal test,
Verified rebuild test, and Scheduled pipeline pending/delivery tests.

## Paid HTTP reads reserve durably and settle once

**Always:** a reservation-bearing HTTP read records Pending(Read) before
returning a body; transmission stops at the configured creation-based deadline.
Completion and reconciliation conditionally replace the same pending bytes.
Partial transmission records ReadServed(actual bytes handed to the stream),
and a zero-byte failure records Aborted(INTERNAL); HEAD succeeds with zero bytes.

**Because:** charging without a durable obligation loses accounting on a crash,
and independent terminal writes can charge one reservation twice.

**If violated:** a paid stream can escape accounting or create duplicate outcomes.

**Enforced by:** `pipeline/http_admission.rs`, `http_objects/paid.rs`,
`timers/reservation_reconcile.rs` and the focused `http_objects/paid_reads` tests.
Stage 2 only; adapters must retain the injected spawner's tasks (WP-4.16).

## HTTP URL tokens bind before stored epoch access

**Always:** private HTTP reads precheck signatures before repository lookup,
then bind audience, repository, decoded target, expiry and lifetime before
reading the stored epoch. Public reads ignore every token result. A valid
private token still requires the Authorizer, and the caller stays anonymous.
Private immutable freshness never exceeds the token's remaining lifetime.

**Because:** early epoch access reveals extra state to invalid tokens, and
cache freshness beyond expiry extends a private authorization capability.

**If violated:** invalid tokens can probe stored state or private content can
remain fresh after the authorization expires.

**Enforced by:** `pipeline/http_tokens.rs`, `policy/read.rs` and counted-store
`http_objects/private_tokens` tests. Stage 2 only; shared-cache bypass belongs
to the adapters in WP-4.16.

## Published ref snapshots never authorize a read

**Always:** configured snapshots serve only anonymous reads after the authoritative
coordinator authorization. Signed reads bypass them, private publication is skipped,
and inspection configuration refuses live fallback. Snapshot misses or expiry use the
same bounded live merge and repository-bound token contract. Dirty generation and timer
seeding commit with index changes; upload completion cannot clear a newer generation.

**Because:** a ref-data cache must not become a visibility cache, an inspection bypass,
or a source of lost index updates after an upload race.

**If violated:** private or pending values leak, or anonymous listings remain stale
without a future alarm wake.

**Enforced by:** core `pipeline/tests/published.rs` and Worker
`published_view/tests.rs`; runtime feature/configuration are off by default (Stage 2).

## HTTP adapter mounts remain explicitly opt-in

**Always:** the native and Worker HTTP-object adapter features are default
off, and a mount requires explicit indexed and HTTP configuration plus
adapter opt-in. Mounted requests retain escaped paths and empty queries,
stream without collecting bodies, suppress every HEAD body, apply read
CORS to every response and perform no shared-cache operations. URL-token
active and retained public keys remain distinct from other deployment roles.

**Because:** Stage 1 must not expose indexed content, private content must
not enter shared caches, and URI normalization or query logging could
reinterpret paths or disclose bearer capabilities.

**If violated:** a deployment exposes routes unintentionally, leaks private
content or tokens, or serves a different object from the requested URL.

**Enforced by:** native `tests/http_mount.rs`, Worker `http_mount` tests,
 default feature/startup configuration, and the release feature gate.

## HTTP proofs share content admission and settlement

**Always:** proof contexts are published-reachable and their exact decoded paths
match the selected leaf before validators/payment. Proof ETags are selected before
common weak validation. Requested-content and exact encoded-size caps precede
anonymous GET/HEAD admission; incremental wire sizing stops metadata collection
when its encoded prefix exceeds the cap. No Merkle/Bao proof is built until
allowance. HEAD never builds. Build or planned-length failure after reservation aborts before bytes;
consumption and cancellation settle actual encoded bytes through the common read
finalizer. Canonical source reads enforce repository membership, takedown checks,
integrity and a cumulative decode budget, retaining one preceding chunk at a time.

**Because:** a proof representation must not bypass payment, reveal unpublished
contexts, trust global CAS as authority, or retain an unbounded prefix of file bytes.

**If violated:** free paid downloads, disclosure of pending content, leaked
reservations, incorrect byte accounting or prefix-dependent memory exhaustion.

**Enforced by:** common HTTP `proof`/`paid_reads` tests, native mount verifier round
trips, core structural/golden sizing tests and the existing bounded prefix builder
tests. Preparation, reachability and post-admission canonical reads share
WP-5.4's reader facade and serving-stop seam; cached leaves cannot authorize
an orphan commit or bypass held membership. Successfully selected range chunks, including
preceding length-proof chunks, pass membership and takedown checks before
validators or admission; selector/cap errors still follow validators.
Native mounts remain opt-in; Workers
prefetch is WP-4.14b-2.

## Published refs and durable dependency work (WP-5.4)

**Always:** branch head and packmap publish as one pair at the greatest contiguous
cleared-or-resolved prefix. Ref deletion establishes a boundary without resetting
its sequence; late clearance may publish retained membership but cannot resurrect
an old ref. **Because:** live commits and completed inspection are different
facts. **If violated:** readers can observe uncleared or resurrected content.
Enforced by `store/publication.rs` guarded append/clear/prefix and paired RefShard
planning; out-of-order and deletion/recreation tests assert the boundary.

**Always:** inspection-enabled publication accounts for every external source
used by every consumed entry, including unreachable surplus entries and every
intermediate source in a delta chain. Own additions never waive external-base
publication. Blocked advances retain kind-12 work until all dependencies and
obligations complete; holds/hits cannot auto-clear. **Because:** an inspector Pass
and live membership do not establish reader-visible dependencies. **If violated:**
pending content can become public through cross-ref reuse or an external delta.
Enforced by native MemberCache exports, Scheduled vc6 exports, server pair
verification and guarded PublicationRecheck. Native surplus and Scheduled
fault/restart chain tests pin exports; Single/D34 relay/restart tests prove progress
without client traffic. Paid Worker activation reserves one bounded fire; Free
retains unknown timers and inspection is not activated there.

**Always:** private-read authorization precedes view selection. Readers use
published refs/membership; writers retain live refs and pending membership, but
held bytes are absent to both. **Because:** view classification cannot grant
permission or turn quarantine into a distribution channel. **If violated:**
private or held content leaks. Enforced by read_policy, ViewStore and the trusted
coherent PublicationPolicy serving-stop seam; HTTP and tokens remain anonymous.
RPC identity/pending/held tests, private token/proof tests and existing authorization
matrix cover the paths. The actual inspector/flag scheduler and cache purge remain
WP-5.5c/5.6a responsibilities; this change does not claim their activation.

## Independent global denial and pending takedown intent (WP-5.6a-1)

**Always:** current V1 rows and every active V2 action keep denying independently;
accepted intents bind immutable verified descriptors and return success only after
all denial actions activate. Manifest chunks stop only in repositories holding the
blocked manifest. Acceptance remains incomplete with preservation pending.
**Because:** source loss, overlapping actions and stale caches must not undo denial
or turn acceptance into completion. **If violated:** blocked bytes become reusable
or a request loses preservation responsibility. **Enforcement work:** ContentIndex V2
guards, immutable action/inventory pages, fresh pipeline denial checks and audited
intent activation, including contextual HTTP manifest checks, ticketless closure
and bounded namespace purge, with source tests and independent reviews. Gate
exceptions are recorded in the implementation contract; production takedown
activation remains gated on WP-5.6a-2 and launch gates.

## External authority revocation fences final acceptance

**Always:** with authority fencing enabled, a completed namespace generation
barrier prevents every older Authority allowance from accepting a new write.
Facts survive retries, visibility writes compare the coordinator generation,
and D34 writes guard generation-bearing leases and backend deadlines. Ticket
staging coalesces client frames in at most 256 KiB of private buffering and
checks the ticket's generation before and after every actual backend write,
plus receipt, completion and marker boundaries. Metadata work depends on
declared bytes, never the number of client frames. Durable
mode at generation zero prevents a disabled executor from accepting through a
fenced lease, fresh shard, visibility operation or ticket. Initial activation
finishes its barrier before granting ready leases and creates no accounting
namespace. Grant epochs remain independent. Generation/recovery-bound durable
cursors keep bounded completion progressing across cold executor instances;
recovery invalidates them while preserving the fence.
All-key stores inspect durable fence evidence even on disabled Single
executors; atomic all-key stores also guard the observed generation and mode
at acceptance. Single batches these reads into its existing read-ahead call.
Ref-only stores omit unsupported metadata reads and retain sequential ref
batches. Their capabilities cannot enable fencing; generation-bearing plans
on any incapable store refuse rather than dropping their protection.

**Because:** stopping future hook allowances cannot revoke an allowance already
paused between authorization and durable acceptance.

**If violated:** a revoked delegate can commit after revocation was acknowledged.

**Enforced by:** the atomic plan, visibility and ticket guards and shared lease
renewal/completion; memory/SQLite authority tests in
`rust/crates/mkit-server-native/tests/epoch_leases.rs`. Deployment activation is
optional and requires an Authority hook with explicit generation facts.

## Worker extracted-object backend completion verifies before visibility

**Always:** server-internal object multipart sessions pin a trusted raw-root/CV
plan, geometry and operation identity before staging. Actual streamed parts
verify length/CV before receiving opaque backend receipts. Completion checks the
ordered receipt/session binding, geometry and merged root before R2 completion;
it never rereads part payloads. All R2 object writer paths share an immutable
root/length pin. Public pack receipt limits and upload semantics are unchanged.

**Because:** R2 completion immediately publishes and has no conditional object
write option. An ETag selects a backend part and does not prove integrity.
The canonical verifier binds object identity to one correct raw root; AlreadyPresent is
advisory and cannot replace repository-local source verification or charging.

**If violated:** a replacement, forged receipt or competing writer could expose
unverified bytes or falsely authorize reuse in another repository.

**Enforced by:** `r2/object_multipart.rs`, R2 object sink/completion root
pins, bounded-object multipart model tests, and the local R2 runtime probe.
The parent WP-4.10b must establish canonical identity plus immutable verified
source evidence in its first bounded source pass; that integration is pending.

### Pending holder work protects bytes beyond hold TTL (WP-4.10b foundation)

**Always:** any content-shard `gp` row for an object prevents collection.
Insertion guards and bumps `c`; the row does not expire by age. Identical
ownership retry does not bump, and changed ownership refuses.

**Because:** queued holder work may still apply after its ticket or ordinary
GC hold expires. Removing that protection can delete an object before its
durable holder arrives.

**Enforced by:** `ContentIndex::protect_pending_holder` uses guarded fresh
block/deleting observations and NotAfter. `collectable` checks one pending row
and its final plan guards `c`; unknown pending state closes collection. The
content relay hook atomically commits holder/count/c changes, ordinary hold and
exact pending-row release, and the watermark. A late blocked holder retains a
durable takedown request for WP-5.6a. No permissive release API is exposed.

WP-4.10b-1 keeps Extract fail-closed. Source verification, holder enqueue/renewal
and extraction-driver integration remain WP-4.10b-2 work.
