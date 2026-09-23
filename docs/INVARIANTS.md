# Invariants

Properties that must always hold across the mkit monorepo, outside any
single crate or spec. Each entry states the invariant, why it matters, and
what breaks when it is violated. A regression test enforces each one; find
it by the file path listed under "Enforced by".

## Managed authority never opens an incomplete data plane

**Always:** the optional managed Worker denies all seven repository data
methods and every RefStore data path before reading refs, objects or quota.
The owner is pinned by deployment configuration; an initialized policy with
a different audience, repository or owner is unavailable, never reset.

**Because:** a partial permission implementation could disclose a repository
through an unguarded read or internal binding, while a configuration change
could silently reinterpret a durable policy.

**If violated:** an owner or collaborator could reach repository data before
the complete authorization profile exists, or another key could inherit an
old deployment's authority.

**Enforced by:** `apps/vcs-worker/src/worker_impl/{managed,refstore,access_store}.rs`
and `apps/vcs-worker/src/access_policy.rs` native validation tests. Runtime
closure and durable latch tests are in `apps/vcs-worker/tests/managed_access.py`.

## Scoped workspace reads and staging stay inside authenticated selection

**Always:** scoped CLI operations bind an independently supplied base and exact
selected paths to a verified bundle before installation. Working-file capture
uses no-follow descriptors rooted at the opened scoped workspace, checks mode,
link count, size and metadata, and feeds a complete selected-file batch into
the authoritative generation-CAS stage transition. Extra paths are reported
by a bounded name scan with an explicit incomplete indicator; no operation
deletes them or reads their content. Human and JSON output label content and
history as partial.

**Because:** the durable selection is a coverage boundary, not a full
repository or a host write permission. A staged A and working B must remain
distinct after a restart.

**If violated:** a CLI could read hidden files, silently omit unseen extras,
or overwrite a staged edit from current working bytes.

**Enforced by:** `rust/crates/mkit-cli/tests/scoped_workspace_cli.rs` and
`rust/crates/mkit-core/src/partial/layout.rs` capture and state tests.

## Partial recipient facts precede conditional publication

**Always:** complete-base recipient validation authenticates the source-only
base, checks the actual path-occurrence diff, typed resulting Snapshot and
shared resource budget before returning a verified value. Generic explicit
transfer requires an existing append-only packmap and a truthful single-attempt
advance; ambiguous mutating replies remain unknown.

**Because:** a valid MKWU only proves its portable inventory, and hidden
transport retries can turn an earlier success into a later CAS conflict.

**If violated:** a hidden change can be laundered as a selected replacement,
ordinary history can become undiscoverable, or an accepted update can be
reported as definitively rejected.

**Enforced by:** core `tests/partial_edit.rs` recipient cases, file transport
`tests/partial_publication.rs`, and the `SingleAttemptAdvance` API boundary.

## Partial snapshots prove selected coverage, never authority or closure

**Always:** a verified partial snapshot is bound to an independently supplied
base id and exact selection, retains complete authenticated ancestor Trees and
complete selected file representations, and reports `SelectedOnly` coverage.
It neither grants permission nor claims that hidden snapshot/history objects
were supplied.

**Because:** content integrity, signer identity trust, host authorization and
complete-repository availability are different facts. Conflating them lets an
untrusted bundle choose its own trust root or turn omitted data into a false
completeness claim.

**If violated:** fabricated selected entries, widened selections, hidden reads,
or incomplete object sets can be treated as authenticated full repositories or
publication authority.

**Enforced by:** `mkit_core::partial::verify::tests` for independent context,
exact inventory, hidden-source reads and incomplete ordinary closure;
`rust/crates/mkit-core/tests/golden_partial_workspace.rs`; and the bounded
`partial_workspace` fuzz target.

## Partial edits preserve untouched commitments and export explicit bytes

**Always:** a replacement overlay changes only authenticated selected
regular/executable file content, preserves every untouched Tree entry triple and
destination mode, and rebuilds ancestors by path occurrence. Its `MKWU` export
contains exactly the signed ordinary Commit, rebuilt Trees, and every changed
file representation and chunk in an id-sorted raw-only pack. Reused or
previously present changed-file bytes are never omitted because another store
already has their ids. Reused dependency identities are retained and traversed
once per distinct representation rather than once per destination, and share a
single incremental output budget with generated objects, while file lengths
remain occurrence-counted. Export revalidates every output-applicable
active limit before pack construction, so its encoded result decodes under the
same limits.

**Because:** a selected-only client can preserve hidden commitments but cannot
inspect hidden data or run a full closure-difference plan. Tree ids reused at
different paths are distinct edit contexts, and global-store dedup would turn an
explicit update into an unauthenticated dependency on hidden recipient state.

**If violated:** one edit can mutate another path that shared its old Tree,
omitted data can be mistaken for deletion, modes or hidden siblings can change,
or a recipient can accept an update whose changed content was never supplied.

**Enforced by:** `rust/crates/mkit-core/tests/partial_edit.rs` tests
`occurrence_rebuild_preserves_hidden_triples_and_exports_complete_raw_inventory`,
`one_sided_edit_of_shared_tree_keeps_other_occurrence_unchanged`,
`sibling_and_nested_edits_converge_without_overwriting`,
`selected_representation_reuse_exports_even_when_already_in_base`, and
`large_replacement_uses_canonical_writer_and_substitution_rejects`,
`export_revalidates_stricter_file_and_tree_limits`, and
`candidate_object_and_framing_limits_round_trip_at_exact_bounds`; the private
`dependency_retention_is_unique_across_reused_destinations` structural oracle;
plus the
bounded `partial_overlay` fuzz target's deterministic replay, canonical-object,
mode, untouched-triple, and exact/over aggregate-content boundary oracles.

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

**Always:** every live `mkit serve` process holds a **shared** kernel
lock (`mkit_core::repo_lock::acquire_shared`) on `<common_dir>/serve.lock`
for its entire lifetime, across all three of its modes (stdin SSH-frame,
`--listen-enc`, `--http`). Every command that acquires `worktree.lock`
or `worktrees.lock` (`mkit-cli`'s `acquire_worktree_lock` /
`acquire_worktrees_registry_lock`) immediately probes that same
`serve.lock` non-blocking-exclusive (`mkit_core::repo_lock::probe_exclusive`)
and, if it finds the lock busy, prints a warning to stderr naming the
served root before proceeding.

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

**Enforced by:** `mkit-cli/tests/serve_guard.rs`.

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

## Public partial workspaces prove selected files, not confidentiality or publication

**Always:** `public-partial-v1` fetches a digest-addressed bundle only from a
configured HTTPS origin after resource validation is explicitly enabled,
verifies independently supplied base and selection in portable wasm, materializes
selected regular/executable files, and signs at most one ordinary candidate
whose parent is that base. AgentGrant is rechecked after asynchronous public
reads (including the revocation read), immediately before signing, and inside the durable admission
transaction. Export is `candidate_ready`, never remotely accepted. Omitted paths
are not deletions. Selected capture does not silently drop legacy-ignored names.

**Because:** a public static bundle is not a private host, and a signed
candidate is not a published ref. Conflating those lets omitted files look
deleted or treats a downloadable `MKWU` as admission.

**If violated:** the service can fetch hidden objects, invent a Remix import,
claim remote acceptance, or leak owner credentials to the bundle origin.

**Enforced by:** `apps/workspace-worker/src/partial-source.test.ts`,
`apps/workspace-worker/src/partial-candidate.test.ts`,
`apps/workspace-worker/src/partial-wasm.test.ts`,
`apps/workspace-worker/src/partial.lifecycle.test.ts`,
`apps/workspace-worker/src/partial-runner.integration.test.ts`,
`apps/workspace-worker/src/workspace-state.test.ts`,
the opt-in `rust/crates/mkit-core/tests/partial_consumer_oracle.rs` recipient check,
`apps/workspace-worker/src/workspace.integration.test.ts`, and
`apps/workspace-worker/src/auth.test.ts`.

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
walk, and push/fetch pack planning &mdash; takes
its edges from `ops::graph::children(obj, mode)`. Snapshot mode omits
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
`reachable_snapshot_excludes_parent_commit`, and
`mkit_core::verify::closure::tests::history_on_snapshot_reports_parent_missing`
/ `snapshot_on_history_reports_parent_unreferenced`.

## Streaming closure verification reads only reachable objects, each once

**Always:** `verify_closure_streaming` fetches each visited id at most once,
fetches no id outside the selected snapshot/history closure, and drops an
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
snapshot/history fetch sets.

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
incompatible carriers.

**Enforced by:** `mkit_core::pack::tests::raw_only_writer_emits_v1_raw_for_compressible_payload`,
`raw_only_writer_rejects_deltas`,
`mkit_core::verify::closure::tests::delta_pack_is_profile_violation`,
and `rust/tests/golden/closure/neg_delta_entry.*` /
`neg_compressed_entry.*`.

## Scoped-workspace CURRENT selects one coherent state; stage/pending are authoritative

**Always:** a scoped workspace's `.mkit-scoped/CURRENT` names exactly one
manifest-digest-keyed immutable generation, and readers decode only the
records that generation binds &mdash; never the highest surviving generation, and
never working-tree contents. The staged file map and pending operation come
from the selected generation alone; the working tree is materialized only at
create and is never consulted or rewritten by transitions. A transition
validates the complete proposed state &mdash; bindings, selection coverage,
pending/accepted consistency, the exact produced-object inventory minus the
base-authenticated set (each selected representation id AND its declared
chunk dependencies), staged representations, and aggregate limits &mdash;
before `CURRENT` can select it, so
`CURRENT` never names a generation the reopen checks would reject. Immutable
artifacts and generation members install by sibling-temporary write, fsync,
and no-replace rename, so an interrupted write can never occupy a canonical
digest name. The lock is held by a fresh inode-verified per-operation
descriptor that re-verifies the sentinel identity after the blocking flock
returns, so same-handle callers serialize, a sentinel replaced while a writer
waits refuses the stale acquisition, and a panic cannot strand it.

**Because:** torn writes and crashes are expected. Reading anything but the
CURRENT-selected generation can pair a new workspace record with an old
stage or a foreign pending update, and treating the working tree as
authoritative would silently discard staged-but-unmaterialized edits.
Publishing before validating the whole state can strand a workspace on a
generation no reader accepts, and writing a canonical name directly lets a
torn write poison every retry of the same operation.

**If violated:** a crash mid-transition can resurrect a stale stage, an
adversarial or torn generation can be mistaken for committed state, or a
user's divergent working file can overwrite staged content &mdash; each
misrepresenting what the next export would sign. A rejected API call could
still publish an unloadable generation; a torn artifact could make a
legitimate retry fail on `CorruptArtifact` forever; a shared-handle race
could fork the generation sequence.

**Enforced by:** `rust/crates/mkit-core/tests/partial_local.rs`
(`missing_or_corrupt_current_fails_closed`,
`corrupt_manifest_member_bundle_object_update_all_fail_closed`,
`no_highest_generation_or_worktree_fallback`,
`stage_persists_across_restart_and_workfile_is_ignored`,
`contention_same_handle_serializes`,
`contention_separate_handles_serializes`,
`staged_alternate_reuse_survives_replay_and_pending`) and
`mkit_core::partial::state::tests` fault-seam cases covering every
commit-sequence injection point plus pre-publication validation, staged
chunk-bound, retained-inventory, chunked-inventory, deterministic
lock-contention, lock-gate-isolation, and stale-sentinel cases
(`over_budget_complete_stage_is_rejected_before_publish`,
`staged_chunked_declared_total_stops_at_first_overrun`,
`required_inventory_bound_check_precedes_read`,
`bytes_copy_of_selected_content_survives_reopen_and_pending`,
`bytes_copy_of_chunked_selected_content_survives_reopen_and_pending`,
`chunked_bytes_copy_and_reuse_persist_identical_stage_records`,
`mixed_chunked_batch_shares_base_chunks_and_retains_new_ones`,
`lock_serializes_competing_writers_deterministically`,
`lock_gates_are_isolated_per_workspace_and_phase`,
`replaced_lock_sentinel_refuses_stale_waiter`).
