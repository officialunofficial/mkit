# Changelog

All notable changes to mkit are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **`mkit blame` line ranges and revision argument.** `blame` now accepts
  `-L`/`--lines` to restrict output to a line range — `<start>,<end>`,
  `<start>,+<n>` (n lines forward), `<start>,-<n>` (n lines back, ending at
  start), `<start>,`, `,<end>`, and a bare `<start>` — and an optional
  `[<rev>]` argument (`mkit blame <rev> <file>`) to blame the file as of any
  revision instead of only `HEAD`. Range semantics and diagnostics match
  `git blame -L`: inclusive bounds, inverted ranges swap, over-long ends
  clamp to EOF, the low bound is validated against EOF, and bad input
  reproduces git's messages (`-L invalid line number: <n>`, `-L invalid
  empty range`, `file <f> has only N lines`).
- **`mkit blame -w` / `--ignore-whitespace`.** Ignores whitespace when
  matching lines across revisions (like `git blame -w`, ignoring *all*
  whitespace), so a whitespace-only edit — reindent, tab↔space, spacing
  tweak — no longer steals attribution; output still shows the file's
  current bytes.
- **`mkit blame -M` / `-C` move & copy detection.** `-M` (`--find-moves`)
  credits a block moved *within* the file to its origin commit; `-C`
  (`--find-copies`, repeatable, implies `-M`) credits a block copied *from
  another file*, resolving the true origin by blaming the source file.
  Repeating `-C` widens the search from files changed in the commit to
  every file in the parent commit. Detection is block-based over normalized
  keys: the longest contiguous block above git's default thresholds (20 for
  `-M`, 40 for `-C`) is credited, so a moved block beside genuinely-new
  lines is split out and — combined with `-w` — a block copied with a
  whitespace change is still detected. Configured through a typed
  `MoveDetection`/`CopyDetection` API that can't express an invalid
  "enabled but zero-threshold" state. Attribution remains first-parent
  only. Documented divergences from git: inline `-M<num>`/`-C<num>`
  threshold forms aren't exposed on the CLI (the core API takes a custom
  threshold); `-C -C -C` (whole-history search) is approximated as `-C -C`;
  when two source files hold an identical block the earliest by tree-path
  order wins, and when one source holds the block at several offsets the
  earliest offset wins (git scores candidates and tracks line identity
  through its diff); and within a single unmatched run longer than 10,000
  lines only the whole run is matched, not sub-blocks (a cost bound; the
  matcher already caps inputs).
- **`mkit blame --ignore-rev` / `--ignore-revs-file`.** Skip "noise"
  commits — mass reformats, license-header sweeps, renames — during
  attribution, like `git blame --ignore-rev`. A line that would be credited
  to an ignored commit falls through to the commit that previously changed
  it; a line the ignored commit genuinely inserted stays put (git's default,
  no marker). `--ignore-rev` is repeatable and accepts any revision (short
  hash, ref, `HEAD~2`); `--ignore-revs-file` reads full hex object names one
  per line, skipping blank lines and `#` comments (including inline) — both
  verified against real `git`. Unknown or malformed inputs reproduce git's
  messages (`cannot find revision <rev> to ignore`, `invalid object name:
  <token>`, `could not open object name list: <path>`), though mkit returns
  its sysexits-style exit codes rather than git's blanket `128`. mkit does
  not auto-read `.git-blame-ignore-revs` or a `blame.ignoreRevsFile` config
  key — pass the file explicitly.
- **`mkit blame --reverse <start>..<end>`.** Walks history *forward*
  instead of backward, like `git blame --reverse`: blames the `<start>`
  version of the file and attributes each line to the **last** commit in
  the range in which it still existed (answering "which commit removed or
  last touched this line"). `<start>..` defaults `<end>` to `HEAD`; an
  explicit `<start>` is required, and `-w`/`-L` compose with it. Verified
  field-by-field against real `git blame --reverse` (survivors → end,
  removed/modified lines freeze at their last commit, unchanged commits
  advance attribution, file-absence kills a line). Deliberate divergences:
  mkit reports a clear error for a missing / malformed / empty range or open
  `<start>` where git prints a cryptic "dig up from" message; a line that
  never survives a step is shown without git's leading `^` boundary marker
  (mkit's tab format has no `^`); and the range is followed along `<end>`'s
  **first-parent** chain only (mkit blame is first-parent only — a `<start>`
  reached solely through a merge's second parent errors rather than
  resolving; the full-history walk in #458 would lift this).

### Removed

- **Operational slim-down.** Removed governance/process ceremony whose
  maintenance overhead was disproportionate to the project's size:
  `GOVERNANCE.md`, `MAINTAINERS.md`, `TRADEMARKS.md`, `SUPPORT.md`, the GitHub
  issue/PR templates, and eight non-gating or now-obsolete CI workflows
  (`rename-gate`, `crates-owners`, `reproducible-build`, `mutation-score`,
  `state-machine`, `supply-chain`, `typos`, `pr-title`) plus their configs
  (`typos.toml`, `scripts/verify-rename.sh`). Also removed the completed
  `docs/MERKELIZATION-PLAN.md` (the work shipped — see
  `docs/SPEC-MERKLE-OBJECTS.md` and ADR 0001). The license grant
  (`LICENSE-MIT`, `LICENSE-APACHE`, `NOTICE`), `SECURITY.md`,
  `CODE_OF_CONDUCT.md`, `CONTRIBUTING.md`, and the `geiger` unsafe-code
  ceiling check are retained.

### Changed

- **`mkit blame` is now merge-aware by default (git parity).** Blame walks
  the file's whole ancestor subgraph instead of only the first-parent chain:
  at a merge, each line is credited to the first parent that still contains
  it, so a line merged in from a side branch is attributed to the commit
  that actually wrote it rather than to the merge commit — matching
  `git blame`'s default. **This changes output for histories with merges**;
  the new `--first-parent` flag (like `git blame --first-parent`) restores
  the previous first-parent-only attribution and composes with
  `-w`/`-M`/`-C`/`--ignore-rev`. Verified field-by-field against real `git`
  (distinct side-branch lines, first-parent-wins on a line added identically
  on both sides, evil-merge lines credited to the merge, octopus merges).
  This is also the prerequisite for provable blame (#495), which needs
  correct merge-aware attribution before it can be made verifiable. (mkit
  still omits git's `^` boundary marker and uses sysexits exit codes, not
  `128`.)
- **BREAKING (`mkit-core`):** `Tree` and `ChunkedBlob` are now
  content-addressed by a **domain-bound Binary Merkle Tree (BMT) root**
  (`id = domain_digest(TYPE_DOMAIN, bmt_root)`) instead of `BLAKE3` of
  their serialized bytes; every other object type keeps the flat scheme.
  Because a `Tree` id feeds its `Commit` id which feeds every ref, this
  re-addresses all history. Content addressing is preserved (the id is
  still a deterministic function of canonical content) and stays
  tamper-evident (read recomputes the root), and the serialized wire
  format and `schema_version = 0x01` are unchanged — the break is in
  object identity only. Cross-format safety is a **mandatory
  `.mkit/format` repo marker** (`bmt-v1`): a pre-merkle repository is
  rejected at open (`IncompatibleRepoFormat`) instead of silently
  mis-reading every `Tree`/`ChunkedBlob`. Pre-1.0 API/format break, no
  migration. New normative spec
  [`docs/SPEC-MERKLE-OBJECTS.md`](docs/SPEC-MERKLE-OBJECTS.md) pins the
  construction; see also ADR
  [`docs/adr/0001-merkelize-chunkedblob-and-tree.md`](docs/adr/0001-merkelize-chunkedblob-and-tree.md)
  ([#414](https://github.com/officialunofficial/mkit/pull/414)).
- **BREAKING (`mkit-core`):** in the `blame` module, the public type alias
  `BlameResult2<T>` was renamed to `BlameOutcome<T>`, and the unbounded
  `match_lines` function is now private — line matching is an internal,
  size-checked detail of `blame_file_with`. Both are pre-1.0 API breaks; no
  in-workspace consumers were affected. (release-plz's `semver_check`
  enforces the matching version bump at release time.)

### Internal

- Open-source / publish readiness sweep: scrubbed internal identifiers,
  fixed stale manifest/rustdoc claims, deduplicated copy-pasted helpers
  (CLI `emit_err`, transport pubkey decoders, replay/rollback plumbing),
  decomposed oversized modules (`keystore::software`, CLI `serve`), and
  fixed several latent bugs (S3 ref pagination, atomic bisect-state
  write, BLS external-signer fail-closed) with regression tests.

### Security

- **SSH trust-pinning is now actually enforced.** The per-repo
  `ssh.strict_host_key_checking`, `ssh.user_known_hosts_file`, and
  `ssh.identity_file` keys were parsed into `Config` but never threaded
  into the spawned `ssh(1)` process, so the documented control was inert
  (a documented-but-absent security control). They are now mapped into
  `SshOptions` and passed to the child as
  `-o StrictHostKeyChecking=… -o UserKnownHostsFile=… -i …`, matching
  `docs/SSH-SECURITY.md` §3. Pure producer-side wiring — the transport
  already consumed `SshOptions`
  ([#389](https://github.com/officialunofficial/mkit/issues/389)).

## [0.3.0] - 2026-06-15

### Performance

- **Hardened after multi-agent review** (16 findings, all resolved):
  worktree snapshots for `status`/`diff`/safety checks moved to an
  in-memory `EphemeralSink` (no flush cost, no garbage objects, and no
  visible-but-unflushed object can poison content-addressed dedup —
  `SyncPolicy::None` removed); per-file write barriers are real on
  every platform (fdatasync/FlushFileBuffers, not just Apple's
  F_BARRIERFSYNC) so batch durability no longer assumes ext4
  ordered-data journaling; `durability.objects = per-object` config
  key exposes the strict schedule; the index stat cache gained
  ino+ctime fields (catches replace-by-rename and `touch -r`), a
  per-entry racy window for coarse-timestamp files, and `status` heals
  the cache from hash-time observations (never stat-after-verify) and
  never auto-upgrades a v1 index; `stash pop` records the popped
  commit in the recovery log before dropping its manifest entry;
  `status`/`diff` snapshots type-validate staged blobs from the 6-byte
  prologue instead of full read+re-hash, while commit and the other
  tree-publishing paths hash-verify each staged object before a tree
  references it (a corrupt staged object can never be published); pack
  unpack no longer double-hashes every object.

- **Batched durability (`WriteBatch`)**: object writes from one command
  (`add`, `commit`, pack unpack, `stash`) are staged invisibly and made
  durable together at a single commit point — exactly **2 full flushes
  per command** (one over staged data, one terminal device flush)
  instead of 2 per object, with per-file/per-dir writeback barriers
  issued from a scoped-thread pool. Same crash invariant as before,
  stated in SPEC-OBJECTS §10.1: an object is never visible before its
  bytes are durable, and refs/index are only written after their
  referents are durable. `SyncPolicy::{PerObject,Batch}` selects
  the schedule (query snapshots use an in-memory `EphemeralSink`, not a
  sync policy); flush counts and ordering are pinned by unit tests.
  Measured on an M4 Max (APFS): `add`+`commit` of a 100 MiB file
  13.5s → 0.75s; 100 × 10 KiB files 1.1s → 0.18s.
- **Index v2 stat cache**: `.mkit/index` entries now carry
  `mtime_ns`+`size` (SPEC-INDEX v2; v1 indexes read fine and upgrade on
  first write). `add`/`status`/`commit -a` prove unchanged files by
  stat instead of re-reading and re-hashing content — O(stat), with
  git's racy-clean rule applied at read time. `status` with an
  unchanged 100 MiB file: 113ms → 13ms.
- **Zero-copy ingest**: chunk and small-blob writes stream
  `prologue ‖ payload` straight from the source buffer
  (`serialize::blob_prologue`), eliminating two memcpys per chunk;
  `status`/`diff` snapshots use an in-memory `EphemeralSink` and no
  longer pay any durability cost; `worktree::hash_file_object` content-addresses
  without writing, so change detection no longer mutates the store.
- **Checkout**: restored worktree files keep tmp+rename atomicity but
  are no longer flushed per file (the store is the source of truth and
  checkout is re-runnable; matches git).

### Added

- **git-bridge: importer-signed git→mkit import, pull, and fork-mode
  export back** (`mkit git import|fetch|pull`, `mkit git export
  --passthrough`, `mkit git verify|status|format-patch`; behind the
  same default-off `git-bridge` feature;
  [#330](https://github.com/officialunofficial/mkit/pull/330)).
  [`docs/SPEC-GIT-IMPORT.md`](docs/SPEC-GIT-IMPORT.md) pins the
  inbound mapping: a git upstream imports as a downstream fork whose
  every commit/tag is signed by a dedicated, per-state-dir-pinned
  import key (per-key deterministic — same key + upstream ⇒ same
  hashes anywhere), original authorship preserved in the author
  identity, original git bytes retained for audit, and a
  `git-import/v1` attestation minted per head. `mkit git pull`
  fast-forwards or refuses with a native `mkit merge
  upstream/<branch>` hint; force-pushes warn and rewind tracking refs
  only; deletions prune like `git fetch --prune`. Passthrough (fork
  mode, SPEC-GIT-BRIDGE §14) re-emits imported objects as their
  original sha1s so an imported repo publishes as a TRUE git fork
  (shared merge bases, PR-able), with an origin guard refusing
  disconnected re-translations toward any recorded import source.
  `mkit git verify [--fork-audit]` audits bridge state offline;
  `format-patch` renders native commits as `git am`-able patches.
  Journeys in
  [`docs/GUIDE-GIT-WORKFLOWS.md`](docs/GUIDE-GIT-WORKFLOWS.md);
  hostile-upstream surface in THREAT-MODEL §3.1a. Closes the
  importer-signed-import scope of the git-interop exploration.

- **git-bridge: deterministic one-way export to git mirrors**
  (`mkit git export`, behind the default-off `git-bridge` feature;
  [#330](https://github.com/officialunofficial/mkit/pull/330)).
  New normative spec [`docs/SPEC-GIT-BRIDGE.md`](docs/SPEC-GIT-BRIDGE.md)
  pins a byte-deterministic mkit→git object mapping (BLAKE3/SHA-1
  translation with mkit-only fields — signer, signature, identity,
  annotation slots — carried in `mkit-*` commit/tag headers), so the
  original signed mkit objects are reconstructible bit-exactly from a
  mirror and their Ed25519 signatures re-verify (shallow and deep
  verification modes are specified). New `mkit-git-bridge` crate
  implements the mapping with golden vectors under
  `rust/tests/golden/git-bridge/`, round-trip + determinism +
  differential-vs-real-git tests (`git hash-object` id agreement,
  `git fsck --strict`). The exporter pushes with per-ref
  `--force-with-lease` from rebuildable state under `.mkit/git/`,
  skips untranslatable refs loudly (remix ancestry, git-illegal
  names, non-canonical chunking); the import direction is specified
  separately in [`docs/SPEC-GIT-IMPORT.md`](docs/SPEC-GIT-IMPORT.md). PARITY.md gains a scope amendment per its
  own renegotiation rule. Closes the export-bridge foundation scope of the
  git-interop exploration.

- **`mkit mcp` — a local Model Context Protocol server in the CLI.**
  `mkit mcp [--repository <path>]` speaks newline-delimited JSON-RPC
  over stdio so LLM agents can drive local repositories through
  structured tool calls: the git-parity set (status, diffs, log, show,
  branch, add, unstage, signed commit, branch create/checkout, init)
  plus mkit's differentiators (keygen, verify, attest, verify-attest,
  cat-file inspection). Conservative by design: no network operations,
  no history surgery, never passes `-f`; `--repository` confines all
  calls; attestation predicate files must resolve inside the repo,
  trust-roots files outside it; `--signer`/`--algorithm` are always
  pinned explicitly so user config cannot reroute agent-triggered
  signing. See `docs/CLI.md` §"Agent integration".

- **`PinResponse.pin` is `debug_redact`** ([signer.proto]): generated
  `Debug` impls print `[REDACTED]` in place of the PIN, so a stray
  `{:?}` log cannot leak it. Wire format and JSON unchanged.
- **Explicit decode caps on every frame decode.** New
  `mkit_rpc::frame_decode_options()` applies a 16-deep recursion limit
  and the 1 MiB `MAX_FRAME_BYTES` size cap at the protobuf decode
  itself (buffa `DecodeOptions`), in `read_frame` and in the encrypted
  transport's record decodes — so the bound holds even on paths where
  the cipher layer, not the length prefix, does the framing.
- **`rpc_decode` fuzz target**: SignerFrame / SshFrame wire decode
  never panics on arbitrary bytes, plus an `Arbitrary`-driven owned
  encode/decode roundtrip property (new opt-in `arbitrary` feature on
  mkit-rpc, from buffa `generate_arbitrary` codegen). Adopts
  commonware-invariants minifuzz for the `rpc_decode` target.
- **`mkit` Agent Skill + crates/docs MCP server** — a published Agent
  Skill (`SKILL.md`) teaching agents to drive the `mkit` CLI, plus a
  release-gated documentation MCP server indexing the source, SPEC
  docs, and CLI reference at each pinned release
  ([#329](https://github.com/officialunofficial/mkit/pull/329),
  [#331](https://github.com/officialunofficial/mkit/pull/331),
  [#337](https://github.com/officialunofficial/mkit/pull/337)).
- **`samply` profiling support** for the benchmark/profiling workflow
  ([#347](https://github.com/officialunofficial/mkit/pull/347)).

### Changed

- **Idiomatic buffa enum handling** across all crates: raw
  `EnumValue::to_i32` / `as i32` comparisons replaced with
  `EnumValue`'s direct `PartialEq` against enum values, and SHOUTY
  proto value names replaced with the `UpperCamelCase` aliases buffa
  0.7 generates (`ErrorCode::KeyNotFound`, `RefExpectation::Any`, …).
  No behavior change; wire-value pins remain asserted numerically.
- **buffa 0.6 → 0.7.1** across all crates (mkit-rpc, mkit-attest,
  mkit-cli, mkit-transport-ssh, mkit-transport-enc, and the
  contrib/signers reference binaries), with the vendored mkit-rpc
  codegen regenerated under the 0.7.1 toolchain. The wire format and
  all existing generated APIs are unchanged; regeneration adds the new
  `*OwnedView` wrapper types, `HasMessageView` impls, and idiomatic
  `UpperCamelCase` enum value aliases. The declared requirement is
  `0.7.1` (not `0.7`) because regenerated packed-view decoders call the
  `RepeatedView::reserve` hook introduced in 0.7.1.
- **commonware 2026.5.0** dependency train across the workspace,
  including the MMR / authenticated-bitmap port to the new APIs. No
  wire-format or object change.

### Fixed

- **Keystore protector mismatch now names both protectors instead of an
  opaque error** ([#326](https://github.com/officialunofficial/mkit/issues/326)).
  A software key record whose data-encryption key was sealed by one
  protector but opened with another previously surfaced a redacted,
  unactionable message. A new structured `Error::ProtectorMismatch {
  required, got }` reports e.g. "software key record is sealed with the
  `macos-keychain` protector but was opened with the `software`
  protector — its encrypted data-encryption key can only be unwrapped
  by the protector that sealed it". Protector identifiers are surfaced
  (they are not sensitive) while the existing path/label redaction is
  preserved. The message names the software-record DEK protector, not a
  signing-key backend, so it does not misdirect toward `key.backend` or
  `<backend>:<label>` routing.
- `scripts/regen-rpc-proto.sh` could silently copy **stale** staged
  sources back into `generated/` instead of fresh codegen output: the
  default build mode fills its `OUT_DIR` with the same `.rs` file set,
  and the script picked whichever was freshest. Codegen mode now drops
  a `.mkit-rpc-codegen` marker that the script requires.

### Security

- **New `git-bridge/v1` attestation predicate** (SPEC-GIT-BRIDGE §11;
  [#330](https://github.com/officialunofficial/mkit/pull/330)):
  `mkit git export` mints one DSSE/in-toto attestation per exported
  head, signed with the exporter's configured signer — subject is the
  mkit commit (BLAKE3) + ref name; the predicate carries the
  `gitCommit` SHA-1 as a locator (not a proof — SHA-1 is git's naming
  function, never a security boundary here), the mirror URL, and
  schema/spec versions. Bridge attestations are distinguishable from
  author signatures by predicate type and keyid; they assert "this
  exporter translated this commit", never authorship. Published on
  the mirror under `refs/mkit/attestations`. Threat model unchanged:
  carried signatures verify only over reconstructed mkit bytes, and
  translated history that fails reconstruction fails closed.
- **Advisory triage**: `RUSTSEC-2025-0055` (tracing-subscriber 0.2
  ANSI-escape logging) is ignored in `deny.toml` and the audit
  workflow — it reaches the tree only transitively via
  `commonware-runtime → arkworks (ark-r1cs-std) → tracing-subscriber
  0.2`, is arkworks-internal logging not on mkit's logging path, and
  has no reachable fix. Flagged for re-justification by 2026-08-21.

## [0.2.0] - 2026-06-10

### Added

- **Annotated and signed tags** (`mkit tag -a` / `-s` / `-m`,
  [#230](https://github.com/officialunofficial/mkit/issues/230)). Adds
  a new storable object type `tag` (`object_type = 0x07`) carrying the
  tagged object's hash + type, the tagger identity, a message, a
  timestamp, the signer public key, and a 64-byte signature. `-a`
  creates an unsigned annotated tag; `-s` creates a signed tag whose
  signature is Ed25519 over the canonical tag bytes under a **new,
  distinct** signing domain `mkit.tag\0` (deliberately separate from
  the commit/remix domains to prevent cross-protocol signature reuse).
  Lightweight `mkit tag <name>` is unchanged. `mkit verify <rev>` now
  verifies signed tags (resolving a tag name to its tag object), and
  `mkit cat` surfaces annotated-tag metadata. The new object type is an
  **additive** allocation within object schema v1 — no existing object
  layout, signing bytes, hash, or golden vector changes. New golden
  vectors are pinned under `rust/tests/golden/tags/`. Specs:
  [`docs/SPEC-OBJECTS.md`](docs/SPEC-OBJECTS.md) §6a,
  [`docs/SPEC-SIGNING.md`](docs/SPEC-SIGNING.md) §4a.
- **`mkit-keystore` crate** — pluggable signing-key vault subsystem
  (PR [#109](https://github.com/officialunofficial/mkit/pull/109),
  hardened in
  [#135](https://github.com/officialunofficial/mkit/pull/135) and a
  long tail of review-feedback follow-ups). Ships with backends for
  software (encrypted-at-rest, the foundation backend), software-raw,
  macOS Keychain, Windows Credential Store, Linux Secret Service,
  systemd-creds, and YubiKey (PIV and OpenPGP applets). Public
  interface and threat model are documented in
  [`docs/SPEC-KEYSTORE.md`](docs/SPEC-KEYSTORE.md).
- **`mkit key …` subcommand family** — `generate`, `list`, `import`,
  `export`, and `delete` against any built-in keystore backend, with
  `--backend`/`--label`/`--algorithm` selectors and a `--json`
  output mode on `list`.
- **`<backend>:<label>` key-reference routing** — commit signing,
  attestation signing, and the `mkit key …` commands resolve their
  signing key through user-scoped `key.default_ref`,
  `key.ed25519_ref`, `key.secp256k1_ref`, and `key.p256_ref`
  selectors. Repo-local config cannot override these for security
  reasons; the selector keys are accepted from
  `$XDG_CONFIG_HOME/mkit/config` and explicit flags only.
- **`mkit-rpc` crate** — shared length-prefixed framing and wire
  schemas (`signer.proto`, `common.proto`) used by the external
  signer subprocess protocol and reserved for future agent
  protocols. See [`docs/SPEC-RPC.md`](docs/SPEC-RPC.md).
- **`mkit status --porcelain=v1`** — machine-readable status output
  matching the `git status --porcelain=v1` shape, plus the mkit-
  specific `T` (mode change) status letter as the only extension.
- **`mkit log --format=json`** — JSONL output (one commit per line)
  with `hash`, `parents`, `tree`, `author`, `timestamp`, `title`,
  and `message`.
- **`--format=json` on `blame`, `branch`, `remote`, `config`** —
  machine-readable output across the remaining read-style commands.
- **`mkit commit -a` / `-am <msg>`** — Git-style "stage tracked
  modifications and tracked deletions before committing" shortcut.
- **Criterion-based benchmark suite** under `rust/benches/` with a
  `render-charts` binary emitting buffa-style SVG charts; powers the
  Performance section of the README.
- **CLI port to `clap-derive`** — every subcommand is now parsed by
  a derive-based parser routed through a sysexits-aware shim in
  `mkit-cli/src/clap_shim.rs`, replacing the prior hand-rolled
  parsers.
- **Cooperative SIGINT/SIGTERM shutdown**
  ([#111](https://github.com/officialunofficial/mkit/pull/111)) —
  long-running operations poll a graceful-shutdown flag set by
  `signal-hook` and exit with `tempfail` (75) at natural checkpoints.
- **Writing style guide** at
  [`docs/STYLE-GUIDE.md`](docs/STYLE-GUIDE.md)
  ([#127](https://github.com/officialunofficial/mkit/pull/127)).

### Changed

- **Keystore capabilities now report structural operation support.** Operation
  booleans match the corresponding `Keystore` operation accessors and no longer
  promise that the current session, daemon, hardware token, or protector is
  available at probe time. Operations still fail closed when runtime support is
  unavailable.
- **`mkit commit` now reads the staging index** (`.mkit/index`)
  instead of recursively snapshotting the worktree.
  ([#102](https://github.com/officialunofficial/mkit/issues/102))
  Pre-fix, `mkit add` and `mkit rm` wrote to the index but `mkit
  commit` ignored it — a half-state that surprised any user reasoning
  by analogy from git. Post-fix, `mkit add` (or `mkit add .`) is
  required before `mkit commit`; an empty index is now a hard error.
  The "snapshot the whole worktree" workflow is `mkit add . && mkit
  commit -m "..."`.

  New helper: `mkit_core::worktree::build_tree_from_index`. Pinned
  invariant: for a worktree whose contents match an index entry-for-
  entry, `build_tree` and `build_tree_from_index` produce the same
  root tree hash, so attestations signed under either path
  cross-verify against trees built under the other.
- **Confirmation prose and progress lines move to stderr** across 17
  commands; stdout is reserved for machine output so `mkit status
  > /tmp/out` in a clean tree produces an empty file.

### Fixed

- **Keystore vault follow-up hardening**
  ([#135](https://github.com/officialunofficial/mkit/pull/135)) —
  protector AAD binding, length-prefixed encrypted-record AAD,
  authenticated software metadata, zeroizing transient secret
  buffers, software metadata authentication, no-clobber imports,
  PIV-only YubiKey support, runtime-availability honesty in
  capability reports, and other review-feedback items collected
  across `946975e`, `524d3fc`, and `a5b382c`.
- **Silent failure exits** in several subcommands now return proper
  sysexits-aware codes instead of exiting 1 with no diagnostic.
- **`mkit commit` index follow-ups** — preserve executable modes on
  `-a`/`-am`, stage tracked deletions on `add .`, clear stale index
  path conflicts, and keep the index aligned with committed trees
  after PR
  [#103](https://github.com/officialunofficial/mkit/pull/103)
  review.
- **`mkit rebase` preflights its signing key** so the operation fails
  early instead of midway through a replay when no key is configured.
- **Benchmark chart axes** are now apples-to-apples wallclock + ops/s
  across the criterion and `git2`/git-CLI comparison rows.

## [0.1.0] - 2026-05-07

Initial public release. mkit is a content-addressed VCS for creative
work with native cryptographic attestations. Earlier development tags
(`v0.1.0`, `v0.2.0`, `v0.2.1` from the pre-release iteration) are
superseded by this release; the repository history was flattened
prior to publication.

### Added

- **mkit-core** — content-addressed object model (BLAKE3 hashing,
  canonical objects, refs, packs), FastCDC chunker, delta encoding,
  Bao verified streaming, Ed25519 commit signing.
- **mkit-attest** — DSSE + in-toto v1 attestations with multi-algorithm
  signers (Ed25519, secp256k1, P-256) and an RFC 8785 JCS encoder.
- **mkit-cli** — the `mkit` binary, with subcommands for init, add,
  commit, log, status, branch, checkout, merge, cherry-pick, rebase,
  push, pull, fetch, clone, attest, verify-attest, keygen, config.
- **Transports** — memory (test), file (local), http (REST + rustls),
  s3 (SigV4 over rustls, R2-compatible), ssh (forced-command server
  pattern over `ssh(1)`).
- **mkit-wasm** — wasm-bindgen surface for browsers and Cloudflare
  Workers, published to npm as `@makechain/mkit-wasm`.
- **External signers** — reference implementations under `contrib/`
  for FIDO2/WebAuthn (CTAP-HID), TPM 2.0 P-256, and a raw-key file
  signer for development.
- **Release pipeline** — cosign keyless OIDC signing, CycloneDX SBOMs,
  reproducible-build smoke tests, MSRV checks on Linux + macOS.

### Security

- Per-repo `.mkit/config` is partitioned: security-sensitive keys
  (signing key paths, external-signer paths, SSH trust knobs) are
  user-scoped only. A hostile clone cannot redirect signing or
  weaken transport trust via repo-local config.
- `mkit verify-attest` defaults to `$XDG_CONFIG_HOME/mkit/trust-roots.toml`
  rather than a repo-local path; in-repo trust-roots require an
  explicit `--trust-roots` flag.
- Key files are opened with `O_NOFOLLOW`, written via tmp + fsync +
  rename + parent fsync, owner-checked against the running euid, and
  parent directory mode is enforced `0700`.
- HTTP and S3 transports require an explicit user-scoped
  `trusted_remote_endpoint` before they will use ambient environment
  credentials for repo-configured remotes.
- Reference external signer keeps secret material in a zeroizing
  buffer until the per-algorithm signer consumes it.

[0.3.0]: https://github.com/officialunofficial/mkit/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/officialunofficial/mkit/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/officialunofficial/mkit/releases/tag/v0.1.0
