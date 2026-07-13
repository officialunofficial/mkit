# Changelog

All notable changes to mkit are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **BSR-published proto modules for external integrators.** The `mkit-rpc`
  schemas (`common.proto`/`signer.proto`/`ssh.proto`/`verify.proto`) and
  `apps/repo-worker`'s `repo.proto` (`RepoService`) are now named modules in
  the repo-root `buf.yaml` v2 workspace, pushed to the Buf Schema Registry as
  `buf.build/officialunofficial/mkit-rpc` and
  `buf.build/officialunofficial/mkit-repo` on every tagged release (new
  `buf-push` job in `crates-publish.yml`, dormant until `BUF_TOKEN` /
  `BUF_PUBLISH_ENABLED` are provisioned — see `docs/RELEASE.md`). Third-party
  signer integrators (HSM/TPM vendors, custodial signing services) and
  `RepoService` clients can now `buf generate` typed bindings from a pinned
  tag instead of vendoring this repo — see the checked-in `buf.gen.yaml`
  reference recipes in each module's proto directory.
  `contrib/signers/mkit-sign-se`'s checked-in Swift bindings are now
  regenerated via `scripts/regen-mkit-sign-se-swift.sh` (`buf generate`, not
  raw `protoc`) and refreshed to include the previously-missing
  `ALGORITHM_BLS12381_THRESHOLD` case.
- **`mkit serve --http <addr>`: self-hosted Connect remote (SPEC-TRANSPORT-CONNECT).**
  `mkit serve` can now host `mkit.transport.v1.TransportService` over
  axum/HTTP instead of the SSH-frame protocol, behind the new
  `http-transport` cargo feature — an operator without SSH access or a
  cloud object store can run a real, testable `mkit+https://` remote
  against a local repository (server-side half of the `mkit-transport-connect`
  crate, behind that crate's own `server` cargo feature; generic over any
  `mkit_core::protocol::Transport` backend; instantiated today over
  `FileTransport`). All seven wire RPCs
  (`ListRefs`/`ReadRef`/`UpdateRef`/`AdvanceRefs`/`PackExists`/
  `UploadPack`/`DownloadPack`) run the underlying `Transport` call on a
  blocking task so a synchronous CAS ref write never stalls the async
  executor. `UploadPack`/`DownloadPack` validate the full header-then-chunks
  stream (offset contiguity, declared-vs-received length, BLAKE3) before
  ever touching storage, so a rejected upload never creates or overwrites
  the destination pack, and a download either completes or fails before
  any message is sent — never a partial stream. **Fail-closed**, mirroring
  `--listen-enc`: refuses to bind unless `--http-token`/`MKIT_API_TOKEN`
  (checked in constant time on every unary and streaming RPC) or the
  explicit `--unsafe-allow-any-http-peer` development escape is supplied;
  `Ctrl-C`/`SIGTERM` drain in-flight requests before exiting. The
  `mkit.transport.v1` proto (`proto/mkit/transport/v1/transport.proto`) is
  generated via `buffa`/`connectrpc-build`, vendored under `generated/`
  the same way `mkit-repo-client`/`apps/repo-worker` already do — see
  `docs/specs/SPEC-TRANSPORT-CONNECT.md`. A hosted reference-Worker
  deployment is a separate, later change
  ([#699](https://github.com/officialunofficial/mkit/issues/699)).
- **Honest transfer-progress reporting for `clone`/`push`/`pull`/`fetch`
  ([#711](https://github.com/officialunofficial/mkit/issues/711)).**
  These commands now stream a live progress line on stderr while the
  network transfer runs — `Writing objects: N objects, B bytes` while
  building/uploading the outgoing pack, `Unpacking objects: N objects`
  while applying a downloaded one — using only real counts (objects
  actually staged/unpacked, bytes actually handed to the transport).
  mkit still never fabricates git's `Enumerating/Counting/Compressing
  objects` or `Total N (delta D)` lines, per `docs/PARITY.md`: mkit's
  transport is one-object-per-pack and computes no cross-branch delta
  graph. Progress shows only when stderr is a tty; the new `-q`/
  `--quiet` flag on all four commands forces it off, and
  `MKIT_PROGRESS=always`/`never` overrides the tty auto-detection
  explicitly (mirrors `NO_COLOR`/`CLICOLOR_FORCE`).
- **Native ConnectRPC client for `mkit+https://` (SPEC-TRANSPORT-CONNECT,
  [#701](https://github.com/officialunofficial/mkit/issues/701)).**
  The `mkit-transport-connect` crate's mandatory baseline (always compiled,
  independent of its `server` feature above) is now a non-wasm ConnectRPC
  client for `mkit.transport.v1.TransportService`, generated from
  `proto/mkit/transport/v1/transport.proto` via the same vendored-codegen
  pattern `mkit-repo-client`/`apps/repo-worker` use (no `protoc` needed on
  the default build path; `MKIT_REPO_CODEGEN=1` +
  `scripts/regen-transport-proto.sh` to regenerate). `mkit-cli`'s
  `remote_dispatch` now constructs this transport for `mkit+https://` /
  loopback `mkit+http://`, replacing `mkit-transport-http`'s bespoke JSON
  dialect there. TLS trust is pure-Rust (`webpki-roots`, no OS trust
  store); the synchronous `Transport` trait is bridged to the async
  generated client via a dedicated per-instance tokio runtime, mirroring
  `mkit-transport-enc`'s `TokioExecutor`. `ConnectTransport::
  supports_atomic_advance()` defaults to `false` (opt in via
  `with_atomic_advance(true)`) until a confirmed-transactional reference
  deployment exists. `mkit-transport-http` is NOT removed: its
  `sparse-checkout`/`pack-shards` extensions have no `mkit.transport.v1`
  equivalent yet.
- **`Transport`: additive streaming pack transfer (`upload_pack_streaming`
  / `download_pack_streaming`).** Two new opt-in trait methods move a
  pack as a sequence of bounded-size `PackChunk { offset, data, last }`
  segments instead of one `Vec<u8>`, reusing the same chunk shape
  `mkit-rpc`'s `ssh.proto` already defines. Both have default
  implementations expressed in terms of the existing whole-buffer
  `upload_pack`/`download_pack` (buffer-then-delegate for upload,
  delegate-then-wrap-as-one-chunk for download), so every transport
  gets a working implementation with zero code and none is forced to
  change. `mkit-transport-ssh` and `mkit-transport-enc` override both
  to forward chunks straight to the `PackChunk` frame loop they already
  ran internally, so a multi-GB pack streamed from disk over SSH/enc
  now stays in bounded memory (roughly one chunk at a time) regardless
  of total pack size, instead of requiring the whole pack materialized
  up front. `mkit-transport-http` keeps the default buffer-then-delegate
  behavior for now — real HTTP pack streaming arrives via the
  `mkit.transport.v1` Connect service's client-/server-streaming
  `UploadPack`/`DownloadPack` RPCs (SPEC-TRANSPORT-CONNECT §6, pending
  #698/#701) — but its per-retry full-body clone in `upload_pack` is
  fixed separately: the request body is now `Bytes` (refcounted) instead
  of `Vec<u8>`, so a retried upload shares the same buffer across every
  attempt instead of copying it again per retry
  ([#702](https://github.com/officialunofficial/mkit/issues/702)).
- **`log --author`/`--grep`/`--since`/`--until`/`--no-merges`/`--first-parent`
  and `diff -w`/`-b`/`-U<n>` (#712).** `mkit log` filters commits by a
  substring match on the author identity (`--author`) or commit message
  (`--grep`), by a `--since`/`--until` timestamp bound (accepting
  `@<unix-seconds>`, `now`/`today`/`yesterday`, `<N> <unit> ago`, or
  `YYYY-MM-DD[ HH:MM:SS]`), hides merge commits from the output
  (`--no-merges`), or walks only first parents so a merged side branch
  never enters the walk at all (`--first-parent`, stronger than
  `--no-merges`). All filters apply before `-n`'s limit. `mkit diff`
  gains `-w`/`--ignore-all-space` and `-b`/`--ignore-space-change`
  (whitespace-insensitive line comparison; `-w` wins if both are given)
  and `-U<n>`/`--unified=<n>` (context-line count, default 3). Both
  `--author`/`--grep` are plain substring matches rather than regexes
  (mkit identities are opaque, not free-text names) and `--since`/
  `--until` use a small explicit date grammar rather than git's
  `approxidate` — documented divergences, not gaps.
- **Windows release target (`x86_64-pc-windows-msvc`) and PowerShell
  installer.** `release.yml`'s build matrix now ships a fifth leg —
  `windows-latest`, `.zip` archive instead of `.tar.gz`, `mkit.exe` — built
  with the `backend-windows-credential` keystore feature (already the
  default on Windows via `mkit-cli`'s `[target.'cfg(windows)'.dependencies]`
  stanza), matching parity with the already-tested `windows-credential` leg
  of `rust.yml`'s manual-only `keystore-backends` matrix. The Windows
  archive goes through the same cosign keyless signing and mkit-native DSSE
  release attestation as every other target. New `install.ps1` at the repo
  root is the native-Windows counterpart to `install.sh` (same trust model:
  cosign-required by default, downgrade guard, atomic install) — served at
  `https://mkit.sh/install.ps1` alongside the existing `install.sh`. New
  `contrib/scoop/mkit.json` manifest template (mirrors
  `contrib/homebrew/mkit.rb`) un-defers the Scoop-manifest checklist item in
  `docs/RELEASE.md`. `install.sh` itself still targets Darwin/Linux only —
  it now points MINGW/MSYS/Cygwin users at `install.ps1` instead of failing
  with an unsupported-OS error. Known gap: `mkit self update` does not yet
  support the Windows install (it hardcodes `.tar.gz`/tar+gzip extraction
  and resolves its state dir via `$HOME`, which is commonly unset on native
  Windows) — Windows users should reinstall via `install.ps1` or a future
  Scoop bucket instead of `mkit self update` for now
  ([#714](https://github.com/officialunofficial/mkit/issues/714), part of
  [#676](https://github.com/officialunofficial/mkit/issues/676)).
- **SLSA build provenance for release archives.** The `release` job in
  `.github/workflows/release.yml` now generates a standard SLSA build
  provenance attestation (`actions/attest-build-provenance`, GitHub/
  Sigstore-native) over every `dist/*.tar.gz` and `dist/*.zip` archive
  (including the Windows leg), staged alongside the existing cosign
  signatures and the mkit-native DSSE attestation as
  `mkit-X.Y.Z.provenance.jsonl`. This is additive — it does not replace
  cosign or the mkit-native attestation — but gives downstream tooling
  (`gh attestation verify`, `slsa-verifier`) a recognized, off-the-shelf
  provenance format to check against instead of parsing mkit's bespoke DSSE
  predicate. See `docs/RELEASE.md` ("Verify the SLSA build provenance
  attestation").
- **Packfile v2: per-entry zstd compression (SPEC-PACKFILE §3.3, §3.4).**
  `PackWriter`/`PackReader` transparently compress/decompress pack
  entries — two new entry types, `0x03` zstd-raw and `0x04` zstd-delta,
  each carrying its own independent zstd frame (no shared dictionary,
  no whole-pack stream, so existing framing/caps/trailer semantics are
  unchanged and decompression memory is bounded to one entry at a
  time). No call-site changes needed: `push_raw`/`push_delta` compress
  a candidate payload when it is at least 64 bytes and compresses
  strictly smaller on the wire (mirroring the existing delta-preference
  gate's posture), using zstd level 3 (library default). The writer
  emits `version = 1` when a pack has no compressed entries and
  `version = 2` the moment it has at least one; `0x03`/`0x04` are
  illegal inside a `version = 1` pack and rejected as `InvalidEntryType`
  if seen there. Old (pre-v2) readers hitting a v2 pack fail closed
  with `UnsupportedVersion` — the intended behavior, not a bug. Decode
  is bomb-guarded: the claimed decompressed length is checked against
  the 1 GiB object cap *before* any decompression allocation,
  decompression is capacity-bounded to that claim, and the actual
  decompressed length is re-checked against the claim afterward (new
  `PackError::DecompressedSizeOverCap` / `DecompressedSizeMismatch` /
  `ZstdEntryTruncated` / `ZstdDecompress` variants). On a synthetic
  6-commit / 4-file-per-commit text corpus (files 8–48 KiB, <100 KB
  cap), pack bytes went from 655,764 (v1 uncompressed) to 184,881 (v2
  compressed) — a 3.55x reduction (71.8% saved); see
  `rust/benches/benches/pack_compression.rs`. New direct `zstd`
  dependency on `mkit-core` (behind a `pack-zstd` feature, on by
  default) — already present transitively via the `commonware-storage`
  dependency stack at the same resolved version (0.13.3), so this adds
  no new supply-chain root. `mkit-wasm` and `apps/repo-worker` (both
  compile to wasm32-unknown-unknown) opt out (`default-features =
  false`) since `zstd-sys` cannot target that platform.
- **`mkit-core`: CAS-guarded ref delete.** New public `refs` primitives
  `delete_ref_if_matches` and (on `--features history-mmr`)
  `delete_ref_with_history_if_matches` — a `delete_ref`/
  `delete_ref_with_history` that only removes the ref (and, on
  history-mmr builds, its journal) when its current on-disk value is
  exactly the caller-supplied `expected` hash, using the same per-ref
  `cas_lock_name` lock `update_ref`'s `Match` arm already takes.
  `mkit branch -m` now routes its source-branch drop (and, on a lost
  race, its destination rollback) through these instead of an
  unconditional delete — see the Fixed entry below
  ([#658](https://github.com/officialunofficial/mkit/issues/658)).
- **`mkit blame --porcelain` / `--line-porcelain`.** git's grouped
  machine-readable blame: a per-line header (`<id> <orig> <final>
  [<group-len>]`) plus a metadata block (author/committer, `author-time`/
  `-tz`, `summary`, `boundary` on a file-history root, and `filename`) —
  once per commit for `--porcelain`, for every line under `--line-porcelain`
  — with each content line tab-prefixed. Pinned against git 2.50.1 for the
  in-scope fields. Documented divergences, consistent with `--format=json`
  and the `log` precedent: 64-hex ids; `author`/`committer` carry mkit's
  Identity (empty `*-mail`, `+0000` tz, single UTC author = committer);
  `filename` is the `-C` copy source on a cross-file copy; git's `previous`
  line is out of scope and not emitted.
- **`mkit bisect run <cmd> [args…]`.** Drives the bisection loop
  automatically: it checks out each candidate, runs the command, and
  classifies from the exit status using git's contract (`0`=good, `125`=skip,
  `1`–`127` else=bad, `≥128` or signal=abort), converging on the first bad
  commit. The candidate is also exported as `MKIT_BISECT_COMMIT`. mkit's
  bisect stays print-candidate by design, so `run` checks out each candidate
  transiently for the test, then restores the original HEAD and *prints* the
  first bad commit rather than parking there. Each candidate is checked out
  with `--force`, so a test command that dirties a tracked file doesn't block
  the next iteration; and when only skipped candidates remain, `run` reports
  the result as ambiguous (like git) and exits non-zero instead of guessing.
- **`mkit checkout --force` / `-f`.** Discard local changes that would block
  the switch (git `checkout -f`): skip the dirty-tracked/staged safety gate
  and overwrite locally-modified tracked paths with the target's version;
  untracked files are still preserved. Used by `bisect run`.
- **`mkit self update`.** The binary can now update itself in place from a
  signed GitHub Release — but only when installer-managed (the
  `.mkit-installed-tag` receipt written by `install.sh` sits next to the
  executable); Homebrew/cargo installs are refused with channel-specific
  guidance. The downloaded archive is verified against the **mkit-native
  release attestation** (below) using release-attestation public keys
  embedded in the binary at build time — no `cosign`, no GitHub
  attestation API — plus the sha256 sidecar as defense-in-depth, and the
  staged binary must pass a `version` self-check before an atomic
  same-directory swap. Downgrade policy mirrors the installer (`latest`
  never downgrades; explicit `--version` pins need `--allow-downgrade`),
  receipts are rewritten in the installer's exact format, and
  `--check`/`--format json` report without changing anything. There is no
  background update check, ever. Not yet supported on Windows.
- **mkit-native release attestation.** Every release now ships
  `mkit-<ver>.release.dsse`: a DSSE/in-toto v1 envelope over the BLAKE3
  digests of all release tarballs, predicate
  `.../spec/predicate/release/v1` `{"tag": "vX.Y.Z"}`, signed with a
  dedicated Ed25519 release key (public rotation set checked in at
  `docs/keys/release-attest.pub`; custody + rotation runbook in
  `docs/RELEASE.md`). `release.yml` self-verifies the envelope against the
  checked-in public key before publishing, and the envelope is covered by
  the cosign-signed `SHA256SUMS`. Produced by the new internal
  `mkit-release-attest` tool crate (publish = false).
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
  "enabled but zero-threshold" state. Detection is **merge-aware** (#499):
  at a merge both `-M` moves and `-C -C` copies are traced against **every
  relevant parent's tree**, so a block moved or copied in from a
  non-first-parent side is credited to that side's origin — matching
  `git blame -M`/`-C`, which credits the merge parent whose tree holds the
  source (a block whose source is only in the merge's own tree stays on the
  merge, as in git). The `-C`-at-a-merge gaps from the initial #499 landing
  are now closed by implementing git's actual per-parent candidate
  mechanism (from git 2.50.1's `blame.c`, each shape pinned by a test with
  its git recipe): the `-M`/`-C` pass runs against **every real parent** in
  commit order, first-found-wins. A parent that contains the blamed file —
  and whose copy of it is not byte-identical to an earlier parent's (git
  dedups those) — keeps its *porigin*: it supplies the within-file `-M`
  source, and its `-C` candidates are the files *modified between that
  parent and the merge*. A porigin-less parent (deleted the file, holds a
  duplicate blob, or the file is newly added by the merge) has no `-M`
  source and, with `-C -C`, gets its **entire tree** searched. The rules
  previously described as "interior vs boundary tie-breaks" fall out of
  this mechanism, plus the shapes they missed: an unchanged source on the
  first parent is invisible (block stays on the merge) even when another
  parent deleted the file; the same source *modified* at the merge credits
  the first parent — at plain `-C` level 1 too; a parent that deleted the
  blamed file can still supply the `-C -C` copy source from its tree; and
  a file newly added by the merge searches every real parent, first
  included (under `--first-parent`, only the first). Documented divergences from git
  remain: inline `-M<num>`/`-C<num>` threshold forms aren't exposed on the
  CLI (the core API takes a custom threshold); when one source holds the
  block at several offsets the earliest offset wins (git scores candidates
  and tracks line identity through its diff); and within a single unmatched
  run longer than 10,000 lines only the whole run is matched, not sub-blocks
  (a cost bound; the matcher already caps inputs).
- **`mkit blame -C -C -C` whole-history copy search.** git's third `-C`
  ("copies from other files in any commit") now whole-tree-searches the
  parent at *every* walk step, not only at the commit that creates the
  blamed file. So a block copied into a persisting file from a source that
  was *unmodified* in the introducing commit is credited to that source's
  origin — previously `-C -C -C` was approximated as `-C -C` and missed it.
  Pinned against git 2.50.1.
- **`mkit blame -C` copy tie-break now matches git.** When two
  equally-similar copy sources exist, blame credits the source that traces
  to the older (ancestor) commit — git's push-blame-furthest-back bias —
  instead of the first candidate in path order. The ordering is topological
  (mkit commits can share a whole-second timestamp, so ancestry, not time,
  is authoritative), pinned against git 2.50.1.
- **`mkit blame --ignore-rev` / `--ignore-revs-file`.** Skip "noise"
  commits — mass reformats, license-header sweeps, renames — during
  attribution, like `git blame --ignore-rev`. A line that would be credited
  to an ignored commit falls through to the commit that previously changed
  it; a line the ignored commit genuinely inserted stays put (git's default,
  no marker). The fall-through is **merge-aware** (#499): at an ignored merge
  a line the first parent can't pair (it dropped that line) falls through
  across to the next parent that does — first-parent-wins, matching `git blame
  --ignore-rev` at a merge. `--ignore-rev` is repeatable and accepts any revision (short
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
  `docs/specs/SPEC-MERKLE-OBJECTS.md` and ADR 0001). The license grant
  (`LICENSE-MIT`, `LICENSE-APACHE`, `NOTICE`), `SECURITY.md`,
  `CODE_OF_CONDUCT.md`, `CONTRIBUTING.md`, and the `geiger` unsafe-code
  ceiling check are retained.

### Changed

- **BREAKING (`mkit-core`, `pack-shards` feature): pack-shard Reed-Solomon
  hasher cut over from `Sha256` to `Blake3`.** `pack_shard::RsScheme` now
  wraps `commonware_coding::ReedSolomon<Blake3>` instead of `Sha256`,
  matching the hasher mkit uses everywhere else and dropping a redundant
  per-shard SHA-256 pass inside commonware's own Merkle-tree build (it
  was already fully separate from this module's BLAKE3 `shard_hashes`
  envelope check, which is unchanged). `MANIFEST_VERSION` is bumped
  `0x01` → `0x02` since the wire-visible `ShardSet::commitment` value
  changes; this is a **hard cutover, not dual-hasher support** — a
  `0x01` manifest is rejected with a version-specific error ("manifest
  version 0x01 (Sha256-era) — re-shard with a current mkit") instead of
  the generic unsupported-version message, and `0x01` is retired
  permanently. Producers and consumers on different `pack-shards`-era
  mkit versions cannot interoperate; re-shard with a current build.
  `docs/specs/SPEC-PACK-SHARDS.md` §2.1/§4 updated to match, and §4's
  stale "`Sequential` parallel strategy" phrasing (left over from #653,
  which made the strategy a caller-selectable parameter) is corrected
  alongside it ([#661](https://github.com/officialunofficial/mkit/issues/661)).
- **SPEC-WORKTREE.md + worktree parity docs (#493 Phase 4).** New
  normative spec covering the common-dir/per-worktree state split, the
  `mkitdir:` pointer-file format, the `worktrees/` registry, discovery
  (and its fail-closed matrix), the lock model, and cross-tree gc
  semantics. `git worktree` leaves PARITY.md's v1 non-goals list with
  a scope amendment recording the deliberate divergences (per-tree
  stash; `move`/`lock`/`repair` remain follow-ups); SKILL.md, the man
  page, and the bash/zsh/fish completions gain the `worktree` command.
- **Cross-worktree gc + the lock split (#493 Phase 3).** `mkit gc` is
  worktree-aware: root collection unions HEAD, staging index,
  `ORIG_HEAD`, in-progress merge/cherry-pick/revert/rebase state,
  conflict sidecars, and the tree-local stash across the main tree AND
  every registered linked tree (including prunable-but-unpruned
  entries — until `worktree prune` reaps a state dir, whatever it pins
  stays pinned), and fails closed if the registry or any sibling's
  state cannot be read. gc's "shared lock spanning trees" is the union
  of all per-tree worktree locks, acquired in deterministic order
  (main first, then registry ids ascending), so gc serializes against
  worktree/index mutations in every tree — a gc run blocks (then
  TEMPFAILs) while any sibling is mid-mutation. The Phase 2 interim
  refusal of gc-with-linked-worktrees is lifted. Tree-locality of
  `status`/`reset --hard`/`clean`/`rm`/`stash` across trees is pinned
  by tests.
- **`mkit worktree add/list/remove/prune` (#493 Phase 2).** Linked
  working trees with git's semantics: `add <path> [<commit-ish>]`
  creates a tree sharing the one object store and the shared refs
  (default: a new branch named after the path's basename; a branch
  argument checks it out; any other revision detaches), `list`
  (`--porcelain` for scripts) shows every tree with its HEAD, `remove`
  deletes a tree but refuses to destroy local changes, untracked
  files, or an in-progress operation without `--force`, and `prune`
  reaps registry entries whose tree vanished (`--dry-run` previews).
  A branch may be checked out in at most one tree: `worktree add`,
  `checkout`/`switch`, `branch -d`, and `branch -m` all refuse with
  `already checked out at '<path>'` (branch moves are single-writer
  through the history-MMR ref path). Registry mutations serialise on a
  new common-dir `worktrees.lock`; `add` orders its writes so a crash
  leaves at worst a prunable orphan, never a live tree pointing at
  half-built state.
- **Linked-worktree on-disk model + discovery (#493 Phase 1).**
  `mkit_core::layout` gains the linked-worktree groundwork: a linked
  tree's `.mkit` is a pointer FILE (`mkitdir: <path>`, the analog of
  git's `gitdir:` file) naming its per-tree state dir under the main
  repository's `.mkit/worktrees/<id>/` (with `commondir` and a
  `mkitdir` back-pointer inside, git-style); `layout::discover`
  resolves it — a `.mkit` directory or absent `.mkit` still yields the
  classic single-worktree layout byte-identically, while a malformed,
  oversized, or dangling pointer fails closed with a typed
  `DiscoverError`. The CLI's `commands::resolve_layout` now performs
  this discovery, so every command already works from inside a linked
  tree: commits write into the one shared object store and move shared
  refs, while HEAD/index/op-state/stash stay in the invoking tree's
  state dir. Repo-relative signing-key paths (`.mkit/keys/…`) resolve
  against the shared common dir so linked trees sign with the same
  repo keys. No user-facing `worktree` command yet (that lands with
  `mkit worktree add/list/remove/prune`); linked trees can only be
  assembled by hand at this stage.
- **`RepoLayout` path-resolution seam (#493 Phase 0).** `mkit-core` gains
  `layout::RepoLayout`, the single authority for resolving repository
  state under `.mkit/`, classifying every path as **common-dir** state
  (objects, format marker, refs, shallow, config, keys, history MMR,
  recovery log, attestations, applied-packs, git-bridge state, sparse
  bitmap cache, pack-shard output) or **per-worktree** state (`HEAD`,
  index, `ORIG_HEAD`, merge/cherry-pick/revert files, conflict sidecar,
  `rebase-apply/`, bisect, stash, sparse-checkout filter, worktree lock)
  in preparation for linked working trees (`mkit worktree`, later
  phases). Repo-state APIs now take `&RepoLayout` instead of a bare
  `&Path` root: `ObjectStore::{open,init}`, all of `refs`,
  `index::{read_index,write_index,index_path}`, `ops::{conflict_state,
  rebase, bisect, stash, gc, recovery}`, `ops::restore::{load,write}_
  sparse_checkout`, `CommitHistory::open_at` (and
  `CommitHistory::common_dir()` replaces `CommitHistory::mkit_dir()`),
  `mkit_attest::store`, and `mkit_git_bridge::map::state_dir`. In the
  classic single-worktree layout every resolved path is byte-identical
  to before — zero behavior or on-disk change; goldens unchanged. The
  CLI resolves its layout once per command through
  `commands::resolve_layout`, the future discovery seam.

- **buffa 0.8.1 + connectrpc 0.8.0 everywhere.** The main workspace and
  `contrib/signers` move buffa 0.8.0 → 0.8.1 (runtime-only patch; vendored
  codegen verified byte-identical). The ConnectRPC pair
  (`mkit-repo-client` + `apps/repo-worker`) finally leaves its 0.7 pin:
  connectrpc 0.8 ships on buffa ^0.8.1, so both crates now match the rest
  of the repo on a single buffa version (the workspace lockfile drops the
  entire duplicate 0.7 dependency tree). Vendored ConnectRPC codegen was
  regenerated with the 0.8 toolchain — ~4,300 lines smaller thanks to
  buffa 0.8's `impl_default_instance!` runtime macros, fused
  `put_*_field` writers, and shared `check_wire_type`/`map_codec` helpers
  (wire output is byte-identical). Handler traits now return
  `impl Encodable<Resp>`, letting future handlers return zero-copy views.
  connectrpc's now-optional `json` feature is enabled explicitly so
  generated serde derives and JSON error/end-of-stream frames keep
  working on wasm.
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
  [`docs/specs/SPEC-MERKLE-OBJECTS.md`](docs/specs/SPEC-MERKLE-OBJECTS.md) pins the
  construction; see also ADR
  [`docs/adr/0001-merkelize-chunkedblob-and-tree.md`](docs/adr/0001-merkelize-chunkedblob-and-tree.md)
  ([#414](https://github.com/officialunofficial/mkit/pull/414)).
- **BREAKING (`mkit-core`):** in the `blame` module, the public type alias
  `BlameResult2<T>` was renamed to `BlameOutcome<T>`, and the unbounded
  `match_lines` function is now private — line matching is an internal,
  size-checked detail of `blame_file_with`. Both are pre-1.0 API breaks; no
  in-workspace consumers were affected. (release-plz's `semver_check`
  enforces the matching version bump at release time.)
- **BREAKING (`mkit-core`):** dropped `.mkit/index` v1 read compatibility.
  `deserialize` now accepts only the current stat-cached format
  (`FORMAT_VERSION = 0x02`) and rejects every other version byte,
  including the legacy v1 (`0x01`, 35-byte entries with no stat cache).
  The index is repo-local, advisory, and never exchanged between peers
  (SPEC-INDEX §1), so this carries no cross-peer compatibility
  obligation; there is no migration path for a stray v1 file, since mkit
  never shipped a release that wrote one. Pre-1.0 API/format break.
- **BREAKING (`mkit-attest`):** `Subject` gained a new required field,
  `digest_sha256_hex`, and `sha256_hex()` was added to compute it. Every
  subject now carries a `sha256` digest alongside `blake3` (SPEC-ATTESTATIONS
  §4.2) — both digests of the identical underlying bytes — so cosign,
  `gh attestation verify`, and the SLSA verifier (all of which only read
  the in-toto/SLSA `DigestSet` `sha256` key) can read mkit attestations.
  `sha2` moves from optional (gated behind `algo-secp256k1`/`algo-p256`) to
  an unconditional `mkit-attest` dependency. Pre-1.0 API break; every
  caller constructing a `Subject` (`git.rs`, `git_import.rs`,
  `self_update.rs`, `release-attest`) was updated.

### Fixed

- **`branch -m` racing `commit` on the same branch could silently lose
  the commit.** #637 serialized `Match`-conditioned ref writes under a
  shared per-ref lock, but `commit`'s ref advance still used
  `RefWriteCondition::Any` (an unconditional clobber) and `branch -m`'s
  delete of the renamed-away source ref was unconditional too — neither
  side went through `Match`, so the shared lock never engaged between
  them. A rename could read a branch's tip, let a concurrent `commit`
  land on top of it via its own CAS, and then delete the ref anyway,
  destroying the just-landed commit with both commands reporting
  success. `commit`'s `advance_head` now writes `Match(expected_tip)` /
  `Missing` instead of `Any` (aborting with a clear, GC-recoverable
  `TEMPFAIL` if the branch moved underneath it since composing the
  message), and `branch -m` now deletes the source ref via the new
  CAS-guarded `delete_ref_if_matches`, rolling back the just-created
  destination and erroring instead of destroying a concurrent commit
  ([#658](https://github.com/officialunofficial/mkit/issues/658)).
- **`listRefs(prefix)` no longer matches across a ref-name component
  boundary in `mkit-transport-memory` and `mkit-transport-s3`.** A
  request for prefix `refs/heads/feat` incorrectly matched
  `refs/heads/featx` (a bare string-prefix check with no boundary
  enforcement), returning the malformed suffix `"x"`. Both transports
  now require the match be followed by `/` or end-of-string, per
  SPEC-REFS's normative `listRefs` algorithm; a ref that merely shares a
  string prefix with the query, without extending it at a `/` boundary,
  is excluded entirely rather than truncated into a bogus name.
- **CAS conflicts over `mkit serve` now surface as `RefConflict`.**
  Per SPEC-TRANSPORT §4.2.1 the server answers a compare-and-swap
  mismatch on `updateRef` with `Error{INVALID_REQUEST}` carrying the
  current ref value in `Error.details`; previously `mkit serve`
  collapsed every `update_ref` failure into a generic invalid-request
  with empty `details`, so a genuine conflict degraded to `RemoteError`
  on the SSH client (whose classifier requires the current-id payload).
  Both the stdin/stdout SSH server and the encrypted listener now emit
  the spec shape via the shared verb handler, and the enc client was
  tightened from a looser presence-based rule to the same strict
  details-based classification the SSH client uses (shared
  `mkit_rpc::map_update_ref_error`), so genuine invalid requests no
  longer misclassify as conflicts
  ([#551](https://github.com/officialunofficial/mkit/issues/551)).
- **External-signer `PinPrompt`/`PinResponse` round trip is now
  implemented; `mkit-sign-ctap --pin` on argv is deprecated.**
  SPEC-EXTERNAL-SIGNER §4 specifies an in-band PIN round trip so a
  hardware signer can request a PIN mid-sign without it ever touching
  argv, but `ExternalSigner` only wrote `Hello`/`SignRequest` and
  rejected any `PinPrompt` frame with `ExternalSignerBadResponse` —
  the only way to supply a PIN was the reference CTAP signer's plain
  `--pin` flag, readable by any other local user via `ps` /
  `/proc/<pid>/cmdline` (the same exposure class `docs/THREAT-MODEL.md`
  §3.2 defends key-file confidentiality against). `ExternalSigner` now
  keeps the child's stdin open for the whole sign conversation and
  answers a `PinPrompt` via a new `PinProvider` trait (default
  `TtyPinProvider`: an interactive terminal prompt, best-effort
  no-echo via `stty` on Unix — never argv or an environment variable),
  bounded to 8 round trips per conversation. `mkit-sign-ctap` now
  requests a PIN in-band when the authenticator needs one and prints a
  deprecation warning to stderr when `--pin` is passed
  ([#694](https://github.com/officialunofficial/mkit/issues/694)).

### Internal

- Open-source / publish readiness sweep: scrubbed internal identifiers,
  fixed stale manifest/rustdoc claims, deduplicated copy-pasted helpers
  (CLI `emit_err`, transport pubkey decoders, replay/rollback plumbing),
  decomposed oversized modules (`keystore::software`, CLI `serve`), and
  fixed several latent bugs (S3 ref pagination, atomic bisect-state
  write, BLS external-signer fail-closed) with regression tests.

### Security

- **`clone`/`pull`/`fetch` now verify commit/remix/tag signatures and
  fail closed by default.** Previously the only signature check was the
  manual, single-revision `mkit verify <rev>` — a hostile remote
  (THREAT-MODEL §3.1) could push an entirely unsigned or forged history
  and every `clone`/`pull`/`fetch` would accept it with zero indication
  anything was wrong. Every commit/remix/tag a fetch newly introduces is
  now run through `mkit_core::sign::{verify_commit,verify_remix,verify_tag}`
  — the exact check `mkit verify` runs manually — before the
  remote-tracking ref is published; a structurally invalid or missing
  signature aborts with exit 65 and leaves local refs/working tree
  untouched. Only the newly-fetched delta is checked (bounded per-fetch
  cost), and the new `DispatchError::UnsignedOrInvalidObject` is
  deliberately excluded from the applied-pack self-heal retry. Opt out
  per invocation with `--no-verify-signatures`, or persistently via the
  **user-scoped** `pull.require_signed = false` config key (added to
  `REPO_FORBIDDEN_KEYS` — a cloned repo's own config cannot disable the
  check that protects the clone against exactly that repo). A new
  message-only `mkit.rpc.v1.verify` proto (`verify.proto`, co-located
  with `signer.proto`) documents the verification contract so a future
  ConnectRPC transport (e.g. `apps/repo-worker`) can bind the identical
  check instead of reimplementing it
  ([#692](https://github.com/officialunofficial/mkit/issues/692)).

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
  [`docs/specs/SPEC-GIT-IMPORT.md`](docs/specs/SPEC-GIT-IMPORT.md) pins the
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
  New normative spec [`docs/specs/SPEC-GIT-BRIDGE.md`](docs/specs/SPEC-GIT-BRIDGE.md)
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
  separately in [`docs/specs/SPEC-GIT-IMPORT.md`](docs/specs/SPEC-GIT-IMPORT.md). PARITY.md gains a scope amendment per its
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
  [`docs/specs/SPEC-OBJECTS.md`](docs/specs/SPEC-OBJECTS.md) §6a,
  [`docs/specs/SPEC-SIGNING.md`](docs/specs/SPEC-SIGNING.md) §4a.
- **`mkit-keystore` crate** — pluggable signing-key vault subsystem
  (PR [#109](https://github.com/officialunofficial/mkit/pull/109),
  hardened in
  [#135](https://github.com/officialunofficial/mkit/pull/135) and a
  long tail of review-feedback follow-ups). Ships with backends for
  software (encrypted-at-rest, the foundation backend), software-raw,
  macOS Keychain, Windows Credential Store, Linux Secret Service,
  systemd-creds, and YubiKey (PIV and OpenPGP applets). Public
  interface and threat model are documented in
  [`docs/specs/SPEC-KEYSTORE.md`](docs/specs/SPEC-KEYSTORE.md).
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
  protocols. See [`docs/specs/SPEC-RPC.md`](docs/specs/SPEC-RPC.md).
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
