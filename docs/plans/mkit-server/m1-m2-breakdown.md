# mkit-server epic (MKIT-29): M1 + M2 work-package breakdown

Status: coarse rolling-wave plan, **consolidated** (see `00-plan.md`: registry, Defaults adopted, Reconciliation
log R-xx). Detailed executor briefs are written when each milestone starts. Where this file and `00-plan.md` differ,
`00-plan.md` wins. Terminology after consolidation: M0's `NamespaceStore` is a key-level store whose only write is a
declarative `Batch` (M0-02); "a `Mutation` with row X" below means "a planner that emits a `Batch` writing X's key
layout, guarded by preconditions". "Tokio-free baseline" is replaced everywhere by the **server-free CLI** criterion
(`scripts/check-cli-baseline.sh`, M0-13).
Source of truth: PRD `docs/plans/mkit-server/prd-snapshot.md` (decisions D1 to D36 are settled; D21 superseded by D34). Review 01 fixes are
logged in `00-plan.md` §5.6 (R-61…R-84). References below to M0-02 / M0-05 mean the split WPs (M0-02a contract and
`NotAfter`, M0-02b ContentIndex/export; M0-05a planners and unary flow, M0-05b upload/download and `FaultHooks`). Peer draft specs: PR #1087 (`gh pr diff 1087`).
Branch: every WP lands as one PR on `feat/mkit-server`. Each PR stays at or under about 1500 changed lines, not counting generated code, goldens or fixtures. Each PR handles one concern and is independently green.

Dependency notation:
- `M0:<capability>` names a capability the M0 plan must deliver. The assumptions are listed in §4.
- `S1` means spec PR #1084 (addressing, namespace policy, owner key, GetServerInfo). `S2` means #1085 (grants). `S3` means #1086 (admission).

Line references are to `main` at `db0b826b`. M0 will move some code (for example, vcs-worker onto `mkit-server-worker`). Treat the refs as "the logic that lives here today".

---

## 0. Grounding: facts from the code that shape these WPs

| # | Fact | Where | Consequence |
|---|---|---|---|
| G1 | Auth v2 knows only the `body:` and `pack:` commitments. Stream verification *requires* `pack:`. | `mkit-core/src/write_auth.rs:158-174`, `:477-479` | M1 adds a `part:` branch in both places. This is additive, but the canonical-string golden set grows. |
| G2 | The replay scope is `BLAKE3(audience\nrepository\npubkey\nnonce)`. | `write_auth.rs:486-496` | Replay is already per repo once `repository` is the real `ns/name`. No format change is needed for isolation. |
| G3 | `component(repository, 255)` accepts any printable ASCII, including `/` and uppercase. | `write_auth.rs:50-52`, `:142` | The S1 grammar (lowercase, `ns/name`) has to be enforced *above* write_auth: in the server addressing layer and in the client URL parser. write_auth stays permissive. |
| G4 | The client derives the repository from the URL path, falling back to `"default"`. Its doc comment still says the path "has no effect on the wire". | `mkit-transport-connect/src/client.rs:184-194`, `:254-259` | M1 adds grammar validation and fixes the doc. The signed `<repository>` field already uses the path. |
| G5 | `EnvelopeTransport` signs only UpdateRef, AdvanceRefs and UploadPack. Reads pass through with no `x-repository`. | `envelope.rs:76-85`, `:237-241` | M1: always set `x-repository`. M2: sign every read when a signer exists. |
| G6 | One `RetryIdentity` (nonce plus a 300 s window) wraps the *whole* retry ladder, and each UploadPack attempt can itself take up to 300 s. | `client.rs:499-518`, `:48-57`; `envelope.rs:31-39` | Later attempts can carry an expired envelope. M1 implements the PRD §6.2 rule: reuse the identity while it is valid, and re-sign once it lapses. |
| G7 | `resource_exhausted` maps to a retryable 429. | `error.rs:111-113` | Changing it for 402 is M3. M1 must not add new server uses of `resource_exhausted` that clients would retry forever, so ticket and part errors use other codes. |
| G8 | `Transport::advance_refs` has no way to carry tickets. `ConnectTransport` never sets `atomic_advance`: nothing outside `client.rs` calls `with_atomic_advance`. | `mkit-core/src/protocol.rs:394`, `:581`; `client.rs:366` | Tickets need a plumbing decision (WP-1.17). `GetServerInfo` can finally drive `supports_atomic_advance`. |
| G9 | Every push attempt uploads a *new* packlist node (MKPL) through `upload_blob`, then calls `advance_refs`. A `PackmapConflict` loops back and uploads another node. | `mkit-cli/src/remote_dispatch/packmap.rs:468-493` | Each node needs a ticket (§6.2). On retries, stale node tickets are never advanced, so they end as `Expired`. That is fine only if the client does not attach them. |
| G10 | Head-only pushes go through `commit_head` (UpdateRef, no packmap). | `remote_dispatch/mod.rs:748-751`; `packmap.rs:507` | Such a push consumes no tickets and needs no packmap scope. Relevant to M2 ref-scope rules. |
| G11 | The fetch path treats a missing packmap as a hard error. | `remote_dispatch/mod.rs:1477-1479` | M1 isolation must not hide a repo's own packmap nodes: `DownloadPack` of a member MKPL node must work. |
| G12 | vcs-worker has one global DO (`REFSTORE_INSTANCE = "root"`). The destination comes from `AUTH_AUDIENCE`/`AUTH_REPOSITORY` vars. Every envelope failure maps to `unauthenticated`. | `apps/vcs-worker/src/worker_impl/service.rs:59-66`, `:118-129`; `auth.rs:21-32`, `:80`, `:113` | M1 routes by namespace, and M2 aligns the error codes. |
| G13 | `wrangler.jsonc` has no route. `AUTH_AUDIENCE` is `http://localhost:8787`. There is one bucket `mkit-vcs-objects`, DO migration tag `v1` (`RefStore`), and a build that installs rustup 1.95.0. | `apps/vcs-worker/wrangler.jsonc:14-41` | Staging needs an env block, a route, its own bucket, and a new DO class migration. |
| G14 | The replay ledger table is `authenticated_operations(scope, fingerprint, expires, reply)`, with a fingerprint check on reserve. | `apps/mkit-worker-common/src/replay.rs:72`, `:115-166` | M0 replaces this with the in_flight/committed state model (assumption A4). |
| G15 | The vcs-worker already has a `test_fault` injection seam. | `service.rs:580` | This is the pattern for the revoke-race barrier (WP-2.8) and the expiry tests (WP-1.14). |
| G16 | `mkit-attest` already provides: k256 0.14 and p256 0.14 with the `ecdsa` feature; `verify_secp256k1` and `verify_p256` that reject high-S; and WebAuthn verification that takes a *compact* signature. The policy supports `require_user_presence`, RP id and origins. There is no Keccak and no recovery. | `mkit-attest/Cargo.toml` (k256/p256 lines); `signer_k256.rs:175-185`; `signer_p256.rs:186-199`; `webauthn.rs:86-145`, `:198-313` | Recovery is `ecdsa 0.17 recovery::recover_from_prehash`, available through k256's `ecdsa` feature. Keccak needs the new `sha3 = "0.11"` dependency, which is pure Rust and already on the digest-0.11 line; `keccak` is already in `Cargo.lock` through ed25519-dalek. The grant blob carries a **DER** signature, so the verifier must parse DER, require low-S, and convert to compact. |
| G17 | `blake3` is 1.8.7, and `hazmat` provides `HasherExt::set_input_offset`, `finalize_non_root`, `merge_subtrees_{root,non_root}` and `left_subtree_len`. `pack_key` is plain `blake3::hash`. | `rust/Cargo.lock:532`; `mkit-core/src/pack.rs:593`; `hash.rs:24` | Per-part subtree hashing with a merge to the pack id is supported natively. It needs power-of-two, aligned parts, which is the PRD rule. |
| G18 | `mkit-transport-s3` already implements S3/R2 multipart with SigV4. | `mkit-transport-s3/src/lib.rs:23-61` | The native S3 multipart `BlobStore` reuses it (WP-1.13). |
| G19 | Envelope signing is enabled only when `transport_auth = envelope`, and only for the single user-scoped `trusted_remote_endpoint`. | `mkit-cli/src/remote_dispatch/mod.rs:220-231`; `config.rs:72`, `:127` | "Sign every read to its own remote" (M2) means that endpoint. |
| G20 | Today `mkit serve <path>` gets no principal. The SSH-SECURITY §5 forge pattern bakes the account into the path. | `mkit-cli/src/commands/serve/mod.rs:145-220`; `docs/SSH-SECURITY.md:123-150` | M1 needs a principal (owner-key checks on ssh). M2 looks up registered grants by that principal. |
| G21 | Generated transport code is vendored in `rust/crates/mkit-transport-connect/generated/` and `apps/vcs-worker/generated/`. `scripts/check-generated-fresh.sh` runs `regen-transport-proto.sh`. | `mkit-transport-connect/build.rs:5-17` | Every proto WP regenerates all vendored copies. After M0 that probably includes an `mkit-server` copy (A8). |
| G22 | Transport has no ref-delete verb. | `protocol.rs:394-625` | Decided: keep the grant `delete` flag; S1 §7.8 adds ref deletion to `UpdateRef`/`AdvanceRefs` (proto WP-1.2, server WP-1.10, grant check WP-2.7). |

---

## 1. Milestone M1: addressing, namespace policy, sharded metadata (D34), uploads

PRD: §5.3 (Metadata sharding, D34), §6.1, §6.2, the §5.4 per-RPC lifecycle table, and §8 M1.

The M1 exit criteria:
- The conformance tests for multi-repo isolation, namespace policy and tickets pass on both adapters, plus the D34
  cases: lag windows for membership and `ListRefs`, D36 read-your-writes through `X-Mkit-Ref`, epoch-lease
  revocation (revoke during an in-flight write, a paused write reaching its shard after lease expiry, an idle shard
  waking after a revocation, lease expiry racing an ack), many-ref write throughput in one repo,
  `BeginUpload` with a target ref, ticket caps, ListRefs merge pagination under the RPC limit, and bounded growth.
- A real `mkit` push and clone works against staging.
- Conformance runs against deployed staging (not only `wrangler dev`, whose DO bindings are always local). During the
  epic the orchestrator runs it locally against staging; the `server-staging.yml` workflow triggers only on `main`,
  `schedule` or dispatch against `main`, and runs for the first time on the final PR to `main`.

Consolidation changes (00-plan.md reconciliation log): WP-1.1 is folded into S1 (Q18). D34 adds WP-1.22 to WP-1.29
and reshapes 1.7, 1.8, 1.9, 1.10, 1.14 and 1.21. The part-upload shape follows S1 §7.6 (stateless ticket token,
client-held part receipts), so part requests never reach a Durable Object. Size target stays ≲ 1500 lines per PR.

### WP-1.1 — dropped

Folded into WP-S1 §7.6/§7.8/§7.9 (adopted Q18 default). Every former dependent now depends on S1.

### WP-1.2 Proto additions and codegen for M1

- **Depends on:** S1, M0-20.
- **Goal:** Additive `mkit.transport.v1` changes, exactly as S1 specifies:
  - `GetServerInfo` (all §6.1 fields; plus `max_parts`, `index_fanout`, ListRefs page bounds; receipt key and grant
    schemes stay empty until later milestones)
  - `BeginUpload{repository, ref, pack_id, bytes}` → oneof `already_present | ticket{id, part_size, expires, token}`
  - `UploadPart`, **client-streaming** (R-69): `rpc UploadPart(stream UploadPartRequest) returns (PartReceipt)` with
    `UploadPartRequest { oneof msg { UploadPartHeader header = 1 {ticket_token, index}; bytes chunk = 2; } }`;
    `CompleteUpload{ticket_token, receipts[]}`
  - `UploadPackHeader.ticket_token`; `AdvanceRefsRequest.ticket_ids` (repeated)
  - ref deletion (`delete` on the ref update of `UpdateRef` and `AdvanceRefs`, S1 §7.8)
  - `ListRefsRequest.page_size/page_token`, `ListRefsResponse.next_page_token` (S1 §7.9)

  Regenerate every vendored `generated/` dir (G21). Both adapters return `unimplemented` for the new RPCs until
  their WPs land; the client ignores them. **Additive only, strictly (R-79):** new fields and messages only; never
  change the label (`optional`/`repeated`/singular) or the oneof membership of an existing field, and never reuse a
  number. `buf breaking` FILE does not catch every such edit, so the reviewer checks the proto diff for it.
- **Files:** `proto/mkit/transport/v1/transport.proto`; `rust/crates/mkit-transport-connect/generated/*`;
  `rust/crates/mkit-server/generated/*`; stub arms in `mkit_server::connect`.
- **Tests:** codegen round trip; the existing e2e suite stays unchanged.
- **Gates:** `buf lint`, `buf breaking` (FILE, against the branch base), `scripts/check-generated-fresh.sh`, full
  `cargo nextest run --workspace`, worker clippy for wasm32.
- **Size:** S (~300 lines plus generated code).

### WP-1.3 mkit-core: `part:` commitment and BLAKE3 subtree module

- **Depends on:** S1 (grammar). Pure core: may start before M0 exits.
- **Goal:** unchanged from the planner draft: `write_auth` parses `part:<ticket>:<index>:<64hex>:<len>`;
  `verify_headers` accepts it on the part procedure (a `CommitmentKind` in `Authorized`); new wasm-safe
  `mkit-core/src/upload_parts.rs` with part-size validation, `part_subtree_cv`, `merge_to_root` following BLAKE3's
  `left_subtree_len` shape.
- **Files:** `rust/crates/mkit-core/src/{write_auth.rs, upload_parts.rs (new), lib.rs}`,
  `rust/tests/golden/auth-v2/part.json`, `rust/tests/golden/uploads/subtree-merge.json`.
- **Tests:** golden canonical string/digest/signature; merge vectors for 2, 3, 5, 8 parts plus a short last part vs
  `blake3::hash(whole)`; rejection cases; a proptest that merge equals the whole hash.
- **Gates:** rust fmt/clippy/nextest; `cargo build -p mkit-wasm --target wasm32-unknown-unknown`;
  `scripts/check-wasm-dep-graph.sh`; `just ci-scripts`.
- **Size:** M (~600 lines plus goldens).

### WP-1.4 Core: multi-repo addressing through the pipeline

- **Depends on:** S1, M0-20.
- **Goal:** resolve `X-Repository` into a `RepoId` (single-repo: bare name, missing header → configured repo, other
  value → `not_found`; multi-repo: `ns/name` required, grammar failure → `invalid_argument`); the signed
  `<repository>` must equal `X-Repository` (envelope failure → `unauthenticated`, per S1); classify self-certifying
  namespaces; reads of a nonexistent repo → `not_found`. Store access is keyed by `RepoId` through the M0-05
  `ShardMap` (still `SinglePartition` here; D34 routing is WP-1.22).
- **Files:** `rust/crates/mkit-server/src/{addressing.rs, pipeline/*}`; header extraction in both adapters;
  `rust/tests/golden/transport/repository-grammar.json`.
- **Tests:** grammar goldens; wire: `X-Repository` mismatch, bare name on multi-repo, uppercase identity, missing
  header, `ListRefs` on a nonexistent repo; repo isolation over the wire.
- **Gates:** rust nextest; conformance natively (FS+SQLite) and under `wrangler dev`; wasm32 clippy.
- **Size:** M (~900 lines).

### WP-1.22 Core: D34 shard model — `D34Shards`, namespace coordinator, ref shards

- **Depends on:** WP-1.4.
- **Goal:** Implement the D34 partitions from M0-02 behind the M0-05 `ShardMap`:
  - `D34Shards`: `ref_shard(repo, ref)` maps `refs/heads/<x>` and `refs/mkit/packmap/<x>` to one `Partition::Ref`;
    other refs get their own shard; `coordinator(ns)`; `membership(repo, pack)` = `RepoIndex{prefix = pack[0..12 bits]}`
    over the fixed `INDEX_FANOUT` (4096); `ref_index(repo, name)` = `RefIndex{bucket = hash(name) % REF_INDEX_FANOUT}` (16).
  - Coordinator key layouts: namespace record (creation, lease defaults, visibility placeholder), repo registry
    (for `creates_repo`), the epoch key (M2 writes it). Namespace/repo creation is a coordinator batch
    (`Absent` precondition), which gives `creates_namespace`/`creates_repo` to Admission exactly.
  - Ref-shard layouts for head/packmap; `ReadRef`, `UpdateRef` and `AdvanceRefs` route to ref shards (AdvanceRefs
    stays atomic because head and packmap share a shard).
  - A `--sharding single|d34` deployment option, default `single` until WP-1.28 flips it once ListRefs reads the
    ref index. `FsLayoutStore` (ssh, fs-layout) stays `SinglePartition` forever.
- **Files:** `mkit-server/src/shard/{mod.rs, d34.rs, coordinator.rs}`, `store/keys.rs` (new layouts + goldens),
  adapter config.
- **Tests:** shard-mapping goldens (head and packmap co-located; hash buckets stable); coordinator creation races
  (two first writes to a new namespace: exactly one `creates_namespace`); AdvanceRefs atomicity per ref shard;
  wire suite passes with `--sharding d34` on native (ListRefs cases gated until 1.28); a write in steady state costs
  exactly 2 DO calls (spy store), and a first write to a new ref shard 3 (the lease renewal that also creates the
  repo record).
- **Coordinator hot paths (R-76, P-22):** `creates_repo`/`creates_namespace` detection is folded into the lease
  renewal batch (the renewal is `Absent`-guarded on the repo record, so it reports creation exactly once); a ref
  shard that holds a live lease knows its repo exists and never asks the coordinator. Coordinator config (repo
  exists, visibility, lease defaults) carries a `config_version`; ref shards receive it with the lease, and the
  Worker keeps an isolate cache keyed by `(ns, repo, config_version)` (TTL 10 s) for read paths that never touch a
  ref shard (ListRefs, visibility in 2.9), invalidated whenever any shard reply carries a newer version. Result:
  ≤ ~2 DO calls per write in steady state; one extra coordinator call per active shard per lease interval.
- **Size:** L (~1300).

### WP-1.24 Core + adapters: timers `(due_at, kind, ref)` and alarm multiplexing

- **Depends on:** M0-20.
- **Goal:** One scheduling facility for every later timer (ticket expiry, outbox relay/delivery, pruning, lease
  sweeps, backups, verification slices, leases, GC):
  - the M0-02 `w/` timer layout per partition; a `TimerKind` registry with **idempotent** handlers and a per-tick
    budget (items and CPU) so one kind can't starve others
  - Workers: each DO's single alarm is set to `min(due_at)` after every batch that writes a timer and after each
    tick; the alarm is at-least-once with 6 retries and 15 min wall time, so handlers must tolerate re-delivery
  - native: a `TokioSpawner` periodic driver with a timer directory (a native-only helper partition) rebuilt by a
    scan at startup; graceful shutdown drains the current tick
  - a `run_due(partition, now, budget)` core function that both drivers call
- **Files:** `mkit-server/src/timers/{mod.rs, registry.rs}`, `mkit-server-native/src/timers.rs`,
  `mkit-server-worker/src/alarm.rs`, the M0 `RefStore` DO class gains `alarm()` (WP-1.8 reuses it for each class).
- **Tests:** at-least-once re-delivery is idempotent; budget fairness across kinds; alarm rescheduling to the new
  minimum; restart rebuilds the native directory; clock-skew directive drives due timers in black-box tests.
- **Size:** L (~1100).

### WP-1.5 Core: `namespace_policy`, `write_policy = owner` (owner key), startup validation

- **Depends on:** WP-1.22.
- **Goal:** as the planner draft: `allowlist` (default for multi-repo) or `any`; `write_policy` `open` (refused at
  startup in multi-repo mode) or `owner` (`ed25519-` namespace owner key; `0x` denied until M2; `ExternalAuthority`
  hook fails closed). `creates_namespace`/`creates_repo` come from the coordinator (WP-1.22). Startup check: `any`
  with the default Admission refuses to start unless `--unsafe-open-namespaces`. Authorization runs before any
  replay or quota row is allocated. The per-namespace quota aggregate is WP-1.26, not here.
- **Files:** `mkit-server/src/policy/{namespace.rs, write.rs}`, both adapters' config, `apps/vcs-worker/wrangler*.jsonc`
  vars (placeholders).
- **Tests:** as the planner draft (allowlisted owner creates a repo; non-allowlisted owner denied with nothing
  allocated; non-owner key denied; `0x` denied; startup refusals).
- **Size:** M (~800).

### WP-1.6 GetServerInfo (server)

- **Depends on:** WP-1.2, WP-1.5.
- **Goal:** unauthenticated, not replayed. Protocol/spec version; limits (max pack, part size, max parts, ListRefs
  page bounds, `index_fanout`); `begin_upload_threshold` (planner default: 0 on multi-repo deployments, so every
  multi-repo upload is ticketed and membership is always recorded through a ref shard; single-repo keeps today's
  behavior); atomic advance true; indexed mode false; admission support; empty receipt key and grant schemes;
  namespace policy and mode. Wired in both adapters.
- **Tests:** wire case asserting field shape and consistency with configured policy.
- **Size:** S (~350).

### WP-1.7 Ref-shard rows: tickets, reservations, local membership, outbox (planners)

- **Depends on:** WP-1.22, WP-1.24.
- **Goal:** key layouts (M0-02 registry) and pure planners for the ref-shard rows the lifecycle table needs:
  - tickets bound to (ref, signer, pack_id, bytes, part_size, expires, upload session id) + a `w/` expiry timer
  - reservations; open-ticket counters per (ref, signer) and per ref (used by WP-1.9's caps)
  - local membership additions (`m/` in the ref shard, strongly consistent, kept permanently for the `X-Mkit-Ref`
    read path) and the outbox rows that propagate them to repo index shards
  - outbox rows (`Committed`/`Aborted`/`Expired`, keyed by reservation id; unique), the pending index `oq`, the
    sequence `os`, and the backlog counter `oc` {rows, bytes}
  - the `tickets_open` precondition (a ticket consumed by an advance must still be open, `Equals`)
  - no physical migration: new key classes only (M0-09); layout version stays 1 unless an existing key changes
- **Files:** `mkit-server/src/store/keys.rs`, `mkit-server/src/plan/{tickets.rs, outbox.rs}`,
  `mkit-server-conformance/src/storage/{tickets.rs, outbox.rs}`.
- **Tests:** planner unit tests; storage/planner cases over memory and SQLite (ticket create and idempotent re-create
  for the same (signer, ref, pack); atomic refs + local membership + outbox; a failed precondition writes nothing).
- **Size:** L (~1200).

### WP-1.23 Core: repo index shards and the outbox relay

- **Depends on:** WP-1.7, WP-1.24.
- **Goal:**
  - Repo index shards (`RepoIndex{prefix}`, fixed fan-out 4096, created lazily, never resharded) holding repo
    membership.
  - The **outbox relay**: a timer kind in every ref shard that reads pending outbox rows and applies idempotent
    upserts to their target partitions, then deletes the rows (bounded growth). **Dedup by per-source high-water
    marks (R-82):** rows for one (source shard, target partition) are delivered in `seq` order, and the target keeps
    one `hw` row per source (`"rh" 00 <source partition>` → last applied seq) updated in the same batch as the
    upserts; a row with `seq ≤ hw` is a duplicate. This replaces per-(source, seq) keys, which grew without bound.
  - The **relay watermark (P-23)**: each ref shard tracks the commit time up to which its outbox is fully delivered
    and reports it to the coordinator with each lease renewal and when its outbox drains; a shard stays in the
    coordinator's table while it has undelivered rows, even after its lease expires. `namespace_relay_watermark()` =
    the minimum over that table. GC (5.3a/5.3b) and takedown completion (5.6) wait on it.
  - A **pre-delivery hook** on relay targets (no-op until M5): WP-5.6 uses it to check the global blocklist when a
    holder row is recorded. A best-effort immediate kick after `apply` keeps typical lag sub-second; the timer
    guarantees at-least-once. Relay writes are batched per target partition within the DO limits (≤ 100 bound
    parameters per statement, 2 MB rows).
  - `has_pack`/`PackExists`/`DownloadPack`/`AlreadyPresent` read membership from the index shard, plus the named
    ref shard's local additions when the request carries `X-Mkit-Ref` (S1 §7.9, **D36**; the ref must be in the
    same repo, and from M5 the caller's view applies: WP-5.4).
  - A `test-faults` directive delays relay delivery so conformance can observe lag windows.
- **Files:** `mkit-server/src/relay/{mod.rs, targets.rs}`, `mkit-server/src/store/read.rs` (membership reads).
- **Tests:** at-least-once with duplicate delivery (the `hw` row makes re-delivery a no-op); crash between target
  apply and source delete; lag window: `PackExists` is false (or `X-Mkit-Ref` strong-true) until delivery; no
  cross-repo visibility at any time; the watermark doesn't pass a shard with undelivered rows (relay-delay fault).
- **Size:** L (~1200).

### WP-1.28 Core: hash-bucketed ref-name index and ListRefs merge pagination; flip Connect deployments to D34

- **Depends on:** WP-1.23, WP-1.2, WP-1.8 (R-70: the Worker flip needs the DO classes).
- **Goal:** the ref-name index (`RefIndex{bucket}`, `REF_INDEX_FANOUT` = 16 fixed, no resharding) maintained by the
  relay; `ListRefs` k-way merges the buckets for a prefix behind an opaque cursor (the last emitted name), paginated
  with S1's fields and a **≤ 2 MiB** response budget (R-78: below connectrpc's default 4 MiB client message limit);
  `ReadRef` stays on the ref shard (strong). Flip the default of `--sharding` to `d34` for the native SQLite and
  Worker deployments.
- **Known cost (R-82):** a live (signed or writer) ListRefs page reads all 16 buckets, i.e. 16 DO calls per page on
  Workers, issued at most 4 at a time (M0-16's fan-out cap). Unsigned ListRefs is served from the per-bucket
  snapshots (1.21) instead, and a scan-limit per bucket keeps each call small. Documented in the operator README.
- **Tests:** merge order across buckets; cursor stability under concurrent inserts; > 32 MiB total listing where
  every page is ≤ 2 MiB; ListRefs lag vs ReadRef strong consistency.
- **Size:** M (~800).

### WP-1.25 Core: epoch leases (D34 revocation)

- **Depends on:** WP-1.22, WP-1.24.
- **Goal:** the lease mechanism of PRD §5.3, used by M2's `SetGrantEpoch` and visibility:
  - coordinator: the authoritative epoch, a table of currently leased shards (pruned at expiry: bounded by active
    shards), `lease(shard) → (epoch, expires)` with default 30 s
  - ref shard: an `el` key (epoch, expires, config_version); planners use it only while `now + safety_margin <
    expires` (margin default 5 s) and renew on the next write after expiry; every write batch carries
    `Equals(el, observed)` **and `NotAfter(min(expires − safety_margin, plan_time + MAX_APPLY_WINDOW))`** (R-61/R-62,
    P-21), which the store evaluates on its own clock at apply, so a batch that reaches the shard late (queueing, CPU
    stall, DO restart) after the lease expired commits nothing. A `NotAfter` failure re-plans: the planner renews the
    lease, sees the current epoch and, for a revoked grant, returns `permission_denied`. The margin must exceed the
    worst skew between the coordinator's clock and any ref shard's storage clock (documented).
  - revocation: raise the epoch, then push it to currently leased shards (≤ 4 concurrent, sliced on timers); complete
    once every leased shard acks or its lease expires; while pending the caller gets retryable `unavailable` with
    retry-after
  - the lease also carries cached coordinator config (visibility; the namespace quota view from WP-1.26)
  - a `test-faults` bump endpoint so M1 conformance can revoke without M2's signed statements
- **Tests:** revoke during an in-flight write (M0-05b `FaultHooks` barrier between authorize and apply → rejected at
  apply, `Aborted`, no ref moved); **paused write + failed push + expired lease (R-63):** barrier a write after it
  planned its batch, make the revocation push to that shard fail (test fault), advance past the lease expiry so the
  coordinator reports the revocation complete, then release the barrier → the batch fails `NotAfter`, re-plans and is
  rejected, nothing committed; an idle shard waking after a revocation renews and sees the new epoch; lease expiry
  racing an ack completes exactly once; no apply under a stale epoch in a property test over interleavings
  (including arbitrary delays between plan and apply).
- **Size:** L (~1300).

### WP-1.26 Core: default quota — exact per ref shard, approximate per namespace

- **Depends on:** WP-1.22, WP-1.24, WP-1.25.
- **Goal:** `DefaultAdmission` charges per-(namespace, signer) counters **in the ref shard** (exact, inside the
  batch); per-shard counters are reconciled into a coordinator total on a timer and served back through the epoch
  lease, so the per-namespace cap is approximate (documented bound: one reconciliation interval of overshoot per
  active shard). Keeps today's limits (Q14) and pruning of quota windows (bounded growth).
- **Tests:** exact per-shard exhaustion; namespace aggregate converges; overshoot within the documented bound.
- **Size:** M (~700).

### WP-1.8 Worker: Durable Object classes per shard kind

- **Depends on:** WP-1.22, WP-1.24.
- **Goal:** DO classes `NsCoordinator`, `RefShard`, `RepoIndexShard` (repo index and ref-index buckets) and
  `ContentIndexShard` (wired in WP-4.10a), each a thin `#[durable_object]` over M0-16's `ns_object::handle` +
  WP-1.24's alarm handler; `do_target` routing (M0-16 naming); wrangler `migrations` tag `v2` with
  `new_sqlite_classes` for the new classes (and `deleted_classes: ["RefStore"]` once nothing routes to "root";
  the worker was never deployed). Placement: `NAMESPACE_LOCATION_HINT`/`NAMESPACE_JURISDICTION` applied when a
  namespace's shards are first created (default none; a DO is pinned near first access). No DO-specific SQL: every
  class runs `SqlKvStore` (M0-09). Keep `migrations` (not `exports`).
- **Files:** `rust/crates/mkit-server-worker/src/{classes.rs, naming.rs}`, `apps/vcs-worker/src/lib.rs`,
  `apps/vcs-worker/wrangler.jsonc`, `wrangler.dev.jsonc`.
- **Tests:** storage suite through each class under `wrangler dev`; multi-namespace isolation over the wire;
  placement option plumbed (config test).
- **Gates:** the worker gate (local), `scripts/check-wasm-dep-graph.sh`, wrangler-dev conformance.
- **Size:** M (~900).

### WP-1.9 Core: `BeginUpload` (target ref), tickets, stateless ticket token, ticketed `UploadPack`

- **Depends on:** WP-1.2, WP-1.5, WP-1.7, WP-1.23.
- **Goal:** the handler per §5.4 and the lifecycle table: authenticate, replay lookup, authorize, admit (default
  quota; open-ticket caps per (ref, signer) and per ref, enforced at admission with `failed_precondition`, not
  `resource_exhausted`), then one ref-shard batch (replay + reservation + ticket + expiry timer). Returns the
  stateless ticket token (deployment ticket key with key id; S1 §7.6). `AlreadyPresent` only when the pack is a
  member of this repo (index or the ref's local additions); the same (signer, ref, pack) gets the existing ticket.
  Single-part `UploadPack` with a ticket token verifies the token statelessly and checks the `pack:` commitment
  against it before reading chunks. Multi-repo uploads always need a ticket (threshold 0, WP-1.6 default).
- **Tests:** wire: ticket issued; idempotent replay; same ticket for a new nonce; `AlreadyPresent` only after an
  advance (allowing relay lag); wrong signer → `permission_denied`; commitment mismatch → `permission_denied`;
  missing ticket → rejected; in-flight replay → `aborted`; no oracle across repos (D15); ticket caps.
- **Size:** L (~1300).

### WP-1.10 Core: `AdvanceRefs` consumes tickets; outcomes; ref deletion

- **Depends on:** WP-1.9.
- **Goal:** `AdvanceRefs` (and `UpdateRef`) with `ticket_ids`: one ref-shard batch does the head/packmap CAS,
  closes the consumed tickets (which must name this ref), records local membership additions and their relay
  outbox rows, and writes one `Committed` outbox row per ticket. A failure after `Allow` writes `Aborted` in a
  separate batch. The MKPL rule (every listed pack is a member or ticketed in the same advance) reads membership
  from the index plus the batch's own tickets. **A packlist-membership miss is retryable `unavailable`** ("listed pack
  not yet visible") while the youngest ticket involved is within the relay-lag bound (the P-15 rule), then the
  permanent `failed_precondition` (R-76); a lagging index must never turn a valid push into a permanent error. Ref
  deletion per S1 §7.8.
- **Tests:** push round trip with tickets; another repo's pack → `false`/`not_found`; HeadConflict leaves tickets
  open; a retried advance returns the stored `Committed` with no second outbox row; exactly one outcome per
  reservation; deletion of head and packmap together.
- **Size:** L (~1200).

### WP-1.11 Core: `UploadPart`/`CompleteUpload` (stateless), part receipts, `MultipartBlobStore`, FS backend

- **Depends on:** WP-1.3, WP-1.9.
- **Goal:** `MultipartBlobStore: BlobStore` sub-trait (`begin_multipart`, `put_part` taking a chunk stream,
  `complete`, `abort`, session id carried in the ticket token). `UploadPart` is **client-streaming** (R-69): the
  header message carries the ticket token and index; the handler verifies the token and the `part:` commitment
  before reading data, hashes the chunks as a subtree while streaming them to storage (memory bounded by one chunk;
  never collected into one buffer), and returns a signed part receipt at stream end; it touches **no** metadata
  shard. `CompleteUpload` verifies receipts, merges to the root, and commits only if root == pack_id. FS backend:
  part temp files, then concatenate, fsync, rename. Ticket/receipt key config with key-id rotation.
- **Tests:** out-of-order and duplicate parts; wrong subtree hash or length; a merged-root mismatch never becomes
  visible; a short non-last part is rejected; resume from client-held receipts after a crash; no namespace-store
  call on the part path (a spy store).
- **Size:** L (~1400).

### WP-1.12 Worker: R2 multipart, streamed parts

- **Depends on:** WP-1.11, WP-1.8.
- **Goal:** stream each client-streamed part through the Worker (M0-17's streaming dispatch; `uploadPart` fed from a
  `FixedLengthStream` whose put is `spawn_local`'d as in M0-16), hashing it as a BLAKE3 subtree; `complete` only
  after the merged root verifies (R2 visibility is the commit point); no presigned direct-to-R2 uploads; part
  requests never reach a DO. Remove M0's 64 MiB stopgap for ticketed parts. R2 limits: uniform part size ≥ 5 MiB
  except the last, ≤ 10,000 parts, 7-day auto-abort (tickets expire sooner); advertise 8 MiB, cap 32 MiB.
- **Tests:** the storage multipart suite under `wrangler dev`; a ~40 MiB (5-part) upload; peak memory per request
  ≤ one part.
- **Size:** M (~800).

### WP-1.13 Native: S3 multipart `BlobStore`

- **Depends on:** WP-1.11.
- **Goal:** the multipart API on the M0 S3 store, reusing `mkit-transport-s3` multipart/SigV4; verification before
  `CompleteMultipartUpload`; the upload id travels in the ticket token.
- **Tests:** storage multipart suite against the M0 fake S3.
- **Size:** M (~600).

### WP-1.14 Ticket expiry and pre-M3 outbox retention

- **Depends on:** WP-1.10, WP-1.12, WP-1.24.
- **Goal:** the ticket-expiry timer kind: one `Expired` row per unadvanced reservation, the multipart session
  aborted, the ticket **deleted** (bounded growth), the pack GC-eligible (GC is M5). A built-in no-op `OutcomeSink`
  acks and **deletes** outbox rows until M3 replaces it (Q-M1-6 default), keeping the `oc` backlog counter exact.
- **Tests:** with the clock-skew directive: one `Expired` row; advancing an expired ticket is rejected; the R2/S3
  session is aborted; ticket and outbox key counts return to baseline.
- **Size:** M (~700).

### WP-1.29 Ops: periodic backup export to R2 and per-shard storage alerts

- **Depends on:** WP-1.24, WP-1.8.
- **Goal:** a `backup` timer kind that exports each active DO partition with the M0-02 portable export to R2
  (`backups/<partition>/<timestamp>.kvlog`, retention configurable), because DO PITR is per-object only; a restore
  procedure (import into a fresh partition) in the runbook; native: `mkit-server backup` (physical `VACUUM INTO` and
  logical export). Every partition reports `stats` on the timer tick; export `mkit_server_partition_bytes{kind}` and
  raise alerts (log + metric) at 70% and 90% of the per-partition cap (10 GB on DO, configurable). **At the cap**
  (R-83, P-24): Cloudflare documents that writes fail with `SQLITE_FULL` while reads and `DELETE` keep working; the
  store maps it to `StoreError::Full` (M0-16), the pipeline fails the write closed with retryable `unavailable`
  ("storage partition full"), and this WP raises a critical alert (`mkit_server_partition_full_total{kind}`); the
  pruning timer kinds keep running because deletes succeed. No fill-to-cap staging test.
- **Tests:** export/import round trip through R2 under `wrangler dev`; alert thresholds with a fake stats source; a
  store that returns `Full` produces the critical alert and `unavailable`, and pruning still deletes.
- **Size:** M (~800).

### WP-1.15 ssh and enc: multi-repo addressing, principal, implicit session tickets

- **Depends on:** WP-1.5, WP-1.10.
- **Goal:** `mkit serve [--principal <ed25519-hex>] <path>` (sets `Principal::SshForcedCommand{key}`); `<root>/<ns>/<name>`
  → `ns/name`, each repo directory its own `FsLayoutStore` (refs as files, `SinglePartition`; **no SQLite**, so the
  CLI stays server-free); plain `mkit serve <repo-path>` stays single-repo; the enc peer key is the principal;
  owner-key policy; implicit per-session tickets (the frozen `mkit.rpc.v1.ssh` can't carry tickets: each
  `UploadPack` opens one, the next `AdvanceRefs`/`UpdateRef` consumes them; no threshold); no admission on ssh/enc.
- **Files:** `mkit-cli/src/commands/serve/mod.rs`, `mkit-server-native/src/enc.rs`, `docs/SSH-SECURITY.md` §5.
- **Tests:** existing ssh e2e; owner principal pushes, non-owner denied; two repos under one root isolated.
- **Gates:** rust nextest, `scripts/check-cli-baseline.sh` (server-free CLI), ssh e2e.
- **Size:** M (~900).

### WP-1.16 Client: `X-Repository` everywhere, identity validation, GetServerInfo, ListRefs paging, ref hint

- **Depends on:** WP-1.2, WP-1.6.
- **Goal:** `x-repository` on every request; URL-path identity validated against the S1 grammar (`default` for an
  empty path); lazy cached `GetServerInfo` drives `supports_atomic_advance` (Q-M1-10: yes), threshold and part
  size; `unimplemented` → clear error; `ListRefs` follows `next_page_token`; `PackExists`/`DownloadPack` send
  `X-Mkit-Ref` (D36) when the pack came from a packmap just read.
- **Tests:** header on unsigned reads; grammar rejection; atomic advance flips from `GetServerInfo`; paging over a
  multi-page listing; hint header present on packmap-driven fetches.
- **Gates:** rust nextest, `scripts/check-cli-baseline.sh`.
- **Size:** M (~700).

### WP-1.17 Client: `BeginUpload` with target ref, ticket threading, nonce/re-sign rule

- **Depends on:** WP-1.16, WP-1.10.
- **Goal:** `upload_pack`/`upload_blob` call `BeginUpload(repository, ref, …)` naming the branch being pushed;
  `AlreadyPresent` skips the upload; the defaulted `Transport::advance_refs_committing(…, commit: &[PackKey])`
  (adopted default) maps pack keys to `ticket_ids` so stale packlist-node tickets are never attached (G9); retry
  identity reused while valid, re-signed after 300 s (G6).
- **Tests:** in-process push and clone with tickets; `AlreadyPresent` on a re-push; PackmapConflict retry attaches
  only the fresh node's ticket; re-sign after 300 s with the injected clock; other transports unaffected.
- **Gates:** rust nextest, CLI e2e, `scripts/check-cli-baseline.sh`.
- **Size:** L (~1200).

### WP-1.18 Client: resumable part upload with client-held receipts

- **Depends on:** WP-1.17, WP-1.3, WP-1.11.
- **Goal:** for packs larger than `part_size`: subtree chaining values, per-part client-streaming upload with its
  own nonce and `part:` commitment, receipts kept for resume (re-send only parts without a receipt), `CompleteUpload`; parts are
  sliced lazily (no second whole-pack copy).
- **Tests:** 3-part pack with a fault after part 2, then resume; envelope parity against `auth-v2/part.json`.
- **Size:** M (~900).

### WP-1.21 Worker: published-view ref snapshot (R2/Cache) for readers

- **Depends on:** WP-1.28, WP-1.10, WP-1.8.
- **Goal:** protect hot namespaces: snapshots of the published view (M1: equal to the live refs) **per ref-index
  bucket** (R-73): each `RefIndex{bucket}` shard (16 per repo, hash-sharded) owns one R2 object
  `snapshots/<ns>/<repo>/<bucket>` (versioned, conditional overwrite by version), fronted by the Cache API. The
  bucket shard rewrites it from a **debounced** timer after the relay changes the bucket: at most one write per key
  per second (R2 allows 1 write/s per key), coalescing every change since the last write; staleness is bounded by
  the debounce interval (1 s default) plus relay lag. Unsigned `ListRefs` k-way merges the 16 bucket snapshots from
  Cache/R2 (no DO call); private repos are dropped from the snapshots when the config cache (1.22) reports a
  visibility change. Unsigned `ReadRef` is served from it only when the deployment opts in
  (`READREF_FROM_SNAPSHOT`, default off until M2 signed reads let writers bypass it); push CAS always reads the ref
  shard. Private repos are never snapshotted for anonymous readers (M2 enforces visibility).
- **Tests:** snapshot freshness after an advance (within debounce + lag); version race keeps the newest; a burst of
  100 advances to refs in one bucket produces ≤ ~1 R2 write/s for that key and no 429; hot-read load test on
  staging (reads don't touch DOs); writers unaffected.
- **Size:** M (~800).

### WP-1.27 M1 conformance: D34, tickets and growth cases (wire + storage + load)

- **Depends on:** WP-1.9, WP-1.10, WP-1.14, WP-1.25, WP-1.26, WP-1.28.
- **Goal:** add the M1 cases to `mkit-server-conformance` (milestone M1, features `MultiRepo`, `Tickets`):
  multi-repo isolation; namespace policy; `BeginUpload` with a target ref (ticket can't be consumed by another ref);
  open-ticket caps; lag windows for membership and ListRefs (using the relay-delay fault); **D36 read-your-writes:
  a pusher's `PackExists`/`DownloadPack` with `X-Mkit-Ref` sees its just-advanced packs immediately while the relay
  is delayed, and the header never reveals another repo's packs or a ref of another repo**; epoch-lease revocation
  (revoke during an in-flight write, the paused-write/failed-push/expired-lease case of R-63, idle shard waking
  after a revocation, lease expiry racing an ack) via the test bump endpoint; many-ref write throughput in one repo (64 refs written concurrently; on staging assert
  aggregate throughput ≥ 8× a single hot ref; on `wrangler dev` only correctness); bounded growth (replay, quota,
  tickets and outbox key counts shrink back after load + clock skew); ListRefs merge pagination across ref-index
  buckets with a > 32 MiB total listing and every page ≤ 2 MiB.
- **Size:** L (~1400).

### WP-1.19 Staging `vcs-worker` deployment config and runbook

- **Depends on:** WP-1.6, WP-1.8, WP-1.12, WP-1.14, WP-1.18, WP-1.21, WP-1.29.
- **Goal:** `env.staging` in `apps/vcs-worker/wrangler.jsonc`: route/custom domain, `AUTH_AUDIENCE` = the staging
  origin, `SERVER_MODE=multi`, `NAMESPACE_POLICY=allowlist` with the CI key namespace, R2 bucket
  `mkit-vcs-objects-staging` (+ a backups prefix or bucket), the DO bindings and migration `v2`, `limits.cpu_ms`,
  a current `compatibility_date`, placement vars (default none). README runbook: deploy, backup/restore, alerts.
- **HUMAN / CLOUDFLARE STEPS:** see 00-plan.md human-action checklist (hostname/zone, scoped API token, bucket,
  first deploy, CI signer key, manual smoke).
- **Size:** S (~300).

### WP-1.20 CI: conformance and e2e against staging (M1 exit)

- **Depends on:** WP-1.19, WP-1.27, WP-1.13, WP-1.15.
- **Goal:** `.github/workflows/server-staging.yml` (`main`, `schedule` or dispatch against `main` only, per the CI policy; it first runs on the final PR to `main`; during the epic the orchestrator runs the same suite locally against staging at each milestone boundary):
  optional deploy (secret-gated), the full wire suite (M0+M1 cases, including throughput and lag windows) against
  the **deployed** staging URL, and `scripts/staging-roundtrip.sh` (real `mkit` init/commit/push/clone/verify),
  unique repo per run.
- **HUMAN STEPS:** GitHub secrets and variables (checklist).
- **Size:** S (~300).

---

## 2. Milestone M2: identity track

PRD: §6.4, the signed-URL part of §6.6, and §8 M2.

The M2 exit criteria:
- Conformance for grants.
- Revocation, including a revoke during an in-flight write that must be rejected at `apply`, now over D34 epoch
  leases (WP-1.25): also an idle shard waking after a revocation and lease expiry racing an ack, with real signed
  epoch statements.
- Private reads (unauthorized → `not_found`).

### WP-2.1 — dropped

Folded into WP-S2 §9–§11 (adopted Q19 default): signed reads, visibility with `SetRepoVisibility`, the `read`
capability, `not_found` for unauthorized private reads, `IssueObjectUrl` tokens signed by a dedicated URL-token key
(TTL default 15 min), ssh/enc registration, and the error-code table.

### WP-2.2 Proto additions for M2

- **Depends on:** S2, WP-1.20 (M2 starts after the M1 exit).
- **Goal:** Add:
  - `GetGrantEpoch{namespace}` returning `{epoch}`
  - `SetGrantEpoch{statement, scheme, blob}` (or the header-encoded form per S2) returning `{epoch}`; a pending
    revocation returns retryable `unavailable` with retry-after (S2 epoch leases)
  - `IssueObjectUrl`
  - `SetRepoVisibility{repository, visibility}` (owner-signed; S2 §9)
  - `GetServerInfo.grant_schemes` population semantics (the field exists from WP-1.2)

  Regenerate every vendored copy, with stubs returning `unimplemented`.
- **Files:** `proto/mkit/transport/v1/transport.proto`, the generated dirs (G21).
- **Gates:** `buf lint`, `buf breaking`, `check-generated-fresh.sh`, full nextest.
- **Size:** S, about 250 lines plus generated code.

### WP-2.3 mkit-attest: Keccak-256, EIP-191, secp256k1 recovery, address derivation

- **Depends on:** none (S2 for text). It can start in M1.
- **Goal:** A new `mkit-attest/src/eth.rs` with:
  - `keccak256` (new dependency `sha3 = { version = "0.11", default-features = false }`)
  - `eip191_hash(statement)`, meaning `"\x19Ethereum Signed Message:\n" + len + msg` hashed with Keccak
  - `recover_secp256k1(prehash, r||s, v∈{27,28})`, which requires low-S via `ecdsa::RecoveryId` and `VerifyingKey::recover_from_prehash`
  - `address_from_uncompressed(x||y)` returning `keccak256[12..]`, for both secp256k1 and P-256
  - `p256_der_to_compact_low_s_required` (reject high-S; the client side normalizes)

  Put these behind a new `grants` feature that pulls `algo-secp256k1`, `algo-p256` and `algo-ed25519`.
- **PRD refs:** §6.4 namespaces, §4 crypto, "grant verifier lives in mkit-attest".
- **Files:** `rust/crates/mkit-attest/{Cargo.toml,src/eth.rs (new),src/lib.rs}`, `rust/tests/golden/grants/eth-primitives.json` (new, with public Ethereum vectors: known private key to address, and `personal_sign` vectors), `rust/about.toml`/THIRD-PARTY-NOTICES if the license set changes.
- **Tests:**
  - goldens
  - high-S rejection on recovery
  - `v` outside {27, 28} rejected
  - a P-256 address from a fixed key
  - a wasm32 build of `mkit-wasm` (mkit-attest is on its graph)
- **Gates:** rust nextest, `cargo deny check`, `scripts/check-crypto-stack-version.sh` (sha2 and dalek pins unchanged), `scripts/check-wasm-dep-graph.sh`, `cargo build -p mkit-wasm --target wasm32-unknown-unknown`, `just ci-geiger`, third-party-notices workflow.
- **Size:** M, about 600 lines plus goldens.
- **Risks:**
  - The `sha3` version must share the `digest` major with `sha2 0.11`.
  - Recovery misuse: the prehash must be Keccak. Add a doc warning and a test.

### WP-2.4 mkit-attest: grant and epoch statement codec plus the ed25519 scheme

- **Depends on:** S2.
- **Goal:** A new `mkit-attest/src/grant.rs` with:
  - a strict parser and encoder for `mkit-write-grant:v1` per S2, with fields as revised by the PRD:
    - namespace
    - explicit audience list, no wildcard (D5)
    - scope (repo or `ns/*`)
    - ref scopes (patterns plus `create`/`update`/`force`/`delete`) (D6)
    - capabilities (`write`/`read`) (D19)
    - grantee
    - epoch
    - created and expiry, at most 30 days apart
    - nonce
  - `mkit-write-epoch:v1` (namespace, epoch, bounded increment, audience list, created and expiry, nonce)
  - canonical-form rejection rules
  - grant id = BLAKE3(canonical)
  - header encoding (`<statement>.<scheme>.<blob>`, at most 8192 bytes)
  - the `ed25519` owner scheme (strict verification over BLAKE3(canonical))
  - a `GrantVerifier` API that returns a typed `VerifiedGrant{namespace, audiences, scope, ref_scopes, caps, grantee, epoch, window, id}` with no server state; epoch comparison is left to the caller
- **PRD refs:** §6.4, D5, D6, D19.
- **Files:** `rust/crates/mkit-attest/src/{grant.rs (new),grant/ref_scope.rs (new)}`, `rust/tests/golden/grants/{grant-ed25519.json,epoch-ed25519.json,reject/*.json}`, `rust/fuzz/fuzz_targets/grant_parse.rs` (new; follow the existing fuzz layout).
- **Tests:**
  - goldens (canonical bytes, id, signature)
  - reject vectors: trailing newline, uppercase hex, leading zeros, audience wildcard, window over 30 days, unknown capability, duplicate audience
  - the fuzz target
- **Gates:** rust nextest, wasm32 build, fuzz build (`fuzz.yml`), optional `cargo mutants -p mkit-attest --file src/grant.rs`.
- **Size:** L, about 1300 lines plus goldens.
- **Risks:**
  - The ref-scope pattern grammar has to come from S2. Don't invent it.
  - Matching packmap coverage is server logic (WP-2.7), not codec.

### WP-2.5 mkit-attest: `secp256k1-eip191` and `webauthn-p256` owner schemes

- **Depends on:** WP-2.3, WP-2.4.
- **Goal:**
  - `secp256k1-eip191`: a 65-byte `r||s||v` blob. Recover the key, derive the address, and require the address to equal the namespace digits.
  - `webauthn-p256`: four length-prefixed fields (pubkey x||y, authenticatorData, clientDataJSON, DER signature). Reuse `verify_webauthn_wrapping_with_policy` (`webauthn.rs:198`) with:
    - challenge = BLAKE3(canonical)
    - `require_user_presence = true`
    - the deployment RP id and origins policy
    - DER converted to compact with low-S required
    - address from x||y
- **PRD refs:** §6.4, "P-256 signatures are normalized to low-S on the client".
- **Files:** `rust/crates/mkit-attest/src/grant/schemes.rs` (new), `rust/tests/golden/grants/{grant-eip191.json,grant-webauthn.json,epoch-eip191.json}`.
- **Tests:**
  - goldens
  - high-S DER rejected
  - UP flag cleared rejected
  - RP mismatch rejected when pinned
  - an `ed25519` scheme on a `0x` namespace rejected (scheme/namespace-form binding)
- **Gates:** as WP-2.4.
- **Size:** M, about 900 lines.
- **Risks:** WebAuthn golden generation needs a deterministic fixture. Use the existing `build_client_data_json` (`webauthn.rs:359`) plus a fixed P-256 key.

### WP-2.6 Server: grant-based authorization (writes), `0x` namespaces, error-code alignment

- **Depends on:** WP-2.5, WP-1.5, WP-2.2 (grant schemes in GetServerInfo).
- **Goal:** Extend the `owner` write policy to: owner key, or a valid grant from the S2 grant header, or `ExternalAuthority`. The checks run in order:
  1. decode
  2. namespace equals the `X-Repository` namespace
  3. scheme valid for the namespace form, and the signature verifies
  4. the server's `AUTH_AUDIENCE` is in the audience list
  5. scope covers the repo
  6. grantee equals `X-Public-Key`
  7. capability `write`
  8. time window
  9. read the target ref shard's leased epoch (WP-1.25, renewing the lease if needed) and require it to equal the
     grant epoch

  The authorized epoch travels in the `Operation` into `apply` as a precondition (A2). Also:
  - `0x` namespaces become writable through grants.
  - One central error mapping: envelope problems give `unauthenticated`; policy and grant failures give `permission_denied`. This fixes the blanket `unauthenticated` (G12).
  - `GetServerInfo.grant_schemes` is populated.
  - The WebAuthn RP pinning config lives in the server config.
- **PRD refs:** §5.4 step 2, §6.4, D5.
- **Files:** `rust/crates/mkit-server/src/policy/{grants.rs (new),write.rs}`, `rust/crates/mkit-server/Cargo.toml` (`mkit-attest` with `default-features = false, features = ["grants"]`), the error-mapping module.
- **Tests:** wire conformance for:
  - a valid grant for each scheme
  - wrong audience
  - expired
  - future-created by more than 30 s
  - grantee mismatch
  - out-of-scope repo
  - read-only grant used for a write
  - epoch below or above stored
  - no replay or quota row allocated on rejection (storage suite)
- **Gates:** rust nextest, both-adapter conformance, wasm dep graph (`mkit-server-worker` now pulls mkit-attest grants).
- **Size:** L, about 1200 lines.
- **Risks:**
  - Workers CPU for recovery and WebAuthn is small (about 1 ms).
  - Verified-grant caching per request only. Do not cache across requests past the epoch check.

### WP-2.7 Server: ref scopes and packmap coverage

- **Depends on:** WP-2.6.
- **Goal:** Evaluate the grant's ref scopes per ref in `UpdateRef`/`AdvanceRefs`:
  - `create` is a `Missing` expectation
  - `update` is `Match`; without `force`, it is fast-forward only
  - `force` is `Any`, or a non-FF `Match`
  - `delete` governs ref deletion through `UpdateRef`/`AdvanceRefs` (S1 §7.8; adopted default keeps the flag)

  Packmap rules:
  - A scope on `refs/heads/<x>` covers `refs/mkit/packmap/<x>` only when both are in one `AdvanceRefs`.
  - Flags are evaluated on the head only.
  - Direct packmap writes by grantees (UpdateRef on `refs/mkit/packmap/*`) are denied.
  - Head-only `UpdateRef` is allowed under the head scope (G10).

  Opaque mode rejects any grant containing `update` without `force` at authorization time, with a clear message. Indexed FF checks are M4.
- **PRD refs:** §6.4 ref scopes, D6.
- **Files:** `rust/crates/mkit-server/src/policy/ref_scopes.rs` (new).
- **Tests:**
  - unit: pattern matching and flag table
  - wire: the CLI push flow (the AdvanceRefs pair) works under a `refs/heads/main` grant
  - a direct packmap UpdateRef is denied
  - `create`-only rejects an update
  - an opaque server rejects an update-without-force grant
  - a re-baseline push (non-append packmap, `packmap.rs:403-423`) is allowed under the head scope
- **Gates:** rust nextest, conformance.
- **Size:** M, about 800 lines.
- **Risks:** The PRD says the owner key is unrestricted. Keep owner writes out of the ref-scope logic.

### WP-2.8 Epoch: `GetGrantEpoch`/`SetGrantEpoch` over epoch leases, apply precondition, revoke races

- **Depends on:** WP-2.6, WP-2.2.
- **Goal:**
  - `GetGrantEpoch` is an unauthenticated read of the coordinator.
  - `SetGrantEpoch` verifies the owner-signed epoch statement (WP-2.4/2.5), requires the audience to contain the
    server, checks the window (max lifetime 30 days), requires `stored < new ≤ stored + MAX_EPOCH_STEP` (planner
    default 1024), then raises the epoch through WP-1.25's lease protocol and reports success only when every
    currently leased shard has acknowledged or its lease has expired; idempotent for the same statement.
  - Every write batch in a ref shard already carries the leased-epoch precondition and the `NotAfter` commit deadline
    (WP-1.25); the authorized grant epoch (`op.authz.grant.epoch`) must equal it. On mismatch at apply: `permission_denied`, and an `Aborted` row
    in a separate batch for any reservation.
  - Conformance re-runs WP-1.27's lease cases with real statements; the revoke-during-in-flight barrier uses the
    M0-05 `FaultHooks` seam (works under `wrangler dev` and on staging with a `test-faults` build).
- **Files:** `rust/crates/mkit-server/src/handlers/epoch.rs` (new), conformance `wire/revocation.rs`.
- **Tests:** monotonic; over-bound increment rejected; wrong audience; expired statement; **revoke during in-flight
  write** (barrier → `SetGrantEpoch` → resume: rejected at apply, `Aborted` written, no ref moved); **paused write
  whose revocation push failed** (R-63: barrier after planning, push to that shard fails, lease expires, revocation
  reported, resume → rejected by `NotAfter` then the epoch check, nothing committed); an idle shard
  woken after a revocation rejects the old-epoch grant; lease expiry racing an ack; a grant at the new epoch works.
- **Gates:** rust nextest, both-adapter conformance, staging.
- **Size:** M (~900; the lease machinery is WP-1.25).

### WP-2.9 Server: signed reads, visibility, read grants

- **Depends on:** WP-2.6, WP-2.2.
- **Goal:**
  - Verify auth v2 on read RPCs (`ListRefs`, `ReadRef`, `PackExists`, `DownloadPack`, `IssueObjectUrl`), checking the validity window only, with no replay lookup (§5.4 step 0).
  - Unsigned reads map to an anonymous principal.
  - Per-repo visibility `public`/`private` stored in the namespace coordinator, set by the owner-signed
    `SetRepoVisibility` RPC (adopted default), deployment default `public`, carried to ref shards by the epoch lease
    (WP-1.25) and to Workers by the versioned config cache (WP-1.22, P-22); a change to `private` reports completion
    only after the lease rule **and** one cache TTL, so reads that never touch a ref shard (ListRefs) can't serve a
    stale `public`.
  - A private repo read requires the owner key or a grant with the `read` capability, subject to the same epoch and
    audience checks (a read grant's epoch is checked at read time against the ref shard's leased epoch).
  - An unauthorized read of a private repo returns `not_found` (adopted default; no existence oracle).
  - Signed reads bypass the published-view snapshot (WP-1.21); private repos are never served from it.
  - Expose `caller_view ∈ {writer, reader, anonymous}` on the principal for M5's published view. M2 always serves live refs.
- **PRD refs:** §5.4 step 0, §6.4 other rules, D19, D28.
- **Files:** `rust/crates/mkit-server/src/{auth/read.rs (new),policy/visibility.rs (new),handlers/*}`, `mkit-core/src/write_auth.rs` (only if S2 defines a read-specific commitment or procedure rule; else reuse `verify_headers` with `body:`).
- **Tests:**
  - public repo, unsigned read works
  - private repo: unsigned read fails, the owner's signed read works, a read grant works, a write-only grant fails, an expired read signature fails
  - a signed read never creates a replay row (storage suite)
  - multi-repo isolation still holds
- **Gates:** rust nextest, both-adapter conformance.
- **Size:** L, about 1300 lines.
- **Risks:** Existence leakage through error codes: every private-repo denial path must return `not_found`
  byte-identically (a conformance case compares responses).

### WP-2.10 Client: signed reads and grant header

- **Depends on:** WP-2.4, WP-1.16.
- **Goal:**
  - When a signer is configured, `EnvelopeTransport` signs *every* RPC. That signer exists only for `trusted_remote_endpoint` with `transport_auth = envelope` (G19). The new procedures are `ListRefs`, `ReadRef`, `PackExists`, `DownloadPack`, `GetGrantEpoch` and `IssueObjectUrl`; `GetServerInfo` stays unsigned (Q-M2-12).
  - Attach the S2 grant header from the client grant store (WP-2.13), selected by (audience, namespace).
  - Ensure retries of reads re-sign freely: no replay, so a fresh identity is always fine.
- **PRD refs:** §6.4, D28.
- **Files:** `rust/crates/mkit-transport-connect/src/envelope.rs` (`:76-85`, `:237-241`), `rust/crates/mkit-cli/src/remote_dispatch/mod.rs` (grant resolution next to `envelope_signer_from_config`, `:258`).
- **Tests:**
  - envelope parity tests for read signing (capture headers, verify with `mkit_core::write_auth::verify_headers`)
  - an e2e private-repo clone with the owner key and with a read grant
  - golden `rust/tests/golden/auth-v2/read.json`
- **Gates:** rust nextest, CLI e2e.
- **Size:** M, about 700 lines.
- **Risks:** Signing reads reveals the signer's identity to the server. This is by design, and limited to the trusted endpoint.

### WP-2.11 `IssueObjectUrl` and signed URL tokens (mint and verify only)

- **Depends on:** WP-2.9, WP-2.2.
- **Goal:**
  - Deliver in M2:
    - the unary `IssueObjectUrl` handler, which requires read access to the repo
    - token mint and verify in `mkit-server` under the `http-objects` feature
    - the token format per S2 §9, binding audience, repo, target (`object_id`, or unresolved `ref`+`path`), expiry,
      key id and the `caller_view` class, signed by the **dedicated deployment URL-token key** (Ed25519, key id,
      rotation via the published key list; never shared with receipt, hook or admin keys)
    - a TTL clamp; default TTL 15 min (adopted)
    - goldens
  - M4 owns: the HTTP serving endpoints, `ref+path` resolution, reachability checks and cache headers. The verify function is the M2-to-M4 interface.
- **PRD refs:** §6.4 "Signed URL tokens", §6.6 private content.
- **Files:** `rust/crates/mkit-server/src/{handlers/issue_object_url.rs (new),http_objects/token.rs (new)}`, `rust/tests/golden/url-token/*.json`.
- **Tests:**
  - goldens
  - expiry
  - wrong audience or repo
  - a tampered target
  - key rotation by key id
  - private repo mint without a read grant is denied
- **Gates:** rust nextest (with the feature on and off), conformance.
- **Size:** M, about 900 lines.
- **Risks:** `ref+path` in opaque mode is unresolvable, so the token binds the unresolved target and M4 decides
  whether opaque mode can serve it at all (Q-M2-5, planner default: the token binds the unresolved target).

### WP-2.12 ssh and enc: server-side grant registry

- **Depends on:** WP-2.6, WP-2.8.
- **Goal:**
  - A registry of owner-signed grants keyed by the transport principal (Ed25519), registered by the adopted operator
    command `mkit-server grant register|list|remove` (full admin API stays M5, WP-5.11b wraps it). It verifies the
    grant with the same verifier and writes it into the deployment's metadata store:
    - `mkit serve` (ssh; server-free CLI, `FsLayoutStore`): grant and epoch **files** under the served root (e.g.
      `<root>/<ns>/.mkit-server/grants/<grant-id>` and `.../epoch`), read and written under the `.mkit/refs/.lock`
      ref lock, which is what makes the epoch check atomic with the ref write there (single writer, no leases needed)
    - `mkit-server` (enc listener, SQLite): rows in the namespace coordinator, checked through the normal
      leased-epoch precondition
  - At identity mapping, ssh and enc principals look up registered grants and evaluate them exactly like header
    grants (epoch, ref scopes, capabilities).
- **PRD refs:** §6.4 ssh and enc, §6.9, §6.7 admin API (deferred).
- **Files:** `rust/crates/mkit-server-native/src/bin/mkit-server/grant_cmd.rs` (new),
  `rust/crates/mkit-server/src/policy/registered_grants.rs` (new), `rust/crates/mkit-server/src/fs/layout.rs`
  (grant/epoch files), `docs/SSH-SECURITY.md` §5.
- **Tests:** ssh e2e: a registered grant allows a push; raising the epoch invalidates it; an unregistered principal
  is denied; ref scopes are enforced over ssh; the same over enc against `mkit-server`.
- **Gates:** rust nextest, ssh e2e, `scripts/check-cli-baseline.sh` (server-free CLI).
- **Size:** M (~900).

### WP-2.13 CLI: `mkit grant create` / `list`, and the client grant store

- **Depends on:** WP-2.5, WP-2.10.
- **Goal:**
  - `mkit grant create`:
    - builds a statement from flags: `--namespace`, `--repo|--all`, `--audience` (repeatable), `--refs <pattern>:<flags>`, `--cap write,read`, `--grantee`, `--ttl` up to 30 days
    - owner scheme `ed25519` signs natively with the mkit key or keystore
    - `secp256k1-eip191` signs natively with a keystore k256 key, *or* prints the statement for an external wallet and accepts `--signature` (normalizing high-S by flipping `v`)
    - `webauthn-p256` supports external assertion import only, normalizing the DER to low-S
  - `mkit grant add <file>` (import for the grantee) stores the grant under the **user config dir** (adopted default;
    never repo-scoped), keyed by (audience, namespace); selection rule "most specific scope, latest expiry"
    (planner default).
  - `mkit grant list` shows local grants with id, scope, expiry, epoch and status. It optionally checks status against `GetGrantEpoch`.
  - Update `docs/CLI.md`, the completions and the CLI skill doc.
- **PRD refs:** §8 M2 CLI.
- **Files:** `rust/crates/mkit-cli/src/commands/grant.rs` (new), `commands/mod.rs`, `cli.rs`, `config.rs` (user-only grant store path; SPEC-CONFIG-SECURITY classification), `completions/*`, `docs/CLI.md`.
- **Tests:**
  - `trycmd`/snapshot tests for create and list output
  - a round trip: the statement created verifies with the mkit-attest verifier
  - high-S import is normalized
  - a repo-scoped config cannot set the grant store (config-security test pattern, `config.rs:1603`)
- **Gates:** rust nextest, `cargo insta`/`trycmd`, `scripts/check-cli-baseline.sh` (server-free CLI), `just ci-docs`.
- **Size:** L, about 1300 lines.
- **Risks:** UX decisions (Q-M2-7, Q-M2-8). Keep flags minimal and pending review.

### WP-2.14 CLI: `mkit grant revoke` and `mkit epoch`

- **Depends on:** WP-2.13, WP-2.8.
- **Goal:**
  - `mkit epoch show <remote|namespace>` calls `GetGrantEpoch`.
  - `mkit epoch bump [--by n]` builds and signs `mkit-write-epoch:v1` with the same owner-signing modes as WP-2.13, bound to the remote's audience (or a list), then calls `SetGrantEpoch`.
  - `mkit grant revoke` is sugar for an epoch bump, and prints which local grants become invalid and a reissue hint.
- **PRD refs:** §6.4 revocation, §8 M2 CLI.
- **Files:** `rust/crates/mkit-cli/src/commands/{epoch.rs (new),grant.rs}`, docs and completions.
- **Tests:** e2e against the in-process native server:
  - bump, after which the old grant fails and a new grant works
  - an over-bound bump is rejected
- **Gates:** as WP-2.13.
- **Size:** M, about 700 lines.

### WP-2.15 Staging: enable M2 features and run M2 conformance

- **Depends on:** WP-2.7, WP-2.8, WP-2.9, WP-2.11, WP-2.12, WP-2.14 (M2 exit gate).
- **Goal:**
  - Staging config: grant schemes on, WebAuthn RP pinning config, a private test repo, and an epoch bound.
  - Extend the staging workflow with the M2 wire cases: grants for each scheme, revocation (the non-barrier variant; the barrier race runs on native and wrangler dev only) and private reads.
  - A private clone round trip with a read grant.
- **Files:** `apps/vcs-worker/wrangler.jsonc` (`env.staging` vars), `.github/workflows/server-staging.yml`, `scripts/staging-roundtrip.sh`.
- **HUMAN STEPS:** a GitHub secret for a test owner wallet key (secp256k1) if the eip191 case runs against staging;
  the staging URL-token key as a Wrangler secret (dedicated key, key id published); a redeploy.
- **Gates:** `actionlint`, the first green staging run (the orchestrator's local run of the extended suite against
  staging; the workflow change triggers only on `main`, `schedule` or dispatch against `main`, and first runs on the
  final PR to `main`).
- **Size:** S, about 300 lines.

---

## 3. DAG and parallel sets

Superseded by `00-plan.md` §3 (global DAG, waves and critical paths computed from `registry.json`), which includes
the D34 WPs 1.21–1.29 and the dropped 1.1/2.1. The planner's original DAG is not repeated here to avoid drift.

## 4. Interface assumptions on M0: reconciliation status

Every assumption was checked against the M0 briefs. "Provided" means the named M0 brief now delivers it (edits are
logged in `00-plan.md` as R-xx); "Moved" names the later WP that owns it.

| id | Assumption (short) | Status after consolidation |
|---|---|---|
| A1 | `RepoId`/`Namespace`; `Operation` carries procedure, repo, principal, commitment, grant/epoch slot; extensible | Provided: M0-01 (`#[non_exhaustive]` Procedure/OpKind/Commitment, `Operation.authz` with `GrantRef{id, epoch}`) — R-01, R-02 |
| A2 | `apply` precondition list incl. grant epoch and packs present | Provided in key-level form: M0-02a `Batch` preconditions (`Absent`/`Present`/`Equals` and the time-bounded `NotAfter`); planners (M0-05a) guard the epoch key and membership keys and set the commit deadline. D34: the epoch is the ref shard's leased epoch (WP-1.25). "Packs present / not GC-pending" is not an apply precondition: GC's mark → wait → re-check protocol covers it (WP-5.3a/b) — R-16, R-18, R-30, R-61, R-64 |
| A3 | Atomic replay + reservation + N-ref CAS + membership + outbox; versioned migrations | Provided: any set of key writes in one partition commits atomically (M0-02); new rows are new key layouts, no physical migration (M0-09). Row layouts: WP-1.7 — R-05, R-14, R-17 |
| A4 | Replay state model; lookup after signature verification; signed reads bypass | Provided: M0-02 `replay.rs` + M0-05 stage 0. D34: records live in the ref shard of the op's ref |
| A5 | `BlobStore` commit-after-verify; multipart session API? | Provided (single-shot, streaming, bounded memory): M0-02/08/11/16. Moved: `MultipartBlobStore` sub-trait → WP-1.11 (session id in the stateless ticket token) — R-08, R-25, R-28 |
| A6 | Admission input has creates_*, declared bytes, new_to_repo, idempotency key; default quota per (ns, signer) and per ns | Provided: M0-05 `AdmissionInput` (all fields, some unset in M0) — R-10. Moved: creates_* values → WP-1.22 (coordinator); per-namespace aggregate → WP-1.26 (exact per ref shard, approximate per namespace) |
| A7 | Clock/Spawner injected; native periodic task; DO alarm scheduling; SendFuture | Provided: M0-01 (Clock, Spawner, `send_wrap`), M0-10 (`TokioSpawner`). Moved: timers `(due_at, kind, ref)` and alarm multiplexing → WP-1.24 — R-26, R-36 |
| A8 | Vendored codegen in `mkit-server`, regen refreshes all copies | Provided: M0-06 |
| A9 | Test-fault hooks: authorize→apply barrier, clock override, fault after upload; reachable on native and `wrangler dev` | Provided as a seam: M0-05 `FaultHooks` + `TestDirectives` (`x-mkit-test-fault`, `x-mkit-test-clock-skew-ms`), M0-06 header plumbing, M0-16/17 store faults. Barrier implementation → WP-1.25/2.8 — R-11 |
| A10 | Storage suite per backend that can inspect rows; wire suite gated by features and milestone | Provided: M0-03 (key-level suite; rows inspected by scanning the key layouts), M0-07 (`Milestone`/`Feature` gating, `--milestone`) — R-09, R-12, R-22 |
| A11 | ssh/enc via blocking executor with FS blobs and a SQLite NamespaceStore | **Corrected:** the ssh path uses `FsLayoutStore` (refs as files), never SQLite, so the CLI stays server-free (adopted Q3/Q4). Multi-repo dirs → WP-1.15; grant/epoch files → WP-2.12 — R-13 |
| A12 | `Principal` enum {auth-v2, ssh key, enc peer, bearer, anonymous} | Provided: M0-01 (`SshForcedCommand{key: Option<..>}`, `#[non_exhaustive]`); `--principal` → WP-1.15 — R-01 |
| A13 | Worker starts M1 with one "root" instance and a migration tag M1 can follow | Provided: M0-16/17 keep `RefStore`/`REFSTORE`/"root", tag `v1`, and reserve D34 naming. WP-1.8 adds one DO class per shard kind (tag `v2`) — R-29 |
| A14 | Centralized error mapping | Provided: M0-01 `ServerError` (+ HTTP status, headers, typed details) and M0-06's single Connect table — R-03 |
| A15 | Binary subcommand structure for `grant register`; worker config read in one place | Provided: M0-10 (clap subcommand enum), M0-17 (`WorkerConfig::from_env`) |
| A16 | Outbox table exists or M1 adds it; `OutcomeSink` trait exists | `OutcomeSink` provided (M0-05). Outbox rows, pending index and backlog counter → WP-1.7 (layouts reserved in M0-02) — R-17, R-35 |
| A17 | wasm dep-graph covers vcs-worker and mkit-server-worker | Provided: M0-16, M0-17 |
| A18 | single-repo `AUTH_REPOSITORY` mode keeps working | Provided: M0-17 |
| A19 | `write_auth::verify_headers` is the single auth-v2 verifier | Provided: M0-04 |

---

## 5. Open questions: resolution

All planner questions are resolved by the adopted defaults (see `00-plan.md` → Defaults adopted) or by D34:

| Question | Resolution |
|---|---|
| Q-M1-1 | #1090 wire is in S1 §7.6 (Q18); WP-1.1 dropped |
| Q-M1-2 | Client-streaming `UploadPart` (review 01, R-69; was unary), explicit `CompleteUpload`; resume via client-held signed part receipts (not `BeginUpload` returning received parts), because part requests must never reach a DO (coordinator DO constraints) — R-28 |
| Q-M1-3 | Single-part packs use `UploadPack` with the ticket token and the `pack:` commitment (planner default) |
| Q-M1-4 | Part size 8 MiB advertised, 32 MiB max (planner default); `BeginUpload` threshold 0 on multi-repo deployments (planner default; every multi-repo upload is ticketed so membership is always recorded in a ref shard), unchanged for single-repo |
| Q-M1-5 | Defaulted `Transport::advance_refs_committing` (adopted) |
| Q-M1-6 | Built-in no-op sink acks and deletes rows until M3 (planner default; bounded growth) |
| Q-M1-7 | Implicit per-session tickets on ssh/enc (adopted); no threshold |
| Q-M1-8 | Human decision: staging hostname/zone/account and data policy (00-plan.md human checklist) |
| Q-M1-9 | Confirmed: no ContentIndex holders before M4 |
| Q-M1-10 | Yes, auto-enable atomic advance from `GetServerInfo` |
| Q-M1-11 | Accept the break with a clear error (pre-production policy) |
| Q-M2-1 | S2 covers #1089 (Q19); WP-2.1 dropped |
| Q-M2-2 | Owner-signed `SetRepoVisibility` RPC (adopted) |
| Q-M2-3 | `not_found` (adopted) |
| Q-M2-4 | Dedicated deployment URL-token key; TTL 15 min (adopted) |
| Q-M2-5 | Token binds the unresolved target; M4 decides serving (planner default) |
| Q-M2-6 | `mkit-server grant register` operator command (adopted); admin API in M5 |
| Q-M2-7 | Under the user config dir (adopted); "most specific scope, latest expiry" (planner default) |
| Q-M2-8 | ed25519 + keystore secp256k1 native; wallet eip191 and WebAuthn by import (planner default) |
| Q-M2-9 | Keep `delete`; it governs ref deletion in `UpdateRef`/`AdvanceRefs` (adopted; S1 §7.8) |
| Q-M2-10 | Epoch statement max lifetime 30 days (adopted); `MAX_EPOCH_STEP` 1024 (planner default) |
| Q-M2-11 | Single trusted signing remote; multiple is out of scope (planner default) |
| Q-M2-12 | `GetServerInfo` stays unsigned |
| Q-M2-13 | Fail closed: reject webauthn grants when no RP is pinned (planner default) |
| Q-M2-14 | Excluded from this epic |

---

## 6. Human-action checklist

Consolidated in `00-plan.md` → Human-action checklist (includes the M1 staging steps, backups bucket/prefix, DO
placement choice, the ticket/receipt key and the M2 URL-token key secrets).
