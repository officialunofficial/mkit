# Production mkit server (Linear MKIT-29): PRD snapshot

> Snapshot of Linear MKIT-29 taken 2026-09-25. Linear is canonical; decisions D1–D36 are settled (D21 superseded by D34; D35 staging; D36 `X-Mkit-Ref`).

**Status:** Approved by peer review. Three adversarial reviews applied: two of the PRD and one of the implementation plan. Decisions D1–D36. The implementation plan is tracked as sub-issues of this epic.
**Type:** Epic
**Supersedes:** draft spec PR [mkit#1087](https://github.com/officialunofficial/mkit/pull/1087). It will be split into three stacked PRs built on its text; the original author is credited.
**Tracks:** [mkit#1084](https://github.com/officialunofficial/mkit/issues/1084), [mkit#1085](https://github.com/officialunofficial/mkit/issues/1085), [mkit#1086](https://github.com/officialunofficial/mkit/issues/1086), [mkit#1088](https://github.com/officialunofficial/mkit/issues/1088), [mkit#1089](https://github.com/officialunofficial/mkit/issues/1089), [mkit#1090](https://github.com/officialunofficial/mkit/issues/1090), [mkit#1091](https://github.com/officialunofficial/mkit/issues/1091), [mkit#1092](https://github.com/officialunofficial/mkit/issues/1092)

---

## 1. Summary

mkit has a server, but it isn't a production server. Today there are three server implementations that share no code, and none of them is deployed for the CLI protocol:

- `mkit serve`: ssh stdio, enc TCP, and a feature-gated `--http` Connect listener that isn't in release binaries.
- the Connect `TransportServer` in `mkit-transport-connect`.
- `apps/vcs-worker`: a Cloudflare Worker reference server that has never been deployed.

All three are "dumb" single-repo pack+ref stores. They never look inside packs, have no access control, and offer no extension points.

This epic makes the mkit server production-ready, and makes it a **framework** that other products can embed and extend with their own business logic. The motivating example is a storage business that charges for storage through the Machine Payments Protocol (MPP) or x402 over HTTP 402, running on Cloudflare Workers.

The framework stays **payment-neutral**. mkit defines the mechanism; the business defines the policy. It builds on what makes mkit different from git: signed history, verifiable Merkle objects, attestations and disclosure proofs. That makes the server a *verifiable* store, not a git-shaped bucket.

## 2. Goals

1. One server core that doesn't depend on a runtime. It serves both native deployments (tokio/axum, container) and Cloudflare Workers (wasm32) from the same pipeline, and one conformance suite checks both.
2. Many repositories per deployment, owned through self-certifying namespaces, with delegated write and read grants.
3. A generic, fail-closed extension surface: authorization, admission (payment or quota), outcomes and metering, content inspection, and lease policy. Implementers can plug in either in-process Rust code or a remote service in any language.
4. First-class support for HTTP 402 payment protocols (MPP, x402), without mkit taking on any payment logic.
5. Server capabilities that only mkit can offer:
   - verify pushed history before refs move
   - serve files over HTTP with proofs against signed commits
   - issue signed storage receipts
   - take content down with signed redaction notices
6. Production basics: streaming, limits, timeouts, retention and GC, takedown with evidence preservation, observability, CORS, backup and migrations, and private repos.

## 3. Non-goals

- Anything specific to one business: pricing, currency, balances or ledgers, accounts and claiming, a specific CSAM vendor, app-store policy, on-chain authority mappings. These belong to implementers. Uno is a reference example of an implementer, but it is out of scope here.
- A hosted-forge feature set: web UI, issues, PRs, CI, org management.
- Namespaces resolved by a registry at the deployment. Namespaces are self-certifying only (D4).
- A Postgres metadata backend. The trait leaves room for one (D2).
- A transparency log for receipts. Deferred (D22).
- Skipping uploads for public content. Deferred (D15).
- A client mode that tolerates redacted objects (clone with holes). Deferred (D17).
- HTTP listings, archive downloads, and sparse checkout. Deferred (D20).
- Attestation transport (SPEC-ATTESTATIONS §7.3) and refs gated on attestations. Deferred to a follow-up epic (D33); the generic `pre_receive` hook remains.

## 4. Current state (verified)

**`Transport` trait** (`mkit-core/src/protocol.rs:394`)
- It is synchronous, `Send + Sync`, and shaped for clients. `advance_refs` defaults to two non-atomic writes (`:581`).
- It can't back an async, `!Send` Workers server.

**Native Connect server** (`mkit-transport-connect/src/service.rs`)
- It wraps a sync `Transport` in `spawn_blocking`, and `drain_upload` buffers the whole pack in memory (limit 4 GiB).
- `serve --http` accepts a single shared bearer token or `--unsafe-allow-any-http-peer`. There is no auth-v2, no replay protection and no quota.

**`mkit serve` over ssh/enc**
- It is hard-wired to `FileTransport` and has its own upload drain.
- The stdio mode has no read timeout; SSH-SECURITY §4 and §7 list this as "NOT mitigated".
- The `mkit-cli` default build already pulls in tokio, hyper and reqwest through its `mkit+https://` client (`connectrpc`, `reqwest`). It contains no HTTP-server code (no axum and no server stack).

**Release binaries**
- `mkit-cli` has `default = []`, and `release.yml` builds without `--features`. So `serve --http` and `--listen-enc` don't ship.

**vcs-worker**
- Packs live in R2, and one global Durable Object holds all refs.
- It verifies auth-v2 signed headers, keeps a replay ledger, and enforces a per-key hourly quota. Replay, quota and ref compare-and-swap commit in one Durable Object SQLite transaction (`refstore.rs:360`).
- Writes are open to any valid key (no allowlist). It buffers whole packs and has no GC.
- `wrangler.jsonc` has no route, and `AUTH_AUDIENCE` is still `http://localhost:8787`.

**Duplicated logic**
- Upload validation, download chunking, ref compare-and-swap and ref-name validation exist in 3 copies each.
- Quota math and the envelope wrapper exist in 2 copies each.

**Shared across runtimes**
- `mkit-core` (without default features), `connectrpc` 0.9 (Router and Interceptor, on both runtimes), and `mkit_core::write_auth::verify_headers` all compile for wasm32.

**Crypto**
- `mkit-attest` has k256, p256 and WebAuthn verification. `verify_p256` rejects high-S signatures.
- There is no Keccak-256 and no secp256k1 public-key recovery. `mkit-core` depends only on Ed25519.

**Packs**
- SPEC-PACKFILE v2 compresses each entry with zstd. A delta base may resolve from "the destination object store" (§3.2).
- The wasm build has no zstd decoder.
- Every push also writes `refs/mkit/packmap/<branch>`, a chain of pack lists maintained by the client (`remote_dispatch/mod.rs:462`).

**Client**
- It treats `resource_exhausted` as a retryable 429, and `upload_pack` runs inside the retry loop.
- A raw HTTP 402 surfaces as `unknown`, and its headers are dropped.
- It sends `Authorization: Bearer` only when a token is configured (`client.rs:276`).
- The envelope headers are `x-public-key`, `x-signature`, `x-digest`, `x-created-at`, `x-expires-at`, `x-envelope-version`, `x-audience`, `x-repository`, `x-content-commitment`, and `idempotency-key` (the nonce).
- auth-v2 is Ed25519-only (`write_auth.rs:205-222`). The only commitment kinds are `body:` and `pack:` (`write_auth.rs:35`). The replay scope is `hash(audience, repo, public_key, nonce)` (`write_auth.rs:486`). Today's ledger looks it up **after** signature verification, and it checks the fingerprint (`mkit-worker-common/src/replay.rs:138`).
- Reads are never signed (`envelope.rs:74-85`). The client reads the head and the packmap refs separately, and a missing packmap is a hard error (`remote_dispatch/mod.rs:1477`). It compare-and-swaps the packmap against that unsigned read (`packmap.rs:468`). Push deltas are always based on objects already on the remote (`mod.rs:846`).

**Policy**
- CONTRIBUTING's "Pre-production compatibility policy" means no compatibility machinery for APIs that haven't shipped.
- `buf.yaml` runs `breaking: FILE` on every proto module, and `mkit.rpc.v1.ssh` is wire-frozen.
- `scripts/check-wasm-dep-graph.sh` covers `mkit-wasm` and `repo-worker` only.

## 5. Architecture

### 5.1 Crates

| Crate | Role |
|---|---|
| `mkit-server` | The core, which doesn't depend on a runtime. It holds the typed `Operation` model, `RepoId`/`Namespace`, the storage and policy traits, the request pipeline, streaming upload validation, CAS and quota logic, and the mapping from errors to Connect codes. Features: `connect` (on by default; the generated `TransportService` binding), `indexed`, `http-objects`, `receipts`. |
| `mkit-server-native` | An axum/tokio router builder, tower layers (timeout, concurrency limit, tracing, body limit, CORS) and graceful shutdown. Backends: FS blobs (keeping the `.mkit` on-disk layout), S3 blobs (reusing the SigV4 code from `mkit-transport-s3`), and SQLite metadata with versioned schema migrations. It builds the **`mkit-server` binary** (D31): a signed release artifact next to `mkit`, plus a container image. It hosts the long-running HTTP and enc listeners. The CLI's `mkit serve` stays only as the ssh forced-command entry point, and it drops `--http` and `--listen-enc` (the pre-production policy allows removing them). The ssh/enc stdio loops call the same pipeline through a blocking executor, so the `mkit` CLI stays **server-free**: no axum, SQLite or `mkit-server-native` in its default dependency graph, enforced by a script. An implementer can mount the router inside their own axum app. |
| `mkit-server-worker` | A workers-rs adapter: an R2 `BlobStore`, Durable Objects for each shard kind (D34): a namespace coordinator, **one per `(repo, ref)` ref shard**, and repo index shards. They implement `NamespaceStore`, plus `ContentIndex` shards, the bridge between Workers `fetch` and `http` types, and the remote-hook adapter over service bindings. It **depends on** `mkit-worker-common` rather than absorbing it, so the demo workers are unaffected. `vcs-worker` becomes a thin reference deployment. |
| `mkit-server-conformance` | (a) A storage-trait suite that any backend runs against. (b) A black-box wire suite: give it a base URL and a signer, and it covers CAS, atomic advance, replay, upload rejections, multi-repo isolation, rejection of foreign delta bases, grants and revocation races, admission and retries, the published view, leases and GC, takedown and receipts. It runs in native CI, against `wrangler dev` and staging, and against third-party implementations. |

The wasm dependency-graph check extends to `vcs-worker` and `mkit-server-worker`. `connectrpc`'s `zstd` feature stays off on wasm.

### 5.2 Async and runtime model

- Traits use native `async fn` (return-position `impl Future`) with a `MaybeSend` marker: it means `Send` on native and is a blanket impl on wasm. Hook lists that need `dyn` use a boxed-future alias with the same conditional `Send`.
- The Workers adapter wraps the whole handler future in `SendFuture` once.
- `Clock` and `Spawner` are injected; nothing calls `worker::Date` directly. No `no_std`.

### 5.3 Storage traits

**`BlobStore`**: content-addressed and immutable.
- `begin(key, len) -> PackSink` (write, commit, abort), `get(key, range)`, `head(key)`.
- A commit is visible only after the BLAKE3 check passes: on R2 the multipart upload completes only after verification; natively it's temp file, fsync, rename.
- Writes are put-if-absent, or overwrites with identical bytes.

**Metadata sharding (D34).** Metadata is split into shards so writes scale **within a repo**. The core computes a **shard key** for every operation, and each backend maps shards to anything it likes: Durable Objects, SQLite tables, or an implementer's qmdb instances. The trait is still called `NamespaceStore`, but it is partitioned by shard key and has three kinds of shard:

- **Namespace coordinator** (one per namespace). It holds namespace config (`namespace_policy`, visibility, lease defaults), the **grant epoch**, and a table of **currently leased shards**, which is bounded by *active* shards, not by all refs. It's rarely written.
- **Ref shard** (one per `(repo, ref)`). It is **strongly consistent** and carries every write on that ref:
  - the ref's head, and for branches its packmap pointer
  - the **published pointer**, i.e. the (head, packmap) pair from one `AdvanceRefs` (D28)
  - the **tickets and reservations** for uploads that target the ref
  - the **replay records** and **outbox** rows for operations on the ref
  - the **cached epoch**
  - per-ref leases and lifecycle state, and per-shard quota counters
  - `AdvanceRefs` stays atomic because a branch's head and packmap live in the same shard.
- **Repo index shards** (per repo, a **large fixed fan-out** by object-id prefix, e.g. 4,096 and advertised in `GetServerInfo`, plus a ref-name index **hash-sharded with a fixed fan-out**; `ListRefs` k-way merges across those shards behind an opaque cursor). A shard exists only once written, so idle shards cost nothing, and resharding is never needed: about 200–400 billion indexed objects fit per repo at 10 GB per shard. They hold pack/object **membership**, the ref-name index that `ListRefs` reads, quarantine state and tombstone views. The ref shards' outboxes update them **at least once**, so they are **eventually consistent**:
  - A lagging membership read only ever causes a harmless re-upload (a missing `AlreadyPresent`), or a retryable `unavailable` with "base not yet visible" during verification.
  - `ListRefs` may lag by seconds. `ReadRef` on a specific ref always reads its ref shard and is strongly consistent; push compare-and-swap uses `ReadRef`.

- One atomic `apply(shard, Mutation)` commits everything below within **one ref shard**. Its **preconditions** are: the shard's cached epoch equals the one the request was authorized under, the ref-shard state the request was planned on is unchanged, and the batch's **commit deadline** has not passed (a time-bounded `NotAfter(deadline)` precondition that the storage backend evaluates against its own clock at commit). Packs that GC may be collecting live in other shards, so GC safety comes from the deadline plus GC's mark → wait → re-check protocol (§6.7), not from a cross-shard precondition.
  - the replay record
  - the reservation or charge
  - the compare-and-swap on the ref's head and packmap
  - the ref's membership additions, recorded locally and propagated through the outbox
  - the outbox row
- `list_refs` is paginated from the ref index. `has_pack(repo, key)` reads membership, which is eventually consistent and safe as described above.
- **Epoch revocation uses epoch leases.**
  - A ref shard may use its cached epoch only while it holds a short **lease** from the coordinator (default 30 s). It renews the lease, which returns the current epoch, on the next write after expiry.
  - The coordinator raises the epoch and reports success **only after every currently leased shard acknowledges or its lease expires**.
  - An idle shard can never apply under a stale epoch.
  - Every write batch carries `NotAfter(deadline)` with deadline = min(lease_expires − margin, plan_time + `MAX_APPLY_WINDOW`), evaluated by the storage backend on its own clock at commit. A batch planned under a valid lease that reaches the shard late (queueing, CPU stall, restart) after the lease expired commits nothing, even if the revocation push to that shard failed. The margin exceeds the worst clock skew between the coordinator and any shard's backend.
  - Revocation is exact once reported, completes within one lease interval, and costs O(active shards).
- **Bounded growth, required of every backend:**
  - replay records pruned after the envelope window
  - tickets deleted at expiry
  - outbox rows deleted on acknowledgment
  - quota windows pruned
  - every shard reports its storage size, and the deployment alerts at 70% and 90% of the backend's per-shard cap (10 GB on Durable Objects). At the cap, Cloudflare documents that writes fail with `SQLITE_FULL` while reads and `DELETE` keep working ([Durable Objects limits](https://developers.cloudflare.com/durable-objects/platform/limits/)). mkit maps a full shard to a fail-closed error (retryable `unavailable`, "storage partition full", never `resource_exhausted`) plus a critical alert, and pruning keeps running because deletes still succeed.
  - **outbox backpressure:** above a configured backlog (bytes or rows), a ref shard rejects new admitted writes with retryable `unavailable` and raises an alert. It fails closed rather than growing without limit while a hook consumer is down.
  - a **cap on open tickets** per (ref, signer) and per ref, enforced at admission
  - `ContentIndex` **holder rows sub-sharded** by `(object, hash(holder))`, with a holder count kept on the object, so one very widely held object can't fill a shard
- A backup and restore procedure and versioned schema migrations are required for every backend.

**`ContentIndex`**: global, sharded by object id. It holds whatever spans namespaces:
- the **blocklist**
- the **holders** of each object, as (namespace, repo) pairs
- **GC holds**

`BlobStore` dedup records a hold **before** the ref-shard `apply`. GC deletes an object only when it has zero holders and zero holds after the grace period. A takedown finds every holding repo here. On Workers it is a set of Durable Objects sharded by id prefix; natively it is a SQLite table.

**Size budget on Workers.** A Durable Object is capped at 10 GB of SQLite (about 50–100M index rows). Repo index shards are split by object-id prefix (D34), so no single object has to hold a whole repo's index.

**Custom backends** must provide (a) strong consistency and an atomic multi-row write per shard, with at-least-once outbox delivery between shards, (b) an immutable, content-addressed blob store with Range reads, and (c) a `ContentIndex` with atomic per-object updates. The conformance suite is the gate. Running several native replicas needs a shared `NamespaceStore`, e.g. a future Postgres backend.

`Transport` stays client-only, and `FileTransport` leaves the serve path.

### 5.4 Pipeline and extension points (in order)

0. **Authenticate, then look up replay.**
   - First verify the auth-v2 signature and validity window. This writes no state.
   - Then look up (audience, repo, signer, nonce):
     - A stored fingerprint that differs is rejected with `invalid_argument`.
     - A `committed` operation returns its stored result.
     - An `in_flight` operation returns a retryable `aborted` without reaching admission.
   - Only new operations continue. So a retry never presents a spent payment credential again, and one signer's result is never served to another.
   - **Signed reads** skip the replay ledger: they are idempotent and checked only against the validity window.

1. **Identity mapping.**
   - auth-v2 signer, or the ssh key (forced-command argument), or the enc peer key, or an optional bearer token.
   - Each maps to a principal.

2. **Authorizer.**
   - `namespace_policy`: an `allowlist` of owner namespaces (the **default** for stock multi-repo deployments), or `any` (an explicit opt-in, expected to be paired with Admission) (D27).
   - `write_policy`:
     - `open`: single-repo deployments only.
     - `owner`: the owner key, a valid grant, or an external authority source that fails closed.
   - Runs before any quota or replay record is allocated.

3. **Admission.**
   - `admit(op) -> Allow{reservation} | Challenge{[{scheme, value}], description} | Deny`.
   - The `op` passed in carries:
     - audience, repo, procedure, and the verified signer (or anonymous)
     - namespace owner and the grant used
     - `creates_namespace` and `creates_repo`
     - pack_id and declared bytes
     - new-to-repo bytes (known only from membership)
     - the idempotency key
   - **New-to-store bytes are deliberately not included**, because they would reveal whether content exists elsewhere through pricing. They are reported only in `Committed`.
   - The built-in default is an abuse quota per (namespace, signer) and per namespace, counting hourly operations and bytes. It is **exact per ref shard** and **approximate at namespace level** (per-shard counters are reconciled into a namespace total). It can be swapped out.
   - `namespace_policy = any` requires a non-default Admission. Without one, the server refuses to start unless `--unsafe-open-namespaces` is given, because new keys mean new namespaces, which reset the default quota.
   - Applies to writes, and optionally to reads. On the transport, admission only applies to unary RPCs; paid bulk downloads use HTTP serving (§6.6), where a 402 is an ordinary HTTP response.
   - Quota scopes that span namespaces (per payer, per signer across namespaces) can't be atomic on a store sharded by namespace. They are best-effort, reserve-and-reconcile in the implementer's Admission, or kept in the implementer's own store.

4. **Replay reservation** (`in_flight`), then the streamed body. `pending_verification` and challenges are **never** stored as replay results.

5. **`pre_receive`.**
   - Indexed-mode verification.
   - Policy hooks: allowed signers per ref, plus any implementer policy. (Attestation-gated refs are deferred; see D33.)
   - Synchronous `ContentInspector` checks.

6. **Atomic `apply`** with the preconditions above, including the outbox row.

7. **`ReceiptSigner`.**

8. **`OutcomeSink`.**
   - Exactly one `Committed{bytes_stored, new_to_repo, new_to_store, refs}`, `Aborted{reason}` or `Expired` per reservation.
   - Delivered at least once, from the outbox, keyed by reservation id.
   - Implementers settle payment on `Committed` and release on `Aborted`/`Expired`. If settlement fails after a commit, that's the implementer's policy (e.g. suspending via lease).
   - Metering is built on it.

9. **Asynchronous `ContentInspector`** (quarantine) and **lease-policy** events.

**Lifecycle per RPC (normative).** Every RPC carries its own nonce.

| RPC | Admission | What its `apply` writes |
|---|---|---|
| `BeginUpload` (unary, names its target ref) | Yes | In the **target ref shard**: the replay record, a **reservation** row, and the **ticket** |
| `UploadPack` / parts | No | Parts only. The ticket's audience, repo and signer, and its (pack_id, bytes), must equal this request's signer and `pack:` commitment; otherwise `permission_denied` |
| `AdvanceRefs` | No (uses the tickets) | In the **same ref shard**: the head and packmap, the ref's membership additions (propagated to repo index shards by the outbox), and one `Committed` outbox row per ticket it consumes. The tickets are local, so there is no cross-shard handoff |

- **A pack becomes a member of the repo only at the `AdvanceRefs` apply.** Until then, `BeginUpload` for the same pack by the same signer returns the existing ticket, never `AlreadyPresent`.
- If an `apply` fails after `Allow{reservation}` (lost compare-and-swap, epoch mismatch, pack GC'd, replay race), an `Aborted` outbox row is written in a **separate** transaction. So every reservation gets exactly one outcome.
- A ticket that expires without an advance produces `Expired`.

**Remote hooks (`mkit.server.hooks.v1`).**
- A documented Connect/JSON contract for `authorize`, `admit`, `inspect` and `outcome`. mkit ships an adapter that implements the Rust traits by calling it: over HTTP natively, over a service binding on Workers, with outcomes optionally sent to Cloudflare Queues or a webhook.
- **Channel authentication:** requests are signed with a deployment hook key (or rely on the service binding's isolation). Outcome webhooks are signed.
- **Failure behavior per hook:**
  - `authorize` and `admit` fail closed: the operation is denied.
  - `outcome` retries with backoff and is never dropped (it stays in the outbox until acknowledged).
  - `inspect` follows each inspector's fail-closed or publish setting (D18).
- This lets implementers write hooks in TypeScript (e.g. `mppx`, the MPP SDK documented for Workers).

## 6. Protocol and spec changes

`mkit.transport.v1` evolves **additively** (D24): new RPCs and fields only, and `buf breaking` stays green. The semantic breaks ship as **SPEC-TRANSPORT-CONNECT v2**, with no compatibility machinery.

### 6.1 Addressing ([mkit#1084](https://github.com/officialunofficial/mkit/issues/1084))

- A repo id is `namespace/name`. A bare `name` is valid only on single-repository deployments, where a missing `X-Repository` resolves to the configured repo.
- `X-Repository` goes on every RPC. On writes it is the signed `<repository>` field.
- Refs, pack membership and replay records are isolated per repo. **The scope of quota and admission is set by the deployment** (D12).
- A repo is created by its first authorized write. There is no create RPC.
- Stock multi-repo deployments default to `namespace_policy = allowlist` and MUST NOT run `write_policy = open`.
- **`GetServerInfo`** returns:
  - the protocol and spec version, and limits
  - the `BeginUpload` threshold (0 when admission is enabled)
  - whether atomic advance and indexed mode are supported
  - admission support and the receipt public key with key id
  - the supported grant schemes and the namespace policy

### 6.2 Uploads ([mkit#1090](https://github.com/officialunofficial/mkit/issues/1090), and admission for [mkit#1086](https://github.com/officialunofficial/mkit/issues/1086))

**`BeginUpload(repository, ref, pack_id, bytes)`** (unary) names the ref the upload will advance, so the ticket lives in that ref shard (D34). It returns either:
- `AlreadyPresent`: the pack is already a member of *this* repo.
- `Ticket{id, part_size, expires}`: a reservation plus an upload session.

Admission is signalled only by the 402 in §6.3; there is no `AdmissionRequired` result message.

**Rules:**
- **`BeginUpload` is mandatory whenever admission is enabled** (threshold 0), because a 402 can't be carried on a streaming RPC. Otherwise, packs under the advertised threshold may skip it.
- `UploadPack` and its parts reference the ticket. **Packlist nodes (`MKPL`) need tickets too.** Indexed mode classifies uploads by magic, and requires that every pack a node lists is a member of the repo, or is ticketed within the same advance.
- **Retries:** the client reuses the nonce and timestamps while the envelope is still valid (`MAX_VALIDITY_MS` = 300 s). After that it signs a new operation.
- **Read-your-writes for packs (D36):** `PackExists` and `DownloadPack` MAY carry an optional `X-Mkit-Ref: <refname>` header naming a ref of the same repo whose packmap listed the pack. The server then also resolves membership against that ref's strongly consistent shard, so a pusher sees its own advance immediately despite index lag. It is always subject to the caller's view: non-writers get the published view, and quarantined packs stay hidden (§6.7). It never reveals another repo's packs.
- Resumable parts:
  - Parts are a uniform power of two, at least 8 MiB (R2 multipart requires at least 5 MiB and uniform part sizes).
  - `UploadPart` is **client-streaming** (a header message naming the ticket and part index, then data chunks), so no part is ever buffered whole; parts need no 402 because admission happened at `BeginUpload`.
  - Each part is hashed as a BLAKE3 subtree, and the subtrees are merged at completion. Parts need a **new commitment kind** (for example `part:<ticket>:<index>:<subtree-hash>:<len>`), which the M1 spec PR names and adds to `write_auth`.
  - Tickets expire in under 7 days, before R2's automatic abort.
- A request answered with a challenge MUST NOT change state: no repo is created, no quota is reserved, and the replay nonce is not consumed.
- There are no existence oracles across repos. An upload is always required when the repo lacks the pack (D15).
- **`AdvanceRefs` carries the ticket/reservation id(s)** it commits.
  - In indexed mode, a pack still under verification yields `unavailable` with a `PendingVerification{retry_after}` detail. The client polls until the ticket expires rather than following its normal retry ladder of about 15 s (`protocol.rs:209-212`), and re-signs once the 300 s envelope lapses.
  - A reservation that is never advanced before the ticket expires yields an `Expired` outcome, and its pack becomes GC-eligible.

### 6.3 Admission challenges ([mkit#1086](https://github.com/officialunofficial/mkit/issues/1086))

**Server side**
- The server returns **HTTP 402** with a Connect error body and an `AdmissionChallenge` detail: a list of opaque `{scheme, value}` entries.
  - The body code is `permission_denied`, so older clients fail fast instead of retrying.
  - This applies to unary RPCs only (see §6.2).
- The raw payment headers pass through: `WWW-Authenticate: Payment …` (MPP) and/or `PAYMENT-REQUIRED` (x402).
- Cache rules:
  - A 402 carries `Cache-Control: no-store`.
  - A response carrying `Payment-Receipt` (MPP) or `PAYMENT-RESPONSE` (x402) passes it back with `Cache-Control: private`.
- Order: for authenticated operations, authenticate before challenging (per MPP). An anonymous operation, e.g. a paid public download, may be challenged directly.
- CORS: the challenge and receipt headers are exposed (`WWW-Authenticate`, `Payment-Receipt`, `PAYMENT-REQUIRED`, `PAYMENT-RESPONSE`), and preflight requests don't require payment.

**Client side**
- It builds `AdmissionRequired` from either the detail **or** a raw 402 plus its headers. It never parses a problem+json body and never retries automatically.
- **`admission_helper`** (user-scoped config, run only for trusted remotes) receives the challenge list and returns the `{header: value}` pairs to attach. For MPP that's `Authorization: Payment …` by default, or `Payment-Authorization: Payment …` when the challenge sets `header="Payment-Authorization"`. For x402 it's `PAYMENT-SIGNATURE`.
- The client attaches them on one retry, **only if they are on an allowlist** (D30):
  - Default allowlist: `Payment-Authorization`, `PAYMENT-SIGNATURE`, and `Authorization` (only when the remote doesn't already use it).
  - It can be extended per remote in user-scoped config.
  - A **hard-reserved** set can never be allowed, even by config: every mkit envelope header (`x-public-key`, `x-signature`, `x-digest`, `x-created-at`, `x-expires-at`, `x-envelope-version`, `x-audience`, `x-repository`, `x-content-commitment`, and future `x-*` headers mkit signs such as a grant header), `Host`, `Content-*`, `Transfer-Encoding`, `Connect-*`, `Cookie`, `X-Forwarded-*`, `Idempotency-Key`, and hop-by-hop headers.
- mkit registers no schemes and interprets none.
- When a helper returns a header that isn't on the allowlist, the error **names that header**.
- A deployment that uses bearer auth MUST advertise `header="Payment-Authorization"` in its MPP challenges.

**Responsibilities**
- Binding a challenge (HMAC over the MPP parameters, `opaque`, and `digest` over the unary `BeginUpload` body) is the business layer's job. mkit supplies the fingerprint: repo, signer, pack_id, bytes.
- Payment credentials and receipts are **redacted** from all logs and traces.

### 6.4 Write and read grants ([mkit#1085](https://github.com/officialunofficial/mkit/issues/1085), [mkit#1089](https://github.com/officialunofficial/mkit/issues/1089))

**Namespaces**
- Self-certifying only: `0x<address>` (secp256k1-eip191, or webauthn-p256 via `keccak256(x‖y)[12..]`) and `ed25519-<key>`.

**`mkit-write-grant:v1`**
- The owner authorizes one Ed25519 key for one repo or the whole namespace, for at most 30 days.
- **Audience:** an explicit list of server origins, with no wildcard (D5).
- **Ref scopes:** patterns plus `create`/`update`/`force`/`delete` flags (D6).
  - `update` without `force` means fast-forward only. That needs indexed mode, and an opaque server rejects such a grant.
  - A scope on `refs/heads/<x>` covers its `refs/mkit/packmap/<x>`. **Packmap writes are allowed only together with the covered head, in one `AdvanceRefs`**, and the scope flags are evaluated on the head only; re-baselining writes a packmap that isn't an append (`packmap.rs:403-423`). Direct writes to packmap refs are denied.
- **Capabilities:** `write` and `read` (D19).

**Revocation**
- Each namespace has an epoch. A grant is valid only while its epoch **equals** the stored epoch, and that is checked as a precondition **inside** the atomic `apply`.
- `mkit-write-epoch:v1` raises the epoch by a bounded increment. It is bound to the same audience list as the grants it revokes, and it has an expiry.
- `GetGrantEpoch` reads it.
- It is atomic with writes through **epoch leases** (D34): the coordinator reports a revocation only after every leased shard holds the new epoch or its lease has expired, and each shard checks its leased epoch inside `apply`.

**Other rules**
- Private repos have `public`/`private` visibility, signed reads (auth-v2), and a `read` grant capability. **A client that has a signer signs every read to its own remote**; writers need this to see the real, unpublished refs (D28).
- Signed URL tokens come from a unary `IssueObjectUrl(repository, object_id | ref+path, ttl)` RPC.
- P-256 signatures are normalized to low-S on the client, and the spec says so.
- The grant verifier lives in `mkit-attest` (adding Keccak-256 and secp256k1 recovery), not `mkit-core`.
- The error codes in the spec and the implementation are aligned (`unauthenticated` vs `permission_denied`).
- **ssh and enc:** the frozen ssh proto can't carry grants, so grants for ssh principals are registered server-side (through the admin API or an RPC) and looked up by the transport identity.

### 6.5 Indexed mode (D3, D14)

- It is opt-in per deployment.
- The server decodes pushed packs, with a decode-only `ruzstd` feature in `mkit-core` for wasm, and keeps a per-repo object index.
- **Before refs move**, the server:
  - re-hashes objects
  - verifies commit and tag signatures (`sign::verify_commit`)
  - checks closure (connectivity)
- **Isolating lookups:**
  - Delta bases, `AlreadyPresent`, and every object lookup during verification resolve **only against the pushing repo's membership**. The global content store is never consulted for resolution.
  - This closes cross-repo reads through thin deltas, and existence oracles from accepting or rejecting a push.
  - A conformance test covers it.
- **Hybrid storage:**
  - Pushed packs are kept for fetch and clone.
  - **Extraction (D32):** every plain blob of **64 KiB or more** (configurable) is extracted, and every chunked file (`ChunkedBlob`, i.e. files over `CHUNK_THRESHOLD` = 1 MiB, stored as FastCDC chunks of 16–256 KiB) is **reassembled once at ingest into one object keyed by its manifest id**. Both go into a **global content-addressed store** with per-repo membership.
  - Serving is then a direct blob-store read with native Range support. Dedup is by whole file; chunks stay inside packs for clone.
  - Small objects are reached through the index.
  - A later pack rewrite during GC may remove the duplication. That's a server-internal optimization.
- On Workers, verification runs between upload and ref advance (Durable Object alarm or Queue), not inline. `AdvanceRefs` commits only packs that have been verified; see `pending_verification` in §6.2.

### 6.6 HTTP serving ([mkit#1088](https://github.com/officialunofficial/mkit/issues/1088))

**Endpoints**
- `GET /<ns>/<repo>/-/objects/<id>`: immutable, Range-capable, `ETag` = id.
- `GET /<ns>/<repo>/-/refs/<ref>/-/<path>`: the `/-/` delimiter keeps ref names that contain `/` unambiguous. It resolves the path and either redirects to the object URL or serves the object directly.

**What gets served**
- Only objects **reachable from a live ref** of that repo, and for non-writers only from the **published view** (D28).
- An id that isn't reachable **in the caller's view** returns **404** before any blocklist check. A 451 is returned only for taken-down ids that are visible in that view.
- Ref-path responses are `no-cache`. Only object-by-id responses are immutable.

**Proofs**
- `?proof=1` adds a Merkle inclusion proof: path → tree → commit → signature.
- A Range request can include a byte-range disclosure proof.
- Both can be verified with the `mkit-wasm` verifiers.

**Private content and caching**
- Private content uses short-lived **signed URL tokens**.
- Public content is cached as `immutable, public`. Private content is `private`, with no shared cache.

**Every read** goes through the Authorizer and, optionally, Admission.

### 6.7 Leases, GC, quarantine, takedown ([mkit#1091](https://github.com/officialunofficial/mkit/issues/1091))

**Leases**
- They are **per ref**, with a repo-level default. An opaque server supports repo-level leases only.
- States: active → grace (writes blocked, reads allowed, renewal restores the lease) → suspended (reads blocked) → deleted. An event is emitted on every transition.
- No lease means permanent.
- The implementer sets the lease; mkit enforces it.

**GC**
- An expired lease deletes the ref. GC reclaims objects **unreachable** from every root; reachability decides, not membership alone.
- **Roots:** live refs, published pointers, open tickets, and pending advances.
- **Opaque-mode GC** works at pack granularity: any pack or packlist node listed by a root's packmap chain is live.
- Global content is deleted only through `ContentIndex`, when there are zero holders and zero holds.
- Reclaiming is protected by a **grace period plus pins** for objects referenced by open tickets, recent `AlreadyPresent` answers, or pending advances.
- **Mark → wait → re-check → delete.** GC marks candidates `gc_pending`, then waits longer than `MAX_APPLY_WINDOW` plus the relay lag (measured by the namespace's relay watermark, not assumed), so every write that could still reference a candidate has either committed and been relayed or failed its commit deadline. It then re-reads the roots from the strongly consistent ref shards (never only from the eventually consistent ref index) and deletes only through a `ContentIndex` batch guarded on the mark. A write that sees a `gc_pending` pack unmarks it first.

**Quarantine (D18, D28)**
- A `ContentInspector` runs over extracted blobs.
- **Fast checks** (the blocklist, hash lists) run synchronously in `pre_receive` and reject the push.
- **Slow checks** run under quarantine:
  - The ref moves for writers.
  - Anyone without write access (the public and read-only grantees) sees the **published view**. For each branch, the published pointer is the (head, packmap) pair of the last `AdvanceRefs` *k* such that every advance up to *k* has been cleared.
  - `ListRefs`, `ReadRef`, `PackExists` and `DownloadPack` all answer from the caller's view, including through the `X-Mkit-Ref` header (D36).
  - Pending packs and blobs are never served to non-writers, over the transport or over HTTP.
  - Quarantine is indexed-mode only.
  - Once cleared, the published view catches up. A hit becomes a takedown.
- Each inspector is configured either to fail closed or to publish when it is unavailable.
- mkit ships no scanners. The implementer owns the choice of scanner, the policy, and legal reporting.

**Takedown (D17, D29)**
- **Levels:** content, repo, namespace. Takedown at content level exists **only in indexed mode**; opaque mode supports repo and namespace suspension only.
- **Unit:** the **whole object** (a blob id, or a chunked file's manifest id), never a single chunk. Chunks are removed only when no other live object references them.
- **What happens to the bytes:** they move to a restricted **preservation store**, reachable only through the admin API, and are purged after a retention period the implementer configures. Publicly, the object is gone immediately. A tombstone makes reinstatement possible.
- **Objects inside packs:** the server rewrites every pack that contains X, **or contains a delta whose base chain passes through X**, storing those entries raw. It rebuilds each affected packlist chain and compare-and-swaps `refs/mkit/packmap/<branch>`, paired with the unchanged head.
  - The redaction notice records the rewrite and maps old pack ids to new ones, so receipts stay interpretable.
  - A later push whose delta base is tombstoned fails with a `RedactionNotice` detail, and the client re-plans with X absent.
  - `ReadRef`/`ListRefs` for a branch whose closure contains a tombstone attach the notice, so fetch fails with the notice rather than `RemoteMissingObject`.
  - Signed commits are unaffected: signatures cover commits and trees, not packs.
- **Blocklist:** the hash goes on the global blocklist in `ContentIndex`, so re-uploads to any namespace are rejected.
- **Lag:** holders still in flight in the outbox relay are caught by the relay, which checks the blocklist when it records a holder and takes the object down in that repo. A takedown is reported complete only after the relay watermark has passed the takedown. A dedup hold is released only when its holder row is recorded.
- **Responses:** reads return 451 or a Connect detail carrying a **server-signed redaction notice** (object id, reason code, date, server origin, key id). Fetch and clone fail closed with a precise error.
- **Caches:** a **`CachePurger`** hook, implemented by the implementer (e.g. the Cloudflare purge API), runs on every takedown, and also on suspension, lease deletion and visibility changes.
- **Suspension** of a repo or namespace reuses the lease states.

**Admin API**
- Operations: takedown, reinstatement, suspension, blocklist, set or extend a lease, register ssh grants.
- Requests are signed with a deployment admin Ed25519 key and replay-protected, and every action goes to an **audit log**.

### 6.8 Storage receipts ([mkit#1092](https://github.com/officialunofficial/mkit/issues/1092))

- On every commit and every lease change, the server signs an in-toto statement as DSSE with its **deployment key**.
- The predicate covers:
  - the repo, ref, commit and pack ids
  - logical and stored bytes
  - the lease end date and state
  - `issued_at`, the server origin and the key id
  - an opaque `external_ref` supplied by the implementer
- `external_ref` must never contain secrets or credentials; it is meant for things like an MPP `Payment-Receipt` reference.
- The receipt is returned in the response and can be fetched later.
- The client stores receipts locally under `.mkit/attestations/`. **They are not pushed by default.**
- The public key is published at a well-known URL and in `GetServerInfo`.

### 6.9 ssh and enc (D23)

- They use the same pipeline, storage, verification, receipts and leases.
- The transport identity maps to an Ed25519 principal. Grants are registered server-side (§6.4).
- Multi-repo addressing uses the path argument. The FS backend keeps the `.mkit` layout, so `mkit serve <repo-path>` integrations (SSH-SECURITY §5) keep working.
- The stdio path runs through a blocking executor with no server runtime, so the `mkit` CLI stays server-free.
- No admission challenges: a write that needs payment fails with "use mkit+https".
- No change to the frozen `mkit.rpc.v1.ssh`.

### 6.10 New spec: SPEC-SERVER

It covers:
- the remote contract `mkit.server.hooks.v1`, with channel authentication and per-hook failure behavior
- pipeline order, the authenticate-then-replay-lookup rule, the per-RPC lifecycle, and fail-closed rules
- the outcome and outbox guarantees
- the published view and quarantine
- requirements for custom backends, backup, and migrations
- the admin API and audit log
- the scope of the conformance suite

## 7. Boundary: mkit vs implementer

| mkit (mechanism) | Implementer (policy) |
|---|---|
| The admission call point, after authentication and before any state change | Pricing, currency, balances, ledger |
| Byte counts: declared and new-to-repo at admission; new-to-store and stored in `Committed` | Verifying and settling MPP/x402/Stripe payments |
| The reservation and outcome outbox | Top-up and lease-renewal endpoints |
| Namespace policy, grants, epochs, visibility | Namespace allowlist contents; who gets grants |
| Lease enforcement, GC, lifecycle events | Lease terms and prices |
| Quarantine, published view, takedown, blocklist, preservation store, notices | Scanners, moderation policy, NCMEC and legal reporting, preservation period, `CachePurger` |
| Signed storage receipts | Payment receipts; `external_ref` contents |
| The default abuse quota (swappable) | Accounts, claiming, identity mapping for payers without a wallet |

## 8. Milestones and rollout

**Order.** M0 and M1 run in sequence. Then come three tracks: identity (M2), money (M3) and content (M4 → M5). **Every milestone is in scope and gets completed.**

**Dependencies across tracks:**
- M4's private-repo serving and signed URLs depend on M2's read authentication.
- **M5 depends on M2's signed reads.** Writers must sign reads to see real refs during quarantine; without that they loop on `PackmapConflict`. Read-only grantees also come from M2.
- M5's takedown and GC depend on M4's `ContentIndex` holders. The `ContentIndex` trait itself is designed in M0.

**How each milestone lands.** First a spec PR, where there are wire changes. Then implementation PRs, with golden vectors (SPEC-CONVENTIONS §5) and conformance cases.

**PR [mkit#1087](https://github.com/officialunofficial/mkit/pull/1087)** is closed with a comment crediting the author and rebuilt as three stacked spec PRs:
- addressing ([mkit#1084](https://github.com/officialunofficial/mkit/issues/1084)), which also carries namespace policy and owner-key authorization
- grants ([mkit#1085](https://github.com/officialunofficial/mkit/issues/1085))
- admission ([mkit#1086](https://github.com/officialunofficial/mkit/issues/1086))

Grants and admission both stack on addressing and can run in parallel. The admission spec refers to "write authorization" generically, so it doesn't depend on the grants spec.

### M0: Foundation refactor (no new wire features)

- Create `mkit-server`, `-native`, `-worker` and `-conformance`.
- Merge the duplicated upload validation, download chunking, ref compare-and-swap, ref-name validation, quota and envelope code.
- Port `mkit serve` (ssh via a blocking executor, enc, http) and `vcs-worker` onto the core, streaming end to end. On Workers, buffering is capped until resumable parts land in M1.
- Settle two designs that everything later builds on: the replay-ledger **state model** (fingerprint, `in_flight`/`committed`, stored result, never storing challenges or `pending_verification`) and the `ContentIndex` **trait surface**.
- Add the FS (with `.mkit` layout), S3 and SQLite backends, with migrations.
- Production basics: an ssh stdio read timeout, timeouts and concurrency caps, `tracing` spans and a metrics facade, error redaction, CORS.
- Extend the wasm dependency-graph check.
- Ship the `mkit-server` binary (D31) through `release.yml` (build matrix, signing, SBOM, provenance) and publish a container image. Remove `--http` and `--listen-enc` from the CLI's `mkit serve`.

**Exit:**
- The conformance suite passes on native (FS + SQLite and S3 + SQLite) and on `wrangler dev`.
- Existing CLI end-to-end tests pass.
- Nothing changes on the wire.
- The `mkit` CLI stays **server-free** (script-enforced dependency check).

### M1: Addressing, namespace policy, uploads

- SPEC-TRANSPORT-CONNECT v2 addressing ([mkit#1084](https://github.com/officialunofficial/mkit/issues/1084)).
- `namespace_policy` (allowlist, any) and `write_policy = owner` with the owner's own key (grants come in M2).
- Sharded metadata (D34): the namespace coordinator, `(repo, ref)` ref shards, and repo index shards (membership and ref index) with outbox propagation, on both backends. Also epoch leases (the coordinator's leased-shard table and time-bounded `NotAfter` commits).
- `GetServerInfo`.
- `BeginUpload` tickets, resumable parts ([mkit#1090](https://github.com/officialunofficial/mkit/issues/1090)), `AlreadyPresent`, and `AdvanceRefs` carrying the ticket.
- Client changes: `X-Repository` on reads, `BeginUpload`.
- Deploy a staging `vcs-worker`: a route, the real `AUTH_AUDIENCE`, and an R2 bucket with a Durable Object namespace.

**Exit:**
- The conformance tests for multi-repo isolation, namespace policy and tickets pass on both adapters.
- A real `mkit` push and clone round trip works against staging.
- CI runs the conformance suite against staging.

### Track Identity: M2

- The grants spec and verifier ([mkit#1085](https://github.com/officialunofficial/mkit/issues/1085)):
  - epoch matched exactly and checked inside `apply`
  - bounded, audience-bound, expiring epoch statements
  - audience lists and ref scopes, including packmap coverage
  - low-S signatures, `GetGrantEpoch`
- Signed reads, private repos, `read` grants, signed URL tokens ([mkit#1089](https://github.com/officialunofficial/mkit/issues/1089)).
- Server-side grants for ssh.
- CLI: `mkit grant create/list/revoke`, `mkit epoch`.

**Exit:**
- Conformance tests for grants, revocation (including a revoke during an in-flight write, which must be rejected at `apply`), and private reads.

### Track Money: M3

- The admission spec ([mkit#1086](https://github.com/officialunofficial/mkit/issues/1086)) as revised:
  - a 402 carrying the challenge list
  - `BeginUpload` required when admission is on
  - a helper that returns headers, filtered by an allowlist
  - replay lookup before admission
- The admission and outcome hooks, the outbox, and the remote-hook adapter with channel authentication. SPEC-SERVER.
- Client: 402 handling, `admission_helper`, passing through `Payment-Receipt` and `PAYMENT-RESPONSE`.
- A reference example (documentation only, not a supported crate): a TypeScript `mppx` Worker that implements `admit` and `outcome` over a service binding.

**Exit:**
- End to end against a stub MPP server: challenge → helper → credential → commit → exactly one `Committed` outcome.
- An aborted upload gives `Aborted` and settles nothing.
- A retry after a lost response returns the stored result without a new challenge.
- A simulated old client fails fast.
- The hard-reserved headers can't be set even through config.

### Track Content: M4 → M5

**M4: indexed mode**
- `ruzstd` decoding.
- Verification before refs move, with **lookups isolated to the repo**.
- Hybrid extraction and the global content store with membership.
- HTTP serving and proofs ([mkit#1088](https://github.com/officialunofficial/mkit/issues/1088)), with `/-/` URLs and reachability-only serving.

**M5: lifecycle**
- Per-ref leases, and GC with a grace period and pins.
- The published view and quarantine with `ContentInspector`.
- Takedown: tombstones and the preservation store, pack rewrite and packmap compare-and-swap, the blocklist, notices, `CachePurger`, suspension.
- Storage receipts ([mkit#1092](https://github.com/officialunofficial/mkit/issues/1092)).
- The admin API with an audit log.

**Exit:**
- Serving and proof round trips verify with `mkit-wasm`.
- A thin-delta push that references another repo's blob is rejected, and the rejection reveals nothing about whether the blob exists.
- A takedown hits every repo holding the content, a re-upload is rejected, and the preserved bytes stay reachable only through the admin API.
- **A client whose packmap chain predates a takedown rewrite fetches cleanly afterwards**, unless the tip's closure contains the tombstone, in which case it fails with the redaction notice.
- A pack whose delta chain runs through a taken-down object is rewritten, and it still decodes.
- A lease expiry never removes a reachable object, and GC never races an open ticket.
- Quarantined content never reaches a principal without write access, over any path.

### Rollout

- A staging deployment exists from M1 onward, and conformance runs against it in CI.
- The server ships as the separate `mkit-server` binary and container image (D31). The `mkit` CLI stays server-free.
- The existing demo stack is unchanged: `repo-worker`, `keys-worker`, `workspace-worker` and `spammer-worker` keep using `mkit-worker-common` as it is.
- Implementers (e.g. a storage business on Workers) can build on M1 + M3 for paid public uploads (with `namespace_policy = any` plus a non-default Admission). **Before M2, only `ed25519-<key>` namespace owners can write**, because auth-v2 is Ed25519-only; `0x` wallet owners need M2 grants. A public launch that needs serving and CSAM controls depends on M4 + M5 (and on M2 for private content).

## 9. Risks

- **Workers CPU and time limits when verifying large pushes.**
  - Mitigation: verify between upload and ref advance, chunked, with `pending_verification` and advertised limits.
- **Throughput ceiling per shard** (Cloudflare guidance: about 200–500 storage-writing req/s per Durable Object). With D34 this binds only on **one hot ref**, which is serial anyway because every push compares and swaps on the previous head. Writes scale with the number of refs. Reads scale through R2 and cached snapshots.
  - Mitigation: repo index shards batch their outbox updates. Snapshots of the published view, one per ref-index bucket and rewritten with debouncing (R2 allows about one write per second per key), serve `ListRefs`/`ReadRef` for readers.
- **Coordinator lease renewals.** Each active ref shard renews its epoch lease with a coordinator write about every 30 s, so one namespace supports roughly 200–500 writes/s × 30 s ≈ 6,000–15,000 concurrently active ref shards.
  - Mitigation: repo creation and config reads ride on the renewal and a versioned config cache (about 2 Durable Object calls per write in steady state); the coordinator's leased-shard count is monitored; a longer lease trades revocation latency for headroom.
- **Eventual consistency of membership and `ListRefs`** (D34).
  - Mitigation: the safe-failure rules in §5.3 (re-upload, or retryable "base not yet visible"). `ReadRef` stays strongly consistent. Conformance tests cover lag windows.
- **The 10 GB SQLite cap per Durable Object.** A full object fails writes with `SQLITE_FULL`; reads and deletes still work.
  - Mitigation: object-id-prefix sharding of repo index shards (Q5 is largely resolved by D34), 70%/90% alerts, and a fail-closed error plus critical alert at the cap.
- **Pack rewrite during takedown** changes packmap chains that clients have cached.
  - Mitigation: server-authored compare-and-swap, the redaction notice, and the M5 exit test.
- **Legal: preservation and reporting duties differ by jurisdiction.**
  - Mitigation: mkit provides the preservation store and hooks; the implementer configures retention and reporting.
- **Streaming Connect through the Workers bridge** (SPEC-TRANSPORT-CONNECT §6.3). Review of connectrpc 0.9 and workers-rs 0.8.6 shows client-streaming bodies can be consumed incrementally.
  - Mitigation: a streaming Worker adapter with a no-buffering fallback that parses the Connect stream framing directly; resumable client-streamed parts over `BeginUpload` tickets.
- **Storage overhead of the hybrid model.**
  - Mitigation: pack rewrite during GC.
- **Scope size.**
  - Mitigation: a serial foundation, three tracks with the cross-track dependencies stated explicitly, and exit criteria for each milestone.

## 10. Open questions for review

1. ~~Where does the server binary ship?~~ **Resolved (D31):** as a separate `mkit-server` binary.
2. Default values:
   - the `BeginUpload` threshold when admission is off
   - the blob extraction threshold (64 KiB proposed, D32)
   - the bounded epoch increment and the epoch statement's lifetime
   - the lease grace and suspension periods
   - the lifetime of signed URL tokens
   - the GC grace period
   - the preservation retention default
3. Rotating the receipt and notice signing key, and the format for publishing it.
4. The admin key model: a single key, or a threshold (related to the release-threshold work).
5. ~~How the object index overflows the 10 GB Durable Object limit~~ **Largely resolved by D34:** repo index shards split by object-id prefix. What's left is picking the shard fan-out.

## 11. Decision log

| # | Decision |
|---|---|
| D1 | A framework with native and Workers adapters, plus a conformance suite |
| D2 | FS and S3 blobs with SQLite metadata; Postgres deferred |
| D3 | Opaque by default, indexed mode as an opt-in |
| D4 | Namespaces are self-certifying only |
| D5 | A grant's audience is an explicit list, with no wildcard |
| D6 | Grants are scoped to ref patterns with flags; fast-forward-only needs indexed mode |
| D7 | A unary `BeginUpload` |
| D8 | A 402 with a Connect body and an opaque list of challenges |
| D9 | The helper returns headers, filtered by an allowlist (see D30) |
| D10 | Two-phase admission with a transactional outcome outbox |
| D11 | Rust traits plus a remote-hook adapter |
| D12 | Refs, membership and replay are isolated per repo; quota scope is up to the deployment |
| D13 | Mechanism in mkit, policy in the implementer |
| D14 | Hybrid storage (extraction rule refined by D32) |
| D15 | A global content store with per-repo membership; no existence oracle |
| D16 | Leases per ref |
| D17 | Takedown at three levels, with signed notices |
| D18 | Fast checks run synchronously; slow checks run under quarantine; scanners belong to the implementer |
| D19 | Private repos in v1 |
| D20 | HTTP serving with proofs |
| D21 | ~~One Durable Object (or partition) per namespace~~, superseded by D34 |
| D22 | Signed storage receipts |
| D23 | ssh and enc share the pipeline; they carry no payments |
| D24 | `transport.v1` evolves additively |
| D25 | M0 → M1, then three parallel tracks; the full scope gets done |
| D26 | Split [mkit#1087](https://github.com/officialunofficial/mkit/pull/1087) into three stacked spec PRs |
| D27 | The namespace allowlist is the default; `any` is an opt-in that requires a non-default Admission (or `--unsafe-open-namespaces`); admission sees `creates_namespace` and `creates_repo`; the default quota is per (namespace, signer) and per namespace |
| D28 | Quarantine gives readers without write access a published view; writers see pending content |
| D29 | Takedown: whole-object tombstone, preservation store, server-side pack rewrite with packmap compare-and-swap, `CachePurger`; content-level takedown is indexed-only |
| D30 | Helper headers are allowlisted, extensible per remote, with a hard-reserved set |
| D31 | A separate `mkit-server` binary (signed release plus container image); the `mkit` CLI keeps `mkit serve` only for the ssh forced command and stays server-free |
| D32 | Extraction: every blob of 64 KiB or more (configurable), plus every chunked file reassembled once into one object keyed by its manifest id; Range-native serving; dedup by whole file |
| D33 | Attestation-gated refs and attestation transport are deferred to a follow-up epic |
| D34 | Metadata is sharded to scale within a repo: a namespace coordinator (config, epoch, leased-shard table), strongly consistent `(repo, ref)` ref shards (head+packmap, tickets, replay, outbox, published pointer), and eventually consistent repo index shards (membership, ref index). `apply` is atomic per ref shard. Revocation uses epoch leases (O(active shards), done within one lease interval). Index shards have a large fixed prefix fan-out, so there is no resharding. Quota is exact per shard and approximate per namespace. `BeginUpload` names its target ref |
| D35 | Staging runs on `staging-vcs.mkit.sh` (the `mkit.sh` zone, same Cloudflare account as the other mkit workers) as `env.staging` of `vcs-worker`, with dedicated R2 buckets and DO classes, resettable data, and one staging CI signer on the allowlist |
| D36 | `X-Mkit-Ref` is approved as an optional read-your-writes header on `PackExists`/`DownloadPack`: the server resolves it against that ref's strongly consistent shard, always subject to the caller's view (non-writers get the published view; quarantined packs stay hidden) |

## 12. References

- PR [mkit#1087](https://github.com/officialunofficial/mkit/pull/1087); issues [mkit#1084](https://github.com/officialunofficial/mkit/issues/1084)–[mkit#1086](https://github.com/officialunofficial/mkit/issues/1086) and [mkit#1088](https://github.com/officialunofficial/mkit/issues/1088)–[mkit#1092](https://github.com/officialunofficial/mkit/issues/1092).
- Specs: SPEC-TRANSPORT-CONNECT, SPEC-TRANSPORT, SPEC-PACKFILE (§3.2 delta bases), SPEC-CONVENTIONS, SPEC-DISCLOSURE, SPEC-ATTESTATIONS.
- docs/SSH-SECURITY.md; docs/THREAT-MODEL.md.
- MPP: https://mpp.dev/llms-full.txt. Relevant parts:
  - HTTP 402; `WWW-Authenticate`, `Authorization`, `Payment-Authorization`, `Payment-Receipt`
  - multiple challenges; challenge binding
  - idempotency; caching; TLS
  - single-use credentials; CORS
- x402 v2: https://github.com/coinbase/x402/blob/main/specs/x402-specification-v2.md (`PAYMENT-REQUIRED`, `PAYMENT-SIGNATURE`, `PAYMENT-RESPONSE`).
