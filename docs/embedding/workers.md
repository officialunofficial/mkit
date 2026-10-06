# Embedding in Workers

Use the [generic reference](../../apps/embedded-worker/README.md) to compose the
supported APIs. The [server specification](../specs/SPEC-SERVER.md) and conformance
suite define the contracts; the example is a small host, not an application
policy or a deployed performance benchmark. Pin all mkit dependencies to the
same immutable commit or release tag.

## Authority-owned namespace setup

Self-certifying namespace names remain the default. For opaque account names,
including lowercase UUIDv7 names, configure `NAMESPACE_MODE=authority`,
`ADDRESSING=multi`, `NAMESPACE_POLICY=any`, `AUTHORIZER_ROLE=authority`,
`HOOK_ROLES=authorize`, and `AUTHORITY_FENCE=true`. Supply the Authority hook
through `serve_with`, or configure its remote transport. Set `AUTHORITY_KEYS`
to dedicated verification-key lines, for example
`deployment <64 lowercase hex Ed25519 public key> *`. Exact opaque namespace
lists also work. Keep authority keys separate from every other configured
credential role. `*` is refused unless authority namespace mode is selected.

The current Worker var parser requires `UNSAFE_OPEN_NAMESPACES=true` for `any`.
Install a custom Admission hook that vets namespace creation; the setting is
not a replacement for it. Startup rejects a missing fence, wrong hook role,
Single addressing, or an allowlist in authority mode. Supply `TICKET_KEYS` and
a separate URL-token key when you use object URLs. Mode, key-scope, and hook
validation also run for programmatic configuration before requests reach stores.

For direct core embedding, set `PipelineConfig.namespace_mode` to
`namespace::NamespaceMode::Authority` and construct the fence with
`AuthorityFence::parse_with_mode` or `new_with_mode`. Validate names with
`NamespaceMode::namespace`; convert the result to a storage key with `key()`.
Existing `NamespaceKey::from_namespace` and the core self-certifying parser
remain available. Set the matching mode on standalone `admin::Config` and
`takedown::Service` with `with_namespace_mode`, and on `WorkConfig.namespace_mode`.
The Worker adapter supplies these settings automatically.

Return `AuthzFacts::default()` with `authority_generation` set for a write
allowance. For writer reads, set `caller_view = mkit_server::CallerView::Writer`;
that allowance enables `repo_storage`, `repo_storage_many`, owner object reads,
and owner-view `issue_urls`. Selecting `ReaderView::Owner` still requires a
verified envelope and a fresh hook decision on each batch. Reader-only and
denied callers receive uniform absence. Private namespace listing separately
requires `list_repos_authority_full` and a namespace-wide writer allowance.

Register each account namespace before its first write by calling
`SetAuthorityGeneration` with a statement for generation 0 (any valid statement
registers). Under `any` this needs no prior namespace record. Writes,
`BeginUpload` and visibility changes for an unregistered namespace fail with
`permission_denied` ("namespace not registered") before your hooks run, and
`GetAuthorityGeneration` reports 0. Return the current generation from the
Authority hook. When you bump it, a client's retried `BeginUpload` replaces its
stale ticket at once: the old reservation receives an `Aborted` outcome with
`EPOCH_MISMATCH` and procedure `BeginUpload`, the old multipart session is
aborted after commit, and the admission charge for the old reservation is not
refunded, so reconcile it from that outcome. Registration status is
not confidential (an unsigned `GetAuthorityGeneration` already reveals a
generation of 1 or more, and a write probe distinguishes unregistered from
registered at 0); the refusal before your hooks protects their cost, not secrecy.
To reconcile a lost `SetAuthorityGeneration` reply or a crash, re-sign and
resend Set for the target generation: it returns that generation again, whether
the statement is byte-identical or freshly signed. `GetAuthorityGeneration`
returns 0 for both an unregistered namespace and one registered at 0, so it
cannot serve as the reconcile check. A resend never rolls a generation back.
A lost commit acknowledgement or a crash between commit and abort leaves the
old multipart session to backend sweeps and lifecycle rules.

Names are 1–72 lowercase ASCII bytes matching `[a-z0-9][a-z0-9._-]*`.
`root`, `ed25519-` prefixes, and `0x` prefixes are reserved and rejected.
The deployment is the trust root: names do not certify ownership. Owner-signed
grants, grant epochs, and visibility statements are refused; change visibility
with a signed envelope authorized by the hook. Keep keyrings, commit-signer
policy, and landing-time storage in the embedder. Under `any`, namespace
discovery is incomplete and you cannot claim complete deployment-wide takedown.
The mkit CLI retains its self-certifying addressing behavior. See
[the mode contract](../specs/SPEC-SERVER.md#622-opt-in-authority-owned-namespaces).

## Request routing and authority

Construct one validated `WorkerConfig` on fetch and in every Durable Object.
Declare in-process hook capabilities with `HookCapabilities` and supply the
matching Authorizer, Admission and OutcomeSink. `durable_objects!(config, sink)`
reconstructs that sink for cold alarms. Purge uses `PurgeHooks` with its actual
local invalidation and sink. A sink must acknowledge only after every configured
serving cache is invalidated; the reference has only the paired local cache.
Complete preservation/admin settings are required to activate purge delivery.
See [server pipeline order](../specs/SPEC-SERVER.md#2-pipeline-order),
[hook failures](../specs/SPEC-SERVER.md#8-per-hook-failure-behaviour) and
[cache purge](../specs/SPEC-SERVER.md#167-remote-cache-purge).

Transfer the incoming `ReadableStream` into `serve_with`; buffering UploadPart
in the host defeats the streaming upload path. Preserve method, headers and
escaped query when remounting routes. Signatures bind `WorkerConfig::audience`
(the public origin), not the constructed internal request URL. Keep the operator
mount separate, set `admin_on_public_path=false`, and use `serve_admin_with` only
on trusted, restricted ingress. Operator authentication still runs. See
[auth-v2](../specs/SPEC-TRANSPORT-CONNECT.md#71-reference-worker) and
[admin exposure](../specs/SPEC-SERVER.md#161-service-exposure-and-off-by-default).

`ReaderView::Public` sees public repositories and published refs/membership.
`ReaderView::Owner(&meta)` requires a signed auth-v2 ListRefs envelope
for the repository owner, an accepted write grant, or an Authority-hook writer
allowance in authority namespace mode; selecting the enum does not
grant authority. Preserve its exact body and headers in `RequestMeta`.
Authorization and grant epochs are checked again on each batch. Owners read
live refs, while publication holds and global denial still apply. URL issuance
uses published reachability even for owners; an owner can issue a scoped token
for published content in a private repository. Do not turn an owner prefetch into
anonymous HTTP bytes. See [caller views](../specs/SPEC-SERVER.md#101-callers-view),
[all reader surfaces](../specs/SPEC-SERVER.md#103-every-reader-surface-uses-the-published-view)
and [URL tokens](../specs/SPEC-HTTP-OBJECTS.md#6-url-tokens-and-key-publication).

## One reader and one session per request

Create one `embedding_pipeline` with a shared physical `SliceBudget`, one
`object_reader`, and one `ReaderSession::new(ReadLimits::new(...))`. Retain the
same reader/session for sequential `read_canonical_in` and `object_metadata_in`
batches. Never reset the ledger after a failure. Emit all four `session.used()`
dimensions and the outer `budget.used()` as host metrics before returning an
error or success. Encoded reservations include failed I/O; duplicate canonical
outputs count separately; metadata emits no canonical output bytes.

Canonical and metadata calls accept at most `OBJECT_READER_BATCH` (**16**) IDs
by default, preserving order and duplicates. Opt into batches of up to **45**
with `ObjectReader::with_batch_limit`; this changes no storage, byte, decode,
output, or denial allowance. URL issuance still accepts at most **16** targets.
Reader operations retain `OBJECT_READER_CALLS` (**8,500**) core call units and
HTTP decode/denial caps. Default `ReadLimits` aggregate 8,500 calls,
256 MiB decoded and 256 MiB output bytes, with no additional encoded-byte cap;
choose explicit tighter limits for the host. Ranged blob reads cost two units.
These units are conservative internal allowances, not exact platform subrequests
or billing. See the [reader API](../../rust/crates/mkit-server-worker/README.md)
and [read limits contract](../../rust/crates/mkit-server/src/pipeline/read_limits.rs).

The adapter's normal dispatch uses a 9,000-unit physical purse. A custom pipeline
must share its host-supplied purse with the Worker stores; reserve capacity for
host DO calls, hooks, settlement and unrelated host work. Select the invocation
budget against the deployed plan's current subrequest allowance and connection
limits, including calls outside mkit. Do not assume the core cap reserves those
host calls automatically. The reference uses 8,000 physical units and a smaller
4,000-unit session. `issue_urls` accepts at most 16 targets and shares the outer
physical purse, but has independent per-call decode/proof caps and **does not
charge the ReaderSession ledger**. Bound the number of issuance batches in the
host; the reference issues one.

Roots are captured at the first proof-bearing batch, not at an atomic repository
snapshot. The session has a fixed deadline and bounded proof memo. After
reachability-lag expiry it captures fresh roots without refunding budgets or
extending the deadline. A new request gets a new session; start a new session to
observe new commits before proof expiry. `ReaderSession::with_deadline` accepts
an earlier absolute Unix-ms deadline using the pipeline clock. Public
unprovable objects remain absent; authenticated owner exhaustion is typed
`ResourceExhausted`. Do not convert storage failure into successful absence.

For general-ID reads, read parents before children: prefetch a commit, its root
tree, then selected subtrees, manifests, and chunks within the reader's batch
limit. Fetch metadata only when you need kind, canonical length, or logical file
length; a canonical read already gives bytes. ChunkedBlob canonical bytes are
the manifest, not the complete file.

For a selected ref, use `walk_history_in` for bounded parent discovery,
`locate_commit_in` for one commit, and `read_commit_path_in` for an exact decoded
path at a proved commit. `HistoryOptions.mode` explicitly selects
`HistoryMode::FirstParent` or `HistoryMode::AllParents`; all-parent traversal
uses breadth-first decoded parent order with duplicate suppression. Visit,
frontier, tag-peeling, and path-depth bounds prevent unbounded traversal.
These helpers capture a fresh selected ref per operation without refunding the
session ledger or extending its deadline. Optional path witnesses supply commit
and ancestor-tree bytes for local inclusion proofs; they grant no authority.
See the [selected-ref reader contract](../specs/SPEC-SERVER.md#101-callers-view)
and [object format](../specs/SPEC-OBJECTS.md).

For cross-request first-parent paging, configure `PipelineConfig.history_tokens`
with a dedicated `HistoryTokenConfig` secret, backend realm, and TTL. The Worker
adapter exposes the optional `HISTORY_TOKEN_KEYS` setting. Use
`walk_history_page_in` with the previous page's opaque continuation. This API
has no all-parent DAG frontier. Supply a fresh signed credential envelope for
an owner request and create a fresh reader and session for every request.
The stable signer, grant, captured credential headers, and trusted audience must
match; envelope nonce and timestamps may change. Public requests remain public.
Successors inherit the original expiry, bounded at issuance by the configured
TTL, proof lag/deadline, and credential/grant expiry. Live authorization and
source/denial checks run again on every redemption.

Invalid or expired tokens return uniform absence. Ref/publication changes,
visibility changes, grant epochs, authority generations, and key replacement
invalidate continuations; returning a ref to its old hash does not restore them.
Restart at the selected ref after expiry or a bound scope/state change. Paging
proofs stay confined to each operation, and failed work retains its charges.
See the [continuation contract](../specs/SPEC-SERVER.md#authenticated-history-continuations)
for configuration, validation, and invalidation details, and
[history paging measurements](../operations/history-paging.md) for bounded
fixture measurements and their limits.

The host owns filtering, ordering beyond these history modes, general tree/diff
traversal, and unrelated application pagination or durable pagination state.
For synchronous local disclosure construction,
`mkit_core::verify::build_disclosure_from` selects a path over an `ObjectSource`;
you can prefetch ancestors into `MemorySource`.

## Durable writes, retries and deadlines

Request handlers submit writes; the server's Durable Objects own persisted
verification jobs, relay delivery, outboxes and alarm scheduling. A pending write
continues across cold alarms. Persist the host's logical attempt, repository,
nonce/ticket and intended ref update if the host workflow itself must resume.
Retry according to the returned hint, use the same still-valid logical nonce,
and reconcile ambiguous replies through existing ref reads. A process-local task
or `wait_until` is not durable workflow state. Do not serialize ReaderSession
proofs or its ledger into an alarm: a continuation is a new invocation with fresh
limits and authority. See [async verification](../specs/SPEC-SERVER.md#95-asynchronous-verification)
and [outbox lifecycle](../specs/SPEC-SERVER.md#5-outcomes-lifecycle-events-and-the-outbox).

Wasm mkit entry points remove `connect-timeout-ms` and `grpc-timeout` before
connectrpc computes a deadline, and ignore configured DeadlinePolicy defaults
and inter-message timeouts. Native deadlines are unchanged. Use
`connect::ConnectService::new(router)` for a custom mkit mount. A host's unrelated
raw connectrpc service needs equivalent protection, including leaving deadline
policies unset. Bound host work with Worker clock/timer limits; client headers
are not a wasm execution deadline. See the
[dispatch safety contract](../../rust/crates/mkit-server/src/connect/mod.rs) and
[operations guide](../operations/workers.md#embedding).

Pending verification responses carry `Retry-After` rounded to **1–60 seconds**
from the earliest observed persisted timer, with matching typed retry details;
this is a retry hint, not a completion ETA. Retain retry polling even when relay
wake succeeds. Correlate upload ID, job ID, alarm attempt, phase, delivery,
readiness and ref-commit events; inspect `mkit_server_verification_progress_total`
to distinguish CPU work from scheduling/relay waits. See
[verification traces](../operations/workers.md#verification-latency-traces) and
[verification bounds](../specs/SPEC-SERVER.md#95-asynchronous-verification).

## Outcomes and storage projection

Outcome delivery is **at least once and unordered, after commit**. Sink errors
never undo committed writes. Atomically deduplicate by `reservation_id` with the
host's durable effect before acknowledging. A cold alarm rebuilds the same sink
and retries an unacknowledged row; later rows may overtake it. The reference's
private `HostEvents` DO inserts the reservation and updates the storage projection
in one SQLite statement via triggers, pruning dedup rows to the newest **1,024
accepted reservations per receiver**. Counterless outcomes count too; duplicates
do not refresh retention. Pruning leaves the highest-version storage projection
intact. This bounds deduplication state without an extra alarm.

Dedup records only need to outlive the outcome redelivery window. Size a host's
retention count or time window to cover delivery volume, outages, and in-flight
retries. The server retries unacknowledged outcomes until success; it imposes no
finite redelivery age. Consequently this example's count cap cannot guarantee
deduplication after 1,024 newer reservations. Replayed storage counters remain
safe because the projection ignores lower/equal versions. For non-idempotent
host effects, ensure retention covers every possible redelivery or make the
effect independently idempotent before acknowledging it.
See [Outcome](../specs/SPEC-SERVER.md#65-outcome).

Backpressure begins **only above** the configured backlog cap, not at equality
or on the first sink failure. Defaults are 100,000 rows / 64 MiB per outbox.
Reservation-granting writes then return 503, `outbox backlog; retry`, and
`Retry-After: 30`; admitted HTTP reads return empty 503. A real public-to-private
visibility change remains admitted above the cap. Monitor backlog rows/bytes,
restore the receiver and drain persisted rows. See
[outcome backlog](../operations/workers.md#outcome-delivery-and-backlog).

`RepoStorageChanged` is an absolute repository pack-byte total, **eventually
consistent and exact**, not a delta or a ref-commit counter. Count each distinct
member pack once per repository; shared packs count once in each repository.
Sharded relays may lag consumption; publication delay does not defer counting.
Membership is retained, so the total never decreases. Keep the highest version
and ignore lower/equal versions. Single-repository addressing has no counter.
Use owner-authorized `repo_storage` or `repo_storage_many` (up to 100 names) to
reconcile; `Committed.bytes_stored`/`new_to_repo` are not the accounting source.
See [storage accounting](../specs/SPEC-SERVER.md#651-repository-storage-accounting).

## Decoder patch and per-pin upgrades

Cargo does not inherit a dependency workspace's `[patch]`. `pack-ruzstd` requires
the repository's bounded ruzstd decoder patch even when mkit is consumed from
crates.io. Repeat it in the host workspace, using the same approved pin:

```toml
[patch.crates-io]
ruzstd = { git = "https://github.com/officialunofficial/mkit", tag = "v0.5.0" }
```

A build without the patch can succeed while using the unbounded upstream decoder.
Keep it until a released replacement demonstrably contains the bound. See the
[patch requirement and upstream tracking](../operations/workers.md#embedding).

For each pin update, compare [CHANGELOG Unreleased](../../CHANGELOG.md#unreleased)
against the previous pin, recording entries tagged `[embedder: breaking API]`,
`[embedder: stored-format change]` and `[embedder: store reset required]`. Each
breaking entry must include its replacement/migration action. A stored-format
entry says explicitly whether a fresh store is required. This project is
pre-production: reset unsupported stores, with no legacy conversion path.
The host records its chosen old/new pins, applies the actions, repeats its
acceptance flow and keeps that upgrade note with its deployment configuration.
