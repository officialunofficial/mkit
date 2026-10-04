# Workers operator guide

The Paid Workers launch profile serves indexed repositories with D34 sharding
and Multi addressing. Repository content has permanent retention, storage
leases are off, and serving-store GC is off and refused in indexed mode.
Inspection is optional and synchronous. Lean takedown supports immediate global
denial, restricted preservation, legal holds and audited administration; an
accepted request can remain unresolved. See [SPEC-SERVER §18](../specs/SPEC-SERVER.md#18-conformance-scope).

## Launch profile requirements

[SPEC-SERVER §18](../specs/SPEC-SERVER.md#18-conformance-scope) defines the
launch profile without naming a platform. On Workers it means:

- `LAUNCH_PROFILE=paid-workers` selects the profile explicitly, on the Workers
  Paid plan (`WORKERS_PLAN=paid`), with indexed Multi addressing, D34 sharding
  and ticketed uploads at threshold zero.
- Namespace policy is `allowlist`, or `any` with `UNSAFE_OPEN_NAMESPACES=true`;
  under `any`, takedown holder discovery is incomplete.
- HTTP serving and URL tokens, signed HTTPS hooks or the isolated service
  binding, inspection and scanner retrieval, and admin/takedown are
  independent opt-ins. Each validates its complete configuration and key-role
  separation at startup.
- Takedown and `ReadPreserved` activate only with admin keys, `LAUNCH_PROFILE=paid-workers`,
  `TAKEDOWN_ENABLED=true`, indexed Paid mode, and the complete preservation
  configuration: the `PRESERVATION` binding, explicit positive
  `PRESERVATION_RETENTION_MS`, `RECEIPT_NOTICE_KEY` and `RECEIPT_KEYS`, and
  configured cache-purge delivery. Startup refuses partial or invalid
  configuration.
- The environment-configured Worker delivers the global cache purge through the
  signed HTTPS hook (Paid, `signed-http-hooks`, `HOOK_URL`, dedicated
  `MKIT_HOOK_KEY`, explicit `cache-purge` in `HOOK_ROLES`); an embedder can
  supply a `PurgeSink` and local invalidation instead.
- Worker HTTP proofs (`?proof=1`) are unsupported and are not advertised.
  After syntax and normal access checks, they return 416 before proof
  preparation, validators or payment; conditional requests cannot return 304.

## Verification latency traces

The existing Worker console telemetry emits `verification_*` structured events
at INFO and `mkit_server_verification_progress_total` counters labelled only by
`stage`. Counters and these events are not sampled by the adapter. Enable Workers
Logs for the entry Worker and namespace Durable Objects, or capture their live
tail together. Keep the invocation timestamp/identity when exporting JSON lines.
No extra binding or telemetry service is required.

Start with the upload's `ticket` and `pack` hex IDs. Join requests by ticket,
verification checkpoints by pack **and source partition**, and relay delivery by
source plus `relay_sequence`. IDs are log fields, never metric labels. A repeated
upload, advance or alarm produces repeated observations; use the earliest
observation for the particular ticket, not the latest retry.

| Stage/event | What it proves |
| --- | --- |
| `upload_durable` | The ticket upload marker's blob commit returned successfully. |
| `advance_received` | A ticketed advance reached the pipeline; earliest observation measures the pre-verification request gap. |
| `job_created`, `verification_timer_due` | The guarded job/group creation committed; `due_at_ms` is the initial logical wake, already due immediately. |
| `verification_physical_alarm` | A physical Worker alarm entered; `verification_alarm_partition` associates dispatched source partitions in that invocation. |
| `verify_fire`, `verification_timer_entry`, `verification_slice_start` | An actual verification handler started; entry is recorded before the job read, with pack/source correlation. The later slice start adds the ticket and phase. `first_decode` identifies an empty decode cursor, including retries; it does **not** mean ready. |
| `verification_slice_result` | Proposed old/new phases, generation, slice attempt, relay sequence and next wake; this proposal can still lose its commit guard. |
| `verify_checkpoint`, `verification_checkpoint` | The guarded timer/job checkpoint committed. Use these old/new phases as durable progress. |
| `verification_timer_result` | The timer attempt committed, raced or failed; `attempt` counts persisted infrastructure retries and `scheduled_ms` is the physical timer's wake. |
| `relay_delivered`, `verification_relay_delivered` | Target delivery and source cleanup committed through the conservative contiguous `delivered_through` sequence. |
| `verification_usable` | A committed job checkpoint became usable with a guarded Verified state. `ready_observed` is the later advance's observation. |
| `final_cas` | The ref advance batch committed; replaying its nonce does not emit another CAS. |

`now_ms` is injected-clock time; relay and partition-dispatch events use the
tick's business-time snapshot. For real elapsed I/O time, use the Worker log timestamps
as well. Compare upload → advance, job due → physical alarm → first fire, each
committed phase, relay delivery → next fire, and usable → final CAS separately.
The first fire can precede readiness by several slices. A reported nine-second
pending interval remains unexplained until this trace identifies its gaps.

After relay delivery, at most sixteen future timer rows are inspected and eight
waiting jobs are nudged with guarded timer moves. Only ordinary delivery polls
qualify; infrastructure backoff is preserved. There is no upper time cutoff:
work during the tick may have created a poll after its business-time snapshot. There
is no inline verification. Unobserved jobs, contention and a crash before the
nudge commits recover via their existing two-second poll. The nudge commits
independently, so its contention cannot delay remaining relay delivery. A
successful nudge keeps a one-millisecond relay continuation to discover timers
inserted behind the current scan cursor.

`Retry-After` is a polling hint, not an ETA. For the authorized consumed job it
uses the earliest persisted verification timer found in at most four 64-row
pages, including failure backoff, rounded up and bounded to 1–60 seconds. Due,
missing or unobserved timers use one second. Foreign group ownership also uses
the uniform one-second floor without revealing another ticket's schedule. The
typed pending detail carries the same whole-second delay in milliseconds.

## Hosted acceptance

Workers CI requires a locked wasm build of the Uno embedding fixture and a local
paid indexed launch flow with supplied hooks, published object reads, URL tokens
and cold outcome retry. Takedown is off and inspection is unconfigured in this
flow. A separate fault-enabled scenario requires an interrupted verification
slice to resume and commit. Both retain failure diagnostics; the existing Free
and single-sharding wire suites still run. The launch graph guard verifies that
both independent workspaces resolve the patched pure-Rust decoder, and the wasm
decoder harness exercises 32-bit framing. Cloud Build separately runs the ignored
scheduled verifier heap regression with only `memory,pack-ruzstd` enabled.

## Build and deploy

Start with [the reference config](../../apps/vcs-worker/wrangler.jsonc) and
[the staging template](../../apps/vcs-worker/staging/wrangler.staging.jsonc.template).
The reference defaults are not the launch profile. Copy the template into
`apps/vcs-worker/wrangler.staging.jsonc`, choose a distinct Worker name, exact
HTTPS origin and private resource names, and replace every placeholder.
Environment vars and bindings do not inherit: repeat them under `env.staging`.
Use compatibility date `2026-09-09`, `build/worker/shim.mjs`, Smart Placement,
`workers_dev=false`, `preview_urls=false`, and only the approved custom-domain
route. Confirm the account has Workers Paid before setting its storage cap.

Build from `apps/vcs-worker` with `worker-build --release --features launch`
for HTTP, signed HTTPS hooks and bounded zstd decoding. A smaller build can select `pack-ruzstd`, add `http-objects` for
HTTP/tokens, and add `signed-http-hooks` for signed hooks/purge. Never deploy
`test-faults`. The `launch` feature compiles optional facilities; configuration
still selects each one. Set the copied config's build command to the exact
approved feature command so deploy cannot rebuild a default artifact.

Set `limits.cpu_ms=60000` at both top level and `env.staging`, as in the template.
This provisional 60 s allowance requires deployed per-invocation measurement.
Local heavy-request process CPU was 17.17 s, including concurrent alarms and
storage isolates; it is not deployed CPU accounting. Record source SHA, Wasm
and shim hashes, config digest, runtime/tool versions, resource identities,
input geometry and measured limits before accepting a deployment.

The base launch vars are:

| Name | Value / purpose |
|---|---|
| `LAUNCH_PROFILE` | `paid-workers` |
| `WORKERS_PLAN` | `paid`; actual Paid account required |
| `INDEXED_MODE` | `true`; scheduled verification and extraction |
| `ADDRESSING` / `SHARDING` | `multi` / `d34`; fixed over the store lifetime |
| `AUTH_AUDIENCE` | Exact canonical public HTTPS origin; no path |
| `AUTH_REPOSITORY` | Ignored in Multi; only Single uses it |
| `NAMESPACE_POLICY` | `allowlist` (default), or `any`; with `any`, omit `NAMESPACE_ALLOWLIST` entirely |
| `NAMESPACE_ALLOWLIST` | For allowlist (omit `UNSAFE_OPEN_NAMESPACES` entirely): nonempty canonical `ed25519-<64 hex>` or `0x<40 hex>` namespaces, comma/newline separated; blank lines and `#` comments ignored |
| `UNSAFE_OPEN_NAMESPACES` | `true` required with `any`; explicitly admits fresh self-certifying namespaces without a finite inventory |
| `RETENTION` | `permanent` |
| `STORAGE_LEASES` / `GC_ENABLED` | `false` / `false`; true is refused |
| `DEFAULT_REPO_VISIBILITY` | `public` (default) or `private`; set at creation. Explicit repository visibility wins; changing this default changes every repository without an explicit setting |
| `MAX_PACK_BYTES` | Default `1073741824`; allowed 1–5363340410. Select from measured workload, not the ceiling |
| `NAMESPACE_LOCATION_HINT` | Optional placement hint |
| `NAMESPACE_JURISDICTION` | Optional `eu`, `us` or `fedramp`; fixed for the deployment lifetime and consistent with R2 residency |
| `BACKUP_PREFIX` | Distinct deployment prefix, e.g. `mkit-vcs-worker-staging` |
| `BACKUP_INTERVAL_MS` | Default `86400000`; zero disables portable export |
| `BACKUP_MAX_BYTES` | Default `16777216`; maximum `25165824` |
| `BACKUP_FORCE_REUPLOAD_MS` | Default `2419200000` (28 days); keep below backup lifecycle retention |

`LAUNCH_PROFILE=paid-workers` is the only accepted profile value. The former
`uno` alias is removed and is refused at startup.

Ticketed uploads use threshold zero. `any` requires explicit operator acceptance
of incomplete holder discovery. Remove the template's `NAMESPACE_ALLOWLIST`
setting entirely when selecting `any`; even a blank setting is refused. Takedown denial and preservation still apply,
but namespace/repository/global completion cannot be inferred.

### Bindings and storage

Retain all five SQLite Durable Object classes and their migrations:
`v1` creates `RefStore`; `v2` creates `NsCoordinator`, `RefShard`,
`RepoIndexShard` and `ContentIndexShard`. Wrangler migrations provision classes;
they do not migrate unsupported pre-launch data. Each fresh SQL store atomically
creates the current `kv` table, `kv_timers` index and schema marker. Reopen
requires the current schema; wrong versions and incomplete schemas are refused.
Reset unsupported stores. A populated root without its addressing marker is
also refused; backup/timer/sharding housekeeping may precede a fresh marker.
Purge resumes only four-byte path cursors or an empty initial checkpoint.

| Binding | Class / purpose |
|---|---|
| `REFSTORE` | `RefStore`: root deployment markers |
| `NS_COORD` | `NsCoordinator`: namespace coordination |
| `REF_SHARD` | `RefShard`: ref partitions |
| `REPO_INDEX` | `RepoIndexShard`: repository and ref-name indexes |
| `CONTENT_INDEX` | `ContentIndexShard`: content indexes |
| `STORAGE` | Private R2 serving packs and extracted `objects/` |
| `BACKUPS` | Separate private R2 partition exports |
| `PRESERVATION` | Separate restricted R2 takedown evidence; required with takedown |
| `ADMISSION_HOOK` | Optional isolated hook Worker service binding, alternative to signed HTTPS |

Disable r2.dev and public bucket domains. Never apply lifecycle deletion to
serving `packs/` or `objects/`. Restrict a 35-day backup lifecycle rule to
`backups/` in `BACKUPS`; backups cannot replace preservation. Preservation
retention is enforced by the audited server timer and legal-hold arbiter;
do not install a bucket lifecycle that can bypass holds.

With `any`, namespace authority fencing is supported only for Ed25519
namespaces: Address (`0x...`) authority generation setters are not supported
under that policy. Keep that combination disabled; a supported finite allowlist
is required for Address authority administration. The intended embedding host configuration
uses Ed25519 owner/Check policy.

### Secrets and key roles

Install secrets with Wrangler's secret mechanism for the exact config/environment.
The server needs only public admin, authority and scanner keys; keep their
private signing keys offline, in an HSM, or at the dedicated counterparty.
Use fresh material for every role, including owner/write and grant keys.
Never substitute another role's key to satisfy a failed startup check.

| Name | Grammar / role |
|---|---|
| `TICKET_KEYS` | Secret: `<key-id> <64 hex>` per line; first signs upload tickets and multipart receipts, all verify; blank lines and `#` comments allowed |
| `MKIT_HOOK_KEY` | Secret: `<key-id> <64 hex Ed25519 seed>`; outgoing signed hooks, including purge |
| `URL_TOKEN_KEYS` | Secret: `active <64 hex seed>` plus `retired <64 hex public key> <retired_at_ms>` lines; HTTP bearer URL tokens |
| `SCANNER_KEYS` | Secret configuration containing 1–32 distinct non-weak Ed25519 public keys, one 64-hex key per line; incoming scanner signatures |
| `SCANNER_RETRIEVAL_KEYS` | Secret: exactly one `active <id> <64 hex MAC secret>` plus up to 15 `retained <id> <64 hex MAC secret> <retired_at_ms>` lines; assigned-pack capabilities |
| `ADMIN_KEYS` | Secret containing §16.3 version-1 key-list JSON: `keyId`, `alg=ed25519`, `publicKey`, optional validity bounds and required `roles` |
| `AUTHORITY_KEYS` | Secret: `<key-id> <64 lowercase hex public key> <namespace[,namespace...]>`; deployment authority generation setters |
| `RECEIPT_NOTICE_KEY` | Secret: bare 64-hex Ed25519 seed dedicated to preservation's receipt-and-notice role |
| `RECEIPT_KEYS` | Public configuration JSON, version 1, `keys` with `keyId` (BLAKE3 of raw public key), `alg=ed25519`, `publicKey`, optional string `notBeforeMs`/`notAfterMs`; must include the preservation signer's public key |

Role separation includes active and retained keys, MAC material and signing
public keys. Preservation key publication is required by
[SPEC-SERVER §14.7](../specs/SPEC-SERVER.md#147-preservation-store)
even though launch issues no storage receipts or completion notices.
`/.well-known/mkit-receipt-keys.json` exposes its public list when configured.
Cloud provisioning credentials `CLOUDFLARE_API_TOKEN` and
`CLOUDFLARE_ACCOUNT_ID` stay in the operator environment, not Worker vars.
A staging client's `MKIT_STAGING_SIGNER_SEED` and `MKIT_STAGING_URL` are client
credentials/settings, not server role keys.

### Feature opt-ins

| Facility | Required configuration |
|---|---|
| HTTP objects and URL tokens | `http-objects` build, `HTTP_OBJECTS=true`, dedicated `URL_TOKEN_KEYS`; `URL_TOKEN_TTL` is seconds, default 900, range 1–86400 |
| Paid HTTP reads | `HTTP_ADMIT_READS=true`, HTTP objects and `admit` hook role; retain the fetch context for response settlement |
| Binding hooks | `ADMISSION_HOOK` plus `HOOK_ROLES`; hook Worker has no public routes, workers.dev or preview URLs; binding channel is unsigned |
| Signed HTTPS hooks | `signed-http-hooks` build, `HOOK_URL`, `HOOK_ROLES`, `MKIT_HOOK_KEY`; URL is HTTPS with optional base path, no userinfo/query/fragment; cannot coexist with `ADMISSION_HOOK` |
| Hook roles and limits | `HOOK_ROLES` is a nonempty unique comma list of `authorize`, `admit`, `outcome`, `inspect`, `cache-purge`; no implicit roles. `HOOK_TIMEOUT_MS` default 5000, range 1–30000; Outcome delivery also has a 5 s bound. `HOOK_SIGNATURE_VALIDITY_MS` default 60000, range 1–300000 |
| Authorization | `AUTHORIZER_ROLE=check` (default) or `authority`; setting it requires `authorize` |
| Namespace fencing | `AUTHORITY_FENCE=true`, dedicated `AUTHORITY_KEYS`, Multi and authority Authorize; allowances carry `authority_generation` |
| Write grants | `GRANT_SCHEMES` comma list of `ed25519`, `secp256k1-eip191`, `webauthn-p256`; WebAuthn additionally requires `WEBAUTHN_RPS` as `id=origin[,origin...]` entries separated by `;` or newline. Blank/partial settings are refused |
| Inspection and scanner retrieval | `inspect` role on the selected hook channel, `INSPECT_MODE=sync`, `INSPECT_ON_UNAVAILABLE=fail_closed`, `SCANNER_RETRIEVAL=true`, `SCANNER_KEYS`, `SCANNER_RETRIEVAL_KEYS`; `INSPECT_BATCH_MAX_OBJECTS` default 10000, range 1–10000 |
| Admin, takedown and preservation | `ADMIN_KEYS`, `TAKEDOWN_ENABLED=true`, `PRESERVATION`, positive `PRESERVATION_RETENTION_MS` (no default), `RECEIPT_NOTICE_KEY`, `RECEIPT_KEYS`, and configured cache-purge delivery (signed HTTPS hook or an embedder-supplied `PurgeSink`) |
| Global cache purge | Embedders can supply `PurgeSink`; the reference Worker requires Paid, `signed-http-hooks`, `HOOK_URL`, dedicated `MKIT_HOOK_KEY`, explicit `cache-purge` in `HOOK_ROLES`; an isolated binding alone cannot satisfy it |

Successful ordinary ref-path Blob/ChunkedBlob responses select media types by
case-insensitive filename extension. MP4/WebM video, MP3/Ogg/WAV audio, HEIC
images, Markdown and CSV are served inline alongside the existing image,
plain-text and PDF types. Markdown and CSV include `charset=utf-8`; JSON stays
an attachment. HTML, HTM, XHTML, XML, SVG, JS, MJS, CSS and unknown extensions
remain `application/octet-stream` attachments. Object-id and proof responses
keep their existing types.

GET and HEAD retain encoded RFC 5987 filenames, `nosniff`, sandbox CSP and
`no-referrer`. Video playback can use a single `Range: bytes=a-b` request,
which returns 206 with `Content-Range` and the selected length; HEAD has no
body. Multiple ranges return the full 200 representation. See
[SPEC-HTTP-OBJECTS §5.1](../specs/SPEC-HTTP-OBJECTS.md#51-object-content-and-ordinary-ranges).

Zero inspectors is supported; embedders can supply up to four synchronous
fail-closed inspectors. The environment channel configures one inspector.
Each receives one complete added-pack Blob/ChunkedBlob set, surplus included,
within the whole-advance bound. PRE_RECEIVE quarantine rejects without commit.
Async, publish-on-unavailable and `INSPECT_CLEAR_DEADLINE_MS`,
`INSPECT_CLEAR_DEADLINE`, `INSPECT_DEADLINE_MS` are refused.
`UNSAFE_LOOPBACK_GRANTS` and all test-only knobs must be absent in deployment.

The private scanner route is `POST /_mkit/scanner/pack`: both a dedicated
capability and scanner auth-v2 signature are required. It returns only assigned
staged added-pack raw bytes in ranges of at most 1 MiB, with a 16 KiB request
cap and uniform 404 on failed authority, expiry, replay, ticket consumption or
global block. It grants no older-pack, write, admin or preservation permission.
The scanner independently decodes packs and needs its own authorized resolver
or cache for external delta bases. Capabilities last hook timeout + 1000 ms;
measure cold/warm retrieval, all ranges and decoding inside the actual Worker
hook timeout before enabling inspection. Failed inspection commits nothing;
retries retain the inspection id and mint fresh capabilities.

All seven operator routes require admin plus complete takedown configuration:
`Takedown`, `GetTakedown`, `ListTakedowns`, `ReadPreserved`, `SetLegalHold`,
`PurgeCache`, `ReadAuditLog`. Use canonical signed
`/mkit.server.admin.v1.AdminService/<method>` paths behind network controls.
`moderation` or `all` is required for the first six; `audit` or `all` for
ReadAuditLog. Client auth-v2 or bearer credentials confer no admin authority.
Admin responses are `no-store`. ReadPreserved freshly verifies bounded pieces
and rechecks authority/retention/ownership on retries.

The purge receiver must acknowledge with `{}` and deduplicate stable purge ids;
retries use fresh nonces. It must map the audience to the actual deployment
and invalidate all selected global variants.
A selector alone does not attach cache tags. Local cache deletion is only
colo-local; measure global convergence separately.

Only the operator runs provisioning, secret installation and deployment:

```sh
# From apps/vcs-worker, after completing config, resources and role keys:
wrangler secret put TICKET_KEYS --config wrangler.staging.jsonc --env staging
# Install each selected role secret by its name with the same config/env.
wrangler deploy --config wrangler.staging.jsonc --env staging
```

Verify GetServerInfo, signed ticketed push/clone, coherent published head and
packmap, HTTP GET/HEAD/range and token refusal/expiry, and configured admin and
scanner roles. Confirm logs do not capture payment/auth credentials. Measure
CPU, physical DO/R2/hook calls, connections, Wasm/V8/backing/transport memory,
concurrency, billing/egress and cold alarms on the deployed artifact.
No local workerd result certifies these checks.

## Embedding

Use the supported [mkit-server-worker embedding API](../../rust/crates/mkit-server-worker/README.md#embedding-supported-0x)
and [embedded Worker example](../../apps/embedded-worker/README.md).
Use the same validated config on fetch and every DO; in-process dispatch shares
the host isolate's CPU, memory and request budget. A host can supply custom
hooks, Outcome delivery, purge sink and budgeted local invalidation.
`admin_on_public_path=false` plus `serve_admin_with` supports an internal
operator mount while preserving canonical signature verification. Keep operator
ingress trusted and network-restricted; the remaining unauthenticated admin-body
lifetime issue must be hardened before offering admin to untrusted ingress.

With `takedown_denial=false`, the in-process Public reader and batch URL
issuance (`issue_urls`) can use a cached positive reachability proof. Only a
fresh walk records a proof, and a cache hit never extends it, so a ref rewind or
deletion is visible within `reachability_lag_ms` (default 60 s) of the original
proof. Configured complete takedown with fresh global denial bypasses that
cache; a programmatic denial flag alone cannot bypass preservation/purge
prerequisites.

Custom Admission and Authority/fence hooks supplied in process (declared with
`HookCapabilities`) do not require a remote hook binding or signed HTTPS channel,
including for paid HTTP reads; remote configuration is required only for roles
that use a remote channel (inspection, cache-purge signing). Admission and the
Outcome sink also see `SetRepoVisibility`, like every other mutating RPC.

Pin the git dependency to an approved immutable commit or release tag.

`pack-ruzstd` (part of `launch`) relies on a bounded-decode patch to ruzstd 0.9
that exists only in this repository's workspace `[patch.crates-io]`; Cargo does
not inherit dependency patches. A host or Worker workspace that builds with
`pack-ruzstd`, including through crates.io `mkit-core`/`mkit-server`, must
repeat it until upstream releases the fix:

```toml
[patch.crates-io]
ruzstd = { git = "https://github.com/officialunofficial/mkit", tag = "v0.5.0" }
```

Without it the build succeeds but decodes through the unbounded upstream path.
Upstream tracking: [KillingSpark/zstd-rs #124, "Refuse blocks that decode past
Block_Maximum_Size"](https://github.com/KillingSpark/zstd-rs/pull/124) is open. Keep the patch until a released
version includes the bound; the tracked PR does not establish released coverage.

## Operations

### Empty first store and rollback

First deployment, and first enablement of inspection, require an empty store.
The server does not enforce the inspection half of this: it keeps no durable
marker and refuses nothing when inspection is enabled on a store that already
holds content. Enabling inspection on a populated store is an operator error;
reset the store first, because content published before inspection was enabled
was never inspected.
Unreleased pre-launch persisted formats are unsupported: reset explicitly named
staging resources or provision fresh Worker/DO namespaces and buckets.
Do not change markers or transform old rows. Review resource identities before
resetting; production and preservation data require their retention controls.

Retain the previous approved artifact/config, secret key ids, origin and resource
map. Roll back code only to a proven compatible artifact over the same state;
otherwise keep serving offline and recover into a fresh compatible store.
Never disable global denial or drop admin/preservation/purge configuration to
make rollback succeed. Once fencing is persisted, disabling it refuses writes.
Do not change addressing, sharding or jurisdiction on existing state.

Use DO point-in-time recovery first where suitable; portable exports are
per-partition and not one consistent cut. Keep restores offline until root and
coordinator ownership, replay/grant epochs, indexes and all later denial and
legal-hold actions are reconciled. Never restore an older cut that loses current
denial or legal holds. Worker production restore administration is not supplied
by this launch; do not enable the test import route. See the
[backup restrictions](../../apps/vcs-worker/README.md#backup-and-disaster-recovery).

### Rotate keys by role

| Role | Rotation procedure |
|---|---|
| Tickets | First append the new unique id/secret as a verifier on every instance while keeping the old signer first; then promote it first everywhere. Retain old verification secrets at least seven days after the last old-key issuance, the maximum ticket lifetime |
| Hooks/purge | Publish overlapping receiver trust keys, switch outgoing signer, retain old trust through maximum envelope validity and trust-cache propagation; preserve stable delivery ids |
| Scanner retrieval | Move old active MAC to retained with its retirement timestamp; retain verification for 301000 ms. Overlap `SCANNER_KEYS`, switch the scanner's distinct signer, then remove old public keys |
| Admin | Add new role-bearing public key with overlapping validity, switch offline signer, retire old after outstanding envelope validity and replay expiry; retain audit history |
| Authority | Rotate dedicated permission keys, stop old allowances and complete the signed generation barrier before acknowledging revocation; editing the key list alone does not complete it |
| URL tokens | Switch active seed, retain old public key with retirement time through the supported token TTL and public-list cache refresh |
| Preservation | Publish overlapping public keys including the new signer, switch dedicated `RECEIPT_NOTICE_KEY`, retain historical verification keys; never delete evidence or legal holds as part of rotation |

### Outcome delivery and backlog

`OutcomeSink` delivery runs from the durable outbox after commit. Sink errors
and timeouts never roll back the commit; the refused row stays queued for a
later retry. Delivery is at least once and not ordered: a refused row does not
block later rows, which can overtake it. Deduplicate by `reservation_id` and
retain the highest per-repository `RepoStorageChanged.version`.

Monitor `mkit_server_outbox_backlog` with `unit=rows` and `unit=bytes` per
`shard_kind`. Persistent failures can trigger `OutboxBacklogCap`, whose core
default is 100,000 rows / 64 MiB per outbox. Backpressure starts only when
`rows > cap.rows || bytes > cap.bytes`; equality is still admitted. New
reservation-granting writes then return `unavailable` (HTTP 503),
`outbox backlog; retry`, and `Retry-After: 30`. Admitted HTTP-object reads return
an empty HTTP 503 without that message or retry header. A real public-to-private
visibility change remains admitted above the cap; same-value visibility requests
are not exempt. Restore the receiver and drain the queued rows to resume
admission; earlier commits remain durable.
Reconciliation can use `Pipeline::repo_storage_many` for up to
100 names in one namespace with one coordinator `get_many` and per-repository
owner authorization; missing and unauthorized names both yield `None`.

### Failure drills

Run against isolated staging, recording source/artifact/config, input geometry,
timestamps, stable ids, redacted errors, backlog and recovered results.

| Drill | Expected behavior and recovery |
|---|---|
| Hooks down | Authorize/Admit timeout, bad response or redirect fails closed without writes; preserve otherwise-authorized public-read classification rules. Outcome remains durable until acknowledged. Restore receiver and reconcile reservation ids and duplicates |
| Scanner down | Inspect unavailable/invalid verdict fails closed without commit. Restore scanner and retry; verify fresh assigned capability, bounded retrieval and expiry/block denial |
| Purge sink down | Intents remain durable and retry with backoff. Fresh global-denial/visibility checks remain authoritative. Restore sink, deduplicate ids and verify global invalidation plus audited completion; acceptance is not completion |

### Repository storage counter

A missing repository storage counter (`rb`) indicates a corrupt store: stored-bytes relays for that repository stay queued, hold the namespace relay watermark and increment `mkit_server_relay_storage_counter_missing_total`. Write `rb = (0, 0)` in the repository's coordinator to resume.

### Takedown and legal holds

1. With a moderation admin signer, submit a stable `operation_id`, named source
   repository and either 1–256 distinct Blob/manifest ids or one whole pack id.
   Keep reason private. HTTP 200 confirms every requested global denial is
   active and returns `complete=false`; retain the takedown id and audit
   reference. Interrupted activation stores retryable HTTP 503 (`unavailable`)
   with the same takedown id. Replaying the signed request or its `operation_id`
   resumes activation; replay results become HTTP 200 only after every denial
   is active. Timer 15 can also finish activation. `complete=false` describes
   the remaining preservation and takedown lifecycle, not denial activation.
2. Check public HTTP/token/pack/reuse denial, then poll GetTakedown and bounded
   ListTakedowns for acquisition, verification, discovery, retention, holds and
   purge status. Under `any`, holder discovery remains incomplete.
3. ReadPreserved only through signed, audited admin streaming. Verify canonical
   bytes and exact offsets; preservation is never a serving, dedup or delta source.
4. SetLegalHold on the action before retention expires, record its audit entry
   and confirm status. A hold suspends timed preservation purge. Release only by
   an audited SetLegalHold operation; an expired unheld record is purged by the
   audited timer. Preserve action ownership when several takedowns cover bytes.
5. Keep denial and unresolved work in place. Preservation, legal-hold release or
   purge acknowledgement does not establish full takedown completion or reinstate
   content. Rewrite, notices and reinstatement are unavailable.

For a bulk read-block emergency, install an operator-owned Cloudflare WAF
custom rule scoped to the exact serving hostname before the Worker. Cover HTTP
object GET/HEAD paths containing `/-/` and POST read RPCs (`ListRefs`, `ReadRef`,
`DownloadPack`, `PackExists`, `IssueObjectUrl`); broad hostname blocking is
appropriate when immediate total isolation is needed. Block rather than challenge
machine clients. Record the rule id, scope and incident, verify denial from
several colos, and retain operator access through separately controlled ingress.
A WAF block creates no takedown or preservation record. Reopen only after the
underlying denial and cache state are verified, with explicit incident approval.

### Publication verification limits

Publishing a ref value runs a verifier chosen by the deployment's
configuration and the ref being written (SPEC-SERVER §9.3 and §10.2). With
takedown denial off, no custom publication policy and no inspector, no
publication verifier is selected and the limits below do not apply (other
verification, ancestry, input, read and storage limits still do). Otherwise one
of these paths runs:

| Path | Selected when | Real limits |
|---|---|---|
| Resumable takedown | Takedown on, no custom policy, no inspector, and the pair has a packmap whose root pack was verified | At most 4,096 items in each of: packmap chain nodes, listed packs, pending queue, visited objects, dependencies and external delta bases. Canonical bytes are charged against the indexed decode budget (default 2 GiB, at most 8 MiB per slice). Each slice makes at most 128 metadata calls, in the foreground request and in each alarm. The whole job stops after 1,048,576 calls. Its checkpoint must fit in 520,192 bytes, which a long chain or many dependencies can reach before 4,096 items. At most 7 tickets per advance. |
| Canonical, inspected | An inspector is configured | One allowance of 256 calls shared by pair verification and dependency visibility, and a 10,000 object whole-input bound checked before any scanner runs. |
| Canonical, custom policy | A custom publication policy is configured | The 256-call canonical proof, and with takedown on a decode budget of at most 8 MiB. |
| Canonical, mapless | Tags and other refs without a packmap, or a pair whose packmap root has no verification row, with takedown on | The same 256-call proof and 8 MiB decode budget. |

From publication preparation onward, one request counts its metadata and blob
calls against a single 9,000-call allowance, failed dispatches included: preparation,
the resumable slice, dependency visibility, each denial proof, and its own
snapshot, lease, checkpoint and commit calls on every optimistic retry. Proof
work stops 64 calls short of the allowance, enough for one uncontended attempt's
settlement; contended retries keep spending the same allowance and are refused
as capacity when it is empty. The 128- and 256-call slices above are children of
the proof share, never extra allowance. Policy hooks, inspector calls and other
RPC work before preparation, authority activation inside lease reads and
full-partition prune recovery are outside this ledger; the request's physical
budgets also apply
(see Limits and acceptance boundaries). Chain growth,
dependency growth and the number of objects a head reaches consume these
allowances together, so no count of objects, pushes or files is a supported
workload size; the cliff depends on history shape, delta fanout, map depth and
the size of the denial directory.

These are availability limits, not an authorization decision. Hitting one
makes the server refuse the write with `unavailable` and the public message
`publication verification capacity exhausted` (or leave it pending,
`pack verification pending`, while bounded progress continues). The refusal is
the same whichever call the allowance ran out on. A resumable job that reaches
an unsupported historical limit records one stop and answers `unavailable` with
`publication verification limit reached` (counted by
`mkit_server_publication_limit_reached_total` on a successful foreground
checkpoint commit, label `reason`: `index_calls` or `retained_items`): that needs
operator action, not a retry. The byte limit is different: the decode budget is
charged over the whole packmap chain and reachable closure, so it is
history-scoped, but it keeps its specified errors, `invalid_argument` with
`object index limit exceeded` or `pack exceeds indexed decode budget` on the
canonical path and `pack exceeds indexed decode budget` on the resumable path
(whose 2 GiB default is cumulative over the pair). Reclassifying those as capacity needs a separate amendment of the input
contract. It never publishes
on a partial proof, moves a ref, consumes a ticket, writes membership or calls
a scanner. A resumable job that hits an unsupported historical limit ends as one
recorded stop and is not rescheduled by every alarm. A repeated refusal or a
pending state that never completes is an operational failure to investigate,
not an in-progress success, and retrying does not necessarily resolve it.

Operator rules:

- Do not enable takedown on an existing store as a configuration-only change.
  Before activation, copy the store and rehearse the representative worst
  case on the copy: the longest history and packmap depth, tags, new branches
  off the largest heads, force pushes, the real denial directory size and the
  intended custom policies. Enable takedown only if every rehearsed publication
  completes.
- Enable inspection only on an empty store. Existing content has not been
  scanned, and SPEC-SERVER §18 does not support activating inspection over it.
- Keep the deployment on a path whose limits you have rehearsed. Switching
  among these paths changes which limits apply.

### Limits and acceptance boundaries

`ListRepos` is served with the namespace-scoped authorization of SPEC-SERVER §6.2.
Worker HTTP proofs (`?proof=1`) follow SPEC-HTTP-OBJECTS §3's unsupported
profile: syntax and normal access checks precede 416, and no proof preparation,
validator, payment reservation or response stream is started. Publication
Events, async inspection, inspection holds and hold review, the namespace
catalog, edge caching, storage leases, GC and storage receipts are not
implemented. The `store::inspection_*` modules (mode marker, flags, holds) are
unintegrated groundwork for future async inspection: nothing in the server or
Worker installs or reads them. A Committed Outcome means Sent, not Delivered: D34
projections can still delay published-prefix advancement. No full-profile,
rewrite, reinstatement, notices, lease or storage-receipt claim applies.

The request body cap is 65 MiB; non-final multipart parts are at least 8 MiB,
and downloads stream in chunks of at most 800 KiB. ListRefs is paged, with
at most 2 MiB per reply; it is not an unbounded single reply.
Physical budgets remain 9000 backend / 10000 combined request calls, 960 alarm
calls plus reserved headroom, and six simultaneous outgoing response lifetimes.
Measure all nested work and retries; arbitrary host hook work shares those limits.

Whole-isolate memory is still an open acceptance gate. A local sampled
allocated-capacity sum was 104604962 bytes (about 105 MB), with attribution gaps.
The `launch` feature graph enables `pack-ruzstd`, which reserves the
server-local pure-Rust decoder scratch and releases the idle pack reader before
delta decoding. Run the focused allocator regressions on the actual deployment
graph before candidate selection; bounded core decoding alone does not establish
the verification allowance. This is separate from preservation's acquisition
allowance.
Scheduled preservation's Rust allowance is 48 MiB after #1263's latest-base
retention change. This per-acquisition bound does not certify
fit in a 128 MB isolate once JS, transport and overlap are counted. Measure
cold/warm near-1-MiB canonical delta members through 50 hops, largest admitted
source/compressed frames, acquisition alarms and slow ReadPreserved streams,
with overlapping uploads/reads and mixed due alarms at concurrency 1/2/3/4/6.
Capture synchronized per-isolate Wasm/V8/backing/transport high-water, retention,
cancellation and memory-limit errors. Keep gaps visible; process RSS and sums
across different isolates cannot certify headroom.
