# Workers operator guide

The Paid Workers launch profile serves indexed repositories with D34 sharding
and Multi addressing. Repository content has permanent retention, storage
leases are off, and serving-store GC is off and refused in indexed mode.
Inspection is optional and synchronous. Lean takedown supports immediate global
denial, restricted preservation, legal holds and audited administration; an
accepted request can remain unresolved. See [SPEC-SERVER §18](../specs/SPEC-SERVER.md#18-conformance-scope).

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
they do not migrate unsupported pre-launch data.

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

The cached Public in-process reader and batch URL issuance (`issue_urls`) with
`takedown_denial=false` have an open reachability-refresh defect: repeated cache
hits can extend stale authorization and bearer HTTP reads after ref rewind or
deletion. Keep those affected configurations disabled until corrected and
verified against the original invalidation deadline. Configured complete
takedown with fresh global denial avoids that cache path; a programmatic denial
flag alone cannot bypass preservation/purge prerequisites.

Custom paid HTTP Admission and Authority/fence hooks currently require remote
hook configuration, including an external binding or signed HTTPS channel, even
when supplied in process.
Keep those configurations disabled until that validation defect is corrected;
custom write admission with free public reads is the exercised example.

Pin the git dependency to an approved immutable commit until a release tag exists.

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

### Failure drills

Run against isolated staging, recording source/artifact/config, input geometry,
timestamps, stable ids, redacted errors, backlog and recovered results.

| Drill | Expected behavior and recovery |
|---|---|
| Hooks down | Authorize/Admit timeout, bad response or redirect fails closed without writes; preserve otherwise-authorized public-read classification rules. Outcome remains durable until acknowledged. Restore receiver and reconcile reservation ids and duplicates |
| Scanner down | Inspect unavailable/invalid verdict fails closed without commit. Restore scanner and retry; verify fresh assigned capability, bounded retrieval and expiry/block denial |
| Purge sink down | Intents remain durable and retry with backoff. Fresh global-denial/visibility checks remain authoritative. Restore sink, deduplicate ids and verify global invalidation plus audited completion; acceptance is not completion |

### Takedown and legal holds

1. With a moderation admin signer, submit a stable `operation_id`, named source
   repository and either 1–256 distinct Blob/manifest ids or one whole pack id.
   Keep reason private. The intended acceptance contract activates every
   requested global denial and returns pending `complete=false`; retain the
   takedown id and audit reference. An open replay defect can return stored HTTP
   200 after interrupted activation while some requested denials remain inactive.
   Its correction and regression evidence are required before candidate selection.
   Until corrected, verify every requested denial and use the emergency WAF
   isolation procedure when needed; successful replay alone proves no such check.
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

### Limits and acceptance boundaries

There is no list-repos RPC. Worker HTTP proofs (`?proof=1`) are unsupported and
not advertised. Publication Events, async inspection, inspection holds and hold
review are post-launch. A Committed Outcome means Sent, not Delivered: D34
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
The current launch and Paid Workers feature graphs omit the server-local pure-Rust
decoder scratch reservation and idle-reader release. Correct those actual
deployment graphs and run their focused allocator regressions before candidate
selection; bounded core decoding alone does not establish the verification
allowance. This defect is separate from preservation's acquisition allowance.
Scheduled preservation's Rust allowance is 48 MiB after #1263's latest-base
retention change. This per-acquisition bound does not certify
fit in a 128 MB isolate once JS, transport and overlap are counted. Measure
cold/warm near-1-MiB canonical delta members through 50 hops, largest admitted
source/compressed frames, acquisition alarms and slow ReadPreserved streams,
with overlapping uploads/reads and mixed due alarms at concurrency 1/2/3/4/6.
Capture synchronized per-isolate Wasm/V8/backing/transport high-water, retention,
cancellation and memory-limit errors. Keep gaps visible; process RSS and sums
across different isolates cannot certify headroom.
