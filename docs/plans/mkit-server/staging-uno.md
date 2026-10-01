# Uno staging environment definition (D35)

Status: **FINAL DEFINITION — actual staging and sign-offs UNRUN / user-owned**
(WP-1.20, R-195). As-built checkpoint `c3921b06`, not the launch candidate.
Use the [standalone operator guide](../../operations/workers.md) for deployment grammar.
This resource and measurement inventory is not a deployable config.
No resource, secret, route or deployment is created by this document.

[R-185 and D35](00-plan.md) place staging before the single Uno launch.
R-198 requires resetting unsupported pre-launch stores rather than migrating
them. The existing [WP-1.19 template](../../../apps/vcs-worker/staging/wrangler.staging.jsonc.template)
and [runbook](../../../apps/vcs-worker/staging/README.md) remain inert; the runbook
now points to the complete Paid launch profile. Staging precedes user launch
acceptance; no version bump or tag is part of the Workers launch.

## Deployment identity and profile

D35 selects `staging-vcs.mkit.sh` on the `mkit.sh` zone, in the same account as
the other mkit workers, using `env.staging` of `vcs-worker`. Use a distinct
staging Worker identity and DO namespaces, private staging buckets and one
dedicated CI Ed25519 signer. The Uno Kit demo (UNO-420) uses
`NAMESPACE_POLICY=any` with `UNSAFE_OPEN_NAMESPACES=true`. An isolated CI
deployment may instead allowlist that signer's namespace.
Staging data has no retention promise and may be reset by the user.

| Setting | Uno launch requirement | Merged contract / execution owner |
|---|---|---|
| Origin | `AUTH_AUDIENCE=https://staging-vcs.mkit.sh`; exact canonical origin | Merged adapter grammar; user verifies deployed origin |
| Addressing / sharding | `ADDRESSING=multi`, `SHARDING=d34` | Existing deployment markers; never change them over existing state |
| Namespace admission | `allowlist` with a nonempty `NAMESPACE_ALLOWLIST`, or `any` with `UNSAFE_OPEN_NAMESPACES=true` and `NAMESPACE_ALLOWLIST` absent; Uno Kit demo selects `any` | Under `any`, takedown works but holder discovery is incomplete; report that limitation (5.6a-2) |
| Account plan | `WORKERS_PLAN=paid`, actual Workers Paid account | Paid-only launch; 4.18 validates profile. Provisional `limits.cpu_ms=60000`; validate per-invocation CPU in staging |
| Indexed serving | Scheduled verification and extraction; optional HTTP objects; native/core proofs (Worker proofs 4.14b-2 are a post-launch follow-up, R-200) | 4.10b-2 and 4.14b-1; `LAUNCH_PROFILE=uno`, `INDEXED_MODE=true`. Extraction #1244 and activation #1259 are merged; test builds are separate evidence |
| Storage leases | Off | 5.4 launch spec amendment; 4.18 config and discovery. Existing epoch leases and authority fencing remain separate |
| Serving retention | Permanent | 5.4 / 4.18; no lifecycle deletion of packs or extracted `objects/` |
| Serving-store GC | Off; enabling GC in indexed mode refused | R-198 B4; 4.18 validates. No serving GC activation at launch |
| Inspection | Optional, zero to four inspectors. Synchronous PRE_RECEIVE only (R-200): `pass`, `reject` (a `quarantine` is rejected), fail-closed when unavailable; async inspectors, publish-on-unavailable and clear deadlines are refused | 5.5a (sync scope). R-193 retrieval #1243 and activation #1259 are merged. Async inspection, holds and review ops are follow-up 5.5c |
| Publication Events | Not at launch (R-200). Inspection completes synchronously, but D34 dependency projections can leave publication pending. `Committed` means Sent and does not prove publication or Delivered | 5.15 is a post-launch follow-up |
| Lean takedown | Optional with admin plus complete preservation and signed HTTPS cache-purge. Immediate global denial, verified restricted preservation, retention/legal holds, audited administration; requests can remain unresolved | All three 5.6a parts and activation #1259 are merged. No rewrite, 451 notices or reinstatement claim |
| Uploads | Ticketed uploads with threshold zero; measured pack/decode/concurrency limits | `MAX_PACK_BYTES` defaults to 1 GiB, ceiling 4.995 GiB; 65 MiB request cap and 8 MiB non-final multipart minimum. User fills sizing evidence |

Sync-only inspection leaves no durable obligations or holds, so the launch has
no persisted inspection-mode marker (R-200). The marker, async obligations and
`WaiveObligations` arrive with follow-ups 5.5a-0 and 5.5c. Do not advertise incomplete capabilities in GetServerInfo.

## Bindings and storage isolation

These five existing class exports and binding names come from
[vcs-worker](../../../apps/vcs-worker/src/worker_impl.rs) and its
[config](../../../apps/vcs-worker/wrangler.jsonc). Repeat every environment
binding explicitly; use staging instances, never production state.

| DO binding | Class | Role |
|---|---|---|
| `REFSTORE` | `RefStore` | Root deployment markers / Single compatibility surface |
| `NS_COORD` | `NsCoordinator` | Namespace coordinator |
| `REF_SHARD` | `RefShard` | Ref partitions |
| `REPO_INDEX` | `RepoIndexShard` | Repository and ref-name index partitions |
| `CONTENT_INDEX` | `ContentIndexShard` | Content index partitions |

Keep the existing Wrangler class declarations (`v1` / `v2` SQLite classes).
These provision classes; they do not authorize migrating pre-launch rows.
Merged #1259 wires alarm handlers and consistent configured fetch/DO entrypoints.

| R2 purpose | Existing binding / resource name | Contract |
|---|---|---|
| Serving packs and extracted objects | `STORAGE` / `mkit-vcs-objects-staging` | Private; no lifecycle deletion of `packs/` or `objects/`; extraction merged in #1244 |
| Portable partition backups | `BACKUPS` / `mkit-vcs-backups-staging` | Private; existing template's 35-day lifecycle applies only to `backups/`; backups are not preservation |
| Published ref snapshots | `PUBLISHED_SNAPSHOTS` / `mkit-vcs-published-staging` | Private; binding alone does not activate snapshots; configured inspection disables snapshot optimization |
| Preservation | `PRESERVATION`; separate restricted staging bucket, resource name chosen by operator | Never serving, dedup or delta input. Access only through audited ReadPreserved with configured admin and takedown; explicit retention and legal holds |

Disable public bucket access. Optional jurisdiction must match across R2 and
DOs and stay fixed; optional placement is recorded with the final config.
An isolated deployment must carry a fresh published-view identity. User staging records exact artifact digest, compatibility date, config digest,
resource identifiers and all limits before the user operates staging.

## Keys, secrets and receiver roles

Names below refer to configuration contracts, never actual values. Keep private
keys in the approved secret store and record only key ids / public fingerprints.
Do not reuse keys across roles. A receiver's TLS certificate or cloud access
token does not replace mkit message authentication.

| Role | Server configuration / possession | Counterparty / remaining owner |
|---|---|---|
| CI write/read signer | Namespace is allowlisted under `allowlist`; demo `any` admits every self-certifying namespace. Private seed is `MKIT_STAGING_SIGNER_SEED` in the approved CI secret store | User owns CI signer; it grants no scanner, admin or preservation permission |
| Tickets and multipart receipts | `TICKET_KEYS` secret: one `<key-id> <64 hex>` entry per line; first signs, all verify | Dedicated random 32-byte MAC secrets; existing [rotation contract](upload-key-rotation.md) |
| Signed outgoing hooks | `MKIT_HOOK_KEY` secret: `<key-id> <64 hex seed>`; `HOOK_URL` HTTPS, `HOOK_ROLES`, timeout and signature validity | Receiver trusts public hook key list under SPEC-SERVER §7; existing `signed-http-hooks` opt-in. Inspect role uses R-193; publication Event role is post-launch; 4.18 integrates |
| Optional isolated hook binding | `ADMISSION_HOOK` service binding instead of `HOOK_URL` | Mutually exclusive channels; unsigned exception only for the isolated nonpublic §7.3 channel. It does not authorize a public scanner route |
| Deployment authority fence | `AUTHORITY_FENCE=true`, `AUTHORITY_KEYS` configured public key list with namespace permissions; private signer stays with Uno operator | Existing 2.16 contract requires `AUTHORIZER_ROLE=authority` and authorize hook. Merged #1259 wires the profile |
| Incoming scanner | `SCANNER_KEYS`: newline-separated 64-hex Ed25519 public keys; private keys stay with scanner. `SCANNER_RETRIEVAL_KEYS` secret: one `active <key-id> <64-hex secret>` plus optional `retained <key-id> <64-hex secret> <retired_at_ms>` lines | R-193: `POST /_mkit/scanner/pack` requires a dedicated retrieval MAC capability and scanner auth-v2 signature with server-origin audience and exact body/path/repository binding. Only raw added packs in the capability; global blocks always deny. Default-off native `--scanner-retrieval` / Worker `SCANNER_RETRIEVAL=true`, Paid-only and integrated by 4.18. Missing/conflicting keys and configured role reuse refuse startup; no Workers Caching or cache headers |
| Admin | Dedicated public admin key list, §16.3 JSON with roles; private signing keys offline / HSM | `ADMIN_KEYS`; `audit` for ReadAuditLog, appropriate dedicated moderation/preservation roles for takedown/ReadPreserved. Never client bearer/write/hook authentication. No hold review or Reinstate mount |
| Purge sink | CachePurge is signed with a deployment **hook** key under §7, to the sink's canonical audience; sink trusts its configured public key list | Signed HTTPS `cache-purge` hook required when takedown is enabled. Isolated binding alone cannot satisfy that opt-in. No new purge-signature domain or admin key reuse. Manual PurgeCache is **5.6a**, asynchronous with purge id and audited completion |
| URL tokens | Dedicated `URL_TOKEN_KEYS` secret and optional `URL_TOKEN_TTL`; existing HTTP feature grammar | Separate active/retained keys; HTTP serving requires `HTTP_OBJECTS=true` and an `http-objects` build. Keys alone leave routes off. 4.18 activates |
| Preservation signing | Dedicated `PRESERVATION` bucket, explicit positive `PRESERVATION_RETENTION_MS`, secret `RECEIPT_NOTICE_KEY` and published `RECEIPT_KEYS` | Required by §14.7 even for lean takedown; merged 5.6a-2 core is wired in 4.18. Restricted operator endpoints are wired from 5.6a-3. This requirement does not enable storage receipts or notices |

Use [SPEC-SERVER §§7, 14.7 and 16](../../specs/SPEC-SERVER.md) and the final
merged key matrix as authority. Missing admin/preservation contracts
are integration work, not permission to substitute another role's key.

Scanner capabilities use the opaque versioned `r1` codec in SPEC-SERVER §11.4.
`SCANNER_RETRIEVAL_KEYS` starts with exactly one active line and accepts at
most 15 retained lines. Key ids are unique, 1–32 characters of
`[A-Za-z0-9._-]`; retirement times are unsigned canonical decimal Unix
milliseconds. `SCANNER_KEYS` accepts 1–32 distinct, non-weak public keys.
Blank lines and whole-line `#` comments are ignored in both settings.
Each Inspect call mints a fresh capability, including retries with a stable
inspection id. Its lifetime is the hook timeout plus 1,000 ms, at most
301,000 ms, and every requested pack's bound tickets are read afresh: apply
consumption, terminal close or ticket expiry ends access. Fail-closed
attempts leave tickets open and remain readable only until capability expiry.
Use bounded ranges of at most 1 MiB; larger packs cannot be fetched in one
response. Retain old capability verification keys for 301,000 ms after
rotation on every instance. Neither capability nor scanner key grants
write, admin or preservation-read access.
The route bounds its complete shared denial/ticket/blob call budget at
8,500 backend operations; Worker adapter work fits within the existing
9,000-call invocation ceiling. Request bodies are capped at 16 KiB and
pack response bodies at 1 MiB. Inventory proof paging uses the existing
verified metadata; the route does not decode or classify pack entries.
Scanner global-denial checks prefetch up to six shards' first descriptor
pages concurrently, retaining at most 3 MiB of raw descriptor values
(within the 4 MiB contract ceiling),
plus bounded key, cursor and collection overhead.
Continuations and nested inventory, chunk and action proofs remain sequential
with their existing limits. All checks are fresh; existing serving callers
remain serial.

At 4.18, measure cold and warm global-denial proof latency and all ranges
needed to decode each pack against the actual Inspect timeout before
activation. Worker `HOOK_TIMEOUT_MS` remains 5,000 ms by default and at most
30,000 ms; the native/core 300,000 ms retrieval timeout ceiling does not
raise that Worker limit. Host tests exercise the production Worker DO/R2
adapters with two-pack independent decoding and range reads. Local mounted
diagnostics included capability expiry and a runtime restart, and establish
no production timing or mounted-scanner conformance claim. At 4.18, measure
latency and resource use on the actual deployment profile; production inspection acceptance remains UNRUN / user-owned pending that gate.
Scanner deployment also needs its independent authorized
resolver or retained cache for external delta bases (§11.4).

Future staging automation uses only secret names `CLOUDFLARE_API_TOKEN`,
`CLOUDFLARE_ACCOUNT_ID`, `MKIT_STAGING_SIGNER_SEED` and variable
`MKIT_STAGING_URL`. The user supplies scoped credentials; this docs preparation
adds no workflow and invokes no API. Staging is user-operated against already
deployed staging. Its workflow stays main-only, with no automatic provisioning
or deploy and no feature-branch dispatch workaround.

## Local activation checkpoint

`LAUNCH_PROFILE=uno` requires Paid indexed Multi/D34 and ticket keys;
`RETENTION=permanent`, `STORAGE_LEASES=false` and `GC_ENABLED=false` are fixed.
HTTP objects, hooks, inspection and admin/takedown are opt-ins, validated as
complete configurations at startup. URL-token, scanner retrieval, admin,
authority, ticket, hook and preservation keys have distinct roles and cannot
be substituted. See the [app grammar](../../../apps/vcs-worker/README.md#paid-uno-launch-profile-wp-418--r-194).

Extraction (4.10b-2 / #1244) and retrieval (R-193 / #1243) are merged
and are wired by merged 4.18 (#1259). Preservation core (5.6a-2 / #1249) is
configured without the old startup refusal; restricted operator endpoints
use 5.6a-3 / #1251. The launch build enables R-203’s bounded pure-Rust zstd decoder; the default build keeps it off.
The [local launch harness](../../../scripts/vcs-worker-launch.sh) records exact
SHAs and isolated runtime logs. The [requested Uno matrix](launch-read-failure-evidence.md)
passes locally at its pinned source; broader historical
[evidence slots](launch-evidence.md) retain their scope and remain unrun until
executed. See [final readiness](launch-readiness.md) for reviewed source changes
and open items. Local wrangler supplies no deployed CPU, cost or multicolo result.

## Explicit CPU allowance

Set `limits.cpu_ms = 60000` on the launch Worker and its staging environment.
A local workerd inspector profile of the exact Uno two-part upload recorded
28.224 seconds of active V8 samples across the complete upload/verification/
publication sequence (30.502 seconds profiled wall time); the final AdvanceRefs
response took 17.290 seconds of wall time. The whole-sequence samples guide
provisional headroom; they do not establish a per-invocation CPU upper bound.
The 60-second setting provides more than twice that sampled active time. Verification remains alarm
sliced; no slice, call, memory, or pack limit changes. Local development does
not enforce deployed CPU limits; record per-invocation CPU on staging before
launch, as required by the [Cloudflare CPU documentation](https://developers.cloudflare.com/workers/observability/dev-tools/cpu-usage/).

A subsequent direct-runtime run bracketed the final heavy AdvanceRefs fetch
with OS-accounted workerd process CPU: **17.17 seconds CPU versus 18.03 seconds
elapsed**, sampled every 50 ms with 10 ms CPU resolution. This includes all
workerd threads, internal storage isolates and concurrent alarms; it is not
deployed per-isolate accounting. The earlier pending polls each used 0.01–0.10
seconds of bracketed process CPU. These measurements support the provisional
60-second allowance without changing alarm slicing. See the
[completed local Uno matrix](launch-read-failure-evidence.md) for pins and limits.

## Whole-isolate memory gate

The local 104,604,962-byte sampled allocated-capacity maximum is not a peak
certificate: only 154 of 1,667 samples identify the user module, with 27 gaps.
The admitted preservation profile permits 51 MiB of retained canonical delta
chain plus a 16 MiB source frame and bounded decoder scratch inside its 96 MiB
Rust allowance. That phase and concurrent request buffers can plausibly exceed
the shared 128 MB isolate limit once JS, transport and allocator capacity count.
The 48 MiB verification allowance and 96 MiB acquisition allowance remain fixed.

Before accepting memory headroom, stage the exact final Uno artifact/config and
record its source, Wasm, configuration and runtime pins. Preserve a valid
50-hop chain with near-1-MiB canonical members and the largest admitted source
frames/compressed windows; exercise Takedown through the acquisition alarm and
streamed ReadPreserved. Repeat cold and warm, with two slow streamed UploadPart
or public-read responses active and mixed due verification/purge/Outcome alarms.
Record per-isolate memory high-water across Wasm linear capacity, V8 heap,
backing/embedder storage and transport buffers, including retained capacity after
completion; attribute every module/isolate and retain memory-limit outcomes.
Use allocation/phase high-water instrumentation alongside platform telemetry so
unobserved transient peaks cannot become a passing sampled maximum. If the
combined peak cannot fit with headroom, decide a shared resident-work admission
or retention change before user launch acceptance; do not raise the project allowances.
