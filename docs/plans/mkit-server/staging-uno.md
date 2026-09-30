# Uno staging environment definition (D35)

Status: **SKELETON — pending final contracts and user execution** (WP-1.20,
R-195, R-198). This is a resource and role inventory, not a deployable config.
No resource, secret, route or deployment is created by this document.

[R-185 and D35](00-plan.md) place staging before the single Uno launch.
R-198 requires resetting unsupported pre-launch stores rather than migrating
them. The existing [WP-1.19 template](../../../apps/vcs-worker/staging/wrangler.staging.jsonc.template)
and [runbook](../../../apps/vcs-worker/staging/README.md) describe historical
Stage 2 timing; their post-REL-1 and optional-Free instructions do not govern
this launch. Final WP-1.20 will reconcile them after WP-4.18.

## Deployment identity and profile

D35 selects `staging-vcs.mkit.sh` on the `mkit.sh` zone, in the same account as
the other mkit workers, using `env.staging` of `vcs-worker`. Use a distinct
staging Worker identity and DO namespaces, private staging buckets and one
dedicated CI Ed25519 signer. Only that signer's namespace is allowlisted.
Staging data has no retention promise and may be reset by the user.

| Setting | Uno launch requirement | Current contract / finalizing lane |
|---|---|---|
| Origin | `AUTH_AUDIENCE=https://staging-vcs.mkit.sh`; exact canonical origin | Existing adapter grammar; routes and origin verification finalized in 4.18 |
| Addressing / sharding | `ADDRESSING=multi`, `SHARDING=d34` | Existing deployment markers; never change them over existing state |
| Namespace admission | `NAMESPACE_POLICY=allowlist`, `NAMESPACE_ALLOWLIST=<dedicated CI namespace>` | Existing grammar; no open namespace policy |
| Account plan | `WORKERS_PLAN=paid`, actual Workers Paid account | Paid-only launch; 4.18 validates profile. CPU allowance remains user-owned and unfilled |
| Indexed serving | Scheduled verification, extraction, HTTP objects and native/core proofs (Worker proofs 4.14b-2 are a post-launch follow-up, R-200) | 4.10b and 4.14b-1; 4.18 activates the release build. Current release adapter refuses `INDEXED_MODE`; test builds are not production activation |
| Storage leases | Off | 5.4 launch spec amendment; 4.18 config and discovery. Existing epoch leases and authority fencing remain separate |
| Serving retention | Permanent | 5.4 / 4.18; no lifecycle deletion of packs or extracted `objects/` |
| Serving-store GC | Off; enabling GC in indexed mode refused | R-198 B4; 4.18 validates. No post-launch GC machinery in this skeleton |
| Inspection | Synchronous PRE_RECEIVE only (R-200): `pass`, `reject` (a `quarantine` is rejected), fail-closed when unavailable; async inspectors and publish-on-unavailable are refused | 5.5a (sync scope). R-193 owns scanner byte retrieval; 4.18 activates. Async inspection, holds and review ops are follow-up 5.5c |
| Publication Events | Not at launch (R-200): with sync-only inspection every advance publishes at apply, so `Committed` means delivered | 5.15 is a post-launch follow-up |
| Lean takedown | Immediate global denial, verified restricted preservation, retention/legal holds, audited review; requests can remain unresolved | 5.6a owns concrete operations and normative exception; 4.18 activates. No rewrite, 451 notices or reinstatement claim |
| Uploads | Ticketed uploads with threshold zero; measured pack/decode/concurrency limits | Final grammar and limits in 4.18; user fills staging sizing evidence |

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
Final alarm handlers and consistent configured fetch/DO entrypoints are 4.18's.

| R2 purpose | Existing binding / resource name | Contract |
|---|---|---|
| Serving packs and extracted objects | `STORAGE` / `mkit-vcs-objects-staging` | Private; no lifecycle deletion of `packs/` or `objects/`; extraction finalized by 4.10b |
| Portable partition backups | `BACKUPS` / `mkit-vcs-backups-staging` | Private; existing template's 35-day lifecycle applies only to `backups/`; backups are not preservation |
| Published ref snapshots | `PUBLISHED_SNAPSHOTS` / `mkit-vcs-published-staging` | Private; binding alone does not activate snapshots; inspected published sources finalized by 5.4 / 5.5a / 4.18 |
| Preservation | Separate restricted staging bucket/keyspace; binding and resource name **pending 5.6a** | Never serving, dedup or delta input. Access only through audited ReadPreserved; explicit retention and legal holds |

Disable public bucket access. Optional jurisdiction must match across R2 and
DOs and stay fixed; optional placement is recorded with the final config.
An isolated deployment must carry a fresh published-view identity. Final
4.18 / WP-1.20 records exact artifact digest, compatibility date, config digest,
resource identifiers and all limits before the user operates staging.

## Keys, secrets and receiver roles

Names below refer to configuration contracts, never actual values. Keep private
keys in the approved secret store and record only key ids / public fingerprints.
Do not reuse keys across roles. A receiver's TLS certificate or cloud access
token does not replace mkit message authentication.

| Role | Server configuration / possession | Counterparty / remaining owner |
|---|---|---|
| CI write/read signer | Only its namespace in `NAMESPACE_ALLOWLIST`; private seed is `MKIT_STAGING_SIGNER_SEED` in the approved CI secret store | User owns CI signer; it grants no scanner, admin or preservation permission |
| Tickets and multipart receipts | `TICKET_KEYS` secret: one `<key-id> <64 hex>` entry per line; first signs, all verify | Dedicated random 32-byte MAC secrets; existing [rotation contract](upload-key-rotation.md) |
| Signed outgoing hooks | `MKIT_HOOK_KEY` secret: `<key-id> <64 hex seed>`; `HOOK_URL` HTTPS, `HOOK_ROLES`, timeout and signature validity | Receiver trusts public hook key list under SPEC-SERVER §7; existing `signed-http-hooks` opt-in includes Inspect. Each call has a fresh hook nonce; Event role by 5.15; 4.18 integrates |
| Optional isolated hook binding | `ADMISSION_HOOK` service binding instead of `HOOK_URL` | Mutually exclusive channels; unsigned exception only for the isolated nonpublic §7.3 channel. It does not authorize a public scanner route |
| Deployment authority fence | `AUTHORITY_FENCE=true`, `AUTHORITY_KEYS` configured public key list with namespace permissions; private signer stays with Uno operator | Existing 2.16 contract requires `AUTHORIZER_ROLE=authority` and authorize hook. 4.18 decides final profile wiring |
| Incoming scanner | `SCANNER_KEYS`: newline-separated 64-hex Ed25519 public keys; private keys stay with scanner. `SCANNER_RETRIEVAL_KEYS` secret: one `active <key-id> <64-hex secret>` plus optional `retained <key-id> <64-hex secret> <retired_at_ms>` lines | R-193: `POST /_mkit/scanner/pack` requires a dedicated retrieval MAC capability and scanner auth-v2 signature with server-origin audience and exact body/path/repository binding. Only raw added packs in the capability; global blocks always deny. Default-off native `--scanner-retrieval` / Worker `SCANNER_RETRIEVAL=true`, Paid-only and activation refused before 4.18. Missing/conflicting keys and configured role reuse refuse startup; no Workers Caching or cache headers |
| Admin | Dedicated public admin key list, §16.3 JSON with roles; private signing keys offline / HSM | Config name and Worker mount **pending 5.11a / 4.18**. `audit` for ReadAuditLog; `moderation` for review and ReadPreserved; never client bearer/write/hook authentication |
| Purge sink | CachePurge is signed with a deployment **hook** key under §7, to the sink's canonical audience; sink trusts its configured public key list | Sink endpoint/binding and config names **pending 5.10 / 4.18**. No new purge-signature domain or admin key reuse. Manual PurgeCache is **5.6a**, asynchronous with purge id and audited completion |
| URL tokens | Dedicated `URL_TOKEN_KEYS` secret and optional `URL_TOKEN_TTL`; existing HTTP feature grammar | Separate active/retained keys; neither var mounts HTTP routes. 4.18 activates |
| Preservation signing | Explicit preservation retention, dedicated §15 receipt-and-notice signing key and published §15.5 key list | Required by §14.7 even for lean takedown; exact bindings/config **pending 5.6a / 4.18**. This requirement does not enable storage receipts or notices |

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
Scanner global-denial checks prefetch up to eight shards' first descriptor
pages concurrently, retaining at most 4 MiB of raw descriptor values,
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
latency and resource use on the actual deployment profile; production
activation remains off pending that gate.
Scanner deployment also needs its independent authorized
resolver or retained cache for external delta bases (§11.4).

Future staging automation uses only secret names `CLOUDFLARE_API_TOKEN`,
`CLOUDFLARE_ACCOUNT_ID`, `MKIT_STAGING_SIGNER_SEED` and variable
`MKIT_STAGING_URL`. The user supplies scoped credentials; this early subset
adds no workflow and invokes no API. Final 1.20 is user-operated against already
deployed staging. Its workflow stays main-only, with no automatic provisioning
or deploy and no feature-branch dispatch workaround.
