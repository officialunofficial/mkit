# Stage 2 staging activation (WP-1.19)

This directory is an inert template and runbook. Nothing provisions, deploys,
mounts routes, enables snapshots or modifies the Stage 1 app. Perform the
following operations **after REL-1**, on an approved Stage 2 deployment change.
The normal `wrangler.jsonc` and app entrypoints remain the Stage 1 defaults.

## Prepare the deployment

1. Choose the staging hostname/zone and canonical HTTPS audience. Obtain a
   scoped Workers/R2 token; keep it out of the repo. Create a dedicated CI
   signing key and derive its canonical namespace with mkit. Allowlist that
   namespace only; never enable `UNSAFE_OPEN_NAMESPACES`. Install the CI key in
   the approved secret store, not a config file.
2. Copy `wrangler.staging.jsonc.template` to
   `apps/vcs-worker/wrangler.staging.jsonc`. Replace every `REPLACE_*` value.
   Use `ADDRESSING=multi`, `SHARDING=d34` and the exact audience origin.
   The v1/v2 SQLite migrations retain all five DO classes. Use a fresh
   deployment; addressing/sharding markers refuse conversion over old data.
3. Confirm the account plan before choosing `WORKERS_PLAN`. The template's
   `paid`/100 ms allowance is a starting point requiring CPU measurements.
   Never set Paid's 10 GB DO cap on a Free account. A Free deployment must
   explicitly select `free` and establish that CPU fits its account limit;
   the local probe does not establish this. Subrequest accounting retains
   relay 32 + backup 1 + outcome 8 + rollup 8, and anonymous snapshot reads
   use at most 49 calls plus one reserved read-hook call.
4. Provision three separate private R2 buckets named in the template. Disable
   r2.dev and public custom domains on all of them. `PUBLISHED_SNAPSHOTS` is
   mutable ref data, distinct from packs and portable KV backups. Install a
   **35-day** lifecycle rule restricted to `backups/` in the backup bucket;
   never apply it to packs. Keep backup force reupload at 28 days or less.
   Match R2 and DO jurisdiction, if specified; leaving placement hints unset
   is the default. Jurisdiction cannot change over the deployment lifetime.
5. Install `TICKET_KEYS` using Wrangler's secret mechanism with this copied
   config and `--env staging`. Use the adapter's `id=64-hex-characters` format;
   generate a fresh random 32-byte key and unique key id. Do not print it or
   put it in vars. The template intentionally contains no ticket secret.

## Activate the explicit snapshot entrypoints

The `PUBLISHED_SNAPSHOTS` binding alone cannot enable snapshots. In the Stage 2
app change, add the dependency feature `mkit-server-worker/published-view` and
call `adapter::fetch_configured(req, env, published_config)` from the fetch
entrypoint. Each DO constructor uses
`adapter::ns_object_configured(state, &env, class, published_config)` instead
of `ns_object`; preserve each class and its existing alarm delegation. Create
one consistent programmatic config for both fetch and all DO entrypoints:

```rust
PublishedViewConfig::new("staging-UNIQUE-DEPLOYMENT-ID")?
```

Use a fresh identity when changing deployments, and dedicated snapshot storage
when changing DO identity/jurisdiction. There is no enabling environment var.
Unsigned ReadRef stays off (`unsigned_read_ref=false`); signed reads go live.
If inspection is configured, set `inspection_configured=true`: snapshot
publication is disabled and reader values fail closed until WP-5.4/5.5 supplies
published sources. Never substitute live rows under inspection.

Run the feature-on/off wasm gates and local conformance before the deployment
change. R-175 records the local optimized workerd/V8 probe: 42.45 ms sampled
active time/request (13.62 ms Wasm), 128 refs/page over 928 long refs; this is
not a Free production CPU certification. Measure **deployed** ListRefs cache
hits/misses/expired/oversize fallback, quiet/burst snapshot alarms with backup,
and multipart completion across representative and worst-case pack sizes.
Choose the account CPU allowance and `MAX_PACK_BYTES` from those measurements
before mounting the route. The starting pack cap is 1 GiB; the hard ceiling
is 4.995 GiB. Do not infer completion CPU from snapshot timings.

After provisioning, secret installation, activation review and CPU sizing,
build from `apps/vcs-worker` and deploy with the copied config and
`--env staging`. Mount only the chosen staging hostname, with workers.dev and
preview URLs disabled. No public raw snapshot route exists. WP-1.20 owns later
CI wiring; nothing here adds a feature-branch trigger or deploy job.

## Verify and operate

- Confirm GetServerInfo, authenticated push/clone and paged anonymous ListRefs
  on a public test repository. Poll eventual listings after pushes; healthy
  staleness is relay lag + 1 s debounce + 1 s Cache TTL, with no hard relay SLA.
  Snapshot validity is 60 s and quiet refresh 30 s. Missing/expired/malformed
  or oversized buckets go live. Configured pages cap at 128 refs and 2 MiB.
- Verify a signed listing bypasses snapshots, a private repository never
  publishes/serves one, and public→private immediately denies new anonymous
  reads after the authoritative authorization check. Timer cleanup can lag;
  it is not the authorization boundary. Check that signed ReadRef and push
  CAS remain strong. Re-run wire conformance with the staging URL and CI
  signer using the existing conformance client (WP-1.20 automation follows).
- Watch the existing storage-pressure, relay-lag and failure logs. Investigate
  70%/90% SQLite pressure, relay backpressure, snapshot publication failures,
  CPU-limit errors and backup cap warnings. RefIndex alarms allow one snapshot
  fire and at most eight external calls, including backup across all heads.
  Retained snapshot bodies cap at 512 KiB; row/decode/merge retention is tested
  below 2 MiB. Local timings cannot validate R2/DO placement or PITR.
- To disable snapshots, revert to the unconfigured fetch/DO entrypoints and
  remove the Stage 2 feature/binding in the reviewed deployment change.
  Authorization remains authoritative. Previously seeded kind-10 timers are
  retained with backoff by unknown-kind handling; arrange reviewed offline
  administrative cleanup rather than assuming they are deleted. Do not mutate
  sharding markers.
  Obsolete R2 snapshots can then be removed through scoped operations.

## Backup and restore

Use DO point-in-time recovery first for incidents within its retention window.
Portable kind-4 KV logs are separate from published-view snapshots: the latter
are disposable and cannot restore authoritative state. Check daily exports
under `backups/v1/mkit-vcs-worker-staging/`, their digest and retention, and
record partitions that exceed the bounded export cap (16 MiB default).

For an offline recovery beyond PITR, select a complete compatible set of one
`.kvlog` per partition, then use the native export-directory layout and
`mkit-server restore --meta sqlite:<NEW PATH> --from <DIR> --sharding d34`.
Per-partition exports are not a consistent cut. Restore advances grant epochs;
owners reissue grants. Keep the destination offline until missing-source,
coordinator and index reconciliation checks pass. Production Worker in-place
restore/PITR administration is WP-5.11b; never enable the local `test-faults`
import route. See the parent [backup runbook](../README.md#backup-and-disaster-recovery)
for incomplete-set restrictions and outstanding recovery work.
