# Paid launch conformance (WP-4.18 / R-194)

Status: **phase 2 authorized; complete matrix UNRUN**.
Available prerequisite integration can proceed. Preservation core #1249 and
the restricted admin catalog 5.6a-3 (#1251) are merged. The user authorized
configured Takedown/GetTakedown/ListTakedowns/ReadPreserved/SetLegalHold plus
PurgeCache/ReadAuditLog. Activation requires admin, preservation, denial,
indexed work and signed purge configuration; the core catalog's default
activation flag remains false. Adapter wiring and actual runtime results
require separate verification. Extraction
#1244 and private scanner retrieval #1243 have merged; their release wiring
is wired here. Bounded publication recheck timer 12 progress repair #1245 has
merged. Physical alarm bounds/backoff #1247 and deterministic native timer
conformance #1248 are merged at the phase 2 input checkpoint. Rerun timer/alarm
checks without prior native flake exceptions. This document certifies no staging or review gate.

The resolved header ruling adopts merged #1246. Successful ordinary ref-path
files select Content-Type and inline/attachment disposition from the fixed
extension allowlist, including HEAD and 206. They include a sanitized ASCII
filename and an octet-preserving encoded `filename*`, with nosniff and the
sandbox CSP. Object-id file responses remain `application/octet-stream`;
non-file objects, native proofs, 304, and errors retain their specified policy.
Byte content is never sniffed. Header ruling resolution is not runtime evidence.

The launch selects Paid indexed Multi/D34 with permanent retention, leases
off and GC refused. HTTP objects, signed hooks, inspection and admin/takedown
are optional complete configurations. Inspection accepts zero to four sync
`fail_closed` inspectors, one complete batch each, with no clear deadline.
The R-200 inspected set contains every added-pack Blob and ChunkedBlob entry,
surplus included and ids deduplicated. Manifest decoding supplies chunk
membership; the server does not add a full-profile inspection tree walk.
An inspection deployment starts from an empty store. No inspection holds,
hold reviews, async inspector lifecycle, publication Events or Worker proof
generation are launch cases. Native proofs remain required.

## Reproduction driver

The checked-in [case inventory](launch-cases.json) itemizes B4 and B5 and the
B3 request/alarm requirements. `native` and `worker` in that file are source
and component coverage landmarks. `phase2` states the required integrated
probe, not an assertion that the probe already exists. Its matching evidence
slots are [launch-evidence.md](launch-evidence.md).
The [runtime coverage plan](launch-runtime-coverage.md) distinguishes existing
component checks from the proposed actual release probes for all 28 cases,
including the pending R-203 round trip and four separate restricted admin cases.

From a clean, committed candidate in this worktree:

```bash
export TMPDIR="$HOME/.cache/mkit-test-tmp/wp-4-18"
mkdir -p "$TMPDIR"
export CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
export VCS_CONFORMANCE_PORT=18818 VCS_HOOKS_STUB_PORT=18819
# CARGO_TARGET_DIR must be unset; select ports unused by other executors.
bash scripts/vcs-worker-launch.sh validate
bash scripts/vcs-worker-launch.sh plan
bash scripts/vcs-worker-launch.sh native --sha "$(git rev-parse HEAD)"
bash scripts/vcs-worker-launch.sh baseline --sha "$(git rev-parse HEAD)"
bash scripts/vcs-worker-launch.sh hooks --sha "$(git rev-parse HEAD)"
bash scripts/vcs-worker-launch.sh authority --sha "$(git rev-parse HEAD)"
bash scripts/vcs-worker-launch.sh release-launch --sha "$(git rev-parse HEAD)"
```

`validate` checks the inventory without compiling or starting any service.
`plan` prints its coverage and runnable component commands. Executable lanes
require the full current SHA and a clean tree, private nonsymlinked scratch
directory and worktree-local build target. Each writes an evidence JSON with
candidate/tree/base/origin SHAs, command/log hashes, timestamps and actual
component exit status. Logs and local state remain in the printed directory.
It does not record environment values or production secrets. The release
fixture uses public dummy ticket/token keys and an empty isolated local store.
The driver invokes no deploy, cloud API, workflow or staging operation and
stops only processes it starts.

| Lane | Actual command / evidence boundary |
|---|---|
| `native` | Locked all-feature nextest of core, native, Worker adapter and conformance, serialized for shared-machine memory. Includes component/native HTTP proofs. It does not claim a release Worker run |
| `baseline` | Existing real `vcs-worker-conformance.sh --multi -- --filter info.` on the default-off release artifact; deployment discovery only |
| `hooks` | Component smoke: existing real `vcs-worker-conformance.sh --hooks -- --filter info.` plus M3 service-binding hook suite and actual wasm Fetch/Delay probes. Its signed runtime wrapper uses **test-faults**; full opted-in release signed exchanges remain phase 2 work |
| `authority` | Existing `vcs-worker-authority.sh --authority` against an actual release Worker and isolated binding fixture |
| `release-launch` | Builds `worker-build --release --features launch`, runs local pinned wrangler with `LAUNCH_PROFILE=uno`, Paid indexed Multi/D34, `any` unsafe flag and HTTP/token opt-in. Verifies discovery, token key mount and absence of the test-faults route. Inspection and admin/takedown are off in this lane |
| `full` | Refused until R-203 and the complete per-case actual release probes. The configured restricted admin catalog is available. A component suite exit zero cannot pass the integrated matrix |

The release-launch discovery lane verifies threshold zero, leases/async false,
no inspector-bound field when inspection is off, and no proof claim. It does
not certify byte serving, `?proof=1` refusal on a reachable object, extraction
payloads, scanner isolation, paid response lifetimes or takedown. Those remain
explicit phase 2 rows. Reusing the default `--indexed` test-faults script alone
cannot fill them. The native server must advertise and serve proofs; release
Worker proof requests must remain unsupported.

## Phase 2 execution

1. Merge the exact prerequisite versions and record every full SHA, PR and
   independent review outcome. Integrate configured preservation and the
   merged 5.6a-3 admin catalog; enable the decoder only after R-203. The branch includes #1247 and #1248; rerun
   timer/alarm checks without the prior native flake exceptions and report any
   failure. A new flake classification still needs unchanged-base evidence.
2. Complete the itemized release probes in [launch-cases.json](launch-cases.json):
   optional no-inspector baseline; HTTP/token reads; signed HTTPS and isolated
   binding hooks; sync inspection plus R-193 retrieval; admin/takedown with
   complete §14.7 preservation and signed HTTPS cache-purge. Both `allowlist`
   and `any` plus its unsafe flag run; `any` must report discovery incomplete.
3. Run native and actual release wrangler rows at the immutable candidate.
   R-193 retrieval authorizes assigned immutable **raw pack ranges**, for
   staged added packs, rather than public object URLs. External delta bases
   need an independently authorized scanner resolver or local cache; a grant
   does not expose prior packs or base objects. Scanner
   proof reads use at most six ongoing responses (up to 3 MiB first-page data
   with 512 KiB pages, within the 4 MiB raw bound). Verify every expired,
   replayed, foreign, terminal and globally blocked request's uniform denial.
   No launch held-object retrieval scenario is claimed.
4. Count physical routed DO/R2/Fetch calls, retries and response lifetimes for
   complete requests and alarms. Preserve 256-call/48 MiB extraction slices,
   100-op/seven-ticket applies, six outgoing connections, bounded cold-head
   scans and explicit headroom. Refer to [launch-budgets.md](launch-budgets.md).
   Frozen-clock and simultaneous due-kind tests must prove progress as well
   as an upper bound. Cold-head bounding and fairness use the separately
   reviewed, merged #1247 repair; pin its exact version in integrated evidence.
   Component review does not supply actual release runtime evidence.
   HTTP settlement must retain the request's waitUntil
   lifetime and durable completion/reconcile arbiter after disconnect.
5. Run all common/full/area gates, then two independent self-reviews. Record
   exact case pass/fail/skip counts and log hashes. Any deterministic local
   gap blocks complete matrix PASS. Leave external review/staging/resource
   measurement slots UNRUN; they are user-owned.

An unchanged-base flake record includes full baseline SHA, exact command,
initial failure log and up to three isolated reruns, with their actual results.
Do not fix an unrelated native timer flake in this activation lane or turn
an unexecuted test into an accepted skip. Phase 1 remains a committed checkpoint;
the PR opens only after phase 2's prerequisites and gates complete.

## Restricted admin runtime cases

The [5.6a-3 contract](WP-5.6a-3-contract.md) supplies four distinct cases in
addition to Takedown and the shared admin authentication/replay/audit case.
Run them on configured native and actual release Worker mounts; all remain
UNRUN until their command, named assertions and log hashes are retained.

| Case | Required runtime assertions |
|---|---|
| `B4.admin-get-takedown` | Status separates acquisition pending, historical verification, discovery, legal hold and purged copies; unknown ids and role denials leak no preserved bytes. `any` never claims complete discovery or real completion |
| `B4.admin-list-takedowns` | Absent/null/empty scope lists all; repository and namespace scopes are normalized and token-bound. Page size is 1–100, scans inspect at most 100 root rows and 256 KiB record JSON, and tokens are at most 2 KiB. Empty filtered pages may continue; foreign/malformed tokens are refused |
| `B4.admin-read-preserved` | Each retry rechecks current key/role, retention and ownership and audits acceptance; no replayed payload. Verify each bounded owner-framed piece before release and recheck after I/O. Exact ordered offsets, one final piece, empty final piece at size, and errors without a success final piece are observable on the Connect stream. Audit failure and cancellation release no unauthorized bytes; responses are no-store |
| `B4.admin-set-legal-hold` | Set/clear uses current ownership/state/deadline guards and commits hold effects, audit and terminal nonce atomically. Reason/operator-label bounds are 512/128 UTF-8 bytes. Replay is audited, stale holds cannot seize purge-owned work, and held copies cannot be purged; failed apply leaves no mutation |

Exercise both public and host-only admin placement, every configured role and
fresh/replayed/in-flight signed requests. Keep Reinstate and inspection hold
review operations unexposed. Count paged status reads and each preserved-piece
poll in the same request allowance; contract bounds are not memory measurements.

## Phase 2 embedding addenda

The saved brief's embedding addenda are assigned to phase 2, with the final
production-line cap of 3,500. `B4.embedding`
remains UNRUN until the supported 0.x API, combined DO builder for custom
Outcome/purge sinks and publication config, admin host entrypoint/placement,
programmatic ref-policy/takedown knobs, generated DO glue or documented
cross-crate pattern, and embedded-worker example are implemented. Preserve
`publish = false`, git/release-tag pinning and CHANGELOG treatment of breaking
API changes. Verify the constructed request's auth envelope uses the exact
WorkerConfig audience regardless of its local URL. An in-process streamed
UploadPart must pass actual wrangler, sharing the host isolate's CPU, memory
and subrequest budget. Measure raw/gzip release wasm for each feature variant;
fill the [README slots](../../../apps/vcs-worker/README.md#embedding-api-phase-2-in-progress).
No ListRepos protocol addition is included.
