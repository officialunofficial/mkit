## Purpose
Replace extraction's unbounded R2 finalization path with backend multipart completion whose exact selected part identities, lengths/CVs and content root are verified before the final object becomes globally visible. Preserve current ticketed pack upload/public primitives while adding the safe bounded object extraction seam.

## A. Fixed
SPEC-SERVER9.6/13 and R163; root-verified sink semantics; object IDs differ from rawcontent hashes. Slice uploading alone is insufficient: existing complete_with rereads all stagedparts into one finalPUT. No global visibility before validated expected length and BLAKE3 rawcontent root. AlreadyPresent advisory only; no dedup/existence/pricingoracle or repo-access assumption. Native/server/core publicwire/goldens remain, indexed exposure defaultoff/Paid-only and forthcoming4.10b256call/48MiB bounds fixed.

## B. Root decisions
B1. Add minimal backend ObjectBucket/EnvBucket/model multipart primitives and versioned server-owned session/part identities as required. Validate actual R2 complete semantics: selected immutable ETags/parts, replacements, abort, duplicatecomplete, lostreply/sessiongone, object-key conditional/dedup race and metadata. Never claim ETag is an integrity proof. Only server-verified streamed bytes produce trusted partCV/length receipts; exact selected bytes must remain bound to those facts through recovery and completion. If selectedpart replacement invalidatescompletion, failclosed/recover freshverifiedfacts, not trust staleCV. Internal session access cannot become client authority to publish arbitrary objects.
B2. Bind session to namespace/key/objectID/contentroot/partgeometry and operation/hold identity. Each completion validates deterministic chosen part list, indices, exactlengths, fullgeometry/CV merge/root and immutablepartidentities BEFORE finalbackendvisibility. Forged metadata/replayedwrongsession/wrongkey/wrongroot/missing/reordered/duplicateparts close. Optional perpart/root verification APIs cannot provide unchecked public commit bypass. Session metadata/CV caches are versioned, bounded and guarded; serialize competing writers or use conditional/version observations. GenericcallerclaimedCV is not authenticated source evidence.
B3. Bounded finalization must avoid rereading/retaining every stagedpart. Count metadata/partlookups/backendcalls/retries and bound residentbuffer. Expose precise operation accounting for4.10b wholealarm. Tests measure partcountgrowth, finalizationcalls/residentbytes, cancellation and failedroot nevervisible. Keep sourceverification/dedupcharging decisions with4.10b driver, not invented here. Existing pack multipart semantics and maxadvertisements unchanged; do not reducecaps to fit tests.
B4. Existing immutable finalobject/dedup/concurrentcomplete cannot overwrite another verified object or publish unverifieddata. Backendcomplete lacksconditionaloptions: if safety relies on allwriters deterministicverifiedbytes under the samecontentidentity, document/enforce that invariant and test competingdifferentroots/partreplacement. If library/backend cannot guarantee verify-before-visible, STOPwith concreteAPI/source evidence; no unbounded finalPUTfallback masqueradingboundedcompletion.
B5. Update registry to add4.10b-multipart as explicit prerequisite of4.10b, alongside4.8/nativeextraction foundation. R186 remains parentextraction, R192 thisprerequisite; R191Workerproofs andR183–190 reserved. Add spec/versionhistory only where normativeimplementation contracts change; docs/invariants/changelog describe exactenforcement. No extraction/holder/gp/takedown behavior claimed complete by thisPR.

## C. Executor choices
Trait/module layout, compactversioned receipts/sessioncodec, native model support and instrumentation. Keep deepprivate implementation ratherthan spill cryptographic/backend state into productflow. Record API guarantee evidence and allA/B checklist choices in PRbody.

## D. Escalate
Verify-before-visible or immutable selectedpart binding cannot be guaranteed; backend API requires server-buffered finalfile; cap1500 exceeded; existing upload/publicadvertisement semantics would narrow. Preservecoherentcheckpoint/report; request rootsplit/ruling, never weakenroot/length/oracle checks.

## Tests/gates
Red→green models show oldfinalization's linear reread work; actual localWorker runtime validates newbackendmultipart flow where Miniflare supportsit, with explicit skippedunsupportedAPI limit ratherthan fabricatedcloudsuccess. Valid multipart/completeroot and existingnative/Worker uploads; wrongCV/root/length/order/duplicatepart/key/session, deterministicpartreplacement/competingcompletion,abort/restart/lostreply/SessionGone, AlreadyPresent and conditionaldedup races, stale receipts nevervisible; countcalls/peakresident versus many parts. ExistingFs/S3/memory semantics preserved if traitdefaultseams touched. Commonfreshlocalgates plusjustci-server, focusedWorker/R2modeltests, lockedwasmClippy --no-deps andactualWorkerbuild/appropriatewireprobe,fmt/docs/scripts/security. Independenttwo-passselfreview root-scheduled; cleancommittree/openPR withmeasuredcaps andunrunuserstaging/optionalMinIO honestlylisted. No ownmerge/fullreviewergatereruns.

### Backend contract investigation (2026-09-30, not implemented)

Installed worker0.8.5 r2/mod.rs389–437 documents concurrent abort/complete,
uses UploadedPart(partNumber,etag), and makes the object globally visible on
complete. Official R2 Workers API reference agrees; complete has no conditional
options and ETag is not a BLAKE3 proof:
https://developers.cloudflare.com/r2/api/workers/workers-api-reference/

Proposed additive object-only API pins the full ordered CV plan and expected
raw-content root before any part upload. The extraction driver first computes
this in bounded source slices (repository-local verification/charging stays its
responsibility). Immutable metadata binds key, geometry, root, operation/hold
and CV plan. Any slot write must match its pinned CV and exact length, using a
depth-one stream with final byte withheld until verification. Competing retries
therefore write the same verified bytes; backend ETag only selects that receipt.
Completion validates metadata/ordered tags/CV merge before backend complete,
with no part rereads. Existing ticketed-pack staging remains unchanged.

Object-id to canonical raw-root binding is a trusted verifier responsibility
shared with existing complete_with_root/commit_with_root APIs; storage must not
expose these methods as an unauthenticated object publication endpoint. New
session binding will reject changed roots/CVs for an existing operation and
wrong key/session receipt reuse. Investigation of cross-operation root conflict
and lost-reply recovery is still in progress; no enforcement claim yet.

### Implementation checkpoint before independent fence delta review

Object-only R2 API now pins key/rawroot/geometry/fullCVplan/operation in immutable
server metadata before backend uploads. Per-slot sinks stream through the
existing depth-one channel/final-byte withholding, verify actual CV/length and
revalidate session before releasing a receipt. Completion validates ordered
receipt CVs/session binding, geometry and root before backend completion. The
root/length pin is also enforced by legacy R2 object single-PUT and multipart
writers; public PACK completion recovery remains unchanged. Metadata remains
conservatively after abort; replacement attempt must use a new operation id.
No source authorization, extraction/gp/holder or launch activation is claimed.

Tests: initial missing-API regression red, then all6 bounded_object_multipart
model tests green with --test-threads=1 (backend-regressions.log). Covers absent
untilcomplete, forged CV/binding/root/key/session/index/length/order/count,
wrongactualpartbytes, replacedstaleETag, freshreceipt recovery, duplicatecomplete,
restart, abort, legacyrootconflict and lostcompletionreply. Completion has5
backend operations and2metadata reads regardless of2/5parts; measured additional
hostheap below1MiB, excluding simulated remote storage allocations by provenance.
Fmtcheck and gitdiffcheck pass. All owned processes terminal.

PENDING before final PR: review/apply correctness and API design refinements;
actualwasm compile/lint and actuallocalR2 multipart probe; explicit concurrent
session creation/root conflict/part completion and corruption tests; partial
body/cancel/replacement tests, maxgeometry/receipt size bounds; full oldpack/R2
regression surface. Add operation accounting docs, registry/R192/invariants/
CHANGELOG updates and exactproductionlinecount. Run required common/area gates,
integrate fresh feature tip, root-scheduled independent selfreviews, push/openPR.
No cloud/CI/staging calls. Parent extraction aaaf6e45 remains paused in its tree;
its first bounded source pass must compute root/CVplan, charge every repository
source on miss/dedup/replay and count all physicalreads/CPU plus metadata/backend
operations. Parent caps256calls/slice and48MiB stay fixed; fullselection and
protection/relay scope remain unfinished.


## Runtime and resource refinement

Actual local workerd/Miniflare returned a171-byte uploaded-part ETag, disproving
an initial63-byte assumption. Object completion now uses a separate bounded
VerifiedObjectPartRef (opaque ETag up to1024bytes, tag up to1089); public PACK
PartRef128 remains unchanged. Larger unsupported backend tags fail closed.
Local isolated R2 probe passed17checks, including absent-before-completion,
wrongroot refusal and exact completed2part bytes; evidence directory
~/.cache/mkit-test-tmp/wp-4-10b-multipart/http-mount-probe-2631. No cloud run.

At maximum10000slots, worst-case tags total10,890,000bytes and selected backend
strings10,240,000bytes. Two maximum metadata buffers add4,194,304bytes; CV arrays,
Vec headers and bookkeeping add under2MiB. Rust-side resident bookkeeping is
therefore below28MiB, excluding caller/source payload and runtime JS copies.
The boundsgolden tests maximum JSON encoding (all255CVbytes) under2MiB.
No maximum-geometry runtime JS peak is claimed; parent must account runtime
copies and source buffers in its48MiB whole-slice budget at actual geometry.
Metadata work does not grow in number of calls with parts: finalization has
sessionGET, existingrootpinGET, finalHEAD, backendcomplete=4operations;
failed/lostreply adds oneHEAD (5). ExistingAlreadyPresent returns after
HEAD (3). An absent rootpin adds conditionalPUT+confirmationGET: pre-upgrade
existingAlreadyPresent uses5; absentobjectCreated uses6, lostreply7. Exact
existingrootpins avoid metadataPUT/429 during retry; concurrent absentpin
publication recovers only when the observed immutable bytes match. Root merge/receipt validation is O(parts)CPU,
not O(payload), and receipt+plan storage is O(parts).

Legacypre-upgrade objects need not have rootpin metadata. Their head-only reuse
is safe under the trusted canonical verifier objectID→onecorrectrawroot invariant
across all writers, NOT because creating a new pin authenticates old bytes.
Rootpins coordinate new claims; the parent first source pass must validate that
canonical relation and immutable source evidence even on dedup/replay. Storage
presence alone never confers repository membership or skips source charging.


## Executor review checklist (before independent peer review)

A/B1: root verification precedes visibility; backendcomplete has no conditional
options, selected ETags are receipts, pinned actual CVs make every permitted
same-slot replacement byte-identical. Real local R2 probe exercises workers-rs
0.8.6; model tests additionally cover stale/replaced receipts and concurrent
completion. Public PACK paths and receipt128 contract remain separate.
B2: immutable operation metadata binds exact objectpath/root/length/partgeometry/
CVplan; versioned receipts bind raw metadata hash and slotCV. Actual streamed
bytes verify before the finalbyte is released. Corrupt version/UTF8/oversize/
key/root/context/geometry/order/count fail closed. Server-owned source identity
validation is a documented parent prerequisite, not a claim this storage seam
independently derives canonical objectIDs.
B3: finalization has constant backendcall count and O(parts), not O(payload),
CPU/metadata memory; payload never reread. Max10000slot JSON and receipt limits
have explicit encoding/allocation bounds; measured2/5part finalization adds
under1MiB hostheap. This measurement excludes backendstorageallocations and
unrelated parallel tests by provenance/isolation. Parent runtimeJS/source
budget proof remains mandatory and is not replaced by the Rust bound.
B4: every legacyR2 objectwriter pins after verification and before finalvisibility;
competingfirstroots select one claim, sameoperation creators select one session,
loser aborts only its own private backendsession. Existingcanonicalobjects
without pins recover advisorypresence, never repository authorization.
B5: registry explicitly adds4.10b-multipart→4.10b, R192row, invariant andchangelog.
No extraction/gp/holder/relay/activation implementation is claimed here.

Self-review fixed the actual opaqueETag size mismatch and existingrootpin429
retry regression. The global heapmeter tests now isolate unrelated testpayloads
while protocolrace tests retain real concurrent futures/backendthreads. Source
and productionbehavior review are complete locally; independentroot-scheduled
peer reviews remain required before openingPR. Gates are recorded below only
once terminal; staging/deployment/remoteR2 and optionalMinIO are not claimed.

## Terminal executor gate evidence

- just ci-server:2351/2351passed,8optional skips; wasm builds/checks and CLIbaseline green.
- Final Worker nextest --all-features:294/294passed,0skips after test instrumentation/lint refinements.
- Workspace all-target/all-feature lockedClippy -Dwarnings and lockedwasm Clippy --no-deps:green.
- ci-scripts, ci-security, spec-status, fmt workspace+standalonefixture and diffcheck:green.
- RUSTDOCFLAGS=-Dwarnings Worker rustdoc:green; allfeature Worker doctests:0tests/pass.
- Local release vcs-worker conformance:84pass,0fail,131profile skips; concurrent coldstart30/30SERVING.
  Evidence: ~/.cache/mkit-test-tmp/wp-4-10b-multipart/vcs-worker-conformance.SmmZKY.
- Local R2+HTTP bridge probe:17checks passed, including actual verified2part completion.
  Evidence: ~/.cache/mkit-test-tmp/wp-4-10b-multipart/http-mount-probe-7242.

The older unisolated cargo-test run failed the process-wide heapmeter because
parallel fixtures allocated source payloads; nextest process isolation and the
explicit fixture mutex preserve meaningful heap bounds. No assertion was relaxed.
An earlier in-flight server compile overlapped the rootpin correction and used
mixed snapshots; the subsequent frozen-source server gate and finalWorker gate
supersede that run. No deployment, remoteR2, staging or optionalMinIO run is claimed.
All executor-owned gate processes are terminal. Independent peer review is pending.
