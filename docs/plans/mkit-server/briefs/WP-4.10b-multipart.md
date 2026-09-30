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
