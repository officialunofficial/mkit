# Executor prompt: WP-5.6a (launch scope), lean takedown (R-190, R-198, R-200). Can start now.

Run locally in `<repo>`.

**Definition of done:** an open PR into `feat/mkit-server`. Don't merge it.

**Read first:**
- `<local notes>`, including the R-198 section;
- `<local notes>`, including R-200;
- the base brief, `<local notes>`: sections A, B1–B7, C, D, the tests
  and the ct handoff contract;
- `<local notes>`, for mechanisms only.

**This prompt wins over the base brief where they differ.** Ignore the base brief's "QUEUED" line and its
HANDOFF/gpt/root wording.

**Setup:**
- **Worktree:** `.claude/worktrees/wp-5-6a`, from a fresh `origin/feat/mkit-server`. It already includes 5.4
  (#1235) and 5.10/5.11a (#1236).
- **Branch:** `mkit-server/wp-5-6a-lean-takedown`.
- **PR title:** `feat(server): lean global denial and verified takedown preservation (WP-5.6a)`.
- **Cap:** 3,000 non-test lines. Your first commit copies this prompt plus the base brief, from "Purpose" on, to
  `docs/plans/mkit-server/briefs/WP-5.6a.md`.

## Changes to the base brief (decided)

1. **Launch inspection is sync-only (R-200), so there are no inspection hits and no holds at launch.**
   - Drop the 5.5a hit consumer and the hold review ops: `ReleaseHold`, `Reinspect`, `ReleaseFlag`, `ResumeServing`
     and `WaiveObligations`. They are follow-up 5.5c.
   - Keep a documented intake seam so 5.5c can feed hits in later.
2. **Admin-initiated takedown is in scope; it is the main source at launch.** Add an audited admin `Takedown`
   operation on the 5.11a framework (signed, role `moderation`, replay-safe). It takes:
   - a repository and object ids, or a whole pack;
   - a reason;
   - an operation id.

   It installs an independent V2 block action with immediate global denial on every surface (B2), starts verified
   preservation (B4), and records a request that is honestly unresolved (B7). Uno's contract needs this
   (`uno-api` contract tests e20–e21).
3. **The launch admin catalog:**
   - `Takedown` (new);
   - `PurgeCache`: manual, asynchronous (R-198 B5). It returns the purge id; completion is visible in the audit log.
     Reuse 5.10's purge intents and timer 11.
   - `GetTakedown`, `ListTakedowns`, `ReadPreserved` and `SetLegalHold`;
   - `ReadAuditLog`, which already exists.

   No reinstatement, notices or rewrite.
4. **The 4.10b late-holder consumer (ct records, timer 13)** comes from 4.10b-1, which isn't merged yet.
   - Build everything else first against the merged base.
   - If 4.10b-1 merges before you finish, merge the base and implement the consumer per the base brief's ct handoff
     contract.
   - If it hasn't merged, open the PR anyway. Leave the consumer as a documented seam, and list it as a carry-forward
     in the PR body. I'll schedule it.
5. **Allocations:**
   - R-190 is yours.
   - New timer kinds or key tags need my ruling. Propose them, with evidence, before you use them. You may choose
     key tags inside an existing tag's subkey space.
   - No pre-launch compatibility. V1 blocklist rows written by current producers must keep denying; there is no
     migration from older builds.
6. **Preservation storage** needs a binding or keyspace template only; the user provisions it. No cloud calls.

## Escalate

The base brief's section D, plus: if global denial can't cover a real surface without a cross-partition protocol,
stop and report.

## Gates

The base brief's gates, including wasm32 clippy and the vcs-worker default conformance on a free port. Do the
self-review, then open the PR.

---

## Purpose
Consume durable inspection/late-holder takedown requests; immediately deny blocked content globally, preserve verified canonical bytes under restricted admin access, and leave requests honestly unresolved until post-launch completion work. Prepare the authorized normative launch exception and concrete review/retention operations.

## A. Fixed
SPEC-SERVER §§11,13,14,16,18 plus HANDOFF §4.8/R185. Independent V2 action sets, every-surface denial, verified preservation, explicit retention/legal holds and audited review are launch scope. Rewrite,451 notices,reinstatement are follow-ups. No rewrite/tombstone-only/no-op action may falsely resolve a hit. Specs win; needed authorized lean-profile amendment belongs this PR with version-history/R190. Do not amend unrelated full-profile obligations.

Launch is indexed, serving/inspection without storageleases, permanent serving retention, GCoff and Paid-only. Preservation-retention purge is separate from serving-store GC and remains mandatory. Keep epoch/authority fences, guarded observations, NotAfter, active-shard discovery, content sequence/holders/holds and relay watermarks. GCoff never waives protection.

## B. Root decisions
B1. Idempotently consume5.5a hit/request identity and4.10b late-holder durable request seam. Preserve flaggedIDs, reason, inspector/advance/op correlation and retained roots. V2 blocklist records independent active action identities; migrate existingV1 without losing denial. Overlapping requests cannot replace/remove another action. Future named-action removal/reinstatement seam is explicit but no unsupported operation exposed now.
B2. Enforcement covers every decoded pushed file, extraction/dedup, external delta base and chain intermediates, AlreadyPresent, serving bytes/proofs, index writes, snapshots, tokens, relay holder delivery and caches. Denial applies globally including writers. Absent and blocked answers remain uniform404/absent where specified, no global-CAS existence oracle; mutation denials follow existing fixed generic block rules, never disclose foreign repository facts. Atomically fence planning/apply and holder delivery against concurrent block installation. ContentIndex c guards, pendinggp protection and conservative accounting remain valid. Late holders retain durable takedown work, not an ignored block flag.
B3. Manifest takedown records verified canonical chunk IDs with its action; repository-specific containing-pack/chunk stops must not globally block shared chunks merely because one manifest is blocked. Validate all IDs/kinds and parent context through repo-local canonical sources. Never treat extracted raw bytes as canonical serialized Blob/manifest. Complete holder discovery and conservative deployment sweep/watermark seams remain durable/resumable; incomplete reads cannot claim all repositories or completion.
B4. Preservation is a restricted keyspace separate from serving/dedup/delta/GC. Canonical bytes, IDs, kinds/sizes, manifest+chunks, takedown/reason/time, holder discovery and per-repo affected old packs/known signer metadata must be verified and durably bound before success claims. Record acquisition/discovery progress if completion metadata is not yet available; mark unresolved, never invent final holders-at-completion. Existing-source corruption/no member source/missing chunk fails closed while denial persists. Separate preservation/admin credentials; bytes never enter public caches, hooks logs or errors. Required storage provisioning is user work; build adapters/templates, do not provision buckets or call cloud APIs.
B5. Explicit preservation_retention has no default, retain_until = takedown time + duration with checked arithmetic. Legal hold suspends audited timed purge. No age-only cleanup that drops legal holds, incomplete verification or pending retention transitions. Timer/rows/checkpoint recovery must be bounded; ask root for new IDs before allocating. Crash during preservation/purge/legalhold update remains retryable and never resurrects denied bytes. Keep §14.7 signing-key/public-list startup requirements unless a precise normative contradiction requires root ruling; do not silently waive them because notices are deferred.
B6. Launch supported admin/review catalog: ReleaseHold,Reinspect,ReleaseFlag,ResumeServing,WaiveObligations,PurgeCache,GetTakedown,ListTakedowns,ReadPreserved,SetLegalHold,ReadAuditLog. Reuse5.5a implementations for firstfive,5.10/5.11a for purge/audit; finish4 takedown/preservation operations here. Preserve exact signed admin roles/key separation/replay, audit every authenticated result/read/failure and automatic transition/purge. ReadPreserved streams ordered bounded offsets with exactlyone last, authorizedadmin only; failclosed endedretention and unknown record. Legal hold release restrictions and concurrent purge guarded. Do not addReinstate/notice operations or fulladminCLI as launch scope. If directTakedown/AddBlock administrative creation is necessary for normative supportedsubset, report to root before adding catalog scope; inspector/late-holder consumers are in scope.
B7. Normative amendment explicitly permits unresolved lean launch requests and distinguishes immediate denial/verified preservation/request acceptance from repository/global takedown completion. Full-profile rewrite/index substitution/tombstones/notices/physical-deletion requirements remain. Hits block publication until real applicable completion; readviews/retained advances neverrewound orfalsecleared. Advertisements/GET status disclose actual pending/completed state; no inspection capability activated before4.18. Update5.6 aggregate/splits dependencies accurately, remove unnecessary5.2/4.18 implementation cycles, keep final activation dependency on all launch work. Amend R108/R131/R163/R169/R175/R178 only where final concrete seams require; R190,CHANGELOG,invariants and schema versionhistory are required.

## C. Executor decisions
Versioned request/action/preservation codecs, bounded discovery/preservation queues, native/Worker adapter shape, key namespace selection and metrics. Root allocates all newR/timer/key identifiers. Document exact op/call/resident bounds and allA/Bacceptance evidence in PRbody.

## D. Escalate
Global deny cannot cover a real reuse/read/write surface; manifest sharedchunks would require global chunk blocking; no verified canonical preservation source; unavoidable incomplete metadata claimed final; audit/retention/legalhold guarantee unavailable; cap3000 exceeded. Propose additive split with root allocation. Never pull rewrite/notices/reinstatement into launch or weaken immediate denial/preservation to fit cap.

## Required tests/gates
Native+actualWorker every-serving/reuse surface/caller/cache variant, HEAD/range/304/proof/URLtoken, push surplusfile and chainintermediate sources, AlreadyPresent/dedup no-oracle parity; block-plan/finalapply/lateholder/delay>TTL/deleting races; overlappingV1/V2 actions/migration; manifest sharedchunks; restart after each durable request/denial/preservationboundary; canonical bytes/root/kinds/missing/corruptsources; restrictedadminreads/retentionexpiry/legalhold and concurrentpurge; signer/role/mixedcredential/replay/audit chain failure boundaries; review cannotreleaseactivehit/takedown; unresolved request neverclearsadvance; retainedroots and falsecompletionprevented; stale snapshot/purgefailure authoritativefences; measuredbounded queues/alarms anddefault-off regression. Common localgates,justci-server,wasmClippy --no-deps,currentWorkerbuild+focusedwireconformance,script/security/docs/fmt. Userrealstaging/externalreview separateunrun gates. Root-scheduled independent reviews then cleancommit/openPR.


## Concrete extraction handoff contract (R-186 / centrally reserved ct)
The 4.10b holder consumer uses content-shard key `ct 00 object:32 intent:32` and timer kind13. `ContentTakedownV1` binds strict versioned `PendingHolderV1` provenance (canonical namespace/repository, logical source, consuming job ticket, object, hold, stable source operation and domain-separated intent), exact block entry observed at holder commit, queued time and optional ready time. Holder/count update, ordinary hold release, matching gp deletion, ct/timer creation and source relay watermark commit atomically. Duplicate/lost replies preserve identity and do not create a second request or holder count.

Kind13 currently materializes Ready and retains request/timer; Ready is handoff availability, never takedown completion. This lane must consume the real request with durable idempotent acceptance/checkpoint, retain exact provenance and request/action binding, and acknowledge/remove or transfer the producer timer only after the actual owning takedown workflow has durable responsibility. A noop callback, marker-only deletion or aging out is forbidden. Compare the final merged codec/source before implementation; this paragraph records the prototype contract, not a merge/activation claim. Unknown/corrupt/version-mismatched requests fail closed without losing protection or denial.
