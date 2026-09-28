## Purpose

This WP specifies how content is taken down:
- the blocklist;
- serving stops;
- preservation;
- the delta-safe rewrite and replacement of ref values;
- tombstones;
- the signed notice that tells writers and readers what happened.

It also closes the forward obligations 5.1a left on §14.

## A. Fixed (do not change)

1. **PRD §6.7:**
   - Content-level takedown is indexed-mode only.
   - The unit is the whole object.
   - Bytes move to preservation and are purged after a configured retention.
   - The rewrite covers any delta chain through X.
   - The notice maps old→new pack ids.
   - There is a global blocklist, and lag holes are closed by the relay plus the watermark (R-75).
   - Readers get 451 or a signed notice, with 404 before 451.
   - CachePurger runs on every takedown.
   - Suspension reuses lease states.
2. **Plan rules:**
   - Separate restricted preservation storage, reachable only through the admin API.
   - Reinstatement is a server-side rewrite.
   - No mkit default for preservation retention (P-20).
   - R-64, R-75, R-108, R-115.
3. **User decision (2026-09-28): an automated inspector hit triggers a GLOBAL content takedown**, in every namespace
   holding the object, as the PRD says. Reinstatement is the remedy. Add an informative note on the false-positive
   blast radius.
4. **WP-5.7a's `rewrite_excluding` primitive** rawifies only when the direct base is excluded. Its output bytes differ
   between native and wasm builds, so new pack ids are **not** implementation-deterministic. The notice records the
   actual old→new ids.
5. **Proto rules:** additive only (R-79). Spec approval merges like code (00-plan line ~71).

## B. Decided (do not change)

### B.1 Structure

§14 Takedown and redaction notices:

| Section | Title |
|---|---|
| 14.1 | Terms, levels and scope |
| 14.2 | Blocklist |
| 14.3 | Lifecycle and completion |
| 14.4 | Rewrite, replacement and ref-value substitution |
| 14.5 | Tombstones and caller answers |
| 14.6 | Signed redaction notice |
| 14.7 | Preservation store |
| 14.8 | Reinstatement |
| 14.9 | Interaction with GC, restore and caches |

Also amend:
- §1;
- §2 stage 5 (built-in blocklist check);
- §9.4, carving out the blocklist from repository isolation;
- §13.4, with a takedown exemption from the zero-holder guard and from `gc_grace` for superseded packs;
- STC §5 rows;
- SPEC-HTTP-OBJECTS §3 step 8, §4 and §9.

### B.2 Levels and unit

**Content level** (indexed only):
- A takedown names one or more (≤256) blob ids or ChunkedBlob manifest ids.
- Chunks of a taken-down manifest are dropped per repository only when no other live object there references them, and
  are never blocklisted.
- Commits, trees and tags can't be taken down at content level; use the repository or namespace level. Add an
  informative note that message text is a residual channel.

**Repository and namespace level:**
- An administrative suspension override flagged as a takedown (§12).
- Readers get §12.2's byte-identical `not_found`/404, never 451.
- **Writers** get the existing `lease suspended` message **plus the notice detail**, with the message text unchanged
  and readers' bytes unchanged.
- In opaque mode, only these levels exist.

### B.3 Lifecycle, in order

1. Write the blocklist row and apply the §11.3 serving stop immediately.
2. Preserve: copy the canonical bytes (for a ChunkedBlob, the manifest plus its chunks) and verify them against the id.
   Fail closed.
3. Per holder repository:
   - rewrite the affected packs;
   - in one guarded ref-shard batch, substitute the packmap in the **live, published and every retained intermediate
     advance value**. Sequence numbers are unchanged; §13.3's reliance rule and `NotAfter` apply; holds are created
     before replacement bytes are written;
   - substitute membership, index rows and the per-ref membership-addition records;
   - write tombstones and per-ref notice flags;
   - store the signed notice.
4. Delete the extracted copy, under the §13.4 exemption. **Delete superseded packs at completion**, under the
   `gc_grace` exemption: the bytes must not linger for 7 days.
5. Enqueue cache purge (§16).
6. Wait for the relay watermarks of the affected namespaces to pass the takedown time, and for the holder sweep (B.4).

Further rules:
- A `hit` **resolves on per-repository completion**. Global completion is for reporting and the audit log only.
- A replacement pack inherits the published status of the pack it replaces. A `hit` advance's own packs publish
  atomically with its resolution.
- Takedown writes are not advances.

### B.4 Holder discovery (completeness)

- Use the pack-holder and extracted-object holder fast path first.
- Then run a **resumable sweep per takedown**: one index-shard point read per repository across the deployment, to
  find holders of small blobs that have no holder rows.
- Completion waits for the sweep.
- State the fallback wording: completeness is guaranteed for extracted objects, pack holders and swept repositories.

### B.5 Caller answers

**Before the tombstone row is written:** every caller gets the §11.3 absent / `not_found` / 404.

**After it is written:** every caller who can see the ref value gets the notice.
- `ReadRef` and `ListRefs` attach it (B.6).
- An `AdvanceRefs` whose closure contains X gets the existing `invalid_argument` open-closure error, plus the detail.
- A delta base of X gets the existing `failed_precondition` "delta base not available in this repository", plus the
  detail, with no lag window. Never introduce a new `failed_precondition` on a ticketed `AdvanceRefs`, because clients
  would loop on BeginUpload.
- `DownloadPack` of a superseded pack gets `not_found` plus the detail; `PackExists` answers `false`.
- **HTTP 451** is returned only when the id is reachable by the published tree walk **and** this repository has a
  tombstone for it. Otherwise 404.
  - Chunks reachable only through a tombstoned manifest get 404.
  - 451 comes after the 404 checks and before 304 and Admission.
- Ingest of a blocklisted object: `permission_denied` "object blocked", plus a notice with no repository and no
  rewrites.

**Immediacy:**
- Extracted and HTTP serving read the blocklist at serve time, which is strongly consistent per object, so the stop is
  immediate.
- Pack serving stops per repository within a stated bound (C: express it in terms of the relay-lag bound).
- Informative: every branch whose history contains X becomes unfetchable until its owner rewrites history
  (clone-with-holes is deferred, D17). This is accepted.

### B.6 RedactionNotice

- **Envelope:** a DSSE envelope with `payloadType` `application/vnd.mkit.redaction-notice.v1+json`, using the
  receipt+notice key (§15). The payload is JCS JSON and **not** an in-toto Statement.
- **Payload fields:**
  - `version`, `noticeId`, `takedownId`;
  - `origin`, `repository` (empty for an ingest rejection);
  - `objects[{id, kind}]`;
  - `reason`, a token from a small registered set plus deployment tokens, with **no free text**. Document the practice
    of mapping sensitive categories to `legal`;
  - `takenDownAtMs`, `issuedAtMs`, `keyId`;
  - `rewrites[{type: pack|packlist, old, new|""}]`, sorted.
- **Bounds and lifecycle:** at most about 256 KiB. There is one notice per (takedown, repository), signed at takedown
  time and withdrawn on reinstatement.
- **Wire:**
  - A Connect detail, `mkit.transport.v1.RedactionNotice { bytes envelope = 1; }`, carrying the envelope only.
  - `ReadRefResponse.redaction_notices = 3` (repeated).
  - `ListRefsResponse.ref_redactions = 3` (repeated, `RefRedaction{ref, notice}`), within the page bound. `RefEntry`
    stays unchanged.
  - The HTTP 451 body is the detail as canonical protobuf JSON:
    - `application/json`, `no-store`;
    - no `ETag`, `X-Mkit-*` or `Content-Range`;
    - `Link: <origin>; rel="blocked-by"` (RFC 7725), added to the CORS expose list.
- Register the notice `payloadType` in the domain-separator discussion.

### B.7 Preservation store

- **Contents:** canonical bytes, plus a record of:
  - takedown id, ids, kind, size, reason, time;
  - holders at completion;
  - per repository, the affected old pack ids and, where known, the advancing signer keys.
- **Isolation:** a separate keyspace, reachable only through the admin `ReadPreserved` (§16), which is audited. It is
  never a dedup, serving or delta-base source, and never collected by GC.
- **Retention:**
  - `retain_until = takedown time + preservation_retention`. That parameter is **REQUIRED** configuration when
    takedown is enabled, and startup is refused without it. There is no mkit default.
  - A legal hold suspends the purge until an audited release.
  - The purge runs on a timer and is audited.
  - Reinstatement keeps the record, marked as reinstated, until retention ends.

### B.8 Blocklist

- **Row:** one per object id: `{takedownId | "", source: takedown|manual, reason, blockedAtMs}`. The implementation
  moves to a V2 codec.
- **Checked at:**
  - the built-in stage-5 indexed decode of every pushed file object, independent of inspectors;
  - extraction dedup holds;
  - the relay's holder recording (R-75);
  - serve time for extracted and HTTP paths.
- A manual block of an id with known holders becomes a takedown.
- Reinstatement lifts the row only when no other active takedown covers the id.

### B.9 Reinstatement

- A server-side rewrite: restore the bytes from preservation, lift the blocklist row, append a single-object pack, and
  CAS the packmap.
- Withdraw the notices and delete the tombstones. The action is audited.

### B.10 Restore

A restore (the portable restore driver) MUST re-apply every takedown recorded after the snapshot time, so no restored
shard resurrects taken-down content.

Add row **R-117**:

> WP-5.1b-1: restore must re-apply takedowns recorded after the snapshot; the admin store's takedown records are the
> source. Owner: the admin implementation (5.11a/b), with a 1.29b follow-up.

### B.11 hooks.v1

- Add `Event.kind` `TakedownTransition takedown = 8`. Field 7 stays for publication.
- Add optional `InspectResponse.takedown_reason = 6`, a token.

### B.12 Goldens: `rust/tests/golden/redaction/`

- the notice JCS payload;
- the DSSE envelope from a test seed;
- the detail in binary and in canonical JSON;
- the four Connect error bodies;
- the ReadRef and ListRefs responses;
- a `MANIFEST.txt`.

Also add:
- `http-objects` 451 rows;
- `server-hooks` event-takedown.

### B.13 Plan and registry

- Replace the 5.1b row with **5.1b-1** and **5.1b-2**.
- 5.1b-1 depends on 5.1a and 5.1c.
- 5.1b-2 depends on 5.1b-1.
- 5.6 depends on 5.1b-1.
- 5.9a and 5.14 add a 5.1b-1 edge.
- 5.11a depends on 5.1b-2.
- 5.10 depends on 5.1b-2 for remote CachePurge delivery.

Add row **R-118**:

> WP-5.1b split.
>
> - A global hit takedown (user, 2026-09-28).
> - Resolution is per repository.
> - Holder sweep for small blobs.
> - Superseded packs are deleted at completion.
> - Custom-payloadType notices.
> - Writers are told about repository- and namespace-level takedowns.

## C. Your decisions

- The prose structure within B.1.
- The per-repository pack-stop bound (B.5).
- The registered reason tokens.
- The golden layout.

## D. Escalate (stop and report) if

- A §1.2 obligation from the research can't be satisfied under these rules.
- A B item contradicts merged normative text that a citation can't reconcile.
- The spec text exceeds about 1,300 changed lines, excluding goldens.

## Gates

- `buf lint`, and `buf breaking --against '.git#branch=origin/feat/mkit-server'`
- `bash scripts/check-generated-fresh.sh`
- `bash scripts/check-spec-status.sh`
- `bash scripts/check-server-hooks-goldens.sh`
- the redaction golden test
- `just ci-server`
