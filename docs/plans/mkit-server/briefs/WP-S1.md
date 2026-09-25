# WP-S1: SPEC-TRANSPORT-CONNECT v2, part 1 (addressing, namespace policy, owner-key writes, `GetServerInfo`)

- **Milestone/track:** spec PR for M1 (issue mkit#1084)
- **Base:** `feat/mkit-server`
- **Branch:** `mkit-server/wp-s1-addressing`
- **Depends on:** WP-P1
- **Stacked by:** WP-S2 and WP-S3, which both branch from this PR's head
- **Size:** L (docs only, ~600–800 changed lines: #1090 upload tickets/parts and ref deletion are folded in)

## Goal

Rebuild the addressing part of draft PR mkit#1087 against the approved PRD. Bump SPEC-TRANSPORT-CONNECT to
version 2. Specify multi-repository addressing, self-certifying namespace syntax, the namespace and write policies,
owner-key write authorization and `GetServerInfo`, upload tickets and resumable parts (#1090, adopted Q18 default),
and ref deletion. No proto or code changes: messages
land with the M1 implementation (D24 additive).

## Credit (required)

The source text is PR mkit#1087 by Christopher Wallace (@christopherwxyz). Every commit carries these trailers:

```text
Co-authored-by: Christopher Wallace <362387+christopherwxyz@users.noreply.github.com>
Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
```

The PR body opens with "Rebuilt from #1087 by @christopherwxyz (split per PRD D26: addressing / grants / admission)."
Don't close or comment on #1087; the user does that.

## PRD refs

§6.1 (addressing), §5.4 stage 2 (Authorizer), §6.2 (uploads), §6.9 (ssh path argument),
§8 M1. Decisions: D4, D7, D12, D15, D24, D26, D27, D31, D34 (supersedes D21), D36 (`X-Mkit-Ref`).

## Inputs to read first

- `docs/plans/mkit-server/prd-snapshot.md` (full), and the PR #1087 diff (`gh pr diff 1087`), lines 47–263 (SPEC-TRANSPORT-CONNECT hunks)
- `docs/specs/SPEC-TRANSPORT-CONNECT.md` (current v1, 629 lines), `docs/specs/SPEC-CONVENTIONS.md` §2, §4–§6,
  `docs/STYLE-GUIDE.md`, `docs/specs/SPEC-REFS.md` §3
- `rust/crates/mkit-core/src/write_auth.rs` (the v2 canonical fields; `repository` component ≤255 printable ASCII)
- `rust/crates/mkit-transport-connect/src/client.rs:221-296` (the client maps the URL path to the repository and uses
  `default` for an empty path)

## Files to change

1. `docs/specs/SPEC-TRANSPORT-CONNECT.md` (all the normative text)
2. `docs/specs/README.md`: update the SPEC-TRANSPORT-CONNECT bullet text if it names "v1"; there are no new specs in S1
3. `apps/web/src/lib/spec-data.ts`: update the SPEC-TRANSPORT-CONNECT `description` to mention multi-repository
   addressing. `status` stays `draft-normative`. No icon change.
4. `docs/specs/SPEC-TRANSPORT.md`: only if a cross-reference to the v1 single-repo assumption exists (grep "one
   repository" / "single"); otherwise untouched

## Section outline (PRD text → spec section)

Frontmatter: `version: 2`, status `draft-normative`. Rewrite the opening `Status:` paragraph. Keep the history in
§9, and state that v2 is draft and "no v1 compatibility machinery" (CONTRIBUTING pre-production policy; PRD §6
intro). Say that v2 makes semantic breaks only, and that `mkit.transport.v1` evolves additively.

| New/changed section | Content | Source |
|---|---|---|
| §2 Verb-to-RPC mapping | Add rows, marked "M1", for `GetServerInfo`, `BeginUpload` and `CompleteUpload` (unary) and `UploadPart` (**client-streaming**, review 01 R-69). Keep the 7 existing rows. | PRD §6.1, §6.2 |
| **§2.1 `GetServerInfo`** (new) | Request: empty (it MAY carry `X-Repository`). Response fields: protocol and spec version; limits (max pack bytes, part size, max parts, max refs per list page; a deployment MAY advertise a lower max pack size for indexed mode, e.g. on Workers); `begin_upload_threshold_bytes` (0 when admission is enabled; the value when admission is off is an open default, PRD Q2); `atomic_advance` (bool); `indexed_mode` (bool); `admission` (bool); receipt public key + key id (empty until M5); supported grant schemes (empty until M2); `namespace_policy` (`allowlist` \| `any` \| `single-repository`). Unauthenticated and cacheable `private, max-age` ≤ 60 s. Clients MUST NOT infer atomicity without it; they use `atomic_advance` in place of today's `with_atomic_advance` opt-in. | PRD §6.1 bullets; SPEC §7.3 "deliberate gap" paragraph |
| §5 Error taxonomy | Add the authorization split rows: signature, envelope or validity failure → `unauthenticated`; an authenticated principal not authorized by namespace or write policy → `permission_denied`; a malformed repository id → `invalid_argument`; an unknown repository on a read → `not_found`. Keep the mechanical inverse mapping. Don't add admission rows (that's S3). | PRD §6.4 "error codes aligned"; pr1087 §7.4 grammar errors |
| §7.1 Reference Worker | Replace "single global Durable Object … one Worker = one repository" with "a single-repository deployment in §7.4's terms; a multi-repository deployment shards state per D34: a namespace coordinator, one strongly consistent ref shard per (repository, ref), and eventually consistent repository index shards (§7.9)". (D21's "one partition per namespace" is superseded by D34; review 01, R-74.) Keep the auth v2 contract text unchanged, except: (a) `<repository>` is the full repository identity from §7.4; (b) point "write authorization" at §7.5. Drop pr1087's "applies the owner policy of SPEC-WRITE-GRANTS" sentence and replace it with a §7.5 reference. | pr1087 lines 147–169 (partially kept) |
| **§7.4 Repository addressing** (new) | See the subsection below. | pr1087 §7.4 (lines 174–229) with changes |
| **§7.5 Namespace and write policy** (new) | See the subsection below. | PRD §5.4 stage 2, §6.1, D27 |
| **§7.6 Upload tickets and resumable parts** (new) | See the subsection below. | PRD §6.2 minus admission |
| **§7.8 Ref deletion** (new) | See the subsection below. (§7.7 is reserved for S3's lifecycle table.) | adopted M2 default |
| **§7.9 Consistency and paging** (new) | See the subsection below. | D34 |
| §8 Out of scope | Replace pr1087's follow-up bullets with: "Implementation: M1 (multi-repo routing, namespace policy, D34 sharding, `GetServerInfo`, tickets)". Grants go to SPEC-WRITE-GRANTS (forthcoming, S2) and admission to §5.1 (forthcoming, S3). | |
| §9 Version history | Add a row: `2` \| draft \| "§7.4 repository addressing; §7.5 namespace and write policy (owner key); `GetServerInfo`; §7.6 upload tickets and resumable parts; §7.8 ref deletion; error-code split (mkit#1084, mkit#1090)". S2 and S3 append to this same row. | |
| §11 Invariants | Add: "No RPC on one repository reads or changes another repository's refs, pack membership or replay records." "A write is authorized, or rejected with nothing allocated, before any quota or replay state is touched." "A stock multi-repository deployment never runs `write_policy = open`." | pr1087 lines 260–261, amended |

### §7.4 Repository addressing: what to keep from pr1087 and what to change

- **Grammar (ABNF).** Keep the shape and change the namespace production per **D4** (self-certifying only; the
  registry-resolved namespaces in pr1087 §2 "A deployment MAY resolve other namespace forms" are **dropped**):

  ```abnf
  repository = namespace "/" name / name        ; bare name: single-repository deployments only
  namespace  = ed25519-ns / address-ns
  ed25519-ns = "ed25519-" 64HEXLC                ; owner = that Ed25519 public key
  address-ns = "0x" 40HEXLC                      ; owner = key whose derived address matches (SPEC-WRITE-GRANTS)
  name       = lead *99tail
  lead       = %x61-7A / DIGIT
  tail       = lead / "." / "_" / "-"
  HEXLC      = DIGIT / %x61-66
  ```

  Check that the longest identity (`ed25519-` + 64 + `/` + 100 = 173 bytes) fits the auth v2 `repository`
  component limit of 255 (`write_auth.rs:142`); say so in the text. Keep "lowercase only; reject noncanonical with
  `invalid_argument`".
- **Carriage.** Every RPC MUST carry `X-Repository`. On signed writes it MUST equal the signed `<repository>` byte
  for byte. **Change from pr1087:** a mismatch is detected by envelope verification and is `unauthenticated`, not
  `permission_denied`. This matches the implementation (`write_auth.rs:208-212` → vcs-worker `unauthenticated`). If
  the reviewer disagrees, record the decision in the PR. Host, path and forwarded headers MUST NOT select the
  repository (keep).
- **Single-repository compatibility (PRD §6.1).** The deployment configures exactly one identity, which may be
  bare. A request **without** `X-Repository` resolves to it (new, PRD). A request **with** a different value is
  `not_found` (keep from pr1087).
- **Isolation (D12, D15).** Refs, pack membership, packmap chains and replay records are per repository. **Change
  from pr1087:** quota and admission scope are set by the deployment and are *not* required to be per repository.
  `PackExists`/`DownloadPack` answer only for packs that are members of the named repository; keep pr1087's
  "store identical bytes once" and "otherwise a caller could learn another repository's contents". Add: a
  deployment MUST NOT answer any RPC by consulting another repository's membership (no existence oracle, D15).
- **Creation.** A repository comes into existence with its first authorized write; there is no create RPC (keep).
- **Client.** URL path → identity. An empty path is `default` (keep; it matches `client.rs:268-273`). The client
  sends `X-Repository` on reads too (new in M1; today only signed writes carry it).
- **ssh / enc (§6.9, D23).** The path argument of `mkit serve <path>` is the addressing input. The FS layout is
  unchanged. Informative only: the frozen `mkit.rpc.v1.ssh` proto is untouched.

### §7.5 Namespace and write policy

- `namespace_policy`: `allowlist` (a list of owner namespaces; the **default** for stock multi-repo deployments) or
  `any` (explicit opt-in). Under `any` the deployment MUST configure a non-default Admission (S3 §5.1). Without
  one it MUST refuse to start unless the operator passes an explicit unsafe override (name it generically, e.g.
  "unsafe-open-namespaces"; the CLI flag spelling is implementation). Rationale: every new key is a new namespace,
  which resets the default per-namespace quota (D27).
- `write_policy`: `open` (any valid auth v2 signer; single-repository deployments only) or `owner`. A stock
  multi-repository deployment MUST NOT run `open`.
- Under `owner`, a write to `<ns>/<name>` is authorized when (1) `ns` is `ed25519-<k>` and the auth v2 signer
  equals `k`; or (2) a valid grant authorizes the signer (SPEC-WRITE-GRANTS, forthcoming; until it lands, only
  (1) and (3) apply); or (3) a deployment-defined authority source authorizes the signer. It MUST be documented and
  MUST fail closed when unreadable (keep pr1087's text for (3)).
- `address-ns` owners can't sign auth v2 (Ed25519-only), so they can write only through grants (informative;
  PRD §8 rollout).
- Ordering: the Authorizer runs after authentication and replay lookup, and before any quota, reservation or
  replay record is allocated. A rejection allocates nothing (PRD §5.4 stage 2). Replay lookup itself is specified
  by S3; here, say "after authentication" and forward-reference §7.1's replay rules.
- Creation signals: authorization and admission see `creates_namespace` and `creates_repo` (D27). This is
  informative here and normative in S3.

### §7.6 Upload tickets and resumable parts (#1090; adopted Q18 default: folded into S1)

Normative text for PRD §6.2, **excluding** everything about 402 and challenges (S3 owns those). The part RPC shape
is **client-streaming parts with explicit completion** (review 01 decision, R-69: a unary part would be collected
whole by the server's RPC layer, so 8–32 MiB parts would be buffered per request), with the Durable Object
constraint that part requests never reach any strongly consistent metadata partition (reconciliation R-28):

- `BeginUpload(repository, ref, pack_id, bytes)` (unary, signed, `body:` commitment) names the ref the upload will
  advance (D34), so the ticket lives with that ref's state; `AdvanceRefs` on that ref consumes it with no cross-ref
  handoff. A ticket may be consumed only by an advance of the ref it names (else `failed_precondition`). It returns
  `AlreadyPresent` (pack is a member of this repo) | `Ticket{id, part_size, expires, token}`. For the same (signer,
  ref, pack) before advance it returns the existing ticket (same id, same upload session), never `AlreadyPresent`.
  Because membership is eventually consistent (§7.9), a missing `AlreadyPresent` is allowed; it only costs a
  re-upload.
- **Stateless ticket token.** `token` is an opaque, server-authenticated value binding (ticket id, audience,
  repository, signer, pack_id, bytes, part_size, expires, key id). The server verifies it without consulting the
  namespace partition. Clients treat it as opaque. The authenticity mechanism is a deployment secret with a key id
  (informative: a MAC; rotation by key id).
- **Parts** (packs with `bytes > part_size`): `UploadPart` is a **client-streaming** RPC (signed like
  `UploadPack`): the first message is a header `{ticket_token, index}`, followed by data messages carrying the part's
  bytes in order; the response is the part receipt. New auth v2 commitment kind
  `part:<ticket>:<index>:<subtree-hash>:<len>`, named normatively here and added to §7.1's list
  (`mkit_core::write_auth` gains it in M1; informative); the signed headers commit to the whole part before any byte
  is sent. The server verifies the ticket token and commitment before reading data, hashes the data as a BLAKE3
  subtree while streaming it to storage (a server MUST NOT need to hold a whole part in memory), rejects a subtree or
  length mismatch with `invalid_argument`, and returns a **part receipt**: an opaque, server-authenticated value
  binding (ticket id, index, subtree hash, len, storage part tag). No 402 is ever needed on a part: admission
  happened at `BeginUpload`.
  Parts are a uniform power of two ≥ 8 MiB except the last; at most `max_parts` (from `GetServerInfo`).
- **Completion:** `CompleteUpload{ticket_token, receipts[]}` (unary, signed, `body:`). The server verifies every
  receipt, merges the subtree hashes to the root, and makes the pack visible only if root == `pack_id` and the total
  equals `bytes`; otherwise it aborts the storage session and returns `invalid_argument`. Completion does not make
  the pack a member (see below).
- **Resume:** receipts are the durable record of received parts and live with the client. A client that lost them
  re-sends the missing parts (re-sending a part index is idempotent). Re-calling `BeginUpload` returns the same
  ticket. There is no server-side "received parts" listing.
- **Single-part packs** (`bytes ≤ part_size`, planner default, reviewable): `UploadPack` with the ticket token in its
  header and the usual `pack:` commitment; no `part:`/`CompleteUpload`.
- A pack becomes a member **only** at the `AdvanceRefs` apply that consumes its ticket. `AdvanceRefs` gains
  `ticket_ids` (repeated). Head-only `UpdateRef` consumes no tickets.
- Threshold: packs under `begin_upload_threshold_bytes` MAY skip `BeginUpload`. S3 sets the threshold to 0 under
  admission.
- Binding: the ticket's audience, repo and signer, and its (pack_id, bytes), MUST equal the request's signer and
  commitment, otherwise `permission_denied`. `MKPL` packlist nodes need tickets too.
- Error codes (never `resource_exhausted`, which clients retry forever): expired or unknown ticket →
  `failed_precondition`; ticket/signer/commitment mismatch → `permission_denied`; bad part hash or length →
  `invalid_argument`.
- Tickets expire in under 7 days. An expired, unadvanced ticket → `Expired` outcome; its pack is GC-eligible.
- Retries reuse nonce and timestamps within the 300 s validity, then sign a new operation.
- Indexed mode: a pack still under verification → `unavailable` + `PendingVerification{retry_after}`. Clients poll
  until the ticket expires, not on the ~15 s ladder (`protocol.rs:206-215`). Reserved detail here; normative in M4.
- Storage visibility is the commit point on every backend (informative: R2 multipart `complete` is called only after
  the merged root verifies; presigned direct-to-storage part uploads are not allowed because they would bypass
  verify-before-complete).

### §7.9 Consistency and paging (D34, D36; reconciliation R-30, R-32, R-77, R-78)

- `ReadRef` of a specific ref, and every write, is strongly consistent. Push compare-and-swap MUST use `ReadRef`.
- `ListRefs` and pack **membership** (`PackExists`, `DownloadPack`, `AlreadyPresent`) are eventually consistent and
  may lag by seconds after a write. A lag may only cause a re-upload, a retryable `unavailable` ("not yet visible"),
  or an older listing; it never exposes another repository's data (no existence oracle).
- **Read-your-writes for packs (D36, approved by the user; normative):** `PackExists` and `DownloadPack` MAY carry an
  optional `X-Mkit-Ref: <refname>` header naming a ref **of the same repository** whose packmap listed the pack. The
  server then also resolves membership against that ref's strongly consistent shard (the membership additions its
  advances recorded), so a pusher sees its own advance immediately despite index lag. The answer is **always subject
  to the caller's view**: a caller without write access gets the published view, so a pack added by an advance that
  is still quarantined (M5) stays invisible through the header exactly as without it, and the header never reveals
  another repository's packs or whether a ref exists in another repository. An unknown or malformed ref name makes
  the header a no-op (the answer falls back to the index), never an error that would act as an existence oracle.
  Clients SHOULD send it when fetching packs listed by a packmap they just read. `X-Mkit-Ref` is not part of the auth v2
  canonical string: tampering with it can only change which of the caller's own permitted answers is returned,
  never widen the caller's view.
- `ListRefs` is paginated (additive fields): request `page_size` and `page_token`, response `next_page_token`. Every
  response stays below the deployment's message limit (normative bound: **≤ 2 MiB per page**, review 01 R-78, so the
  encoded envelope always fits under the common 4 MiB default client message limit); pages concatenate to the full
  listing in name order.
- `GetServerInfo` advertises `index_fanout` (the fixed object-id-prefix fan-out, default 4096) and the ListRefs page
  bounds.

### §7.8 Ref deletion (adopted M2 default: keep the grant `delete` flag)

- `UpdateRef` and `AdvanceRefs` gain an additive way to delete a ref: a `delete` field on the ref update, valid only
  with a `MATCH` expectation, `new_id` empty. `AdvanceRefs` deleting a branch deletes the head and its packmap
  together. Deleting an absent ref is a CAS conflict.
- Authorization of deletion is by write policy (owner) in M1 and by the grant `d` flag in M2 (SPEC-WRITE-GRANTS).
  A deployment may refuse deletion entirely with `permission_denied`.
- No client CLI surface is required by this spec (informative; a `push --delete` UX is a follow-up).

## What to drop from pr1087 entirely (belongs to S2/S3 or contradicts the PRD)

- §5.1 admission challenges, the `X-Admission-Credential` header, the `AdmissionRequired → resource_exhausted`
  row, and the SPEC-TRANSPORT §7 retry exception (all S3, redesigned per D8/D9/D30).
- The SPEC-WRITE-GRANTS file and its web registration (S2).
- "A deployment MAY resolve other namespace forms through its own registry" (contradicts D4).
- "quota … scoped to one repository" (contradicts D12).

## Validation

```bash
bash scripts/check-spec-status.sh
just ci-scripts          # spec status + wasm dep graph + mkit-wasm check
(cd apps/web && bun install --frozen-lockfile && bun run test -- spec-index)   # only if spec-data.ts changed; use the package manager web.yml uses
git diff --stat origin/feat/mkit-server -- proto/ rust/ apps/*/src   # must be empty
```

Also run a relative-link check by eye. Every `(SPEC-*.md#...)` anchor you add must exist; forward references to
SPEC-WRITE-GRANTS are plain text ("SPEC-WRITE-GRANTS, forthcoming"), not links, until S2 lands.

## Acceptance criteria

- [ ] Frontmatter `version: 2`, status recognized by `check-spec-status.sh`.
- [ ] §7.9 states strong `ReadRef`, eventually consistent `ListRefs`/membership with the safe-failure rules, the
      D36 `X-Mkit-Ref` header with its caller-view rule and no-oracle fallback, ListRefs pagination with the ≤ 2 MiB
      page bound, and `index_fanout` in `GetServerInfo`.
- [ ] §7.6 specifies `BeginUpload(repository, ref, …)`/client-streaming `UploadPart`/`CompleteUpload`, the stateless ticket token, part receipts,
      client-held resume, the single-part rule, the `part:` commitment grammar, error codes and expiry. §7.8
      specifies ref deletion.
- [ ] §7.4 grammar allows only self-certifying namespaces (D4). The bare-name rule and the missing-header rule
      for single-repo are both stated.
- [ ] §7.5 states the allowlist default, `any` needing non-default Admission (or the unsafe override), owner-key
      writes, the fail-closed authority source, and "multi-repo MUST NOT be `open`".
- [ ] `GetServerInfo` field list matches PRD §6.1 exactly (every bullet present).
- [ ] Quota and admission scope is deployment-defined (D12), not per repo.
- [ ] Every item in "drop entirely" is absent. §9 has the v2 row. The §11 invariants are added.
- [ ] Credit trailers on every commit. The PR body credits #1087.
- [ ] No non-docs file changes except `apps/web/src/lib/spec-data.ts`.

## Risks / gotchas

- SPEC-CONVENTIONS §6 (no vendor references): don't name crates or functions normatively. `mkit_core::write_auth`
  and `apps/vcs-worker` may appear only in "Reference implementation" or informative notes.
- S2 and S3 branch from this PR's head. Keep section numbers stable after review starts (§7.4/§7.5/§7.6/§7.8, §2.1),
  because S2/S3 cite them. §7.7 is left for S3's lifecycle table.
