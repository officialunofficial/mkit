# WP-S3: Admission challenges (402, helper headers + allowlist, replay-after-auth, per-RPC lifecycle)

- **Milestone/track:** spec PR for Track Money / M3 (issue mkit#1086)
- **Base:** head of WP-S1's branch; retarget to `feat/mkit-server` after S1 merges
- **Branch:** `mkit-server/wp-s3-admission`
- **Depends on:** WP-S1 (which carries upload tickets and parts, §7.6, per the adopted Q18 default)
- **Parallel with:** WP-S2. S3 refers to "write authorization" generically (SPEC-TRANSPORT-CONNECT §7.5), never to
  grants.
- **Size:** M (docs, ~450–600 lines across 3 spec files)

## Goal

Replace pr1087's §5.1 design with the approved one:

- HTTP 402 carrying an opaque challenge **list** (D8), with raw payment headers passed through
- `BeginUpload` mandatory under admission
- a client `admission_helper` that returns **headers**, filtered by an allowlist and a hard-reserved set (D9, D30)
- replay lookup **after** authentication and **before** admission
- the normative per-RPC lifecycle table
- the rule that challenges and `pending_verification` are never stored

Docs only; proto and implementation land in M3.

## Credit (required)

Source text is PR mkit#1087 by Christopher Wallace (@christopherwxyz). Every commit carries:

```text
Co-authored-by: Christopher Wallace <362387+christopherwxyz@users.noreply.github.com>
Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
```

PR body: "Rebuilt from #1087 (§5.1 admission challenges) by @christopherwxyz, redesigned per MKIT-29 §6.3 / D8 / D9 / D10 / D30."

## PRD refs

§5.4 stages 0–4 and "Lifecycle per RPC (normative)", §6.2 (the admission-related rules), §6.3 (all), §7 boundary
table, §8 M3 exit list. Decisions: D7, D8, D9, D10, D12, D13, D15, D27, D30.

## Inputs

- the PR #1087 diff (`gh pr diff 1087`) lines 59–144 (old §5.1) and 264–279 (the SPEC-TRANSPORT §7 retry exception)
- `mpp.txt` (download https://mpp.dev/llms-full.txt): **grep only**, for header names and cache rules, e.g. `grep -n "Payment-Authorization\|Cache-Control\|preflight\|header=\"" mpp.txt`
  (lines ~6237, 6675, 6759, 6801, 6907, 9755–9757). x402 v2: `PAYMENT-REQUIRED`, `PAYMENT-SIGNATURE`,
  `PAYMENT-RESPONSE` (PRD §12 link; don't fetch unless needed).
- Current auth v2 replay text: `docs/specs/SPEC-TRANSPORT-CONNECT.md` §7.1 "A valid signature alone is insufficient…"
  through "…fails closed" (≈ lines 440–462)
- `docs/specs/SPEC-CONFIG-SECURITY.md` §2 per-key audit table, §3.4 runtime gates, §5 "Adding a new config key"
- `rust/crates/mkit-core/src/protocol.rs:181-215` (`is_retryable`, backoff ladder)
- `apps/mkit-worker-common/src/replay.rs:115-168` (today's ledger: lookup inside the transaction, then admission,
  then insert)

## Files

1. `docs/specs/SPEC-TRANSPORT-CONNECT.md`: new §5.1, §5 table row, §7.1 replay-rule rewrite, new §7.7 lifecycle
   (numbering after S1's §7.4–§7.6), §8, §9 v2 row append, §11 invariants
2. `docs/specs/SPEC-TRANSPORT.md` §7 (retry, ≈ line 620): 402/`AdmissionRequired` never retried. **Drop** pr1087's
   "resource_exhausted with a challenge" exception, because admission no longer uses `resource_exhausted`.
3. `docs/specs/SPEC-CONFIG-SECURITY.md`: per-key audit rows for `admission_helper` (**UNSAFE**; repository config
   MUST NOT set it; runs only for `trusted_remote_endpoint` remotes) and for the per-remote allowlist extension key.
   Name it per the existing key style, e.g. `remote.<name>.admission_headers`, **UNSAFE**, user-scoped. Also a §3.4
   runtime-gate paragraph.
4. `apps/web/src/lib/spec-data.ts`: only if a description changes. No new spec file (SPEC-SERVER is M3, not this PR).

## Section outline

### SPEC-TRANSPORT-CONNECT §5.1 "Admission challenges" (replaces pr1087 §5.1 entirely)

| Topic | Normative content | Source |
|---|---|---|
| Purpose | Kept from pr1087's first paragraph: why neither plain `resource_exhausted` (retried) nor plain `permission_denied` (nothing to act on) is enough. | pr1087 |
| Server response | **HTTP 402** with a Connect error body whose code is **`permission_denied`** (so older clients fail fast instead of retrying), plus exactly one detail `mkit.transport.v1.AdmissionChallenge { repeated Challenge challenges; string description; }`, where `Challenge { string scheme; string value; }` is opaque. Proto lands in M3. Keep the size limits from pr1087 (scheme token grammar, value ≤ 8,192 bytes, description ≤ 512 bytes) and add a list bound (≤ 8 challenges). No `AdmissionRequired` result message on any RPC (PRD §6.2). | D8 |
| Header pass-through | The server MAY also send the raw headers `WWW-Authenticate: Payment …` (MPP) and/or `PAYMENT-REQUIRED` (x402). mkit registers no schemes and interprets none. | §6.3 |
| Unary only | Challenges apply to unary RPCs only. A client-streaming RPC can't carry a 402. Under admission, `BeginUpload` is **mandatory** and `begin_upload_threshold_bytes` = 0 in `GetServerInfo`. Paid bulk downloads go through HTTP serving (§6.6, M4), where 402 is an ordinary response. | §5.4 stage 3, §6.2 |
| Ordering | For authenticated operations, authenticate before challenging (MPP). Anonymous operations (e.g. a paid public download) MAY be challenged directly. Full order in §7.1 (below). | §6.3 |
| No state on challenge | A challenged request MUST NOT change state: no repository or namespace created, no quota reserved, replay nonce not consumed, no ticket. The challenge is never stored as a replay result. | §5.4 stage 4, §6.2 |
| Cache | 402 → `Cache-Control: no-store`. A response carrying `Payment-Receipt` (MPP) or `PAYMENT-RESPONSE` (x402) passes it through with `Cache-Control: private`. | §6.3; mpp.txt ~6675 |
| CORS | Expose `WWW-Authenticate`, `Payment-Receipt`, `PAYMENT-REQUIRED`, `PAYMENT-RESPONSE`. Preflight (`OPTIONS`) never requires payment. Allow the helper request headers (`Payment-Authorization`, `PAYMENT-SIGNATURE`, `Authorization`). | §6.3; mpp.txt ~6237 |
| Admission input (informative, for implementers) | audience, repo, procedure, verified signer or anonymous, namespace owner, grant used, `creates_namespace`, `creates_repo`, pack_id, declared bytes, new-to-repo bytes, idempotency key. New-to-store bytes are **excluded** (pricing oracle), and are reported only in the `Committed` outcome. Cross-namespace quota scopes are best-effort (PRD §5.4 stage 3). | §5.4 stage 3 |
| Binding | Binding a challenge (HMAC over MPP params, `opaque`, `digest` over the unary `BeginUpload` body) is the business layer's job. mkit supplies the fingerprint: repo, signer, pack_id, bytes. | §6.3 |
| Redaction | Payment credentials and receipts MUST be redacted from logs and traces (server and client). | §6.3 |
| Bearer deployments | A deployment using `Authorization: Bearer` MUST advertise `header="Payment-Authorization"` in its MPP challenges. | §6.3 |

### Client behavior (also in §5.1)

- It builds `AdmissionRequired{challenges, description}` from **either** the detail **or** a raw 402 plus its headers.
  It never parses a problem+json body and never retries automatically.
- `admission_helper` (user-scoped; only for remotes listed in `trusted_remote_endpoint`) is invoked at most once per
  logical operation. **Replace pr1087's stdin/stdout-credential contract** with a header contract:
  - Input: the challenge list and context as a JSON document on stdin, e.g.
    `{ "origin", "repository", "procedure", "challenges": [{scheme, value}], "headers": {www-authenticate…, payment-required…} }`.
  - Output: exit 0 with a JSON object `{ "<Header-Name>": "<value>", … }` on stdout. Any other exit aborts.
  - For MPP that's `Authorization: Payment …` by default, or `Payment-Authorization: Payment …` when the challenge
    has `header="Payment-Authorization"`. For x402 it's `PAYMENT-SIGNATURE`.

  Finalize the exact JSON field names in the PR; they're mechanical.
- Allowlist (D30): the default is `Payment-Authorization`, `PAYMENT-SIGNATURE`, and `Authorization` only when the
  remote doesn't already use `Authorization`. It is extensible per remote in user-scoped config.
- **Hard-reserved** (never allowed, even via config): every mkit envelope header (`x-public-key`, `x-signature`,
  `x-digest`, `x-created-at`, `x-expires-at`, `x-envelope-version`, `x-audience`, `x-repository`,
  `x-content-commitment`, and any future `x-*` header mkit signs or defines, including the grant header
  `X-Write-Grant`), `Host`, `Content-*`, `Transfer-Encoding`, `Connect-*`, `Cookie`, `X-Forwarded-*`,
  `Idempotency-Key`, and hop-by-hop headers (`Connection`, `Keep-Alive`, `Proxy-*`, `TE`, `Trailer`, `Upgrade`).
  Comparison is case-insensitive.
- If the helper returns a non-allowlisted header, the client fails **naming that header**.
- Retry: one retry with the headers. Reuse nonce and timestamps while the envelope is valid (`MAX_VALIDITY_MS`
  300 s); after that, sign a new operation. A second challenge for the same operation fails it (keep from pr1087).

### SPEC-TRANSPORT-CONNECT §5 table

- Add `AdmissionRequired{challenges, description}` ← HTTP 402 + `permission_denied` + `AdmissionChallenge` detail.
  Never retryable.
- Keep `PayloadTooLarge` / `ServerError{429}` on `resource_exhausted` (retryable) unchanged.
- Remove pr1087's sentence making `resource_exhausted`+detail non-retryable.

### §7.1 auth v2 replay rules (rewrite of the existing "A valid signature alone…" paragraphs)

Normative order (PRD §5.4 stage 0):

1. Verify signature and validity window. This writes no state.
2. Look up (audience, repo, signer, nonce):
   - stored fingerprint differs → `invalid_argument`
   - `committed` → return the stored result
   - `in_flight` → retryable `aborted`, without reaching admission
3. Only new operations continue, to authorization (§7.5) and then admission (§5.1).
4. Insert the `in_flight` reservation.
5. Effects.
6. Commit the stored result.

- **Signed reads** skip the ledger (idempotent; validity window only).
- `pending_verification` and challenges are **never** stored as results.
- Keep: records survive until signed expiry; quota admission precedes record insertion; a rejection allocates
  nothing; retries after budget exhaustion still get stored results.
- **Change**: the "immutable object publication … resumed by the same signed operation" paragraph is replaced by the
  ticket lifecycle (§7.6/§7.7). Note in §9 that the M0 implementation still resumes interrupted `UploadPack`
  (overview Q5) until M1 tickets land.

### New §7.7 "Lifecycle per RPC (normative)"

Copy PRD §5.4's table and bullets exactly, adapted to spec voice:

| RPC | Admission | What its apply writes |
|---|---|---|
| `BeginUpload` (unary, names its target ref) | Yes | In the target ref's shard (D34): the replay record, a reservation row, the ticket |
| `UploadPack` / parts | No | Parts (client-streaming, S1 §7.6) only, authorized by the stateless ticket token; no metadata-shard write (D34). The ticket's audience, repo and signer, and its (pack_id, bytes), must equal the request's signer and commitment, otherwise `permission_denied`. |
| `AdvanceRefs` | No (uses the tickets) | In the same ref shard: head and packmap, the ref's membership additions (propagated to the repo index at least once), one `Committed` outcome per consumed ticket |

- Every RPC carries its own nonce.
- Membership happens only at `AdvanceRefs` apply. Before that, `BeginUpload` returns the existing ticket, never
  `AlreadyPresent`.
- If `apply` fails after `Allow{reservation}` (lost CAS, epoch mismatch, pack GC'd, replay race), a separate
  transaction records `Aborted`, so every reservation gets exactly one outcome.
- An expired ticket gets `Expired`.
- Outcome delivery (outbox, at least once) is specified in SPEC-SERVER (M3). Reference it informatively as
  "forthcoming".

### SPEC-TRANSPORT §7

Replace pr1087's hunk with: "An `AdmissionRequired` error (HTTP 402; see SPEC-TRANSPORT-CONNECT §5.1) is not a
`ServerError` for this rule and is never retried by the ladder."

## Keep / drop summary vs pr1087

- **Keep:** motivation paragraph; scheme/value/description size bounds; "no automatic retry"; helper is
  user-scoped, UNSAFE and trusted-remote-only; one helper run per operation; nonce reuse within validity.
- **Drop:** `resource_exhausted` code; single `{scheme, challenge}` (now a list); the `X-Admission-Credential`
  header; env-var + stdin-bytes/stdout-bytes credential protocol; "decide before replay-record insertion" as the
  only ordering rule (now the full lookup-first order); `UploadPack` first-header pricing (now `BeginUpload`-only).

## Validation

```bash
bash scripts/check-spec-status.sh
just ci-scripts
git diff --stat origin/feat/mkit-server -- proto/ rust/     # empty
```

Cross-check by eye that every PRD §6.3 bullet and every M3 exit item in PRD §8 has a normative sentence that makes
it testable: challenge → helper → credential → commit → exactly one `Committed`; aborted upload settles nothing;
retry after lost response returns the stored result without a new challenge; old client fails fast (402 +
`permission_denied`); hard-reserved headers can't be set through config.

## Acceptance criteria

- [ ] 402 + `permission_denied` + challenge-list detail; raw header pass-through; unary only; `BeginUpload`
      mandatory under admission (threshold 0).
- [ ] Order: authenticate → replay lookup → authorize → admission → reserve. Signed reads skip the ledger.
      Challenges and `pending_verification` are never stored.
- [ ] Per-RPC lifecycle table and the Aborted/Expired rules are present verbatim in meaning.
- [ ] Helper returns headers. Default allowlist, per-remote extension, hard-reserved set (incl. future `x-*` and the
      grant header), and the error names the offending header.
- [ ] Cache and CORS rules; bearer deployments advertise `header="Payment-Authorization"`; redaction rule.
- [ ] SPEC-CONFIG-SECURITY rows for both new keys (UNSAFE, user-scoped).
- [ ] SPEC-TRANSPORT §7 retry text updated. pr1087's `resource_exhausted` exception is gone.
- [ ] No grant-specific text (it stays generic "write authorization").
- [ ] Credit trailers and PR-body credit.

## Risks / gotchas

- SPEC-CONVENTIONS §6: MPP and x402 are protocols, so naming them in informative text is fine. Don't name `mppx` or
  any crate normatively.
- `Authorization` is conditionally allowlisted. Specify how the client knows the remote "already uses" it:
  `MKIT_API_TOKEN` bearer configured for that remote.
- Section numbers depend on S1's final §7.x numbering. Coordinate if S1 renumbers during review.
