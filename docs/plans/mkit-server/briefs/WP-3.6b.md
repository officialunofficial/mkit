## Purpose

The admission flow (STC §5.1) is:
1. The server challenges.
2. The client's admission helper produces credential headers (`Authorization: Payment …`, `Payment-Authorization`,
   `PAYMENT-SIGNATURE`).
3. The client retries with them.
4. **The deployment's admission verifies the credential.**

SPEC-SERVER §6 currently says hooks "do not receive arbitrary client credentials", and `AdmitRequest` has no field
for them, so a remote Admit hook can never verify a payment. This WP adds exactly the credential headers the
admission step needs, and nothing more.

## A. Fixed (do not change)

1. **STC §5.1:**
   - the client's header allowlist (`Payment-Authorization`, `PAYMENT-SIGNATURE`, and `Authorization` only when the
     client doesn't already send it);
   - the hard-reserved set;
   - "helper headers are not part of the auth v2 canonical string";
   - the redaction rule.
2. SPEC-SERVER structure and every other rule, as merged in #1142. The proto is additive only: `buf breaking` must
   pass.
3. SPEC-CONVENTIONS, including §6 (no vendor references).

## B. Decided by the orchestrator (do not change)

### B.1 Proto (`proto/mkit/server/hooks/v1/hooks.proto`)

Add to `AdmitRequest`, with a doc comment citing SPEC-SERVER §6.3:

```proto
  repeated Header credential_headers = 7;   // admission credential headers the client attached (SPEC-SERVER §6.3)
```

No other proto change.

### B.2 SPEC-SERVER text

- **§6 intro:** replace "Hook implementations do not receive arbitrary client credentials or object contents
  through this contract" with the rule that hooks receive **no** client credentials **except** the admission
  credential headers of §6.3, and no object contents.
- **§6.2:** the sentence "The hook receives the established principal, not a credential to verify on the client's
  behalf" stays true for Authorize. Say that it applies to Authorize, and point to §6.3 for Admit.
- **§6.3,** a new paragraph, "Credential headers":
  - The server forwards, in `credential_headers`, the request headers that STC §5.1 lets a client attach from its
    admission helper. It never forwards any other header.
  - **Default forwarded names** (case-insensitive): `Payment-Authorization`, `PAYMENT-SIGNATURE`, and
    `Authorization` **only when its value's scheme token is `Payment`** (case-insensitive). A bearer token is never
    forwarded.
  - A deployment MAY configure additional names. It MUST NOT forward any STC §5.1 hard-reserved name, whatever its
    configuration.
  - Names are sent as received. Repeated fields are sent as repeated entries, in order.
  - At most 8 entries, each value at most 8,192 bytes. The server answers a request with more, or longer, as an
    admission denial: `permission_denied`, per STC §5's admission-denial row. It does so without calling the hook,
    and writes no state.
  - An empty list means the request carried no credential. That is the normal first attempt, which the hook
    typically answers with a challenge.
  - These headers are payment credentials. The server and the hook MUST keep them out of logs, traces, error
    messages and analytics (cite STC §5.1 "Redaction"). The hook channel's protection is §7 (signed request over
    verified TLS, or binding isolation).
  - Informative: because the request body is signed (§7.1 `body:` digest), the credential headers are covered by
    the hook-channel signature.
- **§6.6:** add the forwarding bounds above to the limits list.
- **§14:** add a version-history row: version 1 draft, "admission credential headers".
- **§15:** update the rows for the goldens you change.

### B.3 Goldens (`rust/tests/golden/server-hooks/`)

- **`admit.request.json`:** add one `credentialHeaders` entry with an obviously fake MPP credential, e.g. name
  `Payment-Authorization`, value `Payment fake-example-credential-not-valid`.
- **Add `admit-first-attempt.request.json`** with no `credentialHeaders`, and map it in
  `scripts/check-server-hooks-goldens.sh`.
- **`signature.json`:** its Admit vector references `admit.request.json`, so regenerate it with `UPDATE_GOLDEN=1`.
  The body bytes change, and so do the digest and signature. Regenerate `MANIFEST.txt`.
- Verify independently that the regenerated Admit vector verifies, e.g. with a scratch Python script using `blake3`
  and `nacl`. Record the command in the PR body.

### B.4 Plan note

Add row `R-92` to `docs/plans/mkit-server/00-plan.md`:

> hooks.v1 `AdmitRequest.credential_headers` (WP-3.6b): the admission step needs the client's credential headers.
> WP-3.2 must add them to the Rust `AdmissionInput`, with the same default name set and bounds. WP-3.7 forwards
> them.

CHANGELOG: one line under Unreleased / Added.

## C. Your decisions

- The wording of the new paragraphs, within B.2.
- The fake example values.

## D. Escalate if

- `buf lint` or `buf breaking` rejects B.1.
- B.2 contradicts STC §5.1 in any case, e.g. an `Authorization: Payment` header on a bearer deployment. Quote the
  passages.

## Gates

- `buf lint`
- `buf breaking --against '.git#branch=origin/feat/mkit-server'`
- `bash scripts/check-server-hooks-goldens.sh`
- `cargo nextest run --locked -p mkit-server --test golden_server_hooks`
- `bash scripts/check-spec-status.sh`
- The goldens outside `server-hooks/` are unchanged.
