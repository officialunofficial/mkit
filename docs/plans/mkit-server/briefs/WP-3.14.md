## Purpose

A deployment that sells storage (e.g. with MPP, the Machine Payments Protocol) implements mkit's admission and
outcome hooks in its own code. This example shows the whole loop in one small TypeScript Cloudflare Worker, using
the `mppx` SDK:
- challenge on a first attempt;
- verify the client's credential on retry, without settling;
- settle on `Committed`;
- release on `Aborted`/`Expired`.

It is a reference to read and copy, not a product.

## A. Fixed (do not change)

1. **Contract:**
   - `docs/specs/SPEC-SERVER.md` §5 (outcomes), §6 (hooks, JSON mapping, limits), §7 (channel auth; §7.3 service
     bindings) and §8 (failure behaviour);
   - `proto/mkit/server/hooks/v1/hooks.proto`;
   - the goldens in `rust/tests/golden/server-hooks/*.json`, which are the exact JSON shapes.
2. **Admission semantics:** STC §5.1 (challenges, the `WWW-Authenticate` pass-through, bearer deployments needing
   `header="Payment-Authorization"`, caching, redaction).
3. **The `mppx` API is external.** Use it exactly as the source defines it at commit `dcf15895`:
   `https://github.com/wevm/mppx/blob/dcf15895d08694374e04a879d4ac8ceb482b8eba/src/server/Mppx.ts`
   (`validateCredential`, `broadcastCredential`, and challenge creation), plus `src/Method.ts`, and the docs at
   `https://mpp.dev/llms-full.txt`.
   - Read them.
   - Don't invent option names or signatures.
   - If you can't confirm a call, mark it in the code with `// ILLUSTRATIVE: verify against mppx docs`, and list it in
     the PR body.
4. **Plan caveat Q-M3-4:** payment methods that settle at verification time make `Aborted` a refund rather than a
   release. The README must say so.

## B. Decided by the orchestrator (do not change)

### B.1 Files (exactly these; no lockfile, no `node_modules`, no CI wiring)

```
docs/examples/mppx-admission-worker/README.md
docs/examples/mppx-admission-worker/src/index.ts
docs/examples/mppx-admission-worker/wrangler.jsonc
docs/examples/mppx-admission-worker/package.json   # dependencies listed, no lockfile, "private": true
```

### B.2 Behaviour of `src/index.ts`

It is a Worker exposing the Connect/JSON unary routes `POST /mkit.server.hooks.v1.HooksService/Admit` and
`/Outcome`:

- **Admit:**
  - Read `credentialHeaders`: repeated `{name, value}` pairs, as in the proto.
  - **No credential** → an `AdmitResponse` with `challenge`:
    - one or more `challenges` entries `{scheme: "payment", value: <the MPP challenge string>}`;
    - `responseHeaders` carrying the matching `WWW-Authenticate: Payment …` field(s);
    - a human `description`.
    - Price from `declaredBytes`, using a clearly labelled example rate constant. Bind the challenge to the request
      as STC §5.1 "Binding" suggests: repository, signer, `packId` and bytes.
  - **Credential present** → validate it without settling (`validateCredential`).
    - Valid → `allow`, with a **fresh** `reservationId` (SPEC-SERVER §6.6: unique per allowance, never derived from
      `idempotencyKey`). Remember `reservationId → credential` in a KV or Durable Object binding named in
      `wrangler.jsonc`.
    - Invalid → `deny {code: "permission_denied", message}`.
  - Bearer-authenticated deployments: the challenge must carry `header="Payment-Authorization"` (STC §5.1). Show this
    as a config flag in the example.
- **Outcome:**
  - `committed` → settle (`broadcastCredential`) using the remembered credential, then acknowledge.
  - `aborted` and `expired` → release. Acknowledge with an empty `OutcomeResponse` (HTTP 200, `{}`).
  - It must be idempotent by `reservationId`: a repeated delivery acknowledges without settling twice (SPEC-SERVER
    §5, "at least once").
  - A transient settlement failure → return a non-2xx, so the server retries (§8).
- **Channel auth:**
  - The default wiring is a **service binding** from the mkit Worker (SPEC-SERVER §7.3, unsigned).
  - The README gives the `wrangler.jsonc` `services` snippet for the mkit side.
  - Also include, as a clearly separated optional function `verifyHookSignature(request, keyList)`, the §7.1
    verification: the eight-field canonical string, BLAKE3-32, strict Ed25519, the audience, validity-window and
    digest checks, and the nonce replay cache.
    - Use `@noble/ed25519` and `@noble/hashes/blake3`, and list them in `package.json`.
    - It must reproduce `rust/tests/golden/server-hooks/signature.json`. Show in the README the exact values the
      function derives for the Admit vector.
- **Never log credential headers or receipts** (STC §5.1 "Redaction"). Leave a comment where logging would be
  tempting.
- **JSON:** canonical proto JSON as in the goldens (lowerCamelCase, 64-bit integers as strings, bytes base64).

### B.3 `README.md` sections (these headings)

- `# mppx admission Worker (reference example)`, with a "Not a supported package" callout
- `## What it does`, the end-to-end sequence as a numbered list:
  1. client push;
  2. 402 challenge;
  3. `admission_helper`;
  4. retry with credential;
  5. Admit validates;
  6. allow;
  7. commit;
  8. `Committed` outcome;
  9. settle.
- `## Wiring`: the service binding, the optional HTTP-with-signatures mode, and `wrangler.jsonc`
- `## Mapping to the contract`: a table from each hook field to what the example does with it
- `## Caveats`: Q-M3-4 (settle-at-verify methods make `Aborted` a refund); exactly-once settlement is the example's
  job (idempotency by reservation id); the example rate is not pricing advice; x402 maps the same way (facilitator
  `/verify` and `/settle`), as an informative note only
- `## Verifying the example`: how to run `npx tsc --noEmit` locally (optional, not CI), and how to check
  `verifyHookSignature` against the golden

## C. Your decisions

- Code structure and helper names inside `src/index.ts`.
- KV vs a Durable Object for the reservation map (B.2), with a one-line justification.
- Exact prose.

## D. Escalate if

- The `mppx` API at the pinned commit has no way to validate without settling, or to settle a previously validated
  credential. That would break the two-phase mapping. Quote the source.
- The hooks contract (including 3.6b's field) can't express something the flow needs.

## Gates

- The repo's docs lint (see `.github/workflows/docs-lint.yml`; run its commands locally if they apply to
  `docs/examples/`).
- `npx tsc --noEmit --strict` inside the example dir, **if** you can install the dependencies without committing a
  lockfile. Otherwise say so in the PR.
- A scratch run of `verifyHookSignature` against the Admit vector in `signature.json`, with the output pasted in the
  PR body.
- Nothing outside `docs/examples/mppx-admission-worker/` and the brief copy changes, apart from a CHANGELOG line
  (Unreleased / Added, docs).
