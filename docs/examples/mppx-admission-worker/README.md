# mppx admission Worker (reference example)

> **Not a supported package.** This is documentation to read and copy into a
> deployment's own code. CI does not build it. It changes no Rust workspace,
> server implementation, or payment policy.

The example targets [`mkit.server.hooks.v1`](../../../proto/mkit/server/hooks/v1/hooks.proto)
with WP-3.6b's `AdmitRequest.credential_headers = 7` (`credentialHeaders` in
JSON). Merge that contract addition before or together with this example.
The exact JSON shapes are the [server-hooks goldens](../../../rust/tests/golden/server-hooks/).

## What it does

1. The client starts a push with a signed `BeginUpload`.
2. `Admit` returns a payment challenge; mkit sends the client a **402** with
   the matching `WWW-Authenticate: Payment …` header and admission detail.
3. The client's configured `admission_helper` obtains a Tempo credential.
4. The client retries the same signed body with that credential header.
5. mkit forwards its approved `credentialHeaders` to `Admit`, which calls
   `mppx.validateCredential` without settling.
6. `Admit` saves the credential under a fresh UUID reservation and returns
   `allow`. mkit records its own pending reservation and creates an upload ticket.
7. The upload finishes; a ticket-consuming `AdvanceRefs` commits the refs.
8. mkit durably records `Committed` and delivers the `Outcome` hook at least once.
9. The Worker calls `mppx.broadcastCredential`, confirms the payment, saves a
   settlement tombstone, and acknowledges with HTTP 200 and `{}`.

`Aborted` and `Expired` discard the remembered credential and mark the local
reservation released. Duplicate terminal deliveries return `{}`. Transient
settlement failures return HTTP 503 (`unavailable`) so the outbox retries.
Unknown reservations and conflicting terminal outcomes are never acknowledged.

The concrete method is **Tempo Moderato testnet charge, pull transactions only**,
with no fee sponsor. Push/hash credentials have already paid and are refused.
The example rate is one atomic token unit per declared byte, with a one-unit
minimum for zero-byte writes and six token decimals. For example, `16384` bytes
cost `0.016384` token units. The HMAC-authenticated challenge binds the mkit
server audience, repository, verified signer/principal, `packId`, declared
bytes and procedure through `meta` and `scope`; validation checks those same
expected parameters. Challenges have an example 24-hour lifetime.

Calls were checked against **mppx commit
[`dcf15895`](https://github.com/wevm/mppx/tree/dcf15895d08694374e04a879d4ac8ceb482b8eba)**:
[`Mppx.ts`](https://github.com/wevm/mppx/blob/dcf15895d08694374e04a879d4ac8ceb482b8eba/src/server/Mppx.ts),
[`Method.ts`](https://github.com/wevm/mppx/blob/dcf15895d08694374e04a879d4ac8ceb482b8eba/src/Method.ts),
[`Charge.ts`](https://github.com/wevm/mppx/blob/dcf15895d08694374e04a879d4ac8ceb482b8eba/src/tempo/server/Charge.ts),
and the [MPP documentation](https://mpp.dev/llms-full.txt).
`package.json` lists `mppx` 0.11.0, the version in that source; its installed
validation, broadcast, and challenge APIs were type-checked locally.

## Wiring

The default is an **unsigned, isolated Workers service binding** under
[SPEC-SERVER §7.3](../../specs/SPEC-SERVER.md#73-service-binding-channels).
The example's [`wrangler.jsonc`](wrangler.jsonc) disables `workers.dev` and
preview URLs and declares the `RESERVATIONS` Durable Object. It requires
`nodejs_compat` because the pinned SDK imports Node utilities.

In the **mkit Worker's** `wrangler.jsonc`, add:

```jsonc
{
  "services": [
    { "binding": "ADMISSION_HOOK", "service": "mppx-admission-reference" }
  ]
}
```

Configure the mkit deployment's hook adapter to call `ADMISSION_HOOK.fetch`
for both `POST /mkit.server.hooks.v1.HooksService/Admit` and
`POST /mkit.server.hooks.v1.HooksService/Outcome`, with `application/json`.
The adapter's configuration belongs to the deployment; this example does not
add a server setting. Enable only the hooks this example implements.

Set the recipient, token and RPC endpoint for the merchant's testnet account;
the checked-in recipient is a placeholder. Supply `MPP_SECRET_KEY` as a secret
for authenticating payment challenges. Set `MKIT_AUDIENCE` to the server's
canonical origin and `PAYMENT_REALM` to the merchant's payment realm. Keep the
secret and payment settings stable while reservations are outstanding.

For a bearer-authenticated mkit deployment, set
`BEARER_AUTHENTICATED = "true"`. `Mppx.create({ requiresAuth: true })` adds
`header="Payment-Authorization"` to every challenge; this example then reads
that credential header. With the flag false, the SDK uses `Authorization`.
The payment credential must never displace an existing `Authorization: Bearer`
token. mkit controls the client's 402 status, `Cache-Control: no-store`, CORS
and response-header pass-through under
[STC §5.1](../../specs/SPEC-TRANSPORT-CONNECT.md#51-admission-challenges).
The hook's own challenge response is HTTP 200 with an `AdmitResponse`.
No receipt is available at admission: settlement happens after commit.

**Optional HTTP with signatures.** If you expose an HTTPS route, first set
`HOOK_HTTP_SIGNATURES = "true"`, set `HOOK_AUDIENCE` to its canonical origin,
and supply `HOOK_KEY_LIST_JSON` with the trusted §7.2 key-list document. Do
not enable an unsigned public route. The hook key role must be separate from
write, grant and receipt keys. Configure mkit to sign each delivery attempt
with a fresh nonce; do not follow redirects.

The separate `verifyHookSignature(request, keyList)` function checks
[SPEC-SERVER §7.1](../../specs/SPEC-SERVER.md#71-signed-requests): required
headers before body reads, the exact receiving procedure, trusted hook audience,
request and key validity windows, exact-body BLAKE3 digest, the eight-field
canonical string and strict Ed25519 signature. The exported
`createHookVerifier(policy)` binds that function to a policy supplying the trusted
origin, clock (only overridden for goldens), and atomic nonce-cache callback.
The Worker uses the Durable Object cache, retaining each accepted nonce through
expiry. `@noble/ed25519` uses `zip215: false` plus explicit small-order public
key and R rejection, plus the uncofactored verification equation used by
Rust's `verify_strict`. `@noble/hashes/blake3` computes both 32-byte digests.
The hook audience is distinct from `operation.audience`/`outcome.audience`.

## Mapping to the contract

All names below use canonical proto JSON: lowerCamelCase, string-encoded
64-bit integers, base64 byte fields and symbolic enum values. Oneofs appear
as their selected field, never as a `kind` or `decision` wrapper.

| Hook field | Example use |
|---|---|
| `operation.audience` | Checks `MKIT_AUDIENCE`; binds it into the challenge and reservation. |
| `operation.repository` | Full repository identity; challenge binding and outcome consistency check. |
| `operation.procedure` | Client RPC path, bound into the challenge; different from the hook path. |
| `operation.principal.signer.ed25519PublicKey` | Verified signer's base64 public key in payment metadata. |
| `operation.principal.anonymous`, `.bearerHolder`, `.transportPeer`, `.sshForcedCommand` | Other verified identity classes; binds their complete JSON identity when no signer is present. Bearer secrets are absent. |
| `operation.idempotencyKey` | Deliberately unused for payment or reservation identity; mkit owns request replay. |
| `operation.refs[].name`, `.any`/`.missing`/`.expected`, `.new`, `.delete` | mkit's intended ref effects; this rate does not price or authorize refs. |
| `operation.owner`, `operation.grant.grantId`, `.epoch` | Already established authorization facts; no extra authorization decision here. |
| `declaredBytes` | Parses uint64 string using `BigInt`; sets the example price and binding. Missing means protobuf zero. |
| `packId` | Base64 pack id in the binding; empty for ref-only operations. |
| `createsNamespace`, `createsRepo` | Available creation facts; this example adds no creation surcharge. |
| `newToRepoBytes` | Unused for pricing; absence remains unknown and present `"0"` remains known zero. |
| `credentialHeaders[].name`, `.value` | WP-3.6b's ordered credential pairs; finds the configured payment header case-insensitively and rejects duplicates. Never logged. |
| `challenge.challenges[].scheme`, `.value` | `payment` and the full serialized MPP `Payment …` challenge. |
| `challenge.description` | Public explanation of delayed settlement, within 512 UTF-8 bytes. |
| `challenge.responseHeaders[].name`, `.value` | Matching `WWW-Authenticate`, within the eight-header and 8,192-byte limits. |
| `allow.reservationId` | Fresh `mppx:<UUID>` for every allowance, within the 128-byte grammar; never derived from a client nonce. |
| `allow.responseHeaders` | Omitted: there is no settlement receipt yet. |
| `deny.code`, `.message` | `permission_denied` with fixed public text; credentials and SDK exceptions stay private. |
| `outcome.reservationId` | Durable reservation lookup and idempotency key. |
| `outcome.audience`, `.repository` | Must match the reservation before acknowledging. |
| `outcome.occurredUnixMs` | Server's int64 timestamp; not used as settlement time or an expiry deadline. |
| `outcome.committed.bytesStored`, `.newToRepo`, `.newToStore`, `.refs[].name`, `.new`, `.deleted` | Commit selects settlement; accounting/ref facts do not change the amount originally authorized. `newToStore` is never an admission input. |
| `outcome.aborted.reason`, `.detail` | Select release; the enum and operator detail are not sent to clients or logged. |
| `outcome.expired` | Empty-message terminal kind selects release. |
| `outcome.readServed.object`, `.bytesServed` | Paid reads are outside this storage example; returns non-2xx rather than falsely acknowledging. |
| `OutcomeResponse` | Empty JSON object `{}` with HTTP 200 after settlement or release, including duplicates. |

## Caveats

- **Q-M3-4:** payment methods that settle at verification time make `Aborted`
  a **refund**, rather than a release. This example selects pull transactions
  and calls the non-mutating API; substituting a method requires reviewing its
  actual validation and settlement behavior.
- Validation is an advisory pre-check, **not a hold on funds**. A payer can
  spend funds elsewhere, broadcast the transaction independently, or let it
  expire. `Committed` cannot be undone by a settlement failure. Align challenge
  and transaction validity with upload-ticket lifetime and settlement retries;
  the 24-hour challenge setting alone does not extend a client's transaction.
- **Exactly-once settlement is the example's job.** mkit supplies at-least-once
  outcomes. The Durable Object serializes calls and retains reservation
  tombstones. It claims both challenge id and canonical transaction hash at
  admission, so one payment cannot fund multiple allowances. Each successful
  allowance still gets a fresh reservation id.
- Before the first broadcast the object durably stores `settling`. On recovery,
  it queries the saved transaction hash and, if absent, resends only the same
  canonical signed bytes. Chain replay protection prevents a second transfer;
  a successful receipt with the expected token, sender, recipient, amount and
  challenge-bound memo closes the payment-success/local-write crash window.
  The pinned SDK keeps its replay claim after an ambiguous broadcast failure,
  so blindly retrying `broadcastCredential` cannot resolve that case. Failed
  or expired transactions continue returning 503 for reconciliation; a copied
  deployment needs an operator policy for permanently unpaid committed writes.
- Release here deletes the local credential, not an on-chain authorization.
  Once issued, the signed transaction may still be broadcast by its holder.
  Receipt confirmation trusts the configured Tempo RPC and its finality model.
  This example does not refund, sponsor fees, or handle chain reorganizations.
- The one-object layout is intentionally small and serializes all calls. It
  retains tombstones, payment claims and nonce rows without a cleanup service.
  A deployment must bound traffic/storage and define retention and reconciliation,
  including a hook allowance lost before mkit records its pending reservation.
- The example rate and minimum are **not pricing advice**. This package has no
  lockfile, CI, deployment automation or support commitment.
- Informative only: x402 maps to the same hook split through facilitator
  `/verify` at admission and `/settle` on `Committed`. This example does not
  implement x402 or select a facilitator.

## Verifying the example

Optional local check from this directory; nothing is added to CI:

```sh
npm install --no-package-lock --ignore-scripts
npx tsc --noEmit --strict --target ES2022 --module ESNext \
  --moduleResolution bundler --lib ES2022 --skipLibCheck src/index.ts
```

The explicit compiler flags replace a `tsconfig.json` so the example contains
exactly the four files in its brief. `skipLibCheck` skips dependency declaration
checking; the example itself is checked strictly. Do not commit `node_modules`
or a lockfile. No testnet funds, deployment, or payment broadcast is needed to
check the signature golden.

From this directory, run the following against the actual exported verifier:

```sh
node --import tsx --input-type=module <<'JS'
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { createHookVerifier } from './src/index.ts';
const { vectors } = JSON.parse(fs.readFileSync(
  '../../../rust/tests/golden/server-hooks/signature.json', 'utf8'));
const v = vectors[0];
const seen = new Set();
const keyList = { version: 1, keys: [
  { keyId: v.key_id, alg: 'ed25519', publicKey: v.public_key }
] };
const policy = {
  audience: v.audience, nowMs: BigInt(v.created_at_ms),
  consumeNonce: async nonce => {
    if (seen.has(nonce)) return false;
    seen.add(nonce); return true;
  }
};
const verifyHookSignature = createHookVerifier(policy);
const request = () => new Request(v.audience + v.procedure, {
  method: 'POST', headers: v.headers, body: v.body_utf8
});
const result = await verifyHookSignature(request(), keyList);
assert.equal(result.bodyDigest, v.body_digest);
assert.equal(result.canonical, v.canonical);
assert.equal(result.canonicalBlake3, v.canonical_blake3);
await assert.rejects(verifyHookSignature(request(), keyList), /nonce replay/);
console.log(JSON.stringify(result, null, 2));
JS
```

The Admit vector derives this exact body digest:

```text
body:46487a726404f5fa774b0590efda97473efed29c28329200d2220f0ae461ccc8
```

Its canonical UTF-8 text has eight fields and **no final newline**:

```text
mkit-hook:v1
test-hook-2026-09
https://hooks.example.test
/mkit.server.hooks.v1.HooksService/Admit
body:46487a726404f5fa774b0590efda97473efed29c28329200d2220f0ae461ccc8
1790424000000
1790424300000
b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1
```

The canonical BLAKE3-32 is
`7dbf6968a866f8ca2e51383ec40fcf41a0cd876c6a57ae8e060ca803f3ec4bdf`;
verification returns `verified: true`. The fixed test clock is necessary because
this golden is not a current delivery. The `Set` is only a single-process scratch
cache; the HTTP Worker uses the durable atomic callback. Never deploy the
fixture's test private key.
