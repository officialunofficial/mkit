## Purpose

The M3 remote-hook adapter (WP-3.7) and its channels (3.8 native HTTP, 3.9 Workers binding/Queue) need a written
contract: what a deployment's business logic receives and returns, how the server authenticates to it, and what the
server guarantees about outcomes. Implementers (for example a TypeScript payments Worker) build against this spec and
the proto alone, with no mkit Rust code. This WP writes that contract:
- a new `docs/specs/SPEC-SERVER.md` (M3 sections, plus headings reserved for M5);
- a new proto `proto/mkit/server/hooks/v1/hooks.proto`;
- golden vectors under `rust/tests/golden/server-hooks/`;
- one Rust test that pins the signature vectors.

## A. Fixed by the plan and specs (do not change)

1. **Plan and PRD:**
   - `docs/plans/mkit-server/m3-m5-breakdown.md` "WP-3.6" and "WP-3.3" (outbox guarantees);
   - `docs/plans/mkit-server/prd-snapshot.md` §5.4 (pipeline, lifecycle, remote hooks), §6.10 (SPEC-SERVER scope) and
     §7 (mkit vs implementer boundary);
   - decisions D11 (Rust traits + remote-hook adapter), D18 (inspection) and Q-M3-1 (a per-role Ed25519 hook key and
     a key list; **no HMAC**).
2. **Wire-visible rules already live in `docs/specs/SPEC-TRANSPORT-CONNECT.md` (STC). SPEC-SERVER cites them by
   section and MUST NOT restate or paraphrase them normatively.** In particular:
   - the processing order of a signed write: STC §7.1, the numbered list after "A server processes a signed write in
     this order";
   - admission challenges, their bounds, header pass-through, caching, CORS and redaction: STC §5.1;
   - namespace and write policy: STC §7.5;
   - tickets and parts: STC §7.6;
   - the per-RPC lifecycle table: STC §7.7.

   Where SPEC-SERVER needs one of these rules, write "as STC §x.y requires" and add only what is server-internal.
3. **SPEC-CONVENTIONS applies in full:**
   - frontmatter `spec`/`version`/`status`/`audience`, with `status: draft-normative`;
   - RFC 2119 keywords;
   - §4, a new domain separator for a new key use;
   - §5, goldens are the authoritative bytes and ship in the same change;
   - §6, **no vendor references**: no crate, library, Rust type or file names in normative text. The word "Workers"
     appears only as an informative example of a deployment.
4. **The existing Rust hook surface is the source to mirror** (`rust/crates/mkit-server/src/pipeline/hooks.rs`,
   `op.rs`, `principal.rs`, `mkit-core/src/refs.rs` `RefWriteCondition`). The proto mirrors its *information*, not
   its Rust shapes. Mkit-internal quota charges (`AdmissionDecision::Allow.charges`) are NOT on the wire: a remote
   admission returns none.
5. **Proto conventions:**
   - `edition = "2023"`, as in `proto/mkit/transport/v1/transport.proto`;
   - package `mkit.server.hooks.v1`;
   - the file lives in the existing root `proto` buf module (`buf.yaml` `path: proto`). **Do not change `buf.yaml`.**
   - `buf lint` (default rules for that module) and `buf breaking` must pass.
   - No Rust codegen in this WP. WP-3.7 generates into `mkit-server/generated/`.

## B. Decided by the orchestrator (do not change)

### B.1 SPEC-SERVER structure (exact headings, in this order)

```
---
spec: SPEC-SERVER
version: 1
status: draft-normative
audience: implementers of mkit.transport.v1 servers and of deployment business logic behind the remote-hook contract
---
# SPEC-SERVER — server pipeline guarantees and the remote-hook contract
## 1. Scope and relation to SPEC-TRANSPORT-CONNECT
## 2. Pipeline order
## 3. Per-RPC lifecycle
## 4. Fail-closed rules
## 5. Outcomes and the outbox
## 6. Remote hooks: mkit.server.hooks.v1
### 6.1 Transport and codec
### 6.2 Authorize
### 6.3 Admit
### 6.4 Inspect (provisional)
### 6.5 Outcome
### 6.6 Limits and response validation
## 7. Hook channel authentication
### 7.1 Signed requests
### 7.2 Key list and rotation
### 7.3 Service-binding channels
## 8. Per-hook failure behaviour
## 9. Published view (reserved, M5)
## 10. Quarantine (reserved, M5)
## 11. Admin API and audit log (reserved, M5)
## 12. Custom backends, backup and migrations (reserved, M5)
## 13. Conformance scope (reserved, M5)
## 14. Version history
## 15. Test anchors
```

- §9–§13 each contain exactly one sentence: "Reserved: this section is specified with M5 (see the version history)."
- §14 has one row: version 1, draft.
- §15 lists every golden file of B.4 and what it pins.

### B.2 Content decisions per section

- **§1:**
  - This spec covers server-internal guarantees and the hook contract; STC covers the client-visible wire.
  - Conformance: a server that runs remote hooks MUST implement §5–§8.
  - A server without remote hooks MUST still implement §2–§5.
- **§2:** Stages 0–9 exactly as PRD §5.4, written without vendor names:
  0 authenticate + replay lookup (cite STC §7.1); 1 identity; 2 authorize; 3 admit; 4 replay reservation and the
  streamed body; 5 pre-receive checks, including synchronous inspection; 6 atomic apply including the outbox row;
  7 receipt signing; 8 outcome delivery; 9 asynchronous inspection and lease events.
  Normative rules to state:
  - a) No stage before 4 writes state, except that a quota *reservation* made by admission is committed with the
    apply (the default quota).
  - b) Stage 2 runs before any quota or replay record is allocated.
  - c) A challenge or a denial at stages 2–3 writes nothing (cite STC §5.1).
  - d) Signed reads skip the replay ledger (cite STC §7.1).
  - e) Unary RPCs only are admitted (cite STC §5.1).
- **§3 (amendment 1):**
  - Cite STC §7.7 for what each RPC's apply writes. Restate nothing from its table.
  - Add only these server-internal rules, as normative text:
    - **a. `BeginUpload`:** the replay record, the reservation and the ticket commit in one atomic unit, in the target
      ref's shard.
    - **b. `AdvanceRefs` that consumes tickets:** the head, the packmap, the membership additions, and one `Committed`
      outcome record per consumed ticket commit in one atomic unit, in that ref's shard.
    - **c. A directly admitted unary write** (`UpdateRef`, including deletion, and an `AdvanceRefs` that consumes no
      ticket): its ref write and its `Committed` outcome record commit in one atomic unit.
    - **d. `Aborted` is recorded in a separate atomic unit** after the failed apply (cite STC §7.7). An `AdvanceRefs`
      that ends in a typed conflict consumes no ticket and records no outcome: its tickets stay usable (cite STC
      §7.7 "Conflicts").
    - **e. A pack becomes a member of the repository only at the apply of the `AdvanceRefs` that consumes its ticket**
      (cite STC §7.7).
  - Do NOT describe key layouts, partitions or shard kinds beyond "the target ref's shard", which STC §7.7 uses.
- **§4:** A bulleted list of fail-closed rules:
  - a missing or unsupported auth version (cite STC §7.1);
  - authorize/admit hook failure (§8);
  - a hook response that breaks §6.6;
  - a store failure never reported as success;
  - an unknown scheduled-work kind is retained, never discarded;
  - startup refusal of `namespace_policy = any` with the default admission unless explicitly overridden (cite STC
    §7.5);
  - an outcome is never dropped.
- **§5 (normative):**
  - exactly one outcome per reservation: `Committed`, `Aborted` or `Expired`, plus `ReadServed` for paid reads;
  - delivery is at least once, with the reservation id as the idempotency key;
  - there is no ordering guarantee between reservations;
  - `Aborted` is written in a separate atomic unit after a failed apply;
  - `Expired` when a ticket expires unconsumed;
  - **Pending reservations (amendment 1).**
    - For every admitted RPC whose admission returned a reservation, the server MUST durably record the reservation
      as *pending* before the apply it guards.
    - That apply replaces the pending record: with the ticket for `BeginUpload` (rule a), or with the `Committed`
      outcome for a directly admitted write (rule c).
    - A failed apply replaces it with `Aborted` (rule d).
  - **Reconcile (amendment 1).**
    - A periodic reconcile pass records `Aborted` with reason `ABANDONED` for every pending reservation whose
      operation's authentication validity (STC §7.1: at most 300,000 ms) has passed without either replacement.
    - A ticket that expires unconsumed produces `Expired` (cite STC §7.7).
    - Every reservation gets exactly one outcome, crashes included.
  - Informative: the pending record costs one extra atomic unit per admitted write. It exists only when a deployment's
    admission returns reservations, so the default quota admission pays nothing.
  - An outcome is retained until acknowledged.
  - **Backpressure:** a server MAY refuse new *admitted* writes with a retryable `unavailable` while its undelivered
    outcome backlog exceeds a configured bound. It MUST NOT drop outcomes, and reads and non-admitted writes are
    unaffected.
  - Settlement semantics (informative): settle on `Committed`, release on `Aborted`/`Expired`.
  - `new_to_store` bytes appear only in `Committed` (cite STC §5.1's rule on the admission input).
- **§6.1:**
  - Connect protocol, unary, over HTTPS.
  - **JSON codec (`application/json`) is REQUIRED** for hook servers; the binary codec MAY be supported. The server
    MUST send JSON unless configured otherwise.
  - Canonical protobuf JSON mapping: lowerCamelCase field names, `bytes` as standard base64, 64-bit integers as JSON
    strings.
  - Service `mkit.server.hooks.v1.HooksService`; paths `/mkit.server.hooks.v1.HooksService/{Authorize,Admit,Inspect,Outcome}`.
  - A deployment MAY implement any subset; the server calls only the hooks it is configured to use.
  - Plain HTTP only to loopback hosts. Redirects MUST NOT be followed.
- **§6.2–§6.5:** Semantics of each request and response field, following B.3.
  - Authorize's Deny codes are an allowlist: `permission_denied`, `not_found`, `unauthenticated`,
    `resource_exhausted`, `failed_precondition`. Any other code is treated as `permission_denied`.
  - The Deny message is public text for the client, at most 512 bytes of UTF-8, with no control characters;
    otherwise the server replaces it with a generic message.
- **§6.4 Inspect** is marked **provisional**: its call shape is fixed, and M5 may add fields additively.
  - Object bytes are NOT sent in the request.
  - The hook fetches content out of band if it needs it (informative: through the deployment's object serving).
- **§6.6 limits** (a response breaking any of them is invalid, handled per §8):
  - response body at most 65,536 bytes;
  - `Challenge` entries within STC §5.1's bounds (1–8 entries; the scheme token; value ≤ 8,192 bytes; description ≤
    512 bytes);
  - pass-through headers:
    - on a Challenge, only `WWW-Authenticate` (repeatable) and `PAYMENT-REQUIRED`;
    - on Allow, only `Payment-Receipt` and `PAYMENT-RESPONSE`;
    - at most 8 headers per response, each value ≤ 8,192 bytes of visible ASCII plus SP;
    - names compared case-insensitively;
  - `reservation_id`: 1–128 bytes of `[A-Za-z0-9._:-]`;
  - in `Admit`, `allow.reservation_id` is REQUIRED (the server keys outcomes by it).
- **§7.1 Signed requests:** every hook request, including `Outcome` delivered as a webhook, is signed with a
  deployment hook key.
  - The signature is strict Ed25519 over the 32-byte BLAKE3 of the following eight newline-separated UTF-8 fields,
    with no final newline:
    ```text
    mkit-hook:v1
    <key id>
    <audience>
    <full procedure>
    body:<64 lowercase hex BLAKE3 of the exact request body bytes>
    <created epoch milliseconds>
    <expiry epoch milliseconds>
    <nonce>
    ```
  - `<audience>` is the hook endpoint's canonical origin, with the same origin rules as STC §7.1's audience.
  - `<full procedure>` is the Connect path.
  - The nonce is 32 random bytes as 64 lowercase hex.
  - The validity interval is positive and at most 300,000 ms, and the sender may lead by at most 30,000 ms (same
    numbers as STC §7.1).
  - Headers, all REQUIRED: `X-Mkit-Hook-Version: 1`, `X-Mkit-Hook-Key-Id`, `X-Mkit-Hook-Audience`,
    `X-Mkit-Hook-Created-At`, `X-Mkit-Hook-Expires-At`, `X-Mkit-Hook-Nonce`, `X-Mkit-Hook-Digest`
    (`body:<hex>`), and `X-Mkit-Hook-Signature` (128 lowercase hex).
  - A hook server MUST:
    - verify the signature against the key list;
    - check the audience equals its own origin;
    - check the validity window;
    - check the digest against the body;
    - reject replays of a nonce within the validity window. `Outcome` is additionally idempotent by
      `reservation_id`.
  - `mkit-hook:v1` is a new domain separator (SPEC-CONVENTIONS §4). The hook key MUST NOT be any key used for
    `mkit-write:v2`, grants or receipts: distinct keys per role.
  - **Key id:** 1–64 bytes of `[A-Za-z0-9._-]`, chosen by the deployment.
- **§7.2 Key list:**
  - A JSON document:
    `{"version":1,"keys":[{"keyId":"…","alg":"ed25519","publicKey":"<64 lowercase hex>","notBeforeMs":"<int64 string, optional>","notAfterMs":"<int64 string, optional>"}]}`.
  - Rotation: publish the new key alongside the old one, switch signing, and retire the old key after the longest
    validity interval has passed.
  - The document is distributed out of band by default. A server MAY serve it at `GET /.well-known/mkit-hook-keys.json`
    (unauthenticated, `Cache-Control: max-age=300`).
  - A hook server MUST reject a key id that is not in its current list, and MUST honour `notBeforeMs`/`notAfterMs`.
- **§7.3:** On a platform service binding that is not reachable from the public internet (informative: a Workers
  service binding), a deployment MAY disable request signing for that channel. Everything in §6 still applies.
- **§8 Per-hook failure behaviour:**
  - **Authorize and Admit** fail closed. A transport error, a timeout, a non-2xx status, a Connect error other than
    Authorize's Deny, or an invalid response (§6.6) denies the operation with retryable `unavailable`, and writes no
    state.
    - Timeouts are deployment configuration (informative: default 5 s).
    - A deliberate `Deny` in a 2xx response is not a failure.
  - **Outcome:** retried with exponential backoff and jitter (informative: 1 s initial, factor 2, capped at 15 min)
    until acknowledged. It is never dropped. Any 2xx Connect response is an acknowledgement.
  - **Inspect:** follows the inspector's configured mode (fail-closed rejects the push; publish proceeds and
    quarantines later), per D18.

### B.3 The proto (`proto/mkit/server/hooks/v1/hooks.proto`): names, numbers and types are final

```proto
edition = "2023";
package mkit.server.hooks.v1;

service HooksService {
  rpc Authorize(AuthorizeRequest) returns (AuthorizeResponse);
  rpc Admit(AdmitRequest) returns (AdmitResponse);
  rpc Inspect(InspectRequest) returns (InspectResponse);
  rpc Outcome(OutcomeRequest) returns (OutcomeResponse);
}

// ---- shared ----
message Operation {
  string audience = 1;            // the server's canonical origin
  string repository = 2;          // full repository identity (STC §7.4)
  string procedure = 3;           // full procedure path of the client RPC
  Principal principal = 4;
  string idempotency_key = 5;     // auth v2 nonce of a signed write; empty otherwise
  repeated RefChange refs = 6;    // ref writes the operation intends, in decision order
  bool owner = 7;                 // the principal is the namespace owner (set for Admit)
  GrantUsed grant = 8;            // the write grant used, if any (set for Admit; M2)
}
message Principal {
  oneof kind {
    Anonymous anonymous = 1;
    Signer signer = 2;
    BearerHolder bearer_holder = 3;
    TransportPeer transport_peer = 4;
    SshForcedCommand ssh_forced_command = 5;
  }
}
message Anonymous {}
message Signer { bytes ed25519_public_key = 1; }          // 32 bytes
message BearerHolder {}                                     // the token is never sent
message TransportPeer { bytes ed25519_public_key = 1; }   // 32 bytes
message SshForcedCommand { bytes ed25519_public_key = 1; } // 32 bytes, or empty if unknown
message RefChange {
  string name = 1;
  oneof condition {
    Unconditional any = 2;
    MustNotExist missing = 3;
    bytes expected = 4;           // 32-byte id the ref must hold
  }
  bytes new = 5;                  // 32-byte id; empty when delete = true
  bool delete = 6;
}
message Unconditional {}
message MustNotExist {}
message GrantUsed { bytes grant_id = 1; uint64 epoch = 2; }   // 32-byte grant id
message Header { string name = 1; string value = 2; }

// ---- Authorize ----
message AuthorizeRequest { Operation operation = 1; }
message AuthorizeResponse {
  oneof result {
    AuthorizeAllow allow = 1;
    Deny deny = 2;
  }
}
message AuthorizeAllow {}
message Deny {
  string code = 1;                // Connect code name, allowlist in SPEC-SERVER §6.2
  string message = 2;             // public text, at most 512 bytes
}

// ---- Admit ----
message AdmitRequest {
  Operation operation = 1;
  uint64 declared_bytes = 2;
  bytes pack_id = 3;              // 32 bytes for BeginUpload; empty otherwise
  bool creates_namespace = 4;
  bool creates_repo = 5;
  uint64 new_to_repo_bytes = 6;   // explicit presence (edition 2023 default): absent when unknown
}
message AdmitResponse {
  oneof decision {
    AdmitAllow allow = 1;
    AdmitChallenge challenge = 2;
    Deny deny = 3;
  }
}
message AdmitAllow {
  string reservation_id = 1;      // REQUIRED
  repeated Header response_headers = 2;   // Payment-Receipt / PAYMENT-RESPONSE only
}
message AdmitChallenge {
  repeated Challenge challenges = 1;      // STC §5.1 bounds
  string description = 2;
  repeated Header response_headers = 3;   // WWW-Authenticate / PAYMENT-REQUIRED only
}
message Challenge { string scheme = 1; string value = 2; }

// ---- Inspect (provisional) ----
message InspectRequest {
  Operation operation = 1;
  repeated InspectObject objects = 2;
}
message InspectObject { bytes id = 1; uint64 size = 2; }   // 32-byte object id
message InspectResponse {
  oneof verdict {
    InspectPass pass = 1;
    InspectQuarantine quarantine = 2;
    Deny reject = 3;
  }
}
message InspectPass {}
message InspectQuarantine { string reason = 1; }

// ---- Outcome ----
message OutcomeRequest { Outcome outcome = 1; }
message OutcomeResponse {}
message Outcome {
  string reservation_id = 1;
  string audience = 2;
  string repository = 3;
  int64 occurred_unix_ms = 4;
  oneof kind {
    Committed committed = 5;
    Aborted aborted = 6;
    Expired expired = 7;
    ReadServed read_served = 8;
  }
}
message Committed {
  uint64 bytes_stored = 1;
  uint64 new_to_repo = 2;
  uint64 new_to_store = 3;
  repeated CommittedRef refs = 4;
}
message CommittedRef { string name = 1; bytes new = 2; bool deleted = 3; }
message Aborted {
  AbortReason reason = 1;
  string detail = 2;              // operator text, at most 512 bytes; not shown to clients
}
enum AbortReason {
  ABORT_REASON_UNSPECIFIED = 0;
  ABORT_REASON_REF_CONFLICT = 1;      // lost compare-and-swap
  ABORT_REASON_EPOCH_MISMATCH = 2;
  ABORT_REASON_PACK_MISSING = 3;
  ABORT_REASON_REPLAY_RACE = 4;
  ABORT_REASON_INTERNAL = 5;
  ABORT_REASON_ABANDONED = 6;   // no recorded apply result; reconcile pass (SPEC-SERVER §5)
}
message Expired {}
message ReadServed { bytes object = 1; uint64 bytes_served = 2; }
```

- Add a doc comment to every message and field, citing SPEC-SERVER sections.
- If `buf lint`'s default rules reject a name above (e.g. `ENUM_ZERO_VALUE_SUFFIX` or `RPC_*_STANDARD_NAME`), that
  is a §D stop, not a rename.
- **Do not** add a `lint.ignore_only` entry to `buf.yaml`.

### B.4 Golden vectors (`rust/tests/golden/server-hooks/`)

1. **One JSON file per message instance, in canonical proto JSON:** `authorize.request.json`,
   `authorize-allow.response.json`, `authorize-deny.response.json`, `admit.request.json`,
   `admit-allow.response.json`, `admit-challenge.response.json`, `admit-deny.response.json`, `inspect.request.json`,
   `inspect-pass.response.json`, `outcome-committed.request.json`, `outcome-aborted.request.json`,
   `outcome-expired.request.json`, `outcome-abandoned.request.json`, `outcome-read-served.request.json`, `outcome.response.json`.
   - Use realistic values: a `0x…`/`ed25519-…` repository identity, a signer principal, a `BeginUpload` admit with a
     `pack_id`, and an MPP-shaped `WWW-Authenticate` pass-through header whose value is an obviously fake example.
2. **`signature.json`:** at least two vectors (an `Admit` request and an `Outcome` webhook). Each has:
   - the 32-byte Ed25519 test seed (hex, clearly labelled as a test key);
   - the public key and key id;
   - every canonical field;
   - the exact canonical string (JSON-escaped);
   - its BLAKE3;
   - the signature;
   - the full header set;
   - the exact body bytes, which must equal one of the JSON goldens byte for byte, referenced by file name.
3. **`key-list.json`:** a §7.2 key-list document holding the test public key.
4. **`MANIFEST.txt`,** in the format of `rust/tests/golden/transport/MANIFEST.txt`: a header comment, then
   `<name> <blake3-hex>` per file.
5. **Pinning test `rust/crates/mkit-server/tests/golden_server_hooks.rs`,** with no new crate dependency beyond what
   `mkit-server` already has as a dependency or dev-dependency:
   - (a) every MANIFEST hash matches;
   - (b) for each signature vector:
     - rebuild the canonical string from its fields and assert equality;
     - recompute the BLAKE3;
     - derive the public key from the seed;
     - re-sign, which is deterministic for Ed25519, and assert the stored signature;
     - verify the signature;
     - assert `X-Mkit-Hook-Digest` equals `body:` + the BLAKE3 of the referenced golden file's bytes;
   - (c) `UPDATE_GOLDEN=1` rewrites `signature.json` and `MANIFEST.txt`, following `mkit-git-bridge/tests/golden.rs`.
6. **Schema check script `scripts/check-server-hooks-goldens.sh`:**
   - For every `*.request.json`/`*.response.json`, run
     `buf convert proto --type mkit.server.hooks.v1.<Message> --from <file>#format=json --to -#format=json`.
   - Fail if any file doesn't parse, or if the round-tripped JSON differs from the file after normalisation with
     `jq -S .`.
   - The mapping from file name to message type is a table in the script.
   - Wire the script into the same `justfile` recipe that runs `buf lint`, so it runs wherever buf runs.

### B.5 Index and cross-references

- Add one row for SPEC-SERVER to `docs/specs/README.md`, in that file's existing format.
- If a check enforces parity between the spec list and the web site's spec list (search for one, e.g.
  `apps/web/src/lib/spec-data.ts` and any test or script reading it), update that list too. Otherwise don't touch
  `apps/web`.
- Add one informative line to STC §8 ("Out of scope"): "the remote-hook contract and outcome guarantees: see
  SPEC-SERVER." That is the only STC edit.
- CHANGELOG: one line under Unreleased / Added.

## C. Your decisions (record each in the PR under "Executor decisions")

- Prose wording, examples and informative notes within B.1/B.2. Keep it tight: target 500–800 lines of spec.
- The golden example values (B.4.1), and the second signature vector's procedure.
- The golden test's internal structure, and how the script normalises JSON (only `jq -S`).
- Whether §6 includes one informative end-to-end sequence (client → server → Admit → 402 → retry → Allow → apply →
  Outcome). Recommended: include it, as a numbered list, not a diagram.

## D. Escalate (stop and report, do not improvise) if

- `buf lint` or `buf breaking` rejects any B.3 name, number or type.
- A B.2 rule contradicts STC or SPEC-WRITE-GRANTS text. Quote both passages.
- A PRD §5.4 guarantee can't be stated without describing key layouts or partitions.
- `buf convert` can't round-trip canonical JSON for a B.3 message (e.g. optional-field presence in edition 2023).

## Gate additions

- `buf lint`, and `buf breaking --against '.git#branch=origin/feat/mkit-server'`, from the repo root.
- `bash scripts/check-server-hooks-goldens.sh`
- `cargo nextest run --locked -p mkit-server --test golden_server_hooks`
- The docs checks the repo already has for specs (e.g. a markdown link check, if one exists in `just ci` / `ci-scripts`).
  Do not add new tooling beyond B.4.6.
- The goldens outside `server-hooks/` are unchanged (`git diff --exit-code rust/tests/golden/ ':!rust/tests/golden/server-hooks'`).

Amendment 1 applied

Amendment 1 additionally requires R-91 in `00-plan.md`, an `outcome-abandoned.request.json` golden
with `ABORT_REASON_ABANDONED`, and its entries in SPEC-SERVER §15 and the golden-check script.
