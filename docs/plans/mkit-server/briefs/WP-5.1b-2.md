## Purpose

This WP specifies the operator-facing control plane:
- a signed, replay-protected admin API, off unless configured;
- every administrative operation 5.1a and 5.1b-1 refer to;
- a tamper-evident audit log;
- remote cache-purge delivery.

## A. Fixed (do not change)

1. **PRD §6.7 admin operations:**
   - takedown, reinstatement, suspension, blocklist;
   - set or extend a lease;
   - ssh grant registration.

   Requests are signed and replay-protected. Every action is audited.
2. **Plan:** the admin API uses its own domain, `mkit-admin:v1`, not `mkit-write:v2`. Roles use distinct keys
   (R-46). There is no threshold signing (it is deferred).
3. **User decision (2026-09-28): the admin key list carries roles.** Several concurrent admin keys, each with a role
   set, so a billing service holds a `lease`-only key and never takedown power.
4. The 5.1a text delegates to §16 the `SetLease` semantics (§12.3), admin release and review, waivers, the suspension
   override and its events, and CachePurge. See the research's §1.3.

## B. Decided (do not change)

### B.1 Structure

§16 Admin API and audit log, with these subsections:
- 16.1 Service, exposure and off-by-default
- 16.2 The `mkit-admin:v1` envelope
- 16.3 Admin key list, roles, rotation and separation
- 16.4 Replay and idempotency
- 16.5 Procedures
- 16.6 Audit log
- 16.7 Remote cache purge

Also amend:
- §7.1: add the admin key to the keys the hook key MUST NOT be;
- SPEC-WRITE-GRANTS §10: ssh grant registration is wrapped by §16.5;
- §12.4: namespace-scoped override events (B.8).

### B.2 Service and exposure

- **Service:** a new `mkit.server.admin.v1.AdminService`.
  - Connect unary for most procedures.
  - Server streaming for `ReadPreserved` and `ReadAuditLog`.
- **Mounting:** mounted **only** when an admin key list is configured.
- **Native:** a separate listener, defaulting to loopback.
- **Workers:** a distinct path, behind the deployment's network controls. Informative note: the server holds only
  public keys, and private admin keys belong offline or in an HSM.
- **Bearer gate:** exempt from the RPC bearer gate.
- **Mixed auth:** a request that carries both auth-v2 and admin headers is rejected.

### B.3 Envelope

`mkit-admin:v1` is a structural clone of `mkit-hook:v1`. It covers:
- domain;
- key id;
- audience (the server origin);
- procedure;
- `body:` digest;
- created time;
- expiry;
- nonce.

Rules:
- headers are `X-Mkit-Admin-*`;
- validity is at most 300 s, and clock lead at most 30 s;
- strict Ed25519;
- register the domain.

### B.4 Keys and roles

- **Key list:** the §7.2 JSON shape plus a `roles` array per key.
- **Roles:** `lease`, `moderation`, `grants`, `audit`, and `all`.
- **Procedure → required role:**

| Procedure | Required role |
|---|---|
| `SetLease` | `lease` |
| `SetSuspension` | `moderation` |
| takedown, block, preservation and legal-hold operations | `moderation` |
| hold, flag and serving releases, re-inspection, waivers | `moderation` |
| ssh grant operations | `grants` |
| `ReadAuditLog` | `audit` |
| `PurgeCache` | `moderation` |
| any procedure | `all` |

- **Separation:** admin keys MUST be distinct from every other role's key.
- **Rotation:** rotate with `notBeforeMs` / `notAfterMs`.
- **Wrong role:** `permission_denied`, and the attempt is audited.
- **Admin roles vs lease causes:** `SetLease` carries `cause ∈ {RENEWAL, POLICY, ADMIN}`. A `lease`-role key may use
  `RENEWAL` and `POLICY` only; `ADMIN` needs `moderation` or `all`. Map these onto the §12.4 events.

### B.5 Replay and idempotency

- **Replay ledger** keyed by (audience, key id, nonce):
  - same digest → the stored result;
  - different digest → `invalid_argument`;
  - still in flight → `aborted`.
- **Long-running operations** (takedown, reinstate, purge) also carry a client `operation_id`, using the reservation-id
  grammar. It is deduplicated for as long as the audit log is retained.

### B.6 Procedures

**Takedown and blocklist** (semantics in §14):
- `Takedown`, `GetTakedown`, `ListTakedowns`, `Reinstate`
- `AddBlock`, `RemoveBlock`
- `SetLegalHold`, `ReadPreserved`

**Suspension and leases:**
- `SetSuspension`: repository or namespace, with the flag "is takedown".
- `SetLease` (§12.3 semantics):
  - on a repository default: set terms or remove;
  - on a ref: set terms, set permanent, or remove;
  - plus `cause`.
  - The response carries the lease receipt (§15).

**Inspection** (§11), as **distinct** operations:
- `ReleaseHold`: an override release.
- `Reinspect`: issue a new inspection id.
- `ReleaseFlag`: releases the holds derived from that flag.
- `ResumeServing`
- `WaiveObligations`: inspector plus advances. Only an audited call may waive.

**ssh grants:** `RegisterSshGrant`, `RemoveSshGrant`, `ListSshGrants`.

**Other:** `PurgeCache` (manual) and `ReadAuditLog`.

**Every procedure** specifies its request and response, and its error codes from the STC §5 vocabulary.

### B.7 Audit log

- **Entry fields:**
  - `seq` (gapless), `recordedAtMs`;
  - `actor`: an admin key id plus an optional signed operator label, or `system:<inspector|timer|relay>`;
  - `procedure`, `requestDigest`, `nonce`, `operationId`;
  - `targets`;
  - `result`: a code plus a bounded message;
  - a bounded `details` field with no secrets and no content bytes.
- **Integrity:** a hash chain, `entryHash = BLAKE3("mkit-admin-audit:v1" ‖ JCS(entry including prevHash))`.
  - Append-only; no update or delete API.
  - Register the domain.
- **What is logged:**
  - every takedown, reinstatement, release, waiver and purge, **including automatic ones** (inspector hit, relay late
    holder);
  - every authenticated failure.
- **Unauthenticated attempts** go to metrics only, never the log. State this explicitly, since it would otherwise be a
  flooding vector.
- **Retention:** at least the longest active preservation retention. Pruning keeps a checkpoint hash.
- **Export:** through `ReadAuditLog` pages, plus the chain head.
- **Access:** admin-only in v1. Repository owners learn through notices (§14) and takedown Events. Deployments build
  their own UI.

### B.8 Events

- **Namespace-scoped override events:**
  - add `Event.namespace = 9` (an additive string);
  - allow `repository` to be empty when the event is namespace-scoped;
  - one event is emitted at the scope where the override is set.

  Update §12.4's shape rule.
- **Admin-caused lease transitions** use `cause = ADMIN`.

### B.9 Remote CachePurge (hooks.v1)

- Add an additive `rpc CachePurge`.
- The request carries:
  - `purge_id`;
  - audience;
  - repository;
  - a trigger enum: takedown, suspension, lease deletion, visibility change, manual;
  - URL paths, object ids, and refs.
- Delivery:
  - through the outbox;
  - signed under §7.1;
  - counted in the §5 backlog;
  - at least once, idempotent by `purge_id`;
  - only when a purge sink is configured, like Events.
- The deployment-internal purge interface remains the alternative.

### B.10 Goldens

**`rust/tests/golden/admin/`:**
- `mkit-admin:v1` signature vectors;
- the key list with roles;
- representative requests and responses: `Takedown`, `SetLease`, `ReleaseHold`, `ReadAuditLog`;
- a 3-entry audit chain;
- a `MANIFEST.txt`;
- a checker script modelled on `check-server-hooks-goldens.sh`, wired into `just ci-scripts`.

**`server-hooks`:**
- a cache-purge request and response;
- an extended `signature.json`.

### B.11 Plan

Add row **R-120**:

> WP-5.1b-2.
>
> - The admin key list carries roles (user, 2026-09-28): `lease`, `moderation`, `grants`, `audit`, `all`.
> - `mkit-admin:v1` envelope; the audit hash chain `mkit-admin-audit:v1`.
> - Native uses a loopback listener by default; Workers use a separate path.
> - The audit log is admin-only in v1.
> - Remote CachePurge is delivered through the outbox (5.10 depends on 5.1b-2).
> - Namespace-scoped `Event.namespace`.

## C. Your decisions

- Proto message layout, and the oneofs for the `SetLease` scope.
- Prose structure inside §16.
- The golden layout.

## D. Escalate (stop and report) if

- A research §1.3 obligation can't be met under these rules.
- A B item contradicts merged normative text that a citation can't reconcile.
- The spec plus proto text exceeds about 1,300 changed lines, excluding goldens.

## Gates

- `buf lint`, and `buf breaking --against '.git#branch=origin/feat/mkit-server'` (the new package is additive)
- `bash scripts/check-generated-fresh.sh`
- `bash scripts/check-spec-status.sh`
- `bash scripts/check-server-hooks-goldens.sh`
- the new admin golden checker
- `just ci-scripts`
- `just ci-server`
