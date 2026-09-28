## Purpose

This WP specifies the storage receipt: a server-signed DSSE statement returned to the writer on every committed advance
and every lease-terms change. It records what the server has recorded, so clients and implementers (for example a
paid-storage business) hold verifiable evidence.

## A. Fixed (do not change)

1. **PRD §6.8, and plan items M5-a, M5-c, M5-e and R-46.**
   - Receipts are DSSE, signed with the **deployment receipt key**.
   - They are returned in the response and can be fetched later.
   - They are stored client-side and never pushed; client receipts are not GC roots.
   - Distinct keys per role, with one receipt+notice key.
   - Opaque receipts cover refs and pack ids only.
   - mkit owns storage receipts; the implementer owns payment receipts and the contents of `external_ref`.
2. **User decisions (2026-09-28):**
   - **(a)** A receipt is **evidence of the recorded state and lease terms at issue time, not a promise** of future
     retention or availability. Admins can shorten leases (§12) and takedown can remove content (§14). State this
     normatively and in a rationale note. `external_ref` links to the implementer's own contract.
   - **(b)** Write receipts attest the **live committed advance** only. They never reveal publication, hold or
     inspection state (§10 forbids exposing it to readers, and it would be a detection-evasion oracle). A reader-side
     signed ref→commit binding is a later follow-up. Amend SPEC-HTTP-OBJECTS' "until M5 receipts" sentence to say so.
3. **SPEC-SERVER §7.2 key-list JSON shape.** STC `GetServerInfo` fields `receipt_public_key = 11` and
   `receipt_key_id = 12` exist, and are "empty until storage receipts are specified".
4. **Proto rules:** additive only, and `buf breaking` stays green (R-79).

## B. Decided (do not change)

### B.1 Predicate

- **Type:** `https://github.com/officialunofficial/mkit/spec/predicate/storage-receipt/v1`, with `kind` set to
  `advance` or `lease`.
- **Advance fields:**
  - `origin` (the canonical audience) and `repository` (the STC §7.4 identity);
  - `ref` and `advance_sequence` (§10.2);
  - `target` (the new ref value, 64-hex), plus `packmap` for branches;
  - `previous` (absent for a creation) and `deleted`;
  - `mode`, either `opaque` or `indexed`;
  - `closure_verified`, true only in indexed mode;
  - `added_packs[] {id, bytes}`, the packs this advance added to membership;
  - `added_bytes`;
  - `storage_lease`, either `{scope: repository|ref, expires_unix_ms, grace_ms, suspension_ms}` or
    `{permanent: true}`, as recorded at apply;
  - `reservations[] {id, external_ref?}`, deployment-supplied reservation ids only. Never synthetic ids.
  - `issued_unix_ms` and `key_id`.
- **Forbidden advance fields:**
  - `new_to_store`, deduplicated or physical bytes, or anything else revealing other repositories' holdings (STC
    §5.1 oracle rule);
  - logical or uncompressed bytes, which opaque mode cannot know. The PRD's "logical/stored bytes" pair is replaced by
    `added_bytes`; say so in the rationale;
  - publication, hold or inspection state.
- **Lease fields:**
  - `scope`, the terms, the effective state, and `cause` (§12.4 enum: `RENEWAL`, `POLICY` or `ADMIN`);
  - a per-scope monotonic `lease_version`;
  - `issued_unix_ms` and `key_id`.
- **Encoding:** every u64 or i64 value is a **decimal string**, for JS/wasm safety.

### B.2 Subject

- **Advance receipts:** `subject[0] = {name: "target", digest: {blake3: <target>}}`. It is **blake3 only**, in both
  modes. A deletion's subject is the previous target.
- **Lease receipts:** the subject is `blake3` and `sha256` of the UTF-8 scope string
  `<repository>\n<ref-or-empty>`.
- **Amend SPEC-ATTESTATIONS §4.2:** a producer that does not hold the subject bytes MUST NOT fabricate `sha256`, and
  storage-receipt subjects carry `blake3` only.
- **Plan note:** WP-5.8 adds an additive blake3-only encoding path to published `mkit-attest`, with no field-type
  change. Record this in R-119.

### B.3 Issuance

- **Advances:**
  - A receipt is issued for every committed advance, including deletions.
  - None is issued for conflicts or failures, or when receipts are disabled.
  - Statement bytes are fixed at apply and reproduced **verbatim** on replay and on fetch. Signing is deterministic
    Ed25519, so replayed envelopes are identical.
- **Leases:**
  - A lease receipt is issued for every change to terms or overrides (`POLICY`, `RENEWAL`, `ADMIN`).
  - None is issued for time-derived `EXPIRY` transitions; Events (§12.4) cover those.
  - A lease set by the creation policy appears in that advance's receipt.
- **Revocation:** receipts are never revoked. A later redaction notice (§14), signed by the same key, maps old→new
  pack ids.
- **GC:** receipts are not server GC roots.

### B.4 Encoding and domain

- The envelope is DSSE v1 with `payloadType` `application/vnd.in-toto+json`, and the payload is JCS, as in
  SPEC-ATTESTATIONS §4.
- Signatures are strict Ed25519 over the PAE.
- **Domain separation:** within the shared receipt+notice key, the domain is the `predicateType` (notices use a
  different `payloadType`, §14). Verifiers MUST check the `predicateType`. State the SPEC-CONVENTIONS §4 argument.
- The envelope is capped at 64 KiB.

### B.5 Keys (shared convention, fixed for 5.1b-1 and 5.1b-2)

- **One receipt+notice role key per deployment,** distinct from the hook, admin, URL-token, write and MAC keys.
- **Key id:**
  - the key-list `keyId` is the 64-hex BLAKE3(public key);
  - the DSSE `keyid` is `blake3:` + `keyId`;
  - `GetServerInfo.receipt_key_id` is the same `keyId`;
  - `receipt_public_key` is the raw 32 bytes of the current signing key.

  Both `GetServerInfo` fields are empty when receipts are disabled.
- **Key list:** `GET /.well-known/mkit-receipt-keys.json` in the §7.2 shape.
  - `public, max-age=300`; no bearer, token or payment; CORS open.
  - Redaction notices (§14) use the same document.
- **Rotation:** set `notAfterMs` on the old key, and **keep it listed forever**. A verifier accepts a key only when
  `notBeforeMs ≤ issued_unix_ms < notAfterMs`.
- **Compromise:** remove the key from the list. That invalidates every receipt and notice it signed. Document this.
  There is no transparency log (D22).

### B.6 Wire

- **Receipt fields:** additive `bytes receipt` fields hold the envelope JSON. They are empty on a conflict or when
  receipts are disabled:
  - `AdvanceRefsResponse.receipt = 2`;
  - `UpdateRefResponse.receipt = 1`.
- **Fetching later:** a new unary `GetReceipt{ref, advance_sequence (0 = latest)}`, plus a lease-receipt selector
  (the executor designs the oneof, C).
  - It is a signed read that needs the **writer view** (§10.1); anyone else gets `not_found`.
  - **Retention:** the server MUST keep the latest receipt per live ref and per lease scope. It MAY keep older ones for
    a deployment-set `receipt_retention`.
- **ssh and enc** retrieve receipts through Connect `GetReceipt` only; their protos stay frozen.
- **hooks.v1:** add `AdmitAllow.external_ref = 3`, at most 256 bytes of visible ASCII. The implementer is responsible
  for keeping it free of secrets. Update SPEC-SERVER §6.3/§6.6.
- **Admin `SetLease`:** its response carries the lease receipt. WP-5.1b-2 adds that field; cross-reference it.

### B.7 Verifier rules (client, normative)

1. Decode the envelope strictly, and check the exact `payloadType` and `predicateType`.
2. Verify the signature against a **pinned** trust root (user trust roots, or TOFU). A key learned only from
   `GetServerInfo` or the well-known URL is reported as "unpinned".
3. `key_id` equals the body of the DSSE keyid, and falls inside that key's validity window.
4. `origin`, `repository`, `ref`, `target`, `packmap` and `previous` equal what the client sent, and every
   `added_packs` entry is a pack the client ticketed.
5. `subject[0].blake3` equals `target`.

A failure produces a warning and the receipt is not stored. It never turns a committed push into an error unless the
user opts in (for example `--require-receipt`). Receipts are never logged in full.

### B.8 Terminology

Use "storage receipt" everywhere. It must be distinguishable from part receipts (STC §7.6) and payment receipts.

### B.9 Goldens: `rust/tests/golden/receipts/`

- **Positive cases:**
  - advance, opaque;
  - advance, indexed;
  - deletion;
  - lease;
  - the key-list document.
- **Negative cases:**
  - wrong `predicateType`;
  - subject mismatch;
  - key outside its validity window.
- **Also:** a `MANIFEST.txt`, a labelled test seed, and a Rust golden test with a test-local JCS/PAE encoder (the
  SPEC-HTTP-OBJECTS precedent).

### B.10 Plan

- **Add row R-119:**

  > WP-5.1c.
  >
  > - Receipts are evidence at issue time, not a promise, and attest the live committed advance only (user,
  >   2026-09-28).
  > - Subjects are blake3-only (a SPEC-ATTESTATIONS §4.2 amendment); WP-5.8 adds an additive blake3-only encode path
  >   to `mkit-attest`.
  > - Keys: `blake3:<64hex>` ids, a well-known key list kept forever, and compromise by removal.
  > - `AdmitAllow.external_ref`.
  > - The advance batch has one op of headroom (`outbox.rs`), so WP-5.8 must budget the receipt row against the
  >   published pointer (WP-5.4).
- **Registry:** 5.1b-1 depends on 5.1c (the notice key); 5.8 depends on 5.1c.

## C. Your decisions

- The `GetReceipt` request/selector shape.
- The prose structure of §15.
- The golden JSON layout.

## D. Escalate (stop and report) if

- Any B item contradicts merged normative text that a citation can't reconcile.
- `buf breaking` fails.
- The spec text exceeds about 1,200 changed lines, excluding goldens.

## Gates

- `buf lint`, and `buf breaking --against '.git#branch=origin/feat/mkit-server'`
- `bash scripts/check-generated-fresh.sh` (regenerate the transport code)
- `bash scripts/check-spec-status.sh`
- `bash scripts/check-server-hooks-goldens.sh`
- `cargo nextest run --locked -p mkit-server --all-features` (the golden tests)
- `just ci-server`
