## Purpose

Indexed mode is the opt-in deployment mode where the server decodes and verifies every pushed pack before refs
move, indexes objects per repository, and extracts large files into a global content-addressed store for HTTP
serving (M4). Clients and alternative server implementations need its contract first:
- what the server verifies, and what it must never reveal (global existence);
- how async verification surfaces to clients (`PendingVerification`);
- what is extracted (D32);
- the per-ref policy hooks.

This WP writes that contract: a new SPEC-SERVER section, the STC client obligations, and one additive proto
message with goldens.

## A. Fixed by the plan and specs (do not change)

1. **Plan and PRD:**
   - `docs/plans/mkit-server/m3-m5-breakdown.md`: "WP-4.4", with the fixed defaults in "WP-4.7" (the delta-base rule
     and uniform permanent error), "WP-4.8" and "WP-4.8a", §A "Code grounding", and §I (Q-M4-1, Q-M4-2 = D32,
     Q-M4-3 = D33, Q-M4-6);
   - `prd-snapshot.md` §6.5 (indexed mode), §5.4 stage 5, D3, D14, D15, D32, D33, D34.
2. **Existing STC text you build on, not restate:**
   - §2.1 `indexed_mode` and `max_pack_bytes`, including "MAY advertise a lower value in indexed mode";
   - §5's table row "A pack still under verification in indexed mode (§7.6): `unavailable`";
   - §7.6 "Pending verification" paragraph, which **reserves** the detail. This WP makes it normative;
   - §7.6 "Membership" (packlist nodes `MKPL` are uploads that need tickets);
   - §7.7 lifecycle;
   - §7.9 eventual consistency ("A lag MUST only cause …", "never acts as an existence oracle").
3. **Wire magic:** a pack starts with `MKIT` (SPEC-PACKFILE, `pack.rs` `MAGIC`); a packlist node starts with `MKPL`
   (`transfer.rs` `PACKLIST_MAGIC`).
4. **D33:** attestation predicates and attestation carriage are out of this epic. Only the generic per-ref policy
   hook stays.
5. **Additive proto only**, in `proto/mkit/transport/v1/transport.proto`; `buf breaking` must pass. There are no
   imports today, so add none.
6. **SPEC-CONVENTIONS** in full (§4 domain separators, §5 goldens ship in the same change, §6 no vendor
   references).

## B. Decided by the orchestrator (do not change)

### B.1 Where the text goes

- **SPEC-SERVER:** insert a new `## 9. Indexed mode`, directly before the reserved M5 sections, and renumber them
  and everything after by one:
  - `## 10. Published view (reserved, M5)`
  - `## 11. Quarantine (reserved, M5)`
  - `## 12. Admin API and audit log (reserved, M5)`
  - `## 13. Custom backends, backup and migrations (reserved, M5)`
  - `## 14. Conformance scope (reserved, M5)`
  - `## 15. Version history`
  - `## 16. Test anchors`

  Fix every internal "§n" reference to the renumbered sections (grep them).
- **STC:**
  - edit §7.6 "Pending verification" to make it normative (B.4);
  - add the `PendingVerification` message to the §5 error text where the `unavailable` row is described;
  - add one §2.1 row (B.5);
  - add a version-history row.

### B.2 SPEC-SERVER §9 subsections (exact headings, in this order)

```
### 9.1 Scope and opt-in
### 9.2 Classification
### 9.3 Verification obligations
### 9.4 Repository-isolated resolution
### 9.5 Asynchronous verification
### 9.6 Extraction (D32)
### 9.7 Ref policy
### 9.8 Limits advertised
```

### B.3 Normative content per subsection

- **9.1:**
  - Indexed mode is opt-in per deployment and advertised by `GetServerInfo.indexed_mode` (cite STC §2.1).
  - In opaque mode (the default), none of §9 applies, and packs are stored as opaque bytes.
- **9.2:** On upload completion of a ticketed blob, the server classifies it by its first four bytes:
  - `MKIT` is a pack;
  - `MKPL` is a packlist node;
  - anything else is `invalid_argument` ("unknown upload type"), at the `AdvanceRefs` that consumes its ticket, or
    earlier (see 9.5).
  - **Packlist rule:** every pack a consumed `MKPL` node lists MUST be either a member of the repository, or
    ticketed and consumed in the same `AdvanceRefs`. Otherwise the advance fails with the uniform error of 9.4.
- **9.3:** Before an `AdvanceRefs` that consumes a pack commits, the server MUST have verified:
  - (a) every object's id against its content (SPEC-OBJECTS);
  - (b) every commit, remix and tag signature the new tips reach, per SPEC-SIGNING;
  - (c) closure: every object reachable from the advanced head is either in the consumed packs or already a verified
    member of the repository;
  - (d) every delta resolves within its chain-depth limit (9.8).

  A failure of (a), (b) or (c), and a delta chain over the limit, is `invalid_argument` with a public message that
  names the failure category (`object hash mismatch`, `bad signature`, `open closure`, `delta chain too deep`). It
  is permanent: clients don't retry it. Cite the SPEC-SIGNING and SPEC-OBJECTS sections.
- **9.4** (the key rule):
  - A delta base MUST resolve only from the same pack's entries or from **verified members of the same
    repository**. A server MUST NOT resolve a base from another repository or from the global store, and whether
    a push is accepted or rejected, and its error text, MUST NOT depend on whether the object exists anywhere
    outside the repository (cite STC §7.4 isolation).
  - Because membership is eventually consistent (STC §7.9), an unresolved base yields a retryable `unavailable`
    with public message "delta base not yet visible", but only while the consuming ticket is younger than the
    deployment's relay-lag bound.
  - After that, it yields a **uniform** `failed_precondition` with public message
    "delta base not available in this repository". This is byte-identical whether the object exists in another
    repository or nowhere.
  - Client obligation (added to STC, B.4): on that `failed_precondition`, the client re-plans the upload once as a
    self-contained pack (no external delta bases) and retries with a new ticket.
- **9.5:**
  - Verification MAY run asynchronously after upload completion. While a consumed pack is unverified, the
    `AdvanceRefs` fails with `unavailable` plus exactly one `PendingVerification` detail (B.4). The answer is
    **never stored as a replay result** (cite STC §7.1).
  - A server MAY report a verification failure earlier than the advance, e.g. on `CompleteUpload`, with the same
    code and message.
  - Verification state is per (repository, pack). A pack verified for one repository is not thereby verified for
    another.
  - A server MUST make verification progress resumable across restarts without re-yielding unverified content, and
    MUST bind resumed reads to an unchanged source object. That is informative about how: e.g. an entity-tag
    condition on range reads.
- **9.6 D32 extraction:**
  - At verified ingest, the server extracts into a global content-addressed object store:
    - every plain blob of at least a deployment threshold, with a default of 65,536 bytes;
    - every chunked blob, reassembled once into a single object keyed by its manifest id.
  - Chunks stay in their packs for clone and fetch; extraction adds a serving copy and doesn't remove anything.
  - Extraction is file-level deduplicated by object id across repositories. That is safe because serving is
    authorized per repository (the HTTP-serving spec, WP-4.11), and existence in the global store is never
    observable through this protocol (9.4).
  - Extracted objects are served with byte-range support (informative: the HTTP serving spec).
  - The threshold is deployment configuration and isn't advertised.
- **9.7 Ref policy** (the generic pre-receive policy; D33 excludes attestation predicates):
  - A deployment MAY configure, per ref-name pattern (the SPEC-WRITE-GRANTS §3.3 pattern grammar, cited):
    - (a) an allowed-signer set: only these auth v2 signers may move matching refs;
    - (b) fast-forward-only: a matching ref may only move to a descendant of its current value.
  - Both are checked at pre-receive (§2 stage 5), after verification. A violation is `permission_denied`, with
    public messages "signer not allowed for this ref" and "non-fast-forward update not allowed on this ref".
  - Fast-forward-only requires indexed mode, because the server needs the commit graph. An opaque-mode deployment
    MUST refuse to start with a fast-forward-only rule configured.
  - Deletion (STC §7.8) of a fast-forward-only ref is refused the same way.
- **9.8 Limits:**
  - `GetServerInfo.max_pack_bytes` is the effective limit in the deployment's mode (cite STC §2.1).
  - A new field `max_delta_chain_depth` (B.5) is the delta-chain depth cap; the default is 50. It is 0 when indexed
    mode is off.

### B.4 `PendingVerification` (proto and STC)

- **Proto**, in the existing errors/details section of `transport.proto`:
  ```proto
  // Detail on an `unavailable` AdvanceRefs whose consumed pack is still under
  // verification (SPEC-TRANSPORT-CONNECT §7.6; SPEC-SERVER §9.5).
  message PendingVerification {
    uint32 retry_after_ms = 1;   // server's suggested poll interval, 1..=60000
  }
  ```
- **STC §7.6 "Pending verification"**, made normative:
  - An `AdvanceRefs` that consumes a pack still under verification fails with `unavailable` and exactly one
    `PendingVerification` detail.
  - The client MUST poll, waiting `retry_after_ms` (clamped to 1–60,000 ms) between attempts, until the ticket
    expires. It does not use its normal backoff ladder.
  - The client reuses the nonce while the envelope is valid, and signs a new operation after it lapses (cite §7.1,
    300 s).
  - A server MUST NOT store this answer as a replay result.
  - Remove the sentence "This detail is reserved here and becomes normative with indexed mode."
- **STC client obligation for 9.4:** add one sentence to §7.6 "Errors": on `failed_precondition` "delta base not
  available in this repository", a client re-plans the upload once as a self-contained pack.

### B.5 `GetServerInfo` field

Append to `GetServerInfoResponse`:

```proto
  uint32 max_delta_chain_depth = 16;   // SPEC-SERVER §9.8; 0 when indexed mode is off
```

Add the matching row to the STC §2.1 table.

### B.6 Codegen and goldens

- Regenerate the vendored transport code with `scripts/regen-transport-proto.sh`. Both
  `rust/crates/mkit-transport-connect/generated` and `rust/crates/mkit-server/generated` must be regenerated, and
  `scripts/check-generated-fresh.sh` must pass.
- Update `GetServerInfo`-related test servers only if they fail to compile (they shouldn't: this is a field
  addition).
- **Goldens** under `rust/tests/golden/transport/`:
  - `pending-verification.bin`: the proto binary of `PendingVerification{retry_after_ms: 5000}`;
  - `pending-verification.json`: its canonical proto JSON;
  - `pending-verification-error.json`: a full Connect error body, code `unavailable`, with the detail as Connect
    encodes it (`type` `mkit.transport.v1.PendingVerification`, base64 `value` of the `.bin`).
  - Add them to `rust/tests/golden/transport/MANIFEST.txt`.
- **Pinning test:** add a test next to the existing transport golden test (the `repo.rs` repository-grammar test
  loads that MANIFEST; mirror its approach, in `mkit-transport-connect` or `mkit-server`, your choice). It:
  - encodes and decodes the message against `.bin` and `.json`;
  - checks the MANIFEST hashes;
  - supports `UPDATE_GOLDEN=1`.

### B.7 Plan and index

- One CHANGELOG line (Unreleased / Added).
- SPEC-SERVER §15 (renumbered) and STC version-history rows.
- SPEC-SERVER §16 lists the new goldens.
- No `00-plan.md` change unless a B rule contradicts a plan default. That is a §D stop.

## C. Your decisions

- Prose, examples and informative notes, within B.3. Target 250–450 new spec lines.
- Which crate holds the pinning test.
- Whether §9 includes an informative sequence, e.g. upload → pending → poll → committed. Recommended: yes, a
  numbered list.

## D. Escalate if

- A B.3 rule contradicts STC, SPEC-WRITE-GRANTS, SPEC-PACKFILE or SPEC-SIGNING. Quote both passages.
- The §7.9 "A lag MUST only cause …" list doesn't admit 9.4's `failed_precondition` after the lag bound. If so,
  stop, and propose the one-line STC §7.9 addition instead of editing it.
- `buf lint` or `buf breaking` rejects B.4/B.5.
- Regeneration changes anything besides the two new items in the generated code.

## Gates

- `buf lint`, and `buf breaking --against '.git#branch=origin/feat/mkit-server'`, from the repo root
- `bash scripts/check-generated-fresh.sh`
- `bash scripts/check-spec-status.sh`
- `just ci-server`
- the wasm32 check of `mkit-server`, and the wasm32 build of `apps/vcs-worker`
- The goldens are unchanged except the new transport files and the MANIFEST lines.

## Amendment 1: STC §7.9 lag list

The orchestrator approved the anticipated §D escalation. Add this exact
bullet as the last item in STC §7.9's “A lag MUST only cause one of these” list:

- in indexed mode, a uniform `failed_precondition` ("delta base not available in this repository") for a delta
  base that is still unresolved once the consuming ticket is older than the deployment's relay-lag bound
  (SPEC-SERVER §9.4). It is byte-identical whether the object exists in another repository or nowhere.

No other §7.9 edit. Include this change in the new STC version-history row
and in the PR body's “Spec changes”. Continue B.1–B.7 and all gates in the
same worktree and branch; the definition of done remains an open PR.
