## Purpose

This WP adds the `AdmissionChallenge` detail message that STC §5.1 specifies, together with golden binary and JSON
bodies. That lets WP-3.2 (the pipeline flip), WP-3.7 (hooks mapping), WP-3.10 (the client) and the HTTP 402 body build
on pinned bytes.

## A. Fixed (do not change)

1. **STC §5.1** fixes the message shape and its bounds:
   - `AdmissionChallenge { repeated Challenge challenges = 1; string description = 2; }`
   - `Challenge { string scheme = 1; string value = 2; }`
   - Bounds: 1–8 challenges; `scheme` matches `[a-z0-9][a-z0-9.-]{0,63}`; `value` is at most 8,192 bytes;
     `description` is at most 512 bytes.

   On the wire it is `permission_denied` + HTTP 402 + exactly one detail.
2. **The server plumbing already exists and is out of scope:** `ServerError::admission_challenge(Bytes)`,
   `ADMISSION_CHALLENGE_TYPE`, and the Connect detail conversion. The pipeline's M0 `Challenge` placeholder is
   WP-3.2's to flip. **Do not change pipeline behavior.**
3. **SPEC-HTTP-OBJECTS §7:** the HTTP 402 body is the bare message in canonical protobuf JSON. It is already pinned in
   the http-objects "challenge" row.
4. The proto file is `edition = "2023"`, so fields have explicit presence. Proto changes are additive only (R-79).

## B. Decided (do not change)

- **B1. Placement.** Add both messages to `transport.proto`, exactly as STC shows them, with comments citing the spec.
  Place them **directly after the `// Errors/details.` header, before `PendingVerification`.** Do not add a new file or
  an RPC, and do not change any existing message.
- **B2. Presence rule.** Servers leave `description` unset when it is empty, and clients treat an absent value as `""`.
  Document this in the golden test.
- **B3. Goldens.** Add these flat files in `rust/tests/golden/transport/`, each with a MANIFEST line, and update the
  MANIFEST header comment:
  - `admission-challenge.bin`
  - `admission-challenge.json`
  - `admission-challenge-error.json`

  Fixture values:
  - Two challenges, in this order:
    - `mpp` → `Payment id="fake-example-not-valid", method="tempo", intent="charge", request="fake-example-request-not-valid"`
    - `x402` → `fake-example-payment-required-not-valid`
  - Description: `Example upload payment required.`

  The files are produced by production code through `ServerError` → `ConnectError::to_json`. Follow
  `golden_pending_verification.rs`, including `UPDATE_GOLDEN=1`.
- **B4. Spec text.** Add at most one informative row to the STC test-anchors section. Make no other spec edits. Leave
  the stale sentence "defines no custom error message type" for a later spec PR, and note that in the PR body.
- **B5. Plan.** Add a row **R-124**:

  > Transport field-number ownership.
  >
  > - The service list is append-only.
  > - New messages number their fields from 1.
  > - A WP that adds a field to an existing transport message claims that number in a 00-plan R-row first.
  > - Next free numbers after #1179 and #1180:
  >   - `GetServerInfoResponse` 19
  >   - `ReadRefResponse` 4
  >   - `ListRefsResponse` 4
  >   - `UpdateRefResponse` 2
  >   - `AdvanceRefsResponse` 3
  >   - `AdvanceRefsRequest` 11
  >   - `UpdateRefRequest` 6
  >   - `UploadPackHeader` 4
  >   - `BeginUploadRequest` 4
  >   - `UploadTicket` 5
  > - Reviewers check label and oneof changes by hand (R-79).
- **B6. Out of scope.**
  - Bound validation goes to WP-3.2, with a shared validator in `mkit-core` that 3.2 decides on.
  - The pipeline flip, client mapping and hooks mapping belong to later WPs.
  - Record the core encoding seam as a carry-forward for WP-3.2: `buffa` is only available with `connect`, so 3.2
    needs a hand encoder pinned against this golden, or a typed detail.

## C. Your decisions

- Test organisation.
- Whether to replace the fake detail in `connect_dispatch.rs` with the real encoding. This is optional; record the
  choice.

## D. Escalate (stop and report) if

- `buf breaking` fails.
- The goldens can't be produced through production code.

## Tests (required)

1. **`mkit-server/tests/golden_admission_challenge.rs`:**
   - binary and JSON bytes equal the files;
   - `ServerError::admission_challenge(bin)` gives `http_status == Some(402)` and `PermissionDenied`;
   - `to_json` equals the error golden;
   - decoding back from all three files works;
   - the detail `type` is the bare name, and the payload decodes with `STANDARD_NO_PAD`;
   - the MANIFEST assertion holds.
2. **Cross-check with SPEC-HTTP-OBJECTS:** parse the http-objects "challenge" `body_json` as `AdmissionChallenge`,
   re-serialize it, and check the result is the same value.
3. **`mkit-transport-connect`:** its vendored copy decodes `admission-challenge.bin` to the same values.
4. **Round-trip unit tests** with 0, 1 and 8 challenges.

## Gates

- `buf lint`, and `buf breaking --against '.git#branch=origin/feat/mkit-server'`
- `bash scripts/check-generated-fresh.sh`
- `just ci-server`, which includes the wasm32 builds
- `cargo nextest run --locked -p mkit-server -p mkit-transport-connect --all-features`
