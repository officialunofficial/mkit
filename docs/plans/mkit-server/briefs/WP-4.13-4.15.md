## Purpose

HTTP object reads can be paid:
- admission at §3 step 11;
- a durable `Pending(Read)` before the first byte;
- `ReadServed` or `Aborted` outcomes.

Private repositories can be served to URL-token holders:
- a staged token check;
- the token-authorized read-policy branch;
- private cache rules.

This fills 4.12's seams. **Adapters and mounting are WP-4.16**, which follows.

## A. Fixed (do not change)

1. **SPEC-HTTP-OBJECTS §3 (steps 5, 6, 11), §5, §6 and §7.**
2. **SPEC-SERVER §5–§8:** `Pending(Read)`, `ReadServed`, the read reconcile grace.
3. **SPEC-WRITE-GRANTS §9.3–§9.4:** tokens, and the uniform `not_found`.
4. **Spec corrections, which win over the breakdown and the earlier prompt wording:**
   - A failed **partial** transmission records `ReadServed(actual_bytes)`. `Aborted(INTERNAL)` applies only to a
     failure before the first byte.
   - HEAD records `ReadServed(0)`.
   - Both GET and HEAD are admitted.
   - A 304 with admission configured is private.
5. **Hook schemas and generated code stay unchanged.** 3.7b is relocating them; consume them through the re-export.
6. **4.12's `open_leaf` ordering is preserved** (a carry-forward).

## B. Decided (do not change)

### Part 1: WP-4.13

- **B1.** `HttpObjectsConfig.admit_reads`, programmatic and default `false`. Admission runs at step 11 through the
  unary challenge path. The Admit input is as the fact sheet §2 describes, with the anonymous principal.
- **B2. Durability:**
  - `Pending(Read)` is written before sending, with a configurable read deadline measured from reservation creation;
    transmission stops at the deadline;
  - settle conditionally through `OutboxBuilder`;
  - promote the grace planner to production as `read_reconcile_grace`, default 60 s;
  - an **async finalizer** is awaited on normal completion, with cancellation work retained by native tasks or the
    Worker request lifetime;
  - accounting counts bytes handed to the response stream.
- **B3. 402:**
  - canonical `AdmissionChallenge` protobuf JSON, with `no-store`; no body on HEAD;
  - no ETag, `X-Mkit-*` or Content-Range on a 402;
  - admitted responses are private.
- **B4. Credentials:**
  - `AdmitRequest` carries redacted payment credentials: `Payment-Authorization`, `PAYMENT-SIGNATURE`, qualifying
    `Authorization: Payment <token68>`, and permitted extras;
  - never Bearer;
  - bounds on occurrence, count and value.
  - **Comma rule, following the spec:** reject comma-joined selected values for **all** selected credential headers,
    not only `Authorization`. Change the shared selector in `pipeline/admission.rs`, and update R-138 to say this
    corrects #1212's decision. Add tests for both paths.

### Part 2: WP-4.15

- **B5.** Replace the boolean token seam with a retained, redacted verification result. The order is:
  - `precheck` (syntax, key, signature) **before** the repository lookup;
  - then `check_binding` (audience, repository, target, expiry, lifetime) before any stored-epoch access;
  - then `check_epoch`.

  Public repositories ignore every token result.
- **B6.**
  - Add an HTTP-specific token-authorized branch in `read_policy::decide`, and remove the unsigned-private early
    rejection only for that path.
  - The principal and view stay anonymous, and the Authorizer still runs.
  - Don't read the combined `rr/rv/e` before the stateless binding checks.
- **B7. Targets:**
  - `object:<hex>`;
  - `path:<full-ref>:<base64url(decoded UTF-8 path)>`, including the root path;
  - proof selectors don't change the target;
  - a non-UTF-8 path can't match.
- **B8. Cache:**
  - private ids and commit-pinned: `private, max-age=n, immutable`, where `n` is the remaining token lifetime floored
    to seconds;
  - private ref paths: `private, no-cache`;
  - document that adapters must suppress shared caching (4.16).

### Both parts

- **B9. Inertness:** everything stays behind `http-objects` (default off) and programmatic configuration.
  `IssueObjectUrl` stays unimplemented in Stage 1, since no keys are configured.
- **B10. Docs and plan:** R-177 and R-178, the spec-correction notes, the R-138 comma-rule update, and a CHANGELOG line
  per WP.

## C. Your decisions

Finalizer mechanics, the deadline parameter placement, and module layout.

## D. Escalate (stop and report) if

- Durable-before-send can't be guaranteed on one of the runtimes.
- The comma rule change breaks the Connect admission tests in a way that would need spec changes.
- Production code passes 2,500 lines.

## Tests (required)

The fact sheet's §9 bullets for 4.13 and 4.15, in full.

## Gates

- The common gate set, plus `just ci-server` and `ci-security`.
- `cargo nextest run --locked -p mkit-server -p mkit-server-native -p mkit-server-conformance --all-features`.
- The wasm32 check with `http-objects`.
