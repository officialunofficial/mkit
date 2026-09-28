## Purpose

When a ticket-consuming AdvanceRefs is still being verified, the server answers `unavailable` with one
`PendingVerification{retry_after_ms}` detail.

Today the client treats that like any 503. It retries on the backoff ladder for about 31 s, then fails the push.

This WP adds correct polling:
- the clamped wait;
- the **same nonce** while the envelope is valid;
- re-signing after it lapses;
- polling until the ticket deadline;
- progress and cancel UX.

Wiring the real ticket deadlines is WP-1.17's job. This WP ships the mechanism.

## A. Fixed (do not change)

1. **STC §7.6 and SPEC-SERVER §9.5.**
   - Clamp `retry_after_ms` to 1,000–60,000 ms, where missing or 0 means 1,000.
   - Poll until the ticket expires. Never apply the backoff ladder to this answer.
   - **Reuse the nonce while the envelope is valid.** Sign a new operation after it lapses (300 s).
   - The server never stores this answer for replay, so a same-nonce resend is safe.
2. **The 1.16 rule:** no new `TransportError` variants (3.10 owns `AdmissionRequired`), and `Transport` changes are
   additive and defaulted only. `mkit-core` stays untouched.
3. **Goldens:** `rust/tests/golden/transport/pending-verification*`.

## B. Decided (do not change)

### B.1 Poll inside `ConnectTransport`

The loop lives inside `ConnectTransport`, not in the CLI. The nonce belongs to `RetryIdentity`, which is created inside
`advance_refs`.

- An outer poll loop wraps `self.retrying(...)`.
- The attempt closure returns `Ok(Err(Pending(ms)))`, so the ladder never retries a pending answer.
- Each poll gets a fresh ladder for genuinely transient errors, including 1.16's `aborted`.
- The loop runs synchronously on the caller's thread.

### B.2 Errors

There is no new `TransportError` variant. A deadline expiry becomes a non-retryable `RemoteError` with a clear message.
This deliberately drops the breakdown's `protocol.rs` edit.

### B.3 Detection

Treat a response as pending only when all of these hold:
- the RPC is `AdvanceRefs`;
- the code is `unavailable`;
- the detail type is `mkit.transport.v1.PendingVerification`, with or without a `type.googleapis.com/` prefix.

An undecodable detail is treated as a plain `unavailable` and goes to the ladder. Don't gate on
`GetServerInfo.indexed_mode`. Add a direct `base64 = "0.22"` dependency; it is already in the lockfile.

### B.4 Identity renewal and clock

- Add `RetryIdentity::expires_at_ms`, and an injectable `now: fn() -> i64` following the existing `fn` hook style.
- Re-sign when less than `max(unary_timeout, 30 s)` of validity remains.
- After at least one pending answer, re-sign once on `unauthenticated`, which covers a server clock ahead of ours. This
  is safe because pending answers are never stored.

### B.5 Deadline

- The helper takes `deadline: Option<i64>`.
- Before WP-1.17 no ticket is known. With no deadline, cap polling at 7 days, the longest ticket lifetime.
- Record in **R-128** that WP-1.17 passes the earliest consumed ticket's `expires_unix_ms`.

### B.6 Observer and cancel

- Add `ConnectTransport::with_pending_observer(...)`. It is called before each wait with the elapsed time and the next
  interval, and it returns continue or stop.
- Sleep in slices of at most 1 s, so Ctrl-C takes effect within 1 s.
- The CLI installs the observer in `open_with_config`.

### B.7 CLI UX

| Output mode | Behaviour |
|---|---|
| tty | A self-overwriting line: "Waiting for server verification: 42s". |
| not a tty, not `--quiet` | One line at the first pending answer and one at completion. |
| `--quiet` | Nothing. |

Ctrl-C returns `DispatchError::Interrupted` (exit 75), with a hint that pushing again gets the same ticket back from
`BeginUpload`.

### B.8 Plan

Add row **R-128**:

> WP-4.9.
> - Polling lives in `ConnectTransport`, with no new error variant; the mechanism ships now.
> - WP-1.17 passes ticket deadlines and reuses this helper.
> - Orphaned client obligations from 4.4 are assigned to **WP-1.17**:
>   - re-plan once on "delta base not available";
>   - rebuild the packlist;
>   - keep retrying membership-lag `unavailable` past the ladder, up to the 60 s bound;
>   - fail cleanly on "too many open upload tickets".
> - WP-4.7 and WP-4.8 own two open cases: inline verification exceeding the 20 s client timeout, and indexed mode with
>   a single repository and a threshold above 0.
> - Consider bundling all `TransportError` changes, with `#[non_exhaustive]`, into the 0.5.0 break.

## C. Your decisions

- The observer signature.
- Module layout.
- Test organisation.

## D. Escalate (stop and report) if

- Polling needs a `mkit-core` change.
- Nonce reuse can't be guaranteed across the retry ladder.

## Tests (required)

1. A fake in-process server answers pending N times, then Committed. Recorded sleeps equal the clamped values, and the
   ladder is never consumed.
2. A clamp table: 0, missing, 500, 5000, 120000, `u32::MAX`.
3. Every attempt inside the validity window carries the same nonce and signature.
4. With an injected clock past the renewal margin, the next attempt carries a new nonce and timestamps, and
   `write_auth::verify_headers` accepts it.
5. Polling stops at the deadline, with no attempt after it.
6. A mixed sequence (pending, then transient `unavailable` or `aborted`, then pending, then Committed) succeeds.
7. A plain `unavailable` still goes through the ladder, and the existing `retry.rs` counts are unchanged.
8. The detail on another RPC is ignored. An undecodable detail follows B.3.
9. The client decodes the `pending-verification-error.json` golden to 5000 ms.
10. Cancel returns within 1 s.
11. CLI stderr output with `MKIT_PROGRESS=always` and with `--quiet`.

## Gates

- `cargo nextest run --locked -p mkit-transport-connect -p mkit-cli -p mkit-core --all-features`
- `just ci` (rust)
- wasm32 clippy (the pure-Rust configuration)
