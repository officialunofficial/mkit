# Connect deadline runtime regression

Run `just ci-connect-deadlines` from the repository root. The probe builds a
locked wasm release and uses the existing Workers harness's pinned local
Wrangler/workerd, artifact checks, startup wait and owned-process cleanup. It
needs Rust with the wasm32 target, worker-build, Node, npx and b3sum 1.8.5
(`cargo install b3sum --locked --version 1.8.5`). It never
contacts a cloud account; fresh R2 and Durable Object state stays in TMPDIR.
The Workers wire-conformance CI job runs the same regression.

Seven header combinations cover absent, each valid header, both valid headers,
each malformed header and both malformed headers. Zero deadlines demonstrate
that wasm calls succeed rather than being cancelled. Requests exercise:

- Direct `connect::service`, including a configured default, minimum, maximum,
  stream deadline and inter-message timeout.
- Custom `connect::router` mounted with `ConnectService::new`.
- `serve`, `serve_with`, `fetch`, `fetch_with`, `fetch_with_context`.
- Signed `ReadAuditLog` through `serve_admin_with` and each Worker entry point.

Connect JSON and gRPC protobuf health calls must return SERVING. Authenticated
transport methods without credentials must return unauthenticated. Signed
admin calls must return success and no-store. The core native regression
`native_deadlines_bound_body_receipt` verifies finite header and configured
default deadlines still cancel stalled request bodies.

The core wrapper removes headers synchronously before calling connectrpc. Its
private inner service starts with `DeadlinePolicy::new()`; the wasm deadline
builder discards every supplied policy. With no timeout metadata or default,
connectrpc's `absolute_deadline(None)` never enters `Instant::now()`, and no
inter-message or response-stream timer is configured. The admin engine uses
`WorkerClock` and `WorkerSleep` independently of connectrpc.
