# Local Durable Object response lifetime fixture

This fixture compiles the production `ns_client::StubTransport` and calls a real
local DO with deliberately delayed headers/bodies, a 503 body, and a body error.
It is excluded from the production deployment. Its lock derives from the
reference Worker's lock, including worker0.8.6 for the current artifact.

Build with `worker-build --release --locked` from this directory, with the normal
owned non-symlinked TMPDIR and debug0 settings. Wrangler local configuration uses
`wrapper.mjs` as main, compatibility date2026-09-09, build command`true`, and one
SQLite DO class`Reply` bound as`REFSTORE`. Use an owned free local port/state.
Then run `python3 verify.py --url http://127.0.0.1:PORT --out "$TMPDIR/transport.json"`.

Eight cases assert success/503 EOF, body error, early Rust-future drop before
headers/during body, joined four-call ordinary success/error and six-call scanner
success, and a serial nested call only after the first batch reaches EOF. Tokens
last through actual response-reader EOF/cancel/error, including native fetch
rejection. Every case observes zero outgoing work at Rust return and after400ms.
The host denial tests separately exercise the production full4096 proof, shared
budget, ordered descriptors, continuations and real nested chunk proof; the
batch fixture exercises transport lifetimes rather than claiming a4096-run.

Abort requests terminate the caller fetch/body. They do not promise to stop a
DO producer's ongoing work. Instrumentation can affect timing; these are local
contract regressions, not the full launch/isolate memory or CPU certificate.
