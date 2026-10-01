# Release inspection runtime fixture

`scripts/vcs-worker-launch-inspection-runtime.sh --sha <clean-HEAD> --mode pass`
builds the ordinary optimized reference Worker with HTTP objects and signed
hooks, then runs real indexed publication and R-193 scanner reads under local
wrangler 4.134.0. Set a private `VCS_CONFORMANCE_PORT` and the executor scratch
`TMPDIR` before running it. The executor owns all builds and runtime processes.

The wrapper maps only `https://inspection.launch.invalid` to the private
receiver. It preserves signed body bytes, manual redirects and cancellation;
it dispatches ordinary release requests and adds no Worker routes or verdicts.
This tests workerd transport, not external HTTPS trust or a deployed account.

The Node receiver independently verifies Ed25519 over the exact BLAKE3 body
and canonical hook digest with the installed `b3sum`. It signs scanner auth-v2
requests with a separate key, fetches the staged pack through the real mounted
route in one-MiB ranges, validates raw framing/trailer and compares the complete
deduplicated Blob set and canonical lengths against Inspect metadata. Seven
invalid-key/audience/repository/capability/pack/range requests must return the
same 404 body. After publication, the consumed-ticket check must deny before
capability expiry, so expiration cannot accidentally satisfy that assertion.

`--mode all` additionally needs the wire case
`launch.inspection_rejects_advance`: reject, redirect, oversize, stalled-header
and stalled-body responses must leave both writer and public refs absent.
Independent two-through-four inspector, manifest/chunk, previous-pack cache,
delta, durable replay-denial and full physical-call accounting are not covered
by this fixture. Its evidence keeps the full launch matrix UNRUN.

`node apps/vcs-worker/tests/launch-inspection/receiver.mjs --self-test` checks
independent signature/body tamper and nonce rejection, raw framing/trailer and
decoder corruption handling without starting a Worker or using cloud services.
