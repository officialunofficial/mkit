# Local Workers HTTP response probe

This standalone test fixture sends synthetic responses through the production
Workers streaming bridge and final response policy. It checks raw escaped paths,
trailing empty queries, streamed GET and Range lengths, HEAD across status codes,
repeated challenges, CORS, key documents, private caching and adapter-error policy.
A delayed local subrequest proves that the first body chunk arrives before EOF.
It does not populate R2 or Durable Objects or exercise the full object pipeline.

Run from the worktree root with `worker-build`, Node/npm and Python 3 available:

```sh
export CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
export TMPDIR="$HOME/.cache/mkit-test-tmp/wp-4-16"
mkdir -p "$TMPDIR"
python3 rust/crates/mkit-server-worker/tests/http-mount-probe/probe.py
```

Use `MKIT_HTTP_PROBE_PORT` and `MKIT_HTTP_PROBE_DELAY_PORT` to select unused ports
(defaults 8836 and 8837). The probe refuses occupied ports, starts `wrangler dev
--local` only, and stops the process group it created. The test configuration has
no cloud bindings. This fixture is never published or deployed.

Build output, logs, local state and results stay under a unique directory in
`TMPDIR`. Cargo artifacts use this worktree's `rust/target` through `--target-dir`;
`CARGO_TARGET_DIR` must be unset. Its standalone lockfile pins the workspace's
reviewed dependency versions without adding fixture dependencies to production
Workers. No deployment manifest is changed.
