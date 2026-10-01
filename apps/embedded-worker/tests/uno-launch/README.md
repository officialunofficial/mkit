# Local Uno acceptance fixture

This host embeds the launch adapter, remounts the restricted admin router at
`/_uno/operator`, supplies local Authorize/Admit/Outcome callbacks and
acknowledges paired LocalCache purge work. It does not certify deployed CDN
purging. The dedicated 13-byte upload receives the fixture's Admit 402.

From a clean worktree, run the existing admin matrix with `--uno`. Set an owned
non-symlink `TMPDIR` under `~/.cache/mkit-test-tmp/wp-4-18`, a private
`VCS_CONFORMANCE_PORT`, and `MKIT_MINIFLARE_MODULE` to the installed, pinned
Miniflare SDK entry point. The final measurement used Miniflare 5.20260925.0
from Wrangler 4.134.0; the harness never downloads a runtime automatically.

```sh
python3 scripts/vcs-worker-launch-admin-runtime.py \
  --uno --namespace any --sha "$(git rev-parse HEAD)"
```

Add `--observe-resources`, an owned `MKIT_LAUNCH_INSPECTOR_PORT` and
`MKIT_PROBE_WS_MODULE` pointing to the pinned `ws` module for physical-call
traces and identified inspector samples. These samples report retained
capacity and observed heap usage; they do not certify full isolate peaks.
Direct Miniflare serves local HTTP. Native HTTPS push/clone is a separate run
using `MKIT_SSL_CA_FILE` and the existing fixture CA.

The matrix starts with `UNO_FIXTURE_OUTCOME_FAIL=true`: committed Outcomes
fail with a retry delay on the existing durable outbox. It stops the process,
changes that fixture flag to false, starts a new process over the same DO/R2
stores and requires every failed reservation ID to be delivered by a cold
alarm before issuing another request. The flag and panic hook exist only in
this test host; no production key, timer or protocol is added.
