# Embedding mkit in a Worker

This local example hosts mkit under `/_uno/mkit/`. Its fetch handler constructs a
`worker::Request` and calls `mkit_server_worker::adapter::serve_with`, transferring
the incoming `ReadableStream` directly. `UploadPart` stays streamed through the
Connect bridge and R2 adapter. No HTTP call to the host's own public origin is
needed. The five Durable Object classes come from `durable_objects!(config, sink)`.

`hooks` composes a custom `HookSet` from `OpenAuthorizer`, `RemoteAdmission`,
`NoPreReceive`, `NoReceipts` and `RemoteOutcomes`. Admission and outcome delivery
call another Worker over the isolated `ADMISSION_HOOK` service binding. `sink`
constructs the same outcome sink for Durable Object alarms. The local fixture
deduplicates admissions and outcomes; a real hook must durably deduplicate
outcomes by reservation ID and have no public route, `workers.dev` or preview URL.

The signed envelope audience must equal `WorkerConfig::audience` (`AUTH_AUDIENCE`,
the exact public origin). Here that is `http://127.0.0.1:<port>`, even though the
constructed request uses `https://embedded.invalid`. The request URL does not
change the audience contract. In-process dispatch shares the caller isolate's
CPU, memory and subrequest allowance. Hosts must account for their own work in
the same budget.

The example keeps AdminService off the public path using
`admin_on_public_path = false`. A host with `ADMIN_KEYS` can route its chosen
admin prefix to `adapter::serve_admin_with`; that entry point still authenticates
the configured operator keys. See the [adapter embedding surface](../../rust/crates/mkit-server-worker/README.md)
for HTTP mount configuration, ref policy, takedown and custom purge sinks.

Use the repo's separate `apps/` workspace convention. The adapter stays
`publish = false`; an external host consumes it as a git dependency pinned to the
release tag. The supported surface is 0.x; breaking changes appear in CHANGELOG.

From the repository root, with Rust 1.95, `worker-build`, Node and `npx` installed:

```sh
export CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
export TMPDIR="$HOME/.cache/mkit-test-tmp/wp-4-18/embedding-example"
mkdir -p "$TMPDIR"
(cd apps/embedded-worker && cargo clippy --locked --target wasm32-unknown-unknown -- -D warnings)
scripts/embedded-worker-conformance.sh --port 8795
```

The script builds the release example, starts both Workers on local pinned
Wrangler, uploads three parts (8 MiB, 8 MiB, then a final smaller part), completes
the upload, verifies pack visibility and observes the committed outcome through
the custom sink. It also verifies that signatures for the internal request's
origin fail before admission. Logs and disposable local state stay in the
private TMPDIR. `--no-build` reuses binaries from the same worktree. Nothing is
deployed and no cloud account is contacted. The fixed development MAC key in
`wrangler.jsonc` is solely for these fresh local fixtures.
