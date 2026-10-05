# In-process test host

Contract tests that need real loopback HTTP can use the debug-only
`test-host` feature. It runs the production core Connect handlers over fresh
`MemoryKv` and `MemoryBlobStore` instances and exposes the same profile shape
as the wire suite. This is an unstable test-support API. Release builds reject
the feature.

Pin the feature-enabled dependency to the same mkit revision as the other
contract-test dependencies:

```toml
[dev-dependencies]
mkit-server-conformance = { git = "https://github.com/officialunofficial/mkit", rev = "<same-revision-as-mkit-dependencies>", features = ["test-host"] }
```

```rust,ignore
use mkit_server_conformance::test_host::TestHost;
use mkit_server_conformance::wire::{Profile, WireAuth, WireTarget, run};

let profile = Profile::new(WireAuth::AuthV2 {
    audience: String::new(), // replaced with the allocated canonical origin
    repository: "default".into(),
    seed: [0x5e; 32],
});
let host = TestHost::start(profile).await?;
let target = WireTarget {
    base_url: host.base_url().parse()?,
    profile: host.profile().clone(),
};
let report = run(&target, None).await;
// Run the consumer's shared contract macro/report assertions here.
host.shutdown().await;
```

`TestHost::start_with_hooks` accepts a consumer's core `HookSet`, including
scripted admission and outcome hooks. `start_with_hooks_factory` supplies the
allocated server origin and manual clock so callers can connect `RemoteAdmission`
to `stubs::hook::FakeHook` through `LoopbackHookChannel`. `clock()` returns a deterministic
`ManualClock`; advance it explicitly and call `drain_core_timers()` with a
partition and budget when a case needs timer delivery. `drain_timers()` accepts
a custom core `TimerRegistry` for tests that need to control the handler set.
Drains have a finite executor-poll budget. A handler or outcome sink that stays
pending returns an unavailable error; its uncommitted timer remains queued.
Each host owns its stores and listener. Dropping it aborts the listener task.

## Portable file and takedown contracts

The shared registry grows from 225 to 233 cases. `health.deadline_headers`
exercises absent, finite, paired and malformed headers over Connect and gRPC;
the existing runtime probe also covers zero timeouts, configured defaults and
all supported wasm dispatch entry points. Native stalled-body deadline tests
remain in `mkit-server`.

`files.empty_readback`, `files.deep_tree`, `files.long_path`,
`files.byte_distinct_names` and `files.path_limits` publish canonical packs and
paired refs through the ordinary transport. Names stay in memory as bytes;
checkout filesystem normalization and case sensitivity cannot change them.
A 100-directory tree round-trips over the ref route. A 2048-byte core path
round-trips through disclosure lookup and object-ID HTTP reads; its ref URL
returns 400 under the specified 1024-byte HTTP limit. Separate boundaries cover
128/129 authenticated core steps, 255/256-byte components and 1024/1025-byte HTTP
paths. `embedding.multipart_file_readback` retains the existing binary payload
and multipart upload, adding GET/HEAD, metadata, conditionals and exact ranges.
Committed advances can precede published indexes. Fixture setup uses bounded
HEAD readiness for each positive HTTP selector, then runs immediate exact
byte/metadata/range assertions. Negative bounds and all takedown denial checks
remain immediate. Private token setup also waits for published membership before
minting the token and checking its HTTP selector; an owner live ref is insufficient.
The Worker observer rejects zero-length R2 ranges; the core HTTP spy also checks
backend range geometry and absence of an empty payload fetch.

`takedown.contract` requires `takedown`, `admin`, `signed-reads`, indexed HTTP
objects and ticketed multi-repository transport. Use a fresh private-by-default
fixture with the synthetic operator key used by the runtime probe. It publishes
the same content into public and private repositories, proves public/ref reads,
private URL-token reads and signed owner downloads work, accepts signed admin
Takedown, and asserts their denial plus restricted admin status. Failure to provide
the enabled capability fails the test. It never silently skips setup failures.
The token stays in an exclusive, mode-0600 scratch file and never enters TAP.

Restart the server over the same stores, origin and configuration, then run
`takedown.persisted_denial` with the original run ID and signer seed. This checks
the original token, owner download, public/ref denial and admin identity/selectors,
then deletes the scratch capture. It fails when the producer capture is missing.
The native test host mounts the two signed admin routes for this profile and
`restart_with_default_hooks()` rebuilds its listener, pipeline and admin engine
over the same metadata, serving and preservation stores. This fixture does not
assert preservation completion; the full admin rehearsal covers acquisition,
legal hold, retention and audit separately.

```sh
python3 scripts/connect-deadline-runtime.py --portable
```

This pinned local workerd run prints all nine selected wire cases (eight new,
one extended), rejects missing/skipped cases, restarts its own process over
persisted state, and checks the R2 observer ran. Hosted Workers CI invokes it.
It proves local runtime behavior, not cloud placement or production timing.

The coverage audit found existing one-winner and atomic-advance races,
`replay.expired_retry_rejected`, nonce/different-operation rejection,
`admission.concurrent_duplicate_during_admit`, repository isolation, private
owner/grant/non-owner reads and URL-token visibility revocation. These seeds add
no duplicate race/replay/privacy-only variants, URL staging or product policy.
