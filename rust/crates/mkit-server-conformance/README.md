# In-process test host

Contract tests that need real loopback HTTP can use the debug-only
`test-host` feature. It runs the production core Connect handlers over fresh
`MemoryKv` and `MemoryBlobStore` instances and exposes the same profile shape
as the wire suite. Release builds reject the feature.

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
Each host owns its stores and listener. Dropping it aborts the listener task.
