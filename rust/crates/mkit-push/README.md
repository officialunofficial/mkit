# mkit-push (deprecated)

`mkit-push` is now a re-export of [`mkit-client`](../mkit-client/README.md).
Depend on `mkit-client` instead; this crate stays for one release so existing
`use mkit_push::...` code keeps compiling, then it is removed.

Everything documented there is available here under the same names, including
`Plan`, `Push`, `HttpTransport`, `Signer` and `Clock`. The push example:

```rust,no_run
use mkit_core::{hash::Hash, refs::RefWriteCondition};
use mkit_push::{Clock, Destination, Entry, HttpTransport, Limits, PackmapMode, Plan, Push, Signer};

async fn publish<T: HttpTransport, S: Signer, C: Clock>(
    http: &T, signer: &S, clock: &C, tip: Hash, entries: Vec<Entry>,
) -> Result<mkit_push::Outcome, mkit_push::Error> {
    let destination = Destination::new("https://vcs.example.org".into(), "default".into())?;
    let info = destination.server_info(http).await?;
    let limits = Limits::from_server_info(&info, 8 << 20, 64 << 20)?;
    let plan = Plan::prepare(entries, limits)?;
    Push::new(destination, "main", RefWriteCondition::Missing, tip,
        PackmapMode::Append { self_contained: true }, plan,
        clock.now_ms() + 300_000)?.run(http, signer, clock).await
}
```

Migration: replace `mkit-push` with `mkit-client` in `Cargo.toml` and
`mkit_push` with `mkit_client` in code. The `pack-zstd` and `pack-ruzstd`
features forward to `mkit-client`.
