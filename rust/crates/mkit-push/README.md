# mkit-push

An async ticketed push primitive for Rust clients on native and wasm targets.
It uses the same generated transport messages as the server and native client,
with no Connect runtime, tokio or C compression dependency.

The host supplies ordered canonical objects or delta streams to `Plan::prepare`,
then constructs a `Push` with its destination, head lease, tip and packmap mode.
`Push::run` plans the packmap, reserves and uploads data and packmap tickets
(including multipart uploads), and atomically advances both refs. Results
include committed, head conflict, packmap contention and explicit replan reasons.

The host implements `HttpTransport`, `Signer` and `Clock`. Their futures need
not be `Send`. The HTTP boundary carries standard `http::Request<Vec<u8>>`
and bounded `http::Response<Vec<u8>>`; it works with Fetch, a Worker HTTP
client, or a native client. The primitive owns Connect framing and auth v2
commitments, so the host can delete copied protobuf, envelope and ticket logic.

The transport owns network retry policy and must replay the exact signed
request while its credential is valid. It must not replace its nonce after an
ambiguous response loss. It can journal requests before sending them. The
primitive refreshes credentials only after a definitive pending answer. Its
clock supplies epoch milliseconds, secure nonce entropy and async waiting;
there is no platform clock or sleep in this crate.

Replacing a private port: keep staged input, object prefetch/closure selection,
delta selection, authorization/grant selection, persistence, restart scheduling
and multi-step history policy in the host. Feed those canonical entries and
leases to this API. Persist the host's logical operation and transport journal;
reconstruct the same plan on restart. A current head equal to the requested tip
is treated as landed, as in the CLI. This is an observation of the requested
state, not proof that a particular expired operation performed a write.

This first slice accepts one bounded advance (at most six ticketed data packs
plus one packmap ticket). It does not change the CLI's push path. The pack
encoding follows enabled `mkit-core` features: default builds write raw packs;
a native host may enable `mkit-core/pack-zstd`. The same feature choice and entry
order are required to reproduce identical pack ids across restarts.

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

The host must certify `self_contained` only when the entries reconstruct the
whole tip closure, and use `ResetSelfContained` only with that same guarantee.
Append validates existing packlist content commitments and detects cycles;
its maximum walk is 100,000 nodes and 1,000,000 distinct pack ids. Each HTTP
response is capped at 1 MiB. Packs and HTTP upload frames are buffered, so the
host must budget for the sealed input plus the framed request and its replay
copy. The default retained sealed input limit is 64 MiB; it includes a reserved
packlist node. Multipart receipts are held for the current operation; a host
restart can resend the same content under the live ticket. Durable receipt
caching and cancellation are implemented at the host transport boundary.
