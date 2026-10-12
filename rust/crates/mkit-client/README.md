# mkit-client

The async protocol client for mkit servers, for Rust hosts on native and wasm
targets. It speaks `mkit.transport.v1` over a host-supplied HTTP channel, signs
with a host-supplied signer, and has no Connect runtime, tokio, hyper or C
compression dependency. It is the former `mkit-push`, renamed and extended.

## Layers

- **`Client`: one typed call per RPC.** `server_info`, `list_refs` /
  `list_all_refs`, `read_ref`, `pack_exists`, `download_pack`, `update_ref` /
  `delete_ref`, `begin_upload`, `upload_pack`, `upload_part`, `complete_upload`
  and `advance_refs`. `Client::anonymous` sends unsigned reads;
  `Client::signed` signs every RPC except discovery, as the protocol requires
  of a client that has a signer. Writes need a signed client. There is no fork
  RPC in `mkit.transport.v1`, so none is exposed (a branch copy from a published
  source is `advance_refs` with `source_ref`).
- **`Push`: the bounded whole-push** built on the same calls (below).
- **Read helpers.** `Client::resolve_pack_chain` walks a packmap chain (bounded
  at 100,000 nodes and 1,000,000 listed pack ids, every node checked against its
  content id) and returns pack ids oldest first. `unpack` decodes a pack into an
  `ObjectSink` you implement (no filesystem; `MemorySink` is provided), after
  checking the pack against its requested id.

## Per-RPC calls never wait

A call sends one request and returns. What would otherwise be a wait is a typed
`Error` the caller schedules:

| Error | Meaning |
| --- | --- |
| `PaymentRequired(AdmissionRequired)` | An admission challenge (402). Carries every challenge in the server's order, the description, and the raw `WWW-Authenticate` / `PAYMENT-REQUIRED` values for a helper. A 402 whose body is not a Connect error parses from those headers alone, with no challenges. |
| `PendingVerification { retry_after }` | A consumed pack is still under verification. The hint is 1-60 s. |
| `MembershipNotVisible` | The ticket's repository membership is not visible yet (index lag). |
| `RetryAfter { ms }` | `unavailable` with a `Retry-After` delay, clamped to 1-60 s. |

`Clock::wait` is called in exactly one place, `Push::run`'s polling loop.

## Caller-owned request identity

Every signed call takes an optional `Identity` (the nonce, which is also the
`Idempotency-Key`, plus the created and expiry times). The call uses it exactly
and returns it in `Reply::identity`. Persist `Client::new_identity()` before a
call, pass it, and after a restart replay the same call with the same identity:
the request is byte-identical and, for a write, a server that saved the first
reply returns it instead of applying the operation again (signed reads are
idempotent and keep no reply). An identity past its expiry is rejected by the
server. Without one, each call draws a fresh
identity from the clock and returns it. The window is at most 300 s.

## Reading and verifying

`unpack(pack_id, bytes, &mut sink, UnpackOptions::default())` verifies the
signature of every commit, remix and tag before it reaches the sink, and rejects
an unsigned or badly signed one (`Error::Signature`). The check is integrity
under the signer key embedded in the object; whether that key is trusted is the
caller's decision. `Verification::Skip` is
the explicit opt-out. A failed unpack can leave earlier verified objects in the
sink: treat it as staging and publish refs only after success. Decoding is
bounded by `UnpackOptions::limits` (the format maximum by default; size it down
for a constrained host). Delta bases that are not in the same pack come from
`ObjectSink::get` and are re-hashed.

## Features and dependency footprint

| Feature | Effect |
| --- | --- |
| `pack-ruzstd` (default) | Pure-Rust decode of compressed packs. Builds for `wasm32-unknown-unknown`. Push still writes raw packs. |
| `pack-zstd` | Native only: the C zstd backend. Push writes compressed packs and reads use the C decoder. Pulls in `zstd-sys`. |
| neither | Raw packs only; a compressed entry fails closed at runtime. |

The default build contains no tokio, hyper,
connectrpc, reqwest or zstd-sys; `scripts/check-wasm-dep-graph.sh` fails CI if
one appears. CI builds the crate for `wasm32-unknown-unknown` with and without
the default feature. With `pack-zstd` the writer compresses; the same feature
choice and entry order are required to reproduce identical pack ids across
restarts (a golden test pins the ids of a fixed plan).

## Memory

Request bodies are buffered. The seam is `Request<Vec<u8>>` because the
transport must replay the exact request bytes after an ambiguous failure and
because browser fetch cannot stream request bodies portably; a streaming body
does not fit it, so the limit is documented rather than lifted. Each send clones
the body once for the transport. A ticketed upload frames one part at a time
(parts are at least 8 MiB), so the per-request buffer is bounded by the part
size, not the pack; an un-ticketed upload is bounded by the server's
`begin_upload_threshold_bytes`. `Plan` holds the sealed packs
(`Limits::max_staged_bytes`, 64 MiB by default). Responses are capped while
received: 1 MiB by default, 2 MiB for a `ListRefs` page, and for
`download_pack` the caller's `max_bytes` plus framing; the returned pack is a
second copy, so a download peaks near twice `max_bytes`.

## Whole-push

The host supplies ordered canonical objects or delta streams to `Plan::prepare`,
then constructs a `Push` with its destination, head lease, tip and packmap mode.
`Push::run` plans the packmap, reserves and uploads data and packmap tickets
(including multipart uploads), and atomically advances both refs. Results
include committed, head conflict, packmap contention and explicit replan reasons.
Repeated sealed pack contents are retained once, in first occurrence order.

The host implements `HttpTransport`, `Signer` and `Clock`. Their futures need
not be `Send`. The HTTP boundary carries standard `http::Request<Vec<u8>>`
and bounded `http::Response<Vec<u8>>`; it works with Fetch, a Worker HTTP
client, or a native client. The primitive owns Connect framing and auth v2
commitments, so the host can delete copied protobuf, envelope and ticket logic.

The transport owns network retry policy and must replay the exact signed
request while its credential is valid. It must not replace its nonce after an
ambiguous response loss. It can journal requests before sending them. The
primitive refreshes credentials only after a definitive pending answer. A
post-pending authentication rejection permits one credential refresh to cover
expiry in transit or server clock lead; repeated rejection returns to the host. Its
clock supplies epoch milliseconds, secure nonce entropy and async waiting;
there is no platform clock or sleep in this crate.

Replacing a private port: keep staged input, object prefetch/closure selection,
delta selection, authorization/grant selection, persistence, restart scheduling
and multi-step history policy in the host. Feed those canonical entries and
leases to this API. Persist the host's logical operation and transport journal;
reconstruct the same plan on restart. A current head equal to the requested tip
is treated as landed, as in the CLI. This is an observation of the requested
state, not proof that a particular expired operation performed a write.

`Push` accepts one bounded advance (at most six ticketed data packs plus one
packmap ticket) and does not change the CLI's push path. The pack
encoding follows enabled `mkit-core` features: default builds write raw packs;
a native host may enable the `pack-zstd` feature. The same feature choice and entry
order are required to reproduce identical pack ids across restarts.

```rust,no_run
use mkit_core::{hash::Hash, refs::RefWriteCondition};
use mkit_client::{Clock, Destination, Entry, HttpTransport, Limits, PackmapMode, Plan, Push, Signer};

async fn publish<T: HttpTransport, S: Signer, C: Clock>(
    http: &T, signer: &S, clock: &C, tip: Hash, entries: Vec<Entry>,
) -> Result<mkit_client::Outcome, mkit_client::Error> {
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
