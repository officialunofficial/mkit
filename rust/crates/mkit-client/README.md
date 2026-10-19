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
  of a client that has a signer. Writes need a signed client or explicit
  unsigned-write opt-in (below). There is no fork
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
the authenticated operation, body and identity are identical; unsigned observer
headers may be regenerated. Exact-byte replay applies to a retained request.
For a write, a server that saved the first reply returns it instead of applying the operation again (signed reads are
idempotent and keep no reply). An identity past its expiry is rejected by the
server. Without one, each call draws a fresh
identity from the clock and returns it. The window is at most 300 s.

## Request credentials and receipts

`HttpTransport::send_classified` can distinguish transient I/O from a channel
refusal through `ChannelError`. Its default preserves string-only transports as
terminal `Error::Transport`; explicit transience becomes `Error::Connection`.
`ChannelError::TimedOut` becomes `Error::RequestTimeout`. The client still
performs one exchange per RPC and leaves recovery to its caller.

Anonymous clients remain read-only by default. A host that uses bearer or
unsigned write authentication explicitly enables per-RPC writes with
`Client::with_unsigned_writes()`. The server still enforces its authentication
mode; ticketed upload reservations require a signer. Signed visibility and
external-envelope methods remain signer-only. Unsigned RPC policy uses
`UnsignedRequestContext`, without a synthetic signer or public key.
`Client::anonymous_with_clock` (or `with_unsigned_clock` on a typed client)
opts unsigned writes into caller-owned nonce and validity metadata and observer
callbacks. Clockless unsigned writes use `RequestPolicy::unsigned_headers` for
pre-dispatch policy. Retry the
same identity until expiry; unsigned reads and discovery stay identity-free.

`Client::with_request_policy(&policy)` installs host-owned `RequestPolicy`.
The policy type stays part of the client type: default clients retain their
conditional `Send` and `Sync` traits, and explicitly configured policies may
use local state.
The client consults it for each signed request, including reads, after the write
observer and before signing. `RequestContext` carries the operation, public key,
and optional write intent. `WriteIntent::ticketed` identifies ticket credentials
even when the caller knows only their opaque token. Dedicated `RequestHeaders` setters carry a write grant
or authorization credential; ordinary extra headers retain reserved-name checks.
The host verifies grant authority and scope, filters helper headers, and prevents
replacement of a transport credential. Policy callbacks do not run helpers or
schedule retries. `after_response` observes successful response headers so the
host can record bounded payment receipts.

`PartReceiptStore`, `TicketMetadata`, and `StoredPart` describe caller-owned
multipart acknowledgement persistence. `put` must finish durably before returning;
`load` rejects mismatched ticket bindings and part geometry. `MemoryPartReceiptStore`
is a process-local fallback. Native upload orchestration in `mkit-sync` consumes
this seam; per-RPC client calls remain independent of filesystem storage.

## Host policy seams: signer and observer

The client carries no policy; it gives the host two places to run its own,
before anything is signed or written. Both apply to every per-RPC call and to
`Push::run_with`.

For each signed request the client runs, in this order:

1. **Observer** (`Observer::before_dispatch`, write RPCs only). It receives a
   `WriteIntent` and the `Attempt`, and may veto (`Veto`, which surfaces as
   `Error::Vetoed`) or return `AttemptHeaders`.
2. **Signer** (`Signer::sign_operation`). It receives a `SigningRequest` next to
   the digest and may refuse (`SignError::Refused`, `Error::SignerRefused`).
3. **Deadline check.** If the signed window has ended, the request is never
   sent: `Error::EnvelopeExpired`. An identity that has already ended fails the
   same way before step 1.
4. **Dispatch.**

A veto or refusal stops the call there: nothing is signed after a veto and
nothing is sent after either. Install an observer with
`Client::with_observer(&observer)` or `Push::run_with(.., &observer)`. The
default observer does nothing, and a signer that implements only
`Signer::sign` keeps working, because `sign_operation` defaults to it.

- **What the signer sees.** `SigningRequest` has the full procedure, audience,
  repository, the parsed `ContentCommitment` (`body:`, `pack:` or `part:`, so a
  policy can bound pack size or part index without parsing text), and the
  attempt (nonce, validity window).
- **What the observer sees.** `WriteIntent` has the procedure, the exact
  `RefMove`s the request carries (name, `old` precondition, `new`: `Set`,
  `Delete` or `CopyFrom`), the target ref, pack id and length, ticket ids, the
  part index and, for a whole push whose pack holds only raw entries, the ids
  of the objects it introduces (`new_objects`, reported on each RPC of that
  pack's upload, ticketed or not; `None` when unknown, as for a pack with a
  delta entry, the packmap node and every per-RPC upload). Intents are built
  from the request being sent, so the observer sees exactly what the server
  receives; an `advance_refs` request whose ids or expectations are
  malformed is `Error::Invalid` before any seam runs, with or without an
  observer. A branch copy (`source_ref`) names only the destination head; the
  server also writes its packmap twin (`RefTarget::CopyFrom`).
- **Which calls.** `begin_upload`, `upload_pack`, `upload_part`,
  `complete_upload`, `advance_refs`, `update_ref` and `delete_ref` (the five
  write RPCs of the protocol plus `CompleteUpload`). Reads are signed but not
  observed. A per-RPC `complete_upload` has only the opaque token, so its intent
  has no ticket ids; a whole push reports them.
- **Once per attempt.** The seams run each time an envelope is built, with the
  same `Attempt` for both (number from 1, nonce, created and expiry times), so a
  host can write one durable note per nonce. A new envelope (a fresh call, or
  the renewal inside `Push::run_with` after a pending answer and an
  authentication rejection, or after a poll wait that reaches the envelope's
  expiry) runs observer, signer and dispatch again with the next
  number and a new nonce. A caller who replays a persisted `Identity` (for
  example after a restart) builds an envelope again, so the seams run again with
  the same nonce and number 1: key the note on the nonce and replace it.
  Re-sending already signed bytes (a pending-verification poll while the
  envelope is valid, a transport retry) builds nothing and does not call the
  seams.
- **Per-attempt headers.** `AttemptHeaders` (for example `traceparent` or a
  request id) is added to that attempt's request and is not signed. A name that
  is not reserved replaces a transport default of the same name. Names are
  checked against the hard-reserved list of SPEC-TRANSPORT-CONNECT section 5.1
  (the auth v2 headers, `X-Mkit-*`, `X-Forwarded-*`, `Content-*`, `Connect-*`,
  `Host`, `Cookie`, `Idempotency-Key`, hop-by-hop headers; `Authorization` too,
  because the client cannot know whether its transport already sends one) and a
  reserved name is `Error::ReservedHeader` before anything is signed.
  `is_reserved_header` exposes the check.
- **Signing outside the client.** `Client::sign_envelope(procedure,
  &commitment, identity, intent)` returns the auth v2 request headers
  (`SignedEnvelope`) without sending: the same observer, signer and deadline
  check, for a host that dispatches an mkit
  procedure through its own binding. The six transport write procedures require an
  `intent` naming that procedure (`Error::Invalid` otherwise), so the observer
  cannot be skipped; any other procedure reaches the signer and is observed only
  when an `intent` is passed; the
  attempt number is 1. The observer sees the intent the host passes, so build it
  from the body that will be sent. The caller supplies a body that matches the
  commitment. The headers verify with `mkit_core::write_auth::verify_headers`.

Objects the client signs itself: none. It verifies commits, remixes and tags in
`unpack` and signs only auth envelopes, so the signer seam covers envelopes.

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

Complete ref listings validate strict name ordering across pages, reject cursor
cycles, and retain at most 128 MiB of charged state (names, entries, cursor
digests, collection overhead, and the active cursor). Cursors are limited to
4 KiB. `list_all_refs` uses the smaller of your page cap and 100,000 pages;
invalid or excessive listings return `Error::Invalid`. `list_refs` also checks
ordering and duplicates within a page and rejects oversized continuation tokens.

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

## Streaming channels

`HttpTransport::send_stream` consumes a runtime-free `RequestStream` and delivers
response bytes to a `ResponseStream`. Its default buffers and calls the existing
channel API. Native channels can override it to send one frame at a time and
decode incoming Connect frames incrementally. Wire and inflated response bounds,
frame ordering, end markers, protobuf chunk offsets, and content commitments
still apply. A failure returns no complete pack.

`RequestPolicy::request_timeout` can shorten a request budget. The client stores
it in a `RequestTimeout` extension; native channels take the smaller of that
budget and their configured metadata or transfer limit. A zero policy budget
refuses dispatch. Recovery and scheduling remain in the host.

## Pack locations

Channels can implement `HttpTransport::supports_pack_locations` and
`fetch_pack_location` to fetch external packs without credentials or redirects.
The client negotiates support through discovery, checks the exact length and
pack content address before returning bytes, and retries once through streaming
if a location fails. `Client::with_pack_locations(false)` disables negotiation.
Channels without that implementation and wasm clients keep streaming.
