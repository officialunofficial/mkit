# mkit-sync

Native clone, fetch, pull, and push for `.mkit` repositories, as a library.

`mkit-sync` is the filesystem layer behind the `mkit` command line's `clone`,
`fetch`, `pull`, and `push`. The read path walks a branch's packmap chain, downloads the packs it
does not already have, unpacks them under the per-branch repository lock,
verifies the signature of every commit, remix and tag it introduced, checks
the tip's closure is complete, publishes the remote-tracking ref, and (for
`pull`) fast-forwards the branch, HEAD and worktree with rollback on failure.

The push path plans the repository closure and deltas, builds and uploads
packs, advances the packmap and branch refs with CAS, and records each published
remote-tracking ref. It preserves split-push bounds and resumable uploads.

Every call returns a typed report or a typed error. **Nothing is printed**
(`#![deny(clippy::print_stdout, clippy::print_stderr)]`), and the library
reads **no mkit config, credentials or environment variables** of its own.
(Downloaded packs are staged under the system temporary directory unless
`SyncOptions::staging_dir` names another.)

## API

```rust,ignore
use mkit_sync::{
    CloneRemote, NoopObserver, SyncOptions, TransportSource, clone, fetch, pull,
};

// `transport` is any mkit-core `Transport`, built and authenticated by the
// caller. The library never opens a connection or reads a credential itself.
let source = TransportSource::new(&transport);
let remote = CloneRemote {
    name: "default".into(),
    url: "mkit+https://example.invalid/repo".into(),
    kind: "http".into(),
};

let cloned = clone(&dir, &source, &remote, &SyncOptions::default(), &NoopObserver)?;
let fetched = fetch(&dir, &source, "default", &SyncOptions::default(), &NoopObserver)?;
let pulled = pull(&dir, &source, "default", &SyncOptions::default(), &NoopObserver)?;
```

| Call | Does |
|---|---|
| `init_clone_dir(dir, &CloneRemote)` | Create the directory, an empty repository and its config (the flat `remote_endpoint` / `remote_type` keys for the `default` remote, `remote.<name>.*` otherwise). |
| `fetch(dir, source, remote, &SyncOptions, observer) -> FetchReport` | Reconstruct every remote branch and publish `refs/remotes/<remote>/*`. HEAD, local branches and the worktree are untouched. |
| `pull(...) -> PullReport` | `fetch`, then fast-forward the current (or `target_branch`) branch, HEAD and worktree. Anything that is not a fast-forward is `SyncError::NonFastForwardPull`. A worktree whose local changes the fast-forward would overwrite is `SyncError::RestoreSafety`. |
| `clone(...) -> CloneReport` | `init_clone_dir` followed by `pull`. |
| `push(dir, source, &PushOptions) -> PushReport` | Publish selected branches through a write-capable source and durably record their remote-tracking refs. |

`SyncOptions`:

* `verify_signatures` (default `true`): verify every commit, remix and tag the
  call introduces and fail closed with `SyncError::UnsignedOrInvalidObject`.
  Setting it to `false` is the explicit opt-out.
* `target_branch`: land on this branch. It must exist on the remote; there is
  no silent fallback (`SyncError::RemoteBranchMissing`).
* `sync_policy`: object-store durability (`Batch` by default).
* `staging_dir`: where downloaded packs are staged (system temp dir by default).

`SyncOptions` is `#[non_exhaustive]`: start from `SyncOptions::default()` and
use the `with_*` setters.

### Incremental fetch checkpoints

With signature verification enabled, fetch records the last fully applied
packmap head per remote branch. Both `ClientSource` and `TransportSource`
use `RemoteSource::repository_address` to bind it to the repository and
origin. Sources without that identity retain the full walk. Changing the
origin or repository prevents reuse, even with the same remote and branch names.

The disposable common-dir cache lives in **.mkit/applied-packs/.heads/**.
The leading dot keeps the directory outside the valid remote-record namespace.
Its filename is lowercase BLAKE3 over the remote name, branch name, repository,
and origin, in that order. Each UTF-8 value has an eight-byte little-endian
byte-length prefix. File contents are six LF-separated fields, without a final
LF: `mkit-fetch-head-v1`, lowercase head hash, lowercase tracking-tip hash,
decimal pack count, decimal node count, and lowercase BLAKE3 of the preceding
five fields including their four separators. The checksum detects accidental
corruption. Readers cap input at 512 bytes and validate counts against the
existing chain limits. Missing, unreadable, or invalid records cause a full walk.
You can delete these files; they never pin objects for GC. Remote rename starts
a new checkpoint, and removing a remote may leave a harmless disposable file.

Fetch reads the atomic checkpoint, walks from the new head, and stops before
downloading the recorded immutable node. Prefix validity does not depend on
the current tracking tip: the locked closure check remains authoritative even
after a tracking change or GC. Fetch still verifies and publishes the listed
tip when it changes under an unchanged packmap head. If the recorded head is
absent from the chain, the walk continues to the root. When both the
listed tip and packmap head match, no nodes or packs download. Cancellation
checks and the local closure check still run. A missing local object triggers
the existing applied-pack recovery, resolving and downloading the full chain
with no skips. If decoding a new delta fails because its base is missing from
an omitted prefix, fetch first retries the full walk with the current pack
record, matching the original download order and skip behavior. Stale-listing
reads and the concurrent re-baseline retry retain their existing behavior.

New packs still pass digest and signature verification. Only after successful
application and closure verification does fetch durably publish the tracking
ref, then atomically write and fsync the checkpoint, under the same worktree
lock. Tracking directories now sync per branch before checkpoint publication.
A crash before the checkpoint write leaves the old record; the next fetch
walks more nodes. Cache write failure does not fail an otherwise successful fetch.

For a single branch, one listing page, one pack per node, and no retries,
let `N` be the total chain length after the operation. Count each ListRefs,
ReadRef, node download, and pack download as one RPC:

| Operation | Before | After |
|---|---:|---:|
| Clone | `2 + 2N` | `2 + 2N` |
| Pull after one appended commit | `3 + N` | `4` |
| No-op pull | `2 + N` | `2` |

For `k` appended nodes containing `p` missing packs, incremental fetch costs
`2 + k + p`. A rewritten chain costs `2 + N + p`. Additional listing pages,
branches, and recovery reads add their own calls. The report continues to count
packs in the verified prefix as already applied; CLI output and exit codes stay
the same. These formulas concern network calls; the local closure check still
scales with reachable objects.

### Pushing a repository

Start with `PushOptions::default()`. Use `with_target(PushTarget::Branch { .. })` for
one local-to-remote branch mapping, with `PushLease::FastForward`, `WithLease`,
or `Force`; the default pushes all branches without force. `remote_name` selects
the local tracking refs. `sync_policy`, `rebaseline_threshold`, and
`pack_payload_cap` carry caller policy. `control` sets split bounds, an optional
`StepAuthority` check before split uploads, and `observer` for progress and
cancellation. The library loads the repository's shallow boundaries.

```rust,ignore
use mkit_sync::{PushLease, PushOptions, PushTarget, push};

let mut options = PushOptions::default().with_target(PushTarget::Branch {
    local: "main".into(),
    remote: "main".into(),
    lease: PushLease::FastForward,
});
options.remote_name = "origin";
options.control.observer = &my_observer;
let report = push(&dir, &source, &options)?;
```

On atomic-capable sources, force pushes publish the head and packmap together,
including a head-only change. The uncontended success path adds at most one
strong packmap read; other pushes keep their existing requests. A replaced chain causes
a re-plan within the same eight-attempt budget as publication. Sustained
contention returns `PushError::PackmapContended`. A dependent plan compares both
observed refs so a reset back to an identical packmap digest is safe. The
superseded JSON HTTP endpoint uses its existing head `Match`/`Missing` condition
alongside the packmap guard; it does not use the ordered `Any` fallback.
Connect sources whose capability discovery failed or was invalid refuse force
pushes with `PushError::ForceCapabilityUnknown` before uploading. Reconnect and
retry discovery. Explicitly non-atomic transports retain their existing push
behavior; failed discovery is not evidence that a server is non-atomic.

`PushReport` contains the completed ref count, advance count, and optional
single-branch tip. `PushError` preserves push-specific refusals and carries
filesystem and backend failures through `PushError::Sync`; backend failures
remain `SyncError::Source(SourceError)`. The CLI maps these errors to its
existing output and exit codes. Configuration, trust gates, grant checks,
admission helpers, signing, and extra certificate trust stay caller-owned.

### Observing a sync

Warnings and progress that a command line would print arrive as
`SyncEvent`s on a `SyncObserver` (`ObjectsUnpacked`, `BranchSkippedStale`,
`AppliedPacksStale`, `RepositoryServed`, ...). The same trait is polled for
cancellation (`cancelled()`), which makes the call fail with
`SyncError::Interrupted`. `NoopObserver` ignores everything.

### Remote sources

The engine reads through the `RemoteSource` trait: list branches, read a ref,
download a packmap node, and download a pack. Write-capable sources also
advertise limits, upload packs, and advance refs. `supports_push()` is `false`
by default, so custom read-only sources need no write implementation. Two
backends ship:

* `TransportSource` (always): mkit-core's synchronous `Transport`, so every
  transport scheme (file, ssh, s3, http, connect) works. Credentials live in
  the transport the caller built; `with_error_classifier` lets a caller map
  transport-specific failures to typed errors. This backend supports push.
* `ClientSource` (feature `client`): `mkit_client::Client` for `mkit+https` and
  `mkit+http` remotes, anonymous or **signed by an injected
  `mkit_client::Signer` and `Clock`**. Private reads are authenticated by the
  signer; nothing is read from the environment or from user config. The async
  client is driven by an `Executor` (`block_on`): `FuturesExecutor` for a
  transport that needs no reactor, or the transport itself when it owns a
  runtime, as `NativeHttp` does.

```rust,ignore
use mkit_client::Client;
use mkit_sync::{ClientSource, NativeClock, NativeHttp, NoopObserver, SyncOptions, clone};

let http = NativeHttp::new()?;                       // feature `connect-native`
let client = Client::signed(&http, destination, &my_signer, &NativeClock)
    .with_observer(&my_observer);
let source = ClientSource::new(&client, &http);
clone(&dir, &source, &remote, &SyncOptions::default(), &NoopObserver)?;
```

A signed `ClientSource` supports push through the client's per-RPC calls.
A host using bearer or unsigned authentication can explicitly enable ticketless
writes with `Client::with_unsigned_writes()` and retain retry identity through
`Client::anonymous_with_clock`; anonymous clients remain read-only
without that opt-in.
Use `Client::with_request_policy` to select stored grants and validated admission
headers for each signed request, including reads. The host verifies grants,
selects credentials, and observes bounded payment receipts; the source does not
read configuration or run helpers.

`ClientSession` retains negotiated capabilities and upload commitments across
fresh borrowed clients. Use `ClientSource::with_session` to lend it for one
operation; reuse with another origin, repository, or signer is refused. Session
bookkeeping uses short internal locks. Default sources retain their conditional
`Send` and `Sync` traits; explicitly configured policy and recovery types may
use local state.

`ClientSource::with_receipt_store` accepts a caller-owned `PartReceiptStore`.
Its `put` must finish durably before returning. The source saves each acknowledged
part before reporting progress or sending another part. A fresh instance calls
`BeginUpload` to recover the open ticket, validates saved receipt bindings, and
uploads only missing parts. Receipt types are shared with the synchronous Connect
adapter, so existing stores keep their record format.

Without `with_write_recovery`, typed scheduling and payment outcomes return to the
caller. Install a `WriteRecovery` to schedule retries or run an admission helper;
its `recover` runs outside the asynchronous executor. The source retains the
operation identity across ambiguous failures and renews expired envelopes.
Ticketed uploads and advances never invoke admission recovery. The callback also
reports multipart progress after durable persistence and can cancel before a part.
The host must bound its retry ladder and waits.

The CLI uses a configured `ClientSource` for `mkit+https` and `mkit+http` push,
fetch, pull, and clone. Native extra-CA, bearer credentials, grants, helpers, and
configuration remain host-owned. Other schemes retain `TransportSource`.
`NativeHttp` streams upload frames and incrementally decodes downloads; generic
HTTP transports retain an additive buffered fallback. The protocol client's
whole-push API is unchanged.

A missing repository, a private one read anonymously and one read by a signer
the server denies all come back as the same `SyncError::RepositoryNotFound`
(the wire answer is a uniform `not_found`).

### Source failures and host scheduling

Every source operation returns `SourceError`, carried by `SyncError::Source`.
`PendingVerification { retry_after }`, `MembershipNotVisible`,
`RetryAfter { ms }`, and `PaymentRequired { challenges }` preserve the host's
next action. Payment challenges retain the full `AdmissionRequired` record,
including helper headers and terminal admission reasons. The library returns
these outcomes immediately unless a host write-recovery callback schedules a retry.

`SourceError::class()` returns `FailureClass::Resumable` for these outcomes
(except a terminal admission reason), `Transient` for classified connection
failures, HTTP 429/5xx transport failures, and Connect `resource_exhausted`,
`unavailable`, or `aborted`, and `Refusal` otherwise. This is evidence for host
policy, not an automatic retry instruction. Signing and signer refusals remain
separate typed variants. Unclassified `HttpTransport` string failures are
terminal: that seam also reports refused redirects and malformed responses.
A channel can override `HttpTransport::send_classified` to distinguish actual
connection failures. `NativeHttp` does so; those failures retain the existing
Connect adapter's retryable HTTP 503 class. Request budgets retain the terminal
`client-side deadline exceeded` diagnostic. Redirect, parsing, negotiation,
and response-bound refusals remain terminal.

Raw Connect failures keep code, message, opaque details, actual HTTP status,
and every response header value as bytes in `RemoteFailure`. Treat these fields
as untrusted and potentially sensitive. Display text omits details and headers.
`TransportSource` explicitly maps core's classified errors; its metadata is
limited to what the underlying transport supplies. Core transports may return
the three scheduling variants directly; existing Connect transport polling
behavior remains inside that transport. Core's generic backoff does not retry
the new scheduling outcomes.

Migration toward 0.6: change custom `RemoteSource` results and classifiers to
`SourceError`, map core errors with `SourceError::from`, and replace matches on
`SyncError::Transport` with `SyncError::Source`. The observer parameter on
`ClientSource` defaults to `NoObserver`; inferred construction also accepts
`Client::with_observer`. Read calls do not invoke the write observer.

### `connect-native`: a small native HTTP channel

`NativeHttp` implements `mkit_client::HttpTransport` with hyper over rustls
(`ring`) on a **current-thread** tokio runtime (DNS lookups use tokio's blocking pool), HTTP/1.1 only. It speaks
**gzip as its only compressed content coding** (`accept-encoding: gzip` by default; a response in any
other coding is refused, and an inflated body is bounded by the same response
limit as a plain one), refuses cleartext `http` to any host but loopback unless
`allow_insecure_http(true)`, never follows a redirect (a signed request must not be
replayed to another origin), bounds every response while receiving it, and
bounds metadata requests by 30 seconds and `UploadPack`, `UploadPart` and
`DownloadPack` by 300 seconds, including receipt of the response body. These
defaults replace the previous ten-minute bound. Use `with_metadata_timeout` and
`with_transfer_timeout` to tune them independently, or `with_timeout` to set both.
Supplied `user-agent` and gzip/identity-compatible `accept-encoding` values are
preserved. Negotiation naming another coding (including wildcards or a coding
with quality zero), or malformed negotiation, is refused before connecting.
`send_typed` returns `NativeHttpError::UnsupportedAcceptEncoding`; the
`HttpTransport` adapter converts native errors to its string error contract.
TLS trusts the
built-in web PKI roots unless the caller passes a `rustls::ClientConfig`.
`NativeClock` supplies the epoch clock, OS entropy for nonces and the tokio
timer. Calling `NativeHttp` from inside another tokio runtime panics, as
`block_on` does.

The owned runtime and HTTP pool survive between operations. The pool keeps at
most one idle connection per origin for ten seconds, with TCP_NODELAY enabled.
Reads and signed writes, including streamed transfers, reuse the connection.
Hyper automatically retries only an untouched request canceled before writing
starts; it retains the same body and identity. An exchange failure after writing
starts is returned to the caller. Pool checkout checks elapsed idle time even
when the current-thread runtime is paused. No scheduler thread is added.

The channel adds no zstd: with `--no-default-features` the tree has none, and pack decode goes through
mkit-core's `pack-ruzstd`. `scripts/check-sync-native-deps.sh` runs in CI and
fails if `zstd`, `zstd-safe`, `zstd-sys`, `aws-lc-*`, `openssl*`,
`native-tls`, `rustls-native-certs`, `brotli` and other compression crates,
`libz-sys`, `hyper-tls`, `h2`, `connectrpc` or `reqwest` enter the normal or
build graph, if tokio's multi-thread scheduler is enabled, or if `flate2`,
`hyper`, `rustls`, `ring` or (in the `pack-ruzstd` row) `ruzstd` leave it.

### Worktree primitives

`mkit_sync::worktree` holds the restore-safety, index and history-aware
branch-write primitives a fast-forward is built on (`ensure_restore_safe`,
`restore_worktree_and_index`, `write_ref_recording_history`, ...). The `mkit`
command line's `checkout`, `reset` and `restore` use the same functions.

## Features

| Feature | Default | Effect |
|---|---|---|
| `pack-zstd` | yes | Reads zstd-compressed (format v2) pack entries through the zstd C library. Without it, v2 packs are rejected unless `pack-ruzstd` is on. |
| `pack-ruzstd` | no | Pure-Rust decode of v2 pack entries, for builds without `pack-zstd`. |
| `history-mmr` | no | Publish versioned first-parent ancestry snapshots with branch writes. |
| `client` | no | `ClientSource`, `Executor`, `FuturesExecutor`: the `mkit-client` backend. |
| `connect-native` | no | `client` plus `NativeHttp`, `NativeClock`, `default_tls_config`. Gzip only; adds no zstd of its own (build with `--no-default-features` for a tree without it). |

The embedding native addon builds `--no-default-features --features
pack-ruzstd,connect-native`.

## Dependency footprint

`cargo tree -e normal -p mkit-sync` (host target, unique crate names):

| Build | Crates | `zstd-sys` | Pack decode |
|---|---|---|---|
| default (`pack-zstd`) | 67 | yes | C zstd |
| `--no-default-features` | 64 | no | raw packs only |
| `--no-default-features --features pack-ruzstd` | 66 | no | `ruzstd` |
| `--features client` | 88 | yes | C zstd |
| `--no-default-features --features pack-ruzstd,client` | 87 | no | `ruzstd` |
| `--features connect-native` | 117 | yes | C zstd |
| `--no-default-features --features connect-native` | 114 | no | raw packs only |
| `--no-default-features --features pack-ruzstd,connect-native` | **116** | **no** | `ruzstd` |

The last row is the addon build. `connect-native` adds hyper, hyper-util,
hyper-rustls, rustls (`ring`), webpki-roots, tokio (`rt`, `net`, `time`),
flate2 (pure-Rust backend), http, http-body-util, bytes and getrandom, about 30
crates over the `client` row; no async runtime beyond the current-thread
scheduler, no HTTP/2, no Connect runtime.

## License

MIT OR Apache-2.0.
