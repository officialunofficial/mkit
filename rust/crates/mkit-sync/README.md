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

`ClientSource` remains read-only (`supports_push() == false`). The CLI's
`mkit+https` push uses `TransportSource` until the client adapter has parity for
grants, admission and 402 helpers, durable receipt persistence, and resumable
parts. Native extra-CA and configuration wiring remain host-owned. The protocol
client's own push API is unchanged.

A missing repository, a private one read anonymously and one read by a signer
the server denies all come back as the same `SyncError::RepositoryNotFound`
(the wire answer is a uniform `not_found`).

### Source failures and host scheduling

Every source read returns `SourceError`, carried by `SyncError::Source`.
`PendingVerification { retry_after }`, `MembershipNotVisible`,
`RetryAfter { ms }`, and `PaymentRequired { challenges }` preserve the host's
next action. Payment challenges retain the full `AdmissionRequired` record,
including helper headers and terminal admission reasons. The library returns
these outcomes immediately and never sleeps or retries them.

`SourceError::class()` returns `FailureClass::Resumable` for these outcomes
(except a terminal admission reason), `Transient` for classified connection
failures, HTTP 429/5xx transport failures, and Connect `resource_exhausted`,
`unavailable`, or `aborted`, and `Refusal` otherwise. This is evidence for host
policy, not an automatic retry instruction. Signing and signer refusals remain
separate typed variants. Unclassified `HttpTransport` string failures are
terminal: that seam also reports refused redirects and malformed responses.

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
