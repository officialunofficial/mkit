# mkit-sync

Native clone, fetch and pull for `.mkit` repositories, as a library.

`mkit-sync` is the filesystem layer behind the `mkit` command line's `clone`,
`fetch` and `pull`: it walks a branch's packmap chain, downloads the packs it
does not already have, unpacks them under the per-branch repository lock,
verifies the signature of every commit, remix and tag it introduced, checks
the tip's closure is complete, publishes the remote-tracking ref, and (for
`pull`) fast-forwards the branch, HEAD and worktree with rollback on failure.

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

### Observing a sync

Warnings and progress that a command line would print arrive as
`SyncEvent`s on a `SyncObserver` (`ObjectsUnpacked`, `BranchSkippedStale`,
`AppliedPacksStale`, `RepositoryServed`, ...). The same trait is polled for
cancellation (`cancelled()`), which makes the call fail with
`SyncError::Interrupted`. `NoopObserver` ignores everything.

### Remote sources

The engine reads through the `RemoteSource` trait: list branches, read a ref,
download a packmap node, download a pack. The first backend is
`TransportSource`, over mkit-core's synchronous `Transport`, so every
transport scheme (file, ssh, s3, http, connect) works. Credentials live in
the transport the caller built; `TransportSource::with_error_classifier` lets
a caller map transport-specific failures to typed errors.

### Worktree primitives

`mkit_sync::worktree` holds the restore-safety, index and history-aware
branch-write primitives a fast-forward is built on (`ensure_restore_safe`,
`restore_worktree_and_index`, `write_ref_recording_history`, ...). The `mkit`
command line's `checkout`, `reset` and `restore` use the same functions.

## Features

| Feature | Default | Effect |
|---|---|---|
| `pack-zstd` | yes | Pack decode and encode through the zstd C library. |
| `pack-ruzstd` | no | Pure-Rust decode of v2 pack entries, for builds without `pack-zstd`. |
| `history-mmr` | no | Publish versioned first-parent ancestry snapshots with branch writes. |

## Dependency footprint

`cargo tree -e normal -p mkit-sync`: direct dependencies are `mkit-core`,
`rayon`, `tempfile` and `thiserror`.

| Build | Unique crates in the normal tree | `zstd-sys` |
|---|---|---|
| default (`pack-zstd`) | 85 | yes |
| `--no-default-features` | 82 | no |
| `--no-default-features --features pack-ruzstd` | 84 | no |

No async runtime, HTTP client or TLS stack is involved.

## License

MIT OR Apache-2.0.
