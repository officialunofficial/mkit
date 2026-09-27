## Purpose

The M1 server routes every RPC by `X-Repository`, answers `GetServerInfo`, will page `ListRefs` (WP-1.28), and honours
`X-Mkit-Ref` for read-your-writes (WP-1.23b). Today the client:
- sends `X-Repository` only on signed writes;
- never validates the URL path as a repository identity;
- decides atomic advance from a builder flag the CLI never sets;
- ignores paging;
- can't send the ref hint.

This WP brings the client to STC v2. Tickets and BeginUpload (1.17), parts (1.18), 402 handling (3.10) and signed
reads (2.10) are out of scope.

## A. Fixed by the plan and specs (do not change)

1. **STC:**
   - §7.3: the native CLI Connect client;
   - §7.4, client: the remote URL path is the repository identity; trim leading and trailing `/`; an empty path is
     the bare `default`; `X-Repository` is carried on RPCs;
   - §7.9: `X-Mkit-Ref` (a client SHOULD send it when fetching packs listed by a packmap it just read; it is not in
     the auth v2 canonical string; an unknown or malformed value is a server-side no-op); paging (`page_size`,
     `page_token`, `next_page_token`; an empty token ends the listing; pages concatenate in ref-name order; the
     2 MiB bound);
   - §2.1: a client MUST NOT assume atomic advance without `atomic_advance = true`, which replaces the v1 opt-in;
   - §7.1: auth v2 `<repository>` = `X-Repository`;
   - §5: the error mapping, including `aborted` → retryable;
   - §11: mapping is mechanical, never by message text, except where §5 explicitly names a message.
2. **`mkit_core::repo_identity`:** `RepositoryIdentity::parse_bare_allowed` and `IdentityError`. Bare names stay
   legal, because the client can't know the deployment kind before connecting.
3. **Compatibility:**
   - 0.4.x servers and the pre-M0 vcs-worker ignore `x-repository` on reads, and answer `GetServerInfo` with
     `unimplemented` (an unknown route). The client MUST keep working against them, with conservative defaults.
   - An M1 single-repository server answers `not_found` for a well-formed identity that isn't its configured one
     (STC §7.4).
4. **`TransportError` is not `#[non_exhaustive]`:** add **no** variants (3.10 owns `AdmissionRequired`). Changes to
   the `Transport` trait are **additive defaulted methods only**.
5. **`scripts/check-cli-baseline.sh`** (the server-free CLI) must stay green.

## B. Decided by the orchestrator (do not change)

### B.1 URL → identity (in `mkit-transport-connect`)

- A new public fn, `repository_identity_from_url(url: &str) -> Result<RepositoryIdentity, UrlIdentityError>`:
  - strip `mkit+`;
  - parse the URL;
  - **reject a non-empty query or fragment**;
  - trim leading and trailing `/`; empty → `default`;
  - validate with `parse_bare_allowed`;
  - **no** normalisation, lowercasing or percent-decoding, so `%`, uppercase and `//` fail.
  - `UrlIdentityError` is a small local enum wrapping `IdentityError`, plus `QueryOrFragment`.
- `ConnectTransport::connect*` calls it, storing the validated identity. A failure keeps returning
  `TransportError::InvalidResponse`, with a message naming the path and the reason.
- **The CLI** (`remote_dispatch::open_with_ssh_options`, the Connect branch) calls it first, and maps a failure to
  `DispatchError::MalformedUrl("repository identity `<path>` in <url>: <reason>")`.
- Fix or replace the unit test that uses `/some/project/path` (`client.rs:~802`).
- Update the stale doc comment saying the path "has no effect on the wire" (`client.rs:~184-194`).

### B.2 `X-Repository` on every RPC

- Set it in `EnvelopeTransport::send` for **every** procedure, before the signer check, from a `HeaderValue`
  precomputed at construction.
- Use `headers.insert`, so the signed path never duplicates it. The signed value is identical by construction.
- Add a `carries_repository(procedure) -> bool` predicate, true for every current procedure, with a comment reserving
  the M2 exclusion of `GetGrantEpoch`/`SetGrantEpoch` (STC §7.4).

### B.3 GetServerInfo

- Call it lazily, **once per `ConnectTransport` instance**, cached in a `OnceLock<ServerInfoState>`:
  - `V2(ServerInfo)` when the response validates: `protocol == "mkit.transport.v1"`, `spec_version >= 2`,
    `part_size` a power of two ≥ 8 MiB, `max_list_refs_page_size >= 1`;
  - `Legacy` on `unimplemented`;
  - `Unknown` on anything else, after the normal retry ladder, or on an invalid response.
- **The cached state never changes for the instance's lifetime.** Push calls `supports_atomic_advance()` twice, once
  in a `debug_assert!` (`packmap.rs:~413-416`).
- `supports_atomic_advance()` is `true` iff `V2` with `atomic_advance == Some(true)`.
- Expose `pub fn server_info(&self) -> TransportResult<ServerInfoView>` (or equivalent) for 1.17 and 1.18. They turn
  `Legacy` into a clear "server predates mkit.transport.v1 v2" error where they need v2.
- **In 1.16 only `supports_atomic_advance` triggers the call.** Don't call it from `list_refs` or other verbs: that
  would add an RPC to every fetch and change retry-count tests.
- Send `X-Repository` on it too (allowed; the server ignores it).

### B.4 Atomic advance: GetServerInfo is the only source of truth

- **Remove `ConnectTransport::with_atomic_advance`.** Nothing outside tests calls it.
- The crate is 0.x and the next release is 0.5.0 (a breaking minor), so record it under the CHANGELOG's breaking
  changes. If a semver-checks gate covers this crate on the feature branch, note the intended break in the PR.
- Update STC §7.3's v1 opt-in paragraph (≈ lines 948–970) to say the client reads `atomic_advance` from
  `GetServerInfo`.
- Behaviour change: SQLite and Durable Object deployments now report `atomic_advance = true`, so pushes may
  re-baseline the packmap chain. Put that in the CHANGELOG.

### B.5 ListRefs paging

- Leave `page_size` **unset**; the server applies its cap.
- Loop until `next_page_token` is absent or empty. Wrap **each page** in its own `retrying`; a retry re-sends the same
  token and prefix.
- **Guards,** each failing with `InvalidResponse`:
  - the token equals the previous token;
  - the first name of a page is not strictly greater than the last name of the previous page;
  - more than a documented maximum page count (C), a generous constant.
- Add row **R-105** to `00-plan.md`:

  > WP-1.28 defines an absent or 0 `page_size` as the server's `max_list_refs_page_size`, and adds that sentence to
  > STC §7.9. The WP-1.16 client never sets `page_size`.

### B.6 Ref hint (`X-Mkit-Ref`)

- **Add defaulted methods to `mkit_core::protocol::Transport`** (additive; the defaults ignore the hint):
  - `download_pack_via_ref(&self, key, ref_name: &str)` → `self.download_pack(key)`;
  - `download_blob_via_ref(&self, key, ref_name: &str)` → `self.download_blob(key)`, or `download_pack_via_ref` if
    blob downloads go through `DownloadPack` in this client;
  - `pack_exists_via_ref(&self, key, ref_name: &str)` → `self.pack_exists(key)`.
- **`ConnectTransport` overrides them** to add `x-mkit-ref: <ref>` through `CallOptions`, inside the retry closure.
  - A hint that fails `refs::validate_ref_name` is dropped, never an error.
  - The header is never part of the signed canonical string.
- **The CLI passes `refs/heads/<branch>`** from `download_packlist_node`, `walk_pack_chain` and
  `download_pack_chain_with_limits`, plus the self-heal download at `packmap.rs:~679`. The server honours it from
  WP-1.23b; until then it's a harmless no-op.

### B.7 `not_found` semantics for multi-repository (closes gap G2)

- **`read_ref`:** `not_found` → `Ok(None)`. A ref in a nonexistent repository doesn't exist; the first push then
  creates the repository, and CAS stays authoritative.
- **`list_refs`:** `not_found` → a clear error. Add `DispatchError::RepositoryNotFound { identity, origin }` in the
  CLI, mapping `PackNotFound` from `list_refs` there. The message names the identity sent and hints that a
  single-repository deployment behind an empty path is `default`.
- **`update_ref`, `advance_refs`, `upload_pack`:** `not_found` → the same repository-not-found message.
- **`download_pack`, `pack_exists`:** keep `PackNotFound` / `false`.
- **Also fix `aborted` → `ServerError { status: 503 }` (retryable)** in `tc/src/error.rs`, per STC §5. The current
  catch-all maps it to `RemoteError`, and `aborted` is the in-flight replay answer that clients must retry.

### B.8 Docs

- CHANGELOG entries:
  - path identity is now validated and enforced;
  - anonymous reads now fail when the path doesn't match a single-repository server's configured name;
  - atomic advance is automatic, from `GetServerInfo`;
  - `with_atomic_advance` is removed;
  - the new `Transport` `_via_ref` methods;
  - `aborted` is now retryable.
- Update STC §7.3 per B.4. No other spec edits.

## C. Your decisions

- The internal shape of `ServerInfoState` / `ServerInfoView`.
- The maximum page count constant (B.5).
- Error-message wording, within B.7.
- Test organisation.

## Tests (required)

1. **tc, unit** (`envelope.rs` `CapturingTransport`):
   - `x-repository` is present on `ListRefs`, `ReadRef`, `PackExists`, `DownloadPack` and `GetServerInfo`, with and
     without a signer;
   - the signed value equals the header;
   - `x-mkit-ref` never appears in the canonical string.
2. **tc URL table:** empty → `default`, `ns/name`, a trailing `/`, uppercase, `%`, `//`, a query, a fragment, 174
   bytes, and a bare name.
3. **tc integration** (a roundtrip-style in-process server with a configurable `GetServerInfo`):
   - `atomic_advance` true and false;
   - `unimplemented` → false;
   - persistent `unavailable` → false, **called once**;
   - the cached state holds across calls;
   - a multi-page `ListRefs`;
   - a token-repeat and an out-of-order page each give `InvalidResponse`;
   - a paging retry of one page;
   - the hint header present on `_via_ref` calls and absent otherwise;
   - `aborted` retried.
4. **`retry.rs`:** the existing attempt counts are unchanged.
5. **mkit-cli** (`tests/remote_dispatch_connect.rs`):
   - `TestService` captures headers, and push then fetch asserts `x-repository` = `myproj` on every RPC;
   - `x-mkit-ref = refs/heads/main` on packmap-driven downloads;
   - a bad path gives `MalformedUrl`;
   - a `list_refs` `not_found` gives `RepositoryNotFound`;
   - a `read_ref` `not_found` gives `None`.
6. **mkit-server-native `client_e2e.rs`:** real `GetServerInfo`, with `supports_atomic_advance()` false on fs-layout
   and true on SQLite, if the harness can start one.

## D. Escalate (stop and report) if

- Removing `with_atomic_advance` breaks a non-test caller anywhere in the workspace or `apps/`.
- A `Transport` default method would change behaviour for an existing implementor.
- `check-cli-baseline.sh` fails because of a new normal-edge dependency.

## Gates

- `cargo nextest run --locked -p mkit-transport-connect -p mkit-cli -p mkit-core -p mkit-server-native --all-features`
- `just ci` (this touches `mkit-core`'s public trait)
- `scripts/check-cli-baseline.sh`
- clippy `-D warnings`
