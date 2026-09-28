# WP-2.10 — signed reads and the grant header in the Connect client

## Purpose

This WP makes the Connect client:
- sign read RPCs when a signer is configured, so an M2 server can classify the caller as a writer or a reader and
  authorize private reads (SPEC-WRITE-GRANTS §9.2);
- attach the matching write or read grant header.

It ships the mechanism and the API. The user grant store is WP-2.13.

## A. Fixed (do not change)

1. **What gets signed.**
   - SPEC-WRITE-GRANTS §9.2: a client with a signer MUST sign reads.
   - SPEC-WRITE-GRANTS line ~826 and STC §7.1: the client MUST NOT sign `GetServerInfo`, `GetGrantEpoch` or
     `SetGrantEpoch`.
   - The grant-epoch RPCs carry no `X-Repository`.
2. **Read replay.** Reads record and look up nothing, and a read MAY be re-signed on every retry.
3. **The grant header** `X-Write-Grant` is outside the signed canonical string. A grant without auth v2 is
   `unauthenticated`, and the namespace owner never needs a grant.
4. **mkit-core's public API** stays unchanged. `mkit-transport-connect` changes are additive.

## B. Decided (do not change)

### B.1 Classification table

Replace the two predicates at `envelope.rs:~76-91` with one total classification table:

| Procedures | Signing |
|---|---|
| `ListRefs` (each page), `ReadRef`, `PackExists`, `DownloadPack`, and `IssueObjectUrl` once 2.2 lands | Signed with `body:` over the **exact HTTP request body** (including DownloadPack's 5-byte framing), plus `X-Digest` |
| `UpdateRef`, `AdvanceRefs` | Unchanged (`body:`) |
| `UploadPack` | `pack:` |
| `BeginUpload`, `CompleteUpload` (written ahead for 1.17/1.18) | `body:` |
| `UploadPart` (written ahead) | the caller's `part:` |
| `GetServerInfo`, `GetGrantEpoch`, `SetGrantEpoch` | Never signed |

- A unit test walks every generated procedure.
- `SetRepoVisibility` has no client yet. Record it for WP-2.13/2.14.

### B.2 Read identities

- Build a **fresh `RetryIdentity` per attempt, inside the retry closure**, for reads.
- Never add a "generate if missing" fallback inside `EnvelopeTransport`, because it could silently mint a new nonce for
  a write.
- Invert the test `read_only_procedures_are_never_signed` to match the new behavior.

### B.3 Grant selection

Grants are chosen in `client.rs` and set via `CallOptions`, never inside the signed string.

**Attach a grant only when all of these hold:**
- a signer exists;
- the signer is not the `ed25519-` namespace owner;
- the RPC is not on the part path, and is not `GetServerInfo`, a grant-epoch RPC, or `SetRepoVisibility`.

**Filters**, all computed locally:
- The namespace matches, and the repository scope is `== X-Repository` or `ns/*`.
- The remote origin is in `audiences`.
- `grantee` is the signer's key.
- `created ≤ now + 30 s` and `now < expiry`.
- Capability: `write` for writes, `read` for private reads.
- For writes, a ref scope matches the head ref, with packmap refs covered through their branch.
- The required flag follows from the write condition:

  | Condition | Required flag |
  |---|---|
  | Missing | `c` |
  | Match | `u` or `f` |
  | Any | `f` |
  | Delete | `d` |

**Ranking** (P-18): the most specific scope first, then the latest expiry.

**Reads:** prefer `read,write`, then `read`, then `write`. Epoch is not used.

### B.4 API

- A dependency-free `GrantSource` trait in `mkit-transport-connect` (`ConnectTransport::with_grant_source`).
- The selection logic lives in `mkit-cli`, in a new `remote_dispatch/grants.rs`.
- `mkit-cli` depends on `mkit-attest` with `features = ["grants"]`. This triggers the `sec` gate; run it.

### B.5 No interim config

- Ship no config path and no environment variable. The CLI passes no grant source until WP-2.13.
- The breakdown's e2e cases (a private clone with a read grant) move to WP-2.13 or WP-2.15. Record this in R-129.

### B.6 Compatibility

Signed reads are harmless to every existing server: their auth v2 read handlers ignore auth headers. Record these
follow-ups in R-129:
- **WP-2.9** must special-case `DownloadPack`, which is classed as streaming and whose verification path assumes a
  `pack:` commitment.
- **WP-2.9** must add `x-write-grant` to `CORS_ALLOW_HEADERS`.
- Keystore and hardware signers are asked for a signature on **every read**. This is accepted. WP-2.13 documents it
  and may cache the prompt.

### B.7 Plan

Add row **R-129**:

> WP-2.10.
> - Four reads are signed per attempt; `GetServerInfo` and the grant-epoch RPCs never are.
> - Grant selection is an API, and the store comes with 2.13.
> - WP-2.9 carries the `DownloadPack` and CORS follow-ups.
> - The signature prompt on every read is accepted.
> - `SetRepoVisibility` has no client until 2.13/2.14.
> - The 00-plan dependency "2.4" means 2.4b.

Also update STC §7.3 prose to say the client signs reads.

## C. Your decisions

- The shape of the `GrantSource` trait.
- The module layout.

## D. Escalate (stop and report) if

- Signing `DownloadPack` over its exact framed body isn't possible through connectrpc without buffering the response.
- Any B item contradicts SPEC-WRITE-GRANTS.

## Tests (required)

1. The classification table walks every generated procedure.
2. Each read, with and without a signer:
   - with a signer, it is signed, and `write_auth::verify_headers` verifies it over the exact body, including
     DownloadPack's framing;
   - without one, it is unsigned.
3. The grant-epoch paths are never signed and carry no `X-Repository`.
4. Each read retry gets a fresh, valid nonce. Writes keep their existing same-nonce behavior.
5. The grant header:
   - is never sent with the owner key, without a signer, or on the part path;
   - follows the full selection matrix;
   - is not part of the canonical string.
6. New golden `rust/tests/golden/auth-v2/read.json` (a ReadRef and a framed DownloadPack), with its MANIFEST line.
7. `mkit-server-native/tests/client_e2e.rs` still clones with envelope config against the current server.

## Gates

- `cargo nextest run --locked -p mkit-transport-connect -p mkit-cli -p mkit-core -p mkit-server-native --all-features`
- `just ci`
- `just ci-security`
- wasm32 clippy (pure-Rust configuration)
