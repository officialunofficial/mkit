## Purpose

This WP adds the four M2 RPCs to `mkit.transport.v1`, additively, along with their messages, regenerated code and
`unimplemented` stubs. It lets the M2 server WPs (2.8 epochs, 2.9 visibility, 2.11 URL tokens) and the client WPs
build on fixed wire shapes.

## A. Fixed (do not change)

1. **The RPC names are fixed by STC §2** and are load-bearing, because auth v2 signs the full procedure:
   `GetGrantEpoch`, `SetGrantEpoch`, `SetRepoVisibility`, `IssueObjectUrl`.
2. **The semantics come from SPEC-WRITE-GRANTS:**
   - **§5.3 grant epochs.** `GetGrantEpoch` is unauthenticated and returns 0 when nothing is stored. `SetGrantEpoch`
     takes one §4.2-encoded statement of at most 8,192 bytes, with no auth v2 and no replay.
   - **§9.1 visibility.** It works in two modes, and a grant **never** authorizes it.
   - **§9.4 URL tokens.** The target is an object id or a ref+path, and the path is 0–1024 bytes, where empty means
     the root tree.
3. **STC §7.4:** the repository comes only from `X-Repository`. Namespace RPCs carry none.
4. **The ssh proto `mkit.rpc.v1.ssh` is frozen.** Don't touch it.
5. **The proto rules:** additive only, and never change a label or oneof membership (R-79).

## B. Decided (do not change)

### B1. Proto

Append the RPCs to the service block after `CompleteUpload`, in this order. Add a new section,
`// Grants, visibility and URL tokens (SPEC-WRITE-GRANTS).`, after `CompleteUploadResponse` and before the Errors
separator.

```proto
rpc GetGrantEpoch(GetGrantEpochRequest) returns (GetGrantEpochResponse);
rpc SetGrantEpoch(SetGrantEpochRequest) returns (SetGrantEpochResponse);
rpc SetRepoVisibility(SetRepoVisibilityRequest) returns (SetRepoVisibilityResponse);
rpc IssueObjectUrl(IssueObjectUrlRequest) returns (IssueObjectUrlResponse);

message GetGrantEpochRequest  { string namespace = 1; }          // no X-Repository
message GetGrantEpochResponse { uint64 epoch = 1; }              // 0 when none stored
message SetGrantEpochRequest  { string signed_statement = 1; }   // §4.2 encoding, ≤ 8192 bytes
message SetGrantEpochResponse { uint64 epoch = 1; }              // stored epoch after completion
enum RepoVisibility { REPO_VISIBILITY_UNSPECIFIED = 0; REPO_VISIBILITY_PUBLIC = 1; REPO_VISIBILITY_PRIVATE = 2; }
message SetRepoVisibilityRequest {                               // repository from X-Repository
  oneof mode {
    RepoVisibility visibility = 1;     // auth v2 body: owner key or authority; UNSPECIFIED → invalid_argument
    string signed_statement = 2;       // mkit-repo-visibility:v1 in §4.2 encoding; no auth v2
  }
}
message SetRepoVisibilityResponse {}
message IssueObjectUrlRequest {                                  // signed read; repository from X-Repository
  oneof target {
    bytes object_id = 1;               // 32-byte id → object:<hex>
    RefPath ref_path = 2;              // → path:<ref>:<b64url(path)>
  }
  uint32 ttl_seconds = 3;              // 0 = default; clamped to url_token_ttl
}
message RefPath { string ref = 1; string path = 2; }             // full ref; UTF-8 path 0..1024; "" = root tree
message IssueObjectUrlResponse { string token = 1; int64 expires_unix_ms = 2; }
```

Write spec-citing comments in the proto.

### B2. Where the spec wins over the breakdown

Record each of these in the PR body:
- `SetGrantEpoch` takes **one** statement field.
- **No** repository field appears in any request.
- A grant never sets visibility.

### B3. Retry-after

- A pending `SetGrantEpoch` or `SetRepoVisibility` answers `unavailable` with a **`Retry-After` response header**. Add
  no proto detail.
- Add one sentence to STC stating this.
- Record it for WP-2.8 and WP-2.9.

### B4. Stubs

- All four RPCs return `ServerError::unimplemented("not implemented yet")`.
- Add **no** `Procedure` variants, and don't change the interceptor.
- Put a `// SECURITY: … the implementing WP MUST add it` comment and a `TODO` on each stub:
  - `GetGrantEpoch` and `SetGrantEpoch` → 2.8;
  - `SetRepoVisibility` → 2.9;
  - `IssueObjectUrl` → 2.11.
- Record that `GetGrantEpoch` and `SetGrantEpoch` must never verify auth-v2 headers. WP-2.8 keeps them outside the
  auth-v2 `Procedure` path, the way `GetServerInfo` is handled.
- Extend the INVARIANTS entry "M1 Connect surfaces remain explicit stubs" to cover the M2 stubs.

### B5. Also fix

`service.rs:~500` uses the scheme token `eip191-secp256k1`. The correct token is `secp256k1-eip191`.

### B6. Plan

Add an R-row **R-125**:

> WP-2.2 message shapes:
> - one `signed_statement` field;
> - no repository fields;
> - a `RepoVisibility` enum;
> - a `RefPath` oneof;
> - `Retry-After` for pending epoch and visibility updates;
> - `grant_schemes` population is WP-2.6's.

Also append the S2-brief correction ("a grant never sets visibility").

## C. Your decisions

- The exact comment text in the proto.
- Test organisation.

## D. Escalate (stop and report) if

- `buf breaking` fails.
- Any B1 shape contradicts SPEC-WRITE-GRANTS in a way a citation can't reconcile.

## Tests (required)

1. A codegen round trip of every new message with non-default values, covering both oneof arms and every enum value.
2. `m2_stub_paths_are_not_authenticated_procedures_yet`: `from_connect_path` returns `None` for all four paths.
3. Over the wire, with the binary and JSON codecs, no auth headers, and both the Bearer and AuthV2 modes: each RPC
   answers `unimplemented` "not implemented yet", and nothing is written (use the Spy store).
4. The existing mkit-server, transport-connect, CLI and conformance suites pass unchanged, with zero baseline
   divergences. Six implementors of `TransportService` need stubs.

## Gates

- `buf lint`, and `buf breaking --against '.git#branch=origin/feat/mkit-server'`
- `bash scripts/check-generated-fresh.sh`
- `just ci-server`
- `cargo nextest run --locked -p mkit-server -p mkit-transport-connect -p mkit-cli -p mkit-server-native -p mkit-server-conformance --all-features`
- the wasm32 build of `mkit-server-worker`
