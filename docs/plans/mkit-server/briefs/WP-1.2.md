## Purpose

M1 needs new wire messages for deployment discovery (`GetServerInfo`), ticketed and resumable uploads (`BeginUpload`,
`UploadPart`, `CompleteUpload`, ticket tokens), ref deletion, and `ListRefs` paging. This WP adds them to the proto,
**additively**, and regenerates the vendored code. The server answers every new RPC and new field with a well-defined
"not yet implemented" until the WP that implements it lands. **No behaviour changes for any existing request.**

## A. Fixed by the plan and specs (do not change)

1. **Normative source:** `docs/specs/SPEC-TRANSPORT-CONNECT.md` v2:
   - §2 (the RPC table) and §2.1 (the `GetServerInfo` fields);
   - §7.4: the repository comes from the `X-Repository` header, never from a message field;
   - §7.6: `BeginUpload`, tickets, `UploadPart`, `CompleteUpload`, ticketed `UploadPack`, `AdvanceRefs.ticket_ids`;
   - §7.8: the `delete` field;
   - §7.9: `page_size`, `page_token` and `next_page_token`.
2. **Additive only (plan R-79):** new messages, new fields and new RPCs only.
   - Never change an existing field's number, type, label (singular/`repeated`/`optional`) or oneof membership.
   - Never reuse or renumber a field.
   - `buf breaking` (FILE) does not catch every such edit, so the reviewer diffs the proto by hand.
3. **File:** `proto/mkit/transport/v1/transport.proto` (`edition = "2023"`, `package mkit.transport.v1`). No new proto
   files.
4. **Vendored codegen:** refresh both vendored dirs with `scripts/regen-transport-proto.sh`
   (`rust/crates/mkit-transport-connect/generated`, and `rust/crates/mkit-server/generated`, which is built for
   wasm32). `scripts/check-generated-fresh.sh` must pass. The other generated dirs (repo-worker, mkit-rpc, web) are a
   different proto; don't touch them.
5. **Out of scope:**
   - no server behaviour beyond the stubs in B.3;
   - no client behaviour (`mkit-transport-connect` compiles against the new code and ignores the new RPCs and fields);
   - no auth-v2 canonical-string changes (the `part:` commitment already exists in mkit-core from WP-1.3);
   - no `PendingVerification` detail (M4), and no M2/M3 RPCs.

## B. Decided by the orchestrator (do not change)

1. **Exact proto additions.** Keep every existing comment, and add doc comments to new items that cite the spec
   section.
   ```proto
   // --- service additions (append after DownloadPack, in this order) ---
   rpc GetServerInfo(GetServerInfoRequest) returns (GetServerInfoResponse);
   rpc BeginUpload(BeginUploadRequest) returns (BeginUploadResponse);
   rpc UploadPart(stream UploadPartRequest) returns (UploadPartResponse);
   rpc CompleteUpload(CompleteUploadRequest) returns (CompleteUploadResponse);

   // --- existing messages: new fields only ---
   message ListRefsRequest    { /* existing 1 */ uint32 page_size = 2; string page_token = 3; }
   message ListRefsResponse   { /* existing 1 */ string next_page_token = 2; }
   message UpdateRefRequest   { /* existing 1-4 */ bool delete = 5; }
   message AdvanceRefsRequest { /* existing 1-8 */ repeated bytes ticket_ids = 9; bool delete = 10; }
   message UploadPackHeader   { /* existing 1-2 */ bytes ticket_token = 3; }

   // --- new messages ---
   message GetServerInfoRequest {}
   message GetServerInfoResponse {
     string protocol = 1;                      // "mkit.transport.v1"
     uint32 spec_version = 2;                  // 2
     uint64 max_pack_bytes = 3;
     uint64 part_size = 4;                     // power of two, >= 8 MiB
     uint32 max_parts = 5;
     uint32 max_list_refs_page_size = 6;
     uint64 begin_upload_threshold_bytes = 7;
     bool atomic_advance = 8;
     bool indexed_mode = 9;
     bool admission = 10;
     bytes receipt_public_key = 11;            // empty until storage receipts (M5)
     string receipt_key_id = 12;               // empty until storage receipts (M5)
     repeated string grant_schemes = 13;       // empty until M2
     string namespace_policy = 14;             // "allowlist" | "any" | "single-repository" (§7.5)
     uint32 index_fanout = 15;                 // default 4096 (§7.9)
   }

   message BeginUploadRequest {                // the repository comes from X-Repository (§7.4)
     string ref = 1;                           // the ref this upload will advance (§7.6)
     bytes pack_id = 2;                        // 32-byte BLAKE3
     uint64 bytes = 3;                         // total pack length
   }
   message BeginUploadResponse {
     oneof result {
       AlreadyPresent already_present = 1;
       UploadTicket ticket = 2;
     }
   }
   message AlreadyPresent {}
   message UploadTicket {
     bytes id = 1;                             // 32 bytes; its hex form is the <ticket> in part: commitments
     uint64 part_size = 2;
     int64 expires_unix_ms = 3;                // same time unit as auth-v2 timestamps
     bytes token = 4;                          // opaque, server-authenticated (§7.6 "Ticket token")
   }

   message UploadPartHeader {
     bytes ticket_token = 1;
     uint32 index = 2;                         // zero-based part index
   }
   message UploadPartRequest {
     oneof msg {
       UploadPartHeader header = 1;            // first message only
       bytes chunk = 2;                        // following messages: the part's bytes, in order
     }
   }
   message UploadPartResponse {
     bytes receipt = 1;                        // opaque, server-authenticated part receipt (§7.6)
   }

   message CompleteUploadRequest {
     bytes ticket_token = 1;
     repeated bytes receipts = 2;              // in part-index order
   }
   message CompleteUploadResponse {}
   ```
   The names, numbers and types are final. Field names use snake_case, as already in the file.
2. **Placement:** new messages go in new sections with the file's existing section-comment style: `// Discovery.`
   (GetServerInfo) and `// Uploads (tickets and parts).`, after the existing `// Packs.` section.
3. **Server stubs**, in `rust/crates/mkit-server/src/connect/service.rs` (the only server change). There must be no
   silent behaviour change: every new surface is explicit.
   - `GetServerInfo`, `BeginUpload`, `UploadPart`, `CompleteUpload`: return `ServerError` code `unimplemented` with the
     public message "not implemented yet". `UploadPart` must not read the request stream beyond what connectrpc
     requires.
   - `UpdateRef` with `delete = true`, and `AdvanceRefs` with `delete = true` or non-empty `ticket_ids`: return
     `unimplemented` before any other validation or pipeline call.
   - `UploadPack` whose header has a non-empty `ticket_token`: return `unimplemented` before reading chunks.
   - `ListRefs` with a non-empty `page_token`: return `unimplemented`. `page_size` is ignored for now (the full listing
     is returned, as today), with a `// TODO(WP-1.28): honour page_size and caps` comment.
     `next_page_token` is always empty.
   - Each stub branch carries a `// TODO(WP-x.y)` naming its implementing WP:

     | Surface | Implementing WP |
     |---|---|
     | `GetServerInfo` | 1.6 |
     | `BeginUpload`, ticketed `UploadPack` | 1.9 |
     | `UploadPart`, `CompleteUpload` | 1.11 |
     | `ticket_ids`, `delete` | 1.10 |
     | paging | 1.28 |
   - **Auth for the new RPCs: do NOT change the interceptor, and do NOT add `mkit_server::op::Procedure` variants.**
     Today `AuthInterceptor` authenticates only paths that `Procedure::from_connect_path` recognises; any other path
     (Health, and the four new RPCs) passes through unauthenticated. That is acceptable only because every new RPC is
     a stub. Add a comment at each of the four stub handlers:
     `// SECURITY: unauthenticated until WP-x.y adds a Procedure variant; the implementing WP MUST add it.`
     (`GetServerInfo` stays unauthenticated by spec §2.1; its comment says so.) Add one test asserting that the four new
     paths are NOT recognised by `Procedure::from_connect_path` today. The implementing WPs flip that test when they add
     authentication.
4. **The client** (`mkit-transport-connect`): compile only. Don't call the new RPCs, and don't set the new fields.
5. **Workers:** `apps/vcs-worker` has no vendored transport code of its own since M0-17. It routes through
   `mkit-server-worker`, so the stubs cover it automatically. Verify the vcs-worker still builds for wasm32
   (`cargo build --target wasm32-unknown-unknown` in `apps/vcs-worker`), and refresh `apps/vcs-worker/Cargo.lock` with
   `cargo metadata --offline` only if it goes stale.

## C. Your decisions (record each in the PR under "Executor decisions")

- The wording of the doc comments on new proto items (they must cite the spec sections).
- How the stub helper is factored in `service.rs`, e.g. one `fn not_yet(wp: &str) -> ServerError`.
- Test organisation.

## Tests (required)

1. **Codegen round trip:** encode and decode each new message with non-default values (unit tests, in
   mkit-transport-connect or mkit-server).
2. **Stub behaviour over the wire:** extend mkit-server's connect dispatch tests (e.g. `connect_dispatch` / the
   existing connect test file).
   - Each new RPC gives `unimplemented`.
   - `GetServerInfo` without any auth headers reaches the stub.
   - `UpdateRef{delete}`, `AdvanceRefs{delete}` and `AdvanceRefs{ticket_ids}` give `unimplemented`, with no store write.
   - `UploadPack{ticket_token}` gives `unimplemented`.
   - `ListRefs{page_token}` gives `unimplemented`, and `ListRefs{page_size: 1}` returns the full listing unchanged.
3. **Unchanged behaviour:**
   - the existing mkit-server, mkit-transport-connect and mkit-server-conformance test suites pass unchanged;
   - the M0-07 wire suite baselines pass with zero divergences (`cargo nextest run -p mkit-server-conformance
     --all-features` and `-p mkit-server-native --all-features`).

## D. Escalate (stop and report, do not improvise) if

- connectrpc's codegen can't express one of the B.1 shapes as written, e.g. a `bytes` oneof member in a
  client-streaming request.
- `buf lint` or `buf breaking` rejects B.1 and the fix would change a name, number or type.
- Any new RPC reaches a handler that does anything other than return the stub error (e.g. connectrpc routing
  surprises).

## Gate additions

- From the repo root: `buf lint`, and `buf breaking --against '.git#branch=origin/feat/mkit-server'` (FILE).
- `bash scripts/check-generated-fresh.sh`
- the wasm32 build of `apps/vcs-worker`
- `just ci-server`
