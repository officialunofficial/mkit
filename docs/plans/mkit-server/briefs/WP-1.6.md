## Purpose

A client needs to learn, before relying on it, what a deployment supports: limits, atomic advance, admission, the
namespace policy, and the upload threshold. The RPC and message exist since WP-1.2 as a stub that returns
`unimplemented` (`connect/service.rs:353-361`). This WP implements it in core, answers it unauthenticated on both
adapters, and adds wire conformance.

## A. Fixed by the plan and specs (do not change)

1. **STC §2.1 (read it all):**
   - the request is empty and MAY carry `X-Repository`;
   - **the response MUST NOT depend on whether that repository exists**;
   - the call is **unauthenticated**: no auth v2 headers and no bearer token needed;
   - it MAY be cached with `Cache-Control: private, max-age=<n>`, where n ≤ 60;
   - the field table, including `begin_upload_threshold_bytes = 0` on every multi-repository deployment and whenever
     `admission` is true.
2. **Plan:** `m1-m2-breakdown.md` "WP-1.6". `atomic_advance` comes from `Pipeline::capabilities()`. `indexed_mode` is
   false until M4. The receipt key and `grant_schemes` are empty.
3. **Proto** (`GetServerInfoResponse`, fields 1–15, plus 16 if WP-4.4 has merged): no proto changes in this WP.
4. **Existing helpers:**
   - `PipelineConfig::advertised_namespace_policy()` and `Admission::is_default()` (WP-1.5);
   - `store::INDEX_FANOUT` (4096);
   - `mkit_core::upload_parts::MIN_PART_SIZE` (8 MiB);
   - `UploadLimits::max_total_bytes`.

## B. Decided by the orchestrator (do not change)

### B.1 Config additions to `PipelineConfig` (defaults in parentheses; validated in `Pipeline::new`)

- `part_size: u64` (`MIN_PART_SIZE` = 8 MiB). It must be a power of two, `≥ MIN_PART_SIZE` and `≤ 32 MiB`.
- `max_parts: u32` (`10_000`). It must be ≥ 1, and `part_size × max_parts ≥ upload_limits.max_total_bytes`.
  Otherwise refuse ("max_pack_bytes is unreachable with part_size × max_parts").
- `max_list_refs_page_size: u32` (`1000`). It must be in `1..=10_000`.
  - Document: 1000 refs of at most 512-byte names fit STC §7.9's 2 MiB page bound.
  - Paging itself is WP-1.28, so leave `// TODO(WP-1.28): honour page_size up to this bound`.
- `begin_upload_threshold_bytes: u64` (`u64::MAX`, meaning "never required"). Only single-repository deployments
  without admission advertise it. In every other case the advertised value is 0 (B.2).

### B.2 `pub fn server_info(&self) -> ServerInfo` on `Pipeline`

It's a pure function of config and hooks, with no store access, and returns a `#[non_exhaustive]` struct mirroring
the response.

| Field | Value |
|---|---|
| `protocol` | `"mkit.transport.v1"` |
| `spec_version` | `2` |
| `max_pack_bytes` | `upload_limits.max_total_bytes` |
| `part_size`, `max_parts`, `max_list_refs_page_size` | from B.1 |
| `begin_upload_threshold_bytes` | `0` if `Addressing::Multi` or `admission`; else the configured value |
| `atomic_advance` | `self.capabilities().atomic_advance` |
| `indexed_mode` | `false` |
| `admission` | `!self.hooks.admission().is_default()` |
| `receipt_public_key`, `receipt_key_id`, `grant_schemes` | empty |
| `namespace_policy` | `self.cfg.advertised_namespace_policy()` |
| `index_fanout` | `INDEX_FANOUT` |
| `max_delta_chain_depth` | `0`, only if field 16 exists at your base (WP-4.4 merged); otherwise skip |

### B.3 The handler (`connect/service.rs` `get_server_info`)

- Returns `server_info()` mapped to the proto.
- **Ignores `X-Repository` completely:** no resolution, no validation, no store access. So a malformed or unknown
  identity gets the same answer.
- Sets the response header `Cache-Control: private, max-age=60`.
- Remove the stub's `TODO(WP-1.6)`.
- **No `Procedure` variant.** GetServerInfo stays outside `Procedure`, so the interceptor and stage-0 repository
  resolution never apply to it. Replace the stub's SECURITY comment with one explaining that it is deliberately
  unauthenticated and never resolves a repository (STC §2.1).
- Update the test `m1_stub_paths_are_not_authenticated_procedures_yet`: GetServerInfo is **permanently**
  unrecognised by `Procedure::from_connect_path`, and the other three M1 paths are still pending (WPs 1.9 and 1.11).

### B.4 Adapters

- **Native `BearerGate`** (`mkit-server-native/src/guard.rs:~168`, `guarded()`): exempt exactly the path
  `/mkit.transport.v1.TransportService/GetServerInfo`, alongside health.
  - It still takes a concurrency permit, like any request.
  - Test: a bearer deployment answers GetServerInfo without a token, and still refuses other RPCs without one.
- **Worker:** no change is expected: the Worker serves the same Connect service. Verify it through the wire case
  (B.5).
- **ssh and enc:** there is no GetServerInfo on those transports. Nothing to do.

### B.5 Conformance

1. New wire case `info.shape_and_policy`, unconditional (every profile), M1. Call with **no auth headers at all**,
   then assert:
   - `protocol` and `spec_version`;
   - `part_size` is a power of two, ≥ 8 MiB;
   - `max_parts ≥ 1`, and `max_pack_bytes ≤ part_size × max_parts`;
   - `max_list_refs_page_size` is in 1..=10,000;
   - `index_fanout == 4096`;
   - `atomic_advance` matches the profile's `atomic-advance` feature;
   - `namespace_policy` is `"single-repository"` unless the profile declares `multi-repo`, and `"allowlist"` or
     `"any"` otherwise;
   - `begin_upload_threshold_bytes == 0` when `multi-repo` is declared;
   - `receipt_public_key`, `receipt_key_id` and `grant_schemes` are empty;
   - the `Cache-Control` header is present with `max-age ≤ 60`.
2. Case `info.ignores_repository_header`: the same response bytes (excluding headers) with no `X-Repository`, a
   well-formed but nonexistent identity, and a malformed one.
3. On bearer profiles, the case must pass without a token.
4. Runners: the in-process baselines (Single and Multi), the native binary (single, and d34 if it runs), and
   `scripts/vcs-worker-conformance.sh` (default phase).

### B.6 Docs

- CHANGELOG entry.
- `INVARIANTS.md`: "GetServerInfo is unauthenticated, never resolves a repository and never reads the store".
- Remove WP-1.6 from any "not yet" lists you touch (e.g. `profile.rs`'s comment that features "will come from
  GetServerInfo (WP-1.6)": change it to say the runner still derives features from the profile, and that switching
  to server-reported features is a follow-up). Don't implement that switch.

## C. Your decisions

- How `ServerInfo` maps to the proto (a `From` impl, etc.).
- How the Connect handler sets the response header in connectrpc 0.9.
- Test organisation.

## D. Escalate (stop and report) if

- connectrpc 0.9 can't set a response header on a unary success. In that case, propose dropping `Cache-Control`,
  since it's a MAY.
- The Worker adapter blocks unauthenticated GetServerInfo somewhere, e.g. a Worker-side auth gate.

## Gates

- `just ci-server`
- `cargo nextest run --locked -p mkit-server -p mkit-server-native -p mkit-server-conformance -p mkit-server-worker --all-features`
- the wasm32 check of `mkit-server`; the build of `mkit-server-worker`
- `scripts/vcs-worker-conformance.sh` (default phase), if wrangler is available
- goldens unchanged
