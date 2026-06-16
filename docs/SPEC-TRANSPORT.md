---
spec: SPEC-TRANSPORT
version: 1
status: draft
audience: implementers of compatible transport clients and servers
---

# SPEC-TRANSPORT — mkit v1 transport protocols

mkit talks to remote stores through a small set of pluggable
transports (memory, file, HTTP, S3, SSH). All implement the same
[`Transport`](../rust/crates/mkit-core/src/protocol.rs) trait —
seven verbs over a synchronous, object-safe interface — but the wire
shape and authentication model differ per scheme.

There is no negotiation between transports and no scheme fallback.
The URL scheme is part of the remote address; if the scheme is
unsupported, the dispatcher returns an error rather than guessing
([`mkit-cli`'s `remote_dispatch::open`](../rust/crates/mkit-cli/src/remote_dispatch.rs)
performs the scheme switch).

The SSH wire format is defined in
[`SPEC-RPC`](SPEC-RPC.md) and lives in the generated
[`ssh.proto`](../rust/crates/mkit-rpc/proto/ssh.proto) bindings.
This document covers the cross-transport contract: verbs, URL
parsing, authentication, the forced-command server pattern, size
caps, retry policy, and the error taxonomy.

---

## 1. Verbs

Every transport implements the same seven verbs exposed by the
[`Transport`](../rust/crates/mkit-core/src/protocol.rs) trait. Method
signatures are synchronous and take `&self`; transports that need
interior mutability (connection pools, child-process stdio) use an
internal `Mutex` so the trait object remains object-safe.

| Verb | Purpose |
|---|---|
| `upload_pack(bytes, key)` | Store a packfile keyed by its 32-byte BLAKE3 digest (`PackKey`). |
| `download_pack(key)` | Fetch a packfile by digest. |
| `pack_exists(key)` | HEAD-check a pack by digest. |
| `update_ref(name, condition, hash)` | CAS ref write. |
| `read_ref(name)` | Read a ref's current hash, or `None` if absent. |
| `list_refs(prefix)` | List refs whose full name starts with `prefix`. Returned names have `prefix` stripped per SPEC-REFS §4. |
| `write_ref(name, hash)` | Convenience: `update_ref(name, RefWriteCondition::Any, hash)`. A default trait impl delegates here, so transports only need to implement `update_ref`. |

`update_ref`'s condition is one of:

- `Any` — clobber the ref unconditionally.
- `Missing` — write only if the ref is absent.
- `Match(expected)` — write only if the ref currently contains `expected`.

CAS failure (`Missing` on an existing ref, or `Match` on a mismatched
hash) returns `TransportError::RefConflict`. Per §6, callers retrying
after a network timeout MUST follow up with `read_ref` to disambiguate
whether the first attempt landed before treating `RefConflict` as a
true conflict.

---

## 2. Error taxonomy

Implementations MAY wrap transport-specific errors internally but
MUST surface one of the following variants at the trait boundary
([`TransportError`](../rust/crates/mkit-core/src/protocol.rs)):

```rust
TransportError::PackNotFound        // download_pack on missing digest
TransportError::AccessDenied        // HTTP 401/403, SSH auth refusal, S3 SignatureDoesNotMatch
TransportError::RemoteError(msg)    // catch-all remote failure; message is advisory only
TransportError::RefConflict         // update_ref CAS precondition failed
TransportError::InvalidRef(name)    // ref name failed SPEC-REFS §3, or URL parse failed
TransportError::ConnectionFailed    // DNS / TCP / TLS / SSH spawn / mutex poisoning
TransportError::ServerError{status} // unexpected status code (transports without a status integer use 0)
TransportError::InvalidResponse     // truncated frame, unknown opcode, bad JSON, mismatched server-returned digest
TransportError::ProtocolError       // malformed frame, failed handshake
TransportError::PayloadTooLarge(n)  // payload exceeded a transport-specific cap (see §4.4, §5.4)
TransportError::InsecureScheme      // plain http:// supplied for a non-loopback host
```

Programs MUST NOT pattern-match on the advisory message strings.

---

## 3. URL schemes

| Scheme prefix | Transport | Notes |
|---|---|---|
| `mkit+memory://…` | In-memory (`MemoryTransport`) | Test / fuzz only. Cannot be opened by `remote_dispatch::open` — the URL is accepted by `mkit remote add` for round-tripping, but actual construction happens in-process. |
| `mkit+file:///abs/path` | Filesystem (`FileTransport`) | Triple slash; everything after `mkit+file://` is taken as the on-disk root path. |
| `mkit+https://host/project` | HTTPS REST + JSON (`HttpTransport`) | The `mkit+` prefix is stripped before the inner `reqwest` call; production uses `https://`. |
| `mkit+http://localhost…` | Plain HTTP for local dev | Plain `http://` is restricted to loopback hosts (`127.0.0.1`, `::1`, `localhost`) per `validate_http_scheme`; any other host returns `InsecureScheme`. |
| `mkit+s3://endpoint/bucket[/prefix]` | S3-compatible (`S3Transport`) | The endpoint becomes `https://<endpoint>`; R2 is the primary target, AWS S3 also works but its CAS semantics are weaker (see §6.3). |
| `mkit+ssh://user@host[:port]/path` | SSH child + `mkit serve` (`SshTransport`) | The `user@` prefix is REQUIRED. Path is restricted to `[A-Za-z0-9._-/]` with no empty / `.` / `..` segments. SCP-style `mkit+ssh://user@host:path` / `mkit+ssh://user@host:port:path` are also accepted (see [`mkit-transport-ssh/src/url.rs`](../rust/crates/mkit-transport-ssh/src/url.rs)). |
| `mkit+enc://[user@]host[:port]/path?pubkey=<…>` | Encrypted-stream (`EncTransport`) | Self-contained ChaCha20-Poly1305 + ed25519 transport — does not shell out to `ssh(1)`. The server's static public key MUST be carried out-of-band in the URL. URL parsing + CLI plumbing land in Phase 2; see [SPEC-TRANSPORT-ENC](SPEC-TRANSPORT-ENC.md). |

Bare `ssh://`, `https://`, `http://`, `s3://`, `file://` URLs (without
the `mkit+` prefix) are deliberately rejected. The prefix marks a URL
as something mkit recognises; we do not silently extend the namespace
of any sibling tool.

---

## 4. SSH transport

mkit's SSH transport spawns a long-lived `ssh(1)` child process and
exchanges length-prefixed [`SshFrame`](../rust/crates/mkit-rpc/proto/ssh.proto)
messages on its stdin/stdout. The framing layer is defined in
[SPEC-RPC §1](SPEC-RPC.md#1-wire-framing).

The transport is implemented with `std::process::Command` — mkit does
NOT ship its own SSH stack (no `russh`, no in-process crypto). See
[`SSH-SECURITY.md`](SSH-SECURITY.md) for the trade-offs that choice
implies.

### 4.1 Forced-command server pattern

Server-side, the user configures their `~/.ssh/authorized_keys` to
force `mkit serve <repo-path>` on connection:

```
command="mkit serve /srv/mkit/myrepo",no-port-forwarding,no-X11-forwarding,no-agent-forwarding ecdsa-sha2-nistp256 AAAA…
```

This binds an SSH key to a single repository on the server side. The
server process never sees a shell prompt; sshd hands it an open
stdin/stdout pair against the `authorized_keys`-resolved command.

The client spawns `ssh` with `mkit serve <path>` as three separate
argv tokens so sshd invokes the binary directly without an
intervening `sh -c` (which broke the handshake on some sshd
configurations). The path is already restricted to a safe ASCII
subset by `validate_ssh_path`, so passing it as a separate token is
sound.

### 4.2 Conversation

```
client → server:    Hello { proto = PROTOCOL_VERSION_1, client_id }
server → client:    HelloResponse { proto, server_id }
                      OR
                    Error

client → server:    one of: ListRefs, ReadRef, UpdateRef,
                            PackExists, UploadPack (+ PackChunks),
                            DownloadPack, Close
server → client:    matching *Response, OR Error
```

`Close` is advisory — either side MAY drop the underlying stream
without a `Close` frame and the peer detects EOF. The client always
emits a best-effort `Close` from its `Drop` impl.

Pack uploads stream as `UploadPack { pack_id, total_bytes }` followed
by one or more `PackChunk { pack_id, offset, data, last }` frames.
The client caps each chunk's `data` segment at 800 KiB so the framing
layer's 1 MiB `MAX_FRAME_BYTES` cap accommodates the protobuf
overhead. Empty packs still emit a single `last=true` chunk so the
server sees an unambiguous end-of-stream. The server emits
`UploadPackResponse{}` once `last=true` is observed and the bytes
verify against the announced digest.

The server MUST reject malformed upload streams before storing bytes:
`total_bytes` is required and MUST be within the server upload cap;
every `PackChunk.pack_id` MUST match the `UploadPack.pack_id`; every
`PackChunk.offset` MUST equal the next expected byte offset; the stream
MUST end exactly at `total_bytes`; and `BLAKE3(received_bytes)` MUST
equal `UploadPack.pack_id`. A rejected upload MUST NOT create or
overwrite the destination pack.

Pack downloads: client sends `DownloadPack { pack_id }`; server
replies with `DownloadPackHeader { total_bytes }` followed by a
sequence of `PackChunk`s ending in `last=true`. If the pack is
absent the server replies with `Error { code = ERROR_CODE_KEY_NOT_FOUND }`
before any header is emitted.

#### 4.2.1 `UpdateRef` CAS encoding

CAS intent is carried entirely by the `RefExpectation` enum in
`UpdateRef.expectation`. `expected_id` carries the digest only when
`expectation = REF_EXPECTATION_MATCH`; it is ignored for `ANY` /
`MISSING`.

| `RefWriteCondition` | `expectation`             | `expected_id`       | Semantics |
|---|---|---|---|
| `Any`        | `REF_EXPECTATION_ANY`      | empty               | Last-writer-wins; current ref value is ignored. |
| `Missing`    | `REF_EXPECTATION_MISSING`  | empty               | Create-only; the ref MUST NOT exist on the server. |
| `Match(h)`   | `REF_EXPECTATION_MATCH`    | 32-byte digest `h`  | Current ref value MUST equal `h`. |

A conforming server MUST treat `REF_EXPECTATION_UNSPECIFIED` (the
zero value, sent when the client omits the field) as a protocol
error and reply with `ERROR_CODE_INVALID_REQUEST`. mkit is alpha
(pre-1.0) — clients and servers move together; there is no v0.x
back-compatibility surface to preserve.

On a CAS mismatch the server returns `Error { code =
ERROR_CODE_INVALID_REQUEST }` with the current ref value in
`Error.details`.

### 4.3 Trust model

SSH transport security is delegated to the user's `ssh(1)` CLI:

- Host-key verification → `ssh(1)`.
- Identity selection → `ssh-agent` / `~/.ssh/config`.
- Kex / cipher / auth → `ssh(1)` / sshd.

Three `.mkit/config` keys override `ssh(1)` defaults for the mkit SSH
child only (see [`SshOptions`](../rust/crates/mkit-transport-ssh/src/lib.rs)):

```
ssh.strict_host_key_checking = yes
ssh.user_known_hosts_file    = /path/to/project.known_hosts
ssh.identity_file            = /path/to/id_ed25519
```

These plumb to `-o StrictHostKeyChecking=…`, `-o UserKnownHostsFile=…`,
and `-i …` respectively.

When `ssh.strict_host_key_checking` is not set, the transport
implicitly passes `-o StrictHostKeyChecking=accept-new` so the first
connection is not an interactive prompt. `-o BatchMode=yes` is
always passed so a missing key never blocks on a password prompt.

See [`SSH-SECURITY.md`](SSH-SECURITY.md) for the full trust model.

### 4.4 Resource caps

The `mkit serve` server enforces per-connection budgets to bound a
misbehaving or malicious client (see
[`mkit-cli/src/commands/serve.rs`](../rust/crates/mkit-cli/src/commands/serve.rs)):

- `MAX_FRAMES_PER_CONN = 10_000` — hard cap on frames after `Hello`.
- `MAX_BYTES_PER_CONN  = 1 GiB`  — cap on cumulative request payload bytes.

Each cap trips emits an `Error{ ERROR_CODE_INVALID_REQUEST }` and
closes the connection with `exit::PROTOCOL_ERROR`.

Nested `UploadPack` chunk drains enforce the same 1 GiB byte ceiling on
the declared upload length and additionally cap the number of chunk
frames at `MAX_FRAMES_PER_CONN`, so a client cannot bypass the outer
frame loop by streaming unbounded chunks inside one upload request.

The framing layer's per-frame `MAX_FRAME_BYTES = 1 MiB` cap (per
[SPEC-RPC §1](SPEC-RPC.md#1-wire-framing)) bounds individual frames;
pack data flows through `PackChunk` streams to stay under that limit.

Client side, the SSH transport mirrors the HTTP transport's
`PACK_BODY_LIMIT = 4 GiB` cap on `download_pack`. A server-advertised
`DownloadPackHeader.total_bytes` greater than 4 GiB is rejected
before any allocation; if the announced size is honest but the
streamed chunks overshoot, the running total check terminates the
read mid-stream rather than letting the `Vec` grow without bound.
Both paths surface as `TransportError::RemoteError` with a message
mentioning the client cap.

---

## 5. HTTP transport

The HTTP transport ([`mkit-transport-http`](../rust/crates/mkit-transport-http/))
speaks a simple JSON REST dialect against an mkit VCS Worker
(Cloudflare Worker + R2 is the reference deployment).

### 5.1 Wire contract

| Method | Path | Body | Notes |
|---|---|---|---|
| `POST` | `/<project>/packs` | raw pack bytes | Response `{"key": "<64-hex>"}`. The client cross-checks the returned key against the digest it pre-computed; mismatch → `InvalidResponse`. |
| `GET`  | `/<project>/packs/<key>` | — | Response is raw pack bytes. |
| `HEAD` | `/<project>/packs/<key>` | — | 200 → exists, 404 → missing. |
| `GET`  | `/<project>/refs/<name>` | — | Response is `{"hash": "<64-hex>"}` or `404 Not Found` (mapped to `Ok(None)`). |
| `PUT`  | `/<project>/refs/<name>` | `{"hash": "<hex>"}` | `If-Match` / `If-None-Match` headers carry CAS. |
| `GET`  | `/<project>/refs?prefix=<p>` | — | Response is `{"refs":[{"name":..., "hash":...}]}`. The query parameter is always set, even when empty, so the server can distinguish "list everything" from a missing parameter. |

### 5.2 Authentication

Optional bearer token sourced from the `MKIT_API_TOKEN` environment
variable at `HttpTransport::connect` time. A missing variable is
fine — public read endpoints remain accessible. The token is read
once at construct time, not per-request.

### 5.3 CAS encoding

| `RefWriteCondition` | Header | Server response on conflict |
|---|---|---|
| `Any`        | (no conditional header) | — |
| `Missing`    | `If-None-Match: *` | `412 Precondition Failed` → `RefConflict` |
| `Match(h)`   | `If-Match: "<64-hex>"` (RFC 7232 quoted ETag) | `409` or `412` → `RefConflict` |

`409` and `412` are NOT retried (`is_retryable` rejects all 4xx),
so a CAS write never silently turns into a duplicate PUT.

### 5.4 Limits and timeouts

- `DEFAULT_TIMEOUT = 300 s` per request.
- `PACK_BODY_LIMIT = 4 GiB` for `download_pack` responses. A
  `Content-Length` greater than the cap is rejected before any body
  is read; a missing `Content-Length` is bounded by a streaming
  byte counter that surfaces `PayloadTooLarge` if the running total
  overshoots.

### 5.5 Transport layer

`rustls` via `reqwest::blocking`. The trait is synchronous; callers
inside an async context MUST wrap calls with
`tokio::task::spawn_blocking`.

### 5.6 Verifiable sparse-checkout fetch (issue #158 Phase 2)

Feature-gated extension. Off by default — built only when the
`sparse-checkout` cargo feature is enabled on the consuming crate
chain.

```
POST /<project>/trees/<tree-hex>/sparse?sparse=<filter-hex>
Content-Type:   application/json
Accept:         application/x-mkit-sparse
Body:           {"filter": ["<utf8 path>", "<utf8 path>", ...]}
```

The server returns a single `application/x-mkit-sparse` byte stream
defined by SPEC-SPARSE-CHECKOUT §5 (envelope = manifest + entries +
proof). The client runs `mkit_core::sparse::verify_sparse` on the
decoded result; the transport layer does NOT verify anything beyond
the envelope shape and the
`SPARSE_WIRE_MAX_BYTES = 16 MiB` body cap.

| Status | Maps to |
|---|---|
| `200 OK` (`application/x-mkit-sparse` body) | `Ok(SparseResponse)` |
| `404 Not Found` | `TransportError::PackNotFound` |
| `409` / `412` (server-side filter-hash disagreement) | `TransportError::RefConflict` |
| `4xx` other | not retried |
| `5xx` / `429` | retried per §7 |

The query param `?sparse=<filter-hex>` MUST equal `BLAKE3` of the
canonicalised filter — the same value `hash_filter` computes (see
SPEC-SPARSE-CHECKOUT §2.3). A conforming server canonicalises the
body filter independently and rejects with `409` on mismatch, so a
proxy cannot silently substitute a different filter.

---

## 6. S3 / R2 transport

The S3 transport ([`mkit-transport-s3`](../rust/crates/mkit-transport-s3/))
talks SigV4 against Cloudflare R2 (primary target) or AWS S3
(works but with weaker CAS guarantees — see §6.3).

### 6.1 Object layout

The table below lists canonical repository-relative keys. For a URL of
the form `mkit+s3://endpoint/bucket/prefix`, the transport prepends
`prefix/` to every canonical object key and every `ListObjectsV2`
query prefix. A no-prefix URL continues to address keys at bucket root.
Prefixes MUST NOT be empty path segments, `.`, `..`, contain duplicate
slashes, contain backslashes, or begin/end with `/`.

| Object | S3 key |
|---|---|
| Pack | `packs/<64-hex-blake3-digest>` |
| Ref  | `<ref-name>` (e.g. `refs/heads/main`) |

Examples:

| URL | Canonical key | Effective S3 path |
|---|---|---|
| `mkit+s3://host/bucket` | `packs/<hex>` | `/bucket/packs/<hex>` |
| `mkit+s3://host/bucket/repo-a` | `packs/<hex>` | `/bucket/repo-a/packs/<hex>` |
| `mkit+s3://host/bucket/repo-a` | `refs/heads/main` | `/bucket/repo-a/refs/heads/main` |

For `list_refs("refs/heads/")` under `repo-a`, the transport sends
`ListObjectsV2` to `/bucket?list-type=2&prefix=repo-a/refs/heads/`,
fetches returned ref bodies through `/bucket/repo-a/...`, then strips
both the URL namespace and requested ref prefix before returning names.

The ref body is the 65-byte wire form: 64 hex chars + `\n`.

### 6.2 Authentication

Credentials from environment at `connect` time
([`mkit-transport-s3::ENV_*`](../rust/crates/mkit-transport-s3/src/lib.rs)):

- `MKIT_R2_ACCESS_KEY_ID`
- `MKIT_R2_SECRET_ACCESS_KEY`
- `MKIT_R2_REGION` (optional; defaults to `auto` — R2 ignores region)

Missing credentials do NOT fail `connect`. The first signed call
surfaces `TransportError::AccessDenied`.

### 6.3 CAS encoding

`update_ref` maps to a signed `PUT`:

| `RefWriteCondition` | Header | Comment |
|---|---|---|
| `Any`        | (none) | Last writer wins. |
| `Missing`    | `If-None-Match: *` | R2 honours this for conditional create. |
| `Match(h)`   | `If-Match: "<md5-of-expected-wire>"` | R2 returns the body MD5 as the ETag on `PUT`; matching against that value is how we get CAS without server-side hash awareness. AWS S3 also returns body MD5 as the ETag for simple PUTs, so `Match` works on S3 too — but multipart uploads break the equivalence, which is why §6.4 caps single-PUT size. |

`409` and `412` → `RefConflict`; never retried.

### 6.4 Limits

- `S3_SINGLE_PUT_MAX = 5 GiB` — anything larger requires multipart
  upload, deferred to a future revision.
- `PACK_BODY_LIMIT = 4 GiB` for `download_pack`.
- `REF_BODY_LIMIT = 256` bytes (a ref is 64 hex + newline; the
  256-byte ceiling accommodates trailing whitespace and trivial
  S3 metadata).
- `REF_LIST_BODY_LIMIT = 16 MiB` for the `ListObjectsV2` XML
  response.
- HTTP timeout: 60 s per request.

### 6.5 Retry

Same ladder as §7. 5xx and 429 retry; 4xx including 412 does not.

### 6.6 Verifiable sparse-checkout fetch (issue #158 Phase 2)

Feature-gated extension. Off by default — built only when the
`sparse-checkout` cargo feature is enabled on the consuming crate
chain.

S3 has no "POST a request, get a computed response" verb, so the
sparse delivery is content-addressed at a canonical object key the
server pre-populates:

```
GET /<bucket>[/<url-prefix>]/sparse/<tree-hex>/<filter-hex>
```

The response body IS the SPEC-SPARSE-CHECKOUT §5 envelope. SigV4
signing is unchanged — this is just another signed GET on the same
bucket. The client runs `verify_sparse` on the decoded result.

| Status | Maps to |
|---|---|
| `200 OK` | `Ok(SparseResponse)` |
| `404 Not Found` | `TransportError::PackNotFound` (no precomputed sparse for that `(tree, filter)`) |
| `403` / `401` | `TransportError::AccessDenied` |
| Other | mapped per `ServerError { status }` |

The `?sparse=<filter-hex>` URL query that HTTP uses (§5.6) is a no-op
on S3 because the object key already encodes the filter hash. The
client omits it so the SigV4 canonical request stays tight.

---

## 7. Retry / idempotency

All transports MUST retry the following errors with exponential
backoff: `ConnectionFailed`, `ServerError{status >= 500}`, and
`ServerError{status == 429}`. The default ladder is `1s, 2s, 4s,
8s, 16s` (5 attempts), with subsequent delays doubling and capped
at 300 s. The ladder is exposed via
[`BackoffIterator`](../rust/crates/mkit-core/src/protocol.rs) and the
classifier as [`is_retryable`].

`update_ref` with `Missing` or `Match` is NOT idempotent across
retries: a network timeout after the server applied the write looks
identical to a write that never landed. After a retried `update_ref`
returns `RefConflict`, callers MUST follow up with `read_ref` to
disambiguate.

`upload_pack` IS idempotent (content-addressed: re-uploading the
same bytes produces the same digest and is a no-op on the server
side).

`download_pack` and `pack_exists` are pure reads; no idempotency
concerns.

### 7.1 Cross-transport CAS guarantee summary

| Transport | `Missing` | `Match(h)` | Cross-process safe |
|---|---|---|---|
| Memory | `Mutex`-protected read-then-write | `Mutex`-protected | N/A (test only) |
| File   | `link(2)` after `write_atomic` (atomic per POSIX) | OS exclusive file lock on `<root>/.mkit/refs/.lock` (via `std::fs::File::lock`) wraps a read-then-`write_atomic`; an in-process `Mutex` keeps multi-threaded callers within one process from contending on the OS lock | Yes |
| HTTP   | `If-None-Match: *` enforced by the Worker | `If-Match: "<hex>"` enforced by the Worker | Yes |
| S3     | `If-None-Match: *` enforced by R2 | `If-Match: "<md5-of-wire>"` enforced by R2 | Yes (on R2; S3 multipart breaks `Match` — see §6.3) |
| SSH    | Server-enforced via `expectation = REF_EXPECTATION_MISSING` | Server-enforced via `expectation = REF_EXPECTATION_MATCH` + 32-byte `expected_id` | Depends on server-side ref-store atomicity |

---

## 8. Pack format

`upload_pack` and `download_pack` move opaque pack bytes. The pack
format itself (object index + delta encoding + chunk store) is
defined in [SPEC-PACKFILE](SPEC-PACKFILE.md). Transport
implementations MUST NOT inspect or rewrite pack bytes.

The 32-byte pack digest is the BLAKE3 hash of the full pack-bytes
buffer, wrapped in [`PackKey`](../rust/crates/mkit-core/src/protocol.rs)
to keep pack digests and object hashes from silently crossing
purposes at API boundaries.

---

## 9. Versioning

This document and `ssh.proto` are jointly v1. The cross-transport
trait surface (`Transport`, `TransportError`, `PackKey`,
`RefWriteCondition`) is API-stable within the v0.1.x line. See
[SPEC-RPC §2](SPEC-RPC.md#2-versioning) for SSH wire-format
versioning.

A native SSH implementation (with in-process host-key pinning) is a
future enhancement; [`SSH-SECURITY.md`](SSH-SECURITY.md) tracks the
gaps inherited from delegating to `ssh(1)`. S3 multipart upload
(for packs above the 5 GiB single-PUT cap) is similarly deferred.
