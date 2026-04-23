# SPEC-TRANSPORT — mkit v1 transport protocols

Status: **Normative** for mkit v1.
Scope: the 7 transport verbs, their per-transport wire encoding, their
atomicity guarantees, and retry/backoff policy.

This spec complements SPEC-REFS (which pins ref wire bytes) and
SPEC-PACKFILE (which pins pack wire bytes). Here we pin the *verbs*.

Resolves red-team R-02 (no written transport spec), R-07/R-08/R-09
(per-verb divergence), R-10/R-11 (SSH trust model), R-14/R-15 (S3 retry
and size limits).

---

## 1. The 7 verbs

All transports implement the same abstract vtable
(`src/protocol.zig:20-61`):

```
uploadPack(bytes, digest)      upload a pack under "packs/<hex>"
downloadPack(digest) -> bytes  retrieve a pack by digest
packExists(digest) -> bool     HEAD-check for a pack
writeRef(name, hash)           unconditional ref write
updateRef(name, cond, hash)    CAS ref write (see SPEC-REFS §5)
readRef(name) -> Option<Hash>  GET the current ref value, or None
listRefs(prefix) -> [Ref]      enumerate refs (see SPEC-REFS §4)
```

`writeRef` is defined as `updateRef(name, .any, hash)` and MUST be
implemented that way.

The abstract errors surfaced by the vtable are (lowercase in Zig,
SPEC-DOC here uses PascalCase):

```
PackNotFound         downloadPack on absent digest
AccessDenied         auth/ACL failure
RemoteError          other transport-level failure
RefConflict          updateRef CAS condition not satisfied
InvalidRef           caller passed a ref name failing SPEC-REFS §3
ConnectionFailed     network-level failure (connection refused, DNS fail)
ServerError          unexpected HTTP status / SSH protocol error
```

Implementations MAY add transport-specific errors but MUST map them to
one of the above when crossing the trait boundary.

---

## 2. Atomicity matrix

See SPEC-REFS §5.1 for the ref-write matrix. For pack-write:

| Transport | uploadPack atomic? | Notes |
|-----------|-------------------|-------|
| memory    | yes (single map put) | |
| file      | no (plain `createFile` then `writeAll`) | v1 known gap; W4 will use temp-rename. |
| s3        | yes (PUT is atomic from server's perspective) | Single-PUT only; 5 GiB cap. |
| http      | depends on server | Worker target is atomic. |
| ssh       | yes (server writes to temp then renames) | |

---

## 3. memory transport (`transport/memory.zig`)

In-process `StringHashMap<Hash, Vec<u8>>`. Single-threaded contract.
No wire format — function calls only. Exists for tests.

`listRefs` strips prefix per SPEC-REFS §4. `updateRef(.match)` is
read-then-write (non-atomic across threads; documented).

---

## 4. file transport (`transport/file.zig`)

Directory-rooted local filesystem. Writes are plain `createFile +
writeAll`. No fsync in v1 (known gap — SPEC-REFS §6 requires
atomic-rename for local refs, which W4 adds; pack writes remain plain
`createFile` in v1).

### 4.1 Layout

```
<root>/packs/<64-hex>               pack object
<root>/refs/heads/<name>            ref file (65-byte wire)
<root>/refs/tags/<name>             ref file
```

`ensureParentDirs` creates subdirectories on demand
(`src/transport/file.zig:176-186`). Refs under nested names
(e.g. `refs/heads/feat/x`) create the `feat` directory as needed.

### 4.2 `updateRef` semantics

- `.any`: open + write. Clobbers.
- `.missing`: `createFile(..., .exclusive = true)`. On
  `PathAlreadyExists` → `RefConflict`. Atomic via POSIX `O_EXCL`.
- `.match`: read, compare, write. **Non-atomic across processes.** A
  concurrent writer can invalidate the compare between read and write.

Documented non-atomicity. Callers requiring CAS on a multi-writer local
filesystem MUST use an external lock.

---

## 5. s3 transport (`transport/s3.zig`)

AWS Signature Version 4 PUT/GET/HEAD. Target backends: AWS S3, Cloudflare
R2, and MinIO-style S3-compatible. Uses `rustls`-backed HTTP client;
no OpenSSL.

### 5.1 Region

`region = "auto"` for R2; `region = "us-east-1"` (or the bucket's
home region) for AWS. Silent SigV4 failure if the wrong region is
configured (red-team R-16). Implementations SHOULD document this and
fail fast on SigV4 rejection with a readable error.

### 5.2 Wire

- PUT `/{key}` — body = payload; headers include SigV4 `Authorization`,
  `x-amz-date`, `x-amz-content-sha256`, and any `If-Match` /
  `If-None-Match` header.
- GET `/{key}` — empty body, SigV4 headers only.
- HEAD `/{key}` — empty body, SigV4 headers only.

`{key}` is one of:

- `packs/<64-hex>` for pack objects.
- `<ref-name>` (full ref path including `refs/heads/...`) for refs.

Status codes:

- `200 OK` / `201 Created` → success (write) or `ok` (read).
- `404 Not Found` → `PackNotFound` / `readRef` returns `None`.
- `403 Forbidden` → `AccessDenied`.
- `412 Precondition Failed` / `409 Conflict` → `RefConflict` (CAS
  failure).
- Any other 4xx/5xx → `ServerError`.

### 5.3 CAS conditional headers

Per SPEC-REFS §5.2:

- `.missing` → `If-None-Match: *`.
- `.match(H)` → `If-Match: "<MD5_hex>"` where `MD5_hex = md5(wire(H))`
  (32 hex chars between double-quotes).

### 5.4 listRefs

XML `list-type=2` output parsed to strip the prefix per SPEC-REFS §4
(`src/transport/s3.zig:301-316`). Implementations MUST handle
pagination (`<NextContinuationToken>`). Current mkit implementation
assumes a single page; v1 clarifies this is a bug to fix in W4.

### 5.5 Size limit

Single PUT only. Files over ~5 GiB will be rejected by the server or
silently truncated. Mkit v1 caps packs at 4 GiB (SPEC-PACKFILE §5) to
stay under this. Multipart upload is not implemented in v1.

---

## 6. http transport (`transport/http.zig`)

Worker-flavoured HTTP API. This is NOT a generic S3-compatible HTTP
layer; it assumes a server that implements mkit's specific endpoint
shapes. A separate, S3-semantics HTTP transport may be added in a
future version; v1 ships only the Worker flavour.

### 6.1 Endpoint shape

```
PUT    <base>/packs/<64-hex>           upload pack (body = pack bytes)
GET    <base>/packs/<64-hex>           download pack
HEAD   <base>/packs/<64-hex>           existence check
PUT    <base>/<ref-name>                write/update ref (body = 65-byte wire)
GET    <base>/<ref-name>                read ref
GET    <base>/refs/?prefix=<prefix>    list refs; JSON response
```

JSON listing response (`src/transport/http.zig:79-112`):

```json
{"refs":["refs/heads/main","refs/heads/feature/x"]}
```

The server returns FULL names; the client strips `prefix` per SPEC-REFS
§4 before returning.

Hashes in the JSON response are **not returned** in v1 — the client
calls `readRef` for each as needed. This is suboptimal; flagged for v2.

### 6.2 Auth

Optional `Authorization: Bearer <token>` header.

### 6.3 CAS conditional headers

Per SPEC-REFS §5.2:

- `.missing` → `If-None-Match: *`.
- `.match(H)` → `If-Match: "<hash_hex>"` (64-char lowercase hex in
  double-quotes).

**This is incompatible with generic S3-style ETag semantics.** A bare
S3 + nginx server will compute the MD5 of the body for its ETag and
reject the hex-hash `If-Match`. Known and documented (red-team R-12,
R-13).

---

## 7. ssh transport (`transport/ssh.zig`)

Process-exec SSH: the client invokes
`ssh [-p port] [user@]host mkit serve <path>` and speaks a custom
binary protocol over the child's stdin/stdout. Host key verification,
agent, keepalives — all delegated to the user's `ssh` CLI.

### 7.1 Wire framing

Every request and response is framed as:

```
[u8 opcode_or_status]
[u32 LE payload_len]
[payload_len bytes payload]
```

`payload_len` max: 16 MiB (`MAX_PAYLOAD`,
`src/transport/ssh.zig:28`). Larger payloads (e.g. packs
> 16 MiB) use repeated frames — SSH transport does NOT fragment; v1
clarifies this is an intentional limit. Large packs over SSH require a
v2 fragmented protocol or a switch to S3/HTTP for transfer.

### 7.2 Opcodes (client → server)

```
0x00    OP_HELLO            new in v1 (see §7.4)
0x01    OP_UPLOAD_PACK      payload = [32 digest] [pack bytes]
0x02    OP_DOWNLOAD_PACK    payload = [32 digest]
0x03    OP_PACK_EXISTS      payload = [32 digest]
0x04    OP_WRITE_REF        payload = [u16 name_len][name][32 hash]
0x05    OP_UPDATE_REF       payload = [condition][u16 name_len][name][32 hash]
                             condition: 0x00 ANY, 0x01 MISSING,
                                        0x02 MATCH + [32 expected]
0x06    OP_READ_REF         payload = [u16 name_len][name]
0x07    OP_LIST_REFS        payload = [u16 prefix_len][prefix]
0xFF    OP_CLOSE            payload = empty
```

### 7.3 Status bytes (server → client)

```
0x00    STATUS_OK
0x01    STATUS_ERROR        payload = error message bytes (UTF-8, advisory)
0x02    STATUS_NULL         payload = empty; means "absent"
0x03    STATUS_UNSUPPORTED  server rejects client protocol version (§7.4)
```

`STATUS_NULL` is returned by `OP_READ_REF` for a missing ref and by
`OP_DOWNLOAD_PACK` for a missing pack (clients map this to
`PackNotFound`).

`STATUS_UNSUPPORTED` is emitted by the OP_HELLO handler when the
client advertises a `proto_version` the server does not speak.

`STATUS_ERROR` on `OP_UPDATE_REF` maps to `RefConflict` — the server
MUST only emit STATUS_ERROR for `OP_UPDATE_REF` when the CAS condition
failed, not for transport or permission errors; those use a distinct
error code in v2. In v1, this conflation is a documented limitation.

### 7.4 OP_HELLO (new in v1)

The FIRST frame on every connection MUST be OP_HELLO; servers reject
any other opening opcode with STATUS_ERROR + disconnect. This is a
synchronous handshake — client sends, server replies, then the normal
request/response loop begins.

```
Client → Server:
  opcode  = 0x00 OP_HELLO
  payload = [u8 proto_version]            = 0x01
            [u8 binary_name_len]          ≤ 32
            [binary_name_len bytes]       "mkit"
            [u8 client_version_len]       ≤ 64
            [client_version_len bytes]    "mkit 0.2.0"

Server → Client (on match):
  status  = 0x00 STATUS_OK
  payload = [u8 proto_version]            = 0x01
            [u8 server_version_len]       ≤ 64
            [server_version_len bytes]    "mkit 0.2.0"

Server → Client (on binary_name mismatch):
  status  = 0x01 STATUS_ERROR
  payload = "binary name mismatch" (UTF-8, advisory) — then disconnect

Server → Client (on client proto_version > server's):
  status  = 0x03 STATUS_UNSUPPORTED
  payload = "unsupported proto version" — then disconnect
```

Concrete successful v1 wire (bytes in hex; versions in examples reflect
the current release — the wire contract is `proto_version=1`, not a
specific human version string):

```
Client → Server frame (opcode=0x00, payload 18 bytes):
  00               opcode OP_HELLO
  12 00 00 00      u32 LE payload length = 18
  01               proto_version = 1
  04               binary_name_len = 4
  6D 6B 69 74      "mkit"
  0A               client_version_len = 10
  6D 6B 69 74 20 30 2E 32 2E 30   "mkit 0.2.0"

Server → Client frame (status=0x00, payload 12 bytes):
  00               STATUS_OK
  0C 00 00 00      u32 LE payload length = 12
  01               proto_version = 1
  0A               server_version_len = 10
  6D 6B 69 74 20 30 2E 32 2E 30   "mkit 0.2.0"
```

Client behaviour on an unparseable / truncated / non-OK server reply:
return `error.IncompatiblePeer` and teardown. Do NOT silently continue;
no pre-v1 fallback is supported in 0.1.0 (no-back-compat per W1). A
pre-v1 server (no OP_HELLO support) will reject opcode 0x00 and the
client will see STATUS_ERROR → IncompatiblePeer.

This resolves red-team R-10 (binary rename breaks remotes): a renamed
or legacy peer fails loud on the first byte exchange instead of
silently read-writing incompatible frames.

### 7.5 Trust model (R-11)

SSH transport security is **delegated to the user's `ssh` CLI**. mkit:

- Does NOT implement host-key checking.
- Does NOT read `~/.ssh/known_hosts` directly.
- Does NOT negotiate kex, ciphers, or auth.
- Does NOT expose a way to pin a fingerprint from `.mkit/config`.

Three `.mkit/config` keys override the `ssh(1)` defaults for the mkit
SSH child process only (they do not affect other `ssh` invocations) —
each defaults to empty, meaning "inherit":

```
ssh.strict_host_key_checking = yes
ssh.user_known_hosts_file    = /path/to/project.known_hosts
ssh.identity_file            = /path/to/id_ed25519
```

These are plumbed into the child's argv as `-o StrictHostKeyChecking=…`,
`-o UserKnownHostsFile=…`, and `-i …` respectively. See
`docs/SSH-SECURITY.md` for the full trust model, recommended defaults,
and known limitations. A native SSH implementation (with in-process
fingerprint pinning) is deferred to 0.2.0.

---

## 8. Retry and idempotency policy (R-15, Team Lead 7p)

All transports MUST implement the following retry policy for any verb
that returns `ConnectionFailed`, `ServerError` on a 5xx, or HTTP 429:

```
attempt = 1
delay   = 1s
while attempt <= 5 and transient_error:
    sleep(delay)
    retry
    attempt += 1
    delay = min(delay * 2, 300)      # cap at 5 minutes
```

Cap of 5 minutes per attempt; total budget ~10 min (1+2+4+8+16+32+...
up to 5×300s).

**Idempotency per verb:**

- `uploadPack` — idempotent (same pack bytes always produce same
  digest; server-side dedup is allowed by keying on digest).
- `downloadPack`, `packExists`, `readRef`, `listRefs` — trivially
  idempotent (read-only).
- `writeRef` / `updateRef(.any)` — idempotent (same input → same final
  state).
- `updateRef(.missing)` — **NOT idempotent**. On retry after a timeout
  where the first request actually succeeded, the retry will return
  `RefConflict`. Callers MUST treat `RefConflict` as possibly-success
  when retrying a `.missing`; follow up with `readRef` to confirm.
- `updateRef(.match)` — **NOT idempotent** for the same reason.
  Callers MUST follow up with `readRef`.

Servers SHOULD accept an optional idempotency key header (e.g.
`X-Mkit-Idempotency-Key: <uuid>`) to dedupe retries within a window.
v1 does not make this mandatory.

---

## 9. Test vectors (implementer MUST produce)

TO BE FIXED IN IMPLEMENTATION:

1. **Cross-transport listRefs parity**: seed identical refs
   (`refs/heads/main`, `refs/heads/feat/x`, `refs/tags/v1`) on each of
   memory, file, s3, http, ssh. `listRefs("refs/heads")` and
   `listRefs("refs/heads/")` both return identical ordered `["feat/x",
   "main"]`.
2. **S3 MD5 ETag round-trip**: write ref, then `updateRef(.match)` with
   correct expected hash — succeeds. With wrong hash — `RefConflict`.
3. **HTTP hex ETag** similarly.
4. **SSH OP_HELLO**: client sends 0x00 HELLO v1 "mkit"; server
   responds STATUS_OK v1 "mkit". Then unrelated verb succeeds.
5. **SSH fall-through on pre-v1 server**: server returns
   STATUS_ERROR on 0x00; client emits `ProtocolMismatch` or adapts.
6. **Retry ladder**: mock a 503-then-200 server; first attempt sleeps
   ~1 s, then 2 s, succeeds on third.
7. **`.missing` retry after timeout**: simulate first write succeeding
   but response lost; retry returns `RefConflict`; `readRef` confirms
   success.
8. **File transport concurrent `.match` race**: two writers, both
   succeed — asserted as a negative test demonstrating the documented
   non-atomicity.

---

*~1900 words.*
