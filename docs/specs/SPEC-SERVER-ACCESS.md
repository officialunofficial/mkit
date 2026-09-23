---
spec: SPEC-SERVER-ACCESS
version: 1
status: draft-normative
audience: implementers of the optional mkit managed hosting profile
---

# Optional managed repository authority

This profile applies to one standalone hosting deployment and one repository.
It does not change object, signature, pack, ref, transport protobuf, or core
permission semantics. Managed repository data access follows the exact role
matrix in §4. The public deployment and native client defaults are unchanged.

## 1. Identity and initialization

An operator MUST configure an exact canonical HTTP(S) audience, a nonempty
printable ASCII repository identifier of at most 255 bytes, and one canonical
lowercase 32-byte Ed25519 owner public key. An absent, invalid, all-zero, or
changed identity MUST fail closed. The deployment MUST bind its own object
store and durable authority store. The owner is immutable; no first caller
may claim ownership, and key transfer or recovery is not specified.

The durable store has a versioned identity latch containing the audience,
repository, owner, generation, and policy. Unknown schema, corruption, or a
configured identity mismatch MUST produce `unavailable`; no reset or public
fallback is allowed. An explicit owner-authenticated InitializePolicy against
an absent latch commits the full identity, generation `1`, policy, and replay
result atomically. Before that commit, owner-authenticated GetPolicy and
ReplacePolicy return `unavailable` without creating policy or replay state.

## 2. Authentication and management wire

Management methods are POST-only paths:

| Path | Request | Success |
|---|---|---|
| `/mkit/host/v1/InitializePolicy` | `{version,collaborators}` | policy |
| `/mkit/host/v1/GetPolicy` | `{version}` | policy |
| `/mkit/host/v1/ReplacePolicy` | `{version,expected_generation,collaborators}` | policy |

The exact path is the auth-v2 procedure. The content commitment is
`body:<BLAKE3 of exact raw request bytes>`. All auth-v2 headers, including
`X-Digest`, are required. The authenticated public key MUST equal the pinned
owner before any policy contents are returned. The HTTP verb is checked
separately because it is not part of the auth-v2 signature. All management
responses, including errors, use `Cache-Control: private, no-store`.

Requests MUST be UTF-8 JSON with `Content-Type: application/json` exactly,
at most 65,536 bytes, without content encoding.
An absent or malformed Content-Length does not relax the cap: implementations
MUST stop accumulating body bytes once the limit would be exceeded.
Every object rejects duplicate and unknown fields. A JSON document MUST end
after the sole value; surrounding whitespace is accepted. `version` is the
JSON integer `1`. Key order and whitespace need not be canonical because the
signature binds exact bytes. After a successfully committed Initialize or
Replace, a same-nonce request with different signed bytes conflicts even if
the JSON meaning is identical. A request rejected before admission creates no
replay row; retry reevaluates current authority and generation.

Every management reply is one JSON value followed by one LF byte. The policy
response is
`{version,audience,repository,owner,generation,collaborators}`. Generation
is a canonical decimal string representing u64: `0` or a nonzero digit
followed by digits, without signs, leading zeros, or fraction. A stored
policy generation is at least `1`. Replace requires the exact current
generation and increments it by one; overflow conflicts without effects.
Initialize and Replace policy effects and their replay results MUST commit in
one transaction. An exact signed mutation retry returns the saved result even
after a later generation change. GetPolicy returns the current policy after
fresh owner authentication and expiry validation; it does not allocate a
replay row. Ordinary auth-v2 nonce expiry rules apply.

## 3. Collaborators

`collaborators` is an array of zero through 256 `{public_key,role}` objects.
Each public key is a valid canonical lowercase Ed25519 key. Roles are exactly
`reader` or `writer`; writer includes reader capability in future data
profiles. The owner is implicit and MUST NOT appear in this array. Entries
MUST be strictly sorted by decoded public-key bytes, hence distinct. No
wildcard, group, chain, or delegation semantics exist.

## 4. Managed data methods

The only data procedures are POST
`/mkit.transport.v1.TransportService/<Method>`. The allowed roles are:

| Method | Reader | Writer | Owner |
|---|---:|---:|---:|
| ListRefs, ReadRef, PackExists, DownloadPack | yes | yes | yes |
| UploadPack, UpdateRef, AdvanceRefs | no | yes | yes |

Anonymous, nonmembers, and grant-only subjects have no data access. Unknown
methods fail closed. Policy management remains owner-only. The optional
owner-controlled MKHG registry in
[SPEC-HOSTED-WORKSPACE-GRANTS](SPEC-HOSTED-WORKSPACE-GRANTS.md) does not add a
role or unlock a data method. Every data request
MUST carry auth v2 bound to the configured audience, repository, exact
procedure and request message bytes; UploadPack instead signs its existing
pack id and declared length commitment. For DownloadPack, the signed bytes are
the sole decoded protobuf request message, excluding Connect's five-byte
frame. Extra frames, trailing bytes, compressed requests and non-POST methods
MUST reject before repository access. A signature alone does not grant access:
every operation checks live durable policy. Policy corruption, identity
mismatch, missing policy or storage failure fails closed.

The native Connect client opts into authenticated reads only through the
user-scoped `transport_signed_reads = true` setting with envelope mode and an
exact user-trusted endpoint (SPEC-TRANSPORT-CONNECT §7). The public client's
unsigned-read default is unchanged. Client signing authenticates an identity;
this service's live role check independently decides whether it may read.

The outer Worker MUST authenticate and check writer membership before
collecting an UploadPack body. This precheck creates no reservation. The
service repeats authorization before reservation, before R2 publication and
at durable completion. Ref authorization, replay lookup, quota, both CAS
predicates and effects share one SQL transaction; authorization runs before
replay lookup, including exact retries. A revoked collaborator cannot resume
an earlier reservation or record a new completion. R2 and SQL are not atomic:
a revocation after a pre-put check may leave an immutable orphan. It cannot
authorize a subsequent ref effect, recall bytes already released, or cancel
an R2 request already issued.

Read authorization precedes ref/R2 access. After asynchronous storage work,
the Worker rechecks live policy after buffering and before releasing the
response. Ref listing materializes at most 257 rows to decide whether the
256-ref limit is exceeded; an excess fails rather than truncates. Managed
ref names and prefixes are at most 1024 UTF-8 bytes, and a serialized list
reply must fit 65,536 bytes. These are service resource limits, not changes
to the repository's portable ref format.

The managed pack payload cap is 4 MiB. Large request bodies and SDK messages
are capped at 4 MiB + 64 KiB; small request bodies and SDK messages at
64 KiB. A full download is one pack-sized protobuf message. Oversized R2
metadata rejects before body reading, and actual bytes are capped while
reading. One upload or download at a time per isolate holds a nonblocking
permit through request and response buffering; competing large transfers
receive `resource_exhausted`. Administration and control requests do not
take this permit. The cap does not establish an exact isolate peak-memory
bound, and already materialized SDK chunks may briefly exceed the retained
buffer length.

## 5. Failure mapping

Responses are JSON `{"code":"<code>"}` with no internal storage detail.

| Condition | HTTP | code |
|---|---:|---|
| Non-POST management method | 405 | `method_not_allowed` |
| Compressed or non-JSON content | 415 | `unsupported_media_type` |
| Body above 65,536 bytes | 413 | `resource_exhausted` |
| Missing or invalid configuration; uninitialized or corrupt authority; storage unavailable | 503 | `unavailable` |
| Missing, foreign, expired, or invalid signature | 401 | `unauthenticated` |
| Invalid JSON, fields, generation encoding, key, or membership | 400 | `invalid_argument` |
| Already initialized, generation mismatch/overflow, or nonce reuse with different bytes | 409 | `conflict` |
| Managed data method forbidden to an authenticated nonmember or role | 403 | `permission_denied` |
| Managed inbound HTTP body or signed upload declaration above its cap | 413 | `resource_exhausted` |
| Managed large-transfer permit unavailable, oversized R2 object, or bounded list over limit | 429 | `resource_exhausted` |

For data RPCs, Connect errors carry the corresponding Connect code;
server-streaming errors may appear in a 200 HTTP response end-stream frame.
All managed success and error responses have `Cache-Control: private,
no-store` and expose no policy, SQL or R2 diagnostics. Health and OPTIONS
MUST disclose no repository policy or data. Unknown paths MUST NOT enter the
data plane. Internal DO calls accept only Worker-produced post-verification
proofs through the private binding and independently check live policy,
expiry and procedure; no production public proof-forwarding alias exists. A public
deployment that formerly served the same stored bytes has no retroactive
confidentiality; binary and binding replacement is outside the latch.

## 6. Committed vectors

`rust/tests/golden/server-access/` holds exact newline-terminated management
request and response bytes for Initialize, Get, Replace, conflict, unavailable,
and duplicate-field rejection. Each request has a JSON metadata sidecar
naming its expected status and response file; BLAKE3 digests are pinned in
`MANIFEST.txt`. Normal consumers read committed files only. The writer requires
`MKIT_WRITE_GOLDEN=1`, and fixture changes require review with the wire
contract.

`rust/tests/golden/managed-service/` additionally pins ReadRef and
DownloadPack request-message bytes, DownloadPack frame bytes and their
different BLAKE3 digests, plus named negative cases. The local workerd
consumer checks committed files and the actual responses. Its writer likewise
requires `MKIT_WRITE_GOLDEN=1`. Existing object, pack, proof and auth-v2
vectors do not change.
