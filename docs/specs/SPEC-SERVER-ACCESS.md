---
spec: SPEC-SERVER-ACCESS
version: 1
status: draft-normative
audience: implementers of the optional mkit managed hosting profile
---

# Optional managed repository authority

This profile applies to one standalone hosting deployment and one repository.
It does not change object, signature, pack, ref, transport protobuf, or core
permission semantics. In this version, managed repository data access is
unavailable: all seven transport methods and every internal data path MUST
reject before repository effects. A future version may define data access.

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

## 4. Failure mapping

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

Health and OPTIONS MUST disclose no repository policy or data. The managed
binary returns `unavailable` for health RPCs while its data plane is closed.
Unknown paths
MUST NOT enter the data plane. This release MUST reject ListRefs, ReadRef,
PackExists, DownloadPack, UpdateRef, AdvanceRefs, UploadPack and internal
ref/object data routes for every identity, including the owner. A public
deployment that formerly served the same stored bytes has no retroactive
confidentiality; binary and binding replacement is outside the latch.

## 5. Committed vectors

`rust/tests/golden/server-access/` holds exact newline-terminated management
request and response bytes for Initialize, Get, Replace, conflict, unavailable,
and duplicate-field rejection. Each request has a JSON metadata sidecar
naming its expected status and response file; BLAKE3 digests are pinned in
`MANIFEST.txt`. Normal consumers read committed files only. The writer requires
`MKIT_WRITE_GOLDEN=1`, and fixture changes require review with the wire
contract.
