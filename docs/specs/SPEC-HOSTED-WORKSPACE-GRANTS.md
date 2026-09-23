---
spec: SPEC-HOSTED-WORKSPACE-GRANTS
version: 1
status: draft-normative
audience: implementers of the optional managed mkit hosting profile
---

# SPEC-HOSTED-WORKSPACE-GRANTS &mdash; service-local workspace credentials

Status: **Draft, normative** for the optional hosted grant service profile.
Scope: MKHG v1 bytes, owner administration, and the durable grant registry.
The credential adds no permission rule to mkit objects, Commits, portable
partial updates, or the seven generic transport methods.
Endianness: fixed-width integers are **big-endian**. Lengths use minimal
unsigned LEB128 u32, overriding [SPEC-CONVENTIONS](SPEC-CONVENTIONS.md) §3.

An independent implementation MUST be able to produce and consume MKHG bytes
from this document alone. A cryptographically valid grant is a fact about its
issuer's signature; only the live registry can establish current authority.

## 1. Envelope

The complete signed envelope MUST be at most 262,144 bytes. Fields appear in
this exact order, without padding:

```text
magic                         [u8;4] = ASCII "MKHG"
version                       u8 = 1
audience                      length + UTF-8 bytes
repository                    length + UTF-8 bytes
exact_ref                     length + UTF-8 bytes
workspace_id                  [u8;32]
issuer                        [u8;32] Ed25519 public key
subject                       [u8;32] Ed25519 public key
receipt_signer                [u8;32] Ed25519 public key
authority_generation          u64 BE
grant_generation              u64 BE
initial_base                  [u8;32] object ID
not_before                    u64 BE Unix milliseconds
expires                       u64 BE Unix milliseconds
max_operations                u32 BE
entries                       length + repeated Entry
  Entry.components            length + repeated (length + UTF-8 bytes)
  Entry.mask                  u8
signature                     [u8;64] Ed25519 signature
```

The three string lengths, entries count, component count, and each component
length use unsigned LEB128 u32 of at most five bytes. A decoder MUST reject
overflow, nonminimal encodings, truncation, an unknown version, trailing bytes,
and every count or length above its cap before allocating from it. It MUST NOT
normalize or sort caller input. Fixed arrays carry no length prefix.

The signature is Ed25519 over the 32-byte digest
`BLAKE3(ASCII "mkit.hosted-workspace-grant.v1" || 0x00 || unsigned envelope)`.
The unsigned envelope includes magic and every field through entries, but not
signature. The grant ID is
`BLAKE3(ASCII "mkit.hosted-workspace-grant-id.v1" || 0x00 || complete signed envelope)`.
These are distinct literal domains; no generic hash wrapper or alternate
signature prehash substitutes for either. Verification MUST use strict
Ed25519 verification and reject invalid or weak issuer, subject, and receipt
signer keys, including all-zero placeholders. The issuer MUST equal the
deployment's configured immutable owner at registration. Receipt signer is a
pinned claim for later use, not proof of key custody or of a receipt.

## 2. Field and path profile

Audience MUST be a canonical HTTP(S) origin of at most 512 bytes under the
[auth-v2 grammar](SPEC-TRANSPORT-CONNECT.md). Repository MUST be 1..=255
printable ASCII bytes. `exact_ref` MUST be a valid
[ref name](SPEC-REFS.md) beginning with `refs/heads/`, at most 1,024 bytes.
Both generations MUST be at least one. The validity interval MUST satisfy
`0 < expires - not_before <= 86,400,000` with checked subtraction.
`max_operations` MUST be 1..=256; an optional owner construction API may
default it to 64, but encoded bytes always carry an explicit value.

There MUST be 1..=256 distinct entries, strictly increasing by their joined
slash-separated UTF-8 **bytes**. Each entry MUST name an exact selected file
path of 1..=32 components, each 1..=255 bytes, with joined length at most
1,024 bytes and total joined lengths at most 65,536 bytes. Every component
MUST satisfy [TreeEntry name grammar](SPEC-OBJECTS.md) and UTF-8 and contain
no Unicode control. Root `.mkit-scoped` is forbidden under ASCII case
folding. The core [selected-path profile](SPEC-PARTIAL-WORKSPACES.md) has the
same grammar; generic Tree validity does not change. A path entry is a full
file path, never a prefix or glob. `*`, `?`, and similar permitted characters
are literal name bytes. The later snapshot or admission verifier checks that
its final mode is a regular or executable file.

Only `READ=1` and `READ|REPLACE=3` masks are valid. Replacement includes
read. The grant cannot delegate or issue another grant, and a request outside
its exact path/mask set MUST fail rather than silently narrow. A path set
inside MKHG does not establish snapshot readiness.

## 3. Owner management wire

All methods are POST-only, use the exact path as the auth-v2 procedure, and
authenticate the exact raw JSON request bytes with the existing `X-Digest`
and configured audience/repository. Only the configured owner may call them.
The HTTP verb is checked separately. Bodies MUST be uncompressed UTF-8 JSON
with exact `Content-Type: application/json`, one complete value, no duplicate
or unknown fields, and version JSON integer `1`. Whitespace and key order
may vary because the signature binds the exact bytes. Every response and
error is one JSON value followed by LF with `Cache-Control: private, no-store`.

| Path | Complete request | Cap |
|---|---|---:|
| `/mkit/host/v1/RegisterGrant` | `{version:1,expected_grant_generation:"<decimal>",grant:"<base64url>"}` | 384 KiB |
| `/mkit/host/v1/RevokeGrant` | `{version:1,workspace_id:"<64hex>",expected_grant_generation:"<decimal>",grant_id:"<64hex>"}` | 64 KiB |
| `/mkit/host/v1/GetGrant` | `{version:1,workspace_id:"<64hex>"}` | 64 KiB |

IDs MUST be exactly 64 lowercase hex digits. Decimal strings MUST be the
canonical u64 spelling: `0` or nonzero first digit then digits, with no sign,
fraction, exponent, leading zero, or overflow. JSON numbers MUST NOT stand
for u64 fields. Grant base64url MUST be unpadded and canonical: decoding and
re-encoding MUST reproduce it exactly. The decoded envelope retains its
256 KiB cap. An implementation MUST bound the outer body incrementally,
including chunked requests, before collecting or decoding it. The existing
policy-admin cap remains 64 KiB.

Register and Revoke success is
`{version:1,workspace_id,grant_id,grant_generation,status}` with generation
as a decimal string and status `active` or `revoked`. An exact auth-v2 nonce
replay within request validity returns the saved mutation response, even if
the incarnation is now expired, revoked, or superseded. It does not restore
old state. A new nonce reevaluates live authority, time, ref and CAS. A
same-nonce different request conflicts. A request rejected before admission
creates no replay row. Live configured identity, owner and healthy policy
MUST be checked before replay lookup.

GetGrant is a fresh live owner read, with no replay reservation. Absent
workspace returns `not_found` after authentication. It returns
`{version,workspace_id,grant_id,grant_generation,status,grant,initial_base,workspace_head,authority_generation_matches,time_valid,snapshot_readiness}`.
The last field is always `"not_checked"` in this version; the two validity
fields are JSON booleans. `status` is current `active` or `revoked`, never
historical `superseded`. The grant remains canonical unpadded base64url, and
the complete response MUST be at most 384 KiB. No `authorized:true`, content,
or enumeration endpoint exists.

## 4. Durable registry

One deployment binds one repository and a configured immutable owner. A
successful owner RegisterGrant may atomically initialize a **wholly absent**
versioned grant registry under an already healthy policy. GetGrant before
bootstrap returns `not_found`; Revoke returns `conflict`. A partial schema,
unknown/missing version metadata, corrupt row, unknown current pointer, or
configured/persisted identity mismatch MUST fail closed as `unavailable` and
MUST NOT be auto-repaired. Registry and replay effects commit in one
synchronous SQL transaction. No network or object-store operation occurs in
that transaction. Complete operator deletion/replacement of all security
storage is outside the service's threat boundary.

Workspace IDs are 32 bytes and never recycled. The first registration
requires expected generation `0`, signed generation `1`, and no prior
workspace row. Renewal requires the exact current generation and a newly
signed next generation, checked for u64 overflow. Audience, repository,
ref, workspace ID, issuer, subject and receipt signer remain immutable
workspace identity. Path entries, expiry, budget and initial base may change.
An old active incarnation becomes `superseded`; an old revoked incarnation
stays `revoked`. Each former row and its exact signed envelope and ID remain
durable. The workspace's current pointer MUST name an active or revoked row;
neither revoked nor superseded rows ever become active again.

Register requires `not_before <= service_now < expires`, exact current
policy generation, and an existing branch ref equal to signed `initial_base`.
It does not create a ref, inspect the object graph, or certify readiness.
The initial base remains immutable within an incarnation. A separate mutable
`workspace_head` starts at that base; future accepted updates advance it.
Renewal reanchors to the then-current owner-reviewed ref. Foreign ref moves
fail closed; future admission must check registry head and actual ref.
Revoke requires exact current generation and grant ID and tombstones the
active row. It may revoke an expired or stale-generation grant under a healthy
current policy. A fresh new-nonce second revocation conflicts.

Registry generations and times MUST be represented as exact decimal text or
bytes, never signed SQLite INTEGER or JavaScript Number. It retains at most
1,024 workspace IDs, 4,096 lifetime incarnations and 16 MiB of inserted
envelope bytes per repository. Each ceiling is independent; insertion beyond
any ceiling is refused atomically. No expiry pruning frees these slots.
`consumed_operations` is zero in this version. A later durable submission
registry charges one slot for each new admitted submission identity, including
saved terminal validation rejections, and none for exact retries, reads,
administration, or legacy operations. The TTL auth replay ledger is not that
submission registry. Rejection from its admission callback leaves state
unchanged.

## 5. Failure and authority boundary

Invalid new envelope, signature, key, path, mask, wrapper or grant time returns
HTTP 400 `invalid_argument`. Request-auth failure returns 401
`unauthenticated`. Generation/identity renewal, ref mismatch, repeated new
revoke and nonce conflict return 409 `conflict`. Registry capacity returns
429 `resource_exhausted`; outer oversized body 413 `resource_exhausted`;
compressed or non-JSON body 415 `unsupported_media_type`. Missing/corrupt
policy, identity mismatch, registry corruption, configuration or storage
failure return 503 `unavailable`. Responses expose no ref values or backend
diagnostics. A current signature-valid but unregistered grant has no
authority. Policy replacement increments the repository-wide generation,
including a no-op replacement, invalidating all earlier grant authority.

Grant-only subjects gain no ListRefs, ReadRef, PackExists, DownloadPack,
UploadPack, UpdateRef or AdvanceRefs access. The managed role matrix in
[SPEC-SERVER-ACCESS](SPEC-SERVER-ACCESS.md) remains independent. This version
has no private snapshot disclosure, candidate admission/publication or receipt
signing. The portable offline partial workflow remains valid without a grant.

## 6. Test vectors and invariants

`rust/tests/golden/hosted-workspace-grants/` contains the complete signed
positive `valid.bin`, its sidecar, and BLAKE3 manifest. Consumers read pinned
bytes; `MKIT_WRITE_GOLDEN=1` is the only regeneration gate. Negative tests
mutate complete valid bytes for nonminimal/overflow varints, trailing bytes,
wrong signatures, key/path/mask/context/time, and over-cap inputs. Native and
hosting-specific wasm exports MUST agree on intrinsic facts; actual managed
workerd/SQLite tests anchor live authority and rollback.

| Invariant | Enforcement |
|---|---|
| Signature fact never implies current authority | owner registry lookup and current policy generation |
| Revocation cannot revive an incarnation | append-only generation/status transitions |
| Replayed mutation changes no state twice | auth-v2 ledger and atomic saved reply |
| Invalid intake cannot allocate unbounded memory | outer and inner caps before allocation |
| Generic mkit validity remains policy-neutral | standalone host package and managed-only Worker dependency |
