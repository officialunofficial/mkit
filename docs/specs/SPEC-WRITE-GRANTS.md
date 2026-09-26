---
spec: SPEC-WRITE-GRANTS
version: 1
status: draft-normative
audience: implementers of mkit.transport.v1 servers that restrict writes or serve private repositories, of the ssh and enc serve paths, and of clients, wallets and CLIs that issue, store or present grants
---

# SPEC-WRITE-GRANTS &mdash; namespace owners delegate repository writes and reads

Status: **Draft**. Only the owner-scheme primitives of §4 (Keccak-256,
the EIP-191 digest, secp256k1 recovery, address derivation and the §4.4
low-`s` rules) are implemented; the grant verifier is not. Golden
vectors land with the implementation
([SPEC-CONVENTIONS §5](SPEC-CONVENTIONS.md#5-golden-vectors-and-conformance-tests));
this document lists them in §13.1.

Scope: who may write to, or read from, a repository on a
multi-repository [SPEC-TRANSPORT-CONNECT](SPEC-TRANSPORT-CONNECT.md)
deployment. The auth v2 contract
([SPEC-TRANSPORT-CONNECT §7.1](SPEC-TRANSPORT-CONNECT.md#71-reference-worker))
proves which Ed25519 key signed a request. This document decides whether
that key may act on the named repository
([SPEC-TRANSPORT-CONNECT §7.4](SPEC-TRANSPORT-CONNECT.md#74-repository-addressing)).
It defines the grant statement an owner signs for an Ed25519 key, the
owner signature schemes, epochs and revocation, ref scopes, repository
visibility and signed reads, signed URL tokens, and server-side grants
for the ssh and enc transports. It plugs into the write policy of
[SPEC-TRANSPORT-CONNECT §7.5](SPEC-TRANSPORT-CONNECT.md#75-namespace-and-write-policy)
and does not restate it.

Conformance: an independent implementation MUST be able to produce and
verify every statement, header and token in this document from this
document alone.

Driving issues: mkit#1085 (grants) and mkit#1089 (signed reads, private
repositories, URL tokens).

---

## 1. Model

A repository identity is `namespace "/" name`
([SPEC-TRANSPORT-CONNECT §7.4](SPEC-TRANSPORT-CONNECT.md#74-repository-addressing)).
The **owner** of a namespace controls every repository in it. An owner
may be a key that cannot sign auth v2, for example a secp256k1 wallet
key or a P-256 passkey. The owner therefore signs a **grant**: a
statement that lets one Ed25519 key, the **grantee**, act on a set of
the owner's repositories at a listed set of deployments until an
expiry. The grantee then signs each request with auth v2 as usual.

A grant carries **capabilities**: `write`, `read`, or both. `write`
lets the grantee change refs within the grant's **ref scopes** (§8).
`read` lets the grantee read a private repository (§9).

A grant authorizes a key. It never authorizes an operation. Auth v2
still binds each operation, and its nonce still gives replay protection
for writes.

### 1.1 Named parameters

Every bound in this document is one of the parameters below. A
**protocol constant** is the same at every deployment, because clients
and verifiers at different deployments must agree on it. A **deployment
parameter** is configured per deployment, within the stated constraint.

| Parameter | Kind | Value | Constraint | Used in |
|---|---|---|---|---|
| `GRANT_MAX_LIFETIME_MS` | protocol constant | 2,592,000,000 (30 days) | &mdash; | §3 |
| `EPOCH_STATEMENT_MAX_LIFETIME_MS` | protocol constant | 2,592,000,000 (30 days) | &mdash; | §5.1, §9.1 |
| `MAX_EPOCH_STEP` | protocol constant | 1024 | &mdash; | §5.2 |
| `MAX_CLOCK_LEAD_MS` | protocol constant | 30,000 | Equal to the auth v2 clock lead (SPEC-TRANSPORT-CONNECT §7.1). | §7, §5.2 |
| `MAX_AUDIENCES` | protocol constant | 8 | &mdash; | §3, §5.1, §9.1 |
| `MAX_REF_SCOPES` | protocol constant | 16 | &mdash; | §3 |
| `MAX_STATEMENT_BYTES` | protocol constant | 4,096 | &mdash; | §3, §5.1, §9.1 |
| `MAX_GRANT_HEADER_BYTES` | protocol constant | 8,192 | &mdash; | §4.2, §5.3, §9.1 |
| `epoch_lease` | deployment parameter | 30 s | Greater than `margin`. | §5.4 |
| `margin` | deployment parameter | 5 s | Greater than the worst clock skew between the namespace coordinator and any ref shard's storage backend. | §5.5 |
| `MAX_APPLY_WINDOW` | deployment parameter | 10 s | Less than the auth v2 validity bound of 300 s. | §5.5 |
| `url_token_ttl` | deployment parameter | 15 min | The longest token lifetime the deployment issues. | §9.4 |

The values of `MAX_EPOCH_STEP`, `epoch_lease`, `margin`,
`MAX_APPLY_WINDOW` and `url_token_ttl` are planner defaults and remain
open to review while this document is a draft. The two 30-day lifetimes
are adopted.

---

## 2. Self-certifying namespaces

The namespace grammar is
[SPEC-TRANSPORT-CONNECT §7.4](SPEC-TRANSPORT-CONNECT.md#74-repository-addressing)'s;
this document does not redefine it. Both namespace forms name their
owner directly, so a verifier needs no registry to find the owner.

| Form | Owner |
|---|---|
| `0x` followed by 40 lowercase hexadecimal digits | Any secp256k1 or P-256 key whose derived 20-byte address (§4.1) equals those digits. |
| `ed25519-` followed by 64 lowercase hexadecimal digits | The Ed25519 public key with those bytes. |

No other namespace form exists
([SPEC-TRANSPORT-CONNECT §7.4](SPEC-TRANSPORT-CONNECT.md#74-repository-addressing)).

---

## 3. Grant statement

### 3.1 Canonical encoding

Every statement in this document (the grant here, the epoch statement of
§5.1, the visibility statement of §9.1 and the URL token of §9.4) uses
the same text rules:

- The statement is a sequence of ASCII fields joined by a single line
  feed (`0x0A`). There is no final line feed, no carriage return, and no
  byte outside `0x21..=0x7E` inside a field. No field is empty.
- A **decimal** field is `0` or a nonzero digit followed by digits, with
  no sign and no leading zero. An epoch is at most
  18446744073709551615 (the largest unsigned 64-bit integer). A
  millisecond timestamp is at most 9223372036854775807 (the largest
  signed 64-bit integer, the auth v2 range).
- A **hex** field is lowercase hexadecimal of the stated length.
- A **list** field joins its items with the stated separator. Its items
  are in strictly ascending byte order, so a list has no duplicates and
  exactly one encoding.
- The whole statement is at most `MAX_STATEMENT_BYTES` (4,096) bytes.

### 3.2 Fields

A grant is eleven fields:

```text
mkit-write-grant:v1
<namespace>
<repository scope>
<grantee>
<capabilities>
<audiences>
<ref scopes>
<epoch>
<created epoch milliseconds>
<expiry epoch milliseconds>
<nonce>
```

| Field | Rule |
|---|---|
| domain | The literal `mkit-write-grant:v1`. |
| `namespace` | A self-certifying namespace (§2). |
| `repository scope` | Either one repository in `namespace`, written `<namespace>/<name>` with `name` from the §7.4 grammar, or the whole namespace, written `<namespace>/*`. No other wildcard exists. |
| `grantee` | The grantee's Ed25519 public key as 64 lowercase hexadecimal digits. |
| `capabilities` | Exactly one of `read`, `read,write`, `write`. |
| `audiences` | 1 to `MAX_AUDIENCES` (8) deployment origins, joined by `,`, in ascending byte order. Each origin satisfies the auth v2 audience rules of SPEC-TRANSPORT-CONNECT §7.1 exactly: lowercase `http://` or `https://` origin, no userinfo, path, query, fragment, trailing dot or default port. No wildcard exists (D5). A deployment's audience, the value §7 step 5 looks for, MUST be an origin whose host the operator controls, never a loopback address. |
| `ref scopes` | `-` when `capabilities` is `read`. Otherwise 1 to `MAX_REF_SCOPES` (16) entries `<pattern>=<flags>`, joined by `;`, in ascending byte order of the whole entry, with no two entries sharing a pattern. §3.3 defines patterns and flags. |
| `epoch` | Decimal epoch (§5). The grant is valid only while this equals the stored epoch. |
| `created` | Decimal millisecond timestamp. |
| `expiry` | Decimal millisecond timestamp. `expiry` MUST be greater than `created`, and `expiry - created` MUST be at most `GRANT_MAX_LIFETIME_MS` (2,592,000,000). |
| `nonce` | 32 random bytes as 64 lowercase hexadecimal digits. It makes each grant distinct. It is not a replay record. |

The `repository scope` MUST name the same namespace as the `namespace`
field.

### 3.3 Ref scope entries

```abnf
ref-scope  = pattern "=" flags
pattern    = ref-name / ref-name "/*"   ; ref-name: SPEC-REFS §3
flags      = 1*4flag                    ; a non-empty subsequence of "cufd", in that order
flag       = "c" / "u" / "f" / "d"
```

- An **exact pattern** is a ref name valid under
  [SPEC-REFS §3](SPEC-REFS.md#3-ref-name-grammar). It matches that ref
  only.
- A **prefix pattern** is a valid ref name `P` followed by `/*`. It
  matches every ref whose name begins with `P/`, at any depth. The single
  trailing `*` is the only wildcard; a bare `*` is not a pattern.
- A pattern MUST NOT be, or begin with, `refs/mkit/packmap/`. Packmap
  refs are never matched directly; §8.3 covers them through their
  branch.
- Flags: `c` create, `u` update, `f` force, `d` delete. §8 defines what
  each permits.

**Why the separators are unambiguous.** SPEC-REFS §3 allows only ASCII
letters, digits, `.`, `_`, `-` and `/` in a ref name, and forbids `*`,
`:` and every other punctuation. So `=`, `;`, `,` and `*` never occur
inside a ref name, and a pattern ends at its only `=`. An auth v2 origin
contains only lowercase letters, digits, `.`, `-`, `:`, `/`, `[` and
`]`, so `,` never occurs inside an origin. Capability names contain no
`,`. No field contains a line feed.

### 3.4 Grant id and example

The **grant id** is the BLAKE3 of the canonical statement bytes, as 64
lowercase hexadecimal digits. It does not cover the scheme or the
signature. Servers SHOULD log it with each request it authorizes. The
logged grant id is not an audit binding: auth v2 does not sign the grant
(§4.2), so the id records which grant the server accepted, not which
grant the signer chose.

An example grant (illustrative, not a test vector):

```text
mkit-write-grant:v1
0x8ba1f109551bd432803012645ac136ddd64dba72
0x8ba1f109551bd432803012645ac136ddd64dba72/website
3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29
read,write
https://git.example.com,https://git.example.org
refs/heads/main=cu;refs/heads/wip/*=cufd
0
1790000000000
1792592000000
9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
```

### 3.5 Parser rejections

A verifier MUST reject a grant that has any of these, and MUST NOT
repair it:

- a field count other than eleven, an empty field, a final line feed,
  a carriage return, or a byte outside the §3.1 range;
- a domain other than `mkit-write-grant:v1`;
- a namespace or repository identity outside the §7.4 grammar, or a
  repository scope in another namespace;
- a decimal with a sign, a leading zero, or a value out of range;
- uppercase or wrong-length hexadecimal;
- an unknown capability, or capabilities not in the canonical spelling;
- an audience that fails the auth v2 origin rules, a `*` anywhere in the
  audience list, more than 8 audiences, or audiences out of order or
  duplicated;
- ref scopes that are not `-` for a `read` grant, or `-` for a grant with
  `write`;
- a pattern outside §3.3, a pattern under `refs/mkit/packmap/`, an
  unknown flag, flags out of the `cufd` order or repeated, more than 16
  entries, entries out of order, or two entries with one pattern;
- `expiry <= created`, or a lifetime above `GRANT_MAX_LIFETIME_MS`;
- a statement longer than `MAX_STATEMENT_BYTES`.

`mkit-write-grant:v1` is a new domain separator
([SPEC-CONVENTIONS §4](SPEC-CONVENTIONS.md#4-domain-separator-and-namespace-naming)).
§12.1 lists every separator this document introduces.

---

## 4. Owner signature schemes

A signed grant is the canonical statement, a scheme token, and a
signature blob. Length-prefixed fields use the
[SPEC-CONVENTIONS §3](SPEC-CONVENTIONS.md#3-wire-encoding-notation)
layout (`[u32 LE length][bytes]`). The same schemes sign epoch
statements (§5.1): read "statement" below as either.

| Scheme | Signed message | Blob | Owner identity |
|---|---|---|---|
| `ed25519` | The 32-byte BLAKE3 of the canonical statement. Verification uses the strict predicate of [SPEC-SIGNING §1](SPEC-SIGNING.md#1-signing-primitives). | The 64-byte signature. | The public key. Valid only for an `ed25519-` namespace. |
| `secp256k1-eip191` | The EIP-191 version `0x45` personal message: the bytes `"\x19Ethereum Signed Message:\n"`, the statement's byte length in decimal ASCII, then the statement bytes. The digest is the Keccak-256 of that message. | 65 bytes: `r` (32 bytes, big-endian), `s` (32 bytes, big-endian), then `v` in {27, 28}. | The address (§4.1) of the public key recovered from `r`, `s` and recovery id `v - 27`. Valid only for a `0x` namespace. |
| `webauthn-p256` | A WebAuthn assertion (§4.3). ECDSA P-256 with SHA-256 over `authenticatorData` followed by the SHA-256 of `clientDataJSON`. | Four length-prefixed fields, in order: the public key, exactly 64 bytes (`x` then `y`, each 32 bytes big-endian); `authenticatorData`; `clientDataJSON`; and the 64-byte signature `r‖s`, each 32 bytes big-endian. Nothing follows the fourth field. | The address (§4.1) of the public key. Valid only for a `0x` namespace. |

The `secp256k1-eip191` scheme signs the readable statement, not a hash,
so a wallet shows the owner what it grants.

A deployment advertises the schemes it accepts in `GetServerInfo`'s
`grant_schemes`
([SPEC-TRANSPORT-CONNECT §2.1](SPEC-TRANSPORT-CONNECT.md#21-getserverinfo)),
using the scheme tokens above. A signed statement whose scheme is not
advertised fails verification.

### 4.1 Address derivation

The 20-byte address of a secp256k1 or P-256 public key is the last 20
bytes of the Keccak-256 of its 64 uncompressed coordinate bytes (`x`
then `y`, each 32 bytes big-endian, without a prefix byte). The
namespace digits are the lowercase hexadecimal of those 20 bytes, with
no mixed-case checksum. A verifier MUST reject a public key that is not
a valid point on its curve, including the point at infinity.

Keccak-256 is the original Keccak submission with `0x01` padding, as
Ethereum uses it, not FIPS 202 SHA3-256.

### 4.2 Header encoding

A client presents a signed grant in one header:

```text
X-Write-Grant: <statement>.<scheme>.<blob>
```

- `<statement>` and `<blob>` are base64url without padding
  ([RFC 4648 §5](https://www.rfc-editor.org/rfc/rfc4648#section-5)). A
  decoder MUST reject padding, characters outside the base64url
  alphabet, and non-zero unused trailing bits, so each value has one
  encoding.
- `<scheme>` is a scheme token from §4. `.` occurs in neither alphabet,
  so the value splits at its two `.` characters.
- The header value MUST NOT exceed `MAX_GRANT_HEADER_BYTES` (8,192)
  bytes. A request carries at most one `X-Write-Grant` header.
- The header carries read grants too, despite its name.
- `X-Write-Grant` is **not** part of the auth v2 canonical string. The
  auth v2 signature does not bind the grant or its id. A substituted
  grant must still name the same grantee (§7 step 9) and pass every
  other check, so substitution can only exchange one of the signer's
  valid authorizations for another. A retried write whose grant header
  changed returns the saved result, as any replay does. The admission
  specification lists the header as hard-reserved, so an admission
  helper can never set it.

A request on the part path
([SPEC-TRANSPORT-CONNECT §7.6](SPEC-TRANSPORT-CONNECT.md#76-upload-tickets-and-resumable-parts))
does not run the Authorizer, so a server ignores `X-Write-Grant` there.
A request that carries `X-Write-Grant` without auth v2 headers is
`unauthenticated`: a grant authorizes a signer, and there is none.

### 4.3 WebAuthn rules

For `webauthn-p256`, the verifier MUST check all of these:

1. The public-key field is exactly 64 bytes, and the signature field is
   exactly 64 bytes. `authenticatorData` is at least 37 bytes. Its flags byte (offset 32)
   has the user-present bit (`0x01`) set. User verification and the
   signature counter are not checked; the verifier is stateless.
2. `clientDataJSON` is a JSON object
   ([RFC 8259](https://www.rfc-editor.org/rfc/rfc8259)) with no
   duplicate member names at any depth. Its `type` member is the string
   `webauthn.get`. Its `challenge` member is exactly the string of 43
   characters that is the unpadded base64url of the 32-byte BLAKE3 of
   the canonical statement. `crossOrigin`, if present, is `false`. A
   `topOrigin` member is rejected.
3. The signature is verified over the exact received `clientDataJSON`
   bytes, never a reserialization.
4. The first 32 bytes of `authenticatorData` equal the SHA-256 of a
   relying-party id the deployment has configured, and the `origin`
   member of `clientDataJSON` equals, byte for byte, an origin the
   deployment has configured for that relying party.

A deployment that has configured no relying party MUST NOT accept, or
advertise, `webauthn-p256`. A passkey signs only for its own relying
party; §12 covers relying parties that sign for other sites.

### 4.4 Low-S signatures

ECDSA signatures are malleable: `(r, s)` and `(r, n - s)` both verify.
Both ECDSA schemes therefore fix one form.

- For `secp256k1-eip191`, `r` and `s` MUST be in `[1, n - 1]` and `s`
  MUST be at most `n / 2`, where `n` is the secp256k1 group order. A
  verifier MUST reject a high-`s` signature and MUST NOT normalize it.
  A client that receives a high-`s` signature from a wallet MUST
  replace `s` with `n - s` and flip `v` between 27 and 28 before
  encoding. A client that receives `v` in {0, 1} adds 27.
- For `webauthn-p256`, authenticators return DER signatures that may be
  high-`s`. A client MUST decode the DER into the raw 64-byte `r‖s`
  form and normalize `s` to at most `n / 2` (the P-256 group order `n`)
  before building the blob. A verifier MUST reject a signature whose
  `r` or `s` is outside `[1, n - 1]`, or whose `s` exceeds `n / 2`, and
  MUST NOT normalize it.

---

## 5. Epochs and revocation

Each namespace has an **epoch** at each deployment: an unsigned 64-bit
integer that starts at 0. The namespace coordinator stores it
authoritatively (D34), and it is persisted as durably as refs. It never
decreases. A grant is valid only while its `epoch` field **equals** the
stored epoch. Raising the epoch therefore revokes every grant in the
namespace at once. To revoke one grant, the owner raises the epoch and
issues new grants to the keys it keeps.

Equality, not "at least", means a grant for a future epoch is not yet
valid. An owner can issue grants for epoch `e + 1` before raising the
epoch to `e + 1` (informative).

The epoch applies to grants only. A write authorized by the namespace's
own Ed25519 key, or by a deployment-defined authority source, does not
depend on it.

### 5.1 Epoch statement

The owner raises the epoch with an epoch statement of seven fields,
encoded by the §3.1 rules:

```text
mkit-write-epoch:v1
<namespace>
<new epoch>
<audiences>
<created epoch milliseconds>
<expiry epoch milliseconds>
<nonce>
```

- `namespace` is a self-certifying namespace (§2).
- `new epoch` is a decimal epoch.
- `audiences` follows the grant's audience rules (§3.2): 1 to 8
  canonical origins, ascending, no wildcard. It MUST contain the
  deployment that verifies it.
- `created` and `expiry` are decimal millisecond timestamps with
  `created < expiry` and `expiry - created` at most
  `EPOCH_STATEMENT_MAX_LIFETIME_MS` (2,592,000,000).
- `nonce` is 64 lowercase hexadecimal digits of fresh randomness.

The owner signs it with any scheme valid for the namespace (§4), and it
travels in the §4.2 encoding `<statement>.<scheme>.<blob>`.
`mkit-write-epoch:v1` is a new domain separator. The §3.5 rejections
apply with the field count seven.

### 5.2 Acceptance

A deployment accepts an epoch statement, and stores `new epoch`, only if
all of these hold:

1. It decodes and parses (§4.2, §5.1).
2. The scheme is advertised, valid for the namespace form, and the
   signature verifies (§4).
3. The recovered or derived owner equals the namespace.
4. The deployment's own audience is in `audiences`.
5. `created <= now + MAX_CLOCK_LEAD_MS` and `now < expiry`, on the
   verifier's clock.
6. The namespace policy serves the namespace
   ([SPEC-TRANSPORT-CONNECT §7.5](SPEC-TRANSPORT-CONNECT.md#75-namespace-and-write-policy)).
7. `stored < new epoch <= stored + MAX_EPOCH_STEP`, computed without
   overflow. A namespace whose epoch is within `MAX_EPOCH_STEP` of the
   64-bit maximum can still be raised to that maximum and no further.

If `new epoch` equals the stored epoch and checks 1 to 6 pass, the
statement is a retry: the deployment changes nothing and answers as for
the statement that set the epoch (§5.3). Any other failure is
`permission_denied`.

The bounded increment stops a single statement from pushing the epoch
to the 64-bit maximum and freezing the namespace's grants for good. The
expiry and the audience list stop a captured statement from being
replayed later, or at another deployment.

### 5.3 RPCs

Both RPCs act on a namespace, not a repository, and their proto lands
with the M2 implementation, additively.

`GetGrantEpoch` and `SetGrantEpoch` are namespace RPCs. They carry no
`X-Repository`, and a client MUST NOT sign them.

- **`GetGrantEpoch(namespace)`** is a unary read. It requires no
  authentication; a server MUST answer it without auth v2 headers. It
  returns the namespace's stored epoch, and 0 for a namespace with no
  stored epoch. The answer does not reveal whether the namespace holds
  any repository.
- **`SetGrantEpoch(statement)`** is a unary call whose request carries
  the signed epoch statement in the §4.2 encoding, at most
  `MAX_GRANT_HEADER_BYTES` (8,192) bytes. The owner signature
  is its only authorization; it needs no auth v2 envelope and records
  no replay entry, because a statement is idempotent. It returns the
  stored epoch **only after** the revocation is complete (§5.4). While
  completion is pending it MAY return retryable `unavailable` with a
  retry-after hint. The new epoch is already stored at that point, and
  retrying the same statement is idempotent (§5.2).

### 5.4 Epoch leases and the apply check

A grant's epoch is checked twice. The Authorizer compares it with the
stored epoch (§7 step 11). The same epoch is then carried into the
atomic `apply` that commits the write, as a precondition: the write
commits only if the epoch it was authorized under still equals the
stored epoch at commit. A revocation that races an in-flight write
therefore rejects the write at `apply`, with `permission_denied`,
nothing committed, and any reservation aborted.

A **single-store backend**, one that holds the epoch and the refs in
one transactional store or under one lock, checks the epoch inside the
same transaction or lock as the ref write. It needs no leases.

A **sharded backend** keeps each ref's state in a ref shard, apart from
the coordinator
([SPEC-TRANSPORT-CONNECT §7.9](SPEC-TRANSPORT-CONNECT.md#79-consistency-and-paging)).
It MUST use epoch leases:

- A ref shard caches the epoch, and MAY use its cached epoch only while
  it holds an **epoch lease** from the coordinator. A lease lasts
  `epoch_lease` (default 30 s) and has an expiry, `lease_expires`, on
  the coordinator's clock. The coordinator records each shard it has
  leased to until that lease expires.
- A shard with no unexpired lease renews on its next write or
  epoch-dependent read. The renewal returns the current epoch.
- `SetGrantEpoch` stores the new epoch, pushes it to every currently
  leased shard, and reports success only when each of those shards has
  acknowledged the new epoch or its lease has expired. Completion
  therefore takes at most one lease interval, and costs O(active
  shards), not O(refs).
- An idle shard, one with no lease, can never apply under a stale
  epoch, because it renews first.
- The coordinator MUST durably record a lease before returning it. It
  MUST serialize lease grants with epoch changes (one lock or a
  serializable transaction), so the leased-shard set `SetGrantEpoch`
  waits on includes every lease granted at the old epoch. A coordinator
  that lost its lease table MUST NOT report completion until
  `epoch_lease + margin` after it resumes.
- A shard uses its cached epoch or visibility to authorize a read only
  until `lease_expires - margin` on its own clock.
- `SetGrantEpoch` completion also waits until every other cached copy of
  the epoch has expired or been invalidated.

### 5.5 Commit deadline

Acknowledgement or lease expiry alone is not enough. A write planned
under a valid lease can reach its shard late (queueing, a CPU stall, a
restart), after the lease expired and after the coordinator reported
the revocation, in particular when the push of the new epoch to that
shard failed.

Every write batch on a sharded backend therefore MUST carry a **commit
deadline**, and the batch's `apply` MUST carry a `NotAfter(deadline)`
precondition:

```text
deadline = min(lease_expires - margin, plan_time + MAX_APPLY_WINDOW)
```

- `lease_expires` is the expiry of the lease the write was planned
  under, and `plan_time` is when the server planned the batch.
- The **storage backend** that commits the batch evaluates
  `NotAfter(deadline)` against **its own clock at commit**, atomically
  with the batch's other preconditions. A batch whose deadline has
  passed commits nothing.
- `margin` (default 5 s) MUST exceed the worst clock skew between the
  coordinator and any shard's storage backend.
- `MAX_APPLY_WINDOW` (default 10 s) bounds the time from planning to
  commit.

A missed deadline is `unavailable`, and a retry with the same nonce is
safe
([SPEC-TRANSPORT-CONNECT §5](SPEC-TRANSPORT-CONNECT.md)). The server
MAY re-plan the write once within the envelope's validity. A re-plan
renews the lease, sees the new epoch, and rejects a revoked grant with
`permission_denied`.

### 5.6 Guarantee

Once `SetGrantEpoch` reports success, no write authorized under the old
epoch commits afterwards, whatever its delivery delay. Proof sketch:
such a write's deadline is at most `lease_expires - margin` for a lease
granted before the revocation completed. The coordinator reports success
only after every such lease has been acknowledged at the new epoch, in
which case the shard's `apply` precondition fails, or has expired on
the coordinator's clock. Because `margin` exceeds the skew, the shard's
backend sees the deadline pass before, or when, the coordinator sees
the lease expire.

Reads have no `apply`. A read of a private repository authorized by a
grant (§9.3) compares the grant's epoch with the leased epoch when the
read is authorized, and a shard uses that leased epoch only until
`lease_expires - margin` on its own clock (§5.4). With the completion
rules of §5.4, after `SetGrantEpoch` reports success, no read that
begins afterwards is authorized by an old-epoch grant. A read authorized
earlier, for example a long `DownloadPack` stream, may finish.

The same lease carries the coordinator's other cached configuration,
including repository visibility (§9.1).

---

## 6. Server policy

`namespace_policy` and `write_policy` are
[SPEC-TRANSPORT-CONNECT §7.5](SPEC-TRANSPORT-CONNECT.md#75-namespace-and-write-policy)'s.
Under `write_policy = owner`, a **write** to `<ns>/<name>` is authorized
by exactly one of these paths:

1. **Owner key.** `ns` has the `ed25519-` form and the auth v2 signer is
   that key.
2. **Grant.** The request's grant, from the `X-Write-Grant` header or,
   on ssh and enc, from the server-side registry (§10), passes every
   check in §7.
3. **Authority source.** A deployment-defined source authorizes the
   signer, as SPEC-TRANSPORT-CONNECT §7.5 rule 3 describes, failing
   closed.

A **read** of a private repository (§9) is authorized by the same three
paths, with the `read` capability in place of `write`. A read of a
public repository needs no authorization.

A client MUST NOT attach a grant when it signs with the namespace key.
When a request carries a grant, the grant is the only path the server
evaluates for it. A write whose grant fails verification is
`permission_denied` even if the signer's key would have authorized it
through another path, so a client never mistakes a broken grant for a
working one. On a read of a private repository, a failing grant is
`not_found` (§9.3). On ssh and enc no grant is carried, and any of the
three paths may authorize (§10).

A grant with `write` does not imply `read`. A client that pushes to a
private repository reads its refs first, so an issuer SHOULD grant
`read,write` for a private repository (informative).

`SetGrantEpoch` is authorized only by the owner signature on its
statement (§5.3). `SetRepoVisibility` is authorized only by the owner
key, an authority source, or an owner-signed visibility statement
(§9.1); a grant never authorizes it. `GetGrantEpoch` and
`GetServerInfo` need no authorization.

**Rollout (informative).** Before the M2 implementation, only the owner
key and authority-source paths exist, so only `ed25519-` owners, or
keys an authority source names, can write. `0x` owners need grants.

---

## 7. Verification order

A server verifies a presented grant in this order, and stops at the
first failure. On a write, every failure is `permission_denied`. On a
read of a private repository, every failure is `not_found` (§9.3).

1. Decode the header (§4.2) and parse the statement (§3).
2. The statement's `namespace` equals the namespace of `X-Repository`.
3. The scheme is advertised and valid for the namespace form, and the
   owner signature verifies under it (§4), including the low-S and
   WebAuthn rules.
4. The recovered or derived owner equals the namespace (§2, §4.1).
5. The deployment's own audience is in `audiences`. The deployment's
   own audience is its configured auth v2 audience (SPEC-TRANSPORT-CONNECT
   §7.1), compared byte for byte.
6. The repository scope covers `X-Repository`: it equals it, or it is
   `<namespace>/*`.
7. The capabilities cover the operation: `write` for the write
   procedures (`UpdateRef`, `AdvanceRefs`, `BeginUpload`, an
   `UploadPack` without a ticket), `read` for a
   read of a private repository (§9.2 lists the read procedures).
8. For writes, the ref scopes cover every ref the RPC names (§8).
9. The `grantee` equals the auth v2 signer (`X-Public-Key`), or, on ssh
   and enc, the transport principal (§10).
10. `created <= now + MAX_CLOCK_LEAD_MS` and `now < expiry`, on the
    server's clock.
11. The grant's `epoch` equals the stored epoch as the server reads it
    now: under an unexpired lease on a sharded backend (§5.4). On a
    write, the same epoch is also carried into `apply` as a
    precondition, together with the commit deadline (§5.5).

Steps 1 to 10 read no server state. Because each failure yields the
same code, a server MAY evaluate them in another order, for example the
cheap comparisons before the signature. Step 11 reads state and comes
last.

All of this completes after authentication and the replay-record and
saved-reply check of SPEC-TRANSPORT-CONNECT §7.1, and before any quota,
admission, reservation, or replay-record allocation
([SPEC-TRANSPORT-CONNECT §7.5](SPEC-TRANSPORT-CONNECT.md#75-namespace-and-write-policy),
"Order"). A rejection allocates nothing. A server MAY cache the outcome of steps
1, 3 and 4 by exact header bytes, and evaluates every other step on each
request.

---

## 8. Ref scopes and packmap coverage

Ref scopes bound what a grant's `write` capability may do to each ref
(D6). They apply only to grant-authorized writes. The owner key and an
authority source are not limited by ref scopes.

### 8.1 Effective flags

The **effective flags** of a grant for a ref `R` are the union of the
flags of every entry whose pattern matches `R` (§3.3). A ref that no
pattern matches has no flags, and every change to it is
`permission_denied`.

### 8.2 Flags per change

For each ref an `UpdateRef` or `AdvanceRefs` changes, the server
determines the required flag from the request and the ref's state at
`apply`:

| Change | Required flag |
|---|---|
| The ref is absent at `apply` and the request creates it (`REF_EXPECTATION_MISSING`, or `REF_EXPECTATION_ANY` on an absent ref). | `c` |
| `REF_EXPECTATION_MATCH` with a new value that is a descendant of the expected value (a fast-forward). | `u` or `f` |
| `REF_EXPECTATION_MATCH` with a new value that is not a fast-forward, or whose ancestry the server does not check. | `f` |
| `REF_EXPECTATION_ANY` on a present ref. | `f` |
| Deletion ([SPEC-TRANSPORT-CONNECT §7.8](SPEC-TRANSPORT-CONNECT.md#78-ref-deletion)). | `d` |

- `update` without `force` permits fast-forwards only, and checking a
  fast-forward needs indexed mode, where the server decodes and indexes
  pushed objects. A server without indexed mode cannot check one. It
  MUST therefore reject, at verification, a change whose effective
  flags contain `u` but not `f` and that would need that check, rather
  than allow a non-fast-forward silently.
- For `REF_EXPECTATION_ANY`, whether the ref is present is known only at
  `apply`. The server carries the required flag into `apply` as a
  precondition next to the epoch: the batch commits only if the flag the
  ref's state requires is in the effective flags. A failure there is
  `permission_denied` with nothing committed.
- The `d` flag governs ref deletion through `UpdateRef` and
  `AdvanceRefs`. A deployment MAY refuse deletion outright
  (SPEC-TRANSPORT-CONNECT §7.8).
- `BeginUpload` names the ref its ticket will advance. It needs `write`
  and a ref-scope entry that matches that ref, with any flag. It changes
  no ref, so no flag is required.

### 8.3 Packmap coverage

A branch's packmap ref travels with its head. For a grantee:

- A scope that matches `refs/heads/<x>` covers `refs/mkit/packmap/<x>`.
- An `AdvanceRefs` is authorized only when its head ref is
  `refs/heads/<x>` and its packmap ref is exactly
  `refs/mkit/packmap/<x>`. The flags are evaluated on the head change
  only.
- Packmap writes are allowed only together with the covered head, in
  one `AdvanceRefs`. A direct `UpdateRef` on any ref under
  `refs/mkit/packmap/` is `permission_denied`.
- A head-only `UpdateRef` on `refs/heads/<x>` is authorized under the
  head's flags. It consumes no ticket and needs no packmap scope.

Why the packmap is not checked as its own ref: a push normally appends
one node to the packmap chain, but a re-baseline writes a fresh,
self-contained chain that is not an append of the old one (informative:
the client's packmap re-baseline). A packmap ref therefore has no
fast-forward relation of its own that a flag could express. Binding it
to its head, in the head's atomic advance, keeps the head and the
packmap consistent and lets the head's flags stand for both.

---

## 9. Reads and private repositories

### 9.1 Visibility

Each repository has a visibility, `public` or `private`, stored in the
namespace coordinator. It is `public` unless changed.

**`SetRepoVisibility(repository, visibility)`** is the only way to
change it. It is a unary call, authorized only by the owner key (§6
path 1), an authority source, or an owner-signed visibility statement.
A grant never authorizes it.

- Under the owner key or an authority source, the request is signed
  with auth v2 and a `body:` commitment, and is replay-protected like
  any write (SPEC-TRANSPORT-CONNECT §7.1).
- Otherwise the request carries a visibility statement in the §4.2
  encoding, at most `MAX_GRANT_HEADER_BYTES` (8,192) bytes, signed with
  any §4 scheme valid for the namespace. It needs no auth v2 envelope,
  and `X-Repository` MUST equal the statement's repository. The
  statement is seven fields, encoded by the §3.1 rules:

  ```text
  mkit-repo-visibility:v1
  <repository>
  <visibility>
  <audiences>
  <created epoch milliseconds>
  <expiry epoch milliseconds>
  <nonce>
  ```

  `repository` is a full identity `<namespace>/<name>` (§7.4);
  `visibility` is `public` or `private`; `audiences` follows the grant's
  audience rules (§3.2); `created < expiry`, with `expiry - created` at
  most `EPOCH_STATEMENT_MAX_LIFETIME_MS`; `nonce` is 64 lowercase
  hexadecimal digits. The deployment accepts it only if the scheme is
  advertised and the signature verifies (§4), the recovered or derived
  owner equals the repository's namespace, its own audience is in
  `audiences`, `created <= now + MAX_CLOCK_LEAD_MS` and `now < expiry`.
  The deployment stores the last accepted `created` per repository and
  accepts only a greater one; identical bytes are an idempotent retry.
  Any other failure is `permission_denied`.
- On a repository that does not exist, `SetRepoVisibility` records the
  visibility without creating the repository. The repository is created
  by its first authorized write, with the recorded visibility. A client
  that wants a private repository sets `private` before its first push,
  so no content is ever public.

A change to `private` is reported complete only when no read that
begins afterwards can be answered as `public`: every currently leased
shard has acknowledged the change or its lease has expired (§5.4), and
every other cached copy of the visibility the deployment keeps has
expired or been invalidated. While completion is pending the RPC MAY
return retryable `unavailable` with a retry-after hint. A retry of the
same signed operation, or of the same statement bytes, returns success
once complete. A new operation that sets the visibility the repository
already has changes nothing, and succeeds under the same completion
rule.

### 9.2 Signed reads

A signed read is an auth v2 request on a read procedure. It uses the
eight-field contract of SPEC-TRANSPORT-CONNECT §7.1 unchanged:
`<full procedure>` is the read procedure, and the commitment is
`body:` over the exact HTTP request body bytes. For the server-streaming
`DownloadPack`, that is the complete request body, which holds one
enveloped request message. The required headers are the same as for a
unary write.

The read procedures are `ListRefs`, `ReadRef`, `PackExists`,
`DownloadPack` and `IssueObjectUrl`.

- A request that carries any auth v2 header (`X-Envelope-Version`,
  `X-Public-Key`, `X-Signature`) is signed, and the server MUST verify
  the whole envelope. A failure is `unauthenticated`. Envelope
  verification does not depend on whether the repository exists or is
  private, so the code is never an existence oracle.
- A signed read is idempotent. The server checks the validity window
  only: it records no replay entry and looks none up. A client MAY
  re-sign a read on every retry.
- A request with no auth v2 header is anonymous.
- `IssueObjectUrl` MUST be signed; an anonymous one is
  `unauthenticated`.
- `GetServerInfo`, `GetGrantEpoch` and `SetGrantEpoch` stay unsigned
  (§5.3). A client MUST NOT sign them, and a server answers them without
  verifying any auth v2 header on them.

A client that has an auth v2 signer for a remote MUST sign every read
procedure it sends to that remote (D28). Writers need this to be seen as
writers, and so to be served strongly consistent state and, with
quarantine, the unpublished refs. A deployment MAY serve an anonymous
`ReadRef` from a snapshot, but MUST serve a signed `ReadRef` from the
ref's strongly consistent state
([SPEC-TRANSPORT-CONNECT §7.9](SPEC-TRANSPORT-CONNECT.md#79-consistency-and-paging)).

### 9.3 Read authorization

For each read procedure on a repository:

- A repository that does not exist is `not_found`
  (SPEC-TRANSPORT-CONNECT §7.4).
- A `public` repository is readable by every caller, anonymous or
  signed. A presented grant is evaluated only to classify the caller as
  a writer or a reader; a failing grant makes the caller a reader and is
  never an error.
- A `private` repository is readable only by a signed caller authorized
  through §6 with the `read` capability. Any unauthorized read,
  including an anonymous one, a signer with no grant, and a grant that
  fails any §7 step, is `not_found`.

An unauthorized read of a private repository MUST be indistinguishable
from a read of a repository that does not exist: the same Connect code,
message, details and response headers. Its timing SHOULD NOT differ
measurably. `X-Mkit-Ref`
([SPEC-TRANSPORT-CONNECT §7.9](SPEC-TRANSPORT-CONNECT.md#79-consistency-and-paging))
follows the same rule.

Writes are not an oracle: whether a write is authorized never depends on
whether the repository exists or is private, so an unauthorized write
is `permission_denied` in every case.

### 9.4 Signed URL tokens

HTTP object serving (M4) serves private content through short-lived
URL tokens. `IssueObjectUrl` mints them.

**Request.** `IssueObjectUrl(repository, target, ttl)` is a signed read
(§9.2). `target` is an object id, or a ref and a path. `ttl` is a
requested lifetime in seconds; 0 asks for the default. The caller needs
read access under §9.3, and an unauthorized caller gets `not_found`. The
server does not resolve the target: the token binds the unresolved
target, and serving decides what it resolves to (M4), so issuing a
token reveals nothing about the repository's contents.

**Lifetime.** The token lives `min(ttl, url_token_ttl)` seconds, or
`url_token_ttl` when `ttl` is 0. `url_token_ttl` defaults to 15 minutes
and is the longest lifetime the deployment issues; a larger request is
clamped, never refused.

**Token statement.** Eight fields, encoded by the §3.1 rules:

```text
mkit-url-token:v1
<audience>
<repository>
<target>
<epoch>
<issued epoch milliseconds>
<expiry epoch milliseconds>
<key id>
```

| Field | Rule |
|---|---|
| `audience` | The issuing deployment's auth v2 audience. |
| `repository` | The full repository identity (§7.4). |
| `target` | `object:<64 lowercase hex object id>`, or `path:<ref>:<path>` where `<ref>` is a full ref name valid under SPEC-REFS §3 and `<path>` is the unpadded base64url of the UTF-8 path. The path is 1 to 1,024 bytes of tree entry names joined by `/`, with no leading, trailing or repeated `/` and no `.` or `..` entry. Ref names contain no `:`, so the field splits at its first two `:`. |
| `epoch` | The namespace's stored epoch when the token was issued (§5). |
| `issued`, `expiry` | Decimal millisecond timestamps, `issued < expiry`, `expiry - issued` at most `url_token_ttl`. |
| `key id` | The first 16 bytes of the BLAKE3 of the signing key's 32-byte public key, as 32 lowercase hexadecimal digits. |

**Signature and encoding.** The token is
`<statement>.<signature>`: the unpadded base64url of the statement, a
`.`, and the unpadded base64url of a 64-byte Ed25519 signature over the
32-byte BLAKE3 of the statement. Verification uses the strict predicate
of [SPEC-SIGNING §1](SPEC-SIGNING.md#1-signing-primitives). `mkit-url-token:v1` is a new
domain separator.

**Key.** A token is signed by a **dedicated deployment URL-token key**:
an Ed25519 key used for nothing else. It MUST NOT be the receipt key,
the hook key, the admin key, or any key that signs auth v2. The
deployment rotates it by key id. It keeps a retired key in its
verification set for at least `url_token_ttl` after retirement, and
publishes the set with key ids (the publication format is specified
with HTTP serving, M4).

**Verification** (the interface HTTP serving calls). A verifier accepts
a token for a request only if it decodes by the §4.2 base64url rules;
the statement parses; `key id` names a key in the deployment's
verification set; the signature verifies under that key; `audience` is
the deployment's own; `repository` and `target` equal the request's,
byte for byte; `epoch` equals the stored epoch, read as §5.6 requires
for reads; and `now < expiry`. Anything else is `not_found` for a
private repository, as in §9.3. Serving always resolves the target in
the published view.

**Response.** `IssueObjectUrl` returns the token and its expiry. The URL
form that carries a token, and cache headers, are specified with HTTP
serving (M4).

---

## 10. ssh and enc principals

The frozen `mkit.rpc.v1.ssh` protocol, and the enc transport, carry no
`X-Write-Grant` header, and this document does not change them. Grants
for their principals are registered server-side instead.

- The **transport principal** is an Ed25519 key: on ssh, the key named
  by the forced command's principal argument; on enc, the peer's static
  key.
- The deployment operator registers a signed grant (in the §4.2
  encoding) for a principal (informative: an operator command in M2,
  which the M5 admin API later wraps). Registration verifies §7 steps
  1, 3, 4 and 5 and rejects a grant whose grantee is not the principal.
- No grant is carried on ssh and enc, so any of the three §6 paths may
  authorize a request: the owner key when the principal is the
  namespace's `ed25519-` key, an authority source, or a registered grant.
- At identity mapping, the server looks up the registered grants whose
  grantee is the principal. The request is authorized through the grant
  path (§6) if one of them passes every §7 step for it, with the
  transport principal as the signer (step 9) and the repository from
  the transport's path argument as `X-Repository`.
- The same repository scope, capability, ref-scope, expiry and epoch
  rules apply, including the epoch check at `apply` (§5.4). A backend
  serving ssh from a single store checks the epoch under the same lock
  as the ref write.
- A deployment that accepts registered grants MUST have an auth v2
  audience, even if it serves no HTTP, and a registered grant MUST list
  it (§7 step 5). The audience MUST be an origin whose host the operator
  controls, never a loopback address. This keeps a grant issued for one deployment from
  being registered at another.
- The epoch of an ssh-only deployment is raised by applying an epoch
  statement through the operator, with the §5.2 acceptance rules
  (informative).

---

## 11. Error codes

| Condition | Connect code |
|---|---|
| A missing, malformed or expired auth v2 envelope, a bad signature, or `X-Repository` differing from the signed repository, on a write or a signed read | `unauthenticated` |
| `X-Write-Grant` on a request without auth v2 headers | `unauthenticated` |
| On a write: a grant that is missing where one is needed, malformed, badly signed, for another owner or audience, expired or not yet valid, out of repository or ref scope, without the needed capability, or at a different epoch | `permission_denied` |
| An epoch mismatch detected at `apply` (§5.4) or a ref flag that fails at `apply` (§8.2). Nothing is committed and the reservation is aborted. | `permission_denied` |
| An epoch statement that fails §5.2, or a visibility statement that fails §9.1 | `permission_denied` |
| `SetRepoVisibility` from a principal that is neither the owner key nor authorized by an authority source, without a visibility statement | `permission_denied` |
| A missed commit deadline (§5.5) | `unavailable` (SPEC-TRANSPORT-CONNECT §5) |
| `SetGrantEpoch` or `SetRepoVisibility` whose completion is pending | `unavailable`, with a retry-after hint |
| Any unauthorized read of a private repository, including every grant failure on it | `not_found` |
| A read of a repository that does not exist | `not_found` |

`unauthenticated` means the request did not prove who sent it.
`permission_denied` means it did, and that identity may not write. A
client maps both to `AccessDenied`
([SPEC-TRANSPORT-CONNECT §5](SPEC-TRANSPORT-CONNECT.md)).

---

## 12. Security considerations

- A grant without the grantee's Ed25519 private key authorizes nothing.
  Its disclosure is harmless.
- A grant is reusable until it expires or the epoch rises. Operation
  replay protection stays with the auth v2 nonce.
- The audience list keeps a grant, or an epoch statement, from being
  replayed at a deployment the owner did not name (D5). There is no
  wildcard, so a grant can never cover a deployment that did not exist
  when it was signed.
- Ref scopes bound what an agent's key can do if it leaks: a key scoped
  to `refs/heads/wip/*` cannot move `refs/heads/main`.
- Packmap coverage (§8.3) lets a re-baselining push work under a head
  scope, without giving any grantee a direct handle on packmap refs.
- An epoch statement expires and is bounded in size, so a captured
  statement cannot be replayed later at another listed deployment, and
  no statement can freeze a namespace at the 64-bit maximum.
- The epoch check inside `apply`, epoch leases, and the commit deadline
  make a reported revocation exact (§5.6): no write authorized by a
  revoked grant commits after `SetGrantEpoch` succeeds.
- Epoch revocation is namespace-wide by design. It keeps per-namespace
  server state to one integer.
- Epochs are per deployment. To revoke a grant, the owner MUST submit an
  epoch statement to every deployment in the grant's audience list.
  Until then the grant stays valid there.
- Only the owner changes visibility (§9.1). A grant, however narrow its
  ref scopes, cannot make a private repository public.
- The namespace wildcard scope covers repositories that do not exist
  yet. Owners SHOULD prefer single-repository scopes for agents.
- A `webauthn-p256` grant signs a digest, not readable text, so the
  authenticator cannot show the owner what it grants. Owners SHOULD
  issue grants only from an application they trust to build the
  statement. A relying party that signs challenges for other sites, such
  as a hosted wallet, can be asked to sign a grant it cannot display;
  relying-party pinning (§4.3) limits which relying parties count.
- Low-S rules (§4.4) give each ECDSA signature one encoding, so a grant
  id and its signature cannot be varied by a third party.
- Address derivation (§4.1) makes secp256k1 and P-256 owners share one
  namespace space. A collision needs a Keccak-256 second preimage.
- `not_found` for unauthorized private reads (§9.3) keeps private
  repositories from being enumerated.
- A URL token is a bearer credential for one target for at most
  `url_token_ttl`. Its dedicated key limits the damage of a key leak to
  URL tokens. Raising the epoch invalidates every outstanding token in
  the namespace. Serving resolves every token in the published view, so
  a forwarded token never exposes content that only writers see.
- Signing reads reveals the signer's identity to the server. Clients
  sign reads only to the remote they already sign writes to.

### 12.1 Domain separators

This document introduces four domain separators
([SPEC-CONVENTIONS §4](SPEC-CONVENTIONS.md#4-domain-separator-and-namespace-naming)).
Each is the literal first field of its statement and is permanent:

| Separator | Statement |
|---|---|
| `mkit-write-grant:v1` | Grant (§3). |
| `mkit-write-epoch:v1` | Epoch statement (§5.1). |
| `mkit-repo-visibility:v1` | Visibility statement (§9.1). |
| `mkit-url-token:v1` | URL token (§9.4). |

They are distinct from the auth v2 separator `mkit-write:v2` and from
the workspace grant separator `mkit-workspace-grant:v1`.

---

## 13. Out of scope

- The verifier implementation (informative: planned in the attestation
  crate, which gains Keccak-256 and secp256k1 recovery, not the core
  crate), server enforcement, and the proto for `GetGrantEpoch`,
  `SetGrantEpoch`, `SetRepoVisibility` and `IssueObjectUrl`. They land
  in M2.
- The CLI: `mkit grant create`, `list` and `revoke`, and `mkit epoch`
  (M2). Informative: the client grant store lives under the user config
  directory and is never repository-scoped, like the other credential
  and signing keys of [SPEC-CONFIG-SECURITY](SPEC-CONFIG-SECURITY.md).
- HTTP object serving: URL forms, target resolution, reachability, cache
  headers, and the publication of the URL-token key set (M4, mkit#1088).
- The published view and quarantine, which decide what the published
  view contains (M5).
- Owners that no single key controls, for example multisig or contract
  accounts.
- The workspace grant (`mkit-workspace-grant:v1`). It grants workspace
  permissions, not repository access, and stays separate.

### 13.1 Planned golden fixtures (informative)

The implementation adds fixtures under `rust/tests/golden/grants/` and
`rust/tests/golden/url-token/`. They become this document's test
vectors when they land, and this subsection then lists them. They cover
at least: canonical grant and epoch statements with their ids and a
signature for each scheme; an EIP-191 message and recovery; address
derivation for a secp256k1 and a P-256 key; a WebAuthn assertion; a
header value; one rejection for each §3.5 rule, a high-`s` signature
for each ECDSA scheme, a cleared user-present flag, and a scheme on the
wrong namespace form; a URL token; and a signed read.

Landed so far (each pinned by BLAKE3 in the directory's `MANIFEST.txt`):

| Fixture | Pins |
|---|---|
| `rust/tests/golden/grants/eth-primitives.json` | Keccak-256 of the empty string, `abc` and a 4,096-byte statement-shaped input, plus the differing SHA3-256 of the empty string (§4.1); two EIP-191 vectors (§4): the public `Some data` vector and the §3.4 example grant, each with its message, digest, private key, 65-byte `r‖s‖v` signature and recovered address; the high-`s` twin of each, which a verifier rejects and a client normalizes back (§4.4); the address, `x` and `y` of two secp256k1 and two P-256 keys, including `d = 1` on each curve (§4.1); one key per curve with `x ≥ p` whose reduction is on the curve, which a verifier rejects (§4.1); and a P-256 DER signature with high `s`, its low-`s` raw `r‖s`, and seven DER encodings a client rejects: a non-minimal integer, a trailing byte, a negative integer, a 33-byte integer, `r = 0`, `r = n` and a long-form length (§4.4). |

---

## 14. Version history

| Version | Status | Changes |
|---|---|---|
| `1` | draft | Initial grant statement (audiences, ref scopes, capabilities), owner schemes, exact-epoch revocation with bounded epoch statements, epoch leases and the commit deadline, server policy, signed reads, private repositories and URL tokens, and server-side grants for ssh and enc (mkit#1085, mkit#1089). |

---

## 15. Invariants

| Invariant | Enforced by |
|---|---|
| Under `write_policy = owner`, no write succeeds unless the namespace's own key signed it, a valid grant names its signer, or a fail-closed authority source authorizes it. | §6, §7. |
| A grant authorizes only its grantee key, only within its repository and ref scopes and capabilities, only before its expiry, and only while its epoch equals the stored epoch at `apply`. | §7, §5.4, §8. |
| A grant is valid only at the deployments in its audience list. | §3.2, §7 step 5. |
| A packmap ref changes only together with its covered head in one `AdvanceRefs`. | §8.3. |
| A stored epoch never decreases. | §5, §5.2 check 7. |
| A stored epoch changes only by a bounded increment from an unexpired, audience-matching epoch statement. | §5.2. |
| Once `SetGrantEpoch` reports success, no write authorized under the old epoch commits. | §5.4, §5.5, §5.6. |
| A rejected grant allocates no quota, reservation, or replay record. | §7, final paragraph. |
| An unauthorized read of a private repository is indistinguishable from a read of a missing repository. | §9.3. |
| A signed read never creates or consumes a replay record. | §9.2. |
| A URL token is signed only by the dedicated URL-token key, is valid only for its audience, repository and target until its expiry and while its epoch equals the stored epoch, and resolves only in the published view. | §9.4. |
| A repository's visibility changes only through the owner key, an authority source, or an owner-signed visibility statement newer than the last accepted one; never through a grant. | §9.1. |
