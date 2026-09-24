---
spec: SPEC-WRITE-GRANTS
version: 1
status: draft-normative
audience: implementers of mkit.transport.v1 servers that restrict writes, and of clients or wallets that issue grants
---

# SPEC-WRITE-GRANTS &mdash; namespace owners delegate repository writes

Status: **Draft**. No implementation exists yet. Golden vectors land
with the first implementation (SPEC-CONVENTIONS §5); this document
lists none until then.

Scope: who may write to a repository on a
[SPEC-TRANSPORT-CONNECT](SPEC-TRANSPORT-CONNECT.md) deployment. The
auth v2 contract (SPEC-TRANSPORT-CONNECT §7.1) proves which Ed25519 key
signed a write. This document decides whether that key may write to
the named repository (SPEC-TRANSPORT-CONNECT §7.4). It defines
self-certifying namespaces, the grant statement an owner signs for an
Ed25519 key, the owner signature schemes, revocation, and the server
policy.

---

## 1. Model

A repository identity is `namespace "/" name` (SPEC-TRANSPORT-CONNECT
§7.4). The **owner** of a namespace controls every repository in it.
An owner may be a key that cannot sign auth v2 envelopes, for example a
secp256k1 wallet key or a P-256 passkey. The owner therefore signs a
**grant**: a statement that lets one Ed25519 key write to a set of the
owner's repositories until an expiry. The Ed25519 key then signs each
write with auth v2 as usual.

A grant authorizes a key. It never authorizes an operation. Auth v2
still binds each operation, and its nonce still gives replay
protection.

## 2. Self-certifying namespaces

Two namespace forms name their owner directly. A verifier needs no
registry to find the owner.

| Form | Owner |
|---|---|
| `0x` followed by 40 lowercase hexadecimal digits | Any key whose derived 20-byte address (§4) equals those digits. |
| `ed25519-` followed by 64 lowercase hexadecimal digits | The Ed25519 public key with those bytes. |

Both forms match the namespace grammar of SPEC-TRANSPORT-CONNECT §7.4.
A deployment MAY resolve other namespace forms through its own
registry. That resolution is outside this document. Without a resolver,
a server under the `owner` policy (§6) MUST reject a write to any other
namespace form with `permission_denied`.

## 3. Grant statement

A grant is eight newline-separated UTF-8 fields, with no final newline:

```text
mkit-write-grant:v1
<namespace>
<scope>
<grantee>
<epoch>
<created epoch milliseconds>
<expiry epoch milliseconds>
<nonce>
```

- `mkit-write-grant:v1` is a new domain separator (SPEC-CONVENTIONS
  §4). It is distinct from `mkit-write:v2` and from the workspace
  grant domain.
- `namespace` is a self-certifying namespace (§2).
- `scope` is either one repository identity inside `namespace`
  (`<namespace>/<name>`) or the whole namespace (`<namespace>/*`). No
  other wildcard exists.
- `grantee` is the Ed25519 public key as 64 lowercase hexadecimal
  digits.
- `epoch` is a decimal unsigned 64-bit integer with no leading zeros
  (§5).
- `created` and `expiry` are decimal non-negative integers with no
  leading zeros. `expiry` MUST be greater than `created`, and
  `expiry - created` MUST be at most 2,592,000,000 ms (30 days).
- `nonce` is 32 random bytes as 64 lowercase hexadecimal digits. It
  makes each grant distinct. It is not a replay record.

The **grant id** is the lowercase hexadecimal BLAKE3 of the canonical
bytes. Servers SHOULD log it with each write it authorizes.

A verifier MUST reject a statement that has a different field count, a
trailing newline, a noncanonical number, uppercase hexadecimal, or any
field outside these rules.

## 4. Owner signature schemes

A signed grant is the canonical statement, a scheme token, and a
signature blob. Length-prefixed fields use the SPEC-CONVENTIONS §3
layout.

| Scheme | Signed message | Blob | Owner identity |
|---|---|---|---|
| `ed25519` | The 32-byte BLAKE3 of the canonical statement. Strict Ed25519 verification. | 64-byte signature. | The public key. Valid only for an `ed25519-` namespace. |
| `secp256k1-eip191` | The canonical statement as an EIP-191 version `0x45` personal message: `"\x19Ethereum Signed Message:\n"`, the decimal byte length, then the statement bytes, hashed with Keccak-256. | 65 bytes: `r`, `s`, then `v` in {27, 28}. `s` MUST be in the lower half of the curve order. | The address recovered from the signature (§4.1). Valid only for a `0x` namespace. |
| `webauthn-p256` | A WebAuthn assertion whose `clientDataJSON` has `type` `webauthn.get` and `challenge` equal to the unpadded base64url of the BLAKE3 of the canonical statement. ECDSA P-256 with SHA-256 over `authenticatorData` followed by SHA-256 of `clientDataJSON`. | Four length-prefixed fields: the 64-byte public key (`x` then `y`), `authenticatorData`, `clientDataJSON`, and the DER signature. | The address derived from the public key (§4.1). Valid only for a `0x` namespace. |

The `secp256k1-eip191` scheme signs the readable statement, not a hash,
so a wallet shows the owner what it grants.

For `webauthn-p256`, the verifier MUST require the user-presence flag
in `authenticatorData`. It MUST verify the signature over the exact
received `clientDataJSON` bytes, never a reserialization. A deployment
SHOULD configure the relying-party id hashes and origins it accepts,
and then MUST reject an assertion outside that set. A passkey works
only on its own relying party. A relying party that signs challenges
for other sites, such as a hosted wallet, can still be asked to sign a
grant it cannot display (§8).

### 4.1 Address derivation

The 20-byte address of a public key is the last 20 bytes of the
Keccak-256 of its 64-byte uncompressed coordinates (`x` then `y`,
without a prefix byte). This rule applies to secp256k1 and P-256 keys
alike. The namespace digits are the lowercase hexadecimal of those 20
bytes.

### 4.2 Header encoding

A client presents a signed grant in one header:

```text
X-Write-Grant: <statement>.<scheme>.<blob>
```

`<statement>` and `<blob>` are unpadded base64url. The header value
MUST NOT exceed 8,192 bytes. A client sends at most one grant per
request.

## 5. Revocation

Each namespace has an **epoch**, a server-stored unsigned integer that
starts at 0. A grant whose `epoch` field is below the stored epoch is
revoked.

The owner raises the epoch with an epoch statement, signed with any
scheme valid for the namespace (§4):

```text
mkit-write-epoch:v1
<namespace>
<epoch>
<created epoch milliseconds>
<nonce>
```

The server MUST accept the statement only if its `epoch` is strictly
greater than the stored epoch. It then stores the new epoch. One
statement therefore revokes every older grant in the namespace at once.
A server MUST persist the stored epoch as durably as the repository's
refs. The statement reaches the server through a `SetGrantEpoch` unary
RPC; its proto lands with the first implementation.

To revoke one grant, the owner raises the epoch and issues new grants
for the keys it keeps. Short grant lifetimes (§3) bound the exposure of
a lost Ed25519 key.

## 6. Server policy

A deployment applies one write policy:

- **`open`**: auth v2 identity only, with no allow-list. This is the
  behavior of SPEC-TRANSPORT-CONNECT §7.1 before this document.
- **`owner`**: every mutating repository RPC (`UpdateRef`,
  `AdvanceRefs`, `UploadPack`) needs authorization for the repository
  in `X-Repository`.

Under `owner`, a write is authorized when either:

1. the namespace has the `ed25519-` form and `X-Public-Key` equals its
   key; or
2. `X-Write-Grant` carries a grant that passes every check in §7; or
3. a deployment-defined authority source authorizes `X-Public-Key` for
   the repository. An example is a ledger's delegated-key record,
   checked against verified state. The deployment MUST document the
   source and MUST fail closed when it cannot read that source.

`SetGrantEpoch` acts on a namespace, not a repository. The owner
signature on its statement is its only authorization.

A repository comes into existence with its first authorized write.
There is no create-repository RPC (SPEC-TRANSPORT-CONNECT §7.4).

## 7. Verification

A server under the `owner` policy verifies a presented grant in this
order and stops at the first failure with `permission_denied`:

1. Decode the header (§4.2) and parse the statement (§3).
2. The statement `namespace` equals the namespace of `X-Repository`.
3. The scheme is valid for the namespace form, and the owner signature
   verifies under it (§4).
4. The owner identity equals the namespace (§2, §4.1).
5. The `scope` covers `X-Repository`: equal to it, or `<namespace>/*`.
6. The `grantee` equals `X-Public-Key`, the key that signed the auth
   v2 envelope.
7. `created` is at most 30,000 ms ahead of the server clock, and the
   server clock is before `expiry`.
8. The `epoch` is at least the namespace's stored epoch.

Grant verification MUST complete before quota admission, replay-record
insertion, or any side effect of SPEC-TRANSPORT-CONNECT §7.1. A
rejected grant allocates nothing.

## 8. Security considerations

- A `webauthn-p256` grant signs a digest, not readable text. The
  authenticator cannot show the owner what it grants. Owners SHOULD
  issue grants only from an application they trust to build the
  statement, and deployments SHOULD pin relying parties (§4).

- A grant without the grantee's Ed25519 private key authorizes
  nothing. Its disclosure is harmless.
- A grant is reusable until it expires or the epoch rises. Operation
  replay protection stays with the auth v2 nonce.
- The namespace wildcard covers repositories that do not exist yet.
  Owners SHOULD prefer single-repository scopes for agents.
- Epoch revocation is namespace-wide by design. It keeps the server
  state to one integer per namespace.
- Address derivation (§4.1) makes secp256k1 and P-256 owners share one
  namespace space. A collision needs a Keccak-256 preimage attack.

## 9. Out of scope

- The verifier in `mkit-core`, `owner` policy support in
  `apps/vcs-worker`, a CLI command that issues grants, and the
  `SetGrantEpoch` proto (mkit#1085 follow-ups).
- Owners that no single key controls, for example multisig or contract
  accounts. A deployment registry can map these to namespaces.
- The workspace grant (`mkit-workspace-grant:v1`,
  `apps/workspace-worker`). It grants workspace permissions, not
  repository writes, and stays separate.

## 10. Version history

| Version | Status | Changes |
|---|---|---|
| `1` | draft | Initial grant statement, owner schemes, epoch revocation, and `open`/`owner` policies (mkit#1085). |

## 11. Invariants

| Invariant | Enforced by |
|---|---|
| Under the `owner` policy, no mutating RPC succeeds unless the owner's Ed25519 key signed it or a valid grant names its signing key. | §6, §7. |
| A grant authorizes only its grantee key, only within its scope, only before its expiry, and only while its epoch is current. | §7 steps 5&ndash;8. |
| A namespace's stored epoch never decreases. | §5. |
| A rejected grant allocates no quota and no replay record. | §7, final paragraph. |
