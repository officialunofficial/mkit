---
spec: SPEC-SIGNING
version: 1
status: stable-normative
audience: implementers of compatible commit / remix signers and verifiers
---

# SPEC-SIGNING — mkit v1 signature domains

Status: **Normative** for mkit v1. See SPEC-CONVENTIONS §1 for the
RFC 2119/8174 boilerplate this document's MUST/SHOULD language relies
on, and §6 for the no-vendor-references rule this document follows:
verification is specified below as a mathematical predicate, not as a
named library function.
Scope: the exact bytes covered by an Ed25519 signature on a commit or
remix, and the domain separator used.

This document resolves red-team risks R-04 (no version / magic in signing
bytes) and R-17 (cross-domain signature confusion).

---

## 1. Signing primitives

- **Hash:** BLAKE3 default mode (no keyed hashing, no derive-key at the
  signing layer). Output: 32 bytes.
- **Signature:** Ed25519 per RFC 8032 only. mkit-core does NOT support
  any other signature algorithm; multi-algorithm signing (if any) lives
  in `mkit-attest` / SPEC-ATTESTATIONS and is out of scope here.
  Public key 32 bytes, seed 32 bytes, signature 64 bytes.
- **Signers sign a BLAKE3 digest of the signing bytes (§2.1), not the
  raw signing bytes.** This is PureEdDSA (RFC 8032's `Sign`/`Verify` as
  defined — no HashEdDSA prehashing indirection) applied to a
  32-byte *message* that happens to itself be a hash. It is
  deliberately **not** Ed25519ph (RFC 8032 §5.1, the "prehash" variant):
  Ed25519ph runs the message through SHA-512 internally as part of the
  signature algorithm and prepends its own `dom2` domain-separation
  context, producing a different signature over the same bytes than
  PureEdDSA would. mkit signs a 32-byte value with plain PureEdDSA; that
  value happens to be `BLAKE3(domain ‖ signing_bytes)` rather than the
  object's raw signing bytes, purely so a signer implementation (in
  particular a hardware or remote signer, SPEC-EXTERNAL-SIGNER) only
  ever needs to handle a fixed-size 32-byte input regardless of object
  size — it never streams or buffers a variable-length message.
  **Security consequence, stated explicitly:** because the signed
  message is a hash rather than the object itself, this construction's
  unforgeability reduces to two independent assumptions instead of one —
  Ed25519's EUF-CMA security *and* BLAKE3's collision resistance (an
  attacker who can find `signing_bytes ≠ signing_bytes'` with
  `BLAKE3(domain ‖ signing_bytes) = BLAKE3(domain ‖ signing_bytes')` can
  transplant a valid signature onto different object content). BLAKE3
  has no known collision weakness and this reduction is the same one
  every hash-then-sign scheme accepts (this is exactly what
  Ed25519ph's `dom2`-wrapped SHA-512 prehash also relies on) — but it is
  a real, stated precondition, not a free property of "PureEdDSA."
- **Verification acceptance predicate:** a signature `(R, S)` over
  message `M` under public key `A` is accepted if and only if all of
  the following hold — this is RFC 8032 §5.1.7's verification
  procedure with its optional additional checks made mandatory:
  1. `A` and `R` each decode as **canonical** encodings of points on
     the curve (the top bit is the sign bit; the remaining 255 bits,
     interpreted little-endian, MUST be strictly less than the field
     prime `p = 2²⁵⁵ - 19`; an encoding using a value ≥ p is rejected
     rather than reduced mod `p`).
  2. `A` and `R` are **not** low-order points (i.e. not in the curve's
     order-8 torsion subgroup) — this is the "small-order key/point"
     rejection.
  3. `S` is **canonical**: interpreted as a little-endian integer,
     `0 ≤ S < L` where `L` is the order of the curve's prime-order
     subgroup (`2²⁵² + 27742317777372353535851937790883648493`); a
     value `S ≥ L` is rejected rather than reduced mod `L`.
  4. The core Ed25519 equation holds over the prime-order subgroup:
     `[S]B = R + [k]A`, where `B` is the base point and
     `k = SHA-512(R ‖ A ‖ M) mod L`.
  A verifier that only performs check 4 (the "batch-friendly"/default
  RFC 8032 verification equation, which tolerates non-canonical and
  low-order `R`/`A`/`S` by implicitly reducing them) is **not**
  conformant with this specification — checks 1–3 MUST also be
  enforced. This is the same acceptance criterion as the widely-used
  `ed25519-dalek` crate's `verify_strict` function, which is offered
  here purely as a cross-reference for implementers, not as this
  predicate's definition; `verify_strict` is **not** identical to the
  ZIP-215 acceptance criterion (ZIP-215 is deliberately *more*
  permissive — cofactored, accepting some non-canonical and torsion
  points that this predicate rejects) and this document does not claim
  ZIP-215 compatibility.
- No batched verification. Each verify is independent.

---

## 2. Domain separation

mkit defines three distinct signing domains. They MUST produce disjoint
signable byte strings for any possible input.

```
COMMIT_DOMAIN   = "mkit.commit\x00"       (12 bytes)
REMIX_DOMAIN    = "mkit.remix\x00"        (11 bytes)
TAG_DOMAIN      = "mkit.tag\x00"          (9 bytes)
```

The terminal `\x00` is part of the domain string. Disjointness here does
not depend on it — the §2.1 length prefix already makes every domain
string self-delimiting, so no well-formed domain can be a prefix of
another regardless of the terminator. The `\x00` is retained because it
makes that prefix-freeness property visually obvious to a reader
inspecting the raw bytes, which is a readability aid, not a
cryptographic requirement (BLAKE3 is not vulnerable to length-extension
in the way some earlier hash constructions were, so nothing here is
compensating for that).

`COMMIT_DOMAIN` covers commits, `REMIX_DOMAIN` covers remixes, and
`TAG_DOMAIN` covers annotated/signed tag objects (§4a, issue #230). The
tag domain is **deliberately distinct** from the commit/remix domains so
a tag signature can never be replayed as a commit/remix signature, or
vice versa.

### 2.1 Signing-hash derivation

Implementations MUST compute the signing digest with a 16-bit little-endian
domain length prefix, followed by the full domain string and canonical signing
bytes:

```
digest = BLAKE3(u16_le(domain.len) || domain || signing_bytes)
```

Where `domain` is the full domain string *including* the trailing
`\x00`. This is the shape we commit to on the wire and in test vectors.

The length prefix makes the `(domain, signing_bytes)` boundary explicit. A
verifier MUST NOT use BLAKE3 `derive_key`, bare `BLAKE3(domain ||
signing_bytes)`, or any other domain construction for v1 signatures.

---

## 3. Commit signing bytes

For a commit C (as defined in SPEC-OBJECTS §5), the canonical signing
bytes are:

```
signing_bytes = PROLOGUE
              || tree_hash
              || u32 LE(parent_count) || parent_hash * parent_count
              || Identity(author)
              || u32 LE(message_len) || message_bytes
              || u64 LE(timestamp)
              || signer_pubkey
```

Where `PROLOGUE` is the 6 bytes defined in SPEC-OBJECTS §2:
`[object_type=0x03] [magic="MKT1"] [schema_version=0x01]`.

**Included fields, in order:**

1. Object prologue (6 bytes) — binds the signature to the object type
   and schema version.
2. `tree_hash` (32 bytes) — content the commit points at.
3. `parent_count` (4 LE) and `parent_count` × `parent_hash` (32 each) —
   commit history.
4. `Identity author` (variable; see SPEC-OBJECTS §9) — length-prefixed,
   so field length ambiguity is impossible.
5. `message_len` (4 LE) and message bytes — length-prefixed.
6. `timestamp` (8 LE).
7. `signer` (32 bytes) — the public key that will verify the signature.

**Excluded fields and why:**

- `signature` (64 bytes) — a signature cannot cover itself.
- `message_hash` (32 bytes) — optional off-chain annotation field;
  irrelevant to core commit identity. Including it would mean any
  downstream re-computation shifts the commit hash.
- `content_digest` (32 bytes) — same reasoning: downstream pack-digest
  annotation. Not a commit identity input.

These two exclusions resolve red-team R-45. They are the only commit-
struct fields excluded from signing bytes.

The **signing hash** is then:

```
signing_hash = BLAKE3(u16_le(12) || "mkit.commit\x00" || signing_bytes)
```

And the commit's `signature` field is `Ed25519.sign(signer_seed,
signing_hash)`.

---

## 4. Remix signing bytes

For a remix R (SPEC-OBJECTS §6):

```
signing_bytes = PROLOGUE                   // object_type=0x04
              || tree_hash
              || u32 LE(parent_count) || parent_hash * parent_count
              || u32 LE(source_count) || (upstream_id || commit_hash) * source_count
              || Identity(author)
              || u32 LE(message_len) || message_bytes
              || u64 LE(timestamp)
              || signer_pubkey
```

Excluded: `signature`.

```
signing_hash = BLAKE3(u16_le(11) || "mkit.remix\x00" || signing_bytes)
```

---

## 4a. Tag signing bytes

For a tag T (SPEC-OBJECTS §6a):

```
signing_bytes = PROLOGUE                   // object_type=0x07
              || target                    // 32 bytes, hash of tagged object
              || target_type               // 1 byte ObjectType
              || u32 LE(name_len) || name_bytes
              || Identity(tagger)
              || u32 LE(message_len) || message_bytes
              || u64 LE(timestamp)
              || signer_pubkey
```

Excluded: `signature` (a signature cannot cover itself). Every other tag
field is covered, so flipping the `target`, `target_type`, `name`,
`tagger`, `message`, `timestamp`, or `signer` invalidates the signature.

```
signing_hash = BLAKE3(u16_le(9) || "mkit.tag\x00" || signing_bytes)
```

The tag's `signature` field is `Ed25519.sign(signer_seed, signing_hash)`.

An **annotated, unsigned** tag (`mkit tag -a`) carries an all-zero
`signature` (`0x00`×64). It is a valid object but not a valid signature:
`verify_tag` over an all-zero signature fails the strict Ed25519 check.
A **signed** tag (`mkit tag -s`) carries a real signature that
`mkit verify <tag>` accepts.

---

## 5. Cross-domain collision proof sketch

Commit signing input always begins with `u16_le(12)` followed by the 12-byte
domain string `"mkit.commit\x00"`; remix signing input begins with
`u16_le(11)` followed by the 11-byte string `"mkit.remix\x00"`; tag
signing input begins with `u16_le(9)` followed by the 9-byte string
`"mkit.tag\x00"`.

- All three domain *lengths* (12 / 11 / 9) differ, so the 2-byte LE
  length prefix alone already distinguishes them before any domain byte
  is read.
- All three domain strings share the 5-byte prefix `"mkit."` (bytes
  0–4) and then diverge at byte index 5 — `'c'` (0x63) for
  `"mkit.commit\x00"`, `'r'` (0x72) for `"mkit.remix\x00"`, and `'t'`
  (0x74) for `"mkit.tag\x00"` — giving a second, independent separator
  once the length check is bypassed (e.g. by a hypothetical
  length-collision in some future fourth domain).

Because the domain length and the first differing domain byte occur strictly
before any possible user-controlled content (domains are compile-time
constants), no user input can make one domain's hash input equal another's.
BLAKE3 is collision-resistant, so distinct inputs have cryptographically
distinct digests.

Therefore, a signature over any one of the commit / remix / tag domain
digests cannot be replayed as a signature over either of the other two.

This is the defence against R-17. The previous scheme used only the
ObjectType tag byte (0x03/0x04) as separator — one byte of domain — and
was fragile. v1 uses ≥ 11 bytes of high-entropy ASCII plus a null
terminator.

---

## 6. Verification algorithm

Given a commit C retrieved from the store:

1. Check object prologue (SPEC-OBJECTS §2).
2. Re-build signing bytes per §3. (It's the caller's responsibility to
   retrieve the exact `signer` field from C; the verifier does not
   accept a public key from elsewhere.)
3. Compute `signing_hash = BLAKE3(u16_le(12) || "mkit.commit\x00" || signing_bytes)`.
4. Parse `signer` as an Ed25519 public key. Invalid point → verify fails.
5. `Ed25519.verify(signer, signing_hash, C.signature)`. Any failure →
   verify fails.

A verifier MUST NOT accept a signature merely because the `Identity
author` field's payload matches the `signer` public key. Those are two
independent fields. Identity is an attribution claim; `signer` is the
verification key. Pairing is adapter/application policy, not a core
invariant.


---

## 7. Key file format

```
Path:           caller-provided; the convention is .mkit/keys/default.key
Contents:       raw 32 bytes (Ed25519 SEED — NOT expanded secret key)
File mode:      0600 (mandatory on POSIX)
Parent-dir mode: 0700 (mandatory on POSIX)
```

The seed is passed to the Ed25519 deterministic key-pair constructor
to recover `(public_key, secret_key)` on load. No PEM, no DER, no
password wrapping in v1.

### 7.1 Write contract

Writers MUST use the following crash-atomic sequence on POSIX:

1. Ensure the parent directory exists at mode 0700. Refuse if any
   ancestor (up to three levels) is a symlink → `KeyPathIsSymlink`.
2. Open a sibling temp file (`.<file>.tmp.<pid>`) with
   `O_CREAT | O_EXCL | O_NOFOLLOW` and mode 0600. `O_EXCL` defeats a
   pre-created symlink at the tmp name.
3. Write the 32-byte seed, `fsync` the file.
4. `rename(2)` the tmp file to the final path. Atomic on the same
   filesystem; replaces any existing key.
5. `fsync` the parent directory so the rename itself is durable.

A `save_raw_32_create_new` variant exists for keygen flows that MUST
NOT clobber an existing key; it returns `Ok(false)` if the destination
already exists.

### 7.2 Load contract

Loaders MUST enforce on POSIX:

- Open with `O_NOFOLLOW`. ELOOP → `KeyPathIsSymlink(path)`.
- Reject if any of the three ancestor directories is a symlink →
  `KeyPathIsSymlink(dir)`.
- `fstat` the open file descriptor (not the path — closes a TOCTOU
  rename(2) window).
- File mode `& 0o077 != 0` → `InsecureKeyPermissions{actual}`.
- File owner uid ≠ process euid → `InsecureKeyOwner{actual, euid}`.
- Immediate parent directory mode `& 0o077 != 0` →
  `InsecureKeyDir{actual}`.
- File length ≠ 32 bytes (short or long) → `InvalidKeyLength{actual}`.

Any I/O failure surfaces as `KeyIo(String)`. Public-key bytes that do
not decode to a valid Edwards point → `InvalidPublicKey`. RNG failure
during `KeyPair::generate()` → `RngFailure`. Signature verification
failure → `SignatureInvalid` (the underlying Ed25519 layer does not
distinguish among bad-signature, wrong-key, tampered-input, or wrong-
domain).

On non-POSIX hosts the symlink, owner, and mode checks degrade to
no-ops; implementations SHOULD use the host's equivalent access
restriction (e.g. keep keys under `%USERPROFILE%` so default Windows
ACLs apply).

---

## 8. One key, many roles

The Ed25519 seed in `.mkit/keys/default.key` MAY be reused for other
Ed25519 roles in the wider mkit ecosystem:

- **Commit / remix / tag signing** (this document, §§3-4a) — the
  message signed is always `BLAKE3(domain ‖ signing_bytes)` for one of
  the three domains in §2.
- **DSSE attestation signing** via the `repo-key` signer
  (`SPEC-ATTESTATIONS.md` §6.2) — the message signed there is the raw
  DSSE pre-authentication-encoding (PAE) byte string, not a domain
  digest from this document.
- **SSH transport authentication** when pushing to `mkit+ssh://`
  servers — the message signed there is whatever byte string the SSH
  protocol itself defines for public-key authentication (RFC 4252
  §7), entirely outside mkit's control.

**Correction:** an earlier version of this section claimed "OpenSSH
8.0+ accepts the same raw Ed25519 seed as its `id_ed25519` private
key." This is not accurate: OpenSSH's private-key files use its own
`openssh-key-v1` container format (a bcrypt-KDF-wrapped, base64,
PEM-bracketed structure), not a bare 32-byte seed. Reusing an mkit
seed as an SSH identity requires an explicit conversion step (wrapping
the same 32 bytes into that container), which is outside this
document's scope.

**Cross-protocol domain separation is not yet analyzed.** §5's
disjointness argument covers only the three domains this document
defines; it says nothing about whether a 32-byte value that is a valid
`signing_hash` under §2.1 could ever also be validly interpreted as a
DSSE PAE byte string or an SSH signed blob under those other
protocols' own framing. Recommending key reuse without that analysis
is a real, open gap — tracked as a Security Considerations addition to
this document (see the project's spec-remediation plan) rather than
resolved here. Until that analysis exists, treat cross-protocol key
reuse as convenient but **unproven** rather than as a stated security
property.

Nothing in the protocol REQUIRES a single key — separate signing and
transport keys are valid, and are the safer default until the
cross-protocol analysis above is complete.

---

## 9. Test vectors

1. **Deterministic commit signing bytes**: fixed-input commit with
   `Identity{kind=0x01, len=32, payload=[0xAA;32]}`, zero
   `message_hash`/`content_digest`, timestamp `1_700_000_000`,
   empty message, zero tree_hash, zero parents, signer = identity
   payload. Record the exact `signing_bytes` hex and `signing_hash` hex.
2. **Ed25519 sign over vector 1** using seed `[0x01;32]` → record
   64-byte signature hex.
3. **Verify tampered message**: flip one bit in the message, verify
   MUST fail.
4. **Domain confusion negative test**: attempt to verify a signed commit
   using `"mkit.remix\x00"` domain (or any other string). MUST fail.
5. **Zero `message_hash`/`content_digest` do not affect signing hash**:
   two commits differing only in those fields MUST produce identical
   signing_hash bytes.
6. **Remix signing vector**: two-source remix sorted correctly,
   fixed author, fixed message, fixed timestamp. Record hash.
7. **Key file roundtrip**: generate keypair, write seed, re-load,
   sign-then-verify a commit. Round-trip stable.
8. **Tag signing bytes + hash + signature**: annotated tag with
   `target_type=0x03`, fixed ed25519 tagger, non-empty message, fixed
   timestamp; record `tag_signing_bytes`, `signing_hash`, and (signing
   with seed `[0x07;32]`) the 64-byte signature. Pinned under
   `rust/tests/golden/tags/`.
9. **Tag cross-domain negative**: a tag-domain signature MUST NOT verify
   under `"mkit.commit\x00"` or `"mkit.remix\x00"`, and vice versa.

---

## 10. Non-goals

- No PQ (post-quantum) signatures in v1. Ed25519 only.
- No signer rotation at the core level. A new `signer` = a new commit.
- No timestamp authority. `timestamp` is self-reported and unverified.
- No partial / threshold signatures.
- No nested signatures (signing a signature) — always sign a BLAKE3
  digest directly.

---

## 11. Invariants

Properties that MUST hold for every v1 commit / remix / tag signature,
and the mechanism that enforces or detects each.

| Invariant | Enforced by |
|---|---|
| A signature in one domain never verifies in another (commit ↔ remix ↔ tag; R-17) | `u16_le(domain.len)` prefix + disjoint domain strings, both preceding any user-controlled byte (§2.1, §5) |
| Flipping any covered field (tree, parents, author, message, timestamp, signer, tag target/type/name) invalidates the signature | signing bytes cover every identity field of the object (§3, §4, §4a) |
| No field-boundary ambiguity in signing bytes | every variable-length field is length-prefixed (`Identity`, `message_len`, `parent_count`, `name_len`) (§3, §4, §4a) |
| A signature is bound to one object type and schema version | the 6-byte PROLOGUE leads the signing bytes (§3) |
| `message_hash` / `content_digest` annotations never shift the signing hash (R-45) | both fields excluded from signing bytes (§3) |
| Malleable / non-canonical signatures are rejected identically by all verifiers | the §1 acceptance predicate's checks 1–3 (non-canonical/low-order `R` or `A`, non-canonical or out-of-range `S` all fail) (§1) |
| An annotated-but-unsigned tag never passes verification | all-zero signature fails the strict Ed25519 check (§4a) |
| The verification key is the object's own `signer` field, never caller-supplied | verifier rebuilds signing bytes and parses `signer` from the object (§6) |
| `author == signer` is never assumed | a verifier MUST NOT accept on identity match; pairing is application policy (§6) |
| Signing hash is deterministic across machines | all count/length/timestamp fields fixed little-endian; domains are compile-time constants (§2, §3) |
| The key file is never world-readable, symlink-swapped, or raced at load (POSIX) | `O_NOFOLLOW`, ancestor-symlink rejection, `fstat` on the open fd, mode/owner/length checks (§7.2) |
| Key writes are crash-atomic and clobber-safe | `O_EXCL` temp create + fsync + `rename(2)` + parent fsync; `create_new` variant for keygen (§7.1) |

Test vectors 3–5 and 9 (§9) pin the tamper-detection and cross-domain
rows as executable negatives. The key-file rows degrade to no-ops on
non-POSIX hosts per §7.2.
