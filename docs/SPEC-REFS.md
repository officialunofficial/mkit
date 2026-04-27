---
spec: SPEC-REFS
version: 1
status: draft
audience: implementers of compatible ref stores and transports
---

# SPEC-REFS — mkit v1 ref wire format and semantics

Status: **Normative** for mkit v1.
Scope: ref names, ref wire bytes, ref storage layout, and the exact
semantics of `listRefs(prefix)` and `updateRef(condition)` across
transports.

Resolves red-team R-07, R-08, R-13, R-40.

---

## 1. Ref wire format

A single ref value on the wire is:

```
[64 bytes lowercase hex]
[1 byte '\n' = 0x0A]
```

Total: **65 bytes**.

- Hex alphabet: `0-9` and `a-f` only. Uppercase is **forbidden**; writers
  MUST emit lowercase. Readers MUST reject uppercase input with
  `InvalidRef`. (v1 locks this down to lowercase-only for the byte-exact
  S3 ETag contract in §5.)
- The terminal `\n` is part of the wire format. Readers MAY tolerate a
  trailing `\r` (for Windows-origin files) or extra trailing whitespace
  when parsing ref *files* on local disk, but a transport that exposes
  ref bytes verbatim (S3, file) MUST store exactly 65 bytes.

Hash value: 32 bytes of BLAKE3. Writer computes
`hex = bytes_to_hex(hash, lowercase)`; reader computes
`hash = hex_to_bytes(wire[0..64])`.

---

## 2. Ref namespace

Refs live under two namespaces:

```
refs/heads/<name>    branch refs
refs/tags/<name>     tag refs
```

On local disk (`.mkit/refs/heads/<name>`, `.mkit/refs/tags/<name>`).
On transports, the same path shape is used relative to the transport's
root.

`HEAD` is a special file at `.mkit/HEAD` containing either:

```
ref: refs/heads/<name>\n
```

or a bare 64-char lowercase hex hash + `\n` (detached HEAD).

The file `.mkit/shallow` contains one `<64-hex>\n` per line denoting
commits beyond which the local repo does not have history.

---

## 3. Ref name grammar

Normative:

```
ref_name    := segment ( '/' segment )*
segment     := char+
char        := ALNUM | '.' | '_' | '-'
ALNUM       := [0-9A-Za-z]
```

Plus these rejections:

- Empty string → invalid.
- Leading `/` → invalid.
- Any segment equal to `"."` or `".."` → invalid.
- Empty segment (i.e. `//`, trailing `/`, leading `/`) → invalid.
- Any byte in `{0x00, '\\'}` → invalid.
- Any byte outside the grammar → invalid.
- Any segment ending in `.lock` → invalid (the canonical lock-file
  suffix; e.g. `refs/heads/main.lock` is reserved).
- Final segment equal to `HEAD` → invalid (shadows the repo-level
  `HEAD` pointer; e.g. `HEAD` and `refs/heads/HEAD` are rejected).

**Notable divergences from Git ref naming:**

- No `@` allowed (Git permits `@{reflog}`-style refs; mkit does not).
- No `+`, `:`, `~`, `^`, `?`, `*`, `[` allowed.
- No Unicode in ref names.
- Case-sensitive: `main` and `Main` are distinct.

This is a deliberately restrictive grammar to simplify cross-transport
name validation.

Implementations MUST validate ref names with this grammar at **every**
transport boundary — writing a ref, reading a ref, listing refs, and
parsing a client-supplied name. No transport may silently lower case
or canonicalise.

---

## 4. Prefix semantics for `listRefs`

`listRefs(prefix) -> [{name, hash}]` walks the ref namespace and
returns all refs whose full name begins with `prefix`. The `name` in
each returned tuple has `prefix` stripped, plus any trailing `/` on the
prefix is also absorbed.

Normative behaviour (this is the single source of truth; all transports
MUST conform):

```
Given full ref name F, prefix P, returned name N:

    if P is empty:
        N = F
    else:
        let P' = P with any trailing '/' removed
        if F == P':
            # A ref named exactly the prefix, no separator.
            # SHOULD NOT be returned (refs never coincide with a "directory").
            skip
        elif F starts with P' + '/':
            N = F[len(P') + 1 ..]
        elif F starts with P':
            # P' was a prefix without separator; this matches, e.g.
            # listRefs("refs/heads/feat") matching "refs/heads/feature"
            N = F[len(P') ..]
        else:
            skip
```

In practice the common case is:

- `listRefs("refs/heads")` → returned names are `{"main", "feature/x"}`.
- `listRefs("refs/heads/")` → same result.
- `listRefs("refs/heads/feat")` → returned names are `{"/x"}` if
  `refs/heads/feat/x` exists, or `{"ure/y"}` if `refs/heads/featUre/y`
  exists (edge case — discouraged but specified).

Callers SHOULD pass prefixes that end at a path component boundary.
Callers MUST NOT assume `prefix` includes a trailing `/`; the transport
normalises either form.

The spec pins the behaviour above; transports MUST conform or fail
conformance tests.

### 4.1 Ordering and duplicates

Returned refs MUST be sorted lexicographically by `name`. No duplicates
(`name` is unique within the result). Empty result is returned as an
empty slice, not null.

### 4.2 Prefix validation

The prefix itself must be empty or pass the same grammar as a ref name
(§3), possibly with a single trailing `/`. Reject invalid prefixes with
`InvalidRef`.

---

## 5. CAS (`updateRef`) semantics

```
updateRef(name, condition, new_hash)

condition := .any
           | .missing
           | .match(expected_hash)
```

`.any` — unconditional write. Clobbers any existing value.

`.missing` — write only if the ref does not currently exist. If it
exists → `RefConflict`.

`.match(H)` — write only if the ref currently contains `H`. If it does
not exist or contains a different hash → `RefConflict`.

### 5.1 Per-transport atomicity matrix

(Normative — this is what conformance tests verify.)

| Transport | `.any`      | `.missing`                            | `.match`                                                       | Notes |
|-----------|-------------|---------------------------------------|----------------------------------------------------------------|-------|
| memory    | atomic*     | atomic*                               | **NOT atomic** — read-then-write race                          | *Single-threaded by construction. Across fibres: no lock. |
| file      | atomic      | atomic (via `O_EXCL` create)          | **NOT atomic** — read-then-write race across processes         | v1 known gap; W4 will replace with lockfile. |
| s3        | atomic      | atomic via `If-None-Match: *`         | atomic via `If-Match: "<md5-of-wire>"`                         | Requires server that supports conditional writes (R2 and post-2024 AWS S3 do; generic S3 may not). |
| http      | atomic      | atomic via `If-None-Match: *`         | atomic via `If-Match: "<hex-hash>"`                            | Worker-flavoured server. Generic S3 + nginx does NOT conform. |
| ssh       | atomic      | atomic (`OP_WRITE_REF_IF_ABSENT` path via condition byte) | atomic (`CONDITION_MATCH` with 32-byte expected hash)          | Server enforces CAS; client trusts `STATUS_ERROR`. |

*memory/file CAS:* v1 ships the non-atomic implementations; SPEC-TRANSPORT
documents this explicitly. Concurrent callers on the file transport MAY
lose updates. Production deployments should use s3/http/ssh for CAS
critical paths.

### 5.2 ETag encoding divergence

The `.match(H)` condition is serialised differently by transport:

- **S3**: ETag value is `"\"<md5_hex>\""` where `md5_hex` is the MD5
  hash of the 65-byte ref wire bytes for `H`. Enclosing double-quotes
  are part of the header value.
- **HTTP** (Worker flavour): ETag value is `"\"<hash_hex>\""` where
  `hash_hex` is the 64-char hex of `H` directly. Enclosing double-quotes
  again.
- **SSH**: no ETag; the 32 raw bytes of `H` are sent in the
  `CONDITION_MATCH` payload.
- **file / memory**: read-then-compare against `H`'s raw bytes
  in-process.

Mkit v1 **does not** unify these encodings. The transport spec
explicitly states which encoding to produce. Clients and servers for a
single transport MUST agree on the transport's encoding; cross-transport
compatibility is not in scope.

### 5.3 `.any` with conditional hint

The HTTP transport's `buildRefWriteHeaders(.any, Some(current))` emits
`If-Match: "<hex>"` opportunistically when the caller knows the prior
value. This is an optimisation and MUST NOT be treated as binding CAS
— a server that ignores the header is still conforming for `.any`.
Clients requiring CAS MUST use `.match` explicitly.

---

## 6. Ref storage (local disk)

```
.mkit/refs/heads/<name>     65 bytes wire
.mkit/refs/tags/<name>      65 bytes wire
.mkit/HEAD                  symbolic ("ref: refs/heads/<name>\n") or detached (64-hex + '\n')
.mkit/shallow               one 65-byte wire per line (no hash in this case — just hex+newline)
```

Writers MUST use atomic write-then-rename on local disk to avoid torn
reads.

---

## 7. Test vectors (implementer MUST produce)

TO BE FIXED IN IMPLEMENTATION:

1. **Wire encode/decode**: hash = BLAKE3("test-ref") → 64 hex + `\n`.
   Record the 65-byte wire.
2. **Reject uppercase wire** on read.
3. **listRefs prefix cross-transport parity**: memory, file, s3, http,
   ssh all asked `listRefs("refs/heads")` and `listRefs("refs/heads/")`
   on an identical seeded state — results MUST be byte-identical.
4. **`.missing` race**: two concurrent `.missing` writers to the same
   ref — exactly one succeeds, the other returns `RefConflict`. Run on
   s3, http, ssh.
5. **`.match` on file transport**: document expected non-atomicity —
   two concurrent `.match` to the same ref may both succeed. This is a
   negative test showing the spec's documented gap.
6. **Ref name grammar**: valid — `main`, `feat/v1.0-beta`,
   `release/2024_09`. Invalid — `feat/..`, `/main`, `main@v1`,
   `feat\branch`, `` (empty).
7. **S3 MD5-of-wire ETag**: compute MD5 of the 65-byte wire for a
   known hash; compare against an S3 PUT's Content-MD5 on the same
   wire.
8. **HTTP hex-hash ETag**: compute `If-Match: "<64-hex>"` for a known
   hash; server echoes back matching state.

---

*~1450 words.*
