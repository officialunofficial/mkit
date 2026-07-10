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

Refs live under three namespaces:

```
refs/heads/<name>                  branch refs
refs/tags/<name>                   tag refs
refs/remotes/<remote>/<name>       remote-tracking branch refs
```

On local disk (`.mkit/refs/heads/<name>`, `.mkit/refs/tags/<name>`,
`.mkit/refs/remotes/<remote>/<name>`). On transports, branch and tag refs
use the same path shape relative to the transport's root.

`refs/remotes/<remote>/<name>` is local-only remote-tracking state. The
single-remote CLI stores fetched branch tips under
`refs/remotes/default/<name>` and never writes fetched tips directly to
`refs/heads/<name>`. `mkit pull` may then fast-forward the current local
branch from the matching remote-tracking ref.

Named remotes (`mkit remote add <name> <url>`) store their tracking refs
under `refs/remotes/<name>/<branch>`. `mkit push` uses the local
remote-tracking ref as its **CAS lease**: a default (current-branch)
push writes the remote `refs/heads/<branch>` with a `Match(tracked)`
condition (or `Missing` for a first push), so a remote that has moved
past the tip we last saw rejects the update as non-fast-forward. On a
successful push, mkit advances the local `refs/remotes/<remote>/<branch>`
to the pushed tip. `--force-with-lease` keeps this lease; `--force`
drops to an unconditional write.

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
- Any segment starting with `.` → invalid (this also rejects the exact
  `"."` and `".."` segments; git's `check-ref-format` rule, kept for
  parity).
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

This section is normative for **transport** implementations of
`listRefs(prefix)`. The local `mkit-core` API (see `refs.rs`) exposes
the simpler `list_refs(mkit_dir)` / `list_tags(mkit_dir)` which return
every ref under `refs/heads/` or `refs/tags/` respectively — the
prefix has been pre-applied implicitly by the function choice. The
algorithm below is what a transport server / a future
`list_refs_with_prefix` core API MUST implement to remain cross-
transport compatible.

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
(§3), possibly with a single trailing `/`. Transports MUST reject
invalid prefixes (the core helper `validate_ref_prefix` returns a
boolean; transports wrap the false case as their domain-specific
`InvalidRef` error, e.g. `RefError::InvalidRefName` on the file
backend).

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
| file      | atomic      | atomic (via `O_EXCL` create)          | atomic — OS exclusive file lock (`<root>/.mkit/refs/.lock`) serialises the read-check-write across processes | Lock guard released on drop (including panic-unwind). |
| s3        | atomic      | atomic via `If-None-Match: *`         | atomic via `If-Match: "<md5-of-wire>"`                         | Requires server that supports conditional writes (R2 and post-2024 AWS S3 do; generic S3 may not). |
| http      | atomic      | atomic via `If-None-Match: *`         | atomic via `If-Match: "<hex-hash>"`                            | Worker-flavoured server. Generic S3 + nginx does NOT conform. |
| ssh       | atomic      | atomic (`OP_WRITE_REF_IF_ABSENT` path via condition byte) | atomic (`CONDITION_MATCH` with 32-byte expected hash)          | Server enforces CAS; client trusts `STATUS_ERROR`. |

*memory CAS:* v1 ships the non-atomic `.match` implementation for the
in-process memory transport only. The file transport's `.match` is atomic
across processes via the OS lock above; the read-then-write race survives
only in the local `mkit-core` `refs::cas_write` helper used by commands that
mutate refs directly on disk without going through the file transport.
Production deployments needing CAS across processes without the file
transport's lock should use s3/http/ssh.

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
.mkit/refs/heads/<name>     65 bytes wire (HEADS_DIR = "refs/heads")
.mkit/refs/tags/<name>      65 bytes wire (TAGS_DIR  = "refs/tags")
.mkit/HEAD                  symbolic ("ref: refs/heads/<name>\n") or detached (64-hex + '\n')
.mkit/shallow               concatenation of N × 65-byte ref-wire blobs (one hash per line)
```

`HEAD` content size is capped at 4 KiB; a single ref file at 128 bytes;
the shallow file at 1 MiB. Reads exceeding these bounds yield
`RefError::InvalidHead` / `RefError::InvalidRef` respectively.

Writers MUST use atomic write-then-rename on local disk to avoid torn
reads. The temp-name pattern is `.<file>.tmp.<pid>.<seq>`, identical
to SPEC-INDEX §4.

`HEAD` reads tolerate trailing `\r`, space, and tab so a Windows-
edited file does not brick a repo; ref-file reads tolerate the same
trailing whitespace plus the optional `\r` before the terminating
`\n`. Fresh writes always emit the strict 65-byte form.

Listing `.mkit/refs/heads/` is recursive (nested directories like
`feature/x/y` are supported), with a hard depth cap of 32 levels to
defeat adversarial nesting. Files that fail `validate_ref_name` or
whose bytes do not decode to a valid ref wire are silently skipped
from listings.

### 6.1 Operation-state files (merge / cherry-pick / rebase)

Resumable history operations persist their state under `.mkit/` using
Git-compatible names plus one documented mkit sidecar. These are not
refs (they are not listed by `listRefs` and are not part of the ref
namespace); they are operation scratch state consumed by
`--continue` / `--abort` / `--skip`.

```
.mkit/MERGE_HEAD           64-hex + '\n'  — other parent of an in-progress merge
.mkit/CHERRY_PICK_HEAD     64-hex + '\n'  — commit being applied by a cherry-pick
.mkit/ORIG_HEAD            64-hex + '\n'  — HEAD before the operation (for --abort)
.mkit/MERGE_MSG            raw bytes      — pending merge commit message
.mkit/CHERRY_PICK_MSG      raw bytes      — pending cherry-pick commit message
.mkit/mkit-conflicts       sidecar (below)
.mkit/rebase-apply/        rebase state dir; holds a mkit-conflicts sidecar when paused
```

Presence of `MERGE_HEAD` ⇒ a merge is in progress; `CHERRY_PICK_HEAD` ⇒
a cherry-pick; `rebase-apply/` ⇒ a rebase. Starting any of the three
while one is already in progress is refused.

The `mkit-conflicts` sidecar is line-oriented, one line per conflicting
path, tab-separated, with the path last (so it may not contain a tab):

```
<kind>\t<base_hex|->\t<ours_hex|->\t<theirs_hex|->\t<path>\n
```

where `<kind>` ∈ {`modify`, `addadd`, `deletemodify`}, a missing side is
encoded as a single `-`, and `<path>` is validated with the same rules
as a staged index path (SPEC-INDEX §2). Hash files tolerate trailing
whitespace on read. The whole sidecar is capped at 1 MiB. This sidecar
does **not** change the `.mkit/index` format: the index remains a
single-stage **resolved** staging area (no unmerged stages); conflict
base/ours/theirs material lives only in this sidecar.

---

## 7. Test vectors

1. **Wire encode/decode**: hash = BLAKE3("test-ref") → 64 hex + `\n`.
   Record the 65-byte wire.
2. **Reject uppercase wire** on read.
3. **listRefs prefix cross-transport parity**: memory, file, s3, http,
   ssh all asked `listRefs("refs/heads")` and `listRefs("refs/heads/")`
   on an identical seeded state — results MUST be byte-identical.
4. **`.missing` race**: two concurrent `.missing` writers to the same
   ref — exactly one succeeds, the other returns `RefConflict`. Run on
   s3, http, ssh.
5. **`.match` on file transport, exactly-one-winner**: two concurrent
   `.match` writers to the same ref — exactly one succeeds, the other
   returns `RefConflict` and the ref is left at the winner's value.
   Enforced by the OS exclusive lock (§5.1); a corresponding negative
   test still documents the read-then-write race in the local
   `mkit-core` `refs::cas_write` helper (not the file transport).
6. **Ref name grammar**: valid — `main`, `feat/v1.0-beta`,
   `release/2024_09`. Invalid — `feat/..`, `/main`, `main@v1`,
   `feat\branch`, `.hidden`, `` (empty).
7. **S3 MD5-of-wire ETag**: compute MD5 of the 65-byte wire for a
   known hash; compare against an S3 PUT's Content-MD5 on the same
   wire.
8. **HTTP hex-hash ETag**: compute `If-Match: "<64-hex>"` for a known
   hash; server echoes back matching state.

---

## 8. Invariants

| Invariant | Enforced by |
|---|---|
| A ref value on any byte-exact transport is exactly 65 bytes: 64 lowercase hex + `\n` | writers MUST emit lowercase; readers reject uppercase with `InvalidRef` (§1) |
| Every ref name crossing a transport boundary satisfies the §3 grammar | validation at **every** boundary — write, read, list, client-supplied parse; no silent case-folding or canonicalisation (§3) |
| No ref shadows `HEAD` or a lock file | grammar rejections for final-segment `HEAD` and the `.lock` suffix (§3) |
| `listRefs(prefix)` is byte-identical across transports | single normative stripping algorithm; lexicographic order, no duplicates; conformance-tested (§4, §4.1, test vector 3) |
| A `.missing` write succeeds at most once per ref | `O_EXCL` / `If-None-Match: *` / condition byte, per the atomicity matrix (§5.1) |
| A `.match(H)` write on s3/http/ssh/file cannot clobber a moved ref | conditional-write CAS per transport encoding, or the OS exclusive lock for file (§5.1, §5.2) |
| An `.any` conditional hint is never binding CAS | clients requiring CAS MUST use `.match` explicitly (§5.3) |
| A default push cannot silently rewind a remote that advanced | `Match(tracked)` / `Missing` CAS lease on the remote-tracking ref (§2) |
| Fetched tips never overwrite local branches | fetch writes only `refs/remotes/<remote>/<name>`; `pull` fast-forwards from it (§2) |
| Local ref reads never observe a torn write | atomic write-then-rename with the SPEC-INDEX §4 temp-name pattern (§6) |
| Ref parsing is allocation-bounded | 128 B ref / 4 KiB `HEAD` / 1 MiB shallow caps; 32-level listing depth cap (§6) |
| At most one of merge / cherry-pick / rebase is in progress | starting a second operation while state files exist is refused (§6.1) |

One property is deliberately **not** guaranteed in v1: `.match` on the
in-process memory transport, and on the local `mkit-core` `refs::cas_write`
helper used by commands that write refs directly rather than through the
file transport, is a read-then-write race (§5.1, test vector 5). The file
transport's own `.match` is race-free (OS exclusive lock). Callers needing
CAS under concurrency through a code path other than the file transport
MUST use s3/http/ssh.

---

*~1450 words.*
