---
spec: SPEC-REFS
version: 1
status: stable-normative
audience: implementers of compatible ref stores and transports
---

# SPEC-REFS &mdash; mkit v1 ref wire format and semantics

Status: **Normative** and **Stable** for mkit v1 &mdash; the wire format,
namespace layout, and CAS semantics below are settled and backed by
shipped, tested transports (memory, file, s3, http, ssh). One
deliberately-scoped limitation is called out inline rather than left
implicit: the in-process memory transport's `.match` CAS is a
read-then-write race by design (§5.1, §8) &mdash; it is single-fiber by
construction and never shared across processes, so this is a
documented, permanent property of that one code path, not an open
question about the format itself, and it does not block this
document's stability. (The local `mkit-core` `refs::cas_write` helper
used by commands that write refs directly is, as of #637, serialized
under a per-ref lock and is *not* part of this exception &mdash; see
§5.1.) See SPEC-CONVENTIONS §2 for what draft/stable and
normative/advisory mean.
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
past the last-seen tip rejects the update as non-fast-forward. On a
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
- Empty segment (that is, `//`, trailing `/`, leading `/`) → invalid.
- Any byte in `{0x00, '\\'}` → invalid.
- Any byte outside the grammar → invalid.
- Any segment ending in `.lock` → invalid (the canonical lock-file
  suffix; for example `refs/heads/main.lock` is reserved).
- Final segment equal to `HEAD` → invalid (shadows the repo-level
  `HEAD` pointer; for example `HEAD` and `refs/heads/HEAD` are rejected).

**Notable divergences from Git ref naming:**

- No `@` allowed (Git permits `@{reflog}`-style refs; mkit does not).
- No `+`, `:`, `~`, `^`, `?`, `*`, `[` allowed.
- No Unicode in ref names.
- Case-sensitive: `main` and `Main` are distinct.

This is a deliberately restrictive grammar to simplify cross-transport
name validation.

Implementations MUST validate ref names with this grammar at **every**
transport boundary &mdash; writing a ref, reading a ref, listing refs, and
parsing a client-supplied name. No transport may silently lower case
or canonicalize.

---

## 4. Prefix semantics for `listRefs`

This section is normative for **transport** implementations of
`listRefs(prefix)`. The local `mkit-core` API (see `refs.rs`) exposes
the simpler `list_refs(mkit_dir)`/`list_tags(mkit_dir)` which return
every ref under `refs/heads/` or `refs/tags/` respectively &mdash; the
prefix has been pre-applied implicitly by the function choice. The
algorithm below is what a transport server / a future
`list_refs_with_prefix` core API MUST implement to remain cross-
transport compatible.

`listRefs(prefix) -> [{name, hash}]` walks the ref namespace and
returns all refs whose full name begins with `prefix` **at a path-
component boundary**. The `name` in each returned tuple has `prefix`
(plus the separating `/`) stripped.

**Correction:** an earlier version of this section specified a third
case &mdash; matching `F` against `P'` as a bare string prefix with no
separator required &mdash; and justified it with a worked example
(`listRefs("refs/heads/feat")` matching `refs/heads/feature`). That
case is removed: it made the prefix-to-name mapping **non-injective**
(`refs/heads/feat/x` and `refs/heads/featx` both stripped to the name
`x` under the old rule, a real defect this document's own §4.1
uniqueness invariant explicitly disallows) and could produce a
returned `name` starting with `/` or otherwise violating the §3 name
grammar. Prefix matching now requires a component boundary,
unconditionally &mdash; matching Git's own `for-each-ref`/`show-ref`
prefix semantics.

Normative behavior (this is the single source of truth; all transports
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
        else:
            # F does not extend P' at a component boundary — including
            # the case where F is a bare string-prefix match with no
            # following '/' (for example P' = "refs/heads/feat", F =
            # "refs/heads/featx"). This is NOT a match.
            skip
```

In practice the common case is:

- `listRefs("refs/heads")` → returned names are `{"main", "feature/x"}`.
- `listRefs("refs/heads/")` → same result.
- `listRefs("refs/heads/feat")` → returns `{"x"}` if `refs/heads/feat/x`
  exists. It does **not** return anything derived from
  `refs/heads/featx` or `refs/heads/feature` &mdash; those names do not
  extend `refs/heads/feat` at a `/` boundary, so they are excluded
  entirely, not truncated into a malformed name.

Callers MUST NOT assume `prefix` includes a trailing `/`; the transport
normalizes either form.

The spec pins the behavior above; transports MUST conform or fail
conformance tests. `mkit-transport-memory` and `mkit-transport-s3`'s
`list_refs` are pinned against this exact rule by the regression test
`list_refs_prefix_respects_path_component_boundary` (one per crate).

### 4.1 Ordering and duplicates

Returned refs MUST be sorted lexicographically by `name`. No duplicates
(`name` is unique within the result). Empty result is returned as an
empty slice, not null.

### 4.2 Prefix validation

The prefix itself must be empty or pass the same grammar as a ref name
(§3), possibly with a single trailing `/`. Transports MUST reject
invalid prefixes (the core helper `validate_ref_prefix` returns a
boolean; transports wrap the false case as their domain-specific
`InvalidRef` error, for example `RefError::InvalidRefName` on the file
backend).

---

## 5. CAS (`updateRef`) semantics

```
updateRef(name, condition, new_hash)

condition := .any
           | .missing
           | .match(expected_hash)
```

`.any` &mdash; unconditional write. Clobbers any existing value.

`.missing` &mdash; write only if the ref does not currently exist. If it
exists → `RefConflict`.

`.match(H)` &mdash; write only if the ref currently contains `H`. If it does
not exist or contains a different hash → `RefConflict`.

### 5.1 Per-transport atomicity matrix

(Normative &mdash; this is what conformance tests verify.)

| Transport | `.any`      | `.missing`                            | `.match`                                                       | Notes |
|-----------|-------------|---------------------------------------|----------------------------------------------------------------|-------|
| memory    | atomic*     | atomic*                               | **NOT atomic** &mdash; read-then-write race                          | *Single-threaded by construction. Across fibers: no lock. |
| file      | atomic      | atomic (via `O_EXCL` create)          | atomic &mdash; OS exclusive file lock (`<root>/.mkit/refs/.lock`) serializes the read-check-write across processes | Lock guard released on drop (including panic-unwind). |
| s3        | atomic      | atomic via `If-None-Match: *`         | atomic via `If-Match: "<md5-of-wire>"`                         | Requires server that supports conditional writes (R2 and post-2024 AWS S3 do; generic S3 may not). |
| http      | atomic      | atomic via `If-None-Match: *`         | atomic via `If-Match: "<hex-hash>"`                            | Worker-flavored server. Generic S3 and nginx do NOT conform. |
| ssh       | atomic      | atomic (`OP_WRITE_REF_IF_ABSENT` path via condition byte) | atomic (`CONDITION_MATCH` with 32-byte expected hash)          | Server enforces CAS; client trusts `STATUS_ERROR`. |

*memory CAS:* v1 ships the non-atomic `.match` implementation for the
in-process memory transport only. The file transport's `.match` is atomic
across processes via the OS lock above. As of #637, the local `mkit-core`
`refs::cas_write` helper used by commands that mutate refs directly on
disk (without going through the file transport) is also atomic across
processes: its `.match` arm takes a dedicated `<common_dir>/refs.lock`
OS exclusive lock (distinct from the file transport's
`<root>/.mkit/refs/.lock`, but the same blocking-kernel-lock primitive)
around the read-check-write, so two uncoordinated callers on the same
repo &mdash; for example `branch -m` and `commit`, or `update-ref` from two linked
worktrees &mdash; can no longer both observe a stale `current` value and both
report success while one write is silently lost. Only the in-process
memory transport's `.match` remains genuinely non-atomic (single-fiber
races), matching the row above.

*Coordination with local worktree operations:* `<root>/.mkit/refs/.lock`
by itself only serializes the file transport against concurrent instances
of itself &mdash; it does not, on its own, coordinate against a `commit`,
`checkout`, or `gc` running locally against the same directory via the
`worktrees.lock`/`worktree.lock`/`refs-history-<branch>.lock` path. **There is no
rule that closes this gap** &mdash; see SPEC-CONCURRENCY §3.1, which documents
it as a real, currently unresolved coordination gap, and states mkit's
supported deployment shape (a served root a worktree-owning process
does not also mutate directly) rather than a locking fix.

### 5.2 ETag encoding divergence

The `.match(H)` condition is serialized differently by transport:

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
value. This is an optimization and MUST NOT be treated as binding CAS
&mdash; a server that ignores the header is still conforming for `.any`.
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
`RefError::InvalidHead`/`RefError::InvalidRef` respectively.

Writers MUST use atomic write-then-rename on local disk to avoid torn
reads. The temp-name pattern is `.<file>.tmp.<pid>.<seq>`, identical
to SPEC-INDEX §5.

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
`--continue`/`--abort`/`--skip`.

```
.mkit/MERGE_HEAD           64-hex plus '\n'  — other parent of an in-progress merge
.mkit/CHERRY_PICK_HEAD     64-hex plus '\n'  — commit being applied by a cherry-pick
.mkit/ORIG_HEAD            64-hex plus '\n'  — HEAD before the operation (for --abort)
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
   on an identical seeded state &mdash; results MUST be byte-identical.
4. **`.missing` race**: two concurrent `.missing` writers to the same
   ref &mdash; exactly one succeeds, the other returns `RefConflict`. Run on
   s3, http, ssh.
5. **`.match` on file transport, exactly-one-winner**: two concurrent
   `.match` writers to the same ref &mdash; exactly one succeeds, the other
   returns `RefConflict` and the ref is left at the winner's value.
   Enforced by the OS exclusive lock (§5.1); the local `mkit-core`
   `refs::cas_write` helper (not the file transport) has the same
   exactly-one-winner property since #637, proven by
   `cas_match_race_never_loses_an_update_across_uncoordinated_callers`.
6. **Ref name grammar**: valid &mdash; `main`, `feat/v1.0-beta`,
   `release/2024_09`. Invalid &mdash; `feat/..`, `/main`, `main@v1`,
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
| A ref value on any byte-exact transport is exactly 65 bytes: 64 lowercase hex plus `\n` | writers MUST emit lowercase; readers reject uppercase with `InvalidRef` (§1) |
| Every ref name crossing a transport boundary satisfies the §3 grammar | validation at **every** boundary &mdash; write, read, list, client-supplied parse; no silent case-folding or canonicalization (§3) |
| No ref shadows `HEAD` or a lock file | grammar rejections for final-segment `HEAD` and the `.lock` suffix (§3) |
| `listRefs(prefix)` is byte-identical across transports | single normative stripping algorithm; lexicographic order, no duplicates; conformance-tested (§4, §4.1, test vector 3) |
| A `.missing` write succeeds at most once per ref | `O_EXCL`/`If-None-Match: *` / condition byte, per the atomicity matrix (§5.1) |
| A `.match(H)` write on s3/http/ssh/file cannot clobber a moved ref | conditional-write CAS per transport encoding, or the OS exclusive lock for file (§5.1, §5.2) |
| An `.any` conditional hint is never binding CAS | clients requiring CAS MUST use `.match` explicitly (§5.3) |
| A default push cannot silently rewind a remote that advanced | `Match(tracked)`/`Missing` CAS lease on the remote-tracking ref (§2) |
| Fetched tips never overwrite local branches | fetch writes only `refs/remotes/<remote>/<name>`; `pull` fast-forwards from it (§2) |
| Local ref reads never observe a torn write | atomic write-then-rename with the SPEC-INDEX §5 temp-name pattern (§6) |
| Ref parsing is allocation-bounded | 128 B ref / 4 KiB `HEAD` / 1 MiB shallow caps; 32-level listing depth cap (§6) |
| At most one of merge / cherry-pick / rebase is in progress | starting a second operation while state files exist is refused (§6.1) |

One property is deliberately **not** guaranteed in v1: `.match` on the
in-process memory transport is a read-then-write race (§5.1, test
vector 5) &mdash; it is single-fiber by construction and never shared across
processes, so this is scoped to that one in-memory code path. The file
transport's own `.match` is race-free (OS exclusive lock), and the
local `mkit-core` `refs::cas_write` helper used by commands that write
refs directly rather than through the file transport is, as of #637,
likewise serialized under a per-ref lock (§5.1) and is *not* part of
this exception. Callers needing CAS under concurrency through the
in-process memory transport MUST use a different transport (file/s3/
http/ssh) or the local `refs::cas_write` path.
