---
spec: SPEC-INDEX
version: 1
status: stable-advisory
audience: implementers of the staging area; advisory and local-only (not exchanged between peers)
---

# SPEC-INDEX &mdash; mkit repo-local index file

Status: **Advisory** for mkit. Local-only; not exchanged between
peers. See SPEC-CONVENTIONS §2 for the maturity/bindingness status
vocabulary this frontmatter uses.
Scope: the on-disk layout of `.mkit/index`, used by the staging area.

---

## 1. Role

`.mkit/index` (the `INDEX_FILE` constant) is the staging area &mdash; a list
of paths that will be included in the next commit, each paired with an
object hash, a status byte, and a stat cache that lets `add`/`status`
prove a worktree file unchanged in O(stat) instead of O(content).
It is repo-local; it is never serialized to a transport and never
signed.

Because it is local-only, its stability requirements are weaker than
commit/pack/ref formats: an implementation change here never
affects wire compatibility with any other peer.

---

## 2. Layout

```
offset  size    field
0       4       magic            "MKIX" = 0x4D 0x4B 0x49 0x58
4       1       version          0x02
5       4       entry_count      u32 LE
9       …       entries          entry_count × entry
```

Each entry:

```
[u8 status]                          see §3
[32 bytes object_hash]               BLAKE3 of the staged object; [0;32] for status=removed
[u64 LE mtime_ns]                    stat cache: worktree mtime (ns since Unix epoch,
                                     saturating) observed when object_hash was computed;
                                     0 = no cache (always re-hash)
[u64 LE size]                        stat cache: file size observed at the same time;
                                     meaningful only when mtime_ns != 0
[u64 LE ino]                         stat cache: inode number; 0 = don't check.
                                     Catches replace-by-rename swaps.
[u64 LE ctime_ns]                    stat cache: status-change time (saturating ns);
                                     0 = don't check. ctime cannot be set from
                                     userspace, catching timestamp restoration.
[u16 LE path_len]                    0 .. 4096
[path_len bytes path]                UTF-8 relative path, forward slashes only
```

Path validation rules (enforced by writers; readers reject violations
with `IndexError::Corrupt` for length bounds and `IndexError::InvalidPath`
for content):

- Non-empty.
- No leading `/`.
- Total length ≤ 4096 bytes (`MAX_PATH_LEN`).
- No path segment is `"."` or `".."`.
- No segment is empty (rejects `//`, leading/trailing `/`).
- No byte in any segment is `0x00` (NUL) or `\\` (backslash).
- The path is not `.mkit` or `.git`, and does not start with `.mkit/`
  or `.git/`. (Repo metadata cannot be staged.)
- The index is a single-stage resolved staging area: it never holds
  more than one live entry per path (no unmerged/conflict stages).

These rules are **looser** than SPEC-OBJECTS §4.1: per-segment Windows
reserved-name, trailing dot/space, and case-insensitive `.mkit`/`.git`
checks are NOT enforced at the index layer. Staging code that needs to
guarantee a clean commit MUST additionally validate via the
SPEC-OBJECTS §4.1 grammar before writing the tree object &mdash; the index
itself is local-only and a more permissive checkpoint.

---

## 3. Status byte

```
0x00    removed       entry marks a path scheduled for deletion; object_hash MUST be [0;32]
0x01    blob          regular file, object_hash is a blob
0x02    tree          reserved; not currently emitted (subtree staging is flattened to blobs)
0x03    symlink       object_hash is a blob whose data is the link target
0x04    executable    regular file with the POSIX executable bit set
                      (mode 0x04 in SPEC-OBJECTS §4.2)
```

Writers MUST emit `0x04` for staged executables. Readers MUST accept
all five defined codes. Any other value → `IndexError::BadStatus(byte)`.

---

## 4. Stat cache and the racy-clean rule

The stat cache is an **optimization, never a source of truth**: an
implementation MAY ignore it entirely (treat every entry as
`mtime_ns = 0`) without changing any observable result, only cost.

A consumer MAY skip re-reading and re-hashing a worktree file and reuse
`object_hash` only when ALL hold:

1. `mtime_ns != 0` (zero is the no-cache sentinel);
2. the live file's mtime (in saturating ns) equals `mtime_ns`;
3. the live file's size equals `size`;
4. when both the recorded and live values are nonzero: the inode
   equals `ino` and the ctime equals `ctime_ns`;
5. the live file's mode class matches `status` (a plain blob has the
   exec bits clear; an executable has any set; on platforms where the
   exec bit is not observable, both classes match). Symlink entries
   never stat-match &mdash; targets are re-read.

**Racy-clean (normative):** a file modified within the filesystem's
timestamp granularity of when it was hashed can carry the same
mtime+size with different bytes. Readers MUST therefore treat as
*uncached* any entry whose `mtime_ns` is not safely older than the
index file's own mtime. The window is judged PER ENTRY: the tight
window (10ms) applies only when both the index file's mtime and the
entry's recorded mtime show sub-second precision &mdash; this follows the
common coarse-clock granularity on the platforms mkit targets; an
entry with a whole-second mtime (vfat/SMB mounts, tar/touch-truncated
timestamps) keeps the conservative 1-second window. Racy entries are
re-hashed on use; a later index write (whose file mtime is then newer)
heals the cache. This is git's racy-git rule applied at read time,
which preserves the on-disk cache instead of destroying it.

Producers record all four cache fields from the metadata of the
**opened file descriptor** used for hashing (not a separate pre-open
`stat`), closing the window where the path is swapped between stat and
read. Consumers that *heal* the cache after verifying an entry clean
(for example, `status`) MUST likewise record the hash-time observation, never
a stat taken after verification &mdash; verify-then-stat can pair a fresh
stat with a stale hash.
Commands that rebuild the index from a tree (commit's post-commit sync,
checkout) SHOULD carry the cache over from the outgoing index for
entries whose path, status, and `object_hash` are unchanged.

---

## 5. Atomicity and versioning

Writes use atomic-rename: write to a sibling tempfile (named
`.<file>.tmp.<pid>.<seq>`), `fsync` the tempfile, `rename(2)` into
place, then `fsync` the parent directory so the rename itself is
durable across power loss. The `.mkit/` directory is created if absent.
(The index write is deliberately NOT part of the object store's batched
durability schedule &mdash; it is one of the durable pointers that schedule
orders itself against; see SPEC-OBJECTS §10.1.)

Readers tolerate:

- File absent → empty index.
- File zero-length → empty index.
- File > 64 MiB (`MAX_INDEX_BYTES`) → `IndexError::TooLarge`. This cap
  is hit only by pathological repos.

Version handling: readers MUST accept exactly the current version byte
`0x02` and MUST reject any other value &mdash; including any byte that was
ever emitted by an older mkit &mdash; with `IndexError::UnsupportedVersion(byte)`.
There is no dual-version read compatibility: the index is local-only
and advisory (§1), so an implementation change here carries no
cross-peer compatibility obligation, and mkit does not maintain
migration shims for its own local, unreleased state files (see
SPEC-CONVENTIONS §2's note on versioning).

Additionally, readers MUST reject a `count` header that cannot possibly
fit in the remaining buffer (each entry is at minimum 67 bytes &mdash;
1 status + 32 hash + 32 stat cache + 2 path_len + 0 path). A 9-byte
buffer declaring `count = u32::MAX` is rejected as `IndexError::Corrupt`
before the entry-allocation loop runs.

Readers MUST reject any trailing bytes after the declared entry list.
Readers MUST also reject duplicate exact paths as `IndexError::DuplicatePath`;
an index cannot contain two live interpretations for the same repo-relative
path.

---

## 6. Test vectors

1. **Empty index**: magic + version + `count=0` = 9 bytes. Record
   BLAKE3 of those bytes (informative &mdash; index is never hashed for
   protocol purposes).
2. **Single entry**: path = "hello.txt", status = blob,
   `mtime_ns = 0x0102030405060708`, `size = 11`, pinned ino/ctime.
   Total length is **85 bytes** (9 header + 1 status + 32 hash +
   32 stat cache + 2 path_len + 9 path). Pinned by
   `single_entry_pinned_bytes`.
3. **Reject `ZMIX` magic** on read → `IndexError::BadMagic`.
4. **Reject version `0x01`** (an old, no-longer-supported version byte,
   rejected the same as any other unrecognized value) →
   `IndexError::UnsupportedVersion`. Pinned by `rejects_old_version_0x01`.
5. **Reject version `0x03`** → `IndexError::UnsupportedVersion`.
6. **Corrupt-path-length** (path_len > remaining bytes) →
   `IndexError::Corrupt`.
7. **64 MiB + 1 byte file** → `IndexError::TooLarge`.
8. **Bogus huge count** (9-byte buffer declaring `count = u32::MAX`)
   → `IndexError::Corrupt`. Guards against attacker-controlled
   pre-allocation.

The golden vectors under `rust/tests/golden/refs-index/` pin the
current format explicitly: `index_empty.bin` / `index_3entries.bin`
carry the entries above and must round-trip byte-for-byte
(deserialize → serialize is the identity). Entries within a serialized
index MUST appear in the order they were added to the in-memory
`Index` &mdash; the format does not require path-sorted output, so
byte-identity is a property of a specific fixture's construction, not
a general "any two logically-equal indexes serialize identically"
guarantee. The generator `examples/generate_refs_index_goldens.rs`
re-emits each filename byte-identically and records every BLAKE3 in
`MANIFEST.txt`.

---

## 7. Non-goals

- No merkle tree over index entries. The index is not a consensus
  artifact.
- No signature. Local-only.
- No compression. Large indexes are expected to be rare in this
  regime; if they become common, future work.
- No reflog or journal embedded in the index; those are separate
  sidecar files (out of scope for this spec).
- No dual-version read compatibility (see §5). If a future change to
  this format is ever needed, it ships as a new current version with
  no obligation to keep reading the old one &mdash; this is a local,
  advisory file with no installed base to protect.

---

## 8. Invariants

| Invariant | Enforced by |
|---|---|
| A file is parsed only under a known layout | `"MKIX"` magic → `IndexError::BadMagic`; exactly one accepted version → `IndexError::UnsupportedVersion` (§2, §5) |
| A header cannot force pathological allocation | `entry_count` checked against the minimum entry size and remaining buffer → `IndexError::Corrupt`; 64 MiB cap → `IndexError::TooLarge` (§5) |
| The file encodes exactly its declared entries | trailing bytes rejected (§5) |
| Each path has exactly one live interpretation | duplicate exact paths → `IndexError::DuplicatePath` (§5) |
| No staged path escapes the worktree or names repo metadata | path grammar: non-empty, no leading `/`, no `.`/`..`/empty segments, no NUL or backslash, not `.mkit`/`.git` → `IndexError::InvalidPath` / `Corrupt` (§2) |
| Every entry has a defined kind, and removals carry no object | status whitelist → `IndexError::BadStatus` (§3); `removed` entries MUST carry `[0;32]`, enforced at read time → `IndexError::RemovedHasHash` (§2, §3) |
| The stat cache never changes an observable result | cache is an optimization only &mdash; all five match conditions must hold, and racy entries (not safely older than the index file's mtime) are re-hashed (§4) |
| A cache hit reflects the bytes that were actually hashed | cache fields recorded from the opened descriptor used for hashing, never a stat taken after verification (§4) |
| A reader never sees a torn index | tempfile + `fsync` + `rename` + parent-dir `fsync` (§5); absent or zero-length file reads as empty (§5) |

The index is local-only and advisory: never transported, never signed,
no merkle structure (§1, §7). Nothing above is load-bearing for history
integrity &mdash; that lives in SPEC-OBJECTS.
