---
spec: SPEC-INDEX
version: 2
status: draft
audience: implementers of the staging area; advisory and local-only (not exchanged between peers)
---

# SPEC-INDEX — mkit v2 repo-local index file

Status: **Advisory** for mkit. Local-only; not exchanged between
peers.
Scope: the on-disk layout of `.mkit/index`, used by the staging area.

---

## 1. Role

`.mkit/index` (the `INDEX_FILE` constant) is the staging area — a list
of paths that will be included in the next commit, each paired with an
object hash, a status byte, and (since v2) a stat cache that lets
`add`/`status` prove a worktree file unchanged in O(stat) instead of
O(content). It is repo-local; it is never serialised to a transport and
never signed.

Because it is local-only, its stability requirements are weaker than
commit / pack / ref formats. Nonetheless each version pins a layout to
prevent accidental drift and to provide a migration path for future
evolution. v2 is that anticipated migration from v1.

---

## 2. Layout

```
offset  size    field
0       4       magic            "MKIX" = 0x4D 0x4B 0x49 0x58
4       1       version          0x02
5       4       entry_count      u32 LE
9       …       entries          entry_count × entry
```

Each v2 entry:

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

A v1 entry (version byte `0x01`) omits the four stat-cache fields
(35-byte minimum instead of 67). Readers MUST accept v1 streams and
zero-fill the cache (see §5); writers always emit v2.

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

These rules are **looser** than SPEC-OBJECTS §4.1: per-segment Windows
reserved-name, trailing dot/space, and case-insensitive `.mkit`/`.git`
checks are NOT enforced at the index layer. Staging code that needs to
guarantee a clean commit MUST additionally validate via the
SPEC-OBJECTS §4.1 grammar before writing the tree object — the index
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

## 4. Stat cache & the racy-clean rule

The stat cache is an **optimisation, never a source of truth**: an
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
   never stat-match — targets are re-read.

**Racy-clean (normative):** a file modified within the filesystem's
timestamp granularity of when it was hashed can carry the same
mtime+size with different bytes. Readers MUST therefore treat as
*uncached* any entry whose `mtime_ns` is not safely older than the
index file's own mtime. The window is judged PER ENTRY: the tight
window (10ms) applies only when both the index file's mtime and the
entry's recorded mtime show sub-second precision; an entry with a
whole-second mtime (vfat/SMB mounts, tar/touch-truncated timestamps)
keeps the conservative 1-second window. Racy entries are re-hashed on
use; a later index write (whose file mtime is then newer) heals the
cache. This is git's racy-git rule applied at read time, which
preserves the on-disk cache instead of destroying it.

Producers record all four cache fields from the metadata of the
**opened file descriptor** used for hashing (not a separate pre-open
`stat`), closing the window where the path is swapped between stat and
read. Consumers that *heal* the cache after verifying an entry clean
(e.g. `status`) MUST likewise record the hash-time observation, never
a stat taken after verification — verify-then-stat can pair a fresh
stat with a stale hash.
Commands that rebuild the index from a tree (commit's post-commit sync,
checkout) SHOULD carry the cache over from the outgoing index for
entries whose path, status, and `object_hash` are unchanged.

---

## 5. Atomicity & versioning

Writes use atomic-rename: write to a sibling tempfile (named
`.<file>.tmp.<pid>.<seq>`), `fsync` the tempfile, `rename(2)` into
place, then `fsync` the parent directory so the rename itself is
durable across power loss. The `.mkit/` directory is created if absent.
(The index write is deliberately NOT part of the object store's batched
durability schedule — it is one of the durable pointers that schedule
orders itself against; see SPEC-OBJECTS §10.1.)

Readers tolerate:

- File absent → empty index.
- File zero-length → empty index.
- File > 64 MiB (`MAX_INDEX_BYTES`) → `IndexError::TooLarge`. This cap
  is hit only by pathological repos.

Version handling: readers MUST accept version bytes `0x01` (zero-filled
stat cache) and `0x02`, and MUST reject any other version with
`IndexError::UnsupportedVersion(byte)`. Writers always emit `0x02`, so
a v1 index upgrades in place on the first index-writing command.
Query commands (`status`) MUST NOT perform that upgrade — an
opportunistic cache refresh skips v1 indexes so a read-only invocation
never breaks an older binary sharing the worktree.

Additionally, readers MUST reject a `count` header that cannot possibly
fit in the remaining buffer (each entry is at minimum 67 bytes in v2 —
1 status + 32 hash + 32 stat cache + 2 path_len + 0 path — and
35 bytes in v1). A 9-byte buffer declaring `count = u32::MAX` is
rejected as `IndexError::Corrupt` before the entry-allocation loop runs.

Readers MUST reject any trailing bytes after the declared entry list.
Readers MUST also reject duplicate exact paths as `IndexError::DuplicatePath`;
an index cannot contain two live interpretations for the same repo-relative
path.

---

## 6. Version history

| Version | Changes                                                            |
|---------|--------------------------------------------------------------------|
| `0x01`  | Initial layout: status + hash + path.                              |
| `0x02`  | Adds per-entry `mtime_ns`+`size`+`ino`+`ctime_ns` stat cache (§4). v1 read-compat. |

Future versions evolving the index MUST:
- Preserve the `"MKIX"` magic as a format-family marker.
- Bump the version byte.
- Continue to reject unknown versions with
  `IndexError::UnsupportedVersion(byte)`.

---

## 7. Test vectors

1. **Empty index**: magic + version + `count=0` = 9 bytes. Record
   BLAKE3 of those bytes (informative — index is never hashed for
   protocol purposes).
2. **Single v2 entry**: path = "hello.txt", status = blob,
   `mtime_ns = 0x0102030405060708`, `size = 11`, pinned ino/ctime.
   Total length is **85 bytes** (9 header + 1 status + 32 hash +
   32 stat cache + 2 path_len + 9 path). Pinned by
   `v2_single_entry_pinned_bytes`.
3. **v1 read-compat**: the 53-byte v1 single-entry stream parses with
   `mtime_ns = 0`, `size = 0`. Pinned by
   `reads_v1_index_with_zeroed_stat_cache`.
4. **Reject `ZMIX` magic** on read → `IndexError::BadMagic`.
5. **Reject version `0x03`** → `IndexError::UnsupportedVersion`.
6. **Corrupt-path-length** (path_len > remaining bytes) →
   `IndexError::Corrupt`.
7. **64 MiB + 1 byte file** → `IndexError::TooLarge`.
8. **Bogus huge count** (9-byte buffer declaring `count = u32::MAX`)
   → `IndexError::Corrupt`. Guards against attacker-controlled
   pre-allocation.

---

## 8. Non-goals

- No merkle tree over index entries. The index is not a consensus
  artifact.
- No signature. Local-only.
- No compression. Large indexes are expected to be rare in this
  regime; if they become common, future work.
- No reflog or journal embedded in the index; those are separate
  sidecar files (out of scope for v2 spec).
