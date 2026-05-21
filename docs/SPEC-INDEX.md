---
spec: SPEC-INDEX
version: 1
status: draft
audience: implementers of the staging area; advisory and local-only (not exchanged between peers)
---

# SPEC-INDEX — mkit v1 repo-local index file

Status: **Advisory** for mkit v1. Local-only; not exchanged between
peers.
Scope: the on-disk layout of `.mkit/index`, used by the staging area.

---

## 1. Role

`.mkit/index` (the `INDEX_FILE` constant) is the staging area — a list
of paths that will be included in the next commit, each paired with an
object hash and a status byte. It is repo-local; it is never serialised
to a transport and never signed.

Because it is local-only, its stability requirements are weaker than
commit / pack / ref formats. Nonetheless v1 pins a layout to prevent
accidental drift and to provide a migration path for future evolution.

---

## 2. Layout

```
offset  size    field
0       4       magic            "MKIX" = 0x4D 0x4B 0x49 0x58
4       1       version          0x01
5       4       entry_count      u32 LE
9       …       entries          entry_count × entry
```

Each entry:

```
[u8 status]                          see §3
[32 bytes object_hash]               BLAKE3 of the staged object; [0;32] for status=removed
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

## 4. Atomicity

Writes use atomic-rename: write to a sibling tempfile (named
`.<file>.tmp.<pid>.<seq>`), `fsync` the tempfile, `rename(2)` into
place, then `fsync` the parent directory so the rename itself is
durable across power loss. The `.mkit/` directory is created if absent.

Readers tolerate:

- File absent → empty index.
- File zero-length → empty index.
- File > 64 MiB (`MAX_INDEX_BYTES`) → `IndexError::TooLarge`. This cap
  is hit only by pathological repos.

Additionally, readers MUST reject a `count` header that cannot possibly
fit in the remaining buffer (each entry is at minimum 35 bytes:
1 status + 32 hash + 2 path_len + 0 path). A 9-byte buffer declaring
`count = u32::MAX` is rejected as `IndexError::Corrupt` before the
entry-allocation loop runs.

---

## 5. Future versions

Future versions evolving the index MUST:
- Preserve the `"MKIX"` magic as a format-family marker.
- Bump the version byte.
- Continue to reject unknown versions with
  `IndexError::UnsupportedVersion(byte)`.

---

## 6. Test vectors

1. **Empty index**: magic + version + `count=0` = 9 bytes. Record
   BLAKE3 of those bytes (informative — index is never hashed for
   protocol purposes).
2. **Single entry**: path = "README.md", status = blob, hash = BLAKE3
   of an empty blob object. Record the serialised bytes — total
   length is **53 bytes** (9 header + 1 status + 32 hash + 2 path_len
   + 9 path).
3. **Reject `ZMIX` magic** on read → `IndexError::BadMagic`.
4. **Corrupt-path-length** (path_len > remaining bytes) →
   `IndexError::Corrupt`.
5. **64 MiB + 1 byte file** → `IndexError::TooLarge`.
6. **Bogus huge count** (9-byte buffer declaring `count = u32::MAX`)
   → `IndexError::Corrupt`. Guards against attacker-controlled
   pre-allocation.

---

## 7. Non-goals

- No merkle tree over index entries. The index is not a consensus
  artifact.
- No signature. Local-only.
- No compression. Large indexes are expected to be rare in this
  regime; if they become common, future work.
- No reflog or journal embedded in the index; those are separate
  sidecar files (out of scope for v1 spec).

---

*~500 words.*
