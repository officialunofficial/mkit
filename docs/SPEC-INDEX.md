# SPEC-INDEX — mkit v1 repo-local index file

Status: **Advisory** for mkit v1. Local-only; not exchanged between
peers.
Scope: the on-disk layout of `.mkit/index`, used by the staging area.

---

## 1. Role

`.mkit/index` is the staging area — a list of paths that will be
included in the next commit, each paired with an object hash and a
mode. It is repo-local; it is never serialised to a transport and
never signed.

Because it is local-only, its stability requirements are weaker than
commit / pack / ref formats. Nonetheless v1 pins a layout to prevent
accidental drift and to provide a migration path for future evolution.

---

## 2. Layout

Current zmit implementation uses magic `"ZMIX"` + version `0x01`
(`zmit/src/index.zig:12-15`). v1 MUST rename to `"MKIX"` — this is the
correct rename scope because, unlike the pack magic, the index file
never round-trips between tools and a rename is cheap.

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
[32 bytes object_hash]               BLAKE3 of the staged object
[u16 LE path_len]                    1 .. 4096
[path_len bytes path]                UTF-8 relative path, forward slashes only
```

Paths MUST be relative to the repo root, use `/` as separator, and
pass SPEC-OBJECTS §4.1 name rules for each path segment except that
`/` is allowed as a separator.

---

## 3. Status byte

```
0x00    removed       entry marks a path scheduled for deletion
0x01    blob          regular file, object_hash is a blob
0x02    tree          reserved; not currently emitted (subtree staging is flattened to blobs)
0x03    symlink       object_hash is a blob whose data is the link target
```

Executable bit (mode 0x04 in SPEC-OBJECTS §4.2) is tracked in v1 via a
planned `0x04 executable` status byte. Implementations MUST emit
`0x04` for staged executables; readers MUST tolerate all 5 defined
codes. Other values → `IndexCorrupt`.

---

## 4. Atomicity

Writes use atomic-rename (`zmit/src/index.zig:166-178`): write to a
sibling tempfile, `fsync`, then `rename` into place. This is already
implemented; v1 preserves it.

Readers tolerate:

- File absent → empty index.
- File zero-length → empty index.
- File > 64 MiB → `IndexTooLarge` (`zmit/src/index.zig:79`). This cap
  is hit only by pathological repos and stays in v1.

---

## 5. No cross-version compatibility

v1 readers MUST reject `"ZMIX"`-prefixed files: there is no upgrade
path. A zmit repo migrating to mkit MUST either commit all staged
work, run `mkit add .` (rebuilding the index from scratch), or wipe
`.mkit/index` manually.

Future versions evolving the index MUST:
- Preserve the `"MKIX"` magic as a format-family marker.
- Bump the version byte.
- Continue to reject unknown versions with
  `UnsupportedIndexVersion`.

---

## 6. Test vectors (implementer MUST produce)

TO BE FIXED IN IMPLEMENTATION:

1. **Empty index**: magic + version + `count=0` = 9 bytes. Record
   BLAKE3 of those bytes (informative — index is never hashed for
   protocol purposes).
2. **Single entry**: path = "README.md", status = blob, hash = BLAKE3
   of an empty blob object. Record the serialised bytes (47 bytes =
   9 + 1 + 32 + 2 + 9).
3. **Reject `ZMIX` magic** on read.
4. **Corrupt-path-length** (path_len > remaining bytes) →
   `IndexCorrupt`.
5. **64 MiB + 1 byte file** → `IndexTooLarge`.

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
