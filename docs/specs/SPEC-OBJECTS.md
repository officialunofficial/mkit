---
spec: SPEC-OBJECTS
version: 1
status: stable
audience: implementers of compatible tools producing or consuming mkit on-disk objects
---

# SPEC-OBJECTS — mkit v1 on-disk object format

Status: **Normative** for mkit v1.
Scope: `.mkit/objects/` content and the byte layout of every object type.
Endianness: **little-endian** throughout. All hashes are 32-byte BLAKE3.

This document defines what W2 (on-disk V1 bump) and W3 (identity / remix
generalisation) must implement. External tools MUST be able to produce and
consume these bytes with only this document.

---

## 1. Object types

```
ObjectType (u8)         name
0x01                    blob
0x02                    tree
0x03                    commit
0x04                    remix
0x05                    chunked_blob
0x06                    delta
0x07                    tag            (annotated / signed tag; new in v1, issue #230)
```

`0x01`–`0x06` are unchanged in v1. `0x07` (tag) is additive: it appends
a new storable object type and does NOT alter the layout, signing bytes,
or hashes of any pre-existing type, so all earlier golden vectors remain
valid. Readers MUST accept `0x01..=0x07`.

`delta` objects are **pack-only**. They MUST NOT appear in the object store
and MUST NOT be served by `downloadObject`-style APIs. Deltas are resolved
during pack unpacking into a materialised base type (`blob`, `tree`,
`commit`, etc.).

---

## 2. V1 prologue — every object

Every stored object begins with:

```
offset  size  field              value
0       1     object_type        one of 0x01..0x07 (see §1)
1       4     magic              ASCII "MKT1" = 0x4D 0x4B 0x54 0x31
5       1     schema_version     0x01
6       …     body               type-specific (see §3-§8)
```

The prologue applies to **all seven object types**. Rationale:

1. Without a version byte, any field addition silently shifts every
   hash.
2. Partial prologue (commit + remix only) leaves four object types
   unversioned and makes readers branch on type before they can detect a
   future format change. All-types prologue lets the prologue itself be
   the single branching point.
3. Cost: 5 bytes per object. Negligible against the 33-byte minimum
   overhead a stored blob already carries.

Readers MUST reject any of:
- `object_type` not in `0x01..0x07` → `InvalidObjectType`
- `magic` != `"MKT1"` → `InvalidMagic`
- `schema_version` != `0x01` → `UnsupportedObjectVersion`

There is no v0. mkit does not read mkit-era bytes.

---

## 3. Blob (`0x01`)

```
[prologue 6]
[u32 LE len]
[len bytes data]
```

No interpretation of `data`. `len = 0` is valid (empty blob). Upper bound
is enforced at the storage layer: the object store rejects objects
> 1 GiB. A pack entry independently caps at the packfile total limit
(see SPEC-PACKFILE).

---

## 4. Tree (`0x02`)

```
[prologue 6]
[u32 LE entry_count]                      0..=1_000_000
repeat entry_count:
    [u32 LE name_len]                     1..=255
    [name_len bytes name]                 UTF-8 (see §4.1)
    [u8 mode]                             see §4.2
    [32 bytes object_hash]
```

`entry_count > 1_000_000` → `TooManyEntries`.

**Identity:** a `Tree`'s object id is its Binary Merkle Tree root over the
entry leaves (one leaf per `(name, mode, object_hash)` triple, in the
canonical lex order), NOT `BLAKE3` of these bytes. The byte layout is
unchanged. See [SPEC-MERKLE-OBJECTS](SPEC-MERKLE-OBJECTS.md) §3.2.

### 4.1 Entry name rules

Normative:

- `name_len` ∈ `[1, 255]`. Zero-length name is illegal.
- Forbidden bytes **anywhere** in name: `0x00`, `/` (`0x2F`), `\` (`0x5C`).
- Forbidden exact names: `"."`, `".."`.
- Forbidden trailing characters: `.` (`0x2E`) and SPACE (`0x20`). Windows
  silently strips these, which would alias one entry onto another of the
  same bare name. Applies to the last byte of `name` only — interior
  dots and spaces are accepted.
- Forbidden case-insensitively: the bare names `.mkit` and `.git`. ASCII
  case-folding only; names containing non-ASCII bytes are not folded
  (they remain constrained by every other rule above). This is a
  Git CVE-2021-21300 family defence.
- Forbidden Windows reserved device names, case-insensitively, with or
  without an extension: `CON`, `PRN`, `AUX`, `NUL`, `COM1`-`COM9`,
  `LPT1`-`LPT9`. Comparison is against the stem (the bytes before the
  first `.`). `COM0` and `LPT0` are NOT reserved.
- No further Unicode validation performed. Implementations SHOULD reject
  input that is not well-formed UTF-8 but MAY pass it through byte-for-byte.

Violations of any rule above → `InvalidEntryName`.

Additionally, entries within a single tree MUST be sorted
lexicographically (byte-wise ascending) by `name` with no duplicates.
Readers MUST reject unsorted trees with `InvalidEntryOrder`. This is
load-bearing: tree hashes are only reproducible across implementations
when ordering is canonical.

### 4.2 Entry mode

```
0x01    blob         regular file content
0x02    tree         subdirectory
0x03    symlink      symbolic link; object_hash points to a blob whose
                     data is the link target path
0x04    executable   regular file, executable bit set (POSIX 0o755)
```

Mode `0x04` is new in v1 (previously absent; see red-team R-41 — silent
data-loss bug for any POSIX workflow). Writers MUST emit `0x04` for any
file with the POSIX executable bit set at staging time. Non-POSIX hosts
MAY round-trip `0x04` bytes opaquely.

Any other mode byte → `InvalidEntryMode`.

### 4.3 Rename detection

mkit detects **exact** renames: because every blob is named by its BLAKE3
content id, a deletion and an addition that share an object id are the same
bytes at two paths — an exact move (git's `similarity index 100%`), found
by an O(n) hash match with no heuristic and no false positives. `status`
and `diff` render these as `R` by default (`--no-renames` opts out),
scoped per diff as git does.

**Not yet detected:** rename-with-edits (similarity < 100%) and copy
detection (`-C`). Those require git's content-similarity scoring; mkit's
chunked/merkle blobs give a natural shared-chunk similarity signal, so they
are a tractable follow-up rather than a structural gap. `merge` still
treats all moves as (delete, add) pairs. Departure tracked from red-team
R-21.

---

## 5. Commit (`0x03`)

```
[prologue 6]
[32 bytes tree_hash]
[u32 LE parent_count]                     0..=1_000
repeat parent_count:
    [32 bytes parent_hash]
[Identity author]                         see §9
[u32 LE message_len]
[message_len bytes message]               UTF-8 by convention (see below), NOT null-terminated
[u64 LE timestamp]                        seconds since Unix epoch
[32 bytes signer]                         Ed25519 public key
[32 bytes message_hash]                   may be zero (see §5.1)
[32 bytes content_digest]                 may be zero (see §5.1)
[64 bytes signature]                      Ed25519, see SPEC-SIGNING
```

Differences from mkit:
- `author_mid: u64` → `Identity` tagged union (§9). (W2.)
- `timestamp: u32` → `u64`. Avoids 2106 overflow (red-team 7d / Team Lead
  7d).
- Relative field order of `signer` and `message` is preserved.

Message bytes are UTF-8 **by convention**: writers SHOULD emit UTF-8,
but readers MUST NOT reject non-UTF-8 message bytes (matching every
existing implementation; load-bearing for histories imported from
systems with legacy encodings).

### 5.1 `message_hash` / `content_digest`

These remain **core fields** on `Commit` but are
**NOT part of the commit signing bytes** (see SPEC-SIGNING §3). They are
optional off-chain annotation slots for downstream consumers. Core
stores them because:
1. They are 32 bytes each and carry a stable meaning regardless of any
   consumer.
2. Stripping them from core would require a sidecar file per commit and
   break in-place round-trip.

Writers with no annotation to record MUST emit them as `0x00`*32 (zero
hash). Readers MUST NOT reject a commit because they are zero.
(This resolves red-team R-45.)

### 5.2 Root commits

`parent_count = 0` is valid and denotes a root commit.
`parent_count > 1_000` → `TooManyParents`.

---

## 6. Remix (`0x04`)

```
[prologue 6]
[32 bytes tree_hash]
[u32 LE parent_count]                     0..=1_000
repeat parent_count:
    [32 bytes parent_hash]
[u32 LE source_count]                     0..=10_000
repeat source_count:
    [32 bytes upstream_id]                was project_id in mkit
    [32 bytes commit_hash]
[Identity author]                         see §9
[u32 LE message_len]
[message_len bytes message]
[u64 LE timestamp]                        widened from u32 (see §5)
[32 bytes signer]                         Ed25519 public key
[64 bytes signature]                      Ed25519, see SPEC-SIGNING
```

Naming: the 32-byte source identifier is called `upstream_id` in v1 (the
byte layout is unchanged — the name transition is cosmetic).

### 6.1 Source sort invariant

Sources MUST be sorted lexicographically by `(upstream_id, commit_hash)`,
primary key `upstream_id`. Duplicate `(upstream_id, commit_hash)` pairs
are illegal. Readers reject unsorted sources with `InvalidSourceOrder`.

`RemixSource` is **opaque in core**: `upstream_id` is 32 bytes of caller-
chosen content. Typical values include `BLAKE3(repo_url)` or any other
32-byte identifier that uniquely names the upstream. Core never
interprets it.

---

## 6a. Tag (`0x07`)

An **annotated / signed tag** object (issue #230). Lightweight tags are
*not* objects — they are a bare `refs/tags/<name>` ref pointing straight
at a commit (see SPEC-REFS). A tag object is created only by
`mkit tag -a` (annotated) or `mkit tag -s` (signed); in both cases the
`refs/tags/<name>` ref points at the **tag object hash**, and the tag
object's `target` field points at the tagged object.

```
[prologue 6]                              object_type=0x07
[32 bytes target]                         hash of the tagged object
[u8 target_type]                          ObjectType of target (0x01..=0x05, 0x07; NOT 0x06 delta)
[u32 LE name_len]                         1..=4096
[name_len bytes name]                     short tag name (e.g. "v1.0.0"); no \0 / \\
[Identity tagger]                         see §9
[u32 LE message_len]
[message_len bytes message]               UTF-8, NOT null-terminated; may be empty
[u64 LE timestamp]                        seconds since Unix epoch
[32 bytes signer]                         Ed25519 public key
[64 bytes signature]                      Ed25519 over the tag signing bytes (SPEC-SIGNING §4a)
```

Rules:

- `target_type` MUST be a storable object type. `0x06` (delta) is
  pack-only and rejected with `TagTargetTypeInvalid`. Recording the
  target type lets a verifier display the tag without fetching the
  target.
- `name` is the **short** ref name, not a full `refs/tags/...` path.
  Empty, over 4096 bytes, or containing `\0` / `/` / `\\` →
  `TagNameInvalid`. The full ref-name grammar (SPEC-REFS) is enforced at
  ref-write time; the object layer enforces only this floor so the wire
  form is unambiguous.
- An **annotated, unsigned** tag carries an all-zero `signature`
  (`0x00`×64). A verifier MUST treat an all-zero signature as
  "unsigned" — it does not verify as a valid Ed25519 signature, so
  `mkit verify` on an unsigned annotated tag fails the signature check.
- A **signed** tag's `signature` is `Ed25519.sign(signer_seed,
  tag_signing_hash)` (SPEC-SIGNING §4a). `signer` is the verification
  key; `tagger` is an independent attribution claim (same separation as
  commit `author` vs `signer`, SPEC-SIGNING §6).

The tag object is content-addressed like every other object; its hash is
`BLAKE3(serialised tag bytes)`.

---

## 7. Chunked blob (`0x05`)

```
[prologue 6]
[u64 LE total_size]
[u32 LE chunk_size]                       0 == content-defined (FastCDC)
[u32 LE chunk_count]                      0..=1_000_000
repeat chunk_count:
    [32 bytes chunk_hash]                 each chunk stored as its own blob
```

`chunk_size = 0` indicates the manifest was produced by FastCDC and
chunk lengths are recovered by re-reading each chunk blob. See
SPEC-FASTCDC.
`chunk_size > 0` indicates fixed-size chunking with the stated size
(final chunk may be shorter).

Reassembly: concatenate each `chunk_hash` blob's contents in order.
The concatenated length MUST equal `total_size`.

`chunk_count > 1_000_000` → `TooManyChunks`.

**Identity:** a `ChunkedBlob`'s object id is its Binary Merkle Tree root
(leaves = a metadata leaf binding `total_size`/`chunk_size`, then the
chunk ids), NOT `BLAKE3` of these manifest bytes. The byte layout above is
unchanged; only the byte→id function differs. See
[SPEC-MERKLE-OBJECTS](SPEC-MERKLE-OBJECTS.md) §3.1.

---

## 8. Delta (`0x06`)

Pack-only. See SPEC-DELTA for the instruction format and SPEC-PACKFILE
for framing. The on-disk layout (if ever serialised alone, which
implementations SHOULD NOT do) is:

```
[prologue 6]
[32 bytes base_hash]
[u32 LE result_size]
[u32 LE instr_len]
[instr_len bytes instructions]
```

---

## 9. Identity — tagged union

```
[u8 kind]
[u16 LE len]
[len bytes payload]
```

Kinds:

```
0x01    ed25519         len MUST be 32; payload = raw 32-byte Ed25519 public key
0x02    did_key         len >= 1;       payload = UTF-8 `did:key:...` string, minus the scheme prefix
                                        (i.e. the multibase-encoded key material, starting with 'z')
0x03    opaque          len >= 1;       payload = arbitrary bytes defined by adapter
```

Rules:

- `len = 0` is **illegal** for every kind → `InvalidIdentity`.
- `len > 4096` → `IdentityTooLarge`.
- Unknown `kind` → `UnknownIdentityKind`.
- Two identities compare equal iff `kind` and `payload` bytes are
  byte-equal. No case-folding, no canonicalisation.

Identity serialisation is used in **both** the on-wire serialised commit
and the signing bytes (see SPEC-SIGNING). The bytes are identical in both
contexts. This means the identity length is variable at signing time,
which is why the `len` field is always explicit.

---

## 10. Storage

Objects are stored at `.mkit/objects/<dd>/<rrrrrrrrr...r>` where `<dd>`
is the lowercase-hex first byte of the **object id** and `<r...>` is the
remaining 62 hex chars.

The object id is **type-dependent**: a `Tree` (`0x02`) or `ChunkedBlob`
(`0x05`) is addressed by its Binary Merkle Tree root
([SPEC-MERKLE-OBJECTS](SPEC-MERKLE-OBJECTS.md)); every other type is
addressed by `BLAKE3(object bytes)`. On read, the store MUST recompute the
id with the same type-dependent rule and fail `HashMismatch` if it does
not match the path (for a merkelized type this re-derives and re-checks the
root, which proves the whole child set is present and correctly ordered).
Objects > 1 GiB MUST be rejected.

`.mkit/` directory: presence of `.mkit/objects` is the repository marker.
A conforming repository MUST also carry a `.mkit/format` file declaring
the object-addressing format (`bmt-v1`); an implementation MUST refuse to
open a repository whose marker is absent or unrecognised
(`IncompatibleRepoFormat`) rather than mis-read a pre-merkle store under
the current id rule. See SPEC-INDEX for the `.mkit/index` sidecar.

### 10.1 Durability

Object writes MUST be atomic with respect to readers (temp file +
rename; a crash mid-write leaves at most a temp file, never a visible
object that fails the read-time hash check), and MUST uphold the
ordering invariant:

> An object MUST NOT become *visible* (resolvable at its final path)
> before its bytes are *durable*, and a ref, index, or recovery-log
> entry MUST only be written after every object it references is
> durable.

Within that invariant, implementations MAY amortise durability across a
multi-object command (batched mode: stage objects as temp files, issue
one full flush, then rename all and flush the touched shard
directories — the design of git's `core.fsyncMethod=batch`). Per-object
flushing remains a conforming, stricter schedule. Batched mode's
directory flushes carry the dirent ordering on metadata-journaling
filesystems in ordered-data mode; deployments on filesystems without
that property SHOULD use per-object mode.

A writer that finds an object already visible (cross-process dedup)
MUST still flush that object's shard directory before referencing it,
because the process that renamed it may not have flushed the dirent
yet.

---

## 11. Trailing-byte rule

Every object deserialiser MUST verify that after parsing the declared
layout there are zero remaining bytes. Extra bytes → `TrailingData`.
This prevents trivial amplification and prologue-replay attacks.

---

## 12. Version history

| Version | Released | Changes                                                          |
|---------|----------|------------------------------------------------------------------|
| `0x01`  | v1.0     | First mkit format. See §2 for prologue. No v0 compatibility.     |

`schema_version` stays at `0x01`. Adding the `tag` object type (`0x07`,
#230) is an **additive object-type allocation within v1**: it introduces
a new `object_type` byte and a new body layout but changes no existing
type's bytes, so `schema_version` is NOT bumped and every pre-tag golden
vector is unaffected. A version bump is reserved for changes that alter
an existing type's layout.

Merkle object addressing (`Tree`/`ChunkedBlob` keyed by BMT root,
[SPEC-MERKLE-OBJECTS](SPEC-MERKLE-OBJECTS.md)) likewise leaves every
type's **bytes** unchanged — only the bytes→id function changes — so
`schema_version` is NOT bumped. The break it does introduce (every
`Tree`/`ChunkedBlob` and thus every `Commit` re-addresses) is guarded
instead by the mandatory `.mkit/format` = `bmt-v1` repository marker
(§10): a pre-merkle store has no marker and is refused at open. Pre-1.0,
no migration is provided.

Future versions MUST increment `schema_version` and MUST preserve the
`"MKT1"` magic prefix. The magic byte string is normative — readers are
allowed to route on `magic` before consulting `schema_version`, enabling
multi-version readers.

---

## 13. Test vectors (implementer MUST produce)

1. **Empty blob hash**: `BLAKE3(prologue{0x01,MKT1,0x01} ‖ u32(0))`
   — 10 bytes total input. Record the resulting hex digest.
2. **Empty tree hash**: `BLAKE3(prologue{0x02,MKT1,0x01} ‖ u32(0))`
   — 10 bytes total input.
3. **Canonical single-file tree**: one entry `{name="README.md",
   mode=0x01, object_hash=<hash of §13.1>}`. Record both the serialised
   bytes and the resulting BLAKE3 digest.
4. **Identity round-trip**: encode `Identity{kind=0x01, len=32,
   payload=[0xAA; 32]}` → must be exactly 35 bytes.
5. **Root commit with zero message_hash/content_digest and Ed25519
   identity**: serialise and record signing bytes hex +
   cross-domain-verification-negative hex.
6. **Remix with two sources (identical upstream_id, distinct
   commit_hash)**: verify sort orders by secondary key.
7. **ChunkedBlob with `chunk_size=0` and 3 chunks**: verify prologue
   present and length=6+8+4+4+32*3=118.
8. **Annotated tag** (`target_type=0x03`, ed25519 tagger, non-empty
   message, all-zero signature): record serialised bytes + BLAKE3.
9. **Signed tag** (same shape, signed with seed `[0x07;32]` over the
   `mkit.tag\0` domain): record serialised bytes, the canonical tag
   signing bytes, the signing hash, and the 64-byte Ed25519 signature.

Vectors 1–7 are committed under `rust/tests/golden/objects/`; the tag
vectors 8–9 under `rust/tests/golden/tags/`. Each set ships a
`MANIFEST.txt` and per-vector `.json` sidecar carrying the BLAKE3
digest, so external implementations can cross-verify byte-for-byte.

---

## 14. Invariants

Properties that MUST hold for every conformant reader/writer, and the
mechanism that enforces or detects each:

| Invariant | Enforced by |
|---|---|
| Every stored object is one of the seven known types under `"MKT1"` / `schema_version 0x01` | prologue rejection: `InvalidObjectType` / `InvalidMagic` / `UnsupportedObjectVersion` (§2) |
| An object's bytes always match its id | read-time recomputation under the type-dependent id rule → `HashMismatch`; for merkelized types this also proves the child set present and correctly ordered (§10) |
| No stored object exceeds 1 GiB | storage-layer rejection (§3, §10) |
| An object encodes exactly its declared layout, nothing more | trailing-byte rule → `TrailingData` (§11) |
| Tree entries are canonical: lex-sorted byte-wise, no duplicates | reader rejection `InvalidEntryOrder` (§4) |
| Tree entry names cannot alias, escape, or shadow repo metadata | name grammar → `InvalidEntryName` (§4.1); mode whitelist → `InvalidEntryMode` (§4.2) |
| Remix sources are canonical and duplicate-free | `(upstream_id, commit_hash)` sort → `InvalidSourceOrder` (§6.1) |
| Collection counts are bounded | `TooManyEntries` ≤ 1 000 000 (§4); `TooManyParents` ≤ 1 000 (§5.2); `source_count` ≤ 10 000 (§6); `TooManyChunks` ≤ 1 000 000 (§7) |
| Identity payloads are non-empty, bounded, and of known kind | `InvalidIdentity` / `IdentityTooLarge` / `UnknownIdentityKind` (§9) |
| A tag targets only a storable object, with an unambiguous name | `target_type` whitelist → `TagTargetTypeInvalid`; name floor → `TagNameInvalid` (§6a) |
| Delta objects never appear in the object store | pack-only rule (§1, §8) |
| Reassembled `ChunkedBlob` content is exactly `total_size` bytes | reassembly length check (§7) |
| A merkle-addressing reader never mis-reads a pre-merkle store | mandatory `.mkit/format` = `bmt-v1` marker → `IncompatibleRepoFormat` (§10, §12) |
| A visible object is durable; refs/index/log entries reference only durable objects | atomic temp-file + rename write and the ordering invariant (§10.1) |

These are format-level guarantees. Signature guarantees are specified in
SPEC-SIGNING; per-object tamper evidence for merkelized types in
SPEC-MERKLE-OBJECTS §6.

---

*~1750 words.*
