# GHSA-003 — `mkit-core` key-file load follows symlinks; save is not crash-atomic

| | |
|---|---|
| **Severity** | Medium |
| **CVSS v3.1** | 6.3 (`AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N`) — local attacker with shared filesystem write access; high complexity (requires racing or pre-positioning a symlink); high confidentiality + integrity impact on success. |
| **Affected** | `mkit-core` and `mkit-cli` `< 0.3.0` |
| **Patched in** | `0.3.0` |
| **CWE** | CWE-59 (Link Following), CWE-367 (TOCTOU), CWE-276 (Incorrect Default Permissions) |
| **Discoverer** | mkit maintainers, internal review |

## Summary

The Ed25519 key-file load and save paths in `mkit_core::sign` had
three related issues that combine to allow a local attacker (or a
shared-volume mount on a multi-user host) to redirect, replace, or
silently corrupt the user's signing key.

1. **`load_key` followed symlinks.** `std::fs::metadata(path)`
   followed by `std::fs::read(path)` are two separate path-based
   syscalls. An attacker who could write into `.mkit/keys/` was
   able to swap `default.key` for a symlink between the two calls
   (TOCTOU), or pre-position it as a symlink to a 32-byte file the
   attacker owned. Result: mkit signed with the attacker's key, or
   read 32 bytes of an arbitrary 0600 file the user could read
   (e.g. another `id_ed25519`).

2. **`save_key` was not crash-atomic.** It used
   `OpenOptions::truncate(true)` on the target path, then
   `write_all` + `sync_all`. SIGINT, OOM, or power loss between
   `truncate` and `sync` left a 0-byte (or partial) `default.key`.
   The next `mkit commit` (which auto-keygen'd at the time —
   GHSA-001) generated a brand-new identity in place, silently
   rotating the user's signer.

3. **`.mkit/keys/` directory mode was the umask default.**
   Typically `0755`, allowing other users on the host to `inotify`
   the directory and race symlink swaps against the load path.

`fs::read` additionally reallocates a growing `Vec` while reading
the seed; intermediate allocations could persist secret bytes in
freed heap chunks even after `Vec::zeroize` ran on the final
allocation.

## Affected behaviour

- Any flow that loads `.mkit/keys/default.key` or the secp256k1 /
  p256 raw key files. That covers `mkit commit`, `mkit attest`,
  `mkit verify`, `mkit cherry-pick`, `mkit rebase`, `mkit merge`.
- The non-atomic save path was reachable via `mkit keygen`,
  `mkit commit` auto-keygen, and `mkit attest` repo-key
  auto-keygen.

## Reproducer (TOCTOU sketch)

Requires write access to the victim's `.mkit/keys/` directory
(default 0755) and the ability to schedule against `mkit commit`.

```sh
# In a loop, race against the user:
while true; do
  rm -f /victim/repo/.mkit/keys/default.key
  ln -s /victim/.ssh/id_ed25519 /victim/repo/.mkit/keys/default.key
  sleep 0.001
  rm -f /victim/repo/.mkit/keys/default.key
  cp /attacker-owned-32-bytes /victim/repo/.mkit/keys/default.key
  chmod 600 /victim/repo/.mkit/keys/default.key
done
```

The race window is small but real on slow filesystems / under load.

## Mitigation in 0.3.0

`load_key` (`mkit_core::sign`):

- Opens the file with `O_NOFOLLOW`. The kernel returns `ELOOP` if
  the final component is a symlink → `MkitError::KeyPathIsSymlink`.
- `fstat`s the **open file handle** (not a path-based stat) so the
  inode that gets read is provably the inode that was permission-
  checked.
- Enforces `mode == 0600` (`InsecureKeyPermissions`),
  `meta.uid() == geteuid()` (`InsecureKeyOwner`), and immediate-
  parent directory `mode <= 0700` (`InsecureKeyDir`).
- Uses `read_exact` into a stack `[u8; 32]` so secret bytes are
  never on the heap.
- Rejects files longer than 32 bytes via a 1-byte probe read.

`save_key`:

- Tightens the parent directory to `0700` first; refuses if the
  parent is a symlink.
- Writes to a uniquely-named tmp file in the same directory with
  `O_CREAT | O_EXCL | O_NOFOLLOW` and mode `0600`.
- `sync_all`s the data, `rename(2)`s the tmp into place, then
  `sync_all`s the parent directory descriptor. On any failure the
  tmp file is unlinked.

`SecretSeed::eq` was a hand-rolled XOR-OR loop that LLVM is
permitted to short-circuit; replaced with
`subtle::ConstantTimeEq` so the constant-time guarantee is pinned
at the type contract.

`KeyPair::generate` and `KeyPair::from_seed` now scrub the local
seed buffer explicitly after the move; `Secp256k1Signer::new` and
`P256Signer::new` scrub their `mut secret` parameter.

## Workarounds for users on `< 0.3.0`

- Keep `.mkit/keys/` on a private home directory at mode 0700; do
  not place it on shared volumes (NFS, bind mounts, dev
  containers, multi-user `/srv` paths).
- After a crash or interrupted `mkit keygen`, verify
  `default.key` is exactly 32 bytes before the next
  `mkit commit` — a 0-byte file was a sign of partial write, and
  the next commit would silently generate a new identity (this is
  partially under GHSA-001 too).
- Upgrade.

## Credit

Found in-house during the 0.3.0 hardening review.

## References

- Patch: <https://github.com/officialunofficial/mkit/pull/91>
- Spec: `docs/SPEC-SIGNING.md` §7 (Key file format)
- Threat model: `docs/THREAT-MODEL.md`
