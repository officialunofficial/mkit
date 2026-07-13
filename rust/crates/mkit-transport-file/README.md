# mkit-transport-file

File-system transport for mkit, used in tests and local content-addressed
repositories.

This is a real local/served transport, not a test-only fixture: it's the
backend for `mkit+file://` remotes and for repositories served via
`mkit serve`. It also doubles as the in-tree test transport. See
`docs/specs/SPEC-TRANSPORT.md` for the `Transport` trait it implements.

## On-disk layout

```text
<root>/
  packs/<64-hex>          — raw pack bytes, written atomically
  refs/heads/main         — 65-byte wire (64-hex + '\n')
  refs/tags/v1.0          — nested dirs created on demand
```

## CAS atomicity guarantees

| Variant    | Mechanism                                                        | Race behavior |
| ---------- | ----------------------------------------------------------------- | --------------- |
| `Any`      | `write_atomic`: tmp file → `fsync` → `rename` → parent           | Last writer wins; `rename(2)` is atomic on POSIX, so no half-written file is ever exposed. |
| `Missing`  | `write_create_new`: same tmp+fsync, then a hard-link              | Only the first writer succeeds; the loser gets `AlreadyExists` → `RefConflict`. |
| `Match(H)` | OS file-lock and in-process `Mutex` around read-then-`write_atomic` | Atomic across processes on the same root, via `std::fs::File::lock` on `<root>/.mkit/refs/.lock`, held for the read-compare-write and released on `Drop` (including on panic). |
