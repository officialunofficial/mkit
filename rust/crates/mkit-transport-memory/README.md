# mkit-transport-memory

In-memory transport for mkit, `HashMap`-backed, used in unit tests and fuzz
harnesses.

A `HashMap`-backed store that holds pack bytes and refs entirely in RAM,
implementing the same `Transport` trait (`docs/specs/SPEC-TRANSPORT.md`) every
other backend does. The trait's 7 verbs don't include attestation methods &mdash;
those live in `mkit-attest`.

## CAS guarantees

| Variant     | Guarantee                                                                                                        |
| ----------- | ----------------------------------------------------------------------------------------------------------------- |
| `Any`       | Unconditional clobber. Lock-free inside the `Mutex`.                                                              |
| `Missing`   | Fails with `RefConflict` if the ref already exists. Atomic w.r.t. concurrent callers sharing one instance, because the whole `HashMap` is held under a `Mutex` for the read-then-write. |
| `Match(H)`  | Fails with `RefConflict` if the ref is absent or has a different value. Same `Mutex`-based atomicity as `Missing`. |

No TOCTOU for in-process callers sharing the same `MemoryTransport`. Not
durable across process restarts &mdash; that's the point: it's the fast,
zero-setup transport for tests and fuzz targets.
