# Fork acceptance semantic fixtures

Governing rule: SPEC-SERVER §9.9. These are in-memory semantic fixtures, not an
encoded protocol format. The executable runner is **tests/fork_acceptance.rs**.

The baseline is a private source at sequence one, deletion boundary zero,
with head `0a` repeated 32 times and packmap pack `01` repeated 32 times.
The packmap inventory names pack `02`; that pack depends on external supplier
`03`. Each whole pack contributes 100 bytes and ten index entries. All logical
revisions initially contain byte `01` repeated 32 times. The destination is
unregistered and private, with three staged members owned by operation `01`,
zero refs, zero visible members, and writes disabled. Admission has already
charged 300 bytes and one operation. The reservation and job expire at 90;
the signed request expires at 100. Staging is ordered at point ten, the final
source proof at eleven, and acceptance at twelve. Explicit limits are three
packs, four edges, 128 branch bytes, 30 index entries, 300 inherited bytes,
and 4,096 abstract work units.

Each action in **acceptance.txt** changes exactly the named fact; the runner
pins its result or stable code. Unacquired observations are distinct from
revisioned authoritative absence. A phantom addition changes the authoritative
all-members revision even when previously sampled rows remain absent.

Companion tests mutate every atomic observation revision and every inherited
pack proof, including the transitive supplier. Replay tests atomically save
the accepted job, response, and reservation disposition, then lose the source
proof. The saved result remains available without construction or a new debit.
The reference digest is BLAKE3 over concatenated sorted pack IDs.
