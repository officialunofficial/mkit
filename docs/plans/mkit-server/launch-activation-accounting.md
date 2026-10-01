# WP-4.18 integrated activation accounting checkpoint

This checkpoint follows feature merge `bba0b90e5b485c564bf7a10e51d2570da903211a`
and decisions D43, D44 and D46. It records source contracts and local component
checks. Full configured release matrix and isolate resource closure remain open.

## Purge effects and the physical purse

Worker timer kind 15 and late-owner kind 13 reserve the entire local allowance
of 64 operations from the shared 960 handler purse before invoking a configured
purge handler. Reservation refusal prevents handler effects. The timer path
retains its shared local 64 allowance and indexed parent; actual metadata and
R2 calls still charge their physical wrappers. It does not charge each local
cache operation a second time against the already reserved physical allowance.

Signed admin work and ordinary Worker pipeline construction use a fresh
`RequestLocal` wrapper for the invocation. Its first callback successfully
reserves 64 from the outer request backend purse before default or custom local
invalidation. Failed reservation does not set the success flag, invoke the
callback, or bypass the normal durable kind-11 fallback. Later callbacks share
that reservation and their existing local/indexed allowances. Completed replay
has no new post-commit callback. Default-off configuration constructs no wrapper
and makes no reservation. Custom callbacks retain their obligation to honor the
passed local allowance and outgoing lifetimes; reservation alone does not prove
their implementation obeys it. Reserved allowance and measured cache calls are
separate ledger columns.

## Content-index audit delivery

Paid ContentIndex registration includes the existing kind-1 relay. Its
`WorkerRelayHook` receives the actual configured `probe_partition` root, distinct
from the optional late-owner takedown root. This supports both Single namespace
and D34 coordinator audit roots when ordinary purge is enabled independently of
takedown. Source audit events, root receipts, chain entries, head, and relay
watermark retain the existing atomic target SQL extension and deduplication.

The audit hook reserves the existing `2*n+2` operations. After the content hook,
both callback entrypoints run a pure capacity preflight with the existing
`extend_audit_batch` on temporary batch vectors. Audit inputs are bounded before
cloning. Distinct missing events produce synthetic appends using a checked
maximum-width sequence and 64-digit hash. Numeric byte padding covers an
accepted raw head up to 512 KiB plus distinct existing-receipt Equals values;
there is no 512-KiB dummy allocation. The already extended synthetic batch uses
full 100-operation validation, without adding the operation reserve again.

Only the exact private audit-capacity sentinel shrinks a combined group by
halving. Shrinking neither blocks the target nor triggers failure backoff. A
single row proceeds to unchanged authoritative target SQL extension, including
its actual head and receipt state, full 100-operation/1-MiB validation, guards,
and atomic rollback. Conservative single-row estimates grant no storage limit
exception. Malformed events, conflicting identities, and other hook errors keep
the original terminal handling. Physical target work remains one watermark
read and at most one apply per target per Worker fire.

Temporary retention includes the original rows and content-adjusted batch,
event-list and receipt-map nodes, cloned batch vectors, the synthetic head,
current typed Event/Request and source partition, detail and audit-entry JSON
intermediates, and encoded audit additions. Key/Value `Bytes` clones share raw
payload allocations. Count their vector/map nodes and new typed/encoded
allocations, rather than treating each clone as another full raw payload.
Simulation drops before real target transport, but Wasm allocator capacity can
remain high. Source and target owners must both appear in an isolate ledger if
they share an isolate.

## Focused local evidence

Owned logs are retained under `$TMPDIR/night2/d31-resume/`. The valid five-row
near-1-MiB regression first failed with the old no-op preflight: SQL rejected
the expanded group, rolled back head/watermark, and repeated alarms made no
progress. Its copied pre-fix source and log are separately hashed. With the
preflight, the same workload progresses with at most two target calls per fire.
Other focused cases cover Single/D34 roots, shared-purse exhaustion, mixed
receipts and duplicate delivery, registry restart, conflict, committed lost
reply, independent gapless chain hashing, maximum-width sequence and accepted
noncanonical head spelling, a largest source-valid single-row conservative
false positive that actually commits, and an actually oversized single apply
that still rolls back. Generic Invalid hook errors remain terminal without
shrinking. Cache-failure activation retains durable purge/audit responsibility.

These tests do not certify full 4,096-shard workerd coverage, all 28 profile
combinations, 128-MB isolate capacity, or cloud staging. The unchanged canonical
admin replay at the merge checkpoint failed with an unclassified connection
loss; its separate diagnosis does not authorize a behavior or workload waiver.
