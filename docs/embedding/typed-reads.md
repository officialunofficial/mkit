# Typed reads for embedding code

Use `mkit_server::reads::ReadAccess` for trusted storage queries.
`Pipeline::read_access()` supplies the pipeline's shard map and visibility default.
You can also borrow a store, shard map, and matching default with `ReadAccess::new`.
Both Single and D34 route through that map.
No accessor returns storage keys, encoded rows, or codec types.

## Accessors

| Question | Accessor | Answer |
| --- | --- | --- |
| Does a repository exist, and what visibility is stored? | `repository_visibility` | Visibility and an opaque equality revision, or absence |
| Which branch pair is published? | `published_branch` | Head, packmap, last applied sequence, published sequence, and membership generation |
| Which member pack holds an object, and is it denied now? | `locate_object` or `locate_objects` | Pack, frame location, decode metadata, and live object-or-pack denial |
| What canonical kind does a member have? | `member_inventory` | Validated kind, canonical and logical lengths, and delta base |
| What are a member's canonical bytes? | `read_member_canonical` | Verified bytes, delta depth, and aggregate decoded bytes |
| What happened to the exact accepted fork? | `fork_job_status` | Phase, failure, completed result, inventory, authority, replay, and reservation identity |
| Did the original owner-admitted fork complete and settle? | `recover_completed_fork` | Completed result and inventory with live original replay and reservation evidence |
| Does an authenticated retry replay a completed fork? | `Pipeline::completed_fork` | Existing request-bound witness; obtain the result through `fork_repo` |

## Authorization and freshness

Authorize the repository before you use this facade.
The facade is for trusted code and does not run authentication or policy hooks.
It can observe private repositories and membership that is not reachable from a public ref.
Do not expose it directly through an anonymous endpoint.
Use the existing pipeline readers for authorized content serving.
Those paths retain their uniform absence, reachability proofs, and final guards.
The new accessors do not change those paths.

Each call reads storage again. No accessor caches rows or decoded bytes across calls.
You can borrow a budgeted store to charge the existing invocation allowance.
Member lookup retains the existing row, page, and membership caps.
`locate_objects` preserves batched index routing and accepts at most `MAX_OBJECT_LOOKUP_IDS` IDs.
Denial observations remain fresh per returned member and are not an atomic batch snapshot.
Canonical decoding uses your `MemberReadLimits` and a fresh operation-local memo.
The canonical resolver keeps its live object and pack denial checks, including delta bases.
A false `denied` observation never replaces a final serving guard.
Trusted policy code can inspect denied membership and immutable inventory.

Absence never consults global blob existence.
`repository_visibility` returns absence for a missing repository record.
Membership queries report only the requested repository's member evidence.
Corrupt consulted rows and exhausted lookup caps fail closed with an error.
A missing publication ledger does not fall back to live heads or projections.
The applied sequence can exceed the published sequence when advances await clearance.

## Visibility consistency

Read visibility before and after a metadata read. Require matching `revision` values.
Treat absence, a changed revision, or an error as an unusable observation.
The token includes repository identity and both stored rows.
A missing visibility row uses the configured deployment default.

The revision is an equality token, not a monotonic journal counter or a lock.
If you maintain a policy journal, also bracket these reads with your journal observations.
Require the same non-pending journal revision before and after.
A pending change to private must fail closed even if storage still says public.
No server accessor can observe a journal that belongs to its caller.
Keep any caller-owned pause and lock policies. Stable storage rows do not override them.
Do not use equal tokens to infer that no intervening write occurred if identical rows can recur.
Recheck policy at the final disclosure boundary.

## Migration from internal reads

| Previous import or path | Need | Replacement |
| --- | --- | --- |
| `adapter_spi::codec::{RepoRecord, RepoVisibilityV1, StoredVisibility}` and their decoders | Repository existence, effective visibility, and a coherent observation | `repository_visibility`; keep caller journal brackets |
| `adapter_spi::keys::{repo_record, repo_visibility}` and coordinator construction | Route repository metadata without knowing keys | `repository_visibility` through the configured `ReadAccess` |
| `adapter_spi::publication::read` and ref-shard construction | Published head and packmap, sequence, and generation | `published_branch` |
| `adapter_spi::index::{locate_many, LocatedObject}` | Repository membership and pack location | `locate_objects` for batches, or `locate_object` for one ID |
| `takedown::inventory::entry` | Validated canonical kind and size | `member_inventory` |
| `indexed::resolve::{member_object, MemberCache}` and `NoopMetrics` | Bounded canonical manifest and external-base decoding | `read_member_canonical`; use `decoded_bytes` to debit aggregate work |
| `fork::{read_job, ForkJobV1, SettleV1, binding}` | Exact job binding, lifecycle, result, inherited packs, and retained landing evidence | `fork_job_status` |
| `adapter_spi::keys::{replay, reservation}` and replay/reservation decoders | Original completed replay and exact committed settlement | `recover_completed_fork` with trusted `ForkReplayIdentity` |
| `Value` wrapping of the job's pending reservation | Check original pending reservation and procedure | `recover_completed_fork` validates this internally |

For public branch disclosure, keep your authorized `Pipeline::read_ref` check and compare its head with the published pair.
A stored pair alone does not authorize a public read.

For confirmed lineage, require `Phase::Done` and compare `status.result` with your retained confirmed result.
Require an authority generation, no grant epoch, and no namespace creation if your landing requires owner admission.
The general status query reports other valid jobs without imposing that deployment policy.

Recovery requires current destination authorization by your caller.
Compare returned authority and reservation identity with your trusted retained landing evidence before adopting the result.
Recovery accepts owner-admitted completions with an authority generation.
It requires no quota charges, grant, namespace cap, or namespace creation.
Use the general status query for other valid jobs and the pipeline for authenticated retries.
It does not authenticate an expired envelope, admit work, read the source, publish refs, or run effects.
Missing, pending, and failed jobs return no completed result.
Conflicting, malformed, inconsistent, or pruned completion evidence fails closed.
The existing authenticated `completed_fork` witness remains available and unchanged.

Public contracts such as `ContentIndex::holders`, `RepoId`, and `ShardMap` remain available.
Storage adapter implementations can still use `store::adapter_spi` for maintenance.
Embedding business logic should use the typed accessors instead.
This change adds APIs. It changes no wire or stored format and requires no store reset.
