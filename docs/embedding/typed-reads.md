# Typed reads for embedding code

Use `mkit_server::reads::ReadAccess` for trusted storage queries.
`Pipeline::read_access()` supplies the pipeline's shard map, visibility default, and takedown-denial mode.
You can also borrow a store, shard map, matching visibility default, and matching `takedown_denial` value with `ReadAccess::new`.
Both Single and D34 route through that map.
No accessor returns storage keys, encoded rows, or codec types.

## Accessors

| Question | Accessor | Answer |
| --- | --- | --- |
| Does a repository exist, and what visibility is stored? | `repository_visibility` | Visibility and an opaque equality revision, or absence |
| What visibility was declared, even before the repository record exists? | `declared_visibility` | The stored declaration and an opaque equality revision, or absence when no declaration exists |
| Which branch pair is published? | `published_branch` | Head, packmap, last applied sequence, published sequence, and membership generation |
| Which member pack holds an object, and is it denied now? | `locate_object` or `locate_objects` | Pack, frame location, decode metadata, and live object-or-pack denial |
| Which of these packs index an object? | `object_index_in_packs` | Exact pack IDs and validated frame/decode metadata, in supplied order |
| Is a pack currently visible in the chosen view? | `pack_witness` and `PackWitness::visible` | Fresh member and published-member witnesses, decoded independently |
| What canonical kind does a member have? | `member_inventory` | Validated kind, canonical and logical lengths, and delta base |
| What are a member's canonical bytes? | `read_member_canonical` | Verified bytes, delta depth, and aggregate decoded bytes |
| What happened to the exact accepted fork? | `fork_job_status` | Phase, failure, completed result, inventory, authority, replay, and reservation identity |
| Did the original owner-admitted fork complete and settle? | `recover_completed_fork` | Completed result and inventory verified against the Done job; replay and reservation rows are checked when present and may be absent after acknowledgement or expiry |
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
When takedown denial is enabled, denial observations remain fresh per returned member and are not an atomic batch snapshot.
When disabled, member locations report `denied = false` and canonical reads do not consult block or denial-action rows.
Inventory and other metadata reads continue in both modes.
Enabling denial on an existing store requires the migration and backfill described in the operations documentation.
`object_index_in_packs` accepts at most `MAX_OBJECT_INDEX_PACKS` (1,024) packs,
reads at most `OBJECT_INDEX_BATCH_SIZE` (128) exact keys per batch, and uses at most eight store calls.
An empty query uses no calls. Present answers retain input order and duplicates;
missing rows are omitted. Supply trusted lengths in `PackRef::len`, for example
from a confirmed `ForkPack::bytes`. Every frame must fit its corresponding pack.
This query reads indexes only: it does not establish membership, publication,
denial clearance, or ref reachability. Validate witnesses separately.
`pack_witness` uses one two-key read on the membership partition.
Both accessors charge through the supplied store, including failed reads;
an error discards the entire answer. Neither increases the caller's budget.
Canonical decoding uses your `MemberReadLimits` and a fresh operation-local memo.
When denial is enabled, the canonical resolver keeps its live object and pack denial checks, including delta bases.
A false `denied` observation never replaces a final serving guard.
Trusted policy code can inspect denied membership and immutable inventory.

Absence never consults global blob existence.
`repository_visibility` returns absence for a missing repository record;
use `declared_visibility` to read a declaration that precedes the record,
for example a private-origin lock taken ahead of a fork.
Membership queries report only the requested repository's member evidence.
Corrupt consulted rows and a lookup cap that cannot change on retry fail
closed with an error.
A missing publication ledger does not fall back to live heads or projections.
The applied sequence can exceed the published sequence when advances await clearance.

## Error classes

Every accessor reports one of three error classes.
`invalid_argument` means your call is wrong, such as a non-branch ref name or
a lookup above the documented cap.
A corrupt or undecodable stored row, or stored rows that contradict each
other, is permanent: `internal`. A retry cannot fix stored data; repair or
remove the row first. An object-index row cap (`TooManyRows`) is also
permanent, since the stored row count cannot shrink on retry.
A store or I/O failure, a malformed reply such as a wrong row count, and a
page or membership lookup cap are retryable: `unavailable`.
Each accessor's `# Errors` section lists the classes it can return.

You decide which errors reach your own clients. The wire answers of the
pipeline are unchanged: storage failures still collapse to the uniform
retryable or absent outcomes clients already see.

## Pack visibility witnesses

`PackWitness::visible(writer, generation)` requires **both** `member` and
`published` rows to exist. Each witness must be unheld, match the supplied
membership generation, and either have `published = true` or be observed in a
writer view. A hold blocks writers too. Sequence and boundary fields do not
change this rule. The serving profile currently uses generation zero; do not
substitute namespace authority generation. This is the internal witness
clearance rule applied to both rows, as required for confirmed lineage evidence.
The internal serving view's own row selection and policy checks remain unchanged.

Both rows are decoded even if one is missing or invisible. The empty immediate
membership representation decodes to generation/sequence zero, published true,
held false, boundary false, exactly as in the internal reader. A corrupt partner
is an error. Visibility is a fresh observation, not authorization, a denial
check, an atomic multi-call snapshot, or a final disclosure guard.

## Visibility consistency

Read visibility before and after a metadata read. Require matching `revision` values.
Treat absence, a changed revision, or an error as an unusable observation.
The token includes repository identity and both stored rows.
A missing visibility row uses the configured deployment default.
`declared_visibility` brackets the declaration alone: it never substitutes the
default, and its revision covers the declaration and repository identity only.
Revisions never compare across the two accessors.

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
| `adapter_spi::keys::repo_visibility` read directly, for a declaration taken before the record | Pre-record visibility, such as a private-origin lock | `declared_visibility` |
| `adapter_spi::keys::{repo_record, repo_visibility}` and coordinator construction | Route repository metadata without knowing keys | `repository_visibility` through the configured `ReadAccess` |
| `adapter_spi::publication::read` and ref-shard construction | Published head and packmap, sequence, and generation | `published_branch` |
| `adapter_spi::index::{locate_many, LocatedObject}` | Repository membership and pack location | `locate_objects` for batches, or `locate_object` for one ID |
| `adapter_spi::keys::object_index` and `codec::decode_object_index` | Exact index rows within retained packs and frame bounds | `object_index_in_packs` with trusted `PackRef` lengths |
| `adapter_spi::keys::{membership, published_member}` and `publication::Witness::decode` | Joint live pack visibility | `pack_witness` and `PackWitness::visible` |
| `takedown::inventory::entry` | Validated canonical kind and size | `member_inventory` |
| `indexed::resolve::{member_object, MemberCache}` and `NoopMetrics` | Bounded canonical manifest and external-base decoding | `read_member_canonical`; use `decoded_bytes` to debit aggregate work |
| `fork::{read_job, ForkJobV1, SettleV1, binding}` | Exact job binding, lifecycle, result, inherited packs, and retained landing evidence | `fork_job_status` |
| `adapter_spi::keys::{replay, reservation}` and replay/reservation decoders | Original completed replay and exact committed settlement | `recover_completed_fork` with trusted `ForkReplayIdentity` |
| `Value` wrapping of the job's pending reservation | Check original pending reservation and procedure | `recover_completed_fork` validates this internally |

For public branch disclosure, keep your authorized `Pipeline::read_ref` check and compare its head with the published pair.
A stored pair alone does not authorize a public read.

For confirmed lineage, require `Phase::Done` and compare `status.result` with your retained confirmed result.
`status.packs` already contains the full confirmed inventory, including pack lengths
in `ForkPack::bytes`, object counts, packmap markers, and delta-base markers.
Require an authority generation, no grant epoch, and no namespace creation if your landing requires owner admission.
The general status query reports other valid jobs without imposing that deployment policy.

Recovery requires current destination authorization by your caller.
Compare returned authority and reservation identity with your trusted retained landing evidence before adopting the result.
Recovery accepts authority-fenced completions with an authority generation, including a first fork into a new namespace.
It requires no quota charges, grant, or namespace cap.
A fork that created its destination namespace (`ForkAuthority::creates_namespace`) is recovered like any other: creation changes neither the reservation nor the replay record, and recovery also requires the namespace record to be present and well formed, read in the same batch; removing it later (for example by a takedown) makes recovery fail closed.
A job carrying a grant epoch is refused: the pipeline never records one, and a grant a later epoch may have revoked cannot be proven from retained evidence.
Use the general status query for other valid jobs and the pipeline for authenticated retries.
It does not authenticate an expired envelope, admit work, read the source, publish refs, or run effects.
Missing, pending, and failed jobs return no completed result.
Conflicting, malformed, inconsistent, or pruned completion evidence fails closed.
The existing authenticated `completed_fork` witness remains available and unchanged.

Public contracts such as `ContentIndex::holders`, `RepoId`, and `ShardMap` remain available.
Storage adapter implementations can still use `store::adapter_spi` for maintenance.
Embedding business logic should use the typed accessors instead.
This change adds APIs. It changes no wire or stored format and requires no store reset.

## Test fixtures

Enable `mkit-server/test-support` only in test dependencies. It is off by default.
Use `mkit_server::test_support::TestSeeder` to seed repository records, visibility,
and pack witnesses through the core's current codecs and routing. Read seeded
visibility through `ReadAccess::repository_visibility` and compare the typed
answer. These fixture writes bypass authorization and effects; they are for
tests, not application mutations. Use pipeline operations for real writes.

`store::adapter_spi` remains for storage adapters. Embedders' tests should use
`test-support` instead of encoding storage rows directly, so fixtures track
format changes. This feature introduces no wire or stored-format change.
