# Stored encodings written by v0.5.0

The JSON files contain exact UTF-8 bodies from the v0.5.0 serde layouts.
Versioned row tests prepend the literal version byte `01` and exercise the
production decoder and encoder. Unversioned JSON is stored verbatim.
Nested DTO and enum fixtures pin their serialized bytes independently.
Binary fixtures are hexadecimal bytes, decoded by tests before use.

Fixtures were captured from representative codec/verification/preservation tests;
additional enum and nested DTO cases follow the v0.5.0 declarations. The codecs
were checked against the v0.5.0 tag. Tests never update fixtures. Keep these
v0.5.0 bytes when adding later fixtures; new fields must have serde defaults.

| Type / variant family | Canonical fixture |
|---|---|
| `admin::Response` | `admin-Response.json` |
| `admin::automatic::Event` | `admin-automatic-Event.json` |
| `admin::ledger::Head` | `admin-ledger-Head.json` |
| `admin::ledger::Nonce` | `admin-ledger-Nonce.json` |
| `admin::ledger::Operation` | `admin-ledger-Operation.json` |
| `indexed::checkpoint::ExtractionGroupMember` | `indexed-checkpoint-ExtractionGroupMember.json` |
| `indexed::checkpoint::ExtractionSource` | `indexed-checkpoint-ExtractionSource.json` |
| `indexed::checkpoint::ExtractionV1` | `indexed-checkpoint-ExtractionV1.json` |
| `indexed::checkpoint::Kind` | `indexed-checkpoint-Kind-pack.json` |
| `indexed::checkpoint::Kind` | `indexed-checkpoint-Kind-packlist.json` |
| `indexed::checkpoint::Kind` | `indexed-checkpoint-Kind-unknown.json` |
| `indexed::checkpoint::MemberCursor` | `indexed-checkpoint-MemberCursor.json` |
| `indexed::checkpoint::MemberLists` | `indexed-checkpoint-MemberLists.json` |
| `indexed::checkpoint::Outcome` | `indexed-checkpoint-Outcome-base_capped.json` |
| `indexed::checkpoint::Outcome` | `indexed-checkpoint-Outcome-base_missing.json` |
| `indexed::checkpoint::Outcome` | `indexed-checkpoint-Outcome-blocked.json` |
| `indexed::checkpoint::Outcome` | `indexed-checkpoint-Outcome-closure_capped.json` |
| `indexed::checkpoint::Outcome` | `indexed-checkpoint-Outcome-closure_missing.json` |
| `indexed::checkpoint::Outcome` | `indexed-checkpoint-Outcome-decode_budget.json` |
| `indexed::checkpoint::Outcome` | `indexed-checkpoint-Outcome-external_too_deep.json` |
| `indexed::checkpoint::Outcome` | `indexed-checkpoint-Outcome-extraction_unavailable.json` |
| `indexed::checkpoint::Outcome` | `indexed-checkpoint-Outcome-object_blocked.json` |
| `indexed::checkpoint::Outcome` | `indexed-checkpoint-Outcome-open_closure.json` |
| `indexed::checkpoint::Outcome` | `indexed-checkpoint-Outcome-packlist_missing.json` |
| `indexed::checkpoint::Phase` | `indexed-checkpoint-Phase-await_delivery.json` |
| `indexed::checkpoint::Phase` | `indexed-checkpoint-Phase-closure_resolve.json` |
| `indexed::checkpoint::Phase` | `indexed-checkpoint-Phase-decode.json` |
| `indexed::checkpoint::Phase` | `indexed-checkpoint-Phase-emit_index.json` |
| `indexed::checkpoint::Phase` | `indexed-checkpoint-Phase-extract.json` |
| `indexed::checkpoint::Phase` | `indexed-checkpoint-Phase-recheck.json` |
| `indexed::checkpoint::Phase` | `indexed-checkpoint-Phase-verify.json` |
| `indexed::checkpoint::Phase` | `indexed-checkpoint-Phase-watch.json` |
| `indexed::checkpoint::VerifyJobV1` | `indexed-checkpoint-VerifyJobV1.json` |
| `indexed::job::extraction::member::Frame` | `indexed-job-extraction-member-Frame.json` |
| `indexed::job::extraction::member::Lookup` | `indexed-job-extraction-member-Lookup.json` |
| `indexed::publication::resume::BaseCursor` | `indexed-publication-resume-BaseCursor.json` |
| `indexed::publication::resume::Exhaustion` | `indexed-publication-resume-Exhaustion-DecodeBudget.json` |
| `indexed::publication::resume::Exhaustion` | `indexed-publication-resume-Exhaustion-IndexCalls.json` |
| `indexed::publication::resume::Exhaustion` | `indexed-publication-resume-Exhaustion-Traversal.json` |
| `indexed::publication::resume::Progress` | `indexed-publication-resume-Progress.json` |
| `indexed::publication::resume::TerminalFailure` | `indexed-publication-resume-TerminalFailure-DeltaDepth.json` |
| `indexed::publication::resume::TerminalFailure` | `indexed-publication-resume-TerminalFailure-OpenClosure.json` |
| `indexed::selection::SelectionFact` | `indexed-selection-SelectionFact-Blob.json` |
| `indexed::selection::SelectionFact` | `indexed-selection-SelectionFact-Manifest.json` |
| `indexed::selection::SelectionFact` | `indexed-selection-SelectionFact-Other.json` |
| `indexed::selection::SelectionFact` | `indexed-selection-SelectionFact-Tree.json` |
| `indexed::state::VerificationV1` | `indexed-state-VerificationV1-pending.json` |
| `indexed::state::VerificationV1` | `indexed-state-VerificationV1-rejected.json` |
| `indexed::state::VerificationV1` | `indexed-state-VerificationV1-verified.json` |
| `indexed::state::VerificationV1` | `indexed-state-VerificationV1-verified-publication.json` |
| `purge::Request` | `purge-Request.json` |
| `purge::Trigger` | `purge-Trigger-CACHE_PURGE_TRIGGER_LEASE_DELETION.json` |
| `purge::Trigger` | `purge-Trigger-CACHE_PURGE_TRIGGER_MANUAL.json` |
| `purge::Trigger` | `purge-Trigger-CACHE_PURGE_TRIGGER_SUSPENSION.json` |
| `purge::Trigger` | `purge-Trigger-CACHE_PURGE_TRIGGER_TAKEDOWN.json` |
| `purge::Trigger` | `purge-Trigger-CACHE_PURGE_TRIGGER_VISIBILITY_CHANGE.json` |
| `purge::delivery::Progress` | `purge-delivery-Progress.json` |
| `store::codec::AbortReason` | `store-codec-AbortReason-ABANDONED.json` |
| `store::codec::AbortReason` | `store-codec-AbortReason-EPOCH_MISMATCH.json` |
| `store::codec::AbortReason` | `store-codec-AbortReason-INTERNAL.json` |
| `store::codec::AbortReason` | `store-codec-AbortReason-PACK_MISSING.json` |
| `store::codec::AbortReason` | `store-codec-AbortReason-REF_CONFLICT.json` |
| `store::codec::AbortReason` | `store-codec-AbortReason-REPLAY_RACE.json` |
| `store::codec::AbortReason` | `store-codec-AbortReason-UNSPECIFIED.json` |
| `store::codec::Backlog` | `store-codec-Backlog.json` |
| `store::codec::BlockV1` | `store-codec-BlockV1.json` |
| `store::codec::EpochLease` | `store-codec-EpochLease.json` |
| `store::codec::HoldV1` | `store-codec-HoldV1.json` |
| `store::codec::HolderV1` | `store-codec-HolderV1.json` |
| `store::codec::LeaseRecovery` | `store-codec-LeaseRecovery.json` |
| `store::codec::LeasedShard` | `store-codec-LeasedShard.json` |
| `store::codec::NamespaceRecord` | `store-codec-NamespaceRecord.json` |
| `store::codec::ObjectStateV1` | `store-codec-ObjectStateV1.json` |
| `store::codec::PendingOp` | `store-codec-PendingOp-read.json` |
| `store::codec::PendingOp` | `store-codec-PendingOp-write.json` |
| `store::codec::QuotaV1` | `store-codec-QuotaV1.json` |
| `store::codec::RecordV1` | `store-codec-RecordV1.json` |
| `store::codec::RecordV1` | `store-codec-RecordV1-already_exists.json` |
| `store::codec::RecordV1` | `store-codec-RecordV1-failed_precondition.json` |
| `store::codec::RecordV1` | `store-codec-RecordV1-invalid_argument.json` |
| `store::codec::RecordV1` | `store-codec-RecordV1-not_found.json` |
| `store::codec::RecordV1` | `store-codec-RecordV1-out_of_range.json` |
| `store::codec::RecordV1` | `store-codec-RecordV1-permission_denied.json` |
| `store::codec::RecordV1` | `store-codec-RecordV1-unimplemented.json` |
| `store::codec::RelayDtoV1` | `store-codec-RelayDtoV1.json` |
| `store::codec::RelayScanDtoV1` | `store-codec-RelayScanDtoV1.json` |
| `store::codec::RepoRecord` | `store-codec-RepoRecord.json` |
| `store::codec::RepoVisibilityV1` | `store-codec-RepoVisibilityV1-private.json` |
| `store::codec::RepoVisibilityV1` | `store-codec-RepoVisibilityV1-public.json` |
| `store::codec::ReservationV1` | `store-codec-ReservationV1-aborted-ABANDONED.json` |
| `store::codec::ReservationV1` | `store-codec-ReservationV1-aborted-EPOCH_MISMATCH.json` |
| `store::codec::ReservationV1` | `store-codec-ReservationV1-aborted-INTERNAL.json` |
| `store::codec::ReservationV1` | `store-codec-ReservationV1-aborted-PACK_MISSING.json` |
| `store::codec::ReservationV1` | `store-codec-ReservationV1-aborted-REF_CONFLICT.json` |
| `store::codec::ReservationV1` | `store-codec-ReservationV1-aborted-REPLAY_RACE.json` |
| `store::codec::ReservationV1` | `store-codec-ReservationV1-aborted-UNSPECIFIED.json` |
| `store::codec::ReservationV1` | `store-codec-ReservationV1-committed.json` |
| `store::codec::ReservationV1` | `store-codec-ReservationV1-expired.json` |
| `store::codec::ReservationV1` | `store-codec-ReservationV1-pending.json` |
| `store::codec::ReservationV1` | `store-codec-ReservationV1-read_served.json` |
| `store::codec::ReservationV1` | `store-codec-ReservationV1-ticketed.json` |
| `store::codec::ResultV1` | `store-codec-ResultV1-advance_committed.json` |
| `store::codec::ResultV1` | `store-codec-ResultV1-advance_head_conflict.json` |
| `store::codec::ResultV1` | `store-codec-ResultV1-advance_packmap_conflict.json` |
| `store::codec::ResultV1` | `store-codec-ResultV1-begin_upload_already_present.json` |
| `store::codec::ResultV1` | `store-codec-ResultV1-begin_upload_ticket.json` |
| `store::codec::ResultV1` | `store-codec-ResultV1-rejected.json` |
| `store::codec::ResultV1` | `store-codec-ResultV1-repo_visibility.json` |
| `store::codec::ResultV1` | `store-codec-ResultV1-update_ref_committed.json` |
| `store::codec::ResultV1` | `store-codec-ResultV1-update_ref_conflict.json` |
| `store::codec::ResultV1` | `store-codec-ResultV1-upload_pack.json` |
| `store::codec::StateV1` | `store-codec-StateV1-advance_committed.json` |
| `store::codec::StateV1` | `store-codec-StateV1-advance_head_conflict.json` |
| `store::codec::StateV1` | `store-codec-StateV1-advance_packmap_conflict.json` |
| `store::codec::StateV1` | `store-codec-StateV1-begin_upload_already_present.json` |
| `store::codec::StateV1` | `store-codec-StateV1-begin_upload_ticket.json` |
| `store::codec::StateV1` | `store-codec-StateV1-in_flight.json` |
| `store::codec::StateV1` | `store-codec-StateV1-rejected.json` |
| `store::codec::StateV1` | `store-codec-StateV1-repo_visibility.json` |
| `store::codec::StateV1` | `store-codec-StateV1-update_ref_committed.json` |
| `store::codec::StateV1` | `store-codec-StateV1-update_ref_conflict.json` |
| `store::codec::StateV1` | `store-codec-StateV1-upload_pack.json` |
| `store::codec::StoredVisibility` | `store-codec-StoredVisibility-private.json` |
| `store::codec::StoredVisibility` | `store-codec-StoredVisibility-public.json` |
| `store::codec::TicketV1` | `store-codec-TicketV1.json` |
| `store::inspection_flags::FlagState` | `store-inspection_flags-FlagState-flagged.json` |
| `store::inspection_flags::FlagState` | `store-inspection_flags-FlagState-released.json` |
| `store::publication::Advance` | `store-publication-Advance.json` |
| `store::publication::Clearance` | `store-publication-Clearance-cleared.json` |
| `store::publication::Clearance` | `store-publication-Clearance-held.json` |
| `store::publication::Clearance` | `store-publication-Clearance-hit.json` |
| `store::publication::Clearance` | `store-publication-Clearance-pending.json` |
| `store::publication::Clearance` | `store-publication-Clearance-resolved.json` |
| `store::publication::Obligation` | `store-publication-Obligation.json` |
| `store::publication::Pair` | `store-publication-Pair.json` |
| `store::publication::Publication` | `store-publication-Publication.json` |
| `takedown::closure::Checkpoint` | `takedown-closure-Checkpoint.json` |
| `takedown::copy::Piece` | `takedown-copy-Piece.json` |
| `takedown::denial::ActionsV2` | `takedown-denial-ActionsV2.json` |
| `takedown::denial::BlockAction` | `takedown-denial-BlockAction.json` |
| `takedown::denial::ChunkPage` | `takedown-denial-ChunkPage.json` |
| `takedown::denial::StoredAction` | `takedown-denial-StoredAction.json` |
| `takedown::discovery::DiscoveryState` | `takedown-discovery-DiscoveryState.json` |
| `takedown::intent::Draft` | `takedown-intent-Draft.json` |
| `takedown::intent::Record` | `takedown-intent-Record.json` |
| `takedown::intent::Reference` | `takedown-intent-Reference.json` |
| `takedown::inventory::Entry` | `takedown-inventory-Entry-0.json` |
| `takedown::inventory::Entry` | `takedown-inventory-Entry-1.json` |
| `takedown::inventory::Entry` | `takedown-inventory-Entry-2.json` |
| `takedown::inventory::Entry` | `takedown-inventory-Entry-3.json` |
| `takedown::inventory::Entry` | `takedown-inventory-Entry-4.json` |
| `takedown::inventory::Entry` | `takedown-inventory-Entry-5.json` |
| `takedown::inventory::Entry` | `takedown-inventory-Entry-7.json` |
| `takedown::inventory::Head` | `takedown-inventory-Head.json` |
| `takedown::inventory::InventoryCursor` | `takedown-inventory-InventoryCursor.json` |
| `takedown::inventory::PacklistFacts` | `takedown-inventory-PacklistFacts.json` |
| `takedown::source::Checkpoint` | `takedown-source-Checkpoint.json` |
| `takedown::source::Frame` | `takedown-source-Frame.json` |
| `takedown::source::Lookup` | `takedown-source-Lookup.json` |
| `takedown::work::ObjectInfo` | `takedown-work-ObjectInfo.json` |
| `takedown::work::Phase` | `takedown-work-Phase-Acquire.json` |
| `takedown::work::Phase` | `takedown-work-Phase-Closure.json` |
| `takedown::work::Phase` | `takedown-work-Phase-Discover.json` |
| `takedown::work::Phase` | `takedown-work-Phase-Purged.json` |
| `takedown::work::Phase` | `takedown-work-Phase-Purging.json` |
| `takedown::work::Phase` | `takedown-work-Phase-Retain.json` |
| `takedown::work::Phase` | `takedown-work-Phase-Seed.json` |
| `takedown::work::State` | `takedown-work-State.json` |
| `takedown::work::Verification` | `takedown-work-Verification-CanonicalPending.json` |
| `takedown::work::Verification` | `takedown-work-Verification-ManifestClosurePending.json` |
| `takedown::work::Verification` | `takedown-work-Verification-SourceCorrupt.json` |
| `takedown::work::Verification` | `takedown-work-Verification-Verified.json` |
| `worker::r2::object_multipart::Definition` | `r2-object_multipart-Definition.json` |
| `worker::r2::object_multipart::Session` | `r2-object_multipart-Session.json` |
| `worker::r2::object_multipart::VerifiedObjectPartRef` | `r2-object_multipart-VerifiedObjectPartRef.json` |

Binary row fixtures pin object indexes (all four wire types), verification frames/bases, namespace usage/views, references/integers, pending holders, publication witnesses, selection projections/pages, inspection holds/mode, denial directory pointers, preservation source frames/pieces, timer cursors, and portable exports. Worker fixtures also pin sharding/addressing markers. The existing `rust/tests/golden/uploads` fixtures pin authenticated multipart receipts and upload-marker blobs.

Additional canonical fixtures: `pipeline-revocation-RevokeCheckpoint.json`, active and sealed inventory/denial records, inspection flag/source rows, and Worker object root bindings.
