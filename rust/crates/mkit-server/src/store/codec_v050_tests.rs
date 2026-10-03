#![allow(clippy::unwrap_used, clippy::too_many_lines)] // Independent fixed-format cases.
use super::*;
#[test]
fn v050_stored_encodings() {
    let _ = crate::stored_golden::json_fixture!(OutcomeRef, "store-codec-OutcomeRef");
    let _ = crate::stored_golden::json_fixture!(AbortReason, "store-codec-AbortReason-ABANDONED");
    let _ =
        crate::stored_golden::json_fixture!(AbortReason, "store-codec-AbortReason-EPOCH_MISMATCH");
    let _ = crate::stored_golden::json_fixture!(AbortReason, "store-codec-AbortReason-INTERNAL");
    let _ =
        crate::stored_golden::json_fixture!(AbortReason, "store-codec-AbortReason-PACK_MISSING");
    let _ =
        crate::stored_golden::json_fixture!(AbortReason, "store-codec-AbortReason-REF_CONFLICT");
    let _ = crate::stored_golden::json_fixture!(AbortReason, "store-codec-AbortReason-REPLAY_RACE");
    let _ = crate::stored_golden::json_fixture!(AbortReason, "store-codec-AbortReason-UNSPECIFIED");
    let _ = crate::stored_golden::json_fixture!(Backlog, "store-codec-Backlog");
    let expected = crate::stored_golden::row_fixture!("store-codec-Backlog", b"\x01");
    let row = decode_backlog(&expected).unwrap();
    assert_eq!(encode_backlog(&row), expected);
    let _ = crate::stored_golden::json_fixture!(BlockV1, "store-codec-BlockV1");
    let expected = crate::stored_golden::row_fixture!("store-codec-BlockV1", b"\x01");
    let row = decode_block_entry(&expected).unwrap();
    assert_eq!(encode_block_entry(&row), expected);
    let _ = crate::stored_golden::json_fixture!(EpochLease, "store-codec-EpochLease");
    let expected = crate::stored_golden::row_fixture!("store-codec-EpochLease", b"\x01");
    let row = decode_epoch_lease(&expected).unwrap();
    assert_eq!(encode_epoch_lease(&row), expected);
    let _ = crate::stored_golden::json_fixture!(HoldV1, "store-codec-HoldV1");
    let expected = crate::stored_golden::row_fixture!("store-codec-HoldV1", b"\x01");
    let row = decode_hold(&expected).unwrap();
    assert_eq!(encode_hold(row), expected);
    let _ = crate::stored_golden::json_fixture!(HolderV1, "store-codec-HolderV1");
    let expected = crate::stored_golden::row_fixture!("store-codec-HolderV1", b"\x01");
    let row = decode_holder(&expected).unwrap();
    assert_eq!(encode_holder(&row), expected);
    let _ = crate::stored_golden::json_fixture!(LeaseRecovery, "store-codec-LeaseRecovery");
    let expected = crate::stored_golden::row_fixture!("store-codec-LeaseRecovery", b"\x01");
    let row = decode_lease_recovery(&expected).unwrap();
    assert_eq!(encode_lease_recovery(&row), expected);
    let _ = crate::stored_golden::json_fixture!(LeasedShard, "store-codec-LeasedShard");
    let expected = crate::stored_golden::row_fixture!("store-codec-LeasedShard", b"\x01");
    let row = decode_leased_shard(&expected).unwrap();
    assert_eq!(encode_leased_shard(&row), expected);
    let _ = crate::stored_golden::json_fixture!(NamespaceRecord, "store-codec-NamespaceRecord");
    let expected = crate::stored_golden::row_fixture!("store-codec-NamespaceRecord", b"\x01");
    let row = decode_namespace_record(&expected).unwrap();
    assert_eq!(encode_namespace_record(&row), expected);
    let _ = crate::stored_golden::json_fixture!(ObjectStateV1, "store-codec-ObjectStateV1");
    let expected = crate::stored_golden::row_fixture!("store-codec-ObjectStateV1", b"\x01");
    let row = decode_object_state(&expected).unwrap();
    assert_eq!(encode_object_state(&row), expected);
    let _ = crate::stored_golden::json_fixture!(PendingOp, "store-codec-PendingOp-read");
    let _ = crate::stored_golden::json_fixture!(PendingOp, "store-codec-PendingOp-write");
    let _ = crate::stored_golden::json_fixture!(QuotaV1, "store-codec-QuotaV1");
    let expected = crate::stored_golden::row_fixture!("store-codec-QuotaV1", b"\x01");
    let row = decode_quota_state(&expected).unwrap();
    assert_eq!(encode_quota_state(&row), expected);
    let _ = crate::stored_golden::json_fixture!(RecordV1, "store-codec-RecordV1");
    let expected = crate::stored_golden::row_fixture!("store-codec-RecordV1", b"\x01");
    let row = decode_replay_record(&expected).unwrap();
    assert_eq!(encode_replay_record(&row), expected);
    let _ = crate::stored_golden::json_fixture!(RecordV1, "store-codec-RecordV1-already_exists");
    let expected =
        crate::stored_golden::row_fixture!("store-codec-RecordV1-already_exists", b"\x01");
    let row = decode_replay_record(&expected).unwrap();
    assert_eq!(encode_replay_record(&row), expected);
    let _ =
        crate::stored_golden::json_fixture!(RecordV1, "store-codec-RecordV1-failed_precondition");
    let expected =
        crate::stored_golden::row_fixture!("store-codec-RecordV1-failed_precondition", b"\x01");
    let row = decode_replay_record(&expected).unwrap();
    assert_eq!(encode_replay_record(&row), expected);
    let _ = crate::stored_golden::json_fixture!(RecordV1, "store-codec-RecordV1-invalid_argument");
    let expected =
        crate::stored_golden::row_fixture!("store-codec-RecordV1-invalid_argument", b"\x01");
    let row = decode_replay_record(&expected).unwrap();
    assert_eq!(encode_replay_record(&row), expected);
    let _ = crate::stored_golden::json_fixture!(RecordV1, "store-codec-RecordV1-not_found");
    let expected = crate::stored_golden::row_fixture!("store-codec-RecordV1-not_found", b"\x01");
    let row = decode_replay_record(&expected).unwrap();
    assert_eq!(encode_replay_record(&row), expected);
    let _ = crate::stored_golden::json_fixture!(RecordV1, "store-codec-RecordV1-out_of_range");
    let expected = crate::stored_golden::row_fixture!("store-codec-RecordV1-out_of_range", b"\x01");
    let row = decode_replay_record(&expected).unwrap();
    assert_eq!(encode_replay_record(&row), expected);
    let _ = crate::stored_golden::json_fixture!(RecordV1, "store-codec-RecordV1-permission_denied");
    let expected =
        crate::stored_golden::row_fixture!("store-codec-RecordV1-permission_denied", b"\x01");
    let row = decode_replay_record(&expected).unwrap();
    assert_eq!(encode_replay_record(&row), expected);
    let _ = crate::stored_golden::json_fixture!(RecordV1, "store-codec-RecordV1-unimplemented");
    let expected =
        crate::stored_golden::row_fixture!("store-codec-RecordV1-unimplemented", b"\x01");
    let row = decode_replay_record(&expected).unwrap();
    assert_eq!(encode_replay_record(&row), expected);
    let _ = crate::stored_golden::json_fixture!(RelayDtoV1, "store-codec-RelayDtoV1");
    let expected = crate::stored_golden::row_fixture!("store-codec-RelayDtoV1", b"\x01");
    let row = decode_relay(&expected).unwrap();
    assert_eq!(encode_relay(&row).unwrap(), expected);
    let _ = crate::stored_golden::json_fixture!(RelayScanDtoV1, "store-codec-RelayScanDtoV1");
    let expected = crate::stored_golden::row_fixture!("store-codec-RelayScanDtoV1", b"\x01");
    let row = decode_relay_scan(&expected).unwrap();
    assert_eq!(encode_relay_scan(&row).unwrap(), expected);
    let _ = crate::stored_golden::json_fixture!(RepoRecord, "store-codec-RepoRecord");
    let expected = crate::stored_golden::row_fixture!("store-codec-RepoRecord", b"\x01");
    let row = decode_repo_record(&expected).unwrap();
    assert_eq!(encode_repo_record(&row), expected);
    let _ = crate::stored_golden::json_fixture!(
        RepoVisibilityV1,
        "store-codec-RepoVisibilityV1-private"
    );
    let expected =
        crate::stored_golden::row_fixture!("store-codec-RepoVisibilityV1-private", b"\x01");
    let row = decode_repo_visibility(&expected).unwrap();
    assert_eq!(encode_repo_visibility(&row), expected);
    let _ = crate::stored_golden::json_fixture!(
        RepoVisibilityV1,
        "store-codec-RepoVisibilityV1-public"
    );
    let expected =
        crate::stored_golden::row_fixture!("store-codec-RepoVisibilityV1-public", b"\x01");
    let row = decode_repo_visibility(&expected).unwrap();
    assert_eq!(encode_repo_visibility(&row), expected);
    let _ = crate::stored_golden::json_fixture!(
        ReservationV1,
        "store-codec-ReservationV1-aborted-ABANDONED"
    );
    let expected =
        crate::stored_golden::row_fixture!("store-codec-ReservationV1-aborted-ABANDONED", b"\x01");
    let row = decode_reservation(&expected).unwrap();
    assert_eq!(encode_reservation(&row), expected);
    let _ = crate::stored_golden::json_fixture!(
        ReservationV1,
        "store-codec-ReservationV1-aborted-EPOCH_MISMATCH"
    );
    let expected = crate::stored_golden::row_fixture!(
        "store-codec-ReservationV1-aborted-EPOCH_MISMATCH",
        b"\x01"
    );
    let row = decode_reservation(&expected).unwrap();
    assert_eq!(encode_reservation(&row), expected);
    let _ = crate::stored_golden::json_fixture!(
        ReservationV1,
        "store-codec-ReservationV1-aborted-INTERNAL"
    );
    let expected =
        crate::stored_golden::row_fixture!("store-codec-ReservationV1-aborted-INTERNAL", b"\x01");
    let row = decode_reservation(&expected).unwrap();
    assert_eq!(encode_reservation(&row), expected);
    let _ = crate::stored_golden::json_fixture!(
        ReservationV1,
        "store-codec-ReservationV1-aborted-PACK_MISSING"
    );
    let expected = crate::stored_golden::row_fixture!(
        "store-codec-ReservationV1-aborted-PACK_MISSING",
        b"\x01"
    );
    let row = decode_reservation(&expected).unwrap();
    assert_eq!(encode_reservation(&row), expected);
    let _ = crate::stored_golden::json_fixture!(
        ReservationV1,
        "store-codec-ReservationV1-aborted-REF_CONFLICT"
    );
    let expected = crate::stored_golden::row_fixture!(
        "store-codec-ReservationV1-aborted-REF_CONFLICT",
        b"\x01"
    );
    let row = decode_reservation(&expected).unwrap();
    assert_eq!(encode_reservation(&row), expected);
    let _ = crate::stored_golden::json_fixture!(
        ReservationV1,
        "store-codec-ReservationV1-aborted-REPLAY_RACE"
    );
    let expected = crate::stored_golden::row_fixture!(
        "store-codec-ReservationV1-aborted-REPLAY_RACE",
        b"\x01"
    );
    let row = decode_reservation(&expected).unwrap();
    assert_eq!(encode_reservation(&row), expected);
    let _ = crate::stored_golden::json_fixture!(
        ReservationV1,
        "store-codec-ReservationV1-aborted-UNSPECIFIED"
    );
    let expected = crate::stored_golden::row_fixture!(
        "store-codec-ReservationV1-aborted-UNSPECIFIED",
        b"\x01"
    );
    let row = decode_reservation(&expected).unwrap();
    assert_eq!(encode_reservation(&row), expected);
    let _ =
        crate::stored_golden::json_fixture!(ReservationV1, "store-codec-ReservationV1-committed");
    let expected =
        crate::stored_golden::row_fixture!("store-codec-ReservationV1-committed", b"\x01");
    let row = decode_reservation(&expected).unwrap();
    assert_eq!(encode_reservation(&row), expected);
    let _ = crate::stored_golden::json_fixture!(ReservationV1, "store-codec-ReservationV1-expired");
    let expected = crate::stored_golden::row_fixture!("store-codec-ReservationV1-expired", b"\x01");
    let row = decode_reservation(&expected).unwrap();
    assert_eq!(encode_reservation(&row), expected);
    let _ = crate::stored_golden::json_fixture!(ReservationV1, "store-codec-ReservationV1-pending");
    let expected = crate::stored_golden::row_fixture!("store-codec-ReservationV1-pending", b"\x01");
    let row = decode_reservation(&expected).unwrap();
    assert_eq!(encode_reservation(&row), expected);
    let _ =
        crate::stored_golden::json_fixture!(ReservationV1, "store-codec-ReservationV1-read_served");
    let expected =
        crate::stored_golden::row_fixture!("store-codec-ReservationV1-read_served", b"\x01");
    let row = decode_reservation(&expected).unwrap();
    assert_eq!(encode_reservation(&row), expected);
    let _ =
        crate::stored_golden::json_fixture!(ReservationV1, "store-codec-ReservationV1-ticketed");
    let expected =
        crate::stored_golden::row_fixture!("store-codec-ReservationV1-ticketed", b"\x01");
    let row = decode_reservation(&expected).unwrap();
    assert_eq!(encode_reservation(&row), expected);
    let _ = crate::stored_golden::json_fixture!(ResultV1, "store-codec-ResultV1-advance_committed");
    let _ =
        crate::stored_golden::json_fixture!(ResultV1, "store-codec-ResultV1-advance_head_conflict");
    let _ = crate::stored_golden::json_fixture!(
        ResultV1,
        "store-codec-ResultV1-advance_packmap_conflict"
    );
    let _ = crate::stored_golden::json_fixture!(
        ResultV1,
        "store-codec-ResultV1-begin_upload_already_present"
    );
    let _ =
        crate::stored_golden::json_fixture!(ResultV1, "store-codec-ResultV1-begin_upload_ticket");
    let _ = crate::stored_golden::json_fixture!(ResultV1, "store-codec-ResultV1-rejected");
    let _ = crate::stored_golden::json_fixture!(ResultV1, "store-codec-ResultV1-repo_visibility");
    let _ =
        crate::stored_golden::json_fixture!(ResultV1, "store-codec-ResultV1-update_ref_committed");
    let _ =
        crate::stored_golden::json_fixture!(ResultV1, "store-codec-ResultV1-update_ref_conflict");
    let _ = crate::stored_golden::json_fixture!(ResultV1, "store-codec-ResultV1-upload_pack");
    let _ = crate::stored_golden::json_fixture!(StateV1, "store-codec-StateV1-advance_committed");
    let _ =
        crate::stored_golden::json_fixture!(StateV1, "store-codec-StateV1-advance_head_conflict");
    let _ = crate::stored_golden::json_fixture!(
        StateV1,
        "store-codec-StateV1-advance_packmap_conflict"
    );
    let _ = crate::stored_golden::json_fixture!(
        StateV1,
        "store-codec-StateV1-begin_upload_already_present"
    );
    let _ = crate::stored_golden::json_fixture!(StateV1, "store-codec-StateV1-begin_upload_ticket");
    let _ = crate::stored_golden::json_fixture!(StateV1, "store-codec-StateV1-in_flight");
    let _ = crate::stored_golden::json_fixture!(StateV1, "store-codec-StateV1-rejected");
    let _ = crate::stored_golden::json_fixture!(StateV1, "store-codec-StateV1-repo_visibility");
    let _ =
        crate::stored_golden::json_fixture!(StateV1, "store-codec-StateV1-update_ref_committed");
    let _ = crate::stored_golden::json_fixture!(StateV1, "store-codec-StateV1-update_ref_conflict");
    let _ = crate::stored_golden::json_fixture!(StateV1, "store-codec-StateV1-upload_pack");
    let _ = crate::stored_golden::json_fixture!(
        StoredVisibility,
        "store-codec-StoredVisibility-private"
    );
    let _ = crate::stored_golden::json_fixture!(
        StoredVisibility,
        "store-codec-StoredVisibility-public"
    );
    let _ = crate::stored_golden::json_fixture!(TicketV1, "store-codec-TicketV1");
    let expected = crate::stored_golden::row_fixture!("store-codec-TicketV1", b"\x01");
    let row = decode_ticket(&expected).unwrap();
    assert_eq!(encode_ticket(&row), expected);
}
#[test]
fn v050_binary_rows() {
    use crate::stored_golden::hex_fixture;
    for (expected, encode, decode) in [
        (
            hex_fixture!("object-index-0"),
            encode_object_index,
            decode_object_index,
        ),
        (
            hex_fixture!("object-index-2"),
            encode_object_index,
            decode_object_index,
        ),
        (
            hex_fixture!("object-index-3"),
            encode_object_index,
            decode_object_index,
        ),
        (
            hex_fixture!("object-index-4"),
            encode_object_index,
            decode_object_index,
        ),
    ] {
        let row = decode(&[1; 32], &expected).unwrap();
        assert_eq!(encode(&[1; 32], &row).unwrap(), expected);
    }
    let expected = hex_fixture!("namespace-usage");
    assert_eq!(
        encode_namespace_usage(decode_namespace_usage(&expected).unwrap()),
        expected
    );
    let expected = hex_fixture!("namespace-view");
    assert_eq!(
        encode_namespace_view(decode_namespace_view(&expected).unwrap()),
        expected
    );
    let expected = hex_fixture!("u32");
    assert_eq!(decode_u32(&expected).unwrap(), 0x0102_0304);
    assert_eq!(encode_u32(0x0102_0304), expected);
    let expected = hex_fixture!("u64");
    assert_eq!(decode_u64(&expected).unwrap(), 0x0102_0304_0506_0708);
    assert_eq!(encode_u64(0x0102_0304_0506_0708), expected);
    let expected = hex_fixture!("ref-id");
    assert_eq!(decode_ref_id(&expected).unwrap(), [1; 32]);
    assert_eq!(encode_ref_id(&[1; 32]), expected);
}
