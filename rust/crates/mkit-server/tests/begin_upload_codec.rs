//! New replay-result codec goldens. Existing result encodings stay pinned by
//! the store codec's unit tests.
#![allow(clippy::unwrap_used)] // Failed decoding is an assertion.

use mkit_server::store::{Value, codec};
use mkit_server::{BeginUploadResult, ReplayRecord, ReplayState, StoredResult};
use serde_json::json;

#[test]
fn begin_upload_replay_codec_goldens() {
    let cases = [
        (
            BeginUploadResult::AlreadyPresent,
            r#"{"kind":"begin_upload_already_present"}"#.to_owned(),
        ),
        (
            BeginUploadResult::Ticket {
                id: [0x11; 32],
                part_size: 8_388_608,
                expires_at_ms: 1_700_086_400_000,
                token: vec![0, 1, 0xfe, 0xff],
            },
            format!(
                r#"{{"kind":"begin_upload_ticket","id":"{}","part_size":8388608,"expires_at_ms":1700086400000,"token_hex":"0001feff"}}"#,
                "11".repeat(32)
            ),
        ),
    ];
    for (result, expected_result) in cases {
        let record = ReplayRecord {
            fingerprint: [9; 32],
            expires_at_ms: 1_700_000_300_000,
            state: ReplayState::Committed(StoredResult::BeginUpload(result)),
        };
        let golden = format!(
            "\x01{{\"fingerprint\":\"{}\",\"expires_at_ms\":1700000300000,\"state\":{{\"state\":\"committed\",\"result\":{expected_result}}}}}",
            "09".repeat(32)
        );
        let encoded = codec::encode_replay_record(&record);
        assert_eq!(encoded.as_bytes(), golden.as_bytes());
        assert_eq!(codec::decode_replay_record(&encoded).unwrap(), record);
    }
}

#[test]
fn malformed_begin_upload_ticket_results_are_rejected() {
    let valid = json!({
        "fingerprint": "09".repeat(32), "expires_at_ms": 1_700_000_300_000_i64,
        "state": { "state": "committed", "result": {
            "kind": "begin_upload_ticket", "id": "11".repeat(32),
            "part_size": 8_388_608, "expires_at_ms": 1_700_086_400_000_u64,
            "token_hex": "0001feff",
        }},
    });
    for (field, invalid) in [
        ("id", json!("11")),
        ("id", json!("gg".repeat(32))),
        ("part_size", json!(0)),
        ("part_size", json!(4_194_304)),
        ("part_size", json!(8_388_609)),
        ("token_hex", json!("")),
        ("token_hex", json!("0")),
        ("token_hex", json!("gg")),
        ("token_hex", json!("FE")),
    ] {
        let mut malformed = valid.clone();
        malformed["state"]["result"][field] = invalid;
        let mut bytes = vec![1];
        bytes.extend_from_slice(serde_json::to_string(&malformed).unwrap().as_bytes());
        assert!(
            codec::decode_replay_record(&Value::new(bytes)).is_err(),
            "{field}: {malformed}"
        );
    }
}
