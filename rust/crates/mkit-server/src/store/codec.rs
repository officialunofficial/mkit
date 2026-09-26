//! Value codecs. Structured values are `serde_json` behind a leading
//! version byte ([`CODEC_V1`]); refs are the raw 32-byte id and integers
//! are raw big-endian. Decoding an unknown version, a wrong length or a
//! value that fails validation is [`StoreError::Corrupt`].

use mkit_core::hash::{Hash, from_hex, to_hex};
use mkit_core::protocol::AdvanceOutcome;
use serde::{Deserialize, Serialize};

use super::content_index::{BlockEntry, ObjectState};
use super::error::StoreError;
use super::kv::Value;
use crate::error::Code;
use crate::quota::QuotaState;
use crate::replay::{ReplayRecord, ReplayState, StoredRejection, StoredResult, UpdateRefResult};

/// Version byte of every structured value this binary writes.
pub const CODEC_V1: u8 = 0x01;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordV1 {
    fingerprint: String,
    expires_at_ms: i64,
    state: StateV1,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum StateV1 {
    InFlight { resumable: bool },
    Committed { result: ResultV1 },
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum ResultV1 {
    UpdateRefCommitted,
    UpdateRefConflict { current: Option<String> },
    AdvanceCommitted,
    AdvanceHeadConflict,
    AdvancePackmapConflict,
    UploadPack,
    Rejected { code: String, message: String },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct QuotaV1 {
    window_start: i64,
    ops: u32,
    bytes: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HoldV1 {
    expires_at_ms: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BlockV1 {
    reason: String,
    blocked_at_ms: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ObjectStateV1 {
    seq: u64,
    changed_at_ms: u64,
    holders: u64,
    deleting: bool,
}

/// Every [`Code`], to invert [`Code::as_str`].
const CODES: [Code; 16] = [
    Code::Canceled,
    Code::Unknown,
    Code::InvalidArgument,
    Code::DeadlineExceeded,
    Code::NotFound,
    Code::AlreadyExists,
    Code::PermissionDenied,
    Code::ResourceExhausted,
    Code::FailedPrecondition,
    Code::Aborted,
    Code::OutOfRange,
    Code::Unimplemented,
    Code::Internal,
    Code::Unavailable,
    Code::DataLoss,
    Code::Unauthenticated,
];

fn corrupt(what: &'static str) -> StoreError {
    StoreError::Corrupt(what.into())
}

fn encode_json<T: Serialize>(value: &T) -> Value {
    let mut out = vec![CODEC_V1];
    serde_json::to_writer(&mut out, value).expect("codec DTOs always serialize");
    Value::new(out)
}

fn decode_json<'a, T: Deserialize<'a>>(
    value: &'a Value,
    what: &'static str,
) -> Result<T, StoreError> {
    match value.as_bytes().split_first() {
        Some((&CODEC_V1, body)) => serde_json::from_slice(body).map_err(|_| corrupt(what)),
        _ => Err(corrupt("unknown codec version")),
    }
}

fn hash_from(hex: &str) -> Result<Hash, StoreError> {
    from_hex(hex).map_err(|_| corrupt("bad hash"))
}

/// Encode a replay record.
#[must_use]
pub fn encode_replay_record(record: &ReplayRecord) -> Value {
    let state = match &record.state {
        ReplayState::InFlight { resumable } => StateV1::InFlight {
            resumable: *resumable,
        },
        ReplayState::Committed(result) => StateV1::Committed {
            result: match result {
                StoredResult::UpdateRef(UpdateRefResult::Committed) => ResultV1::UpdateRefCommitted,
                StoredResult::UpdateRef(UpdateRefResult::Conflict { current }) => {
                    ResultV1::UpdateRefConflict {
                        current: current.as_ref().map(to_hex),
                    }
                }
                StoredResult::AdvanceRefs(AdvanceOutcome::Committed) => ResultV1::AdvanceCommitted,
                StoredResult::AdvanceRefs(AdvanceOutcome::HeadConflict) => {
                    ResultV1::AdvanceHeadConflict
                }
                StoredResult::AdvanceRefs(AdvanceOutcome::PackmapConflict) => {
                    ResultV1::AdvancePackmapConflict
                }
                StoredResult::UploadPack => ResultV1::UploadPack,
                StoredResult::Rejected(r) => ResultV1::Rejected {
                    code: r.code().as_str().to_owned(),
                    message: r.message().to_owned(),
                },
            },
        },
    };
    encode_json(&RecordV1 {
        fingerprint: to_hex(&record.fingerprint),
        expires_at_ms: record.expires_at_ms,
        state,
    })
}

/// Decode a replay record.
pub fn decode_replay_record(value: &Value) -> Result<ReplayRecord, StoreError> {
    let dto: RecordV1 = decode_json(value, "bad replay record")?;
    let state = match dto.state {
        StateV1::InFlight { resumable } => ReplayState::InFlight { resumable },
        StateV1::Committed { result } => ReplayState::Committed(match result {
            ResultV1::UpdateRefCommitted => StoredResult::UpdateRef(UpdateRefResult::Committed),
            ResultV1::UpdateRefConflict { current } => {
                StoredResult::UpdateRef(UpdateRefResult::Conflict {
                    current: current.as_deref().map(hash_from).transpose()?,
                })
            }
            ResultV1::AdvanceCommitted => StoredResult::AdvanceRefs(AdvanceOutcome::Committed),
            ResultV1::AdvanceHeadConflict => {
                StoredResult::AdvanceRefs(AdvanceOutcome::HeadConflict)
            }
            ResultV1::AdvancePackmapConflict => {
                StoredResult::AdvanceRefs(AdvanceOutcome::PackmapConflict)
            }
            ResultV1::UploadPack => StoredResult::UploadPack,
            ResultV1::Rejected { code, message } => {
                let code = CODES
                    .into_iter()
                    .find(|c| c.as_str() == code)
                    .ok_or_else(|| corrupt("unknown code"))?;
                StoredResult::Rejected(
                    StoredRejection::new(code, message)
                        .ok_or_else(|| corrupt("stored rejection code is not final"))?,
                )
            }
        }),
    };
    Ok(ReplayRecord {
        fingerprint: hash_from(&dto.fingerprint)?,
        expires_at_ms: dto.expires_at_ms,
        state,
    })
}

/// Encode a quota window's usage.
#[must_use]
pub fn encode_quota_state(state: &QuotaState) -> Value {
    encode_json(&QuotaV1 {
        window_start: state.window_start,
        ops: state.ops,
        bytes: state.bytes,
    })
}

/// Decode a quota window's usage.
pub fn decode_quota_state(value: &Value) -> Result<QuotaState, StoreError> {
    let dto: QuotaV1 = decode_json(value, "bad quota state")?;
    Ok(QuotaState {
        window_start: dto.window_start,
        ops: dto.ops,
        bytes: dto.bytes,
    })
}

/// Encode a `ContentIndex` GC hold: its expiry, Unix ms.
#[must_use]
pub fn encode_hold(expires_at_ms: u64) -> Value {
    encode_json(&HoldV1 { expires_at_ms })
}

/// Decode a `ContentIndex` GC hold's expiry.
pub fn decode_hold(value: &Value) -> Result<u64, StoreError> {
    let dto: HoldV1 = decode_json(value, "bad hold")?;
    Ok(dto.expires_at_ms)
}

/// Encode a blocklist entry.
#[must_use]
pub fn encode_block_entry(entry: &BlockEntry) -> Value {
    encode_json(&BlockV1 {
        reason: entry.reason.clone(),
        blocked_at_ms: entry.blocked_at_ms,
    })
}

/// Decode a blocklist entry.
pub fn decode_block_entry(value: &Value) -> Result<BlockEntry, StoreError> {
    let dto: BlockV1 = decode_json(value, "bad blocklist entry")?;
    Ok(BlockEntry {
        reason: dto.reason,
        blocked_at_ms: dto.blocked_at_ms,
    })
}

/// Encode a `ContentIndex` object state.
#[must_use]
pub fn encode_object_state(state: &ObjectState) -> Value {
    encode_json(&ObjectStateV1 {
        seq: state.seq,
        changed_at_ms: state.changed_at_ms,
        holders: state.holders,
        deleting: state.deleting,
    })
}

/// Decode a `ContentIndex` object state.
pub fn decode_object_state(value: &Value) -> Result<ObjectState, StoreError> {
    let dto: ObjectStateV1 = decode_json(value, "bad object state")?;
    Ok(ObjectState {
        seq: dto.seq,
        changed_at_ms: dto.changed_at_ms,
        holders: dto.holders,
        deleting: dto.deleting,
    })
}

/// A ref value: the raw 32-byte id.
#[must_use]
pub fn encode_ref_id(id: &Hash) -> Value {
    Value::new(id.to_vec())
}

/// Decode a ref value.
pub fn decode_ref_id(value: &Value) -> Result<Hash, StoreError> {
    Hash::try_from(value.as_bytes()).map_err(|_| corrupt("ref value is not 32 bytes"))
}

/// A be64 integer (the grant epoch).
#[must_use]
pub fn encode_u64(n: u64) -> Value {
    Value::new(n.to_be_bytes().to_vec())
}

/// Decode a be64 integer.
pub fn decode_u64(value: &Value) -> Result<u64, StoreError> {
    <[u8; 8]>::try_from(value.as_bytes())
        .map(u64::from_be_bytes)
        .map_err(|_| corrupt("integer is not 8 bytes"))
}

/// A be32 integer (the layout version).
#[must_use]
pub fn encode_u32(n: u32) -> Value {
    Value::new(n.to_be_bytes().to_vec())
}

/// Decode a be32 integer.
pub fn decode_u32(value: &Value) -> Result<u32, StoreError> {
    <[u8; 4]>::try_from(value.as_bytes())
        .map(u32::from_be_bytes)
        .map_err(|_| corrupt("integer is not 4 bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn records() -> Vec<ReplayRecord> {
        let results = [
            StoredResult::UpdateRef(UpdateRefResult::Committed),
            StoredResult::UpdateRef(UpdateRefResult::Conflict { current: None }),
            StoredResult::UpdateRef(UpdateRefResult::Conflict {
                current: Some([3; 32]),
            }),
            StoredResult::AdvanceRefs(AdvanceOutcome::Committed),
            StoredResult::AdvanceRefs(AdvanceOutcome::HeadConflict),
            StoredResult::AdvanceRefs(AdvanceOutcome::PackmapConflict),
            StoredResult::UploadPack,
            StoredResult::Rejected(StoredRejection::new(Code::PermissionDenied, "no").unwrap()),
        ];
        let mut states: Vec<_> = results.into_iter().map(ReplayState::Committed).collect();
        states.push(ReplayState::InFlight { resumable: true });
        states.push(ReplayState::InFlight { resumable: false });
        states
            .into_iter()
            .map(|state| ReplayRecord {
                fingerprint: [9; 32],
                expires_at_ms: -5,
                state,
            })
            .collect()
    }

    #[test]
    fn codec_roundtrip_every_value_type() {
        for record in records() {
            let value = encode_replay_record(&record);
            assert_eq!(value.as_bytes()[0], CODEC_V1);
            assert_eq!(decode_replay_record(&value).unwrap(), record);
        }
        let quota = QuotaState {
            window_start: 1_700_000_000_000,
            ops: 3,
            bytes: u64::MAX,
        };
        assert_eq!(
            decode_quota_state(&encode_quota_state(&quota)).unwrap(),
            quota
        );
        assert_eq!(decode_ref_id(&encode_ref_id(&[4; 32])).unwrap(), [4; 32]);
        assert_eq!(decode_u64(&encode_u64(u64::MAX - 1)).unwrap(), u64::MAX - 1);
        assert_eq!(
            decode_u32(&encode_u32(1)).unwrap().to_be_bytes(),
            [0, 0, 0, 1]
        );
        for code in CODES {
            assert_eq!(
                CODES.iter().filter(|c| c.as_str() == code.as_str()).count(),
                1
            );
        }
    }

    #[test]
    fn codec_golden_bytes() {
        let head = format!(
            "\x01{{\"fingerprint\":\"{}\",\"expires_at_ms\":-5,\"state\":",
            "09".repeat(32)
        );
        let committed = |result: &str| format!("{{\"state\":\"committed\",\"result\":{result}}}");
        let states = [
            committed(r#"{"kind":"update_ref_committed"}"#),
            committed(r#"{"kind":"update_ref_conflict","current":null}"#),
            committed(&format!(
                r#"{{"kind":"update_ref_conflict","current":"{}"}}"#,
                "03".repeat(32)
            )),
            committed(r#"{"kind":"advance_committed"}"#),
            committed(r#"{"kind":"advance_head_conflict"}"#),
            committed(r#"{"kind":"advance_packmap_conflict"}"#),
            committed(r#"{"kind":"upload_pack"}"#),
            committed(r#"{"kind":"rejected","code":"permission_denied","message":"no"}"#),
            r#"{"state":"in_flight","resumable":true}"#.to_owned(),
            r#"{"state":"in_flight","resumable":false}"#.to_owned(),
        ];
        for (record, state) in records().iter().zip(states) {
            let golden = format!("{head}{state}}}");
            assert_eq!(encode_replay_record(record).as_bytes(), golden.as_bytes());
        }
        let quota = QuotaState {
            window_start: 1_700_000_000_000,
            ops: 3,
            bytes: u64::MAX,
        };
        let golden =
            b"\x01{\"window_start\":1700000000000,\"ops\":3,\"bytes\":18446744073709551615}";
        assert_eq!(encode_quota_state(&quota).as_bytes(), golden);
        assert_eq!(encode_ref_id(&[4; 32]).as_bytes(), [4; 32]);
        assert_eq!(
            encode_u64(u64::MAX - 1).as_bytes(),
            [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe]
        );
        assert_eq!(encode_u64(1).as_bytes(), [0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(encode_u32(1).as_bytes(), [0, 0, 0, 1]);
    }

    #[test]
    fn content_index_codecs_golden_bytes() {
        let block = BlockEntry {
            reason: "dmca".into(),
            blocked_at_ms: 7,
        };
        let state = ObjectState {
            seq: u64::MAX,
            changed_at_ms: 1_700_000_000_000,
            holders: 2,
            deleting: true,
        };
        let cases: [(Value, &[u8]); 3] = [
            (encode_hold(9), b"\x01{\"expires_at_ms\":9}"),
            (
                encode_block_entry(&block),
                b"\x01{\"reason\":\"dmca\",\"blocked_at_ms\":7}",
            ),
            (
                encode_object_state(&state),
                b"\x01{\"seq\":18446744073709551615,\"changed_at_ms\":1700000000000,\"holders\":2,\"deleting\":true}",
            ),
        ];
        for (value, golden) in &cases {
            assert_eq!(value.as_bytes(), *golden);
        }
        assert_eq!(decode_hold(&cases[0].0).unwrap(), 9);
        assert_eq!(decode_block_entry(&cases[1].0).unwrap(), block);
        assert_eq!(decode_object_state(&cases[2].0).unwrap(), state);
        for bad in [
            &b"\x02{\"expires_at_ms\":9}"[..],
            b"\x01{\"expires_at_ms\":-1}",
            b"\x01{\"seq\":0,\"changed_at_ms\":0}",
        ] {
            let v = Value::new(bad.to_vec());
            assert!(matches!(decode_hold(&v), Err(StoreError::Corrupt(_))));
            assert!(matches!(
                decode_block_entry(&v),
                Err(StoreError::Corrupt(_))
            ));
            assert!(matches!(
                decode_object_state(&v),
                Err(StoreError::Corrupt(_))
            ));
        }
    }

    #[test]
    fn unknown_version_byte_is_corrupt() {
        let mut bytes = encode_replay_record(&records()[0]).as_bytes().to_vec();
        bytes[0] = 0x02;
        let bumped = Value::new(bytes);
        assert!(matches!(
            decode_replay_record(&bumped),
            Err(StoreError::Corrupt(_))
        ));
        assert!(matches!(
            decode_quota_state(&bumped),
            Err(StoreError::Corrupt(_))
        ));
        for bad in [
            &b""[..],
            b"\x01{",
            b"\x01{\"window_start\":0,\"ops\":0,\"bytes\":0,\"extra\":1}",
            b"\x01{\"fingerprint\":\"00\",\"expires_at_ms\":0,\"state\":{\"state\":\"in_flight\",\"resumable\":true}}",
        ] {
            let v = Value::new(bad.to_vec());
            assert!(matches!(decode_replay_record(&v), Err(StoreError::Corrupt(_))));
            assert!(matches!(decode_quota_state(&v), Err(StoreError::Corrupt(_))));
        }
        let retryable = format!(
            "\x01{{\"fingerprint\":\"{}\",\"expires_at_ms\":0,\"state\":{{\"state\":\"committed\",\"result\":{{\"kind\":\"rejected\",\"code\":\"unavailable\",\"message\":\"m\"}}}}}}",
            "00".repeat(32)
        );
        assert!(matches!(
            decode_replay_record(&Value::new(retryable.into_bytes())),
            Err(StoreError::Corrupt(_))
        ));
        assert!(matches!(
            decode_ref_id(&Value::new(vec![0; 31])),
            Err(StoreError::Corrupt(_))
        ));
        assert!(matches!(
            decode_u64(&Value::new(vec![0; 4])),
            Err(StoreError::Corrupt(_))
        ));
    }
}
