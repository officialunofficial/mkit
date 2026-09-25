use mkit_core::hash::hash;
use mkit_core::protocol::PACK_BODY_LIMIT;
use proptest::prelude::*;

use super::*;

/// `mkit serve`'s caps: `MAX_BYTES_PER_CONN` and `MAX_FRAMES_PER_CONN`.
const SSH_LIMITS: UploadLimits = UploadLimits {
    max_total_bytes: 1024 * 1024 * 1024,
    max_chunks: 10_000,
};

/// The native Connect server's caps: `PACK_BODY_LIMIT`, no chunk cap.
const CONNECT_LIMITS: UploadLimits = UploadLimits {
    max_total_bytes: PACK_BODY_LIMIT,
    max_chunks: u32::MAX,
};

fn valid_pack() -> (Vec<u8>, [u8; 32]) {
    let bytes = b"valid pack bytes".to_vec();
    let id = hash(&bytes);
    (bytes, id)
}

fn validator(id: &[u8], total: u64, limits: UploadLimits) -> UploadValidator {
    UploadValidator::new(Some(id), Some(total), limits).unwrap()
}

// Ported from mkit-cli/src/commands/serve/tests.rs `upload_drain_accepts_valid_chunks`.
#[test]
fn upload_drain_accepts_valid_chunks() {
    let (bytes, id) = valid_pack();
    let mut v = validator(&id, bytes.len() as u64, SSH_LIMITS);
    assert!(!v.push(Some(&id), Some(0), 5, false).unwrap().complete);
    assert!(
        v.push(Some(&id), Some(5), bytes.len() - 5, true)
            .unwrap()
            .complete
    );
    let done = v.finish().unwrap();
    assert_eq!(done.key, PackKey::new(id));
    assert_eq!(done.total, bytes.len() as u64);
}

// Ported from mkit-cli/src/commands/serve/tests.rs
// `upload_drain_rejects_malformed_streams`, asserting the ssh text.
#[test]
fn upload_drain_rejects_malformed_streams() {
    let (bytes, id) = valid_pack();
    let len = bytes.len() as u64;
    let ssh = |r: Result<Progress, UploadError>| r.unwrap_err().ssh_message();

    let err = UploadValidator::new(Some(&id), None, SSH_LIMITS).unwrap_err();
    assert_eq!(err.ssh_message(), "UploadPack.total_bytes is required");
    let err = UploadValidator::new(Some(&id), Some((1 << 30) + 1), SSH_LIMITS).unwrap_err();
    assert_eq!(
        err.ssh_message(),
        "UploadPack.total_bytes exceeds server cap"
    );

    let mut v = validator(&id, len, SSH_LIMITS);
    assert_eq!(
        ssh(v.push(Some(&id), Some(1), bytes.len(), true)),
        "PackChunk.offset is not the expected next offset"
    );

    let mut v = validator(&id, len, SSH_LIMITS);
    assert_eq!(
        ssh(v.push(Some(&[0xAA; 32]), Some(0), bytes.len(), true)),
        "PackChunk.pack_id does not match UploadPack"
    );

    let mut v = validator(&id, len - 1, SSH_LIMITS);
    assert_eq!(
        ssh(v.push(Some(&id), Some(0), bytes.len(), true)),
        "PackChunk data exceeds declared total_bytes"
    );

    let mut v = validator(&id, len, SSH_LIMITS);
    assert_eq!(
        ssh(v.push(Some(&id), Some(0), bytes.len() - 1, true)),
        "PackChunk stream ended before declared total_bytes"
    );

    // The last ported case (right length, wrong bytes) is the sink's to
    // reject: the validator never hashes, and the binding reports the sink's
    // verdict as `DigestMismatch`.
    let mut v = validator(&id, b"wrong pack bytes".len() as u64, SSH_LIMITS);
    assert!(v.push(Some(&id), Some(0), 16, true).unwrap().complete);
    assert_eq!(
        UploadError::DigestMismatch.ssh_message(),
        "uploaded pack bytes do not match UploadPack.pack_id"
    );
}

/// Every upload message `mkit serve` sends today, copied from
/// `mkit-cli/src/commands/serve/mod.rs` (`dispatch`, `UploadDrain`,
/// `pack_key_from_upload`). Its unreachable "PackChunk.data length overflows
/// u64" (a `usize` never overflows `u64`) is dropped.
const SSH_MESSAGES: &[&str] = &[
    "PackChunk arrived without UploadPack header",
    "expected PackChunk after UploadPack",
    "pack_id missing",
    "pack_id must be 32 bytes",
    "PackChunk.pack_id does not match UploadPack",
    "UploadPack.total_bytes is required",
    "UploadPack.total_bytes exceeds server cap",
    "too many PackChunk frames before last=true",
    "PackChunk.offset is required",
    "PackChunk.offset is not the expected next offset",
    "PackChunk byte count overflow",
    "PackChunk data exceeds declared total_bytes",
    "pack chunk read failed",
    "PackChunk stream ended before declared total_bytes",
    "uploaded pack bytes do not match UploadPack.pack_id",
];

/// One of each variant.
const ALL: &[UploadError] = &[
    UploadError::HeaderMissing { stream_empty: true },
    UploadError::HeaderMissing {
        stream_empty: false,
    },
    UploadError::UnexpectedMessage { header: true },
    UploadError::UnexpectedMessage { header: false },
    UploadError::BadPackId {
        chunk: false,
        len: None,
    },
    UploadError::BadPackId {
        chunk: true,
        len: Some(31),
    },
    UploadError::PackIdMismatch,
    UploadError::TotalMissing,
    UploadError::TotalTooLarge { total: 9, cap: 8 },
    UploadError::TooManyChunks,
    UploadError::OffsetMissing,
    UploadError::OffsetGap {
        offset: 1,
        expected: 0,
    },
    UploadError::ByteCountOverflow,
    UploadError::Overrun,
    UploadError::AfterLast,
    UploadError::NoLast,
    UploadError::LengthMismatch {
        received: 1,
        declared: 2,
    },
    UploadError::DigestMismatch,
];

#[test]
fn ssh_messages_match_todays_list() {
    let mut produced: Vec<_> = ALL.iter().map(|e| e.ssh_message()).collect();
    // The one new message: `mkit serve` stops reading at `last`.
    produced.retain(|m| *m != "PackChunk after last=true");
    produced.sort_unstable();
    produced.dedup();
    let mut expected = SSH_MESSAGES.to_vec();
    expected.sort_unstable();
    assert_eq!(produced, expected);
}

#[test]
fn only_an_oversized_total_is_resource_exhausted() {
    for err in ALL {
        let want = if matches!(err, UploadError::TotalTooLarge { .. }) {
            Code::ResourceExhausted
        } else {
            Code::InvalidArgument
        };
        assert_eq!(err.code(), want, "{err:?}");
        let server = ServerError::from(*err);
        assert_eq!(server.code(), want);
        assert_eq!(server.public_message(), err.connect_message());
    }
}

// One case per `drain_upload` branch in mkit-transport-connect/src/pack.rs,
// plus the digest check the sink now owns.
#[test]
fn connect_messages_match_drain_upload() {
    let (bytes, id) = valid_pack();
    let len = bytes.len() as u64;
    let connect = |e: UploadError| e.connect_message().into_owned();

    assert_eq!(
        connect(UploadError::HeaderMissing { stream_empty: true }),
        "UploadPack: empty request stream"
    );
    assert_eq!(
        connect(UploadError::HeaderMissing {
            stream_empty: false
        }),
        "UploadPack: first message MUST be `header`"
    );
    // The Connect binding passes an absent header pack_id as empty.
    let err = UploadValidator::new(Some(&[]), Some(len), CONNECT_LIMITS).unwrap_err();
    assert_eq!(connect(err), "expected a 32-byte digest, got 0 bytes");
    let err = UploadValidator::new(Some(&id[..31]), Some(len), CONNECT_LIMITS).unwrap_err();
    assert_eq!(connect(err), "expected a 32-byte digest, got 31 bytes");

    let too_big = PACK_BODY_LIMIT + 1;
    let err = UploadValidator::new(Some(&id), Some(too_big), CONNECT_LIMITS).unwrap_err();
    assert_eq!(err.code(), Code::ResourceExhausted);
    assert_eq!(
        connect(err),
        format!("UploadPack: total_bytes {too_big} exceeds the {PACK_BODY_LIMIT}-byte cap")
    );

    assert_eq!(
        connect(UploadError::UnexpectedMessage { header: true }),
        "UploadPack: saw a second `header` message"
    );
    assert_eq!(
        connect(UploadError::UnexpectedMessage { header: false }),
        "UploadPack: message with neither `header` nor `chunk` set"
    );

    for chunk_id in [&[0xAA; 32][..], &[], &id[..31]] {
        let mut v = validator(&id, len, CONNECT_LIMITS);
        let err = v.push(Some(chunk_id), Some(0), 1, false).unwrap_err();
        assert_eq!(
            connect(err),
            "UploadPack: chunk.pack_id does not match header.pack_id"
        );
    }

    let mut v = validator(&id, len, CONNECT_LIMITS);
    v.push(Some(&id), Some(0), 4, false).unwrap();
    let err = v.push(Some(&id), Some(5), 4, false).unwrap_err();
    assert_eq!(
        connect(err),
        "UploadPack: chunk.offset 5 does not match the expected offset 4"
    );

    let mut v = validator(&id, len, CONNECT_LIMITS);
    let err = v
        .push(Some(&id), Some(0), bytes.len() + 1, false)
        .unwrap_err();
    assert_eq!(
        connect(err),
        "UploadPack: received bytes exceed header.total_bytes"
    );

    let mut v = validator(&id, len, CONNECT_LIMITS);
    v.push(Some(&id), Some(0), bytes.len(), false).unwrap();
    assert_eq!(
        connect(v.finish().unwrap_err()),
        "UploadPack: stream ended without a `chunk.last = true` message"
    );

    let mut v = validator(&id, len, CONNECT_LIMITS);
    let err = v.push(Some(&id), Some(0), 3, true).unwrap_err();
    assert_eq!(
        connect(err),
        format!("UploadPack: received 3 bytes, header declared {len}")
    );

    assert_eq!(
        connect(UploadError::DigestMismatch),
        "UploadPack: BLAKE3(received bytes) does not equal header.pack_id"
    );
}

#[test]
fn absent_ids_and_offsets_are_rejected() {
    let (_, id) = valid_pack();
    let err = UploadValidator::new(None, Some(1), SSH_LIMITS).unwrap_err();
    assert_eq!(err.ssh_message(), "pack_id missing");
    let mut v = validator(&id, 1, SSH_LIMITS);
    assert_eq!(
        v.push(None, Some(0), 1, true).unwrap_err().ssh_message(),
        "pack_id missing"
    );
    let mut v = validator(&id, 1, SSH_LIMITS);
    assert_eq!(
        v.push(Some(&id), None, 1, true).unwrap_err(),
        UploadError::OffsetMissing
    );
}

#[test]
fn chunk_cap_counts_every_chunk() {
    let (_, id) = valid_pack();
    let limits = UploadLimits {
        max_total_bytes: 10,
        max_chunks: 2,
    };
    let mut v = validator(&id, 3, limits);
    v.push(Some(&id), Some(0), 1, false).unwrap();
    v.push(Some(&id), Some(1), 1, false).unwrap();
    assert_eq!(
        v.push(Some(&id), Some(2), 1, true).unwrap_err(),
        UploadError::TooManyChunks
    );
}

#[test]
fn empty_pack_and_after_last() {
    let (_, id) = valid_pack();
    let mut v = validator(&id, 0, SSH_LIMITS);
    assert!(v.push(Some(&id), Some(0), 0, true).unwrap().complete);
    assert_eq!(
        v.push(Some(&id), Some(0), 0, true).unwrap_err(),
        UploadError::AfterLast
    );
    assert_eq!(v.finish().unwrap().total, 0);
}

/// One way to break an otherwise valid stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mutation {
    Gap,
    Overrun,
    WrongPackId,
    MissingLast,
}

/// A pack length and a valid split of it into chunk lengths.
fn split() -> impl Strategy<Value = (u64, Vec<usize>)> {
    prop::collection::vec(0usize..64, 1..12).prop_map(|lens| {
        let total = lens.iter().sum::<usize>() as u64;
        (total, lens)
    })
}

/// Feed `lens` as chunks, applying `mutation` at chunk `at`; the result of
/// the whole stream, `finish` included.
fn run(total: u64, lens: &[usize], mutation: Option<(Mutation, usize)>) -> Result<(), UploadError> {
    let id = [7; 32];
    let mut v = validator(&id, total, CONNECT_LIMITS);
    let mut offset = 0u64;
    for (i, &len) in lens.iter().enumerate() {
        let hit = |m: Mutation| mutation == Some((m, i));
        let chunk_id = if hit(Mutation::WrongPackId) {
            [8; 32]
        } else {
            id
        };
        let at = offset + u64::from(hit(Mutation::Gap));
        let data_len = len + usize::from(hit(Mutation::Overrun));
        let last =
            i + 1 == lens.len() && !mutation.is_some_and(|(m, _)| m == Mutation::MissingLast);
        v.push(Some(&chunk_id), Some(at), data_len, last)?;
        offset += len as u64;
    }
    v.finish().map(|_| ())
}

proptest! {
    #[test]
    fn valid_splits_complete((total, lens) in split()) {
        prop_assert_eq!(run(total, &lens, None), Ok(()));
    }

    #[test]
    fn any_single_mutation_is_rejected(
        (total, lens) in split(),
        pick in 0usize..4,
        at in any::<prop::sample::Index>(),
    ) {
        let mutation = [Mutation::Gap, Mutation::Overrun, Mutation::WrongPackId, Mutation::MissingLast][pick];
        let at = at.index(lens.len());
        prop_assert!(run(total, &lens, Some((mutation, at))).is_err(), "{:?} at {}", mutation, at);
    }
}
