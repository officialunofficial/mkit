use super::*;
use crate::exit;
use std::fs;
use std::io::Cursor;

fn upload_header(pack_id: Vec<u8>, total_bytes: Option<u64>) -> UploadPack {
    UploadPack {
        pack_id: Some(pack_id),
        total_bytes,
        ..Default::default()
    }
}

fn upload_chunk(pack_id: Vec<u8>, offset: Option<u64>, data: &[u8], last: bool) -> PackChunk {
    PackChunk {
        pack_id: Some(pack_id),
        offset,
        data: Some(data.to_vec()),
        last: Some(last),
        ..Default::default()
    }
}

fn valid_pack() -> (Vec<u8>, PackKey) {
    let bytes = b"valid pack bytes".to_vec();
    let key = PackKey::new(hash(&bytes));
    (bytes, key)
}

#[test]
fn resolve_repo_path_rejects_missing_path() {
    let err = resolve_repo_path("/definitely/does/not/exist/xyzzy").unwrap_err();
    assert_eq!(err, exit::NOINPUT);
}

#[test]
fn resolve_repo_path_rejects_non_repo_dir() {
    let td = tempfile::tempdir().unwrap();
    let err = resolve_repo_path(td.path().to_str().unwrap()).unwrap_err();
    assert_eq!(err, exit::DATAERR);
}

#[test]
fn resolve_repo_path_accepts_repo_dir() {
    let td = tempfile::tempdir().unwrap();
    fs::create_dir_all(td.path().join(".mkit")).unwrap();
    let resolved = resolve_repo_path(td.path().to_str().unwrap()).unwrap();
    assert!(resolved.join(".mkit").is_dir());
}

#[test]
fn upload_drain_accepts_valid_chunks() {
    let (bytes, key) = valid_pack();
    let mut drain = UploadDrain::new(&upload_header(
        key.as_bytes().to_vec(),
        Some(bytes.len() as u64),
    ))
    .unwrap();
    assert!(
        !drain
            .push_chunk(&upload_chunk(
                key.as_bytes().to_vec(),
                Some(0),
                &bytes[..5],
                false
            ))
            .unwrap()
    );
    assert!(
        drain
            .push_chunk(&upload_chunk(
                key.as_bytes().to_vec(),
                Some(5),
                &bytes[5..],
                true,
            ))
            .unwrap()
    );
    let (got, got_key) = drain.into_parts();
    assert_eq!(got, bytes);
    assert_eq!(got_key.as_bytes(), key.as_bytes());
}

#[test]
fn upload_drain_rejects_malformed_streams() {
    let (bytes, key) = valid_pack();
    assert!(UploadDrain::new(&upload_header(key.as_bytes().to_vec(), None)).is_err());
    assert!(
        UploadDrain::new(&upload_header(
            key.as_bytes().to_vec(),
            Some(MAX_BYTES_PER_CONN + 1),
        ))
        .is_err()
    );

    let mut drain = UploadDrain::new(&upload_header(
        key.as_bytes().to_vec(),
        Some(bytes.len() as u64),
    ))
    .unwrap();
    assert!(
        drain
            .push_chunk(&upload_chunk(
                key.as_bytes().to_vec(),
                Some(1),
                &bytes,
                true
            ))
            .is_err()
    );

    let mut drain = UploadDrain::new(&upload_header(
        key.as_bytes().to_vec(),
        Some(bytes.len() as u64),
    ))
    .unwrap();
    assert!(
        drain
            .push_chunk(&upload_chunk(vec![0xAA; 32], Some(0), &bytes, true))
            .is_err()
    );

    let mut drain = UploadDrain::new(&upload_header(
        key.as_bytes().to_vec(),
        Some(bytes.len() as u64 - 1),
    ))
    .unwrap();
    assert!(
        drain
            .push_chunk(&upload_chunk(
                key.as_bytes().to_vec(),
                Some(0),
                &bytes,
                true
            ))
            .is_err()
    );

    let mut drain = UploadDrain::new(&upload_header(
        key.as_bytes().to_vec(),
        Some(bytes.len() as u64),
    ))
    .unwrap();
    assert!(
        drain
            .push_chunk(&upload_chunk(
                key.as_bytes().to_vec(),
                Some(0),
                &bytes[..bytes.len() - 1],
                true,
            ))
            .is_err()
    );

    let wrong_bytes = b"wrong pack bytes";
    let mut drain = UploadDrain::new(&upload_header(
        key.as_bytes().to_vec(),
        Some(wrong_bytes.len() as u64),
    ))
    .unwrap();
    assert!(
        drain
            .push_chunk(&upload_chunk(
                key.as_bytes().to_vec(),
                Some(0),
                wrong_bytes,
                true,
            ))
            .is_err()
    );
}

fn write_body(buf: &mut Vec<u8>, body: ssh_frame::Body) {
    mkit_rpc::write_frame(
        buf,
        &SshFrame {
            body: Some(body),
            ..Default::default()
        },
    )
    .unwrap();
}

#[test]
fn serve_loop_rejects_invalid_upload_before_storage() {
    let td = tempfile::tempdir().unwrap();
    let tx = FileTransport::new(td.path());
    let bogus_key = PackKey::new([0x77; 32]);

    let mut input = Vec::new();
    write_body(
        &mut input,
        ssh_frame::Body::Hello(Box::new(
            mkit_rpc::mkit::rpc::v1::ssh::Hello::default()
                .with_proto(ProtocolVersion::ProtocolVersion1),
        )),
    );
    write_body(
        &mut input,
        ssh_frame::Body::UploadPack(Box::new(upload_header(
            bogus_key.as_bytes().to_vec(),
            Some(5),
        ))),
    );
    write_body(
        &mut input,
        ssh_frame::Body::PackChunk(Box::new(upload_chunk(
            bogus_key.as_bytes().to_vec(),
            Some(0),
            b"wrong",
            true,
        ))),
    );

    let mut reader = Cursor::new(input);
    let mut output = Vec::new();
    assert_eq!(serve_loop(&tx, &mut reader, &mut output), exit::OK);
    assert!(!tx.pack_exists(&bogus_key).unwrap());

    let mut out = Cursor::new(output);
    let _hello: SshFrame = mkit_rpc::read_frame(&mut out).unwrap();
    let err: SshFrame = mkit_rpc::read_frame(&mut out).unwrap();
    assert!(matches!(err.body, Some(ssh_frame::Body::Error(_))));
}

#[test]
fn serve_loop_rejected_upload_does_not_overwrite_existing_pack() {
    let td = tempfile::tempdir().unwrap();
    let tx = FileTransport::new(td.path());
    let (bytes, key) = valid_pack();
    tx.upload_pack(&bytes, &key).unwrap();

    let mut input = Vec::new();
    write_body(
        &mut input,
        ssh_frame::Body::Hello(Box::new(
            mkit_rpc::mkit::rpc::v1::ssh::Hello::default()
                .with_proto(ProtocolVersion::ProtocolVersion1),
        )),
    );
    write_body(
        &mut input,
        ssh_frame::Body::UploadPack(Box::new(upload_header(key.as_bytes().to_vec(), Some(5)))),
    );
    write_body(
        &mut input,
        ssh_frame::Body::PackChunk(Box::new(upload_chunk(
            key.as_bytes().to_vec(),
            Some(0),
            b"wrong",
            true,
        ))),
    );

    let mut reader = Cursor::new(input);
    let mut output = Vec::new();
    assert_eq!(serve_loop(&tx, &mut reader, &mut output), exit::OK);
    assert_eq!(tx.download_pack(&key).unwrap(), bytes);
}

/// Build an `UpdateRef` request body. `expected` is only set for MATCH.
fn update_ref_body(
    name: &str,
    new_id: [u8; 32],
    expectation: RefExpectation,
    expected: Option<[u8; 32]>,
) -> ssh_frame::Body {
    let mut req = mkit_rpc::mkit::rpc::v1::ssh::UpdateRef::default()
        .with_name(name)
        .with_new_id(new_id.to_vec())
        .with_expectation(expectation);
    if let Some(e) = expected {
        req = req.with_expected_id(e.to_vec());
    }
    ssh_frame::Body::UpdateRef(Box::new(req))
}

/// SPEC-TRANSPORT §4.2.1 over the real sync server: two writers race a
/// create-only (`MISSING`) update; the loser's reply is
/// `Error{INVALID_REQUEST}` carrying the WINNER's id in `details`, and
/// the shared client classifier maps it to `RefConflict` — not
/// `RemoteError`. Before the #551 fix the server sent empty `details`,
/// so the strict SSH classifier degraded the conflict to `RemoteError`.
#[test]
fn serve_loop_cas_conflict_carries_current_id_in_details() {
    let td = tempfile::tempdir().unwrap();
    let tx = FileTransport::new(td.path());
    let id_winner = [0xA1u8; 32];
    let id_loser = [0xB2u8; 32];

    let mut input = Vec::new();
    write_body(
        &mut input,
        ssh_frame::Body::Hello(Box::new(
            mkit_rpc::mkit::rpc::v1::ssh::Hello::default()
                .with_proto(ProtocolVersion::ProtocolVersion1),
        )),
    );
    // Writer A: create-only, wins.
    write_body(
        &mut input,
        update_ref_body("refs/heads/main", id_winner, RefExpectation::Missing, None),
    );
    // Writer B: create-only, loses the race.
    write_body(
        &mut input,
        update_ref_body("refs/heads/main", id_loser, RefExpectation::Missing, None),
    );

    let mut reader = Cursor::new(input);
    let mut output = Vec::new();
    assert_eq!(serve_loop(&tx, &mut reader, &mut output), exit::OK);
    // The ref holds the winner's id; the loser clobbered nothing.
    assert_eq!(tx.read_ref("refs/heads/main").unwrap(), Some(id_winner));

    let mut out = Cursor::new(output);
    let _hello: SshFrame = mkit_rpc::read_frame(&mut out).unwrap();
    let win: SshFrame = mkit_rpc::read_frame(&mut out).unwrap();
    assert!(matches!(
        win.body,
        Some(ssh_frame::Body::UpdateRefResponse(_))
    ));
    let lose: SshFrame = mkit_rpc::read_frame(&mut out).unwrap();
    let Some(ssh_frame::Body::Error(err)) = lose.body else {
        panic!("loser must receive an Error frame, got {:?}", lose.body);
    };
    assert!(err.code.is_some_and(|c| c == ErrorCode::InvalidRequest));
    assert_eq!(
        err.details.as_deref(),
        Some(&id_winner[..]),
        "details must carry the CURRENT ref value (the winner's id)"
    );
    // The exact frame the server produced classifies as RefConflict
    // through the shared client-side mapping both transports use.
    assert!(matches!(
        mkit_rpc::map_update_ref_error(*err, RefWriteCondition::Missing, "ssh"),
        mkit_core::protocol::TransportError::RefConflict
    ));
}

/// A stale `MATCH` update against the real sync server: the reply's
/// `details` carries the current (unchanged) ref value.
#[test]
fn serve_loop_match_conflict_reports_current_value() {
    let td = tempfile::tempdir().unwrap();
    let tx = FileTransport::new(td.path());
    let current = [0x11u8; 32];
    let stale = [0x22u8; 32];
    let next = [0x33u8; 32];
    tx.update_ref("refs/heads/main", RefWriteCondition::Any, &current)
        .unwrap();

    let mut input = Vec::new();
    write_body(
        &mut input,
        ssh_frame::Body::Hello(Box::new(
            mkit_rpc::mkit::rpc::v1::ssh::Hello::default()
                .with_proto(ProtocolVersion::ProtocolVersion1),
        )),
    );
    write_body(
        &mut input,
        update_ref_body("refs/heads/main", next, RefExpectation::Match, Some(stale)),
    );

    let mut reader = Cursor::new(input);
    let mut output = Vec::new();
    assert_eq!(serve_loop(&tx, &mut reader, &mut output), exit::OK);
    assert_eq!(tx.read_ref("refs/heads/main").unwrap(), Some(current));

    let mut out = Cursor::new(output);
    let _hello: SshFrame = mkit_rpc::read_frame(&mut out).unwrap();
    let reply: SshFrame = mkit_rpc::read_frame(&mut out).unwrap();
    let Some(ssh_frame::Body::Error(err)) = reply.body else {
        panic!(
            "stale MATCH must receive an Error frame, got {:?}",
            reply.body
        );
    };
    assert!(err.code.is_some_and(|c| c == ErrorCode::InvalidRequest));
    assert_eq!(err.details.as_deref(), Some(&current[..]));
}

/// `MATCH` against a ref that does not exist: still a CAS conflict on
/// the wire (`INVALID_REQUEST`), but there is no current value to
/// surface, so `details` stays empty — mirroring `ReadRefResponse`'s
/// empty-means-absent encoding. Strict clients surface this as a
/// remote error carrying the server's descriptive message rather than
/// a `RefConflict` with a fabricated id.
#[test]
fn serve_loop_match_conflict_on_absent_ref_has_empty_details() {
    let td = tempfile::tempdir().unwrap();
    let tx = FileTransport::new(td.path());

    let mut input = Vec::new();
    write_body(
        &mut input,
        ssh_frame::Body::Hello(Box::new(
            mkit_rpc::mkit::rpc::v1::ssh::Hello::default()
                .with_proto(ProtocolVersion::ProtocolVersion1),
        )),
    );
    write_body(
        &mut input,
        update_ref_body(
            "refs/heads/ghost",
            [0x44u8; 32],
            RefExpectation::Match,
            Some([0x55u8; 32]),
        ),
    );

    let mut reader = Cursor::new(input);
    let mut output = Vec::new();
    assert_eq!(serve_loop(&tx, &mut reader, &mut output), exit::OK);
    assert_eq!(tx.read_ref("refs/heads/ghost").unwrap(), None);

    let mut out = Cursor::new(output);
    let _hello: SshFrame = mkit_rpc::read_frame(&mut out).unwrap();
    let reply: SshFrame = mkit_rpc::read_frame(&mut out).unwrap();
    let Some(ssh_frame::Body::Error(err)) = reply.body else {
        panic!("absent-ref MATCH must receive an Error frame");
    };
    assert!(err.code.is_some_and(|c| c == ErrorCode::InvalidRequest));
    assert_eq!(err.details.as_deref().map_or(0, <[u8]>::len), 0);
    // Empty details → strict classifier reports the server's message,
    // not RefConflict.
    let mapped =
        mkit_rpc::map_update_ref_error(*err, RefWriteCondition::Match([0x55u8; 32]), "ssh");
    match mapped {
        mkit_core::protocol::TransportError::RemoteError(msg) => {
            assert!(msg.contains("absent"), "message should say absent: {msg}");
        }
        other => panic!("expected RemoteError, got {other:?}"),
    }
}

// Note: containment via MKIT_SERVE_ROOT is enforced — tested via
// an integration test in tests/ rather than here, since this
// crate forbids `unsafe` (which `std::env::set_var` requires
// since Rust 1.92).

#[test]
fn pack_key_from_id_rejects_bad_length_as_invalid_request() {
    // `pack_key_from_id` is the shared decoder behind PackExists and
    // DownloadPack. This covers
    // the decoder itself: a wrong-length or missing pack_id must yield an
    // InvalidRequest verb error, which the dispatcher then turns into an
    // error frame — replacing the pre-unification sync path that silently
    // dropped the connection. (The frame emission is exercised separately
    // by the serve_loop tests.)
    let wrong_len = vec![0u8; 16];
    assert!(matches!(
        pack_key_from_id(Some(&wrong_len)),
        Err((ErrorCode::InvalidRequest, _))
    ));
    assert!(matches!(
        pack_key_from_id(None),
        Err((ErrorCode::InvalidRequest, _))
    ));
    // A correct 32-byte id still decodes.
    assert!(pack_key_from_id(Some(&vec![7u8; 32])).is_ok());
}

#[test]
fn removed_listener_flag_names_the_first_removed_flag() {
    let args = |a: &[&str]| a.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
    assert_eq!(
        removed_listener_flag(&args(&["repo", "--http", "127.0.0.1:0"])),
        Some("--http")
    );
    assert_eq!(
        removed_listener_flag(&args(&["--enc-idle-timeout-secs=5", "--listen-enc", "x"])),
        Some("--enc-idle-timeout-secs")
    );
    // Not a removed flag, a prefix of one, or anything after `--`.
    assert_eq!(removed_listener_flag(&args(&["repo", "--bogus"])), None);
    assert_eq!(removed_listener_flag(&args(&["--htt", "repo"])), None);
    assert_eq!(removed_listener_flag(&args(&["--", "--http"])), None);
}
