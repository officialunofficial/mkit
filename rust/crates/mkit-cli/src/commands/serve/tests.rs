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

#[cfg(feature = "enc-transport")]
#[test]
fn listen_enc_rejected_upload_does_not_overwrite_existing_pack() {
    use commonware_codec::Encode as _;
    use commonware_cryptography::Signer as _;
    use commonware_cryptography::ed25519::PrivateKey;
    use mkit_transport_enc::tcp::{TokioExecutor, connect_tcp_with_executor, serve_tcp_with_addr};
    use std::sync::{Arc, mpsc};
    use std::thread;
    use std::time::Duration;

    let td = tempfile::tempdir().unwrap();
    let tx = FileTransport::new(td.path());
    let (bytes, key) = valid_pack();
    tx.upload_pack(&bytes, &key).unwrap();

    let exec = TokioExecutor::new().expect("tokio runtime");
    let server_key = PrivateKey::from_seed(1001);
    let server_pubkey = {
        let encoded = server_key.public_key().encode();
        let bytes = encoded.as_ref();
        assert_eq!(bytes.len(), 32);
        let mut out = [0u8; 32];
        out.copy_from_slice(bytes);
        out
    };

    let server_tx = Arc::new(FileTransport::new(td.path()));
    let (addr_tx, addr_rx) = mpsc::channel();
    let exec_for_server = exec.clone();
    let _server_handle = thread::spawn(move || {
        let serve_fn =
            move |sess: mkit_transport_enc::EncSession<
                mkit_transport_enc::tokio_io::TokioStream,
                mkit_transport_enc::tokio_io::TokioSink,
            >,
                  _peer: commonware_cryptography::ed25519::PublicKey| {
                let tx = server_tx.clone();
                // Tests drive a cooperative client, so the idle
                // timeout is irrelevant here; keep it generous.
                async move {
                    serve_enc_session(tx, sess, Some(std::time::Duration::from_secs(30))).await;
                }
            };
        let _ = serve_tcp_with_addr(
            "127.0.0.1:0",
            server_key,
            exec_for_server,
            move |addr| {
                let _ = addr_tx.send(addr);
            },
            serve_fn,
        );
    });

    let addr = addr_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("encrypted listener address");
    let client_key = PrivateKey::from_seed(2002);
    let client = connect_tcp_with_executor(
        &addr.ip().to_string(),
        addr.port(),
        &server_pubkey,
        client_key,
        exec,
    )
    .expect("connect encrypted client");

    assert!(client.upload_pack(b"wrong", &key).is_err());
    assert_eq!(tx.download_pack(&key).unwrap(), bytes);
}

// Note: containment via MKIT_SERVE_ROOT is enforced — tested via
// an integration test in tests/ rather than here, since this
// crate forbids `unsafe` (which `std::env::set_var` requires
// since Rust 1.92).

#[cfg(feature = "enc-transport")]
fn enc_repo() -> tempfile::TempDir {
    let td = tempfile::tempdir().unwrap();
    fs::create_dir_all(td.path().join(".mkit")).unwrap();
    td
}

/// Fail-closed: `serve --listen-enc` with neither an authorized-peers
/// file nor the unsafe flag returns `CONFIG_ERROR` before binding.
#[cfg(feature = "enc-transport")]
#[test]
fn listen_enc_fails_closed_without_peer_auth() {
    let td = enc_repo();
    let args = vec![
        td.path().to_str().unwrap().to_string(),
        "--listen-enc".to_string(),
        "127.0.0.1:0".to_string(),
    ];
    assert_eq!(run(&args), exit::CONFIG_ERROR);
}

/// An authorized-peers file that exists but parses to no valid keys
/// is rejected (fail-closed), not silently treated as allow-any.
#[cfg(feature = "enc-transport")]
#[test]
fn listen_enc_rejects_empty_authorized_peers() {
    let td = enc_repo();
    let peers = td.path().join("peers.txt");
    fs::write(&peers, "# only comments\n\n").unwrap();
    let args = vec![
        td.path().to_str().unwrap().to_string(),
        "--listen-enc".to_string(),
        "127.0.0.1:0".to_string(),
        "--enc-authorized-peers".to_string(),
        peers.to_str().unwrap().to_string(),
    ];
    assert_eq!(run(&args), exit::CONFIG_ERROR);
}

/// Supplying both `--enc-authorized-peers` and the unsafe flag is a
/// usage error.
#[cfg(feature = "enc-transport")]
#[test]
fn listen_enc_rejects_conflicting_flags() {
    let td = enc_repo();
    let peers = td.path().join("peers.txt");
    fs::write(&peers, format!("{}\n", "aa".repeat(32))).unwrap();
    let args = vec![
        td.path().to_str().unwrap().to_string(),
        "--listen-enc".to_string(),
        "127.0.0.1:0".to_string(),
        "--enc-authorized-peers".to_string(),
        peers.to_str().unwrap().to_string(),
        "--unsafe-allow-any-enc-peer".to_string(),
    ];
    assert_eq!(run(&args), exit::USAGE);
}

#[cfg(feature = "enc-transport")]
#[test]
fn authorized_peers_parses_hex_and_skips_comments() {
    let td = tempfile::tempdir().unwrap();
    let peers = td.path().join("peers.txt");
    let k1 = "aa".repeat(32);
    let k2 = "bb".repeat(32);
    fs::write(&peers, format!("# header\n{k1}\n\n  {k2}  \n")).unwrap();
    let set = load_authorized_peers(peers.to_str().unwrap()).unwrap();
    assert_eq!(set.len(), 2);
    assert!(set.contains(&[0xAA; 32]));
    assert!(set.contains(&[0xBB; 32]));
}

/// The allowlist file accepts the SAME 43-char url-safe base64
/// encoding the `mkit+enc://?pubkey=` query uses, and it decodes to
/// the identical 32-byte key as the hex form. Without this the docs
/// and `--enc-authorized-peers` help would promise base64 support
/// that the parser silently rejected.
#[cfg(feature = "enc-transport")]
#[test]
#[allow(clippy::cast_possible_truncation)] // test-only b64 encoder
fn authorized_peers_parses_base64_matching_hex() {
    // A key whose final byte's low bits are zero so the canonical
    // 43-char base64 has zero trailing bits. All-0xAA: last byte 0xAA.
    // Build from a real ed25519 public key to guarantee a valid pair
    // of encodings.
    use commonware_codec::Encode as _;
    use commonware_cryptography::Signer as _;
    use commonware_cryptography::ed25519::PrivateKey;

    let pk = PrivateKey::from_seed(4242).public_key();
    let raw: [u8; 32] = {
        let enc = pk.encode();
        let mut out = [0u8; 32];
        out.copy_from_slice(enc.as_ref());
        out
    };
    let hex = mkit_core::hash::to_hex(&raw);
    // Round-trip the raw bytes through our own base64 decoder by
    // first encoding with the standard alphabet.
    let b64 = {
        const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut s = String::new();
        for chunk in raw.chunks(3) {
            let b0 = u32::from(chunk[0]);
            let b1 = chunk.get(1).copied().map_or(0, u32::from);
            let b2 = chunk.get(2).copied().map_or(0, u32::from);
            let n = (b0 << 16) | (b1 << 8) | b2;
            let chars = match chunk.len() {
                1 => 2,
                2 => 3,
                _ => 4,
            };
            for i in 0..chars {
                let idx = ((n >> (18 - 6 * i)) & 0x3F) as usize;
                s.push(A[idx] as char);
            }
        }
        s
    };
    assert_eq!(b64.len(), 43, "ed25519 key encodes to 43 b64 chars");

    let td = tempfile::tempdir().unwrap();
    let peers = td.path().join("peers.txt");
    fs::write(&peers, format!("{hex}\n{b64}\n")).unwrap();
    let set = load_authorized_peers(peers.to_str().unwrap()).unwrap();
    // Both lines decode to the SAME key, so the set has one element.
    assert_eq!(set.len(), 1, "hex and base64 forms must coincide");
    assert!(set.contains(&raw));
}

#[cfg(feature = "enc-transport")]
#[test]
fn authorized_peers_rejects_malformed_key() {
    let td = tempfile::tempdir().unwrap();
    let peers = td.path().join("peers.txt");
    fs::write(&peers, "not-a-valid-key\n").unwrap();
    assert!(load_authorized_peers(peers.to_str().unwrap()).is_err());
}

#[test]
fn pack_key_from_id_rejects_bad_length_as_invalid_request() {
    // `pack_key_from_id` is the shared decoder behind PackExists and
    // DownloadPack on both the sync and encrypted transports. This covers
    // the decoder itself: a wrong-length or missing pack_id must yield an
    // InvalidRequest verb error, which the dispatchers then turn into an
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
