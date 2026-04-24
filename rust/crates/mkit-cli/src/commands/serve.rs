//! `mkit serve <path>` — speak the 7-verb SSH transport wire protocol
//! on stdin/stdout against a local repository.
//!
//! The backing repo is accessed via `FileTransport`, which already
//! implements [`mkit_core::protocol::Transport`]. Frame encoding is
//! [`mkit_core::protocol::encode_frame`] / `decode_frame`; per-verb
//! payload decoders are provided by `mkit-transport-ssh` so this file
//! does not need inlined copies.

use std::io::{Read, Write};
use std::path::PathBuf;

use mkit_core::protocol::{
    self, FRAME_HEADER_LEN, HELLO_NAME_MAX, HELLO_VERSION_MAX, MAX_PAYLOAD_LEN, OP_CLOSE,
    OP_DOWNLOAD_PACK, OP_HELLO, OP_LIST_REFS, OP_PACK_EXISTS, OP_READ_REF, OP_UPDATE_REF,
    OP_UPLOAD_PACK, OP_WRITE_REF, PackKey, SSH_BINARY_NAME, SSH_PROTO_VERSION, STATUS_ERROR,
    STATUS_NULL, STATUS_OK, STATUS_UNSUPPORTED, Transport,
};
use mkit_transport_file::FileTransport;
use mkit_transport_ssh::{
    decode_download_pack, decode_list_refs, decode_pack_exists, decode_read_ref, decode_update_ref,
    decode_upload_pack, decode_write_ref, encode_ref_list,
};

use crate::cli::CLI_VERSION;
use crate::exit;

// -- Per-connection resource caps (finding A14) ------------------------------
//
// A single `mkit serve` invocation is driven by a remote client via an SSH
// forced command. Bounding cumulative work prevents a misbehaving or
// malicious client from pinning the sshd-spawned process indefinitely:
//
//   * `MAX_FRAMES_PER_CONN` — hard cap on frames (excluding HELLO).
//   * `MAX_BYTES_PER_CONN`  — hard cap on cumulative payload bytes read
//     after HELLO.
//
// Each cap trips returns `STATUS_ERROR` to the client then closes the
// connection with `exit::PROTOCOL_ERROR`.
pub(crate) const MAX_FRAMES_PER_CONN: u32 = 10_000;
pub(crate) const MAX_BYTES_PER_CONN: u64 = 1024 * 1024 * 1024; // 1 GiB

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let Some(path) = args.first() else {
        return super::usage_error("usage: mkit serve <path>");
    };

    let repo_root = match resolve_repo_path(path) {
        Ok(p) => p,
        Err(code) => return code,
    };
    let tx = FileTransport::new(&repo_root);

    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut r = stdin.lock();
    let mut w = stdout.lock();

    serve_loop(&tx, &mut r, &mut w)
}

/// Resolve and validate the on-disk path supplied to `mkit serve`.
///
/// Returns an sysexits-style exit code on failure:
///
/// * [`exit::NOINPUT`] — path does not exist / cannot be canonicalised.
/// * [`exit::DATAERR`] — path exists but is not a directory, or the
///   directory does not look like a mkit repository (no `.mkit/` child).
/// * [`exit::NOPERM`]  — `MKIT_SERVE_ROOT` is set and the resolved path
///   escapes that containment root (`..` / absolute-path traversal).
///
/// The containment check compares canonicalised paths, so symlinks that
/// would leave the serve-root are rejected.
pub(crate) fn resolve_repo_path(path: &str) -> Result<PathBuf, u8> {
    let resolved = std::fs::canonicalize(path).map_err(|_| exit::NOINPUT)?;
    if !resolved.is_dir() {
        return Err(exit::DATAERR);
    }
    if !resolved.join(".mkit").is_dir() {
        return Err(exit::DATAERR);
    }
    if let Ok(root) = std::env::var("MKIT_SERVE_ROOT") {
        let pinned = std::fs::canonicalize(&root).map_err(|_| exit::NOPERM)?;
        if !resolved.starts_with(&pinned) {
            return Err(exit::NOPERM);
        }
    }
    Ok(resolved)
}

/// Core serve loop, factored out so it can be driven by in-process tests
/// with a synthetic reader/writer (see finding A14).
pub(crate) fn serve_loop(tx: &FileTransport, r: &mut impl Read, w: &mut impl Write) -> u8 {
    if !handshake(r, w) {
        return exit::PROTOCOL_ERROR;
    }
    let mut frame_count: u32 = 0;
    let mut byte_count: u64 = 0;
    while let Some((op, payload)) = read_frame(r) {
        frame_count = frame_count.saturating_add(1);
        byte_count = byte_count.saturating_add(payload.len() as u64);
        if frame_count > MAX_FRAMES_PER_CONN || byte_count > MAX_BYTES_PER_CONN {
            let _ = write_status(w, STATUS_ERROR, b"per-connection budget exceeded");
            return exit::PROTOCOL_ERROR;
        }
        if op == OP_CLOSE {
            break;
        }
        let (status, body) = dispatch(tx, op, &payload);
        if write_status(w, status, &body).is_err() {
            break;
        }
    }
    exit::OK
}

fn handshake(r: &mut impl Read, w: &mut impl Write) -> bool {
    let Some((op, payload)) = read_frame(r) else {
        return false;
    };
    if op != OP_HELLO {
        let _ = write_status(w, STATUS_ERROR, b"hello required");
        return false;
    }
    let Some(hello) = decode_hello_request(&payload) else {
        let _ = write_status(w, STATUS_ERROR, b"hello decode error");
        return false;
    };
    if hello.binary_name != SSH_BINARY_NAME {
        let _ = write_status(w, STATUS_ERROR, b"binary name mismatch");
        return false;
    }
    if hello.proto_version != SSH_PROTO_VERSION {
        let _ = write_status(w, STATUS_UNSUPPORTED, b"unsupported proto version");
        return false;
    }
    let Ok(server_hello) = protocol::encode_hello_payload(
        SSH_PROTO_VERSION,
        SSH_BINARY_NAME,
        &format!("mkit {CLI_VERSION}"),
    ) else {
        return false;
    };
    write_status(w, STATUS_OK, &server_hello).is_ok()
}

fn dispatch(tx: &FileTransport, op: u8, payload: &[u8]) -> (u8, Vec<u8>) {
    match op {
        OP_UPLOAD_PACK => match decode_upload_pack(payload) {
            Ok(req) => match tx.upload_pack(&req.data, &PackKey(req.digest)) {
                Ok(()) => (STATUS_OK, Vec::new()),
                Err(_) => (STATUS_ERROR, b"upload failed".to_vec()),
            },
            Err(_) => (STATUS_ERROR, b"decode error".to_vec()),
        },
        OP_DOWNLOAD_PACK => match decode_download_pack(payload) {
            Ok(h) => match tx.download_pack(&PackKey(h)) {
                Ok(bytes) => (STATUS_OK, bytes),
                Err(_) => (STATUS_NULL, Vec::new()),
            },
            Err(_) => (STATUS_ERROR, b"decode error".to_vec()),
        },
        OP_PACK_EXISTS => match decode_pack_exists(payload) {
            Ok(h) => {
                let present = tx.pack_exists(&PackKey(h)).unwrap_or(false);
                (STATUS_OK, vec![u8::from(present)])
            }
            Err(_) => (STATUS_ERROR, b"decode error".to_vec()),
        },
        OP_WRITE_REF => match decode_write_ref(payload) {
            Ok(req) => match tx.write_ref(&req.name, &req.hash) {
                Ok(()) => (STATUS_OK, Vec::new()),
                Err(_) => (STATUS_ERROR, b"write ref failed".to_vec()),
            },
            Err(_) => (STATUS_ERROR, b"decode error".to_vec()),
        },
        OP_UPDATE_REF => match decode_update_ref(payload) {
            Ok(req) => match tx.update_ref(&req.name, req.condition, &req.hash) {
                Ok(()) => (STATUS_OK, Vec::new()),
                Err(_) => (STATUS_ERROR, b"update ref failed".to_vec()),
            },
            Err(_) => (STATUS_ERROR, b"decode error".to_vec()),
        },
        OP_READ_REF => match decode_read_ref(payload) {
            Ok(name) => match tx.read_ref(&name) {
                Ok(Some(h)) => (STATUS_OK, h.to_vec()),
                Ok(None) => (STATUS_NULL, Vec::new()),
                Err(_) => (STATUS_ERROR, b"read ref failed".to_vec()),
            },
            Err(_) => (STATUS_ERROR, b"decode error".to_vec()),
        },
        OP_LIST_REFS => match decode_list_refs(payload) {
            Ok(prefix) => match tx.list_refs(&prefix) {
                Ok(refs) => match encode_ref_list(&refs) {
                    Ok(body) => (STATUS_OK, body),
                    Err(_) => (STATUS_ERROR, b"encode error".to_vec()),
                },
                Err(_) => (STATUS_ERROR, b"list refs failed".to_vec()),
            },
            Err(_) => (STATUS_ERROR, b"decode error".to_vec()),
        },
        _ => (STATUS_UNSUPPORTED, Vec::new()),
    }
}

// -- Frame I/O ---------------------------------------------------------------

fn read_frame(r: &mut impl Read) -> Option<(u8, Vec<u8>)> {
    let mut header = [0u8; FRAME_HEADER_LEN];
    r.read_exact(&mut header).ok()?;
    let op = header[0];
    let len = u32::from_le_bytes([header[1], header[2], header[3], header[4]]) as usize;
    if len > MAX_PAYLOAD_LEN {
        return None;
    }
    let mut payload = vec![0u8; len];
    if len > 0 {
        r.read_exact(&mut payload).ok()?;
    }
    Some((op, payload))
}

fn write_status(w: &mut impl Write, status: u8, payload: &[u8]) -> std::io::Result<()> {
    match protocol::encode_frame(status, payload) {
        Ok(frame) => {
            w.write_all(&frame)?;
            w.flush()
        }
        Err(_) => Err(std::io::Error::other("encode frame")),
    }
}

// -- HELLO handshake decoder (serve-side only; not exported from ssh crate) --

struct HelloRequest<'a> {
    proto_version: u8,
    binary_name: &'a str,
}

fn decode_hello_request(p: &[u8]) -> Option<HelloRequest<'_>> {
    if p.len() < 2 {
        return None;
    }
    let proto_version = p[0];
    let name_len = p[1] as usize;
    if name_len > HELLO_NAME_MAX || 2 + name_len + 1 > p.len() {
        return None;
    }
    let name = std::str::from_utf8(&p[2..2 + name_len]).ok()?;
    let ver_len = p[2 + name_len] as usize;
    if ver_len > HELLO_VERSION_MAX || 2 + name_len + 1 + ver_len > p.len() {
        return None;
    }
    Some(HelloRequest {
        proto_version,
        binary_name: name,
    })
}

// -- Public-decoder reachability test ----------------------------------------

#[cfg(test)]
mod tests {
    use super::{resolve_repo_path, serve_loop};
    use crate::exit;
    use mkit_core::protocol::{
        FRAME_HEADER_LEN, OP_CLOSE, OP_HELLO, SSH_BINARY_NAME, SSH_PROTO_VERSION, STATUS_OK,
        encode_frame, encode_hello_payload,
    };
    use mkit_transport_file::FileTransport;
    use std::fs;
    use std::io::Cursor;

    /// Compile-time reachability check: assert each public per-verb decoder
    /// symbol is accessible from outside `mkit-transport-ssh`.  No runtime
    /// logic needed — if the crate compiles this function, the symbols exist.
    #[test]
    fn public_decoders_exist() {
        let _ = mkit_transport_ssh::decode_upload_pack as fn(&[u8]) -> _;
        let _ = mkit_transport_ssh::decode_download_pack as fn(&[u8]) -> _;
        let _ = mkit_transport_ssh::decode_pack_exists as fn(&[u8]) -> _;
        let _ = mkit_transport_ssh::decode_write_ref as fn(&[u8]) -> _;
        let _ = mkit_transport_ssh::decode_update_ref as fn(&[u8]) -> _;
        let _ = mkit_transport_ssh::decode_read_ref as fn(&[u8]) -> _;
        let _ = mkit_transport_ssh::decode_list_refs as fn(&[u8]) -> _;
        let _ = mkit_transport_ssh::decode_ref_list as fn(&[u8]) -> _;
        let _ = mkit_transport_ssh::encode_write_ref
            as fn(&str, &_) -> mkit_core::protocol::TransportResult<_>;
        let _ = mkit_transport_ssh::encode_update_ref
            as fn(&str, _, &_) -> mkit_core::protocol::TransportResult<_>;
        let _ = mkit_transport_ssh::encode_read_ref
            as fn(&str) -> mkit_core::protocol::TransportResult<_>;
        let _ = mkit_transport_ssh::encode_list_refs
            as fn(&str) -> mkit_core::protocol::TransportResult<_>;
    }

    // --- A1: path containment --------------------------------------------

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

// --- A14: per-connection byte/frame budget ---------------------------

    /// Build a handshake-complete input stream, then append enough no-op
    /// OP_HELLO-shaped frames to blow the frame budget.
    #[test]
    fn serve_loop_enforces_frame_budget() {
        let td = tempfile::tempdir().unwrap();
        fs::create_dir_all(td.path().join(".mkit")).unwrap();
        let tx = FileTransport::new(td.path());

        // Client HELLO that will pass handshake.
        let hello = encode_hello_payload(SSH_PROTO_VERSION, SSH_BINARY_NAME, "test/1")
            .expect("hello payload");
        let mut input = encode_frame(OP_HELLO, &hello).expect("hello frame");

        // Append more than MAX_FRAMES_PER_CONN unsupported-but-well-formed
        // frames. Use op=0xFE (not a valid verb) with empty payload so
        // dispatch replies STATUS_UNSUPPORTED and keeps reading.
        for _ in 0..=super::MAX_FRAMES_PER_CONN {
            input.extend_from_slice(&encode_frame(0xFE, &[]).expect("frame"));
        }

        let mut r = Cursor::new(input);
        let mut w = Vec::new();
        let code = serve_loop(&tx, &mut r, &mut w);
        assert_eq!(code, exit::PROTOCOL_ERROR, "should trip frame budget");
    }

    #[test]
    fn serve_loop_enforces_byte_budget() {
        let td = tempfile::tempdir().unwrap();
        fs::create_dir_all(td.path().join(".mkit")).unwrap();
        let tx = FileTransport::new(td.path());

        let hello = encode_hello_payload(SSH_PROTO_VERSION, SSH_BINARY_NAME, "test/1")
            .expect("hello payload");
        let mut input = encode_frame(OP_HELLO, &hello).expect("hello frame");

        // Each frame carries a big payload so we exceed MAX_BYTES_PER_CONN
        // well before MAX_FRAMES_PER_CONN. 16 MiB is MAX_PAYLOAD_LEN; use
        // 8 MiB blobs. 128 of them = 1 GiB, trigger point.
        let blob = vec![0u8; 8 * 1024 * 1024];
        let needed = (super::MAX_BYTES_PER_CONN / blob.len() as u64 + 1)
            .min(u64::from(super::MAX_FRAMES_PER_CONN));
        for _ in 0..needed {
            input.extend_from_slice(&encode_frame(0xFE, &blob).expect("frame"));
        }
        // Sanity: test is meaningful only if we stayed under the frame cap.
        assert!(needed < u64::from(super::MAX_FRAMES_PER_CONN));

        let mut r = Cursor::new(input);
        let mut w = Vec::new();
        let code = serve_loop(&tx, &mut r, &mut w);
        assert_eq!(code, exit::PROTOCOL_ERROR, "should trip byte budget");
    }

    #[test]
    fn serve_loop_close_returns_ok_within_budget() {
        let td = tempfile::tempdir().unwrap();
        fs::create_dir_all(td.path().join(".mkit")).unwrap();
        let tx = FileTransport::new(td.path());

        let hello = encode_hello_payload(SSH_PROTO_VERSION, SSH_BINARY_NAME, "test/1")
            .expect("hello payload");
        let mut input = encode_frame(OP_HELLO, &hello).expect("hello frame");
        input.extend_from_slice(&encode_frame(OP_CLOSE, &[]).expect("close frame"));

        let mut r = Cursor::new(input);
        let mut w = Vec::new();
        let code = serve_loop(&tx, &mut r, &mut w);
        assert_eq!(code, exit::OK);
        assert!(w.len() >= FRAME_HEADER_LEN);
        assert_eq!(w[0], STATUS_OK, "server hello ok");
    }
}
