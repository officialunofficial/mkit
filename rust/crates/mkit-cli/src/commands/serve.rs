//! `mkit serve <path>` — speak the mkit-rpc SSH protocol on
//! stdin/stdout against a local repository.
//!
//! The backing repo is accessed via `FileTransport`. Frames are
//! length-prefixed buffa [`SshFrame`] messages defined in
//! `rust/crates/mkit-rpc/proto/ssh.proto`.

use std::io::{Read, Write};
use std::path::PathBuf;

use mkit_core::protocol::{PackKey, RefWriteCondition, Transport};
use mkit_rpc::mkit::rpc::v1::ssh::{
    DownloadPackHeader, HelloResponse, ListRefsResponse, PackChunk, PackExistsResponse,
    ReadRefResponse, SshFrame, UploadPackResponse, list_refs_response::RefEntry, ssh_frame,
};
use mkit_rpc::mkit::rpc::v1::{Error as RpcError, ErrorCode, ProtocolVersion};
use mkit_rpc::{FrameError, read_frame, write_frame};
use mkit_transport_file::FileTransport;

use crate::cli::CLI_VERSION;
use crate::exit;

// -- Per-connection resource caps -------------------------------------------
//
// A single `mkit serve` invocation is driven by a remote client via an SSH
// forced command. Bounding cumulative work prevents a misbehaving or
// malicious client from pinning the sshd-spawned process indefinitely.
pub(crate) const MAX_FRAMES_PER_CONN: u32 = 10_000;
pub(crate) const MAX_BYTES_PER_CONN: u64 = 1024 * 1024 * 1024; // 1 GiB

/// Pack chunk size cap during downloads. Keeps each `PackChunk` frame
/// well below the `MAX_FRAME_BYTES` (1 MiB) limit imposed by mkit-rpc's
/// length-prefixed framing.
const PACK_CHUNK_DATA_MAX: usize = 800 * 1024;

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

/// Core serve loop, generic over reader/writer so tests can drive it
/// with synthetic streams.
pub(crate) fn serve_loop(tx: &FileTransport, r: &mut impl Read, w: &mut impl Write) -> u8 {
    if !handshake(r, w) {
        return exit::PROTOCOL_ERROR;
    }
    let mut frame_count: u32 = 0;
    let mut byte_count: u64 = 0;

    loop {
        let frame: SshFrame = match read_frame(r) {
            Ok(f) => f,
            Err(FrameError::LengthTruncated) => return exit::OK,
            Err(_) => {
                let _ = send_error(
                    w,
                    ErrorCode::ERROR_CODE_INVALID_REQUEST,
                    "frame parse error",
                );
                return exit::PROTOCOL_ERROR;
            }
        };

        frame_count = frame_count.saturating_add(1);
        if frame_count > MAX_FRAMES_PER_CONN {
            let _ = send_error(
                w,
                ErrorCode::ERROR_CODE_INVALID_REQUEST,
                "per-connection frame budget exceeded",
            );
            return exit::PROTOCOL_ERROR;
        }

        // Approximate per-frame byte cost using the encoded length
        // we just consumed. We do not have the wire bytes here, but
        // the request payload sizes inside the frame body are a
        // close enough proxy for budget tracking.
        byte_count = byte_count.saturating_add(frame_byte_estimate(&frame));
        if byte_count > MAX_BYTES_PER_CONN {
            let _ = send_error(
                w,
                ErrorCode::ERROR_CODE_INVALID_REQUEST,
                "per-connection byte budget exceeded",
            );
            return exit::PROTOCOL_ERROR;
        }

        match frame.body {
            Some(ssh_frame::Body::Close(_)) => return exit::OK,
            body => {
                if dispatch(tx, body, w, r).is_err() {
                    return exit::OK;
                }
            }
        }
    }
}

fn handshake(r: &mut impl Read, w: &mut impl Write) -> bool {
    let frame: SshFrame = match read_frame(r) {
        Ok(f) => f,
        Err(_) => return false,
    };
    let Some(ssh_frame::Body::Hello(hello)) = frame.body else {
        let _ = send_error(
            w,
            ErrorCode::ERROR_CODE_INVALID_REQUEST,
            "first frame must be Hello",
        );
        return false;
    };
    let proto = hello.proto.as_ref().map_or(0, buffa::EnumValue::to_i32);
    if proto != ProtocolVersion::PROTOCOL_VERSION_1 as i32 {
        let _ = send_error(
            w,
            ErrorCode::ERROR_CODE_INVALID_REQUEST,
            &format!("unsupported proto_version {proto}"),
        );
        return false;
    }
    let resp = SshFrame {
        body: Some(ssh_frame::Body::HelloResponse(Box::new(HelloResponse {
            proto: Some(ProtocolVersion::PROTOCOL_VERSION_1.into()),
            server_id: Some(format!("mkit serve/{CLI_VERSION}")),
            ..Default::default()
        }))),
        ..Default::default()
    };
    write_frame(w, &resp).is_ok()
}

#[allow(clippy::too_many_lines)]
fn dispatch(
    tx: &FileTransport,
    body: Option<ssh_frame::Body>,
    w: &mut impl Write,
    r: &mut impl Read,
) -> std::io::Result<()> {
    match body {
        Some(ssh_frame::Body::PackExists(req)) => {
            let key = pack_key_from_bytes(req.pack_id.as_ref())?;
            let exists = tx.pack_exists(&key).unwrap_or(false);
            send(
                w,
                ssh_frame::Body::PackExistsResponse(Box::new(PackExistsResponse {
                    exists: Some(exists),
                    ..Default::default()
                })),
            )
        }
        Some(ssh_frame::Body::DownloadPack(req)) => {
            let key = pack_key_from_bytes(req.pack_id.as_ref())?;
            match tx.download_pack(&key) {
                Ok(bytes) => {
                    send(
                        w,
                        ssh_frame::Body::DownloadPackHeader(Box::new(DownloadPackHeader {
                            total_bytes: Some(bytes.len() as u64),
                            ..Default::default()
                        })),
                    )?;
                    let mut iter_pos = 0usize;
                    let mut offset = 0u64;
                    let total = bytes.len();
                    if total == 0 {
                        send(
                            w,
                            ssh_frame::Body::PackChunk(Box::new(PackChunk {
                                pack_id: req.pack_id.clone(),
                                offset: Some(0),
                                data: Some(Vec::new()),
                                last: Some(true),
                                ..Default::default()
                            })),
                        )?;
                    } else {
                        while iter_pos < total {
                            let end = core::cmp::min(iter_pos + PACK_CHUNK_DATA_MAX, total);
                            send(
                                w,
                                ssh_frame::Body::PackChunk(Box::new(PackChunk {
                                    pack_id: req.pack_id.clone(),
                                    offset: Some(offset),
                                    data: Some(bytes[iter_pos..end].to_vec()),
                                    last: Some(end == total),
                                    ..Default::default()
                                })),
                            )?;
                            offset += (end - iter_pos) as u64;
                            iter_pos = end;
                        }
                    }
                    Ok(())
                }
                Err(_) => emit_error(w, ErrorCode::ERROR_CODE_KEY_NOT_FOUND, "pack not found"),
            }
        }
        Some(ssh_frame::Body::UploadPack(header)) => {
            // Drain pack chunks until we see last=true.
            #[allow(clippy::cast_possible_truncation)]
            let total_bytes = header.total_bytes.unwrap_or(0) as usize;
            let mut accum = Vec::with_capacity(total_bytes);
            loop {
                let frame: SshFrame = match read_frame(r) {
                    Ok(f) => f,
                    Err(_) => {
                        return emit_error(
                            w,
                            ErrorCode::ERROR_CODE_INVALID_REQUEST,
                            "pack chunk read failed",
                        );
                    }
                };
                let Some(ssh_frame::Body::PackChunk(chunk)) = frame.body else {
                    return emit_error(
                        w,
                        ErrorCode::ERROR_CODE_INVALID_REQUEST,
                        "expected PackChunk after UploadPack",
                    );
                };
                if let Some(data) = chunk.data {
                    accum.extend_from_slice(&data);
                }
                if chunk.last.unwrap_or(false) {
                    break;
                }
            }
            let key = pack_key_from_bytes(header.pack_id.as_ref())?;
            match tx.upload_pack(&accum, &key) {
                Ok(()) => send(
                    w,
                    ssh_frame::Body::UploadPackResponse(Box::new(UploadPackResponse {
                        ..Default::default()
                    })),
                ),
                Err(_) => emit_error(w, ErrorCode::ERROR_CODE_INTERNAL, "upload failed"),
            }
        }
        Some(ssh_frame::Body::ReadRef(req)) => {
            let name = req.name.unwrap_or_default();
            match tx.read_ref(&name) {
                Ok(Some(h)) => send(
                    w,
                    ssh_frame::Body::ReadRefResponse(Box::new(ReadRefResponse {
                        object_id: Some(h.to_vec()),
                        ..Default::default()
                    })),
                ),
                Ok(None) => send(
                    w,
                    ssh_frame::Body::ReadRefResponse(Box::new(ReadRefResponse {
                        object_id: Some(Vec::new()),
                        ..Default::default()
                    })),
                ),
                Err(_) => emit_error(w, ErrorCode::ERROR_CODE_INTERNAL, "read ref failed"),
            }
        }
        Some(ssh_frame::Body::UpdateRef(req)) => {
            let name = req.name.unwrap_or_default();
            let new_id = req.new_id.unwrap_or_default();
            if new_id.len() != 32 {
                return emit_error(
                    w,
                    ErrorCode::ERROR_CODE_INVALID_REQUEST,
                    "new_id must be 32 bytes",
                );
            }
            let mut new_h = [0u8; 32];
            new_h.copy_from_slice(&new_id);
            // CAS condition derivation from expected_id length:
            // empty → Any (caller MUST send Match expected for CAS).
            let condition = match req.expected_id.as_deref() {
                None | Some(&[]) => RefWriteCondition::Any,
                Some(b) if b.len() == 32 => {
                    let mut e = [0u8; 32];
                    e.copy_from_slice(b);
                    RefWriteCondition::Match(e)
                }
                Some(_) => {
                    return emit_error(
                        w,
                        ErrorCode::ERROR_CODE_INVALID_REQUEST,
                        "expected_id must be empty or 32 bytes",
                    );
                }
            };
            match tx.update_ref(&name, condition, &new_h) {
                Ok(()) => send(w, ssh_frame::Body::UpdateRefResponse(Box::default())),
                Err(_) => emit_error(
                    w,
                    ErrorCode::ERROR_CODE_INVALID_REQUEST,
                    "update ref failed",
                ),
            }
        }
        Some(ssh_frame::Body::ListRefs(req)) => {
            let prefix = req.prefix.unwrap_or_default();
            match tx.list_refs(&prefix) {
                Ok(refs) => {
                    let entries: Vec<RefEntry> = refs
                        .into_iter()
                        .map(|r| RefEntry {
                            name: Some(r.name),
                            object_id: r.hash.map(|h| h.to_vec()),
                            ..Default::default()
                        })
                        .collect();
                    send(
                        w,
                        ssh_frame::Body::ListRefsResponse(Box::new(ListRefsResponse {
                            refs: entries,
                            ..Default::default()
                        })),
                    )
                }
                Err(_) => emit_error(w, ErrorCode::ERROR_CODE_INTERNAL, "list refs failed"),
            }
        }
        Some(ssh_frame::Body::PackChunk(_)) => emit_error(
            w,
            ErrorCode::ERROR_CODE_INVALID_REQUEST,
            "PackChunk arrived without UploadPack header",
        ),
        Some(ssh_frame::Body::Hello(_)) => emit_error(
            w,
            ErrorCode::ERROR_CODE_INVALID_REQUEST,
            "Hello after handshake",
        ),
        Some(_) => emit_error(
            w,
            ErrorCode::ERROR_CODE_INVALID_REQUEST,
            "unexpected request frame",
        ),
        None => emit_error(w, ErrorCode::ERROR_CODE_INVALID_REQUEST, "empty frame"),
    }
}

fn send(w: &mut impl Write, body: ssh_frame::Body) -> std::io::Result<()> {
    let frame = SshFrame {
        body: Some(body),
        ..Default::default()
    };
    write_frame(w, &frame).map_err(|_| std::io::Error::other("frame write"))
}

fn emit_error(w: &mut impl Write, code: ErrorCode, message: &str) -> std::io::Result<()> {
    send(
        w,
        ssh_frame::Body::Error(Box::new(RpcError {
            code: Some(code.into()),
            message: Some(message.into()),
            details: Some(Vec::new()),
            ..Default::default()
        })),
    )
}

fn send_error(w: &mut impl Write, code: ErrorCode, message: &str) -> std::io::Result<()> {
    emit_error(w, code, message)
}

fn pack_key_from_bytes(bytes: Option<&Vec<u8>>) -> std::io::Result<PackKey> {
    let b = bytes.ok_or_else(|| std::io::Error::other("pack_id missing"))?;
    if b.len() != 32 {
        return Err(std::io::Error::other("pack_id must be 32 bytes"));
    }
    let mut h = [0u8; 32];
    h.copy_from_slice(b);
    Ok(PackKey(h))
}

/// Rough byte cost of a frame for the per-connection budget. Sums the
/// largest size-bearing fields without re-encoding.
fn frame_byte_estimate(f: &SshFrame) -> u64 {
    use ssh_frame::Body;
    match &f.body {
        Some(Body::PackChunk(c)) => c.data.as_ref().map_or(0, Vec::len) as u64,
        Some(Body::UploadPack(h)) => h.total_bytes.unwrap_or(0),
        Some(Body::DownloadPackHeader(h)) => h.total_bytes.unwrap_or(0),
        _ => 64, // small control frames; charge a baseline.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exit;
    use std::fs;

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

    // Note: containment via MKIT_SERVE_ROOT is enforced — tested via
    // an integration test in tests/ rather than here, since this
    // crate forbids `unsafe` (which `std::env::set_var` requires
    // since Rust 1.92).
}
