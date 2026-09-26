//! `mkit serve <path>` — speak the mkit-rpc SSH protocol on
//! stdin/stdout against a local repository.
//!
//! The backing repo is accessed via `FileTransport`. Frames are
//! length-prefixed protobuf [`SshFrame`] messages defined in
//! `rust/crates/mkit-rpc/proto/mkit/rpc/v1/ssh/ssh.proto` (buffa is the Rust
//! runtime; the wire is protobuf 3 / edition 2023).

use std::io::{Read, Write};
use std::path::PathBuf;

use clap::Parser;
use mkit_core::hash::hash;
use mkit_core::protocol::{PackKey, RefWriteCondition, Transport, TransportError};
use mkit_rpc::mkit::common::v1::{RefEntry, RefExpectation};
use mkit_rpc::mkit::rpc::v1::ssh::{
    DownloadPackHeader, HelloResponse, ListRefsResponse, PackChunk, PackExistsResponse,
    ReadRefResponse, SshFrame, UploadPack, UploadPackResponse, ssh_frame,
};
use mkit_rpc::mkit::rpc::v1::{ErrorCode, ProtocolVersion};
use mkit_rpc::{FrameError, read_frame, write_frame};
use mkit_transport_file::FileTransport;

use crate::clap_shim;
use crate::cli::CLI_VERSION;
use crate::exit;

#[derive(Debug, Parser)]
#[command(
    name = "mkit serve",
    about = "Speak the mkit-rpc SSH-frame protocol on stdin/stdout (the \
             mkit+ssh:// forced-command server). The HTTP and mkit+enc:// \
             listeners are the separate `mkit-server` binary."
)]
struct ServeOpts {
    /// Path to the repository to serve.
    path: String,
}

/// The listener flags `mkit serve` used to take, removed when the HTTP
/// (`--http`) and encrypted (`--listen-enc`) listeners moved to the
/// `mkit-server` binary. Clap rejects them as unknown arguments;
/// [`run`] then adds a pointer to `mkit-server`.
const REMOVED_LISTENER_FLAGS: &[&str] = &[
    "--http",
    "--http-token",
    "--unsafe-allow-any-http-peer",
    "--listen-enc",
    "--enc-authorized-peers",
    "--enc-server-key",
    "--unsafe-allow-any-enc-peer",
    "--enc-idle-timeout-secs",
    "--enc-handshake-timeout-secs",
];

/// The first removed listener flag in `args` (as `--flag` or
/// `--flag=value`), stopping at a `--` separator.
fn removed_listener_flag(args: &[String]) -> Option<&'static str> {
    args.iter()
        .take_while(|a| a.as_str() != "--")
        .find_map(|a| {
            let name = a.split_once('=').map_or(a.as_str(), |(n, _)| n);
            REMOVED_LISTENER_FLAGS.iter().copied().find(|f| *f == name)
        })
}

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
    let opts = match clap_shim::parse::<ServeOpts>("mkit serve", args) {
        Ok(o) => o,
        Err(code) => {
            if let Some(flag) = removed_listener_flag(args) {
                eprintln!(
                    "hint: `mkit serve` no longer takes `{flag}`; it only speaks the ssh-frame \
                     protocol on stdin/stdout.\n\
                     \x20     The HTTP and mkit+enc:// listeners are the separate `mkit-server` \
                     binary:\n\
                     \x20       mkit-server serve --repo-root <PATH> --listen <ADDR>      \
                     (was: mkit serve <PATH> --http <ADDR>)\n\
                     \x20       mkit-server serve --repo-root <PATH> --listen-enc <ADDR>  \
                     (was: mkit serve <PATH> --listen-enc <ADDR>)\n\
                     \x20     See \"Migrating from `mkit serve --http` and `--listen-enc`\" in \
                     docs/CLI.md."
                );
            }
            return code;
        }
    };

    let repo_root = match resolve_repo_path(&opts.path) {
        Ok(p) => p,
        Err(code) => return code,
    };

    // Held for the whole lifetime of this `serve` process
    // (SPEC-CONCURRENCY §3.1, MKIT-11/#655): local
    // worktree-mutating commands and `gc` probe this same lock (see
    // `commands::warn_if_served`) to detect a live `serve` and warn.
    // SHARED, not exclusive — SPEC-TRANSPORT documents multiple
    // concurrent `serve` processes against one root (e.g. one per SSH
    // forced-command connection) as a supported deployment, so `serve`
    // instances must not exclude each other.
    let _serve_guard = match mkit_core::repo_lock::acquire_shared(
        &repo_root.join(".mkit"),
        crate::commands::SERVE_LOCK,
        mkit_core::repo_lock::DEFAULT_TIMEOUT,
    ) {
        Ok(g) => g,
        Err(e) => {
            eprintln!("mkit serve: serve lock: {e}");
            return exit::TEMPFAIL;
        }
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

    // Test-only fault injection for the mkit#703 SSH retry regression
    // test (`tests/ssh_retry_e2e.rs`): return immediately after a
    // successful `Hello`/`HelloResponse`, before answering any verb,
    // so the process exits and the child pipe closes — simulating a
    // mid-session connection drop that the client's `SshTransport`
    // retry/reconnect path (SPEC-TRANSPORT §7) must recover from. A
    // no-op — and never read — unless the hermetic harness explicitly
    // sets this env var; production `mkit serve` never sets it.
    if std::env::var_os("MKIT_SERVE_TEST_DIE_AFTER_HELLO").is_some() {
        return exit::OK;
    }

    let mut frame_count: u32 = 0;
    let mut byte_count: u64 = 0;

    loop {
        let frame: SshFrame = match read_frame(r) {
            Ok(f) => f,
            Err(FrameError::LengthTruncated) => return exit::OK,
            Err(_) => {
                let _ = emit_error(w, ErrorCode::InvalidRequest, "frame parse error");
                return exit::PROTOCOL_ERROR;
            }
        };

        frame_count = frame_count.saturating_add(1);
        if frame_count > MAX_FRAMES_PER_CONN {
            let _ = emit_error(
                w,
                ErrorCode::InvalidRequest,
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
            let _ = emit_error(
                w,
                ErrorCode::InvalidRequest,
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
        let _ = emit_error(w, ErrorCode::InvalidRequest, "first frame must be Hello");
        return false;
    };
    let proto = hello.proto.unwrap_or_default();
    if proto != ProtocolVersion::ProtocolVersion1 {
        let _ = emit_error(
            w,
            ErrorCode::InvalidRequest,
            &format!("unsupported proto_version {}", proto.to_i32()),
        );
        return false;
    }
    let resp = SshFrame {
        body: Some(ssh_frame::Body::HelloResponse(Box::new(HelloResponse {
            proto: Some(ProtocolVersion::ProtocolVersion1.into()),
            server_id: Some(format!("mkit serve/{CLI_VERSION}")),
            ..Default::default()
        }))),
        ..Default::default()
    };
    write_frame(w, &resp).is_ok()
}

fn dispatch(
    tx: &FileTransport,
    body: Option<ssh_frame::Body>,
    w: &mut impl Write,
    r: &mut impl Read,
) -> std::io::Result<()> {
    let Some(body) = body else {
        return emit_error(w, ErrorCode::InvalidRequest, "empty frame");
    };

    // Streaming and protocol-control verbs are handled here because they
    // span multiple frames; everything else routes through the shared
    // sans-IO `handle_simple_verb`.
    match &body {
        ssh_frame::Body::DownloadPack(req) => {
            let key = match pack_key_from_id(req.pack_id.as_ref()) {
                Ok(k) => k,
                Err((code, msg)) => return emit_error(w, code, msg),
            };
            match tx.download_pack(&key) {
                Ok(bytes) => {
                    send(
                        w,
                        ssh_frame::Body::DownloadPackHeader(Box::new(DownloadPackHeader {
                            total_bytes: Some(bytes.len() as u64),
                            ..Default::default()
                        })),
                    )?;
                    for chunk in download_chunks(req.pack_id.clone(), &bytes) {
                        send(w, ssh_frame::Body::PackChunk(Box::new(chunk)))?;
                    }
                    Ok(())
                }
                Err(_) => emit_error(w, ErrorCode::KeyNotFound, "pack not found"),
            }
        }
        ssh_frame::Body::UploadPack(header) => {
            let mut upload = match UploadDrain::new(header) {
                Ok(upload) => upload,
                Err(e) => return emit_error(w, ErrorCode::InvalidRequest, e.message()),
            };
            loop {
                let frame: SshFrame = match read_frame(r) {
                    Ok(f) => f,
                    Err(_) => {
                        return emit_error(w, ErrorCode::InvalidRequest, "pack chunk read failed");
                    }
                };
                let Some(ssh_frame::Body::PackChunk(chunk)) = frame.body else {
                    return emit_error(
                        w,
                        ErrorCode::InvalidRequest,
                        "expected PackChunk after UploadPack",
                    );
                };
                let complete = match upload.push_chunk(&chunk) {
                    Ok(complete) => complete,
                    Err(e) => return emit_error(w, ErrorCode::InvalidRequest, e.message()),
                };
                if complete {
                    break;
                }
            }
            let (bytes, key) = upload.into_parts();
            match tx.upload_pack(&bytes, &key) {
                Ok(()) => send(
                    w,
                    ssh_frame::Body::UploadPackResponse(Box::new(UploadPackResponse {
                        ..Default::default()
                    })),
                ),
                Err(_) => emit_error(w, ErrorCode::Internal, "upload failed"),
            }
        }
        ssh_frame::Body::PackChunk(_) => emit_error(
            w,
            ErrorCode::InvalidRequest,
            "PackChunk arrived without UploadPack header",
        ),
        ssh_frame::Body::Hello(_) => {
            emit_error(w, ErrorCode::InvalidRequest, "Hello after handshake")
        }
        other => match handle_simple_verb(tx, other) {
            Some(Ok(resp)) => send(w, resp),
            Some(Err((code, msg))) => emit_error(w, code, msg),
            None => emit_error(w, ErrorCode::InvalidRequest, "unexpected request frame"),
        },
    }
}

fn send(w: &mut impl Write, body: ssh_frame::Body) -> std::io::Result<()> {
    let frame = SshFrame {
        body: Some(body),
        ..Default::default()
    };
    write_frame(w, &frame).map_err(|_| std::io::Error::other("frame write"))
}

// ---------------------------------------------------------------------------
// Verb decoding.
//
// These helpers are pure: they decode a request frame into either a response
// `ssh_frame::Body` or a `(ErrorCode, message)` protocol error, with no I/O.
// The dispatcher routes every non-streaming verb through `handle_simple_verb`
// and uses the download chunking / upload-CAS logic below for the streaming
// ones.
// ---------------------------------------------------------------------------

/// A protocol-level rejection: an `ErrorCode` plus a static message. The
/// transport layer turns this into an `ssh_error_frame`.
type VerbError = (ErrorCode, &'static str);

/// Decode a 32-byte pack id into a [`PackKey`], rejecting wrong lengths.
fn pack_key_from_id(bytes: Option<&Vec<u8>>) -> Result<PackKey, VerbError> {
    let b = bytes.ok_or((ErrorCode::InvalidRequest, "pack_id missing"))?;
    if b.len() != 32 {
        return Err((ErrorCode::InvalidRequest, "pack_id must be 32 bytes"));
    }
    let mut h = [0u8; 32];
    h.copy_from_slice(b);
    Ok(PackKey(h))
}

/// Decode an `UpdateRef` request into `(name, new_hash, condition)`,
/// applying the CAS rules. `expected_id` is only
/// consulted for `MATCH` and MUST be a 32-byte digest. See
/// SPEC-TRANSPORT §4.2.1.
fn decode_update_ref(
    req: &mkit_rpc::mkit::rpc::v1::ssh::UpdateRef,
) -> Result<(String, [u8; 32], RefWriteCondition), VerbError> {
    let name = req.name.clone().unwrap_or_default();
    let new_id = req.new_id.clone().unwrap_or_default();
    if new_id.len() != 32 {
        return Err((ErrorCode::InvalidRequest, "new_id must be 32 bytes"));
    }
    let mut new_h = [0u8; 32];
    new_h.copy_from_slice(&new_id);
    let expectation = req
        .expectation
        .as_ref()
        .and_then(buffa::EnumValue::as_known)
        .unwrap_or(RefExpectation::Unspecified);
    let condition = match expectation {
        RefExpectation::Any => RefWriteCondition::Any,
        RefExpectation::Missing => RefWriteCondition::Missing,
        RefExpectation::Match => {
            let bytes = req.expected_id.as_deref().unwrap_or(&[]);
            if bytes.len() != 32 {
                return Err((
                    ErrorCode::InvalidRequest,
                    "MATCH expectation requires a 32-byte expected_id",
                ));
            }
            let mut e = [0u8; 32];
            e.copy_from_slice(bytes);
            RefWriteCondition::Match(e)
        }
        RefExpectation::Unspecified => {
            return Err((
                ErrorCode::InvalidRequest,
                "UpdateRef.expectation is required",
            ));
        }
    };
    Ok((name, new_h, condition))
}

/// Build the ordered list of `PackChunk` bodies for a download. An empty
/// pack still produces a single `last=true` chunk so the client always
/// sees a terminator.
#[allow(clippy::cast_possible_truncation)]
fn download_chunks(pack_id: Option<Vec<u8>>, bytes: &[u8]) -> Vec<PackChunk> {
    let total = bytes.len();
    if total == 0 {
        return vec![PackChunk {
            pack_id,
            offset: Some(0),
            data: Some(Vec::new()),
            last: Some(true),
            ..Default::default()
        }];
    }
    let mut chunks = Vec::new();
    let mut iter_pos = 0usize;
    let mut offset = 0u64;
    while iter_pos < total {
        let end = core::cmp::min(iter_pos + PACK_CHUNK_DATA_MAX, total);
        chunks.push(PackChunk {
            pack_id: pack_id.clone(),
            offset: Some(offset),
            data: Some(bytes[iter_pos..end].to_vec()),
            last: Some(end == total),
            ..Default::default()
        });
        offset += (end - iter_pos) as u64;
        iter_pos = end;
    }
    chunks
}

/// Build the `ListRefsResponse` ref-entry list from a transport's refs.
fn list_refs_entries(refs: Vec<mkit_core::refs::Ref>) -> Vec<RefEntry> {
    refs.into_iter()
        .map(|r| RefEntry {
            name: Some(r.name),
            object_id: r.hash.map(|h| h.to_vec()),
            ..Default::default()
        })
        .collect()
}

/// Outcome of a non-streaming verb: either a single response body or a
/// protocol error to surface to the client. The `Ok` body may itself be
/// an `Error` frame when the reply needs dynamic payload the static
/// `VerbError` shape cannot carry (the §4.2.1 CAS-conflict reply built
/// by [`cas_conflict_body`]); the dispatcher sends it like any response.
type SimpleVerb = Result<ssh_frame::Body, VerbError>;

/// Handle every non-streaming verb (`PackExists`, `ReadRef`, `UpdateRef`,
/// `ListRefs`) against `tx`, returning the response body or a protocol
/// error. The streaming verbs (`DownloadPack`, `UploadPack`) are handled
/// by [`dispatch`] because they require multiple
/// frames, but they reuse [`pack_key_from_id`], [`download_chunks`], and
/// [`UploadDrain`].
fn handle_simple_verb(tx: &FileTransport, body: &ssh_frame::Body) -> Option<SimpleVerb> {
    Some(match body {
        ssh_frame::Body::PackExists(req) => match pack_key_from_id(req.pack_id.as_ref()) {
            Ok(key) => {
                let exists = tx.pack_exists(&key).unwrap_or(false);
                Ok(ssh_frame::Body::PackExistsResponse(Box::new(
                    PackExistsResponse {
                        exists: Some(exists),
                        ..Default::default()
                    },
                )))
            }
            Err(e) => Err(e),
        },
        ssh_frame::Body::ReadRef(req) => {
            let name = req.name.clone().unwrap_or_default();
            match tx.read_ref(&name) {
                Ok(found) => Ok(ssh_frame::Body::ReadRefResponse(Box::new(
                    ReadRefResponse {
                        object_id: Some(found.map(|h| h.to_vec()).unwrap_or_default()),
                        ..Default::default()
                    },
                ))),
                Err(_) => Err((ErrorCode::Internal, "read ref failed")),
            }
        }
        ssh_frame::Body::UpdateRef(req) => {
            let (name, new_h, condition) = match decode_update_ref(req) {
                Ok(v) => v,
                Err(e) => return Some(Err(e)),
            };
            match tx.update_ref(&name, condition, &new_h) {
                Ok(()) => Ok(ssh_frame::Body::UpdateRefResponse(Box::default())),
                // SPEC-TRANSPORT §4.2.1: a CAS mismatch is answered with
                // `Error{INVALID_REQUEST}` carrying the CURRENT ref value
                // in `details`, which clients classify as `RefConflict`.
                // Built here (as an Ok response body) rather than through
                // the static `VerbError` path because it carries dynamic
                // `details` bytes.
                Err(TransportError::RefConflict) => Ok(cas_conflict_body(tx, &name)),
                Err(_) => Err((ErrorCode::InvalidRequest, "update ref failed")),
            }
        }
        ssh_frame::Body::ListRefs(req) => {
            let prefix = req.prefix.clone().unwrap_or_default();
            match tx.list_refs(&prefix) {
                Ok(refs) => Ok(ssh_frame::Body::ListRefsResponse(Box::new(
                    ListRefsResponse {
                        refs: list_refs_entries(refs),
                        ..Default::default()
                    },
                ))),
                Err(_) => Err((ErrorCode::Internal, "list refs failed")),
            }
        }
        // Streaming and protocol-control frames are handled by the caller.
        _ => return None,
    })
}

/// Build the SPEC-TRANSPORT §4.2.1 CAS-mismatch reply for `update_ref`:
/// `Error { code = ERROR_CODE_INVALID_REQUEST }` with the current ref
/// value (the raw 32-byte digest) in `Error.details`.
///
/// `FileTransport::update_ref` reports a conflict without the winning
/// value, so we read the ref back here. The read happens outside the
/// CAS critical section, which is fine: any value it observes was the
/// ref's current value at some point after the failed CAS, exactly
/// what the loser needs to recover.
///
/// Ref-absent case: when the read finds no ref (a `MATCH` expectation
/// against a ref that never existed, or the ref vanished between the
/// failed CAS and this read) there is no current value to surface.
/// `details` stays empty — mirroring `ReadRefResponse`'s
/// empty-means-absent encoding — and strict clients (which require
/// non-empty `details` to classify `RefConflict`) surface the
/// descriptive message as a remote error instead of fabricating a
/// current id.
fn cas_conflict_body(tx: &FileTransport, name: &str) -> ssh_frame::Body {
    let current = tx.read_ref(name).ok().flatten();
    let (details, message) = match current {
        Some(h) => (
            h.to_vec(),
            "ref update conflict: expectation does not match current ref value",
        ),
        None => (
            Vec::new(),
            "ref update conflict: expectation not met and ref is currently absent",
        ),
    };
    ssh_frame::Body::Error(Box::new(
        mkit_rpc::mkit::rpc::v1::Error::default()
            .with_code(ErrorCode::InvalidRequest)
            .with_message(message)
            .with_details(details),
    ))
}

struct UploadDrain {
    key: PackKey,
    expected_total: u64,
    next_offset: u64,
    chunks: u32,
    bytes: Vec<u8>,
}

#[derive(Debug, Clone, Copy)]
struct UploadDrainError(&'static str);

impl UploadDrainError {
    fn message(self) -> &'static str {
        self.0
    }
}

impl UploadDrain {
    fn new(header: &UploadPack) -> Result<Self, UploadDrainError> {
        let key = pack_key_from_upload(header.pack_id.as_deref())?;
        let expected_total = header
            .total_bytes
            .ok_or(UploadDrainError("UploadPack.total_bytes is required"))?;
        if expected_total > MAX_BYTES_PER_CONN {
            return Err(UploadDrainError(
                "UploadPack.total_bytes exceeds server cap",
            ));
        }
        Ok(Self {
            key,
            expected_total,
            next_offset: 0,
            chunks: 0,
            bytes: Vec::new(),
        })
    }

    fn push_chunk(&mut self, chunk: &PackChunk) -> Result<bool, UploadDrainError> {
        self.chunks = self.chunks.saturating_add(1);
        if self.chunks > MAX_FRAMES_PER_CONN {
            return Err(UploadDrainError(
                "too many PackChunk frames before last=true",
            ));
        }

        let chunk_key = pack_key_from_upload(chunk.pack_id.as_deref())?;
        if chunk_key.as_bytes() != self.key.as_bytes() {
            return Err(UploadDrainError(
                "PackChunk.pack_id does not match UploadPack",
            ));
        }

        let offset = chunk
            .offset
            .ok_or(UploadDrainError("PackChunk.offset is required"))?;
        if offset != self.next_offset {
            return Err(UploadDrainError(
                "PackChunk.offset is not the expected next offset",
            ));
        }

        let data = chunk.data.as_deref().unwrap_or(&[]);
        let data_len = u64::try_from(data.len())
            .map_err(|_| UploadDrainError("PackChunk.data length overflows u64"))?;
        let new_total = self
            .next_offset
            .checked_add(data_len)
            .ok_or(UploadDrainError("PackChunk byte count overflow"))?;
        if new_total > self.expected_total {
            return Err(UploadDrainError(
                "PackChunk data exceeds declared total_bytes",
            ));
        }

        self.bytes.extend_from_slice(data);
        self.next_offset = new_total;

        if !chunk.last.unwrap_or(false) {
            return Ok(false);
        }
        if self.next_offset != self.expected_total {
            return Err(UploadDrainError(
                "PackChunk stream ended before declared total_bytes",
            ));
        }
        if hash(&self.bytes) != *self.key.as_bytes() {
            return Err(UploadDrainError(
                "uploaded pack bytes do not match UploadPack.pack_id",
            ));
        }
        Ok(true)
    }

    fn into_parts(self) -> (Vec<u8>, PackKey) {
        (self.bytes, self.key)
    }
}

// Bypasses `send` because `ssh_error_frame` already returns a full
// `SshFrame`; passing it through `send` would just wrap-and-unwrap.
fn emit_error(w: &mut impl Write, code: ErrorCode, message: &str) -> std::io::Result<()> {
    write_frame(w, &mkit_rpc::ssh_error_frame(code, message))
        .map_err(|_| std::io::Error::other("frame write"))
}

fn pack_key_from_upload(bytes: Option<&[u8]>) -> Result<PackKey, UploadDrainError> {
    let b = bytes.ok_or(UploadDrainError("pack_id missing"))?;
    if b.len() != 32 {
        return Err(UploadDrainError("pack_id must be 32 bytes"));
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
mod tests;
