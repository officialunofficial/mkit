//! `mkit serve <path>` — speak the mkit-rpc SSH protocol on
//! stdin/stdout against a local repository.
//!
//! The backing repo is accessed via `FileTransport`. Frames are
//! length-prefixed protobuf [`SshFrame`] messages defined in
//! `rust/crates/mkit-rpc/proto/ssh.proto` (buffa is the Rust
//! runtime; the wire is protobuf 3 / edition 2023).

use std::io::{Read, Write};
use std::path::PathBuf;

use clap::Parser;
use mkit_core::hash::hash;
use mkit_core::protocol::{PackKey, RefWriteCondition, Transport};
use mkit_rpc::mkit::rpc::v1::ssh::{
    DownloadPackHeader, HelloResponse, ListRefsResponse, PackChunk, PackExistsResponse,
    ReadRefResponse, RefExpectation, SshFrame, UploadPack, UploadPackResponse,
    list_refs_response::RefEntry, ssh_frame,
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
    about = "Speak the mkit-rpc protocol on stdin/stdout (default) or on \
             an encrypted TCP socket (--listen-enc)."
)]
struct ServeOpts {
    /// Path to the repository to serve.
    path: String,
    /// Listen for incoming encrypted-stream connections on `addr`
    /// (e.g. `0.0.0.0:9418` or `127.0.0.1:7777`) instead of speaking
    /// the SSH-frame protocol on stdin/stdout. Requires the
    /// `enc-transport` cargo feature. See SPEC-TRANSPORT-ENC §6 item 4
    /// (issue #156).
    ///
    /// FAIL-CLOSED: the listener refuses to bind unless either
    /// `--enc-authorized-peers <PATH>` is supplied (an allowlist of
    /// client public keys) or `--unsafe-allow-any-enc-peer` is passed.
    /// Server identity is loaded from `--enc-server-key <PATH>` (a
    /// user-scoped raw 32-byte key file) so clients can pin
    /// `?pubkey=<…>` across restarts; with the unsafe flag and no key
    /// file an ephemeral per-process key is generated instead.
    #[arg(long = "listen-enc", value_name = "ADDR")]
    listen_enc: Option<String>,

    /// Path to an allowlist of authorized client public keys, one per
    /// line (64-hex or 43-char url-safe base64; `#` comments and blank
    /// lines ignored). A client whose static ed25519 key is not listed
    /// is rejected at the handshake and never receives any data.
    ///
    /// MUST be a CLI-supplied or user-scoped path — peer-authorization
    /// is NEVER read from repo-local `.mkit/config`.
    #[arg(long = "enc-authorized-peers", value_name = "PATH")]
    enc_authorized_peers: Option<String>,

    /// Path to the server's stable raw 32-byte ed25519 key file. When
    /// allowlisting, this is auto-created at a user-scoped default path
    /// if omitted so the advertised `?pubkey=` is stable across
    /// restarts. User-scoped/CLI-only; never repo-local.
    #[arg(long = "enc-server-key", value_name = "PATH")]
    enc_server_key: Option<String>,

    /// Dev/test escape hatch: accept ANY encrypted peer (fail-open).
    /// Prints a loud warning. Intended only for local development and
    /// the direct-listen e2e harness — NEVER for production.
    #[arg(long = "unsafe-allow-any-enc-peer", default_value_t = false)]
    unsafe_allow_any_enc_peer: bool,

    /// Post-handshake per-frame idle timeout, in seconds, for the
    /// encrypted listener (#216). After the handshake completes, a peer
    /// that does not send the next verb/upload frame within this window
    /// has its session dropped — preventing a slow-loris peer from
    /// pinning a worker + socket forever. `0` disables the timeout
    /// (NOT recommended). Default: 60s.
    #[arg(
        long = "enc-idle-timeout-secs",
        value_name = "SECS",
        default_value_t = 60
    )]
    enc_idle_timeout_secs: u64,

    /// Handshake completion deadline, in seconds, for the encrypted
    /// listener (#216). SPEC-TRANSPORT-ENC §6.2 recommends tightening to
    /// ≤5–10s on real networks; the default is deliberately generous.
    /// Default: 60s.
    #[arg(
        long = "enc-handshake-timeout-secs",
        value_name = "SECS",
        default_value_t = 60
    )]
    enc_handshake_timeout_secs: u64,
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
        Err(code) => return code,
    };

    let repo_root = match resolve_repo_path(&opts.path) {
        Ok(p) => p,
        Err(code) => return code,
    };

    if let Some(addr) = opts.listen_enc.as_deref() {
        return run_listen_enc(
            addr,
            repo_root,
            opts.enc_authorized_peers.as_deref(),
            opts.enc_server_key.as_deref(),
            opts.unsafe_allow_any_enc_peer,
            opts.enc_idle_timeout_secs,
            opts.enc_handshake_timeout_secs,
        );
    }

    let tx = FileTransport::new(&repo_root);
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut r = stdin.lock();
    let mut w = stdout.lock();

    serve_loop(&tx, &mut r, &mut w)
}

mod enc;
#[cfg(feature = "sparse-checkout")]
mod sparse;

// Submodule re-exports kept on the parent surface.
use enc::run_listen_enc;
// Re-exported so the parent module's test suite can drive the encrypted
// listener helpers directly.
#[cfg(all(test, feature = "enc-transport"))]
use enc::{load_authorized_peers, serve_enc_session};
#[cfg(feature = "sparse-checkout")]
#[allow(unused_imports)]
pub use sparse::{
    SparseServeError, build_sparse_response_from_store, build_sparse_response_from_tree,
};

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
// Transport-generic verb decoding (shared by the sync stdin/stdout server and
// the async encrypted listener).
//
// These helpers are pure: they decode a request frame into either a response
// `ssh_frame::Body` or a `(ErrorCode, message)` protocol error, with no I/O.
// Both dispatchers route every non-streaming verb through `handle_simple_verb`
// and share the download chunking / upload-CAS logic below, so the two servers
// cannot drift on length checks, the `RefExpectation` -> `RefWriteCondition`
// mapping, or the per-frame chunk cap.
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
/// applying the CAS rules shared by both servers. `expected_id` is only
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
/// protocol error to surface to the client.
type SimpleVerb = Result<ssh_frame::Body, VerbError>;

/// Handle every non-streaming verb (`PackExists`, `ReadRef`, `UpdateRef`,
/// `ListRefs`) against `tx`, returning the response body or a protocol
/// error. The streaming verbs (`DownloadPack`, `UploadPack`) are handled
/// by the transport-specific dispatchers because they require multiple
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
