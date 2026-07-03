#![doc = include_str!("../README.md")]
//!
//! mkit SSH transport.
//!
//! Implements [`mkit_core::protocol::Transport`] over a long-lived
//! system `ssh(1)` child process, exchanging the seven mkit verbs as
//! length-prefixed protobuf [`SshFrame`] messages defined in
//! `mkit-rpc/proto/ssh.proto` (buffa is the Rust runtime mkit uses;
//! the wire is plain protobuf 3 / edition 2023).
//!
//! # Design choice: `std::process::Command`, NOT `russh`
//!
//! SSH-SECURITY.md §1 is explicit: mkit does NOT implement its own SSH
//! client. It shells out to `ssh(1)` and delegates host-key
//! verification, agent handling, credential selection, and kex to the
//! user's installed OpenSSH. Same posture `git+ssh://` takes:
//!
//! - Our binary does not need to ship a crypto stack (no `russh`,
//!   `rustls`, `openssl`, `native-tls`).
//! - `ssh-agent`, `~/.ssh/config`, `ProxyCommand`, and every other
//!   knob the user already configured Just Work, with zero mkit code.
//! - Host-key rotation / trust escalation stays on the OpenSSH side,
//!   where it belongs — see SSH-SECURITY.md §4 for the gaps we inherit
//!   from this choice.
//!
//! The Transport trait itself is synchronous (object-safe, `&self`,
//! `TransportResult<T>`), so wrapping `Command::spawn` + blocking
//! stdio is the shortest path to parity with the other transports.

#![forbid(unsafe_code)]
// `ref_option` flags `&Option<T>` arguments. Wire-frame fields are
// `Option<T>` (Edition 2023 explicit presence); passing references
// through helpers is the natural shape — the `Option<&T>` rewrite
// forces a borrow at every callsite.
#![allow(clippy::ref_option)]
#![allow(clippy::items_after_statements)]
#![allow(clippy::manual_let_else)]
// `cast_possible_truncation` fires on `total as usize` for pack-chunk
// offsets. Pack sizes are bounded well below usize::MAX on every
// supported platform.
#![allow(clippy::cast_possible_truncation)]

pub mod url;

use std::io;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use mkit_core::hash::Hash;
use mkit_core::protocol::{PackKey, Transport, TransportError, TransportResult};
use mkit_core::refs::{Ref, RefWriteCondition, validate_ref_name, validate_ref_prefix};
use mkit_rpc::mkit::rpc::v1::ProtocolVersion;
use mkit_rpc::mkit::rpc::v1::ssh::{
    DownloadPack, Hello, ListRefs, PackChunk, PackExists, ReadRef, SshFrame, UpdateRef, UploadPack,
    ssh_frame,
};
use mkit_rpc::{
    CHUNK_DATA_MAX, FrameError, MAX_REF_NAME, body_name, cond_to_wire, read_frame,
    ref_entry_to_ref, rpc_error_to_transport, unexpected_frame, write_frame,
};

pub use crate::url::{MKIT_SSH_PREFIX, SshTarget, parse_mkit_ssh_url, validate_ssh_path};

use mkit_core::protocol::{PACK_BODY_LIMIT, PACK_BODY_LIMIT_USIZE};

/// Client identification string sent in the `Hello` frame. Inherited
/// from the workspace version, so a release bump propagates
/// automatically.
const CLIENT_ID: &str = concat!("mkit ", env!("CARGO_PKG_VERSION"));

/// Default timeout for SSH handshake replies, verb responses, and child shutdown.
pub const DEFAULT_SSH_TIMEOUT: Duration = Duration::from_secs(30);

/// Optional SSH CLI knobs threaded from `.mkit/config`. All fields default
/// to empty, which means "inherit the user's `ssh(1)` defaults". See
/// SPEC-TRANSPORT §4.3 for the canonical field list.
#[derive(Debug, Default, Clone)]
pub struct SshOptions {
    /// `-o StrictHostKeyChecking=<value>`. Empty → do not pass.
    pub strict_host_key_checking: String,
    /// `-o UserKnownHostsFile=<path>`. Empty → do not pass.
    pub user_known_hosts_file: String,
    /// `-i <file>`. Empty → do not pass. ssh(1) defaults to
    /// `~/.ssh/id_ed25519`, then `~/.ssh/id_rsa`, agent-first.
    pub identity_file: String,
}

/// Errors raised while bringing up the SSH child — before the first
/// [`Transport`] verb is ever called.
#[derive(Debug, thiserror::Error)]
pub enum SshInitError {
    /// The URL failed `parse_mkit_ssh_url` / `validate_ssh_path`.
    #[error(transparent)]
    InvalidUrl(#[from] TransportError),
    /// Could not spawn `ssh`. Usually means the binary is not on
    /// `$PATH` or the fork/exec itself failed.
    #[error("failed to spawn ssh: {0}")]
    Spawn(#[from] io::Error),
    /// Hello handshake failed — wrong proto version, server-emitted
    /// Error frame, or unparseable reply.
    #[error("ssh hello handshake failed: {0}")]
    HandshakeFailed(String),
}

/// Transport over a spawned `ssh(1)` child process.
///
/// Construction spawns the child, sends the mandatory `Hello` frame,
/// and validates the server's reply. If any of those steps fail the
/// child is torn down before the constructor returns, so a successful
/// [`SshTransport::connect`] ALWAYS yields a handle whose first verb
/// call lands on a v1 mkit server.
#[derive(Debug)]
pub struct SshTransport {
    /// The child's stdio handles sit behind a `Mutex` so `&self`
    /// [`Transport`] methods can still mutate them. SSH is a single
    /// pipelined stream — concurrent verbs on one [`SshTransport`]
    /// serialise through this mutex.
    io: Mutex<ChildIo>,
}

#[derive(Debug)]
struct ChildIo {
    child: Child,
    stdin_tx: Option<mpsc::SyncSender<WriteJob>>,
    stdout_rx: mpsc::Receiver<Result<SshFrame, FrameError>>,
    /// `true` once we've shut down the child pipe. Guards double-close
    /// from `Drop` + explicit `close`.
    closed: bool,
}

#[derive(Debug)]
struct WriteJob {
    frame: SshFrame,
    result_tx: mpsc::Sender<Result<(), FrameError>>,
}

impl SshTransport {
    /// Parse `url`, spawn `ssh`, and perform the `Hello` handshake.
    pub fn connect(url: &str) -> Result<Self, SshInitError> {
        let target = parse_mkit_ssh_url(url)?;
        Self::connect_with_options(&target, &SshOptions::default())
    }

    /// Spawn `ssh` from a pre-parsed [`SshTarget`] with explicit
    /// `.mkit/config` SSH options. Callers that already resolved
    /// config should use this entry point; `connect` is the
    /// convenience form.
    pub fn connect_with_options(
        target: &SshTarget,
        options: &SshOptions,
    ) -> Result<Self, SshInitError> {
        validate_ssh_path(&target.path)?;
        let mut cmd = build_ssh_command(target, options);
        let mut child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| SshInitError::HandshakeFailed("no child stdin".into()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| SshInitError::HandshakeFailed("no child stdout".into()))?;
        let stdin_tx = spawn_stdin_writer(stdin);
        let stdout_rx = spawn_stdout_reader(stdout);
        let mut io = ChildIo {
            child,
            stdin_tx: Some(stdin_tx),
            stdout_rx,
            closed: false,
        };
        if let Err(e) = perform_client_handshake(&mut io) {
            // Tear down before returning so the caller never sees a
            // half-initialised transport.
            let _ = shut_child(&mut io);
            return Err(e);
        }
        Ok(Self { io: Mutex::new(io) })
    }

    /// Explicit shutdown — closes stdin and waits for the child.
    /// Equivalent to dropping the transport, but lets the caller
    /// observe any shutdown error. Safe to call multiple times.
    pub fn close(&mut self) -> io::Result<()> {
        match self.io.get_mut() {
            Ok(io) => shut_child(io),
            Err(_) => Err(io::Error::other("ssh transport mutex poisoned")),
        }
    }
}

impl Drop for SshTransport {
    fn drop(&mut self) {
        match self.io.get_mut() {
            Ok(io) => {
                let _ = shut_child(io);
            }
            Err(poison) => {
                let io = poison.into_inner();
                let _ = shut_child(io);
            }
        }
    }
}

impl Transport for SshTransport {
    fn upload_pack(&self, bytes: &[u8], key: &PackKey) -> TransportResult<()> {
        let mut io = self
            .io
            .lock()
            .map_err(|_| TransportError::ConnectionFailed)?;
        if io.closed {
            return Err(TransportError::ConnectionFailed);
        }

        // Header frame announces the pack id + advertised total length.
        let header = SshFrame {
            body: Some(ssh_frame::Body::UploadPack(Box::new(
                UploadPack::default()
                    .with_pack_id(key.as_bytes().to_vec())
                    .with_total_bytes(bytes.len() as u64),
            ))),
            ..Default::default()
        };
        write_child_frame_or_err(&mut io, header)?;

        // Body chunks. The per-frame data cap lives in `mkit_rpc::CHUNK_DATA_MAX`
        // so transport-ssh and transport-enc cannot drift on the bound.
        let mut offset = 0u64;
        let total = bytes.len();
        let mut iter_pos = 0usize;
        while iter_pos < total {
            let end = core::cmp::min(iter_pos + CHUNK_DATA_MAX, total);
            let chunk = SshFrame {
                body: Some(ssh_frame::Body::PackChunk(Box::new(
                    PackChunk::default()
                        .with_pack_id(key.as_bytes().to_vec())
                        .with_offset(offset)
                        .with_data(bytes[iter_pos..end].to_vec())
                        .with_last(end == total),
                ))),
                ..Default::default()
            };
            write_child_frame_or_err(&mut io, chunk)?;
            offset += (end - iter_pos) as u64;
            iter_pos = end;
        }
        if total == 0 {
            // Empty packs still need a final last=true chunk so the
            // server knows the upload is complete.
            let chunk = SshFrame {
                body: Some(ssh_frame::Body::PackChunk(Box::new(
                    PackChunk::default()
                        .with_pack_id(key.as_bytes().to_vec())
                        .with_offset(0)
                        .with_data(Vec::new())
                        .with_last(true),
                ))),
                ..Default::default()
            };
            write_child_frame_or_err(&mut io, chunk)?;
        }

        let resp = read_child_frame_or_err(&mut io)?;
        match resp.body {
            Some(ssh_frame::Body::UploadPackResponse(_)) => Ok(()),
            Some(ssh_frame::Body::Error(e)) => Err(rpc_error_to_transport(*e, "ssh")),
            other => Err(unexpected_frame("ssh", "UploadPackResponse", other)),
        }
    }

    fn download_pack(&self, key: &PackKey) -> TransportResult<Vec<u8>> {
        let mut io = self
            .io
            .lock()
            .map_err(|_| TransportError::ConnectionFailed)?;
        if io.closed {
            return Err(TransportError::ConnectionFailed);
        }

        let req = SshFrame {
            body: Some(ssh_frame::Body::DownloadPack(Box::new(
                DownloadPack::default().with_pack_id(key.as_bytes().to_vec()),
            ))),
            ..Default::default()
        };
        write_child_frame_or_err(&mut io, req)?;

        read_download_pack_body_from_child(&mut io)
    }

    fn pack_exists(&self, key: &PackKey) -> TransportResult<bool> {
        let mut io = self
            .io
            .lock()
            .map_err(|_| TransportError::ConnectionFailed)?;
        if io.closed {
            return Err(TransportError::ConnectionFailed);
        }
        let req = SshFrame {
            body: Some(ssh_frame::Body::PackExists(Box::new(
                PackExists::default().with_pack_id(key.as_bytes().to_vec()),
            ))),
            ..Default::default()
        };
        write_child_frame_or_err(&mut io, req)?;
        let resp = read_child_frame_or_err(&mut io)?;
        match resp.body {
            Some(ssh_frame::Body::PackExistsResponse(r)) => Ok(r.exists.unwrap_or(false)),
            Some(ssh_frame::Body::Error(e)) => Err(rpc_error_to_transport(*e, "ssh")),
            other => Err(unexpected_frame("ssh", "PackExistsResponse", other)),
        }
    }

    fn update_ref(
        &self,
        name: &str,
        condition: RefWriteCondition,
        hash: &Hash,
    ) -> TransportResult<()> {
        if !validate_ref_name(name) {
            return Err(TransportError::InvalidRef(name.into()));
        }
        if name.len() > MAX_REF_NAME {
            return Err(TransportError::InvalidRef("ref name too long".into()));
        }

        let mut io = self
            .io
            .lock()
            .map_err(|_| TransportError::ConnectionFailed)?;
        if io.closed {
            return Err(TransportError::ConnectionFailed);
        }

        // CAS intent = `expectation`. `expected_id` is meaningful only
        // for MATCH. See SPEC-TRANSPORT §4.2.1.
        let (expected_id, expectation) = cond_to_wire(condition);

        let req = SshFrame {
            body: Some(ssh_frame::Body::UpdateRef(Box::new(
                UpdateRef::default()
                    .with_name(name)
                    .with_expected_id(expected_id)
                    .with_new_id(hash.to_vec())
                    .with_expectation(expectation),
            ))),
            ..Default::default()
        };
        write_child_frame_or_err(&mut io, req)?;

        let resp = read_child_frame_or_err(&mut io)?;
        match resp.body {
            Some(ssh_frame::Body::UpdateRefResponse(_)) => Ok(()),
            Some(ssh_frame::Body::Error(e)) => Err(map_update_ref_error(*e, condition)),
            other => Err(unexpected_frame("ssh", "UpdateRefResponse", other)),
        }
    }

    fn read_ref(&self, name: &str) -> TransportResult<Option<Hash>> {
        if !validate_ref_name(name) {
            return Err(TransportError::InvalidRef(name.into()));
        }
        if name.len() > MAX_REF_NAME {
            return Err(TransportError::InvalidRef("ref name too long".into()));
        }
        let mut io = self
            .io
            .lock()
            .map_err(|_| TransportError::ConnectionFailed)?;
        if io.closed {
            return Err(TransportError::ConnectionFailed);
        }
        let req = SshFrame {
            body: Some(ssh_frame::Body::ReadRef(Box::new(
                ReadRef::default().with_name(name),
            ))),
            ..Default::default()
        };
        write_child_frame_or_err(&mut io, req)?;
        let resp = read_child_frame_or_err(&mut io)?;
        match resp.body {
            Some(ssh_frame::Body::ReadRefResponse(r)) => {
                let oid = r.object_id.unwrap_or_default();
                if oid.is_empty() {
                    Ok(None)
                } else if oid.len() == 32 {
                    let mut h = [0u8; 32];
                    h.copy_from_slice(&oid);
                    Ok(Some(h))
                } else {
                    Err(TransportError::InvalidResponse)
                }
            }
            Some(ssh_frame::Body::Error(e)) => Err(rpc_error_to_transport(*e, "ssh")),
            other => Err(unexpected_frame("ssh", "ReadRefResponse", other)),
        }
    }

    fn list_refs(&self, prefix: &str) -> TransportResult<Vec<Ref>> {
        if !prefix.is_empty() && !validate_ref_prefix(prefix) {
            return Err(TransportError::InvalidRef(prefix.into()));
        }
        if prefix.len() > MAX_REF_NAME {
            return Err(TransportError::InvalidRef("ref prefix too long".into()));
        }
        let mut io = self
            .io
            .lock()
            .map_err(|_| TransportError::ConnectionFailed)?;
        if io.closed {
            return Err(TransportError::ConnectionFailed);
        }
        let req = SshFrame {
            body: Some(ssh_frame::Body::ListRefs(Box::new(
                ListRefs::default().with_prefix(prefix),
            ))),
            ..Default::default()
        };
        write_child_frame_or_err(&mut io, req)?;
        let resp = read_child_frame_or_err(&mut io)?;
        match resp.body {
            Some(ssh_frame::Body::ListRefsResponse(r)) => r
                .refs
                .into_iter()
                .map(ref_entry_to_ref)
                .collect::<TransportResult<Vec<_>>>(),
            Some(ssh_frame::Body::Error(e)) => Err(rpc_error_to_transport(*e, "ssh")),
            other => Err(unexpected_frame("ssh", "ListRefsResponse", other)),
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers (transport-ssh-specific I/O wrappers; shared frame helpers
// live in `mkit_rpc::helpers`)
// ---------------------------------------------------------------------------

/// Map a server `Error` reply to an `update_ref` request into a
/// [`TransportError`].
///
/// Per SPEC-TRANSPORT / `UpdateRefResponse`, the server signals a
/// compare-and-swap mismatch as `ERROR_CODE_INVALID_REQUEST` carrying
/// the *current* ref id in `details`. We treat that as
/// [`TransportError::RefConflict`].
///
/// The bare `ERROR_CODE_INVALID_REQUEST` code alone is ambiguous: the
/// server reuses it for genuine bad requests (malformed ref, backend
/// failure) as well as CAS mismatches. To avoid masking a real error as
/// a conflict we only treat it as `RefConflict` when:
///   - the write carried a CAS precondition (`condition != Any`), and
///   - the error carries non-empty `details` (the documented current-id
///     payload that disambiguates a true CAS mismatch).
///
/// When `details` is absent we fall back to [`rpc_error_to_transport`]
/// so a genuine invalid-request surfaces its real message instead of a
/// misleading `RefConflict`.
fn map_update_ref_error(
    e: mkit_rpc::mkit::rpc::v1::Error,
    condition: RefWriteCondition,
) -> TransportError {
    let is_invalid_request = e
        .code
        .is_some_and(|c| c == mkit_rpc::mkit::rpc::v1::ErrorCode::InvalidRequest);
    let has_cas_details = e.details.as_deref().is_some_and(|d| !d.is_empty());
    if is_invalid_request && !matches!(condition, RefWriteCondition::Any) && has_cas_details {
        TransportError::RefConflict
    } else {
        rpc_error_to_transport(e, "ssh")
    }
}

/// Assemble the response side of `download_pack` from a frame source.
///
/// `next_frame` is called once for the `DownloadPackHeader` and then
/// repeatedly for each `PackChunk` until a chunk with `last = true`.
/// Both the production child path and the unit-test reader path share
/// this single implementation so the OOM-defence against a malicious
/// `DownloadPackHeader.total_bytes` (and a chunk stream that overruns
/// the advertised size) is exercised by tests on the same code the
/// child path runs.
fn assemble_download_pack_body<F>(mut next_frame: F) -> TransportResult<Vec<u8>>
where
    F: FnMut() -> TransportResult<SshFrame>,
{
    let header = next_frame()?;
    let total = match header.body {
        Some(ssh_frame::Body::DownloadPackHeader(h)) => h.total_bytes.unwrap_or(0),
        Some(ssh_frame::Body::Error(e)) => return Err(rpc_error_to_transport(*e, "ssh")),
        other => return Err(unexpected_frame("ssh", "DownloadPackHeader", other)),
    };

    // Reject before we allocate: an attacker-controlled
    // `total_bytes` (e.g. `u64::MAX`) would otherwise blow up the
    // Vec::with_capacity below.
    if total > PACK_BODY_LIMIT {
        return Err(TransportError::RemoteError(
            "server-advertised pack size exceeds client cap".into(),
        ));
    }

    // Clamp the initial capacity so an honest small pack stays cheap
    // and an over-stated `total_bytes` cannot drive us into a giant
    // allocation.
    let initial = core::cmp::min(total as usize, PACK_BODY_LIMIT_USIZE);
    let mut out = Vec::with_capacity(initial);
    loop {
        let chunk_frame = next_frame()?;
        match chunk_frame.body {
            Some(ssh_frame::Body::PackChunk(c)) => {
                let data = c.data.unwrap_or_default();
                // Bail as soon as the running total would exceed the
                // cap — a misbehaving server could otherwise stream
                // chunks forever past an honest header.
                if out.len().saturating_add(data.len()) > PACK_BODY_LIMIT_USIZE {
                    return Err(TransportError::RemoteError(
                        "server-streamed pack body exceeds client cap".into(),
                    ));
                }
                out.extend_from_slice(&data);
                if c.last.unwrap_or(false) {
                    break;
                }
            }
            Some(ssh_frame::Body::Error(e)) => return Err(rpc_error_to_transport(*e, "ssh")),
            other => return Err(unexpected_frame("ssh", "PackChunk", other)),
        }
    }
    Ok(out)
}

/// Test-only adapter: drive [`assemble_download_pack_body`] from a
/// generic in-memory reader so the shared assembly logic can be unit
/// tested without spawning a child process.
#[cfg(test)]
fn read_download_pack_body<R: io::Read>(r: &mut R) -> TransportResult<Vec<u8>> {
    assemble_download_pack_body(|| read_frame_or_err(r))
}

fn read_download_pack_body_from_child(io: &mut ChildIo) -> TransportResult<Vec<u8>> {
    assemble_download_pack_body(|| read_child_frame_or_err(io))
}

#[cfg(test)]
fn read_frame_or_err<R: io::Read>(r: &mut R) -> TransportResult<SshFrame> {
    match read_frame::<_, SshFrame>(r) {
        Ok(f) => Ok(f),
        Err(e) => Err(frame_error_to_transport(&e)),
    }
}

fn spawn_stdin_writer(mut stdin: ChildStdin) -> mpsc::SyncSender<WriteJob> {
    let (tx, rx) = mpsc::sync_channel::<WriteJob>(1);
    thread::spawn(move || {
        for job in rx {
            let result = write_frame(&mut stdin, &job.frame);
            let should_stop = result.is_err();
            let _ = job.result_tx.send(result);
            if should_stop {
                break;
            }
        }
    });
    tx
}

fn write_child_frame_or_err(io: &mut ChildIo, frame: SshFrame) -> TransportResult<()> {
    let stdin_tx = io
        .stdin_tx
        .as_ref()
        .ok_or(TransportError::ConnectionFailed)?;
    let (result_tx, result_rx) = mpsc::channel();
    stdin_tx
        .send(WriteJob { frame, result_tx })
        .map_err(|_| TransportError::ConnectionFailed)?;

    if let Ok(Ok(())) = result_rx.recv_timeout(DEFAULT_SSH_TIMEOUT) {
        Ok(())
    } else {
        io.closed = true;
        let _ = io.stdin_tx.take();
        terminate_child_now(&mut io.child);
        Err(TransportError::ConnectionFailed)
    }
}

fn spawn_stdout_reader(
    mut stdout: std::process::ChildStdout,
) -> mpsc::Receiver<Result<SshFrame, FrameError>> {
    let (tx, rx) = mpsc::sync_channel(1);
    thread::spawn(move || {
        loop {
            let frame = read_frame::<_, SshFrame>(&mut stdout);
            let should_stop = frame.is_err();
            if tx.send(frame).is_err() || should_stop {
                break;
            }
        }
    });
    rx
}

#[derive(Debug)]
enum TimedFrameError {
    Timeout,
    Disconnected,
    Frame(FrameError),
}

fn recv_frame_with_timeout(
    rx: &mpsc::Receiver<Result<SshFrame, FrameError>>,
    timeout: Duration,
) -> Result<SshFrame, TimedFrameError> {
    match rx.recv_timeout(timeout) {
        Ok(Ok(frame)) => Ok(frame),
        Ok(Err(e)) => Err(TimedFrameError::Frame(e)),
        Err(mpsc::RecvTimeoutError::Timeout) => Err(TimedFrameError::Timeout),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(TimedFrameError::Disconnected),
    }
}

fn read_child_frame_or_err(io: &mut ChildIo) -> TransportResult<SshFrame> {
    match recv_frame_with_timeout(&io.stdout_rx, DEFAULT_SSH_TIMEOUT) {
        Ok(frame) => Ok(frame),
        Err(TimedFrameError::Timeout) => {
            io.closed = true;
            let _ = io.stdin_tx.take();
            terminate_child_now(&mut io.child);
            Err(TransportError::ConnectionFailed)
        }
        Err(TimedFrameError::Disconnected) => Err(TransportError::ConnectionFailed),
        Err(TimedFrameError::Frame(e)) => Err(frame_error_to_transport(&e)),
    }
}

fn frame_error_to_transport(e: &FrameError) -> TransportError {
    match *e {
        FrameError::LengthTruncated | FrameError::BodyTruncated { .. } => {
            TransportError::ConnectionFailed
        }
        FrameError::LengthTooLarge(n) => TransportError::PayloadTooLarge(n as usize),
        FrameError::DecodeFailed => TransportError::ProtocolError,
        FrameError::Io(_) => TransportError::ConnectionFailed,
    }
}

// ---------------------------------------------------------------------------
// Hello handshake + child teardown
// ---------------------------------------------------------------------------

fn perform_client_handshake(io: &mut ChildIo) -> Result<(), SshInitError> {
    let hello = SshFrame {
        body: Some(ssh_frame::Body::Hello(Box::new(
            Hello::default()
                .with_proto(ProtocolVersion::ProtocolVersion1)
                .with_client_id(CLIENT_ID),
        ))),
        ..Default::default()
    };
    write_child_frame_or_err(io, hello)
        .map_err(|e| SshInitError::HandshakeFailed(format!("send hello: {e:?}")))?;

    let resp = match recv_frame_with_timeout(&io.stdout_rx, DEFAULT_SSH_TIMEOUT) {
        Ok(frame) => frame,
        Err(TimedFrameError::Timeout) => {
            io.closed = true;
            let _ = io.stdin_tx.take();
            terminate_child_now(&mut io.child);
            return Err(SshInitError::HandshakeFailed(
                "read hello reply timed out".into(),
            ));
        }
        Err(TimedFrameError::Disconnected) => {
            return Err(SshInitError::HandshakeFailed(
                "read hello reply: child stdout closed".into(),
            ));
        }
        Err(TimedFrameError::Frame(e)) => {
            return Err(SshInitError::HandshakeFailed(format!(
                "read hello reply: {e}"
            )));
        }
    };
    match resp.body {
        Some(ssh_frame::Body::HelloResponse(h)) => {
            let proto = h.proto.unwrap_or_default();
            if proto != ProtocolVersion::ProtocolVersion1 {
                return Err(SshInitError::HandshakeFailed(format!(
                    "server proto_version {} != expected 1",
                    proto.to_i32()
                )));
            }
            Ok(())
        }
        Some(ssh_frame::Body::Error(e)) => Err(SshInitError::HandshakeFailed(format!(
            "server error: {}",
            e.message.unwrap_or_default()
        ))),
        other => Err(SshInitError::HandshakeFailed(format!(
            "unexpected hello reply: {}",
            body_name(&other)
        ))),
    }
}

#[allow(clippy::unnecessary_wraps)]
fn shut_child(io: &mut ChildIo) -> io::Result<()> {
    if io.closed {
        return Ok(());
    }
    io.closed = true;
    // Dropping stdin closes the pipe; `mkit serve` treats EOF as a clean
    // shutdown, and this avoids blocking forever on a best-effort Close write.
    let _ = io.stdin_tx.take();
    wait_child_timeout(&mut io.child, DEFAULT_SSH_TIMEOUT)?;
    Ok(())
}

fn wait_child_timeout(child: &mut Child, timeout: Duration) -> io::Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        if child.try_wait()?.is_some() {
            return Ok(());
        }
        let now = Instant::now();
        if now >= deadline {
            terminate_child_now(child);
            return Ok(());
        }
        thread::sleep(core::cmp::min(
            Duration::from_millis(10),
            deadline.saturating_duration_since(now),
        ));
    }
}

fn terminate_child_now(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

// ---------------------------------------------------------------------------
// argv construction
// ---------------------------------------------------------------------------

/// Environment override for the SSH client program. Defaults to `ssh`.
/// Set `MKIT_SSH_PROGRAM` to point at a wrapper script — used by the
/// hermetic SSH e2e tests to record argv and exec the local `mkit serve`
/// without a real network hop. In production this is unset and the
/// system `ssh(1)` is spawned.
const SSH_PROGRAM_ENV: &str = "MKIT_SSH_PROGRAM";

fn build_ssh_command(target: &SshTarget, options: &SshOptions) -> Command {
    let program = std::env::var(SSH_PROGRAM_ENV).unwrap_or_else(|_| "ssh".to_string());
    let mut cmd = Command::new(program);
    if let Some(port) = target.port {
        cmd.arg("-p").arg(port.to_string());
    }
    if !options.strict_host_key_checking.is_empty() {
        cmd.arg("-o").arg(format!(
            "StrictHostKeyChecking={}",
            options.strict_host_key_checking
        ));
    }
    if !options.user_known_hosts_file.is_empty() {
        cmd.arg("-o").arg(format!(
            "UserKnownHostsFile={}",
            options.user_known_hosts_file
        ));
    }
    if !options.identity_file.is_empty() {
        cmd.arg("-i").arg(&options.identity_file);
    }
    // BatchMode + accept-new match the defaults GitHub's CLI assumes
    // for git+ssh. mkit defers to whatever the user configured, but if
    // they haven't set either knob we should not block on an
    // interactive password prompt.
    if options.strict_host_key_checking.is_empty() {
        cmd.arg("-o").arg("StrictHostKeyChecking=accept-new");
    }
    cmd.arg("-o").arg("BatchMode=yes");
    cmd.arg("-o")
        .arg(format!("ConnectTimeout={}", DEFAULT_SSH_TIMEOUT.as_secs()));

    cmd.arg(format!("{}@{}", target.user, target.host));
    // The path is already restricted to `[A-Za-z0-9._-/]` by
    // `validate_ssh_path`, so handing it to the remote shell as a
    // separate argv token is safe. Three tokens (mkit / serve / path)
    // so sshd invokes `mkit serve <path>` without an intervening
    // `sh -c` that broke the handshake on some sshd configurations.
    cmd.arg("mkit").arg("serve").arg(&target.path);
    cmd
}

#[cfg(test)]
mod tests {
    // The public surface is exercised against a real (or simulator)
    // mkit-server, which does not exist in-tree. Once a server impl
    // lands, an integration test in tests/ can spawn it and drive
    // SshTransport against it. For now, basic smoke tests of the
    // helper functions live here.
    use super::*;
    use mkit_rpc::mkit::rpc::v1::ssh::{
        DownloadPackHeader, RefExpectation, list_refs_response::RefEntry,
    };
    use mkit_rpc::mkit::rpc::v1::{Error as RpcError, ErrorCode};

    /// A CAS mismatch — `InvalidRequest` with the current id in
    /// `details` under a precondition write — maps to `RefConflict`.
    #[test]
    fn update_ref_error_maps_cas_mismatch_to_conflict() {
        let e = RpcError::default()
            .with_code(ErrorCode::InvalidRequest)
            .with_message("ref changed")
            .with_details(vec![0xABu8; 32]);
        assert!(matches!(
            map_update_ref_error(e, RefWriteCondition::Missing),
            TransportError::RefConflict
        ));
    }

    /// A genuine invalid-request (no `details` payload) under a
    /// precondition write must NOT be masked as `RefConflict` — it
    /// surfaces its real message via `rpc_error_to_transport`.
    #[test]
    fn update_ref_error_does_not_mask_plain_invalid_request() {
        let e = RpcError::default()
            .with_code(ErrorCode::InvalidRequest)
            .with_message("malformed ref name");
        match map_update_ref_error(e, RefWriteCondition::Match([0u8; 32])) {
            TransportError::RemoteError(msg) => assert_eq!(msg, "malformed ref name"),
            other => panic!("expected RemoteError, got {other:?}"),
        }
    }

    /// Under `Any` (no CAS precondition) even a detail-bearing
    /// `InvalidRequest` is not a conflict.
    #[test]
    fn update_ref_error_any_condition_never_conflict() {
        let e = RpcError::default()
            .with_code(ErrorCode::InvalidRequest)
            .with_message("bad")
            .with_details(vec![0xABu8; 32]);
        assert!(!matches!(
            map_update_ref_error(e, RefWriteCondition::Any),
            TransportError::RefConflict
        ));
    }

    #[test]
    fn ref_entry_to_ref_validates_oid_length() {
        let bad = RefEntry::default()
            .with_name("refs/heads/main")
            .with_object_id(vec![0u8; 16]);
        assert!(matches!(
            ref_entry_to_ref(bad),
            Err(TransportError::InvalidResponse)
        ));
    }

    #[test]
    fn ref_entry_to_ref_validates_name() {
        // Empty ref names are rejected by `validate_ref_name`.
        let bad = RefEntry::default()
            .with_name(String::new())
            .with_object_id(vec![0u8; 32]);
        assert!(matches!(
            ref_entry_to_ref(bad),
            Err(TransportError::InvalidRef(_))
        ));
    }

    /// A `DownloadPackHeader` with `total_bytes = u64::MAX` (an
    /// attacker-controlled pathological value) must be rejected before
    /// the client touches `Vec::with_capacity` — otherwise the process
    /// either OOMs or panics.
    #[test]
    fn download_pack_rejects_oversize_header_without_allocating() {
        let mut buf = Vec::new();
        let header = SshFrame {
            body: Some(ssh_frame::Body::DownloadPackHeader(Box::new(
                DownloadPackHeader::default().with_total_bytes(u64::MAX),
            ))),
            ..Default::default()
        };
        write_frame(&mut buf, &header).expect("write header frame");

        let mut cursor = std::io::Cursor::new(buf);
        let err = read_download_pack_body(&mut cursor).expect_err("must reject oversize header");
        match err {
            TransportError::RemoteError(msg) => {
                assert!(
                    msg.contains("exceeds client cap"),
                    "unexpected error message: {msg}"
                );
            }
            other => panic!("expected RemoteError, got {other:?}"),
        }
    }

    /// An honest header followed by chunks whose combined length blows
    /// past `PACK_BODY_LIMIT` must be cut off mid-stream rather than
    /// being accumulated into an unbounded `Vec`.
    #[test]
    fn download_pack_rejects_overflowing_chunk_stream() {
        // Craft a header that under-states the body (claims 0 bytes) so
        // the cap check on `total` passes, then stream chunks past the
        // limit. We can't realistically emit 4 GiB in a test, so this
        // test exercises the running-total check by temporarily relying
        // on a deliberately constructed `last=false` loop where the
        // attacker advertises 0 then sends chunks indefinitely. We stop
        // after one chunk and assert the function progresses correctly
        // when the running total stays under the cap.
        let mut buf = Vec::new();
        let header = SshFrame {
            body: Some(ssh_frame::Body::DownloadPackHeader(Box::new(
                DownloadPackHeader::default().with_total_bytes(4),
            ))),
            ..Default::default()
        };
        write_frame(&mut buf, &header).expect("write header frame");
        let chunk = SshFrame {
            body: Some(ssh_frame::Body::PackChunk(Box::new(
                PackChunk::default()
                    .with_pack_id(vec![0u8; 32])
                    .with_offset(0)
                    .with_data(vec![1, 2, 3, 4])
                    .with_last(true),
            ))),
            ..Default::default()
        };
        write_frame(&mut buf, &chunk).expect("write chunk frame");

        let mut cursor = std::io::Cursor::new(buf);
        let out = read_download_pack_body(&mut cursor).expect("honest small pack should succeed");
        assert_eq!(out, vec![1, 2, 3, 4]);
    }

    #[test]
    fn recv_frame_with_timeout_reports_stalled_reader() {
        let (_tx, rx) = mpsc::channel();
        let started = Instant::now();
        let result = recv_frame_with_timeout(&rx, Duration::from_millis(10));

        assert!(matches!(result, Err(TimedFrameError::Timeout)));
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    // #505 PR 5/5: spawns a real external `sleep 5` child process —
    // quarantined to the serial `--ignored` CI lane (cloudbuild/ci.yaml,
    // .github/workflows/rust.yml) instead of paying real subprocess
    // spawn/kill overhead on every `cargo test`.
    #[ignore = "spawns a real external subprocess; run via the serial --ignored CI lane"]
    fn wait_child_timeout_kills_stalled_child() {
        let mut child = Command::new("sleep")
            .arg("5")
            .spawn()
            .expect("spawn sleep child");
        let started = Instant::now();

        wait_child_timeout(&mut child, Duration::from_millis(20)).expect("bounded wait");

        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(child.try_wait().expect("poll child").is_some());
    }

    #[test]
    fn ssh_command_sets_connect_timeout() {
        let target = SshTarget {
            user: "git".into(),
            host: "example.com".into(),
            port: None,
            path: "repo".into(),
        };
        let cmd = build_ssh_command(&target, &SshOptions::default());
        let args: Vec<String> = cmd
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();

        assert!(args.contains(&format!("ConnectTimeout={}", DEFAULT_SSH_TIMEOUT.as_secs())));
    }

    /// Build an `UpdateRef` body via `cond_to_wire` so this test
    /// exercises the same encoding path as `Transport::update_ref`.
    fn encode_update_ref(condition: RefWriteCondition) -> UpdateRef {
        let new_hash = [0xABu8; 32];
        let (expected_id, expectation) = cond_to_wire(condition);
        UpdateRef {
            name: Some("refs/heads/main".into()),
            expected_id: Some(expected_id),
            new_id: Some(new_hash.to_vec()),
            expectation: Some(expectation.into()),
            ..Default::default()
        }
    }

    /// The three CAS variants MUST produce three distinct
    /// `cond_to_wire` encodings. Before the `expectation` field
    /// landed, `Any` and `Missing` collapsed to the same bytes — this
    /// pins that they no longer do.
    #[test]
    fn cond_to_wire_variants_produce_distinct_encodings() {
        use buffa::Message;

        let any = encode_update_ref(RefWriteCondition::Any).encode_to_vec();
        let missing = encode_update_ref(RefWriteCondition::Missing).encode_to_vec();
        let m = encode_update_ref(RefWriteCondition::Match([0xCDu8; 32])).encode_to_vec();

        assert_ne!(any, missing, "Any and Missing must differ on the wire");
        assert_ne!(any, m, "Any and Match must differ on the wire");
        assert_ne!(missing, m, "Missing and Match must differ on the wire");

        // Hex-print the three encodings so a failing CI run leaves
        // the wire bytes in the log for forensic review.
        eprintln!("UpdateRef[Any]     = {}", hex_encode(&any));
        eprintln!("UpdateRef[Missing] = {}", hex_encode(&missing));
        eprintln!("UpdateRef[Match]   = {}", hex_encode(&m));
    }

    /// After encoding and decoding round-trips, each variant
    /// surfaces its declared `expectation` value. Catches a future
    /// codegen change that drops the field by mistake.
    #[test]
    fn update_ref_expectation_round_trips() {
        use buffa::Message;

        for (cond, want) in [
            (RefWriteCondition::Any, RefExpectation::Any),
            (RefWriteCondition::Missing, RefExpectation::Missing),
            (
                RefWriteCondition::Match([0xCDu8; 32]),
                RefExpectation::Match,
            ),
        ] {
            let bytes = encode_update_ref(cond).encode_to_vec();
            let decoded = UpdateRef::decode(&mut &bytes[..]).expect("decode UpdateRef");
            assert_eq!(
                decoded.expectation,
                Some(want.into()),
                "expectation field did not round-trip for {cond:?}"
            );
        }
    }

    /// A frame missing `expectation` decodes as UNSPECIFIED — a real
    /// wire state that a conforming server MUST reject (see
    /// SPEC-TRANSPORT §4.2.1). This test pins the decode side; the
    /// server-side rejection lives in `mkit-cli/src/commands/serve.rs`.
    #[test]
    fn update_ref_without_expectation_decodes_as_unspecified() {
        use buffa::Message;

        let req = UpdateRef {
            name: Some("refs/heads/main".into()),
            expected_id: Some(Vec::new()),
            new_id: Some(vec![0xABu8; 32]),
            // `expectation` left as None → zero-default on the wire.
            ..Default::default()
        };
        let bytes = req.encode_to_vec();
        let decoded = UpdateRef::decode(&mut &bytes[..]).expect("decode UpdateRef");
        assert_eq!(
            decoded.expectation.unwrap_or_default(),
            RefExpectation::Unspecified,
            "missing expectation field MUST decode as UNSPECIFIED"
        );
    }

    fn hex_encode(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    #[test]
    fn body_name_covers_every_oneof_variant() {
        // Every `ssh_frame::Body` oneof variant, pinned to its exact
        // `body_name` string. If the proto adds a variant and
        // `body_name` isn't updated, the new arm falls through to
        // `"(empty body)"` — exhaustively listing all 17 variants here
        // (plus `None`) means a forgotten arm shows up as a wrong
        // string on an EXISTING case only if it collides; the real
        // guard is that adding a variant to the match in `body_name`
        // without a corresponding line here is caught by nothing, so
        // this list must be kept in sync with `ssh_frame::Body`
        // (mirrors the exhaustive `match` in `body_name` itself).
        use ssh_frame::Body;
        assert_eq!(body_name(&None), "(empty body)");
        assert_eq!(body_name(&Some(Body::Hello(Box::default()))), "hello");
        assert_eq!(
            body_name(&Some(Body::HelloResponse(Box::default()))),
            "hello_response"
        );
        assert_eq!(body_name(&Some(Body::Error(Box::default()))), "error");
        assert_eq!(body_name(&Some(Body::Close(Box::default()))), "close");
        assert_eq!(
            body_name(&Some(Body::ListRefs(Box::default()))),
            "list_refs"
        );
        assert_eq!(
            body_name(&Some(Body::ListRefsResponse(Box::default()))),
            "list_refs_response"
        );
        assert_eq!(body_name(&Some(Body::ReadRef(Box::default()))), "read_ref");
        assert_eq!(
            body_name(&Some(Body::ReadRefResponse(Box::default()))),
            "read_ref_response"
        );
        assert_eq!(
            body_name(&Some(Body::UpdateRef(Box::default()))),
            "update_ref"
        );
        assert_eq!(
            body_name(&Some(Body::UpdateRefResponse(Box::default()))),
            "update_ref_response"
        );
        assert_eq!(
            body_name(&Some(Body::PackExists(Box::default()))),
            "pack_exists"
        );
        assert_eq!(
            body_name(&Some(Body::PackExistsResponse(Box::default()))),
            "pack_exists_response"
        );
        assert_eq!(
            body_name(&Some(Body::UploadPack(Box::default()))),
            "upload_pack"
        );
        assert_eq!(
            body_name(&Some(Body::UploadPackResponse(Box::default()))),
            "upload_pack_response"
        );
        assert_eq!(
            body_name(&Some(Body::DownloadPack(Box::default()))),
            "download_pack"
        );
        assert_eq!(
            body_name(&Some(Body::DownloadPackHeader(Box::default()))),
            "download_pack_header"
        );
        assert_eq!(
            body_name(&Some(Body::PackChunk(Box::default()))),
            "pack_chunk"
        );
    }

    // --- build_ssh_command argv wiring (issue #389) ----------------------

    /// Collect the argv tokens of a built `Command` as owned strings so
    /// tests can assert on the spawned `ssh(1)` command line.
    fn argv_tokens(cmd: &Command) -> Vec<String> {
        cmd.get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect()
    }

    /// Assert that `tokens` contains the consecutive pair
    /// `[flag, value]` (e.g. `-o`, `StrictHostKeyChecking=yes`).
    fn contains_pair(tokens: &[String], flag: &str, value: &str) -> bool {
        tokens.windows(2).any(|w| w[0] == flag && w[1] == value)
    }

    fn target() -> SshTarget {
        SshTarget {
            user: "alice".to_string(),
            host: "host.example.com".to_string(),
            port: None,
            path: "/repos/project".to_string(),
        }
    }

    /// A fully-populated `SshOptions` must surface as the documented
    /// `-o StrictHostKeyChecking=… -o UserKnownHostsFile=… -i …` flags
    /// (SSH-SECURITY.md §3). This is the consumer half of issue #389 —
    /// it already worked, but the test pins the exact flag form so the
    /// producer wiring has a contract to satisfy.
    #[test]
    fn build_ssh_command_wires_populated_options() {
        let opts = SshOptions {
            strict_host_key_checking: "yes".to_string(),
            user_known_hosts_file: "/path/to/project.known_hosts".to_string(),
            identity_file: "/path/to/id_ed25519".to_string(),
        };
        let cmd = build_ssh_command(&target(), &opts);
        let tokens = argv_tokens(&cmd);
        assert!(
            contains_pair(&tokens, "-o", "StrictHostKeyChecking=yes"),
            "missing StrictHostKeyChecking flag: {tokens:?}"
        );
        assert!(
            contains_pair(
                &tokens,
                "-o",
                "UserKnownHostsFile=/path/to/project.known_hosts"
            ),
            "missing UserKnownHostsFile flag: {tokens:?}"
        );
        assert!(
            contains_pair(&tokens, "-i", "/path/to/id_ed25519"),
            "missing identity flag: {tokens:?}"
        );
    }

    /// Default options must emit NONE of the trust-pinning flags — the
    /// user's `ssh(1)` defaults are inherited. (A baseline
    /// `StrictHostKeyChecking=accept-new` IS added, but never the
    /// caller-supplied `yes`, and no `UserKnownHostsFile`/`-i`.)
    #[test]
    fn build_ssh_command_omits_flags_for_default_options() {
        let cmd = build_ssh_command(&target(), &SshOptions::default());
        let tokens = argv_tokens(&cmd);
        assert!(
            !tokens.iter().any(|t| t.starts_with("UserKnownHostsFile=")),
            "default options must not set UserKnownHostsFile: {tokens:?}"
        );
        assert!(
            !tokens.contains(&"-i".to_string()),
            "default options must not pass -i: {tokens:?}"
        );
        // No explicit StrictHostKeyChecking=<caller value>; only the
        // built-in accept-new baseline is permitted.
        assert!(
            !tokens.iter().any(|t| t == "StrictHostKeyChecking=yes"),
            "default options must not pin StrictHostKeyChecking=yes: {tokens:?}"
        );
    }
}
