//! mkit SSH transport.
//!
//! Implements [`mkit_core::protocol::Transport`] over a long-lived
//! system `ssh(1)` child process, exchanging the 7 v1 verbs as framed
//! stdin/stdout messages (SPEC-TRANSPORT §7).
//!
//! # Design choice: `std::process::Command`, NOT `russh`
//!
//! SSH-SECURITY.md §1 is explicit: mkit does NOT implement its own SSH
//! client. It shells out to `ssh(1)` and delegates host-key
//! verification, agent handling, credential selection, and kex to the
//! user's installed OpenSSH. This is the same posture `git+ssh://`
//! takes, and it is deliberately chosen so:
//!
//! - Our binary does not need to ship a crypto stack (no `russh`,
//!   `rustls`, `openssl`, `native-tls`).
//! - `ssh-agent`, `~/.ssh/config`, `ProxyCommand`, and every other
//!   knob the user already configured Just Work, with zero mkit code.
//! - Host-key rotation / trust escalation stays on the OpenSSH side,
//!   where it belongs — see SSH-SECURITY.md §4 for the known gaps we
//!   inherit from this choice.
//!
//! Trade-off: we cannot observe or rotate host keys from `.mkit/config`,
//! and a misbehaving server can stall the handshake until the user's
//! ssh CLI times out. Both are flagged in SSH-SECURITY.md §4/§6 as
//! deferred work.
//!
//! The Transport trait itself is synchronous (object-safe, `&self`,
//! `TransportResult<T>`), so wrapping `Command::spawn` + blocking
//! stdio is the shortest path to parity with the other transports. No
//! tokio runtime needed.

#![forbid(unsafe_code)]

pub mod url;

use std::io::{self, Read, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::Mutex;

use mkit_core::hash::Hash;
use mkit_core::protocol::{
    self, FRAME_HEADER_LEN, HELLO_VERSION_MAX, MAX_PAYLOAD_LEN, OP_CLOSE, OP_DOWNLOAD_PACK,
    OP_HELLO, OP_LIST_REFS, OP_PACK_EXISTS, OP_READ_REF, OP_UPDATE_REF, OP_UPLOAD_PACK,
    OP_WRITE_REF, PackKey, SSH_BINARY_NAME, SSH_PROTO_VERSION, STATUS_ERROR, STATUS_NULL,
    STATUS_OK, STATUS_UNSUPPORTED, Transport, TransportError, TransportResult, decode_frame,
    encode_frame, encode_hello_payload,
};
use mkit_core::refs::{Ref, RefWriteCondition, validate_ref_name, validate_ref_prefix};

pub use crate::url::{MKIT_SSH_PREFIX, SshTarget, parse_mkit_ssh_url, validate_ssh_path};

/// Maximum combined ref / prefix name length accepted over the wire.
const MAX_REF_NAME: usize = 4096;

/// Client version string sent in the `OP_HELLO` payload. Crate version
/// is inherited from the workspace (0.2.1 at cut) so a release bump
/// propagates automatically.
const CLIENT_VERSION: &str = concat!("mkit ", env!("CARGO_PKG_VERSION"));

/// Optional SSH CLI knobs threaded from `.mkit/config`. All fields default
/// to empty, which means "inherit the user's `ssh(1)` defaults". See
/// SPEC-TRANSPORT §7.5 for the canonical field list.
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
    /// HELLO handshake failed — wrong binary name, future proto
    /// version, or unparseable reply. The embedded message is advisory.
    #[error("ssh hello handshake failed: {0}")]
    HandshakeFailed(String),
}

/// Transport over a spawned `ssh(1)` child process.
///
/// Construction spawns the child, sends the mandatory `OP_HELLO` frame,
/// and validates the server's reply. If any of those steps fail the
/// child is torn down before the constructor returns, so a successful
/// [`SshTransport::connect`] ALWAYS yields a handle whose first verb
/// call lands on a v1 mkit server.
#[derive(Debug)]
pub struct SshTransport {
    // The child's stdio handles sit behind a `Mutex` so `&self`
    // [`Transport`] methods can still mutate them. SSH is a single
    // pipelined stream — concurrent verbs on one [`SshTransport`]
    // serialise through this mutex.
    io: Mutex<ChildIo>,
}

#[derive(Debug)]
struct ChildIo {
    child: Child,
    stdin: ChildStdin,
    stdout: ChildStdout,
    /// `true` once we've written `OP_CLOSE` + shut the pipe. Guards
    /// double-close from `Drop` + explicit `close`.
    closed: bool,
}

impl SshTransport {
    /// Parse `url`, spawn `ssh`, and perform the `OP_HELLO` handshake.
    pub fn connect(url: &str) -> Result<Self, SshInitError> {
        let target = parse_mkit_ssh_url(url)?;
        Self::connect_with_options(&target, &SshOptions::default())
    }

    /// Spawn `ssh` from a pre-parsed [`SshTarget`] with explicit
    /// `.mkit/config` SSH options. Callers that already resolved config
    /// should use this entry point; `connect` is the convenience form.
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
        let mut io = ChildIo {
            child,
            stdin,
            stdout,
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

    /// Explicit shutdown — sends `OP_CLOSE` and waits for the child.
    /// Equivalent to dropping the transport, but lets the caller
    /// observe any shutdown error. Safe to call multiple times; the
    /// `closed` flag guards double-close.
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
                // Mutex poisoned but we can still reach the inner
                // `ChildIo` via the poison error for a best-effort
                // cleanup.
                let io = poison.into_inner();
                let _ = shut_child(io);
            }
        }
    }
}

impl Transport for SshTransport {
    fn upload_pack(&self, bytes: &[u8], key: &PackKey) -> TransportResult<()> {
        let mut payload = Vec::with_capacity(32 + bytes.len());
        payload.extend_from_slice(key.as_bytes());
        payload.extend_from_slice(bytes);
        let (status, _data) = self.exchange(OP_UPLOAD_PACK, &payload)?;
        match status {
            STATUS_OK => Ok(()),
            STATUS_ERROR => Err(TransportError::RemoteError("upload_pack failed".into())),
            _ => Err(TransportError::ProtocolError),
        }
    }

    fn download_pack(&self, key: &PackKey) -> TransportResult<Vec<u8>> {
        let (status, data) = self.exchange(OP_DOWNLOAD_PACK, key.as_bytes())?;
        match status {
            STATUS_OK => Ok(data),
            STATUS_NULL | STATUS_ERROR => Err(TransportError::PackNotFound),
            _ => Err(TransportError::ProtocolError),
        }
    }

    fn pack_exists(&self, key: &PackKey) -> TransportResult<bool> {
        let (status, data) = self.exchange(OP_PACK_EXISTS, key.as_bytes())?;
        match status {
            STATUS_OK => {
                if data.is_empty() {
                    Err(TransportError::InvalidResponse)
                } else {
                    Ok(data[0] != 0)
                }
            }
            STATUS_ERROR => Err(TransportError::RemoteError("pack_exists failed".into())),
            _ => Err(TransportError::ProtocolError),
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
        let (opcode, payload) = if matches!(condition, RefWriteCondition::Any) {
            // `write_ref` wire shape: no condition byte.
            (OP_WRITE_REF, encode_write_ref(name, hash)?)
        } else {
            (OP_UPDATE_REF, encode_update_ref(name, condition, hash)?)
        };
        let (status, _data) = self.exchange(opcode, &payload)?;
        match status {
            STATUS_OK => Ok(()),
            STATUS_ERROR => {
                // §7.3: server uses STATUS_ERROR to signal CAS failure
                // on OP_UPDATE_REF. For OP_WRITE_REF the only defined
                // failure is a generic remote error.
                if opcode == OP_UPDATE_REF {
                    Err(TransportError::RefConflict)
                } else {
                    Err(TransportError::RemoteError("write_ref failed".into()))
                }
            }
            _ => Err(TransportError::ProtocolError),
        }
    }

    fn read_ref(&self, name: &str) -> TransportResult<Option<Hash>> {
        if !validate_ref_name(name) {
            return Err(TransportError::InvalidRef(name.into()));
        }
        if name.len() > MAX_REF_NAME {
            return Err(TransportError::InvalidRef("ref name too long".into()));
        }
        let payload = encode_read_ref(name)?;
        let (status, data) = self.exchange(OP_READ_REF, &payload)?;
        match status {
            STATUS_NULL => Ok(None),
            STATUS_OK => {
                if data.len() < 32 {
                    return Err(TransportError::InvalidResponse);
                }
                let mut h = [0u8; 32];
                h.copy_from_slice(&data[..32]);
                Ok(Some(h))
            }
            STATUS_ERROR => Err(TransportError::RemoteError("read_ref failed".into())),
            _ => Err(TransportError::ProtocolError),
        }
    }

    fn list_refs(&self, prefix: &str) -> TransportResult<Vec<Ref>> {
        if !validate_ref_prefix(prefix) {
            return Err(TransportError::InvalidRef(prefix.into()));
        }
        if prefix.len() > MAX_REF_NAME {
            return Err(TransportError::InvalidRef("ref prefix too long".into()));
        }
        let payload = encode_list_refs(prefix)?;
        let (status, data) = self.exchange(OP_LIST_REFS, &payload)?;
        match status {
            STATUS_OK => decode_ref_list(&data),
            STATUS_ERROR => Err(TransportError::RemoteError("list_refs failed".into())),
            _ => Err(TransportError::ProtocolError),
        }
    }
}

// ---------------------------------------------------------------------------
// Exchange loop — private
// ---------------------------------------------------------------------------

impl SshTransport {
    /// Send one frame and read one reply frame. The mutex guarantees
    /// concurrent callers serialise on the single stdio stream.
    fn exchange(&self, opcode: u8, payload: &[u8]) -> TransportResult<(u8, Vec<u8>)> {
        let mut io = self
            .io
            .lock()
            .map_err(|_| TransportError::ConnectionFailed)?;
        if io.closed {
            return Err(TransportError::ConnectionFailed);
        }
        write_frame(&mut io.stdin, opcode, payload)?;
        read_frame(&mut io.stdout)
    }
}

fn write_frame(w: &mut ChildStdin, opcode: u8, payload: &[u8]) -> TransportResult<()> {
    let framed = encode_frame(opcode, payload)?;
    w.write_all(&framed)
        .map_err(|_| TransportError::ConnectionFailed)?;
    w.flush().map_err(|_| TransportError::ConnectionFailed)?;
    Ok(())
}

fn read_frame(r: &mut ChildStdout) -> TransportResult<(u8, Vec<u8>)> {
    let mut header = [0u8; FRAME_HEADER_LEN];
    read_exact(r, &mut header)?;
    let (status, payload_len) = peek_header(header)?;
    if payload_len > MAX_PAYLOAD_LEN {
        return Err(TransportError::PayloadTooLarge(payload_len));
    }
    let mut payload = vec![0u8; payload_len];
    if payload_len > 0 {
        read_exact(r, &mut payload)?;
    }
    Ok((status, payload))
}

/// Peek `[opcode/status][u32 LE payload_len]` from a 5-byte header
/// buffer. Equivalent to calling [`decode_frame`] on `header` followed
/// by a second read for the payload — but avoids an intermediate
/// allocation.
fn peek_header(header: [u8; FRAME_HEADER_LEN]) -> TransportResult<(u8, usize)> {
    // Delegate to the core decoder so encode/decode parity is enforced
    // in one place. `decode_frame` tolerates extra bytes after the
    // advertised length, so feeding it a lone header still yields the
    // status + len when `payload_len == 0`; for non-zero lengths it
    // returns `TruncatedFrame`, which we translate back into the split
    // header/payload read.
    match decode_frame(&header) {
        Ok((op, _)) => Ok((op, 0)),
        Err(TransportError::TruncatedFrame {
            expected,
            actual: _,
        }) => Ok((header[0], expected)),
        Err(e) => Err(e),
    }
}

fn read_exact(r: &mut ChildStdout, buf: &mut [u8]) -> TransportResult<()> {
    let mut off = 0;
    while off < buf.len() {
        match r.read(&mut buf[off..]) {
            Ok(0) => return Err(TransportError::InvalidResponse),
            Ok(n) => off += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return Err(TransportError::ConnectionFailed),
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// HELLO handshake
// ---------------------------------------------------------------------------

fn perform_client_handshake(io: &mut ChildIo) -> Result<(), SshInitError> {
    let hello = encode_hello_payload(SSH_PROTO_VERSION, SSH_BINARY_NAME, CLIENT_VERSION)
        .map_err(|e| SshInitError::HandshakeFailed(format!("encode hello: {e}")))?;
    write_frame(&mut io.stdin, OP_HELLO, &hello)
        .map_err(|e| SshInitError::HandshakeFailed(format!("send hello: {e}")))?;
    let (status, data) = read_frame(&mut io.stdout)
        .map_err(|e| SshInitError::HandshakeFailed(format!("read hello reply: {e}")))?;
    match status {
        STATUS_OK => validate_server_hello(&data),
        STATUS_UNSUPPORTED => Err(SshInitError::HandshakeFailed(
            "server rejected proto_version".into(),
        )),
        STATUS_ERROR => Err(SshInitError::HandshakeFailed(format!(
            "server STATUS_ERROR: {}",
            String::from_utf8_lossy(&data)
        ))),
        other => Err(SshInitError::HandshakeFailed(format!(
            "unexpected hello status 0x{other:02X}"
        ))),
    }
}

/// Parse the server's `OP_HELLO` reply payload:
/// `[u8 proto_version][u8 server_version_len][server_version]`.
fn validate_server_hello(payload: &[u8]) -> Result<(), SshInitError> {
    if payload.len() < 2 {
        return Err(SshInitError::HandshakeFailed(
            "hello reply too short".into(),
        ));
    }
    let proto = payload[0];
    if proto != SSH_PROTO_VERSION {
        return Err(SshInitError::HandshakeFailed(format!(
            "server proto_version 0x{proto:02X} != expected 0x{SSH_PROTO_VERSION:02X}"
        )));
    }
    let ver_len = payload[1] as usize;
    if ver_len > HELLO_VERSION_MAX {
        return Err(SshInitError::HandshakeFailed(
            "server_version too long".into(),
        ));
    }
    if 2 + ver_len > payload.len() {
        return Err(SshInitError::HandshakeFailed(
            "server_version field truncated".into(),
        ));
    }
    // server_version is advisory; silently accepted.
    Ok(())
}

// ---------------------------------------------------------------------------
// Child teardown
// ---------------------------------------------------------------------------

// We intentionally wrap in Result<()> so the public `close()` call can
// surface a poisoned-mutex error; the inner best-effort teardown itself
// never fails, hence the `unnecessary_wraps` allow.
#[allow(clippy::unnecessary_wraps)]
fn shut_child(io: &mut ChildIo) -> io::Result<()> {
    if io.closed {
        return Ok(());
    }
    io.closed = true;
    // Best-effort OP_CLOSE; server might already be gone.
    if let Ok(frame) = encode_frame(OP_CLOSE, &[]) {
        let _ = io.stdin.write_all(&frame);
        let _ = io.stdin.flush();
    }
    // The child's stdin drops with `ChildIo`, which sends EOF to the
    // server and lets it exit cleanly on the OP_CLOSE it already saw.
    let _ = io.child.wait();
    Ok(())
}

// ---------------------------------------------------------------------------
// argv construction
// ---------------------------------------------------------------------------

fn build_ssh_command(target: &SshTarget, options: &SshOptions) -> Command {
    let mut cmd = Command::new("ssh");
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
    // for git+ssh — mkit defers to whatever the user configured, but
    // if they haven't set either knob we should not block on an
    // interactive password prompt.
    if options.strict_host_key_checking.is_empty() {
        cmd.arg("-o").arg("StrictHostKeyChecking=accept-new");
    }
    cmd.arg("-o").arg("BatchMode=yes");

    cmd.arg(format!("{}@{}", target.user, target.host));
    // The path is already restricted to `[A-Za-z0-9._-/]` by
    // `validate_ssh_path`, so handing it to the remote shell as a
    // separate argv token is safe. Three tokens (mkit / serve / path)
    // so sshd invokes `mkit serve <path>` without an intervening
    // `sh -c` that broke the OP_HELLO handshake on some sshd
    // configurations.
    cmd.arg("mkit").arg("serve").arg(&target.path);
    cmd
}

// ---------------------------------------------------------------------------
// Verb payload encoders / decoders
//
// All encode_* and decode_* functions are public so the `mkit serve`
// command (CLI-WIRE / PR #48) can import them from this crate instead of
// inlining copies.  The public surface is flat:
//   mkit_transport_ssh::decode_upload_pack
//   mkit_transport_ssh::decode_download_pack
//   mkit_transport_ssh::decode_pack_exists
//   mkit_transport_ssh::decode_write_ref
//   mkit_transport_ssh::decode_update_ref
//   mkit_transport_ssh::decode_read_ref
//   mkit_transport_ssh::decode_list_refs
//   mkit_transport_ssh::decode_ref_list
//   mkit_transport_ssh::encode_write_ref
//   mkit_transport_ssh::encode_update_ref
//   mkit_transport_ssh::encode_read_ref
//   mkit_transport_ssh::encode_list_refs
// ---------------------------------------------------------------------------

/// Returned by [`decode_upload_pack`]: the pack digest and raw pack bytes
/// extracted from an `OP_UPLOAD_PACK` client request payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadPackRequest {
    pub digest: Hash,
    pub data: Vec<u8>,
}

/// Decode an `OP_UPLOAD_PACK` request payload sent by the client.
///
/// Wire format: `[32-byte digest][pack bytes...]`
pub fn decode_upload_pack(payload: &[u8]) -> TransportResult<UploadPackRequest> {
    if payload.len() < 32 {
        return Err(TransportError::InvalidResponse);
    }
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&payload[..32]);
    Ok(UploadPackRequest {
        digest,
        data: payload[32..].to_vec(),
    })
}

/// Decode an `OP_DOWNLOAD_PACK` request payload sent by the client.
///
/// Wire format: `[32-byte digest]`
pub fn decode_download_pack(payload: &[u8]) -> TransportResult<Hash> {
    if payload.len() < 32 {
        return Err(TransportError::InvalidResponse);
    }
    let mut h = [0u8; 32];
    h.copy_from_slice(&payload[..32]);
    Ok(h)
}

/// Decode an `OP_PACK_EXISTS` request payload sent by the client.
///
/// Wire format: `[32-byte digest]`
pub fn decode_pack_exists(payload: &[u8]) -> TransportResult<Hash> {
    if payload.len() < 32 {
        return Err(TransportError::InvalidResponse);
    }
    let mut h = [0u8; 32];
    h.copy_from_slice(&payload[..32]);
    Ok(h)
}

/// Returned by [`decode_write_ref`]: the ref name and new hash value from
/// an `OP_WRITE_REF` client request payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteRefRequest {
    pub name: String,
    pub hash: Hash,
}

/// Decode an `OP_WRITE_REF` request payload sent by the client.
///
/// Wire format: `[u16 LE name_len][name bytes][32-byte hash]`
pub fn decode_write_ref(payload: &[u8]) -> TransportResult<WriteRefRequest> {
    if payload.len() < 2 {
        return Err(TransportError::InvalidResponse);
    }
    let name_len = u16::from_le_bytes([payload[0], payload[1]]) as usize;
    if payload.len() < 2 + name_len + 32 {
        return Err(TransportError::InvalidResponse);
    }
    let name_bytes = &payload[2..2 + name_len];
    let name = core::str::from_utf8(name_bytes)
        .map_err(|_| TransportError::InvalidResponse)?
        .to_string();
    if !validate_ref_name(&name) {
        return Err(TransportError::InvalidRef(name));
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&payload[2 + name_len..2 + name_len + 32]);
    Ok(WriteRefRequest { name, hash })
}

/// Returned by [`decode_update_ref`]: the ref name, CAS condition, and new
/// hash from an `OP_UPDATE_REF` client request payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateRefRequest {
    pub name: String,
    pub condition: RefWriteCondition,
    pub hash: Hash,
}

/// Decode an `OP_UPDATE_REF` request payload sent by the client.
///
/// Wire format:
/// - `[u8 cond_tag]` — `COND_ANY` (0x00), `COND_MISSING` (0x01), or `COND_MATCH` (0x02)
/// - if `COND_MATCH`: `[32-byte expected hash]`
/// - `[u16 LE name_len][name bytes][32-byte new hash]`
pub fn decode_update_ref(payload: &[u8]) -> TransportResult<UpdateRefRequest> {
    if payload.is_empty() {
        return Err(TransportError::InvalidResponse);
    }
    let mut pos = 0usize;
    let tag = payload[pos];
    pos += 1;
    let condition = match tag {
        protocol::COND_ANY => RefWriteCondition::Any,
        protocol::COND_MISSING => RefWriteCondition::Missing,
        protocol::COND_MATCH => {
            if pos + 32 > payload.len() {
                return Err(TransportError::InvalidResponse);
            }
            let mut expected = [0u8; 32];
            expected.copy_from_slice(&payload[pos..pos + 32]);
            pos += 32;
            RefWriteCondition::Match(expected)
        }
        _ => return Err(TransportError::ProtocolError),
    };
    if pos + 2 > payload.len() {
        return Err(TransportError::InvalidResponse);
    }
    let name_len = u16::from_le_bytes([payload[pos], payload[pos + 1]]) as usize;
    pos += 2;
    if pos + name_len + 32 > payload.len() {
        return Err(TransportError::InvalidResponse);
    }
    let name_bytes = &payload[pos..pos + name_len];
    let name = core::str::from_utf8(name_bytes)
        .map_err(|_| TransportError::InvalidResponse)?
        .to_string();
    if !validate_ref_name(&name) {
        return Err(TransportError::InvalidRef(name));
    }
    pos += name_len;
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&payload[pos..pos + 32]);
    Ok(UpdateRefRequest {
        name,
        condition,
        hash,
    })
}

/// Decode an `OP_READ_REF` request payload sent by the client.
///
/// Wire format: `[u16 LE name_len][name bytes]`
///
/// Returns the ref name as a `String`.
pub fn decode_read_ref(payload: &[u8]) -> TransportResult<String> {
    if payload.len() < 2 {
        return Err(TransportError::InvalidResponse);
    }
    let name_len = u16::from_le_bytes([payload[0], payload[1]]) as usize;
    if payload.len() < 2 + name_len {
        return Err(TransportError::InvalidResponse);
    }
    let name = core::str::from_utf8(&payload[2..2 + name_len])
        .map_err(|_| TransportError::InvalidResponse)?
        .to_string();
    if !validate_ref_name(&name) {
        return Err(TransportError::InvalidRef(name));
    }
    Ok(name)
}

/// Decode an `OP_LIST_REFS` request payload sent by the client.
///
/// Wire format: `[u16 LE prefix_len][prefix bytes]`
///
/// Returns the prefix string (may be empty, which lists all refs).
pub fn decode_list_refs(payload: &[u8]) -> TransportResult<String> {
    if payload.len() < 2 {
        return Err(TransportError::InvalidResponse);
    }
    let prefix_len = u16::from_le_bytes([payload[0], payload[1]]) as usize;
    if payload.len() < 2 + prefix_len {
        return Err(TransportError::InvalidResponse);
    }
    let prefix = core::str::from_utf8(&payload[2..2 + prefix_len])
        .map_err(|_| TransportError::InvalidResponse)?
        .to_string();
    if !prefix.is_empty() && !validate_ref_prefix(&prefix) {
        return Err(TransportError::InvalidRef(prefix));
    }
    Ok(prefix)
}

/// Check `name.len() <= MAX_REF_NAME` and coerce to `u16`. The encoder
/// enforces this cap even if the Transport impl has already checked —
/// we don't want a silent truncation path for any caller of the public
/// encoder surface. Returns an `InvalidRef` error mentioning the cap.
fn ref_name_len_u16(name: &str) -> TransportResult<u16> {
    let len = name.len();
    if len > MAX_REF_NAME {
        return Err(TransportError::InvalidRef(format!(
            "ref name exceeds {MAX_REF_NAME}-byte cap: got {len}"
        )));
    }
    // `len <= MAX_REF_NAME (4096)` so the cast is in range of u16.
    u16::try_from(len)
        .map_err(|_| TransportError::InvalidRef(format!("ref name too long: got {len}")))
}

/// Encode an `OP_WRITE_REF` request payload for the client.
///
/// Wire format: `[u16 LE name_len][name bytes][32-byte hash]`
///
/// # Errors
/// Returns [`TransportError::InvalidRef`] if `name.len()` exceeds
/// `MAX_REF_NAME` (4096 bytes). The encoder enforces this cap
/// independently of any caller-side check.
pub fn encode_write_ref(name: &str, hash: &Hash) -> TransportResult<Vec<u8>> {
    let name_bytes = name.as_bytes();
    let name_len = ref_name_len_u16(name)?;
    let mut out = Vec::with_capacity(2 + name_bytes.len() + 32);
    out.extend_from_slice(&name_len.to_le_bytes());
    out.extend_from_slice(name_bytes);
    out.extend_from_slice(hash);
    Ok(out)
}

/// Encode an `OP_UPDATE_REF` request payload for the client.
///
/// # Errors
/// Returns [`TransportError::InvalidRef`] if `name.len()` exceeds
/// `MAX_REF_NAME` (4096 bytes).
pub fn encode_update_ref(
    name: &str,
    condition: RefWriteCondition,
    hash: &Hash,
) -> TransportResult<Vec<u8>> {
    let name_bytes = name.as_bytes();
    let name_len = ref_name_len_u16(name)?;
    let mut out = Vec::with_capacity(1 + 32 + 2 + name_bytes.len() + 32);
    match condition {
        RefWriteCondition::Any => out.push(protocol::COND_ANY),
        RefWriteCondition::Missing => out.push(protocol::COND_MISSING),
        RefWriteCondition::Match(expected) => {
            out.push(protocol::COND_MATCH);
            out.extend_from_slice(&expected);
        }
    }
    out.extend_from_slice(&name_len.to_le_bytes());
    out.extend_from_slice(name_bytes);
    out.extend_from_slice(hash);
    Ok(out)
}

/// Encode an `OP_READ_REF` request payload for the client.
///
/// # Errors
/// Returns [`TransportError::InvalidRef`] if `name.len()` exceeds
/// `MAX_REF_NAME` (4096 bytes).
pub fn encode_read_ref(name: &str) -> TransportResult<Vec<u8>> {
    let name_bytes = name.as_bytes();
    let name_len = ref_name_len_u16(name)?;
    let mut out = Vec::with_capacity(2 + name_bytes.len());
    out.extend_from_slice(&name_len.to_le_bytes());
    out.extend_from_slice(name_bytes);
    Ok(out)
}

/// Encode an `OP_LIST_REFS` request payload for the client.
///
/// # Errors
/// Returns [`TransportError::InvalidRef`] if `prefix.len()` exceeds
/// `MAX_REF_NAME` (4096 bytes).
pub fn encode_list_refs(prefix: &str) -> TransportResult<Vec<u8>> {
    let prefix_bytes = prefix.as_bytes();
    let prefix_len = ref_name_len_u16(prefix)?;
    let mut out = Vec::with_capacity(2 + prefix_bytes.len());
    out.extend_from_slice(&prefix_len.to_le_bytes());
    out.extend_from_slice(prefix_bytes);
    Ok(out)
}

/// Decode the ref-list payload emitted by the server in response to
/// `OP_LIST_REFS`: `[u32 LE count][count × ([u16 LE name_len][name][32 hash])]`.
pub fn decode_ref_list(data: &[u8]) -> TransportResult<Vec<Ref>> {
    if data.len() < 4 {
        return Err(TransportError::InvalidResponse);
    }
    let count = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
    // Cheapest sanity check: reject impossible counts BEFORE allocating.
    // Each entry is at least 2 + 0 + 32 = 34 bytes.
    let max_count = (data.len() - 4) / (2 + 32);
    if count > max_count {
        return Err(TransportError::InvalidResponse);
    }
    let mut out = Vec::with_capacity(count);
    let mut pos = 4;
    for _ in 0..count {
        if pos + 2 > data.len() {
            return Err(TransportError::InvalidResponse);
        }
        let name_len = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        if pos + name_len + 32 > data.len() {
            return Err(TransportError::InvalidResponse);
        }
        let name_bytes = &data[pos..pos + name_len];
        pos += name_len;
        let name = core::str::from_utf8(name_bytes)
            .map_err(|_| TransportError::InvalidResponse)?
            .to_string();
        if !validate_ref_name(&name) {
            return Err(TransportError::InvalidRef(name));
        }
        let mut h = [0u8; 32];
        h.copy_from_slice(&data[pos..pos + 32]);
        pos += 32;
        out.push(Ref {
            name,
            hash: Some(h),
        });
    }
    Ok(out)
}

/// Encode the `OP_LIST_REFS` response payload sent by the server.
///
/// Wire format: `[u32 LE count][count × ([u16 LE name_len][name][32 hash])]`
///
/// This is the complement of [`decode_ref_list`] and is used by the server
/// to serialise the ref listing back to the client.
///
/// # Errors
/// - [`TransportError::InvalidRef`] if any entry's name exceeds
///   `MAX_REF_NAME` (4096 bytes).
/// - [`TransportError::InvalidResponse`] if `refs.len()` does not fit
///   in a `u32`.
pub fn encode_ref_list(refs: &[Ref]) -> TransportResult<Vec<u8>> {
    let mut out = Vec::with_capacity(4 + refs.len() * (2 + 32));
    let count = u32::try_from(refs.len()).map_err(|_| TransportError::InvalidResponse)?;
    out.extend_from_slice(&count.to_le_bytes());
    for r in refs {
        let name_bytes = r.name.as_bytes();
        let name_len = ref_name_len_u16(&r.name)?;
        out.extend_from_slice(&name_len.to_le_bytes());
        out.extend_from_slice(name_bytes);
        out.extend_from_slice(&r.hash.unwrap_or([0u8; 32]));
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use mkit_core::protocol::{FRAME_HEADER_LEN, OP_HELLO, SSH_BINARY_NAME, SSH_PROTO_VERSION};

    // Helper: build a fake server reply frame.
    fn server_frame(status: u8, payload: &[u8]) -> Vec<u8> {
        encode_frame(status, payload).unwrap()
    }

    // Helper: encode a full HELLO reply (status + payload).
    fn server_hello_ok() -> Vec<u8> {
        let mut p = Vec::new();
        p.push(SSH_PROTO_VERSION);
        let ver = b"mkit 0.1.0";
        p.push(u8::try_from(ver.len()).unwrap());
        p.extend_from_slice(ver);
        server_frame(STATUS_OK, &p)
    }

    // --- Payload encoders -------------------------------------------------

    #[test]
    fn encode_write_ref_shape() {
        let name = "refs/heads/main";
        let h = [0xABu8; 32];
        let got = encode_write_ref(name, &h).unwrap();
        // Expected wire: [u16 LE name_len][name][32 hash].
        assert_eq!(got.len(), 2 + name.len() + 32);
        let name_len = u16::from_le_bytes([got[0], got[1]]);
        assert_eq!(name_len as usize, name.len());
        assert_eq!(&got[2..2 + name.len()], name.as_bytes());
        assert_eq!(&got[2 + name.len()..], &h);
    }

    #[test]
    fn encode_update_ref_any_variant() {
        let name = "refs/heads/dev";
        let h = [1u8; 32];
        let got = encode_update_ref(name, RefWriteCondition::Any, &h).unwrap();
        assert_eq!(got[0], protocol::COND_ANY);
        let name_len = u16::from_le_bytes([got[1], got[2]]);
        assert_eq!(name_len as usize, name.len());
        assert_eq!(&got[3..3 + name.len()], name.as_bytes());
        assert_eq!(&got[3 + name.len()..], &h);
    }

    #[test]
    fn encode_update_ref_match_variant() {
        let name = "refs/heads/main";
        let h = [2u8; 32];
        let expected = [0x5Au8; 32];
        let got = encode_update_ref(name, RefWriteCondition::Match(expected), &h).unwrap();
        assert_eq!(got[0], protocol::COND_MATCH);
        assert_eq!(&got[1..33], &expected);
        let name_len = u16::from_le_bytes([got[33], got[34]]);
        assert_eq!(name_len as usize, name.len());
        assert_eq!(&got[35..35 + name.len()], name.as_bytes());
        assert_eq!(&got[35 + name.len()..], &h);
    }

    #[test]
    fn encode_read_ref_shape() {
        let got = encode_read_ref("refs/tags/v1.0").unwrap();
        let name_len = u16::from_le_bytes([got[0], got[1]]);
        assert_eq!(name_len as usize, "refs/tags/v1.0".len());
        assert_eq!(&got[2..], b"refs/tags/v1.0");
    }

    #[test]
    fn encode_list_refs_shape() {
        let got = encode_list_refs("refs/heads/").unwrap();
        let len = u16::from_le_bytes([got[0], got[1]]);
        assert_eq!(len as usize, "refs/heads/".len());
        assert_eq!(&got[2..], b"refs/heads/");
    }

    // --- Ref-list decoder -------------------------------------------------

    #[test]
    fn decode_ref_list_roundtrip() {
        let h1 = [1u8; 32];
        let h2 = [2u8; 32];
        let mut payload = Vec::new();
        payload.extend_from_slice(&2u32.to_le_bytes());
        // entry 1: "main"
        payload.extend_from_slice(&4u16.to_le_bytes());
        payload.extend_from_slice(b"main");
        payload.extend_from_slice(&h1);
        // entry 2: "dev"
        payload.extend_from_slice(&3u16.to_le_bytes());
        payload.extend_from_slice(b"dev");
        payload.extend_from_slice(&h2);
        let refs = decode_ref_list(&payload).unwrap();
        assert_eq!(refs.len(), 2);
        assert_eq!(refs[0].name, "main");
        assert_eq!(refs[0].hash, Some(h1));
        assert_eq!(refs[1].name, "dev");
        assert_eq!(refs[1].hash, Some(h2));
    }

    #[test]
    fn decode_ref_list_rejects_impossible_count() {
        // count=1000 but only 4 bytes of payload.
        let payload = 1000u32.to_le_bytes().to_vec();
        assert!(decode_ref_list(&payload).is_err());
    }

    #[test]
    fn decode_ref_list_rejects_invalid_ref_name() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&1u32.to_le_bytes());
        payload.extend_from_slice(&9u16.to_le_bytes());
        payload.extend_from_slice(b"bad space"); // space is disallowed
        payload.extend_from_slice(&[0u8; 32]);
        assert!(decode_ref_list(&payload).is_err());
    }

    #[test]
    fn decode_ref_list_empty() {
        let payload = 0u32.to_le_bytes().to_vec();
        let refs = decode_ref_list(&payload).unwrap();
        assert!(refs.is_empty());
    }

    // --- HELLO validation -------------------------------------------------

    #[test]
    fn validate_server_hello_ok() {
        let mut p = Vec::new();
        p.push(SSH_PROTO_VERSION);
        p.push(4);
        p.extend_from_slice(b"mkit");
        assert!(validate_server_hello(&p).is_ok());
    }

    #[test]
    fn validate_server_hello_rejects_future_proto() {
        let p = vec![0x02u8, 1, b'x'];
        assert!(validate_server_hello(&p).is_err());
    }

    #[test]
    fn validate_server_hello_rejects_truncated() {
        assert!(validate_server_hello(&[0x01]).is_err());
        assert!(validate_server_hello(&[0x01, 0xC8, b'x']).is_err()); // len 200 in 3 bytes
    }

    // --- Framing smoke: round-trip every verb through a mock stream ------

    /// Framing smoke-test helper: given a client `op` + payload, produce
    /// what the client would write, then check a prepared server reply
    /// round-trips through the core decoder. This exercises exactly the
    /// bytes that `write_frame` / `read_frame` push in production.
    fn framing_roundtrip(op: u8, payload: &[u8], reply_status: u8, reply_body: &[u8]) {
        let client_out = encode_frame(op, payload).unwrap();
        assert_eq!(client_out[0], op);
        let client_payload_len =
            u32::from_le_bytes([client_out[1], client_out[2], client_out[3], client_out[4]])
                as usize;
        assert_eq!(client_payload_len, payload.len());
        let (decoded_op, decoded_payload) = decode_frame(&client_out).unwrap();
        assert_eq!(decoded_op, op);
        assert_eq!(decoded_payload, payload);

        let server_out = server_frame(reply_status, reply_body);
        let (s, p) = decode_frame(&server_out).unwrap();
        assert_eq!(s, reply_status);
        assert_eq!(p, reply_body);
    }

    #[test]
    fn smoke_hello_frame() {
        let payload =
            encode_hello_payload(SSH_PROTO_VERSION, SSH_BINARY_NAME, "mkit 0.1.0").unwrap();
        let hello = server_hello_ok();
        framing_roundtrip(OP_HELLO, &payload, STATUS_OK, &hello[FRAME_HEADER_LEN..]);
    }

    #[test]
    fn smoke_upload_pack_frame() {
        let mut payload = Vec::with_capacity(32 + 4);
        payload.extend_from_slice(&[0xAA; 32]);
        payload.extend_from_slice(b"data");
        framing_roundtrip(OP_UPLOAD_PACK, &payload, STATUS_OK, &[]);
    }

    #[test]
    fn smoke_download_pack_frame() {
        let digest = [0xBBu8; 32];
        framing_roundtrip(OP_DOWNLOAD_PACK, &digest, STATUS_OK, b"pack-bytes");
    }

    #[test]
    fn smoke_pack_exists_frame() {
        let digest = [0xCCu8; 32];
        framing_roundtrip(OP_PACK_EXISTS, &digest, STATUS_OK, &[1u8]);
    }

    #[test]
    fn smoke_write_ref_frame() {
        let payload = encode_write_ref("refs/heads/main", &[0xDDu8; 32]).unwrap();
        framing_roundtrip(OP_WRITE_REF, &payload, STATUS_OK, &[]);
    }

    #[test]
    fn smoke_update_ref_frame() {
        let payload = encode_update_ref(
            "refs/heads/main",
            RefWriteCondition::Match([0xEEu8; 32]),
            &[0xFFu8; 32],
        )
        .unwrap();
        framing_roundtrip(OP_UPDATE_REF, &payload, STATUS_OK, &[]);
    }

    #[test]
    fn smoke_read_ref_frame() {
        let payload = encode_read_ref("refs/heads/main").unwrap();
        framing_roundtrip(OP_READ_REF, &payload, STATUS_OK, &[0x42u8; 32]);
    }

    #[test]
    fn smoke_list_refs_frame() {
        let payload = encode_list_refs("refs/heads/").unwrap();
        let mut reply = Vec::new();
        reply.extend_from_slice(&0u32.to_le_bytes());
        framing_roundtrip(OP_LIST_REFS, &payload, STATUS_OK, &reply);
    }

    #[test]
    fn smoke_hello_first_before_any_verb() {
        // Sanity: the constant wiring says proto=1, name="mkit", and
        // the crate's own pkg version is surfaced as the client string.
        let payload =
            encode_hello_payload(SSH_PROTO_VERSION, SSH_BINARY_NAME, CLIENT_VERSION).unwrap();
        assert_eq!(payload[0], 1);
        assert_eq!(payload[1] as usize, SSH_BINARY_NAME.len());
        assert_eq!(&payload[2..2 + SSH_BINARY_NAME.len()], b"mkit");
        let ver_len_idx = 2 + SSH_BINARY_NAME.len();
        let ver_len = payload[ver_len_idx] as usize;
        assert_eq!(ver_len, CLIENT_VERSION.len());
        assert!(CLIENT_VERSION.starts_with("mkit "));
    }

    // --- Command wiring --------------------------------------------------

    #[test]
    fn build_ssh_command_default_flags() {
        let t = SshTarget {
            user: "alice".into(),
            host: "host.example.com".into(),
            port: None,
            path: "/repos/project".into(),
        };
        let opts = SshOptions::default();
        let cmd = build_ssh_command(&t, &opts);
        let args: Vec<String> = cmd
            .get_args()
            .map(|s| s.to_string_lossy().to_string())
            .collect();
        assert!(args.iter().any(|a| a == "alice@host.example.com"));
        assert!(args.iter().any(|a| a == "mkit"));
        assert!(args.iter().any(|a| a == "serve"));
        assert!(args.iter().any(|a| a == "/repos/project"));
        // Defaults pin BatchMode + accept-new.
        assert!(args.iter().any(|a| a == "BatchMode=yes"));
        assert!(args.iter().any(|a| a == "StrictHostKeyChecking=accept-new"));
    }

    #[test]
    fn build_ssh_command_with_port_and_options() {
        let t = SshTarget {
            user: "alice".into(),
            host: "host.example.com".into(),
            port: Some(2222),
            path: "repos/project".into(),
        };
        let opts = SshOptions {
            strict_host_key_checking: "yes".into(),
            user_known_hosts_file: "/tmp/kh".into(),
            identity_file: "/tmp/id".into(),
        };
        let cmd = build_ssh_command(&t, &opts);
        let args: Vec<String> = cmd
            .get_args()
            .map(|s| s.to_string_lossy().to_string())
            .collect();
        assert!(args.iter().any(|a| a == "-p"));
        assert!(args.iter().any(|a| a == "2222"));
        assert!(args.iter().any(|a| a == "StrictHostKeyChecking=yes"));
        assert!(args.iter().any(|a| a == "UserKnownHostsFile=/tmp/kh"));
        assert!(args.iter().any(|a| a == "-i"));
        assert!(args.iter().any(|a| a == "/tmp/id"));
        // When the user explicitly pinned StrictHostKeyChecking, we do
        // NOT also add the accept-new fallback.
        assert!(!args.iter().any(|a| a == "StrictHostKeyChecking=accept-new"));
    }

    // ------------------------------------------------------------------
    // E8: encoders must refuse oversize names instead of truncating
    // ------------------------------------------------------------------

    #[test]
    fn encode_write_ref_rejects_oversize_name() {
        let name = "a".repeat(70_000);
        let h = [0u8; 32];
        let err = encode_write_ref(&name, &h)
            .expect_err("70_000-byte name must error, not silently truncate");
        assert!(matches!(err, TransportError::InvalidRef(_)));
    }

    #[test]
    fn encode_write_ref_rejects_name_at_max_ref_name() {
        // MAX_REF_NAME = 4096; the encoder must reject > MAX_REF_NAME
        // even without relying on the Transport impl to have pre-checked.
        // 4097 bytes is one past the cap.
        let name = "a".repeat(MAX_REF_NAME + 1);
        let h = [0u8; 32];
        assert!(encode_write_ref(&name, &h).is_err());
    }

    #[test]
    fn encode_write_ref_accepts_short_name() {
        // Regression: 100-byte valid name still round-trips.
        let name = "a".repeat(100);
        let h = [0u8; 32];
        let got = encode_write_ref(&name, &h).expect("short name encodes");
        let name_len = u16::from_le_bytes([got[0], got[1]]);
        assert_eq!(name_len as usize, 100);
    }

    #[test]
    fn encode_update_ref_rejects_oversize_name() {
        let name = "a".repeat(70_000);
        let h = [0u8; 32];
        assert!(encode_update_ref(&name, RefWriteCondition::Any, &h).is_err());
    }

    #[test]
    fn encode_read_ref_rejects_oversize_name() {
        let name = "a".repeat(70_000);
        assert!(encode_read_ref(&name).is_err());
    }

    #[test]
    fn encode_list_refs_rejects_oversize_prefix() {
        let prefix = "a".repeat(70_000);
        assert!(encode_list_refs(&prefix).is_err());
    }

    #[test]
    fn encode_ref_list_rejects_oversize_name_entry() {
        let long = "a".repeat(70_000);
        let refs = vec![Ref {
            name: long,
            hash: Some([0u8; 32]),
        }];
        assert!(encode_ref_list(&refs).is_err());
    }
}
