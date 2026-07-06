#![doc = include_str!("../README.md")]
//!
//! mkit encrypted-stream transport.
//!
//! Implements [`mkit_core::protocol::Transport`] by layering the
//! existing mkit-rpc [`SshFrame`] message set on top of an
//! authenticated, encrypted byte stream provided by
//! [`commonware_stream::encrypted`]. The crate ships the full client
//! and server stack: in-process round-trips, a real TCP dial helper
//! (`tcp::connect_tcp`), a TCP listener with peer-authorization policy
//! (`tcp::serve_tcp_with_policy_and_bounds`), and `mkit+enc://` URL
//! parsing ([`url::parse_enc_url`]). It is consumed in production by
//! `mkit-cli`'s remote dispatch and `mkit serve --listen-enc`.
//!
//! ## Layering (see SPEC-TRANSPORT-ENC for the full picture)
//!
//! ```text
//!   ┌──────────────────────────────────────────────┐
//!   │ mkit-rpc::SshFrame  (verb-level protobuf)    │  app payload
//!   ├──────────────────────────────────────────────┤
//!   │ length-prefixed framing (4-byte LE u32)      │  same as ssh transport
//!   ├──────────────────────────────────────────────┤
//!   │ commonware-stream::encrypted                 │  ChaCha20-Poly1305
//!   │   X25519 ephemeral DH + ed25519 static auth  │  + handshake transcript
//!   ├──────────────────────────────────────────────┤
//!   │ commonware-runtime Sink / Stream             │  any byte transport
//!   └──────────────────────────────────────────────┘
//! ```
//!
//! The encrypted layer guarantees mutual authentication (client knows
//! the server's static `ed25519` public key out-of-band; server bouncer
//! decides whether to accept the client's key), forward secrecy via
//! ephemeral X25519, and per-direction nonce-derived AEAD keys. The
//! transport above it is the same length-prefixed `SshFrame` wire used
//! by `mkit-transport-ssh` — keeping a single source of truth for verb
//! framing across encrypted and SSH-tunnelled paths.
//!
//! ## Async/sync shim
//!
//! [`mkit_core::protocol::Transport`] is a synchronous, object-safe
//! trait; `commonware-stream::encrypted` is async on
//! `commonware-runtime`. This is reconciled with a deliberately tiny
//! shim: every verb implementation acquires the [`EncSession`]'s
//! `Mutex`, then drives a single round-trip future to completion via a
//! caller-provided [`Executor`]. In-process tests use a
//! `deterministic::Runner` executor; production TCP callers use the
//! tokio-backed `tcp::TokioExecutor`.
//!
//! ## Entry points
//!
//! - In-process round-trip via [`commonware_runtime::mocks::Channel`],
//!   wrapped with [`EncTransport::from_session`] from an
//!   already-established [`EncSession`].
//! - Real TCP via `tcp::connect_tcp` (client) and
//!   `tcp::serve_tcp_with_policy_and_bounds` (server).
//! - `mkit+enc://` URL parsing via [`url::parse_enc_url`]. See
//!   [docs/specs/SPEC-TRANSPORT-ENC.md](../../../docs/specs/SPEC-TRANSPORT-ENC.md)
//!   §6.

#![forbid(unsafe_code)]
// Wire-frame fields are `Option<T>` (Edition 2023 explicit presence).
// Same allowance as `mkit-transport-ssh`.
#![allow(clippy::ref_option)]
#![allow(clippy::items_after_statements)]
#![allow(clippy::manual_let_else)]
// Allow `*as usize` casts on bounded pack sizes.
#![allow(clippy::cast_possible_truncation)]

pub mod url;

// Real-TCP entry points. Feature-gated so consumers that only want the
// in-process path build without dragging tokio in.
#[cfg(feature = "tcp")]
pub mod tcp;
#[cfg(feature = "tcp")]
pub mod tokio_io;

#[cfg(feature = "tcp")]
pub use tcp::{
    PeerPolicy, TokioExecutor, connect_tcp, connect_tcp_with_executor,
    serve_tcp_with_policy_and_bounds,
};

/// Re-export of the encrypted-stream `Sender` / `Receiver` types
/// downstream callers need to plug a custom server-side verb loop on
/// top of an [`EncSession`]. The `mkit serve --listen-enc` dispatch
/// lives in `mkit-cli` and consumes this re-export rather than
/// depending on `commonware-stream` directly; that keeps the CLI
/// crate's transitive surface area centred on `mkit-transport-enc`.
pub use commonware_stream::encrypted::{Receiver as EncReceiver, Sender as EncSender};

use std::sync::Mutex;
use std::time::Duration;

use buffa::Message;
use commonware_cryptography::ed25519::PrivateKey;
use commonware_runtime::{Sink, Stream};
use commonware_stream::encrypted::{Config as EncConfig, Receiver, Sender};

use mkit_core::hash::Hash;
use mkit_core::protocol::{PackKey, Transport, TransportError, TransportResult};
use mkit_core::refs::{Ref, RefWriteCondition, validate_ref_name, validate_ref_prefix};
use mkit_rpc::mkit::rpc::v1::ProtocolVersion;
use mkit_rpc::mkit::rpc::v1::ssh::{
    DownloadPack, Hello, ListRefs, PackChunk, PackExists, ReadRef, SshFrame, UpdateRef, UploadPack,
    ssh_frame,
};
use mkit_rpc::{
    CHUNK_DATA_MAX, MAX_FRAME_BYTES, MAX_REF_NAME, body_name, cond_to_wire, ref_entry_to_ref,
    rpc_error_to_transport, unexpected_frame,
};

use mkit_core::protocol::{PACK_BODY_LIMIT, PACK_BODY_LIMIT_USIZE};

/// Client identification string sent in the `Hello` frame. Inherits
/// the workspace version so a release bump propagates automatically.
const CLIENT_ID: &str = concat!("mkit ", env!("CARGO_PKG_VERSION"));

/// Application namespace bound into the
/// [`commonware_stream::encrypted`] handshake transcript. Prevents
/// cross-application replay even if peers share `ed25519` keys with
/// some other commonware-stream user. See SPEC-TRANSPORT-ENC §2.1.
pub const HANDSHAKE_NAMESPACE: &[u8] = b"mkit/transport-enc/v1";

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors raised while bringing up the encrypted session — before the
/// first [`Transport`] verb is ever called.
#[derive(Debug, thiserror::Error)]
pub enum EncInitError {
    /// The peer's `ed25519` public key was rejected during the
    /// handshake (server-side `bouncer` returned `false`, or our
    /// dialer's `peer` argument did not match the actual remote key).
    #[error("peer rejected during handshake")]
    PeerRejected,
    /// commonware-stream surfaced a handshake-layer error
    /// (timeout, codec, signature failure, …).
    #[error("encrypted handshake failed: {0}")]
    HandshakeFailed(String),
    /// Application-level `Hello` exchange (after the encrypted
    /// handshake completes) failed.
    #[error("application hello failed: {0}")]
    AppHelloFailed(String),
}

impl From<commonware_stream::encrypted::Error> for EncInitError {
    fn from(value: commonware_stream::encrypted::Error) -> Self {
        match value {
            commonware_stream::encrypted::Error::PeerRejected(_) => EncInitError::PeerRejected,
            other => EncInitError::HandshakeFailed(other.to_string()),
        }
    }
}

// ---------------------------------------------------------------------------
// Session state
// ---------------------------------------------------------------------------

/// One peer's half of an established encrypted session: the
/// post-handshake [`Sender`] and [`Receiver`] from
/// [`commonware_stream::encrypted`]. Wrapped in a `Mutex` inside
/// [`EncTransport`] so `&self` Transport methods can mutate them.
///
/// Generic over the underlying [`Sink`] / [`Stream`] so the same code
/// path works against in-process [`commonware_runtime::mocks::Channel`]
/// in tests and against real TCP sockets in production.
pub struct EncSession<I: Stream, O: Sink> {
    sender: Sender<O>,
    receiver: Receiver<I>,
}

impl<I: Stream, O: Sink> std::fmt::Debug for EncSession<I, O> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncSession").finish_non_exhaustive()
    }
}

impl<I: Stream, O: Sink> EncSession<I, O> {
    /// Construct an [`EncSession`] from the [`Sender`] / [`Receiver`]
    /// pair handed back by [`commonware_stream::encrypted::dial`] or
    /// [`commonware_stream::encrypted::listen`]. Callers are expected
    /// to have driven the encrypted handshake to completion already.
    #[must_use]
    pub fn new(sender: Sender<O>, receiver: Receiver<I>) -> Self {
        Self { sender, receiver }
    }

    /// Decompose into the raw encrypted-stream halves. Useful for
    /// server-side callers (the accept loop's `serve_fn` in
    /// `tcp::serve_tcp_with_policy_and_bounds`) that want to run a
    /// custom request-response loop instead of
    /// going through the [`EncTransport`] client surface. The
    /// returned [`Sender`] / [`Receiver`] still share the same cipher
    /// state — drop either to tear the session down.
    #[must_use]
    pub fn into_parts(self) -> (Sender<O>, Receiver<I>) {
        (self.sender, self.receiver)
    }
}

// ---------------------------------------------------------------------------
// Executor trait — re-exported from mkit-core::protocol::async_shim
// ---------------------------------------------------------------------------

/// Pluggable async/sync shim. Re-exported here for the convenience of
/// callers that import `mkit_transport_enc::Executor`. New code MAY
/// prefer [`mkit_core::protocol::async_shim::Executor`] directly — the
/// trait is generic infrastructure that also serves other consumers and
/// doesn't strictly belong in a transport crate.
pub use mkit_core::protocol::async_shim::Executor;

// ---------------------------------------------------------------------------
// Transport implementation
// ---------------------------------------------------------------------------

/// Encrypted-stream transport implementing
/// [`mkit_core::protocol::Transport`].
///
/// Each verb acquires the inner [`EncSession`]'s lock, sends one
/// [`SshFrame`] request, reads one response, and unlocks. The
/// underlying ChaCha20-Poly1305 cipher state advances per-message in
/// both directions; pipelining across concurrent callers is therefore
/// **not** supported (same posture as `mkit-transport-ssh`).
pub struct EncTransport<I: Stream, O: Sink, E: Executor> {
    session: Mutex<EncSession<I, O>>,
    executor: E,
    /// Remote host (for diagnostics / URL round-tripping). Carried but
    /// unused for routing — the session is already established by the
    /// time this struct exists; surfaced via the `Debug` impl so
    /// logging stays useful.
    host: String,
    /// Remote port. Same diagnostic-only caveat as `host`.
    port: u16,
}

impl<I: Stream, O: Sink, E: Executor> std::fmt::Debug for EncTransport<I, O, E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncTransport")
            .field("host", &self.host)
            .field("port", &self.port)
            .finish_non_exhaustive()
    }
}

impl<I: Stream, O: Sink, E: Executor> EncTransport<I, O, E> {
    /// Wrap an already-established [`EncSession`] in an [`EncTransport`].
    ///
    /// The application-level [`Hello`] handshake is performed eagerly
    /// here, so a successful return guarantees the first verb call
    /// lands on a v1 mkit peer.
    ///
    /// Tests use this constructor after driving the commonware-stream
    /// handshake manually; production TCP callers use `tcp::connect_tcp`,
    /// which folds dial + handshake + Hello and then calls this.
    pub fn from_session(
        session: EncSession<I, O>,
        executor: E,
        host: impl Into<String>,
        port: u16,
    ) -> Result<Self, EncInitError> {
        let mut me = Self {
            session: Mutex::new(session),
            executor,
            host: host.into(),
            port,
        };
        me.app_hello()?;
        Ok(me)
    }

    fn app_hello(&mut self) -> Result<(), EncInitError> {
        let hello = SshFrame {
            body: Some(ssh_frame::Body::Hello(Box::new(
                Hello::default()
                    .with_proto(ProtocolVersion::ProtocolVersion1)
                    .with_client_id(CLIENT_ID),
            ))),
            ..Default::default()
        };
        // A poisoned session mutex means a prior holder panicked. As a library
        // we surface that as an error rather than panicking the host process.
        let session = self
            .session
            .get_mut()
            .map_err(|_| EncInitError::AppHelloFailed("session mutex poisoned".into()))?;
        let executor = &self.executor;
        executor.block_on(async {
            send_frame_init(&mut session.sender, &hello)
                .await
                .map_err(|e| EncInitError::AppHelloFailed(format!("send hello: {e}")))?;
            let resp = recv_frame_init(&mut session.receiver)
                .await
                .map_err(|e| EncInitError::AppHelloFailed(format!("read hello reply: {e}")))?;
            match resp.body {
                Some(ssh_frame::Body::HelloResponse(h)) => {
                    let proto = h.proto.unwrap_or_default();
                    if proto != ProtocolVersion::ProtocolVersion1 {
                        return Err(EncInitError::AppHelloFailed(format!(
                            "server proto_version {} != expected 1",
                            proto.to_i32()
                        )));
                    }
                    Ok(())
                }
                Some(ssh_frame::Body::Error(e)) => Err(EncInitError::AppHelloFailed(format!(
                    "server error: {}",
                    e.message.unwrap_or_default()
                ))),
                other => Err(EncInitError::AppHelloFailed(format!(
                    "unexpected hello reply: {}",
                    body_name(&other)
                ))),
            }
        })
    }
}

/// Default [`EncConfig`] suitable for mkit's encrypted transport.
///
/// - `namespace`: [`HANDSHAKE_NAMESPACE`] (`mkit/transport-enc/v1`).
/// - `max_message_size`: [`MAX_FRAME_BYTES`] — the same 1 MiB ceiling
///   that bounds the inner length-prefixed `SshFrame` framing layer,
///   so a maximally-sized verb frame still fits in a single encrypted
///   record (matching the cap removes a class of off-by-overhead bugs
///   where one of the two limits sneaks past the other).
/// - Handshake/synchrony bounds default to 30 s / 30 s / 60 s. These
///   are deliberately generous to keep flaky-CI failures out of the
///   in-tree test; production listeners can tighten them via
///   [`default_handshake_config_with_bounds`] /
///   [`EncHandshakeBounds`] per SPEC-TRANSPORT-ENC §4.
#[must_use]
pub fn default_handshake_config(signing_key: PrivateKey) -> EncConfig<PrivateKey> {
    default_handshake_config_with_bounds(signing_key, EncHandshakeBounds::default())
}

/// Operator-tunable handshake/synchrony bounds.
///
/// SPEC-TRANSPORT-ENC §6.2 recommends tightening these to ≤5–10s for
/// real networks. They are exposed so a production listener can pick a
/// tighter ladder than the (deliberately generous) defaults without
/// flaky-CI failures in the in-tree deterministic tests.
#[derive(Debug, Clone, Copy)]
pub struct EncHandshakeBounds {
    /// Acceptable clock skew between the two peers.
    pub synchrony_bound: Duration,
    /// Maximum age of a handshake message before it is rejected.
    pub max_handshake_age: Duration,
    /// Overall deadline for completing the handshake.
    pub handshake_timeout: Duration,
}

impl Default for EncHandshakeBounds {
    fn default() -> Self {
        // Deliberately generous defaults (30s / 30s / 60s) to keep
        // flaky-CI failures out of the in-tree deterministic test.
        Self {
            synchrony_bound: Duration::from_secs(30),
            max_handshake_age: Duration::from_secs(30),
            handshake_timeout: Duration::from_mins(1),
        }
    }
}

/// Like [`default_handshake_config`] but with operator-supplied
/// [`EncHandshakeBounds`].
#[must_use]
pub fn default_handshake_config_with_bounds(
    signing_key: PrivateKey,
    bounds: EncHandshakeBounds,
) -> EncConfig<PrivateKey> {
    EncConfig {
        signing_key,
        namespace: HANDSHAKE_NAMESPACE.to_vec(),
        max_message_size: MAX_FRAME_BYTES,
        synchrony_bound: bounds.synchrony_bound,
        max_handshake_age: bounds.max_handshake_age,
        handshake_timeout: bounds.handshake_timeout,
    }
}

// ---------------------------------------------------------------------------
// Transport trait
// ---------------------------------------------------------------------------

impl<I: Stream, O: Sink, E: Executor> Transport for EncTransport<I, O, E> {
    fn upload_pack(&self, bytes: &[u8], key: &PackKey) -> TransportResult<()> {
        let mut session = self
            .session
            .lock()
            .map_err(|_| TransportError::ConnectionFailed)?;

        // Header frame.
        let header = SshFrame {
            body: Some(ssh_frame::Body::UploadPack(Box::new(
                UploadPack::default()
                    .with_pack_id(key.as_bytes().to_vec())
                    .with_total_bytes(bytes.len() as u64),
            ))),
            ..Default::default()
        };
        self.executor
            .block_on(send_frame(&mut session.sender, &header))?;

        // Body chunks. `CHUNK_DATA_MAX` lives in `mkit_rpc` so the
        // ssh and enc transports cannot drift on the bound, keeping the
        // inner SshFrame under `MAX_FRAME_BYTES` after protobuf overhead.
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
            self.executor
                .block_on(send_frame(&mut session.sender, &chunk))?;
            offset += (end - iter_pos) as u64;
            iter_pos = end;
        }
        if total == 0 {
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
            self.executor
                .block_on(send_frame(&mut session.sender, &chunk))?;
        }

        let resp = self.executor.block_on(recv_frame(&mut session.receiver))?;
        match resp.body {
            Some(ssh_frame::Body::UploadPackResponse(_)) => Ok(()),
            Some(ssh_frame::Body::Error(e)) => Err(rpc_error_to_transport(*e, "enc")),
            other => Err(unexpected_frame("enc", "UploadPackResponse", other)),
        }
    }

    fn download_pack(&self, key: &PackKey) -> TransportResult<Vec<u8>> {
        let mut session = self
            .session
            .lock()
            .map_err(|_| TransportError::ConnectionFailed)?;

        let req = SshFrame {
            body: Some(ssh_frame::Body::DownloadPack(Box::new(
                DownloadPack::default().with_pack_id(key.as_bytes().to_vec()),
            ))),
            ..Default::default()
        };
        self.executor
            .block_on(send_frame(&mut session.sender, &req))?;

        let header = self.executor.block_on(recv_frame(&mut session.receiver))?;
        let total = match header.body {
            Some(ssh_frame::Body::DownloadPackHeader(h)) => h.total_bytes.unwrap_or(0),
            Some(ssh_frame::Body::Error(e)) => return Err(rpc_error_to_transport(*e, "enc")),
            other => return Err(unexpected_frame("enc", "DownloadPackHeader", other)),
        };

        if total > PACK_BODY_LIMIT {
            return Err(TransportError::RemoteError(
                "server-advertised pack size exceeds client cap".into(),
            ));
        }

        let initial = core::cmp::min(total as usize, PACK_BODY_LIMIT_USIZE);
        let mut out = Vec::with_capacity(initial);
        loop {
            let chunk_frame = self.executor.block_on(recv_frame(&mut session.receiver))?;
            match chunk_frame.body {
                Some(ssh_frame::Body::PackChunk(c)) => {
                    let data = c.data.unwrap_or_default();
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
                Some(ssh_frame::Body::Error(e)) => return Err(rpc_error_to_transport(*e, "enc")),
                other => return Err(unexpected_frame("enc", "PackChunk", other)),
            }
        }
        Ok(out)
    }

    fn pack_exists(&self, key: &PackKey) -> TransportResult<bool> {
        let mut session = self
            .session
            .lock()
            .map_err(|_| TransportError::ConnectionFailed)?;
        let req = SshFrame {
            body: Some(ssh_frame::Body::PackExists(Box::new(
                PackExists::default().with_pack_id(key.as_bytes().to_vec()),
            ))),
            ..Default::default()
        };
        self.executor
            .block_on(send_frame(&mut session.sender, &req))?;
        let resp = self.executor.block_on(recv_frame(&mut session.receiver))?;
        match resp.body {
            Some(ssh_frame::Body::PackExistsResponse(r)) => Ok(r.exists.unwrap_or(false)),
            Some(ssh_frame::Body::Error(e)) => Err(rpc_error_to_transport(*e, "enc")),
            other => Err(unexpected_frame("enc", "PackExistsResponse", other)),
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

        let mut session = self
            .session
            .lock()
            .map_err(|_| TransportError::ConnectionFailed)?;

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
        self.executor
            .block_on(send_frame(&mut session.sender, &req))?;

        let resp = self.executor.block_on(recv_frame(&mut session.receiver))?;
        match resp.body {
            Some(ssh_frame::Body::UpdateRefResponse(_)) => Ok(()),
            Some(ssh_frame::Body::Error(e)) => {
                if e.code
                    .is_some_and(|c| c == mkit_rpc::mkit::rpc::v1::ErrorCode::InvalidRequest)
                    && !matches!(condition, RefWriteCondition::Any)
                {
                    Err(TransportError::RefConflict)
                } else {
                    Err(rpc_error_to_transport(*e, "enc"))
                }
            }
            other => Err(unexpected_frame("enc", "UpdateRefResponse", other)),
        }
    }

    fn read_ref(&self, name: &str) -> TransportResult<Option<Hash>> {
        if !validate_ref_name(name) {
            return Err(TransportError::InvalidRef(name.into()));
        }
        if name.len() > MAX_REF_NAME {
            return Err(TransportError::InvalidRef("ref name too long".into()));
        }
        let mut session = self
            .session
            .lock()
            .map_err(|_| TransportError::ConnectionFailed)?;
        let req = SshFrame {
            body: Some(ssh_frame::Body::ReadRef(Box::new(
                ReadRef::default().with_name(name),
            ))),
            ..Default::default()
        };
        self.executor
            .block_on(send_frame(&mut session.sender, &req))?;
        let resp = self.executor.block_on(recv_frame(&mut session.receiver))?;
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
            Some(ssh_frame::Body::Error(e)) => Err(rpc_error_to_transport(*e, "enc")),
            other => Err(unexpected_frame("enc", "ReadRefResponse", other)),
        }
    }

    fn list_refs(&self, prefix: &str) -> TransportResult<Vec<Ref>> {
        if !prefix.is_empty() && !validate_ref_prefix(prefix) {
            return Err(TransportError::InvalidRef(prefix.into()));
        }
        if prefix.len() > MAX_REF_NAME {
            return Err(TransportError::InvalidRef("ref prefix too long".into()));
        }
        let mut session = self
            .session
            .lock()
            .map_err(|_| TransportError::ConnectionFailed)?;
        let req = SshFrame {
            body: Some(ssh_frame::Body::ListRefs(Box::new(
                ListRefs::default().with_prefix(prefix),
            ))),
            ..Default::default()
        };
        self.executor
            .block_on(send_frame(&mut session.sender, &req))?;
        let resp = self.executor.block_on(recv_frame(&mut session.receiver))?;
        match resp.body {
            Some(ssh_frame::Body::ListRefsResponse(r)) => r
                .refs
                .into_iter()
                .map(ref_entry_to_ref)
                .collect::<TransportResult<Vec<_>>>(),
            Some(ssh_frame::Body::Error(e)) => Err(rpc_error_to_transport(*e, "enc")),
            other => Err(unexpected_frame("enc", "ListRefsResponse", other)),
        }
    }
}

// ---------------------------------------------------------------------------
// SshFrame ↔ encrypted-stream framing helpers
// ---------------------------------------------------------------------------

/// Send one [`SshFrame`] over the encrypted stream.
///
/// The encrypted layer already provides message framing (one varint
/// prefix per ciphertext record), so we do **not** prepend the
/// length-prefixed wire used by `mkit-transport-ssh` — the inner
/// `SshFrame` rides as a single protobuf payload per encrypted record.
/// This is the only deliberate departure from the SSH transport's
/// wire and is recorded in SPEC-TRANSPORT-ENC §3.1.
///
/// Errors from the cipher layer collapse to
/// [`TransportError::ConnectionFailed`]; preserving the detailed
/// reason would require an orphan-rules workaround and isn't worth it
/// — callers retry on `ConnectionFailed` regardless.
pub async fn send_frame<O: Sink>(sender: &mut Sender<O>, msg: &SshFrame) -> TransportResult<()> {
    let body = msg.encode_to_vec();
    sender.send(body).await.map_err(stream_err)
}

/// Receive one [`SshFrame`]. See [`send_frame`] for the wire choice
/// and error-collapse rationale.
pub async fn recv_frame<I: Stream>(receiver: &mut Receiver<I>) -> TransportResult<SshFrame> {
    let bufs = receiver.recv().await.map_err(stream_err)?;
    let buf = bufs.coalesce();
    // The cipher layer frames records but does not know the protocol's
    // 1 MiB frame cap — `frame_decode_options` re-states it (plus the
    // recursion limit) at the decode itself.
    mkit_rpc::frame_decode_options()
        .decode_from_slice(buf.as_ref())
        .map_err(|_| TransportError::ProtocolError)
}

/// Receive one [`SshFrame`] but fail with [`TransportError::ConnectionFailed`]
/// if no complete frame arrives within `idle`.
///
/// This is the post-handshake slow-loris guard for the encrypted
/// listener: a peer that completes the handshake but then stalls the
/// verb loop (or an upload's chunk stream) must not be able to pin a
/// tokio worker + socket indefinitely. The handshake itself is already
/// bounded by [`default_handshake_config`]; this caps every *subsequent*
/// frame read.
///
/// Requires a tokio runtime context (the
/// [`tcp::serve_tcp_with_policy_and_bounds`] listener provides one), so
/// it is gated on the `tcp` feature.
#[cfg(feature = "tcp")]
pub async fn recv_frame_within<I: Stream>(
    receiver: &mut Receiver<I>,
    idle: core::time::Duration,
) -> TransportResult<SshFrame> {
    match tokio::time::timeout(idle, recv_frame(receiver)).await {
        Ok(res) => res,
        // Timed out waiting for the next frame — treat the peer as gone.
        Err(_elapsed) => Err(TransportError::ConnectionFailed),
    }
}

/// Variant of [`send_frame`] used during the application-level Hello
/// handshake — returns the cipher's [`commonware_stream::encrypted::Error`]
/// so [`EncInitError::AppHelloFailed`] can carry the precise reason.
async fn send_frame_init<O: Sink>(
    sender: &mut Sender<O>,
    msg: &SshFrame,
) -> Result<(), commonware_stream::encrypted::Error> {
    sender.send(msg.encode_to_vec()).await
}

/// Variant of [`recv_frame`] used during the application-level Hello
/// handshake. See [`send_frame_init`] for the error-preserving rationale.
async fn recv_frame_init<I: Stream>(
    receiver: &mut Receiver<I>,
) -> Result<SshFrame, commonware_stream::encrypted::Error> {
    let bufs = receiver.recv().await?;
    let buf = bufs.coalesce();
    mkit_rpc::frame_decode_options()
        .decode_from_slice(buf.as_ref())
        .map_err(|_| {
            commonware_stream::encrypted::Error::UnableToDecode(commonware_codec::Error::Invalid(
                "SshFrame",
                "decode failed",
            ))
        })
}

/// Collapse a commonware-stream error to [`TransportError::ConnectionFailed`].
///
/// Orphan rules prevent `impl From<encrypted::Error> for TransportError`
/// here (neither type is local), so each verb threads `.map_err(stream_err)`
/// on its `send_frame` / `recv_frame` calls. Callers retry on
/// `ConnectionFailed` regardless of the cipher's reason — preserving the
/// detailed reason is not worth the orphan-rules workaround.
fn stream_err(_: commonware_stream::encrypted::Error) -> TransportError {
    TransportError::ConnectionFailed
}

// ---------------------------------------------------------------------------
// (Shared frame helpers now live in `mkit_rpc::helpers` — re-used by
// both this crate and `mkit-transport-ssh`, keeping a single source of
// truth for verb framing across the encrypted and SSH paths.)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    //! In-process round-trip tests for the encrypted transport. All
    //! tests run inside [`commonware_runtime::deterministic::Runner`]
    //! so they exercise the same async code paths that production
    //! (tokio) wiring hits, without depending on wall-clock time or a
    //! multi-threaded executor.
    //!
    //! The Transport-trait sync facade is **not** exercised here — its
    //! `Executor` shim is only useful from a *separate* runtime than
    //! the one driving the server task, which is covered by the TCP
    //! integration tests in `tcp.rs` and the e2e harness under
    //! `tests/`. These tests assert the wire-level invariants
    //! (handshake correctness, ciphertext-on-wire, peer-rejection) by
    //! driving both halves' async helpers directly.
    //!
    //! See SPEC-TRANSPORT-ENC §5 for the test plan.

    use super::*;
    use commonware_cryptography::Signer;
    use commonware_cryptography::ed25519::PrivateKey;
    use commonware_runtime::{
        Error as RuntimeError, IoBuf, IoBufs, Runner as _, Spawner as _, Supervisor as _,
        deterministic, mocks,
    };
    use commonware_stream::encrypted::{
        Error as EncryptedError, Receiver as EncReceiver, Sender as EncSender, dial, listen,
    };
    use commonware_utils::sync::Mutex as CwMutex;
    use mkit_rpc::mkit::rpc::v1::ssh::{HelloResponse, ListRefsResponse, list_refs_response};
    use std::sync::Arc;

    /// `Sink` wrapper that also stashes every chunk into a shared
    /// `Vec<Vec<u8>>` so the test can assert the bytes-on-wire are
    /// ciphertext, not plaintext. Mirrors the `CountingSink` pattern
    /// from commonware-stream's own tests but captures payload bytes
    /// instead of just chunk counts.
    struct CapturingSink<S> {
        inner: S,
        captured: Arc<CwMutex<Vec<u8>>>,
    }

    impl<S> CapturingSink<S> {
        fn new(inner: S, captured: Arc<CwMutex<Vec<u8>>>) -> Self {
            Self { inner, captured }
        }
    }

    impl<S: commonware_runtime::Sink> commonware_runtime::Sink for CapturingSink<S> {
        async fn send(&mut self, bufs: impl Into<IoBufs> + Send) -> Result<(), RuntimeError> {
            let bufs = bufs.into();
            // Coalesce into a single byte run so the assertion can
            // grep for a sentinel plaintext token across all bytes
            // ever written. `coalesce` is zero-copy when only one
            // chunk is present.
            let coalesced = bufs.coalesce();
            {
                let mut guard = self.captured.lock();
                guard.extend_from_slice(coalesced.as_ref());
            }
            // Re-wrap into an IoBufs so the underlying sink still
            // receives the original bytes. `IoBuf::copy_from_slice`
            // returns a frozen `IoBuf` ready to feed back into the
            // sink — no separate freeze step needed.
            let buf = IoBuf::copy_from_slice(coalesced.as_ref());
            self.inner.send(IoBufs::from(buf)).await
        }
    }

    fn test_config(signing_key: PrivateKey) -> EncConfig<PrivateKey> {
        EncConfig {
            signing_key,
            namespace: HANDSHAKE_NAMESPACE.to_vec(),
            max_message_size: 64 * 1024,
            synchrony_bound: Duration::from_secs(5),
            max_handshake_age: Duration::from_secs(5),
            handshake_timeout: Duration::from_secs(5),
        }
    }

    /// Drives the server side of one round-trip: read a `Hello`, reply
    /// `HelloResponse`, read a `ListRefs`, reply with a canned
    /// `ListRefsResponse` carrying the given refs.
    async fn server_one_round_trip<I: Stream, O: Sink>(
        mut sender: EncSender<O>,
        mut receiver: EncReceiver<I>,
        refs_to_return: Vec<(String, [u8; 32])>,
    ) -> Result<(), EncryptedError> {
        // App Hello.
        let hello_frame = recv_frame_init(&mut receiver).await?;
        assert!(matches!(hello_frame.body, Some(ssh_frame::Body::Hello(_))));
        let reply = SshFrame {
            body: Some(ssh_frame::Body::HelloResponse(Box::new(
                HelloResponse::default().with_proto(ProtocolVersion::ProtocolVersion1),
            ))),
            ..Default::default()
        };
        send_frame_init(&mut sender, &reply).await?;

        // ListRefs.
        let lr = recv_frame_init(&mut receiver).await?;
        assert!(matches!(lr.body, Some(ssh_frame::Body::ListRefs(_))));
        let entries: Vec<list_refs_response::RefEntry> = refs_to_return
            .into_iter()
            .map(|(name, h)| {
                list_refs_response::RefEntry::default()
                    .with_name(name)
                    .with_object_id(h.to_vec())
            })
            .collect();
        let resp = ListRefsResponse {
            refs: entries,
            ..Default::default()
        };
        let resp_frame = SshFrame {
            body: Some(ssh_frame::Body::ListRefsResponse(Box::new(resp))),
            ..Default::default()
        };
        send_frame_init(&mut sender, &resp_frame).await?;
        Ok(())
    }

    /// End-to-end in-process round-trip: handshake completes, app-level
    /// Hello succeeds, `ListRefs` returns the canned refs, and the bytes
    /// written by the dialer's sink do **not** contain the plaintext
    /// of a known sentinel ref name — they are ChaCha20-Poly1305
    /// ciphertext.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn hello_and_list_refs_roundtrip_over_ciphertext() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let dialer_key = PrivateKey::from_seed(42);
            let listener_key = PrivateKey::from_seed(24);
            let listener_pub = listener_key.public_key();

            // The dialer writes through a CapturingSink so we can
            // inspect everything that crosses the wire.
            let (raw_dialer_sink, listener_stream) = mocks::Channel::init();
            let (listener_sink, dialer_stream) = mocks::Channel::init();
            let captured = Arc::new(CwMutex::new(Vec::<u8>::new()));
            let dialer_sink = CapturingSink::new(raw_dialer_sink, captured.clone());

            // Server task: accept any peer, then serve one round trip.
            // `child` yields an owned child context (Context lost its
            // `Clone` impl in the commonware 2026.5.x train), leaving
            // `context` itself free to move into the dialer below.
            let listener_handle = context.child("listener").spawn(move |ctx| async move {
                let (_peer, sender, receiver) = listen(
                    ctx,
                    |_| async { true },
                    test_config(listener_key.clone()),
                    listener_stream,
                    listener_sink,
                )
                .await?;
                let canned: Vec<(String, [u8; 32])> = vec![
                    ("refs/heads/main".into(), [0x11; 32]),
                    ("refs/heads/sentinel-plaintext".into(), [0x22; 32]),
                ];
                server_one_round_trip(sender, receiver, canned).await?;
                Ok::<(), EncryptedError>(())
            });

            // Client side: dial the encrypted channel, perform app
            // Hello, then issue a ListRefs and parse the response —
            // exercising the same helper functions the Transport
            // verbs use.
            let (mut dialer_sender, mut dialer_receiver) = dial(
                context,
                test_config(dialer_key.clone()),
                listener_pub,
                dialer_stream,
                dialer_sink,
            )
            .await
            .expect("dial should succeed");

            // App Hello (client side).
            let hello = SshFrame {
                body: Some(ssh_frame::Body::Hello(Box::new(
                    Hello::default()
                        .with_proto(ProtocolVersion::ProtocolVersion1)
                        .with_client_id(CLIENT_ID),
                ))),
                ..Default::default()
            };
            send_frame_init(&mut dialer_sender, &hello)
                .await
                .expect("send hello");
            let hello_resp = recv_frame_init(&mut dialer_receiver)
                .await
                .expect("recv hello response");
            match hello_resp.body {
                Some(ssh_frame::Body::HelloResponse(h)) => {
                    assert_eq!(h.proto, Some(ProtocolVersion::ProtocolVersion1.into()));
                }
                other => panic!("expected HelloResponse, got {}", body_name(&other)),
            }

            // ListRefs round-trip.
            let req = SshFrame {
                body: Some(ssh_frame::Body::ListRefs(Box::new(
                    ListRefs::default().with_prefix("refs/heads/"),
                ))),
                ..Default::default()
            };
            send_frame_init(&mut dialer_sender, &req)
                .await
                .expect("send list_refs");
            let resp = recv_frame_init(&mut dialer_receiver)
                .await
                .expect("recv list_refs response");
            let refs = match resp.body {
                Some(ssh_frame::Body::ListRefsResponse(r)) => r.refs,
                other => panic!("expected ListRefsResponse, got {}", body_name(&other)),
            };
            assert_eq!(refs.len(), 2);
            let names: Vec<_> = refs
                .iter()
                .map(|e| e.name.clone().unwrap_or_default())
                .collect();
            assert!(names.iter().any(|n| n == "refs/heads/main"));
            assert!(names.iter().any(|n| n == "refs/heads/sentinel-plaintext"));

            listener_handle
                .await
                .expect("server task join")
                .expect("server task result");

            // Bytes-on-wire are ciphertext: the sentinel plaintext
            // string is part of the ref name returned by the SERVER
            // (which we don't capture), but the CLIENT sent it as
            // part of the ListRefs prefix path ("refs/heads/"). To
            // catch any plaintext leak on the *dialer* side, search
            // for the literal "refs/heads/" — the most distinctive
            // plaintext the client wrote.
            //
            // If the encrypted layer ever degraded to plaintext, this
            // 11-byte ASCII sequence would appear in the capture. It
            // must NOT.
            let bytes = captured.lock().clone();
            assert!(
                !bytes.is_empty(),
                "captured sink should have observed bytes"
            );
            assert!(
                !contains_subsequence(&bytes, b"refs/heads/"),
                "plaintext leaked through encrypted sink (this would be a critical bug)"
            );
            // Sanity: the captured stream must be non-trivially large —
            // a handshake plus two encrypted frames is well over 100
            // bytes — to rule out the assertion above being vacuously
            // true on an empty buffer.
            assert!(
                bytes.len() > 100,
                "captured stream suspiciously short ({} bytes)",
                bytes.len()
            );
        });
    }

    /// When the listener's bouncer rejects the dialer's public key, the
    /// dialer's `dial` future must resolve to `Error::PeerRejected` —
    /// not hang or surface as an opaque handshake failure.
    ///
    /// This is the lower-level guarantee that
    /// `EncInitError::PeerRejected` propagates from
    /// `commonware_stream::encrypted::Error::PeerRejected`; the
    /// conversion is exercised in [`EncInitError::from`].
    #[test]
    fn handshake_rejection_surfaces_peer_rejected() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let dialer_key = PrivateKey::from_seed(7);
            let listener_key = PrivateKey::from_seed(8);
            let listener_pub = listener_key.public_key();

            let (dialer_sink, listener_stream) = mocks::Channel::init();
            let (listener_sink, dialer_stream) = mocks::Channel::init();

            // The bouncer unconditionally rejects whatever public key
            // the dialer presents.
            let listener_handle = context.child("listener").spawn(move |ctx| async move {
                listen(
                    ctx,
                    |_| async { false },
                    test_config(listener_key.clone()),
                    listener_stream,
                    listener_sink,
                )
                .await
            });

            let dial_result = dial(
                context,
                test_config(dialer_key.clone()),
                listener_pub,
                dialer_stream,
                dialer_sink,
            )
            .await;

            // Server side observes PeerRejected.
            let listener_outcome = listener_handle.await.expect("server task join");
            match listener_outcome {
                Err(EncryptedError::PeerRejected(_)) => {}
                Err(other) => panic!("expected PeerRejected on listener, got {other:?}"),
                Ok(_) => panic!("listener should have rejected the dialer"),
            }

            // Client side: at minimum the dial future must NOT succeed.
            // commonware-stream's current behavior surfaces this on the
            // dialer as either a handshake-layer error (the listener
            // closed the channel mid-handshake) or `StreamClosed`. The
            // public mapping in `EncInitError::from` collapses every
            // non-PeerRejected error to `HandshakeFailed` — either way
            // the dialer cannot establish a session.
            assert!(
                dial_result.is_err(),
                "dialer must not succeed when bouncer rejected its public key"
            );
            // And if the cipher layer ever surfaced PeerRejected
            // directly on the dialer (e.g. in a future commonware
            // release), the mapping must funnel it to
            // EncInitError::PeerRejected.
            if let Err(EncryptedError::PeerRejected(_)) = dial_result {
                let mapped: EncInitError = EncryptedError::PeerRejected(Vec::new()).into();
                assert!(matches!(mapped, EncInitError::PeerRejected));
            }
        });
    }

    /// Sanity test for the mapping `EncryptedError::PeerRejected ->
    /// EncInitError::PeerRejected`. Pure unit test — exists so a
    /// hand-written `From` impl regression is caught even if
    /// commonware-stream changes which side surfaces the rejection.
    #[test]
    fn peer_rejected_error_maps_to_init_error() {
        let mapped: EncInitError = EncryptedError::PeerRejected(b"fake-peer-key".to_vec()).into();
        assert!(matches!(mapped, EncInitError::PeerRejected));
    }

    /// Naive subsequence search — `Vec<u8>::contains_slice` is not
    /// stable yet on our MSRV.
    fn contains_subsequence(haystack: &[u8], needle: &[u8]) -> bool {
        if needle.is_empty() || haystack.len() < needle.len() {
            return false;
        }
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }
}
