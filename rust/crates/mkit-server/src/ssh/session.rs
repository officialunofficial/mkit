//! The session driver: `Hello`, then the verb loop under the
//! per-connection budgets (`mkit serve`'s `serve_loop` and `handshake`).

use core::future::Future;

use mkit_rpc::mkit::rpc::v1::ssh::{HelloResponse, SshFrame, ssh_frame};
use mkit_rpc::mkit::rpc::v1::{ErrorCode, ProtocolVersion};

use super::budget::Budget;
use super::verbs;
use crate::error::Redacted;
use crate::pipeline::{AuthMode, HookSet, Pipeline};
use crate::principal::Principal;
use crate::rt::MaybeSend;
use crate::store::{BlobStore, NamespaceStore};

/// Why a frame could not be read or written.
#[derive(Debug)]
#[non_exhaustive]
pub enum FrameIoError {
    /// The peer closed the stream cleanly, between frames.
    Eof,
    /// The source's read deadline passed.
    Timeout,
    /// A frame that is too long, truncated or undecodable.
    Malformed,
    /// Any other I/O failure; the detail is for the server log only.
    Io(Redacted),
}

impl From<mkit_rpc::FrameError> for FrameIoError {
    /// A truncated length prefix is [`Self::Eof`] (`mkit serve`'s clean end
    /// of stream); an I/O failure is [`Self::Io`]; anything else is
    /// [`Self::Malformed`].
    fn from(err: mkit_rpc::FrameError) -> Self {
        match err {
            mkit_rpc::FrameError::LengthTruncated => Self::Eof,
            mkit_rpc::FrameError::Io(e) => Self::Io(Redacted::new(e.to_string())),
            _ => Self::Malformed,
        }
    }
}

/// Where a session reads its frames.
pub trait FrameSource: MaybeSend {
    /// The next frame. A source with a read deadline returns
    /// [`FrameIoError::Timeout`] when it passes.
    fn next_frame(&mut self) -> impl Future<Output = Result<SshFrame, FrameIoError>> + MaybeSend;
}

/// Where a session writes its frames.
pub trait FrameSink: MaybeSend {
    /// Write one frame, flushed.
    fn send(
        &mut self,
        frame: &SshFrame,
    ) -> impl Future<Output = Result<(), FrameIoError>> + MaybeSend;
}

/// A session's settings.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SessionConfig {
    /// `HelloResponse.server_id`: `mkit serve/<version>` for the ssh
    /// forced command, `mkit serve-enc/<version>` for the enc listener.
    pub server_id: String,
    /// End cleanly right after a successful handshake, before any verb.
    /// `mkit serve`'s `MKIT_SERVE_TEST_DIE_AFTER_HELLO` harness sets it; a
    /// production caller never does.
    pub stop_after_hello: bool,
}

impl SessionConfig {
    /// A session that answers `Hello` with `server_id`.
    #[must_use]
    pub fn new(server_id: impl Into<String>) -> Self {
        Self {
            server_id: server_id.into(),
            stop_after_hello: false,
        }
    }
}

/// How a session ended. `mkit serve` maps [`Self::Clean`] and
/// [`Self::IoError`] to `exit::OK` and the rest to `exit::PROTOCOL_ERROR`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionEnd {
    /// The client sent `Close` or closed the stream between frames, or
    /// `stop_after_hello` was set.
    Clean,
    /// A failed handshake, an unreadable frame or an exceeded budget. The
    /// error frame, if any, was sent first.
    ProtocolError,
    /// The source timed out.
    Timeout,
    /// The sink failed while answering a verb.
    IoError,
}

/// A verb's dispatch stopped the session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Stop {
    /// The sink failed.
    Io,
    /// The source timed out inside an upload.
    Timeout,
}

impl From<FrameIoError> for Stop {
    fn from(_: FrameIoError) -> Self {
        Self::Io
    }
}

/// Send an `Error{code, message}` frame with empty `details`.
pub(super) async fn emit_error<K: FrameSink>(
    sink: &mut K,
    code: ErrorCode,
    message: &str,
) -> Result<(), Stop> {
    let frame = mkit_rpc::ssh_error_frame(code, message);
    sink.send(&frame).await.map_err(Stop::from)
}

/// Send a frame holding `body`.
pub(super) async fn send_body<K: FrameSink>(
    sink: &mut K,
    body: ssh_frame::Body,
) -> Result<(), Stop> {
    let frame = SshFrame {
        body: Some(body),
        ..Default::default()
    };
    sink.send(&frame).await.map_err(Stop::from)
}

/// The application handshake (SPEC-RPC §4): the first frame must be a
/// protocol-1 `Hello`, answered by a `HelloResponse` carrying `server_id`.
///
/// # Errors
/// [`SessionEnd::Timeout`] when the source times out; otherwise
/// [`SessionEnd::ProtocolError`], after an error frame for a first frame
/// that is not `Hello` or names another protocol version, and silently
/// for an unreadable first frame or a failed `HelloResponse` write.
pub async fn handshake<S: FrameSource, K: FrameSink>(
    src: &mut S,
    sink: &mut K,
    server_id: &str,
) -> Result<(), SessionEnd> {
    let frame = match src.next_frame().await {
        Ok(frame) => frame,
        Err(FrameIoError::Timeout) => return Err(SessionEnd::Timeout),
        Err(_) => return Err(SessionEnd::ProtocolError),
    };
    let Some(ssh_frame::Body::Hello(hello)) = frame.body else {
        let _ = emit_error(sink, ErrorCode::InvalidRequest, "first frame must be Hello").await;
        return Err(SessionEnd::ProtocolError);
    };
    let proto = hello.proto.unwrap_or_default();
    if proto != ProtocolVersion::ProtocolVersion1 {
        let message = format!("unsupported proto_version {}", proto.to_i32());
        let _ = emit_error(sink, ErrorCode::InvalidRequest, &message).await;
        return Err(SessionEnd::ProtocolError);
    }
    let resp = ssh_frame::Body::HelloResponse(Box::new(HelloResponse {
        proto: Some(ProtocolVersion::ProtocolVersion1.into()),
        server_id: Some(server_id.to_owned()),
        ..Default::default()
    }));
    send_body(sink, resp)
        .await
        .map_err(|_| SessionEnd::ProtocolError)
}

/// Serve one ssh-frame session: the handshake, then one verb per top-level
/// frame until `Close`, a clean end of stream, a protocol error or a
/// failure. Each verb runs on `pipeline` as `principal`.
///
/// The pipeline must be configured with [`AuthMode::TransportIdentity`]:
/// the transport has already authenticated the peer, and no replay record
/// or quota is written. Any other mode ends the session at once with
/// [`SessionEnd::ProtocolError`], before reading a frame. Its upload
/// limits should be [`super::upload_limits`].
///
/// Responses and error frames are `mkit serve`'s, byte for byte
/// (`rust/tests/golden/ssh-serve/`).
pub async fn serve_session<B, N, H, S, K>(
    pipeline: &Pipeline<B, N, H>,
    principal: Principal,
    src: &mut S,
    sink: &mut K,
    cfg: &SessionConfig,
) -> SessionEnd
where
    B: BlobStore,
    N: NamespaceStore,
    H: HookSet,
    S: FrameSource,
    K: FrameSink,
{
    if !matches!(pipeline.auth_mode(), AuthMode::TransportIdentity) {
        tracing::error!("ssh session refused: the pipeline is not in TransportIdentity mode");
        return SessionEnd::ProtocolError;
    }
    if let Err(end) = handshake(src, sink, &cfg.server_id).await {
        return end;
    }
    if cfg.stop_after_hello {
        return SessionEnd::Clean;
    }
    let verbs = verbs::Verbs::new(pipeline, principal);
    let mut budget = Budget::default();
    loop {
        let frame = match src.next_frame().await {
            Ok(frame) => frame,
            Err(FrameIoError::Eof) => return SessionEnd::Clean,
            Err(FrameIoError::Timeout) => return SessionEnd::Timeout,
            Err(_) => {
                let _ = emit_error(sink, ErrorCode::InvalidRequest, "frame parse error").await;
                return SessionEnd::ProtocolError;
            }
        };
        if let Err(message) = budget.charge(&frame) {
            let _ = emit_error(sink, ErrorCode::InvalidRequest, message).await;
            return SessionEnd::ProtocolError;
        }
        let body = match frame.body {
            Some(ssh_frame::Body::Close(_)) => return SessionEnd::Clean,
            body => body,
        };
        match verbs.dispatch(body, src, sink).await {
            Ok(()) => {}
            Err(Stop::Io) => return SessionEnd::IoError,
            Err(Stop::Timeout) => return SessionEnd::Timeout,
        }
    }
}
