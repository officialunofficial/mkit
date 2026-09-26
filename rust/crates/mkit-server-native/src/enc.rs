//! `mkit-server serve --listen-enc`: the `mkit+enc://` listener
//! (SPEC-TRANSPORT-ENC §6), moved here from `mkit serve --listen-enc`.
//!
//! The encrypted handshake and the accept loop are `mkit-transport-enc`'s
//! ([`serve_tcp_listener`]); every session then runs
//! `mkit_server::ssh::serve_session` over the server's pipeline, as the
//! `TransportPeer` principal holding the key the handshake authenticated.
//! The fail-closed gate, its messages and banner, the timeouts and the
//! `server_id` are `mkit serve --listen-enc`'s.
//!
//! The listener faces the network, so it is bounded like the HTTP one: a
//! cap on sessions (`--max-connections`) and a separate, smaller cap on
//! handshakes (`--enc-max-handshakes`), so silent sockets cannot lock
//! authorized clients out; the handshake deadline; an idle timeout on every
//! frame read and write after it; and the session's per-connection frame
//! and byte budgets. On shutdown a session ends at its next frame boundary
//! (never inside an upload).

use std::collections::HashSet;
use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use commonware_codec::DecodeExt as _;
use commonware_cryptography::Signer as _;
use commonware_cryptography::ed25519::{PrivateKey, PublicKey};
use mkit_core::protocol::TransportError;
use mkit_rpc::mkit::rpc::v1::ssh::SshFrame;
use mkit_rpc::mkit::rpc::v1::ssh::ssh_frame;
use mkit_server::pipeline::{HookSet, Pipeline};
use mkit_server::ssh::{FrameIoError, FrameSink, FrameSource, SessionConfig, serve_session};
use mkit_server::{BlobStore, BoxFuture, NamespaceStore, Principal, Redacted};
use mkit_transport_enc::tokio_io::{TokioSink, TokioStream};
use mkit_transport_enc::{
    EncHandshakeBounds, EncInitError, EncReceiver, EncSender, EncSession, ListenerLimits,
    PeerPolicy, serve_tcp_listener,
};
use tokio::net::TcpListener;

use crate::Shutdown;
use crate::config::{ConfigError, PREFIX, ReadRule, ServeArgs, read_checked};
use crate::exit;

/// The banner `--unsafe-allow-any-enc-peer` prints, as `mkit serve
/// --listen-enc` printed it.
pub const UNSAFE_ENC_BANNER: &str = "\
============================================================
WARNING: mkit-server serve --listen-enc --unsafe-allow-any-enc-peer
The encrypted listener will accept ANY client that completes
the handshake. There is NO client authentication. Use this
only for local development or testing, NEVER in production.
============================================================";

/// `HelloResponse.server_id`: `mkit serve --listen-enc`'s prefix, so
/// clients' logs read the same.
#[must_use]
pub fn server_id() -> String {
    format!("mkit serve-enc/{}", env!("CARGO_PKG_VERSION"))
}

/// Where the server's static key comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerKeySource {
    /// A raw 32-byte key file, created on first run.
    File(PathBuf),
    /// A fresh key per process (`--unsafe-allow-any-enc-peer` without
    /// `--enc-server-key` only).
    Ephemeral,
}

/// Default `--enc-handshake-timeout-secs` (SPEC-TRANSPORT-ENC §2.1: at most
/// 10 s on real networks).
pub const DEFAULT_HANDSHAKE_TIMEOUT_SECS: u64 = 10;

/// Default `--enc-max-handshakes`, lowered to `--max-connections` when that
/// is smaller.
pub const DEFAULT_MAX_HANDSHAKES: usize = 128;

/// A resolved `--listen-enc` configuration. Holds no secret: the key is
/// loaded by [`load_server_key`] when the server opens.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct EncOptions {
    /// Where to listen.
    pub listen: SocketAddr,
    /// Which client keys the handshake admits.
    pub policy: PeerPolicy,
    /// The server's static key.
    pub server_key: ServerKeySource,
    /// The deadline of every frame read and write after the handshake;
    /// `None` disables it.
    pub idle_timeout: Option<Duration>,
    /// The deadline of the encrypted handshake.
    pub handshake_timeout: Duration,
    /// Sessions open at once (`--max-connections`).
    pub max_sessions: usize,
    /// Connections in the handshake at once (`--enc-max-handshakes`).
    pub max_handshakes: usize,
    /// After shutdown begins, how long sessions in flight may run.
    pub grace: Duration,
}

impl EncOptions {
    /// Options for `listen` with `policy`, and the `mkit-server serve`
    /// defaults otherwise.
    #[must_use]
    pub fn new(listen: SocketAddr, policy: PeerPolicy, server_key: ServerKeySource) -> Self {
        Self {
            listen,
            policy,
            server_key,
            idle_timeout: Some(Duration::from_mins(1)),
            handshake_timeout: Duration::from_secs(DEFAULT_HANDSHAKE_TIMEOUT_SECS),
            max_sessions: 1024,
            max_handshakes: DEFAULT_MAX_HANDSHAKES,
            grace: Duration::from_secs(30),
        }
    }

    /// Whether any client key is admitted (`--unsafe-allow-any-enc-peer`).
    #[must_use]
    pub fn is_open(&self) -> bool {
        matches!(self.policy, PeerPolicy::AllowAny)
    }

    /// The handshake bounds: the defaults with this handshake deadline.
    #[must_use]
    pub fn bounds(&self) -> EncHandshakeBounds {
        EncHandshakeBounds {
            handshake_timeout: self.handshake_timeout,
            ..EncHandshakeBounds::default()
        }
    }
}

/// The `--listen-enc` flags, fail-closed as `mkit serve --listen-enc`: an
/// allowlist and the unsafe flag exclude each other, an allowlist without
/// a key is refused, and with neither nothing binds. The allowlist is read
/// here; the key file is not touched until [`load_server_key`].
///
/// # Errors
/// `USAGE` for conflicting or orphaned flags, `CONFIG_ERROR` for a missing
/// peer policy, an unreadable or empty allowlist, or an allowlist without
/// `--enc-server-key`.
pub(crate) fn resolve(args: &ServeArgs) -> Result<Option<EncOptions>, ConfigError> {
    let usage = |m: &str| ConfigError::new(exit::USAGE, format!("{PREFIX}: {m}"));
    let config = |m: String| ConfigError::new(exit::CONFIG_ERROR, format!("{PREFIX}: {m}"));
    let Some(listen) = args.listen_enc else {
        if args.enc_authorized_peers.is_some()
            || args.enc_server_key.is_some()
            || args.unsafe_allow_any_enc_peer
        {
            return Err(usage(
                "--enc-authorized-peers, --enc-server-key and --unsafe-allow-any-enc-peer \
                 configure the enc listener; pass --listen-enc <ADDR>",
            ));
        }
        return Ok(None);
    };
    if args.enc_handshake_timeout_secs == 0 {
        return Err(usage("--enc-handshake-timeout-secs must be at least 1"));
    }
    // The peer policy comes only from these flags, never from the served
    // root's `.mkit/config`.
    let policy = match (&args.enc_authorized_peers, args.unsafe_allow_any_enc_peer) {
        (Some(_), true) => {
            return Err(usage(
                "--enc-authorized-peers and --unsafe-allow-any-enc-peer are mutually exclusive",
            ));
        }
        (Some(path), false) => match load_authorized_peers(path) {
            Ok(set) if set.is_empty() => {
                return Err(config(format!(
                    "--enc-authorized-peers '{}' contained no valid peer keys; refusing to bind \
                     (fail-closed)",
                    path.display()
                )));
            }
            Ok(set) => PeerPolicy::Allowlist(set),
            Err(msg) => return Err(config(msg)),
        },
        (None, true) => PeerPolicy::AllowAny,
        (None, false) => {
            return Err(config(
                "--listen-enc: refusing to bind without peer authorization.\n\
                 Pass --enc-authorized-peers <PATH> with an allowlist of client public keys,\n\
                 or --unsafe-allow-any-enc-peer to accept any peer (development only)."
                    .to_owned(),
            ));
        }
    };
    let server_key = match (&args.enc_server_key, &policy) {
        (Some(path), _) => ServerKeySource::File(path.clone()),
        (None, PeerPolicy::AllowAny) => ServerKeySource::Ephemeral,
        (None, PeerPolicy::Allowlist(_)) => {
            return Err(config(
                "--enc-authorized-peers needs --enc-server-key <PATH>: allowlisted clients pin \
                 the server's key (?pubkey=), so it must be stable across restarts. The file \
                 is created on first run."
                    .to_owned(),
            ));
        }
    };
    let max_handshakes = args
        .enc_max_handshakes
        .unwrap_or_else(|| args.max_connections.min(DEFAULT_MAX_HANDSHAKES));
    if max_handshakes == 0 {
        return Err(usage("--enc-max-handshakes must be at least 1"));
    }
    let idle = args.enc_idle_timeout_secs;
    Ok(Some(EncOptions {
        idle_timeout: (idle != 0).then(|| Duration::from_secs(idle)),
        handshake_timeout: Duration::from_secs(args.enc_handshake_timeout_secs),
        max_sessions: args.max_connections,
        max_handshakes,
        grace: Duration::from_secs(args.shutdown_grace_secs),
        ..EncOptions::new(listen, policy, server_key)
    }))
}

/// Parse an authorized-peers allowlist into raw 32-byte ed25519 public
/// keys: one per line as 64-hex or 43-char url-safe base64 (the
/// `?pubkey=` encodings, with the same canonical-form rules), blank lines
/// and `#` comments ignored.
///
/// The file is opened without following a symlink and must be a regular
/// file of at most 1 MiB, owned by the server's user or root, that neither
/// group nor others may write: whoever can edit it decides who may
/// connect. It is read once, at startup.
///
/// # Errors
/// A message naming the file, and the line of a malformed key.
pub fn load_authorized_peers(path: &Path) -> Result<HashSet<[u8; 32]>, String> {
    let shown = path.display();
    let symlink = "is a symlink; point the flag at the file itself";
    let contents = read_checked(path, &ReadRule::OWNER_WRITABLE, symlink)
        .map_err(|why| format!("--enc-authorized-peers '{shown}': {why}"))?;
    let mut set = HashSet::new();
    for (lineno, raw) in contents.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let key = mkit_transport_enc::url::decode_pubkey(line)
            .map_err(|e| format!("authorized-peers '{shown}' line {}: {e}", lineno + 1))?;
        set.insert(key);
    }
    Ok(set)
}

/// The server's static key. A [`ServerKeySource::File`] that does not
/// exist yet is created from the system RNG (`0600`, its missing parent
/// directories `0700`, never overwriting); the file is then read with
/// `mkit_core::sign::load_raw_32`'s checks: no symlink anywhere on the
/// path, owned by this user, no group or other bits, exactly 32 bytes.
///
/// # Errors
/// `CONFIG_ERROR` for a key file that cannot be created or is refused;
/// `TEMPFAIL` when the system RNG fails.
pub fn load_server_key(source: &ServerKeySource) -> Result<PrivateKey, ConfigError> {
    let path = match source {
        ServerKeySource::Ephemeral => return random_key(),
        ServerKeySource::File(path) => path,
    };
    let refuse = |why: String| {
        ConfigError::new(
            exit::CONFIG_ERROR,
            format!("{PREFIX}: --enc-server-key {}: {why}", path.display()),
        )
    };
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            return Err(refuse("is a symlink".to_owned()));
        }
        Ok(meta) if !meta.is_file() => return Err(refuse("is not a regular file".to_owned())),
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let secret = random_seed()?;
            // Refuses to clobber a key created meanwhile; that one is
            // loaded below.
            mkit_core::sign::save_raw_32_create_new(path, &secret)
                .map_err(|e| refuse(format!("cannot create it: {e}")))?;
        }
        Err(e) => return Err(refuse(e.to_string())),
    }
    let seed = mkit_core::sign::load_raw_32(path).map_err(|e| refuse(e.to_string()))?;
    PrivateKey::decode(seed.as_ref()).map_err(|e| refuse(format!("not an ed25519 key: {e}")))
}

fn random_seed() -> Result<zeroize::Zeroizing<[u8; 32]>, ConfigError> {
    let mut secret = zeroize::Zeroizing::new([0u8; 32]);
    getrandom::fill(secret.as_mut()).map_err(|e| {
        ConfigError::new(
            exit::TEMPFAIL,
            format!("{PREFIX}: --listen-enc: the system RNG failed: {e}"),
        )
    })?;
    Ok(secret)
}

fn random_key() -> Result<PrivateKey, ConfigError> {
    let seed = random_seed()?;
    PrivateKey::decode(seed.as_ref()).map_err(|e| {
        ConfigError::new(
            exit::TEMPFAIL,
            format!("{PREFIX}: --listen-enc: ephemeral key construction failed: {e}"),
        )
    })
}

/// A key's public half as clients pin it (`?pubkey=`, hex).
#[must_use]
pub fn public_key_hex(key: &PrivateKey) -> String {
    key.public_key().to_string()
}

/// Serves one authenticated session: the enc session and the peer's
/// static key, as the handshake established them, until the session ends
/// or, at a frame boundary, the server's [`Shutdown`] triggers.
pub type SessionFn = Arc<
    dyn Fn(EncSession<TokioStream, TokioSink>, PublicKey, Shutdown) -> BoxFuture<'static, ()>
        + Send
        + Sync,
>;

/// Run each session through `mkit_server::ssh::serve_session` on
/// `pipeline`, which must be in `TransportIdentity` mode (see
/// `Pipeline::with_auth`), as `Principal::TransportPeer` with the peer's
/// key. The principal comes only from the handshake: nothing the client
/// sends can set it. `idle_timeout` bounds every frame read and write.
/// Once the shutdown triggers, the session ends at its next frame
/// boundary: an idle session at once, a verb after it answers, never
/// inside an upload.
pub fn session_fn<B, N, H>(
    pipeline: Arc<Pipeline<B, N, H>>,
    idle_timeout: Option<Duration>,
) -> SessionFn
where
    B: BlobStore + 'static,
    N: NamespaceStore + 'static,
    H: HookSet + 'static,
{
    Arc::new(move |session, peer, shutdown| {
        let pipeline = Arc::clone(&pipeline);
        Box::pin(async move {
            let Ok(ed25519) = <[u8; 32]>::try_from(peer.as_ref()) else {
                return;
            };
            let (sender, receiver) = session.into_parts();
            let mut src = EncFrameSource {
                receiver,
                idle: idle_timeout,
                shutdown,
                in_upload: false,
            };
            let mut sink = EncFrameSink {
                sender,
                idle: idle_timeout,
            };
            let cfg = SessionConfig::new(server_id());
            let principal = Principal::TransportPeer { ed25519 };
            let end = serve_session(&pipeline, principal, &mut src, &mut sink, &cfg).await;
            tracing::debug!(?end, "enc session ended");
        })
    })
}

/// A [`FrameSource`] over the encrypted stream: one `SshFrame` per record
/// (SPEC-TRANSPORT-ENC §3.1).
///
/// A record that decrypts but does not decode is [`FrameIoError::Malformed`]
/// (the session answers `frame parse error`, as over stdio). Any
/// record-layer failure (the peer closed the stream, an oversized or
/// forged record) is [`FrameIoError::Eof`]: the receive direction cannot be
/// resumed (§6.3), so the session ends without a reply.
///
/// At a frame boundary a triggered shutdown is [`FrameIoError::Eof`] too,
/// so the session ends cleanly. The source follows the upload framing it
/// hands out (an `UploadPack`, then chunks until `last`, or until a frame
/// that is not a chunk ends it) and never stops inside an upload. When the
/// session rejects an upload early it reads no chunk, and the source keeps
/// waiting out that one next read (bounded by the idle timeout): it may
/// finish late, never early.
struct EncFrameSource {
    receiver: EncReceiver<TokioStream>,
    idle: Option<Duration>,
    shutdown: Shutdown,
    in_upload: bool,
}

impl EncFrameSource {
    async fn read(&mut self) -> Result<SshFrame, FrameIoError> {
        let read = mkit_transport_enc::recv_frame(&mut self.receiver);
        let result = match self.idle {
            Some(idle) => tokio::time::timeout(idle, read)
                .await
                .map_err(|_| FrameIoError::Timeout)?,
            None => read.await,
        };
        result.map_err(|e| match e {
            TransportError::ProtocolError => FrameIoError::Malformed,
            _ => FrameIoError::Eof,
        })
    }

    /// Where `frame` leaves the upload framing.
    fn track(&mut self, frame: &SshFrame) {
        self.in_upload = match &frame.body {
            Some(ssh_frame::Body::UploadPack(_)) => !self.in_upload,
            Some(ssh_frame::Body::PackChunk(c)) => self.in_upload && c.last != Some(true),
            _ => false,
        };
    }
}

impl FrameSource for EncFrameSource {
    async fn next_frame(&mut self) -> Result<SshFrame, FrameIoError> {
        let result = if self.in_upload {
            self.read().await
        } else {
            if self.shutdown.is_triggered() {
                return Err(FrameIoError::Eof);
            }
            let stop = self.shutdown.wait();
            tokio::select! {
                biased;
                () = stop => return Err(FrameIoError::Eof),
                result = self.read() => result,
            }
        };
        match &result {
            Ok(frame) => self.track(frame),
            Err(_) => self.in_upload = false,
        }
        result
    }
}

/// A [`FrameSink`] over the encrypted stream. A write that cannot finish
/// within the idle timeout (a peer that stops reading) fails the session.
struct EncFrameSink {
    sender: EncSender<TokioSink>,
    idle: Option<Duration>,
}

impl FrameSink for EncFrameSink {
    async fn send(&mut self, frame: &SshFrame) -> Result<(), FrameIoError> {
        let write = mkit_transport_enc::send_frame(&mut self.sender, frame);
        let result = match self.idle {
            Some(idle) => tokio::time::timeout(idle, write)
                .await
                .map_err(|_| FrameIoError::Timeout)?,
            None => write.await,
        };
        result.map_err(|_| FrameIoError::Io(Redacted::new("enc record send failed")))
    }
}

/// A bound-ready enc listener: its key and its session function.
pub struct EncService {
    /// The server's static key.
    pub key: PrivateKey,
    /// How each session is served.
    pub session: SessionFn,
}

impl fmt::Debug for EncService {
    /// Shows the public key only.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncService")
            .field("pubkey", &public_key_hex(&self.key))
            .finish_non_exhaustive()
    }
}

/// The startup line `mkit serve --listen-enc` printed: the address and the
/// `?pubkey=` clients pin.
#[must_use]
pub fn announcement(addr: SocketAddr, key: &PrivateKey) -> String {
    let pk = public_key_hex(key);
    format!(
        "{PREFIX} --listen-enc on {addr} (server pubkey = {pk}); clients dial \
         mkit+enc://<host>:<port>?pubkey={pk}"
    )
}

/// Serve `service` on `listener` until `shutdown` triggers: stop
/// accepting, then let sessions in flight finish for at most
/// [`EncOptions::grace`]; those still running are dropped (an interrupted
/// upload leaves nothing visible).
///
/// # Errors
/// A non-transient accept error, after the sessions in flight drained.
pub async fn serve(
    listener: TcpListener,
    service: EncService,
    opts: &EncOptions,
    shutdown: Shutdown,
) -> Result<(), EncInitError> {
    let session = service.session;
    let run = serve_tcp_listener(
        listener,
        service.key,
        opts.policy.clone(),
        opts.bounds(),
        ListenerLimits::new(opts.max_sessions, opts.max_handshakes),
        shutdown.wait(),
        {
            let shutdown = shutdown.clone();
            move |sess, peer| session(sess, peer, shutdown.clone())
        },
    );
    tokio::pin!(run);
    tokio::select! {
        result = &mut run => return result,
        () = shutdown.wait() => {}
    }
    if let Ok(result) = tokio::time::timeout(opts.grace, run).await {
        result
    } else {
        tracing::warn!(
            grace_secs = opts.grace.as_secs(),
            "shutdown grace expired; dropping enc sessions in flight"
        );
        Ok(())
    }
}
