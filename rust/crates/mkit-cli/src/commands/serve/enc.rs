//! Encrypted-TCP listener for `mkit serve --listen-enc` (issue #156).
//!
//! Split out of the parent `serve` module so the stdin/stdout SSH-frame
//! server and the encrypted listener live in focused files. The verb
//! dispatch reuses the transport-generic helpers (`handle_simple_verb`,
//! `pack_key_from_id`, `download_chunks`, `UploadDrain`) from the parent.

// The glob pulls the parent `serve` module's shared verb helpers
// (`handle_simple_verb`, `pack_key_from_id`, `download_chunks`,
// `UploadDrain`) and frame types into scope.
#[allow(clippy::wildcard_imports)]
use super::*;

/// `--listen-enc <addr>` entry point. Without the `enc-transport`
/// cargo feature this prints a helpful error and exits with
/// `UNAVAILABLE` so package builders shipping the bare-bones binary
/// get a clear signal.
#[cfg(not(feature = "enc-transport"))]
#[allow(clippy::too_many_arguments)]
pub(super) fn run_listen_enc(
    _addr: &str,
    _repo_root: PathBuf,
    _authorized_peers: Option<&str>,
    _server_key: Option<&str>,
    _unsafe_allow_any: bool,
    _idle_timeout_secs: u64,
    _handshake_timeout_secs: u64,
) -> u8 {
    eprintln!(
        "mkit serve --listen-enc requires the `enc-transport` cargo feature; \
         rebuild with `--features enc-transport` to enable it."
    );
    exit::UNAVAILABLE
}

#[cfg(feature = "enc-transport")]
#[allow(
    clippy::needless_pass_by_value,
    clippy::manual_let_else,
    clippy::items_after_statements,
    clippy::cast_possible_truncation,
    clippy::box_default,
    clippy::too_many_lines,
    clippy::too_many_arguments
)]
pub(super) fn run_listen_enc(
    addr: &str,
    repo_root: PathBuf,
    authorized_peers: Option<&str>,
    server_key: Option<&str>,
    unsafe_allow_any: bool,
    idle_timeout_secs: u64,
    handshake_timeout_secs: u64,
) -> u8 {
    use commonware_cryptography::Signer as _;
    use mkit_transport_enc::{EncHandshakeBounds, PeerPolicy};
    use std::sync::Arc;
    use std::time::Duration;

    // --- Fail-closed gate (issue #178) ---------------------------------
    //
    // The encrypted listener historically accepted ANY peer. We now
    // refuse to bind unless the operator has either supplied an
    // allowlist of authorized client keys or explicitly opted into the
    // unsafe allow-any escape. The peer-authorization config is NEVER
    // read from repo-local `.mkit/config`: it comes only from the CLI
    // flag (a CLI-supplied or user-scoped path).
    let policy = match (authorized_peers, unsafe_allow_any) {
        (Some(_), true) => {
            eprintln!(
                "mkit serve --listen-enc: --enc-authorized-peers and \
                 --unsafe-allow-any-enc-peer are mutually exclusive"
            );
            return exit::USAGE;
        }
        (Some(path), false) => match load_authorized_peers(path) {
            Ok(set) if set.is_empty() => {
                eprintln!(
                    "mkit serve --listen-enc: --enc-authorized-peers '{path}' \
                     contained no valid peer keys; refusing to bind (fail-closed)"
                );
                return exit::CONFIG_ERROR;
            }
            Ok(set) => PeerPolicy::Allowlist(set),
            Err(msg) => {
                eprintln!("mkit serve --listen-enc: {msg}");
                return exit::CONFIG_ERROR;
            }
        },
        (None, true) => {
            eprintln!(
                "============================================================\n\
                 WARNING: mkit serve --listen-enc --unsafe-allow-any-enc-peer\n\
                 The encrypted listener will accept ANY client that completes\n\
                 the handshake. There is NO client authentication. Use this\n\
                 only for local development or testing, NEVER in production.\n\
                 ============================================================"
            );
            PeerPolicy::AllowAny
        }
        (None, false) => {
            eprintln!(
                "mkit serve --listen-enc: refusing to bind without peer authorization.\n\
                 Pass --enc-authorized-peers <PATH> with an allowlist of client public keys,\n\
                 or --unsafe-allow-any-enc-peer to accept any peer (development only)."
            );
            return exit::CONFIG_ERROR;
        }
    };

    // --- Server identity ----------------------------------------------
    //
    // When allowlisting we want a STABLE server key so clients can pin
    // `?pubkey=` across restarts. Load it from the supplied/derived
    // user-scoped path (auto-created on first run). With the unsafe
    // allow-any escape and no key file we keep the historic ephemeral
    // per-process key.
    let sk = match resolve_server_key(server_key, &policy) {
        Ok(sk) => sk,
        Err(code) => return code,
    };

    let pk = sk.public_key().to_string();
    eprintln!(
        "mkit serve --listen-enc on {addr} (server pubkey = {pk}); \
         clients dial mkit+enc://<host>:<port>?pubkey={pk}"
    );

    let tx = Arc::new(FileTransport::new(&repo_root));

    // Post-handshake per-frame idle timeout (#216). `0` disables it.
    let idle_timeout = (idle_timeout_secs != 0).then(|| Duration::from_secs(idle_timeout_secs));

    let serve_fn = move |sess: mkit_transport_enc::EncSession<
        mkit_transport_enc::tokio_io::TokioStream,
        mkit_transport_enc::tokio_io::TokioSink,
    >,
                         _peer: commonware_cryptography::ed25519::PublicKey| {
        let tx = tx.clone();
        // Each accepted connection gets its own future. `serve_tcp`
        // awaits this inside a per-connection `tokio::spawn`, so we
        // can `.await` freely without deadlocking the listener.
        async move { serve_enc_session(tx, sess, idle_timeout).await }
    };

    // Operator-tunable handshake bounds (#216). `synchrony_bound` /
    // `max_handshake_age` keep their generous defaults; only the overall
    // completion deadline is exposed as a flag for now.
    let bounds = EncHandshakeBounds {
        handshake_timeout: Duration::from_secs(handshake_timeout_secs),
        ..EncHandshakeBounds::default()
    };

    match mkit_transport_enc::serve_tcp_with_policy_and_bounds(addr, sk, policy, bounds, serve_fn) {
        Ok(()) => exit::OK,
        Err(e) => {
            eprintln!("mkit serve --listen-enc: {e}");
            exit::TEMPFAIL
        }
    }
}

/// Parse an authorized-peers allowlist file into a set of raw 32-byte
/// ed25519 public keys. Accepts one key per line as 64-hex or 43-char
/// url-safe base64. Blank lines and `#` comments are ignored. The path
/// MUST be CLI-supplied / user-scoped — this function is never fed a
/// repo-local config value.
#[cfg(feature = "enc-transport")]
pub(super) fn load_authorized_peers(
    path: &str,
) -> Result<std::collections::HashSet<[u8; 32]>, String> {
    let contents = std::fs::read_to_string(path)
        .map_err(|e| format!("failed to read authorized-peers file '{path}': {e}"))?;
    let mut set = std::collections::HashSet::new();
    for (lineno, raw) in contents.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Reuse the canonical on-wire pubkey decoder from
        // mkit-transport-enc (the owner of the `?pubkey=` encoding) so the
        // allowlist accepts exactly the keys a client `?pubkey=` pin can
        // express — including the same rejection of non-canonical
        // base64 trailing bits — and the two acceptance rules cannot drift.
        let key = mkit_transport_enc::url::decode_pubkey(line)
            .map_err(|e| format!("authorized-peers '{path}' line {}: {e}", lineno + 1))?;
        set.insert(key);
    }
    Ok(set)
}

/// Resolve the server's signing key.
///
/// - Allowlisting: load (or auto-create) a STABLE raw-32 key from the
///   supplied `--enc-server-key` path, or a user-scoped default
///   (`~/.config/mkit/enc/server.key`). A stable key is required so
///   pinned client `?pubkey=` values survive restarts.
/// - `AllowAny` (unsafe) with no key file: keep the historic ephemeral
///   per-process key.
#[cfg(feature = "enc-transport")]
fn resolve_server_key(
    server_key: Option<&str>,
    policy: &mkit_transport_enc::PeerPolicy,
) -> Result<commonware_cryptography::ed25519::PrivateKey, u8> {
    use mkit_transport_enc::PeerPolicy;

    match (server_key, policy) {
        (Some(path), _) => load_or_create_server_key(std::path::Path::new(path)),
        (None, PeerPolicy::Allowlist(_)) => {
            let Some(home) = crate::config::home_dir_for_euid() else {
                eprintln!(
                    "mkit serve --listen-enc: cannot resolve a user-scoped key path; \
                     pass --enc-server-key <PATH>"
                );
                return Err(exit::CONFIG_ERROR);
            };
            let path = home.join(".config/mkit/enc/server.key");
            load_or_create_server_key(&path)
        }
        (None, PeerPolicy::AllowAny) => ephemeral_server_key(),
    }
}

/// Load a stable raw-32 server key from `path`, creating it (and its
/// parent directories) on first run with `0700`/`0600` hardening.
#[cfg(feature = "enc-transport")]
fn load_or_create_server_key(
    path: &std::path::Path,
) -> Result<commonware_cryptography::ed25519::PrivateKey, u8> {
    use commonware_codec::DecodeExt as _;
    use commonware_cryptography::ed25519::PrivateKey;

    if !path.exists() {
        if let Some(parent) = path.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                eprintln!(
                    "mkit serve --listen-enc: create key dir '{}': {e}",
                    parent.display()
                );
                return Err(exit::CANTCREAT);
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
            }
        }
        let mut secret = zeroize::Zeroizing::new([0u8; 32]);
        if getrandom::fill(secret.as_mut()).is_err() {
            eprintln!("mkit serve --listen-enc: failed to read system RNG for server key");
            return Err(exit::TEMPFAIL);
        }
        // `save_raw_32_create_new` refuses to clobber an existing key and
        // applies the same 0600/owner hardening as `load_raw_32`.
        match mkit_core::sign::save_raw_32_create_new(path, &secret) {
            Ok(_created) => {}
            Err(e) => {
                eprintln!(
                    "mkit serve --listen-enc: write server key '{}': {e}",
                    path.display()
                );
                return Err(exit::CANTCREAT);
            }
        }
    }

    let seed = match mkit_core::sign::load_raw_32(path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "mkit serve --listen-enc: load server key '{}': {e}",
                path.display()
            );
            return Err(exit::NOPERM);
        }
    };
    PrivateKey::decode(seed.as_ref()).map_err(|e| {
        eprintln!("mkit serve --listen-enc: server key construction failed: {e}");
        exit::DATAERR
    })
}

/// Generate an ephemeral per-process server key (allow-any/unsafe only).
#[cfg(feature = "enc-transport")]
fn ephemeral_server_key() -> Result<commonware_cryptography::ed25519::PrivateKey, u8> {
    use commonware_codec::DecodeExt as _;
    use commonware_cryptography::ed25519::PrivateKey;

    let mut secret = zeroize::Zeroizing::new([0u8; 32]);
    if getrandom::fill(secret.as_mut()).is_err() {
        eprintln!("mkit serve --listen-enc: failed to read system RNG for ephemeral key");
        return Err(exit::TEMPFAIL);
    }
    PrivateKey::decode(secret.as_ref()).map_err(|e| {
        eprintln!("mkit serve --listen-enc: ephemeral key construction failed: {e}");
        exit::TEMPFAIL
    })
}

#[cfg(feature = "enc-transport")]
pub(super) async fn serve_enc_session(
    tx: std::sync::Arc<FileTransport>,
    sess: mkit_transport_enc::EncSession<
        mkit_transport_enc::tokio_io::TokioStream,
        mkit_transport_enc::tokio_io::TokioSink,
    >,
    idle_timeout: Option<std::time::Duration>,
) {
    use mkit_transport_enc::send_frame;

    let (mut sender, mut receiver) = sess.into_parts();
    // App-level Hello — also bounded by the idle timeout so a peer that
    // completes the cryptographic handshake then stalls before sending
    // the app Hello can't pin the worker either.
    let Ok(frame) = recv_frame_idle(&mut receiver, idle_timeout).await else {
        return;
    };
    let proto = match frame.body {
        Some(ssh_frame::Body::Hello(h)) => h.proto.unwrap_or_default(),
        _ => return,
    };
    if proto != ProtocolVersion::ProtocolVersion1 {
        return;
    }
    let resp = SshFrame {
        body: Some(ssh_frame::Body::HelloResponse(Box::new(HelloResponse {
            proto: Some(ProtocolVersion::ProtocolVersion1.into()),
            server_id: Some(format!("mkit serve-enc/{}", crate::cli::CLI_VERSION)),
            ..Default::default()
        }))),
        ..Default::default()
    };
    if send_frame(&mut sender, &resp).await.is_err() {
        return;
    }

    // Verb loop. Mirrors the stdin/stdout `serve_loop`'s dispatch
    // decisions but uses async encrypted-frame helpers so we never
    // block the listener's tokio worker.
    loop {
        let Ok(frame) = recv_frame_idle(&mut receiver, idle_timeout).await else {
            return;
        };
        if let Some(ssh_frame::Body::Close(_)) = frame.body {
            return;
        }
        if dispatch_enc_one(&tx, frame, &mut sender, &mut receiver, idle_timeout)
            .await
            .is_err()
        {
            return;
        }
    }
}

/// Receive one frame, applying the post-handshake idle timeout when set
/// (#216). With `None` the read is unbounded (operator opted out via
/// `--enc-idle-timeout-secs 0`).
#[cfg(feature = "enc-transport")]
async fn recv_frame_idle(
    receiver: &mut mkit_transport_enc::EncReceiver<mkit_transport_enc::tokio_io::TokioStream>,
    idle_timeout: Option<std::time::Duration>,
) -> Result<SshFrame, ()> {
    match idle_timeout {
        Some(d) => mkit_transport_enc::recv_frame_within(receiver, d)
            .await
            .map_err(|_| ()),
        None => mkit_transport_enc::recv_frame(receiver)
            .await
            .map_err(|_| ()),
    }
}

/// One verb dispatch in async form for the encrypted listener.
///
/// Talks to the encrypted-session helpers from `mkit-transport-enc`
/// instead of `mkit-rpc`'s `read_frame`/`write_frame`, but routes every
/// non-streaming verb through the same sans-IO [`handle_simple_verb`] the
/// sync server uses, and shares [`pack_key_from_id`], [`download_chunks`],
/// and [`UploadDrain`] for the streaming verbs — so the SSH and encrypted
/// servers cannot drift on validation, the CAS mapping, or the chunk cap.
#[cfg(feature = "enc-transport")]
#[allow(clippy::box_default, clippy::manual_let_else)]
async fn dispatch_enc_one(
    tx: &FileTransport,
    frame: SshFrame,
    sender: &mut mkit_transport_enc::EncSender<mkit_transport_enc::tokio_io::TokioSink>,
    receiver: &mut mkit_transport_enc::EncReceiver<mkit_transport_enc::tokio_io::TokioStream>,
    idle_timeout: Option<std::time::Duration>,
) -> Result<(), ()> {
    use mkit_transport_enc::send_frame;

    async fn send_body(
        sender: &mut mkit_transport_enc::EncSender<mkit_transport_enc::tokio_io::TokioSink>,
        body: ssh_frame::Body,
    ) -> Result<(), ()> {
        let frame = SshFrame {
            body: Some(body),
            ..Default::default()
        };
        send_frame(sender, &frame).await.map_err(|_| ())
    }
    async fn send_err(
        sender: &mut mkit_transport_enc::EncSender<mkit_transport_enc::tokio_io::TokioSink>,
        code: ErrorCode,
        msg: &str,
    ) -> Result<(), ()> {
        send_frame(sender, &mkit_rpc::ssh_error_frame(code, msg))
            .await
            .map_err(|_| ())
    }

    let Some(body) = frame.body else {
        return send_err(sender, ErrorCode::InvalidRequest, "empty frame").await;
    };

    match &body {
        ssh_frame::Body::DownloadPack(req) => {
            let key = match pack_key_from_id(req.pack_id.as_ref()) {
                Ok(k) => k,
                Err((code, msg)) => return send_err(sender, code, msg).await,
            };
            match tx.download_pack(&key) {
                Ok(bytes) => {
                    send_body(
                        sender,
                        ssh_frame::Body::DownloadPackHeader(Box::new(DownloadPackHeader {
                            total_bytes: Some(bytes.len() as u64),
                            ..Default::default()
                        })),
                    )
                    .await?;
                    for chunk in download_chunks(req.pack_id.clone(), &bytes) {
                        send_body(sender, ssh_frame::Body::PackChunk(Box::new(chunk))).await?;
                    }
                    Ok(())
                }
                Err(_) => send_err(sender, ErrorCode::KeyNotFound, "pack not found").await,
            }
        }
        ssh_frame::Body::UploadPack(header) => {
            let mut upload = match UploadDrain::new(header) {
                Ok(upload) => upload,
                Err(e) => return send_err(sender, ErrorCode::InvalidRequest, e.message()).await,
            };
            loop {
                let f = recv_frame_idle(receiver, idle_timeout).await?;
                let Some(ssh_frame::Body::PackChunk(chunk)) = f.body else {
                    return send_err(
                        sender,
                        ErrorCode::InvalidRequest,
                        "expected PackChunk after UploadPack",
                    )
                    .await;
                };
                let complete = match upload.push_chunk(&chunk) {
                    Ok(complete) => complete,
                    Err(e) => {
                        return send_err(sender, ErrorCode::InvalidRequest, e.message()).await;
                    }
                };
                if complete {
                    break;
                }
            }
            let (bytes, key) = upload.into_parts();
            match tx.upload_pack(&bytes, &key) {
                Ok(()) => {
                    send_body(
                        sender,
                        ssh_frame::Body::UploadPackResponse(
                            Box::new(UploadPackResponse::default()),
                        ),
                    )
                    .await
                }
                Err(_) => send_err(sender, ErrorCode::Internal, "upload failed").await,
            }
        }
        other => match handle_simple_verb(tx, other) {
            Some(Ok(resp)) => send_body(sender, resp).await,
            Some(Err((code, msg))) => send_err(sender, code, msg).await,
            None => send_err(sender, ErrorCode::InvalidRequest, "unexpected frame").await,
        },
    }
}
