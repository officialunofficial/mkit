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
    /// `enc-transport` cargo feature. Phase 2 of issue #156 — see
    /// SPEC-TRANSPORT-ENC §6 item 4.
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

/// `--listen-enc <addr>` entry point. Without the `enc-transport`
/// cargo feature this prints a helpful error and exits with
/// `UNAVAILABLE` so package builders shipping the bare-bones binary
/// get a clear signal.
#[cfg(not(feature = "enc-transport"))]
#[allow(clippy::too_many_arguments)]
fn run_listen_enc(
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
fn run_listen_enc(
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
fn load_authorized_peers(path: &str) -> Result<std::collections::HashSet<[u8; 32]>, String> {
    let contents = std::fs::read_to_string(path)
        .map_err(|e| format!("failed to read authorized-peers file '{path}': {e}"))?;
    let mut set = std::collections::HashSet::new();
    for (lineno, raw) in contents.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let key = decode_peer_pubkey_line(line)
            .map_err(|msg| format!("authorized-peers '{path}' line {}: {msg}", lineno + 1))?;
        set.insert(key);
    }
    Ok(set)
}

/// Decode a single allowlist entry (64-hex or 43-char url-safe base64)
/// into a raw 32-byte ed25519 public key. Reuses the same encodings the
/// `mkit+enc://?pubkey=` query accepts.
#[cfg(feature = "enc-transport")]
fn decode_peer_pubkey_line(s: &str) -> Result<[u8; 32], String> {
    if s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()) {
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            let hi = hex_nibble(s.as_bytes()[i * 2])?;
            let lo = hex_nibble(s.as_bytes()[i * 2 + 1])?;
            *byte = (hi << 4) | lo;
        }
        return Ok(out);
    }
    if s.len() == 43 && s.bytes().all(is_b64url_byte) {
        return decode_b64url_pubkey(s);
    }
    Err("peer key must be 64 hex chars or 43 url-safe base64 chars".to_string())
}

#[cfg(feature = "enc-transport")]
fn hex_nibble(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(10 + b - b'a'),
        b'A'..=b'F' => Ok(10 + b - b'A'),
        _ => Err("invalid hex digit".to_string()),
    }
}

#[cfg(feature = "enc-transport")]
const fn is_b64url_byte(b: u8) -> bool {
    matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_')
}

/// Decode a 43-char unpadded url-safe base64 ed25519 public key into 32
/// raw bytes. Mirrors `mkit-transport-enc`'s `?pubkey=` decoder, including
/// the rejection of non-zero trailing bits in the final character so two
/// distinct base64 strings cannot map to the same key.
#[cfg(feature = "enc-transport")]
#[allow(clippy::cast_possible_truncation)] // intentional byte extraction from packed 24-bit groups
fn decode_b64url_pubkey(s: &str) -> Result<[u8; 32], String> {
    let bytes = s.as_bytes();
    // 43 chars -> pad to 44 (multiple of 4) with the zero-bit char.
    let mut buf = [0u8; 44];
    buf[..43].copy_from_slice(bytes);
    buf[43] = b'A';
    let mut out = [0u8; 32];
    let mut out_pos = 0usize;
    for chunk in buf.chunks_exact(4) {
        let v0 = b64url_nibble(chunk[0])?;
        let v1 = b64url_nibble(chunk[1])?;
        let v2 = b64url_nibble(chunk[2])?;
        let v3 = b64url_nibble(chunk[3])?;
        let triple =
            (u32::from(v0) << 18) | (u32::from(v1) << 12) | (u32::from(v2) << 6) | u32::from(v3);
        if out_pos < 32 {
            out[out_pos] = (triple >> 16) as u8;
        }
        if out_pos + 1 < 32 {
            out[out_pos + 1] = (triple >> 8) as u8;
        }
        if out_pos + 2 < 32 {
            out[out_pos + 2] = triple as u8;
        }
        out_pos += 3;
    }
    // The 43rd char (index 42) carries 6 bits, only the top 4 of which
    // are significant; its two low bits MUST be zero.
    let last = b64url_nibble(bytes[42])?;
    if last & 0b0000_0011 != 0 {
        return Err("base64 peer key has non-zero trailing bits".to_string());
    }
    Ok(out)
}

#[cfg(feature = "enc-transport")]
fn b64url_nibble(b: u8) -> Result<u8, String> {
    match b {
        b'A'..=b'Z' => Ok(b - b'A'),
        b'a'..=b'z' => Ok(26 + b - b'a'),
        b'0'..=b'9' => Ok(52 + b - b'0'),
        b'-' => Ok(62),
        b'_' => Ok(63),
        _ => Err("invalid base64 url-safe digit".to_string()),
    }
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
async fn serve_enc_session(
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
        Some(ssh_frame::Body::Hello(h)) => h.proto.as_ref().map_or(0, buffa::EnumValue::to_i32),
        _ => return,
    };
    if proto != ProtocolVersion::PROTOCOL_VERSION_1 as i32 {
        return;
    }
    let resp = SshFrame {
        body: Some(ssh_frame::Body::HelloResponse(Box::new(HelloResponse {
            proto: Some(ProtocolVersion::PROTOCOL_VERSION_1.into()),
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
/// Mirrors the sync `dispatch` function above but talks to the
/// encrypted-session helpers from `mkit-transport-enc` instead of
/// `mkit-rpc`'s `read_frame` / `write_frame`. Kept inline (rather
/// than refactoring the existing sync dispatch to be transport-
/// generic) so this PR stays additive — the SSH stdin/stdout server
/// remains exactly as it was.
#[cfg(feature = "enc-transport")]
#[allow(
    clippy::too_many_lines,
    clippy::items_after_statements,
    clippy::cast_possible_truncation,
    clippy::box_default,
    clippy::manual_let_else
)]
async fn dispatch_enc_one(
    tx: &FileTransport,
    frame: SshFrame,
    sender: &mut mkit_transport_enc::EncSender<mkit_transport_enc::tokio_io::TokioSink>,
    receiver: &mut mkit_transport_enc::EncReceiver<mkit_transport_enc::tokio_io::TokioStream>,
    idle_timeout: Option<std::time::Duration>,
) -> Result<(), ()> {
    use mkit_core::protocol::PackKey;
    use mkit_rpc::mkit::rpc::v1::ssh::DownloadPackHeader;
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
    fn pack_key_from(b: Option<&Vec<u8>>) -> Result<PackKey, ()> {
        let v = b.ok_or(())?;
        if v.len() != 32 {
            return Err(());
        }
        let mut h = [0u8; 32];
        h.copy_from_slice(v);
        Ok(PackKey(h))
    }

    match frame.body {
        Some(ssh_frame::Body::PackExists(req)) => {
            let key = pack_key_from(req.pack_id.as_ref())?;
            let exists = tx.pack_exists(&key).unwrap_or(false);
            send_body(
                sender,
                ssh_frame::Body::PackExistsResponse(Box::new(PackExistsResponse {
                    exists: Some(exists),
                    ..Default::default()
                })),
            )
            .await
        }
        Some(ssh_frame::Body::DownloadPack(req)) => {
            let key = pack_key_from(req.pack_id.as_ref())?;
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
                    let mut iter_pos = 0usize;
                    let mut offset = 0u64;
                    let total = bytes.len();
                    if total == 0 {
                        return send_body(
                            sender,
                            ssh_frame::Body::PackChunk(Box::new(PackChunk {
                                pack_id: req.pack_id.clone(),
                                offset: Some(0),
                                data: Some(Vec::new()),
                                last: Some(true),
                                ..Default::default()
                            })),
                        )
                        .await;
                    }
                    const PACK_CHUNK_DATA_MAX: usize = 800 * 1024;
                    while iter_pos < total {
                        let end = core::cmp::min(iter_pos + PACK_CHUNK_DATA_MAX, total);
                        send_body(
                            sender,
                            ssh_frame::Body::PackChunk(Box::new(PackChunk {
                                pack_id: req.pack_id.clone(),
                                offset: Some(offset),
                                data: Some(bytes[iter_pos..end].to_vec()),
                                last: Some(end == total),
                                ..Default::default()
                            })),
                        )
                        .await?;
                        offset += (end - iter_pos) as u64;
                        iter_pos = end;
                    }
                    Ok(())
                }
                Err(_) => {
                    send_err(
                        sender,
                        ErrorCode::ERROR_CODE_KEY_NOT_FOUND,
                        "pack not found",
                    )
                    .await
                }
            }
        }
        Some(ssh_frame::Body::UploadPack(header)) => {
            let mut upload = match UploadDrain::new(&header) {
                Ok(upload) => upload,
                Err(e) => {
                    return send_err(sender, ErrorCode::ERROR_CODE_INVALID_REQUEST, e.message())
                        .await;
                }
            };
            loop {
                let f = recv_frame_idle(receiver, idle_timeout).await?;
                let Some(ssh_frame::Body::PackChunk(chunk)) = f.body else {
                    return send_err(
                        sender,
                        ErrorCode::ERROR_CODE_INVALID_REQUEST,
                        "expected PackChunk after UploadPack",
                    )
                    .await;
                };
                let complete = match upload.push_chunk(&chunk) {
                    Ok(complete) => complete,
                    Err(e) => {
                        return send_err(
                            sender,
                            ErrorCode::ERROR_CODE_INVALID_REQUEST,
                            e.message(),
                        )
                        .await;
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
                Err(_) => send_err(sender, ErrorCode::ERROR_CODE_INTERNAL, "upload failed").await,
            }
        }
        Some(ssh_frame::Body::ReadRef(req)) => {
            let name = req.name.unwrap_or_default();
            match tx.read_ref(&name) {
                Ok(Some(h)) => {
                    send_body(
                        sender,
                        ssh_frame::Body::ReadRefResponse(Box::new(ReadRefResponse {
                            object_id: Some(h.to_vec()),
                            ..Default::default()
                        })),
                    )
                    .await
                }
                Ok(None) => {
                    send_body(
                        sender,
                        ssh_frame::Body::ReadRefResponse(Box::new(ReadRefResponse {
                            object_id: Some(Vec::new()),
                            ..Default::default()
                        })),
                    )
                    .await
                }
                Err(_) => send_err(sender, ErrorCode::ERROR_CODE_INTERNAL, "read ref failed").await,
            }
        }
        Some(ssh_frame::Body::UpdateRef(req)) => {
            use mkit_core::protocol::RefWriteCondition;
            let name = req.name.unwrap_or_default();
            let new_id = req.new_id.unwrap_or_default();
            if new_id.len() != 32 {
                return send_err(
                    sender,
                    ErrorCode::ERROR_CODE_INVALID_REQUEST,
                    "new_id must be 32 bytes",
                )
                .await;
            }
            let mut new_h = [0u8; 32];
            new_h.copy_from_slice(&new_id);
            let expectation = req
                .expectation
                .as_ref()
                .and_then(buffa::EnumValue::as_known)
                .unwrap_or(RefExpectation::REF_EXPECTATION_UNSPECIFIED);
            let condition = match expectation {
                RefExpectation::REF_EXPECTATION_ANY => RefWriteCondition::Any,
                RefExpectation::REF_EXPECTATION_MISSING => RefWriteCondition::Missing,
                RefExpectation::REF_EXPECTATION_MATCH => {
                    let bytes = req.expected_id.as_deref().unwrap_or(&[]);
                    if bytes.len() != 32 {
                        return send_err(
                            sender,
                            ErrorCode::ERROR_CODE_INVALID_REQUEST,
                            "MATCH expectation requires a 32-byte expected_id",
                        )
                        .await;
                    }
                    let mut e = [0u8; 32];
                    e.copy_from_slice(bytes);
                    RefWriteCondition::Match(e)
                }
                RefExpectation::REF_EXPECTATION_UNSPECIFIED => {
                    return send_err(
                        sender,
                        ErrorCode::ERROR_CODE_INVALID_REQUEST,
                        "UpdateRef.expectation is required",
                    )
                    .await;
                }
            };
            match tx.update_ref(&name, condition, &new_h) {
                Ok(()) => {
                    send_body(sender, ssh_frame::Body::UpdateRefResponse(Box::default())).await
                }
                Err(_) => {
                    send_err(
                        sender,
                        ErrorCode::ERROR_CODE_INVALID_REQUEST,
                        "update ref failed",
                    )
                    .await
                }
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
                    send_body(
                        sender,
                        ssh_frame::Body::ListRefsResponse(Box::new(ListRefsResponse {
                            refs: entries,
                            ..Default::default()
                        })),
                    )
                    .await
                }
                Err(_) => {
                    send_err(sender, ErrorCode::ERROR_CODE_INTERNAL, "list refs failed").await
                }
            }
        }
        _ => {
            send_err(
                sender,
                ErrorCode::ERROR_CODE_INVALID_REQUEST,
                "unexpected frame",
            )
            .await
        }
    }
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
                let _ = emit_error(
                    w,
                    ErrorCode::ERROR_CODE_INVALID_REQUEST,
                    "frame parse error",
                );
                return exit::PROTOCOL_ERROR;
            }
        };

        frame_count = frame_count.saturating_add(1);
        if frame_count > MAX_FRAMES_PER_CONN {
            let _ = emit_error(
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
            let _ = emit_error(
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
        let _ = emit_error(
            w,
            ErrorCode::ERROR_CODE_INVALID_REQUEST,
            "first frame must be Hello",
        );
        return false;
    };
    let proto = hello.proto.as_ref().map_or(0, buffa::EnumValue::to_i32);
    if proto != ProtocolVersion::PROTOCOL_VERSION_1 as i32 {
        let _ = emit_error(
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
            let mut upload = match UploadDrain::new(&header) {
                Ok(upload) => upload,
                Err(e) => {
                    return emit_error(w, ErrorCode::ERROR_CODE_INVALID_REQUEST, e.message());
                }
            };
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
                let complete = match upload.push_chunk(&chunk) {
                    Ok(complete) => complete,
                    Err(e) => {
                        return emit_error(w, ErrorCode::ERROR_CODE_INVALID_REQUEST, e.message());
                    }
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
            // CAS intent = `expectation`. `expected_id` is only
            // consulted for MATCH and MUST be a 32-byte digest. See
            // SPEC-TRANSPORT §4.2.1.
            let expectation = req
                .expectation
                .as_ref()
                .and_then(buffa::EnumValue::as_known)
                .unwrap_or(RefExpectation::REF_EXPECTATION_UNSPECIFIED);
            let condition = match expectation {
                RefExpectation::REF_EXPECTATION_ANY => RefWriteCondition::Any,
                RefExpectation::REF_EXPECTATION_MISSING => RefWriteCondition::Missing,
                RefExpectation::REF_EXPECTATION_MATCH => {
                    let bytes = req.expected_id.as_deref().unwrap_or(&[]);
                    if bytes.len() != 32 {
                        return emit_error(
                            w,
                            ErrorCode::ERROR_CODE_INVALID_REQUEST,
                            "MATCH expectation requires a 32-byte expected_id",
                        );
                    }
                    let mut e = [0u8; 32];
                    e.copy_from_slice(bytes);
                    RefWriteCondition::Match(e)
                }
                RefExpectation::REF_EXPECTATION_UNSPECIFIED => {
                    return emit_error(
                        w,
                        ErrorCode::ERROR_CODE_INVALID_REQUEST,
                        "UpdateRef.expectation is required",
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

fn pack_key_from_bytes(bytes: Option<&Vec<u8>>) -> std::io::Result<PackKey> {
    let b = bytes.ok_or_else(|| std::io::Error::other("pack_id missing"))?;
    if b.len() != 32 {
        return Err(std::io::Error::other("pack_id must be 32 bytes"));
    }
    let mut h = [0u8; 32];
    h.copy_from_slice(b);
    Ok(PackKey(h))
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

// ---------------------------------------------------------------------------
// Server-side sparse-tree reference implementation (issue #158 Phase 2).
//
// The SSH transport is currently bytes-on-stream framed (mkit-rpc) and
// has no sparse-tree verb today; the Cloudflare Worker that backs the
// HTTP transport lives in `web/` outside the workspace. Both are
// expected to evolve to call this helper directly — it captures the
// "read the source tree, walk it with the supplied filter, produce a
// verifiable manifest+entries+proof" pipeline once so future server
// implementations stay byte-for-byte consistent with the client-side
// verifier.
//
// What the Cloudflare Worker would need to do:
//   1. Resolve `<project>/trees/<hex>` against R2.
//   2. Deserialise the resulting bytes into an `Object::Tree`.
//   3. Cross-check the URL's `?sparse=<filter-hex>` against
//      `hash_filter(filter_paths_from_body)`. Reject on mismatch with
//      HTTP 409 (transport surface: `RefConflict`).
//   4. Call `build_sparse_response_from_tree` here.
//   5. Serialise via `encode_sparse_response` and return as
//      `application/x-mkit-sparse`.
//
// All four steps are pure once you have the deserialised tree, hence
// the narrow `(tree, filter)` shape below.
// ---------------------------------------------------------------------------

/// Errors raised by [`build_sparse_response_from_tree`].
#[cfg(feature = "sparse-checkout")]
#[derive(Debug, thiserror::Error)]
pub enum SparseServeError {
    /// Forward of any [`mkit_core::sparse::SparseError`] — the source
    /// tree was unsorted, oversized, or the filter was too large.
    #[error("sparse build: {0}")]
    Build(#[from] mkit_core::sparse::SparseError),
}

/// Build a [`mkit_core::sparse::SparseResponse`] from an already-resolved
/// tree and a filter. Pure — no I/O. The caller has already loaded the
/// tree from whatever backing store they own (object store for `mkit
/// serve`, R2 for the Cloudflare Worker, memory transport for tests).
///
/// This is the reference implementation for the server side: any
/// conforming server MUST produce the same bytes given the same
/// `(tree, filter)` inputs, so a client comparing two server responses
/// would see a byte-for-byte match.
///
/// # Errors
///
/// Forwards [`mkit_core::sparse::SparseError`] — unsorted tree, too
/// many leaves, too many filter paths.
#[cfg(feature = "sparse-checkout")]
pub fn build_sparse_response_from_tree(
    tree: &mkit_core::object::Tree,
    filter: &[std::path::PathBuf],
) -> Result<mkit_core::sparse::SparseResponse, SparseServeError> {
    let (entries, manifest, proof) = mkit_core::sparse::build_sparse(tree, filter)?;
    Ok(mkit_core::sparse::SparseResponse {
        manifest,
        entries,
        proof,
    })
}

/// Convenience: resolve a `tree_hash` from `store` and build a sparse
/// response. Used by both the on-disk `mkit serve` path (when an SSH
/// verb is eventually added) and by integration tests that drive the
/// server pipeline end-to-end.
///
/// # Errors
///
/// - [`mkit_core::store::StoreError`] surfaces if `tree_hash` is not
///   present or the on-disk object is malformed.
/// - The address must resolve to an `Object::Tree`; anything else is
///   reported as `StoreError::IntegrityFailure` with a descriptive
///   message. (We rewrap rather than introduce a new error type so the
///   downstream serve loop can keep its existing error taxonomy.)
#[cfg(feature = "sparse-checkout")]
pub fn build_sparse_response_from_store(
    store: &mkit_core::store::ObjectStore,
    tree_hash: &mkit_core::hash::Hash,
    filter: &[std::path::PathBuf],
) -> Result<mkit_core::sparse::SparseResponse, String> {
    use mkit_core::object::Object;
    let tree = match store.read_object(tree_hash) {
        Ok(Object::Tree(t)) => t,
        Ok(_) => return Err("addressed object is not a tree".to_string()),
        Err(e) => return Err(format!("read tree: {e}")),
    };
    build_sparse_response_from_tree(&tree, filter).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exit;
    use std::fs;
    use std::io::Cursor;

    fn upload_header(pack_id: Vec<u8>, total_bytes: Option<u64>) -> UploadPack {
        UploadPack {
            pack_id: Some(pack_id),
            total_bytes,
            ..Default::default()
        }
    }

    fn upload_chunk(pack_id: Vec<u8>, offset: Option<u64>, data: &[u8], last: bool) -> PackChunk {
        PackChunk {
            pack_id: Some(pack_id),
            offset,
            data: Some(data.to_vec()),
            last: Some(last),
            ..Default::default()
        }
    }

    fn valid_pack() -> (Vec<u8>, PackKey) {
        let bytes = b"valid pack bytes".to_vec();
        let key = PackKey::new(hash(&bytes));
        (bytes, key)
    }

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

    #[test]
    fn upload_drain_accepts_valid_chunks() {
        let (bytes, key) = valid_pack();
        let mut drain = UploadDrain::new(&upload_header(
            key.as_bytes().to_vec(),
            Some(bytes.len() as u64),
        ))
        .unwrap();
        assert!(
            !drain
                .push_chunk(&upload_chunk(
                    key.as_bytes().to_vec(),
                    Some(0),
                    &bytes[..5],
                    false
                ))
                .unwrap()
        );
        assert!(
            drain
                .push_chunk(&upload_chunk(
                    key.as_bytes().to_vec(),
                    Some(5),
                    &bytes[5..],
                    true,
                ))
                .unwrap()
        );
        let (got, got_key) = drain.into_parts();
        assert_eq!(got, bytes);
        assert_eq!(got_key.as_bytes(), key.as_bytes());
    }

    #[test]
    fn upload_drain_rejects_malformed_streams() {
        let (bytes, key) = valid_pack();
        assert!(UploadDrain::new(&upload_header(key.as_bytes().to_vec(), None)).is_err());
        assert!(
            UploadDrain::new(&upload_header(
                key.as_bytes().to_vec(),
                Some(MAX_BYTES_PER_CONN + 1),
            ))
            .is_err()
        );

        let mut drain = UploadDrain::new(&upload_header(
            key.as_bytes().to_vec(),
            Some(bytes.len() as u64),
        ))
        .unwrap();
        assert!(
            drain
                .push_chunk(&upload_chunk(
                    key.as_bytes().to_vec(),
                    Some(1),
                    &bytes,
                    true
                ))
                .is_err()
        );

        let mut drain = UploadDrain::new(&upload_header(
            key.as_bytes().to_vec(),
            Some(bytes.len() as u64),
        ))
        .unwrap();
        assert!(
            drain
                .push_chunk(&upload_chunk(vec![0xAA; 32], Some(0), &bytes, true))
                .is_err()
        );

        let mut drain = UploadDrain::new(&upload_header(
            key.as_bytes().to_vec(),
            Some(bytes.len() as u64 - 1),
        ))
        .unwrap();
        assert!(
            drain
                .push_chunk(&upload_chunk(
                    key.as_bytes().to_vec(),
                    Some(0),
                    &bytes,
                    true
                ))
                .is_err()
        );

        let mut drain = UploadDrain::new(&upload_header(
            key.as_bytes().to_vec(),
            Some(bytes.len() as u64),
        ))
        .unwrap();
        assert!(
            drain
                .push_chunk(&upload_chunk(
                    key.as_bytes().to_vec(),
                    Some(0),
                    &bytes[..bytes.len() - 1],
                    true,
                ))
                .is_err()
        );

        let wrong_bytes = b"wrong pack bytes";
        let mut drain = UploadDrain::new(&upload_header(
            key.as_bytes().to_vec(),
            Some(wrong_bytes.len() as u64),
        ))
        .unwrap();
        assert!(
            drain
                .push_chunk(&upload_chunk(
                    key.as_bytes().to_vec(),
                    Some(0),
                    wrong_bytes,
                    true,
                ))
                .is_err()
        );
    }

    fn write_body(buf: &mut Vec<u8>, body: ssh_frame::Body) {
        mkit_rpc::write_frame(
            buf,
            &SshFrame {
                body: Some(body),
                ..Default::default()
            },
        )
        .unwrap();
    }

    #[test]
    fn serve_loop_rejects_invalid_upload_before_storage() {
        let td = tempfile::tempdir().unwrap();
        let tx = FileTransport::new(td.path());
        let bogus_key = PackKey::new([0x77; 32]);

        let mut input = Vec::new();
        write_body(
            &mut input,
            ssh_frame::Body::Hello(Box::new(
                mkit_rpc::mkit::rpc::v1::ssh::Hello::default()
                    .with_proto(ProtocolVersion::PROTOCOL_VERSION_1),
            )),
        );
        write_body(
            &mut input,
            ssh_frame::Body::UploadPack(Box::new(upload_header(
                bogus_key.as_bytes().to_vec(),
                Some(5),
            ))),
        );
        write_body(
            &mut input,
            ssh_frame::Body::PackChunk(Box::new(upload_chunk(
                bogus_key.as_bytes().to_vec(),
                Some(0),
                b"wrong",
                true,
            ))),
        );

        let mut reader = Cursor::new(input);
        let mut output = Vec::new();
        assert_eq!(serve_loop(&tx, &mut reader, &mut output), exit::OK);
        assert!(!tx.pack_exists(&bogus_key).unwrap());

        let mut out = Cursor::new(output);
        let _hello: SshFrame = mkit_rpc::read_frame(&mut out).unwrap();
        let err: SshFrame = mkit_rpc::read_frame(&mut out).unwrap();
        assert!(matches!(err.body, Some(ssh_frame::Body::Error(_))));
    }

    #[test]
    fn serve_loop_rejected_upload_does_not_overwrite_existing_pack() {
        let td = tempfile::tempdir().unwrap();
        let tx = FileTransport::new(td.path());
        let (bytes, key) = valid_pack();
        tx.upload_pack(&bytes, &key).unwrap();

        let mut input = Vec::new();
        write_body(
            &mut input,
            ssh_frame::Body::Hello(Box::new(
                mkit_rpc::mkit::rpc::v1::ssh::Hello::default()
                    .with_proto(ProtocolVersion::PROTOCOL_VERSION_1),
            )),
        );
        write_body(
            &mut input,
            ssh_frame::Body::UploadPack(Box::new(upload_header(key.as_bytes().to_vec(), Some(5)))),
        );
        write_body(
            &mut input,
            ssh_frame::Body::PackChunk(Box::new(upload_chunk(
                key.as_bytes().to_vec(),
                Some(0),
                b"wrong",
                true,
            ))),
        );

        let mut reader = Cursor::new(input);
        let mut output = Vec::new();
        assert_eq!(serve_loop(&tx, &mut reader, &mut output), exit::OK);
        assert_eq!(tx.download_pack(&key).unwrap(), bytes);
    }

    #[cfg(feature = "enc-transport")]
    #[test]
    fn listen_enc_rejected_upload_does_not_overwrite_existing_pack() {
        use commonware_codec::Encode as _;
        use commonware_cryptography::Signer as _;
        use commonware_cryptography::ed25519::PrivateKey;
        use mkit_transport_enc::tcp::{
            TokioExecutor, connect_tcp_with_executor, serve_tcp_with_addr,
        };
        use std::sync::{Arc, mpsc};
        use std::thread;
        use std::time::Duration;

        let td = tempfile::tempdir().unwrap();
        let tx = FileTransport::new(td.path());
        let (bytes, key) = valid_pack();
        tx.upload_pack(&bytes, &key).unwrap();

        let exec = TokioExecutor::new().expect("tokio runtime");
        let server_key = PrivateKey::from_seed(1001);
        let server_pubkey = {
            let encoded = server_key.public_key().encode();
            let bytes = encoded.as_ref();
            assert_eq!(bytes.len(), 32);
            let mut out = [0u8; 32];
            out.copy_from_slice(bytes);
            out
        };

        let server_tx = Arc::new(FileTransport::new(td.path()));
        let (addr_tx, addr_rx) = mpsc::channel();
        let exec_for_server = exec.clone();
        let _server_handle = thread::spawn(move || {
            let serve_fn =
                move |sess: mkit_transport_enc::EncSession<
                    mkit_transport_enc::tokio_io::TokioStream,
                    mkit_transport_enc::tokio_io::TokioSink,
                >,
                      _peer: commonware_cryptography::ed25519::PublicKey| {
                    let tx = server_tx.clone();
                    // Tests drive a cooperative client, so the idle
                    // timeout is irrelevant here; keep it generous.
                    async move {
                        serve_enc_session(tx, sess, Some(std::time::Duration::from_secs(30))).await;
                    }
                };
            let _ = serve_tcp_with_addr(
                "127.0.0.1:0",
                server_key,
                exec_for_server,
                move |addr| {
                    let _ = addr_tx.send(addr);
                },
                serve_fn,
            );
        });

        let addr = addr_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("encrypted listener address");
        let client_key = PrivateKey::from_seed(2002);
        let client = connect_tcp_with_executor(
            &addr.ip().to_string(),
            addr.port(),
            &server_pubkey,
            client_key,
            exec,
        )
        .expect("connect encrypted client");

        assert!(client.upload_pack(b"wrong", &key).is_err());
        assert_eq!(tx.download_pack(&key).unwrap(), bytes);
    }

    // Note: containment via MKIT_SERVE_ROOT is enforced — tested via
    // an integration test in tests/ rather than here, since this
    // crate forbids `unsafe` (which `std::env::set_var` requires
    // since Rust 1.92).

    #[cfg(feature = "enc-transport")]
    fn enc_repo() -> tempfile::TempDir {
        let td = tempfile::tempdir().unwrap();
        fs::create_dir_all(td.path().join(".mkit")).unwrap();
        td
    }

    /// Fail-closed: `serve --listen-enc` with neither an authorized-peers
    /// file nor the unsafe flag returns `CONFIG_ERROR` before binding.
    #[cfg(feature = "enc-transport")]
    #[test]
    fn listen_enc_fails_closed_without_peer_auth() {
        let td = enc_repo();
        let args = vec![
            td.path().to_str().unwrap().to_string(),
            "--listen-enc".to_string(),
            "127.0.0.1:0".to_string(),
        ];
        assert_eq!(run(&args), exit::CONFIG_ERROR);
    }

    /// An authorized-peers file that exists but parses to no valid keys
    /// is rejected (fail-closed), not silently treated as allow-any.
    #[cfg(feature = "enc-transport")]
    #[test]
    fn listen_enc_rejects_empty_authorized_peers() {
        let td = enc_repo();
        let peers = td.path().join("peers.txt");
        fs::write(&peers, "# only comments\n\n").unwrap();
        let args = vec![
            td.path().to_str().unwrap().to_string(),
            "--listen-enc".to_string(),
            "127.0.0.1:0".to_string(),
            "--enc-authorized-peers".to_string(),
            peers.to_str().unwrap().to_string(),
        ];
        assert_eq!(run(&args), exit::CONFIG_ERROR);
    }

    /// Supplying both `--enc-authorized-peers` and the unsafe flag is a
    /// usage error.
    #[cfg(feature = "enc-transport")]
    #[test]
    fn listen_enc_rejects_conflicting_flags() {
        let td = enc_repo();
        let peers = td.path().join("peers.txt");
        fs::write(&peers, format!("{}\n", "aa".repeat(32))).unwrap();
        let args = vec![
            td.path().to_str().unwrap().to_string(),
            "--listen-enc".to_string(),
            "127.0.0.1:0".to_string(),
            "--enc-authorized-peers".to_string(),
            peers.to_str().unwrap().to_string(),
            "--unsafe-allow-any-enc-peer".to_string(),
        ];
        assert_eq!(run(&args), exit::USAGE);
    }

    #[cfg(feature = "enc-transport")]
    #[test]
    fn authorized_peers_parses_hex_and_skips_comments() {
        let td = tempfile::tempdir().unwrap();
        let peers = td.path().join("peers.txt");
        let k1 = "aa".repeat(32);
        let k2 = "bb".repeat(32);
        fs::write(&peers, format!("# header\n{k1}\n\n  {k2}  \n")).unwrap();
        let set = load_authorized_peers(peers.to_str().unwrap()).unwrap();
        assert_eq!(set.len(), 2);
        assert!(set.contains(&[0xAA; 32]));
        assert!(set.contains(&[0xBB; 32]));
    }

    /// The allowlist file accepts the SAME 43-char url-safe base64
    /// encoding the `mkit+enc://?pubkey=` query uses, and it decodes to
    /// the identical 32-byte key as the hex form. Without this the docs
    /// and `--enc-authorized-peers` help would promise base64 support
    /// that the parser silently rejected.
    #[cfg(feature = "enc-transport")]
    #[test]
    #[allow(clippy::cast_possible_truncation)] // test-only b64 encoder
    fn authorized_peers_parses_base64_matching_hex() {
        // A key whose final byte's low bits are zero so the canonical
        // 43-char base64 has zero trailing bits. All-0xAA: last byte 0xAA.
        // Build from a real ed25519 public key to guarantee a valid pair
        // of encodings.
        use commonware_codec::Encode as _;
        use commonware_cryptography::Signer as _;
        use commonware_cryptography::ed25519::PrivateKey;

        let pk = PrivateKey::from_seed(4242).public_key();
        let raw: [u8; 32] = {
            let enc = pk.encode();
            let mut out = [0u8; 32];
            out.copy_from_slice(enc.as_ref());
            out
        };
        let hex = mkit_core::hash::to_hex(&raw);
        // Round-trip the raw bytes through our own base64 decoder by
        // first encoding with the standard alphabet.
        let b64 = {
            const A: &[u8; 64] =
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
            let mut s = String::new();
            for chunk in raw.chunks(3) {
                let b0 = u32::from(chunk[0]);
                let b1 = chunk.get(1).copied().map_or(0, u32::from);
                let b2 = chunk.get(2).copied().map_or(0, u32::from);
                let n = (b0 << 16) | (b1 << 8) | b2;
                let chars = match chunk.len() {
                    1 => 2,
                    2 => 3,
                    _ => 4,
                };
                for i in 0..chars {
                    let idx = ((n >> (18 - 6 * i)) & 0x3F) as usize;
                    s.push(A[idx] as char);
                }
            }
            s
        };
        assert_eq!(b64.len(), 43, "ed25519 key encodes to 43 b64 chars");

        let td = tempfile::tempdir().unwrap();
        let peers = td.path().join("peers.txt");
        fs::write(&peers, format!("{hex}\n{b64}\n")).unwrap();
        let set = load_authorized_peers(peers.to_str().unwrap()).unwrap();
        // Both lines decode to the SAME key, so the set has one element.
        assert_eq!(set.len(), 1, "hex and base64 forms must coincide");
        assert!(set.contains(&raw));
    }

    #[cfg(feature = "enc-transport")]
    #[test]
    fn authorized_peers_rejects_malformed_key() {
        let td = tempfile::tempdir().unwrap();
        let peers = td.path().join("peers.txt");
        fs::write(&peers, "not-a-valid-key\n").unwrap();
        assert!(load_authorized_peers(peers.to_str().unwrap()).is_err());
    }
}
