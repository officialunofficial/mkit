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
use mkit_core::protocol::{PackKey, RefWriteCondition, Transport};
use mkit_rpc::mkit::rpc::v1::ssh::{
    DownloadPackHeader, HelloResponse, ListRefsResponse, PackChunk, PackExistsResponse,
    ReadRefResponse, RefExpectation, SshFrame, UploadPackResponse, list_refs_response::RefEntry,
    ssh_frame,
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
    /// The listener generates an ephemeral ed25519 keypair per
    /// process by default; keystore integration is deferred (#5 in
    /// the punch list). Clients establish trust out-of-band via the
    /// `?pubkey=<…>` query parameter on their `mkit+enc://` URL.
    #[arg(long = "listen-enc", value_name = "ADDR")]
    listen_enc: Option<String>,
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
        return run_listen_enc(addr, repo_root);
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
fn run_listen_enc(_addr: &str, _repo_root: PathBuf) -> u8 {
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
    clippy::too_many_lines
)]
fn run_listen_enc(addr: &str, repo_root: PathBuf) -> u8 {
    use commonware_codec::DecodeExt as _;
    use commonware_cryptography::Signer as _;
    use commonware_cryptography::ed25519::PrivateKey;
    use mkit_transport_enc::{EncSession, recv_frame, send_frame};
    use std::sync::Arc;
    use zeroize::Zeroizing;

    // Ephemeral signing key. Same caveat as remote_dispatch's
    // dialer key — keystore integration is deferred. The
    // server's public key is what clients pin via the
    // `?pubkey=<…>` query parameter; operators currently must read
    // the printed key off the serve process's stderr.
    //
    // The previous shape passed only 64 bits of entropy (a `u64`
    // seed via `PrivateKey::from_seed`) — commonware's own
    // documentation calls `from_seed` "insecure" and reserves it
    // for examples / testing. Draw 32 bytes (≥256 bits) from
    // `getrandom` and hand them to the Ed25519 SigningKey via
    // commonware-codec's `DecodeExt::decode`, mirroring
    // `PrivateKey`'s own `Read` impl. The intermediate bytes are
    // wrapped in `Zeroizing` so the stack copy is scrubbed on drop;
    // the resulting `PrivateKey` carries its own `Secret`-based
    // zeroization for the lifetime of the value.
    let mut secret = Zeroizing::new([0u8; 32]);
    if getrandom::fill(secret.as_mut()).is_err() {
        eprintln!("mkit serve --listen-enc: failed to read system RNG for ephemeral key");
        return exit::TEMPFAIL;
    }
    let sk = match PrivateKey::decode(secret.as_ref()) {
        Ok(sk) => sk,
        Err(e) => {
            eprintln!("mkit serve --listen-enc: ephemeral key construction failed: {e}");
            return exit::TEMPFAIL;
        }
    };
    // `secret` drops here and is zeroized; `sk` holds an internal
    // `Secret` that scrubs on its own drop.
    let pk = sk.public_key().to_string();
    eprintln!(
        "mkit serve --listen-enc on {addr} (server pubkey = {pk}); \
         clients dial mkit+enc://<host>:<port>?pubkey={pk}"
    );

    let tx = Arc::new(FileTransport::new(&repo_root));

    let serve_fn = move |sess: EncSession<
        mkit_transport_enc::tokio_io::TokioStream,
        mkit_transport_enc::tokio_io::TokioSink,
    >,
                         _peer: commonware_cryptography::ed25519::PublicKey| {
        let tx = tx.clone();
        // Each accepted connection gets its own future. `serve_tcp`
        // awaits this inside a per-connection `tokio::spawn`, so we
        // can `.await` freely without deadlocking the listener.
        async move {
            let (mut sender, mut receiver) = sess.into_parts();
            // App-level Hello.
            let frame = match recv_frame(&mut receiver).await {
                Ok(f) => f,
                Err(_) => return,
            };
            let proto = match frame.body {
                Some(ssh_frame::Body::Hello(h)) => {
                    h.proto.as_ref().map_or(0, buffa::EnumValue::to_i32)
                }
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

            // Verb loop. Mirrors the stdin/stdout `serve_loop`'s
            // dispatch decisions but uses the async encrypted-frame
            // helpers so we never block the listener's tokio worker.
            loop {
                let frame = match recv_frame(&mut receiver).await {
                    Ok(f) => f,
                    Err(_) => return,
                };
                if let Some(ssh_frame::Body::Close(_)) = frame.body {
                    return;
                }
                if dispatch_enc_one(&tx, frame, &mut sender, &mut receiver)
                    .await
                    .is_err()
                {
                    return;
                }
            }
        }
    };

    match mkit_transport_enc::serve_tcp(addr, sk, serve_fn) {
        Ok(()) => exit::OK,
        Err(e) => {
            eprintln!("mkit serve --listen-enc: {e}");
            exit::TEMPFAIL
        }
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
) -> Result<(), ()> {
    use mkit_core::protocol::PackKey;
    use mkit_rpc::mkit::rpc::v1::ssh::DownloadPackHeader;
    use mkit_transport_enc::{recv_frame, send_frame};

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
            let total = header.total_bytes.unwrap_or(0) as usize;
            let mut accum = Vec::with_capacity(total);
            loop {
                let f = recv_frame(receiver).await.map_err(|_| ())?;
                let Some(ssh_frame::Body::PackChunk(chunk)) = f.body else {
                    return send_err(
                        sender,
                        ErrorCode::ERROR_CODE_INVALID_REQUEST,
                        "expected PackChunk after UploadPack",
                    )
                    .await;
                };
                if let Some(d) = chunk.data {
                    accum.extend_from_slice(&d);
                }
                if chunk.last.unwrap_or(false) {
                    break;
                }
            }
            let key = pack_key_from(header.pack_id.as_ref())?;
            match tx.upload_pack(&accum, &key) {
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
