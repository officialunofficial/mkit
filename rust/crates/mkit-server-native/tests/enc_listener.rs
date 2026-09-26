//! `mkit-server serve --listen-enc`: the fail-closed gate and the
//! allowlist parser (moved from `mkit serve --listen-enc`'s tests, with
//! their names), and sessions over real loopback TCP, in process
//! (`config::resolve`, `server::open`, `enc::serve`) and against the
//! spawned binary.
//!
//! Every session runs `mkit_server::ssh::serve_session`, so its error
//! replies are the ssh session's (SPEC-TRANSPORT §4.2, SPEC-TRANSPORT-ENC
//! §3): `listen_enc_rejects_non_hello_first_frame` and
//! `listen_enc_error_replies_match_the_ssh_session` pin the replies that
//! changed from the old enc dispatcher.

#![cfg(unix)]
#![allow(clippy::unwrap_used)] // unwrap is the assertion in tests

mod common;

use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use commonware_codec::Encode as _;
use commonware_cryptography::Signer as _;
use commonware_cryptography::ed25519::PrivateKey;
use mkit_core::hash::hash;
use mkit_core::protocol::{PackKey, RefWriteCondition, Transport, TransportError};
use mkit_rpc::mkit::rpc::v1::ssh::{Hello, ListRefs, PackChunk, SshFrame, UploadPack, ssh_frame};
use mkit_rpc::mkit::rpc::v1::{Error as RpcError, ErrorCode, ProtocolVersion};
use mkit_server::ssh::MAX_FRAMES_PER_CONN;
use mkit_server_native::{Shutdown, enc, exit, server};
use mkit_transport_enc::tcp::{
    TokioExecutor, connect_tcp_with_executor, dial_tcp_session_for_test,
};
use mkit_transport_enc::tokio_io::{TokioSink, TokioStream};
use mkit_transport_enc::{
    EncReceiver, EncSender, HANDSHAKE_NAMESPACE, recv_frame_within, send_frame,
};
use mkit_transport_file::FileTransport;

type Client = mkit_transport_enc::EncTransport<TokioStream, TokioSink, TokioExecutor>;

fn raw_pubkey(key: &PrivateKey) -> [u8; 32] {
    key.public_key().encode().as_ref().try_into().unwrap()
}

fn valid_pack() -> (Vec<u8>, PackKey) {
    let bytes = b"valid pack bytes".to_vec();
    let key = PackKey::new(hash(&bytes));
    (bytes, key)
}

/// A served root, canonical: key files must have no symlinked ancestor.
fn enc_repo() -> (tempfile::TempDir, PathBuf) {
    let td = common::repo_root();
    let path = fs::canonicalize(td.path()).unwrap();
    (td, path)
}

/// An in-process `mkit-server serve --listen-enc` on a loopback port:
/// `config::resolve`, `server::open`, then `enc::serve`.
struct EncServer {
    addr: SocketAddr,
    pubkey: [u8; 32],
    shutdown: Shutdown,
    served: Option<tokio::task::JoinHandle<Result<(), mkit_transport_enc::EncInitError>>>,
    runtime: tokio::runtime::Runtime,
    _locks: server::ServerLocks,
}

impl EncServer {
    fn start(root: &Path, flags: &[&str]) -> Self {
        let mut all = vec![
            "--listen-enc",
            "127.0.0.1:0",
            "--repo-root",
            common::s(root),
        ];
        all.extend_from_slice(flags);
        let cfg = common::resolve_with(&all, &[]).unwrap();
        let (services, locks) = server::open(&cfg).unwrap().into_parts();
        let service = services.enc.unwrap();
        let pubkey = raw_pubkey(&service.key);
        let opts = cfg.enc.clone().unwrap();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let listener = runtime
            .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = Shutdown::new();
        let stop = shutdown.clone();
        let served = runtime.spawn(async move { enc::serve(listener, service, &opts, stop).await });
        Self {
            addr,
            pubkey,
            shutdown,
            served: Some(served),
            runtime,
            _locks: locks,
        }
    }

    /// Trigger the shutdown; how long `enc::serve` then took to return.
    fn stop(&mut self) -> Duration {
        let served = self.served.take().unwrap();
        let start = Instant::now();
        self.shutdown.trigger();
        let result = self
            .runtime
            .block_on(async { tokio::time::timeout(Duration::from_mins(1), served).await })
            .expect("enc::serve returned")
            .unwrap();
        assert!(result.is_ok(), "{result:?}");
        start.elapsed()
    }

    /// Unsafe allow-any with an ephemeral key.
    fn open(root: &Path) -> Self {
        Self::start(root, &["--unsafe-allow-any-enc-peer"])
    }

    /// A `connect_tcp` client (it sends `Hello`) with the key of `seed`.
    fn client(&self, seed: u64) -> Result<Client, mkit_transport_enc::EncInitError> {
        connect_tcp_with_executor(
            &self.addr.ip().to_string(),
            self.addr.port(),
            &self.pubkey,
            PrivateKey::from_seed(seed),
            TokioExecutor::new().unwrap(),
        )
    }

    /// Connect (handshake and `Hello`) and list refs with the key of
    /// `seed` on another thread; the receiver gets whether it worked. The
    /// session then stays open for a while.
    fn connect_in_thread(&self, seed: u64) -> std::sync::mpsc::Receiver<bool> {
        let (addr, pubkey) = (self.addr, self.pubkey);
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let client = connect_tcp_with_executor(
                &addr.ip().to_string(),
                addr.port(),
                &pubkey,
                PrivateKey::from_seed(seed),
                TokioExecutor::new().unwrap(),
            );
            let worked = client.as_ref().is_ok_and(|c| c.list_refs("").is_ok());
            let _ = tx.send(worked);
            std::thread::sleep(Duration::from_secs(10));
        });
        rx
    }

    /// A session past the encrypted handshake, before any frame.
    fn raw(&self, seed: u64) -> Raw {
        let exec = TokioExecutor::new().unwrap();
        let session = dial_tcp_session_for_test(
            &self.addr.ip().to_string(),
            self.addr.port(),
            &self.pubkey,
            PrivateKey::from_seed(seed),
            HANDSHAKE_NAMESPACE.to_vec(),
            &exec,
        )
        .unwrap();
        let (sender, receiver) = session.into_parts();
        Raw {
            exec,
            sender,
            receiver,
        }
    }
}

impl Drop for EncServer {
    fn drop(&mut self) {
        // The runtime, dropped next, cancels what is left.
        self.shutdown.trigger();
    }
}

/// One enc session driven frame by frame.
struct Raw {
    exec: TokioExecutor,
    sender: EncSender<TokioSink>,
    receiver: EncReceiver<TokioStream>,
}

impl Raw {
    fn send(&mut self, body: ssh_frame::Body) {
        self.send_frame(&SshFrame {
            body: Some(body),
            ..Default::default()
        });
    }

    fn send_frame(&mut self, frame: &SshFrame) {
        let sender = &mut self.sender;
        self.exec
            .handle()
            .block_on(send_frame(sender, frame))
            .unwrap();
    }

    /// Send one encrypted record that is not an `SshFrame`.
    fn send_garbage(&mut self) {
        let sender = &mut self.sender;
        self.exec
            .handle()
            .block_on(sender.send(vec![0xff; 16]))
            .unwrap();
    }

    fn recv(&mut self, within: Duration) -> Result<SshFrame, TransportError> {
        let receiver = &mut self.receiver;
        self.exec
            .handle()
            .block_on(recv_frame_within(receiver, within))
    }

    fn hello(&mut self) {
        self.send(ssh_frame::Body::Hello(Box::new(Hello {
            proto: Some(ProtocolVersion::ProtocolVersion1.into()),
            client_id: Some("test".to_owned()),
            ..Default::default()
        })));
        match self.recv(Duration::from_secs(10)).unwrap().body {
            Some(ssh_frame::Body::HelloResponse(r)) => {
                assert_eq!(r.server_id.as_deref(), Some(enc::server_id().as_str()));
                assert!(enc::server_id().starts_with("mkit serve-enc/"));
            }
            other => panic!("expected HelloResponse, got {other:?}"),
        }
    }

    /// The next frame must be `Error{code, message}`.
    fn expect_error(&mut self, code: ErrorCode, message: &str) {
        match self.recv(Duration::from_secs(10)).unwrap().body {
            Some(ssh_frame::Body::Error(e)) => {
                let e: RpcError = *e;
                assert!(e.code.is_some_and(|c| c == code), "{e:?}");
                assert_eq!(e.message.as_deref(), Some(message), "{e:?}");
            }
            other => panic!("expected Error {message:?}, got {other:?}"),
        }
    }

    /// The server closes the session: the next read fails at once, not
    /// by timing out.
    fn expect_closed(&mut self) {
        let start = Instant::now();
        assert!(self.recv(Duration::from_secs(10)).is_err());
        assert!(
            start.elapsed() < Duration::from_secs(9),
            "session not closed"
        );
    }
}

// ---------------------------------------------------------------------------
// Moved from mkit-cli's `serve` tests.

#[test]
// Real localhost TCP; kept in the serial `--ignored` lane, whose filter
// (rust/.config/nextest.toml) names the four `listen_enc_*` real-TCP tests.
#[ignore = "real localhost TCP + wall-clock recv_timeout; run via the serial --ignored CI lane"]
fn listen_enc_rejected_upload_does_not_overwrite_existing_pack() {
    let (_td, root) = enc_repo();
    let tx = FileTransport::new(&root);
    let (bytes, key) = valid_pack();
    tx.upload_pack(&bytes, &key).unwrap();

    let server = EncServer::open(&root);
    let client = server.client(2002).unwrap();
    assert!(client.upload_pack(b"wrong", &key).is_err());
    assert_eq!(tx.download_pack(&key).unwrap(), bytes);
}

#[test]
#[ignore = "real localhost TCP + wall-clock recv_timeout; run via the serial --ignored CI lane"]
fn listen_enc_rejects_non_hello_first_frame() {
    // SPEC-RPC §4 / SPEC-TRANSPORT §4.2: the first frame after the crypto
    // handshake must be `Hello`. Over the shared ssh session a peer that
    // skips it gets `Error{INVALID_REQUEST, "first frame must be Hello"}`
    // and the session closes, without the request being served. (`mkit
    // serve --listen-enc` closed without replying.)
    let (_td, root) = enc_repo();
    let server = EncServer::open(&root);
    let mut raw = server.raw(6006);
    raw.send(ssh_frame::Body::ListRefs(Box::<ListRefs>::default()));
    raw.expect_error(ErrorCode::InvalidRequest, "first frame must be Hello");
    raw.expect_closed();
}

#[test]
#[ignore = "real localhost TCP + wall-clock recv_timeout; run via the serial --ignored CI lane"]
fn listen_enc_cas_conflict_classifies_as_ref_conflict() {
    // SPEC-TRANSPORT §4.2.1 over the real listener: a stale MATCH update
    // surfaces as `RefConflict` through the enc client, and the losing
    // write clobbers nothing.
    let (_td, root) = enc_repo();
    let tx = FileTransport::new(&root);
    let current = [0x11u8; 32];
    let stale = [0x22u8; 32];
    let next = [0x33u8; 32];
    tx.update_ref("refs/heads/main", RefWriteCondition::Any, &current)
        .unwrap();

    let server = EncServer::open(&root);
    let client = server.client(4004).unwrap();
    let err = client
        .update_ref("refs/heads/main", RefWriteCondition::Match(stale), &next)
        .unwrap_err();
    assert!(
        matches!(err, TransportError::RefConflict),
        "stale MATCH over the enc transport must classify as RefConflict, got {err:?}"
    );
    assert_eq!(tx.read_ref("refs/heads/main").unwrap(), Some(current));
}

#[test]
#[ignore = "real localhost TCP + MAX_FRAMES_PER_CONN round trips; run via the serial --ignored CI lane"]
fn listen_enc_terminates_connection_past_frame_budget() {
    // SPEC-TRANSPORT §4.4: the enc session enforces the ssh session's
    // cumulative frame budget.
    let (_td, root) = enc_repo();
    let server = EncServer::open(&root);
    let client = server.client(6006).unwrap();
    for _ in 0..MAX_FRAMES_PER_CONN {
        client
            .read_ref("refs/heads/does-not-exist")
            .expect("request under the frame budget must succeed");
    }
    let err = client.read_ref("refs/heads/does-not-exist").unwrap_err();
    assert!(
        !matches!(err, TransportError::InvalidRef(_)),
        "budget rejection must not be misclassified as a client-side validation error, got {err:?}"
    );
}

/// Fail-closed: `--listen-enc` with neither an allowlist nor the unsafe
/// flag is refused before binding.
#[test]
fn listen_enc_fails_closed_without_peer_auth() {
    let (_td, root) = enc_repo();
    let err = common::resolve_with(
        &[
            "--listen-enc",
            "127.0.0.1:0",
            "--repo-root",
            common::s(&root),
        ],
        &[],
    )
    .unwrap_err();
    assert_eq!(err.code, exit::CONFIG_ERROR);
    assert!(err.message.contains("refusing to bind"), "{}", err.message);
}

/// An allowlist that parses to no key is refused, not read as allow-any.
#[test]
fn listen_enc_rejects_empty_authorized_peers() {
    let (_td, root) = enc_repo();
    let peers = root.join("peers.txt");
    fs::write(&peers, "# only comments\n\n").unwrap();
    let err = common::resolve_with(
        &[
            "--listen-enc",
            "127.0.0.1:0",
            "--repo-root",
            common::s(&root),
            "--enc-authorized-peers",
            common::s(&peers),
            "--enc-server-key",
            common::s(&root.join("server.key")),
        ],
        &[],
    )
    .unwrap_err();
    assert_eq!(err.code, exit::CONFIG_ERROR);
    assert!(
        err.message.contains("no valid peer keys"),
        "{}",
        err.message
    );
}

/// An allowlist together with the unsafe flag is a usage error.
#[test]
fn listen_enc_rejects_conflicting_flags() {
    let (_td, root) = enc_repo();
    let peers = root.join("peers.txt");
    fs::write(&peers, format!("{}\n", "aa".repeat(32))).unwrap();
    let err = common::resolve_with(
        &[
            "--listen-enc",
            "127.0.0.1:0",
            "--repo-root",
            common::s(&root),
            "--enc-authorized-peers",
            common::s(&peers),
            "--unsafe-allow-any-enc-peer",
        ],
        &[],
    )
    .unwrap_err();
    assert_eq!(err.code, exit::USAGE);
}

#[test]
fn authorized_peers_parses_hex_and_skips_comments() {
    let td = tempfile::tempdir().unwrap();
    let peers = td.path().join("peers.txt");
    let k1 = "aa".repeat(32);
    let k2 = "bb".repeat(32);
    fs::write(&peers, format!("# header\n{k1}\n\n  {k2}  \n")).unwrap();
    let set = enc::load_authorized_peers(&peers).unwrap();
    assert_eq!(set.len(), 2);
    assert!(set.contains(&[0xAA; 32]));
    assert!(set.contains(&[0xBB; 32]));
}

/// The allowlist accepts the 43-char url-safe base64 of `?pubkey=`, which
/// decodes to the same key as the hex form.
#[test]
#[allow(clippy::cast_possible_truncation)] // test-only b64 encoder
fn authorized_peers_parses_base64_matching_hex() {
    let raw = raw_pubkey(&PrivateKey::from_seed(4242));
    let hex = mkit_core::hash::to_hex(&raw);
    let b64 = {
        const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
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
    let set = enc::load_authorized_peers(&peers).unwrap();
    assert_eq!(set.len(), 1, "hex and base64 forms must coincide");
    assert!(set.contains(&raw));
}

#[test]
fn authorized_peers_rejects_malformed_key() {
    let td = tempfile::tempdir().unwrap();
    let peers = td.path().join("peers.txt");
    fs::write(&peers, "not-a-valid-key\n").unwrap();
    assert!(enc::load_authorized_peers(&peers).is_err());
}

// ---------------------------------------------------------------------------
// The gate and the files it reads.

#[test]
fn listen_enc_flag_rules() {
    let (_td, root) = enc_repo();
    let r = common::s(&root);
    let peers = root.join("peers.txt");
    fs::write(&peers, format!("{}\n", "aa".repeat(32))).unwrap();
    let p = common::s(&peers);
    let refused = |flags: &[&str]| common::resolve_with(flags, &[]).unwrap_err();

    // No listener at all.
    assert_eq!(refused(&["--repo-root", r]).code, exit::USAGE);
    // Enc flags without --listen-enc.
    assert_eq!(
        refused(&[
            "--listen",
            "127.0.0.1:0",
            "--repo-root",
            r,
            "--unsafe-allow-any-enc-peer"
        ])
        .code,
        exit::USAGE
    );
    // HTTP auth flags without --listen.
    let enc_only = [
        "--listen-enc",
        "127.0.0.1:0",
        "--repo-root",
        r,
        "--unsafe-allow-any-enc-peer",
    ];
    let mut with_http = enc_only.to_vec();
    with_http.push("--unsafe-allow-any-peer");
    assert_eq!(refused(&with_http).code, exit::USAGE);
    // A zero handshake deadline.
    let mut zero = enc_only.to_vec();
    zero.extend(["--enc-handshake-timeout-secs", "0"]);
    assert_eq!(refused(&zero).code, exit::USAGE);
    // An allowlist needs a stable key.
    let err = refused(&[
        "--listen-enc",
        "127.0.0.1:0",
        "--repo-root",
        r,
        "--enc-authorized-peers",
        p,
    ]);
    assert_eq!(err.code, exit::CONFIG_ERROR);
    assert!(err.message.contains("--enc-server-key"), "{}", err.message);

    // Enc only needs no HTTP credentials; MKIT_API_TOKEN is ignored.
    let cfg = common::resolve_with(&enc_only, &[("MKIT_API_TOKEN", "t")]).unwrap();
    assert!(cfg.listen.is_none() && !cfg.is_open());
    let opts = cfg.enc.as_ref().unwrap();
    assert!(opts.is_open());
    assert_eq!(opts.server_key, enc::ServerKeySource::Ephemeral);
    assert_eq!(opts.idle_timeout, Some(Duration::from_mins(1)));
    assert_eq!(opts.handshake_timeout, Duration::from_secs(10));
    assert_eq!((opts.max_sessions, opts.max_handshakes), (1024, 128));
    assert_eq!(cfg.banners(), vec![enc::UNSAFE_ENC_BANNER]);
    let mut idle_off = enc_only.to_vec();
    idle_off.extend(["--enc-idle-timeout-secs", "0"]);
    let err = refused(&idle_off);
    assert_eq!(err.code, exit::CONFIG_ERROR);
    assert!(err.message.contains("at least 1"), "{}", err.message);

    // The handshake cap: at most --max-connections by default, settable,
    // never 0.
    let mut small = enc_only.to_vec();
    small.extend(["--max-connections", "5"]);
    let opts = common::resolve_with(&small, &[]).unwrap().enc.unwrap();
    assert_eq!((opts.max_sessions, opts.max_handshakes), (5, 5));
    small.extend(["--enc-max-handshakes", "2"]);
    let opts = common::resolve_with(&small, &[]).unwrap().enc.unwrap();
    assert_eq!(opts.max_handshakes, 2);
    let mut zero = enc_only.to_vec();
    zero.extend(["--enc-max-handshakes", "0"]);
    assert_eq!(refused(&zero).code, exit::USAGE);

    // An open enc listener beside an HTTP listener that requires
    // authentication is refused; beside an open one it is allowed.
    let mut beside = vec!["--listen", "127.0.0.1:0"];
    beside.extend(enc_only);
    let err = common::resolve_with(&beside, &[("MKIT_API_TOKEN", "t")]).unwrap_err();
    assert_eq!(err.code, exit::CONFIG_ERROR);
    assert!(
        err.message.contains("--enc-authorized-peers"),
        "{}",
        err.message
    );
    beside.push("--unsafe-allow-any-peer");
    let cfg = common::resolve_with(&beside, &[]).unwrap();
    assert_eq!(
        cfg.banners(),
        vec![
            mkit_server_native::config::UNSAFE_BANNER,
            enc::UNSAFE_ENC_BANNER
        ]
    );
}

#[test]
fn authorized_peers_file_must_not_be_writable_by_others() {
    use std::os::unix::fs::PermissionsExt as _;

    let td = tempfile::tempdir().unwrap();
    let peers = td.path().join("peers.txt");
    fs::write(&peers, format!("{}\n", "aa".repeat(32))).unwrap();
    for mode in [0o600, 0o644, 0o444] {
        fs::set_permissions(&peers, fs::Permissions::from_mode(mode)).unwrap();
        assert!(enc::load_authorized_peers(&peers).is_ok(), "{mode:o}");
    }
    for mode in [0o620, 0o602, 0o666] {
        fs::set_permissions(&peers, fs::Permissions::from_mode(mode)).unwrap();
        let err = enc::load_authorized_peers(&peers).unwrap_err();
        assert!(err.contains("chmod go-w"), "{err}");
    }
    fs::set_permissions(&peers, fs::Permissions::from_mode(0o600)).unwrap();
    let link = td.path().join("link");
    std::os::unix::fs::symlink(&peers, &link).unwrap();
    assert!(
        enc::load_authorized_peers(&link)
            .unwrap_err()
            .contains("symlink")
    );
    assert!(
        enc::load_authorized_peers(td.path())
            .unwrap_err()
            .contains("not a regular file")
    );
}

#[test]
fn server_key_is_created_private_then_reloaded() {
    use std::os::unix::fs::PermissionsExt as _;

    let (_td, root) = enc_repo();
    let path = root.join("enc").join("server.key");
    let source = enc::ServerKeySource::File(path.clone());
    let first = enc::load_server_key(&source).unwrap();
    let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&path), 0o600);
    assert_eq!(mode(path.parent().unwrap()), 0o700);
    let again = enc::load_server_key(&source).unwrap();
    assert_eq!(raw_pubkey(&first), raw_pubkey(&again), "the key is stable");

    // A readable key, a symlink, or a key of the wrong length is refused.
    fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
    assert_eq!(
        enc::load_server_key(&source).unwrap_err().code,
        exit::CONFIG_ERROR
    );
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let link = root.join("enc").join("link.key");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    let err = enc::load_server_key(&enc::ServerKeySource::File(link)).unwrap_err();
    assert!(err.message.contains("symlink"), "{}", err.message);
    let short = root.join("enc").join("short.key");
    common::secret_file(&short, &[7u8; 31]);
    assert!(enc::load_server_key(&enc::ServerKeySource::File(short)).is_err());
}

// ---------------------------------------------------------------------------
// Sessions.

#[test]
fn enc_client_roundtrip_via_transport() {
    let (_td, root) = enc_repo();
    let client_key = PrivateKey::from_seed(77);
    let peers = root.join("peers.txt");
    fs::write(
        &peers,
        format!("{}\n", mkit_core::hash::to_hex(&raw_pubkey(&client_key))),
    )
    .unwrap();
    let key_path = root.join("enc").join("server.key");
    let server = EncServer::start(
        &root,
        &[
            "--enc-authorized-peers",
            common::s(&peers),
            "--enc-server-key",
            common::s(&key_path),
        ],
    );

    let client = server.client(77).unwrap();
    assert!(client.list_refs("").unwrap().is_empty());
    let (bytes, key) = valid_pack();
    assert!(!client.pack_exists(&key).unwrap());
    client.upload_pack(&bytes, &key).unwrap();
    assert!(client.pack_exists(&key).unwrap());
    assert_eq!(client.download_pack(&key).unwrap(), bytes);
    let id = *key.as_bytes();
    client
        .update_ref("refs/heads/main", RefWriteCondition::Missing, &id)
        .unwrap();
    assert_eq!(client.read_ref("refs/heads/main").unwrap(), Some(id));
    let refs = client.list_refs("refs/heads").unwrap();
    assert_eq!(refs.len(), 1);
    assert_eq!(refs[0].name, "main");
    // The listener serves the root's files.
    let tx = FileTransport::new(&root);
    assert_eq!(tx.read_ref("refs/heads/main").unwrap(), Some(id));
    assert_eq!(tx.download_pack(&key).unwrap(), bytes);

    // A key not on the allowlist gets no session.
    assert!(server.client(78).is_err());
}

#[test]
fn listen_enc_error_replies_match_the_ssh_session() {
    let (_td, root) = enc_repo();
    let server = EncServer::open(&root);

    // A frame the session does not serve gets its specific message
    // (the old dispatcher said "unexpected frame"), and the session goes
    // on.
    let mut raw = server.raw(11);
    raw.hello();
    raw.send(ssh_frame::Body::PackChunk(Box::<PackChunk>::default()));
    raw.expect_error(
        ErrorCode::InvalidRequest,
        "PackChunk arrived without UploadPack header",
    );
    raw.send(ssh_frame::Body::Hello(Box::<Hello>::default()));
    raw.expect_error(ErrorCode::InvalidRequest, "Hello after handshake");
    raw.send_frame(&SshFrame::default());
    raw.expect_error(ErrorCode::InvalidRequest, "empty frame");
    raw.send(ssh_frame::Body::ListRefsResponse(Box::default()));
    raw.expect_error(ErrorCode::InvalidRequest, "unexpected request frame");

    // A chunk that cannot be read inside an upload is answered (the old
    // dispatcher ended the session silently) and stores nothing.
    let (bytes, key) = valid_pack();
    raw.send(ssh_frame::Body::UploadPack(Box::new(UploadPack {
        pack_id: Some(key.as_bytes().to_vec()),
        total_bytes: Some(bytes.len() as u64),
        ..Default::default()
    })));
    raw.send_garbage();
    raw.expect_error(ErrorCode::InvalidRequest, "pack chunk read failed");
    assert!(!root.join("packs").join(key.to_hex()).exists());

    // A top-level record that is not an `SshFrame`: `frame parse error`,
    // then the session closes (the old dispatcher closed silently).
    raw.send_garbage();
    raw.expect_error(ErrorCode::InvalidRequest, "frame parse error");
    raw.expect_closed();

    // A Hello for another protocol version is refused by name.
    let mut raw = server.raw(12);
    raw.send(ssh_frame::Body::Hello(Box::new(Hello {
        proto: Some(ProtocolVersion::ProtocolVersionUnspecified.into()),
        ..Default::default()
    })));
    raw.expect_error(ErrorCode::InvalidRequest, "unsupported proto_version 0");
    raw.expect_closed();
}

#[test]
fn listen_enc_idle_and_handshake_timeouts_drop_silent_peers() {
    use std::io::Read as _;

    let (_td, root) = enc_repo();
    let server = EncServer::start(
        &root,
        &[
            "--unsafe-allow-any-enc-peer",
            "--enc-idle-timeout-secs",
            "1",
            "--enc-handshake-timeout-secs",
            "1",
        ],
    );
    // Past the handshake, a silent peer is dropped after the idle timeout.
    let mut raw = server.raw(21);
    raw.hello();
    let start = Instant::now();
    assert!(raw.recv(Duration::from_secs(10)).is_err());
    let waited = start.elapsed();
    assert!(
        waited >= Duration::from_millis(900) && waited < Duration::from_secs(8),
        "{waited:?}"
    );

    // A TCP client that never starts the handshake is closed after the
    // handshake deadline.
    let mut tcp = std::net::TcpStream::connect(server.addr).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let start = Instant::now();
    let mut buf = [0u8; 16];
    let n = tcp.read(&mut buf).unwrap_or(0);
    assert_eq!(n, 0, "the server sent bytes to a silent client");
    assert!(
        start.elapsed() < Duration::from_secs(8),
        "not closed in time"
    );
}

#[test]
fn listen_enc_caps_open_connections() {
    let (_td, root) = enc_repo();
    let server = EncServer::start(
        &root,
        &["--unsafe-allow-any-enc-peer", "--max-connections", "1"],
    );
    // The one session slot is held.
    let mut first = server.raw(31);
    first.hello();
    // A second client gets no session (its Hello goes unanswered)...
    let second = server.connect_in_thread(32);
    assert!(
        second.recv_timeout(Duration::from_millis(1500)).is_err(),
        "a second session was served past the cap"
    );
    // ...until the first one closes.
    drop(first);
    assert!(second.recv_timeout(Duration::from_secs(20)).unwrap());
}

/// Silent sockets fill only the handshake slots: established sessions go
/// on, and an allowlisted client connects as soon as one slot frees.
#[test]
fn listen_enc_silent_sockets_cannot_lock_out_clients() {
    let (_td, root) = enc_repo();
    let peers = root.join("peers.txt");
    let listed: Vec<String> = [41, 42]
        .iter()
        .map(|&seed| mkit_core::hash::to_hex(&raw_pubkey(&PrivateKey::from_seed(seed))))
        .collect();
    fs::write(&peers, listed.join("\n")).unwrap();
    let key = root.join("enc").join("server.key");
    let server = EncServer::start(
        &root,
        &[
            "--enc-authorized-peers",
            common::s(&peers),
            "--enc-server-key",
            common::s(&key),
            "--enc-max-handshakes",
            "2",
            "--enc-handshake-timeout-secs",
            "60",
        ],
    );
    let established = server.client(41).unwrap();

    // Two sockets that never handshake take both handshake slots.
    let mut silent: Vec<_> = (0..2)
        .map(|_| std::net::TcpStream::connect(server.addr).unwrap())
        .collect();
    std::thread::sleep(Duration::from_millis(200));
    let waiting = server.connect_in_thread(42);
    assert!(
        waiting.recv_timeout(Duration::from_millis(1500)).is_err(),
        "a handshake ran past the handshake cap"
    );
    // The established session is unaffected.
    assert!(established.list_refs("").unwrap().is_empty());

    // One silent socket goes: the allowlisted client gets through.
    drop(silent.remove(0));
    assert!(waiting.recv_timeout(Duration::from_secs(20)).unwrap());
    assert!(established.list_refs("").unwrap().is_empty());
    drop(silent);
}

/// On shutdown an idle session ends at once, well inside the grace period
/// (30 s here), and the listener returns.
#[test]
fn listen_enc_shutdown_ends_idle_sessions() {
    let (_td, root) = enc_repo();
    let mut server = EncServer::open(&root);
    let mut idle = server.raw(51);
    idle.hello();
    let client = server.client(52).unwrap();
    assert!(client.list_refs("").unwrap().is_empty());
    let took = server.stop();
    assert!(took < Duration::from_secs(5), "{took:?}");
    idle.expect_closed();
}

/// A client that completed its handshake but finds every session slot
/// taken waits at most the handshake timeout.
#[test]
fn listen_enc_session_slot_wait_is_bounded() {
    let (_td, root) = enc_repo();
    let server = EncServer::start(
        &root,
        &[
            "--unsafe-allow-any-enc-peer",
            "--max-connections",
            "1",
            "--enc-handshake-timeout-secs",
            "2",
        ],
    );
    let mut first = server.raw(61);
    first.hello();
    let start = Instant::now();
    let waiting = server.connect_in_thread(62);
    assert!(!waiting.recv_timeout(Duration::from_secs(30)).unwrap());
    let waited = start.elapsed();
    assert!(waited >= Duration::from_millis(1500), "{waited:?}");
    // The session that held the slot is untouched.
    first.send(ssh_frame::Body::ListRefs(Box::<ListRefs>::default()));
    assert!(matches!(
        first.recv(Duration::from_secs(10)).unwrap().body,
        Some(ssh_frame::Body::ListRefsResponse(_))
    ));
}

/// A shutdown releases a client waiting for a session slot at once rather
/// than at the end of the grace period.
#[test]
fn listen_enc_shutdown_releases_clients_waiting_for_a_slot() {
    let (_td, root) = enc_repo();
    let mut server = EncServer::start(
        &root,
        &[
            "--unsafe-allow-any-enc-peer",
            "--max-connections",
            "1",
            "--enc-handshake-timeout-secs",
            "60",
        ],
    );
    // The slot holder is inside an upload, so it outlives the shutdown.
    let mut first = server.raw(63);
    first.hello();
    let (bytes, key) = valid_pack();
    let id = key.as_bytes().to_vec();
    first.send(ssh_frame::Body::UploadPack(Box::new(UploadPack {
        pack_id: Some(id.clone()),
        total_bytes: Some(bytes.len() as u64),
        ..Default::default()
    })));
    let waiting = server.connect_in_thread(64);
    std::thread::sleep(Duration::from_millis(500));
    server.shutdown.trigger();
    // The waiting client is let go at once, not after 60 s.
    assert!(
        !waiting
            .recv_timeout(Duration::from_secs(5))
            .expect("the waiting client was not released")
    );
    // The upload finishes; then everything has drained.
    first.send(ssh_frame::Body::PackChunk(Box::new(PackChunk {
        pack_id: Some(id),
        offset: Some(0),
        data: Some(bytes),
        last: Some(true),
        ..Default::default()
    })));
    assert!(matches!(
        first.recv(Duration::from_secs(10)).unwrap().body,
        Some(ssh_frame::Body::UploadPackResponse(_))
    ));
    let took = server.stop();
    assert!(took < Duration::from_secs(5), "{took:?}");
}

/// An upload in flight when the shutdown begins still completes; the
/// session ends after it.
#[test]
fn listen_enc_shutdown_never_cuts_an_upload() {
    let (_td, root) = enc_repo();
    let mut server = EncServer::open(&root);
    let mut raw = server.raw(53);
    raw.hello();
    let (bytes, key) = valid_pack();
    let id = key.as_bytes().to_vec();
    raw.send(ssh_frame::Body::UploadPack(Box::new(UploadPack {
        pack_id: Some(id.clone()),
        total_bytes: Some(bytes.len() as u64),
        ..Default::default()
    })));
    std::thread::sleep(Duration::from_millis(200));
    server.shutdown.trigger();
    std::thread::sleep(Duration::from_millis(200));
    raw.send(ssh_frame::Body::PackChunk(Box::new(PackChunk {
        pack_id: Some(id),
        offset: Some(0),
        data: Some(bytes.clone()),
        last: Some(true),
        ..Default::default()
    })));
    match raw.recv(Duration::from_secs(10)).unwrap().body {
        Some(ssh_frame::Body::UploadPackResponse(_)) => {}
        other => panic!("expected UploadPackResponse, got {other:?}"),
    }
    raw.expect_closed();
    assert!(server.stop() < Duration::from_secs(5));
    assert_eq!(
        FileTransport::new(&root).download_pack(&key).unwrap(),
        bytes
    );
}

// ---------------------------------------------------------------------------
// The binary.

/// A free loopback port.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// The spawned `mkit-server` and its stderr lines; killed if the test
/// fails early.
struct Binary {
    child: std::process::Child,
    stderr: std::sync::mpsc::Receiver<String>,
}

impl Binary {
    /// `mkit-server serve <flags>`, once every address in `wait_for`
    /// accepts connections.
    fn start(flags: &[&std::ffi::OsStr], wait_for: &[&str]) -> Self {
        use std::io::BufRead as _;
        use std::process::{Command, Stdio};

        let mut child = Command::new(env!("CARGO_BIN_EXE_mkit-server"))
            .arg("serve")
            .args(flags)
            .env_remove("MKIT_API_TOKEN")
            .env_remove("MKIT_SERVE_ROOT")
            .env("RUST_LOG", "warn")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let pipe = child.stderr.take().unwrap();
        let (tx, stderr) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for line in std::io::BufReader::new(pipe).lines() {
                let Ok(line) = line else { break };
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        let binary = Self { child, stderr };
        let deadline = Instant::now() + Duration::from_mins(1);
        for addr in wait_for {
            while std::net::TcpStream::connect(addr).is_err() {
                assert!(
                    Instant::now() < deadline,
                    "mkit-server did not listen on {addr}"
                );
                std::thread::sleep(Duration::from_millis(50));
            }
        }
        binary
    }

    /// The first stderr line containing `needle`.
    fn line_with(&self, needle: &str) -> String {
        loop {
            let line = self.stderr.recv_timeout(Duration::from_secs(10)).unwrap();
            if line.contains(needle) {
                return line;
            }
        }
    }

    /// SIGTERM, then the exit status.
    fn stop(mut self) -> std::process::ExitStatus {
        let pid = self.child.id().to_string();
        let killed = std::process::Command::new("kill")
            .args(["-TERM", &pid])
            .status()
            .unwrap();
        assert!(killed.success());
        self.child.wait().unwrap()
    }
}

impl Drop for Binary {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// `mkit-server serve` with both listeners: a ref written over enc is read
/// over Connect and a pack uploaded over Connect is seen over enc (one
/// pipeline's stores), the startup line names the pinned key, and SIGTERM
/// drains both listeners to exit 0.
#[test]
fn enc_and_http_listeners_share_one_pipeline() {
    use commonware_codec::DecodeExt as _;
    use std::os::unix::fs::PermissionsExt as _;

    let (_td, root) = enc_repo();
    let server_seed = [0x5au8; 32];
    let dir = root.join("enc");
    fs::create_dir(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    let key_path = dir.join("server.key");
    common::secret_file(&key_path, &server_seed);
    let server_key = PrivateKey::decode(server_seed.as_slice()).unwrap();
    let client_key = PrivateKey::from_seed(91);
    let peers = root.join("peers.txt");
    let listed = mkit_core::hash::to_hex(&raw_pubkey(&client_key));
    fs::write(&peers, format!("{listed}\n")).unwrap();

    let (http_port, enc_port) = (free_port(), free_port());
    let http = format!("127.0.0.1:{http_port}");
    let enc_addr = format!("127.0.0.1:{enc_port}");
    let flags: Vec<&std::ffi::OsStr> = vec![
        "--listen".as_ref(),
        http.as_ref(),
        "--unsafe-allow-any-peer".as_ref(),
        "--listen-enc".as_ref(),
        enc_addr.as_ref(),
        "--enc-authorized-peers".as_ref(),
        peers.as_os_str(),
        "--enc-server-key".as_ref(),
        key_path.as_os_str(),
        "--repo-root".as_ref(),
        root.as_os_str(),
    ];
    let binary = Binary::start(&flags, &[&http, &enc_addr]);
    let pubkey = enc::public_key_hex(&server_key);
    let announced = binary.line_with("--listen-enc on");
    assert!(
        announced.contains(&format!("?pubkey={pubkey}")),
        "{announced}"
    );

    let enc_client = connect_tcp_with_executor(
        "127.0.0.1",
        enc_port,
        &raw_pubkey(&server_key),
        client_key,
        TokioExecutor::new().unwrap(),
    )
    .unwrap();
    let http_client =
        mkit_transport_connect::ConnectTransport::connect(&format!("mkit+http://{http}")).unwrap();

    let id = [0x42u8; 32];
    enc_client
        .update_ref("refs/heads/main", RefWriteCondition::Missing, &id)
        .unwrap();
    assert_eq!(http_client.read_ref("refs/heads/main").unwrap(), Some(id));
    let (bytes, key) = valid_pack();
    http_client.upload_pack(&bytes, &key).unwrap();
    assert!(enc_client.pack_exists(&key).unwrap());
    assert_eq!(enc_client.download_pack(&key).unwrap(), bytes);
    // A CAS race across the two listeners is decided by the one store.
    let err = http_client
        .update_ref("refs/heads/main", RefWriteCondition::Missing, &[0x43; 32])
        .unwrap_err();
    assert!(matches!(err, TransportError::RefConflict), "{err:?}");
    drop((enc_client, http_client));

    let status = binary.stop();
    assert!(status.success(), "{status:?}");
}
