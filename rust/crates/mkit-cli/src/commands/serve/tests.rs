//! `mkit serve`'s own code: repo resolution, the stdio adapter and its idle
//! timeout, the session cap flag and the startup sweep. The session's
//! frame-level behavior is tested in `mkit-server` (`ssh::tests`); the
//! golden sessions run through the real binary in `tests/serve_golden.rs`.

use std::fs;
use std::io::{self, Cursor, Read};
use std::path::Path;
use std::time::{Duration, Instant};

use mkit_core::hash::hash;
use mkit_core::protocol::{PackKey, RefWriteCondition, Transport as _};
use mkit_rpc::mkit::rpc::v1::ssh::{
    Close, Hello, HelloResponse, PackChunk, SshFrame, UploadPack, ssh_frame,
};
use mkit_rpc::mkit::rpc::v1::{ErrorCode, ProtocolVersion};
use mkit_transport_file::FileTransport;

use super::*;
use crate::exit;

const GOLDEN_IN: &[u8] = include_bytes!("../../../../../tests/golden/ssh-serve/session-1.in.bin");
const GOLDEN_OUT: &[u8] = include_bytes!("../../../../../tests/golden/ssh-serve/session-1.bin");
/// The `server_id` the golden sessions were captured with.
const GOLDEN_SERVER_ID: &str = "mkit serve/0.4.2";

type Body = ssh_frame::Body;

// ---------------------------------------------------------------- helpers

fn repo_root() -> tempfile::TempDir {
    let td = tempfile::tempdir().unwrap();
    fs::create_dir_all(td.path().join(".mkit")).unwrap();
    td
}

fn frame(body: Body) -> SshFrame {
    SshFrame {
        body: Some(body),
        ..Default::default()
    }
}

fn hello() -> Body {
    Body::Hello(Box::new(
        Hello::default().with_proto(ProtocolVersion::ProtocolVersion1),
    ))
}

fn close() -> Body {
    Body::Close(Box::<Close>::default())
}

fn encode(bodies: impl IntoIterator<Item = Body>) -> Vec<u8> {
    let mut out = Vec::new();
    for body in bodies {
        mkit_rpc::write_frame(&mut out, &frame(body)).unwrap();
    }
    out
}

fn decode(mut bytes: &[u8]) -> Vec<SshFrame> {
    let mut out = Vec::new();
    while !bytes.is_empty() {
        out.push(mkit_rpc::read_frame::<_, SshFrame>(&mut bytes).unwrap());
    }
    out
}

fn assert_error(f: &SshFrame, code: ErrorCode, message: &str) {
    let Some(Body::Error(e)) = &f.body else {
        panic!("expected Error, got {:?}", f.body);
    };
    assert!(e.code.is_some_and(|c| c == code), "code of {e:?}");
    assert_eq!(e.message.as_deref(), Some(message));
}

/// `serve_stdio` over in-memory streams, with the output bytes.
fn serve(root: &Path, input: impl Read + Send + 'static, idle: Option<Duration>) -> (u8, Vec<u8>) {
    let mut out = Vec::new();
    let code = serve_stdio(root, input, &mut out, idle, false);
    (code, out)
}

/// The golden patterned pack bytes (`mkit-server`'s `ssh::tests`).
fn pack_bytes(len: usize, seed: u8) -> Vec<u8> {
    #[allow(clippy::cast_possible_truncation)]
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

/// `golden` with its `HelloResponse` (the first frame) re-encoded with
/// this build's `server_id`, so the pin survives a version bump; the rest
/// is compared byte for byte.
fn with_current_server_id(golden: &[u8]) -> Vec<u8> {
    let mut tail = golden;
    let first: SshFrame = mkit_rpc::read_frame(&mut tail).unwrap();
    let resp = HelloResponse {
        proto: Some(ProtocolVersion::ProtocolVersion1.into()),
        server_id: Some(GOLDEN_SERVER_ID.to_owned()),
        ..Default::default()
    };
    assert_eq!(first, frame(Body::HelloResponse(Box::new(resp.clone()))));
    let current = HelloResponse {
        server_id: Some(format!("mkit serve/{CLI_VERSION}")),
        ..resp
    };
    let mut out = Vec::new();
    mkit_rpc::write_frame(&mut out, &frame(Body::HelloResponse(Box::new(current)))).unwrap();
    out.extend_from_slice(tail);
    out
}

/// A reader that serves `bytes` in `piece`-byte reads, sleeping `gap`
/// before each (and `first_gap` before the first).
struct Trickle {
    bytes: Cursor<Vec<u8>>,
    piece: usize,
    first_gap: Duration,
    gap: Duration,
    started: bool,
}

impl Read for Trickle {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let gap = if self.started {
            self.gap
        } else {
            self.first_gap
        };
        self.started = true;
        std::thread::sleep(gap);
        let n = buf.len().min(self.piece);
        self.bytes.read(&mut buf[..n])
    }
}

// ------------------------------------------------------------- resolution

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
    let td = repo_root();
    let resolved = resolve_repo_path(td.path().to_str().unwrap()).unwrap();
    assert!(resolved.join(".mkit").is_dir());
}

#[test]
fn removed_listener_flag_names_the_first_removed_flag() {
    let args = |a: &[&str]| a.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
    assert_eq!(
        removed_listener_flag(&args(&["repo", "--http", "127.0.0.1:0"])),
        Some("--http")
    );
    assert_eq!(
        removed_listener_flag(&args(&["--enc-idle-timeout-secs=5", "--listen-enc", "x"])),
        Some("--enc-idle-timeout-secs")
    );
    // Not a removed flag, a prefix of one, anything after `--`, or the
    // idle timeout `mkit serve` does take.
    assert_eq!(removed_listener_flag(&args(&["repo", "--bogus"])), None);
    assert_eq!(removed_listener_flag(&args(&["--htt", "repo"])), None);
    assert_eq!(removed_listener_flag(&args(&["--", "--http"])), None);
    assert_eq!(
        removed_listener_flag(&args(&["repo", "--idle-timeout-secs", "5"])),
        None
    );
}

/// Both timeout flags are bounded at 7 days; past that clap refuses the
/// value (no `Instant` overflow can follow from a huge one).
#[test]
fn timeout_flags_are_bounded() {
    let parse = |a: &[&str]| {
        let args = a.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        clap_shim::parse::<ServeOpts>("mkit serve", &args)
    };
    let week = MAX_TIMEOUT_SECS.to_string();
    let over = (MAX_TIMEOUT_SECS + 1).to_string();
    for flag in ["--idle-timeout-secs", "--max-session-secs"] {
        assert!(parse(&["repo", flag, &week]).is_ok(), "{flag}");
        assert_eq!(
            parse(&["repo", flag, &over]).unwrap_err(),
            exit::DATAERR,
            "{flag}"
        );
        let max = u64::MAX.to_string();
        assert_eq!(
            parse(&["repo", flag, &max]).unwrap_err(),
            exit::DATAERR,
            "{flag}"
        );
    }
    let opts = parse(&["repo"]).unwrap();
    assert_eq!(
        opts.max_session_secs, 0,
        "the session cap is off by default"
    );
    assert_eq!(
        parse(&["repo", "--max-session-secs", "30"])
            .unwrap()
            .max_session_secs,
        30
    );
}

/// An idle timeout whose deadline an `Instant` cannot hold waits forever
/// instead of panicking.
#[test]
fn a_huge_idle_timeout_does_not_overflow() {
    let td = repo_root();
    let input = Cursor::new(encode([hello(), close()]));
    let (code, out) = serve(td.path(), input, Some(Duration::from_secs(u64::MAX)));
    assert_eq!(code, exit::OK);
    assert!(matches!(decode(&out)[0].body, Some(Body::HelloResponse(_))));
}

#[test]
fn idle_timeout_flag_defaults_to_60_and_takes_zero() {
    let parse = |a: &[&str]| {
        let args = a.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        clap_shim::parse::<ServeOpts>("mkit serve", &args).unwrap()
    };
    assert_eq!(parse(&["repo"]).idle_timeout_secs, 60);
    assert_eq!(
        parse(&["repo", "--idle-timeout-secs", "0"]).idle_timeout_secs,
        0
    );
    assert_eq!(
        parse(&["--idle-timeout-secs=5", "repo"]).idle_timeout_secs,
        5
    );
}

// ---------------------------------------------------------------- session

/// The M0-12 golden session through `serve_stdio`, over the `.mkit`
/// layout seeded as it was captured: refs `main`, `dev`, `tags/v1` and one
/// 1000-byte pack.
#[test]
fn serve_stdio_matches_golden_session() {
    let td = repo_root();
    let tx = FileTransport::new(td.path());
    for (name, id) in [
        ("refs/heads/main", [0x11; 32]),
        ("refs/heads/dev", [0x22; 32]),
        ("refs/tags/v1", [0x33; 32]),
    ] {
        tx.update_ref(name, RefWriteCondition::Any, &id).unwrap();
    }
    let seeded = pack_bytes(1000, 7);
    tx.upload_pack(&seeded, &PackKey::new(hash(&seeded)))
        .unwrap();

    let (code, out) = serve(
        td.path(),
        Cursor::new(GOLDEN_IN),
        Some(Duration::from_mins(1)),
    );
    assert_eq!(code, exit::OK);
    let want = with_current_server_id(GOLDEN_OUT);
    let (got_frames, want_frames) = (decode(&out), decode(&want));
    for (i, (g, w)) in got_frames.iter().zip(&want_frames).enumerate() {
        assert_eq!(g, w, "frame {i}");
    }
    assert_eq!(out, want);
    // The refs the session left are `FileTransport`'s files.
    assert_eq!(tx.read_ref("refs/heads/main").unwrap(), Some([0x44; 32]));
}

#[test]
fn idle_timeout_ends_session_with_protocol_error() {
    let td = repo_root();
    // A client that connects and sends nothing: the pipe's writer stays
    // open until the test ends.
    let (reader, _writer) = io::pipe().unwrap();
    let started = Instant::now();
    let (code, out) = serve(td.path(), reader, Some(Duration::from_millis(100)));
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(code, exit::PROTOCOL_ERROR);
    let frames = decode(&out);
    assert_eq!(frames.len(), 1, "{frames:?}");
    assert_error(&frames[0], ErrorCode::InvalidRequest, "idle timeout");
}

#[test]
fn zero_disables_timeout() {
    let td = repo_root();
    let slow = Trickle {
        bytes: Cursor::new(encode([hello(), close()])),
        piece: usize::MAX,
        first_gap: Duration::from_millis(300),
        gap: Duration::ZERO,
        started: false,
    };
    let (code, out) = serve(td.path(), slow, None);
    assert_eq!(code, exit::OK);
    let frames = decode(&out);
    assert!(matches!(frames[0].body, Some(Body::HelloResponse(_))));
    // The same client against a 100 ms timeout is cut off before `Hello`.
    let slow = Trickle {
        bytes: Cursor::new(encode([hello(), close()])),
        piece: usize::MAX,
        first_gap: Duration::from_millis(300),
        gap: Duration::ZERO,
        started: false,
    };
    let (code, _) = serve(td.path(), slow, Some(Duration::from_millis(100)));
    assert_eq!(code, exit::PROTOCOL_ERROR);
}

/// An upload that keeps sending never trips the timeout, even though one
/// chunk frame takes several timeouts to arrive; a client that stops in
/// the middle of one does, and the upload is discarded.
#[test]
fn idle_timeout_counts_bytes_not_frames() {
    let pack = pack_bytes(4000, 3);
    let id = hash(&pack).to_vec();
    let header = Body::UploadPack(Box::new(UploadPack {
        pack_id: Some(id.clone()),
        total_bytes: Some(pack.len() as u64),
        ..Default::default()
    }));
    let chunk = Body::PackChunk(Box::new(PackChunk {
        pack_id: Some(id.clone()),
        offset: Some(0),
        data: Some(pack.clone()),
        last: Some(true),
        ..Default::default()
    }));
    let input = encode([hello(), header.clone(), chunk, close()]);

    // ~4 KiB at 400 bytes per 40 ms: about 400 ms, 4x the timeout.
    let td = repo_root();
    let trickle = Trickle {
        bytes: Cursor::new(input),
        piece: 400,
        first_gap: Duration::ZERO,
        gap: Duration::from_millis(40),
        started: false,
    };
    let (code, out) = serve(td.path(), trickle, Some(Duration::from_millis(100)));
    assert_eq!(code, exit::OK);
    let frames = decode(&out);
    assert!(
        matches!(frames[1].body, Some(Body::UploadPackResponse(_))),
        "{frames:?}"
    );
    let key = PackKey::new(hash(&pack));
    assert!(FileTransport::new(td.path()).pack_exists(&key).unwrap());

    // The header, then silence.
    let td = repo_root();
    let (reader, mut writer) = io::pipe().unwrap();
    io::Write::write_all(&mut writer, &encode([hello(), header])).unwrap();
    let (code, out) = serve(td.path(), reader, Some(Duration::from_millis(100)));
    assert_eq!(code, exit::PROTOCOL_ERROR);
    let frames = decode(&out);
    assert_error(&frames[1], ErrorCode::InvalidRequest, "idle timeout");
    assert!(!FileTransport::new(td.path()).pack_exists(&key).unwrap());
    let packs = td.path().join("packs");
    let left = fs::read_dir(&packs).map_or(0, Iterator::count);
    assert_eq!(left, 0, "the upload's temp file is removed");
    drop(writer);
}

#[test]
fn a_root_whose_refs_live_in_sqlite_is_refused() {
    let td = repo_root();
    fs::write(td.path().join(".mkit/server-meta"), b"sqlite").unwrap();
    let (code, out) = serve(td.path(), Cursor::new(encode([hello()])), None);
    assert_eq!(code, exit::CONFIG_ERROR);
    assert!(out.is_empty());
}

#[test]
fn stop_after_hello_ends_cleanly_after_the_handshake() {
    let td = repo_root();
    let input = Cursor::new(encode([hello(), close()]));
    let mut out = Vec::new();
    let code = serve_stdio(td.path(), input, &mut out, None, true);
    assert_eq!(code, exit::OK);
    let frames = decode(&out);
    assert_eq!(frames.len(), 1);
    assert!(matches!(frames[0].body, Some(Body::HelloResponse(_))));
}

// ------------------------------------------------------- startup upkeep

#[test]
fn startup_sweeps_crashed_uploads_only_when_no_server_holds_the_lock() {
    let td = repo_root();
    let packs = td.path().join("packs");
    fs::create_dir_all(&packs).unwrap();
    let stale = packs.join(format!(".{}.tmp.4242.0", "ab".repeat(32)));
    fs::write(&stale, b"partial").unwrap();
    let old = std::time::SystemTime::now() - Duration::from_hours(2);
    fs::File::options()
        .write(true)
        .open(&stale)
        .unwrap()
        .set_modified(old)
        .unwrap();

    // Another server is up (it holds `serve.lock` shared): no sweep.
    let dot_mkit = td.path().join(".mkit");
    let other = repo_lock::acquire_shared(
        &dot_mkit,
        crate::commands::SERVE_LOCK,
        repo_lock::DEFAULT_TIMEOUT,
    )
    .unwrap();
    let ours = lock_and_sweep(td.path()).unwrap();
    assert!(stale.exists(), "swept while another server was up");
    drop((ours, other));

    // Alone: swept, and the shared lock is held afterwards.
    let ours = lock_and_sweep(td.path()).unwrap();
    assert!(!stale.exists());
    assert!(!repo_lock::probe_exclusive(&dot_mkit, crate::commands::SERVE_LOCK).unwrap());
    drop(ours);
}
