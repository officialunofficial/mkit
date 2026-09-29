//! The five golden ssh sessions (`rust/tests/golden/ssh-serve/`; sessions
//! 1–2 were captured from `mkit serve` 0.4.2 before it moved onto
//! `mkit-server`, sessions 3–5 pin WP-1.15's root-mode refusal frames)
//! through the real `mkit serve` binary: stdin is the captured input, and
//! stdout must be the captured output byte for byte (with this build's
//! version in the `HelloResponse`, the only frame that names it).
//!
//! Also: a name outside `refs/` is refused by name, and
//! `--max-session-secs` ends a session the client holds open.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use mkit_core::hash::hash;
use mkit_core::protocol::{PackKey, RefWriteCondition, Transport as _};
use mkit_rpc::mkit::common::v1::RefExpectation;
use mkit_rpc::mkit::rpc::v1::ProtocolVersion;
use mkit_rpc::mkit::rpc::v1::ssh::{
    Close, Hello, HelloResponse, PackChunk, ReadRef, SshFrame, UpdateRef, UploadPack, ssh_frame,
};
use mkit_transport_file::FileTransport;

type Body = ssh_frame::Body;

const SESSION_1_IN: &[u8] = include_bytes!("../../../tests/golden/ssh-serve/session-1.in.bin");
const SESSION_1_OUT: &[u8] = include_bytes!("../../../tests/golden/ssh-serve/session-1.bin");
const SESSION_2_IN: &[u8] = include_bytes!("../../../tests/golden/ssh-serve/session-2.in.bin");
const SESSION_2_OUT: &[u8] = include_bytes!("../../../tests/golden/ssh-serve/session-2.bin");
const SESSION_3_IN: &[u8] = include_bytes!("../../../tests/golden/ssh-serve/session-3.in.bin");
const SESSION_3_OUT: &[u8] = include_bytes!("../../../tests/golden/ssh-serve/session-3.bin");
const SESSION_4_IN: &[u8] = include_bytes!("../../../tests/golden/ssh-serve/session-4.in.bin");
const SESSION_4_OUT: &[u8] = include_bytes!("../../../tests/golden/ssh-serve/session-4.bin");
const SESSION_5_IN: &[u8] = include_bytes!("../../../tests/golden/ssh-serve/session-5.in.bin");
const SESSION_5_OUT: &[u8] = include_bytes!("../../../tests/golden/ssh-serve/session-5.bin");
const GOLDEN_SERVER_ID: &str = "mkit serve/0.4.2";

fn mkit_serve(root: &Path, input: &[u8]) -> Output {
    mkit_serve_args(
        &["serve".to_owned(), root.to_str().unwrap().to_owned()],
        input,
    )
}

/// `mkit serve` with `args`, `input` on its stdin and its stdout
/// captured — the session the ssh forced command runs.
fn mkit_serve_args(args: &[String], input: &[u8]) -> Output {
    let xdg = tempfile::tempdir().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_mkit"))
        .args(args)
        .env("XDG_CONFIG_HOME", xdg.path())
        .env("HOME", xdg.path())
        .env_remove("MKIT_SERVE_ROOT")
        .env_remove("SSH_ORIGINAL_COMMAND")
        .env_remove("MKIT_SERVE_TEST_DIE_AFTER_HELLO")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let input = input.to_vec();
    // Written from a thread: the server answers while it reads, and a
    // full stdout pipe would otherwise deadlock both sides.
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(&input);
    });
    let out = child.wait_with_output().unwrap();
    writer.join().unwrap();
    out
}

fn repo_root() -> tempfile::TempDir {
    let td = tempfile::tempdir().unwrap();
    fs::create_dir_all(td.path().join(".mkit")).unwrap();
    td
}

/// The golden patterned pack bytes (`mkit-server`'s `ssh::tests`).
fn pack_bytes(len: usize, seed: u8) -> Vec<u8> {
    #[allow(clippy::cast_possible_truncation)]
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

fn seed(root: &Path, refs: &[(&str, [u8; 32])], packs: &[&[u8]]) {
    let tx = FileTransport::new(root);
    for (name, id) in refs {
        tx.update_ref(name, RefWriteCondition::Any, id).unwrap();
    }
    for pack in packs {
        tx.upload_pack(pack, &PackKey::new(hash(pack))).unwrap();
    }
}

fn frame(body: Body) -> SshFrame {
    SshFrame {
        body: Some(body),
        ..Default::default()
    }
}

fn decode(mut bytes: &[u8]) -> Vec<SshFrame> {
    let mut out = Vec::new();
    while !bytes.is_empty() {
        out.push(mkit_rpc::read_frame::<_, SshFrame>(&mut bytes).unwrap());
    }
    out
}

/// `golden` with its first frame, the golden `HelloResponse`, re-encoded
/// with this build's version.
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
        server_id: Some(format!("mkit serve/{}", env!("CARGO_PKG_VERSION"))),
        ..resp
    };
    let mut out = Vec::new();
    mkit_rpc::write_frame(&mut out, &frame(Body::HelloResponse(Box::new(current)))).unwrap();
    out.extend_from_slice(tail);
    out
}

fn assert_golden(out: &Output, golden: &[u8]) {
    assert!(out.status.success(), "{out:?}");
    let want = with_current_server_id(golden);
    let (got, wanted) = (decode(&out.stdout), decode(&want));
    for (i, (g, w)) in got.iter().zip(&wanted).enumerate() {
        assert_eq!(g, w, "frame {i}");
    }
    assert_eq!(got.len(), wanted.len(), "frame count");
    assert!(out.stdout == want, "stdout differs from the golden bytes");
}

#[test]
fn session_1_is_byte_identical_through_the_binary() {
    let td = repo_root();
    let seeded = pack_bytes(1000, 7);
    seed(
        td.path(),
        &[
            ("refs/heads/main", [0x11; 32]),
            ("refs/heads/dev", [0x22; 32]),
            ("refs/tags/v1", [0x33; 32]),
        ],
        &[&seeded],
    );
    let out = mkit_serve(td.path(), SESSION_1_IN);
    assert_golden(&out, SESSION_1_OUT);
    assert!(
        out.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn session_2_is_byte_identical_through_the_binary() {
    let td = repo_root();
    let big = pack_bytes(800 * 1024 + 1000, 5);
    seed(
        td.path(),
        &[
            ("refs/heads/main", [0x11; 32]),
            ("refs/heads/feat/x", [0x12; 32]),
            ("refs/heads/featx", [0x13; 32]),
            ("refs/tags/v1", [0x33; 32]),
        ],
        &[&big],
    );
    fs::write(td.path().join("refs/heads/README"), b"not a ref\n").unwrap();
    let out = mkit_serve(td.path(), SESSION_2_IN);
    assert_golden(&out, SESSION_2_OUT);
}

/// `session-3` (WP-1.15 B11): root mode — `mkit serve --root <root>
/// --principal <key> <ns>/<name>` — run as a NON-owner principal. The
/// upload and the CAS-correct ref write are refused
/// `INVALID_REQUEST "write not permitted"`, and the read still answers
/// the seeded ref, byte-identical to the golden.
#[test]
fn session_3_is_byte_identical_through_the_binary() {
    let (root, args) = session_3_fixture();
    let out = mkit_serve_args(&args, SESSION_3_IN);
    assert_golden(&out, SESSION_3_OUT);
    assert!(
        out.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    // The denied CAS left the seeded ref alone.
    let repo = root
        .path()
        .join(format!("ed25519-{}", "0a".repeat(32)))
        .join("room-a");
    let tx = FileTransport::new(&repo);
    assert_eq!(
        tx.read_ref("refs/heads/main").unwrap(),
        Some([0x44; 32]),
        "the refused UpdateRef must not have moved the ref"
    );
}

/// The `session-3` fixture: `<root>/ed25519-<owner>/room-a` holding the
/// seeded `refs/heads/main`, and the argv `mkit serve` gets for a
/// NON-owner forced command (`--principal` names the peer's key, which
/// is not the namespace's).
fn session_3_fixture() -> (tempfile::TempDir, Vec<String>) {
    let root = tempfile::tempdir().unwrap();
    let owner_ns = format!("ed25519-{}", "0a".repeat(32));
    let repo = root.path().join(&owner_ns).join("room-a");
    fs::create_dir_all(repo.join(".mkit")).unwrap();
    seed(&repo, &[("refs/heads/main", [0x44; 32])], &[]);
    let args = vec![
        "serve".to_owned(),
        "--root".to_owned(),
        root.path().to_str().unwrap().to_owned(),
        "--principal".to_owned(),
        "0b".repeat(32),
        format!("{owner_ns}/room-a"),
    ];
    (root, args)
}

/// The `session-4`/`session-5` fixture: the same root-mode repository as
/// `session-3`, but `--principal` names the namespace's owner, so
/// uploads and the packmap write are permitted and the session carries
/// B9's implicit pending set.
fn owner_fixture() -> (tempfile::TempDir, Vec<String>) {
    let root = tempfile::tempdir().unwrap();
    let owner_ns = format!("ed25519-{}", "0a".repeat(32));
    let repo = root.path().join(&owner_ns).join("room-a");
    fs::create_dir_all(repo.join(".mkit")).unwrap();
    seed(&repo, &[("refs/heads/main", [0x44; 32])], &[]);
    let args = vec![
        "serve".to_owned(),
        "--root".to_owned(),
        root.path().to_str().unwrap().to_owned(),
        "--principal".to_owned(),
        "0a".repeat(32),
        format!("{owner_ns}/room-a"),
    ];
    (root, args)
}

/// `session-4` (WP-1.15 B10): root mode, Single namespaced, owner
/// principal. A pending packmap node lists a pack that was never
/// uploaded; the write is refused `INVALID_REQUEST "packmap names packs
/// not uploaded to this repository"` and nothing is written — the read
/// after it still answers the seeded ref, byte-identical to the golden.
#[test]
fn session_4_is_byte_identical_through_the_binary() {
    let (root, args) = owner_fixture();
    let out = mkit_serve_args(&args, SESSION_4_IN);
    assert_golden(&out, SESSION_4_OUT);
    assert!(
        out.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    // The refused packmap left the repository with no packmap ref.
    let repo = root
        .path()
        .join(format!("ed25519-{}", "0a".repeat(32)))
        .join("room-a");
    let tx = FileTransport::new(&repo);
    assert_eq!(
        tx.read_ref("refs/mkit/packmap/main").unwrap(),
        None,
        "the refused packmap write must leave no ref"
    );
}

/// Regenerate `session-4`'s golden pair. Manual:
/// `cargo test -p mkit-cli --test serve_golden record_session_4 -- --ignored`
#[test]
#[ignore = "golden recorder; run manually"]
fn record_session_4() {
    let absent = hash(b"a pack this session never uploaded");
    let node = mkit_core::transfer::encode_packlist(None, &[absent]).unwrap();
    let node_id = hash(&node);
    let bodies = [
        Body::Hello(Box::new(
            Hello::default().with_proto(ProtocolVersion::ProtocolVersion1),
        )),
        Body::UploadPack(Box::new(
            UploadPack::default()
                .with_pack_id(node_id.to_vec())
                .with_total_bytes(node.len() as u64),
        )),
        Body::PackChunk(Box::new(
            PackChunk::default()
                .with_pack_id(node_id.to_vec())
                .with_offset(0)
                .with_data(node)
                .with_last(true),
        )),
        Body::UpdateRef(Box::new(
            UpdateRef::default()
                .with_name("refs/mkit/packmap/main")
                .with_new_id(node_id.to_vec())
                .with_expectation(RefExpectation::Missing),
        )),
        Body::ReadRef(Box::new(ReadRef::default().with_name("refs/heads/main"))),
        Body::Close(Box::<Close>::default()),
    ];
    record(&owner_fixture().1, &bodies, "session-4");
}

/// `session-5` (WP-1.15 B9): root mode, Single namespaced, owner
/// principal. Eight distinct packs upload before a packmap write; the
/// eighth is decided at its header and its `INVALID_REQUEST "too many
/// packs uploaded before a packmap update"` frame is sent after its
/// bounded drain, byte-identical to the golden.
#[test]
fn session_5_is_byte_identical_through_the_binary() {
    let (_root, args) = owner_fixture();
    let out = mkit_serve_args(&args, SESSION_5_IN);
    assert_golden(&out, SESSION_5_OUT);
    assert!(
        out.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Regenerate `session-5`'s golden pair. Manual:
/// `cargo test -p mkit-cli --test serve_golden record_session_5 -- --ignored`
#[test]
#[ignore = "golden recorder; run manually"]
fn record_session_5() {
    let mut bodies = vec![Body::Hello(Box::new(
        Hello::default().with_proto(ProtocolVersion::ProtocolVersion1),
    ))];
    // Seven packs join the pending set; the eighth distinct one crosses
    // MAX_TICKETS_PER_ADVANCE and is refused after its drain.
    for i in 0u8..8 {
        let pack = pack_bytes(64, i + 1);
        let pack_id = hash(&pack);
        bodies.push(Body::UploadPack(Box::new(
            UploadPack::default()
                .with_pack_id(pack_id.to_vec())
                .with_total_bytes(pack.len() as u64),
        )));
        bodies.push(Body::PackChunk(Box::new(
            PackChunk::default()
                .with_pack_id(pack_id.to_vec())
                .with_offset(0)
                .with_data(pack)
                .with_last(true),
        )));
    }
    bodies.push(Body::ReadRef(Box::new(
        ReadRef::default().with_name("refs/heads/main"),
    )));
    bodies.push(Body::Close(Box::<Close>::default()));
    record(&owner_fixture().1, &bodies, "session-5");
}

/// The golden recorders' shared tail: encode `bodies`, run the session
/// through the real binary, and write the input/output pair under
/// `tests/golden/ssh-serve/`.
fn record(args: &[String], bodies: &[Body], name: &str) {
    let mut input = Vec::new();
    for body in bodies {
        mkit_rpc::write_frame(&mut input, &frame(body.clone())).unwrap();
    }
    let out = mkit_serve_args(args, &input);
    assert!(out.status.success(), "{out:?}");
    assert!(out.stderr.is_empty(), "{out:?}");
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("golden")
        .join("ssh-serve");
    fs::write(dir.join(format!("{name}.in.bin")), &input).unwrap();
    fs::write(dir.join(format!("{name}.bin")), &out.stdout).unwrap();
    eprintln!(
        "recorded {name}.in.bin ({} B) and {name}.bin ({} B) in {}",
        input.len(),
        out.stdout.len(),
        dir.display()
    );
}

/// Regenerate `session-3`'s golden pair — the input frames, and this
/// build's answers under root mode as a non-owner — by running the real
/// binary. Manual:
/// `cargo test -p mkit-cli --test serve_golden record_session_3 -- --ignored`
#[test]
#[ignore = "golden recorder; run manually"]
fn record_session_3() {
    let ref_id = [0x44u8; 32];
    let pack = pack_bytes(64, 3);
    let pack_id = hash(&pack);
    let bodies = [
        Body::Hello(Box::new(
            Hello::default().with_proto(ProtocolVersion::ProtocolVersion1),
        )),
        Body::UploadPack(Box::new(
            UploadPack::default()
                .with_pack_id(pack_id.to_vec())
                .with_total_bytes(pack.len() as u64),
        )),
        Body::PackChunk(Box::new(
            PackChunk::default()
                .with_pack_id(pack_id.to_vec())
                .with_offset(0)
                .with_data(pack)
                .with_last(true),
        )),
        Body::UpdateRef(Box::new(
            UpdateRef::default()
                .with_name("refs/heads/main")
                .with_new_id([0x55; 32].to_vec())
                .with_expectation(RefExpectation::Match)
                .with_expected_id(ref_id.to_vec()),
        )),
        Body::ReadRef(Box::new(ReadRef::default().with_name("refs/heads/main"))),
        Body::Close(Box::<Close>::default()),
    ];
    let mut input = Vec::new();
    for body in bodies {
        mkit_rpc::write_frame(&mut input, &frame(body)).unwrap();
    }

    let (_root, args) = session_3_fixture();
    let out = mkit_serve_args(&args, &input);
    assert!(out.status.success(), "{out:?}");
    assert!(out.stderr.is_empty(), "{out:?}");

    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("golden")
        .join("ssh-serve");
    fs::write(dir.join("session-3.in.bin"), &input).unwrap();
    fs::write(dir.join("session-3.bin"), &out.stdout).unwrap();
    eprintln!(
        "recorded session-3.in.bin ({} B) and session-3.bin ({} B) in {}",
        input.len(),
        out.stdout.len(),
        dir.display()
    );
}

/// R-86 (SPEC-REFS §2): `<root>/main`, a ref an older `mkit serve` stored
/// for the name `main`, is not served: a read of `main` is refused by name,
/// pointing at the migration notes. Nothing reaches stderr (no server path
/// is sent to the client), and the file is left alone.
#[test]
fn refs_outside_refs_dir_are_refused_without_leaking_paths() {
    let td = repo_root();
    seed(td.path(), &[("refs/heads/main", [0x11; 32])], &[]);
    let wire = mkit_core::refs::encode_ref_wire(&[0x22; 32]);
    fs::write(td.path().join("main"), wire).unwrap();

    let mut input = Vec::new();
    for body in [
        Body::Hello(Box::new(
            Hello::default().with_proto(ProtocolVersion::ProtocolVersion1),
        )),
        Body::ReadRef(Box::new(ReadRef {
            name: Some("main".to_owned()),
            ..Default::default()
        })),
        Body::Close(Box::<Close>::default()),
    ] {
        mkit_rpc::write_frame(&mut input, &frame(body)).unwrap();
    }
    let out = mkit_serve(td.path(), &input);
    assert!(out.status.success(), "{out:?}");
    assert!(
        out.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let frames = decode(&out.stdout);
    let Some(Body::Error(e)) = &frames[1].body else {
        panic!("expected Error, got {:?}", frames[1].body);
    };
    let message = e.message.as_deref().unwrap_or_default();
    assert!(
        message.starts_with("ref name must start with refs/"),
        "{message}"
    );
    assert!(message.contains("migration notes"), "{message}");
    assert_eq!(fs::read(td.path().join("main")).unwrap(), wire);
}

/// `--max-session-secs` ends the process even while the client holds the
/// session open and silent (with the idle timeout off), exit 76.
#[test]
fn max_session_secs_ends_a_held_session() {
    let td = repo_root();
    let xdg = tempfile::tempdir().unwrap();
    let started = std::time::Instant::now();
    let mut child = Command::new(env!("CARGO_BIN_EXE_mkit"))
        .args([
            "serve",
            "--idle-timeout-secs",
            "0",
            "--max-session-secs",
            "1",
        ])
        .arg(td.path())
        .env("XDG_CONFIG_HOME", xdg.path())
        .env("HOME", xdg.path())
        .env_remove("MKIT_SERVE_ROOT")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Kept open (never written) until the process has exited.
    let stdin = child.stdin.take().unwrap();
    let out = child.wait_with_output().unwrap();
    drop(stdin);
    assert_eq!(out.status.code(), Some(76), "{out:?}");
    assert!(
        started.elapsed() < std::time::Duration::from_secs(30),
        "{:?}",
        started.elapsed()
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("--max-session-secs"), "{stderr}");
}
