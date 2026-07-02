//! Integration coverage for the `mkit+https` / `mkit+http` dispatch
//! branch in [`mkit_cli::remote_dispatch::open`].
//!
//! We stand up a [`mockito`] HTTP server, point the dispatcher at it via
//! `mkit+http://127.0.0.1:<port>/<project>`, and exercise:
//!
//! 1. `open()` successfully returns a usable transport (smoke check that
//!    the scheme branch is wired — the previous stub returned
//!    `UnsupportedScheme`).
//! 2. A full push roundtrip — list refs, upload pack, write ref — lands
//!    against the mock server in the shape the HTTP wire contract
//!    (SPEC-TRANSPORT §5.1) expects.
//! 3. A full pull roundtrip — list refs + download pack — materialises
//!    the remote's single ref into a fresh local repo.
//!
//! We use the `mockito` server as an in-memory worker: every handler
//! responds with canned JSON / bytes that mimic the real VCS Worker. The
//! test doesn't depend on the real worker; it only asserts the client's
//! wire behaviour.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::process::Command;

use mkit_cli::remote_dispatch;
use mockito::{Matcher, Server};

fn mkit_bin() -> &'static str {
    env!("CARGO_BIN_EXE_mkit")
}

fn run_in(cwd: &std::path::Path, args: &[&str]) -> std::process::Output {
    let xdg = tempfile::tempdir().expect("xdg tempdir");
    let out = Command::new(mkit_bin())
        .args(args)
        .current_dir(cwd)
        .env("XDG_CONFIG_HOME", xdg.path())
        .output()
        .expect("spawn mkit");
    drop(xdg);
    out
}

#[test]
fn open_accepts_mkit_http_url_and_returns_transport() {
    // Previously this branch returned `UnsupportedScheme`. With the
    // wiring in place, `open` should now succeed for a syntactically
    // valid `mkit+http://` URL — even if nothing is listening on the
    // other side. Construction does NOT make a network call.
    let tx = remote_dispatch::open("mkit+http://127.0.0.1:1/proj")
        .expect("mkit+http:// must now dispatch to HttpTransport");
    // Smoke: the returned `Arc<dyn Transport>` is live. We don't poke it
    // further because there's no server on port 1.
    drop(tx);
}

#[test]
fn open_accepts_mkit_https_url() {
    // Same branch, different sub-scheme — covered explicitly so a
    // regression in the `http`/`https` match can't go unnoticed.
    let tx = remote_dispatch::open("mkit+https://example.invalid/p")
        .expect("mkit+https:// must dispatch to HttpTransport");
    drop(tx);
}

#[test]
fn open_rejects_malformed_mkit_http_url() {
    // No scheme body — `HttpTransport::connect` surfaces this as an
    // `InvalidResponse` inside `TransportError`, which
    // `remote_dispatch::open` re-exports as `DispatchError::Transport`.
    let Err(err) = remote_dispatch::open("mkit+http://") else {
        panic!("expected error for empty mkit+http URL");
    };
    // Anything non-`Ok` is enough; the precise variant is an
    // implementation detail of the underlying transport crate.
    let msg = err.to_string();
    assert!(
        msg.contains("transport") || msg.contains("malformed"),
        "unexpected error for empty mkit+http URL: {msg}"
    );
}

/// Stand up a source repo with a single commit on `main`. Returns the
/// tempdir and the tip hash hex.
fn source_repo_with_one_commit() -> (tempfile::TempDir, String) {
    let td = tempfile::tempdir().unwrap();
    assert!(run_in(td.path(), &["init"]).status.success());
    assert!(run_in(td.path(), &["keygen"]).status.success());
    std::fs::write(td.path().join("hello.txt"), b"hello\n").unwrap();
    assert!(run_in(td.path(), &["add", "hello.txt"]).status.success());
    let out = run_in(td.path(), &["commit", "-m", "init"]);
    assert!(out.status.success(), "commit failed: {out:?}");
    let tip_hex = std::fs::read_to_string(td.path().join(".mkit/refs/heads/main"))
        .unwrap()
        .trim()
        .to_owned();
    (td, tip_hex)
}

/// Mock the push side of the wire dialect on `server`: 404 every ref
/// probe (fresh remote), echo the BLAKE3 of every uploaded body as the
/// `{"key": …}` confirmation (so the client's integrity cross-check
/// passes), and commit the atomic head+packmap advance. Captured
/// upload bodies land in `uploads`.
fn mock_fresh_remote_push(
    server: &mut Server,
    uploads: std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
) -> (mockito::Mock, mockito::Mock, mockito::Mock) {
    let ref_gets = server
        .mock("GET", Matcher::Regex(r"^/myproj/refs/refs/".to_string()))
        .with_status(404)
        // Branch-tip probe + packmap probe.
        .expect(2)
        .create();
    let pack_posts = server
        .mock("POST", "/myproj/packs")
        .with_status(201)
        .with_header("content-type", "application/json")
        .with_body_from_request(move |req| {
            let body = req.body().expect("upload body").clone();
            let hex = mkit_core::hash::to_hex(&mkit_core::hash::hash(&body));
            uploads.lock().unwrap().push(body);
            format!(r#"{{"key":"{hex}"}}"#).into_bytes()
        })
        // One pack + one packlist-node blob.
        .expect(2)
        .create();
    let advance = server
        .mock("POST", "/myproj/refs/advance")
        .with_status(200)
        .expect(1)
        .create();
    (ref_gets, pack_posts, advance)
}

#[test]
fn push_roundtrip_against_mockito_http_server() {
    // Build a small repo with one commit on `main`, point a mockito
    // server at the HTTP wire dialect, and run `push_all` through
    // `remote_dispatch`. The server echoes the BLAKE3 of each uploaded
    // body, so the client's integrity cross-check passes and the push
    // must SUCCEED end-to-end: one branch pushed, the pack + packlist
    // node uploaded, and the head+packmap advance committed.
    let (td, _tip_hex) = source_repo_with_one_commit();

    let mut server = Server::new();
    let uploads = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let (ref_gets, pack_posts, advance) = mock_fresh_remote_push(&mut server, uploads.clone());

    let url = format!("{}/myproj", server.url());
    let dispatch_url = format!("mkit+{url}");
    let tx = remote_dispatch::open(&dispatch_url).expect("open mkit+http");

    let n = remote_dispatch::push_all(td.path(), tx.as_ref()).expect("push must succeed");
    assert_eq!(n, 1, "exactly one branch (main) must be pushed");
    // Every leg of the roundtrip landed, the expected number of times.
    ref_gets.assert();
    pack_posts.assert();
    advance.assert();
    // Exactly one pack and one packlist node (MKPL magic) were sent.
    let uploads = uploads.lock().unwrap();
    assert_eq!(uploads.len(), 2);
    assert_eq!(
        uploads.iter().filter(|b| b.starts_with(b"MKPL")).count(),
        1,
        "push must advertise exactly one packlist node"
    );
}

#[test]
fn pull_roundtrip_against_mockito_http_server() {
    // Full pull roundtrip: `list_refs` → packmap ref → packlist-node
    // blob → pack download → unpack → branch ref + worktree
    // materialise in a fresh local repo.
    //
    // To serve REAL pack/node bytes without duplicating the wire
    // format in the test, phase 1 drives an actual `push_all` from a
    // source repo into a mock server, capturing the uploaded bodies;
    // phase 2 serves those bodies back to a fresh repo's `pull_all`.
    let (src, tip_hex) = source_repo_with_one_commit();

    // --- phase 1: capture the push's pack + packlist node ---
    let captured = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let mut server = Server::new();
    let _mocks = mock_fresh_remote_push(&mut server, captured.clone());
    let dispatch_url = format!("mkit+{}/myproj", server.url());
    let tx = remote_dispatch::open(&dispatch_url).expect("open mkit+http");
    assert_eq!(
        remote_dispatch::push_all(src.path(), tx.as_ref()).expect("seed push"),
        1
    );
    drop(tx);
    drop(server);

    let captured = captured.lock().unwrap().clone();
    assert_eq!(captured.len(), 2, "seed push uploads pack + node");
    let (nodes, packs): (Vec<Vec<u8>>, Vec<Vec<u8>>) =
        captured.into_iter().partition(|b| b.starts_with(b"MKPL"));
    let (node, pack) = (&nodes[0], &packs[0]);
    let node_hex = mkit_core::hash::to_hex(&mkit_core::hash::hash(node));
    let pack_hex = mkit_core::hash::to_hex(&mkit_core::hash::hash(pack));

    // --- phase 2: serve the captured remote to a fresh repo ---
    let mut server = Server::new();
    let refs_list = server
        .mock("GET", Matcher::Regex(r"^/myproj/refs\?prefix=".to_string()))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(format!(
            r#"{{"refs":[{{"name":"main","hash":"{tip_hex}"}}]}}"#
        ))
        .expect_at_least(1)
        .create();
    let packmap_get = server
        .mock("GET", "/myproj/refs/refs/mkit/packmap/main")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(format!(r#"{{"hash":"{node_hex}"}}"#))
        .expect_at_least(1)
        .create();
    let node_get = server
        .mock("GET", format!("/myproj/packs/{node_hex}").as_str())
        .with_status(200)
        .with_body(node.clone())
        .expect_at_least(1)
        .create();
    let pack_get = server
        .mock("GET", format!("/myproj/packs/{pack_hex}").as_str())
        .with_status(200)
        .with_body(pack.clone())
        .expect_at_least(1)
        .create();

    let dst = tempfile::tempdir().unwrap();
    assert!(run_in(dst.path(), &["init"]).status.success());
    let dispatch_url = format!("mkit+{}/myproj", server.url());
    let tx = remote_dispatch::open(&dispatch_url).expect("open mkit+http");

    let n = remote_dispatch::pull_all(dst.path(), tx.as_ref(), "default").expect("pull");
    assert_eq!(n, 1, "one remote branch must be fetched");
    // Every leg of the pull actually landed.
    refs_list.assert();
    packmap_get.assert();
    node_get.assert();
    pack_get.assert();
    // The remote's single ref materialised: branch ref on the remote
    // tip and the committed file restored into the worktree.
    let local_tip = std::fs::read_to_string(dst.path().join(".mkit/refs/heads/main")).unwrap();
    assert_eq!(
        local_tip.trim(),
        tip_hex,
        "pulled branch must land on the remote tip"
    );
    assert_eq!(
        std::fs::read(dst.path().join("hello.txt")).unwrap(),
        b"hello\n",
        "pull must materialise the committed file"
    );
}
