//! End-to-end HTTP-transport sparse-checkout coverage (issue #158).
//! Spins up a `mockito` server that responds to
//! `POST /<project>/trees/<hex>/sparse?sparse=<filter-hex>` with a
//! server-built sparse envelope, then asserts the client decodes and
//! verifies it.

#![cfg(feature = "sparse-checkout")]
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::path::PathBuf;

use mkit_core::hash::{Hash, to_hex};
use mkit_core::object::{EntryMode, Tree, TreeEntry};
use mkit_core::sparse::{build_sparse, encode_sparse_response, hash_filter, tree_hash};
use mkit_transport_http::HttpTransport;
use mockito::{Matcher, Server};

fn entry(name: &[u8]) -> TreeEntry {
    TreeEntry {
        name: name.to_vec(),
        mode: EntryMode::Blob,
        object_hash: [0u8; 32],
    }
}

fn tree_for(names: &[&[u8]]) -> Tree {
    Tree {
        entries: names.iter().copied().map(entry).collect(),
    }
}

fn make_transport(server: &Server) -> HttpTransport {
    // `HttpTransport::connect` parses the `mkit+http://` form and
    // validates loopback for plain http; mockito always binds on
    // 127.0.0.1, so this is the production code path.
    let url = format!("mkit+{}/myproj", server.url());
    HttpTransport::connect(&url).expect("connect to mockito")
}

fn sparse_path(tree: &Hash) -> String {
    format!("/myproj/trees/{}/sparse", to_hex(tree))
}

#[test]
fn http_sparse_fetch_round_trip_verifies() {
    let tree = tree_for(&[b"a", b"b", b"c"]);
    let th = tree_hash(&tree);
    let filter = vec![PathBuf::from("a")];
    let fh = hash_filter(&filter);

    // Server-side: build the sparse response just like the
    // Cloudflare Worker reference impl would.
    let response = build_sparse(&tree, &filter).unwrap();
    let body = encode_sparse_response(&response).unwrap();

    let mut server = Server::new();
    let path = sparse_path(&th);
    let query = format!("sparse={}", to_hex(&fh));
    let _m = server
        .mock("POST", path.as_str())
        .match_query(Matcher::Exact(query))
        .match_header("content-type", "application/json")
        .with_status(200)
        .with_header("content-type", "application/x-mkit-sparse")
        .with_body(body)
        .create();

    let tx = make_transport(&server);
    let resp = tx
        .fetch_sparse_tree(&th, &filter)
        .expect("HTTP sparse fetch must succeed");

    // The transport returns the selection derived from the verified witness.
    assert_eq!(resp.manifest.tree_hash, th);
    assert_eq!(resp.manifest.filter_hash, fh);
    assert_eq!(resp.entries.len(), 1);
    assert_eq!(resp.entries[0].name, b"a");
}

#[test]
fn http_sparse_fetch_rejects_tampered_witness() {
    let tree = tree_for(&[b"a", b"b", b"c"]);
    let th = tree_hash(&tree);
    let filter = vec![PathBuf::from("a")];

    // Alter the encoded witness; the transport must reject it.
    let response = build_sparse(&tree, &filter).unwrap();
    let mut body = encode_sparse_response(&response).unwrap();

    body[73] ^= 2;
    let mut server = Server::new();
    let path = sparse_path(&th);
    let _m = server
        .mock("POST", path.as_str())
        .match_query(Matcher::Any)
        .with_status(200)
        .with_header("content-type", "application/x-mkit-sparse")
        .with_body(body)
        .create();

    let tx = make_transport(&server);
    // Decode and requested-root verification reject the altered witness.
    assert!(tx.fetch_sparse_tree(&th, &filter).is_err());
}

#[test]
fn http_sparse_fetch_404_is_pack_not_found() {
    let tree = tree_for(&[b"a"]);
    let th = tree_hash(&tree);
    let filter = vec![PathBuf::from("a")];

    let mut server = Server::new();
    let _m = server
        .mock("POST", sparse_path(&th).as_str())
        .match_query(Matcher::Any)
        .with_status(404)
        .create();

    let tx = make_transport(&server);
    let err = tx.fetch_sparse_tree(&th, &filter).unwrap_err();
    assert!(
        matches!(err, mkit_core::protocol::TransportError::PackNotFound),
        "404 must surface as PackNotFound, got {err:?}"
    );
}

#[test]
fn http_sparse_fetch_garbage_body_is_invalid_response() {
    let tree = tree_for(&[b"a"]);
    let th = tree_hash(&tree);
    let filter = vec![PathBuf::from("a")];

    let mut server = Server::new();
    let _m = server
        .mock("POST", sparse_path(&th).as_str())
        .match_query(Matcher::Any)
        .with_status(200)
        .with_body(b"this is not a sparse envelope")
        .create();

    let tx = make_transport(&server);
    let err = tx.fetch_sparse_tree(&th, &filter).unwrap_err();
    assert!(
        matches!(err, mkit_core::protocol::TransportError::InvalidResponse),
        "bad envelope must surface as InvalidResponse, got {err:?}"
    );
}
