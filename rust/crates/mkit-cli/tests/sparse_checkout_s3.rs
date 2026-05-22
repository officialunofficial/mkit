//! End-to-end S3-transport sparse-checkout coverage (issue #158
//! Phase 2). The S3 transport assumes the server (or a populating
//! Cloudflare Worker) has pre-built the sparse delivery under the
//! `sparse/<tree-hex>/<filter-hex>` object key — clients GET it.
//!
//! `S3Transport::with_parts` is the test-only constructor that
//! bypasses the `https://` rewrite `S3Transport::connect` performs;
//! mockito serves over plain `http://127.0.0.1:<port>`, so we use it
//! here to drive signed requests against the mock.

#![cfg(feature = "sparse-checkout")]

use std::path::PathBuf;

use mkit_core::hash::{Hash, to_hex};
use mkit_core::object::{EntryMode, Tree, TreeEntry};
use mkit_core::sparse::{
    SparseResponse, build_sparse, encode_sparse_response, hash_filter, tree_hash, verify_sparse,
};
use mkit_transport_s3::S3Transport;
use mkit_transport_s3::sigv4::Credentials;
use mockito::Server;

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

fn make_transport(server: &Server) -> S3Transport {
    S3Transport::with_parts(
        server.url(),
        "mybucket",
        None,
        Credentials {
            access_key_id: "AKIAEXAMPLE".to_string(),
            secret_access_key: "SECRETEXAMPLE".to_string(),
            region: "auto".to_string(),
        },
    )
    .expect("construct S3 test transport")
}

fn sparse_path(tree_hash: &Hash, filter_hash: &Hash) -> String {
    format!(
        "/mybucket/sparse/{}/{}",
        to_hex(tree_hash),
        to_hex(filter_hash)
    )
}

#[test]
fn s3_sparse_fetch_round_trip_verifies() {
    let tree = tree_for(&[b"a", b"b", b"c"]);
    let th = tree_hash(&tree);
    let filter = vec![PathBuf::from("a")];
    let fh = hash_filter(&filter);

    let (entries, manifest, proof) = build_sparse(&tree, &filter).unwrap();
    let body = encode_sparse_response(&SparseResponse {
        manifest,
        entries,
        proof,
    })
    .unwrap();

    let mut server = Server::new();
    let path = sparse_path(&th, &fh);
    let _m = server
        .mock("GET", path.as_str())
        .with_status(200)
        .with_body(body)
        .create();

    let tx = make_transport(&server);
    let resp = tx
        .fetch_sparse_tree(&th, &filter)
        .expect("S3 sparse fetch must succeed");
    assert!(verify_sparse(
        &resp.manifest,
        &resp.entries,
        &filter,
        &resp.proof
    ));
    assert_eq!(resp.manifest.tree_hash, th);
}

#[test]
fn s3_sparse_fetch_404_is_pack_not_found() {
    let tree = tree_for(&[b"a"]);
    let th = tree_hash(&tree);
    let filter = vec![PathBuf::from("a")];
    let fh = hash_filter(&filter);

    let mut server = Server::new();
    let path = sparse_path(&th, &fh);
    let _m = server.mock("GET", path.as_str()).with_status(404).create();

    let tx = make_transport(&server);
    let err = tx.fetch_sparse_tree(&th, &filter).unwrap_err();
    assert!(
        matches!(err, mkit_core::protocol::TransportError::PackNotFound),
        "S3 404 must surface as PackNotFound, got {err:?}"
    );
}

#[test]
fn s3_sparse_fetch_rejects_tampered_bitmap() {
    let tree = tree_for(&[b"a", b"b", b"c"]);
    let th = tree_hash(&tree);
    let filter = vec![PathBuf::from("a")];
    let fh = hash_filter(&filter);

    let (entries, manifest, mut proof) = build_sparse(&tree, &filter).unwrap();
    proof.bitmap_bytes[0] ^= 0b0000_0010;
    let body = encode_sparse_response(&SparseResponse {
        manifest,
        entries,
        proof,
    })
    .unwrap();

    let mut server = Server::new();
    let path = sparse_path(&th, &fh);
    let _m = server
        .mock("GET", path.as_str())
        .with_status(200)
        .with_body(body)
        .create();

    let tx = make_transport(&server);
    let resp = tx.fetch_sparse_tree(&th, &filter).unwrap();
    assert!(
        !verify_sparse(&resp.manifest, &resp.entries, &filter, &resp.proof),
        "tampered bitmap from S3 must still be rejected by verify_sparse"
    );
}
