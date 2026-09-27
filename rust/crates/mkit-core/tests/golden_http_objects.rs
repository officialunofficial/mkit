//! SPEC-HTTP-OBJECTS tables, unchanged MKDP bodies, and test-only MKDS codec.
//! Check mode consumes committed bytes; only `MKIT_WRITE_GOLDEN=1` builds fixtures.
#![allow(clippy::unwrap_used)]

use std::{collections::BTreeMap, fmt::Write as _, fs, path::PathBuf};

use commonware_codec::Write as _;
use mkit_core::{
    hash::{Hash, hash, to_hex},
    object::{Object, Tree, TreeEntry},
    serialize::{deserialize, serialize},
    sign::{KeyPair, sign_commit},
    verify::{Disclosed, DisclosedPayload, Selector, build_disclosure_from, verify_disclosure},
};
use serde_json::{Value, json};

mod common;
#[path = "http_objects/span.rs"]
mod span;
#[path = "http_objects/tables.rs"]
mod tables;

const CAP: usize = 64 * 1024 * 1024;

fn directory() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/golden/http-objects")
}

fn encoded_span(commit: Hash, offset: u64, len: u64, anchor: &[u8], chunks: &[Vec<u8>]) -> Vec<u8> {
    let mut out = b"MKDS\x01".to_vec();
    commit.write(&mut out);
    offset.write(&mut out);
    len.write(&mut out);
    anchor.write(&mut out);
    chunks.write(&mut out);
    out
}

fn body(disclosed: &Disclosed) -> &[u8] {
    match &disclosed.payload {
        DisclosedPayload::Object { bytes }
        | DisclosedPayload::Chunk { bytes, .. }
        | DisclosedPayload::Range { bytes, .. } => bytes,
    }
}

fn summary(disclosed: &Disclosed) -> Value {
    let payload = match &disclosed.payload {
        DisclosedPayload::Object { .. } => json!({"kind": "Object"}),
        DisclosedPayload::Chunk {
            index,
            total_size,
            chunk_size,
            ..
        } => {
            json!({"kind": "Chunk", "index": index, "total_size": total_size, "chunk_size": chunk_size})
        }
        DisclosedPayload::Range {
            offset_in_blob,
            absolute_offset,
            chunk,
            ..
        } => {
            json!({"kind": "Range", "offset_in_blob": offset_in_blob, "absolute_offset": absolute_offset, "chunk": chunk})
        }
    };
    json!({"commit": to_hex(&disclosed.commit_id), "leaf": to_hex(&disclosed.leaf_id),
        "path_hex": disclosed.path.iter().map(|(n, _)| hex(n)).collect::<Vec<_>>(),
        "payload": payload, "bytes_blake3": to_hex(&hash(body(disclosed))), "bytes_len": body(disclosed).len(),
        "signature_valid": disclosed.signature_valid})
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, b| {
        write!(out, "{b:02x}").unwrap();
        out
    })
}

fn add_proof(
    files: &mut BTreeMap<String, Vec<u8>>,
    name: &str,
    commit: Hash,
    bin: Vec<u8>,
    expected: Value,
) {
    let mut sidecar = json!({"schema_version": 1, "name": name, "commit": to_hex(&commit),
        "size": bin.len(), "blake3": to_hex(&hash(&bin))});
    sidecar["expect"] = expected;
    files.insert(format!("{name}.bin"), bin);
    files.insert(
        format!("{name}.json"),
        serde_json::to_vec_pretty(&sidecar).unwrap(),
    );
}

#[allow(clippy::too_many_lines)] // Declarative accept/reject fixture list.
fn fixture_files() -> BTreeMap<String, Vec<u8>> {
    let fixture = common::build_fixture();
    let mut files = BTreeMap::new();
    for (name, path, selector) in [
        (
            "object_shallow",
            vec![b"shallow.txt".as_slice()],
            Selector::Object,
        ),
        ("object_root", vec![], Selector::Object),
        ("chunk", vec![b"chunked.bin".as_slice()], Selector::Chunk(1)),
        (
            "blob_range",
            vec![b"range.bin".as_slice()],
            Selector::Range {
                offset: 32,
                len: 16,
                with_offsets: true,
            },
        ),
    ] {
        let bin =
            build_disclosure_from(&fixture.store, &fixture.commit_id, &path, selector).unwrap();
        let disclosed = verify_disclosure(&fixture.commit_id, &bin).unwrap();
        add_proof(
            &mut files,
            name,
            fixture.commit_id,
            bin,
            json!({"accept": true, "disclosed": summary(&disclosed)}),
        );
    }
    let Object::Tree(tree) = fixture.store.read_object(&fixture.tree_hash).unwrap() else {
        panic!("tree")
    };
    let chunked_id = tree
        .entries
        .iter()
        .find(|e| e.name == b"chunked.bin")
        .unwrap()
        .object_hash;
    let Object::ChunkedBlob(cb) = fixture.store.read_object(&chunked_id).unwrap() else {
        panic!("manifest")
    };
    assert!(cb.chunks.len() >= 3);
    let lengths: Vec<u64> = cb
        .chunks
        .iter()
        .map(|id| {
            let Object::Blob(b) = fixture.store.read_object(id).unwrap() else {
                panic!("blob")
            };
            b.data.len() as u64
        })
        .collect();
    let build = |commit: Hash, path: &[&[u8]], selector| {
        build_disclosure_from(&fixture.store, &commit, path, selector).unwrap()
    };
    let path: &[&[u8]] = &[b"chunked.bin"];
    let in_chunk = build(
        fixture.commit_id,
        path,
        Selector::Range {
            offset: lengths[0] + 32,
            len: 16,
            with_offsets: true,
        },
    );
    let disclosed = verify_disclosure(&fixture.commit_id, &in_chunk).unwrap();
    add_proof(
        &mut files,
        "in_chunk_range",
        fixture.commit_id,
        in_chunk,
        json!({"accept": true, "disclosed": summary(&disclosed)}),
    );

    let anchor = |commit, first: usize, with_offsets| {
        build(
            commit,
            path,
            Selector::Range {
                offset: lengths[..first].iter().sum(),
                len: 1,
                with_offsets,
            },
        )
    };
    let chunk = |commit, i| build(commit, path, Selector::Chunk(i));
    let start = lengths[0];
    let offset = start + lengths[1] - 10;
    let anchor_bundle = anchor(fixture.commit_id, 1, true);
    let chunk_bundles = vec![chunk(fixture.commit_id, 1), chunk(fixture.commit_id, 2)];
    let valid = encoded_span(
        fixture.commit_id,
        offset,
        20,
        &anchor_bundle,
        &chunk_bundles,
    );
    let mut vectors = vec![
        (
            "span_two_chunks",
            fixture.commit_id,
            valid.clone(),
            None,
            None,
        ),
        (
            "span_first_zero",
            fixture.commit_id,
            encoded_span(
                fixture.commit_id,
                lengths[0] - 10,
                20,
                &anchor(fixture.commit_id, 0, true),
                &[chunk(fixture.commit_id, 0), chunk(fixture.commit_id, 1)],
            ),
            None,
            None,
        ),
        (
            "span_three_chunks",
            fixture.commit_id,
            encoded_span(
                fixture.commit_id,
                lengths[0] - 10,
                lengths[1] + 20,
                &anchor(fixture.commit_id, 0, true),
                &[
                    chunk(fixture.commit_id, 0),
                    chunk(fixture.commit_id, 1),
                    chunk(fixture.commit_id, 2),
                ],
            ),
            None,
            None,
        ),
        (
            "neg_noncontiguous",
            fixture.commit_id,
            encoded_span(
                fixture.commit_id,
                offset,
                20,
                &anchor_bundle,
                &[chunk(fixture.commit_id, 0), chunk(fixture.commit_id, 2)],
            ),
            Some("span_chunk_order"),
            None,
        ),
        (
            "neg_reordered",
            fixture.commit_id,
            encoded_span(
                fixture.commit_id,
                offset,
                20,
                &anchor_bundle,
                &[chunk_bundles[1].clone(), chunk_bundles[0].clone()],
            ),
            Some("span_chunk_order"),
            None,
        ),
        (
            "neg_missing_anchor",
            fixture.commit_id,
            encoded_span(fixture.commit_id, offset, 20, &[], &chunk_bundles),
            Some("span_anchor_invalid"),
            None,
        ),
        (
            "neg_missing_offsets",
            fixture.commit_id,
            encoded_span(
                fixture.commit_id,
                offset,
                20,
                &anchor(fixture.commit_id, 1, false),
                &chunk_bundles,
            ),
            Some("span_anchor_offset"),
            None,
        ),
        (
            "neg_outside_span",
            fixture.commit_id,
            encoded_span(
                fixture.commit_id,
                start - 1,
                20,
                &anchor_bundle,
                &chunk_bundles,
            ),
            Some("span_range_outside"),
            None,
        ),
        (
            "neg_superfluous_last",
            fixture.commit_id,
            encoded_span(fixture.commit_id, start, 1, &anchor_bundle, &chunk_bundles),
            Some("span_last_unneeded"),
            None,
        ),
        (
            "neg_zero_length",
            fixture.commit_id,
            encoded_span(fixture.commit_id, offset, 0, &anchor_bundle, &chunk_bundles),
            Some("span_range_arithmetic"),
            None,
        ),
        (
            "neg_overflow",
            fixture.commit_id,
            encoded_span(
                fixture.commit_id,
                u64::MAX,
                2,
                &anchor_bundle,
                &chunk_bundles,
            ),
            Some("span_range_arithmetic"),
            None,
        ),
        (
            "neg_one_chunk",
            fixture.commit_id,
            encoded_span(
                fixture.commit_id,
                offset,
                20,
                &anchor_bundle,
                &chunk_bundles[..1],
            ),
            Some("span_chunk_count"),
            None,
        ),
    ];
    // A second genuine signed commit over the same tree isolates commit mixing.
    let Object::Commit(mut commit) = fixture.store.read_object(&fixture.commit_id).unwrap() else {
        panic!("commit")
    };
    commit.timestamp += 1;
    commit.signature = sign_commit(&commit, &KeyPair::from_seed([0x07; 32]))
        .unwrap()
        .0;
    let second = fixture
        .store
        .write(&serialize(&Object::Commit(commit.clone())).unwrap())
        .unwrap();
    vectors.push((
        "neg_mixed_commits",
        fixture.commit_id,
        encoded_span(
            fixture.commit_id,
            offset,
            20,
            &anchor_bundle,
            &[chunk_bundles[0].clone(), chunk(second, 2)],
        ),
        Some("span_inner_invalid"),
        None,
    ));
    vectors.push((
        "neg_trusted_commit",
        second,
        valid.clone(),
        Some("span_commit"),
        None,
    ));
    // An extended tree in the SAME fixture store provides anchor_bundle genuine different
    // chunked leaf under one commit, without changing the shared fixture.
    let other = mkit_core::worktree::store_file_object(
        &fixture.store,
        &common::prng_bytes(99, 3 * 1024 * 1024),
    )
    .unwrap();
    let mut entries = tree.entries;
    entries.push(TreeEntry {
        name: b"other.bin".to_vec(),
        mode: mkit_core::object::EntryMode::Blob,
        object_hash: other,
    });
    entries.sort_by(|left, right| left.name.cmp(&right.name));
    commit.tree_hash = fixture
        .store
        .write(&serialize(&Object::Tree(Tree { entries })).unwrap())
        .unwrap();
    commit.signature = sign_commit(&commit, &KeyPair::from_seed([0x07; 32]))
        .unwrap()
        .0;
    let extended = fixture
        .store
        .write(&serialize(&Object::Commit(commit)).unwrap())
        .unwrap();
    let other_chunk = build(extended, &[b"other.bin"], Selector::Chunk(2));
    vectors.push((
        "neg_mismatched_leaf",
        extended,
        encoded_span(
            extended,
            offset,
            20,
            &anchor(extended, 1, true),
            &[chunk(extended, 1), other_chunk],
        ),
        Some("span_leaf_context"),
        None,
    ));
    // Existing invalid MKDP anchor proves that nonempty but incomplete length
    // sets are rejected, rather than silently treated as omitted.
    let incomplete = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/golden/disclosure/neg_incomplete_length_proof_set.bin");
    vectors.push((
        "neg_incomplete_anchor",
        fixture.commit_id,
        encoded_span(
            fixture.commit_id,
            offset,
            20,
            &fs::read(incomplete).unwrap(),
            &chunk_bundles,
        ),
        Some("span_anchor_invalid"),
        None,
    ));
    let mut magic = valid.clone();
    magic[0] = b'X';
    vectors.push((
        "neg_magic",
        fixture.commit_id,
        magic,
        Some("span_magic"),
        None,
    ));
    let mut version = valid.clone();
    version[4] = 2;
    vectors.push((
        "neg_version",
        fixture.commit_id,
        version,
        Some("span_version"),
        None,
    ));
    let mut trailing = valid.clone();
    trailing.push(0);
    vectors.push((
        "neg_trailing",
        fixture.commit_id,
        trailing,
        Some("span_trailing_bytes"),
        None,
    ));
    vectors.push((
        "neg_truncated",
        fixture.commit_id,
        valid[..20].to_vec(),
        Some("span_encoding"),
        None,
    ));
    vectors.push((
        "neg_oversize",
        fixture.commit_id,
        b"MKDS\x01".to_vec(),
        Some("span_too_large"),
        Some(CAP + 1),
    ));
    let plaintext = common::prng_bytes(0x1234_5678_9abc_def0, 3 * 1024 * 1024);
    for (name, trusted, bin, reject, expanded) in vectors {
        let mut input = bin.clone();
        if let Some(n) = expanded {
            input.resize(n, 0);
        }
        let got = span::verify(&trusted, &input);
        let expected = if let Some(reason) = reject {
            assert_eq!(got.unwrap_err(), reason, "{name}");
            json!({"accept": false, "reject_reason": reason, "expand_to": expanded})
        } else {
            let verified_span = got.unwrap();
            assert_eq!(
                verified_span.bytes,
                plaintext[usize::try_from(verified_span.offset).unwrap()
                    ..usize::try_from(verified_span.offset).unwrap() + verified_span.bytes.len()]
            );
            json!({"accept": true, "offset": verified_span.offset, "bytes_len": verified_span.bytes.len(), "bytes_blake3": to_hex(&hash(&verified_span.bytes)), "leaf": to_hex(&verified_span.leaf), "path_hex": verified_span.path.iter().map(|n| hex(n)).collect::<Vec<_>>(), "signature_valid": verified_span.signature_valid})
        };
        add_proof(&mut files, name, trusted, bin, expected);
    }
    for (name, table) in [
        ("url-parse.json", tables::urls()),
        ("response-cases.json", tables::responses()),
    ] {
        files.insert(name.into(), serde_json::to_vec_pretty(&table).unwrap());
    }
    files
}

#[test]
fn write_http_object_goldens_if_requested() {
    if std::env::var("MKIT_WRITE_GOLDEN").as_deref() != Ok("1") {
        return;
    }
    let dir = directory();
    fs::create_dir_all(&dir).unwrap();
    let files = fixture_files();
    let mut manifest = String::from(
        "# SPEC-HTTP-OBJECTS and MKDS v1; <artifact> <BLAKE3>\n# MKIT_WRITE_GOLDEN=1 cargo test -p mkit-core --test golden_http_objects\n",
    );
    for (name, bytes) in files {
        writeln!(manifest, "{name} {}", to_hex(&hash(&bytes))).unwrap();
        fs::write(dir.join(name), bytes).unwrap();
    }
    fs::write(dir.join("MANIFEST.txt"), manifest).unwrap();
}

#[test]
fn committed_http_object_goldens_verify() {
    if std::env::var("MKIT_WRITE_GOLDEN").as_deref() == Ok("1") {
        return;
    }
    let dir = directory();
    let manifest = fs::read_to_string(dir.join("MANIFEST.txt")).unwrap();
    let mut count = 0;
    for row in manifest
        .lines()
        .filter(|verified_span| !verified_span.starts_with('#') && !verified_span.is_empty())
    {
        let (name, digest) = row.split_once(' ').unwrap();
        let bytes = fs::read(dir.join(name)).unwrap();
        assert_eq!(to_hex(&hash(&bytes)), digest, "{name}");
        count += 1;
        if std::path::Path::new(name).extension() != Some(std::ffi::OsStr::new("bin")) {
            continue;
        }
        let sidecar: Value =
            serde_json::from_slice(&fs::read(dir.join(name.replace(".bin", ".json"))).unwrap())
                .unwrap();
        assert_eq!(sidecar["size"], json!(bytes.len()));
        assert_eq!(sidecar["blake3"], digest);
        let trusted = mkit_core::hash::from_hex(sidecar["commit"].as_str().unwrap()).unwrap();
        let want = &sidecar["expect"];
        if name.starts_with("object_")
            || ["chunk.bin", "blob_range.bin", "in_chunk_range.bin"].contains(&name)
        {
            let disclosed = verify_disclosure(&trusted, &bytes).unwrap();
            assert_eq!(summary(&disclosed), want["disclosed"], "{name}");
        } else {
            let mut bytes = bytes;
            if let Some(n) = want["expand_to"].as_u64() {
                assert_eq!(n, (CAP + 1) as u64);
                bytes.resize(usize::try_from(n).unwrap(), 0);
            }
            let got = span::verify(&trusted, &bytes);
            if want["accept"] == true {
                let verified_span = got.unwrap();
                assert_eq!(json!(verified_span.offset), want["offset"]);
                assert_eq!(json!(verified_span.bytes.len()), want["bytes_len"]);
                assert_eq!(to_hex(&hash(&verified_span.bytes)), want["bytes_blake3"]);
                assert_eq!(to_hex(&verified_span.leaf), want["leaf"]);
                assert_eq!(
                    json!(
                        verified_span
                            .path
                            .iter()
                            .map(|n| hex(n))
                            .collect::<Vec<_>>()
                    ),
                    want["path_hex"]
                );
                assert_eq!(
                    json!(verified_span.signature_valid),
                    want["signature_valid"]
                );
            } else {
                assert_eq!(
                    got.unwrap_err(),
                    want["reject_reason"].as_str().unwrap(),
                    "{name}"
                );
            }
        }
    }
    assert!(count >= 40);
    tables::check(&dir);
}
