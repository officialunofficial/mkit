//! SPEC-HTTP-OBJECTS tables, unchanged MKDP bodies, and test-only MKDS codec.
//! Check mode consumes committed bytes; only `MKIT_WRITE_GOLDEN=1` builds fixtures.
#![allow(clippy::unwrap_used)]

use std::{
    collections::{BTreeMap, HashMap},
    fmt::Write as _,
    fs,
    path::PathBuf,
    sync::OnceLock,
};

use commonware_codec::Write as _;
use mkit_core::verify::span::{RangeProof, build_range_proof_from, verify_disclosure_span};
use mkit_core::{
    hash::{Hash, hash, to_hex},
    object::{Object, Tree, TreeEntry},
    serialize::{deserialize, serialize},
    sign::{KeyPair, sign_commit},
    verify::{Disclosed, DisclosedPayload, Selector, build_disclosure_from, verify_disclosure},
};
use proptest::prelude::*;
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

struct RecipeIndex {
    sources: Vec<(String, Vec<u8>)>,
    positions: HashMap<[u8; 32], Vec<(usize, usize)>>,
}

impl RecipeIndex {
    fn new(files: &BTreeMap<String, Vec<u8>>) -> Self {
        let sources: Vec<_> = [
            "span_two_chunks.bin",
            "span_first_zero.bin",
            "span_three_chunks.bin",
        ]
        .into_iter()
        .map(|name| (name.to_owned(), files[name].clone()))
        .collect();
        let mut positions = HashMap::<[u8; 32], Vec<(usize, usize)>>::new();
        for (source, (_, bytes)) in sources.iter().enumerate() {
            for offset in 0..=bytes.len() - 32 {
                let key: [u8; 32] = bytes[offset..offset + 32].try_into().unwrap();
                let candidates = positions.entry(key).or_default();
                if candidates.len() < 8 {
                    candidates.push((source, offset));
                }
            }
        }
        Self { sources, positions }
    }
}

fn compact_against_bases(files: &mut BTreeMap<String, Vec<u8>>, name: &str, index: &RecipeIndex) {
    let bin_name = format!("{name}.bin");
    let bin = files.remove(&bin_name).unwrap();
    let mut segments = Vec::new();
    let mut literal = Vec::new();
    let mut cursor = 0;
    while cursor < bin.len() {
        let mut best = (0usize, 0usize, 0usize);
        if let Some(window) = bin.get(cursor..cursor + 32) {
            let key: [u8; 32] = window.try_into().unwrap();
            if let Some(candidates) = index.positions.get(&key) {
                for &(source, offset) in candidates {
                    let bytes = &index.sources[source].1;
                    let length = bin[cursor..]
                        .iter()
                        .zip(&bytes[offset..])
                        .take_while(|(a, b)| a == b)
                        .count();
                    if length > best.2 {
                        best = (source, offset, length);
                    }
                }
            }
        }
        if best.2 >= 32 {
            if !literal.is_empty() {
                segments.push(json!({"hex":hex(&literal)}));
                literal.clear();
            }
            segments
                .push(json!({"source":index.sources[best.0].0,"offset":best.1,"length":best.2}));
            cursor += best.2;
        } else {
            literal.push(bin[cursor]);
            cursor += 1;
        }
    }
    if !literal.is_empty() {
        segments.push(json!({"hex":hex(&literal)}));
    }
    let json_name = format!("{name}.json");
    let mut sidecar: Value = serde_json::from_slice(&files[&json_name]).unwrap();
    sidecar["recipe"] = json!({"segments":segments});
    files.insert(json_name, serde_json::to_vec_pretty(&sidecar).unwrap());
}

fn body_from_sidecar(dir: &std::path::Path, name: &str, sidecar: &Value) -> Vec<u8> {
    let Some(recipe) = sidecar.get("recipe") else {
        return fs::read(dir.join(format!("{name}.bin"))).unwrap();
    };
    let mut out = Vec::new();
    for segment in recipe["segments"].as_array().unwrap() {
        if let Some(source) = segment["source"].as_str() {
            let base = fs::read(dir.join(source)).unwrap();
            let offset = usize::try_from(segment["offset"].as_u64().unwrap()).unwrap();
            let length = usize::try_from(segment["length"].as_u64().unwrap()).unwrap();
            out.extend_from_slice(&base[offset..offset + length]);
        } else {
            let insert_hex = segment["hex"].as_str().unwrap();
            assert_eq!(insert_hex.len() % 2, 0);
            for pair in insert_hex.as_bytes().chunks_exact(2) {
                assert!(pair.iter().all(u8::is_ascii_hexdigit));
                out.push(u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap());
            }
        }
    }
    out
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
            "neg_gap",
            fixture.commit_id,
            encoded_span(
                fixture.commit_id,
                lengths[0] - 10,
                20,
                &anchor(fixture.commit_id, 0, true),
                &[chunk(fixture.commit_id, 0), chunk(fixture.commit_id, 2)],
            ),
            Some("span_chunk_order"),
            None,
        ),
        (
            "neg_duplicate",
            fixture.commit_id,
            encoded_span(
                fixture.commit_id,
                lengths[0] - 10,
                lengths[1] + 20,
                &anchor(fixture.commit_id, 0, true),
                &[
                    chunk(fixture.commit_id, 0),
                    chunk(fixture.commit_id, 1),
                    chunk(fixture.commit_id, 1),
                ],
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
            "neg_anchor_selector",
            fixture.commit_id,
            encoded_span(
                fixture.commit_id,
                offset,
                20,
                &chunk_bundles[0],
                &chunk_bundles,
            ),
            Some("span_anchor_selector"),
            None,
        ),
        (
            "neg_chunk_selector",
            fixture.commit_id,
            encoded_span(
                fixture.commit_id,
                offset,
                20,
                &anchor_bundle,
                &[anchor_bundle.clone(), chunk_bundles[1].clone()],
            ),
            Some("span_chunk_selector"),
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
            "neg_end_beyond_span",
            fixture.commit_id,
            encoded_span(
                fixture.commit_id,
                offset,
                lengths[1] + lengths[2],
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
    // Structural failures must be diagnosed before any embedded MKDP verification.
    let mut nonminimal = valid[..53].to_vec();
    nonminimal.extend_from_slice(&[0x80, 0x00]);
    vectors.push((
        "neg_nonminimal_varint",
        fixture.commit_id,
        nonminimal,
        Some("span_encoding"),
        None,
    ));
    let mut over_u32 = valid[..53].to_vec();
    over_u32.extend_from_slice(&[0x80, 0x80, 0x80, 0x80, 0x10]);
    vectors.push((
        "neg_varint_over_u32",
        fixture.commit_id,
        over_u32,
        Some("span_encoding"),
        None,
    ));
    vectors.push((
        "neg_mkdp_as_mkds",
        fixture.commit_id,
        files["in_chunk_range.bin"].clone(),
        Some("span_magic"),
        None,
    ));
    vectors.push((
        "neg_mkds_anchor",
        fixture.commit_id,
        encoded_span(fixture.commit_id, offset, 20, &valid, &chunk_bundles),
        Some("span_anchor_invalid"),
        None,
    ));
    let mut excessive_count = valid[..53].to_vec();
    excessive_count.extend_from_slice(&[0, 0xc1, 0x84, 0x3d]); // anchor length 0; count 1,000,001
    vectors.push((
        "neg_chunk_count_too_large",
        fixture.commit_id,
        excessive_count,
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
    let index = RecipeIndex::new(&files);
    let negatives: Vec<String> = files
        .keys()
        .filter_map(|name| name.strip_suffix(".bin"))
        .filter(|name| {
            name.starts_with("neg_") && !["neg_oversize", "neg_truncated"].contains(name)
        })
        .map(str::to_owned)
        .collect();
    for name in negatives {
        compact_against_bases(&mut files, &name, &index);
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
    for entry in fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if path
            .extension()
            .is_some_and(|ext| ext == "bin" || ext == "json")
            || path.file_name().is_some_and(|name| name == "MANIFEST.txt")
        {
            fs::remove_file(path).unwrap();
        }
    }
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
#[allow(clippy::too_many_lines)] // Golden checks enumerate every sidecar and proof format.
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
    }
    for entry in fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension() != Some(std::ffi::OsStr::new("json")) {
            continue;
        }
        let name = path.file_stem().unwrap().to_str().unwrap();
        if ["url-parse", "response-cases"].contains(&name) {
            continue;
        }
        let sidecar: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        let bytes = body_from_sidecar(&dir, name, &sidecar);
        assert_eq!(sidecar["size"], json!(bytes.len()));
        assert_eq!(sidecar["blake3"], to_hex(&hash(&bytes)));
        let trusted = mkit_core::hash::from_hex(sidecar["commit"].as_str().unwrap()).unwrap();
        let want = &sidecar["expect"];
        if name.starts_with("object_") || ["chunk", "blob_range", "in_chunk_range"].contains(&name)
        {
            let reference_reason = span::verify(&trusted, &bytes).unwrap_err();
            assert_eq!(reference_reason, "span_magic", "{name}");
            assert_eq!(
                verify_disclosure_span(&trusted, &bytes)
                    .unwrap_err()
                    .reason(),
                reference_reason,
                "{name}"
            );
            let disclosed = verify_disclosure(&trusted, &bytes).unwrap();
            assert_eq!(summary(&disclosed), want["disclosed"], "{name}");
        } else {
            let mut bytes = bytes;
            if let Some(n) = want["expand_to"].as_u64() {
                assert_eq!(n, (CAP + 1) as u64);
                bytes.resize(usize::try_from(n).unwrap(), 0);
            }
            let got = span::verify(&trusted, &bytes);
            let product = verify_disclosure_span(&trusted, &bytes);
            if want["accept"] == true {
                let verified_span = got.unwrap();
                let product_span = product.unwrap_or_else(|e| panic!("{name}: {e:?}"));
                assert_eq!(product_span.offset, verified_span.offset, "{name}");
                assert_eq!(product_span.bytes, verified_span.bytes, "{name}");
                assert_eq!(product_span.leaf_id, verified_span.leaf, "{name}");
                assert_eq!(
                    product_span.signature_valid, verified_span.signature_valid,
                    "{name}"
                );
                assert_eq!(
                    product_span
                        .path
                        .iter()
                        .map(|(n, _)| n.as_slice())
                        .collect::<Vec<_>>(),
                    verified_span
                        .path
                        .iter()
                        .map(Vec::as_slice)
                        .collect::<Vec<_>>(),
                    "{name}"
                );
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
                let expected_reason = want["reject_reason"].as_str().unwrap();
                assert_eq!(got.unwrap_err(), expected_reason, "{name}");
                assert_eq!(product.unwrap_err().reason(), expected_reason, "{name}");
            }
        }
    }
    assert!(count >= 40);
    tables::check(&dir);
}

fn chunk_boundaries(fixture: &common::Fixture) -> Vec<u64> {
    let Object::Tree(tree) = fixture.store.read_object(&fixture.tree_hash).unwrap() else {
        panic!("fixture root is not a tree")
    };
    let chunked_id = tree
        .entries
        .iter()
        .find(|entry| entry.name == b"chunked.bin")
        .unwrap()
        .object_hash;
    let Object::ChunkedBlob(manifest) = fixture.store.read_object(&chunked_id).unwrap() else {
        panic!("fixture file is not chunked")
    };
    let mut boundaries = vec![0u64];
    for id in manifest.chunks {
        let Object::Blob(blob) = fixture.store.read_object(&id).unwrap() else {
            panic!("fixture chunk is not a blob")
        };
        boundaries.push(boundaries.last().unwrap() + blob.data.len() as u64);
    }
    boundaries
}

#[test]
fn boundary_aware_builder_matches_committed_bytes() {
    let fixture = common::build_fixture();
    let boundaries = chunk_boundaries(&fixture);
    let starts = &boundaries;
    let cases = [
        ("span_two_chunks", starts[2] - 10, 20),
        ("span_first_zero", starts[1] - 10, 20),
        (
            "span_three_chunks",
            starts[1] - 10,
            starts[2] - starts[1] + 20,
        ),
        ("in_chunk_range", starts[1] + 32, 16),
    ];
    for (name, offset, len) in cases {
        for hints in [None, Some(boundaries.as_slice())] {
            let proof = build_range_proof_from(
                &fixture.store,
                &fixture.commit_id,
                &[b"chunked.bin"],
                offset,
                len,
                hints,
            )
            .unwrap();
            let bytes = match proof {
                RangeProof::Mkdp(bytes) | RangeProof::Mkds(bytes) => bytes,
            };
            assert_eq!(
                bytes,
                fs::read(directory().join(format!("{name}.bin"))).unwrap(),
                "{name} hints={}",
                hints.is_some()
            );
        }
    }
    let proof = build_range_proof_from(
        &fixture.store,
        &fixture.commit_id,
        &[b"range.bin"],
        32,
        16,
        None,
    )
    .unwrap();
    let RangeProof::Mkdp(bytes) = proof else {
        panic!("plain Blob must use MKDP")
    };
    assert_eq!(bytes, fs::read(directory().join("blob_range.bin")).unwrap());
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]
    #[test]
    fn mutated_spans_match_reference_reason(
        operation in 0u8..5,
        at in any::<usize>(),
        payload in proptest::collection::vec(any::<u8>(), 0..32),
    ) {
        let dir = directory();
        let trusted = mkit_core::hash::from_hex(
            serde_json::from_slice::<Value>(&fs::read(dir.join("span_two_chunks.json")).unwrap())
                .unwrap()["commit"].as_str().unwrap(),
        ).unwrap();
        let mut bytes = fs::read(dir.join("span_two_chunks.bin")).unwrap();
        let index = at % bytes.len();
        match operation {
            0 => bytes[index] ^= 1,
            1 => bytes.truncate(index),
            2 => {
                let next = (index + 1) % bytes.len();
                bytes.swap(index, next);
            }
            3 => {
                let length = payload.len().min(bytes.len() - index);
                let duplicated = bytes[index..index + length].to_vec();
                bytes.splice(index..index, duplicated);
            }
            _ => {
                let length = payload.len().min(bytes.len() - index);
                bytes.splice(index..index + length, payload);
            }
        }
        let reference = span::verify(&trusted, &bytes).map(|span| span.bytes);
        let product = verify_disclosure_span(&trusted, &bytes).map(|span| span.bytes);
        match (reference, product) {
            (Ok(expected), Ok(actual)) => prop_assert_eq!(actual, expected),
            (Err(expected), Err(actual)) => prop_assert_eq!(actual.reason(), expected),
            (left, right) => prop_assert!(false, "reference={left:?}, product={right:?}"),
        }
    }

}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]
    #[test]
    fn built_range_round_trips(offset_seed in any::<u32>(), len_seed in any::<u32>()) {
        static FIXTURE: OnceLock<common::Fixture> = OnceLock::new();
        let fixture = FIXTURE.get_or_init(common::build_fixture);
        let boundaries = chunk_boundaries(fixture);
        let total = *boundaries.last().unwrap();
        let offset = u64::from(offset_seed) % total;
        let len = 1 + u64::from(len_seed) % (total - offset);
        let proof = build_range_proof_from(
            &fixture.store,
            &fixture.commit_id,
            &[b"chunked.bin"],
            offset,
            len,
            Some(&boundaries),
        ).unwrap();
        let first = boundaries.partition_point(|&start| start <= offset) - 1;
        let last = boundaries.partition_point(|&start| start < offset + len) - 1;
        let actual = match proof {
            RangeProof::Mkdp(bytes) => {
                prop_assert_eq!(first, last);
                let disclosed = verify_disclosure(&fixture.commit_id, &bytes).unwrap();
                body(&disclosed).to_vec()
            }
            RangeProof::Mkds(bytes) => {
                prop_assert!(first < last);
                verify_disclosure_span(&fixture.commit_id, &bytes).unwrap().bytes
            }
        };
        let plaintext = common::prng_bytes(0x1234_5678_9abc_def0, 3 * 1024 * 1024);
        let begin = usize::try_from(offset).unwrap();
        let end = usize::try_from(offset + len).unwrap();
        prop_assert_eq!(actual.as_slice(), &plaintext[begin..end]);
    }
}
