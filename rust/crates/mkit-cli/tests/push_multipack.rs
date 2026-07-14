//! Multi-pack push integration tests (issue #831).
//!
//! `push_branch`/`push_branch_with_depth` build the whole push plan into a
//! single pack, hard-capped at `pack::MAX_TOTAL_PAYLOAD` (4 GiB in
//! production). A push whose plan exceeds that in one pack now splits
//! across multiple packs — sealed and uploaded as they fill — recorded
//! together on ONE packmap node (`PackListNode.packs: Vec<Hash>`, apply
//! order preserved) instead of failing with `PackfileTooLarge`.
//!
//! `push_branch_with_limits` (#547-style seam) takes an explicit
//! `pack_payload_cap` so these tests can force a split with a few KiB of
//! content instead of moving gigabytes through the harness.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

mod common;

use std::fs;
use std::path::Path;

use common::Repo;
use mkit_cli::remote_dispatch::{pull_all, push_all, push_branch_with_limits};
use mkit_core::hash::Hash;
use mkit_core::layout::RepoLayout;
use mkit_core::protocol::{PackKey, RefWriteCondition, Transport};
use mkit_core::refs;
use mkit_core::store::ObjectStore;
use mkit_core::transfer::{self, PackListNode};
use mkit_transport_memory::MemoryTransport;

/// Tiny cap that a handful of KiB-sized files reliably exceeds, forcing a
/// split without moving gigabytes through the test harness.
const TINY_PAYLOAD_CAP: u64 = 4096;

fn head_hash(dir: &Path) -> Hash {
    refs::read_ref(&RepoLayout::single(dir), "main")
        .unwrap()
        .unwrap()
}

/// Walk `<remote>`'s packlist chain for `branch` newest-first via the
/// public [`Transport`] verbs — the same way the push/fetch paths do, so
/// the test never assumes anything about a transport's on-disk layout.
/// Mirrors `pack_rebaseline.rs`'s helper of the same name.
fn packmap_chain(tx: &dyn Transport, branch: &str) -> Vec<PackListNode> {
    let mut nodes = Vec::new();
    let mut cursor = tx.read_ref(&format!("refs/mkit/packmap/{branch}")).unwrap();
    while let Some(key) = cursor {
        let bytes = tx.download_blob(&PackKey::from_hash(key)).unwrap();
        let node = transfer::decode_packlist(&bytes).unwrap();
        cursor = node.prev;
        nodes.push(node);
    }
    nodes
}

/// Deterministic, low-compressibility filler so a handful of small files
/// reliably sums to more than [`TINY_PAYLOAD_CAP`] on the wire — an LCG
/// byte stream, same construction pack.rs's own test helper uses.
fn filler(seed: u64, len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    let mut state = seed | 1;
    for chunk in buf.chunks_mut(8) {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        chunk.copy_from_slice(&state.to_le_bytes()[..chunk.len()]);
    }
    buf
}

#[test]
fn oversized_push_splits_into_one_node_with_multiple_packs_and_stays_fetchable() {
    let alice = Repo::new();
    let files: Vec<(String, Vec<u8>)> = (0..8)
        .map(|i| (format!("f{i}.bin"), filler(0xA11C_E000 + i, 2048)))
        .collect();
    for (name, body) in &files {
        alice.write(name, body);
    }
    alice.ok(&["add", "."]);
    alice.ok(&["commit", "-m", "eight incompressible files"]);
    let tip = head_hash(alice.path());

    let tx = MemoryTransport::new();
    let store = ObjectStore::open(&RepoLayout::single(alice.path())).unwrap();
    push_branch_with_limits(
        &tx,
        &store,
        "main",
        tip,
        RefWriteCondition::Missing,
        0, // no re-baselining — isolate the payload-split behavior
        TINY_PAYLOAD_CAP,
    )
    .expect("oversized push must split, not fail with PackfileTooLarge");

    let chain = packmap_chain(&tx, "main");
    assert_eq!(chain.len(), 1, "one push records exactly one packmap node");
    assert!(
        chain[0].packs.len() > 1,
        "8 * 2 KiB of incompressible content must exceed a {TINY_PAYLOAD_CAP}-byte cap and split, \
         got {} pack(s)",
        chain[0].packs.len()
    );

    // Every advertised pack must actually exist — no node references an
    // un-uploaded pack.
    for pack_key in &chain[0].packs {
        tx.download_pack(&PackKey::from_hash(*pack_key))
            .unwrap_or_else(|e| panic!("pack {pack_key:?} must be downloadable: {e}"));
    }

    assert_eq!(tx.read_ref("refs/heads/main").unwrap(), Some(tip));

    // Fetch-side zero-change confirmation: a fresh clone reconstructs the
    // branch and every file byte-for-byte, with no changes to the
    // multi-pack-aware `packmap.rs::resolve_pack_chain` (it already
    // `flat_map`s every node's `packs`).
    let carol = Repo::new();
    pull_all(carol.path(), &tx, "default", None).expect("clone from a multi-pack node");
    assert_eq!(head_hash(carol.path()), tip);
    for (name, body) in &files {
        assert_eq!(
            fs::read(carol.path().join(name)).unwrap(),
            *body,
            "{name} must round-trip byte-identical through a multi-pack push"
        );
    }
}

#[test]
fn normal_push_still_produces_exactly_one_pack() {
    // Regression: a push whose plan fits comfortably in one pack — the
    // overwhelming common case — must be completely unaffected by the
    // multi-pack machinery.
    let alice = Repo::new();
    alice.commit_file("small.txt", b"just one small file", "small commit");
    let tip = head_hash(alice.path());

    let tx = MemoryTransport::new();
    push_all(alice.path(), &tx).expect("normal push");

    assert_eq!(tx.read_ref("refs/heads/main").unwrap(), Some(tip));
    let chain = packmap_chain(&tx, "main");
    assert_eq!(chain.len(), 1);
    assert_eq!(
        chain[0].packs.len(),
        1,
        "a plan well under the payload cap must still produce exactly one pack"
    );
}
