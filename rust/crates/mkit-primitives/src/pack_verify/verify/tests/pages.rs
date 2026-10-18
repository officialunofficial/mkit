//! Evidence-page emission, live-page accounting, and host round-trip cost.
//!
//! Figures quoted in comments were measured on the write-through driver that
//! flushed every sequence after every entry and handed the host every
//! copy-on-write page.
use super::*;
use crate::{
    codec::Budget,
    evidence::{
        checkpoint::{CheckpointState, IndexCheckpoint},
        pages::{BranchChild, EncodedPage, LeafRecord, encode_internal, encode_leaf},
    },
};
use std::collections::{BTreeMap as Map, BTreeSet as Set};

/// Host-visible page traffic for one run to completion.
#[derive(Debug, Default, Clone, Copy)]
struct Traffic {
    emitted: u64,
    released: u64,
    fetches: u64,
    /// Pages reachable from the final roots.
    reachable: u64,
    /// Pages the host still holds: emitted and not released.
    held: u64,
}

impl Traffic {
    /// Page-related host interactions: retentions, fetches, and releases.
    fn round_trips(&self) -> u64 {
        self.emitted + self.fetches + self.released
    }
}

fn start(pack: &[u8], limits: VerifyLimits) -> VerifyDriver {
    VerifyDriver::new(source(pack), REPOSITORY, profile(), limits, 17).unwrap()
}

fn ephemeral(pack: &[u8], limits: VerifyLimits) -> VerifyDriver {
    VerifyDriver::new_with_retention(
        source(pack),
        REPOSITORY,
        profile(),
        limits,
        17,
        PageRetention::Ephemeral,
    )
    .unwrap()
}

fn serve_bytes(pack: &[u8], machine: &mut VerifyDriver, request: &Request) {
    let Request::Bytes {
        request,
        source,
        range,
    } = request
    else {
        panic!("unexpected request {request:?}");
    };
    assert!(matches!(source, ByteSource::Pack(_)));
    let start = usize::try_from(range.offset).unwrap();
    let end = usize::try_from(range.offset + range.len).unwrap();
    machine
        .supply(Response::Bytes {
            request: *request,
            source: *source,
            range: *range,
            value: Acquisition::Present(&pack[start..end]),
        })
        .unwrap();
}

fn evidence_limits(limits: VerifyLimits) -> EvidenceLimits {
    EvidenceLimits {
        page_bytes: limits.page_bytes,
        allocated_bytes: limits.page_bytes,
        ..EvidenceLimits::indexed()
    }
}

type Roots = [(PageKind, PageCommitment, u64); 6];

/// Digests of every page reachable from the six roots, by authenticated walk.
fn reachable_digests(
    binding: EvidenceBinding,
    limits: VerifyLimits,
    roots: &Roots,
    pages: &Map<Hash, Vec<u8>>,
) -> Set<Hash> {
    let mut seen = Set::new();
    for &(kind, root, count) in roots {
        let mut index = Index::resume(kind, binding, evidence_limits(limits), root, count).unwrap();
        let mut op = index.audit();
        loop {
            match index.poll(&mut op).unwrap() {
                Event::Page(want) => {
                    seen.insert(want.digest);
                    let bytes = pages
                        .get(&want.digest)
                        .expect("a page reachable from the roots is held");
                    let mut budget = Budget::new(u64::MAX, u64::MAX);
                    index.feed(&mut op, bytes, &mut budget).unwrap();
                }
                Event::Done { .. } => break,
                _ => panic!("audit emitted an unexpected event"),
            }
        }
    }
    seen
}

fn driver_roots(machine: &VerifyDriver) -> Roots {
    [
        (
            PageKind::Objects,
            machine.objects.commitment(),
            machine.objects.count(),
        ),
        (
            PageKind::Objects,
            machine.referenced.commitment(),
            machine.referenced.count(),
        ),
        (
            PageKind::Ordinals,
            machine.ordinals.commitment(),
            machine.ordinals.committed(),
        ),
        (
            PageKind::Occurrences,
            machine.occurrences.commitment(),
            machine.occurrences.committed(),
        ),
        (
            PageKind::Dependencies,
            machine.dependencies.commitment(),
            machine.dependencies.committed(),
        ),
        (
            PageKind::Heads,
            machine.heads.commitment(),
            machine.heads.committed(),
        ),
    ]
}

fn checkpoint_roots(state: &CheckpointState) -> Roots {
    let verify = state.verify.expect("verify checkpoint");
    let of = |kind: PageKind, index: IndexCheckpoint| (kind, index.commitment, index.count);
    [
        of(PageKind::Objects, verify.objects),
        of(PageKind::Objects, verify.referenced),
        of(PageKind::Ordinals, verify.ordinals),
        of(PageKind::Occurrences, verify.occurrences),
        of(PageKind::Dependencies, verify.dependencies),
        of(PageKind::Heads, verify.heads),
    ]
}

fn page_map(host: &Host) -> Map<Hash, Vec<u8>> {
    host.pages
        .iter()
        .map(|(commitment, bytes)| (commitment.digest, bytes.clone()))
        .collect()
}

/// Serves a run to completion the way a careful host does: retained pages are
/// stored, released pages are deleted at once, and a deleted page that is
/// requested again is gone for good.
fn drive(pack: &[u8], machine: &mut VerifyDriver) -> (Traffic, VerifiedPack) {
    let mut pages: Map<Hash, Vec<u8>> = Map::new();
    let mut traffic = Traffic::default();
    let verified = loop {
        match machine.step().unwrap() {
            Step::Request(Request::EvidencePage { request, page }) => {
                traffic.fetches += 1;
                let value = pages
                    .get(&page.digest)
                    .map_or(Acquisition::Unavailable, |bytes| {
                        Acquisition::Present(bytes.as_slice())
                    });
                machine
                    .supply(Response::EvidencePage {
                        request,
                        page,
                        value,
                    })
                    .unwrap();
            }
            Step::Request(request) => serve_bytes(pack, machine, &request),
            Step::ProvisionalObject(_) | Step::Progress => (),
            Step::RetainEvidence(page) => {
                traffic.emitted += 1;
                let commitment = page.commitment;
                pages.insert(commitment.digest, page.bytes.to_vec());
                machine.acknowledge_retention(commitment).unwrap();
            }
            Step::ReleasePage(page) => {
                traffic.released += 1;
                assert!(
                    pages.remove(&page.digest).is_some(),
                    "released a page the host does not hold"
                );
            }
            Step::Complete(verified) => break verified,
        }
    };
    traffic.held = pages.len() as u64;
    if machine.retention == PageRetention::Durable {
        // An ephemeral run leaves its final pages in the cache, not with the host.
        let binding = VerifyDriver::binding(machine.source, machine.repository);
        traffic.reachable =
            reachable_digests(binding, machine.limits, &driver_roots(machine), &pages).len() as u64;
    }
    (traffic, verified)
}

fn raw_blobs(count: usize, size: usize) -> Vec<u8> {
    let mut writer = PackWriter::new_raw_only();
    for index in 0..count {
        let mut data = vec![0_u8; size.max(8)];
        data[..8].copy_from_slice(&(index as u64).to_le_bytes());
        let (id, bytes) = blob(&data);
        writer.push_raw(id, &bytes).unwrap();
    }
    writer.finish().unwrap()
}

/// Blob plus single-entry tree pairs, giving edges and referenced-index work.
fn blob_tree_pairs(pairs: usize) -> Vec<u8> {
    let mut writer = PackWriter::new_raw_only();
    for index in 0..pairs {
        let (blob_id, bytes) = blob(&(index as u64).to_le_bytes());
        writer.push_raw(blob_id, &bytes).unwrap();
        let (tree_id, bytes) = tree(b"file", EntryMode::Blob, blob_id);
        writer.push_raw(tree_id, &bytes).unwrap();
    }
    writer.finish().unwrap()
}

fn wide_tree_pack(entries: usize) -> Vec<u8> {
    let (child_id, child) = blob(b"child");
    let entries: Vec<TreeEntry> = (0..entries)
        .map(|n| TreeEntry {
            name: format!("entry-{n:04}").into_bytes(),
            mode: EntryMode::Blob,
            object_hash: child_id,
        })
        .collect();
    let (tree_id, tree) = canonical(&Object::Tree(Tree { entries }));
    let mut writer = PackWriter::new_raw_only();
    writer.push_raw(child_id, &child).unwrap();
    writer.push_raw(tree_id, &tree).unwrap();
    writer.finish().unwrap()
}

/// One shared child and `trees` distinct trees of `entries` edges each, so
/// every tree entry appends a batch of dependency records.
fn many_wide_trees(trees: usize, entries: usize) -> Vec<u8> {
    let (child_id, child) = blob(b"child");
    let mut writer = PackWriter::new_raw_only();
    writer.push_raw(child_id, &child).unwrap();
    for tree_index in 0..trees {
        let entries: Vec<TreeEntry> = (0..entries)
            .map(|n| TreeEntry {
                name: format!("t{tree_index:03}-e{n:03}").into_bytes(),
                mode: EntryMode::Blob,
                object_hash: child_id,
            })
            .collect();
        let (tree_id, tree) = canonical(&Object::Tree(Tree { entries }));
        writer.push_raw(tree_id, &tree).unwrap();
    }
    writer.finish().unwrap()
}

fn duplicate_pack() -> Vec<u8> {
    let mut writer = PackWriter::new_raw_only();
    for round in 0..3 {
        for index in 0..40_u64 {
            let (id, bytes) = blob(&(index + round % 2).to_le_bytes());
            writer.push_raw(id, &bytes).unwrap();
        }
    }
    writer.finish().unwrap()
}

/// A cache that holds one 4 KiB page, so nearly every lookup misses.
fn tiny_cache() -> VerifyLimits {
    VerifyLimits {
        page_bytes: 4096,
        resident_pages: 1,
        ..limits()
    }
}

fn report(name: &str, traffic: Traffic) {
    println!(
        "pages {name}: emitted={} released={} held={} reachable={} fetches={} round_trips={}",
        traffic.emitted,
        traffic.released,
        traffic.held,
        traffic.reachable,
        traffic.fetches,
        traffic.round_trips()
    );
}

/// Roots of the five evidence trees, hex.
fn roots_of(verified: &VerifiedPack) -> [String; 5] {
    [
        verified.object_set_root(),
        verified.occurrences().root,
        verified.dependencies().root,
        verified.ordinals().root,
        verified.head_facts().root,
    ]
    .map(|root| hash::to_hex(&root))
}

#[test]
fn single_entry_pack_costs_the_host_only_its_final_pages() {
    // Write-through: 10 pages emitted, 9 held, 6 reachable, 7 fetches.
    let pack = raw_blobs(1, 64);
    let (traffic, _) = drive(&pack, &mut start(&pack, limits()));
    report("1-entry", traffic);
    assert_eq!(
        (traffic.emitted, traffic.held, traffic.reachable),
        (6, 6, 6)
    );
    assert_eq!((traffic.fetches, traffic.released), (0, 0));
}

#[test]
fn twenty_four_entry_pack_costs_the_host_only_its_final_pages() {
    // Write-through: 106 emitted, 105 held, 14 reachable, 154 fetches.
    let pack = raw_blobs(24, 8192);
    let (traffic, _) = drive(&pack, &mut start(&pack, limits()));
    report("24-entry", traffic);
    assert_eq!(traffic.emitted, traffic.reachable);
    assert_eq!(traffic.held, traffic.reachable);
    assert_eq!((traffic.fetches, traffic.released), (0, 0));
}

#[test]
fn ninety_six_blob_pack_costs_the_host_only_its_final_pages() {
    // Write-through: 552 emitted, 551 held, 32 reachable, 658 fetches.
    let pack = raw_blobs(96, 768 << 10);
    let limits = VerifyLimits {
        acquisition_bytes: 16 << 20,
        resident_bytes: 48 << 20,
        ..limits()
    };
    let (traffic, verified) = drive(&pack, &mut start(&pack, limits));
    report("96-blob", traffic);
    assert_eq!(verified.counts().objects, 96);
    assert_eq!(traffic.emitted, traffic.reachable);
    assert_eq!(traffic.held, traffic.reachable);
    assert_eq!((traffic.fetches, traffic.released), (0, 0));
}

#[test]
fn ordinal_leaf_reuse_changes_neither_work_nor_residency_nor_roots() {
    // Several ordinal leaves, a cache small enough to evict, and a tight
    // resident ceiling: each lookup the kept leaf serves must charge what a
    // descent would, and the reservation must be fully returned.
    let pack = raw_blobs(200, 300);
    let outcome = |disabled: bool| {
        super::super::NO_ORDINAL_LEAF.with(|flag| flag.set(disabled));
        let mut machine = start(&pack, tiny_cache());
        let (_, verified) = drive(&pack, &mut machine);
        super::super::NO_ORDINAL_LEAF.with(|flag| flag.set(false));
        let usage = machine.usage();
        (usage.work, usage.resident_bytes, roots_of(&verified))
    };
    assert_eq!(outcome(false), outcome(true));
}

#[test]
fn live_page_cap_counts_held_pages_not_every_page_ever_produced() {
    // Write-through emitted about 7 pages per object here, so this pack
    // exceeded a cap that its held pages now fit under easily.
    let pack = blob_tree_pairs(1_500);
    let capped = VerifyLimits {
        evidence_pages: 1_200,
        ..tiny_cache()
    };
    let mut machine = start(&pack, capped);
    let (traffic, verified) = drive(&pack, &mut machine);
    report("3000-object tiny cache", traffic);
    assert_eq!(verified.counts().objects, 3_000);
    assert!(
        traffic.emitted > capped.evidence_pages,
        "cap was never tested"
    );
    assert!(traffic.released > 0);
    assert!(traffic.held <= capped.evidence_pages);
    assert_eq!(traffic.held, traffic.reachable);
    assert_eq!(machine.usage().evidence_pages, traffic.held);
}

#[test]
fn ephemeral_run_costs_a_pack_that_fits_the_cache_no_pages() {
    let pack = raw_blobs(24, 8192);
    let (_, expected) = drive(&pack, &mut start(&pack, limits()));
    let mut machine = ephemeral(&pack, limits());
    let (traffic, verified) = drive(&pack, &mut machine);
    assert_eq!(
        (traffic.emitted, traffic.released, traffic.fetches),
        (0, 0, 0)
    );
    assert_eq!(roots_of(&verified), roots_of(&expected));
    assert_eq!(machine.usage().evidence_pages, 0);
}

#[test]
fn ephemeral_run_refuses_checkpoints_and_still_completes_under_eviction() {
    let pack = blob_tree_pairs(200);
    let (_, expected) = drive(&pack, &mut start(&pack, limits()));
    let mut machine = ephemeral(&pack, tiny_cache());
    assert_eq!(
        machine.checkpoint().unwrap_err().code,
        FailureCode::UnsupportedCapability
    );
    let (traffic, verified) = drive(&pack, &mut machine);
    assert!(traffic.emitted > 0, "eviction must hand pages to the host");
    assert_eq!(roots_of(&verified), roots_of(&expected));
    assert_eq!(
        machine.checkpoint().unwrap_err().code,
        FailureCode::UnsupportedCapability
    );
}

#[test]
fn roots_are_independent_of_cache_size_retention_and_flush_timing() {
    for pack in [
        raw_blobs(300, 40),
        blob_tree_pairs(100),
        wide_tree_pack(25),
        wide_tree_pack(400),
        duplicate_pack(),
    ] {
        let (_, expected) = drive(&pack, &mut start(&pack, limits()));
        let expected = roots_of(&expected);
        let (_, small) = drive(&pack, &mut start(&pack, tiny_cache()));
        assert_eq!(roots_of(&small), expected, "tiny cache");
        let (_, verified) = drive(&pack, &mut ephemeral(&pack, limits()));
        assert_eq!(roots_of(&verified), expected, "ephemeral");
        // A checkpoint flushes buffered records at an arbitrary boundary; the
        // resumed run must still land on the same roots.
        let mut host = Host::new(&pack);
        let mut machine = start(&pack, tiny_cache());
        let mut restarts = 0;
        let mut restarted_at = u64::MAX;
        let verified = loop {
            match machine.step().unwrap() {
                Step::Request(request) => host.serve(&mut machine, &request).unwrap(),
                Step::ProvisionalObject(fragment) => host
                    .fragments
                    .entry(fragment.ordinal)
                    .or_default()
                    .extend_from_slice(fragment.bytes),
                Step::RetainEvidence(page) => {
                    let commitment = page.commitment;
                    host.pages.push((commitment, page.bytes.to_vec()));
                    machine.acknowledge_retention(commitment).unwrap();
                }
                Step::ReleasePage(page) => host.pages.retain(|(held, _)| *held != page),
                Step::Progress => (),
                Step::Complete(verified) => break verified,
            }
            let ordinal = machine.ordinal;
            if machine.work.is_none()
                && ordinal % 37 == 36
                && ordinal != restarted_at
                && let Ok(snapshot) = machine.checkpoint()
            {
                restarted_at = ordinal;
                let checkpoint = Checkpoint::from_bytes(snapshot.bytes(), tiny_cache()).unwrap();
                machine = VerifyDriver::resume(
                    source(&pack),
                    REPOSITORY,
                    profile(),
                    tiny_cache(),
                    18 + restarts,
                    &checkpoint,
                )
                .unwrap();
                restarts += 1;
            }
        };
        assert_eq!(roots_of(&verified), expected, "checkpoint restarts");
    }
}

/// Recorded on the previous write-through driver. Object, occurrence,
/// ordinal, and head roots are unchanged. The dependency root changes
/// wherever one entry's dependency records cross a leaf boundary
/// (`wide-tree-20`, `wide-tree-25`, `wide-tree-400`, `trees-30x3`,
/// `trees-40x5`): those flushes used to split a leaf evenly or graft two
/// leaves at once, while the tree now grows one leaf at a time, exactly as if
/// the records were appended singly. Entries whose records never cross a
/// boundary (`trees-30x2`, single-edge trees) keep their root.
#[test]
#[allow(clippy::too_many_lines)] // a table of recorded digests
fn roots_match_the_write_through_driver() {
    let cases: [(&str, Vec<u8>, [&str; 5]); 11] = [
        (
            "blobs-24",
            raw_blobs(24, 8192),
            [
                "efc132873e70c52114f506b9a75fca577293e761fff920e7b52b1c8210856715",
                "3664e69038507aaf4a9c02e28a668f257c812a16477cdf1fa1f15eef3314afa3",
                "ed485c73709c40752327c0cd9990fdeba9d2f517760e6cad8a56cc4b7c560819",
                "ac7f8a495d2bc750407bcdf0c8b13d32c058e3336e5d049c1de4669ebbef9e45",
                "1027ac26eeed8b766d2eac6aa07ec5db973bb722336ab00590220d6ab08fc1d8",
            ],
        ),
        (
            "blobs-300",
            raw_blobs(300, 40),
            [
                "7d4cf46b3643b73e8d6e9fe8dcfc2034638005c9c7b6723734f95c5fb58a20ee",
                "b3a9b9b22c847cc02afefcaf729b2a36a41efc67359e384daa94f75f67b1c4ce",
                "bc959a123614515ce24f44df2ec53c436ee8ed0eeae7c6e9edba5e9971b3da99",
                "3401e9a1f71ca03007b5d7c5e2a332ffae6b03e24281828ef3b0b7fd11684d45",
                "8050994ae0acc2b4007f68f40a33896c86b328cd27be5ffb792217d0cc65feb1",
            ],
        ),
        (
            "pairs-100",
            blob_tree_pairs(100),
            [
                "d7bfeaf14ab1bc8397a5de7f452e56ea0dd947137cf908a49ec5d46caf6c4f3e",
                "5ce5b291168e2e3efedfb3a3c29196cc1d95aa67a04b144d1c7b3a14a3112ba6",
                "706e97a557a14fa7b2ef765d82958bb2628d6b379f899171c2074cc8ad3698f3",
                "2462f75ea4ac282441bf0e8f6f4c4398fff68e0680ec4c58e89028216b52eb02",
                "c2dc96e5bc70ff414d975b200fdc25a5a0cc563f853a61f9768eba1de6cc2713",
            ],
        ),
        (
            "wide-tree-20",
            wide_tree_pack(20),
            [
                "fa5c3f0e9db174bfa655f6c11fc4e30fbca192ff74dd7187aadfbe26bbc68c52",
                "d73dfb446f03db2153daf8e2a9efc7cd5267ff8e594a032e384f5a6c30477cee",
                // Write-through: 9673d795bfbcbdf18fbb71c0a3f6602f2219f8d813e27f51a489d8403c557803.
                "85ca815ded18a9f0af1fab98ab562f341ea31447c6e42be39ec36195109340d1",
                "0ee3e094883d98dcd8568742918f13ac0fc349b46730373330fae63c90c00dc1",
                "9ac31fdfd375ef7111e40250e67383ea9f82c2d102f78161de996316a50fd8a7",
            ],
        ),
        (
            "wide-tree-25",
            wide_tree_pack(25),
            [
                "0b46ef3d3bf73c756df546bffdb548590093c9fcb28372b3e60c36fbde0115af",
                "fb5d28c007dcb65b214ef2da3f4f25b9e743616000c83c363aabb2919da4af5e",
                // Write-through: cbf92ea13527ae4b1da10e1a69d8b6eed9234bb24e56e456436a60f30f2d20e3.
                "50fd14a54e5844cdc20e1f8a57a1fe84f0e5b23e9773015d48494b35dec96fb3",
                "fa3a7c0e58b9459c6f721aba8efcc98297dba2fbdfc8035c755bd43b5cefdc3d",
                "4967e30c8f393c2eedc3d296b767b4c00dddab82013bcb3282d7de3b0654a6be",
            ],
        ),
        (
            "wide-tree-40",
            wide_tree_pack(40),
            [
                "40aa1233f4eb25fa4a4f0f6e9a2b693967c5c72b132c0bc5d28a9cc2d06463eb",
                "73e17cc8b23f1a8a3e6b38d627a2fb8694033b91ef5d579249382e0994c39c07",
                "72d9fc188de82b68c5d7a2064ff6d1f49a2a81f087eae114c3a436e8125167fd",
                "ffbec06569b8627993191d3ef0143271ee222bed77ca6713477493994da53ca6",
                "6c37dbedf924f2f2f83238f8f282c2e9e3d3b83e96536c96b1a58ab61f5155d1",
            ],
        ),
        (
            "wide-tree-400",
            wide_tree_pack(400),
            [
                "c902f6571d9c4d7f35e150d99a12757c7ef0daf2f87aa8ec1dc43fa038ea2f66",
                "f13035dfbd6d22bec018d0634c5c156c9f90d7451c67419693a0fb120b8143fd",
                // Write-through: cb5b773ef0fe4c5bf19d255dd016787017914fd02ea1309d9dea673db9649ca3.
                "371024c7a819bc6a7554e74c56329bcf4ff2ced77dc9258aa341aab595911d59",
                "e2d038a43f5cf494b6bd6e89da3dbea9e9b93e8ee92980fea10f32b2ca1851d8",
                "7917f8100fe78b488a0b125f5086f02bb354f87e7c3dc562dcd7384872ca0d63",
            ],
        ),
        (
            "trees-30x2",
            many_wide_trees(30, 2),
            [
                "28a73205dda5520ae91069da05d415d26dd43aa7e55e7d22f02a530f11a68a38",
                "c394c17bcd3ffe387493c2a07629b061d938e3535a61ae81d5e8b367c1453d6d",
                "39c31ccd9a12dc659e9f2fcd66ca1becca09477286b3aa203ae79fa08c0ea49b",
                "dccbe945490a586032ade3fb2b523727a1764677af62f34abfdacfe1924563ea",
                "699709c82baeba829abd49b550526ad03528de91df769d6eb18b0da49cc8d100",
            ],
        ),
        (
            "trees-30x3",
            many_wide_trees(30, 3),
            [
                "27580cbe70242634d08bde4caab9abcd66566c492d7318c47238efe42ec2c00b",
                "fa9ab118f389d387af547156340461af79213e606c43d9c41d972bccb48a148d",
                // Write-through: 79ad6b0aaa05f0c805ae7f852683bf1747c0e5b8e508493d64e43cdf2845d0df.
                "5e7a9ac947b5fada0a56d5eeeebfb1e0c4de9e011bd78b8a66b75d3f0c5357c2",
                "1e7d8ffa121a3c725847850fbed3a87b614ac2b75ba2766b2e7e132f3fd26284",
                "4bfebe9331d44baafc723f7388582b58ac81bed9bb807582160fadec7a45df47",
            ],
        ),
        (
            "trees-40x5",
            many_wide_trees(40, 5),
            [
                "b56795459c188617925d6e87b87fafadef306c48160c0aba690b81cb8d194c96",
                "8ba491b8e60264c00f2753e3dc0d65e1841c244333c143787f0d38becd066804",
                // Write-through: ee53fc55af92a6f576d9d4edc36eacaf738a36cc3f3730d01724ab8e1e3d64d7.
                "4b2a8afe3697b27cbb918025ec45e48920e828f0c07fe2ce4a90f59b5ceace8f",
                "28b3e247644887334c758be20e24c991ee1825787d09559335a77afd01019a32",
                "793ee0c038ce83626fad7b0216fb6dfafc1bcc55a4de842157155e9288044ae9",
            ],
        ),
        (
            "duplicates",
            duplicate_pack(),
            [
                "b16014cdeabf0e3531db2a5f58417ca057d0c64a75e4fd73b4018c3cfcf07225",
                "f9a94d50f57a0930993f10e1b4d84d0803f564eef2dffb0016abf1e919247606",
                "7599ed606272919d0a1880694e9f82cda6f82bb3ad466c978c7dab67d290be86",
                "f22cedb7bbb1045a683daab446eaacdb92ef07b6172c664539ac8970e6bca10e",
                "faedcbbdcbb0a4e9a1952bb0e3990300dd6735ef581265d405fd663028a928b5",
            ],
        ),
    ];
    for (name, pack, expected) in cases {
        let (_, verified) = drive(&pack, &mut start(&pack, limits()));
        assert_eq!(roots_of(&verified), expected, "{name}");
    }
}

/// Drives `machine` until `done` holds after a step, applying every release.
fn pump(
    machine: &mut VerifyDriver,
    host: &mut Host,
    released: &mut u64,
    mut done: impl FnMut(&VerifyDriver) -> bool,
) -> Option<VerifiedPack> {
    loop {
        match machine.step().unwrap() {
            Step::Request(request) => host.serve(machine, &request).unwrap(),
            Step::ProvisionalObject(fragment) => host
                .fragments
                .entry(fragment.ordinal)
                .or_default()
                .extend_from_slice(fragment.bytes),
            Step::RetainEvidence(page) => {
                let commitment = page.commitment;
                host.pages.push((commitment, page.bytes.to_vec()));
                machine.acknowledge_retention(commitment).unwrap();
            }
            Step::ReleasePage(page) => {
                *released += 1;
                let before = host.pages.len();
                host.pages.retain(|(held, _)| *held != page);
                assert_eq!(before, host.pages.len() + 1, "released an unheld page");
            }
            Step::Progress => (),
            Step::Complete(verified) => return Some(verified),
        }
        if done(machine) {
            return None;
        }
    }
}

/// Runs until the first drained boundary at or after `ordinal`.
fn run_to_boundary(machine: &mut VerifyDriver, host: &mut Host, released: &mut u64, ordinal: u64) {
    let finished = pump(machine, host, released, |m| {
        m.ordinal >= ordinal && m.work.is_none()
    });
    assert!(finished.is_none(), "run ended before ordinal {ordinal}");
}

fn crash_and_resume(
    pack: &[u8],
    host: &Host,
    checkpoint: &Checkpoint,
    generation: u64,
) -> VerifiedPack {
    let mut machine = VerifyDriver::resume(
        source(pack),
        REPOSITORY,
        profile(),
        tiny_cache(),
        generation,
        checkpoint,
    )
    .unwrap();
    let mut restarted = Host::new(pack);
    restarted.pages.clone_from(&host.pages);
    restarted.finish(&mut machine).unwrap()
}

#[test]
fn pages_a_checkpoint_reaches_survive_until_the_next_checkpoint_exists() {
    let pack = blob_tree_pairs(120);
    let limits = tiny_cache();
    let (_, expected) = drive(&pack, &mut start(&pack, limits));
    let binding = VerifyDriver::binding(source(&pack), REPOSITORY);
    let mut host = Host::new(&pack);
    let mut machine = start(&pack, limits);
    let mut released = 0;

    // First checkpoint, early in the run.
    run_to_boundary(&mut machine, &mut host, &mut released, 20);
    let first = boundary_checkpoint(&mut machine, &mut host);
    let first_state = first.decode(limits).unwrap();
    let first_reach = reachable_digests(
        binding,
        limits,
        &checkpoint_roots(&first_state),
        &page_map(&host),
    );
    let after_first = released;

    // Keep running. The driver releases pages that only this run produced and
    // superseded, but never one the first checkpoint reaches.
    run_to_boundary(&mut machine, &mut host, &mut released, 150);
    assert!(released > after_first, "the run released nothing: vacuous");
    let held: Set<Hash> = page_map(&host).into_keys().collect();
    assert!(
        first_reach.is_subset(&held),
        "a page the first checkpoint reaches was released early"
    );
    // A crash now restarts from the first checkpoint over the current store.
    let verified = crash_and_resume(&pack, &host, &first, 30);
    assert_eq!(roots_of(&verified), roots_of(&expected));

    // The second checkpoint obsoletes the first: its exclusive pages go now.
    let before_second = released;
    let second = boundary_checkpoint(&mut machine, &mut host);
    let second_state = second.decode(limits).unwrap();
    let second_reach = reachable_digests(
        binding,
        limits,
        &checkpoint_roots(&second_state),
        &page_map(&host),
    );
    run_to_boundary(&mut machine, &mut host, &mut released, 200);
    assert!(
        released > before_second,
        "the first checkpoint's pages were never released"
    );
    let held: Set<Hash> = page_map(&host).into_keys().collect();
    assert!(second_reach.is_subset(&held));
    // Pages only the first checkpoint reached are gone now.
    let exclusive: Vec<_> = first_reach.difference(&second_reach).collect();
    assert!(
        !exclusive.is_empty(),
        "nothing was exclusive to the first checkpoint"
    );
    assert!(exclusive.iter().all(|digest| !held.contains(*digest)));
    let verified = crash_and_resume(&pack, &host, &second, 31);
    assert_eq!(roots_of(&verified), roots_of(&expected));
    let finished = pump(&mut machine, &mut host, &mut released, |_| false).unwrap();
    assert_eq!(roots_of(&finished), roots_of(&expected));
}

#[test]
fn dependency_root_is_independent_of_how_flushes_batch_the_stream() {
    // 30 entries of 30 edges each: batches of 17 or more land on leaf and
    // parent boundaries all along a sequence with more than 50 leaves.
    let pack = many_wide_trees(30, 30);
    let (_, expected) = drive(&pack, &mut start(&pack, limits()));
    assert_eq!(expected.dependencies().count, 900);
    let expected = roots_of(&expected);
    let (_, tiny) = drive(&pack, &mut start(&pack, tiny_cache()));
    assert_eq!(roots_of(&tiny), expected, "tiny cache");
    // A checkpoint at every entry boundary flushes after every entry, which
    // is how the earlier write-through driver batched.
    let mut host = Host::new(&pack);
    let mut machine = start(&pack, limits());
    let mut released = 0;
    for ordinal in 1..=31 {
        run_to_boundary(&mut machine, &mut host, &mut released, ordinal);
        let _ = boundary_checkpoint(&mut machine, &mut host);
    }
    let verified = pump(&mut machine, &mut host, &mut released, |_| false).unwrap();
    assert_eq!(
        roots_of(&verified),
        expected,
        "checkpoint at every boundary"
    );
    // Flushing every third entry batches differently again.
    let mut host = Host::new(&pack);
    let mut machine = start(&pack, limits());
    for ordinal in (3..=30).step_by(3) {
        run_to_boundary(&mut machine, &mut host, &mut released, ordinal);
        let _ = boundary_checkpoint(&mut machine, &mut host);
    }
    let verified = pump(&mut machine, &mut host, &mut released, |_| false).unwrap();
    assert_eq!(
        roots_of(&verified),
        expected,
        "checkpoint every third entry"
    );
}

#[test]
fn a_ready_checkpoint_covers_every_buffered_record_and_page() {
    let pack = blob_tree_pairs(30);
    let mut host = Host::new(&pack);
    let mut machine = start(&pack, limits());
    let mut released = 0;
    run_to_boundary(&mut machine, &mut host, &mut released, 7);
    // Unflushed records exist before the request, none after it.
    let buffered = machine.occurrences.pending() + machine.ordinals.pending();
    assert!(buffered > 0, "nothing was buffered: vacuous");
    let checkpoint = boundary_checkpoint(&mut machine, &mut host);
    assert_eq!(machine.occurrences.pending(), 0);
    assert_eq!(machine.ordinals.pending(), 0);
    assert_eq!(machine.dependencies.pending(), 0);
    let state = checkpoint.decode(limits()).unwrap();
    let verify = state.verify.unwrap();
    assert_eq!(verify.occurrences.count, state.meta.ordinal);
    let binding = VerifyDriver::binding(source(&pack), REPOSITORY);
    // The walk panics if the host lacks any page the roots reach.
    let reach = reachable_digests(
        binding,
        limits(),
        &checkpoint_roots(&state),
        &page_map(&host),
    );
    assert_eq!(
        reach.len() as u64,
        state.meta.usage.evidence_pages,
        "the host holds exactly the pages the checkpoint reaches"
    );
    // The call consumed readiness; a second call must arm and wait again.
    assert_eq!(
        machine.checkpoint().unwrap_err().code,
        FailureCode::CheckpointNotReady
    );
}

#[test]
fn checkpoint_readiness_lasts_only_until_the_next_mutating_call() {
    let pack = raw_blobs(8, 64);
    let mut host = Host::new(&pack);
    let mut machine = start(&pack, limits());
    let mut released = 0;
    run_to_boundary(&mut machine, &mut host, &mut released, 3);
    assert_eq!(
        machine.checkpoint().unwrap_err().code,
        FailureCode::CheckpointNotReady
    );
    // Step until the driver reports readiness, then let one more call pass.
    loop {
        match machine.step().unwrap() {
            Step::RetainEvidence(page) => {
                let commitment = page.commitment;
                host.pages.push((commitment, page.bytes.to_vec()));
                machine.acknowledge_retention(commitment).unwrap();
            }
            Step::Progress | Step::ReleasePage(_) => (),
            other => panic!("unexpected {other:?}"),
        }
        if machine.checkpoint_ready {
            break;
        }
    }
    let _ = machine.step().unwrap();
    assert_eq!(
        machine.checkpoint().unwrap_err().code,
        FailureCode::CheckpointNotReady
    );
}

#[test]
fn decoded_byte_budget_is_an_execution_limit_and_the_profile_a_content_limit() {
    let pack = raw_blobs(4, 1000);
    for (profile_bytes, budget_bytes, expected) in [
        (100, 4 << 30, FailureCode::PackfileTooLarge),
        (4 << 30, 100, FailureCode::ResourceLimit),
        (100, 100, FailureCode::PackfileTooLarge),
    ] {
        let execution = VerifyLimits {
            decoded_bytes: budget_bytes,
            ..limits()
        };
        let profile = IndexedProfile {
            decoded_bytes: profile_bytes,
            ..profile()
        };
        let mut machine =
            VerifyDriver::new(source(&pack), REPOSITORY, profile, execution, 17).unwrap();
        let error = Host::new(&pack).finish(&mut machine).unwrap_err();
        assert_eq!(error.code, expected, "{profile_bytes} {budget_bytes}");
    }
}

fn evidence_binding() -> EvidenceBinding {
    VerifyDriver::binding(
        PackSource {
            id: [1; 32],
            len: 44,
            binding: SourceBinding([2; 32]),
        },
        REPOSITORY,
    )
}

/// Pages for the hostile-tree tests, keyed by digest.
struct Pages {
    pages: Map<Hash, Vec<u8>>,
}

impl Pages {
    fn new() -> Self {
        Self { pages: Map::new() }
    }

    fn leaf(&mut self, keys: &[u8]) -> PageCommitment {
        let records: Vec<_> = keys
            .iter()
            .map(|byte| LeafRecord {
                key: [*byte; 32],
                value: b"v",
            })
            .collect();
        let page = encode_leaf(
            evidence_binding(),
            PageKind::Objects,
            &records,
            EvidenceLimits::indexed(),
        )
        .unwrap();
        self.keep(&page)
    }

    fn internal(
        &mut self,
        height: u8,
        first: PageCommitment,
        rest: &[(u8, PageCommitment)],
    ) -> PageCommitment {
        let rest: Vec<_> = rest
            .iter()
            .map(|(separator, child)| BranchChild {
                separator: [*separator; 32],
                child: *child,
            })
            .collect();
        let page = encode_internal(
            evidence_binding(),
            PageKind::Objects,
            height,
            first,
            &rest,
            EvidenceLimits::indexed(),
        )
        .unwrap();
        self.keep(&page)
    }

    fn keep(&mut self, page: &EncodedPage) -> PageCommitment {
        let commitment = page.commitment();
        self.pages.insert(commitment.digest, page.bytes().to_vec());
        commitment
    }

    fn index(root: PageCommitment, count: u64) -> Index {
        Index::resume(
            PageKind::Objects,
            evidence_binding(),
            EvidenceLimits::indexed(),
            root,
            count,
        )
        .unwrap()
    }

    /// Runs an operation, feeding it pages until it finishes or refuses.
    fn run(&self, index: &mut Index, mut op: Op) -> Result<(), Failure> {
        loop {
            match index.poll(&mut op)? {
                Event::Page(want) => {
                    let bytes = self.pages.get(&want.digest).expect("tree page");
                    let mut budget = Budget::new(u64::MAX, u64::MAX);
                    index.feed(&mut op, bytes, &mut budget)?;
                }
                Event::Descended(_) | Event::Done { .. } => return Ok(()),
                Event::Emit(_) => panic!("read-only walk emitted a page"),
            }
        }
    }

    fn both_refuse(&self, root: PageCommitment, count: u64, key: u8) {
        let mut index = Self::index(root, count);
        let descend = index.descend([key; 32]);
        assert_eq!(
            self.run(&mut index, descend).unwrap_err().code,
            FailureCode::InvalidEvidence
        );
        let audit = index.audit();
        assert_eq!(
            self.run(&mut index, audit).unwrap_err().code,
            FailureCode::InvalidEvidence
        );
    }

    fn both_accept(&self, root: PageCommitment, count: u64, key: u8) {
        let mut index = Self::index(root, count);
        let descend = index.descend([key; 32]);
        self.run(&mut index, descend).unwrap();
        let audit = index.audit();
        self.run(&mut index, audit).unwrap();
    }
}

#[test]
fn lookups_and_audits_refuse_a_child_at_the_wrong_height() {
    let mut pages = Pages::new();
    let leaf = pages.leaf(&[0x10]);
    // Height 2 names a child that must itself be an internal page.
    let root = pages.internal(2, leaf, &[]);
    pages.both_refuse(root, 1, 0x10);
    // The same shape one level up is well formed.
    let root = pages.internal(1, leaf, &[]);
    pages.both_accept(root, 1, 0x10);
}

#[test]
fn lookups_and_audits_refuse_a_leaf_key_outside_its_inherited_interval() {
    let mut pages = Pages::new();
    let low = pages.leaf(&[0x10]);
    // Routed by separator 0x80, so every key here must be at least 0x80.
    let stray = pages.leaf(&[0x05]);
    let root = pages.internal(1, low, &[(0x80, stray)]);
    pages.both_refuse(root, 2, 0x90);
    // A key at or above the separator is equally out of place on the left.
    let stray_high = pages.leaf(&[0x90]);
    let root = pages.internal(1, stray_high, &[(0x80, low)]);
    pages.both_refuse(root, 2, 0x00);
    // Control: a well-formed two-leaf tree passes both walks.
    let high = pages.leaf(&[0x90]);
    let root = pages.internal(1, low, &[(0x80, high)]);
    pages.both_accept(root, 2, 0x90);
}

#[test]
fn the_resident_ceiling_is_never_passed_whatever_the_budget() {
    // Every reservation, the cache's included, is checked against the ceiling
    // before it happens, so a tight budget refuses with ResourceLimit; it
    // never overshoots. Sweep budgets from far too small to comfortable.
    let pack = blob_tree_pairs(400);
    let mut completed = 0;
    let mut refused = 0;
    for megabytes in [1_u64, 4, 8, 9, 10, 11, 12, 14, 16, 24, 64] {
        let budget = VerifyLimits {
            resident_bytes: megabytes << 20,
            page_bytes: 4096,
            resident_pages: 4,
            ..limits()
        };
        let mut machine = match VerifyDriver::new(source(&pack), REPOSITORY, profile(), budget, 17)
        {
            Ok(machine) => machine,
            Err(error) => {
                assert_eq!(error.code, FailureCode::ResourceLimit, "{megabytes} MiB");
                refused += 1;
                continue;
            }
        };
        let outcome = Host::new(&pack).finish(&mut machine);
        match outcome {
            Ok(_) => completed += 1,
            Err(error) => {
                assert_eq!(error.code, FailureCode::ResourceLimit, "{megabytes} MiB");
                refused += 1;
            }
        }
        assert!(
            machine.usage().peak_resident_bytes <= budget.resident_bytes,
            "{megabytes} MiB budget passed"
        );
    }
    assert!(
        completed > 0 && refused > 0,
        "sweep must cross the boundary"
    );
}
