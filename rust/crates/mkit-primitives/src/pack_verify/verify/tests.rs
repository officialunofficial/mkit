//! End-to-end driver tests over real packs and live acquisition loops.
use super::*;

mod checkpoints;
mod compute;
mod onepass;
mod pages;
use crate::evidence::{MemberFact, Revision, SourceBinding};
use mkit_core::{
    delta,
    hash::{self, Hash},
    object::{Blob, Commit, EntryMode, Identity, Object, Tag, Tree, TreeEntry, id_from_object},
    pack::PackWriter,
    serialize::serialize,
    sign,
};
use std::collections::BTreeMap;

const REPOSITORY: RepositoryId = RepositoryId([9; 32]);
const BINDING: SourceBinding = SourceBinding([7; 32]);

fn limits() -> VerifyLimits {
    VerifyLimits::indexed()
}

fn profile() -> IndexedProfile {
    IndexedProfile {
        pack_bytes: MAX_PACK_BYTES,
        decoded_bytes: 4 << 30,
        delta_depth: 50,
    }
}

fn source(pack: &[u8]) -> PackSource {
    PackSource {
        id: hash::hash(pack),
        len: pack.len() as u64,
        binding: BINDING,
    }
}

fn driver(pack: &[u8]) -> VerifyDriver {
    VerifyDriver::new(source(pack), REPOSITORY, profile(), limits(), 17).unwrap()
}

/// Takes a checkpoint at the current drained boundary. The first refused call
/// arms the request; the driver then retains the remaining pages itself.
fn boundary_checkpoint(machine: &mut VerifyDriver, host: &mut Host) -> Checkpoint {
    for _ in 0..1_000 {
        match machine.checkpoint() {
            Ok(checkpoint) => {
                return Checkpoint::from_bytes(checkpoint.bytes(), limits()).unwrap();
            }
            Err(error) => assert_eq!(error.code, FailureCode::CheckpointNotReady),
        }
        match machine.step().unwrap() {
            Step::RetainEvidence(page) => {
                let commitment = page.commitment;
                host.pages.push((commitment, page.bytes.to_vec()));
                machine.acknowledge_retention(commitment).unwrap();
            }
            Step::ReleasePage(page) => host.pages.retain(|(held, _)| *held != page),
            // Flushing may need a page the cache evicted.
            Step::Request(request @ Request::EvidencePage { .. }) => {
                host.serve(machine, &request).unwrap();
            }
            Step::Progress => (),
            other => panic!("boundary work needs only pages, got {other:?}"),
        }
    }
    panic!("the boundary never became ready")
}

fn canonical(object: &Object) -> (Hash, Vec<u8>) {
    let bytes = serialize(object).unwrap();
    (id_from_object(object, &bytes), bytes)
}

fn blob(data: &[u8]) -> (Hash, Vec<u8>) {
    canonical(&Object::Blob(Blob {
        data: data.to_vec(),
    }))
}

fn tree(name: &[u8], mode: EntryMode, child: Hash) -> (Hash, Vec<u8>) {
    canonical(&Object::Tree(Tree {
        entries: vec![TreeEntry {
            name: name.to_vec(),
            mode,
            object_hash: child,
        }],
    }))
}

fn signed_commit(tree_id: Hash, parents: Vec<Hash>) -> (Hash, Vec<u8>) {
    let kp = sign::KeyPair::from_seed([0x42; 32]);
    let mut commit = Commit::new_unannotated(
        tree_id,
        parents,
        Identity::ed25519(kp.public.0),
        kp.public.0,
        b"commit".to_vec(),
        100,
        [0; 64],
    );
    commit.signature = sign::sign_commit(&commit, &kp).unwrap().0;
    canonical(&Object::Commit(commit))
}

fn signed_tag(target: Hash, kind: ObjectType) -> (Hash, Vec<u8>) {
    let kp = sign::KeyPair::from_seed([0x42; 32]);
    let mut tag = Tag {
        target,
        target_type: kind,
        name: b"v1".to_vec(),
        tagger: Identity::ed25519(kp.public.0),
        signer: kp.public.0,
        message: b"tag".to_vec(),
        timestamp: 101,
        signature: [0; 64],
    };
    tag.signature = sign::sign_tag(&tag, &kp).unwrap().0;
    canonical(&Object::Tag(tag))
}

fn fact(object: Hash, bytes: &[u8], kind: ObjectType) -> MemberFact {
    MemberFact {
        repository: REPOSITORY,
        incarnation: Revision([1; 32]),
        object,
        kind,
        canonical_len: bytes.len() as u64,
        supplier: PackSource {
            id: [4; 32],
            len: 1024,
            binding: SourceBinding([5; 32]),
        },
        canonical_binding: SourceBinding([6; 32]),
        revision: Revision([2; 32]),
        delta_depth: 0,
        published: true,
        held: false,
    }
}

/// Serving state for a driven verification; provisional fragments are
/// accumulated per ordinal so canonical-base reads observe only what the
/// driver emitted.
#[derive(Default)]
struct Host {
    pack: Vec<u8>,
    fragments: BTreeMap<u64, Vec<u8>>,
    pages: Vec<(PageCommitment, Vec<u8>)>,
    externals: BTreeMap<Hash, (MemberFact, Vec<u8>)>,
    lost_pages: Vec<PageCommitment>,
    members_absent: bool,
    unavailable: bool,
}

impl Host {
    fn new(pack: &[u8]) -> Self {
        Self {
            pack: pack.to_vec(),
            ..Self::default()
        }
    }

    fn canonical(&self, object: Hash) -> Option<Vec<u8>> {
        self.fragments
            .values()
            .chain(self.externals.values().map(|(_, bytes)| bytes))
            .find(|bytes| {
                deserialize(bytes).is_ok_and(|parsed| id_from_object(&parsed, bytes) == object)
            })
            .cloned()
    }

    fn finish(&mut self, machine: &mut VerifyDriver) -> Result<VerifiedPack, Failure> {
        loop {
            match machine.step()? {
                Step::Request(request) => self.serve(machine, &request)?,
                Step::ProvisionalObject(fragment) => {
                    self.fragments
                        .entry(fragment.ordinal)
                        .or_default()
                        .extend_from_slice(fragment.bytes);
                }
                Step::RetainEvidence(page) => {
                    let commitment = page.commitment;
                    self.pages.push((commitment, page.bytes.to_vec()));
                    machine.acknowledge_retention(commitment)?;
                }
                Step::Progress | Step::ReleasePage(_) => (),
                Step::Complete(pack) => return Ok(pack),
            }
        }
    }

    fn serve(&mut self, machine: &mut VerifyDriver, request: &Request) -> Result<(), Failure> {
        match request {
            Request::Bytes {
                request,
                source,
                range,
            } => {
                let owned;
                let value = match source {
                    ByteSource::Pack(_) => self
                        .pack
                        .get(
                            usize::try_from(range.offset).unwrap()
                                ..usize::try_from(range.offset + range.len).unwrap(),
                        )
                        .map_or(Acquisition::Unavailable, Acquisition::Present),
                    ByteSource::Canonical { object, len, .. } => {
                        owned = self.canonical(*object);
                        match owned.as_deref() {
                            Some(bytes)
                                if !self.unavailable
                                    && bytes.len() as u64 == *len
                                    && range.offset + range.len <= *len =>
                            {
                                Acquisition::Present(
                                    &bytes[usize::try_from(range.offset).unwrap()
                                        ..usize::try_from(range.offset + range.len).unwrap()],
                                )
                            }
                            _ => Acquisition::Unavailable,
                        }
                    }
                };
                machine.supply(Response::Bytes {
                    request: *request,
                    source: *source,
                    range: *range,
                    value,
                })
            }
            Request::ExternalObject {
                request, object, ..
            } => {
                let value = if self.members_absent {
                    Acquisition::Absent
                } else {
                    self.externals
                        .get(object)
                        .map_or(Acquisition::Unavailable, |(member, _)| {
                            Acquisition::Present(member.clone())
                        })
                };
                machine.supply(Response::ExternalObject {
                    request: *request,
                    value,
                })
            }
            Request::Compute { job } => {
                let output = machine.take_compute(*job)?.run();
                let disposition = machine.supply_compute(output)?;
                assert_eq!(disposition, ComputeDisposition::Accepted);
                Ok(())
            }
            Request::EvidencePage { request, page } => {
                let value = if self.lost_pages.contains(page) {
                    Acquisition::Unavailable
                } else {
                    self.pages
                        .iter()
                        .find(|(commitment, _)| commitment == page)
                        .map_or(Acquisition::Unavailable, |(_, bytes)| {
                            Acquisition::Present(bytes.as_slice())
                        })
                };
                machine.supply(Response::EvidencePage {
                    request: *request,
                    page: *page,
                    value,
                })
            }
        }
    }
}

#[test]
fn raw_pack_seals_exact_counts_and_heads() {
    let (a_id, a) = blob(b"alpha");
    let (b_id, b) = blob(b"beta");
    let mut writer = PackWriter::new_raw_only();
    writer.push_raw(a_id, &a).unwrap();
    writer.push_raw(b_id, &b).unwrap();
    writer.push_raw(a_id, &a).unwrap();
    let pack = writer.finish().unwrap();
    let mut host = Host::new(&pack);
    let verified = host.finish(&mut driver(&pack)).unwrap();
    let counts = verified.counts();
    assert_eq!(counts.entries, 3);
    assert_eq!(counts.objects, 2);
    assert_eq!(counts.delta_entries, 0);
    assert_eq!(counts.wire_payload_bytes, (a.len() * 2 + b.len()) as u64);
    assert_eq!(counts.decoded_bytes, counts.wire_payload_bytes);
    assert_eq!(verified.occurrences().count, 3);
    assert_eq!(verified.head_facts().count, 2);
    assert_eq!(verified.dependencies().count, 0);
    assert_eq!(verified.source().id, source(&pack).id);
}

#[test]
fn in_pack_delta_chain_counts_delta_entries_exactly() {
    let (base_id, base) = blob(b"base");
    let (middle_id, middle) = blob(b"middle");
    let (target_id, target) = blob(b"target");
    let mut writer = PackWriter::new();
    writer.push_raw(base_id, &base).unwrap();
    writer
        .push_delta(&base_id, &delta::encode(&base, &middle).unwrap())
        .unwrap();
    writer
        .push_delta(&middle_id, &delta::encode(&middle, &target).unwrap())
        .unwrap();
    let pack = writer.finish().unwrap();
    let mut host = Host::new(&pack);
    let verified = host.finish(&mut driver(&pack)).unwrap();
    let counts = verified.counts();
    assert_eq!(counts.entries, 3);
    assert_eq!(counts.objects, 3);
    assert_eq!(counts.delta_entries, 2);
    assert!(counts.delta_entries <= counts.entries);
    assert_eq!(
        counts.decoded_bytes,
        (base.len() + middle.len() + target.len()) as u64
    );
    let _ = target_id;
}

#[test]
fn unavailable_canonical_base_is_retryable_unavailable_input() {
    let (base_id, base) = blob(b"lost canonical");
    let (result_id, result) = blob(b"canonical result");
    let mut writer = PackWriter::new();
    writer.push_raw(base_id, &base).unwrap();
    writer
        .push_delta(&base_id, &delta::encode(&base, &result).unwrap())
        .unwrap();
    let pack = writer.finish().unwrap();
    let mut host = Host::new(&pack);
    host.unavailable = true;
    let mut machine = driver(&pack);
    let mut refusals = 0;
    let verified = loop {
        match machine.step().unwrap() {
            Step::Request(request) => {
                if let Err(error) = host.serve(&mut machine, &request) {
                    assert_eq!(error.code, FailureCode::UnavailableInput);
                    refusals += 1;
                    if refusals == 2 {
                        host.unavailable = false;
                    }
                }
            }
            Step::ProvisionalObject(fragment) => {
                host.fragments
                    .entry(fragment.ordinal)
                    .or_default()
                    .extend_from_slice(fragment.bytes);
            }
            Step::RetainEvidence(page) => {
                let commitment = page.commitment;
                host.pages.push((commitment, page.bytes.to_vec()));
                machine.acknowledge_retention(commitment).unwrap();
            }
            Step::Progress | Step::ReleasePage(_) => (),
            Step::Complete(pack) => break pack,
        }
        assert!(refusals <= 8, "canonical fetch never recovered");
    };
    assert!(refusals >= 1);
    assert_eq!(verified.counts().delta_entries, 1);
    let _ = result_id;
}

#[test]
fn wide_tree_flushes_edge_records_across_bounded_rewrites() {
    let (child_id, child) = blob(b"child");
    let entries: Vec<TreeEntry> = (0..40)
        .map(|n| TreeEntry {
            name: format!("entry-{n:02}").into_bytes(),
            mode: EntryMode::Blob,
            object_hash: child_id,
        })
        .collect();
    let (tree_id, tree) = canonical(&Object::Tree(Tree { entries }));
    let mut writer = PackWriter::new_raw_only();
    writer.push_raw(child_id, &child).unwrap();
    writer.push_raw(tree_id, &tree).unwrap();
    let pack = writer.finish().unwrap();
    let mut host = Host::new(&pack);
    let verified = host.finish(&mut driver(&pack)).unwrap();
    let counts = verified.counts();
    assert_eq!(counts.entries, 2);
    assert_eq!(counts.objects, 2);
    assert_eq!(verified.dependencies().count, 40);
    assert_eq!(verified.head_facts().count, 1);
}

#[test]
fn resident_ledger_is_symmetric_across_leaf_flushes() {
    // 4 KiB pages fit a full leaf but commit one every few edge records; a
    // leaked spine reservation would grow resident bytes once per commit.
    let (child_id, child) = blob(b"child");
    let entries: Vec<TreeEntry> = (0..400)
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
    let pack = writer.finish().unwrap();
    let mut host = Host::new(&pack);
    let mut limits = limits();
    limits.page_bytes = 4096;
    let mut machine = VerifyDriver::new(source(&pack), REPOSITORY, profile(), limits, 17).unwrap();
    let mut first = None;
    let mut last = 0;
    for _ in 0..200_000 {
        let step = match machine.step() {
            Ok(step) => step,
            Err(error) => panic!("{error:?} usage={:?}", machine.usage()),
        };
        match step {
            Step::Request(request) => host.serve(&mut machine, &request).unwrap(),
            Step::ProvisionalObject(fragment) => {
                host.fragments
                    .entry(fragment.ordinal)
                    .or_default()
                    .extend_from_slice(fragment.bytes);
            }
            Step::RetainEvidence(page) => {
                let commitment = page.commitment;
                host.pages.push((commitment, page.bytes.to_vec()));
                machine.acknowledge_retention(commitment).unwrap();
            }
            Step::Progress | Step::ReleasePage(_) => (),
            Step::Complete(_) => break,
        }
        if machine.checkpoint().is_ok() {
            let resident = machine.usage().resident_bytes;
            if first.is_none() {
                first = Some(resident);
            }
            last = resident;
        }
    }
    let first = first.expect("a drained boundary exists");
    // Committed leaves release their spine reservation: the ledger may grow
    // only by the live spines, at most one page of records per sequence.
    assert!(
        last <= first + 6 * limits.page_bytes,
        "resident ledger leaked across flushes: {first} -> {last}"
    );
}

#[test]
fn undersized_page_bytes_refuses_without_losing_inertness() {
    let (a_id, a) = blob(b"alpha");
    let mut writer = PackWriter::new_raw_only();
    writer.push_raw(a_id, &a).unwrap();
    let pack = writer.finish().unwrap();
    let mut host = Host::new(&pack);
    let mut limits = limits();
    limits.page_bytes = 140;
    let mut machine = VerifyDriver::new(source(&pack), REPOSITORY, profile(), limits, 17).unwrap();
    let mut refused = None;
    for _ in 0..400 {
        match machine.step() {
            Ok(Step::Request(request)) => host.serve(&mut machine, &request).unwrap(),
            Ok(Step::ProvisionalObject(fragment)) => {
                host.fragments
                    .entry(fragment.ordinal)
                    .or_default()
                    .extend_from_slice(fragment.bytes);
            }
            Ok(Step::RetainEvidence(page)) => {
                let commitment = page.commitment;
                host.pages.push((commitment, page.bytes.to_vec()));
                if machine.acknowledge_retention(commitment).is_err() {
                    refused = Some(FailureCode::InvalidResponse);
                    break;
                }
            }
            Ok(Step::Progress | Step::ReleasePage(_)) => (),
            Ok(Step::Complete(_)) => panic!("verification completed with unusable page size"),
            Err(error) => {
                refused = Some(error.code);
                break;
            }
        }
    }
    assert_eq!(refused, Some(FailureCode::ResourceLimit));
    // A terminal refusal makes the driver inert: no panic, no new requests.
    for _ in 0..8 {
        assert!(machine.step().is_err());
    }
}

#[test]
fn absurd_external_fact_length_is_a_protocol_violation() {
    let (base_id, base) = blob(b"absurd base");
    let (result_id, result) = blob(b"absurd result");
    let mut writer = PackWriter::new();
    writer
        .push_delta(&base_id, &delta::encode(&base, &result).unwrap())
        .unwrap();
    let pack = writer.finish().unwrap();
    let mut host = Host::new(&pack);
    let mut oversized = fact(base_id, &base, ObjectType::Blob);
    oversized.canonical_len = u64::MAX;
    host.externals.insert(base_id, (oversized, base.clone()));
    let mut machine = driver(&pack);
    let result_outcome = host.finish(&mut machine);
    assert_eq!(
        result_outcome.unwrap_err().code,
        FailureCode::InvalidResponse
    );
    let _ = result_id;
}

#[test]
fn delta_entries_stays_within_entries_on_fixture_pack() {
    let pack = include_bytes!("../../../fixtures/framing/earlier-delta-base.bin");
    let mut host = Host::new(pack);
    let verified = host.finish(&mut driver(pack)).unwrap();
    let counts = verified.counts();
    assert!(counts.delta_entries <= counts.entries);
    assert!(counts.delta_entries > 0);
    assert_eq!(counts.entries, 3);
}

#[test]
fn later_delta_base_is_an_external_lookup_then_absent() {
    let pack = include_bytes!("../../../fixtures/framing/later-delta-base.bin");
    let mut host = Host::new(pack);
    host.members_absent = true;
    let mut machine = driver(pack);
    let result = host.finish(&mut machine);
    assert_eq!(result.unwrap_err().code, FailureCode::ExternalBaseAbsent);
}

#[test]
fn external_delta_base_verifies_through_member_fact() {
    let (base_id, base) = blob(b"external base");
    let (result_id, result) = blob(b"external result");
    let mut writer = PackWriter::new();
    writer
        .push_delta(&base_id, &delta::encode(&base, &result).unwrap())
        .unwrap();
    let pack = writer.finish().unwrap();
    let mut host = Host::new(&pack);
    host.externals.insert(
        base_id,
        (fact(base_id, &base, ObjectType::Blob), base.clone()),
    );
    let verified = host.finish(&mut driver(&pack)).unwrap();
    let counts = verified.counts();
    assert_eq!(counts.entries, 1);
    assert_eq!(counts.delta_entries, 1);
    assert!(counts.delta_entries <= counts.entries);
    assert_eq!(verified.dependencies().count, 1);
    let _ = result_id;
    // The sealed commitment is exactly the one fact the host supplied, and any
    // other list differs.
    let supplied = fact(base_id, &base, ObjectType::Blob);
    assert_eq!(
        verified.external_bases(),
        crate::pack_verify::ExternalBases::of([&supplied]).unwrap()
    );
    assert_eq!(verified.external_bases().count, 1);
    assert_ne!(
        verified.external_bases(),
        crate::pack_verify::ExternalBases::EMPTY
    );
    let mut altered = supplied;
    altered.revision = Revision([0xee; 32]);
    assert_ne!(
        verified.external_bases(),
        crate::pack_verify::ExternalBases::of([&altered]).unwrap()
    );
}

#[test]
fn external_delta_base_unavailable_is_not_absent() {
    let (base_id, base) = blob(b"lost external");
    let mut writer = PackWriter::new();
    writer
        .push_delta(&base_id, &delta::encode(&base, &base).unwrap())
        .unwrap();
    let pack = writer.finish().unwrap();
    let mut host = Host::new(&pack);
    let result = host.finish(&mut driver(&pack));
    assert_eq!(result.unwrap_err().code, FailureCode::UnavailableInput);
}

#[test]
fn held_and_unpublished_facts_refuse_external_bases() {
    let (base_id, base) = blob(b"held external");
    let mut writer = PackWriter::new();
    writer
        .push_delta(&base_id, &delta::encode(&base, &base).unwrap())
        .unwrap();
    let pack = writer.finish().unwrap();
    for mutate in [
        (|member: &mut MemberFact| member.held = true) as fn(&mut MemberFact),
        |member| member.published = false,
    ] {
        let mut member = fact(base_id, &base, ObjectType::Blob);
        mutate(&mut member);
        let mut host = Host::new(&pack);
        host.externals.insert(base_id, (member, base.clone()));
        let result = host.finish(&mut driver(&pack));
        assert_eq!(result.unwrap_err().code, FailureCode::ExternalBaseAbsent);
    }
}

#[test]
fn an_external_depth_overflow_is_transient_and_a_stored_base_with_wrong_bytes_is_unavailable() {
    let (base_id, base) = blob(b"deep external");
    let mut writer = PackWriter::new();
    writer
        .push_delta(&base_id, &delta::encode(&base, &base).unwrap())
        .unwrap();
    let pack = writer.finish().unwrap();
    // The base is at the profile depth, so its delta is one past it.
    let mut member = fact(base_id, &base, ObjectType::Blob);
    member.delta_depth = profile().delta_depth;
    let mut host = Host::new(&pack);
    host.externals.insert(base_id, (member, base.clone()));
    let failure = host.finish(&mut driver(&pack)).unwrap_err();
    assert_eq!(failure.code, FailureCode::ExternalDeltaChainTooDeep);
    assert_eq!(failure.persistence(), crate::error::Persistence::Transient);
    // Bytes that do not match the stored base's identity are a repository
    // fault: retryable, never a content verdict.
    let (_, other) = blob(b"deep externaX");
    let mut member = fact(base_id, &base, ObjectType::Blob);
    member.canonical_len = other.len() as u64;
    let mut host = Host::new(&pack);
    host.externals.insert(base_id, (member, other));
    let failure = host.finish(&mut driver(&pack)).unwrap_err();
    assert_eq!(failure.code, FailureCode::UnavailableInput);
}

#[test]
fn bad_signature_refuses_terminal_sealing() {
    let (tree_id, tree) = tree(b"child", EntryMode::Blob, [1; 32]);
    let (commit_id, mut commit) = signed_commit(tree_id, vec![]);
    let last = commit.len() - 1;
    commit[last] ^= 1;
    let mut writer = PackWriter::new();
    writer.push_raw(tree_id, &tree).unwrap();
    writer.push_raw(commit_id, &commit).unwrap();
    let pack = writer.finish().unwrap();
    let mut host = Host::new(&pack);
    let result = host.finish(&mut driver(&pack));
    assert_eq!(result.unwrap_err().code, FailureCode::BadSignature);
}

#[test]
fn signed_commit_tag_and_tree_edges_seal() {
    let (blob_id, blob) = blob(b"leaf");
    let (tree_id, tree) = tree(b"leaf", EntryMode::Blob, blob_id);
    let (commit_id, commit) = signed_commit(tree_id, vec![]);
    let (tag_id, tag) = signed_tag(commit_id, ObjectType::Commit);
    let mut writer = PackWriter::new();
    for (id, bytes) in [
        (blob_id, &blob),
        (tree_id, &tree),
        (commit_id, &commit),
        (tag_id, &tag),
    ] {
        writer.push_raw(id, bytes).unwrap();
    }
    let pack = writer.finish().unwrap();
    let mut host = Host::new(&pack);
    let verified = host.finish(&mut driver(&pack)).unwrap();
    let counts = verified.counts();
    assert_eq!(counts.entries, 4);
    assert_eq!(counts.objects, 4);
    assert_eq!(counts.delta_entries, 0);
    // Only the tag is unreferenced: it alone is a head.
    assert_eq!(verified.head_facts().count, 1);
    // tree→blob, commit→tree, tag→commit.
    assert_eq!(verified.dependencies().count, 3);
}

#[test]
fn integrity_failure_precedes_every_entry_check() {
    let (id, bytes) = blob(b"content");
    let mut writer = PackWriter::new_raw_only();
    writer.push_raw(id, &bytes).unwrap();
    let mut pack = writer.finish().unwrap();
    let last = pack.len() - 1;
    pack[last] ^= 1;
    let mut host = Host::new(&pack);
    let result = host.finish(&mut driver(&pack));
    assert_eq!(result.unwrap_err().code, FailureCode::PackfileCorrupted);
}

#[test]
fn wrong_stale_and_malformed_replies_keep_requests_stable() {
    let (id, bytes) = blob(b"stable");
    let mut writer = PackWriter::new_raw_only();
    writer.push_raw(id, &bytes).unwrap();
    let pack = writer.finish().unwrap();
    let mut machine = driver(&pack);
    let (request, source, range) = loop {
        match machine.step().unwrap() {
            Step::Request(Request::Bytes {
                request,
                source,
                range,
            }) => break (request, source, range),
            Step::RetainEvidence(page) => {
                let commitment = page.commitment;
                machine.acknowledge_retention(commitment).unwrap();
            }
            Step::Progress | Step::ReleasePage(_) => (),
            _ => panic!(),
        }
    };
    // Wrong request identity.
    let stale = RequestId {
        generation: 17,
        sequence: request.sequence + 1,
    };
    assert_eq!(
        machine
            .supply(Response::Bytes {
                request: stale,
                source,
                range,
                value: Acquisition::Present(&pack[..12]),
            })
            .unwrap_err()
            .code,
        FailureCode::InvalidResponse
    );
    // Short value.
    assert_eq!(
        machine
            .supply(Response::Bytes {
                request,
                source,
                range,
                value: Acquisition::Present(&pack[..11]),
            })
            .unwrap_err()
            .code,
        FailureCode::InvalidResponse
    );
    // The identical request is still outstanding.
    let Step::Request(Request::Bytes {
        request: again,
        source: src,
        range: rng,
    }) = machine.step().unwrap()
    else {
        panic!()
    };
    assert_eq!((again, src, rng), (request, source, range));
}

#[test]
fn retention_backpressure_blocks_checkpointing_until_acknowledged() {
    let (id, bytes) = blob(b"backpressure");
    let mut writer = PackWriter::new_raw_only();
    writer.push_raw(id, &bytes).unwrap();
    let pack = writer.finish().unwrap();
    let mut host = Host::new(&pack);
    let mut machine = driver(&pack);
    let mut retained = Vec::new();
    loop {
        match machine.step().unwrap() {
            Step::Request(request) => host.serve(&mut machine, &request).unwrap(),
            Step::ProvisionalObject(_) | Step::Progress | Step::ReleasePage(_) => (),
            Step::Complete(_) => break,
            Step::RetainEvidence(page) => {
                let (commitment, page_bytes) = (page.commitment, page.bytes.to_vec());
                assert_eq!(
                    machine.checkpoint().unwrap_err().code,
                    FailureCode::CheckpointNotReady
                );
                // A wrong commitment preserves the outstanding page.
                let mut wrong = commitment;
                wrong.digest[0] ^= 1;
                assert_eq!(
                    machine.acknowledge_retention(wrong).unwrap_err().code,
                    FailureCode::InvalidResponse
                );
                let Step::RetainEvidence(again) = machine.step().unwrap() else {
                    panic!()
                };
                assert_eq!(again.commitment, commitment);
                host.pages.push((commitment, page_bytes));
                machine.acknowledge_retention(commitment).unwrap();
                retained.push(commitment);
            }
        }
    }
    assert!(retained.len() >= 6);
}

#[test]
fn mid_decode_checkpoint_resumes_through_page_audit() {
    let (a_id, a) = blob(b"alpha");
    let (b_id, b) = blob(b"beta");
    let (c_id, c) = blob(b"gamma");
    let mut writer = PackWriter::new();
    for (id, bytes) in [(a_id, &a), (b_id, &b), (c_id, &c)] {
        writer.push_raw(id, bytes).unwrap();
    }
    let (_, d_bytes) = blob(b"delta result");
    writer
        .push_delta(&a_id, &delta::encode(&a, &d_bytes).unwrap())
        .unwrap();
    let pack = writer.finish().unwrap();
    let mut host = Host::new(&pack);
    let mut machine = driver(&pack);
    // Drive past the first entry's records, then snapshot at a drained boundary.
    let mut snapshot = None;
    for _ in 0..400 {
        match machine.step().unwrap() {
            Step::Request(request) => host.serve(&mut machine, &request).unwrap(),
            Step::ProvisionalObject(fragment) => {
                host.fragments
                    .entry(fragment.ordinal)
                    .or_default()
                    .extend_from_slice(fragment.bytes);
            }
            Step::RetainEvidence(page) => {
                let commitment = page.commitment;
                host.pages.push((commitment, page.bytes.to_vec()));
                machine.acknowledge_retention(commitment).unwrap();
            }
            Step::Progress | Step::ReleasePage(_) => (),
            Step::Complete(_) => panic!("pack finished before a snapshot"),
        }
        if machine.ordinal == 1 && snapshot.is_none() {
            match machine.checkpoint() {
                Ok(cp) => {
                    snapshot = Some(Checkpoint::from_bytes(cp.bytes(), limits()).unwrap());
                    break;
                }
                Err(error) => eprintln!(
                    "checkpoint refused: {:?} at ordinal {}",
                    error.code, machine.ordinal
                ),
            }
        }
    }
    let snapshot = snapshot.expect("a drained boundary exists mid-decode");
    let mut resumed = VerifyDriver::resume(
        source(&pack),
        REPOSITORY,
        profile(),
        limits(),
        18,
        &snapshot,
    )
    .unwrap();
    let verified = host.finish(&mut resumed).unwrap();
    assert_eq!(verified.counts().entries, 4);
    assert_eq!(verified.counts().delta_entries, 1);
}

#[test]
fn a_resumed_run_keeps_the_external_base_commitment() {
    let (first_id, first) = blob(b"first external base");
    let (second_id, second) = blob(b"second external base");
    let (_, first_result) = blob(b"first result");
    let (_, second_result) = blob(b"second result");
    let mut writer = PackWriter::new();
    writer
        .push_delta(&first_id, &delta::encode(&first, &first_result).unwrap())
        .unwrap();
    writer
        .push_delta(&second_id, &delta::encode(&second, &second_result).unwrap())
        .unwrap();
    let pack = writer.finish().unwrap();
    let mut host = Host::new(&pack);
    let facts = [
        fact(first_id, &first, ObjectType::Blob),
        fact(second_id, &second, ObjectType::Blob),
    ];
    host.externals
        .insert(first_id, (facts[0].clone(), first.clone()));
    host.externals
        .insert(second_id, (facts[1].clone(), second.clone()));
    let mut machine = driver(&pack);
    let mut snapshot = None;
    for _ in 0..400 {
        match machine.step().unwrap() {
            Step::Request(request) => host.serve(&mut machine, &request).unwrap(),
            Step::ProvisionalObject(fragment) => {
                host.fragments
                    .entry(fragment.ordinal)
                    .or_default()
                    .extend_from_slice(fragment.bytes);
            }
            Step::RetainEvidence(page) => {
                let commitment = page.commitment;
                host.pages.push((commitment, page.bytes.to_vec()));
                machine.acknowledge_retention(commitment).unwrap();
            }
            Step::Progress | Step::ReleasePage(_) => (),
            Step::Complete(_) => panic!("pack finished before a snapshot"),
        }
        if machine.ordinal == 1
            && snapshot.is_none()
            && let Ok(cp) = machine.checkpoint()
        {
            snapshot = Some(Checkpoint::from_bytes(cp.bytes(), limits()).unwrap());
            break;
        }
    }
    let snapshot = snapshot.expect("a drained boundary after the first delta");
    let state = snapshot.decode(limits()).unwrap();
    assert_eq!(state.verify.unwrap().external_lookups, 1);
    let mut resumed = VerifyDriver::resume(
        source(&pack),
        REPOSITORY,
        profile(),
        limits(),
        18,
        &snapshot,
    )
    .unwrap();
    let verified = host.finish(&mut resumed).unwrap();
    // The first base counted before the checkpoint, the second after resume.
    assert_eq!(
        verified.external_bases(),
        crate::pack_verify::ExternalBases::of(&facts).unwrap()
    );
    assert_eq!(verified.external_bases().count, 2);
}

#[test]
fn resumed_run_refuses_lost_evidence_pages() {
    let (a_id, a) = blob(b"alpha");
    let (b_id, b) = blob(b"beta");
    let mut writer = PackWriter::new_raw_only();
    writer.push_raw(a_id, &a).unwrap();
    writer.push_raw(b_id, &b).unwrap();
    let pack = writer.finish().unwrap();
    let mut host = Host::new(&pack);
    let mut machine = driver(&pack);
    let mut snapshot = None;
    let mut last_error = None;
    for _ in 0..200 {
        match machine.step().unwrap() {
            Step::Request(request) => host.serve(&mut machine, &request).unwrap(),
            Step::ProvisionalObject(fragment) => {
                host.fragments
                    .entry(fragment.ordinal)
                    .or_default()
                    .extend_from_slice(fragment.bytes);
            }
            Step::RetainEvidence(page) => {
                let commitment = page.commitment;
                host.pages.push((commitment, page.bytes.to_vec()));
                machine.acknowledge_retention(commitment).unwrap();
            }
            Step::Progress | Step::ReleasePage(_) => (),
            Step::Complete(_) => panic!("pack finished before a snapshot"),
        }
        if machine.ordinal == 1 && snapshot.is_none() {
            match machine.checkpoint() {
                Ok(cp) => {
                    snapshot = Some(Checkpoint::from_bytes(cp.bytes(), limits()).unwrap());
                    break;
                }
                Err(error) => last_error = Some(error.code),
            }
        }
    }
    let snapshot = snapshot.unwrap_or_else(|| panic!("no snapshot; last error: {last_error:?}"));
    // Lose the last retained page: it is always live in a committed index, so
    // the audit must surface the loss as unavailable input.
    host.lost_pages.push(host.pages.last().unwrap().0);
    let mut resumed = VerifyDriver::resume(
        source(&pack),
        REPOSITORY,
        profile(),
        limits(),
        18,
        &snapshot,
    )
    .unwrap();
    let result = host.finish(&mut resumed);
    assert_eq!(result.unwrap_err().code, FailureCode::UnavailableInput);
}

#[test]
fn reused_generation_and_changed_bindings_refuse_resume() {
    let (id, bytes) = blob(b"bindings");
    let mut writer = PackWriter::new_raw_only();
    writer.push_raw(id, &bytes).unwrap();
    let pack = writer.finish().unwrap();
    let mut host = Host::new(&pack);
    let mut machine = driver(&pack);
    let snapshot = loop {
        match machine.step().unwrap() {
            Step::Request(request) => host.serve(&mut machine, &request).unwrap(),
            Step::ProvisionalObject(_) | Step::Progress | Step::ReleasePage(_) => (),
            Step::RetainEvidence(page) => {
                let commitment = page.commitment;
                host.pages.push((commitment, page.bytes.to_vec()));
                machine.acknowledge_retention(commitment).unwrap();
            }
            Step::Complete(_) => panic!(),
        }
        if machine.ordinal == 1
            && let Ok(cp) = machine.checkpoint()
        {
            break Checkpoint::from_bytes(cp.bytes(), limits()).unwrap();
        }
    };
    assert_eq!(
        VerifyDriver::resume(
            source(&pack),
            REPOSITORY,
            profile(),
            limits(),
            17,
            &snapshot
        )
        .unwrap_err()
        .code,
        FailureCode::InvalidCheckpoint
    );
    let mut moved = source(&pack);
    moved.binding = SourceBinding([8; 32]);
    assert_eq!(
        VerifyDriver::resume(moved, REPOSITORY, profile(), limits(), 18, &snapshot)
            .unwrap_err()
            .code,
        FailureCode::SourceChanged
    );
    assert_eq!(
        VerifyDriver::resume(
            source(&pack),
            RepositoryId([4; 32]),
            profile(),
            limits(),
            18,
            &snapshot
        )
        .unwrap_err()
        .code,
        FailureCode::InvalidCheckpoint
    );
}

#[test]
fn ceiling_refusals_stop_bounded_work() {
    let (id, bytes) = blob(b"ceiling");
    let mut writer = PackWriter::new_raw_only();
    writer.push_raw(id, &bytes).unwrap();
    let pack = writer.finish().unwrap();
    let narrow = IndexedProfile {
        pack_bytes: 8,
        ..profile()
    };
    assert_eq!(
        VerifyDriver::new(source(&pack), REPOSITORY, narrow, limits(), 17)
            .unwrap_err()
            .code,
        FailureCode::PackfileTooLarge
    );
}

#[test]
fn record_fixtures_decode_canonically_and_version_bytes_refuse() {
    use records::{DependencyRecord, HeadRecord, ObjectRecord, OccurrenceRecord, OrdinalRecord};
    for bytes in [
        include_bytes!("../../../fixtures/evidence/verify-record-object.bin").as_slice(),
        include_bytes!("../../../fixtures/evidence/verify-record-occurrence.bin").as_slice(),
        include_bytes!("../../../fixtures/evidence/verify-record-ordinal.bin").as_slice(),
        include_bytes!("../../../fixtures/evidence/verify-record-head.bin").as_slice(),
        include_bytes!("../../../fixtures/evidence/verify-record-edge.bin").as_slice(),
        include_bytes!("../../../fixtures/evidence/verify-record-external.bin").as_slice(),
    ] {
        let reencoded = match bytes.len() {
            records::OBJECT_BYTES => ObjectRecord::from_bytes(bytes).unwrap().to_bytes(),
            records::OCCURRENCE_BYTES => OccurrenceRecord::from_bytes(bytes).unwrap().to_bytes(),
            records::ORDINAL_BYTES => OrdinalRecord::from_bytes(bytes).unwrap().to_bytes(),
            records::HEAD_BYTES => HeadRecord::from_bytes(bytes).unwrap().to_bytes(),
            _ => DependencyRecord::from_bytes(bytes).unwrap().to_bytes(),
        };
        assert_eq!(reencoded, bytes);
    }
    for bytes in [
        include_bytes!("../../../fixtures/evidence/verify-record-object-version.bin").as_slice(),
        include_bytes!("../../../fixtures/evidence/verify-record-occurrence-version.bin")
            .as_slice(),
        include_bytes!("../../../fixtures/evidence/verify-record-ordinal-version.bin").as_slice(),
        include_bytes!("../../../fixtures/evidence/verify-record-head-version.bin").as_slice(),
        include_bytes!("../../../fixtures/evidence/verify-record-edge-version.bin").as_slice(),
        include_bytes!("../../../fixtures/evidence/verify-record-external-version.bin").as_slice(),
    ] {
        assert_eq!(
            match bytes.len() {
                records::OBJECT_BYTES => ObjectRecord::from_bytes(bytes).unwrap_err(),
                records::OCCURRENCE_BYTES => OccurrenceRecord::from_bytes(bytes).unwrap_err(),
                records::ORDINAL_BYTES => OrdinalRecord::from_bytes(bytes).unwrap_err(),
                records::HEAD_BYTES => HeadRecord::from_bytes(bytes).unwrap_err(),
                _ => DependencyRecord::from_bytes(bytes).unwrap_err(),
            }
            .code,
            FailureCode::InvalidEvidence
        );
    }
}

#[test]
fn record_domain_must_match_the_kind_signing_domain() {
    let signed = ObjectRecord {
        kind: ObjectType::Commit,
        canonical_len: 42,
        first_ordinal: 0,
        delta_depth: 0,
        signature: Signature::Valid,
        domain: Domain::Commit,
        signer: [7; 32],
        signing_digest: [8; 32],
        dep_start: 0,
        dep_count: 0,
        chunk_total: 0,
        chunk_count: 0,
    }
    .to_bytes();
    assert!(ObjectRecord::from_bytes(&signed).is_ok());
    // A commit signature under a non-signed kind is rejected.
    let mut wrong_kind = signed.clone();
    wrong_kind[1] = 1;
    assert_eq!(
        ObjectRecord::from_bytes(&wrong_kind).unwrap_err().code,
        FailureCode::InvalidEvidence
    );
    // A mismatched signing domain under a signed kind is rejected.
    let mut wrong_domain = signed;
    wrong_domain[23] = 2;
    assert_eq!(
        ObjectRecord::from_bytes(&wrong_domain).unwrap_err().code,
        FailureCode::InvalidEvidence
    );

    let signed = OccurrenceRecord {
        object: [9; 32],
        kind: ObjectType::Tag,
        canonical_len: 42,
        frame_offset: 0,
        frame_len: 10,
        wire_type: 0,
        from_delta: false,
        delta_base: [0; 32],
        delta_depth: 0,
        signature: Signature::Valid,
        first: true,
        domain: Domain::Tag,
        signer: [7; 32],
        signing_digest: [8; 32],
        ext_start: 0,
        ext_count: 0,
    }
    .to_bytes();
    assert!(OccurrenceRecord::from_bytes(&signed).is_ok());
    // kind at offset 33, domain at offset 98.
    let mut wrong_kind = signed.clone();
    wrong_kind[33] = 2;
    assert_eq!(
        OccurrenceRecord::from_bytes(&wrong_kind).unwrap_err().code,
        FailureCode::InvalidEvidence
    );
    let mut wrong_domain = signed;
    wrong_domain[98] = 1;
    assert_eq!(
        OccurrenceRecord::from_bytes(&wrong_domain)
            .unwrap_err()
            .code,
        FailureCode::InvalidEvidence
    );
}

mod decoded_leaves;
