//! Synchronous launch inspection through real pack verification and apply.

use super::*;
use crate::hooks::InspectVerdict;
use crate::pipeline::inspection::{ContentInspector, InspectorPhase, OnUnavailable};
use mkit_core::object::ChunkedBlob;
use mkit_rpc::hooks::{InspectObject, InspectObjectKind};

#[derive(Clone, Debug, PartialEq)]
struct Call {
    id: String,
    objects: Vec<InspectObject>,
}

struct Scanner {
    name: String,
    phase: InspectorPhase,
    availability: OnUnavailable,
    unavailable: AtomicBool,
    reject: bool,
    calls: Mutex<Vec<Call>>,
}

impl Scanner {
    fn new(name: &str) -> Arc<Self> {
        Arc::new(Self {
            name: name.into(),
            phase: InspectorPhase::Sync,
            availability: OnUnavailable::FailClosed,
            unavailable: AtomicBool::new(false),
            reject: false,
            calls: Mutex::default(),
        })
    }
}

impl ContentInspector for Scanner {
    fn id(&self) -> &str {
        &self.name
    }
    fn phase(&self) -> InspectorPhase {
        self.phase
    }
    fn on_unavailable(&self) -> OnUnavailable {
        self.availability
    }
    fn inspect<'a>(
        &'a self,
        _: &'a Operation,
        id: &'a str,
        objects: &'a [InspectObject],
    ) -> crate::BoxFuture<'a, Result<InspectVerdict, ServerError>> {
        Box::pin(async move {
            self.calls.lock().unwrap().push(Call {
                id: id.into(),
                objects: objects.to_vec(),
            });
            if self.unavailable.load(Ordering::SeqCst) {
                Err(ServerError::unavailable("scanner unavailable"))
            } else if self.reject {
                Ok(InspectVerdict::Reject("scanner policy".into()))
            } else {
                Ok(InspectVerdict::Pass)
            }
        })
    }
}

fn configure(env: &mut Env, scanners: Vec<Arc<dyn ContentInspector>>, limit: usize) {
    env.pipe.cfg.begin_upload_threshold_bytes = 0;
    // Replace the owned pipeline without fabricating a second store.
    let (replacement, _, _) = environment();
    env.pipe = std::mem::replace(&mut env.pipe, replacement.pipe)
        .with_inspectors(scanners, limit)
        .unwrap();
}

fn replay(env: &Env, request: &Req) -> Option<ReplayRecord> {
    let auth = env.auth(request).unwrap();
    let partition = env.pipe.shards.ref_shard(&auth.repo().repo, HEAD);
    block_on(read::replay_lookup(
        &env.pipe.meta,
        &partition,
        &ReplayKey(auth.auth.unwrap().replay_scope),
    ))
    .unwrap()
}

fn advance(
    env: &Env,
    owner: &SigningKey,
    identity: &str,
    bytes: &[u8],
    head: Hash,
    tickets: Vec<Hash>,
    nonce: u32,
) -> (Req, Result<AdvanceOutcome, ServerError>) {
    let request = signed(owner, identity, Procedure::AdvanceRefs, nonce);
    let result = block_on(env.pipe.advance_refs_with_tickets(
        &env.auth(&request).unwrap(),
        upd(HEAD, Missing, head),
        upd(PACKMAP, Missing, hash(bytes)),
        tickets,
    ));
    (request, result)
}

fn object_pack(objects: &[Object]) -> Vec<u8> {
    let mut writer = PackWriter::new_raw_only();
    for object in objects {
        writer
            .push_raw(object.id().unwrap(), &serialize(object).unwrap())
            .unwrap();
    }
    writer.finish().unwrap()
}

fn file_fixture() -> (Vec<Object>, Hash, Vec<(Hash, InspectObjectKind, u64)>) {
    let dual = Object::Blob(Blob {
        data: b"dual role".to_vec(),
    });
    let chunk = Object::Blob(Blob {
        data: b"only a chunk".to_vec(),
    });
    let surplus = Object::Blob(Blob {
        data: b"unreachable but inspected".to_vec(),
    });
    let manifest = Object::ChunkedBlob(ChunkedBlob {
        total_size: 21,
        chunk_size: 0,
        chunks: vec![dual.id().unwrap(), chunk.id().unwrap()],
    });
    let tree = Object::Tree(Tree {
        entries: vec![
            TreeEntry {
                name: b"chunked".to_vec(),
                mode: EntryMode::Blob,
                object_hash: manifest.id().unwrap(),
            },
            TreeEntry {
                name: b"direct".to_vec(),
                mode: EntryMode::Blob,
                object_hash: dual.id().unwrap(),
            },
        ],
    });
    let signer = KeyPair::from_seed([9; 32]);
    let mut commit = Commit::new_unannotated(
        tree.id().unwrap(),
        Vec::new(),
        Identity::ed25519(signer.public.0),
        signer.public.0,
        b"inspection".to_vec(),
        42,
        [0; 64],
    );
    commit.signature = sign_commit(&commit, &signer).unwrap().0;
    let commit = Object::Commit(commit);
    let head = commit.id().unwrap();
    let expected = vec![
        (
            dual.id().unwrap(),
            InspectObjectKind::INSPECT_OBJECT_KIND_BLOB,
            serialize(&dual).unwrap().len() as u64,
        ),
        (
            chunk.id().unwrap(),
            InspectObjectKind::INSPECT_OBJECT_KIND_CHUNK,
            serialize(&chunk).unwrap().len() as u64,
        ),
        (
            surplus.id().unwrap(),
            InspectObjectKind::INSPECT_OBJECT_KIND_BLOB,
            serialize(&surplus).unwrap().len() as u64,
        ),
        (
            manifest.id().unwrap(),
            InspectObjectKind::INSPECT_OBJECT_KIND_CHUNKED_FILE,
            serialize(&manifest).unwrap().len() as u64,
        ),
    ];
    (
        vec![tree, commit, dual, chunk, surplus, manifest],
        head,
        expected,
    )
}

fn upload_file_fixture(
    env: &Env,
    owner: &SigningKey,
    identity: &str,
    number: u32,
) -> (Vec<u8>, Hash, Vec<Hash>, Hash) {
    let (objects, head, _) = file_fixture();
    let pack = object_pack(&objects);
    let pack_id = hash(&pack);
    let list = encode_packlist(None, &[pack_id]).unwrap();
    let tickets = vec![
        begin_and_upload(env, owner, identity, &pack, number),
        begin_and_upload(env, owner, identity, &list, number + 1),
    ];
    (list, head, tickets, pack_id)
}

#[test]
fn complete_set_deduplicates_and_every_inspector_receives_one_batch() {
    let (mut env, owner, identity) = environment_with(
        Sharding::Single,
        crate::indexed::IndexedConfig {
            extract_min_bytes: 1,
            ..Default::default()
        },
    );
    let first = Scanner::new("first");
    let second = Scanner::new("second");
    configure(&mut env, vec![first.clone(), second.clone()], 10_000);
    let (objects, head, expected) = file_fixture();
    let full = object_pack(&objects);
    // A second added pack repeats the dual file/chunk object.
    let duplicate = object_pack(&objects[2..3]);
    let list = encode_packlist(None, &[hash(&full), hash(&duplicate)]).unwrap();
    let tickets = [(&full, 10000), (&duplicate, 10001), (&list, 10002)]
        .into_iter()
        .map(|(bytes, n)| begin_and_upload(&env, &owner, &identity, bytes, n))
        .collect();
    let (_, result) = advance(&env, &owner, &identity, &list, head, tickets, 10003);
    assert_eq!(result.unwrap(), AdvanceOutcome::Committed);
    let a = first.calls.lock().unwrap();
    let b = second.calls.lock().unwrap();
    assert_eq!(a.len(), 1);
    assert_eq!(b.len(), 1);
    assert_eq!(a[0].objects, b[0].objects);
    assert_ne!(a[0].id, b[0].id);
    assert_eq!(a[0].objects.len(), expected.len());
    for (id, kind, size) in expected {
        let matching: Vec<_> = a[0]
            .objects
            .iter()
            .filter(|object| object.id.as_deref() == Some(&id[..]))
            .collect();
        assert_eq!(matching.len(), 1);
        assert_eq!(matching[0].kind, Some(kind.into()));
        assert_eq!(matching[0].size, Some(size));
    }
    // Blob extraction is enabled: selecting metadata must also retain objects
    // whose bytes the verifier placed in the global object store.
    assert!(
        block_on(
            env.pipe
                .blobs
                .head(&BlobKey::object(objects[2].id().unwrap()))
        )
        .unwrap()
        .is_some()
    );
}

#[test]
fn reject_dominates_unavailability_and_does_not_publish() {
    let (mut env, owner, identity) = environment();
    let unavailable = Scanner::new("unavailable");
    unavailable.unavailable.store(true, Ordering::SeqCst);
    let mut reject = Scanner::new("reject");
    Arc::get_mut(&mut reject).unwrap().reject = true;
    configure(&mut env, vec![unavailable.clone(), reject.clone()], 10_000);
    let (bytes, head, tickets, _) = upload_file_fixture(&env, &owner, &identity, 10100);
    let (request, result) = advance(
        &env,
        &owner,
        &identity,
        &bytes,
        head,
        tickets.clone(),
        10102,
    );
    assert_eq!(result.unwrap_err().code(), Code::PermissionDenied);
    assert_eq!(unavailable.calls.lock().unwrap().len(), 1);
    assert_eq!(reject.calls.lock().unwrap().len(), 1);
    assert_advance_unmoved(
        &env,
        &env.auth(&request).unwrap().repo().repo,
        &[hash(&bytes)],
    );
    assert!(replay(&env, &request).is_some());
    let (_, retried) = advance(
        &env,
        &owner,
        &identity,
        &bytes,
        head,
        tickets.clone(),
        10102,
    );
    assert_eq!(retried.unwrap_err().code(), Code::PermissionDenied);
    assert_eq!(unavailable.calls.lock().unwrap().len(), 1);
    assert_eq!(reject.calls.lock().unwrap().len(), 1);
}

#[test]
fn unavailable_has_no_replay_and_retry_reuses_inspection_id() {
    let (mut env, owner, identity) = environment();
    let scanner = Scanner::new("retrying");
    scanner.unavailable.store(true, Ordering::SeqCst);
    configure(&mut env, vec![scanner.clone()], 10_000);
    let (bytes, head, tickets, _) = upload_file_fixture(&env, &owner, &identity, 10200);
    let (request, result) = advance(
        &env,
        &owner,
        &identity,
        &bytes,
        head,
        tickets.clone(),
        10202,
    );
    assert_eq!(result.unwrap_err().code(), Code::Unavailable);
    assert!(replay(&env, &request).is_none());
    assert_advance_unmoved(
        &env,
        &env.auth(&request).unwrap().repo().repo,
        &[hash(&bytes)],
    );
    scanner.unavailable.store(false, Ordering::SeqCst);
    let (_, retried) = advance(
        &env,
        &owner,
        &identity,
        &bytes,
        head,
        tickets.clone(),
        10202,
    );
    assert_eq!(retried.unwrap(), AdvanceOutcome::Committed);
    let calls = scanner.calls.lock().unwrap();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0], calls[1]);
}

#[test]
fn inspection_upper_bound_rejects_before_hooks_with_existing_input_limit_replay_behavior() {
    let (mut env, owner, identity) = environment();
    let scanner = Scanner::new("bounded");
    configure(&mut env, vec![scanner.clone()], 5);
    let (bytes, head, tickets, pack_id) = upload_file_fixture(&env, &owner, &identity, 10300); // Six entries, four files.
    let (request, result) = advance(
        &env,
        &owner,
        &identity,
        &bytes,
        head,
        tickets.clone(),
        10302,
    );
    assert_eq!(result.unwrap_err().code(), Code::InvalidArgument);
    assert!(scanner.calls.lock().unwrap().is_empty());
    assert_advance_unmoved(
        &env,
        &env.auth(&request).unwrap().repo().repo,
        &[hash(&bytes)],
    );
    let repo = env.auth(&request).unwrap().repo().repo.clone();
    let source = env.pipe.shards.ref_shard(&repo, HEAD);
    assert!(
        block_on(
            env.pipe
                .meta
                .get(&source, &keys::verification(&repo.name, &pack_id))
        )
        .unwrap()
        .is_none(),
        "the header limit precedes whole-pack verification/enumeration"
    );
    assert!(replay(&env, &request).is_none());
    let (_, retry) = advance(
        &env,
        &owner,
        &identity,
        &bytes,
        head,
        tickets.clone(),
        10302,
    );
    assert_eq!(retry.unwrap_err().code(), Code::InvalidArgument);
    assert!(scanner.calls.lock().unwrap().is_empty());
}

#[test]
fn exactly_at_inspection_upper_bound_is_accepted() {
    let (mut env, owner, identity) = environment();
    let scanner = Scanner::new("bounded");
    configure(&mut env, vec![scanner.clone()], 6);
    let (bytes, head, tickets, _) = upload_file_fixture(&env, &owner, &identity, 10400);
    let (_, result) = advance(
        &env,
        &owner,
        &identity,
        &bytes,
        head,
        tickets.clone(),
        10402,
    );
    assert_eq!(result.unwrap(), AdvanceOutcome::Committed);
    assert_eq!(scanner.calls.lock().unwrap().len(), 1);
}

#[test]
fn exactly_ten_thousand_distinct_file_objects_are_inspected_and_accepted() {
    let (mut env, owner, identity) = environment();
    let (initial_pack, head) = pack();
    let initial_map = encode_packlist(None, &[hash(&initial_pack)]).unwrap();
    let initial_tickets = vec![
        begin_and_upload(&env, &owner, &identity, &initial_pack, 10700),
        begin_and_upload(&env, &owner, &identity, &initial_map, 10701),
    ];
    let (_, initial) = advance(
        &env,
        &owner,
        &identity,
        &initial_map,
        head,
        initial_tickets,
        10702,
    );
    assert_eq!(initial.unwrap(), AdvanceOutcome::Committed);

    let scanner = Scanner::new("ten-thousand");
    configure(&mut env, vec![scanner.clone()], 10_000);
    let objects: Vec<_> = (0_u32..10_000)
        .map(|number| {
            Object::Blob(Blob {
                data: number.to_le_bytes().to_vec(),
            })
        })
        .collect();
    let added_pack = object_pack(&objects);
    let added_map = encode_packlist(Some(hash(&initial_map)), &[hash(&added_pack)]).unwrap();
    let tickets = vec![
        begin_and_upload(&env, &owner, &identity, &added_pack, 10703),
        begin_and_upload(&env, &owner, &identity, &added_map, 10704),
    ];
    let request = signed(&owner, &identity, Procedure::AdvanceRefs, 10705);
    assert_eq!(
        block_on(env.pipe.advance_refs_with_tickets(
            &env.auth(&request).unwrap(),
            upd(HEAD, Match(head), head),
            upd(PACKMAP, Match(hash(&initial_map)), hash(&added_map)),
            tickets,
        ))
        .unwrap(),
        AdvanceOutcome::Committed
    );
    let calls = scanner.calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].objects.len(), 10_000);
    let seen: std::collections::BTreeSet<_> = calls[0]
        .objects
        .iter()
        .map(|object| {
            assert_eq!(
                object.kind,
                Some(InspectObjectKind::INSPECT_OBJECT_KIND_BLOB.into())
            );
            object.id.clone().unwrap()
        })
        .collect();
    let expected: std::collections::BTreeSet<_> = objects
        .iter()
        .map(|object| object.id().unwrap().to_vec())
        .collect();
    assert_eq!(seen, expected);
}

#[test]
fn launch_configuration_refuses_incompatible_inspectors_and_modes() {
    for case in 0..9 {
        let (mut env, _, _) = environment();
        env.pipe.cfg.begin_upload_threshold_bytes = 0;
        let mut scanner = Scanner::new("configured");
        let mut limit = 10_000;
        match case {
            0 => Arc::get_mut(&mut scanner).unwrap().phase = InspectorPhase::Async,
            1 => Arc::get_mut(&mut scanner).unwrap().availability = OnUnavailable::Publish,
            2 => env.pipe.cfg.write_policy = WritePolicy::Open,
            3 => env.pipe.cfg.indexed = None,
            4 => env.pipe.cfg.ticket_keys = None,
            5 => env.pipe.cfg.begin_upload_threshold_bytes = 1,
            6 => limit = 0,
            7 => limit = 10_001,
            _ => {}
        }
        let scanners: Vec<Arc<dyn ContentInspector>> = if case == 8 {
            (0..5)
                .map(|n| Scanner::new(&format!("scanner-{n}")) as Arc<dyn ContentInspector>)
                .collect()
        } else {
            vec![scanner]
        };
        assert!(
            env.pipe.with_inspectors(scanners, limit).is_err(),
            "case {case}"
        );
    }
}

#[test]
fn empty_inspector_configuration_preserves_b4_backend_calls_and_apply_bytes() {
    let mut observed = Vec::new();
    for configured in [false, true] {
        let (mut env, owner, identity) = environment();
        if configured {
            configure(&mut env, Vec::new(), 10_000);
        }
        let (bytes, head) = pack();
        let ticket = begin_and_upload(&env, &owner, &identity, &bytes, 10500);
        let (_, result) = advance(&env, &owner, &identity, &bytes, head, vec![ticket], 10501);
        assert_eq!(result.unwrap(), AdvanceOutcome::Committed);
        observed.push((
            env.pipe.meta.ops(),
            env.pipe.meta.seen(),
            env.pipe.meta.batches.lock().unwrap().clone(),
        ));
    }
    assert_eq!(observed[0], observed[1]);
}

#[test]
fn four_inspectors_are_accepted_and_deletion_skips_them() {
    let (mut env, owner, identity) = environment();
    let scanners: Vec<_> = (0..4)
        .map(|n| Scanner::new(&format!("scanner-{n}")))
        .collect();
    configure(
        &mut env,
        scanners
            .iter()
            .cloned()
            .map(|scanner| scanner as Arc<dyn ContentInspector>)
            .collect(),
        10_000,
    );
    let (bytes, head, tickets, _) = upload_file_fixture(&env, &owner, &identity, 10600);
    let (_, result) = advance(
        &env,
        &owner,
        &identity,
        &bytes,
        head,
        tickets.clone(),
        10602,
    );
    assert_eq!(result.unwrap(), AdvanceOutcome::Committed);
    for scanner in &scanners {
        assert_eq!(scanner.calls.lock().unwrap().len(), 1);
        scanner.unavailable.store(true, Ordering::SeqCst);
    }
    let request = signed(&owner, &identity, Procedure::AdvanceRefs, 10603);
    let remove = |name: &str, target| RefUpdate {
        name: name.into(),
        condition: Match(target),
        new: None,
    };
    assert_eq!(
        block_on(env.pipe.advance_refs(
            &env.auth(&request).unwrap(),
            remove(HEAD, head),
            remove(PACKMAP, hash(&bytes))
        ))
        .unwrap(),
        AdvanceOutcome::Committed
    );
    for scanner in scanners {
        assert_eq!(scanner.calls.lock().unwrap().len(), 1);
    }
}

fn tree_commit(entries: Vec<TreeEntry>, parents: Vec<Hash>) -> (Object, Object, Hash) {
    let tree = Object::Tree(Tree { entries });
    let signer = KeyPair::from_seed([9; 32]);
    let mut commit = Commit::new_unannotated(
        tree.id().unwrap(),
        parents,
        Identity::ed25519(signer.public.0),
        signer.public.0,
        b"existing file inspection".to_vec(),
        42,
        [0; 64],
    );
    commit.signature = sign_commit(&commit, &signer).unwrap().0;
    let commit = Object::Commit(commit);
    let head = commit.id().unwrap();
    (tree, commit, head)
}

struct ExistingFilesAdvance {
    env: Env,
    owner: SigningKey,
    identity: String,
    old_head: Hash,
    old_map: Hash,
    new_head: Hash,
    new_map: Hash,
    added_pack: Hash,
    candidate_pack: Hash,
    candidate: Hash,
    published: Hash,
    tickets: Vec<Hash>,
}

impl ExistingFilesAdvance {
    fn new(scanner: Arc<Scanner>, limit: usize) -> Self {
        let (mut env, owner, identity) = environment();
        let published = Object::Blob(Blob {
            data: b"published file".to_vec(),
        });
        let candidate = Object::Blob(Blob {
            data: b"newly reachable existing file".to_vec(),
        });
        let entry = |name: &[u8], object: &Object| TreeEntry {
            name: name.to_vec(),
            mode: EntryMode::Blob,
            object_hash: object.id().unwrap(),
        };
        let (old_tree, old_commit, old_head) =
            tree_commit(vec![entry(b"published", &published)], vec![]);
        let initial_pack = object_pack(&[old_tree, old_commit, published.clone()]);
        let candidate_pack = object_pack(std::slice::from_ref(&candidate));
        let old_map = encode_packlist(None, &[hash(&initial_pack), hash(&candidate_pack)]).unwrap();
        let initial_tickets = [
            (&initial_pack, 10800),
            (&candidate_pack, 10801),
            (&old_map, 10802),
        ]
        .into_iter()
        .map(|(bytes, n)| begin_and_upload(&env, &owner, &identity, bytes, n))
        .collect();
        let (_, initial) = advance(
            &env,
            &owner,
            &identity,
            &old_map,
            old_head,
            initial_tickets,
            10803,
        );
        assert_eq!(initial.unwrap(), AdvanceOutcome::Committed);

        // Seed the full-profile state this launch consumer must correctly read:
        // the old pack is live to writers but has not acquired published membership.
        let auth = env
            .auth(&signed(&owner, &identity, Procedure::AdvanceRefs, 10804))
            .unwrap();
        let repo = &auth.repo().repo;
        let source = env.pipe.shards.ref_shard(repo, HEAD);
        let key = keys::membership(&repo.name, &hash(&candidate_pack));
        let raw = block_on(env.pipe.meta.inner.get(&source, &key))
            .unwrap()
            .unwrap();
        let mut witness = crate::store::publication::Witness::decode(&raw).unwrap();
        witness.published = false;
        block_on(
            env.pipe
                .meta
                .inner
                .apply(&source, Batch::new().put(key, witness.encode())),
        )
        .unwrap();
        configure(&mut env, vec![scanner], limit);

        let (tree, commit, new_head) = tree_commit(
            vec![entry(b"new", &candidate), entry(b"published", &published)],
            vec![old_head],
        );
        let added_pack = object_pack(&[tree, commit]);
        let new_map = encode_packlist(Some(hash(&old_map)), &[hash(&added_pack)]).unwrap();
        let tickets = vec![
            begin_and_upload(&env, &owner, &identity, &added_pack, 10805),
            begin_and_upload(&env, &owner, &identity, &new_map, 10806),
        ];
        Self {
            env,
            owner,
            identity,
            old_head,
            old_map: hash(&old_map),
            new_head,
            new_map: hash(&new_map),
            added_pack: hash(&added_pack),
            candidate_pack: hash(&candidate_pack),
            candidate: candidate.id().unwrap(),
            published: published.id().unwrap(),
            tickets,
        }
    }

    fn run(&self) -> (Req, Result<AdvanceOutcome, ServerError>) {
        let request = signed(&self.owner, &self.identity, Procedure::AdvanceRefs, 10807);
        let result = block_on(self.env.pipe.advance_refs_with_tickets(
            &self.env.auth(&request).unwrap(),
            upd(HEAD, Match(self.old_head), self.new_head),
            upd(PACKMAP, Match(self.old_map), self.new_map),
            self.tickets.clone(),
        ));
        (request, result)
    }

    fn assert_unmoved(&self) {
        let auth = self
            .env
            .auth(&signed(
                &self.owner,
                &self.identity,
                Procedure::AdvanceRefs,
                10807,
            ))
            .unwrap();
        let repo = &auth.repo().repo;
        let source = self.env.pipe.shards.ref_shard(repo, HEAD);
        for (name, target) in [(HEAD, self.old_head), (PACKMAP, self.old_map)] {
            assert_eq!(
                block_on(
                    self.env
                        .pipe
                        .meta
                        .get(&source, &keys::ref_key(&repo.name, name))
                )
                .unwrap(),
                Some(codec::encode_ref_id(&target))
            );
        }
        for pack in [self.added_pack, self.new_map] {
            assert!(
                block_on(
                    self.env
                        .pipe
                        .meta
                        .get(&source, &keys::membership(&repo.name, &pack))
                )
                .unwrap()
                .is_none()
            );
        }
    }

    fn publish_existing_pack(&self) {
        let auth = self
            .env
            .auth(&signed(
                &self.owner,
                &self.identity,
                Procedure::AdvanceRefs,
                10807,
            ))
            .unwrap();
        let repo = &auth.repo().repo;
        let source = self.env.pipe.shards.ref_shard(repo, HEAD);
        let key = keys::membership(&repo.name, &self.candidate_pack);
        let raw = block_on(self.env.pipe.meta.inner.get(&source, &key))
            .unwrap()
            .unwrap();
        let mut witness = crate::store::publication::Witness::decode(&raw).unwrap();
        witness.published = true;
        block_on(
            self.env
                .pipe
                .meta
                .inner
                .apply(&source, Batch::new().put(key, witness.encode())),
        )
        .unwrap();
    }
}

#[test]
fn newly_reachable_existing_file_is_inspected_and_published_files_are_excluded() {
    let scanner = Scanner::new("existing-files");
    let fixture = ExistingFilesAdvance::new(scanner.clone(), 3); // Two added entries + one existing file.
    assert_eq!(fixture.run().1.unwrap(), AdvanceOutcome::Committed);
    let calls = scanner.calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].objects.len(), 1);
    assert_eq!(
        calls[0].objects[0].id.as_deref(),
        Some(&fixture.candidate[..])
    );
    assert!(
        !calls[0]
            .objects
            .iter()
            .any(|object| object.id.as_deref() == Some(&fixture.published[..]))
    );
}

#[test]
fn newly_reachable_existing_file_counts_toward_upper_bound_before_hooks_and_apply() {
    let scanner = Scanner::new("bounded-existing-files");
    let fixture = ExistingFilesAdvance::new(scanner.clone(), 2);
    let (request, result) = fixture.run();
    let error = result.unwrap_err();
    assert_eq!(error.code(), Code::InvalidArgument);
    assert_eq!(error.public_message(), "object index limit exceeded");
    assert!(scanner.calls.lock().unwrap().is_empty());
    assert!(replay(&fixture.env, &request).is_none());
    fixture.assert_unmoved();
}

#[test]
fn unavailable_retry_uses_new_inspection_id_for_a_changed_logical_batch() {
    let scanner = Scanner::new("membership-retry");
    scanner.unavailable.store(true, Ordering::SeqCst);
    let fixture = ExistingFilesAdvance::new(scanner.clone(), 3);
    let (request, result) = fixture.run();
    assert_eq!(result.unwrap_err().code(), Code::Unavailable);
    assert!(replay(&fixture.env, &request).is_none());
    fixture.assert_unmoved();
    fixture.publish_existing_pack();
    scanner.unavailable.store(false, Ordering::SeqCst);
    assert_eq!(fixture.run().1.unwrap(), AdvanceOutcome::Committed);
    let calls = scanner.calls.lock().unwrap();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].objects.len(), 1);
    assert!(calls[1].objects.is_empty());
    // Publishing existing membership changes this batch's immutable content.
    // An inspector's cached result for the earlier batch must not be reused.
    assert_ne!(calls[0].id, calls[1].id);
}
