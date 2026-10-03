//! Real publication, retained evidence, and upgrade/security regressions.
use super::indexed::{environment_with, signed_at, upload};
use super::*;
use crate::store::{BorrowedStore, publication, publication_certificate as cert};
use mkit_core::object::{Blob, Commit, EntryMode, Identity, Object, Tree, TreeEntry};
use mkit_core::pack::PackWriter;
use mkit_core::serialize::serialize;
use mkit_core::sign::{KeyPair, sign_commit};

fn commit(tree: Hash, parent: Option<Hash>, number: u64) -> Object {
    let key = KeyPair::from_seed([9; 32]);
    let mut value = Commit::new_unannotated(
        tree,
        parent.into_iter().collect(),
        Identity::ed25519(key.public.0),
        key.public.0,
        b"publication".to_vec(),
        number,
        [0; 64],
    );
    value.signature = sign_commit(&value, &key).unwrap().0;
    Object::Commit(value)
}
fn pack(objects: &[Object]) -> Vec<u8> {
    let mut writer = PackWriter::new_raw_only();
    for object in objects {
        writer
            .push_raw(object.id().unwrap(), &serialize(object).unwrap())
            .unwrap();
    }
    writer.finish().unwrap()
}
fn fixture(count: u32) -> (Vec<u8>, Hash, Hash, Hash) {
    let mut objects: Vec<_> = (0..count)
        .map(|n| {
            Object::Blob(Blob {
                data: n.to_be_bytes().repeat(4),
            })
        })
        .collect();
    let last = objects.last().unwrap().id().unwrap();
    let tree = Object::Tree(Tree {
        entries: objects
            .iter()
            .enumerate()
            .map(|(n, o)| TreeEntry {
                name: format!("f{n:06}").into_bytes(),
                mode: EntryMode::Blob,
                object_hash: o.id().unwrap(),
            })
            .collect(),
    });
    let tree_id = tree.id().unwrap();
    let head = commit(tree_id, None, 1);
    let id = head.id().unwrap();
    objects.extend([tree, head]);
    (pack(&objects), id, tree_id, last)
}
fn ticket(env: &Env, owner: &SigningKey, identity: &str, bytes: &[u8], nonce: u32) -> Hash {
    let request = signed_at(
        owner,
        identity,
        Procedure::BeginUpload,
        nonce,
        env.clock.now_ms(),
    );
    let BeginUploadResult::Ticket { id, .. } = block_on(env.pipe.begin_upload(
        &env.auth(&request).unwrap(),
        HEAD,
        &hash(bytes),
        bytes.len() as u64,
    ))
    .unwrap() else {
        panic!("ticket")
    };
    upload(env, bytes, id);
    id
}
#[allow(clippy::too_many_arguments)]
fn publish(
    env: &Env,
    owner: &SigningKey,
    identity: &str,
    old: &publication::Pair,
    head: Hash,
    map: Hash,
    tickets: &[Hash],
    nonce: u32,
) -> (u32, u32) {
    let request = signed_at(
        owner,
        identity,
        Procedure::AdvanceRefs,
        nonce,
        env.clock.now_ms(),
    );
    let repo = env.auth(&request).unwrap().repo().repo.clone();
    let source = env.pipe.shards.ref_shard(&repo, HEAD);
    let alarm_budget = crate::purge::SliceBudget::new(128);
    let registry = crate::timers::TimerRegistry::new().register(
        crate::timers::publication_recheck::PublicationRecheck::new(BorrowedStore(&env.pipe.meta))
            .with_alarm_budget(alarm_budget.clone()),
    );
    let before = env.pipe.meta.calls();
    let mut slices = 0;
    for round in 0..20_000 {
        let request = signed_at(
            owner,
            identity,
            Procedure::AdvanceRefs,
            nonce + round,
            env.clock.now_ms(),
        );
        let result = block_on(env.pipe.advance_refs_with_tickets(
            &env.auth(&request).unwrap(),
            upd(HEAD, old.head.map_or(Missing, Match), head),
            upd(PACKMAP, old.packmap.map_or(Missing, Match), map),
            tickets.to_vec(),
        ));
        match result {
            Ok(AdvanceOutcome::Committed) => {
                let published =
                    block_on(publication::read(&env.pipe.meta, &source, &repo.name, HEAD)).unwrap();
                assert_eq!(
                    published.value,
                    publication::Pair {
                        head: Some(head),
                        packmap: Some(map)
                    }
                );
                assert_eq!(published.published, published.sequence);
                return (env.pipe.meta.calls() - before, slices);
            }
            Err(error) if error.public_message() == "pack verification pending" => {
                assert_eq!(
                    block_on(publication::read(&env.pipe.meta, &source, &repo.name, HEAD))
                        .unwrap()
                        .value,
                    *old
                );
                env.clock.advance(1000);
                let before = env.pipe.meta.calls();
                alarm_budget.reset();
                block_on(crate::timers::run_due(
                    &env.pipe.meta,
                    &source,
                    &registry,
                    env.clock.as_ref(),
                    u64::try_from(env.clock.now_ms()).unwrap(),
                    &crate::timers::TickBudget::new(1, 1, 64, 10_000),
                ))
                .unwrap();
                assert!(
                    env.pipe.meta.calls() - before <= 136 && alarm_budget.used() <= 128,
                    "128 verification calls plus bounded timer enumeration and source settlement: {}, round {round}",
                    env.pipe.meta.calls() - before
                );
                slices += 1;
            }
            other => panic!("publication failed: {other:?}"),
        }
    }
    panic!("publication must finish")
}
fn page_bytes(env: &Env) -> (usize, usize) {
    let mut unique = std::collections::BTreeMap::new();
    for batch in env.pipe.meta.batches.lock().unwrap().iter() {
        for write in &batch.writes {
            if let Write::Put(key, value) = write
                && matches!(
                    keys::parse(key),
                    Some(
                        keys::ParsedKey::PublicationPage(_)
                            | keys::ParsedKey::PublicationCertificate(_)
                    )
                )
            {
                unique.insert(key.clone(), value.as_bytes().len());
            }
        }
    }
    (unique.len(), unique.values().sum())
}

fn published_fixture(count: u32) -> (Env, SigningKey, String, Hash, Hash, Hash, Hash) {
    let (mut env, owner, identity) =
        environment_with(Sharding::Single, crate::indexed::IndexedConfig::default());
    env.pipe.cfg.begin_upload_threshold_bytes = 0;
    env.pipe.cfg.takedown_denial = true;
    let (bytes, head, tree, leaf) = fixture(count);
    let map_bytes = mkit_core::transfer::encode_packlist(None, &[hash(&bytes)]).unwrap();
    let map = hash(&map_bytes);
    let tickets = [
        ticket(&env, &owner, &identity, &bytes, 200_000),
        ticket(&env, &owner, &identity, &map_bytes, 200_001),
    ];
    publish(
        &env,
        &owner,
        &identity,
        &publication::Pair::default(),
        head,
        map,
        &tickets,
        201_000,
    );
    (env, owner, identity, head, map, tree, leaf)
}

fn same_pair(
    env: &Env,
    owner: &SigningKey,
    identity: &str,
    head: Hash,
    map: Hash,
    nonce: u32,
) -> Result<AdvanceOutcome, ServerError> {
    let request = signed_at(
        owner,
        identity,
        Procedure::AdvanceRefs,
        nonce,
        env.clock.now_ms(),
    );
    block_on(env.pipe.advance_refs_with_tickets(
        &env.auth(&request).unwrap(),
        upd(HEAD, Match(head), head),
        upd(PACKMAP, Match(map), map),
        vec![],
    ))
}

fn inventory_seal(env: &Env, pack: Hash) -> (Partition, Key, Value) {
    let partition = crate::store::content_shard(&pack);
    let key = Key::new([keys::block(&pack).as_bytes(), b"\0inventory-head"].concat());
    let raw = block_on(env.pipe.meta.inner.get(&partition, &key))
        .unwrap()
        .unwrap();
    (partition, key, raw)
}

#[test]
fn v050_upgrade_builds_certificate_without_rewriting_sealed_inventory() {
    let (mut env, owner, identity) =
        environment_with(Sharding::Single, crate::indexed::IndexedConfig::default());
    env.pipe.cfg.begin_upload_threshold_bytes = 0;
    let (bytes, head, _, _) = fixture(80);
    let map_bytes = mkit_core::transfer::encode_packlist(None, &[hash(&bytes)]).unwrap();
    let map = hash(&map_bytes);
    let tickets = [
        ticket(&env, &owner, &identity, &bytes, 240_000),
        ticket(&env, &owner, &identity, &map_bytes, 240_001),
    ];
    publish(
        &env,
        &owner,
        &identity,
        &publication::Pair::default(),
        head,
        map,
        &tickets,
        241_000,
    );
    let request = signed_at(
        &owner,
        &identity,
        Procedure::AdvanceRefs,
        242_000,
        env.clock.now_ms(),
    );
    let repo = env.auth(&request).unwrap().repo().repo.clone();
    let source = env.pipe.shards.ref_shard(&repo, HEAD);
    let key = keys::publication(&repo.name, HEAD);
    let raw = block_on(env.pipe.meta.get(&source, &key)).unwrap().unwrap();
    assert!(publication::stored(&raw).unwrap().1.is_none());
    let seals = [
        inventory_seal(&env, hash(&bytes)),
        inventory_seal(&env, map),
    ];
    let (_, prev, packs) = block_on(crate::takedown::inventory::packlist_facts(
        &env.pipe.meta,
        &map,
    ))
    .unwrap();
    assert!(prev.is_none());
    assert_eq!(packs, vec![hash(&bytes)]);
    let row = block_on(crate::takedown::inventory::entry(
        &env.pipe.meta,
        &hash(&bytes),
        &head,
    ))
    .unwrap()
    .unwrap();
    assert!(row.canonical_len > 0);
    env.pipe.cfg.takedown_denial = true;
    let (_, slices) = publish(
        &env,
        &owner,
        &identity,
        &publication::Pair {
            head: Some(head),
            packmap: Some(map),
        },
        head,
        map,
        &[],
        243_000,
    );
    assert!(slices > 1);
    for (p, key, raw) in seals {
        assert_eq!(block_on(env.pipe.meta.get(&p, &key)).unwrap(), Some(raw));
    }
    let raw = block_on(env.pipe.meta.get(&source, &key)).unwrap().unwrap();
    assert!(publication::stored(&raw).unwrap().1.is_some());
}

#[test]
fn absent_anchor_bootstraps_but_missing_and_corrupt_certificates_refuse() {
    for fault in 0..4 {
        let (env, owner, identity, head, map, _, _) = published_fixture(80);
        let request = signed_at(
            &owner,
            &identity,
            Procedure::AdvanceRefs,
            220_000,
            env.clock.now_ms(),
        );
        let repo = env.auth(&request).unwrap().repo().repo.clone();
        let source = env.pipe.shards.ref_shard(&repo, HEAD);
        let key = keys::publication(&repo.name, HEAD);
        let raw = block_on(env.pipe.meta.get(&source, &key)).unwrap().unwrap();
        let (plain, evidence) = publication::stored(&raw).unwrap();
        let evidence = evidence.unwrap();
        let header = block_on(cert::Header::read(&env.pipe.meta, &evidence.certificate)).unwrap();
        let (partition, batch) = match fault {
            0 => (source.clone(), Batch::new().put(key.clone(), plain)),
            1 => (
                crate::store::content_shard(&evidence.certificate),
                Batch::new().delete(keys::publication_certificate(&evidence.certificate)),
            ),
            3 => {
                let wrong = cert::Header::new(
                    &repo,
                    0,
                    publication::Pair::default(),
                    crate::indexed::IndexedConfig::default().max_delta_chain_depth,
                    header.root(),
                )
                .with_support(header.support_root());
                let address = block_on(
                    wrong.write(&env.pipe.meta, u64::try_from(env.clock.now_ms()).unwrap()),
                )
                .unwrap();
                let mut row: serde_json::Value =
                    serde_json::from_slice(&raw.as_bytes()[1..]).unwrap();
                row["certificate"]["certificate"] = serde_json::to_value(address).unwrap();
                let mut bytes = vec![raw.as_bytes()[0]];
                bytes.extend(serde_json::to_vec(&row).unwrap());
                (
                    source.clone(),
                    Batch::new().put(key.clone(), Value::new(bytes)),
                )
            }
            _ => {
                let root = header.root().unwrap();
                (
                    crate::store::content_shard(&root),
                    Batch::new().put(keys::publication_page(&root), Value::new(vec![1, 0])),
                )
            }
        };
        assert_eq!(
            block_on(env.pipe.meta.inner.apply(&partition, batch)).unwrap(),
            BatchOutcome::Committed
        );
        let prior = block_on(publication::read(&env.pipe.meta, &source, &repo.name, HEAD)).unwrap();
        if fault == 0 {
            let (_, slices) = publish(
                &env,
                &owner,
                &identity,
                &prior.value,
                head,
                map,
                &[],
                221_000,
            );
            assert!(slices > 1);
            let raw = block_on(env.pipe.meta.get(&source, &key)).unwrap().unwrap();
            assert!(publication::stored(&raw).unwrap().1.is_some());
        } else {
            let error = same_pair(&env, &owner, &identity, head, map, 221_000).unwrap_err();
            assert_eq!(error.code(), Code::Unavailable);
            assert_eq!(
                block_on(publication::read(&env.pipe.meta, &source, &repo.name, HEAD)).unwrap(),
                prior
            );
        }
    }
}

fn denied_reference(new_tree: bool) {
    let (env, owner, identity, head, map, tree, leaf) = published_fixture(300);
    let new = Object::Tree(Tree {
        entries: vec![TreeEntry {
            name: b"denied".to_vec(),
            mode: EntryMode::Blob,
            object_hash: leaf,
        }],
    });
    let object = commit(
        if new_tree { new.id().unwrap() } else { tree },
        Some(head),
        2,
    );
    let bytes = if new_tree {
        pack(&[new, object.clone()])
    } else {
        pack(std::slice::from_ref(&object))
    };
    let old_pack = block_on(crate::takedown::inventory::packlist_facts(
        &env.pipe.meta,
        &map,
    ))
    .unwrap()
    .2[0];
    let inventory = [keys::block(&old_pack).as_bytes(), b"\0inventory\0"].concat();
    let map_bytes = mkit_core::transfer::encode_packlist(Some(map), &[hash(&bytes)]).unwrap();
    let tickets = [
        ticket(&env, &owner, &identity, &bytes, 230_000),
        ticket(&env, &owner, &identity, &map_bytes, 230_001),
    ];
    let action = crate::takedown::denial::BlockAction {
        id: [81; 32],
        takedown_id: [82; 32],
        reason: "denied".into(),
        blocked_at_ms: u64::try_from(env.clock.now_ms()).unwrap(),
        chunk_ids: vec![],
    };
    block_on(
        crate::store::ContentIndex::new(BorrowedStore(&env.pipe.meta)).install_block_action(
            &leaf,
            &action,
            action.blocked_at_ms,
        ),
    )
    .unwrap();
    let before = env.pipe.meta.calls();
    let seen = env.pipe.meta.seen().len();
    for round in 0..100 {
        let request = signed_at(
            &owner,
            &identity,
            Procedure::AdvanceRefs,
            231_000 + round,
            env.clock.now_ms(),
        );
        let auth = env.auth(&request).unwrap();
        let result = block_on(env.pipe.advance_refs_with_tickets(
            &auth,
            upd(HEAD, Match(head), object.id().unwrap()),
            upd(PACKMAP, Match(map), hash(&map_bytes)),
            tickets.to_vec(),
        ));
        match result {
            Err(e) if e.public_message() == "pack verification pending" => env.clock.advance(1000),
            Err(e) => {
                assert_eq!(e.code(), Code::PermissionDenied);
                assert!(env.pipe.meta.calls() - before < 1500);
                assert!(
                    !env.pipe.meta.seen()[seen..]
                        .iter()
                        .any(|k| k.as_bytes().starts_with(&inventory))
                );
                let source = env.pipe.shards.ref_shard(&auth.repo().repo, HEAD);
                assert_eq!(
                    block_on(publication::read(
                        &env.pipe.meta,
                        &source,
                        &auth.repo().repo.name,
                        HEAD
                    ))
                    .unwrap()
                    .value,
                    publication::Pair {
                        head: Some(head),
                        packmap: Some(map)
                    }
                );
                return;
            }
            other => panic!("denied inherited object published: {other:?}"),
        }
    }
    panic!("denial must finish within bounded new work")
}
#[test]
fn takedown_publication_over_4096_objects_reuses_history_with_bounded_growth() {
    let (mut env, owner, identity) =
        environment_with(Sharding::Single, crate::indexed::IndexedConfig::default());
    env.pipe.cfg.begin_upload_threshold_bytes = 0;
    env.pipe.cfg.takedown_denial = false;
    let (bytes, mut head, tree, _) = fixture(4200);
    let map_bytes = mkit_core::transfer::encode_packlist(None, &[hash(&bytes)]).unwrap();
    let mut map = hash(&map_bytes);
    let tickets = vec![
        ticket(&env, &owner, &identity, &bytes, 80000),
        ticket(&env, &owner, &identity, &map_bytes, 80001),
    ];
    publish(
        &env,
        &owner,
        &identity,
        &publication::Pair::default(),
        head,
        map,
        &tickets,
        81000,
    );
    env.pipe.cfg.takedown_denial = true;
    let (_, slices) = publish(
        &env,
        &owner,
        &identity,
        &publication::Pair {
            head: Some(head),
            packmap: Some(map),
        },
        head,
        map,
        &[],
        90_000,
    );
    assert!(slices > 1);
    for n in 0..3 {
        let object = commit(tree, Some(head), 2 + n);
        let bytes = pack(std::slice::from_ref(&object));
        let map_bytes = mkit_core::transfer::encode_packlist(Some(map), &[hash(&bytes)]).unwrap();
        let tickets = vec![
            ticket(
                &env,
                &owner,
                &identity,
                &bytes,
                100_000 + u32::try_from(n).unwrap() * 100,
            ),
            ticket(
                &env,
                &owner,
                &identity,
                &map_bytes,
                100_001 + u32::try_from(n).unwrap() * 100,
            ),
        ];
        let before = page_bytes(&env);
        let (calls, _) = publish(
            &env,
            &owner,
            &identity,
            &publication::Pair {
                head: Some(head),
                packmap: Some(map),
            },
            object.id().unwrap(),
            hash(&map_bytes),
            &tickets,
            100_010 + u32::try_from(n).unwrap() * 100,
        );
        assert!(
            calls < 1500,
            "one new commit/map/pack must not re-walk 4202 inherited objects: {calls}"
        );
        let after = page_bytes(&env);
        assert!(after.0 - before.0 <= 3 * 68 + 4);
        assert!(
            after.1 - before.1 <= 3 * 68 * cert::MAX_PAGE_BYTES + cert::MAX_HEADER_BYTES + 4 * 4261
        );
        head = object.id().unwrap();
        map = hash(&map_bytes);
    }
}
#[test]
fn custom_policy_publication_with_hundreds_of_reachable_objects_completes() {
    let (mut env, owner, identity) =
        environment_with(Sharding::Single, crate::indexed::IndexedConfig::default());
    env.pipe.cfg.begin_upload_threshold_bytes = 0;
    env.pipe.publication_policy = Some(Arc::new(clearance::Immediate));
    let (bytes, head, _, _) = fixture(300);
    let map_bytes = mkit_core::transfer::encode_packlist(None, &[hash(&bytes)]).unwrap();
    let tickets = vec![
        ticket(&env, &owner, &identity, &bytes, 130_000),
        ticket(&env, &owner, &identity, &map_bytes, 130_001),
    ];
    let (_, slices) = publish(
        &env,
        &owner,
        &identity,
        &publication::Pair::default(),
        head,
        hash(&map_bytes),
        &tickets,
        130_010,
    );
    assert!(slices > 1);
}

#[test]
fn a_large_advance_finishes_its_proof_on_alarms_without_foreground_walks() {
    let (mut env, owner, identity) =
        environment_with(Sharding::Single, crate::indexed::IndexedConfig::default());
    env.pipe.cfg.begin_upload_threshold_bytes = 0;
    env.pipe.cfg.takedown_denial = true;
    let (bytes, head, _, _) = fixture(300);
    let node = mkit_core::transfer::encode_packlist(None, &[hash(&bytes)]).unwrap();
    let map = hash(&node);
    let tickets = [
        ticket(&env, &owner, &identity, &bytes, 270_000),
        ticket(&env, &owner, &identity, &node, 270_001),
    ];
    let request = signed_at(
        &owner,
        &identity,
        Procedure::AdvanceRefs,
        271_000,
        env.clock.now_ms(),
    );
    let auth = env.auth(&request).unwrap();
    assert_eq!(
        block_on(env.pipe.advance_refs_with_tickets(
            &auth,
            upd(HEAD, Missing, head),
            upd(PACKMAP, Missing, map),
            tickets.to_vec()
        ))
        .unwrap_err()
        .public_message(),
        "pack verification pending"
    );
    let repo = auth.repo().repo.clone();
    let source = env.pipe.shards.ref_shard(&repo, HEAD);
    let budget = crate::purge::SliceBudget::new(128);
    let registry = crate::timers::TimerRegistry::new().register(
        crate::timers::publication_recheck::PublicationRecheck::new(BorrowedStore(&env.pipe.meta))
            .with_alarm_budget(budget.clone()),
    );
    let mut fires = 0;
    loop {
        let (state, _) = block_on(crate::indexed::state::read(
            &env.pipe.meta,
            &source,
            &repo.name,
            &map,
        ))
        .unwrap()
        .unwrap();
        let progress = serde_json::to_value(state).unwrap();
        if !progress["publication"]["incremental"]["complete"].is_null() {
            break;
        }
        env.clock.advance(1000);
        budget.reset();
        block_on(crate::timers::run_due(
            &env.pipe.meta,
            &source,
            &registry,
            env.clock.as_ref(),
            u64::try_from(env.clock.now_ms()).unwrap(),
            &crate::timers::TickBudget::new(1, 1, 64, 10_000),
        ))
        .unwrap();
        assert!(budget.used() <= 128);
        assert_eq!(
            block_on(publication::read(&env.pipe.meta, &source, &repo.name, HEAD))
                .unwrap()
                .value,
            publication::Pair::default()
        );
        fires += 1;
        assert!(fires < 1000);
    }
    assert!(fires > 1);
    let (_, more_fires) = publish(
        &env,
        &owner,
        &identity,
        &publication::Pair::default(),
        head,
        map,
        &tickets,
        272_000,
    );
    assert_eq!(more_fires, 0);
}
#[cfg(feature = "remote-hooks")]
#[test]
fn synchronous_inspection_with_hundreds_of_reachable_objects_completes() {
    struct Scanner(AtomicU32);
    impl inspection::ContentInspector for Scanner {
        fn id(&self) -> &'static str {
            "publication-scanner"
        }
        fn inspect<'a>(
            &'a self,
            _: &'a Operation,
            _: &'a str,
            objects: &'a [mkit_rpc::hooks::InspectObject],
        ) -> crate::BoxFuture<'a, Result<crate::hooks::InspectVerdict, ServerError>> {
            Box::pin(async move {
                assert_eq!(objects.len(), 300);
                self.0.fetch_add(1, Ordering::SeqCst);
                Ok(crate::hooks::InspectVerdict::Pass)
            })
        }
    }
    let (mut env, owner, identity) =
        environment_with(Sharding::Single, crate::indexed::IndexedConfig::default());
    env.pipe.cfg.begin_upload_threshold_bytes = 0;
    let scanner = Arc::new(Scanner(AtomicU32::new(0)));
    let Env {
        pipe,
        clock,
        metrics,
    } = env;
    let mut env = Env {
        pipe: pipe.with_inspectors(vec![scanner.clone()], 10000).unwrap(),
        clock,
        metrics,
    };
    env.pipe.cfg.begin_upload_threshold_bytes = 0;
    let (bytes, head, _, _) = fixture(300);
    let map_bytes = mkit_core::transfer::encode_packlist(None, &[hash(&bytes)]).unwrap();
    let tickets = vec![
        ticket(&env, &owner, &identity, &bytes, 131_000),
        ticket(&env, &owner, &identity, &map_bytes, 131_001),
    ];
    let (_, slices) = publish(
        &env,
        &owner,
        &identity,
        &publication::Pair::default(),
        head,
        hash(&map_bytes),
        &tickets,
        131_010,
    );
    assert!(slices > 1);
    assert_eq!(scanner.0.load(Ordering::SeqCst), 1);
}

#[test]
fn inherited_denial_is_checked_fresh_without_scanning_inherited_inventory() {
    denied_reference(false);
}
#[test]
fn new_content_referencing_a_denied_object_is_refused() {
    denied_reference(true);
}

#[test]
fn altered_packmap_facts_cannot_forge_an_extension_of_the_seed() {
    let (env, owner, identity, head, map, _, _) = published_fixture(20);
    let request = signed_at(
        &owner,
        &identity,
        Procedure::AdvanceRefs,
        250_000,
        env.clock.now_ms(),
    );
    let auth = env.auth(&request).unwrap();
    let repo = auth.repo().repo.clone();
    let source = env.pipe.shards.ref_shard(&repo, HEAD);
    let packs = block_on(crate::takedown::inventory::packlist_facts(
        &env.pipe.meta,
        &map,
    ))
    .unwrap()
    .2;
    let node = mkit_core::transfer::encode_packlist(None, &[packs[0], map]).unwrap();
    let id = hash(&node);
    let now = u64::try_from(env.clock.now_ms()).unwrap();
    block_on(crate::takedown::inventory::stage_packlist(
        &env.pipe.meta,
        &id,
        node.len() as u64,
        None,
        &[packs[0], map],
        now,
    ))
    .unwrap();
    block_on(crate::takedown::inventory::complete(
        &env.pipe.meta,
        &id,
        node.len() as u64,
        now,
    ))
    .unwrap();
    let partition = crate::store::content_shard(&id);
    let key = Key::new([keys::block(&id).as_bytes(), b"\0inventory-head"].concat());
    let raw = block_on(env.pipe.meta.get(&partition, &key))
        .unwrap()
        .unwrap();
    let mut row: serde_json::Value = serde_json::from_slice(raw.as_bytes()).unwrap();
    row["packlist"]["prev"] = serde_json::to_value(map).unwrap();
    row["length"] = serde_json::to_value(node.len() + 32).unwrap();
    block_on(env.pipe.meta.inner.apply(
        &partition,
        Batch::new().put(key, Value::new(serde_json::to_vec(&row).unwrap())),
    ))
    .unwrap();
    let witness = publication::Witness {
        generation: 0,
        sequence: 1,
        published: true,
        held: false,
    }
    .encode();
    block_on(
        env.pipe.meta.inner.apply(
            &source,
            Batch::new()
                .put(keys::membership(&repo.name, &id), witness.clone())
                .put(keys::published_member(&repo.name, &id), witness),
        ),
    )
    .unwrap();
    let before = block_on(publication::read(&env.pipe.meta, &source, &repo.name, HEAD)).unwrap();
    let error = block_on(env.pipe.advance_refs_with_tickets(
        &auth,
        upd(HEAD, Match(head), head),
        upd(PACKMAP, Match(map), id),
        vec![],
    ))
    .unwrap_err();
    assert_eq!(error.code(), Code::Unavailable);
    assert_eq!(
        block_on(publication::read(&env.pipe.meta, &source, &repo.name, HEAD)).unwrap(),
        before
    );
}

#[test]
#[allow(clippy::too_many_lines)] // Retained candidate, policy race, and fresh denial share one fixture.
fn retained_custom_candidate_rechecks_policy_and_new_denial_before_clearance() {
    struct Gate(AtomicBool);
    impl clearance::PublicationPolicy for Gate {
        fn prepare<'a>(
            &'a self,
            _: &'a Operation,
            _: &'a publication::Pair,
        ) -> crate::BoxFuture<'a, Result<publication::Advance, ServerError>> {
            Box::pin(async { panic!("timer never prepares an advance") })
        }
        fn pack_available(&self, _: &RepoId, _: &Hash) -> bool {
            self.0.load(Ordering::SeqCst)
        }
    }
    let (env, owner, identity, _, _, _, leaf) = published_fixture(80);
    let request = signed_at(
        &owner,
        &identity,
        Procedure::AdvanceRefs,
        260_000,
        env.clock.now_ms(),
    );
    let repo = env.auth(&request).unwrap().repo().repo.clone();
    let source = env.pipe.shards.ref_shard(&repo, HEAD);
    let key = keys::publication(&repo.name, HEAD);
    let raw = block_on(env.pipe.meta.get(&source, &key)).unwrap().unwrap();
    let mut evidence = publication::stored(&raw).unwrap().1.unwrap();
    evidence.custom_policy = true;
    evidence.denial = false;
    let published = publication::Publication::decode(Some(&raw)).unwrap();
    let advance = publication::Advance {
        sequence: 0,
        generation: published.generation,
        value: published.value.clone(),
        additions: vec![],
        dependencies: vec![],
        external_bases: vec![],
        obligations: vec![],
        state: publication::Clearance::Pending,
        operation: [85; 32],
    };
    let mut batch = Batch::new();
    let mut outbox = crate::store::outbox::OutboxBuilder::new(None, None).unwrap();
    let pending = publication::append_evidenced(
        &repo,
        HEAD,
        &source,
        env.pipe.shards.as_ref(),
        Some(&raw),
        advance,
        false,
        Some(&evidence),
        &mut batch.preconditions,
        &mut batch.writes,
        &mut outbox,
    )
    .unwrap();
    assert_eq!(
        block_on(env.pipe.meta.apply(&source, batch)).unwrap(),
        BatchOutcome::Committed
    );
    let gate = Arc::new(Gate(AtomicBool::new(false)));
    let budget = crate::purge::SliceBudget::new(128);
    let registry = crate::timers::TimerRegistry::new().register(
        crate::timers::publication_recheck::PublicationRecheck::new(BorrowedStore(&env.pipe.meta))
            .with_alarm_budget(budget.clone())
            .with_publication_policy(
                gate.clone(),
                crate::indexed::IndexedConfig::default().max_delta_chain_depth,
            ),
    );
    for denied in [false, true] {
        if denied {
            gate.0.store(true, Ordering::SeqCst);
            let action = crate::takedown::denial::BlockAction {
                id: [86; 32],
                takedown_id: [87; 32],
                reason: "denied".into(),
                blocked_at_ms: u64::try_from(env.clock.now_ms()).unwrap(),
                chunk_ids: vec![],
            };
            block_on(
                crate::store::ContentIndex::new(BorrowedStore(&env.pipe.meta))
                    .install_block_action(&leaf, &action, action.blocked_at_ms),
            )
            .unwrap();
        }
        env.clock
            .advance(i64::try_from(publication::RECHECK_MS).unwrap());
        budget.reset();
        let report = block_on(crate::timers::run_due(
            &env.pipe.meta,
            &source,
            &registry,
            env.clock.as_ref(),
            u64::try_from(env.clock.now_ms()).unwrap(),
            &crate::timers::TickBudget::default(),
        ))
        .unwrap();
        assert_eq!(report.fired, 1);
        let after = block_on(publication::read(&env.pipe.meta, &source, &repo.name, HEAD)).unwrap();
        assert_eq!(after.published, published.published);
        assert_eq!(after.value, published.value);
        assert_eq!(after.sequence, pending.sequence);
        assert!(budget.used() <= 128);
    }
}

#[test]
fn object_provider_search_resumes_across_short_index_pages() {
    let (mut env, owner, identity, old_head, old_map, _, _) = published_fixture(15);
    let old = publication::Pair {
        head: Some(old_head),
        packmap: Some(old_map),
    };
    let (bytes, head, _, _) = fixture(160);
    let pack_id = hash(&bytes);
    let map_bytes = mkit_core::transfer::encode_packlist(Some(old_map), &[pack_id]).unwrap();
    let map = hash(&map_bytes);
    let tickets = [
        ticket(&env, &owner, &identity, &bytes, 700_000),
        ticket(&env, &owner, &identity, &map_bytes, 700_001),
    ];
    let request = signed_at(
        &owner,
        &identity,
        Procedure::AdvanceRefs,
        701_000,
        env.clock.now_ms(),
    );
    let repo = env.auth(&request).unwrap().repo().repo.clone();
    let first = block_on(env.pipe.advance_refs_with_tickets(
        &env.auth(&request).unwrap(),
        upd(HEAD, Match(old_head), head),
        upd(PACKMAP, Match(old_map), map),
        tickets.to_vec(),
    ));
    assert_eq!(
        first.unwrap_err().public_message(),
        "pack verification pending"
    );
    let shard = env.pipe.shards.object_index(&repo, &head);
    let raw = block_on(
        env.pipe
            .meta
            .inner
            .get(&shard, &keys::object_index(&repo.name, &head, &pack_id)),
    )
    .unwrap()
    .unwrap();
    for n in 0u16..160 {
        let mut unrelated = [0; 32];
        unrelated[30..].copy_from_slice(&n.to_be_bytes());
        assert!(unrelated < pack_id);
        assert_eq!(
            block_on(env.pipe.meta.inner.apply(
                &shard,
                Batch::new().put(
                    keys::object_index(&repo.name, &head, &unrelated),
                    raw.clone()
                )
            ))
            .unwrap(),
            BatchOutcome::Committed
        );
    }
    env.pipe.meta.scan_limit = Some(1);
    let (_, alarms) = publish(&env, &owner, &identity, &old, head, map, &tickets, 702_000);
    assert!(alarms > 2);
}
