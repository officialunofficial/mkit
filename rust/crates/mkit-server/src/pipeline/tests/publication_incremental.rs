//! Publication verification is bounded by new content, not by history.
use super::indexed::{environment_with, signed_at, upload};
use super::*;
use crate::store::{BorrowedStore, publication};
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
/// One pack holding `count` blobs, a tree naming them all, and a commit.
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
fn registry<'a>(
    env: &'a Env,
    budget: &crate::purge::SliceBudget,
) -> crate::timers::TimerRegistry<'a, Spy> {
    crate::timers::TimerRegistry::new().register(
        crate::timers::publication_recheck::PublicationRecheck::new(BorrowedStore(&env.pipe.meta))
            .with_alarm_budget(budget.clone()),
    )
}
fn fire(env: &Env, source: &Partition, registry: &crate::timers::TimerRegistry<'_, Spy>) {
    block_on(crate::timers::run_due(
        &env.pipe.meta,
        source,
        registry,
        env.clock.as_ref(),
        u64::try_from(env.clock.now_ms()).unwrap(),
        &crate::timers::TickBudget::new(1, 1, 64, 10_000),
    ))
    .unwrap();
}
type Attempt = Result<AdvanceOutcome, ServerError>;
fn advance(
    env: &Env,
    (owner, identity): (&SigningKey, &str),
    old: &publication::Pair,
    (head, map): (Hash, Hash),
    tickets: &[Hash],
    nonce: u32,
) -> Attempt {
    let request = signed_at(
        owner,
        identity,
        Procedure::AdvanceRefs,
        nonce,
        env.clock.now_ms(),
    );
    block_on(env.pipe.advance_refs_with_tickets(
        &env.auth(&request).unwrap(),
        upd(HEAD, old.head.map_or(Missing, Match), head),
        upd(PACKMAP, old.packmap.map_or(Missing, Match), map),
        tickets.to_vec(),
    ))
}
fn is_pending(result: &Attempt) -> bool {
    result
        .as_ref()
        .is_err_and(|e| e.public_message() == "pack verification pending")
}
fn read(
    env: &Env,
    owner: &SigningKey,
    identity: &str,
) -> (RepoId, Partition, publication::Publication) {
    let request = signed_at(
        owner,
        identity,
        Procedure::AdvanceRefs,
        1,
        env.clock.now_ms(),
    );
    let repo = env.auth(&request).unwrap().repo().repo.clone();
    let source = env.pipe.shards.ref_shard(&repo, HEAD);
    let state = block_on(publication::read(&env.pipe.meta, &source, &repo.name, HEAD)).unwrap();
    (repo, source, state)
}
/// Foreground retries plus real timer slices until the advance publishes.
/// Returns the backend calls it cost and how many alarm slices it needed.
fn publish(
    env: &Env,
    who: (&SigningKey, &str),
    old: &publication::Pair,
    target: (Hash, Hash),
    tickets: &[Hash],
    nonce: u32,
) -> (u32, u32) {
    let (_, source, _) = read(env, who.0, who.1);
    let alarm = crate::purge::SliceBudget::new(128);
    let timers = registry(env, &alarm);
    let before = env.pipe.meta.calls();
    let mut slices = 0;
    for round in 0..20_000 {
        let result = advance(env, who, old, target, tickets, nonce + round);
        if is_pending(&result) {
            assert_eq!(read(env, who.0, who.1).2.value, *old);
            env.clock.advance(1000);
            alarm.reset();
            let before = env.pipe.meta.calls();
            fire(env, &source, &timers);
            // 128 verification calls, plus the due-timer enumeration and the
            // one guarded settlement outside that share.
            assert!(
                alarm.used() <= 128 && env.pipe.meta.calls() - before <= 128 + 64,
                "one alarm slice stays inside its fixed share: {} {}",
                env.pipe.meta.calls() - before,
                alarm.used()
            );
            slices += 1;
            continue;
        }
        assert_eq!(result.unwrap(), AdvanceOutcome::Committed);
        let published = read(env, who.0, who.1).2;
        assert_eq!(
            published.value,
            publication::Pair {
                head: Some(target.0),
                packmap: Some(target.1)
            }
        );
        assert_eq!(published.published, published.sequence);
        return (env.pipe.meta.calls() - before, slices);
    }
    panic!("publication must finish")
}
fn pair(head: Hash, map: Hash) -> publication::Pair {
    publication::Pair {
        head: Some(head),
        packmap: Some(map),
    }
}

struct Published {
    env: Env,
    owner: SigningKey,
    identity: String,
    head: Hash,
    map: Hash,
    tree: Hash,
    leaf: Hash,
}
impl Published {
    fn who(&self) -> (&SigningKey, &str) {
        (&self.owner, &self.identity)
    }
    fn pair(&self) -> publication::Pair {
        pair(self.head, self.map)
    }
    /// A new commit and packmap node. With `new_tree`, a new tree names `leaf`
    /// again beside `extra` brand-new blobs, which need several slices to verify.
    fn next(&self, new_tree: bool, extra: u32, nonce: u32) -> (Hash, Hash, Vec<Hash>) {
        let blobs: Vec<_> = (0..extra)
            .map(|n| {
                Object::Blob(Blob {
                    data: (1_000_000 + n).to_be_bytes().repeat(4),
                })
            })
            .collect();
        let mut entries: Vec<_> = blobs
            .iter()
            .enumerate()
            .map(|(n, o)| TreeEntry {
                name: format!("n{n:06}").into_bytes(),
                mode: EntryMode::Blob,
                object_hash: o.id().unwrap(),
            })
            .collect();
        entries.insert(
            0,
            TreeEntry {
                name: b"again".to_vec(),
                mode: EntryMode::Blob,
                object_hash: self.leaf,
            },
        );
        let tree = Object::Tree(Tree { entries });
        let object = commit(
            if new_tree {
                tree.id().unwrap()
            } else {
                self.tree
            },
            Some(self.head),
            2 + u64::from(nonce),
        );
        let mut objects = blobs;
        if new_tree {
            objects.push(tree);
        }
        objects.push(object.clone());
        let bytes = pack(&objects);
        let node = mkit_core::transfer::encode_packlist(Some(self.map), &[hash(&bytes)]).unwrap();
        let tickets = vec![
            ticket(&self.env, &self.owner, &self.identity, &bytes, nonce),
            ticket(&self.env, &self.owner, &self.identity, &node, nonce + 1),
        ];
        (object.id().unwrap(), hash(&node), tickets)
    }
}
fn published(count: u32, takedown: bool) -> Published {
    let (mut env, owner, identity) =
        environment_with(Sharding::Single, crate::indexed::IndexedConfig::default());
    env.pipe.cfg.begin_upload_threshold_bytes = 0;
    // The first publication runs without verification, like a deployment that
    // turns takedown on after the repository has grown.
    env.pipe.cfg.takedown_denial = false;
    let (bytes, head, tree, leaf) = fixture(count);
    let node = mkit_core::transfer::encode_packlist(None, &[hash(&bytes)]).unwrap();
    let tickets = [
        ticket(&env, &owner, &identity, &bytes, 200_000),
        ticket(&env, &owner, &identity, &node, 200_001),
    ];
    publish(
        &env,
        (&owner, &identity),
        &publication::Pair::default(),
        (head, hash(&node)),
        &tickets,
        201_000,
    );
    env.pipe.cfg.takedown_denial = takedown;
    Published {
        env,
        owner,
        identity,
        head,
        map: hash(&node),
        tree,
        leaf,
    }
}
fn block(env: &Env, id: &Hash, tag: u8) {
    let action = crate::takedown::denial::BlockAction {
        id: [tag; 32],
        takedown_id: [tag + 1; 32],
        reason: "denied".into(),
        blocked_at_ms: u64::try_from(env.clock.now_ms()).unwrap(),
        chunk_ids: vec![],
    };
    block_on(
        crate::store::ContentIndex::new(BorrowedStore(&env.pipe.meta)).install_block_action(
            id,
            &action,
            action.blocked_at_ms,
        ),
    )
    .unwrap();
}

#[test]
fn takedown_publication_over_4096_objects_costs_only_new_content() {
    let mut state = published(4200, true);
    // Re-advancing the unchanged pair reuses the sealed facts of its objects.
    let (calls, _) = publish(
        &state.env,
        state.who(),
        &state.pair(),
        (state.head, state.map),
        &[],
        210_000,
    );
    assert!(calls < 600, "unchanged pair over 4202 objects: {calls}");
    for n in 0..3u32 {
        let (head, map, tickets) = state.next(false, 0, 220_000 + n * 100);
        let (calls, _) = publish(
            &state.env,
            state.who(),
            &state.pair(),
            (head, map),
            &tickets,
            220_010 + n * 100,
        );
        assert!(
            calls < 900,
            "one new commit must not re-walk 4202 inherited objects: {calls}"
        );
        (state.head, state.map) = (head, map);
    }
}

#[test]
fn custom_policy_publication_with_hundreds_of_reachable_objects_completes() {
    let (mut env, owner, identity) =
        environment_with(Sharding::Single, crate::indexed::IndexedConfig::default());
    env.pipe.cfg.begin_upload_threshold_bytes = 0;
    env.pipe.publication_policy = Some(Arc::new(clearance::Immediate));
    let (bytes, head, _, _) = fixture(300);
    let node = mkit_core::transfer::encode_packlist(None, &[hash(&bytes)]).unwrap();
    let tickets = [
        ticket(&env, &owner, &identity, &bytes, 130_000),
        ticket(&env, &owner, &identity, &node, 130_001),
    ];
    let (_, slices) = publish(
        &env,
        (&owner, &identity),
        &publication::Pair::default(),
        (head, hash(&node)),
        &tickets,
        130_010,
    );
    assert!(slices > 1);
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
    env = Env {
        pipe: pipe.with_inspectors(vec![scanner.clone()], 10_000).unwrap(),
        clock,
        metrics,
    };
    env.pipe.cfg.begin_upload_threshold_bytes = 0;
    let (bytes, head, _, _) = fixture(300);
    let node = mkit_core::transfer::encode_packlist(None, &[hash(&bytes)]).unwrap();
    let tickets = [
        ticket(&env, &owner, &identity, &bytes, 131_000),
        ticket(&env, &owner, &identity, &node, 131_001),
    ];
    let (_, slices) = publish(
        &env,
        (&owner, &identity),
        &publication::Pair::default(),
        (head, hash(&node)),
        &tickets,
        131_010,
    );
    assert!(slices > 1);
    assert_eq!(scanner.0.load(Ordering::SeqCst), 1);
}

#[test]
fn a_large_advance_finishes_its_proof_on_alarms_alone() {
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
    let who = (&owner, identity.as_str());
    assert!(is_pending(&advance(
        &env,
        who,
        &publication::Pair::default(),
        (head, map),
        &tickets,
        271_000
    )));
    let (repo, source, _) = read(&env, &owner, &identity);
    let alarm = crate::purge::SliceBudget::new(128);
    let timers = registry(&env, &alarm);
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
        if serde_json::to_value(state).unwrap()["publication"]["complete"] == true {
            break;
        }
        env.clock.advance(1000);
        alarm.reset();
        fire(&env, &source, &timers);
        assert!(alarm.used() <= 128);
        assert_eq!(
            read(&env, &owner, &identity).2.value,
            publication::Pair::default(),
            "no alarm moves a ref"
        );
        fires += 1;
        assert!(fires < 1000);
    }
    assert!(fires > 1);
    // The next foreground request only consumes the finished proof.
    let (_, more) = publish(
        &env,
        who,
        &publication::Pair::default(),
        (head, map),
        &tickets,
        272_000,
    );
    assert_eq!(more, 0);
}

#[test]
fn newly_referenced_denied_content_is_refused_and_inherited_denial_is_served_denied() {
    for new_reference in [true, false] {
        let state = published(300, true);
        let (head, map, tickets) = state.next(new_reference, 0, 230_000);
        block(&state.env, &state.leaf, 81);
        let mut nonce = 231_000;
        let result = loop {
            let result = advance(
                &state.env,
                state.who(),
                &state.pair(),
                (head, map),
                &tickets,
                nonce,
            );
            nonce += 1;
            assert!(nonce < 231_050, "bounded continuations must finish");
            if !is_pending(&result) {
                break result;
            }
            state.env.clock.advance(1000);
        };
        let (_, _, now) = read(&state.env, &state.owner, &state.identity);
        if new_reference {
            assert_eq!(result.unwrap_err().code(), Code::PermissionDenied);
            assert_eq!(now.value, state.pair());
        } else {
            // The leaf is inherited through the unchanged tree: it is not
            // proved again, and every read path denies it immediately.
            assert_eq!(result.unwrap(), AdvanceOutcome::Committed);
            assert_eq!(now.value, pair(head, map));
        }
        assert!(
            block_on(crate::takedown::denial::denied(
                state.env.pipe.meta.inner.as_ref(),
                &state.leaf
            ))
            .unwrap()
        );
    }
}

#[test]
fn missing_or_corrupt_inventory_facts_of_a_member_refuse_publication() {
    for corrupt in [false, true] {
        let state = published(40, true);
        let (head, map, tickets) = state.next(false, 0, 240_000);
        let (repo, source, before) = read(&state.env, &state.owner, &state.identity);
        let _ = repo;
        let old_pack = block_on(crate::takedown::inventory::packlist_facts(
            &state.env.pipe.meta,
            &state.map,
        ))
        .unwrap()
        .2[0];
        let partition = crate::store::content_shard(&old_pack);
        let key = crate::takedown::inventory::entry_key(&old_pack, &state.tree);
        let batch = if corrupt {
            Batch::new().put(key, Value::new(b"not an entry".to_vec()))
        } else {
            Batch::new().delete(key)
        };
        assert_eq!(
            block_on(state.env.pipe.meta.inner.apply(&partition, batch)).unwrap(),
            BatchOutcome::Committed
        );
        for round in 0..40 {
            let result = advance(
                &state.env,
                state.who(),
                &state.pair(),
                (head, map),
                &tickets,
                241_000 + round,
            );
            if is_pending(&result) {
                state.env.clock.advance(1000);
                continue;
            }
            // Fail closed: never a skip. Nothing publishes or moves.
            assert!(result.is_err(), "corrupt={corrupt}: {result:?}");
            break;
        }
        let after = block_on(publication::read(
            &state.env.pipe.meta,
            &source,
            &repo.name,
            HEAD,
        ))
        .unwrap();
        assert_eq!(after.value, before.value);
        assert_eq!(after.published, before.published);
    }
}

#[test]
fn current_policy_is_asked_again_after_the_proof_is_complete() {
    struct Gate(AtomicBool);
    impl clearance::PublicationPolicy for Gate {
        fn prepare<'a>(
            &'a self,
            _: &'a Operation,
            value: &'a publication::Pair,
        ) -> crate::BoxFuture<'a, Result<publication::Advance, ServerError>> {
            Box::pin(async move { Ok(clearance::immediate(value.clone(), [0; 32], Vec::new())) })
        }
        fn pack_available(&self, _: &RepoId, _: &Hash) -> bool {
            self.0.load(Ordering::SeqCst)
        }
    }
    let mut state = published(120, false);
    let gate = Arc::new(Gate(AtomicBool::new(true)));
    state.env.pipe.publication_policy = Some(gate.clone());
    let (head, map, tickets) = state.next(true, 300, 250_000);
    // Finish the retained proof on alarms, with the policy still open.
    let first = advance(
        &state.env,
        state.who(),
        &state.pair(),
        (head, map),
        &tickets,
        251_000,
    );
    assert!(is_pending(&first), "{first:?}");
    let (_, source, _) = read(&state.env, &state.owner, &state.identity);
    let alarm = crate::purge::SliceBudget::new(128);
    let timers = registry(&state.env, &alarm);
    for _ in 0..50 {
        state.env.clock.advance(1000);
        alarm.reset();
        fire(&state.env, &source, &timers);
    }
    // The cached complete proof must not outlive the policy's current answer.
    gate.0.store(false, Ordering::SeqCst);
    let error = advance(
        &state.env,
        state.who(),
        &state.pair(),
        (head, map),
        &tickets,
        252_000,
    )
    .unwrap_err();
    assert!(
        matches!(
            error.public_message(),
            "open closure" | "repository membership not yet visible"
        ),
        "{}",
        error.public_message()
    );
    assert_eq!(
        read(&state.env, &state.owner, &state.identity).2.value,
        state.pair()
    );
    gate.0.store(true, Ordering::SeqCst);
    assert_eq!(
        advance(
            &state.env,
            state.who(),
            &state.pair(),
            (head, map),
            &tickets,
            253_000
        )
        .unwrap(),
        AdvanceOutcome::Committed
    );
}

#[test]
fn denial_installed_after_the_proof_completed_still_refuses_new_references() {
    let state = published(120, true);
    let (head, map, tickets) = state.next(true, 300, 260_000);
    let first = advance(
        &state.env,
        state.who(),
        &state.pair(),
        (head, map),
        &tickets,
        261_000,
    );
    assert!(is_pending(&first), "{first:?}");
    let (_, source, _) = read(&state.env, &state.owner, &state.identity);
    let alarm = crate::purge::SliceBudget::new(128);
    let timers = registry(&state.env, &alarm);
    for _ in 0..50 {
        state.env.clock.advance(1000);
        alarm.reset();
        fire(&state.env, &source, &timers);
    }
    // The finished retained proof carries no denial verdict: a later block is
    // proved against the new reference on the request that would publish it.
    block(&state.env, &state.leaf, 91);
    let error = advance(
        &state.env,
        state.who(),
        &state.pair(),
        (head, map),
        &tickets,
        262_000,
    )
    .unwrap_err();
    assert_eq!(error.code(), Code::PermissionDenied);
    assert_eq!(
        read(&state.env, &state.owner, &state.identity).2.value,
        state.pair()
    );
}
