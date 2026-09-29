//! Ref policy (SPEC-SERVER §9.7): allowed signers, fast-forward-only rules,
//! `u`-only ancestry (SPEC-WRITE-GRANTS §8.2) and ticketless head
//! membership, over the real pipeline and memory stores.
#![allow(clippy::unwrap_used)] // Invalid fixtures should fail the test immediately.

use super::*;
use crate::indexed::IndexedConfig;
use crate::policy::{RefPolicy, RefRule};
use crate::telemetry::METRIC_REF_POLICY_ANCESTRY_UNCHECKED;
use mkit_attest::grant::{RefPattern, RefScopes};
use mkit_core::object::{Commit, Identity, Object, Tree};
use mkit_core::pack::PackWriter;
use mkit_core::serialize::serialize;
use mkit_core::sign::{KeyPair, sign_commit};
use std::collections::BTreeSet;

const FF_MESSAGE: &str = "non-fast-forward update not allowed on this ref";
const SIGNER_MESSAGE: &str = "signer not allowed for this ref";
const NOT_VISIBLE: &str = "repository membership not yet visible";
const LAG_MS: i64 = crate::relay::RELAY_LAG_BOUND_MS.cast_signed();

fn rule(pattern: &str, signers: Option<&[&SigningKey]>, ff: bool) -> RefRule {
    RefRule {
        pattern: RefPattern::parse(pattern).unwrap(),
        allowed_signers: signers.map(|keys| {
            keys.iter()
                .map(|key| *key.verifying_key().as_bytes())
                .collect::<BTreeSet<_>>()
        }),
        fast_forward_only: ff,
    }
}

fn ff_main() -> RefPolicy {
    RefPolicy::new(vec![rule(HEAD, None, true)])
}

fn tree() -> Object {
    Object::Tree(Tree {
        entries: Vec::new(),
    })
}

fn commit(parents: &[Hash], salt: u8) -> (Object, Hash) {
    let signer = KeyPair::from_seed([9; 32]);
    let mut commit = Commit::new_unannotated(
        tree().id().unwrap(),
        parents.to_vec(),
        Identity::ed25519(signer.public.0),
        signer.public.0,
        vec![salt],
        42,
        [0; 64],
    );
    commit.signature = sign_commit(&commit, &signer).unwrap().0;
    let commit = Object::Commit(commit);
    let id = commit.id().unwrap();
    (commit, id)
}

fn pack_of(objects: &[&Object]) -> Vec<u8> {
    let mut writer = PackWriter::new_raw_only();
    for object in objects {
        writer
            .push_raw(object.id().unwrap(), &serialize(object).unwrap())
            .unwrap();
    }
    writer.finish().unwrap()
}

struct World {
    env: Env,
    owner: SigningKey,
    identity: String,
    n: u32,
}

impl World {
    fn new(policy: Option<RefPolicy>, indexed: Option<IndexedConfig>) -> Self {
        Self::with_store(policy, indexed, |clock| Spy::new(store(clock)))
    }

    fn with_store(
        policy: Option<RefPolicy>,
        indexed: Option<IndexedConfig>,
        spy: impl FnOnce(&Arc<ManualClock>) -> Spy,
    ) -> Self {
        let owner = key(7);
        let mut config = grants::config(&owner, AuthorizerRole::Check);
        config.indexed = indexed;
        config.ref_policy = policy;
        let clock = clock();
        let store = spy(&clock);
        Self {
            env: build(config, store, Hooks::new(), clock),
            identity: grants::repository(&owner),
            owner,
            n: 0,
        }
    }

    fn indexed(policy: Option<RefPolicy>) -> Self {
        Self::new(policy, Some(IndexedConfig::default()))
    }

    fn other_identity(&self, name: &str) -> String {
        let (namespace, _) = self.identity.split_once('/').unwrap();
        format!("{namespace}/{name}")
    }

    fn req(&mut self, signer: &SigningKey, identity: &str, procedure: Procedure, at: i64) -> Req {
        self.n += 1;
        Req::signed_for(
            signer,
            procedure,
            identity,
            b"ref-policy",
            &nonce(self.n),
            at,
        )
    }

    fn auth(&mut self, procedure: Procedure) -> Authenticated {
        let (owner, identity) = (self.owner.clone(), self.identity.clone());
        let req = self.req(&owner, &identity, procedure, T0);
        self.env.auth(&req).unwrap()
    }

    /// Upload `objects` as one pack to a ticket for `branch`.
    fn begin(&mut self, branch: &str, objects: &[&Object]) -> Result<(Vec<u8>, Hash), ServerError> {
        let pack = pack_of(objects);
        let auth = self.auth(Procedure::BeginUpload);
        let BeginUploadResult::Ticket { id, .. } = block_on(self.env.pipe.begin_upload(
            &auth,
            &format!("refs/heads/{branch}"),
            &hash(&pack),
            pack.len() as u64,
        ))?
        else {
            panic!("expected an upload ticket");
        };
        super::indexed::upload(&self.env, &pack, id);
        Ok((pack, id))
    }

    /// Advance `branch` to `head`, consuming the ticket of `pack`.
    fn advance(
        &mut self,
        branch: &str,
        (pack, ticket): &(Vec<u8>, Hash),
        head: Hash,
        condition: RefWriteCondition,
    ) -> Result<AdvanceOutcome, ServerError> {
        let auth = self.auth(Procedure::AdvanceRefs);
        block_on(self.env.pipe.advance_refs_with_tickets(
            &auth,
            upd(&format!("refs/heads/{branch}"), condition, head),
            upd(&format!("refs/mkit/packmap/{branch}"), Any, hash(pack)),
            vec![*ticket],
        ))
    }

    /// Upload `objects` and advance `branch` to `head` in one go.
    fn push(
        &mut self,
        branch: &str,
        objects: &[&Object],
        head: Hash,
        condition: RefWriteCondition,
    ) -> Result<AdvanceOutcome, ServerError> {
        let ticket = self.begin(branch, objects)?;
        self.advance(branch, &ticket, head, condition)
    }

    fn update_as(
        &mut self,
        (signer, identity, created): (&SigningKey, &str, i64),
        header: Option<&str>,
        change: RefUpdate,
    ) -> Result<UpdateRefResult, ServerError> {
        let mut req = self.req(signer, identity, Procedure::UpdateRef, created);
        if let Some(header) = header {
            req = req.header("x-write-grant", header);
        }
        let auth = self.env.auth(&req)?;
        block_on(self.env.pipe.update_ref(&auth, change))
    }

    fn update(
        &mut self,
        name: &str,
        condition: RefWriteCondition,
        new: Option<Hash>,
    ) -> Result<UpdateRefResult, ServerError> {
        let (owner, identity) = (self.owner.clone(), self.identity.clone());
        let change = RefUpdate {
            name: name.into(),
            condition,
            new,
        };
        self.update_as((&owner, &identity, T0), None, change)
    }

    fn value(&self, name: &str) -> Option<Hash> {
        let repo = self.repo();
        let partition = self.env.pipe.shards.ref_shard(&repo, name);
        block_on(
            self.env
                .pipe
                .meta
                .get(&partition, &keys::ref_key(&repo.name, name)),
        )
        .unwrap()
        .map(|raw| codec::decode_ref_id(&raw).unwrap())
    }

    fn repo(&self) -> RepoId {
        self.env
            .pipe
            .cfg
            .addressing
            .resolve(Some(&self.identity), true)
            .unwrap()
            .repo
    }

    /// Write a ref value directly, as a concurrent writer would have.
    fn set_ref(&self, name: &str, id: &Hash) {
        let repo = self.repo();
        let partition = self.env.pipe.shards.ref_shard(&repo, name);
        let batch = Batch::new().put(keys::ref_key(&repo.name, name), codec::encode_ref_id(id));
        block_on(self.env.pipe.meta.inner.apply(&partition, batch)).unwrap();
    }

    /// Remove `id`'s index row, as if its membership were not yet visible;
    /// returns the row to restore.
    fn hide(&self, id: &Hash) -> (Key, Value) {
        let repo = self.repo();
        let partition = self.env.pipe.shards.object_index(&repo, id);
        let (start, end) = keys::object_index_range(&repo.name, id);
        let page = block_on(self.env.pipe.meta.scan(&partition, &start, &end, None, 10)).unwrap();
        let row = page.entries[0].clone();
        block_on(
            self.env
                .pipe
                .meta
                .inner
                .apply(&partition, Batch::new().delete(row.0.clone())),
        )
        .unwrap();
        row
    }

    fn restore(&self, id: &Hash, row: (Key, Value)) {
        let partition = self.env.pipe.shards.object_index(&self.repo(), id);
        block_on(
            self.env
                .pipe
                .meta
                .inner
                .apply(&partition, Batch::new().put(row.0, row.1)),
        )
        .unwrap();
    }

    fn index_reads(&self) -> usize {
        self.env
            .pipe
            .meta
            .seen()
            .iter()
            .filter(|key| key.as_bytes().first() == Some(&b'i'))
            .count()
    }

    fn unchecked(&self) -> usize {
        self.env.metrics.count(METRIC_REF_POLICY_ANCESTRY_UNCHECKED)
    }

    /// History `c1 <- c2 <- c3` on `main`, each in its own pack, plus a
    /// divergent root `stray` on `side`. Returns `[c1, c2, c3, stray]`.
    fn history(&mut self) -> [Hash; 4] {
        let (c1, id1) = commit(&[], 1);
        let (c2, id2) = commit(&[id1], 2);
        let (c3, id3) = commit(&[id2], 3);
        let (stray, stray_id) = commit(&[], 4);
        let empty = tree();
        assert_eq!(
            self.push("main", &[&empty, &c1], id1, Missing).unwrap(),
            AdvanceOutcome::Committed
        );
        assert_eq!(
            self.push("main", &[&c2], id2, Match(id1)).unwrap(),
            AdvanceOutcome::Committed
        );
        assert_eq!(
            self.push("feature", &[&c3], id3, Missing).unwrap(),
            AdvanceOutcome::Committed
        );
        assert_eq!(
            self.push("side", &[&stray], stray_id, Missing).unwrap(),
            AdvanceOutcome::Committed
        );
        [id1, id2, id3, stray_id]
    }
}

fn denied(error: &ServerError, message: &str) {
    assert_eq!(error.code(), Code::PermissionDenied, "{error:?}");
    assert_eq!(error.public_message(), message);
}

#[test]
fn signer_rule_denies_every_ref_moving_change_even_for_the_owner() {
    for indexed in [None, Some(IndexedConfig::default())] {
        let elsewhere = key(3);
        let policy = RefPolicy::new(vec![rule("refs/heads/*", Some(&[&elsewhere]), false)]);
        let mut w = World::new(Some(policy), indexed);
        let owner = w.owner.clone();
        for (condition, new) in [(Missing, Some(A)), (Match(B), Some(A)), (Match(B), None)] {
            denied(&w.update(HEAD, condition, new).unwrap_err(), SIGNER_MESSAGE);
        }
        let head = upd(HEAD, Missing, A);
        let auth = w.auth(Procedure::AdvanceRefs);
        let error = block_on(
            w.env
                .pipe
                .advance_refs(&auth, head, upd(PACKMAP, Missing, B)),
        )
        .unwrap_err();
        denied(&error, SIGNER_MESSAGE);
        // D5: a direct packmap write is covered through its head.
        denied(
            &w.update(PACKMAP, Missing, Some(A)).unwrap_err(),
            SIGNER_MESSAGE,
        );
        let auth = w.auth(Procedure::BeginUpload);
        let error = block_on(w.env.pipe.begin_upload(&auth, HEAD, &B, 1)).unwrap_err();
        denied(&error, SIGNER_MESSAGE);
        // Nothing moved and the owner was the signer throughout.
        assert_eq!(w.value(HEAD), None);
        assert_eq!(w.owner.verifying_key(), owner.verifying_key());
    }
}

#[test]
fn signer_rule_allows_listed_signers_and_uncovered_refs_and_intersects() {
    let (owner, other) = (key(7), key(3));
    let policy = RefPolicy::new(vec![
        rule("refs/heads/*", Some(&[&owner, &other]), false),
        rule(HEAD, Some(&[&other]), false),
    ]);
    let mut w = World::new(Some(policy), None);
    // The rules intersect on main: only `other` may move it.
    denied(
        &w.update(HEAD, Missing, Some(A)).unwrap_err(),
        SIGNER_MESSAGE,
    );
    assert_eq!(
        w.update("refs/heads/dev", Missing, Some(A)).unwrap(),
        UpdateRefResult::Committed
    );
    assert_eq!(
        w.update("refs/tags/v1", Missing, Some(A)).unwrap(),
        UpdateRefResult::Committed
    );
    // `other` is in both sets, so the intersection lets it through (as a
    // grantee: it does not own the namespace).
    let header = grants::grant(&owner, &other, |grant| {
        grant.ref_scopes = Some(RefScopes::parse("refs/heads/*=cufd").unwrap());
    });
    let identity = w.identity.clone();
    let change = upd(HEAD, Missing, A);
    assert_eq!(
        w.update_as((&other, &identity, T0), Some(&header), change)
            .unwrap(),
        UpdateRefResult::Committed
    );
}

#[test]
fn matching_signer_rule_denies_a_write_with_no_auth_v2_signer() {
    let ssh = Principal::SshForcedCommand { key: None };
    let bearer = || Req::unsigned(Procedure::UpdateRef).header("authorization", "Bearer tok");
    let mut enc = Req::unsigned(Procedure::UpdateRef);
    enc.principal = Some(ssh);
    for (mode, request) in [
        (AuthMode::Open, Req::unsigned(Procedure::UpdateRef)),
        (
            AuthMode::Bearer {
                token: crate::error::Redacted::new("tok"),
            },
            bearer(),
        ),
        (AuthMode::TransportIdentity, enc),
    ] {
        let policy = RefPolicy::new(vec![rule("refs/heads/*", Some(&[&key(3)]), false)]);
        let clock = clock();
        let mut config = cfg(mode);
        config.ref_policy = Some(policy);
        let env = build(config, Spy::new(store(&clock)), Hooks::new(), clock);
        denied(
            &env.update(&request, &upd(HEAD, Missing, A)).unwrap_err(),
            SIGNER_MESSAGE,
        );
        assert_eq!(
            env.update(&request, &upd("refs/tags/v1", Missing, A))
                .unwrap(),
            UpdateRefResult::Committed
        );
    }
}

#[derive(Clone)]
struct Shared(Arc<MemoryKv>);

impl crate::store::NamespaceStore for Shared {
    fn capabilities(&self) -> crate::store::StoreCapabilities {
        self.0.capabilities()
    }
    async fn get(&self, p: &Partition, key: &Key) -> Result<Option<Value>, crate::StoreError> {
        self.0.get(p, key).await
    }
    async fn scan(
        &self,
        p: &Partition,
        start: &Key,
        end: &Key,
        after: Option<&crate::store::Cursor>,
        limit: u32,
    ) -> Result<ScanPage, crate::StoreError> {
        self.0.scan(p, start, end, after, limit).await
    }
    async fn apply(&self, p: &Partition, batch: Batch) -> Result<BatchOutcome, crate::StoreError> {
        self.0.apply(p, batch).await
    }
    async fn stats(&self, p: &Partition) -> Result<PartitionStats, crate::StoreError> {
        self.0.stats(p).await
    }
    async fn probe(&self) -> Result<(), crate::StoreError> {
        self.0.probe().await
    }
}

#[test]
fn with_auth_siblings_inherit_the_policy_and_deny_without_an_auth_v2_signer() {
    let clock = clock();
    let mut config = cfg(authv2());
    config.ref_policy = Some(RefPolicy::new(vec![rule(
        "refs/heads/*",
        Some(&[&key(3)]),
        false,
    )]));
    let metrics = Arc::new(SpyMetrics::default());
    let primary = Pipeline::new(
        MemoryBlobStore::default(),
        Shared(Arc::new(store(&clock))),
        Hooks::new(),
        config,
        clock.clone(),
        metrics.clone(),
    )
    .unwrap();
    let sibling = primary.with_auth(AuthMode::Open).unwrap();
    assert_eq!(sibling.cfg.ref_policy, primary.cfg.ref_policy);
    let lookup = |_: &str| None;
    let auth = sibling
        .authenticate(&RequestMeta {
            procedure: Procedure::UpdateRef,
            header: &lookup,
            header_values: None,
            unary_body: Some(&[]),
            transport_principal: None,
        })
        .unwrap();
    let error = block_on(sibling.update_ref(&auth, upd(HEAD, Missing, A))).unwrap_err();
    denied(&error, SIGNER_MESSAGE);
}

#[test]
fn fast_forward_only_needs_indexed_mode_and_a_valid_policy() {
    for (policy, indexed, ok) in [
        (ff_main(), None, false),
        (ff_main(), Some(IndexedConfig::default()), true),
        (RefPolicy::new(vec![rule(HEAD, None, false)]), None, true),
        (
            RefPolicy::new(vec![RefRule {
                pattern: RefPattern::Exact(PACKMAP.into()),
                allowed_signers: None,
                fast_forward_only: false,
            }]),
            None,
            false,
        ),
    ] {
        let mut config = grants::config(&key(7), AuthorizerRole::Check);
        config.indexed = indexed;
        config.ref_policy = Some(policy);
        let clock = clock();
        let built = Pipeline::new(
            MemoryBlobStore::default(),
            store(&clock),
            Hooks::new(),
            config,
            clock,
            Arc::new(SpyMetrics::default()),
        );
        assert_eq!(built.is_ok(), ok);
    }
}

#[test]
fn fast_forward_only_follows_staged_and_member_history_and_refuses_the_rest() {
    let mut w = World::indexed(Some(ff_main()));
    let [id1, id2, id3, stray] = w.history();
    assert_eq!(w.value(HEAD), Some(id2));
    // Staged: c4 and c5 arrive together, so the walk reads no member.
    let (c4, id4) = commit(&[id3], 5);
    let (c5, id5) = commit(&[id4], 6);
    // Member-only history: `feature` already holds c3; main fast-forwards to
    // it through c3 -> c2, reading one member commit.
    assert_eq!(
        w.update(HEAD, Match(id2), Some(id3)).unwrap(),
        UpdateRefResult::Committed
    );
    assert_eq!(
        w.push("main", &[&c4, &c5], id5, Match(id3)).unwrap(),
        AdvanceOutcome::Committed
    );
    assert_eq!(w.value(HEAD), Some(id5));
    // Not a fast-forward: c4' forks off c3 while main sits at c5.
    let (fork, fork_id) = commit(&[id3], 7);
    let error = w.push("main", &[&fork], fork_id, Match(id5)).unwrap_err();
    denied(&error, FF_MESSAGE);
    // A member that is not a descendant, ticketless.
    denied(
        &w.update(HEAD, Match(id5), Some(stray)).unwrap_err(),
        FF_MESSAGE,
    );
    denied(
        &w.update(HEAD, Match(id5), Some(id1)).unwrap_err(),
        FF_MESSAGE,
    );
    // Delete is refused on both routes.
    denied(&w.update(HEAD, Match(id5), None).unwrap_err(), FF_MESSAGE);
    let auth = w.auth(Procedure::AdvanceRefs);
    let delete = RefUpdate {
        name: HEAD.into(),
        condition: Match(id5),
        new: None,
    };
    let packmap = RefUpdate {
        name: PACKMAP.into(),
        condition: Match(B),
        new: None,
    };
    let error = block_on(w.env.pipe.advance_refs(&auth, delete, packmap)).unwrap_err();
    denied(&error, FF_MESSAGE);
    assert_eq!(w.value(HEAD), Some(id5));
    // Creation is allowed, and an unrelated ref is not bound by the rule.
    assert_eq!(
        w.update("refs/heads/copy", Missing, Some(stray)).unwrap(),
        UpdateRefResult::Committed
    );
    assert_eq!(
        w.update("refs/heads/feature", Match(id3), Some(stray))
            .unwrap(),
        UpdateRefResult::Committed
    );
    assert_eq!(w.unchecked(), 0);
}

#[test]
fn fast_forward_walks_a_merges_second_parent() {
    let mut w = World::indexed(Some(ff_main()));
    let [id1, id2, id3, stray] = w.history();
    // `merge` has parents [stray, c3]: c3 is reached as its second parent.
    let (merge, merge_id) = commit(&[stray, id3], 8);
    assert_eq!(
        w.push("merged", &[&merge], merge_id, Missing).unwrap(),
        AdvanceOutcome::Committed
    );
    // main (c2) is an ancestor of merge only through the second parent.
    assert_eq!(
        w.update(HEAD, Match(id2), Some(merge_id)).unwrap(),
        UpdateRefResult::Committed
    );
    assert_eq!(w.value(HEAD), Some(merge_id));
    // A commit c1 is an ancestor, not a descendant, of the merge.
    denied(
        &w.update(HEAD, Match(merge_id), Some(id1)).unwrap_err(),
        FF_MESSAGE,
    );
}

#[test]
fn any_on_a_present_fast_forward_only_ref_becomes_match_and_loses_a_race() {
    use std::sync::atomic::{AtomicBool, Ordering::SeqCst};
    let (armed, raced) = (
        Arc::new(AtomicBool::new(false)),
        Arc::new(AtomicBool::new(false)),
    );
    let (arm, once) = (armed.clone(), raced.clone());
    let mut w = World::with_store(
        Some(ff_main()),
        Some(IndexedConfig::default()),
        move |clock| {
            Spy::new(store(clock)).hook(move |inner, partition, batch| {
                let name = RepoName::new(REPO).unwrap();
                let ref_key = keys::ref_key(&name, HEAD);
                let guarded = batch
                    .preconditions
                    .iter()
                    .any(|pre| matches!(pre, Precondition::Equals(k, _) if *k == ref_key));
                if guarded && arm.load(SeqCst) && !once.swap(true, SeqCst) {
                    let moved = Batch::new().put(ref_key, codec::encode_ref_id(&[0x77; 32]));
                    assert_eq!(
                        now(inner.apply(partition, moved)).unwrap(),
                        BatchOutcome::Committed
                    );
                }
            })
        },
    );
    let [_, _, id3, _] = w.history();
    armed.store(true, SeqCst);
    // ANY over a present ref is checked against the value it observed (c2)
    // and guarded by it: the concurrent move makes the CAS lose.
    assert_eq!(
        w.update(HEAD, Any, Some(id3)).unwrap(),
        UpdateRefResult::Conflict {
            current: Some([0x77; 32])
        }
    );
    assert!(raced.load(SeqCst));
}

#[test]
fn any_on_a_fast_forward_only_ref_checks_the_observed_value() {
    let mut w = World::indexed(Some(ff_main()));
    let [_, _, id3, stray] = w.history();
    denied(&w.update(HEAD, Any, Some(stray)).unwrap_err(), FF_MESSAGE);
    assert_eq!(
        w.update(HEAD, Any, Some(id3)).unwrap(),
        UpdateRefResult::Committed
    );
    assert_eq!(w.value(HEAD), Some(id3));
    // ANY creating an absent ref is allowed and guarded as a creation, and
    // once present the same ref is checked against its observed value.
    let any_branch = RefPolicy::new(vec![rule("refs/heads/*", None, true)]);
    let mut w = World::indexed(Some(any_branch));
    let [id1, _, _, stray] = w.history();
    assert_eq!(
        w.update("refs/heads/main2", Any, Some(stray)).unwrap(),
        UpdateRefResult::Committed
    );
    denied(
        &w.update("refs/heads/main2", Any, Some(id1)).unwrap_err(),
        FF_MESSAGE,
    );
    assert_eq!(w.value("refs/heads/main2"), Some(stray));
}

fn update_only_grantee(w: &World, flags: &str) -> (SigningKey, String) {
    let grantee = key(2);
    let header = grants::grant(&w.owner, &grantee, |grant| {
        grant.ref_scopes = Some(RefScopes::parse(&format!("{HEAD}={flags}")).unwrap());
    });
    (grantee, header)
}

#[test]
fn update_only_grant_fast_forwards_in_indexed_mode_and_denies_the_rest() {
    let mut w = World::indexed(None);
    let [_, id2, id3, stray] = w.history();
    let (grantee, header) = update_only_grantee(&w, "u");
    let identity = w.identity.clone();
    let change = |new| RefUpdate {
        name: HEAD.into(),
        condition: Match(id2),
        new: Some(new),
    };
    let error = w
        .update_as((&grantee, &identity, T0), Some(&header), change(stray))
        .unwrap_err();
    denied(&error, "write grant rejected: ref scope");
    assert_eq!(w.value(HEAD), Some(id2));
    assert_eq!(
        w.update_as((&grantee, &identity, T0), Some(&header), change(id3))
            .unwrap(),
        UpdateRefResult::Committed
    );
    assert_eq!(w.value(HEAD), Some(id3));
    assert_eq!(w.unchecked(), 0);
}

#[test]
fn update_only_grant_stays_fail_closed_in_opaque_mode() {
    let mut w = World::new(None, None);
    let (grantee, header) = update_only_grantee(&w, "u");
    let identity = w.identity.clone();
    let change = RefUpdate {
        name: HEAD.into(),
        condition: Match(A),
        new: Some(B),
    };
    let error = w
        .update_as((&grantee, &identity, T0), Some(&header), change)
        .unwrap_err();
    denied(&error, "update without force needs indexed mode");
    // Nothing looked at the index.
    assert_eq!(w.index_reads(), 0);
}

#[test]
fn force_grant_skips_the_walk_and_a_capped_walk_denies_with_a_metric() {
    let capped = IndexedConfig {
        max_ancestry_commits: 1,
        ..IndexedConfig::default()
    };
    let mut w = World::new(None, Some(capped));
    let [id1, id2, id3, stray] = w.history();
    let identity = w.identity.clone();
    // c3 -> c2 -> c1 needs two member reads with a cap of one.
    let (grantee, header) = update_only_grantee(&w, "u");
    let change = RefUpdate {
        name: HEAD.into(),
        condition: Match(id1),
        new: Some(id3),
    };
    let error = w
        .update_as((&grantee, &identity, T0), Some(&header), change)
        .unwrap_err();
    denied(&error, "write grant rejected: ref scope");
    assert_eq!(w.unchecked(), 1);
    // `uf` needs no ancestry: a non-descendant commits although its walk
    // would have been denied, and the metric does not move.
    let (forcer, force_header) = update_only_grantee(&w, "uf");
    let force = RefUpdate {
        name: HEAD.into(),
        condition: Match(id2),
        new: Some(stray),
    };
    assert_eq!(
        w.update_as((&forcer, &identity, T0), Some(&force_header), force)
            .unwrap(),
        UpdateRefResult::Committed
    );
    assert_eq!(w.value(HEAD), Some(stray));
    assert_eq!(w.unchecked(), 1);
}

#[test]
fn staged_history_costs_no_member_reads_and_survives_a_cap_of_one() {
    let capped = IndexedConfig {
        max_ancestry_commits: 1,
        ..IndexedConfig::default()
    };
    let mut w = World::new(Some(ff_main()), Some(capped));
    let [_, id2, id3, _] = w.history();
    let (c4, id4) = commit(&[id3], 5);
    let (c5, id5) = commit(&[id4], 6);
    // main = c2 -> c5: staged c5 and c4, then member c3 (one read, the cap).
    assert_eq!(
        w.push("main", &[&c4, &c5], id5, Match(id2)).unwrap(),
        AdvanceOutcome::Committed
    );
    assert_eq!(w.unchecked(), 0);
}

#[test]
fn lag_miss_mid_walk_is_retryable_inside_the_window_and_permanent_after() {
    let mut w = World::indexed(Some(ff_main()));
    let [id1, id2, id3, _] = w.history();
    let (owner, identity) = (w.owner.clone(), w.identity.clone());
    // main sits at c1 and c2's membership is not visible yet: the walk
    // c3 -> c2 -> c1 misses c2 before it can reach c1.
    w.set_ref(HEAD, &id1);
    let row = w.hide(&id2);
    let req = w.req(&owner, &identity, Procedure::UpdateRef, T0);
    let change = RefUpdate {
        name: HEAD.into(),
        condition: Match(id1),
        new: Some(id3),
    };
    let attempt = |w: &World| {
        let auth = w.env.auth(&req).unwrap();
        block_on(w.env.pipe.update_ref(&auth, change.clone()))
    };
    let error = attempt(&w).unwrap_err();
    assert_eq!(error.code(), Code::Unavailable);
    assert_eq!(error.public_message(), NOT_VISIBLE);
    // Not stored: once the row is visible the same nonce commits.
    w.restore(&id2, row);
    assert_eq!(attempt(&w).unwrap(), UpdateRefResult::Committed);

    // After the window the same miss is the permanent policy denial.
    w.set_ref(HEAD, &id1);
    w.hide(&id2);
    w.env.clock.advance(LAG_MS);
    let later = w.req(&owner, &identity, Procedure::UpdateRef, T0);
    let auth = w.env.auth(&later).unwrap();
    let error = block_on(w.env.pipe.update_ref(&auth, change.clone())).unwrap_err();
    denied(&error, FF_MESSAGE);
}

#[test]
fn ticketless_head_must_be_a_member_commit_of_this_repository() {
    let mut answers = Vec::new();
    for foreign_exists in [false, true] {
        let mut w = World::indexed(None);
        let (c1, id1) = commit(&[], 1);
        if foreign_exists {
            assert_eq!(
                w.push("main", &[&tree(), &c1], id1, Missing).unwrap(),
                AdvanceOutcome::Committed
            );
        }
        // Repository B never saw c1.
        let (owner, other) = (w.owner.clone(), w.other_identity("other"));
        let mut per_time = Vec::new();
        for offset in [0, LAG_MS] {
            w.env.clock.advance(offset);
            let change = RefUpdate {
                name: "refs/heads/x".into(),
                condition: Missing,
                new: Some(id1),
            };
            let error = w.update_as((&owner, &other, T0), None, change).unwrap_err();
            per_time.push((
                error.code(),
                error.public_message().to_owned(),
                error.details().to_vec(),
            ));
        }
        assert_eq!(per_time[0].0, Code::Unavailable);
        assert_eq!(per_time[0].1, NOT_VISIBLE);
        assert_eq!(per_time[1].0, Code::InvalidArgument);
        assert_eq!(per_time[1].1, "open closure");
        answers.push(per_time);
    }
    assert_eq!(
        answers[0], answers[1],
        "byte-identical whether or not repository A has it"
    );
}

#[test]
fn ticketless_head_rejects_non_history_members_and_accepts_commits() {
    let mut w = World::indexed(None);
    let [id1, _, id3, _] = w.history();
    // A member tree is not a tip.
    let tree_id = tree().id().unwrap();
    let error = w
        .update("refs/heads/tree", Missing, Some(tree_id))
        .unwrap_err();
    assert_eq!(error.code(), Code::InvalidArgument);
    assert_eq!(error.public_message(), "open closure");
    // A member commit passes, ticketless, on both routes.
    assert_eq!(
        w.update("refs/heads/copy", Missing, Some(id3)).unwrap(),
        UpdateRefResult::Committed
    );
    let auth = w.auth(Procedure::AdvanceRefs);
    assert_eq!(
        block_on(w.env.pipe.advance_refs(
            &auth,
            upd("refs/heads/again", Missing, id1),
            upd("refs/mkit/packmap/again", Missing, B),
        ))
        .unwrap(),
        AdvanceOutcome::Committed
    );
    // A delete names no head, and a packmap ref is not a head.
    assert_eq!(
        w.update("refs/heads/copy", Match(id3), None).unwrap(),
        UpdateRefResult::Committed
    );
    assert_eq!(
        w.update("refs/mkit/packmap/free", Missing, Some(B))
            .unwrap(),
        UpdateRefResult::Committed
    );
}

#[test]
fn ticketless_lag_window_follows_the_signed_created_at_clamped_to_now() {
    let mut w = World::indexed(None);
    let (owner, identity) = (w.owner.clone(), w.identity.clone());
    let unknown = RefUpdate {
        name: "refs/heads/x".into(),
        condition: Missing,
        new: Some(A),
    };
    // Signed a full window ago: the answer is already permanent.
    let stale = (&owner, identity.as_str(), T0 - LAG_MS);
    let error = w.update_as(stale, None, unknown.clone()).unwrap_err();
    assert_eq!(error.public_message(), "open closure");
    // Signed now: retryable.
    let error = w
        .update_as((&owner, &identity, T0), None, unknown.clone())
        .unwrap_err();
    assert_eq!(error.public_message(), NOT_VISIBLE);
    // The boundary follows the signed `x-created-at` exactly: a request
    // signed 20 s ahead of the server clock (inside the permitted skew) turns
    // permanent one window after that instant.
    let future = w.req(&owner, &identity, Procedure::UpdateRef, T0 + 20_000);
    let attempt = |w: &World| {
        let auth = w.env.auth(&future).unwrap();
        block_on(w.env.pipe.update_ref(&auth, unknown.clone())).unwrap_err()
    };
    assert_eq!(attempt(&w).public_message(), NOT_VISIBLE);
    w.env.clock.advance(LAG_MS + 20_000 - 1);
    assert_eq!(attempt(&w).public_message(), NOT_VISIBLE);
    w.env.clock.advance(1);
    assert_eq!(attempt(&w).public_message(), "open closure");
}

#[test]
fn opaque_and_default_configs_never_touch_the_policy_or_the_index() {
    // No policy, opaque: a ticketless write of an unrelated hash works and
    // reads nothing from the object index.
    let mut w = World::new(None, None);
    assert_eq!(
        w.update(HEAD, Missing, Some(A)).unwrap(),
        UpdateRefResult::Committed
    );
    assert_eq!(
        w.update(HEAD, Match(A), None).unwrap(),
        UpdateRefResult::Committed
    );
    assert_eq!(w.index_reads(), 0);
    assert_eq!(w.unchecked(), 0);
    // Indexed with no policy: a non-fast-forward by the owner is allowed.
    let mut w = World::indexed(None);
    let [_, id2, _, stray] = w.history();
    assert_eq!(
        w.update(HEAD, Match(id2), Some(stray)).unwrap(),
        UpdateRefResult::Committed
    );
    assert_eq!(w.unchecked(), 0);
}

#[test]
fn ticketed_lag_window_runs_from_the_earliest_ticket() {
    let mut w = World::indexed(Some(ff_main()));
    let [id1, id2, id3, _] = w.history();
    // main sits at c1 with c2 not yet visible; c4 (staged) reaches c1 only
    // through member c3 -> c2.
    w.set_ref(HEAD, &id1);
    let row = w.hide(&id2);
    let (c4, id4) = commit(&[id3], 5);
    let ticket = w.begin("main", &[&c4]).unwrap();
    let error = w.advance("main", &ticket, id4, Match(id1)).unwrap_err();
    assert_eq!(error.code(), Code::Unavailable);
    assert_eq!(error.public_message(), NOT_VISIBLE);
    // The ticket, not the request, opens the window: after it, permanent.
    w.env.clock.advance(LAG_MS);
    let error = w.advance("main", &ticket, id4, Match(id1)).unwrap_err();
    denied(&error, FF_MESSAGE);
    // Visible again: the same ticket now commits.
    w.restore(&id2, row);
    assert_eq!(
        w.advance("main", &ticket, id4, Match(id1)).unwrap(),
        AdvanceOutcome::Committed
    );
}

#[test]
fn walk_answers_do_not_depend_on_other_repositories() {
    let mut answers = Vec::new();
    for foreign_history in [false, true] {
        let mut w = World::indexed(Some(ff_main()));
        let (stray, stray_id) = commit(&[], 4);
        let (c1, id1) = commit(&[], 1);
        let (c2, id2) = commit(&[id1], 2);
        if foreign_history {
            w.push("main", &[&tree(), &c1], id1, Missing).unwrap();
            w.push("other", &[&c2], id2, Missing).unwrap();
        }
        // Repository B holds only `stray`; `from` (c2) is a member of A or of
        // nothing at all, and the answers must be byte-identical.
        w.identity = w.other_identity("other");
        w.push("main", &[&tree(), &stray], stray_id, Missing)
            .unwrap();
        let error = w.update(HEAD, Match(id2), Some(stray_id)).unwrap_err();
        denied(&error, FF_MESSAGE);
        answers.push((
            error.code(),
            error.public_message().to_owned(),
            error.details().to_vec(),
        ));
    }
    assert_eq!(answers[0], answers[1]);
}

#[test]
fn a_ticketless_advance_must_pair_a_head_with_its_own_packmap() {
    let mut w = World::indexed(Some(ff_main()));
    let [_, id2, _, stray] = w.history();
    // The head is a free branch but the second ref is protected `main`.
    let auth = w.auth(Procedure::AdvanceRefs);
    let error = block_on(w.env.pipe.advance_refs(
        &auth,
        upd("refs/heads/free", Missing, stray),
        upd(HEAD, Any, stray),
    ))
    .unwrap_err();
    assert_eq!(error.code(), Code::InvalidArgument);
    assert_eq!(w.value(HEAD), Some(id2));
}
