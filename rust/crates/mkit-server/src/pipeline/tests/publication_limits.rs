//! Baseline publication-verification behavior of the selected verifier paths.
//!
//! These tests pin what main must keep doing, not how much it can do: valid
//! publications of every ref kind succeed under each path, invalid or
//! over-capacity ones are refused (or stay pending) without any effect, and
//! two reuse scenarios that an incremental verifier could weaken stay refused.
//! They deliberately avoid asserting an exact object count at which capacity
//! runs out, because that count is an implementation detail of each path.
#![allow(clippy::unwrap_used)] // Invalid fixtures should fail the test immediately.
use super::indexed::{environment_with, signed};
use super::*;
use crate::store::BorrowedStore;
use mkit_core::object::{Blob, Commit, EntryMode, Identity, Object, Tree, TreeEntry};
use mkit_core::pack::PackWriter;
use mkit_core::serialize::serialize;
use mkit_core::sign::{KeyPair, sign_commit};
use mkit_core::transfer::encode_packlist;
use std::cell::Cell;

/// The publication verifier a deployment selected.
#[derive(Clone, Copy, Debug)]
enum Path {
    /// Takedown denial only: resumable metadata path for branch pairs.
    Takedown,
    /// Takedown plus a custom publication policy: canonical proof.
    Custom,
    /// Takedown plus synchronous inspection: canonical proof.
    #[cfg(feature = "remote-hooks")]
    Inspected,
}

#[cfg(feature = "remote-hooks")]
const PATHS: &[Path] = &[Path::Takedown, Path::Custom, Path::Inspected];
#[cfg(not(feature = "remote-hooks"))]
const PATHS: &[Path] = &[Path::Takedown, Path::Custom];

#[cfg(feature = "remote-hooks")]
struct Scanner(AtomicU32);
#[cfg(feature = "remote-hooks")]
impl crate::pipeline::inspection::ContentInspector for Scanner {
    fn id(&self) -> &'static str {
        "limits-scanner"
    }
    fn inspect<'a>(
        &'a self,
        _: &'a Operation,
        _: &'a str,
        _: &'a [mkit_rpc::hooks::InspectObject],
    ) -> crate::BoxFuture<'a, Result<crate::hooks::InspectVerdict, ServerError>> {
        Box::pin(async move {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(crate::hooks::InspectVerdict::Pass)
        })
    }
}

fn commit(tree: Hash, parent: Option<Hash>, number: u64) -> Object {
    let key = KeyPair::from_seed([9; 32]);
    let mut value = Commit::new_unannotated(
        tree,
        parent.into_iter().collect(),
        Identity::ed25519(key.public.0),
        key.public.0,
        b"limits".to_vec(),
        number,
        [0; 64],
    );
    value.signature = sign_commit(&value, &key).unwrap().0;
    Object::Commit(value)
}

fn blob(tag: u32) -> Object {
    Object::Blob(Blob {
        data: tag.to_be_bytes().repeat(4),
    })
}

fn tree(files: &[(&str, &Object)]) -> Object {
    Object::Tree(Tree {
        entries: files
            .iter()
            .map(|(name, object)| TreeEntry {
                name: name.as_bytes().to_vec(),
                mode: EntryMode::Blob,
                object_hash: object.id().unwrap(),
            })
            .collect(),
    })
}

fn pack(objects: &[&Object]) -> Vec<u8> {
    let mut writer = PackWriter::new_raw_only();
    for object in objects {
        writer
            .push_raw(object.id().unwrap(), &serialize(object).unwrap())
            .unwrap();
    }
    writer.finish().unwrap()
}

/// A pack, its packmap node and the head it delivers.
struct Push {
    bytes: Vec<u8>,
    node: Vec<u8>,
    head: Hash,
}
impl Push {
    fn new(objects: &[&Object], head: &Object, parent_map: Option<Hash>, extra: &[Hash]) -> Self {
        let bytes = pack(objects);
        let mut packs = vec![hash(&bytes)];
        packs.extend_from_slice(extra);
        Self {
            node: encode_packlist(parent_map, &packs).unwrap(),
            bytes,
            head: head.id().unwrap(),
        }
    }
    fn map(&self) -> Hash {
        hash(&self.node)
    }
}

type Attempt = Result<(), ServerError>;

fn is_pending(result: &Attempt) -> bool {
    result
        .as_ref()
        .is_err_and(|e| e.public_message() == "pack verification pending")
}

fn branch(name: &str) -> (String, String) {
    (
        format!("refs/heads/{name}"),
        format!("refs/mkit/packmap/{name}"),
    )
}

struct World {
    env: Env,
    owner: SigningKey,
    identity: String,
    repo: RepoId,
    nonce: Cell<u32>,
    #[cfg(feature = "remote-hooks")]
    scanner: Arc<Scanner>,
}

/// Everything a failed preparation must leave untouched.
#[derive(PartialEq, Debug)]
struct Effects {
    refs: Vec<Option<Hash>>,
    memberships: Vec<bool>,
    tickets: Vec<Option<Vec<u8>>>,
    scans: u32,
}

impl World {
    fn new(path: Path) -> Self {
        let (mut env, owner, identity) =
            environment_with(Sharding::Single, crate::indexed::IndexedConfig::default());
        env.pipe.cfg.begin_upload_threshold_bytes = 0;
        env.pipe.cfg.takedown_denial = true;
        #[cfg(feature = "remote-hooks")]
        let scanner = Arc::new(Scanner(AtomicU32::new(0)));
        match path {
            Path::Takedown => {}
            Path::Custom => env.pipe.publication_policy = Some(Arc::new(clearance::Immediate)),
            #[cfg(feature = "remote-hooks")]
            Path::Inspected => {
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
            }
        }
        let request = signed(&owner, &identity, Procedure::UpdateRef, 1);
        let repo = env.auth(&request).unwrap().repo().repo.clone();
        Self {
            env,
            owner,
            identity,
            repo,
            nonce: Cell::new(100),
            #[cfg(feature = "remote-hooks")]
            scanner,
        }
    }

    fn nonce(&self) -> u32 {
        self.nonce.set(self.nonce.get() + 1);
        self.nonce.get()
    }

    #[cfg_attr(not(feature = "remote-hooks"), allow(clippy::unused_self))]
    fn scans(&self) -> u32 {
        #[cfg(feature = "remote-hooks")]
        return self.scanner.0.load(Ordering::SeqCst);
        #[cfg(not(feature = "remote-hooks"))]
        0
    }

    /// An upload ticket is bound to the branch it will advance.
    fn upload(&self, head_ref: &str, bytes: &[u8]) -> Hash {
        let request = signed(
            &self.owner,
            &self.identity,
            Procedure::BeginUpload,
            self.nonce(),
        );
        let BeginUploadResult::Ticket { id, .. } = block_on(self.env.pipe.begin_upload(
            &self.env.auth(&request).unwrap(),
            head_ref,
            &hash(bytes),
            bytes.len() as u64,
        ))
        .unwrap() else {
            panic!("expected upload ticket");
        };
        super::indexed::upload(&self.env, bytes, id);
        id
    }

    fn tickets(&self, head_ref: &str, push: &Push) -> Vec<Hash> {
        vec![
            self.upload(head_ref, &push.bytes),
            self.upload(head_ref, &push.node),
        ]
    }

    fn source(&self) -> Partition {
        self.env.pipe.shards.ref_shard(&self.repo, HEAD)
    }

    fn fire(&self) {
        let timers = crate::timers::TimerRegistry::new().register(
            crate::timers::publication_recheck::PublicationRecheck::new(BorrowedStore(
                &self.env.pipe.meta,
            )),
        );
        block_on(crate::timers::run_due(
            &self.env.pipe.meta,
            &self.source(),
            &timers,
            self.env.clock.as_ref(),
            u64::try_from(self.env.clock.now_ms()).unwrap(),
            &crate::timers::TickBudget::default(),
        ))
        .unwrap();
    }

    /// Retries a pending publication, running real alarm slices between
    /// attempts. The returned result is the first non-pending one, or the last
    /// pending one after `rounds` attempts.
    fn settle(&self, rounds: u32, mut attempt: impl FnMut(&Self) -> Attempt) -> Attempt {
        let mut result = attempt(self);
        for _ in 0..rounds {
            if !is_pending(&result) {
                break;
            }
            self.env.clock.advance(1000);
            self.fire();
            result = attempt(self);
        }
        result
    }

    fn lag(&self) {
        self.env.clock.advance(
            i64::try_from(crate::indexed::IndexedConfig::default().relay_lag_bound_ms).unwrap(),
        );
    }

    fn advance(
        &self,
        (head_ref, map_ref): &(String, String),
        old: Option<(Hash, Hash)>,
        new: (Hash, Hash),
        tickets: &[Hash],
    ) -> Attempt {
        let cond = |old: Option<Hash>| old.map_or(Missing, Match);
        let request = signed(
            &self.owner,
            &self.identity,
            Procedure::AdvanceRefs,
            self.nonce(),
        );
        let auth = self.env.auth(&request).unwrap();
        let (a, b) = (
            upd(head_ref, cond(old.map(|o| o.0)), new.0),
            upd(map_ref, cond(old.map(|o| o.1)), new.1),
        );
        if tickets.is_empty() {
            block_on(self.env.pipe.advance_refs(&auth, a, b)).map(|_| ())
        } else {
            block_on(
                self.env
                    .pipe
                    .advance_refs_with_tickets(&auth, a, b, tickets.to_vec()),
            )
            .map(|_| ())
        }
    }

    fn update(&self, name: &str, old: Option<Hash>, new: Option<Hash>) -> Attempt {
        let request = signed(
            &self.owner,
            &self.identity,
            Procedure::UpdateRef,
            self.nonce(),
        );
        let auth = self.env.auth(&request).unwrap();
        let update = RefUpdate {
            name: name.to_owned(),
            condition: old.map_or(Missing, Match),
            new,
        };
        block_on(self.env.pipe.update_ref(&auth, update)).map(|_| ())
    }

    /// Publishes `push` on `names`, settling pending proofs. Must commit.
    fn publish(&self, names: &(String, String), old: Option<(Hash, Hash)>, push: &Push) -> Hash {
        let tickets = self.tickets(&names.0, push);
        let result = self.settle(60, |w| {
            w.advance(names, old, (push.head, push.map()), &tickets)
        });
        result.unwrap_or_else(|e| panic!("fixture publication refused: {e:?}"));
        push.map()
    }

    fn read(&self, name: &str) -> Option<Hash> {
        let source = self.env.pipe.shards.ref_shard(&self.repo, name);
        block_on(read::read_ref(
            &self.env.pipe.meta,
            &source,
            &self.repo.name,
            name,
        ))
        .unwrap()
    }

    fn pair(&self, names: &(String, String)) -> (Option<Hash>, Option<Hash>) {
        (self.read(&names.0), self.read(&names.1))
    }

    fn effects(&self, names: &[&str], packs: &[Hash], tickets: &[Hash]) -> Effects {
        let source = self.source();
        Effects {
            refs: names.iter().map(|n| self.read(n)).collect(),
            memberships: packs
                .iter()
                .map(|p| {
                    block_on(
                        self.env
                            .pipe
                            .meta
                            .get(&source, &keys::membership(&self.repo.name, p)),
                    )
                    .unwrap()
                    .is_some()
                })
                .collect(),
            tickets: tickets
                .iter()
                .map(|t| {
                    block_on(self.env.pipe.meta.get(&source, &keys::ticket(t)))
                        .unwrap()
                        .map(|v| v.as_bytes().to_vec())
                })
                .collect(),
            scans: self.scans(),
        }
    }

    fn block(&self, id: &Hash, tag: u8) {
        let at = u64::try_from(self.env.clock.now_ms()).unwrap();
        let action = crate::takedown::denial::BlockAction {
            id: [tag; 32],
            takedown_id: [tag + 1; 32],
            reason: "denied".into(),
            blocked_at_ms: at,
            chunk_ids: vec![],
        };
        block_on(
            crate::store::ContentIndex::new(BorrowedStore(&self.env.pipe.meta))
                .install_block_action(id, &action, at),
        )
        .unwrap();
    }
}

/// A small published history: `c1 <- c2` on `refs/heads/main`, with the file
/// `b1` and tree `t1` in the first pack and the second pack holding one commit.
struct History {
    names: (String, String),
    first: Push,
    second: Push,
    blob: Object,
}

fn history(world: &World) -> History {
    let b1 = blob(1);
    let t1 = tree(&[("f", &b1)]);
    let c1 = commit(t1.id().unwrap(), None, 1);
    let first = Push::new(&[&b1, &t1, &c1], &c1, None, &[]);
    let c2 = commit(t1.id().unwrap(), Some(c1.id().unwrap()), 2);
    let second = Push::new(&[&c2], &c2, Some(first.map()), &[]);
    let names = (HEAD.to_owned(), PACKMAP.to_owned());
    world.publish(&names, None, &first);
    world.publish(&names, Some((first.head, first.map())), &second);
    History {
        names,
        first,
        second,
        blob: b1,
    }
}

/// A repository-unrelated root commit with its own pack and chain.
fn unrelated(number: u32) -> Push {
    let file = blob(900 + number);
    let root = tree(&[("g", &file)]);
    let head = commit(root.id().unwrap(), None, 900 + u64::from(number));
    Push::new(&[&file, &root, &head], &head, None, &[])
}

fn pair_of(push: &Push) -> (Hash, Hash) {
    (push.head, push.map())
}

#[test]
fn valid_publications_of_every_ref_kind_succeed_under_each_path() {
    for &path in PATHS {
        let w = World::new(path);
        let h = history(&w);
        let tip = pair_of(&h.second);
        let ctx = |what: &str| format!("{path:?}: {what}");

        // Same-pair new branch: ticketless reuse of the published pair.
        let other = branch("copy");
        w.settle(60, |w| w.advance(&other, None, tip, &[]))
            .unwrap_or_else(|e| panic!("{}: {e:?}", ctx("same-pair new branch")));
        assert_eq!(w.pair(&other), (Some(tip.0), Some(tip.1)));

        // Tag / mapless head over the published commit.
        w.settle(60, |w| w.update("refs/tags/v1", None, Some(tip.0)))
            .unwrap_or_else(|e| panic!("{}: {e:?}", ctx("tag")));
        assert_eq!(w.read("refs/tags/v1"), Some(tip.0));

        // Head-only change to an ancestor that the unchanged chain covers.
        w.settle(60, |w| {
            w.update(HEAD, Some(h.second.head), Some(h.first.head))
        })
        .unwrap_or_else(|e| panic!("{}: {e:?}", ctx("head-only")));
        assert_eq!(w.read(HEAD), Some(h.first.head));
        w.settle(60, |w| {
            w.update(HEAD, Some(h.first.head), Some(h.second.head))
        })
        .unwrap_or_else(|e| panic!("{}: {e:?}", ctx("head-only restore")));

        // Existing branch moved to an unrelated root (force push) with its own
        // freshly uploaded chain.
        let fresh = unrelated(1);
        let tickets = w.tickets(&h.names.0, &fresh);
        w.settle(60, |w| {
            w.advance(&h.names, Some(tip), pair_of(&fresh), &tickets)
        })
        .unwrap_or_else(|e| panic!("{}: {e:?}", ctx("unrelated force push")));
        assert_eq!(w.pair(&h.names), (Some(fresh.head), Some(fresh.map())));

        // Deletion publishes immediately and never reaches an inspector.
        let scans = w.scans();
        w.settle(60, |w| w.update("refs/tags/v1", Some(tip.0), None))
            .unwrap_or_else(|e| panic!("{}: {e:?}", ctx("tag deletion")));
        assert_eq!(w.read("refs/tags/v1"), None);
        assert_eq!(w.scans(), scans, "{}", ctx("deletion scans nothing"));
    }
}

#[test]
fn head_only_and_map_only_changes_refuse_an_uncovered_counterpart() {
    for &path in PATHS {
        let w = World::new(path);
        let h = history(&w);
        // A second, independent branch supplies members that main's chain
        // does not cover.
        let side = unrelated(2);
        let side_names = branch("side");
        w.publish(&side_names, None, &side);
        let tip = pair_of(&h.second);
        for (name, old, new) in [(HEAD, tip.0, side.head), (PACKMAP, tip.1, side.map())] {
            w.lag();
            let before = w.effects(&[HEAD, PACKMAP], &[], &[]);
            let result = w.settle(60, |w| w.update(name, Some(old), Some(new)));
            let error = result.expect_err(&format!("{path:?}: {name} must not publish"));
            assert_eq!(error.code(), Code::InvalidArgument, "{path:?} {name}");
            assert_eq!(error.public_message(), "open closure", "{path:?} {name}");
            assert_eq!(w.effects(&[HEAD, PACKMAP], &[], &[]), before);
        }
    }
}

/// A closure far beyond every selected path's capacity, as one ticketed push
/// onto a new or existing branch, is refused or left pending, never published,
/// and leaves no effect behind. A small closure of the same shape publishes, so
/// the refusal is about capacity and not about the fixture.
#[test]
fn over_capacity_closure_fails_closed_without_effects() {
    const CONTROL: u32 = 16;
    const BLOBS: u32 = 4_300;
    for &path in PATHS {
        for (existing, blobs) in [
            (false, CONTROL),
            (true, CONTROL),
            (false, BLOBS),
            (true, BLOBS),
        ] {
            let w = World::new(path);
            let (names, old, parent_map, parent_head) = if existing {
                let h = history(&w);
                (
                    h.names,
                    Some(pair_of(&h.second)),
                    Some(h.second.map()),
                    Some(h.second.head),
                )
            } else {
                (branch("big"), None, None, None)
            };
            let files: Vec<Object> = (0..blobs).map(|n| blob(10_000 + n)).collect();
            let listing: Vec<(String, &Object)> = files
                .iter()
                .enumerate()
                .map(|(n, o)| (format!("f{n:06}"), o))
                .collect();
            let big = tree(
                &listing
                    .iter()
                    .map(|(n, o)| (n.as_str(), *o))
                    .collect::<Vec<_>>(),
            );
            let head = commit(big.id().unwrap(), parent_head, 50);
            let mut objects: Vec<&Object> = files.iter().collect();
            objects.extend([&big, &head]);
            let push = Push::new(&objects, &head, parent_map, &[]);
            let tickets = w.tickets(&names.0, &push);
            let tracked = [names.0.as_str(), names.1.as_str()];
            w.lag();
            let before = w.effects(&tracked, &[hash(&push.bytes), push.map()], &tickets);
            let result = w.settle(30, |w| w.advance(&names, old, pair_of(&push), &tickets));
            if blobs == CONTROL {
                result.unwrap_or_else(|e| panic!("{path:?} existing={existing}: {e:?}"));
                assert_eq!(w.pair(&names), (Some(push.head), Some(push.map())));
                continue;
            }
            let error = result.expect_err(&format!(
                "{path:?} existing={existing}: over-capacity closure must not publish"
            ));
            // Refused for capacity or left pending, not for a fixture mistake.
            assert!(
                matches!(
                    error.public_message(),
                    "pack verification pending" | "publication verification capacity exhausted"
                ),
                "{path:?} existing={existing}: {error:?}"
            );
            assert_eq!(
                w.effects(&tracked, &[hash(&push.bytes), push.map()], &tickets),
                before,
                "{path:?} existing={existing}"
            );
        }
    }
}

/// Inspection bounds the whole dependency visibility of a pair by one fixed
/// call allowance, so a long chain of members is refused before any scanner
/// runs. This is a capacity refusal of the inspected path (`takedown` off, as
/// for a deployment that only inspects), not a statement about chain validity.
#[cfg(feature = "remote-hooks")]
#[test]
fn inspected_long_packmap_chain_fails_closed_before_scanning() {
    let mut w = World::new(Path::Inspected);
    w.env.pipe.cfg.takedown_denial = false;
    let witness = crate::store::publication::Witness {
        generation: 0,
        sequence: 1,
        published: true,
        held: false,
    }
    .encode();
    // 40 chained nodes of 110 member packs each, with no content: a chain that
    // is valid but far beyond what one inspected publication can verify.
    let mut parent = None;
    let mut index = 0_u32;
    for _ in 0..40 {
        let packs: Vec<Hash> = (0..110)
            .map(|_| {
                index += 1;
                hash(&index.to_be_bytes())
            })
            .collect();
        let node = encode_packlist(parent, &packs).unwrap();
        let id = hash(&node);
        super::indexed::upload(&w.env, &node, [8; 32]);
        for member in packs.iter().chain(std::iter::once(&id)) {
            let partition = w
                .env
                .pipe
                .shards
                .membership(&w.repo, &crate::BlobKey::pack(*member));
            block_on(
                w.env.pipe.meta.inner.apply(
                    &partition,
                    Batch::new()
                        .put(keys::membership(&w.repo.name, member), witness.clone())
                        .put(
                            keys::published_member(&w.repo.name, member),
                            witness.clone(),
                        ),
                ),
            )
            .unwrap();
        }
        parent = Some(id);
    }
    let root = parent.unwrap();
    w.lag();
    let before = w.effects(&[HEAD, PACKMAP], &[], &[]);
    let error = w
        .settle(30, |w| w.update(PACKMAP, None, Some(root)))
        .expect_err("a chain this long must not publish through the inspected path");
    // Spent execution capacity, not an invalid-content verdict.
    assert_eq!(error.code(), Code::Unavailable);
    assert_eq!(
        error.public_message(),
        "publication verification capacity exhausted"
    );
    assert_eq!(w.effects(&[HEAD, PACKMAP], &[], &[]), before);
}

/// An existing ref must not adopt another ref's pack holding a blocked id
/// unless that pack already belongs to this ref's own verified chain; a new
/// ref is refused for the same pack.
#[test]
fn existing_ref_adopting_a_pack_with_a_blocked_id_is_refused_like_a_new_ref() {
    for &path in PATHS {
        let w = World::new(path);
        let h = history(&w);
        // Force `main` to a clean root pair, then create `x` there.
        let clean = unrelated(3);
        let tickets = w.tickets(&h.names.0, &clean);
        w.settle(60, |w| {
            w.advance(
                &h.names,
                Some(pair_of(&h.second)),
                pair_of(&clean),
                &tickets,
            )
        })
        .unwrap();
        let x = branch("x");
        w.settle(60, |w| w.advance(&x, None, pair_of(&clean), &[]))
            .unwrap();
        // The old history's file is blocked afterwards.
        w.block(&h.blob.id().unwrap(), 81);
        let old = pair_of(&h.second);
        w.lag();

        let y = branch("y");
        let new_ref = w
            .settle(60, |w| w.advance(&y, None, old, &[]))
            .expect_err("a new ref must not reuse a pack with a blocked id");
        assert_eq!(new_ref.code(), Code::PermissionDenied, "{path:?}");
        assert_eq!(new_ref.public_message(), "object blocked", "{path:?}");

        let before = w.effects(&[&x.0, &x.1], &[], &[]);
        let existing = w
            .settle(60, |w| w.advance(&x, Some(pair_of(&clean)), old, &[]))
            .expect_err("an existing ref must not adopt a pack with a blocked id");
        assert_eq!(existing.code(), Code::PermissionDenied, "{path:?}");
        assert_eq!(existing.public_message(), "object blocked", "{path:?}");
        assert_eq!(w.effects(&[&x.0, &x.1], &[], &[]), before, "{path:?}");
    }
}

/// A packmap that omits an old history pack must not publish, including when
/// an old chain pack carries a surplus object that the head cannot reach.
#[test]
fn packmap_chain_omitting_an_old_history_pack_is_refused() {
    for &path in PATHS {
        let w = World::new(path);
        let b1 = blob(1);
        let t1 = tree(&[("f", &b1)]);
        let c1 = commit(t1.id().unwrap(), None, 1);
        let first = Push::new(&[&b1, &t1, &c1], &c1, None, &[]);
        // The second pack carries a surplus blob that no head reaches.
        let surplus = blob(777);
        let c2 = commit(t1.id().unwrap(), Some(c1.id().unwrap()), 2);
        let second = Push::new(&[&surplus, &c2], &c2, Some(first.map()), &[]);
        let names = (HEAD.to_owned(), PACKMAP.to_owned());
        w.publish(&names, None, &first);
        w.publish(&names, Some(pair_of(&first)), &second);
        // The third push chains over the second pack only: its history reaches
        // `c1`, whose pack is no longer listed by the chain.
        let b3 = blob(3);
        let t3 = tree(&[("f", &b1), ("g", &b3)]);
        let c3 = commit(t3.id().unwrap(), Some(c2.id().unwrap()), 3);
        let third = Push::new(&[&b3, &t3, &c3], &c3, None, &[hash(&second.bytes)]);
        let tickets = w.tickets(&names.0, &third);
        w.lag();
        let before = w.effects(&[HEAD, PACKMAP], &[hash(&third.bytes)], &tickets);
        let result = w.settle(60, |w| {
            w.advance(&names, Some(pair_of(&second)), pair_of(&third), &tickets)
        });
        let error = result.expect_err(&format!("{path:?}: omitted history pack must refuse"));
        assert_eq!(error.code(), Code::InvalidArgument, "{path:?}");
        assert_eq!(error.public_message(), "open closure", "{path:?}");
        assert_eq!(
            w.effects(&[HEAD, PACKMAP], &[hash(&third.bytes)], &tickets),
            before,
            "{path:?}"
        );
        // The same pair as a new ref is refused identically.
        let z = branch("z");
        let new_ref = w
            .settle(60, |w| w.advance(&z, None, pair_of(&third), &[]))
            .unwrap_err();
        assert_eq!(new_ref.public_message(), "open closure", "{path:?}");
    }
}
