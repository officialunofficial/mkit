//! A tiny inspected set must not make a large packmap's dependency fanout free,
//! and must not make it impossible either: both modes verify it in bounded calls.

use super::*;
use crate::BlobKey;
use crate::hooks::InspectVerdict;
use crate::pipeline::inspection::ContentInspector;
use crate::store::publication::{Pair, Witness};
use mkit_rpc::hooks::InspectObject;

struct Scanner(AtomicU32);
impl ContentInspector for Scanner {
    fn id(&self) -> &'static str {
        "budget-scanner"
    }
    fn inspect<'a>(
        &'a self,
        _: &'a Operation,
        _: &'a str,
        _: &'a [InspectObject],
    ) -> crate::BoxFuture<'a, Result<InspectVerdict, ServerError>> {
        Box::pin(async move {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(InspectVerdict::Pass)
        })
    }
}

#[allow(clippy::too_many_lines)] // One packmap chain, witnesses and optional proof row.
fn fixture(inspecting: bool, with_row: bool) -> (Env, Operation, Hash, Arc<Scanner>) {
    let (mut env, owner, identity) =
        indexed::environment_with(Sharding::D34, crate::indexed::IndexedConfig::default());
    env.pipe.cfg.begin_upload_threshold_bytes = 0;
    let scanner = Arc::new(Scanner(AtomicU32::new(0)));
    let Env {
        pipe,
        clock,
        metrics,
    } = env;
    let mut env = Env {
        pipe: pipe
            .with_inspectors(
                if inspecting {
                    vec![scanner.clone()]
                } else {
                    vec![]
                },
                10_000,
            )
            .unwrap(),
        clock,
        metrics,
    };
    // Keep the same publication policy in both cases to pin the disabled
    // path's original behavior, not bypass publication preparation.
    env.pipe.publication_policy = Some(Arc::new(inspection::Immediate));
    let request = indexed::signed(&owner, &identity, Procedure::UpdateRef, 30_000);
    let authenticated = env.auth(&request).unwrap();
    let repo = authenticated.repo().repo.clone();
    let packs: Vec<_> = (0_u16..1001)
        .map(|prefix| {
            let mut id = [0; 32];
            id[..2].copy_from_slice(&(prefix << 4).to_be_bytes());
            id
        })
        .collect();
    // A real packmap node lists at most a few hundred packs, so the 1,001
    // dependencies arrive as a chain of four nodes with sealed facts.
    let now = u64::try_from(env.clock.now_ms()).unwrap();
    let mut nodes = Vec::new();
    let mut previous = None;
    for (n, chunk) in packs.chunks(251).enumerate() {
        let node = mkit_core::transfer::encode_packlist(previous, chunk).unwrap();
        let id = hash(&node);
        indexed::upload(&env, &node, [8 + u8::try_from(n).unwrap(); 32]);
        block_on(crate::takedown::inventory::stage_packlist(
            &env.pipe.meta,
            &id,
            node.len() as u64,
            previous,
            chunk,
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
        nodes.push(id);
        previous = Some(id);
    }
    let node_id = previous.unwrap();
    let witness = Witness {
        generation: 0,
        sequence: 1,
        published: true,
        held: false,
    }
    .encode();
    for pack in packs.iter().chain(&nodes) {
        let partition = D34Shards.membership(&repo, &BlobKey::pack(*pack));
        block_on(
            env.pipe.meta.inner.apply(
                &partition,
                Batch::new()
                    .put(keys::membership(&repo.name, pack), witness.clone())
                    .put(keys::published_member(&repo.name, pack), witness.clone()),
            ),
        )
        .unwrap();
    }
    if with_row {
        // The retained proof lives in the packmap's verification row.
        block_on(crate::indexed::state::write(
            env.pipe.meta.inner.as_ref(),
            &D34Shards.ref_shard(&repo, HEAD),
            &repo.name,
            &node_id,
            None,
            &crate::indexed::state::VerificationV1::Verified {
                pack_len: 100,
                verified_at_ms: 0,
                publication: None,
            },
            u64::MAX,
        ))
        .unwrap();
    }
    let operation = env
        .pipe
        .identify(
            &authenticated,
            OpKind::UpdateRef(upd(PACKMAP, Missing, node_id)),
        )
        .unwrap();
    (env, operation, node_id, scanner)
}

type Prepared = (crate::store::publication::Advance, Vec<Hash>, bool);
fn run(
    env: &Env,
    operation: &Operation,
    node_id: Hash,
    inspected: Option<&mut crate::indexed::inspection::InspectionSet>,
    external: &std::collections::BTreeSet<Hash>,
    budget: &crate::indexed::budget::SliceBudget,
) -> Result<Option<Prepared>, ServerError> {
    let repo = operation.repo.clone();
    let source = D34Shards.ref_shard(&repo, HEAD);
    let refs = [upd(PACKMAP, Missing, node_id)];
    let write = WriteRequest {
        denial_ids: None,
        denial_packs: &[],
        authority_store: AuthorityStore::Guarded,
        authority_generation: None,
        repo: &repo.name,
        kind: WriteKind::UpdateRef,
        refs: &refs,
        ref_index: None,
        replay: None,
        charges: &[],
        namespace_charge: None,
        grant: None,
        lease: None,
        layout_version: false,
        mark_repo_known: false,
        begin: None,
        advance: None,
        implicit: None,
        rejection: None,
        pending: None,
        publication: Some(clearance::PublicationWrite {
            repo: &repo,
            source: &source,
            shards: &D34Shards,
            prepared: None,
            frontier: &[],
            inherits: false,
            budget: None,
        }),
    };
    let mut snapshot = None;
    block_on(env.pipe.prepare_publication(
        operation,
        REPO,
        &source,
        &write,
        &mut snapshot,
        None,
        external,
        inspected,
        budget,
    ))
}

#[test]
fn inspection_pair_budget_includes_dependency_visibility_before_hooks() {
    for inspecting in [false, true] {
        let (env, operation, node_id, _scanner) = fixture(inspecting, false);
        let mut collected = crate::indexed::inspection::InspectionSet::new(10_000);
        let budget = crate::indexed::budget::SliceBudget::new(9000);
        let before = env.pipe.meta.calls();
        let writes = env.pipe.meta.batches.lock().unwrap().len();
        let result = run(
            &env,
            &operation,
            node_id,
            inspecting.then_some(&mut collected),
            &std::collections::BTreeSet::new(),
            &budget,
        );
        let calls = env.pipe.meta.calls() - before;
        let (prepared, frontier, _) = result.unwrap().unwrap();
        assert_eq!(
            prepared.value,
            Pair {
                head: None,
                packmap: Some(node_id)
            }
        );
        assert_eq!(prepared.dependencies.len(), 1005);
        assert!(frontier.is_empty());
        // Random pack ids land on distinct shards, so the witnesses cost about
        // one routed read each; the shared allowance covers them in both modes.
        assert!((1000..2000).contains(&calls), "{calls}");
        // Preparation spent the same allowance that final clearance continues.
        assert!(budget.used() >= 1000, "{}", budget.used());
        assert!(prepared.state.publishable());
        assert_eq!(env.pipe.meta.batches.lock().unwrap().len(), writes);
    }
}

#[test]
fn nested_preparation_exhaustion_stays_resource_exhausted() {
    for inspecting in [false, true] {
        let (env, operation, node_id, _scanner) = fixture(inspecting, false);
        let mut collected = crate::indexed::inspection::InspectionSet::new(10_000);
        let error = run(
            &env,
            &operation,
            node_id,
            inspecting.then_some(&mut collected),
            &std::collections::BTreeSet::new(),
            &crate::indexed::budget::SliceBudget::new(50),
        )
        .unwrap_err();
        assert_eq!(error.code(), Code::ResourceExhausted, "{error:?}");
    }
}

#[test]
fn a_later_verification_reports_its_own_external_dependencies() {
    let (env, operation, node_id, _scanner) = fixture(false, true);
    let budget = || crate::indexed::budget::SliceBudget::new(9000);
    let x = std::collections::BTreeSet::from([[0x11; 32]]);
    let y = std::collections::BTreeSet::from([[0x22; 32]]);
    // The first call retains a complete proof for this exact pair.
    let first = run(&env, &operation, node_id, None, &x, &budget())
        .unwrap()
        .unwrap();
    assert_eq!(first.0.external_bases, vec![[0x11; 32]]);
    // A later advance over the same pair consumes that proof, not its bases.
    let later = run(&env, &operation, node_id, None, &y, &budget())
        .unwrap()
        .unwrap();
    assert_eq!(later.0.external_bases, vec![[0x22; 32]]);
    assert_eq!(later.0.dependencies, first.0.dependencies);
}
