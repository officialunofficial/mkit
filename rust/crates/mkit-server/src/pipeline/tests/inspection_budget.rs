//! A tiny inspected set must not make a large packmap's dependency fanout free.

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

fn fixture(inspecting: bool) -> (Env, Operation, Hash, Arc<Scanner>) {
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
    // Spread over the repository's sixteen index shards; enough packs that
    // reading every dependency's visibility needs more calls than the shared
    // verification allocation.
    let mut packs: Vec<_> = (0_u16..3000)
        .map(|n| {
            let mut id = [0; 32];
            id[0] = u8::try_from(n & 15).unwrap() << 4;
            id[1] = u8::try_from(n >> 4).unwrap();
            id
        })
        .collect();
    packs.sort_unstable();
    let node = mkit_core::transfer::encode_packlist(None, &packs).unwrap();
    let node_id = hash(&node);
    indexed::upload(&env, &node, [8; 32]);
    let witness = Witness {
        generation: 0,
        sequence: 1,
        published: true,
        held: false,
    }
    .encode();
    for pack in packs.iter().chain(std::iter::once(&node_id)) {
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
    let operation = env
        .pipe
        .identify(
            &authenticated,
            OpKind::UpdateRef(upd(PACKMAP, Missing, node_id)),
        )
        .unwrap();
    (env, operation, node_id, scanner)
}

#[test]
fn inspection_pair_budget_includes_dependency_visibility_before_hooks() {
    for inspecting in [false, true] {
        let (env, operation, node_id, scanner) = fixture(inspecting);
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
                bound: None,
            }),
        };
        let mut collected = crate::indexed::inspection::InspectionSet::new(10_000);
        let mut snapshot = None;
        let before = env.pipe.meta.calls();
        let result = block_on(env.pipe.prepare_publication(
            &operation,
            REPO,
            &source,
            &write,
            &mut snapshot,
            None,
            &std::collections::BTreeSet::new(),
            inspecting.then_some(&mut collected),
            &crate::pipeline::publication_budget::PublicationBudget::new(),
        ));
        let calls = env.pipe.meta.calls() - before;
        if inspecting {
            let error = result.unwrap_err();
            // Spent execution capacity is `unavailable`, never an index-limit verdict.
            assert_eq!(error.code(), Code::Unavailable);
            assert_eq!(
                error.public_message(),
                "publication verification capacity exhausted"
            );
            // The one snapshot read is outside the shared allocation; the
            // MKPL HEAD and GET consume its other two non-metadata calls.
            assert_eq!(calls + 2 - 1, 256);
            assert_eq!(scanner.0.load(Ordering::SeqCst), 0);
            assert!(collected.finalize().is_empty());
            assert!(env.pipe.meta.batches.lock().unwrap().is_empty());
        } else {
            let (prepared, _) = result.unwrap().unwrap();
            assert_eq!(
                prepared.value,
                Pair {
                    head: None,
                    packmap: Some(node_id)
                }
            );
            assert_eq!(prepared.dependencies.len(), 3001);
            assert!(
                calls > 256,
                "disabled behavior retains the original dependency reads"
            );
        }
    }
}
