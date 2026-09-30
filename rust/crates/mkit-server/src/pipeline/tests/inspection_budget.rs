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
    let packs: Vec<_> = (0_u16..1001)
        .map(|prefix| {
            let mut id = [0; 32];
            id[..2].copy_from_slice(&(prefix << 4).to_be_bytes());
            id
        })
        .collect();
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
            }),
        };
        let mut collected = crate::indexed::inspection::InspectionSet::new(10_000);
        let mut snapshot = None;
        let before = env.pipe.meta.calls();
        let result = block_on(env.pipe.prepare_publication(
            &operation,
            &source,
            &write,
            &mut snapshot,
            None,
            &std::collections::BTreeSet::new(),
            inspecting.then_some(&mut collected),
        ));
        let calls = env.pipe.meta.calls() - before;
        if inspecting {
            let error = result.unwrap_err();
            assert_eq!(error.code(), Code::InvalidArgument);
            assert_eq!(error.public_message(), "object index limit exceeded");
            // The one snapshot read is outside the shared allocation; the
            // MKPL HEAD and GET consume its other two non-metadata calls.
            assert_eq!(calls + 2 - 1, 256);
            assert_eq!(scanner.0.load(Ordering::SeqCst), 0);
            assert!(collected.finalize().is_empty());
            assert!(env.pipe.meta.batches.lock().unwrap().is_empty());
        } else {
            let prepared = result.unwrap().unwrap();
            assert_eq!(
                prepared.value,
                Pair {
                    head: None,
                    packmap: Some(node_id)
                }
            );
            assert_eq!(prepared.dependencies.len(), 1002);
            assert!(
                calls > 1000,
                "disabled behavior retains the original dependency reads"
            );
        }
    }
}
