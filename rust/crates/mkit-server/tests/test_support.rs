//! Exercise fixture writes as a downstream crate, without storage-layout APIs.
use futures_executor::block_on;
use mkit_server::pipeline::{D34Shards, RepoVisibility, ShardMap, SinglePartition};
use mkit_server::reads::{ReadAccess, VisibilityWitness};
use mkit_server::test_support::{TestSeeder, VisibilitySeed};
use mkit_server::{ManualClock, MemoryKv, NamespaceKey, RepoId, RepoName};
use std::sync::Arc;

fn repo() -> RepoId {
    RepoId {
        namespace: NamespaceKey::from_namespace(&mkit_core::repo_identity::Namespace::Ed25519(
            [1; 32],
        )),
        name: RepoName::new("fixtures").expect("valid fixture repository name"),
    }
}

fn maps() -> [Box<dyn ShardMap>; 2] {
    [Box::new(SinglePartition), Box::new(D34Shards)]
}

#[test]
fn seeded_visibility_is_read_back_in_single_and_d34() {
    for shards in maps() {
        let store = MemoryKv::with_clock(Arc::new(ManualClock::new(1)));
        let repo = repo();
        let seed = TestSeeder::new(&store, shards.as_ref());
        let reads = ReadAccess::new(&store, shards.as_ref(), RepoVisibility::Public, true);
        let visibility = VisibilitySeed {
            visibility: RepoVisibility::Private,
            last_created_ms: 2,
            last_statement_id: Some([7; 32]),
            changed_ms: 2,
        };
        block_on(seed.seed_visibility(&repo, visibility)).unwrap();
        assert_eq!(block_on(reads.repository_visibility(&repo)).unwrap(), None);
        // The declaration is observable before the repository record exists.
        let declared = block_on(reads.declared_visibility(&repo)).unwrap().unwrap();
        assert_eq!(declared.visibility, RepoVisibility::Private);
        block_on(seed.seed_repository(&repo, 1)).unwrap();
        let private = block_on(reads.repository_visibility(&repo))
            .unwrap()
            .unwrap();
        assert_eq!(private.visibility, RepoVisibility::Private);
        assert_eq!(
            private,
            block_on(reads.repository_visibility(&repo))
                .unwrap()
                .unwrap()
        );
        block_on(seed.seed_visibility(
            &repo,
            VisibilitySeed {
                visibility: RepoVisibility::Public,
                last_created_ms: 3,
                last_statement_id: None,
                changed_ms: 3,
            },
        ))
        .unwrap();
        let public = block_on(reads.repository_visibility(&repo))
            .unwrap()
            .unwrap();
        assert_eq!(public.visibility, RepoVisibility::Public);
        assert_ne!(private.revision, public.revision);
        let declared_public = block_on(reads.declared_visibility(&repo)).unwrap().unwrap();
        assert_eq!(declared_public.visibility, RepoVisibility::Public);
        assert_ne!(declared.revision, declared_public.revision);
    }
}

#[test]
fn seeded_witnesses_round_trip_and_replace_in_single_and_d34() {
    for shards in maps() {
        let store = MemoryKv::with_clock(Arc::new(ManualClock::new(1)));
        let repo = repo();
        let seed = TestSeeder::new(&store, shards.as_ref());
        let reads = ReadAccess::new(&store, shards.as_ref(), RepoVisibility::Public, true);
        let pack = [3; 32];
        let member = VisibilityWitness {
            generation: 4,
            sequence: 7,
            published: true,
            held: false,
            boundary: true,
        };
        let published = VisibilityWitness {
            generation: 5,
            sequence: 8,
            published: false,
            held: true,
            boundary: false,
        };
        for (member, published) in [
            (Some(member), Some(published)),
            (None, Some(published)),
            (Some(member), None),
            (None, None),
        ] {
            block_on(seed.seed_pack_witness(&repo, &pack, member, published)).unwrap();
            let witness = block_on(reads.pack_witness(&repo, &pack)).unwrap();
            assert_eq!(witness.member, member);
            assert_eq!(witness.published, published);
        }
    }
}
