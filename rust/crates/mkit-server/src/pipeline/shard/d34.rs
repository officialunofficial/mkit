//! Fixed D34 routing: one branch shard, a namespace coordinator, and
//! enumerable membership and ref-name index shards. Each repository's object
//! and membership rows spread over [`REPO_INDEX_FANOUT`] shards.

use mkit_core::hash::Hash;
use mkit_core::hash::hash;
use mkit_core::refs::PACKMAP_REF_PREFIX;

use super::ShardMap;
use crate::repo::{NamespaceKey, RepoId};
use crate::store::{BlobKey, Partition, REF_INDEX_FANOUT};

/// The D34 shard map. Fan-outs and head/packmap co-location are permanent
/// storage contracts; changing them would strand existing rows.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct D34Shards;

impl ShardMap for D34Shards {
    fn ref_shard(&self, repo: &RepoId, ref_name: &str) -> Partition {
        let shard_ref = ref_name.strip_prefix(PACKMAP_REF_PREFIX).map_or_else(
            || ref_name.to_owned(),
            |branch| format!("refs/heads/{branch}"),
        );
        Partition::Ref {
            ns: repo.namespace.clone(),
            repo: repo.name.clone(),
            shard_ref,
        }
    }

    fn coordinator(&self, ns: &NamespaceKey) -> Partition {
        Partition::Coordinator(ns.clone())
    }

    fn ref_index(&self, repo: &RepoId, ref_name: &str) -> Partition {
        let digest = hash(ref_name.as_bytes());
        Partition::RefIndex {
            ns: repo.namespace.clone(),
            repo: repo.name.clone(),
            bucket: u16::from_be_bytes([digest[0], digest[1]]) % REF_INDEX_FANOUT,
        }
    }

    fn ref_index_partitions(&self, repo: &RepoId) -> Vec<Partition> {
        (0..REF_INDEX_FANOUT)
            .map(|bucket| Partition::RefIndex {
                ns: repo.namespace.clone(),
                repo: repo.name.clone(),
                bucket,
            })
            .collect()
    }

    fn membership(&self, repo: &RepoId, pack: &BlobKey) -> Partition {
        let p = pack.hash();
        Partition::RepoIndex {
            ns: repo.namespace.clone(),
            repo: repo.name.clone(),
            prefix: u16::from(p[0] >> 4),
        }
    }

    fn object_index(&self, repo: &RepoId, object: &Hash) -> Partition {
        Partition::RepoIndex {
            ns: repo.namespace.clone(),
            repo: repo.name.clone(),
            prefix: u16::from(object[0] >> 4),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::path::PathBuf;

    use mkit_core::hash::{to_hex, to_hex_bytes};
    use proptest::prelude::*;
    use serde::Serialize;

    use super::*;
    use crate::repo::RepoName;
    use crate::store::REPO_INDEX_FANOUT;

    fn repo(ns: &str, name: &str) -> RepoId {
        RepoId {
            namespace: NamespaceKey::from_stored(ns.into()),
            name: RepoName::new(name).unwrap(),
        }
    }

    fn encoded(partition: &Partition) -> String {
        let bytes = partition.encode().unwrap();
        assert_eq!(Partition::decode(&bytes).unwrap(), *partition);
        to_hex_bytes(&bytes)
    }

    #[derive(Serialize)]
    struct RefMapping {
        namespace: String,
        repo: String,
        ref_name: String,
        ref_partition_hex: String,
        ref_index_partition_hex: String,
    }

    #[derive(Serialize)]
    struct PackMapping {
        namespace: String,
        repo: String,
        pack_id: String,
        prefix: u16,
        membership_partition_hex: String,
        object_index_partition_hex: String,
    }

    #[derive(Serialize)]
    struct Mapping {
        ref_index_fanout: u16,
        membership_fanout: u16,
        refs: Vec<RefMapping>,
        packs: Vec<PackMapping>,
        coordinator_partition_hex: String,
        ref_index_partitions_hex: Vec<String>,
    }

    fn golden_mapping() -> String {
        let refs = [
            ("root", "a", "refs/heads/main"),
            ("root", "a", "refs/mkit/packmap/main"),
            ("root", "a", "refs/tags/v1"),
            ("root", "a", "refs/heads/a/b"),
            ("root", "a", "refs/mkit/packmap/a/b"),
            ("root", "b", "refs/heads/main"),
            ("tenant", "a", "refs/heads/main"),
            ("tenant", "a", "refs/packmaps/main"),
        ]
        .into_iter()
        .map(|(ns, name, ref_name)| {
            let r = repo(ns, name);
            RefMapping {
                namespace: ns.into(),
                repo: name.into(),
                ref_name: ref_name.into(),
                ref_partition_hex: encoded(&D34Shards.ref_shard(&r, ref_name)),
                ref_index_partition_hex: encoded(&D34Shards.ref_index(&r, ref_name)),
            }
        })
        .collect();
        let r = repo("root", "a");
        let packs = [
            (0x00, 0x00, 0x0),
            (0xff, 0xff, 0xf),
            (0x12, 0x3f, 0x1),
            (0x1f, 0xff, 0x1),
            (0x20, 0x00, 0x2),
        ]
        .into_iter()
        .map(|(first, second, prefix)| {
            let mut id = [0; 32];
            id[..2].copy_from_slice(&[first, second]);
            let pack = BlobKey::pack(id);
            PackMapping {
                namespace: "root".into(),
                repo: "a".into(),
                pack_id: to_hex(&id),
                prefix,
                membership_partition_hex: encoded(&D34Shards.membership(&r, &pack)),
                object_index_partition_hex: encoded(&D34Shards.object_index(&r, &id)),
            }
        })
        .collect();
        let mapping = Mapping {
            ref_index_fanout: REF_INDEX_FANOUT,
            membership_fanout: REPO_INDEX_FANOUT,
            refs,
            packs,
            coordinator_partition_hex: encoded(&D34Shards.coordinator(&r.namespace)),
            ref_index_partitions_hex: D34Shards
                .ref_index_partitions(&r)
                .iter()
                .map(encoded)
                .collect(),
        };
        format!("{}\n", serde_json::to_string_pretty(&mapping).unwrap())
    }

    #[test]
    fn d34_mapping_golden() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/golden/shards");
        let mapping = golden_mapping();
        let manifest = format!(
            "# WP-1.22 D34 shard mapping. <file> <blake3>\n\
             # Regenerate: UPDATE_GOLDEN=1 cargo test -p mkit-server d34_mapping_golden\n\
             d34-mapping.json {}\n",
            to_hex(&hash(mapping.as_bytes())),
        );
        if std::env::var("UPDATE_GOLDEN").as_deref() == Ok("1") {
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("d34-mapping.json"), &mapping).unwrap();
            std::fs::write(dir.join("MANIFEST.txt"), &manifest).unwrap();
            return;
        }
        assert_eq!(
            std::fs::read_to_string(dir.join("d34-mapping.json")).unwrap(),
            mapping
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("MANIFEST.txt")).unwrap(),
            manifest
        );
    }

    #[test]
    fn d34_ref_index_partitions_are_distinct_and_ordered() {
        let r = repo("root", "a");
        let partitions = D34Shards.ref_index_partitions(&r);
        assert_eq!(partitions.len(), usize::from(REF_INDEX_FANOUT));
        assert_eq!(
            partitions.iter().collect::<BTreeSet<_>>().len(),
            partitions.len()
        );
        for (bucket, partition) in (0..REF_INDEX_FANOUT).zip(partitions) {
            assert_eq!(
                partition,
                Partition::RefIndex {
                    ns: r.namespace.clone(),
                    repo: r.name.clone(),
                    bucket,
                }
            );
        }
    }

    proptest! {
        #[test]
        fn d34_branch_and_packmap_share_the_ref_shard(
            branch in "[a-zA-Z0-9_-]{1,16}(/[a-zA-Z0-9_-]{1,16}){0,4}",
        ) {
            let r = repo("root", "a");
            let head = format!("refs/heads/{branch}");
            let packmap = format!("{PACKMAP_REF_PREFIX}{branch}");
            prop_assert_eq!(D34Shards.ref_shard(&r, &head), D34Shards.ref_shard(&r, &packmap));
        }

        #[test]
        fn d34_index_buckets_and_membership_prefixes_stay_in_fixed_ranges(
            name in ".*",
            id in any::<[u8; 32]>(),
        ) {
            let r = repo("root", "a");
            let Partition::RefIndex { bucket, .. } = D34Shards.ref_index(&r, &name) else {
                unreachable!("D34 ref-name index is a RefIndex");
            };
            let Partition::RepoIndex { prefix, .. } = D34Shards.membership(&r, &BlobKey::pack(id)) else {
                unreachable!("D34 membership index is a RepoIndex");
            };
            prop_assert!(bucket < REF_INDEX_FANOUT);
            prop_assert!(prefix < REPO_INDEX_FANOUT);
            prop_assert_eq!(prefix, u16::from(id[0] >> 4));
            prop_assert_eq!(D34Shards.object_index(&r, &id), D34Shards.membership(&r, &BlobKey::pack(id)));
        }
    }
}
