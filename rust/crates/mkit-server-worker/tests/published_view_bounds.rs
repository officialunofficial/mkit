#![cfg(feature = "published-view")]
#[allow(dead_code, unreachable_pub)]
#[path = "common/multipart_allocator.rs"]
mod allocator;
use mkit_server::pipeline::{D34Shards, ShardMap};
use mkit_server::{NamespaceKey, RepoId, RepoName};
use mkit_server_worker::published_view::{Envelope, MAX_BYTES, VALIDITY_MS};

#[test]
fn sixteen_maximum_bodies_and_rows_fit_in_two_mib_of_heap() {
    let repo = RepoId {
        namespace: NamespaceKey::deployment_default(),
        name: RepoName::new("bounded").unwrap(),
    };
    let mut buckets = vec![Vec::new(); 16];
    let mut i = 0;
    while buckets.iter().any(|rows| rows.len() < 58) {
        let name = format!("refs/heads/{i:08}{}", "a".repeat(480));
        i += 1;
        let mkit_server::Partition::RefIndex { bucket, .. } = D34Shards.ref_index(&repo, &name)
        else {
            unreachable!()
        };
        if buckets[usize::from(bucket)].len() < 58 {
            buckets[usize::from(bucket)].push((name, [1; 32]));
        }
    }
    let envelopes = D34Shards
        .ref_index_partitions(&repo)
        .into_iter()
        .zip(buckets)
        .map(|(partition, rows)| Envelope {
            partition,
            generation: 1,
            captured_at_ms: 1000,
            valid_until_ms: 1000 + VALIDITY_MS,
            rows,
        })
        .collect::<Vec<_>>();
    let probe = allocator::probe();
    (probe.start)();
    let encoded = envelopes
        .iter()
        .map(|e| e.encode().unwrap())
        .collect::<Vec<_>>();
    assert!(encoded.iter().all(|b| b.len() <= MAX_BYTES));
    let decoded = encoded
        .iter()
        .zip(&envelopes)
        .map(|(bytes, e)| Envelope::decode(bytes, &e.partition, 1000).unwrap())
        .collect::<Vec<_>>();
    let mut rows = decoded
        .iter()
        .flat_map(|e| e.rows.clone())
        .collect::<Vec<_>>();
    rows.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(rows.len(), 928);
    let peak = (probe.finish)();
    assert!(peak < 2 * 1024 * 1024, "snapshot peak {peak} exceeds 2 MiB");
}
