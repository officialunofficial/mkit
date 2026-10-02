//! Allocator regression for legal orphan-index geometry using the production
//! Worker client, serializer and real producer-encoded delta metadata.
#![allow(clippy::unwrap_used)] // Fixture failures must fail the regression.

use mkit_server::pipeline::D34Shards;
use mkit_server::store::{codec, index, keys};
use mkit_server::{NamespaceKey, Partition, RepoId, RepoName, StoreError};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static BODY_PEAK: AtomicUsize = AtomicUsize::new(0);
struct Meter;
unsafe impl GlobalAlloc for Meter {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(l) };
        if !p.is_null() {
            let n = LIVE.fetch_add(l.size(), Ordering::SeqCst) + l.size();
            PEAK.fetch_max(n, Ordering::SeqCst);
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        LIVE.fetch_sub(l.size(), Ordering::SeqCst);
        unsafe { System.dealloc(p, l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        let q = unsafe { System.realloc(p, l, n) };
        if !q.is_null() {
            let old = LIVE.fetch_sub(l.size(), Ordering::SeqCst);
            let live = old - l.size() + n;
            LIVE.fetch_add(n, Ordering::SeqCst);
            PEAK.fetch_max(live, Ordering::SeqCst);
        }
        q
    }
}
#[global_allocator]
static ALLOC: Meter = Meter;
use mkit_server_worker::{naming, ns_client, wire};
#[derive(Debug, Clone)]
struct Lazy {
    metadata: index::IndexValue,
    members: bool,
}
impl ns_client::NsTransport for Lazy {
    async fn call(
        &self,
        _: &naming::DoTarget,
        op: &'static str,
        body: String,
    ) -> Result<String, StoreError> {
        if op == "get_many" {
            // Observe actual production request before parsing/copying it in this mock.
            let req: wire::NsRequest = serde_json::from_str(&body).unwrap();
            let wire::NsCall::GetMany { keys } = req.call else {
                panic!("wrong call")
            };
            BODY_PEAK.fetch_max(body.len(), Ordering::SeqCst);
            let values = keys
                .iter()
                .map(|k| {
                    if self.members && k.0.last() == Some(&0) {
                        Some(wire::Blob(vec![]))
                    } else {
                        None
                    }
                })
                .collect();
            return Ok(serde_json::to_string(&wire::NsReply::Values { values }).unwrap());
        }
        let req: wire::NsRequest = serde_json::from_str(&body).unwrap();
        let partition = Partition::decode(&req.part.0).unwrap();
        let Partition::RepoIndex { repo, .. } = &partition else {
            panic!("wrong partition")
        };
        let wire::NsCall::ScanMany { ranges: call } = req.call else {
            panic!("unexpected {op}")
        };
        let mut left = 1000usize;
        let mut pages = Vec::new();
        for r in call {
            if left == 0 {
                break;
            }
            let mut object = [0u8; 32];
            object.copy_from_slice(&r.start.0[r.start.0.len() - 32..]);
            let object_number = u32::from_be_bytes(object[28..32].try_into().unwrap());
            let start = r.after.map_or(0, |c| {
                let b = &c.0[c.0.len() - 4..];
                u32::from_be_bytes(b.try_into().unwrap()) - object_number * 4096 + 1
            });
            let n = (r.limit as usize).min(left).min(4096 - start as usize);
            let mut entries = Vec::new();
            let n_u32 = u32::try_from(n).unwrap();
            for row in start..start + n_u32 {
                let mut pack = [0u8; 32];
                pack[28..].copy_from_slice(&(object_number * 4096 + row).to_be_bytes());
                let key = keys::object_index(repo, &object, &pack);
                let value = codec::encode_object_index(&object, &self.metadata).unwrap();
                entries.push((
                    wire::Blob(key.as_bytes().to_vec()),
                    wire::Blob(value.as_bytes().to_vec()),
                ));
            }
            let next = if start + n_u32 < 4096 {
                Some(entries.last().unwrap().0.clone())
            } else {
                None
            };
            left -= n;
            pages.push(wire::NsReply::Page { entries, next });
        }
        let pages = pages
            .into_iter()
            .map(|p| match p {
                wire::NsReply::Page { entries, next } => wire::WirePage { entries, next },
                _ => unreachable!(),
            })
            .collect();
        serde_json::to_string(&wire::NsReply::Pages { pages })
            .map_err(|e| StoreError::unavailable(e.to_string()))
    }
}
fn witness() -> index::IndexValue {
    use mkit_core::object::{Blob, Object};
    use mkit_core::pack::{DecodeLimits, NoExternalBases, PackWriter, decode_entries_with};
    use mkit_core::serialize::serialize;
    let base = Object::Blob(Blob {
        data: vec![1; 2000],
    });
    let target = Object::Blob(Blob {
        data: vec![2; 2000],
    });
    let base_id = base.id().unwrap();
    let target_id = target.id().unwrap();
    let base_bytes = serialize(&base).unwrap();
    let target_bytes = serialize(&target).unwrap();
    let mut writer = PackWriter::new();
    writer.push_raw(base_id, &base_bytes).unwrap();
    writer
        .push_delta(
            &base_id,
            &mkit_core::delta::encode(&base_bytes, &target_bytes).unwrap(),
        )
        .unwrap();
    let pack = writer.finish().unwrap();
    let mut result = None;
    decode_entries_with(&pack, &mut NoExternalBases, DecodeLimits::default(), |e| {
        if e.id == target_id {
            result = Some(index::IndexValue {
                frame_offset: e.frame_offset,
                frame_length: e.frame_length,
                wire_type: e.wire_type,
                decoded_size: e.bytes.len() as u64,
                chain_depth: 1,
                delta_base: e.delta_base,
            });
        }
        Ok(())
    })
    .unwrap();
    let row = result.unwrap();
    let encoded = codec::encode_object_index(&target_id, &row).unwrap();
    assert_eq!(encoded.as_bytes().len(), 63);
    println!(
        "actual_valid_pack_delta_metadata={row:?} codec_bytes={} pack_bytes={}",
        encoded.as_bytes().len(),
        pack.len()
    );
    row
}
#[test]
fn aggregate_index_lookup_has_bounded_peak_and_smaller_batches_work() {
    oversized_membership_request_is_rejected_before_cloning_or_dispatch();
    let repo = RepoId {
        namespace: NamespaceKey::from_namespace(&mkit_core::repo_identity::Namespace::Ed25519(
            [9; 32],
        )),
        name: RepoName::new("a".repeat(100)).unwrap(),
    };
    let metadata = witness();
    for count in [64_u32, 256] {
        let ids: Vec<_> = (0..count)
            .map(|n| {
                let mut id = [0u8; 32];
                id[0] = 0x10;
                id[28..].copy_from_slice(&n.to_be_bytes());
                id
            })
            .collect();
        let store = ns_client::DoNamespaceStore::new(
            Lazy {
                metadata,
                members: false,
            },
            Partition::Coordinator(repo.namespace.clone()),
        );
        let baseline = LIVE.load(Ordering::SeqCst);
        PEAK.store(baseline, Ordering::SeqCst);
        BODY_PEAK.store(0, Ordering::SeqCst);
        let result =
            futures::executor::block_on(index::locate_many(&store, &D34Shards, &repo, &ids))
                .unwrap();
        let peak = PEAK.load(Ordering::SeqCst) - baseline;
        println!(
            "ids={count} peak={peak} membership_json={}",
            BODY_PEAK.load(Ordering::SeqCst)
        );
        assert!(
            peak <= 16 * 1024 * 1024,
            "lookup peak {peak} exceeds 16 MiB"
        );
        assert!(
            BODY_PEAK.load(Ordering::SeqCst) <= 64 * 1024,
            "membership JSON must be bounded"
        );
        assert!(
            result.iter().any(Result::is_err),
            "aggregate must return a smaller-batch cap"
        );
        let store = ns_client::DoNamespaceStore::new(
            Lazy {
                metadata,
                members: true,
            },
            Partition::Coordinator(repo.namespace.clone()),
        );
        for batch in [&ids[..1], &ids[ids.len() - 1..]] {
            let result =
                futures::executor::block_on(index::locate_many(&store, &D34Shards, &repo, batch))
                    .unwrap();
            assert!(
                result.iter().all(|r| matches!(r, Ok(Some(_)))),
                "smaller batch: {result:?}"
            );
            for answer in result {
                assert_eq!(answer.unwrap().unwrap().value, metadata);
            }
        }
    }
}

fn oversized_membership_request_is_rejected_before_cloning_or_dispatch() {
    use mkit_server::{Key, NamespaceStore};
    let partition = Partition::Namespace(NamespaceKey::deployment_default());
    let store = ns_client::DoNamespaceStore::new(
        Lazy {
            metadata: witness(),
            members: false,
        },
        partition.clone(),
    );
    let keys = vec![Key::new(vec![0; 1024]); 2048];
    let baseline = LIVE.load(Ordering::SeqCst);
    PEAK.store(baseline, Ordering::SeqCst);
    let error = futures::executor::block_on(store.get_many(&partition, &keys)).unwrap_err();
    assert!(matches!(error, StoreError::Invalid(_)));
    assert!(
        PEAK.load(Ordering::SeqCst) - baseline < 64 * 1024,
        "must reject before cloning keys or serializing JSON"
    );
}
