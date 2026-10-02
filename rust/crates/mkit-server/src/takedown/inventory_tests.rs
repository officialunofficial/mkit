//! JSON constants transcribed from the inventory DTOs at 8948ae34.
#![allow(clippy::unwrap_used)]
use super::*;
use crate::{MemoryKv, rt::ManualClock};
use futures_executor::block_on;
use std::sync::Arc;

const LEGACY_ENTRIES: [&[u8]; 4] = [
    br#"{"version":1,"kind":0,"base":null,"references":{"action":{"id":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"takedown_id":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"reason":"inventory","blocked_at_ms":0,"chunk_ids":[]},"sorted_pages":false,"chunk_count":0,"chunk_digest":[175,19,73,185,245,249,161,166,160,64,77,234,54,220,201,73,155,203,37,201,173,193,18,183,204,154,147,202,228,31,50,98],"pages":[],"page_owner":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"page_action":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"pack_scope":null,"pack_digest":null}}"#,
    br#"{"version":1,"kind":1,"base":null,"references":{"action":{"id":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"takedown_id":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"reason":"inventory","blocked_at_ms":0,"chunk_ids":[]},"sorted_pages":false,"chunk_count":0,"chunk_digest":[175,19,73,185,245,249,161,166,160,64,77,234,54,220,201,73,155,203,37,201,173,193,18,183,204,154,147,202,228,31,50,98],"pages":[],"page_owner":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"page_action":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"pack_scope":null,"pack_digest":null}}"#,
    br#"{"version":1,"kind":5,"base":null,"references":{"action":{"id":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"takedown_id":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"reason":"inventory","blocked_at_ms":0,"chunk_ids":[]},"sorted_pages":false,"chunk_count":0,"chunk_digest":[175,19,73,185,245,249,161,166,160,64,77,234,54,220,201,73,155,203,37,201,173,193,18,183,204,154,147,202,228,31,50,98],"pages":[],"page_owner":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"page_action":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"pack_scope":null,"pack_digest":null}}"#,
    br#"{"version":1,"kind":3,"base":null,"references":{"action":{"id":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"takedown_id":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"reason":"inventory","blocked_at_ms":0,"chunk_ids":[]},"sorted_pages":false,"chunk_count":0,"chunk_digest":[175,19,73,185,245,249,161,166,160,64,77,234,54,220,201,73,155,203,37,201,173,193,18,183,204,154,147,202,228,31,50,98],"pages":[],"page_owner":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"page_action":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"pack_scope":null,"pack_digest":null}}"#,
];
const LEGACY_HEAD: &[u8] = br#"{"version":1,"length":100,"count":0,"parents":0,"parent_digest":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"digest":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"complete":true}"#;

#[test]
fn legacy_entries_decode_per_kind_without_inventing_lengths() {
    block_on(async {
        let store = MemoryKv::with_clock(Arc::new(ManualClock::new(0)));
        let pack = [1; 32];
        for (n, bytes) in LEGACY_ENTRIES.into_iter().enumerate() {
            let id = [u8::try_from(n).unwrap(); 32];
            let raw = Value::new(bytes.to_vec());
            store
                .apply(
                    &content_shard(&pack),
                    Batch::new().put(entry_key(&pack, &id), raw.clone()).put(
                        marker_key(&pack, &id),
                        Value::new(entry_digest(&id, &raw).to_vec()),
                    ),
                )
                .await
                .unwrap();
            let row = entry(&store, &pack, &id).await.unwrap().unwrap();
            assert_eq!(row.known_canonical_len(), None);
            assert_eq!(row.logical_len, None);
            assert_eq!(encode(&row).unwrap(), raw);
        }
    });
}

#[test]
fn legacy_head_seals_and_traverses_without_packlist_facts() {
    block_on(async {
        let store = MemoryKv::with_clock(Arc::new(ManualClock::new(0)));
        let pack = [1; 32];
        let raw = Value::new(LEGACY_HEAD.to_vec());
        let head: Head = decode(&raw).unwrap();
        assert!(head.packlist.is_none());
        assert_eq!(encode(&head).unwrap(), raw);
        store
            .apply(
                &content_shard(&pack),
                Batch::new().put(head_key(&pack), raw.clone()),
            )
            .await
            .unwrap();
        assert_eq!(
            seal(&store, &pack).await.unwrap(),
            mkit_core::hash::hash(raw.as_bytes())
        );
        assert!(has_seal(&store, &pack).await.unwrap());
        assert!(
            next(&store, &pack, InventoryCursor::default())
                .await
                .unwrap()
                .2
        );
        assert!(packlist_facts(&store, &pack).await.unwrap().is_none());
        stage_packlist(&store, &pack, 100, Some([2; 32]), &[], 0)
            .await
            .unwrap();
        assert_eq!(
            store
                .get(&content_shard(&pack), &head_key(&pack))
                .await
                .unwrap(),
            Some(raw)
        );
    });
}

#[test]
fn known_lengths_still_validate_and_reserved_or_partial_lengths_fail() {
    let legacy: Entry = decode(&Value::new(LEGACY_ENTRIES[1].to_vec())).unwrap();
    for (kind, canonical_len, logical_len) in [
        (0, 0, None),
        (1, 10, Some(0)),
        (5, 22, Some(0)),
        (3, 6, None),
    ] {
        let row = Entry {
            kind,
            canonical_len,
            logical_len,
            ..legacy.clone()
        };
        row.validate().unwrap();
        assert_eq!(decode::<Entry>(&encode(&row).unwrap()).unwrap(), row);
    }
    for (kind, canonical_len, logical_len) in [
        (0, 1, None),
        (1, 0, Some(0)),
        (1, 10, None),
        (1, 10, Some(1)),
        (5, 21, Some(0)),
        (5, 22, None),
        (3, 0, None),
        (3, 6, Some(0)),
        (8, UNKNOWN_CANONICAL_LEN, None),
        (1, UNKNOWN_CANONICAL_LEN, Some(0)),
    ] {
        assert!(
            Entry {
                kind,
                canonical_len,
                logical_len,
                ..legacy.clone()
            }
            .validate()
            .is_err()
        );
    }
    let mut json: serde_json::Value = serde_json::from_slice(LEGACY_ENTRIES[1]).unwrap();
    for length in [serde_json::json!(u64::MAX), serde_json::Value::Null] {
        json["canonical_len"] = length;
        assert!(decode::<Entry>(&Value::new(serde_json::to_vec(&json).unwrap())).is_err());
    }
    json.as_object_mut().unwrap().remove("canonical_len");
    json["future_field"] = serde_json::json!(1);
    assert!(decode::<Entry>(&Value::new(serde_json::to_vec(&json).unwrap())).is_err());
}

// Install the exact old DTO shape over a real verified fixture, rebinding
// entry markers, parent copies and aggregate digests to the legacy JSON bytes.
// Production readers must preserve these bytes; backfill would break the seal.
pub(crate) async fn install_legacy_pack<S: NamespaceStore>(store: &S, pack: &Hash) {
    let prefix = Key::new([keys::block(pack).as_bytes(), b"\0inventory\0"].concat());
    let mut end = prefix.as_bytes().to_vec();
    *end.last_mut().unwrap() = 1;
    let mut cursor = None;
    let mut digest = [0; 32];
    let mut parent_digest = [0; 32];
    loop {
        let page = store
            .scan(
                &content_shard(pack),
                &prefix,
                &Key::new(end.clone()),
                cursor.as_ref(),
                8,
            )
            .await
            .unwrap();
        for (key, raw) in page.entries {
            let id: Hash = key
                .as_bytes()
                .strip_prefix(prefix.as_bytes())
                .unwrap()
                .try_into()
                .unwrap();
            let mut json: serde_json::Value = serde_json::from_slice(raw.as_bytes()).unwrap();
            // The old producer only recorded tree edges and manifest chunks.
            if !matches!(json["kind"].as_u64().unwrap(), 2 | 5) {
                json["references"]["pages"] = serde_json::json!([]);
                json["references"]["chunk_count"] = serde_json::json!(0);
                json["references"]["chunk_digest"] = serde_json::json!(mkit_core::hash::hash(b""));
            }
            let fields = json.as_object_mut().unwrap();
            fields.remove("canonical_len");
            fields.remove("logical_len");
            let raw = Value::new(serde_json::to_vec(&json).unwrap());
            add_digest(&mut digest, &id, &raw);
            let mut batch = Batch::new().put(key, raw.clone()).put(
                marker_key(pack, &id),
                Value::new(entry_digest(&id, &raw).to_vec()),
            );
            if store
                .get(&content_shard(pack), &parent_key(pack, &id))
                .await
                .unwrap()
                .is_some()
            {
                add_digest(&mut parent_digest, &id, &raw);
                batch = batch.put(parent_key(pack, &id), raw);
            }
            store.apply(&content_shard(pack), batch).await.unwrap();
        }
        cursor = page.next;
        if cursor.is_none() {
            break;
        }
    }
    let raw = store
        .get(&content_shard(pack), &head_key(pack))
        .await
        .unwrap()
        .unwrap();
    let mut head: serde_json::Value = serde_json::from_slice(raw.as_bytes()).unwrap();
    head.as_object_mut().unwrap().remove("packlist");
    head["digest"] = serde_json::json!(digest);
    head["parent_digest"] = serde_json::json!(parent_digest);
    store
        .apply(
            &content_shard(pack),
            Batch::new().put(
                head_key(pack),
                Value::new(serde_json::to_vec(&head).unwrap()),
            ),
        )
        .await
        .unwrap();
}
