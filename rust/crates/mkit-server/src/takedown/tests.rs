use super::intent::*;
use super::*;
use crate::pipeline::SinglePartition;
use crate::{MemoryKv, NamespaceKey, NamespaceStore, Partition};
use serde_json::json;
use std::sync::Arc;

fn service() -> Service<Arc<MemoryKv>> {
    Service::new(
        Arc::new(MemoryKv::with_clock(Arc::new(crate::ManualClock::new(10)))),
        Partition::Namespace(NamespaceKey::deployment_default()),
        Arc::new(SinglePartition),
    )
}
#[test]
fn strict_registered_and_deployment_reason_tokens() {
    for token in [
        "legal",
        "policy",
        "malware",
        "abuse",
        "manual",
        "x-restricted.1",
    ] {
        assert!(reason_token(token));
    }
    for token in [
        "other",
        "Manual",
        "x-",
        "x-CAPITAL",
        "x-private_reason",
        "x-contains space",
    ] {
        assert!(!reason_token(token));
    }
}
#[test]
fn selector_is_exactly_named_ids_or_one_whole_pack() {
    let named = json!({"repository":"root/repo","objectIds":[base64::Engine::encode(&base64::engine::general_purpose::STANDARD,[1u8;32])],"operationId":"one","reason":"policy review"});
    assert!(Request::parse(&named).is_ok());
    let mut both = named.clone();
    both["packId"] = named["objectIds"][0].clone();
    assert!(Request::parse(&both).is_err());
    let mut duplicate = named.clone();
    duplicate["objectIds"] = json!([named["objectIds"][0], named["objectIds"][0]]);
    assert!(Request::parse(&duplicate).is_err());
    let pack = json!({"repository":"root/repo","packId":named["objectIds"][0],"operationId":"whole","reason":"review"});
    assert!(Request::parse(&pack).is_ok());
}
#[tokio::test]
async fn retry_before_acceptance_keeps_creation_time_and_rejects_changed_payload() {
    let service = service();
    let id = [5u8; 32];
    let first = service
        .draft(&service.store, id, "body:first", 10)
        .await
        .unwrap();
    let retry = service
        .draft(&service.store, id, "body:first", 200)
        .await
        .unwrap();
    assert_eq!(first.created, retry.created);
    assert!(
        service
            .draft(&service.store, id, "body:changed", 201)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn accepted_action_activates_from_staged_headers_without_source_reread() {
    use crate::indexed::budget::SliceBudget;
    use crate::store::{BorrowedStore, content_shard};
    use crate::{Batch, BatchOutcome, ContentIndex, Value};
    use mkit_core::hash::hash;
    let service = service();
    let id = [7u8; 32];
    let object = [8u8; 32];
    let action = denial::BlockAction {
        id: hash(&[id.as_slice(), object.as_slice()].concat()),
        takedown_id: id,
        reason: "policy".into(),
        blocked_at_ms: 10,
        chunk_ids: Vec::new(),
    };
    let staged = denial::stage_action(&service.store, &object, &action, 10)
        .await
        .unwrap();
    let bytes = serde_json::to_vec(&staged).unwrap();
    let root = Partition::Namespace(NamespaceKey::deployment_default());
    service
        .store
        .apply(
            &content_shard(&object),
            Batch::new().put(staged_key(&object, &id), Value::new(bytes.clone())),
        )
        .await
        .unwrap();
    let record = json!({"version":1,"id":id,"digest":"body:accepted","operation":"accepted","repository":"root/repo",
        "reason":"private","reason_token":"policy","created":10,"pack":null,
        "actions":[{"object":object,"descriptor_hash":hash(&bytes)}],"activation_cursor":0,"preservation_pending":true});
    assert_eq!(
        service
            .store
            .apply(
                &root,
                Batch::new().put(
                    request_key(&id),
                    Value::new(record.to_string().into_bytes())
                )
            )
            .await
            .unwrap(),
        BatchOutcome::Committed
    );
    // No blob backend or original inventory source is present. Only the
    // immutable accepted descriptor remains, as after source loss.
    service
        .resume(id, 11, &SliceBudget::new(9000))
        .await
        .unwrap();
    service
        .resume(id, 12, &SliceBudget::new(9000))
        .await
        .unwrap();
    assert!(
        ContentIndex::new(BorrowedStore(&service.store))
            .blocked(&object)
            .await
            .unwrap()
            .is_some()
    );
    let raw = service
        .store
        .get(&root, &request_key(&id))
        .await
        .unwrap()
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(raw.as_bytes()).unwrap();
    assert_eq!(value["activation_cursor"], 1);
    assert_eq!(value["preservation_pending"], true);
}

#[tokio::test]
async fn whole_pack_over_256_objects_is_one_pending_action() {
    use crate::admin::AdminOperations;
    use crate::indexed::budget::SliceBudget;
    use crate::pipeline::ShardMap;
    use crate::store::keys;
    use crate::{Batch, BlobKey, Value};
    use mkit_core::{
        hash::hash,
        object::{Blob, Object},
        pack::PackWriter,
        serialize::serialize,
    };
    let service = service();
    let mut writer = PackWriter::new_raw_only();
    let mut objects = Vec::new();
    for n in 0u32..300 {
        let object = Object::Blob(Blob {
            data: n.to_le_bytes().to_vec(),
        });
        let bytes = serialize(&object).unwrap();
        let id = hash(&bytes);
        writer.push_raw(id, &bytes).unwrap();
        objects.push((id, object));
    }
    let pack = writer.finish().unwrap();
    let id = hash(&pack);
    for (object_id, object) in &objects {
        inventory::stage(
            &service.store,
            &id,
            pack.len() as u64,
            object_id,
            object,
            None,
            10,
        )
        .await
        .unwrap();
    }
    inventory::complete(&service.store, &id, pack.len() as u64, 10)
        .await
        .unwrap();
    let repository = crate::RepoId {
        namespace: NamespaceKey::deployment_default(),
        name: crate::RepoName::new("repo").unwrap(),
    };
    let partition = SinglePartition.membership(&repository, &BlobKey::pack(id));
    service
        .store
        .apply(
            &partition,
            Batch::new().put(keys::membership(&repository.name, &id), Value::default()),
        )
        .await
        .unwrap();
    let input = json!({"repository":"root/repo","packId":base64::Engine::encode(&base64::engine::general_purpose::STANDARD,id),"operationId":"whole-300","reason":"private","reasonToken":"policy"});
    let budget = SliceBudget::new(9000);
    let prepared = service
        .plan(
            crate::admin::TAKEDOWN_PATH,
            &input,
            "body:whole",
            11,
            &budget,
        )
        .await
        .unwrap();
    let response = prepared.response.clone();
    service
        .store
        .apply(
            &Partition::Namespace(NamespaceKey::deployment_default()),
            prepared.batch,
        )
        .await
        .unwrap();
    let response = service
        .after_commit(crate::admin::TAKEDOWN_PATH, &input, response, 11, &budget)
        .await
        .unwrap();
    let reply: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    let request = mkit_core::hash::from_hex(reply["takedownId"].as_str().unwrap()).unwrap();
    let raw = service
        .store
        .get(&partition, &request_key(&request))
        .await
        .unwrap()
        .unwrap();
    let record: serde_json::Value = serde_json::from_slice(raw.as_bytes()).unwrap();
    assert_eq!(record["actions"].as_array().unwrap().len(), 1);
    assert_eq!(record["actions"][0]["object"], json!(id));
    assert_eq!(reply["complete"], false);
    assert_eq!(record["activation_cursor"], 1);
    assert_eq!(record["preservation_pending"], true);
}
