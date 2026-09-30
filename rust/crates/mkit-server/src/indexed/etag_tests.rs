use super::*;
use crate::memory::MemoryKv;
use crate::repo::NamespaceKey;
use crate::rt::ManualClock;
use futures_executor::block_on;
use std::sync::Arc;

#[test]
fn opaque_etag_facts_replay_without_changing_identity_and_fail_closed_on_corruption() {
    let store = MemoryKv::with_clock(Arc::new(ManualClock::new(100)));
    let partition = Partition::Namespace(NamespaceKey::deployment_default());
    let repo = RepoName::new("one").unwrap();
    let pack = [4; 32];
    let tag = "opaque".repeat(25_000);
    let token = block_on(capture(&store, &partition, &repo, &pack, &tag, 200)).unwrap();
    assert_eq!(token.len(), 64);
    assert_eq!(
        block_on(capture(&store, &partition, &repo, &pack, &tag, 200)).unwrap(),
        token
    );
    assert_eq!(
        block_on(resolve(&store, &partition, &repo, &pack, Some(&token))).unwrap(),
        Some(tag)
    );
    let key = keys::verify_row(
        &repo,
        &pack,
        keys::VC_CANDIDATE,
        Some(&from_hex(&token).unwrap()),
    );
    block_on(store.apply(
        &partition,
        Batch::new().put(key.clone(), Value::new(b"replacement".to_vec())),
    ))
    .unwrap();
    assert!(matches!(
        block_on(resolve(&store, &partition, &repo, &pack, Some(&token))),
        Err(StoreError::Corrupt(_))
    ));
    block_on(store.apply(&partition, Batch::new().delete(key))).unwrap();
    assert!(matches!(
        block_on(resolve(&store, &partition, &repo, &pack, Some(&token))),
        Err(StoreError::Corrupt(_))
    ));
    assert!(
        block_on(resolve(
            &store,
            &partition,
            &repo,
            &pack,
            Some("not-a-token")
        ))
        .is_err()
    );
}
