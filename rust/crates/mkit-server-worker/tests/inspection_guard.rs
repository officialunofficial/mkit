//! Inspection marker through the real Worker protocol and simulated DOs.
mod common;
use common::{DoConfig, Loopback};
use futures::executor::block_on;
use mkit_server::pipeline::Sharding;
use mkit_server::store::restore::{RestoreOptions, restore};
use mkit_server::store::{
    EXPORT_END, encode_export_header, encode_export_record, export_header, export_page, keys,
};
use mkit_server::{Batch, NamespaceKey, NamespaceStore, Partition, StoreError, Value};
use mkit_server_worker::inspection_guard::{GuardError, Outcome, Settled, check_mode};
use std::cell::RefCell;

fn root() -> Partition {
    Partition::Namespace(NamespaceKey::deployment_default())
}

#[test]
fn worker_empty_activation_and_cached_success_and_refusal() {
    let dir = tempfile::tempdir().unwrap();
    let store = Loopback::store(dir.path().to_path_buf(), DoConfig::default());
    let cache = RefCell::new(None);
    let outcome = block_on(check_mode(&store, true));
    Settled::finish(&cache, true, Sharding::Single, false, None, outcome).unwrap();
    assert_eq!(store.transport().calls(), 3);
    assert_eq!(
        Settled::cached(&cache, true, Sharding::Single, false, None),
        Some(Outcome::Ok)
    );
    assert_eq!(
        store.transport().calls(),
        3,
        "settled cache performs no storage calls"
    );
    assert_eq!(
        Settled::cached(&cache, false, Sharding::Single, false, None),
        None
    );
    let result = block_on(check_mode(&store, false));
    let error = Settled::finish(&cache, false, Sharding::Single, false, None, result).unwrap_err();
    assert_eq!(error.public_message(), "deployment inspection mismatch");
    assert_eq!(
        Settled::cached(&cache, false, Sharding::Single, false, None),
        Some(Outcome::Disabled)
    );
    assert_eq!(
        store.transport().calls(),
        4,
        "one read settles a restart refusal"
    );
    assert_eq!(block_on(check_mode(&store, true)).unwrap(), Outcome::Ok);
}

#[test]
fn worker_nonempty_unmarked_root_refuses() {
    let dir = tempfile::tempdir().unwrap();
    let store = Loopback::store(dir.path().to_path_buf(), DoConfig::default());
    block_on(store.apply(
        &root(),
        Batch::new().put(keys::sharding_marker(), Value::new(b"single".to_vec())),
    ))
    .unwrap();
    assert_eq!(
        block_on(check_mode(&store, true)).unwrap(),
        Outcome::NonEmpty
    );
    assert_eq!(block_on(check_mode(&store, false)).unwrap(), Outcome::Ok);
    assert_eq!(
        block_on(store.get(&root(), &keys::inspection_marker())).unwrap(),
        None
    );
}

#[test]
fn worker_corrupt_marker_fails_closed_and_caches_refusal() {
    let dir = tempfile::tempdir().unwrap();
    let store = Loopback::store(dir.path().to_path_buf(), DoConfig::default());
    block_on(store.apply(
        &root(),
        Batch::new().put(keys::inspection_marker(), Value::new(b"off".to_vec())),
    ))
    .unwrap();
    for enabled in [true, false] {
        let cache = RefCell::new(None);
        let error = Settled::finish(
            &cache,
            enabled,
            Sharding::Single,
            false,
            None,
            block_on(check_mode(&store, enabled)),
        )
        .unwrap_err();
        assert_eq!(
            error.public_message(),
            "deployment inspection marker corrupt"
        );
        assert_eq!(
            Settled::cached(&cache, enabled, Sharding::Single, false, None),
            Some(Outcome::Corrupt)
        );
    }
}

#[test]
fn transient_errors_do_not_settle_and_old_completions_preserve_new_cache() {
    let cache = RefCell::new(None);
    let error = Settled::finish(
        &cache,
        true,
        Sharding::Single,
        false,
        None,
        Err(StoreError::unavailable("backend secret")),
    )
    .unwrap_err();
    assert_eq!(error.public_message(), "deployment storage unavailable");
    assert!(matches!(error, GuardError::Storage(_)));
    assert!(cache.borrow().is_none());
    Settled::finish(
        &cache,
        true,
        Sharding::Single,
        false,
        Some("eu"),
        Ok(Outcome::Ok),
    )
    .unwrap();
    assert_eq!(
        Settled::cached(&cache, true, Sharding::Single, false, Some("us")),
        None
    );
    Settled::finish(
        &cache,
        true,
        Sharding::Single,
        false,
        Some("us"),
        Ok(Outcome::Ok),
    )
    .unwrap();
    Settled::finish(
        &cache,
        true,
        Sharding::Single,
        false,
        Some("eu"),
        Ok(Outcome::Disabled),
    )
    .unwrap_err();
    assert_eq!(
        Settled::cached(&cache, true, Sharding::Single, false, Some("us")),
        Some(Outcome::Ok)
    );
}

#[test]
fn settled_cache_tracks_sharding_and_addressing_selection() {
    let cache = RefCell::new(None);
    Settled::finish(&cache, true, Sharding::Single, false, None, Ok(Outcome::Ok)).unwrap();
    assert_eq!(
        Settled::cached(&cache, true, Sharding::D34, false, None),
        None
    );
    Settled::finish(&cache, true, Sharding::D34, false, None, Ok(Outcome::Ok)).unwrap();
    assert_eq!(
        Settled::cached(&cache, true, Sharding::D34, true, None),
        None
    );
    Settled::finish(&cache, true, Sharding::D34, true, None, Ok(Outcome::Ok)).unwrap();
    assert!(
        mkit_server_worker::inspection_guard::into_result(
            Settled::cached(&cache, true, Sharding::D34, true, None).unwrap()
        )
        .is_ok()
    );
}

#[test]
fn worker_export_restore_preserves_mode() {
    let source_dir = tempfile::tempdir().unwrap();
    let target_dir = tempfile::tempdir().unwrap();
    let source = Loopback::store(source_dir.path().to_path_buf(), DoConfig::default());
    let target = Loopback::store(target_dir.path().to_path_buf(), DoConfig::default());
    assert_eq!(block_on(check_mode(&source, true)).unwrap(), Outcome::Ok);
    block_on(source.apply(
        &root(),
        Batch::new().put(keys::sharding_marker(), Value::new(b"single".to_vec())),
    ))
    .unwrap();
    let header = block_on(export_header(&source, &root(), 0)).unwrap();
    let page = block_on(export_page(&source, &root(), None, 100)).unwrap();
    assert!(page.next.is_none());
    let mut bytes = encode_export_header(&header).to_vec();
    for record in page.records {
        bytes.extend(encode_export_record(&record).unwrap());
    }
    bytes.extend(EXPORT_END);
    block_on(restore(&[bytes], &target, RestoreOptions::default())).unwrap();
    assert_eq!(block_on(check_mode(&target, true)).unwrap(), Outcome::Ok);
    assert_eq!(
        block_on(check_mode(&target, false)).unwrap(),
        Outcome::Disabled
    );
}
