#![allow(clippy::unwrap_used)]
use super::*;
#[test]
fn v050_stored_encodings() {
    use crate::pipeline::{Addressing, AuthMode, Hooks, PipelineConfig};
    use crate::{MemoryBlobStore, MemoryKv, NoopMetrics, RepoId, RepoName};
    futures_executor::block_on(async {
        let expected =
            crate::stored_golden::row_fixture!("pipeline-revocation-RevokeCheckpoint", b"\x01");
        let checkpoint = crate::stored_golden::json_fixture!(
            RevokeCheckpoint,
            "pipeline-revocation-RevokeCheckpoint"
        );
        let ns = NamespaceKey::deployment_default();
        let partition = Partition::Coordinator(ns.clone());
        let state = CoordinatorState {
            kind: FenceKind::Grant,
            epoch: checkpoint.generation,
            epoch_value: Some(codec::encode_u64(checkpoint.generation)),
            config_version: 1,
            recovery: checkpoint.recovery,
        };
        let kv = MemoryKv::default();
        let key = keys::revoke_cursor(false);
        kv.apply(
            &partition,
            Batch::new()
                .put(key.clone(), expected.clone())
                .put(state.kind.key(), state.epoch_value.clone().unwrap())
                .put(
                    keys::lease_recovery(),
                    codec::encode_lease_recovery(&state.recovery.unwrap()),
                ),
        )
        .await
        .unwrap();
        let cfg = PipelineConfig::new(
            Addressing::Single {
                repo: RepoId {
                    namespace: ns,
                    name: RepoName::new("repo").unwrap(),
                },
            },
            AuthMode::Open,
            crate::upload::UploadLimits {
                max_total_bytes: 1 << 20,
                max_chunks: 64,
            },
        );
        let pipe = Pipeline::new(
            MemoryBlobStore::default(),
            kv,
            Hooks::new(),
            cfg,
            std::sync::Arc::new(crate::ManualClock::new(1000)),
            std::sync::Arc::new(NoopMetrics),
        )
        .unwrap();
        let (raw, cursor) = pipe.read_revoke_cursor(&partition, &state).await.unwrap();
        assert_eq!(raw, Some(expected.clone()));
        assert_eq!(cursor.as_ref().unwrap().as_bytes(), [1, 2]);
        assert!(
            pipe.save_revoke_cursor(&partition, &state, raw.as_ref(), cursor)
                .await
                .unwrap()
        );
        assert_eq!(
            pipe.meta.get(&partition, &key).await.unwrap(),
            Some(expected)
        );
    });
}
