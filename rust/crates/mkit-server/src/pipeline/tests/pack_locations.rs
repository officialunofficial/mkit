//! Location fixtures used alongside the streaming security regression cases.

use super::*;
use crate::pack_location::{PackLocation, PackLocationConfig, PackLocationProvider};
use crate::store::BlobStore;

#[derive(Debug)]
struct Provider;
impl PackLocationProvider for Provider {
    fn locate(
        &self,
        key: PackKey,
        total_bytes: u64,
        expires_at_ms: i64,
    ) -> crate::BoxFuture<'_, Result<Option<PackLocation>, ServerError>> {
        Box::pin(async move {
            Ok(Some(PackLocation {
                url: format!("https://cdn.example.test/packs/{}", to_hex(&key.0)),
                total_bytes,
                expires_at_ms,
            }))
        })
    }
}

pub(super) fn config() -> Arc<PackLocationConfig> {
    Arc::new(PackLocationConfig::new(Arc::new(Provider), 1000).unwrap())
}

#[test]
fn location_does_not_expose_a_globally_stored_non_member_pack() {
    let (mut env, owner, identity) =
        indexed::environment_with(Sharding::Single, crate::indexed::IndexedConfig::default());
    env.pipe.cfg.pack_locations = Some(config());
    let repo = visibility::repo_id(&env, &owner);
    visibility::put_repo(&env, &repo, None);
    let (bytes, _) = indexed::pack();
    indexed::upload(&env, &bytes, [99; 32]);
    let reader = env
        .auth(&Req::unsigned(Procedure::DownloadPack).header("x-repository", &identity))
        .unwrap();
    assert_eq!(
        block_on(
            env.pipe
                .download_response(&reader, PackKey(hash(&bytes)), true)
        )
        .unwrap_err()
        .code(),
        Code::NotFound
    );
}

/// Advance virtual time while opening the body, after download has checked
/// authorization and membership. The optional denial races those checks.
struct DelayedBlobs {
    inner: MemoryBlobStore,
    clock: Arc<ManualClock>,
    delay_ms: i64,
    denial: Option<MemoryKv>,
}

impl BlobStore for DelayedBlobs {
    type Sink = <MemoryBlobStore as crate::store::BlobStore>::Sink;

    async fn begin(&self, key: crate::BlobKey, len: u64) -> Result<Self::Sink, StoreError> {
        self.inner.begin(key, len).await
    }

    async fn get(
        &self,
        key: &crate::BlobKey,
        range: Option<crate::ByteRange>,
    ) -> Result<Option<crate::BlobBody>, StoreError> {
        let body = self.inner.get(key, range).await?;
        if let Some(meta) = &self.denial {
            crate::store::ContentIndex::new(meta.clone())
                .block(
                    &crate::takedown::DenialCapability::for_test(),
                    key.hash(),
                    &crate::store::BlockEntry::new("manual", T0 as u64),
                    T0 as u64,
                )
                .await?;
        }
        self.clock.advance(self.delay_ms);
        YieldOnce::default().await;
        Ok(body)
    }

    async fn head(&self, key: &crate::BlobKey) -> Result<Option<crate::BlobMeta>, StoreError> {
        self.inner.head(key).await
    }

    async fn probe(&self) -> Result<(), StoreError> {
        self.inner.probe().await
    }

    async fn delete(&self, key: &crate::BlobKey) -> Result<bool, StoreError> {
        self.inner.delete(key).await
    }
}

impl MultipartBlobStore for DelayedBlobs {
    type PartSink = crate::store::UnsupportedPartSink;
    const MAX_PARTS: u32 = u32::MAX;
}

#[test]
fn location_lifetime_starts_before_download_checks_and_blob_open() {
    use mkit_core::transfer::encode_packlist;

    for (delay_ms, deny) in [(250, false), (1001, true)] {
        let (mut env, owner, identity) =
            indexed::environment_with(Sharding::Single, crate::indexed::IndexedConfig::default());
        env.pipe.cfg.pack_locations = Some(config());
        env.pipe.cfg.takedown_denial = true;
        let (bytes, head) = indexed::pack();
        let pack_id = hash(&bytes);
        let node = encode_packlist(None, &[pack_id]).unwrap();
        let tickets = vec![
            indexed::begin_and_upload(&env, &owner, &identity, &bytes, 9500),
            indexed::begin_and_upload(&env, &owner, &identity, &node, 9501),
        ];
        let writer = env
            .auth(&indexed::signed(
                &owner,
                &identity,
                Procedure::AdvanceRefs,
                9502,
            ))
            .unwrap();
        block_on(env.pipe.advance_refs_with_tickets(
            &writer,
            upd(HEAD, Missing, head),
            upd(PACKMAP, Missing, hash(&node)),
            tickets,
        ))
        .unwrap();
        let reader = env
            .auth(&Req::unsigned(Procedure::DownloadPack).header("x-repository", &identity))
            .unwrap();
        let denial = deny.then(|| env.pipe.meta.inner.clone());
        let blobs = DelayedBlobs {
            inner: env.pipe.blobs,
            clock: env.clock.clone(),
            delay_ms,
            denial,
        };
        let pipe = Pipeline::new(
            blobs,
            env.pipe.meta,
            env.pipe.hooks,
            env.pipe.cfg,
            env.clock.clone(),
            env.metrics,
        )
        .unwrap();
        let response = block_on(pipe.download_response(&reader, PackKey(pack_id), true)).unwrap();
        assert_eq!(env.clock.now_ms(), T0 + delay_ms);
        if deny {
            assert!(matches!(response, DownloadResponse::Stream(_)));
            assert_eq!(
                block_on(pipe.download_response(&reader, PackKey(pack_id), true))
                    .unwrap_err()
                    .code(),
                Code::NotFound
            );
        } else {
            let DownloadResponse::Location(location) = response else {
                panic!("short body-open delay should leave a useful location");
            };
            assert_eq!(location.expires_at_ms, T0 + 1000);
        }
    }
}
