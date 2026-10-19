//! Location fixtures used alongside the streaming security regression cases.

use super::*;
use crate::pack_location::{PackLocation, PackLocationConfig, PackLocationProvider};

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
