//! Authorization for denial rows, issued by an enabled deployment pipeline.
/// Permission to install block rows and denial actions.
///
/// Obtain this capability from [`crate::pipeline::Pipeline::denial_capability`].
/// Its private fields prevent direct construction outside the server core.
///
/// ```compile_fail
/// let capability = mkit_server::takedown::DenialCapability {};
/// ```
///
/// Raw writers require this capability:
///
/// ```compile_fail
/// async fn write_without_authorization<S: mkit_server::NamespaceStore>(
///     index: mkit_server::ContentIndex<S>,
/// ) {
///     index.block(&[0; 32], &mkit_server::store::BlockEntry::new("policy", 0), 0)
///         .await.unwrap();
/// }
/// ```
#[derive(Clone, Copy, Debug)]
pub struct DenialCapability {
    _private: (),
}
impl DenialCapability {
    pub(crate) fn enabled() -> Self {
        Self { _private: () }
    }
    #[cfg(test)]
    pub(crate) fn for_test() -> Self {
        Self::enabled()
    }
}
pub(crate) fn disabled() -> crate::ServerError {
    crate::ServerError::failed_precondition("takedown denial disabled")
}

#[cfg(all(test, feature = "memory"))]
mod tests {
    use crate::pipeline::{AuthMode, Hooks, Pipeline, PipelineConfig};

    #[test]
    fn only_enabled_pipeline_issues_denial_write_capability() {
        for enabled in [false, true] {
            let mut config = PipelineConfig::new(
                crate::Addressing::Multi(crate::repo::MultiAddressing::new()),
                AuthMode::AuthV2(
                    crate::auth_v2::AuthV2Config::new("http://localhost", "default").unwrap(),
                ),
                crate::upload::UploadLimits::new(1 << 20, 64),
            );
            config.indexed = Some(crate::indexed::IndexedConfig::default());
            config.ticket_keys = Some(
                crate::upload::token::TicketKeys::new(vec![("test".into(), [7; 32])]).unwrap(),
            );
            config.begin_upload_threshold_bytes = 0;
            config.takedown_denial = enabled;
            let pipeline = Pipeline::new(
                crate::MemoryBlobStore::default(),
                crate::MemoryKv::default(),
                Hooks::new(),
                config,
                std::sync::Arc::new(crate::SystemClock),
                std::sync::Arc::new(crate::NoopMetrics),
            )
            .unwrap();
            assert_eq!(pipeline.denial_capability().is_some(), enabled);
        }
    }
}
