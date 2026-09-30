//! Generate the five Workers DO exports with a shared embedding configuration.

/// Export `RefStore`, `NsCoordinator`, `RefShard`, `RepoIndexShard` and `ContentIndexShard`.
///
/// `config_factory(&Env)` returns a validated `Result<WorkerConfig, ConfigError>`;
/// `sink_factory(&Env, &WorkerConfig)` returns the outcome sink for that same
/// configuration. Use the config factory on fetch as well, so policies, snapshots
/// and purge delivery agree. The caller must depend on `worker` (workers-rs).
/// Errors retain queued work. Class names match the standard Wrangler bindings.
#[macro_export]
macro_rules! durable_objects {
    () => {
        $crate::durable_objects!(
            $crate::adapter::WorkerConfig::from_env,
            $crate::hooks::build::sink_from_env
        );
    };
    ($config:path, $sink:path) => {
        mod __mkit_durable_objects {
            use super::*;
            // wasm-bindgen's generated code resolves this crate name locally.
            use ::worker::wasm_bindgen;
            $crate::durable_objects!(@class RefStore, RefStore, $config, $sink);
            $crate::durable_objects!(@class NsCoordinator, NsCoordinator, $config, $sink);
            $crate::durable_objects!(@class RefShard, RefShard, $config, $sink);
            $crate::durable_objects!(@class RepoIndexShard, RepoIndexShard, $config, $sink);
            $crate::durable_objects!(@class ContentIndexShard, ContentIndexShard, $config, $sink);
        }
        pub use __mkit_durable_objects::{RefStore, NsCoordinator, RefShard, RepoIndexShard, ContentIndexShard};
    };
    (@class $name:ident, $class:ident, $config:path, $sink:path) => {
        #[::worker::durable_object]
        pub struct $name {
            object: $crate::ns_object::NsObject,
        }
        impl ::worker::DurableObject for $name {
            fn new(state: ::worker::State, env: ::worker::Env) -> Self {
                Self {
                    object: $crate::embedding::NsObjectBuilder::new(
                        state, &env, $crate::classes::ShardClass::$class, $config(&env),
                    ).build_with($sink),
                }
            }
            async fn fetch(&self, req: ::worker::Request) -> ::worker::Result<::worker::Response> {
                self.object.handle(req).await
            }
            async fn alarm(&self) -> ::worker::Result<::worker::Response> {
                self.object.alarm().await
            }
        }
    };
}
