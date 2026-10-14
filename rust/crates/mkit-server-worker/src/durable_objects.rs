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
        $crate::__mkit_durable_object_class!($name, $class, $config, $sink);
    };
}

// Select here, so consumer feature names cannot change the export surface.
#[cfg(not(feature = "perf-metrics"))]
#[doc(hidden)]
#[macro_export]
macro_rules! __mkit_durable_object_class {
    ($name:ident, $class:ident, $config:path, $sink:path) => {
        #[::worker::durable_object]
        pub struct $name {
            object: $crate::ns_object::NsObject,
        }
        impl ::worker::DurableObject for $name {
            fn new(state: ::worker::State, env: ::worker::Env) -> Self {
                Self {
                    object: $crate::embedding::NsObjectBuilder::new(
                        state,
                        &env,
                        $crate::classes::ShardClass::$class,
                        $config(&env),
                    )
                    .build_with($sink),
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

#[cfg(feature = "perf-metrics")]
#[doc(hidden)]
#[macro_export]
macro_rules! __mkit_durable_object_class {
    ($name:ident, $class:ident, $config:path, $sink:path) => {
        // Preserve every upstream export, including methods added by newer
        // workers-rs versions. The optional JavaScript wrapper forwards metadata
        // to an additive method, leaving the generated alarm export intact.
        #[::worker::durable_object]
        pub struct $name {
            object: ::std::rc::Rc<$crate::ns_object::NsObject>,
        }
        impl ::worker::DurableObject for $name {
            fn new(state: ::worker::State, env: ::worker::Env) -> Self {
                Self {
                    object: ::std::rc::Rc::new(
                        $crate::embedding::NsObjectBuilder::new(
                            state,
                            &env,
                            $crate::classes::ShardClass::$class,
                            $config(&env),
                        )
                        .build_with($sink),
                    ),
                }
            }
            async fn fetch(&self, req: ::worker::Request) -> ::worker::Result<::worker::Response> {
                self.object.handle(req).await
            }
            async fn alarm(&self) -> ::worker::Result<::worker::Response> {
                self.object.alarm().await
            }
        }
        #[::worker::wasm_bindgen::prelude::wasm_bindgen(wasm_bindgen=::worker::wasm_bindgen)]
        impl $name {
            #[wasm_bindgen(js_name = alarmWithInfo, wasm_bindgen=::worker::wasm_bindgen)]
            pub fn alarm_with_info(
                &self,
                info: ::worker::wasm_bindgen::JsValue,
            ) -> ::worker::js_sys::Promise {
                let object = self.object.clone();
                ::worker::js_sys::futures::future_to_promise(::std::panic::AssertUnwindSafe(
                    async move {
                        object
                            .alarm_with_info(info)
                            .await
                            .map(::worker::worker_sys::web_sys::Response::from)
                            .map(::worker::wasm_bindgen::JsValue::from)
                            .map_err(::worker::wasm_bindgen::JsValue::from)
                    },
                ))
            }
        }
    };
}
