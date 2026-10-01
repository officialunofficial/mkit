//! Supported embedding configuration and Durable Object construction.

use mkit_server::purge::{LocalInvalidation, PurgeSink};
use std::sync::Arc;

/// Explicit in-process purge delivery and its local cache invalidation.
/// The sink acknowledges global invalidation; local work must charge the
/// supplied budget and persist resumable checkpoints through the existing API.
#[derive(Clone)]
pub struct PurgeHooks {
    /// Global sink, replacing the environment's signed HTTPS purge hook.
    pub sink: Arc<dyn PurgeSink>,
    /// Invalidation used on requests and durable timer retries.
    pub local: Arc<dyn LocalInvalidation>,
}

impl PurgeHooks {
    /// Pair the actual sink with the cache implementation it invalidates.
    #[must_use]
    pub fn new(sink: Arc<dyn PurgeSink>, local: Arc<dyn LocalInvalidation>) -> Self {
        Self { sink, local }
    }

    #[cfg(any(target_arch = "wasm32", test))]
    pub(crate) fn delivery(
        &self,
        budget: mkit_server::purge::SliceBudget,
    ) -> mkit_server::purge::PurgeDelivery {
        mkit_server::purge::PurgeDelivery::new(self.local.clone(), Some(self.sink.clone()), budget)
    }
}
impl core::fmt::Debug for PurgeHooks {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PurgeHooks").finish_non_exhaustive()
    }
}
impl PartialEq for PurgeHooks {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.sink, &other.sink) && Arc::ptr_eq(&self.local, &other.local)
    }
}
impl Eq for PurgeHooks {}

/// Construct a DO from the same validated configuration as its fetch path.
/// Configuration/sink errors keep delivery work queued; they never waive rows.
#[cfg(target_arch = "wasm32")]
#[must_use]
pub struct NsObjectBuilder {
    state: worker::State,
    env: worker::Env,
    class: crate::classes::ShardClass,
    config: Result<crate::adapter::WorkerConfig, crate::adapter::ConfigError>,
}

#[cfg(target_arch = "wasm32")]
impl core::fmt::Debug for NsObjectBuilder {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NsObjectBuilder")
            .field("class", &self.class)
            .finish_non_exhaustive()
    }
}

#[cfg(target_arch = "wasm32")]
impl NsObjectBuilder {
    /// Keep configuration failures fail-closed during infallible DO construction.
    pub fn new(
        state: worker::State,
        env: &worker::Env,
        class: crate::classes::ShardClass,
        config: Result<crate::adapter::WorkerConfig, crate::adapter::ConfigError>,
    ) -> Self {
        Self {
            state,
            env: env.clone(),
            class,
            config,
        }
    }

    /// Configure snapshot reads/generation together with a custom outcome sink.
    #[cfg(feature = "published-view")]
    pub fn with_published_view(
        mut self,
        config: crate::published_view::PublishedViewConfig,
    ) -> Self {
        if let Ok(cfg) = &mut self.config {
            cfg.published_view = Some(config);
        }
        self
    }

    /// Use custom global delivery and local invalidation for durable purges.
    /// For a takedown environment, parse with `from_env_with_purge` first so
    /// the actual sink participates in startup validation.
    pub fn with_purge(
        mut self,
        sink: Arc<dyn PurgeSink>,
        local: Arc<dyn LocalInvalidation>,
    ) -> Self {
        if let Ok(cfg) = &mut self.config {
            cfg.custom_purge = Some(PurgeHooks::new(sink, local));
        }
        self
    }

    /// Build all existing handlers, including the supplied outcome factory.
    pub fn build_with<O, F>(self, make_sink: F) -> crate::ns_object::NsObject
    where
        O: mkit_server::pipeline::OutcomeSink + 'static,
        F: FnOnce(
            &worker::Env,
            &crate::adapter::WorkerConfig,
        ) -> Result<O, crate::adapter::ConfigError>,
    {
        crate::adapter::build_ns_object(self.state, &self.env, self.class, self.config, make_sink)
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, sync::Arc};

    use mkit_server::purge::{NoLocalCache, PurgeSink, Request};
    use mkit_server::{
        BoxFuture, StoreError,
        policy::{RefPolicy, RefRule},
    };

    use crate::adapter::WorkerConfig;

    struct Sink;
    impl PurgeSink for Sink {
        fn deliver<'a>(&'a self, _: &'a Request) -> BoxFuture<'a, Result<(), StoreError>> {
            Box::pin(async { Ok(()) })
        }
    }

    fn vars() -> BTreeMap<String, String> {
        [
            ("AUTH_AUDIENCE", "https://server.example"),
            ("AUTH_REPOSITORY", "repo"),
        ]
        .into_iter()
        .map(|(key, value)| (key.into(), value.into()))
        .collect()
    }

    fn purge() -> super::PurgeHooks {
        super::PurgeHooks::new(Arc::new(Sink), Arc::new(NoLocalCache))
    }

    #[test]
    fn programmatic_policy_is_validated_before_store_access() {
        let v = vars();
        let mut cfg = WorkerConfig::from_vars(|key| v.get(key).cloned()).unwrap();
        assert!(cfg.admin_on_public_path);
        assert!(cfg.ref_policy.is_none());
        assert!(!cfg.takedown_denial);
        cfg.ref_policy = Some(RefPolicy::new(vec![RefRule {
            pattern: mkit_attest::grant::RefPattern::parse("refs/tags/*").unwrap(),
            allowed_signers: None,
            fast_forward_only: true,
        }]));
        assert!(
            cfg.validate()
                .unwrap_err()
                .0
                .contains("require indexed mode")
        );
        cfg.ref_policy = Some(RefPolicy::new(vec![RefRule {
            pattern: mkit_attest::grant::RefPattern::Exact("refs/mkit/packmap/main".into()),
            allowed_signers: None,
            fast_forward_only: false,
        }]));
        assert!(
            cfg.validate()
                .unwrap_err()
                .0
                .contains("invalid ref policy pattern")
        );
        cfg.ref_policy = None;
        cfg.takedown_denial = true;
        assert!(
            cfg.validate()
                .unwrap_err()
                .0
                .contains("complete preservation")
        );
    }

    #[test]
    fn custom_purge_attaches_the_actual_sink_and_local_invalidation() {
        let v = vars();
        let hooks = purge();
        let cfg =
            WorkerConfig::from_vars_with_purge(|key| v.get(key).cloned(), hooks.clone()).unwrap();
        let pipeline = cfg.pipeline_config().unwrap();
        let enabled = pipeline.purge.unwrap();
        assert!(enabled.remote_sink);
        assert!(Arc::ptr_eq(enabled.local.as_ref().unwrap(), &hooks.local));
        assert!(Arc::ptr_eq(
            &cfg.custom_purge.as_ref().unwrap().sink,
            &hooks.sink
        ));
        assert!(cfg.hooks.is_none());
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn custom_purge_does_not_waive_admin_or_preservation_configuration() {
        let mut v = vars();
        v.remove("AUTH_REPOSITORY");
        for (key, value) in [
            ("LAUNCH_PROFILE", "uno"),
            ("INDEXED_MODE", "true"),
            ("WORKERS_PLAN", "paid"),
            ("ADDRESSING", "multi"),
            ("NAMESPACE_POLICY", "any"),
            ("UNSAFE_OPEN_NAMESPACES", "true"),
            (
                "TICKET_KEYS",
                "ticket 1111111111111111111111111111111111111111111111111111111111111111",
            ),
            ("TAKEDOWN_ENABLED", "true"),
        ] {
            v.insert(key.into(), value.into());
        }
        let parse = |v: &BTreeMap<String, String>| {
            WorkerConfig::from_vars_with_purge(|key| v.get(key).cloned(), purge())
        };
        assert!(parse(&v).unwrap_err().0.contains("ADMIN_KEYS"));
        v.insert(
            "ADMIN_KEYS".into(),
            serde_json::json!({"version":1,"keys":[{
                "keyId":"operator", "alg":"ed25519", "publicKey":"11".repeat(32),
                "roles":["audit","moderation"]
            }]})
            .to_string(),
        );
        assert!(
            parse(&v)
                .unwrap_err()
                .0
                .contains("PRESERVATION_RETENTION_MS")
        );
        let receipt =
            mkit_server::hooks::HookSigner::new("receipt", zeroize::Zeroizing::new([41; 32]))
                .unwrap()
                .public_key();
        v.insert("PRESERVATION_RETENTION_MS".into(), "60000".into());
        assert!(parse(&v).unwrap_err().0.contains("RECEIPT_NOTICE_KEY"));
        v.insert(
            "RECEIPT_NOTICE_KEY".into(),
            mkit_core::hash::to_hex(&[41; 32]),
        );
        assert!(parse(&v).unwrap_err().0.contains("RECEIPT_KEYS"));
        v.insert(
            "RECEIPT_KEYS".into(),
            serde_json::json!({"version":1,"keys":[{
                "keyId":mkit_core::hash::to_hex(&mkit_core::hash::hash(&receipt)),
                "alg":"ed25519", "publicKey":mkit_core::hash::to_hex(&receipt)
            }]})
            .to_string(),
        );
        assert!(
            parse(&v).is_ok(),
            "custom sink with complete preservation must parse"
        );
        let mut cfg = parse(&v).unwrap();
        cfg.takedown_denial = false;
        cfg.launch.as_mut().unwrap().takedown = false;
        cfg.takedown.as_mut().unwrap().retention_ms = 0;
        assert!(
            cfg.validate().is_err(),
            "configured preservation requires positive retention even when denial is disabled"
        );
        v.insert("PRESERVATION_RETENTION_MS".into(), "0".into());
        assert!(
            parse(&v)
                .unwrap_err()
                .0
                .contains("positive PRESERVATION_RETENTION_MS")
        );
    }

    #[test]
    fn custom_purge_timer_delivers_and_charges_the_shared_allowance() {
        use mkit_server::purge::{SliceBudget, Trigger, plan_enqueue, read_request};
        use mkit_server::timers::{TickBudget, TimerRegistry, run_due};
        use mkit_server::{ManualClock, MemoryKv, NamespaceKey, NamespaceStore, Partition};
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct Counted(Arc<AtomicUsize>);
        impl PurgeSink for Counted {
            fn deliver<'a>(&'a self, _: &'a Request) -> BoxFuture<'a, Result<(), StoreError>> {
                Box::pin(async {
                    self.0.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                })
            }
        }
        futures::executor::block_on(async {
            let store = MemoryKv::default();
            let partition = Partition::Namespace(NamespaceKey::deployment_default());
            let request = Request {
                purge_id: "embedded-purge".into(),
                audience: "https://server.example".into(),
                repository: "root/repo".into(),
                namespace: String::new(),
                trigger: Trigger::Manual,
                url_paths: vec!["/object/path".into()],
                object_ids: Vec::new(),
                refs: Vec::new(),
            };
            store
                .apply(&partition, plan_enqueue(&request, 10, None, None).unwrap())
                .await
                .unwrap();
            let count = Arc::new(AtomicUsize::new(0));
            let hooks =
                super::PurgeHooks::new(Arc::new(Counted(count.clone())), Arc::new(NoLocalCache));
            let budget = SliceBudget::new(1);
            let registry = TimerRegistry::new().register(hooks.delivery(budget.clone()));
            run_due(
                &store,
                &partition,
                &registry,
                &ManualClock::new(10),
                10,
                &TickBudget::default(),
            )
            .await
            .unwrap();
            assert_eq!(count.load(Ordering::SeqCst), 1);
            assert_eq!(budget.used(), 1);
            assert!(
                read_request(&store, &partition, &request.purge_id)
                    .await
                    .unwrap()
                    .is_none()
            );
        });
    }
}
