//! Supported embedding configuration and Durable Object construction.

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, sync::Arc};

    use mkit_server::{BoxFuture, StoreError, policy::{RefPolicy, RefRule}};
    use mkit_server::purge::{NoLocalCache, PurgeSink, Request};

    use crate::adapter::WorkerConfig;

    struct Sink;
    impl PurgeSink for Sink {
        fn deliver<'a>(&'a self, _: &'a Request) -> BoxFuture<'a, Result<(), StoreError>> {
            Box::pin(async { Ok(()) })
        }
    }

    fn vars() -> BTreeMap<String, String> {
        [("AUTH_AUDIENCE", "https://server.example"), ("AUTH_REPOSITORY", "repo")]
            .into_iter().map(|(key,value)| (key.into(),value.into())).collect()
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
        assert!(cfg.validate().unwrap_err().0.contains("require indexed mode"));
        cfg.ref_policy = Some(RefPolicy::new(vec![RefRule {
            pattern: mkit_attest::grant::RefPattern::Exact("refs/mkit/packmap/main".into()),
            allowed_signers: None,
            fast_forward_only: false,
        }]));
        assert!(cfg.validate().unwrap_err().0.contains("invalid ref policy pattern"));
        cfg.ref_policy = None;
        cfg.takedown_denial = true;
        assert!(cfg.validate().unwrap_err().0.contains("WP-5.6a-2"));
    }

    #[test]
    fn custom_purge_attaches_the_actual_sink_and_local_invalidation() {
        let v = vars();
        let hooks = purge();
        let cfg = WorkerConfig::from_vars_with_purge(|key| v.get(key).cloned(), hooks.clone()).unwrap();
        let pipeline = cfg.pipeline_config().unwrap();
        let enabled = pipeline.purge.unwrap();
        assert!(enabled.remote_sink);
        assert!(Arc::ptr_eq(enabled.local.as_ref().unwrap(), &hooks.local));
        assert!(Arc::ptr_eq(&cfg.custom_purge.as_ref().unwrap().sink, &hooks.sink));
        assert!(cfg.hooks.is_none());
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn custom_purge_does_not_waive_admin_or_preservation_configuration() {
        let mut v = vars();
        v.remove("AUTH_REPOSITORY");
        for (key, value) in [
            ("LAUNCH_PROFILE", "uno"), ("INDEXED_MODE", "true"),
            ("WORKERS_PLAN", "paid"), ("ADDRESSING", "multi"),
            ("NAMESPACE_POLICY", "any"), ("UNSAFE_OPEN_NAMESPACES", "true"),
            ("TICKET_KEYS", "ticket 1111111111111111111111111111111111111111111111111111111111111111"),
            ("TAKEDOWN_ENABLED", "true"),
        ] { v.insert(key.into(), value.into()); }
        let parse = |v: &BTreeMap<String,String>| WorkerConfig::from_vars_with_purge(|key| v.get(key).cloned(), purge());
        assert!(parse(&v).unwrap_err().0.contains("ADMIN_KEYS"));
        v.insert("ADMIN_KEYS".into(), serde_json::json!({"version":1,"keys":[{
            "keyId":"operator", "alg":"ed25519", "publicKey":"11".repeat(32),
            "roles":["audit","moderation"]
        }]}).to_string());
        assert!(parse(&v).unwrap_err().0.contains("PRESERVATION_BUCKET"));
        for (key,value) in [("PRESERVATION_BUCKET","preserved"),
            ("PRESERVATION_RETENTION_SECS","60"),("PRESERVATION_KEY","configured")]
        { v.insert(key.into(),value.into()); }
        assert!(parse(&v).unwrap_err().0.contains("WP-5.6a-2"));
        v.insert("PRESERVATION_RETENTION_SECS".into(), "0".into());
        assert!(parse(&v).unwrap_err().0.contains("positive canonical integer"));
    }
}
