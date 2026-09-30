//! Assemble the hooks and the kind-8 sink over one hook client (WP-3.9).
//!
//! One binding is one client: every role shares it, so an Admit and the
//! Outcome of its reservation name one audience. That audience is the
//! deployment's own canonical origin, the value [`crate::adapter::outcome_audience`]
//! stamps on the outcomes too (R-162, R-166).

use std::sync::Arc;

use mkit_server::hooks::{
    HookChannel, HookClient, HookSigner, RemoteAdmission, RemoteAuthorizer, RemoteOutcomes,
};
use mkit_server::pipeline::{
    Choice, DefaultAdmission, Hooks, NoOutcomes, NoPreReceive, NoReceipts, OpenAuthorizer,
};
use mkit_server::{Clock, Sleep};

use super::config::HookVars;
use crate::adapter::{ConfigError, OUTCOME_SINK_TIMEOUT};

/// Stage 2: open, or the remote hook.
pub type WorkerAuthorizer<C> = Choice<OpenAuthorizer, RemoteAuthorizer<C>>;
/// Stage 3: the built-in quota, or the remote hook.
pub type WorkerAdmission<C> = Choice<DefaultAdmission, RemoteAdmission<C>>;
/// Stage 8 (kind 8): the local acknowledger, or the remote hook.
pub type WorkerSink<C> = Choice<NoOutcomes, RemoteOutcomes<C>>;
/// The hooks a Worker runs.
pub type WorkerHooks<C> = Hooks<WorkerAuthorizer<C>, WorkerAdmission<C>>;

/// What [`build`] produces.
#[derive(Debug)]
pub struct Built<C> {
    /// Stages 2 and 3.
    pub hooks: WorkerHooks<C>,
    /// Stage 8.
    pub sink: WorkerSink<C>,
}

/// The local hooks: open authorization, the built-in quota, local outcomes.
#[must_use]
pub fn local<C>() -> Built<C> {
    Built {
        hooks: Hooks {
            authorizer: Choice::Left(OpenAuthorizer),
            admission: Choice::Left(DefaultAdmission),
            pre_receive: NoPreReceive,
            receipts: NoReceipts,
            outcomes: NoOutcomes,
        },
        sink: Choice::Left(NoOutcomes),
    }
}

/// The hooks for `vars` over `channel`. `server_audience` is the deployment's
/// canonical origin. The channel is unsigned, so it must report
/// [`HookChannel::isolated`].
///
/// # Errors
/// [`ConfigError`] when the client refuses the channel or the audience.
pub fn build<C: HookChannel>(
    vars: Option<&HookVars>,
    channel: C,
    server_audience: &str,
    clock: Arc<dyn Clock>,
    sleep: Arc<dyn Sleep>,
) -> Result<Built<C>, ConfigError> {
    build_signed(vars, channel, server_audience, None, clock, sleep)
}

/// Assemble signed or isolated channels over the same role contract.
///
/// # Errors
/// An invalid channel, signer or audience.
pub fn build_signed<C: HookChannel>(
    vars: Option<&HookVars>,
    channel: C,
    server_audience: &str,
    signer: Option<HookSigner>,
    clock: Arc<dyn Clock>,
    sleep: Arc<dyn Sleep>,
) -> Result<Built<C>, ConfigError> {
    let mut built = local();
    let Some(vars) = vars else {
        return Ok(built);
    };
    let client = Arc::new(
        HookClient::new(channel, server_audience, signer, clock, sleep)
            .map_err(|e| ConfigError(format!("hook client: {e}")))?,
    );
    if vars.roles.authorize {
        built.hooks.authorizer =
            Choice::Right(RemoteAuthorizer::new(Arc::clone(&client)).with_timeout(vars.timeout));
    }
    if vars.roles.admit {
        built.hooks.admission =
            Choice::Right(RemoteAdmission::new(Arc::clone(&client)).with_timeout(vars.timeout));
    }
    if vars.roles.outcome {
        // Kind 8 also bounds each call by `OUTCOME_SINK_TIMEOUT`.
        built.sink = Choice::Right(
            RemoteOutcomes::new(client).with_timeout(vars.timeout.min(OUTCOME_SINK_TIMEOUT)),
        );
    }
    Ok(built)
}

#[cfg(target_arch = "wasm32")]
pub use glue::{hooks_from_env, sink_from_env};

#[cfg(target_arch = "wasm32")]
mod glue {
    use std::sync::Arc;

    use worker::Env;

    use super::{Built, WorkerHooks, WorkerSink, build_signed, local};
    use crate::adapter::{ConfigError, WorkerConfig, outcome_audience};
    use crate::clock::WorkerClock;
    use crate::hooks::binding::BindingChannel;
    use crate::hooks::config::{BINDING, HookVars};
    use crate::hooks::fetch::{FetchChannel, WorkerChannel};
    use crate::sleep::WorkerSleep;

    fn from_env(env: &Env, cfg: &WorkerConfig) -> Result<Built<WorkerChannel>, ConfigError> {
        let binding = env.service(BINDING).is_ok();
        let http = cfg.hooks.as_ref().and_then(|v| v.http.as_ref());
        if http.is_some() && binding {
            return Err(ConfigError(
                "HOOK_URL and ADMISSION_HOOK are mutually exclusive".into(),
            ));
        }
        let key = env.secret("MKIT_HOOK_KEY").ok().map(|s| s.to_string());
        if http.is_none() && key.is_some() {
            return Err(ConfigError("MKIT_HOOK_KEY needs HOOK_URL".into()));
        }
        if http.is_none() {
            HookVars::check_binding(cfg.hooks.as_ref(), binding)?;
        }
        if cfg.hooks.is_none() {
            return Ok(local());
        }
        let (channel, signer) = if let Some(http) = http {
            #[cfg(feature = "http-objects")]
            let other_keys = cfg
                .url_tokens
                .as_ref()
                .map(|t| t.keys().public_keys().collect::<Vec<_>>())
                .unwrap_or_default();
            #[cfg(not(feature = "http-objects"))]
            let other_keys = Vec::new();
            let signer = super::super::config::http_signer(
                key,
                http,
                cfg.ticket_keys.as_ref(),
                &other_keys,
            )?;
            (
                WorkerChannel::Http(FetchChannel::new(http.endpoint.clone())),
                Some(signer),
            )
        } else {
            (WorkerChannel::Binding(BindingChannel::from_env(env)?), None)
        };
        build_signed(
            cfg.hooks.as_ref(),
            channel,
            &outcome_audience(cfg),
            signer,
            Arc::new(WorkerClock),
            Arc::new(WorkerSleep),
        )
    }

    /// The hooks of `cfg`'s hook vars over `env`'s [`BINDING`].
    ///
    /// # Errors
    /// [`ConfigError`] for vars and binding that disagree.
    pub fn hooks_from_env(
        env: &Env,
        cfg: &WorkerConfig,
    ) -> Result<WorkerHooks<WorkerChannel>, ConfigError> {
        from_env(env, cfg).map(|built| built.hooks)
    }

    /// The kind-8 sink of `cfg`'s hook vars over `env`'s [`BINDING`].
    ///
    /// # Errors
    /// As [`hooks_from_env`].
    pub fn sink_from_env(
        env: &Env,
        cfg: &WorkerConfig,
    ) -> Result<WorkerSink<WorkerChannel>, ConfigError> {
        from_env(env, cfg).map(|built| built.sink)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use futures::executor::block_on;
    use mkit_server::hooks::{ChannelError, HookRequest, HookResponse};
    use mkit_server::pipeline::{Admission, Authorizer, Outcome, OutcomeSink};
    use mkit_server::store::codec::ReservationV1;
    use mkit_server::{ManualClock, ManualSleep};

    use super::*;
    use crate::hooks::config::{HookRoles, HookVars};

    const AUDIENCE: &str = "https://vcs.example";

    struct Shared {
        isolated: bool,
        origin: Option<&'static str>,
        status: u16,
        seen: Mutex<Vec<(String, String)>>,
    }

    /// A channel that records what it is asked and answers `status`.
    #[derive(Clone)]
    struct Mock(Arc<Shared>);

    impl Mock {
        fn with(isolated: bool, origin: Option<&'static str>, status: u16) -> Self {
            Self(Arc::new(Shared {
                isolated,
                origin,
                status,
                seen: Mutex::new(Vec::new()),
            }))
        }

        fn binding(status: u16) -> Self {
            Self::with(true, None, status)
        }

        fn seen(&self) -> Vec<(String, String)> {
            self.0.seen.lock().unwrap().clone()
        }
    }

    impl HookChannel for Mock {
        fn audience(&self) -> Option<&str> {
            self.0.origin
        }

        fn isolated(&self) -> bool {
            self.0.isolated
        }

        async fn call(&self, request: HookRequest) -> Result<HookResponse, ChannelError> {
            let body = String::from_utf8(request.body.to_vec()).unwrap();
            self.0
                .seen
                .lock()
                .unwrap()
                .push((request.procedure.to_owned(), body));
            let signed = request
                .headers
                .iter()
                .any(|(name, _)| name.starts_with("X-Mkit-Hook"));
            assert!(!signed, "a binding channel sends no signature");
            Ok(HookResponse::new(
                self.0.status,
                Some("application/json".to_owned()),
                b"{}".to_vec(),
            ))
        }
    }

    fn vars(authorize: bool, admit: bool, outcome: bool) -> HookVars {
        HookVars {
            roles: HookRoles {
                authorize,
                admit,
                outcome,
            },
            timeout: crate::hooks::config::DEFAULT_TIMEOUT,
            authorizer_role: mkit_server::policy::AuthorizerRole::Check,
            http: None,
        }
    }

    fn built(vars: Option<&HookVars>, mock: &Mock) -> Result<Built<Mock>, ConfigError> {
        build(
            vars,
            mock.clone(),
            AUDIENCE,
            Arc::new(ManualClock::new(1_790_000_000_000)),
            Arc::new(ManualSleep::new()),
        )
    }

    fn expired(audience: &str) -> Outcome {
        Outcome::from_reservation(
            "r-1".to_owned(),
            audience.to_owned(),
            ReservationV1::Expired {
                repository: "ns/repo".to_owned(),
                occurred_at_ms: 1_790_000_000_000,
            },
        )
        .unwrap()
    }

    #[test]
    fn no_vars_run_the_local_hooks() {
        let mock = Mock::binding(200);
        let local = built(None, &mock).unwrap();
        assert!(local.hooks.authorizer.is_open());
        assert!(local.hooks.admission.is_default());
        assert!(block_on(local.sink.deliver(&expired(""))).is_ok());
        assert!(mock.seen().is_empty());
    }

    #[test]
    fn each_role_is_remote_only_when_listed() {
        for (roles, open, default, remote_sink) in [
            ((true, false, false), false, true, false),
            ((false, true, false), true, false, false),
            ((false, false, true), true, true, true),
            ((true, true, true), false, false, true),
        ] {
            let mock = Mock::binding(200);
            let vars = vars(roles.0, roles.1, roles.2);
            let built = built(Some(&vars), &mock).unwrap();
            assert_eq!(built.hooks.authorizer.is_open(), open, "{roles:?}");
            assert_eq!(built.hooks.admission.is_default(), default, "{roles:?}");
            assert_eq!(
                matches!(built.sink, Choice::Right(_)),
                remote_sink,
                "{roles:?}"
            );
        }
    }

    #[test]
    fn the_sink_delivers_unsigned_over_the_binding() {
        let mock = Mock::binding(200);
        let built = built(Some(&vars(false, false, true)), &mock).unwrap();
        block_on(built.sink.deliver(&expired(AUDIENCE))).unwrap();
        let seen = mock.seen();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].0, "/mkit.server.hooks.v1.HooksService/Outcome");
        assert!(seen[0].1.contains(AUDIENCE), "{}", seen[0].1);
    }

    /// The audience a sink names is the deployment's; a row stamped with
    /// another is retained (an error), never delivered.
    #[test]
    fn an_audience_mismatch_is_retained() {
        let mock = Mock::binding(200);
        let built = built(Some(&vars(false, false, true)), &mock).unwrap();
        let err = block_on(built.sink.deliver(&expired("https://other.example"))).unwrap_err();
        assert!(err.reason.expose().contains("audience"), "{err}");
        assert!(mock.seen().is_empty(), "nothing was sent");
    }

    #[test]
    fn a_non_2xx_outcome_answer_is_retained_and_a_bad_channel_refused() {
        let down = Mock::binding(503);
        let built_down = built(Some(&vars(false, false, true)), &down).unwrap();
        assert!(block_on(built_down.sink.deliver(&expired(AUDIENCE))).is_err());
        // A channel that is not isolated must sign, and this one cannot.
        let public = Mock::with(false, None, 200);
        assert!(built(Some(&vars(true, true, true)), &public).is_err());
        // An unsigned channel must not report an origin.
        let origin = Mock::with(true, Some("https://hooks.example"), 200);
        assert!(built(Some(&vars(true, true, true)), &origin).is_err());
        // An invalid deployment audience is refused up front.
        let mock = Mock::binding(200);
        let bad = build(
            Some(&vars(true, true, true)),
            mock,
            "not-an-origin",
            Arc::new(ManualClock::new(0)),
            Arc::new(ManualSleep::new()),
        );
        assert!(bad.is_err());
    }
}
