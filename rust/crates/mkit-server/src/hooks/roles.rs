//! The three roles a remote hook service can play, one type each so a
//! deployment enables any subset through `Hooks<…>` (SPEC-SERVER §6.1).

use core::time::Duration;
use std::sync::Arc;

use super::channel::HookChannel;
use super::client::{DEFAULT_TIMEOUT, HookClient, Rpc};
use super::map;
use super::proto::v1 as pb;
use crate::error::ServerError;
use crate::op::{AuthzFacts, Operation};
use crate::pipeline::{
    Admission, AdmissionDecision, AdmissionInput, Authorizer, DeliveryError, Outcome, OutcomeSink,
    validate_decision,
};

/// Stage 2 over `HooksService.Authorize`. Any failure, and any decision
/// that is not a deliberate allow or deny, answers retryable `unavailable`.
pub struct RemoteAuthorizer<C> {
    client: Arc<HookClient<C>>,
    timeout: Duration,
}

/// Stage 3 over `HooksService.Admit`. It returns no quota charges and every
/// allow carries the hook's reservation id.
pub struct RemoteAdmission<C> {
    client: Arc<HookClient<C>>,
    timeout: Duration,
}

/// Stage 8 over `HooksService.Outcome`: any 2xx acknowledges, everything else
/// leaves the outcome queued for kind 8's backoff.
pub struct RemoteOutcomes<C> {
    client: Arc<HookClient<C>>,
    timeout: Duration,
}

/// Signed durable global cache-purge delivery, distinct from admission.
pub struct RemotePurge<C> {
    client: Arc<HookClient<C>>,
    timeout: Duration,
}

macro_rules! role {
    ($name:ident) => {
        impl<C> core::fmt::Debug for $name<C> {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.debug_struct(stringify!($name))
                    .field("timeout", &self.timeout)
                    .finish_non_exhaustive()
            }
        }

        impl<C> Clone for $name<C> {
            fn clone(&self) -> Self {
                Self {
                    client: self.client.clone(),
                    timeout: self.timeout,
                }
            }
        }

        impl<C> $name<C> {
            /// The role over a shared client, with the default 5 s timeout.
            #[must_use]
            pub fn new(client: Arc<HookClient<C>>) -> Self {
                Self {
                    client,
                    timeout: DEFAULT_TIMEOUT,
                }
            }

            /// Bound each call by `timeout`.
            #[must_use]
            pub fn with_timeout(mut self, timeout: Duration) -> Self {
                self.timeout = timeout;
                self
            }
        }
    };
}
role!(RemoteAuthorizer);
role!(RemoteAdmission);
role!(RemoteOutcomes);
role!(RemotePurge);

type PurgeAcknowledgement = std::collections::BTreeMap<String, serde::de::IgnoredAny>;

impl<C: HookChannel> crate::purge::PurgeSink for RemotePurge<C> {
    fn deliver<'a>(
        &'a self,
        request: &'a crate::purge::Request,
    ) -> crate::BoxFuture<'a, Result<(), crate::StoreError>> {
        Box::pin(async move {
            request.validate()?;
            if !self.client.is_signed() {
                return Err(crate::StoreError::unavailable("purge signing required"));
            }
            if request.audience != self.client.server_audience() {
                return Err(crate::StoreError::unavailable("purge audience mismatch"));
            }
            let acknowledgement = self
                .client
                .decide::<_, PurgeAcknowledgement>(Rpc::CachePurge, request, self.timeout)
                .await
                .map_err(|_| crate::StoreError::unavailable("purge delivery failed"))?;
            if !acknowledgement.is_empty() {
                return Err(crate::StoreError::unavailable(
                    "invalid purge acknowledgement",
                ));
            }
            Ok(())
        })
    }
}

#[cfg(test)]
mod purge_tests {
    use super::*;
    use crate::hooks::tests::{MockChannel, Step, channel_of, client};
    use crate::purge::{PurgeSink, Request, Trigger};
    use crate::{ManualClock, ManualSleep};
    use futures_executor::block_on;

    fn request() -> Request {
        Request {
            purge_id: "purge:test".into(),
            audience: "https://vcs.example.test".into(),
            repository: "root/repo".into(),
            namespace: String::new(),
            trigger: Trigger::VisibilityChange,
            url_paths: Vec::new(),
            object_ids: Vec::new(),
            refs: Vec::new(),
        }
    }

    #[test]
    fn cache_purge_requires_an_empty_json_acknowledgement() {
        for step in [
            Step::json(r#"{"code":"error"}"#),
            Step::json("null"),
            Step::json("[]"),
            Step::json(""),
            Step::Reply(204, None, Vec::new()),
            Step::Reply(200, Some("text/plain"), b"{}".to_vec()),
            Step::Reply(200, Some("application/json"), vec![b' '; 65_537]),
            Step::Reply(503, Some("application/json"), b"{}".to_vec()),
        ] {
            let client = client(MockChannel::new(step), ManualSleep::new());
            assert!(block_on(RemotePurge::new(client).deliver(&request())).is_err());
        }
        let client = client(MockChannel::new(Step::json(" {} ")), ManualSleep::new());
        block_on(RemotePurge::new(client).deliver(&request())).unwrap();
    }

    #[test]
    fn retry_retains_body_and_id_but_refreshes_signature_nonce() {
        let client = client(MockChannel::new(Step::json("{}")), ManualSleep::new());
        let sink = RemotePurge::new(client.clone());
        for _ in 0..2 {
            block_on(sink.deliver(&request())).unwrap();
        }
        let seen = channel_of(&client).seen.lock().unwrap();
        assert_eq!(seen[0].body, seen[1].body);
        assert_eq!(
            seen[0].procedure,
            "/mkit.server.hooks.v1.HooksService/CachePurge"
        );
        assert_eq!(
            serde_json::from_slice::<Request>(&seen[0].body).unwrap(),
            request()
        );
        let nonce = |i: usize| {
            &seen[i]
                .headers
                .iter()
                .find(|(name, _)| *name == "X-Mkit-Hook-Nonce")
                .unwrap()
                .1
        };
        assert_ne!(nonce(0), nonce(1));
    }

    struct UnsignedBinding;
    impl HookChannel for UnsignedBinding {
        fn audience(&self) -> Option<&str> {
            None
        }
        fn isolated(&self) -> bool {
            true
        }
        async fn call(
            &self,
            _: crate::hooks::HookRequest,
        ) -> Result<crate::hooks::HookResponse, crate::hooks::ChannelError> {
            panic!("an unsigned purge must be refused before transport");
        }
    }
    #[test]
    fn cache_purge_refuses_unsigned_service_bindings() {
        let client = HookClient::new(
            UnsignedBinding,
            request().audience,
            None,
            Arc::new(ManualClock::new(1)),
            Arc::new(ManualSleep::new()),
        )
        .unwrap();
        assert!(block_on(RemotePurge::new(Arc::new(client)).deliver(&request())).is_err());
    }
}

/// What a [`WipeOnDrop`] holds: credential values that must not outlive the
/// call that carried them.
pub(super) trait Wipe {
    fn wipe(&mut self);
}

impl Wipe for pb::AdmitRequest {
    fn wipe(&mut self) {
        map::wipe(self);
    }
}

/// Wipes its value on drop, so a cancelled or panicking call wipes too.
pub(super) struct WipeOnDrop<T: Wipe>(pub(super) T);

impl<T: Wipe> Drop for WipeOnDrop<T> {
    fn drop(&mut self) {
        self.0.wipe();
    }
}

impl<C: HookChannel> Authorizer for RemoteAuthorizer<C> {
    async fn authorize(&self, op: &Operation) -> Result<AuthzFacts, ServerError> {
        let request = map::authorize_request(op, self.client.server_audience());
        let answer: pb::AuthorizeResponse = self
            .client
            .decide(Rpc::Authorize, &request, self.timeout)
            .await
            .map_err(|failure| map::unavailable("authorization", failure.0))?;
        map::authorize_answer(answer, op)
    }
}

impl<C: HookChannel> Admission for RemoteAdmission<C> {
    async fn admit(&self, input: &AdmissionInput<'_>) -> Result<AdmissionDecision, ServerError> {
        // The pipeline's own origin and this adapter's must agree, or an Admit
        // and the Outcome for its reservation would name different audiences.
        if input
            .audience
            .is_some_and(|origin| origin != self.client.server_audience())
        {
            return Err(map::unavailable("admission", "audience mismatch"));
        }
        // Wiped when this future finishes, is cancelled or unwinds.
        let request = WipeOnDrop(map::admit_request(input, self.client.server_audience()));
        let answer = self
            .client
            .decide::<_, pb::AdmitResponse>(Rpc::Admit, &request.0, self.timeout)
            .await;
        let answer = answer.map_err(|failure| map::unavailable("admission", failure.0))?;
        let decision = map::admit_answer(answer)?;
        validate_decision(&decision)?;
        Ok(decision)
    }
}

impl<C: HookChannel> OutcomeSink for RemoteOutcomes<C> {
    async fn deliver(&self, outcome: &Outcome) -> Result<(), DeliveryError> {
        // The row's audience and this adapter's must be one value (an Admit
        // and its Outcome name the same origin); a mismatch is retried, and
        // the operator fixes the wiring.
        if !outcome.audience.is_empty() && outcome.audience != self.client.server_audience() {
            tracing::warn!(reason = "audience mismatch", "remote outcome hook unusable");
            return Err(DeliveryError::new("audience mismatch", None));
        }
        let request = map::outcome_request(outcome);
        self.client
            .deliver(Rpc::Outcome, &request, self.timeout)
            .await
            .map_err(|failure| DeliveryError::new(failure.0, None))
    }
}
