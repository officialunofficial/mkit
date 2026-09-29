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
        let request = map::admit_request(input, self.client.server_audience());
        let answer: pb::AdmitResponse = self
            .client
            .decide(Rpc::Admit, &request, self.timeout)
            .await
            .map_err(|failure| map::unavailable("admission", failure.0))?;
        let decision = map::admit_answer(answer)?;
        validate_decision(&decision)?;
        Ok(decision)
    }
}

impl<C: HookChannel> OutcomeSink for RemoteOutcomes<C> {
    async fn deliver(&self, outcome: &Outcome) -> Result<(), DeliveryError> {
        let request = map::outcome_request(outcome);
        self.client
            .deliver(Rpc::Outcome, &request, self.timeout)
            .await
            .map_err(|failure| DeliveryError::new(failure.0, None))
    }
}
