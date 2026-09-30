//! Synchronous `PRE_RECEIVE` inspection over the existing signed hook channels.
//!
//! Calls carry metadata and optional R-193 raw-pack retrieval credentials only.
//! Public object serving cannot supply unpublished content (SPEC-SERVER §6.4).

use core::time::Duration;
use std::collections::BTreeSet;
use std::sync::Arc;

use super::client::Rpc;
use super::map;
use super::proto::v1 as pb;
use super::proto::v1::__buffa::oneof::inspect_response::Verdict;
use super::{DEFAULT_TIMEOUT, HookChannel, HookClient};
use crate::error::ServerError;
use crate::op::Operation;

/// A validated launch-profile verdict. Quarantine rejects the push at stage 5.
/// Quarantine is a rejection under the launch amendment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InspectVerdict {
    /// This inspector permits the batch.
    Pass,
    /// Reject this push with sanitized public policy text.
    Reject(String),
}

/// One named synchronous inspector over a shared hook client.
pub struct RemoteInspector<C> {
    name: String,
    client: Arc<HookClient<C>>,
    timeout: Duration,
}

impl<C> Clone for RemoteInspector<C> {
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            client: self.client.clone(),
            timeout: self.timeout,
        }
    }
}

impl<C> core::fmt::Debug for RemoteInspector<C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RemoteInspector")
            .field("name", &self.name)
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl<C> RemoteInspector<C> {
    /// The inspector's configuration identity, with the default 5 s timeout.
    #[must_use]
    pub fn new(name: impl Into<String>, client: Arc<HookClient<C>>) -> Self {
        Self {
            name: name.into(),
            client,
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// The stable configured identity used to derive logical inspection ids.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.name
    }

    /// Bound each remote attempt by this timeout.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

impl<C: HookChannel> RemoteInspector<C> {
    /// Inspect one complete assigned batch before apply. Every attempt signs
    /// afresh; the caller retains `inspection_id` across logical retries.
    ///
    /// # Errors
    /// Retryable unavailable for transport failures or invalid metadata/verdicts.
    pub async fn inspect(
        &self,
        op: &Operation,
        inspection_id: &str,
        objects: &[pb::InspectObject],
    ) -> Result<InspectVerdict, ServerError> {
        self.inspect_request(op, inspection_id, objects, None).await
    }

    async fn inspect_request(
        &self,
        op: &Operation,
        inspection_id: &str,
        objects: &[pb::InspectObject],
        retrieval: Option<pb::InspectRetrieval>,
    ) -> Result<InspectVerdict, ServerError> {
        if self.name.is_empty() || inspection_id.is_empty() || !objects.iter().all(valid_object) {
            return Err(map::unavailable("inspection", "invalid request metadata"));
        }
        let request = pb::InspectRequest {
            operation: map::authorize_request(op, self.client.server_audience()).operation,
            objects: objects.to_vec(),
            scanner_retrieval: retrieval.into(),
            phase: Some(pb::InspectPhase::INSPECT_PHASE_PRE_RECEIVE.into()),
            inspection_id: Some(inspection_id.to_owned()),
            ..Default::default()
        };
        let answer: pb::InspectResponse = self
            .client
            .decide(Rpc::Inspect, &request, self.timeout)
            .await
            .map_err(|failure| map::unavailable("inspection", failure.0))?;
        validate_answer(answer, objects)
    }
}

impl<C: HookChannel> crate::pipeline::inspection::ContentInspector for RemoteInspector<C> {
    fn id(&self) -> &str {
        self.id()
    }

    fn retrieval_timeout(&self) -> Duration {
        self.timeout
    }

    fn inspect_with_retrieval<'a>(
        &'a self,
        op: &'a Operation,
        id: &'a str,
        objects: &'a [pb::InspectObject],
        retrieval: Option<pb::InspectRetrieval>,
    ) -> crate::BoxFuture<'a, Result<InspectVerdict, ServerError>> {
        Box::pin(self.inspect_request(op, id, objects, retrieval))
    }

    fn inspect<'a>(
        &'a self,
        op: &'a Operation,
        inspection_id: &'a str,
        objects: &'a [pb::InspectObject],
    ) -> crate::BoxFuture<'a, Result<InspectVerdict, ServerError>> {
        Box::pin(self.inspect(op, inspection_id, objects))
    }
}

fn valid_object(object: &pb::InspectObject) -> bool {
    object.id.as_ref().is_some_and(|id| id.len() == 32)
        && object.size.is_some()
        && object.kind.is_some_and(|kind| {
            [
                pb::InspectObjectKind::INSPECT_OBJECT_KIND_BLOB,
                pb::InspectObjectKind::INSPECT_OBJECT_KIND_CHUNKED_FILE,
                pb::InspectObjectKind::INSPECT_OBJECT_KIND_CHUNK,
            ]
            .into_iter()
            .any(|value| kind == value)
        })
}

fn policy_text(text: Option<String>) -> String {
    text.filter(|text| !text.is_empty() && text.len() <= 512 && !text.chars().any(char::is_control))
        .unwrap_or_else(|| "inspection rejected".to_owned())
}

fn validate_answer(
    response: pb::InspectResponse,
    objects: &[pb::InspectObject],
) -> Result<InspectVerdict, ServerError> {
    let bad = |reason| map::unavailable("inspection", reason);
    let ids: BTreeSet<&[u8]> = objects.iter().filter_map(|o| o.id.as_deref()).collect();
    if response
        .flagged_objects
        .iter()
        .any(|id| id.len() != 32 || !ids.contains(id.as_slice()))
    {
        return Err(bad("flagged object outside batch"));
    }
    let verdict = response.verdict.ok_or_else(|| bad("absent verdict"))?;
    if response.takedown_reason.is_some() && !matches!(verdict, Verdict::Reject(_)) {
        return Err(bad("takedown reason on non-reject verdict"));
    }
    match verdict {
        Verdict::Pass(_) if response.flagged_objects.is_empty() => Ok(InspectVerdict::Pass),
        Verdict::Pass(_) => Err(bad("flagged objects on pass")),
        // PRE_RECEIVE rejects ignore takedown_reason, including unregistered
        // tokens: denying this push creates no global takedown (SPEC §6.4).
        Verdict::Reject(reject) => Ok(InspectVerdict::Reject(policy_text(reject.message))),
        Verdict::Quarantine(quarantine) => {
            if quarantine.reason.as_ref().is_some_and(|r| r.len() > 512) {
                return Err(bad("quarantine reason too long"));
            }
            Ok(InspectVerdict::Reject(policy_text(quarantine.reason)))
        }
        Verdict::Defer(_) => Err(bad("defer invalid at pre-receive")),
    }
}

#[cfg(test)]
mod tests {
    use futures_executor::block_on;
    use mkit_core::refs::RefWriteCondition;

    use super::*;
    use crate::error::Code;
    use crate::hooks::tests::{MockChannel, Step, channel_of, client};
    use crate::op::{OpKind, RefUpdate};
    use crate::principal::Principal;
    use crate::repo::{NamespaceKey, RepoId, RepoName};
    use crate::rt::ManualSleep;

    fn objects() -> Vec<pb::InspectObject> {
        vec![pb::InspectObject {
            id: Some(vec![0x22; 32]),
            size: Some(123),
            kind: Some(pb::InspectObjectKind::INSPECT_OBJECT_KIND_BLOB.into()),
            ..Default::default()
        }]
    }

    fn answer(json: &str) -> Result<InspectVerdict, ServerError> {
        validate_answer(serde_json::from_str(json).unwrap(), &objects())
    }

    #[test]
    fn launch_verdicts_validate_and_sanitize_policy_text() {
        assert_eq!(answer(r#"{"pass":{}}"#).unwrap(), InspectVerdict::Pass);
        assert_eq!(
            answer(r#"{"reject":{"code":"unauthenticated","message":"policy"},"takedownReason":"anything"}"#).unwrap(),
            InspectVerdict::Reject("policy".into())
        );
        assert_eq!(
            answer(r#"{"quarantine":{"reason":"hold"}}"#).unwrap(),
            InspectVerdict::Reject("hold".into())
        );
        assert_eq!(
            answer(r#"{"reject":{"message":"secret\ntext"}}"#).unwrap(),
            InspectVerdict::Reject("inspection rejected".into())
        );
        let flagged = "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI=";
        assert!(
            answer(&format!(
                r#"{{"reject":{{}},"flaggedObjects":["{flagged}"]}}"#
            ))
            .is_ok()
        );
        assert!(
            answer(&format!(
                r#"{{"quarantine":{{}},"flaggedObjects":["{flagged}"]}}"#
            ))
            .is_ok()
        );
    }

    #[test]
    fn invalid_verdicts_fail_closed() {
        for json in [
            "{}",
            r#"{"defer":{"retryAfterMs":1}}"#,
            r#"{"pass":{},"flaggedObjects":["IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI="]}"#,
            r#"{"reject":{},"flaggedObjects":["AQ=="]}"#,
            r#"{"reject":{},"flaggedObjects":["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="]}"#,
            r#"{"pass":{},"takedownReason":"policy"}"#,
            r#"{"quarantine":{},"takedownReason":"policy"}"#,
        ] {
            assert_eq!(
                answer(json).unwrap_err().code(),
                Code::Unavailable,
                "{json}"
            );
        }
        let long = serde_json::json!({"quarantine": {"reason": "x".repeat(513)}});
        assert_eq!(
            answer(&long.to_string()).unwrap_err().code(),
            Code::Unavailable
        );
    }

    #[test]
    fn signed_retries_keep_metadata_and_inspection_id_with_fresh_nonce() {
        let client = client(
            MockChannel::new(Step::json(r#"{"pass":{}}"#)),
            ManualSleep::new(),
        );
        let remote = RemoteInspector::new("scanner", client.clone());
        let inspector: &dyn crate::pipeline::inspection::ContentInspector = &remote;
        assert_eq!(inspector.id(), "scanner");
        assert_eq!(
            inspector.phase(),
            crate::pipeline::inspection::InspectorPhase::Sync
        );
        assert_eq!(
            inspector.on_unavailable(),
            crate::pipeline::inspection::OnUnavailable::FailClosed
        );
        let op = Operation::new(
            RepoId {
                namespace: NamespaceKey::deployment_default(),
                name: RepoName::new("test").unwrap(),
            },
            Principal::Anonymous,
            None,
            OpKind::UpdateRef(RefUpdate {
                name: "refs/heads/main".into(),
                condition: RefWriteCondition::Missing,
                new: Some([0x33; 32]),
            }),
        );
        for _ in 0..2 {
            assert_eq!(
                block_on(inspector.inspect(&op, "inspection:stable", &objects())).unwrap(),
                InspectVerdict::Pass
            );
        }
        let seen = channel_of(&client).seen.lock().unwrap();
        assert_eq!(seen[0].body, seen[1].body);
        assert_eq!(seen[0].procedure, Rpc::Inspect.path());
        let request: pb::InspectRequest = serde_json::from_slice(&seen[0].body).unwrap();
        assert_eq!(request.inspection_id.as_deref(), Some("inspection:stable"));
        assert_eq!(
            request.phase,
            Some(pb::InspectPhase::INSPECT_PHASE_PRE_RECEIVE.into())
        );
        assert_eq!(request.objects, objects());
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
    #[test]
    fn retrieval_descriptor_is_metadata_and_covered_by_hook_signature() {
        use crate::pipeline::inspection::ContentInspector as _;
        use crate::scanner_retrieval::{Assignment, PackGrant, RetrievalConfig};
        use mkit_core::hash::to_hex;
        let client = client(
            MockChannel::new(Step::json(r#"{"pass":{}}"#)),
            ManualSleep::new(),
        );
        let remote = RemoteInspector::new("scanner", client.clone());
        let scanner = ed25519_dalek::SigningKey::from_bytes(&[0x65; 32]);
        let config = RetrievalConfig::parse(
            &format!("active current {}", to_hex(&[0x64; 32])),
            &to_hex(&scanner.verifying_key().to_bytes()),
        )
        .unwrap();
        let assignment = Assignment {
            namespace: "default".into(),
            repo_name: "test".into(),
            repository: "test".into(),
            ref_name: "refs/heads/main".into(),
            signer: [0x66; 32],
            packs: vec![PackGrant {
                id: [0x67; 32],
                length: 123,
                tickets: vec![[0x68; 32]],
            }],
        };
        let op = Operation::new(
            RepoId {
                namespace: NamespaceKey::deployment_default(),
                name: RepoName::new("test").unwrap(),
            },
            Principal::Anonymous,
            None,
            OpKind::UpdateRef(RefUpdate {
                name: "refs/heads/main".into(),
                condition: RefWriteCondition::Missing,
                new: Some([0x33; 32]),
            }),
        );
        let descriptors: Vec<_> = (0..2)
            .map(|_| {
                config
                    .mint(
                        "https://vcs.example",
                        "inspection:stable",
                        &assignment,
                        remote.retrieval_timeout(),
                        100,
                    )
                    .unwrap()
            })
            .collect();
        for descriptor in &descriptors {
            assert_eq!(
                block_on(remote.inspect_with_retrieval(
                    &op,
                    "inspection:stable",
                    &objects(),
                    Some(descriptor.clone()),
                ))
                .unwrap(),
                InspectVerdict::Pass
            );
        }
        let seen = channel_of(&client).seen.lock().unwrap();
        for (call, descriptor) in seen.iter().zip(&descriptors) {
            crate::hooks::tests::verify(call);
            let request: pb::InspectRequest = serde_json::from_slice(&call.body).unwrap();
            assert_eq!(request.scanner_retrieval.as_option(), Some(descriptor));
            assert_eq!(request.objects, objects());
            assert_eq!(request.inspection_id.as_deref(), Some("inspection:stable"));
        }
        assert_ne!(descriptors[0].capability, descriptors[1].capability);
        assert_ne!(seen[0].body, seen[1].body);
    }
}
