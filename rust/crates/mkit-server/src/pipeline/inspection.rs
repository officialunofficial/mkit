//! Launch-only synchronous checks. No hold, timer, or durable continuation.

use crate::ServerError;
use crate::hooks::InspectVerdict;
use crate::op::Operation;
use crate::rt::{BoxFuture, MaybeSend, MaybeSync};
use mkit_rpc::hooks::InspectObject;

/// The launch ceiling and default inspected-set bound.
pub const MAX_OBJECTS: usize = 10_000;
/// The launch inspector bound.
pub const MAX_INSPECTORS: usize = 4;
/// Verification and enumeration share this request allocation.
pub const VERIFY_CALLS: u32 = 300;
/// Existing ancestry, resulting-pair walk, hooks, and other-stage allocations.
pub const ADVANCE_CALLS: u32 = VERIFY_CALLS + 256 + 256 + MAX_INSPECTORS as u32 + 144;
const _: () = assert!(ADVANCE_CALLS <= 1_000);

/// Configured inspection phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InspectorPhase {
    /// Before apply.
    Sync,
    /// Full-profile follow-up, refused at launch.
    Async,
}
/// Inspector availability policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnUnavailable {
    /// Fail without committing or recording replay.
    FailClosed,
    /// Full-profile follow-up, refused at launch.
    Publish,
}
/// Metadata-only inspection. Enumeration belongs to the server.
pub trait ContentInspector: MaybeSend + MaybeSync {
    /// Stable, unique deployment identity.
    fn id(&self) -> &str;
    /// Launch supports synchronous checks only.
    fn phase(&self) -> InspectorPhase {
        InspectorPhase::Sync
    }
    /// Launch supports fail-closed availability only.
    fn on_unavailable(&self) -> OnUnavailable {
        OnUnavailable::FailClosed
    }
    /// Inspect exactly this assigned batch; the logical id survives retries.
    fn inspect<'a>(
        &'a self,
        op: &'a Operation,
        id: &'a str,
        objects: &'a [InspectObject],
    ) -> BoxFuture<'a, Result<InspectVerdict, ServerError>>;
}

pub(super) struct Immediate;
impl super::clearance::PublicationPolicy for Immediate {
    fn prepare<'a>(
        &'a self,
        _: &'a Operation,
        pair: &'a crate::store::publication::Pair,
    ) -> BoxFuture<'a, Result<crate::store::publication::Advance, ServerError>> {
        Box::pin(async move {
            Ok(super::clearance::immediate(
                pair.clone(),
                [0; 32],
                Vec::new(),
            ))
        })
    }
    fn pack_available(&self, _: &crate::repo::RepoId, _: &mkit_core::hash::Hash) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn launch_advance_allocations_fit_the_repository_contract() {
        // The 300 verification calls include preflight and all frame scans.
        // Even seven independently rounded packs require <=16 pages for
        // <=10,000 total entries at the Worker's 1,000-row page ceiling.
        let frame_pages = super::MAX_OBJECTS.div_ceil(1_000) + 6;
        assert_eq!(frame_pages, 16);
        assert!(frame_pages < super::VERIFY_CALLS as usize);
        assert_eq!(super::ADVANCE_CALLS, 960);
        assert!(super::ADVANCE_CALLS <= 1_000);
    }
}

impl<B: crate::store::MultipartBlobStore, N: crate::NamespaceStore, H: super::HookSet>
    super::Pipeline<B, N, H>
{
    pub(super) async fn inspect_advance(
        &self,
        op: &Operation,
        pair: &crate::store::publication::Pair,
        objects: Vec<crate::indexed::inspection::InspectObject>,
    ) -> Result<(), ServerError> {
        use mkit_rpc::hooks::InspectObjectKind as K;
        let objects: Vec<_> = objects
            .into_iter()
            .map(|object| InspectObject {
                id: Some(object.id.to_vec()),
                size: Some(object.size),
                kind: Some(
                    match object.kind {
                        crate::indexed::inspection::Kind::Blob => K::INSPECT_OBJECT_KIND_BLOB,
                        crate::indexed::inspection::Kind::ChunkedFile => {
                            K::INSPECT_OBJECT_KIND_CHUNKED_FILE
                        }
                        crate::indexed::inspection::Kind::Chunk => K::INSPECT_OBJECT_KIND_CHUNK,
                    }
                    .into(),
                ),
                ..Default::default()
            })
            .collect();
        let mut rejection = None;
        let mut unavailable = None;
        for inspector in &self.inspectors {
            // The id binds the inspector, signed logical advance, phase and
            // immutable batch. It is independent of hook authentication nonces.
            let bytes = serde_json::to_vec(&(
                inspector.id(),
                op.repo.namespace.as_str(),
                op.repo.name.as_str(),
                op.auth.as_ref().map(|a| a.fingerprint),
                pair,
                "PRE_RECEIVE",
                &objects,
            ))
            .map_err(|_| ServerError::unavailable("inspection metadata unavailable"))?;
            let id = mkit_core::hash::to_hex(&mkit_core::hash::hash(&bytes));
            let verdict = inspector.inspect(op, &id, &objects).await;
            let result = match &verdict {
                Ok(InspectVerdict::Pass) => "pass",
                Ok(InspectVerdict::Reject(_)) => "reject",
                Err(_) => "unavailable",
            };
            self.metrics.incr(
                crate::telemetry::METRIC_INSPECTION_CALLS,
                &[("result", result)],
                1,
            );
            match verdict {
                Ok(InspectVerdict::Pass) => {}
                Ok(InspectVerdict::Reject(message)) => rejection = Some(message),
                Err(_) => {
                    unavailable = Some(ServerError::unavailable("inspection unavailable; retry"))
                }
            }
        }
        if let Some(message) = rejection {
            return Err(ServerError::permission_denied(message));
        }
        if let Some(error) = unavailable {
            return Err(error);
        }
        Ok(())
    }
}
