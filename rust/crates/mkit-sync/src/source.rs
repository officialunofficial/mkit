//! Remote repository reads and optional native push operations.
//!
//! Reads list branches, read refs, and download packmap nodes and packs.
//! Push adds bounded uploads and conditioned head/packmap advances.
//! [`TransportSource`] delegates these operations to mkit-core's synchronous
//! [`Transport`], preserving every existing scheme. Read-only sources retain
//! the default push refusal.

use mkit_core::hash::Hash;
use mkit_core::protocol::{PackKey, Transport};
use mkit_core::refs::Ref;

use crate::SourceError;
use crate::error::SyncError;

/// A remote repository. Read-only backends keep the default push refusal.
pub trait RemoteSource {
    /// Every branch (`refs/heads/*`) with its tip, named without the prefix.
    fn list_branches(&self) -> Result<Vec<Ref>, SourceError>;
    /// A strong read of one ref by its full name (`refs/heads/main`,
    /// `refs/mkit/packmap/main`).
    fn read_ref(&self, name: &str) -> Result<Option<Hash>, SourceError>;
    /// Download a packmap node blob. `ref_name` is the branch hint.
    fn download_blob_via_ref(&self, key: &PackKey, ref_name: &str) -> Result<Vec<u8>, SourceError>;
    /// Download a pack. `ref_name` is the branch hint.
    fn download_pack_via_ref(&self, key: &PackKey, ref_name: &str) -> Result<Vec<u8>, SourceError>;

    /// Whether this source implements the native push operations. Read-only
    /// sources refuse push before any local tracking or remote mutation.
    fn supports_push(&self) -> bool {
        false
    }
    /// Upload a sealed pack using the head ref as its authorization hint.
    fn upload_pack_via_ref(
        &self,
        bytes: &[u8],
        key: &PackKey,
        name: &str,
    ) -> Result<(), SourceError> {
        let _ = (bytes, key, name);
        Err(SourceError::ProtocolError)
    }
    /// Upload a packmap node using the head ref as its authorization hint.
    fn upload_blob_via_ref(
        &self,
        bytes: &[u8],
        key: &PackKey,
        name: &str,
    ) -> Result<(), SourceError> {
        let _ = (bytes, key, name);
        Err(SourceError::ProtocolError)
    }
    /// Advance a head under its lease.
    fn update_ref(
        &self,
        name: &str,
        condition: mkit_core::refs::RefWriteCondition,
        tip: &Hash,
    ) -> Result<(), SourceError> {
        let _ = (name, condition, tip);
        Err(SourceError::ProtocolError)
    }
    /// Advance the packmap and head, consuming their upload commitments.
    #[allow(clippy::too_many_arguments)]
    fn advance_refs_committing(
        &self,
        head: &str,
        head_condition: mkit_core::refs::RefWriteCondition,
        tip: &Hash,
        packmap: &str,
        packmap_condition: mkit_core::refs::RefWriteCondition,
        node: &Hash,
        keys: &[PackKey],
    ) -> Result<mkit_core::protocol::CommitOutcome, SourceError> {
        let _ = (
            head,
            head_condition,
            tip,
            packmap,
            packmap_condition,
            node,
            keys,
        );
        Err(SourceError::ProtocolError)
    }
    /// Remote upload bounds, unchanged from the transport contract.
    fn upload_limits(&self) -> mkit_core::protocol::UploadLimits {
        mkit_core::protocol::UploadLimits::default()
    }
    /// Both conditioned refs can advance atomically.
    fn supports_atomic_advance(&self) -> bool {
        false
    }
    /// Known atomic-advance capability; `None` means discovery was unavailable
    /// or invalid, so a force push must refuse before uploading or publishing.
    fn atomic_advance_status(&self) -> Option<bool> {
        Some(self.supports_atomic_advance())
    }
    /// Select an encodable atomic head condition for a self-contained force
    /// advance. The caller also compares the packmap; dependency plans compare
    /// the observed head as well, even when the endpoint supports `Any`.
    fn atomic_force_head_condition(
        &self,
        _observed_head: Option<Hash>,
    ) -> mkit_core::refs::RefWriteCondition {
        mkit_core::refs::RefWriteCondition::Any
    }
    /// Identity and origin of the repository, for error context and fetch
    /// checkpoints. Both must identify this source's destination: changing
    /// either invalidates checkpoint reuse. `None` disables checkpoints.
    fn repository_address(&self) -> Option<(String, String)> {
        None
    }
    /// Map a failed repository-level call to a [`SyncError`]. The default
    /// recognises a missing repository; backends may add their own cases.
    fn repository_error(&self, error: SourceError) -> SyncError {
        default_repository_error(self.repository_address(), error)
    }
}

/// The default mapping of a failed repository-level call: a missing pack at
/// repository level means the repository does not exist.
fn default_repository_error(address: Option<(String, String)>, error: SourceError) -> SyncError {
    if error.is_not_found()
        && let Some((identity, origin)) = address
    {
        return SyncError::RepositoryNotFound {
            identity,
            origin,
            source: error,
        };
    }
    error.into()
}

/// Classifies a failed repository-level call before the default mapping.
pub type ErrorClassifier<'a> = &'a (dyn Fn(&SourceError) -> Option<SyncError> + Send + Sync);

/// A [`RemoteSource`] over a synchronous mkit-core [`Transport`].
#[derive(Clone, Copy)]
pub struct TransportSource<'a> {
    transport: &'a dyn Transport,
    classifier: Option<ErrorClassifier<'a>>,
}

impl std::fmt::Debug for TransportSource<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransportSource")
            .field("classifier", &self.classifier.is_some())
            .finish_non_exhaustive()
    }
}

impl<'a> TransportSource<'a> {
    #[must_use]
    pub fn new(transport: &'a dyn Transport) -> Self {
        Self {
            transport,
            classifier: None,
        }
    }

    /// Recognise transport-specific failures of repository-level calls (for
    /// example an interrupted upload) and map them to a typed error.
    #[must_use]
    pub fn with_error_classifier(mut self, classifier: ErrorClassifier<'a>) -> Self {
        self.classifier = Some(classifier);
        self
    }
}

impl RemoteSource for TransportSource<'_> {
    fn supports_push(&self) -> bool {
        true
    }
    fn upload_pack_via_ref(
        &self,
        bytes: &[u8],
        key: &PackKey,
        name: &str,
    ) -> Result<(), SourceError> {
        self.transport
            .upload_pack_via_ref(bytes, key, name)
            .map_err(Into::into)
    }
    fn upload_blob_via_ref(
        &self,
        bytes: &[u8],
        key: &PackKey,
        name: &str,
    ) -> Result<(), SourceError> {
        self.transport
            .upload_blob_via_ref(bytes, key, name)
            .map_err(Into::into)
    }
    fn update_ref(
        &self,
        name: &str,
        condition: mkit_core::refs::RefWriteCondition,
        tip: &Hash,
    ) -> Result<(), SourceError> {
        self.transport
            .update_ref(name, condition, tip)
            .map_err(Into::into)
    }
    fn advance_refs_committing(
        &self,
        head: &str,
        head_condition: mkit_core::refs::RefWriteCondition,
        tip: &Hash,
        packmap: &str,
        packmap_condition: mkit_core::refs::RefWriteCondition,
        node: &Hash,
        keys: &[PackKey],
    ) -> Result<mkit_core::protocol::CommitOutcome, SourceError> {
        self.transport
            .advance_refs_committing(
                head,
                head_condition,
                tip,
                packmap,
                packmap_condition,
                node,
                keys,
            )
            .map_err(Into::into)
    }
    fn upload_limits(&self) -> mkit_core::protocol::UploadLimits {
        self.transport.upload_limits()
    }
    fn supports_atomic_advance(&self) -> bool {
        self.transport.supports_atomic_advance()
    }

    fn atomic_advance_status(&self) -> Option<bool> {
        self.transport.atomic_advance_status()
    }

    fn atomic_force_head_condition(
        &self,
        observed_head: Option<Hash>,
    ) -> mkit_core::refs::RefWriteCondition {
        self.transport.atomic_force_head_condition(observed_head)
    }

    fn list_branches(&self) -> Result<Vec<Ref>, SourceError> {
        self.transport
            .list_refs("refs/heads/")
            .map_err(SourceError::from)
    }

    fn read_ref(&self, name: &str) -> Result<Option<Hash>, SourceError> {
        self.transport.read_ref(name).map_err(SourceError::from)
    }

    fn download_blob_via_ref(&self, key: &PackKey, ref_name: &str) -> Result<Vec<u8>, SourceError> {
        self.transport
            .download_blob_via_ref(key, ref_name)
            .map_err(SourceError::from)
    }

    fn download_pack_via_ref(&self, key: &PackKey, ref_name: &str) -> Result<Vec<u8>, SourceError> {
        self.transport
            .download_pack_via_ref(key, ref_name)
            .map_err(SourceError::from)
    }

    fn repository_address(&self) -> Option<(String, String)> {
        self.transport
            .repository_address()
            .map(|a| (a.repository.to_owned(), a.origin.to_owned()))
    }

    fn repository_error(&self, error: SourceError) -> SyncError {
        if let Some(classified) = self.classifier.and_then(|classify| classify(&error)) {
            return classified;
        }
        default_repository_error(self.repository_address(), error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FailureClass;
    use mkit_core::protocol::{
        AdmissionChallengeEntry, AdmissionRequired, RefWriteCondition, TransportError,
        TransportResult,
    };
    use std::sync::Mutex;
    use std::time::Duration;

    struct Failure(Mutex<Option<TransportError>>);
    impl Failure {
        fn take<T>(&self) -> TransportResult<T> {
            Err(self
                .0
                .lock()
                .unwrap()
                .take()
                .expect("source must never retry"))
        }
    }
    impl Transport for Failure {
        fn upload_pack(&self, _: &[u8], _: &PackKey) -> TransportResult<()> {
            self.take()
        }
        fn download_pack(&self, _: &PackKey) -> TransportResult<Vec<u8>> {
            self.take()
        }
        fn pack_exists(&self, _: &PackKey) -> TransportResult<bool> {
            unreachable!()
        }
        fn update_ref(&self, _: &str, _: RefWriteCondition, _: &Hash) -> TransportResult<()> {
            self.take()
        }
        fn read_ref(&self, _: &str) -> TransportResult<Option<Hash>> {
            self.take()
        }
        fn list_refs(&self, _: &str) -> TransportResult<Vec<Ref>> {
            self.take()
        }
    }

    #[test]
    fn every_resumable_outcome_survives_transport_source_and_sync() {
        let required = AdmissionRequired::new(
            vec![AdmissionChallengeEntry {
                scheme: "payment".into(),
                value: "opaque".into(),
            }],
            "pay".into(),
            vec!["challenge".into()],
            vec!["payment".into()],
        );
        for index in 0..4 {
            // Every read verb uses the same explicit adapter, and none retries.
            for verb in 0..4 {
                let error = match index {
                    0 => TransportError::PendingVerification {
                        retry_after: Duration::from_secs(2),
                    },
                    1 => TransportError::MembershipNotVisible,
                    2 => TransportError::RetryAfter { ms: 3000 },
                    _ => TransportError::AdmissionRequired(Box::new(required.clone())),
                };
                // Core backoff must not schedule host-owned outcomes.
                assert!(!mkit_core::protocol::is_retryable(&error));
                let transport = Failure(Mutex::new(Some(error)));
                let source = TransportSource::new(&transport);
                let key = PackKey::new([0; 32]);
                let error = match verb {
                    0 => source.list_branches().unwrap_err(),
                    1 => source.read_ref("refs/heads/main").unwrap_err(),
                    2 => source
                        .download_blob_via_ref(&key, "refs/heads/main")
                        .unwrap_err(),
                    _ => source
                        .download_pack_via_ref(&key, "refs/heads/main")
                        .unwrap_err(),
                };
                assert_eq!(error.class(), FailureClass::Resumable);
                let SyncError::Source(error) = source.repository_error(error) else {
                    panic!("outcome flattened")
                };
                match (index, error) {
                    (0, SourceError::PendingVerification { retry_after }) => {
                        assert_eq!(retry_after, Duration::from_secs(2));
                    }
                    (1, SourceError::MembershipNotVisible) => (),
                    (2, SourceError::RetryAfter { ms }) => assert_eq!(ms, 3000),
                    (3, SourceError::PaymentRequired { challenges }) => {
                        assert_eq!(*challenges, required);
                    }
                    other => panic!("unexpected {other:?}"),
                }
            }
        }
    }

    fn write_error(source: &TransportSource<'_>, verb: usize) -> SourceError {
        let key = PackKey::new([0; 32]);
        match verb {
            0 => source
                .upload_pack_via_ref(b"pack", &key, "refs/heads/main")
                .unwrap_err(),
            1 => source
                .upload_blob_via_ref(b"node", &key, "refs/heads/main")
                .unwrap_err(),
            2 => source
                .update_ref("refs/heads/main", RefWriteCondition::Missing, &[1; 32])
                .unwrap_err(),
            _ => source
                .advance_refs_committing(
                    "refs/heads/main",
                    RefWriteCondition::Missing,
                    &[1; 32],
                    "refs/mkit/packmap/main",
                    RefWriteCondition::Missing,
                    &[2; 32],
                    &[key],
                )
                .unwrap_err(),
        }
    }

    #[test]
    fn every_resumable_write_outcome_survives_transport_source_and_sync() {
        let required = AdmissionRequired::new(
            vec![AdmissionChallengeEntry {
                scheme: "payment".into(),
                value: "opaque".into(),
            }],
            "pay".into(),
            vec!["challenge".into()],
            vec!["payment".into()],
        );
        for index in 0..4 {
            for verb in 0..4 {
                let error = match index {
                    0 => TransportError::PendingVerification {
                        retry_after: Duration::from_secs(2),
                    },
                    1 => TransportError::MembershipNotVisible,
                    2 => TransportError::RetryAfter { ms: 3000 },
                    _ => TransportError::AdmissionRequired(Box::new(required.clone())),
                };
                assert!(!mkit_core::protocol::is_retryable(&error));
                let transport = Failure(Mutex::new(Some(error)));
                let source = TransportSource::new(&transport);
                let error = write_error(&source, verb);
                // The default advance stops at the failed packmap write;
                // a retry or head write would exhaust Failure and panic.
                assert!(transport.0.lock().unwrap().is_none());
                assert_eq!(error.class(), FailureClass::Resumable);
                let SyncError::Source(error) = source.repository_error(error) else {
                    panic!("write outcome flattened")
                };
                match (index, error) {
                    (0, SourceError::PendingVerification { retry_after }) => {
                        assert_eq!(retry_after, Duration::from_secs(2));
                    }
                    (1, SourceError::MembershipNotVisible) => (),
                    (2, SourceError::RetryAfter { ms }) => assert_eq!(ms, 3000),
                    (3, SourceError::PaymentRequired { challenges }) => {
                        assert_eq!(*challenges, required);
                    }
                    other => panic!("unexpected {other:?}"),
                }
            }
        }
    }

    #[test]
    fn write_refusals_and_transient_failures_keep_display_and_class() {
        for verb in 0..4 {
            for error in [
                TransportError::AccessDenied,
                TransportError::RemoteError("deterministic refusal".into()),
                TransportError::ConnectionFailed,
                TransportError::ServerError { status: 429 },
                TransportError::ServerError { status: 503 },
                TransportError::ServerError { status: 400 },
                TransportError::AdmissionRequired(Box::new(
                    AdmissionRequired::new(Vec::new(), "pay".into(), Vec::new(), Vec::new())
                        .with_reason("helper failed"),
                )),
            ] {
                let expected = error.to_string();
                let class = if mkit_core::protocol::is_retryable(&error) {
                    FailureClass::Transient
                } else {
                    FailureClass::Refusal
                };
                let transport = Failure(Mutex::new(Some(error)));
                let source = TransportSource::new(&transport);
                let error = write_error(&source, verb);
                assert_eq!(error.to_string(), expected);
                assert_eq!(error.class(), class);
                let SyncError::Source(error) = source.repository_error(error) else {
                    panic!("write failure flattened")
                };
                assert_eq!(error.to_string(), expected);
                assert_eq!(error.class(), class);
            }
        }
    }

    #[test]
    fn repository_classifier_can_recognize_typed_write_errors() {
        let classify = |error: &SourceError| {
            matches!(error, SourceError::ConnectionFailed).then_some(SyncError::Interrupted)
        };
        for verb in 0..4 {
            let transport = Failure(Mutex::new(Some(TransportError::ConnectionFailed)));
            let source = TransportSource::new(&transport).with_error_classifier(&classify);
            assert!(matches!(
                source.repository_error(write_error(&source, verb)),
                SyncError::Interrupted
            ));
        }
    }

    struct Absent(crate::RemoteFailure);
    impl RemoteSource for Absent {
        fn list_branches(&self) -> Result<Vec<Ref>, SourceError> {
            Err(SourceError::Remote(Box::new(self.0.clone())))
        }
        fn read_ref(&self, _: &str) -> Result<Option<Hash>, SourceError> {
            Err(SourceError::Remote(Box::new(self.0.clone())))
        }
        fn download_blob_via_ref(&self, _: &PackKey, _: &str) -> Result<Vec<u8>, SourceError> {
            Err(SourceError::Remote(Box::new(self.0.clone())))
        }
        fn download_pack_via_ref(&self, _: &PackKey, _: &str) -> Result<Vec<u8>, SourceError> {
            Err(SourceError::Remote(Box::new(self.0.clone())))
        }
        fn repository_address(&self) -> Option<(String, String)> {
            Some(("default".into(), "https://vcs.example.org".into()))
        }
    }

    #[test]
    fn contextual_sync_errors_keep_remote_evidence() {
        let source = Absent(crate::RemoteFailure {
            code: "not_found".into(),
            message: "absent".into(),
            status: 404,
            details: vec![crate::RemoteDetail {
                type_url: "example.Detail".into(),
                value: Some("opaque".into()),
            }],
            headers: vec![("x-evidence".into(), b"value".to_vec())],
        });
        let SyncError::RepositoryNotFound { source: cause, .. } =
            source.repository_error(source.list_branches().unwrap_err())
        else {
            panic!("wrong repository error")
        };
        let chain_error =
            crate::packmap::walk_pack_chain(&source, &crate::NoopObserver, "main", [0; 32])
                .unwrap_err();
        let SyncError::PackChainInvalid {
            source: Some(chain_cause),
            ..
        } = chain_error
        else {
            panic!("wrong chain error")
        };
        let td = tempfile::tempdir().unwrap();
        let applied =
            crate::AppliedPacks::load(&mkit_core::layout::RepoLayout::single(td.path()), "origin")
                .unwrap();
        let Err(SyncError::AdvertisedPackMissing {
            source: pack_cause, ..
        }) = crate::stage::download_pack_chain(
            &source,
            &crate::NoopObserver,
            "main",
            &[[0; 32]],
            &applied,
            Some(td.path()),
        )
        else {
            panic!("wrong pack error")
        };
        for cause in [cause, chain_cause, pack_cause] {
            let SourceError::Remote(remote) = cause else {
                panic!("remote evidence flattened")
            };
            assert_eq!(remote.code, "not_found");
            assert_eq!(remote.status, 404);
            assert_eq!(remote.details, source.0.details);
            assert_eq!(remote.headers, source.0.headers);
        }
    }

    #[test]
    fn classified_transport_errors_retain_display_and_class() {
        for error in [
            TransportError::PackNotFound,
            TransportError::AccessDenied,
            TransportError::AdmissionConfiguration("bad".into()),
            TransportError::TlsConfiguration("bad".into()),
            TransportError::AdmissionHelperFailed("bad".into()),
            TransportError::RemoteError("bad".into()),
            TransportError::RefConflict,
            TransportError::InvalidRef("bad".into()),
            TransportError::ConnectionFailed,
            TransportError::ServerError { status: 429 },
            TransportError::ServerError { status: 503 },
            TransportError::ServerError { status: 400 },
            TransportError::InvalidResponse,
            TransportError::ProtocolError,
            TransportError::PayloadTooLarge(42),
            TransportError::InsecureScheme,
        ] {
            let expected = error.to_string();
            let class = if mkit_core::protocol::is_retryable(&error) {
                FailureClass::Transient
            } else {
                FailureClass::Refusal
            };
            let source = Failure(Mutex::new(Some(error)));
            let error = TransportSource::new(&source).list_branches().unwrap_err();
            assert_eq!(error.to_string(), expected);
            assert_eq!(error.class(), class);
        }
    }
}
