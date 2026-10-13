//! The remote-source abstraction the fetch engine reads through.
//!
//! The engine needs five read operations from a remote: list the branches,
//! read one ref, and download a packmap node or a pack by digest. A
//! [`RemoteSource`] provides them. The first backend is
//! [`TransportSource`], over mkit-core's synchronous [`Transport`], so every
//! existing scheme (file, ssh, s3, http, connect) keeps working unchanged.

use mkit_core::hash::Hash;
use mkit_core::protocol::{PackKey, Transport};
use mkit_core::refs::Ref;

use crate::SourceError;
use crate::error::SyncError;

/// The read side of a remote repository.
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
    /// Identity and origin of the repository, for error context.
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
            unreachable!()
        }
        fn download_pack(&self, _: &PackKey) -> TransportResult<Vec<u8>> {
            self.take()
        }
        fn pack_exists(&self, _: &PackKey) -> TransportResult<bool> {
            unreachable!()
        }
        fn update_ref(&self, _: &str, _: RefWriteCondition, _: &Hash) -> TransportResult<()> {
            unreachable!()
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
