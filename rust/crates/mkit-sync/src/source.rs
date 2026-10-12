//! The remote-source abstraction the fetch engine reads through.
//!
//! The engine needs five read operations from a remote: list the branches,
//! read one ref, and download a packmap node or a pack by digest. A
//! [`RemoteSource`] provides them. The first backend is
//! [`TransportSource`], over mkit-core's synchronous [`Transport`], so every
//! existing scheme (file, ssh, s3, http, connect) keeps working unchanged.

use mkit_core::hash::Hash;
use mkit_core::protocol::{PackKey, Transport, TransportError};
use mkit_core::refs::Ref;

use crate::error::SyncError;

/// The read side of a remote repository.
pub trait RemoteSource {
    /// Every branch (`refs/heads/*`) with its tip, named without the prefix.
    fn list_branches(&self) -> Result<Vec<Ref>, TransportError>;
    /// A strong read of one ref by its full name (`refs/heads/main`,
    /// `refs/mkit/packmap/main`).
    fn read_ref(&self, name: &str) -> Result<Option<Hash>, TransportError>;
    /// Download a packmap node blob. `ref_name` is the branch hint.
    fn download_blob_via_ref(
        &self,
        key: &PackKey,
        ref_name: &str,
    ) -> Result<Vec<u8>, TransportError>;
    /// Download a pack. `ref_name` is the branch hint.
    fn download_pack_via_ref(
        &self,
        key: &PackKey,
        ref_name: &str,
    ) -> Result<Vec<u8>, TransportError>;
    /// Identity and origin of the repository, for error context.
    fn repository_address(&self) -> Option<(String, String)> {
        None
    }
    /// Map a failed repository-level call to a [`SyncError`]. The default
    /// recognises a missing repository; backends may add their own cases.
    fn repository_error(&self, error: TransportError) -> SyncError {
        default_repository_error(self.repository_address(), error)
    }
}

/// The default mapping of a failed repository-level call: a missing pack at
/// repository level means the repository does not exist.
fn default_repository_error(address: Option<(String, String)>, error: TransportError) -> SyncError {
    if matches!(error, TransportError::PackNotFound)
        && let Some((identity, origin)) = address
    {
        return SyncError::RepositoryNotFound { identity, origin };
    }
    error.into()
}

/// Classifies a failed repository-level call before the default mapping.
pub type ErrorClassifier<'a> = &'a (dyn Fn(&TransportError) -> Option<SyncError> + Send + Sync);

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
    fn list_branches(&self) -> Result<Vec<Ref>, TransportError> {
        self.transport.list_refs("refs/heads/")
    }

    fn read_ref(&self, name: &str) -> Result<Option<Hash>, TransportError> {
        self.transport.read_ref(name)
    }

    fn download_blob_via_ref(
        &self,
        key: &PackKey,
        ref_name: &str,
    ) -> Result<Vec<u8>, TransportError> {
        self.transport.download_blob_via_ref(key, ref_name)
    }

    fn download_pack_via_ref(
        &self,
        key: &PackKey,
        ref_name: &str,
    ) -> Result<Vec<u8>, TransportError> {
        self.transport.download_pack_via_ref(key, ref_name)
    }

    fn repository_address(&self) -> Option<(String, String)> {
        self.transport
            .repository_address()
            .map(|a| (a.repository.to_owned(), a.origin.to_owned()))
    }

    fn repository_error(&self, error: TransportError) -> SyncError {
        if let Some(classified) = self.classifier.and_then(|classify| classify(&error)) {
            return classified;
        }
        default_repository_error(self.repository_address(), error)
    }
}
