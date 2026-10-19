//! Caller-owned execution of immutable, bounded entry verification jobs.
//!
//! Jobs come only from the verification driver. Running one performs no I/O
//! and starts no threads. Its opaque output must return to the issuing driver;
//! only that driver merges results in entry order and commits evidence.

use super::{
    OneBase, VerifyDriver, invalid,
    records::{Domain, Signature},
};
use crate::{
    codec::failure,
    error::{Failure, FailureCode},
    evidence::{PackSource, RepositoryId},
    pack_verify::{RequestId, framing::map_core},
};
use mkit_core::{
    hash::Hash,
    object::Object,
    pack::{PackEntry, decode_entry_with, window::FrameInfo},
    serialize::deserialize,
    sign::{commit_signing_hash, remix_signing_hash, tag_signing_hash, verify_object_signature},
};

/// Finite caller execution configuration; serial execution remains the default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ComputeConfig {
    /// Maximum outstanding jobs, including completed jobs awaiting ordinal merge.
    /// The driver accepts values from one through sixteen.
    pub max_jobs: u8,
    /// Minimum canonical byte length of a raw entry dispatched to a worker.
    /// Smaller raw entries decode inline. Delta entries still use jobs.
    /// Defaults to 64 KiB; zero dispatches every entry.
    pub min_job_bytes: u64,
}

impl ComputeConfig {
    /// Configures one through sixteen outstanding jobs with a 64 KiB threshold.
    /// [`VerifyDriver::with_compute`] validates the capacity.
    #[must_use]
    pub const fn new(max_jobs: u8) -> Self {
        Self {
            max_jobs,
            min_job_bytes: 64 << 10,
        }
    }

    /// Sets the minimum raw canonical entry size dispatched to a worker.
    #[must_use]
    pub const fn with_min_job_bytes(mut self, bytes: u64) -> Self {
        self.min_job_bytes = bytes;
        self
    }
}

impl Default for ComputeConfig {
    fn default() -> Self {
        Self::new(1)
    }
}

/// Pure operation authorized by a verification job.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ComputeOperation {
    /// Canonical admission, object identity, and individual signature checking.
    VerifyEntry,
}

/// Conservative permits held against the issuing driver's shared ceilings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ComputePermits {
    /// Maximum simultaneous job-owned input, scratch, and output bytes.
    pub resident_bytes: u64,
    /// Maximum abstract work authorized for this operation.
    pub work: u64,
}

/// Immutable identity of a library-created compute job.
///
/// The requested whole-pack identity and provisional frame placement bind the
/// entry input. Only terminal verification authenticates the pack. A delta additionally binds its validated canonical base identity.
/// This descriptor is local execution state, not an encoded proof or wire format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub struct ComputeRequest {
    pub(super) request: RequestId,
    pub(super) source: PackSource,
    pub(super) repository: RepositoryId,
    pub(super) ordinal: u64,
    pub(super) info: FrameInfo,
    pub(super) base: Option<Hash>,
    pub(super) operation: ComputeOperation,
    pub(super) permits: ComputePermits,
}

impl ComputeRequest {
    /// Run generation and unique request sequence.
    #[must_use]
    pub const fn request(&self) -> RequestId {
        self.request
    }

    /// Requested immutable pack source; authentication awaits terminal verification.
    #[must_use]
    pub const fn source(&self) -> PackSource {
        self.source
    }

    /// Repository in which external base facts were validated.
    #[must_use]
    pub const fn repository(&self) -> RepositoryId {
        self.repository
    }

    /// Entry position in wire order.
    #[must_use]
    pub const fn ordinal(&self) -> u64 {
        self.ordinal
    }

    /// Provisional complete frame placement in the requested pack.
    #[must_use]
    pub const fn frame(&self) -> FrameInfo {
        self.info
    }

    /// Input commitment: whole-pack identity together with exact frame placement.
    #[must_use]
    pub const fn input_commitment(&self) -> (Hash, FrameInfo) {
        (self.source.id, self.info)
    }

    /// Validated base identity for a delta, or no base for a raw entry.
    #[must_use]
    pub const fn base(&self) -> Option<Hash> {
        self.base
    }

    /// Authorized pure operation.
    #[must_use]
    pub const fn operation(&self) -> ComputeOperation {
        self.operation
    }

    /// Memory and work held until the driver retires this job.
    #[must_use]
    pub const fn permits(&self) -> ComputePermits {
        self.permits
    }
}

/// Owned, immutable verification work supplied only by the driver.
///
/// After taking a job from the driver, the caller may move it to its own worker,
/// call [`Self::run`], and return the output. Dropping a job does not report a
/// successful result or release the driver's outstanding reservation.
#[must_use]
pub struct ComputeJob {
    descriptor: ComputeRequest,
    entry: PackEntry<'static>,
    base: Option<Hash>,
    base_bytes: Option<Vec<u8>>,
}

impl std::fmt::Debug for ComputeJob {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ComputeJob")
            .field("descriptor", &self.descriptor)
            .finish_non_exhaustive()
    }
}

impl ComputeJob {
    pub(super) fn new(
        descriptor: ComputeRequest,
        entry: PackEntry<'static>,
        base: Option<Hash>,
        base_bytes: Option<Vec<u8>>,
    ) -> Self {
        Self {
            descriptor,
            entry,
            base,
            base_bytes,
        }
    }

    /// Immutable identity and permits of this job.
    pub const fn request(&self) -> ComputeRequest {
        self.descriptor
    }

    /// Executes the bounded pure operation without I/O or thread creation.
    ///
    /// Content failures remain opaque until the issuing driver merges this
    /// output in ordinal order. Signature failures are deferred separately so
    /// they cannot outrank structural, profile, or cumulative budget checks.
    pub fn run(self) -> ComputeOutput {
        let descriptor = self.descriptor;
        let outcome = self.decode();
        ComputeOutput {
            descriptor,
            outcome,
        }
    }

    fn decode(self) -> Result<Decoded, Failure> {
        let mut bases = OneBase {
            id: self.base.unwrap_or([0; 32]),
            bytes: self.base_bytes,
        };
        let (id, bytes) = decode_entry_with(self.entry, &mut bases, VerifyDriver::decode_limits())
            .map_err(|error| map_core(&error))?;
        let object = deserialize(&bytes).map_err(|_| failure(FailureCode::NonCanonicalObject))?;
        let signature = signature_facts(&object);
        Ok(Decoded {
            id,
            bytes,
            object,
            signature,
        })
    }
}

/// Library-created output whose result can be consumed only by a driver.
#[must_use]
pub struct ComputeOutput {
    pub(super) descriptor: ComputeRequest,
    pub(super) outcome: Result<Decoded, Failure>,
}

impl std::fmt::Debug for ComputeOutput {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ComputeOutput")
            .field("descriptor", &self.descriptor)
            .finish_non_exhaustive()
    }
}

impl ComputeOutput {
    /// Immutable identity of the job that produced this output.
    pub const fn request(&self) -> ComputeRequest {
        self.descriptor
    }
}

/// Whether an output still belongs to outstanding work in the receiving run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
#[non_exhaustive]
pub enum ComputeDisposition {
    /// The output was recorded; ordinal merge may still await earlier jobs.
    Accepted,
    /// The output is stale or already retired and changed no verification state.
    Stale,
}

#[derive(Debug)]
pub(super) struct Decoded {
    pub(super) id: Hash,
    pub(super) bytes: Vec<u8>,
    pub(super) object: Object,
    pub(super) signature: Result<SignatureFacts, Failure>,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct SignatureFacts {
    pub(super) signature: Signature,
    pub(super) signer: Hash,
    pub(super) digest: Hash,
}

pub(super) fn signature_facts(object: &Object) -> Result<SignatureFacts, Failure> {
    let domain = Domain::for_kind(object.object_type());
    let (valid, signer, digest) = match object {
        Object::Commit(commit) => (
            verify_object_signature(object).is_ok(),
            commit.signer,
            commit_signing_hash(commit).map_err(|_| invalid())?,
        ),
        Object::Remix(remix) => (
            verify_object_signature(object).is_ok(),
            remix.signer,
            remix_signing_hash(remix).map_err(|_| invalid())?,
        ),
        Object::Tag(tag) => (
            verify_object_signature(object).is_ok(),
            tag.signer,
            tag_signing_hash(tag).map_err(|_| invalid())?,
        ),
        _ => (true, [0; 32], [0; 32]),
    };
    let signature = if domain == Domain::None {
        Signature::None
    } else if valid {
        Signature::Valid
    } else {
        Signature::Invalid
    };
    Ok(SignatureFacts {
        signature,
        signer,
        digest,
    })
}
