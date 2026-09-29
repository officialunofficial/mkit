//! Deployment discovery without repository resolution or store reads (STC §2.1).

use mkit_core::upload_parts::MIN_PART_SIZE;

use super::{Admission, HookSet, Pipeline, PipelineConfig};
use crate::ServerError;
use crate::repo::Addressing;
use crate::store::{BlobStore, INDEX_FANOUT, MultipartBlobStore, NamespaceStore};

/// Deployment capabilities and limits, independent of any repository.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ServerInfo {
    /// Wire package.
    pub protocol: &'static str,
    /// Transport specification version.
    pub spec_version: u32,
    /// Largest accepted pack length.
    pub max_pack_bytes: u64,
    /// Resumable upload part size.
    pub part_size: u64,
    /// Largest number of parts per upload.
    pub max_parts: u32,
    /// Largest requested ref count per page.
    pub max_list_refs_page_size: u32,
    /// Smaller packs may skip `BeginUpload`; zero with admission or Multi.
    pub begin_upload_threshold_bytes: u64,
    /// Whether `AdvanceRefs` commits both refs atomically.
    pub atomic_advance: bool,
    /// Whether pushed packs are decoded and verified.
    pub indexed_mode: bool,
    /// Whether a non-default admission hook is installed.
    pub admission: bool,
    /// Storage receipt signing key, empty until receipts are supported.
    pub receipt_public_key: Vec<u8>,
    /// Storage receipt key identifier, empty until receipts are supported.
    pub receipt_key_id: String,
    /// Accepted grant signature schemes.
    pub grant_schemes: Vec<String>,
    /// Configured namespace policy, or single-repository.
    pub namespace_policy: &'static str,
    /// Fixed repository index fan-out.
    pub index_fanout: u32,
    /// Delta-chain depth cap; 0 while indexed mode is off (SPEC-SERVER §9.8).
    pub max_delta_chain_depth: u32,
}

impl PipelineConfig {
    pub(super) fn validate_server_info_limits(&self) -> Result<(), ServerError> {
        let refusal = if !self.part_size.is_power_of_two()
            || !(MIN_PART_SIZE..=32 * 1024 * 1024).contains(&self.part_size)
        {
            "part_size must be a power of two in 8..=32 MiB"
        } else if self.max_parts == 0 {
            "max_parts must be at least 1"
        } else if self.part_size * u64::from(self.max_parts) < self.upload_limits.max_total_bytes {
            // The validated 32 MiB part bound makes this product fit u64.
            "max_pack_bytes is unreachable with part_size × max_parts"
        } else if !(1..=10_000).contains(&self.max_list_refs_page_size) {
            "max_list_refs_page_size must be in 1..=10_000"
        } else {
            return Ok(());
        };
        Err(ServerError::invalid_argument(refusal))
    }
}

impl<B: BlobStore, N: NamespaceStore, H: HookSet> Pipeline<B, N, H> {
    /// Threshold used by discovery and un-ticketed `UploadPack` enforcement.
    pub(super) fn effective_threshold(&self) -> u64 {
        if !self.hooks.admission().is_default()
            || matches!(self.cfg.addressing, Addressing::Multi(_))
        {
            0
        } else {
            self.cfg.begin_upload_threshold_bytes
        }
    }
}

impl<B: MultipartBlobStore, N: NamespaceStore, H: HookSet> Pipeline<B, N, H> {
    /// Configured deployment information. Never resolves a repository or
    /// reads a store; the atomic flag comes from store capabilities only.
    #[must_use]
    pub fn server_info(&self) -> ServerInfo {
        let admission = !self.hooks.admission().is_default();
        ServerInfo {
            protocol: "mkit.transport.v1",
            spec_version: 2,
            max_pack_bytes: if self.blobs.supports_multipart() {
                self.cfg.upload_limits.max_total_bytes
            } else {
                self.cfg
                    .upload_limits
                    .max_total_bytes
                    .min(self.cfg.part_size)
            },
            part_size: self.cfg.part_size,
            max_parts: self.cfg.max_parts,
            max_list_refs_page_size: self.cfg.max_list_refs_page_size,
            begin_upload_threshold_bytes: self.effective_threshold(),
            atomic_advance: self.capabilities().atomic_advance,
            indexed_mode: self.cfg.indexed_mode(),
            admission,
            receipt_public_key: Vec::new(),
            receipt_key_id: String::new(),
            grant_schemes: self.cfg.grants.as_ref().map_or_else(Vec::new, |grants| {
                grants.schemes().tokens().map(str::to_owned).collect()
            }),
            namespace_policy: self.cfg.advertised_namespace_policy(),
            index_fanout: u32::from(INDEX_FANOUT),
            max_delta_chain_depth: self
                .cfg
                .indexed
                .as_ref()
                .map_or(0, |cfg| cfg.max_delta_chain_depth),
        }
    }
}
