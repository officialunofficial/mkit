//! Resource limits for portable partial snapshot bundles.

/// Explicit limits for producing and verifying a partial snapshot.
///
/// Values may be lowered by callers. Values above the v1 profile are rejected:
/// widening the portable profile requires a new format/version decision rather
/// than an accidental caller-side override.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PartialLimits {
    pub max_selected_paths: usize,
    pub max_path_depth: usize,
    pub max_component_bytes: usize,
    pub max_path_bytes: usize,
    pub max_total_path_bytes: usize,
    pub max_selected_file_bytes: usize,
    pub max_total_selected_bytes: usize,
    pub max_base_object_bytes: usize,
    pub max_tree_object_bytes: usize,
    pub max_tree_entries: usize,
    pub max_witness_bytes: usize,
    pub max_tree_visits: usize,
    pub max_bundle_bytes: usize,
    pub max_objects: usize,
    pub max_object_bytes: usize,
    pub max_update_bytes: usize,
    pub max_raw_pack_bytes: usize,
    pub max_update_objects: usize,
    pub max_commit_message_bytes: usize,
    pub max_changed_paths: usize,
}

impl PartialLimits {
    pub const V1: Self = Self {
        max_selected_paths: 256,
        max_path_depth: 32,
        max_component_bytes: 255,
        max_path_bytes: 1024,
        max_total_path_bytes: 64 * 1024,
        max_selected_file_bytes: 4 * 1024 * 1024,
        max_total_selected_bytes: 16 * 1024 * 1024,
        max_base_object_bytes: 4 * 1024 * 1024,
        max_tree_object_bytes: 16 * 1024 * 1024,
        max_tree_entries: 100_000,
        max_witness_bytes: 32 * 1024 * 1024,
        max_tree_visits: 8_193,
        max_bundle_bytes: 56 * 1024 * 1024,
        max_objects: 65_536,
        max_object_bytes: 16 * 1024 * 1024,
        max_update_bytes: 56 * 1024 * 1024,
        max_raw_pack_bytes: 48 * 1024 * 1024,
        max_update_objects: 65_536,
        max_commit_message_bytes: 4 * 1024,
        max_changed_paths: 256,
    };

    /// True when every field is at most the v1 interoperability profile.
    #[must_use]
    pub fn is_v1_subset(&self) -> bool {
        self.max_selected_paths <= Self::V1.max_selected_paths
            && self.max_path_depth <= Self::V1.max_path_depth
            && self.max_component_bytes <= Self::V1.max_component_bytes
            && self.max_path_bytes <= Self::V1.max_path_bytes
            && self.max_total_path_bytes <= Self::V1.max_total_path_bytes
            && self.max_selected_file_bytes <= Self::V1.max_selected_file_bytes
            && self.max_total_selected_bytes <= Self::V1.max_total_selected_bytes
            && self.max_base_object_bytes <= Self::V1.max_base_object_bytes
            && self.max_tree_object_bytes <= Self::V1.max_tree_object_bytes
            && self.max_tree_entries <= Self::V1.max_tree_entries
            && self.max_witness_bytes <= Self::V1.max_witness_bytes
            && self.max_tree_visits <= Self::V1.max_tree_visits
            && self.max_bundle_bytes <= Self::V1.max_bundle_bytes
            && self.max_objects <= Self::V1.max_objects
            && self.max_object_bytes <= Self::V1.max_object_bytes
            && self.max_update_bytes <= Self::V1.max_update_bytes
            && self.max_raw_pack_bytes <= Self::V1.max_raw_pack_bytes
            && self.max_update_objects <= Self::V1.max_update_objects
            && self.max_commit_message_bytes <= Self::V1.max_commit_message_bytes
            && self.max_changed_paths <= Self::V1.max_changed_paths
    }
}

impl Default for PartialLimits {
    fn default() -> Self {
        Self::V1
    }
}
