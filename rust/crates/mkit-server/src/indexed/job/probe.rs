//! Test-only nested attribution for verification probe storage calls.

pub(super) struct DecodeScope {
    category: &'static str,
}

impl DecodeScope {
    pub(super) fn new(category: &'static str) -> Self {
        tracing::trace!(
            event = "verification_probe_decode_scope",
            category,
            begin = true
        );
        Self { category }
    }
}

impl Drop for DecodeScope {
    fn drop(&mut self) {
        tracing::trace!(
            event = "verification_probe_decode_scope",
            category = self.category,
            begin = false
        );
    }
}
