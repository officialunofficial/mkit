//! Coalesce client framing into bounded, authority-checked storage writes.
use bytes::{Bytes, BytesMut};

pub(super) const STAGING_BYTES: usize = 256 * 1024;

#[derive(Default)]
pub(super) struct StagingBuffer(BytesMut);
impl StagingBuffer {
    pub(super) fn push(&mut self, input: &mut Bytes) -> Option<Bytes> {
        if self.0.capacity() == 0 {
            self.0.reserve(STAGING_BYTES);
        }
        let n = input.len().min(STAGING_BYTES - self.0.len());
        self.0.extend_from_slice(&input.split_to(n));
        (self.0.len() == STAGING_BYTES).then(|| core::mem::take(&mut self.0).freeze())
    }
    pub(super) fn finish(&mut self) -> Option<Bytes> {
        (!self.0.is_empty()).then(|| core::mem::take(&mut self.0).freeze())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn client_framing_preserves_fixed_buffer_and_storage_boundaries() {
        let data = vec![13; STAGING_BYTES * 2 + 17];
        for framing in [1, 4096, 65536, data.len()] {
            let mut buffer = StagingBuffer::default();
            let mut writes = Vec::new();
            for chunk in data.chunks(framing) {
                let mut input = Bytes::copy_from_slice(chunk);
                while !input.is_empty() {
                    if let Some(bytes) = buffer.push(&mut input) {
                        writes.push(bytes);
                    }
                    assert!(buffer.0.capacity() <= 256 * 1024);
                    assert!(buffer.0.len() < STAGING_BYTES);
                }
            }
            if let Some(bytes) = buffer.finish() {
                writes.push(bytes);
            }
            assert_eq!(
                writes.iter().map(Bytes::len).collect::<Vec<_>>(),
                [STAGING_BYTES, STAGING_BYTES, 17]
            );
            assert_eq!(writes.concat(), data);
        }
    }
}
