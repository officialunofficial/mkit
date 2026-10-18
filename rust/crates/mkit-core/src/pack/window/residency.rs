use super::{Phase, WindowReader};

impl WindowReader {
    /// Conservative data-buffer residency through the next [`Self::step`].
    ///
    /// Includes the retained window, carried frame capacity, and owned entry
    /// output. Compressed entries additionally charge the supplied decoder
    /// scratch ceiling. Fixed state and subtree frontiers remain the caller's
    /// control allowance; an outstanding acquisition is charged separately.
    /// Inspecting the next frame neither allocates nor advances the reader.
    #[must_use]
    pub fn memory_bound(&self, decoder_scratch: u64) -> u64 {
        let window = self.window.capacity() as u64;
        let carry = self.carry.capacity() as u64;
        let current = window.saturating_add(carry);
        if self.integrity_only || self.request.is_some() || self.window.is_empty() {
            return current;
        }
        let (kind, payload_len) = if self.phase == Phase::Payload {
            (self.kind, self.payload_len)
        } else if matches!(self.phase, Phase::Header | Phase::Boundary | Phase::Frame) {
            // Header parsing can reach the first entry in this same step. A
            // boundary after the final entry proceeds directly to the trailer.
            if self.phase == Phase::Header {
                let Some(count) = self.window.get(8..12) else {
                    return current;
                };
                if count == [0, 0, 0, 0] {
                    return current;
                }
            } else if self.phase == Phase::Boundary && self.state.index == self.state.count {
                return current;
            }
            let used = if self.phase == Phase::Frame {
                self.header_used
            } else {
                0
            };
            let Some(begin) = self
                .state
                .pos
                .checked_sub(self.start)
                .and_then(|pos| usize::try_from(pos).ok())
            else {
                return current;
            };
            let Some(bytes) = self
                .window
                .get(begin..)
                .and_then(|bytes| bytes.get(..5 - used))
            else {
                // A partial header cannot allocate a payload before returning
                // its next window request. Re-evaluate after that feed.
                return current;
            };
            let mut header = self.header;
            header[used..].copy_from_slice(bytes);
            (
                header[0],
                u64::from(u32::from_le_bytes([
                    header[1], header[2], header[3], header[4],
                ])),
            )
        } else {
            return current;
        };
        let (frame, stream) = self
            .limits
            .entry_geometry
            .unwrap_or((self.limits.max_decoded_bytes, self.limits.max_decoded_bytes));
        // Oversized framing fails before any carry reservation or decoding.
        if self.limits.entry_geometry.is_some() && payload_len > frame {
            return current;
        }
        let output = match kind {
            0 | 3 => self.limits.max_decoded_bytes,
            2 => stream.saturating_add(32),
            4 => stream,
            _ => return current,
        };
        if matches!(kind, 3 | 4) {
            window
                .saturating_add(carry.max(payload_len))
                .saturating_add(output)
                .saturating_add(decoder_scratch)
        } else {
            // Raw/delta carry storage becomes the owned entry without a copy.
            // The legacy reader may reserve a carried frame before checking its
            // decoded cap; the one-pass reader checks that cap first.
            let entry = if self.one_pass {
                payload_len.min(output)
            } else {
                payload_len
            };
            window.saturating_add(carry.max(entry))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pack::DecodeLimits;

    fn at_header(kind: u8, len: u32) -> WindowReader {
        let mut reader = WindowReader::new_one_pass(
            128 << 10,
            64 << 10,
            DecodeLimits::default()
                .with_max_decoded_bytes(1024)
                .with_entry_geometry(16 << 20, 2048),
            Some([0; 32]),
        )
        .unwrap();
        reader.window = vec![0; 64 << 10];
        reader.window[8..12].copy_from_slice(&1u32.to_le_bytes());
        reader.window[12] = kind;
        reader.window[13..17].copy_from_slice(&len.to_le_bytes());
        reader.end = reader.window.len() as u64;
        reader
    }

    #[test]
    fn compressed_header_uses_actual_frame_length() {
        let reader = at_header(3, 64);
        assert_eq!(
            reader.memory_bound(28 << 20),
            (64 << 10) + 64 + 1024 + (28 << 20)
        );
    }

    #[test]
    fn final_boundary_does_not_decode_trailer_bytes() {
        let mut reader = at_header(3, 64);
        reader.phase = Phase::Boundary;
        reader.state.index = 1;
        reader.state.count = 1;
        assert_eq!(reader.memory_bound(28 << 20), 64 << 10);
    }

    #[test]
    fn split_header_is_reconsidered_after_next_feed() {
        let mut reader = at_header(0, 64);
        reader.phase = Phase::Frame;
        reader.header[0] = 3;
        reader.header_used = 1;
        reader.state.pos = reader.end - 2;
        assert_eq!(reader.memory_bound(28 << 20), 64 << 10);
        reader.state.pos = 12;
        reader.window[12..16].copy_from_slice(&64u32.to_le_bytes());
        assert_eq!(
            reader.memory_bound(28 << 20),
            (64 << 10) + 64 + 1024 + (28 << 20)
        );
    }

    #[test]
    fn legacy_raw_carry_reservation_precedes_decoded_cap() {
        let mut reader = at_header(0, 16 << 20);
        reader.one_pass = false;
        assert_eq!(reader.memory_bound(0), (64 << 10) + (16 << 20));
        reader.carry.reserve_exact(20 << 20);
        assert_eq!(
            reader.memory_bound(0),
            (64 << 10) + reader.carry.capacity() as u64
        );
    }
}
