//! Minimal unpadded standard-alphabet base64 (RFC 4648 §4), encode +
//! strict decode. Hand-rolled to keep the bridge dependency-free;
//! the alphabet and the no-padding rule are pinned by
//! SPEC-GIT-BRIDGE §6.3.

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub(crate) fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = u32::from(chunk.get(1).copied().unwrap_or(0));
        let b2 = u32::from(chunk.get(2).copied().unwrap_or(0));
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(n >> 18) as usize & 0x3F] as char);
        out.push(ALPHABET[(n >> 12) as usize & 0x3F] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[(n >> 6) as usize & 0x3F] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[n as usize & 0x3F] as char);
        }
    }
    out
}

/// Strict decode: rejects padding, whitespace, non-alphabet bytes,
/// impossible lengths (`len % 4 == 1`), and non-canonical trailing
/// bits (an encoding that no byte string produces).
// The `as u8` casts below extract masked low bytes of a u32
// accumulator; truncation is the point.
#[allow(clippy::cast_possible_truncation)]
pub(crate) fn decode(s: &str) -> Option<Vec<u8>> {
    fn val(b: u8) -> Option<u32> {
        Some(match b {
            b'A'..=b'Z' => u32::from(b - b'A'),
            b'a'..=b'z' => u32::from(b - b'a') + 26,
            b'0'..=b'9' => u32::from(b - b'0') + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        })
    }
    let bytes = s.as_bytes();
    if bytes.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3 + 2);
    for chunk in bytes.chunks(4) {
        let mut n: u32 = 0;
        for &b in chunk {
            n = (n << 6) | val(b)?;
        }
        match chunk.len() {
            4 => {
                out.push((n >> 16) as u8);
                out.push((n >> 8) as u8);
                out.push(n as u8);
            }
            3 => {
                // 18 significant bits; low 2 must be zero (canonical).
                if n & 0b11 != 0 {
                    return None;
                }
                n >>= 2;
                out.push((n >> 8) as u8);
                out.push(n as u8);
            }
            2 => {
                // 12 significant bits; low 4 must be zero.
                if n & 0b1111 != 0 {
                    return None;
                }
                out.push((n >> 4) as u8);
            }
            _ => return None,
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_all_lengths() {
        for len in 0..=9 {
            let data: Vec<u8> = (0..u8::try_from(len).unwrap())
                .map(|i| i.wrapping_mul(37))
                .collect();
            let enc = encode(&data);
            assert!(!enc.contains('='), "unpadded");
            assert_eq!(decode(&enc).unwrap(), data, "len {len}");
        }
    }

    #[test]
    fn known_vector() {
        assert_eq!(encode(b"foob"), "Zm9vYg");
        assert_eq!(decode("Zm9vYg").unwrap(), b"foob");
    }

    #[test]
    fn rejects_padding_and_junk() {
        assert!(decode("Zm9vYg==").is_none());
        assert!(decode("Zm9 vYg").is_none());
        assert!(decode("A").is_none());
        // non-canonical trailing bits: "Zm9vYh" decodes the same prefix
        // but with a nonzero low bit.
        assert!(decode("Zm9vYh").is_none());
    }
}
