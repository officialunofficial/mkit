//! Failure-only source integrity: no work or rows on a successful decode.
//!
//! A failed entry cannot decide whether a later trailer is corrupt. Retain only
//! bounded BLAKE3 subtree frontiers, never a hasher memory image, and recheck the
//! frozen source before selecting a membership or content-profile refusal.
use super::{
    BlobStore, Hash, NamespaceStore, Outcome, PackWindows, Run, SliceExtension, Stop, StoreError,
    VerifyJobV1, checkpoint, hash, unavailable,
};
use blake3::hazmat::{self, HasherExt, Mode};
use serde::{Deserialize, Serialize};

/// Disposable failure-path progress, bound to the job's immutable source/etag.
///
/// This is not verification evidence and can never make a pack usable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntegrityCheck {
    window: u64,
    offset: u64,
    whole: Frontier,
    prefix: Frontier,
    #[serde(with = "hex_hash")]
    trailer: Hash,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Frontier {
    #[serde(with = "hex_hashes")]
    stack: Vec<Hash>,
    #[serde(with = "hex_root")]
    root: Option<Hash>,
}

// Hex keeps the worst-case progress inside the job header ceiling; a JSON
// number array is about twice as large.
mod hex_hash {
    use super::Hash;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub(super) fn serialize<S: Serializer>(hash: &Hash, s: S) -> Result<S::Ok, S::Error> {
        mkit_core::hash::to_hex(hash).serialize(s)
    }
    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Hash, D::Error> {
        let text = String::deserialize(d)?;
        mkit_core::hash::from_hex(&text).map_err(serde::de::Error::custom)
    }
}

mod hex_hashes {
    use super::Hash;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub(super) fn serialize<S: Serializer>(hashes: &[Hash], s: S) -> Result<S::Ok, S::Error> {
        hashes
            .iter()
            .map(mkit_core::hash::to_hex)
            .collect::<Vec<_>>()
            .serialize(s)
    }
    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Hash>, D::Error> {
        Vec::<String>::deserialize(d)?
            .iter()
            .map(|text| mkit_core::hash::from_hex(text).map_err(serde::de::Error::custom))
            .collect()
    }
}

mod hex_root {
    use super::Hash;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    // serde's `with` contract passes the field by reference.
    #[allow(clippy::ref_option)]
    pub(super) fn serialize<S: Serializer>(hash: &Option<Hash>, s: S) -> Result<S::Ok, S::Error> {
        hash.as_ref().map(mkit_core::hash::to_hex).serialize(s)
    }
    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Hash>, D::Error> {
        Option::<String>::deserialize(d)?
            .map(|text| mkit_core::hash::from_hex(&text).map_err(serde::de::Error::custom))
            .transpose()
    }
}

fn corrupt() -> StoreError {
    StoreError::Corrupt("invalid integrity recheck progress".into())
}

impl Frontier {
    // The same binary-carry subtree composition used by core's window reader.
    // Each complete window is a power-of-two subtree at its original offset.
    fn absorb(
        &mut self,
        offset: u64,
        bytes: &[u8],
        total: u64,
        window: u64,
    ) -> Result<(), StoreError> {
        if offset >= total {
            return Ok(());
        }
        let len = (total - offset).min(bytes.len() as u64);
        let input = bytes
            .get(..usize::try_from(len).map_err(|_| corrupt())?)
            .ok_or_else(corrupt)?;
        if offset == 0 && len == total {
            self.root = Some(hash(input));
            return Ok(());
        }
        let mut hasher = blake3::Hasher::new();
        hasher.set_input_offset(offset);
        hasher.update(input);
        let mut cv = hasher.finalize_non_root();
        if offset + len == total {
            let split = hazmat::left_subtree_len(total);
            if !split.is_multiple_of(window) || offset / split != 1 {
                return Err(corrupt());
            }
            let (left, rest) = self.stack.split_first().ok_or_else(corrupt)?;
            for left in rest.iter().rev() {
                cv = hazmat::merge_subtrees_non_root(left, &cv, Mode::Hash);
            }
            self.root = Some(*hazmat::merge_subtrees_root(left, &cv, Mode::Hash).as_bytes());
        } else {
            let mut count = offset / window;
            while count & 1 != 0 {
                let left = self.stack.pop().ok_or_else(corrupt)?;
                cv = hazmat::merge_subtrees_non_root(&left, &cv, Mode::Hash);
                count >>= 1;
            }
            self.stack.push(cv);
        }
        Ok(())
    }

    fn valid(&self, offset: u64, total: u64, window: u64) -> bool {
        let completed = offset.div_ceil(window);
        self.stack.len() == completed.min((total - 1) / window).count_ones() as usize
            && self.root.is_some() == (offset >= total)
    }
}

impl IntegrityCheck {
    pub(super) fn defer(stop: &Stop, window: u64, resident: u64) -> Option<Self> {
        match stop {
            Stop::Wait(_)
            | Stop::Outcome(
                Outcome::BaseMissing
                | Outcome::BaseCapped
                | Outcome::ExternalTooDeep
                | Outcome::DecodeBudget
                // Denial is a policy check: it follows integrity like every
                // entry-level refusal (SPEC-PACKFILE 6.1).
                | Outcome::Blocked,
            )
            | Stop::Reject("delta chain too deep") => (),
            // Hash refusals already have the same public, persisted rejection as
            // integrity failures. Signatures wait until WindowReader::Done.
            _ => return None,
        }
        Self::new(window, resident)
    }

    fn new(window: u64, resident: u64) -> Option<Self> {
        let cap = window.min(checkpoint::WINDOW_BYTES).min(resident / 2);
        if cap < 1024 {
            return None;
        }
        let window = 1_u64 << cap.ilog2();
        Some(Self {
            window,
            offset: 0,
            whole: Frontier::default(),
            prefix: Frontier::default(),
            trailer: [0; 32],
        })
    }

    pub(super) fn complete(&self, pack_len: u64, pack: Hash) -> bool {
        self.offset == pack_len
            && self.whole.root == Some(pack)
            && self.prefix.root == Some(self.trailer)
    }

    pub(crate) fn valid(&self, pack_len: u64) -> bool {
        pack_len >= 44
            && self.window >= 1024
            && self.window <= checkpoint::WINDOW_BYTES
            && self.window.is_power_of_two()
            && self.offset <= pack_len
            && (self.offset == pack_len || self.offset.is_multiple_of(self.window))
            && self.whole.valid(self.offset, pack_len, self.window)
            && self.prefix.valid(self.offset, pack_len - 32, self.window)
    }
}

impl<S, R, B, W, X> Run<'_, S, R, B, W, X>
where
    S: NamespaceStore,
    R: NamespaceStore,
    B: BlobStore,
    W: PackWindows,
    X: SliceExtension,
{
    pub(super) async fn integrity(&self, job: &mut VerifyJobV1) -> Result<u64, Stop> {
        let mut check = job.integrity.take().ok_or_else(|| Stop::Store(corrupt()))?;
        if !check.valid(job.pack_len) {
            return Err(corrupt().into());
        }
        // A lower current slice configuration must not inherit a larger read.
        let bounded = IntegrityCheck::new(self.h.limits.window_bytes, self.h.limits.resident_bytes)
            .ok_or(Stop::Outcome(Outcome::DecodeBudget))?;
        if check.window > bounded.window {
            check = bounded;
        }
        let len = (job.pack_len - check.offset).min(check.window);
        if len != 0 {
            let window = self.read(job, check.offset, len).await?;
            if window.bytes.len() as u64 != len {
                return Err(unavailable("pack window read failed"));
            }
            check
                .whole
                .absorb(check.offset, &window.bytes, job.pack_len, check.window)?;
            check
                .prefix
                .absorb(check.offset, &window.bytes, job.pack_len - 32, check.window)?;
            let start = check.offset.max(job.pack_len - 32);
            let end = check.offset + len;
            if start < end {
                let src = usize::try_from(start - check.offset).map_err(|_| corrupt())?;
                let dst = usize::try_from(start - (job.pack_len - 32)).map_err(|_| corrupt())?;
                let n = usize::try_from(end - start).map_err(|_| corrupt())?;
                check.trailer[dst..dst + n].copy_from_slice(&window.bytes[src..src + n]);
            }
            check.offset = end;
        }
        if check.offset != job.pack_len {
            job.integrity = Some(check);
            return Ok(0);
        }
        if check.whole.root != Some(self.pack) || check.prefix.root != Some(check.trailer) {
            return Err(Stop::Reject("object hash mismatch"));
        }
        // Re-run the failed entry against fresh membership after integrity
        // succeeds. A completed marker survives membership waits, preventing
        // either a stale absence verdict or another full source scan.
        job.integrity = Some(check);
        Ok(0)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn frontiers_match_independent_whole_and_trailer_hashes_after_every_restart() {
        for window in [1024, 4096, 1 << 20] {
            for len in [
                44,
                1023,
                1024,
                1025,
                1055,
                1056,
                1057,
                2047,
                2048,
                2049,
                4097,
                (1 << 20) + 17,
            ] {
                let mut bytes = (0..len)
                    .map(|i| u8::try_from(i % 251).unwrap())
                    .collect::<Vec<_>>();
                let trailer = hash(&bytes[..len - 32]);
                bytes[len - 32..].copy_from_slice(&trailer);
                let mut check = IntegrityCheck::defer(&Stop::Wait(1), window, 48 << 20).unwrap();
                for chunk in bytes.chunks(usize::try_from(window).unwrap()) {
                    assert!(check.valid(len as u64));
                    check
                        .whole
                        .absorb(check.offset, chunk, len as u64, window)
                        .unwrap();
                    check
                        .prefix
                        .absorb(check.offset, chunk, len as u64 - 32, window)
                        .unwrap();
                    check.offset += chunk.len() as u64;
                    check = serde_json::from_slice(&serde_json::to_vec(&check).unwrap()).unwrap();
                }
                assert!(check.valid(len as u64));
                assert_eq!(
                    check.whole.root,
                    Some(hash(&bytes)),
                    "window={window} len={len}"
                );
                assert_eq!(
                    check.prefix.root,
                    Some(trailer),
                    "window={window} len={len}"
                );
                check.offset -= 1;
                assert!(!check.valid(len as u64));
            }
        }
    }
}
