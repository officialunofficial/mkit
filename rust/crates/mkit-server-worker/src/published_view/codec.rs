use super::{MAX_BYTES, MAX_ROWS, VALIDITY_MS};
use mkit_core::hash::{Hash, hash, to_hex_bytes};
use mkit_server::pipeline::{D34Shards, ShardMap};
use mkit_server::{Partition, RepoId, StoreError};
use std::fmt::Write as _;

/// Deterministic v2 envelope: magic, identity length+partition, three `BE` u64s,
/// `BE` u16 row count, then `BE` u16 name length, `UTF-8` full name, raw 32-byte id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    /// `RefIndex` identity (namespace, repository, bucket).
    pub partition: Partition,
    /// Bucket-local generation, independent of producer sequences.
    pub generation: u64,
    /// Capture time (Unix ms).
    pub captured_at_ms: u64,
    /// Exclusive validity deadline (Unix ms).
    pub valid_until_ms: u64,
    /// Strictly sorted and correctly routed full ref names.
    pub rows: Vec<(String, Hash)>,
}
fn bad() -> StoreError {
    StoreError::Corrupt("invalid published snapshot".into())
}
fn identity(partition: &Partition) -> Result<RepoId, StoreError> {
    match partition {
        Partition::RefIndex { ns, repo, bucket }
            if *bucket < mkit_server::store::REF_INDEX_FANOUT =>
        {
            Ok(RepoId {
                namespace: ns.clone(),
                name: repo.clone(),
            })
        }
        _ => Err(bad()),
    }
}
impl Envelope {
    fn validate(&self) -> Result<(), StoreError> {
        let repo = identity(&self.partition)?;
        if self.rows.len() > MAX_ROWS
            || self.generation == 0
            || self.valid_until_ms <= self.captured_at_ms
            || self.valid_until_ms - self.captured_at_ms > VALIDITY_MS
        {
            return Err(bad());
        }
        let mut previous: Option<&str> = None;
        for (name, _) in &self.rows {
            if !mkit_server::refs::validate_ref_name(name)
                || previous.is_some_and(|p| p >= name.as_str())
                || D34Shards.ref_index(&repo, name) != self.partition
            {
                return Err(bad());
            }
            previous = Some(name);
        }
        Ok(())
    }
    /// Encode only a bounded, validated envelope.
    pub fn encode(&self) -> Result<Vec<u8>, StoreError> {
        self.validate()?;
        let partition = self.partition.encode()?;
        let length = 4
            + 2
            + partition.len()
            + 24
            + 2
            + self
                .rows
                .iter()
                .map(|(n, _)| 2 + n.len() + 32)
                .sum::<usize>();
        if length > MAX_BYTES {
            return Err(bad());
        }
        let mut bytes = Vec::with_capacity(length);
        bytes.extend_from_slice(b"MKP\x02");
        bytes.extend_from_slice(
            &u16::try_from(partition.len())
                .map_err(|_| bad())?
                .to_be_bytes(),
        );
        bytes.extend_from_slice(&partition);
        for v in [self.generation, self.captured_at_ms, self.valid_until_ms] {
            bytes.extend_from_slice(&v.to_be_bytes());
        }
        bytes.extend_from_slice(
            &u16::try_from(self.rows.len())
                .map_err(|_| bad())?
                .to_be_bytes(),
        );
        for (name, id) in &self.rows {
            bytes.extend_from_slice(&u16::try_from(name.len()).map_err(|_| bad())?.to_be_bytes());
            bytes.extend_from_slice(name.as_bytes());
            bytes.extend_from_slice(id);
        }
        Ok(bytes)
    }
    /// Reject malformed, future, expired, misrouted, unsupported and oversized data.
    pub fn decode(bytes: &[u8], expected: &Partition, now_ms: u64) -> Result<Self, StoreError> {
        if bytes.len() > MAX_BYTES {
            return Err(bad());
        }
        let mut read = Reader(bytes);
        if read.take(4)? != b"MKP\x02" {
            return Err(bad());
        }
        let n = usize::from(read.u16()?);
        let partition = Partition::decode(read.take(n)?)?;
        if &partition != expected {
            return Err(bad());
        }
        let generation = read.u64()?;
        let captured_at_ms = read.u64()?;
        let valid_until_ms = read.u64()?;
        if captured_at_ms > now_ms || now_ms >= valid_until_ms {
            return Err(bad());
        }
        let n = usize::from(read.u16()?);
        if n > MAX_ROWS {
            return Err(bad());
        }
        let mut rows = Vec::with_capacity(n);
        for _ in 0..n {
            let length = usize::from(read.u16()?);
            if length > mkit_server::refs::MAX_REF_NAME_BYTES {
                return Err(bad());
            }
            let name = std::str::from_utf8(read.take(length)?)
                .map_err(|_| bad())?
                .to_owned();
            let id = read.take(32)?.try_into().map_err(|_| bad())?;
            rows.push((name, id));
        }
        if !read.0.is_empty() {
            return Err(bad());
        }
        let envelope = Self {
            partition,
            generation,
            captured_at_ms,
            valid_until_ms,
            rows,
        };
        envelope.validate()?;
        Ok(envelope)
    }
}
struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], StoreError> {
        let (a, b) = self.0.split_at_checked(n).ok_or_else(bad)?;
        self.0 = b;
        Ok(a)
    }
    fn u16(&mut self) -> Result<u16, StoreError> {
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().map_err(|_| bad())?,
        ))
    }
    fn u64(&mut self) -> Result<u64, StoreError> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().map_err(|_| bad())?,
        ))
    }
}
fn component(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.') {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}
/// Stable R2 key; percent-encoding prevents ambiguous repository path components.
pub fn object_key(partition: &Partition) -> Result<String, StoreError> {
    let repo = identity(partition)?;
    let Partition::RefIndex { bucket, .. } = partition else {
        return Err(bad());
    };
    Ok(format!(
        "snapshots/v1/{}/{}/{bucket}",
        component(repo.namespace.as_str()),
        component(repo.name.as_str())
    ))
}
/// Internal `Cache` key binds the deployment, format and unambiguous partition encoding.
pub fn cache_key(deployment: &str, partition: &Partition) -> Result<String, StoreError> {
    let mut bytes = b"mkit.published-view.v1\0".to_vec();
    bytes.extend_from_slice(
        &u64::try_from(deployment.len())
            .map_err(|_| bad())?
            .to_be_bytes(),
    );
    bytes.extend_from_slice(deployment.as_bytes());
    bytes.extend_from_slice(&partition.encode()?);
    Ok(format!(
        "https://mkit-snapshot.invalid/v1/{}",
        to_hex_bytes(&hash(&bytes))
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::too_many_lines)]
mod v050_tests {
    crate::stored_golden::tests!(published_view_codec);
}
