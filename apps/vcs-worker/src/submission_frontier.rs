// SPDX-License-Identifier: MIT OR Apache-2.0
//! Bounded trusted queue codec for staged diff/file work records.
//! These rows are not client proofs; every transition reinspects object bytes.

use mkit_core::{
    hash::Hash,
    partial::{ChangedPairRecord, RequiredFileRecord},
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiffFrontier {
    version: u8,
    kind: String,
    old_id: String,
    new_id: String,
    path: Vec<String>,
    change_index: u32,
    next_index: u32,
    sum: u64,
    checksum: String,
}

fn id(value: &str) -> Result<Hash, &'static str> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err("invalid frontier ID");
    }
    hex::decode(value)
        .map_err(|_| "invalid frontier ID")?
        .try_into()
        .map_err(|_| "invalid frontier ID")
}
fn path(value: &[String]) -> Result<Vec<Vec<u8>>, &'static str> {
    if value.len() > 32 {
        return Err("path too deep");
    }
    let mut joined = 0usize;
    let mut out = Vec::with_capacity(value.len());
    for (index, part) in value.iter().enumerate() {
        if part.len() > 510
            || part.len() % 2 != 0
            || !part
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err("invalid path component");
        }
        let decoded = hex::decode(part).map_err(|_| "invalid path component")?;
        if decoded.is_empty() || decoded.len() > 255 {
            return Err("invalid path component");
        }
        joined = joined
            .checked_add(decoded.len() + usize::from(index > 0))
            .ok_or("path overflow")?;
        if joined > 1024 {
            return Err("path too long");
        }
        out.push(decoded);
    }
    Ok(out)
}
impl DiffFrontier {
    fn checksum(&self) -> String {
        let mut copy = self.clone();
        copy.checksum.clear();
        let bytes = serde_json::to_vec(&copy).expect("serializable local record");
        hex::encode(mkit_core::hash::hash(
            [
                b"mkit.host.submission.frontier.v1\0".as_slice(),
                bytes.as_slice(),
            ]
            .concat()
            .as_slice(),
        ))
    }
    pub fn from_pair(value: &ChangedPairRecord) -> Self {
        let (kind, old_id, new_id, path, next_index) = match value {
            ChangedPairRecord::Visit {
                old_id,
                new_id,
                path,
            } => ("pair_visit", old_id, new_id, path, 0),
            ChangedPairRecord::Page {
                old_id,
                new_id,
                path,
                next_index,
            } => ("pair_page", old_id, new_id, path, *next_index),
        };
        let mut out = Self {
            version: 1,
            kind: kind.into(),
            old_id: hex::encode(old_id),
            new_id: hex::encode(new_id),
            path: path.iter().map(hex::encode).collect(),
            change_index: 0,
            next_index,
            sum: 0,
            checksum: String::new(),
        };
        out.checksum = out.checksum();
        out
    }
    pub fn from_file(value: &RequiredFileRecord) -> Self {
        let (kind, change_index, expected_file_id, next_index, sum) = match value {
            RequiredFileRecord::Visit {
                change_index,
                expected_file_id,
            } => ("file_visit", *change_index, expected_file_id, 0, 0),
            RequiredFileRecord::ManifestPage {
                change_index,
                expected_file_id,
                next_index,
                sum,
            } => (
                "file_page",
                *change_index,
                expected_file_id,
                *next_index,
                *sum,
            ),
        };
        let mut out = Self {
            version: 1,
            kind: kind.into(),
            old_id: String::new(),
            new_id: hex::encode(expected_file_id),
            path: Vec::new(),
            change_index,
            next_index,
            sum,
            checksum: String::new(),
        };
        out.checksum = out.checksum();
        out
    }
    pub fn pair(&self) -> Result<ChangedPairRecord, &'static str> {
        if self.version != 1
            || self.checksum != self.checksum()
            || self.change_index != 0
            || self.sum != 0
            || self.path.len() > 32
        {
            return Err("invalid pair record");
        }
        let old_id = id(&self.old_id)?;
        let new_id = id(&self.new_id)?;
        let path = path(&self.path)?;
        match self.kind.as_str() {
            "pair_visit" if self.next_index == 0 => Ok(ChangedPairRecord::Visit {
                old_id,
                new_id,
                path,
            }),
            "pair_page" if self.next_index <= 65_536 => Ok(ChangedPairRecord::Page {
                old_id,
                new_id,
                path,
                next_index: self.next_index,
            }),
            _ => Err("invalid pair record"),
        }
    }
    pub fn file(&self) -> Result<RequiredFileRecord, &'static str> {
        if self.version != 1
            || self.checksum != self.checksum()
            || !self.old_id.is_empty()
            || !self.path.is_empty()
            || self.change_index >= 256
        {
            return Err("invalid file record");
        }
        let expected_file_id = id(&self.new_id)?;
        match self.kind.as_str() {
            "file_visit" if self.next_index == 0 && self.sum == 0 => {
                Ok(RequiredFileRecord::Visit {
                    change_index: self.change_index,
                    expected_file_id,
                })
            }
            "file_page" if self.next_index <= 32_768 => Ok(RequiredFileRecord::ManifestPage {
                change_index: self.change_index,
                expected_file_id,
                next_index: self.next_index,
                sum: self.sum,
            }),
            _ => Err("invalid file record"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn roundtrip_core_emitted_zero_and_positive_pages() {
        let pairs = [
            ChangedPairRecord::Visit {
                old_id: [1; 32],
                new_id: [2; 32],
                path: vec![],
            },
            ChangedPairRecord::Page {
                old_id: [1; 32],
                new_id: [2; 32],
                path: vec![b"dir".to_vec()],
                next_index: 0,
            },
            ChangedPairRecord::Page {
                old_id: [1; 32],
                new_id: [2; 32],
                path: vec![b"dir".to_vec()],
                next_index: 64,
            },
        ];
        for value in &pairs {
            assert_eq!(DiffFrontier::from_pair(value).pair().unwrap(), *value);
        }
        let files = [
            RequiredFileRecord::Visit {
                change_index: 0,
                expected_file_id: [3; 32],
            },
            RequiredFileRecord::ManifestPage {
                change_index: 0,
                expected_file_id: [3; 32],
                next_index: 0,
                sum: 0,
            },
            RequiredFileRecord::ManifestPage {
                change_index: 0,
                expected_file_id: [3; 32],
                next_index: 64,
                sum: 270_532_608,
            },
        ];
        for value in &files {
            assert_eq!(DiffFrontier::from_file(value).file().unwrap(), *value);
        }
        let mut bad = DiffFrontier::from_pair(&pairs[1]);
        bad.next_index = 65_537;
        assert!(bad.pair().is_err());
    }
}
