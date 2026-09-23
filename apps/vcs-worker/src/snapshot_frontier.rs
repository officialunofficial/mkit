// SPDX-License-Identifier: MIT OR Apache-2.0
//! Compact, versioned internal work records. These are not object facts or
//! externally submitted proofs; every transition reinspects object bytes.

use mkit_core::{
    hash::Hash,
    partial::{SnapshotRole, SnapshotWalkRecord},
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Frontier {
    pub version: u8,
    pub kind: String,
    pub id: String,
    pub role: String,
    pub depth: u64,
    pub next_index: u32,
    pub sum: u64,
    pub checksum: String,
}

impl Frontier {
    pub fn from_record(record: &SnapshotWalkRecord) -> Self {
        let mut frontier = match record {
            SnapshotWalkRecord::Visit {
                id,
                role,
                tree_depth,
            } => Self {
                version: 1,
                kind: "visit".into(),
                id: hex::encode(id),
                role: role_name(*role).into(),
                depth: *tree_depth,
                next_index: 0,
                sum: 0,
                checksum: String::new(),
            },
            SnapshotWalkRecord::TreePage {
                id,
                tree_depth,
                next_index,
            } => Self {
                version: 1,
                kind: "tree_page".into(),
                id: hex::encode(id),
                role: "tree".into(),
                depth: *tree_depth,
                next_index: *next_index,
                sum: 0,
                checksum: String::new(),
            },
            SnapshotWalkRecord::ManifestPage {
                id,
                tree_depth,
                next_index,
                sum,
            } => Self {
                version: 1,
                kind: "manifest_page".into(),
                id: hex::encode(id),
                role: "file".into(),
                depth: *tree_depth,
                next_index: *next_index,
                sum: *sum,
                checksum: String::new(),
            },
        };
        frontier.checksum = frontier.compute_checksum();
        frontier
    }

    fn compute_checksum(&self) -> String {
        let payload = format!(
            "mkit.host.snapshot.frontier.v1\0{}\0{}\0{}\0{}\0{}\0{}\0{}",
            self.version, self.kind, self.id, self.role, self.depth, self.next_index, self.sum
        );
        hex::encode(mkit_core::hash::hash(payload.as_bytes()))
    }

    pub fn record(&self) -> Result<SnapshotWalkRecord, &'static str> {
        if self.version != 1
            || self.depth > 128
            || !crate::snapshot_wire::id(&self.id)
            || self.checksum != self.compute_checksum()
        {
            return Err("invalid frontier record");
        }
        let id: Hash = hex::decode(&self.id)
            .map_err(|_| "invalid frontier id")?
            .try_into()
            .map_err(|_| "invalid frontier id")?;
        match self.kind.as_str() {
            "visit" if self.next_index == 0 && self.sum == 0 => Ok(SnapshotWalkRecord::Visit {
                id,
                role: parse_role(&self.role)?,
                tree_depth: self.depth,
            }),
            "tree_page" if self.role == "tree" && self.sum == 0 && self.next_index <= 65_536 => {
                Ok(SnapshotWalkRecord::TreePage {
                    id,
                    tree_depth: self.depth,
                    next_index: self.next_index,
                })
            }
            // `sum` is positional logical file bytes, not distinct canonical
            // repository bytes. Repeated chunks may exceed the latter cap.
            "manifest_page" if self.role == "file" && self.next_index <= 32_768 => {
                Ok(SnapshotWalkRecord::ManifestPage {
                    id,
                    tree_depth: self.depth,
                    next_index: self.next_index,
                    sum: self.sum,
                })
            }
            _ => Err("invalid frontier record"),
        }
    }
}

fn role_name(role: SnapshotRole) -> &'static str {
    match role {
        SnapshotRole::BaseRoot => "base_root",
        SnapshotRole::CandidateRoot => "candidate_root",
        SnapshotRole::Tree => "tree",
        SnapshotRole::File => "file",
        SnapshotRole::Symlink => "symlink",
        SnapshotRole::Chunk => "chunk",
    }
}

fn parse_role(value: &str) -> Result<SnapshotRole, &'static str> {
    match value {
        "base_root" => Ok(SnapshotRole::BaseRoot),
        "candidate_root" => Ok(SnapshotRole::CandidateRoot),
        "tree" => Ok(SnapshotRole::Tree),
        "file" => Ok(SnapshotRole::File),
        "symlink" => Ok(SnapshotRole::Symlink),
        "chunk" => Ok(SnapshotRole::Chunk),
        _ => Err("invalid frontier role"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn work_record_roundtrip_and_invalid_cursor() {
        let records = [
            SnapshotWalkRecord::Visit {
                id: [1; 32],
                role: SnapshotRole::BaseRoot,
                tree_depth: 0,
            },
            SnapshotWalkRecord::TreePage {
                id: [2; 32],
                tree_depth: 1,
                next_index: 0,
            },
            SnapshotWalkRecord::TreePage {
                id: [2; 32],
                tree_depth: 1,
                next_index: 64,
            },
            SnapshotWalkRecord::ManifestPage {
                id: [3; 32],
                tree_depth: 1,
                next_index: 0,
                sum: 0,
            },
            SnapshotWalkRecord::ManifestPage {
                id: [3; 32],
                tree_depth: 1,
                next_index: 64,
                sum: 4096,
            },
            SnapshotWalkRecord::ManifestPage {
                id: [3; 32],
                tree_depth: 1,
                next_index: 129,
                sum: 270_532_608,
            },
        ];
        for record in records {
            let stored = Frontier::from_record(&record);
            assert_eq!(stored.record().unwrap(), record);
        }
        let mut bad = Frontier::from_record(&records[2]);
        bad.next_index = 65_537;
        assert!(bad.record().is_err());
        let mut bad = Frontier::from_record(&records[4]);
        bad.sum += 1;
        assert!(bad.record().is_err(), "cursor checksum binds progress");
    }
}
