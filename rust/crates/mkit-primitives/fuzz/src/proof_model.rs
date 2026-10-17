//! Small generated trees checked against an independent ordered-map oracle.
use mkit_core::hash::Hash;
use mkit_primitives::{
    evidence::{
        PageCommitment, PageKind,
        pages::{BranchChild, EncodedPage, LeafRecord, encode_internal, encode_leaf},
        proof::verify_path,
    },
    limits::EvidenceLimits,
};
use std::collections::BTreeMap;

fn limits() -> EvidenceLimits {
    EvidenceLimits {
        page_bytes: 4096,
        value_bytes: 32,
        proof_bytes: 16384,
        proof_pages: 4,
        work: 1 << 20,
        allocated_bytes: 4096,
    }
}

struct Tree {
    oracle: BTreeMap<Hash, Vec<u8>>,
    leaves: Vec<EncodedPage>,
    branches: Vec<EncodedPage>,
    root: EncodedPage,
}

impl Tree {
    fn generate(data: &[u8]) -> Self {
        let mut oracle = BTreeMap::new();
        for group in 0_u8..4 {
            let count = 1 + data.get(usize::from(group)).copied().unwrap_or(0) % 4;
            for rank in 0..count {
                let mut key = [0; 32];
                key[0] = group * 64;
                key[1] = rank * 16;
                let start = (usize::from(group) * 4 + usize::from(rank)) * 16;
                let value = data
                    .get(start..data.len().min(start + 16))
                    .unwrap_or(&[])
                    .to_vec();
                oracle.insert(key, value);
            }
        }
        let mut leaves = Vec::with_capacity(4);
        for group in 0_u8..4 {
            let records: Vec<_> = oracle
                .iter()
                .filter(|(key, _)| key[0] == group * 64)
                .map(|(key, value)| LeafRecord { key: *key, value })
                .collect();
            leaves.push(
                encode_leaf(super::seed_binding(), PageKind::Objects, &records, limits())
                    .expect("bounded model invariant"),
            );
        }
        let branches: Vec<_> = (0..2)
            .map(|index| {
                let mut separator = [0; 32];
                separator[0] = if index == 0 { 64 } else { 192 };
                encode_internal(
                    super::seed_binding(),
                    PageKind::Objects,
                    1,
                    leaves[index * 2].commitment(),
                    &[BranchChild {
                        separator,
                        child: leaves[index * 2 + 1].commitment(),
                    }],
                    limits(),
                )
                .expect("bounded model invariant")
            })
            .collect();
        let mut separator = [0; 32];
        separator[0] = 128;
        let root = encode_internal(
            super::seed_binding(),
            PageKind::Objects,
            2,
            branches[0].commitment(),
            &[BranchChild {
                separator,
                child: branches[1].commitment(),
            }],
            limits(),
        )
        .expect("bounded model invariant");
        Self {
            oracle,
            leaves,
            branches,
            root,
        }
    }

    fn check(&self, query: Hash) {
        let group = usize::from(query[0] / 64);
        let middle = &self.branches[group / 2];
        let pages = [
            self.root.bytes(),
            middle.bytes(),
            self.leaves[group].bytes(),
        ];
        let proof = encode_path(&pages, self.root.commitment(), query);
        let answer = verify_path(
            &proof,
            super::seed_binding(),
            self.root.commitment(),
            query,
            EvidenceLimits {
                allocated_bytes: 0,
                ..limits()
            },
        )
        .expect("bounded model invariant");
        assert_eq!(answer.value(), self.oracle.get(&query).map(Vec::as_slice));
        let missing = encode_path(&pages[..2], self.root.commitment(), query);
        assert!(
            verify_path(
                &missing,
                super::seed_binding(),
                self.root.commitment(),
                query,
                limits()
            )
            .is_err()
        );
        let wrong = encode_path(
            &[pages[0], pages[1], self.leaves[(group + 1) % 4].bytes()],
            self.root.commitment(),
            query,
        );
        assert!(
            verify_path(
                &wrong,
                super::seed_binding(),
                self.root.commitment(),
                query,
                limits()
            )
            .is_err()
        );
        let mut corrupted = proof;
        *corrupted.last_mut().expect("bounded model invariant") ^= 1;
        assert!(
            verify_path(
                &corrupted,
                super::seed_binding(),
                self.root.commitment(),
                query,
                limits()
            )
            .is_err()
        );
    }
}

fn encode_path(pages: &[&[u8]], root: PageCommitment, query: Hash) -> Vec<u8> {
    let mut bytes = b"MKPF\x01\0".to_vec();
    bytes.extend_from_slice(&root.digest);
    bytes.push(0); // The model uses object pages only.
    bytes.extend_from_slice(&root.len.to_le_bytes());
    bytes.extend_from_slice(&root.items.to_le_bytes());
    bytes.extend_from_slice(&query);
    bytes.extend_from_slice(
        &u16::try_from(pages.len())
            .expect("bounded model invariant")
            .to_le_bytes(),
    );
    for page in pages {
        bytes.extend_from_slice(
            &u32::try_from(page.len())
                .expect("bounded model invariant")
                .to_le_bytes(),
        );
        bytes.extend_from_slice(page);
    }
    bytes
}

pub(super) fn exercise(data: &[u8]) {
    // Four leaves, at most sixteen records/256 value bytes; each path < 4 KiB.
    // Every input reaches valid commitment checks and both lookup outcomes.
    let tree = Tree::generate(data);
    for key in tree.oracle.keys() {
        tree.check(*key);
        let mut absent = *key;
        absent[31] = 1;
        tree.check(absent);
    }
    let mut query = [0; 32];
    let len = data.len().min(query.len());
    query[..len].copy_from_slice(&data[..len]);
    tree.check(query);
}

#[cfg(test)]
mod tests {
    #[test]
    fn generated_multilevel_membership_absence_and_bad_paths_are_reachable() {
        super::exercise(&[]);
        super::exercise(&[255; 256]);
        super::exercise(&(0..=255).collect::<Vec<_>>());
    }
}
