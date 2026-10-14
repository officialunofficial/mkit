//! Disposable, checksummed per-source/remote/branch fetch checkpoints.
//! See the sync README for the on-disk contract. Writes are under the
//! worktree lock; atomic reads, loss, or corruption can only cause a longer walk.

use std::path::PathBuf;

use mkit_core::hash::{Hash, hash, to_hex};
use mkit_core::layout::RepoLayout;
use mkit_core::refs::parse_lowercase_hash;

use crate::packmap::{MAX_FETCH_PACKS, MAX_PACK_CHAIN_DEPTH};
use crate::source::RemoteSource;

#[derive(Clone, Copy, Debug)]
pub(crate) struct Checkpoint {
    pub(crate) head: Hash,
    pub(crate) tip: Hash,
    pub(crate) packs: usize,
    pub(crate) nodes: usize,
}

pub(crate) fn path(
    layout: &RepoLayout,
    source: &dyn RemoteSource,
    remote: &str,
    branch: &str,
) -> Option<PathBuf> {
    let (repository, origin) = source.repository_address()?;
    // Length prefixes avoid ambiguous concatenations, including embedded separators.
    let mut key = Vec::new();
    for part in [remote, branch, &repository, &origin] {
        key.extend_from_slice(&(part.len() as u64).to_le_bytes());
        key.extend_from_slice(part.as_bytes());
    }
    Some(
        layout
            .applied_packs_dir()
            .join(".heads")
            .join(to_hex(&hash(&key))),
    )
}

impl Checkpoint {
    pub(crate) fn load(path: &std::path::Path) -> Option<Self> {
        // A bounded read also makes an unexpectedly large cache file harmless.
        use std::io::Read as _;
        let mut bytes = Vec::new();
        std::fs::File::open(path)
            .ok()?
            .take(513)
            .read_to_end(&mut bytes)
            .ok()?;
        if bytes.len() > 512 {
            return None;
        }
        let text = std::str::from_utf8(&bytes).ok()?;
        let (body, checksum) = text.rsplit_once('\n')?;
        if parse_lowercase_hash(checksum.as_bytes())? != hash(body.as_bytes()) {
            return None;
        }
        let mut fields = body.split('\n');
        if fields.next()? != "mkit-fetch-head-v1" {
            return None;
        }
        let head = parse_lowercase_hash(fields.next()?.as_bytes())?;
        let tip = parse_lowercase_hash(fields.next()?.as_bytes())?;
        let packs = fields.next()?.parse().ok()?;
        let nodes = fields.next()?.parse().ok()?;
        if fields.next().is_some()
            || packs > MAX_FETCH_PACKS
            || nodes == 0
            || nodes > MAX_PACK_CHAIN_DEPTH
        {
            return None;
        }
        Some(Self {
            head,
            tip,
            packs,
            nodes,
        })
    }

    pub(crate) fn persist(self, path: &std::path::Path) -> std::io::Result<()> {
        let body = format!(
            "mkit-fetch-head-v1\n{}\n{}\n{}\n{}",
            to_hex(&self.head),
            to_hex(&self.tip),
            self.packs,
            self.nodes
        );
        let bytes = format!("{body}\n{}", to_hex(&hash(body.as_bytes())));
        crate::applied_packs::write_atomic(path, bytes.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checkpoint_roundtrip_rejects_corruption_and_invalid_counts() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("record");
        let valid = Checkpoint {
            head: hash(b"head"),
            tip: hash(b"tip"),
            packs: 3,
            nodes: 2,
        };
        valid.persist(&path).unwrap();
        let loaded = Checkpoint::load(&path).unwrap();
        assert_eq!(
            (loaded.head, loaded.tip, loaded.packs, loaded.nodes),
            (valid.head, valid.tip, 3, 2)
        );
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[20] = if bytes[20] == b'a' { b'b' } else { b'a' };
        std::fs::write(&path, bytes).unwrap();
        assert!(Checkpoint::load(&path).is_none());
        for record in [
            Checkpoint { nodes: 0, ..valid },
            Checkpoint {
                packs: MAX_FETCH_PACKS + 1,
                ..valid
            },
            Checkpoint {
                nodes: MAX_PACK_CHAIN_DEPTH + 1,
                ..valid
            },
        ] {
            record.persist(&path).unwrap();
            assert!(Checkpoint::load(&path).is_none());
        }
        std::fs::write(&path, vec![b'a'; 513]).unwrap();
        assert!(Checkpoint::load(&path).is_none());
    }
}
