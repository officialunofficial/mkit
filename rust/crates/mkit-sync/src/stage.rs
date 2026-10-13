//! Private staging of downloaded packs, and applying them.
//!
//! Packs are downloaded to files in a private directory without any repo
//! lock held, then unpacked into the object store under the lock. Success,
//! cancellation and every error remove the private directory.

use std::io::{Read as _, Write as _};

use mkit_core::hash::Hash;
use mkit_core::pack::PackReader;
use mkit_core::protocol::PackKey;
use mkit_core::store::ObjectStore;

use crate::applied_packs::AppliedPacks;
use crate::error::SyncError;
use crate::observer::{SyncEvent, SyncObserver};
use crate::packmap::{MAX_FETCH_PACKS, MAX_FETCH_STAGED_BYTES, branch_ref_hint};
use crate::source::RemoteSource;
use crate::verify::verify_new_object_signatures;

/// Owns all staging paths; success, cancellation and every error remove the
/// private directory. Files are closed between operations, so a large history
/// does not also require one live file descriptor per pack.
pub(crate) struct StagedPacks {
    pub(crate) directory: tempfile::TempDir,
    pub(crate) packs: Vec<StagedPack>,
    pub(crate) bytes: u64,
}

pub(crate) struct StagedPack {
    key: PackKey,
    bytes: usize,
}

/// Download to private files without holding the repo lock. Only one returned
/// pack buffer exists at a time; chain metadata and staging disk have explicit
/// aggregate limits. No authoritative objects or applied records are changed.
pub(crate) fn download_pack_chain(
    source: &dyn RemoteSource,
    observer: &dyn SyncObserver,
    branch: &str,
    chain: &[Hash],
    applied: &AppliedPacks,
    stage_parent: Option<&std::path::Path>,
) -> Result<StagedPacks, SyncError> {
    download_pack_chain_with_limits(
        source,
        observer,
        branch,
        chain,
        applied,
        MAX_FETCH_STAGED_BYTES,
        stage_parent,
    )
}

pub(crate) fn download_pack_chain_with_limits(
    source: &dyn RemoteSource,
    observer: &dyn SyncObserver,
    branch: &str,
    chain: &[Hash],
    applied: &AppliedPacks,
    disk_limit: u64,
    stage_parent: Option<&std::path::Path>,
) -> Result<StagedPacks, SyncError> {
    if chain.len() > MAX_FETCH_PACKS {
        return Err(SyncError::PackChainInvalid {
            branch: branch.to_owned(),
            source: None,
        });
    }
    let directory = match stage_parent {
        Some(parent) => tempfile::Builder::new()
            .prefix("mkit-fetch-")
            .tempdir_in(parent)?,
        None => tempfile::Builder::new().prefix("mkit-fetch-").tempdir()?,
    };
    let mut staged = StagedPacks {
        directory,
        packs: Vec::new(),
        bytes: 0,
    };
    let ref_name = branch_ref_hint(branch);
    for &pk in chain {
        if observer.cancelled() {
            return Err(SyncError::Interrupted);
        }
        let key = PackKey::from_hash(pk);
        if applied.contains(&key) {
            continue;
        }
        let pack = match source.download_pack_via_ref(&key, &ref_name) {
            Ok(b) => b,
            Err(error) if error.is_not_found() => {
                return Err(SyncError::AdvertisedPackMissing {
                    branch: branch.to_owned(),
                    pack: mkit_core::hash::to_hex(&pk),
                    source: error,
                });
            }
            Err(e) => return Err(e.into()),
        };
        #[cfg(test)]
        observe_retained_pack_bytes(pack.capacity());
        if pack.len() as u64 > mkit_core::protocol::PACK_BODY_LIMIT {
            return Err(crate::SourceError::PayloadTooLarge(pack.len()).into());
        }
        key.verify_bytes(&pack).map_err(crate::SourceError::from)?;
        let next_bytes = staged
            .bytes
            .checked_add(pack.len() as u64)
            .filter(|&bytes| bytes <= disk_limit)
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::StorageFull,
                    format!("fetch staging exceeds the {disk_limit}-byte disk budget"),
                )
            })?;
        let path = staged.directory.path().join(staged.packs.len().to_string());
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?;
        file.write_all(&pack)?;
        staged.packs.push(StagedPack {
            key,
            bytes: pack.len(),
        });
        staged.bytes = next_bytes;
        // `pack` and the file handle drop before the next download. No fsync
        // is needed for disposable staging: a crash never publishes a ref.
    }
    Ok(staged)
}

#[cfg(test)]
std::thread_local! {
    // Tracks owned download payloads at the retention boundary. Thread-local
    // state keeps concurrently running unit tests independent.
    static PEAK_RETAINED_PACK_BYTES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn observe_retained_pack_bytes(bytes: usize) {
    PEAK_RETAINED_PACK_BYTES.with(|peak| peak.set(peak.get().max(bytes)));
}

/// Apply staged packs in order while the caller holds the repo lock through
/// ref publication. Signature checks run per pack, so the full history's
/// newly stored-object IDs are not accumulated in memory. The applied key is
/// recorded only after digest, unpack and signature checks succeed.
pub(crate) fn unpack_downloaded_packs(
    store: &ObjectStore,
    observer: &dyn SyncObserver,
    staged: StagedPacks,
    applied: &mut AppliedPacks,
    require_signed: bool,
) -> Result<usize, SyncError> {
    let mut total = 0usize;
    for (index, entry) in staged.packs.iter().enumerate() {
        if observer.cancelled() {
            return Err(SyncError::Interrupted);
        }
        let path = staged.directory.path().join(index.to_string());
        let file = std::fs::File::open(&path)?;
        let mut pack = Vec::new();
        // Bound the read even if local temporary bytes were modified. The
        // independently requested digest is rechecked before store effects.
        file.take(entry.bytes as u64 + 1).read_to_end(&mut pack)?;
        if pack.len() != entry.bytes {
            return Err(crate::SourceError::InvalidResponse.into());
        }
        entry
            .key
            .verify_bytes(&pack)
            .map_err(crate::SourceError::from)?;
        let report = PackReader::read(&pack, store)?;
        let unpacked = (report.raw_count + report.delta_count) as usize;
        total += unpacked;
        if unpacked > 0 {
            observer.event(&SyncEvent::ObjectsUnpacked { count: unpacked });
        }
        verify_new_object_signatures(store, &report.stored, require_signed)?;
        applied.insert(&entry.key);
        std::fs::remove_file(path)?;
    }
    drop(staged);
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observer::NoopObserver;
    use crate::packmap::download_packlist_node;
    use crate::source::TransportSource;
    use mkit_core::hash;
    use mkit_core::object::Object;
    use mkit_core::pack;
    use mkit_core::protocol::Transport as _;
    use mkit_core::transfer;
    use mkit_transport_memory::MemoryTransport;

    fn h(seed: &str) -> Hash {
        hash::hash(seed.as_bytes())
    }

    #[test]
    fn requested_pack_identity_rejects_valid_substitute_before_unpack() {
        use mkit_core::layout::RepoLayout;
        use mkit_core::object::Blob;
        use mkit_core::pack::PackWriter;

        let objects = [
            Object::Blob(Blob {
                data: b"first".to_vec(),
            }),
            Object::Blob(Blob {
                data: b"second".to_vec(),
            }),
        ];
        let mut a = PackWriter::new();
        let mut b = PackWriter::new();
        for object in &objects {
            a.push_raw(
                object.id().unwrap(),
                &mkit_core::serialize::serialize(object).unwrap(),
            )
            .unwrap();
        }
        for object in objects.iter().rev() {
            b.push_raw(
                object.id().unwrap(),
                &mkit_core::serialize::serialize(object).unwrap(),
            )
            .unwrap();
        }
        let a = a.finish().unwrap();
        let b = b.finish().unwrap();
        let key = pack::pack_key(&a);
        assert_ne!(key, pack::pack_key(&b));
        let tx = MemoryTransport::new();
        tx.upload_pack(&b, &PackKey::from_hash(key)).unwrap();
        let td = tempfile::tempdir().unwrap();
        let applied = AppliedPacks::load(&RepoLayout::single(td.path()), "origin").unwrap();

        assert!(matches!(
            download_pack_chain(
                &TransportSource::new(&tx),
                &NoopObserver,
                "main",
                &[key],
                &applied,
                None
            ),
            Err(SyncError::Source(crate::SourceError::InvalidResponse))
        ));
        assert!(!applied.contains(&PackKey::from_hash(key)));
    }

    #[test]
    fn requested_packlist_identity_rejects_substitute() {
        let tx = MemoryTransport::new();
        let a = transfer::encode_packlist(None, &[h("pack-a")]).unwrap();
        let b = transfer::encode_packlist(None, &[h("pack-b")]).unwrap();
        let key = hash::hash(&a);
        tx.upload_blob(&b, &PackKey::from_hash(key)).unwrap();
        assert!(matches!(
            download_packlist_node(&TransportSource::new(&tx), key, "refs/heads/main"),
            Err(SyncError::Source(crate::SourceError::InvalidResponse))
        ));
    }

    #[test]
    fn fetch_retains_at_most_one_downloaded_pack() {
        let tx = MemoryTransport::new();
        let bytes = vec![0xAB; 1024 * 1024];
        let key = hash::hash(&bytes);
        tx.upload_pack(&bytes, &PackKey::from_hash(key)).unwrap();
        let td = tempfile::tempdir().unwrap();
        let applied =
            AppliedPacks::load(&mkit_core::layout::RepoLayout::single(td.path()), "origin")
                .unwrap();
        PEAK_RETAINED_PACK_BYTES.with(|peak| peak.set(0));
        let downloaded = download_pack_chain(
            &TransportSource::new(&tx),
            &NoopObserver,
            "main",
            &vec![key; 32],
            &applied,
            None,
        )
        .unwrap();
        let peak = PEAK_RETAINED_PACK_BYTES.with(std::cell::Cell::get);
        assert!(
            peak <= bytes.len(),
            "retained {peak} bytes for one-MiB packs"
        );
        drop(downloaded);
    }

    #[test]
    fn fetch_staging_budget_failure_cleans_every_partial_file() {
        let tx = MemoryTransport::new();
        let bytes = vec![0xAB; 128];
        let key = hash::hash(&bytes);
        tx.upload_pack(&bytes, &PackKey::from_hash(key)).unwrap();
        let td = tempfile::tempdir().unwrap();
        let applied =
            AppliedPacks::load(&mkit_core::layout::RepoLayout::single(td.path()), "origin")
                .unwrap();
        let result = download_pack_chain_with_limits(
            &TransportSource::new(&tx),
            &NoopObserver,
            "main",
            &[key, key],
            &applied,
            128,
            Some(td.path()),
        );
        assert!(
            matches!(result, Err(SyncError::Io(ref error)) if error.kind() == std::io::ErrorKind::StorageFull)
        );
        assert_eq!(std::fs::read_dir(td.path()).unwrap().count(), 0);
        assert!(!applied.contains(&PackKey::from_hash(key)));
    }

    #[test]
    fn fetch_staging_drop_removes_successful_downloads() {
        let tx = MemoryTransport::new();
        let bytes = b"downloaded object bytes";
        let key = hash::hash(bytes);
        tx.upload_pack(bytes, &PackKey::from_hash(key)).unwrap();
        let td = tempfile::tempdir().unwrap();
        let applied =
            AppliedPacks::load(&mkit_core::layout::RepoLayout::single(td.path()), "origin")
                .unwrap();
        let staged = download_pack_chain_with_limits(
            &TransportSource::new(&tx),
            &NoopObserver,
            "main",
            &[key],
            &applied,
            1024,
            Some(td.path()),
        )
        .unwrap();
        assert_eq!(
            std::fs::read(staged.directory.path().join("0")).unwrap(),
            bytes
        );
        assert_eq!(staged.bytes, bytes.len() as u64);
        drop(staged);
        assert_eq!(std::fs::read_dir(td.path()).unwrap().count(), 0);
    }

    #[test]
    fn fetch_staging_digest_failure_cleans_prior_downloads() {
        let tx = MemoryTransport::new();
        let valid = b"valid first bytes";
        let first = hash::hash(valid);
        let wrong = h("missing expected bytes");
        tx.upload_pack(valid, &PackKey::from_hash(first)).unwrap();
        tx.upload_pack(b"substitute", &PackKey::from_hash(wrong))
            .unwrap();
        let td = tempfile::tempdir().unwrap();
        let applied =
            AppliedPacks::load(&mkit_core::layout::RepoLayout::single(td.path()), "origin")
                .unwrap();
        assert!(matches!(
            download_pack_chain_with_limits(
                &TransportSource::new(&tx),
                &NoopObserver,
                "main",
                &[first, wrong],
                &applied,
                1024,
                Some(td.path())
            ),
            Err(SyncError::Source(crate::SourceError::InvalidResponse))
        ));
        assert_eq!(std::fs::read_dir(td.path()).unwrap().count(), 0);
    }
}
