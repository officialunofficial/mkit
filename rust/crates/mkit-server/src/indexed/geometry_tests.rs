//! Producer and verification parity at the indexed canonical boundary.
use super::*;
use crate::indexed::geometry;

fn inline_result(
    rig: &Rig,
    ticket: &TicketV1,
    id: Hash,
    head: Hash,
) -> Result<crate::indexed::verify::StagedCommits, crate::ServerError> {
    block_on(crate::indexed::verify::verify_ticketed(
        rig.blobs.as_ref(),
        rig.store.as_ref(),
        rig.shards.as_ref(),
        &rig.repo,
        &rig.source(),
        std::slice::from_ref(ticket),
        &[id],
        head,
        rig.cfg,
        rig.clock.as_ref(),
        rig.recorder.as_ref(),
    ))
}

#[test]
fn exact_payload_and_one_over_have_typed_inline_scheduled_parity() {
    for extra in [0, 1] {
        for delta in [false, true] {
            let mut rig = Rig::new();
            rig.limits = SliceLimits::default();
            rig.cfg.extract_min_bytes = 8 << 20;
            let object = Object::Blob(Blob {
                data: vec![42; (1 << 20) + extra],
            });
            let id = object.id().unwrap();
            let raw = serialize(&object).unwrap();
            let (tree, commit, head) = tree_head(&[id]);
            let mut writer = PackWriter::new();
            if delta {
                let base = serialize(&Object::Blob(Blob {
                    data: vec![41; 1 << 20],
                }))
                .unwrap();
                writer.push_raw(hash(&base), &base).unwrap();
                let stream = mkit_core::delta::encode(&base, &raw).unwrap();
                assert!(stream.len() as u64 > geometry::CANONICAL_BYTES);
                writer.push_delta(&hash(&base), &stream).unwrap();
            } else {
                writer.push_raw(id, &raw).unwrap();
            }
            for object in [tree, commit] {
                writer
                    .push_raw(object.id().unwrap(), &serialize(&object).unwrap())
                    .unwrap();
            }
            let bytes = writer.finish().unwrap();
            let (ticket, ticket_id) = rig.add(&bytes);
            assert!(rig.check(&[(&ticket, ticket_id)], head).is_err());
            rig.drive(|r| r.finished(&ticket.pack_id));
            let scheduled = rig.check(&[(&ticket, ticket_id)], head);
            let oracle = Rig::new();
            let (ticket, ticket_id) = oracle.add(&bytes);
            let inline = inline_result(&oracle, &ticket, ticket_id, head);
            if extra == 0 {
                assert_eq!(scheduled.unwrap(), inline.unwrap());
            } else {
                let error = scheduled.unwrap_err();
                assert_eq!(error.code(), crate::Code::InvalidArgument);
                assert_eq!(error.public_message(), "pack exceeds indexed decode budget");
                let native_error = inline.unwrap_err();
                assert_eq!(error.code(), native_error.code());
                assert_eq!(error.public_message(), native_error.public_message());
                assert_eq!(
                    rig.job(&ticket.pack_id).unwrap().outcome,
                    Some(crate::indexed::checkpoint::Outcome::DecodeBudget)
                );
            }
        }
    }
}

#[test]
fn cli_ingest_exact_file_verifies_extracts_and_acquires_preservation_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("exact.bin");
    let data = vec![83; 1 << 20];
    std::fs::write(&file, &data).unwrap();
    let store =
        mkit_core::store::ObjectStore::init(&mkit_core::layout::RepoLayout::single(dir.path()))
            .unwrap();
    let id = mkit_core::worktree::hash_file(&store, &file).unwrap();
    let canonical = store.read(&id).unwrap();
    assert_eq!(canonical.len() as u64, geometry::CANONICAL_BYTES);
    let object = mkit_core::serialize::deserialize(&canonical).unwrap();
    assert!(matches!(object, Object::Blob(_)));
    let (tree, commit, head) = tree_head(&[id]);
    let bytes = pack(&[object, tree, commit]);
    let mut rig = Rig::new();
    rig.limits = SliceLimits::default();
    let (ticket, ticket_id) = rig.add(&bytes);
    assert!(rig.check(&[(&ticket, ticket_id)], head).is_err());
    drive(&rig, &TestExtraction::new(&rig), &[ticket.pack_id]);
    rig.check(&[(&ticket, ticket_id)], head).unwrap();
    assert_eq!(
        read_blob(&rig.blobs, &BlobKey::object(id)),
        Some(data.clone())
    );
    assert_holder(&rig, id);
    let oracle = Rig::new();
    let (ticket, ticket_id) = oracle.add(&bytes);
    inline_result(&oracle, &ticket, ticket_id, head).unwrap();
    assert_eq!(read_blob(&oracle.blobs, &BlobKey::object(id)), Some(data));
    block_on(
        rig.store.apply(
            &rig.shards
                .membership(&rig.repo, &BlobKey::pack(hash(&bytes))),
            Batch::new().put(
                keys::membership(&rig.repo.name, &hash(&bytes)),
                Value::default(),
            ),
        ),
    )
    .unwrap();
    for profile in [
        crate::takedown::acquisition::Profile::scheduled(),
        crate::takedown::acquisition::Profile::inline(2 << 30, 50).unwrap(),
    ] {
        let verified = block_on(crate::takedown::acquisition::resolve(
            rig.blobs.as_ref(),
            rig.store.as_ref(),
            rig.shards.as_ref(),
            &rig.repo,
            id,
            &profile,
            rig.recorder.as_ref(),
        ))
        .unwrap();
        assert_eq!(verified.canonical.as_ref(), canonical);
    }
}

#[test]
fn manifest_and_raw_frame_geometry_includes_all_length_fields() {
    let manifest = Object::ChunkedBlob(ChunkedBlob {
        total_size: u64::MAX,
        chunk_size: 0,
        chunks: vec![[9; 32]; usize::try_from(geometry::MANIFEST_CHUNKS).unwrap()],
    });
    let size = serialize(&manifest).unwrap().len() as u64;
    assert_eq!(
        size,
        geometry::MANIFEST_FRAMING_BYTES + 32 * geometry::MANIFEST_CHUNKS
    );
    assert!(geometry::check_entry(size, size + 5).is_ok());
    assert!(matches!(
        geometry::check_entry(size + 32, size + 37),
        Err(mkit_core::pack::PackError::PackfileTooLarge)
    ));
    assert!(
        geometry::check_entry(geometry::CANONICAL_BYTES, geometry::CANONICAL_BYTES + 5).is_ok()
    );
    assert!(matches!(
        geometry::check_entry(10, geometry::FRAME_BYTES + 1),
        Err(mkit_core::pack::PackError::PackfileTooLarge)
    ));
    assert_eq!(
        geometry::decode_limits(geometry::RESIDENT_BYTES, geometry::FRAME_PAYLOAD_BYTES)
            .max_decoded_bytes,
        geometry::CANONICAL_BYTES
    );
    assert_eq!(
        geometry::decode_limits(geometry::RESIDENT_BYTES, 64 << 10).max_decoded_bytes,
        geometry::CANONICAL_BYTES
    );
}

#[cfg(feature = "pack-ruzstd")]
#[test]
fn compressed_exact_blob_crossing_read_window_matches_inline_and_preservation() {
    let object = Object::Blob(Blob {
        data: vec![57; 1 << 20],
    });
    let raw = serialize(&object).unwrap();
    let id = object.id().unwrap();
    let (tree, commit, head) = tree_head(&[id]);
    let mut writer = PackWriter::new_raw_only();
    for tag in 0..15 {
        let filler = Object::Blob(Blob {
            data: vec![tag; 1 << 20],
        });
        writer
            .push_raw(filler.id().unwrap(), &serialize(&filler).unwrap())
            .unwrap();
    }
    let prefix = writer.finish().unwrap();
    let mut bytes = prefix[..prefix.len() - 32].to_vec();
    bytes[4..8].copy_from_slice(&2u32.to_le_bytes());
    bytes[8..12].copy_from_slice(&18u32.to_le_bytes());
    // A valid zstd stream of raw RFC blocks; it needs no C encoder feature.
    let mut zstd = vec![0x28, 0xb5, 0x2f, 0xfd, 0, 0x68];
    let count = raw.chunks(128 << 10).len();
    for (index, piece) in raw.chunks(128 << 10).enumerate() {
        let block = (u32::try_from(piece.len()).unwrap() << 3) | u32::from(index + 1 == count);
        zstd.extend_from_slice(&block.to_le_bytes()[..3]);
        zstd.extend_from_slice(piece);
    }
    let offset = bytes.len() as u64;
    bytes.push(3);
    bytes.extend_from_slice(&u32::try_from(zstd.len() + 4).unwrap().to_le_bytes());
    bytes.extend_from_slice(&u32::try_from(raw.len()).unwrap().to_le_bytes());
    bytes.extend_from_slice(&zstd);
    assert!(offset < geometry::FRAME_PAYLOAD_BYTES);
    assert!(bytes.len() as u64 > geometry::FRAME_PAYLOAD_BYTES);
    for object in [tree, commit] {
        let canonical = serialize(&object).unwrap();
        bytes.push(0);
        bytes.extend_from_slice(&u32::try_from(canonical.len()).unwrap().to_le_bytes());
        bytes.extend_from_slice(&canonical);
    }
    bytes.extend_from_slice(&hash(&bytes));
    let mut rig = Rig::new();
    rig.cfg.extract_min_bytes = 8 << 20;
    rig.limits = SliceLimits::default();
    let (ticket, ticket_id) = rig.add(&bytes);
    rig.check(&[(&ticket, ticket_id)], head).unwrap_err();
    rig.drive(|r| r.finished(&ticket.pack_id));
    let scheduled = rig.check(&[(&ticket, ticket_id)], head).unwrap();
    let mut oracle = Rig::new();
    oracle.cfg = rig.cfg;
    let (ticket, ticket_id) = oracle.add(&bytes);
    assert_eq!(
        scheduled,
        inline_result(&oracle, &ticket, ticket_id, head).unwrap()
    );
    block_on(
        rig.store.apply(
            &rig.shards
                .membership(&rig.repo, &BlobKey::pack(hash(&bytes))),
            Batch::new().put(
                keys::membership(&rig.repo.name, &hash(&bytes)),
                Value::default(),
            ),
        ),
    )
    .unwrap();
    let verified = block_on(crate::takedown::acquisition::resolve(
        rig.blobs.as_ref(),
        rig.store.as_ref(),
        rig.shards.as_ref(),
        &rig.repo,
        id,
        &crate::takedown::acquisition::Profile::scheduled(),
        rig.recorder.as_ref(),
    ))
    .unwrap();
    assert_eq!(verified.canonical.as_ref(), raw);
}
