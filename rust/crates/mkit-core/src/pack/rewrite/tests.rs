#![allow(clippy::unwrap_used)]

use super::*;
use crate::pack::{NoExternalBases, PackEntries, PackEntry, PackReader, TRAILER_LEN};
use crate::{
    delta, hash,
    object::{Blob, Object},
    serialize,
};
use proptest::prelude::*;
use std::collections::HashMap;

#[derive(Clone, Default)]
struct Bases {
    objects: HashMap<Hash, Vec<u8>>,
    fetched: Vec<Hash>,
}

impl DeltaBaseSource for Bases {
    fn base(&mut self, id: &Hash) -> Result<Option<Vec<u8>>, PackError> {
        self.fetched.push(*id);
        Ok(self.objects.get(id).cloned())
    }
}

fn blob(data: &[u8]) -> Vec<u8> {
    serialize::serialize(&Object::Blob(Blob {
        data: data.to_vec(),
    }))
    .unwrap()
}

fn collect<B: DeltaBaseSource>(pack: &[u8], bases: &mut B) -> Vec<(Hash, Vec<u8>)> {
    let mut objects = Vec::new();
    decode_entries_with(pack, bases, DecodeLimits::default(), |e| {
        objects.push((e.id, e.bytes.to_vec()));
        Ok(())
    })
    .unwrap();
    objects
}

fn rewrite(pack: &[u8], excluded: &[Hash]) -> Rewritten {
    rewrite_excluding(
        pack,
        &excluded.iter().copied().collect(),
        &mut NoExternalBases,
        DecodeLimits::default(),
    )
    .unwrap()
}

fn chain() -> (Vec<u8>, Vec<(Hash, Vec<u8>)>) {
    let objects: Vec<_> = (0..3)
        .map(|i| {
            let mut data = vec![17; 2048];
            data[100] = i;
            let bytes = blob(&data);
            (hash::hash(&bytes), bytes)
        })
        .collect();
    let mut w = PackWriter::new();
    w.push_raw(objects[0].0, &objects[0].1).unwrap();
    for pair in objects.windows(2) {
        w.push_delta(&pair[0].0, &delta::encode(&pair[0].1, &pair[1].1).unwrap())
            .unwrap();
    }
    (w.finish().unwrap(), objects)
}

#[test]
fn rewrite_through_taken_down_base_still_decodes() {
    let (pack, objects) = chain();
    let result = rewrite(&pack, &[objects[0].0]);
    assert_eq!(result.removed, vec![objects[0].0]);
    assert_eq!(result.rawified, vec![objects[1].0]);
    assert!(!result.unchanged);
    assert_eq!(collect(&result.bytes, &mut NoExternalBases), objects[1..]);
    let entries: Vec<_> = PackEntries::new(&result.bytes)
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert!(matches!(entries[0], PackEntry::Raw { .. }));
    assert!(matches!(entries[1], PackEntry::Delta { base, .. } if base == objects[1].0));
    let dir = tempfile::tempdir().unwrap();
    let store =
        crate::store::ObjectStore::init(&crate::layout::RepoLayout::single(dir.path())).unwrap();
    assert_eq!(
        PackReader::read(&result.bytes, &store).unwrap().stored,
        vec![objects[1].0, objects[2].0]
    );
}

#[cfg(feature = "pack-zstd")]
#[test]
fn compression_respects_uncompressed_claim_cap() {
    let bytes = vec![17; 4096];
    assert!(super::super::maybe_compress_capped(&bytes, bytes.len() - 1).is_none());
    assert!(super::super::maybe_compress_capped(&bytes, bytes.len()).is_some());
}

#[test]
fn rewrite_retained_uncompressed_delta_is_readable() {
    let base = blob(b"base");
    let target = blob(b"target");
    let removed = blob(b"unrelated");
    let base_id = hash::hash(&base);
    let target_id = hash::hash(&target);
    let mut w = PackWriter::new();
    w.push_raw(base_id, &base).unwrap();
    // This stream is below MIN_COMPRESS_LEN, so the input is 0x02 in
    // both native and decode-only builds.
    w.push_delta(&base_id, &delta::encode(&base, &target).unwrap())
        .unwrap();
    w.push_raw(hash::hash(&removed), &removed).unwrap();
    let pack = w.finish().unwrap();
    assert_eq!(pack[HEADER_LEN + ENTRY_FRAME_LEN + base.len()], 0x02);
    let result = rewrite(&pack, &[hash::hash(&removed)]);
    assert!(!result.unchanged);
    assert!(result.rawified.is_empty());
    assert_eq!(
        collect(&result.bytes, &mut NoExternalBases),
        vec![(base_id, base), (target_id, target)]
    );
    let dir = tempfile::tempdir().unwrap();
    let store =
        crate::store::ObjectStore::init(&crate::layout::RepoLayout::single(dir.path())).unwrap();
    assert_eq!(
        PackReader::read(&result.bytes, &store).unwrap().stored,
        vec![base_id, target_id]
    );
}

#[test]
fn external_excluded_base_is_rawified() {
    let (pack, objects) = chain();
    let mut w = PackWriter::new();
    w.push_delta(
        &objects[0].0,
        &delta::encode(&objects[0].1, &objects[1].1).unwrap(),
    )
    .unwrap();
    let external_pack = w.finish().unwrap();
    let mut bases = Bases::default();
    bases.objects.insert(objects[0].0, objects[0].1.clone());
    let result = rewrite_excluding(
        &external_pack,
        &HashSet::from([objects[0].0]),
        &mut bases,
        DecodeLimits::default(),
    )
    .unwrap();
    assert!(result.removed.is_empty());
    assert_eq!(result.rawified, vec![objects[1].0]);
    assert_eq!(bases.fetched, vec![objects[0].0]);
    assert_eq!(collect(&result.bytes, &mut NoExternalBases), objects[1..2]);
    assert_eq!(rewrite(&pack, &[objects[0].0]).rawified, result.rawified);
}

#[test]
fn unchanged_is_verbatim_and_absent_exclusions_do_not_lookup() {
    let (pack, _) = chain();
    let empty = rewrite(&pack, &[]);
    assert!(empty.unchanged);
    assert_eq!(empty.bytes, pack);
    let mut bases = Bases::default();
    let absent = rewrite_excluding(
        &pack,
        &HashSet::from([[99; 32]]),
        &mut bases,
        DecodeLimits::default(),
    )
    .unwrap();
    assert_eq!(absent, empty);
    assert!(bases.fetched.is_empty());
    assert!(rewrite(&PackWriter::new().finish().unwrap(), &[[99; 32]]).unchanged);
}

#[test]
fn denied_and_absent_bases_have_identical_errors() {
    struct Scoped(Bases);
    impl DeltaBaseSource for Scoped {
        fn base(&mut self, id: &Hash) -> Result<Option<Vec<u8>>, PackError> {
            // Global presence does not establish repository membership.
            self.0.base(id).map(|_| None)
        }
    }
    let (_, objects) = chain();
    let mut w = PackWriter::new();
    w.push_delta(
        &objects[0].0,
        &delta::encode(&objects[0].1, &objects[1].1).unwrap(),
    )
    .unwrap();
    let pack = w.finish().unwrap();
    let errors: Vec<_> = [true, false]
        .into_iter()
        .map(|has_base| {
            let err = rewrite_excluding(
                &pack,
                &HashSet::from([objects[0].0]),
                &mut Scoped(Bases {
                    objects: if has_base {
                        HashMap::from([(objects[0].0, objects[0].1.clone())])
                    } else {
                        HashMap::new()
                    },
                    fetched: Vec::new(),
                }),
                DecodeLimits::default(),
            )
            .unwrap_err();
            assert!(matches!(err, PackError::DeltaBaseMissing(_)));
            err.to_string()
        })
        .collect();
    assert_eq!(errors[0], errors[1]);
}

#[test]
fn duplicate_entries_and_all_excluded() {
    let (pack, objects) = chain();
    let mut w = PackWriter::new();
    for _ in 0..2 {
        w.push_raw(objects[0].0, &objects[0].1).unwrap();
        w.push_delta(
            &objects[0].0,
            &delta::encode(&objects[0].1, &objects[1].1).unwrap(),
        )
        .unwrap();
    }
    let result = rewrite(&w.finish().unwrap(), &[objects[0].0]);
    assert_eq!(result.removed, vec![objects[0].0]);
    assert_eq!(result.rawified, vec![objects[1].0; 2]);
    assert_eq!(
        collect(&result.bytes, &mut NoExternalBases),
        vec![objects[1].clone(); 2]
    );
    let result = rewrite(&pack, &objects.iter().map(|o| o.0).collect::<Vec<_>>());
    assert_eq!(
        result.removed,
        objects.iter().map(|o| o.0).collect::<Vec<_>>()
    );
    assert!(result.rawified.is_empty());
    assert_eq!(result.bytes, PackWriter::new().finish().unwrap());
}

fn seal(mut body: Vec<u8>) -> Vec<u8> {
    body.extend_from_slice(&hash::hash(&body));
    body
}

#[test]
fn delta_bomb_rejected_before_sink_or_writer_grows() {
    let base = blob(b"base");
    let id = hash::hash(&base);
    let mut w = PackWriter::new();
    w.push_raw(id, &base).unwrap();
    let mut stream = vec![delta::STREAM_VERSION];
    stream.extend_from_slice(&u32::try_from(base.len()).unwrap().to_le_bytes());
    stream.extend_from_slice(&(512u32 << 20).to_le_bytes());
    for _ in 0..3 {
        w.push_delta(&id, &stream).unwrap();
    }
    let pack = w.finish().unwrap();
    assert!(pack.len() < 256);
    assert_before_sink_rejection(&pack, DecodeLimits::default());
}

fn assert_before_sink_rejection(pack: &[u8], limits: DecodeLimits) {
    let excluded = HashSet::new();
    let mut state = Rewrite::new(pack, &excluded);
    let mut sink_calls = 0;
    let err = decode_entries_with(pack, &mut NoExternalBases, limits, |entry| {
        sink_calls += 1;
        state.accept(&entry)
    })
    .unwrap_err();
    assert!(matches!(err, PackError::PackfileTooLarge));
    assert_eq!(sink_calls, 0);
    assert_eq!(
        state.writer.finish().unwrap(),
        PackWriter::new().finish().unwrap()
    );
    assert!(matches!(
        rewrite_excluding(pack, &excluded, &mut NoExternalBases, limits).unwrap_err(),
        PackError::PackfileTooLarge
    ));
}

#[test]
fn compressed_claim_rejected_before_decompression() {
    let mut body = b"MKIT".to_vec();
    body.extend_from_slice(&2u32.to_le_bytes());
    body.extend_from_slice(&1u32.to_le_bytes());
    body.push(0x03);
    body.extend_from_slice(&12u32.to_le_bytes());
    body.extend_from_slice(&(512u32 << 20).to_le_bytes());
    body.extend_from_slice(&[0; 8]);
    assert_before_sink_rejection(
        &seal(body),
        DecodeLimits::default().with_max_decoded_bytes(1 << 20),
    );
}

#[test]
fn external_base_charges_release_at_last_use() {
    let target = blob(b"small target");
    let mut bases = Bases::default();
    let mut deltas = Vec::new();
    for byte in [1, 2] {
        let bytes = blob(&vec![byte; 600 * 1024]);
        let id = hash::hash(&bytes);
        deltas.push((id, delta::encode(&bytes, &target).unwrap()));
        bases.objects.insert(id, bytes);
    }
    let limits = DecodeLimits::default().with_max_decoded_bytes(1 << 20);
    for (order, succeeds) in [([0, 0, 1], true), ([0, 1, 0], false)] {
        let mut w = PackWriter::new();
        for i in order {
            w.push_delta(&deltas[i].0, &deltas[i].1).unwrap();
        }
        let pack = w.finish().unwrap();
        let excluded = deltas.iter().map(|d| d.0).collect();
        let result = rewrite_excluding(&pack, &excluded, &mut bases.clone(), limits);
        if succeeds {
            let result = result.unwrap();
            assert_eq!(
                collect(&result.bytes, &mut NoExternalBases),
                vec![(hash::hash(&target), target.clone()); 3]
            );
            assert_eq!(result.rawified.len(), 3);
        } else {
            assert!(matches!(result.unwrap_err(), PackError::PackfileTooLarge));
        }
    }
    let mut w = PackWriter::new();
    w.push_delta(&deltas[0].0, &deltas[0].1).unwrap();
    let err = rewrite_excluding(
        &w.finish().unwrap(),
        &HashSet::from([deltas[0].0]),
        &mut bases,
        limits.with_max_decoded_bytes(512 * 1024),
    )
    .unwrap_err();
    assert!(matches!(err, PackError::PackfileTooLarge));
}

#[test]
fn malformed_input_matches_decoder_even_when_everything_is_excluded() {
    let (pack, objects) = chain();
    let excluded = objects.iter().map(|o| o.0).collect();
    let mut corpus = vec![vec![], vec![0; 44]];
    for pos in [0, 4, 8, 12, 13, pack.len() - 1] {
        let mut bad = pack.clone();
        bad[pos] ^= 0xFF;
        corpus.push(bad.clone());
        if pos < pack.len() - TRAILER_LEN {
            bad.truncate(bad.len() - TRAILER_LEN);
            corpus.push(seal(bad));
        }
    }
    let mut hostile = pack.clone();
    hostile[HEADER_LEN + 1..HEADER_LEN + 5].copy_from_slice(&u32::MAX.to_le_bytes());
    hostile.truncate(hostile.len() - TRAILER_LEN);
    let hostile = seal(hostile);
    assert!(matches!(
        rewrite_excluding(
            &hostile,
            &excluded,
            &mut NoExternalBases,
            DecodeLimits::default()
        )
        .unwrap_err(),
        PackError::UnexpectedEof
    ));
    corpus.push(hostile);
    let mut invalid_object = PackWriter::new();
    invalid_object.push_raw([0; 32], b"not an object").unwrap();
    corpus.push(invalid_object.finish().unwrap());
    for bad in corpus {
        let expected =
            decode_entries_with(&bad, &mut NoExternalBases, DecodeLimits::default(), |_| {
                Ok(())
            })
            .unwrap_err();
        let actual = rewrite_excluding(
            &bad,
            &excluded,
            &mut NoExternalBases,
            DecodeLimits::default(),
        )
        .unwrap_err();
        assert_eq!(format!("{actual:?}"), format!("{expected:?}"));
    }
}

#[test]
fn decoder_errors_precede_deferred_writer_errors() {
    let valid = blob(b"valid first entry");
    let mut w = PackWriter::new();
    w.push_raw(hash::hash(&valid), &valid).unwrap();
    w.push_raw([0; 32], b"not an object").unwrap();
    let pack = w.finish().unwrap();
    let excluded = HashSet::from([hash::hash(&valid)]);
    let mut state = Rewrite::new(&pack, &excluded);
    // Inject a writer cap error instead of allocating a >4 GiB output.
    state.writer_error = Some(PackError::PackfileTooLarge);
    let mut calls = 0;
    let err = decode_entries_with(
        &pack,
        &mut NoExternalBases,
        DecodeLimits::default(),
        |entry| {
            calls += 1;
            state.accept(&entry)
        },
    )
    .unwrap_err();
    assert_eq!(calls, 1);
    assert!(matches!(err, PackError::InvalidObject(_)));
    assert!(matches!(
        state.finish().unwrap_err(),
        PackError::PackfileTooLarge
    ));
}

#[test]
fn unchanged_ignores_a_deferred_writer_error() {
    let (pack, _) = chain();
    let excluded = HashSet::new();
    let mut state = Rewrite::new(&pack, &excluded);
    state.writer_error = Some(PackError::PackfileTooLarge);
    decode_entries_with(
        &pack,
        &mut NoExternalBases,
        DecodeLimits::default(),
        |entry| state.accept(&entry),
    )
    .unwrap();
    assert_eq!(state.finish().unwrap().bytes, pack);
}

#[cfg(any(feature = "pack-zstd", feature = "pack-ruzstd"))]
#[test]
fn committed_compressed_fixtures_rewrite_with_either_decoder() {
    for pack in [
        include_bytes!("../../../../../tests/golden/pack-v2/mixed.bin").as_slice(),
        include_bytes!("../../../../../tests/golden/pack-v2/delta_repeat.bin").as_slice(),
        include_bytes!("../../../../../tests/golden/pack-v2/tree_and_commit.bin").as_slice(),
    ] {
        let original = collect(pack, &mut NoExternalBases);
        let result = rewrite(pack, &[original[0].0]);
        let expected: Vec<_> = original
            .into_iter()
            .filter(|o| o.0 != result.removed[0])
            .collect();
        assert_eq!(collect(&result.bytes, &mut NoExternalBases), expected);
        assert_eq!(result, rewrite(pack, &result.removed));
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]
    #[test]
    fn rewrite_preserves_objects_and_direct_base_rule(
        chains in prop::collection::vec((any::<u8>(), 1usize..=5, any::<bool>()), 1..=3),
        selections in prop::collection::vec(any::<bool>(), 32),
        duplicate in any::<bool>(),
    ) {
        let mut bases = Bases::default();
        let mut w = PackWriter::new();
        let mut entries = Vec::new();
        let mut candidates = Vec::new();
        for (chain_index, (seed, depth, external)) in chains.into_iter().enumerate() {
            let mut data = vec![seed; 2048];
            data[0] = u8::try_from(chain_index).unwrap();
            let mut previous = blob(&data);
            let mut base = hash::hash(&previous);
            candidates.push(base);
            if external { bases.objects.insert(base, previous.clone()); }
            else {
                w.push_raw(base, &previous).unwrap();
                entries.push((base, None));
            }
            for level in 1..=depth {
                // Large, compressible inserts exercise compressed deltas,
                // while unique markers keep each chain's object ids distinct.
                data[512..1536].fill(seed.wrapping_add(u8::try_from(level).unwrap()));
                data[1] = u8::try_from(level).unwrap();
                let target = blob(&data);
                let stream = delta::encode(&previous, &target).unwrap();
                let id = hash::hash(&target);
                w.push_delta(&base, &stream).unwrap();
                entries.push((id, Some(base)));
                candidates.push(id);
                if duplicate {
                    w.push_delta(&base, &stream).unwrap();
                    entries.push((id, Some(base)));
                }
                previous = target;
                base = id;
            }
        }
        let small = blob(b"uncompressed independent object");
        w.push_raw(hash::hash(&small), &small).unwrap();
        entries.push((hash::hash(&small), None));
        candidates.push(hash::hash(&small));
        candidates.push([99;32]);
        let excluded: HashSet<_> = candidates.into_iter().zip(selections).filter_map(|(id, yes)| yes.then_some(id)).collect();
        let pack = w.finish().unwrap();
        let original = collect(&pack, &mut bases.clone());
        let first = rewrite_excluding(&pack, &excluded, &mut bases.clone(), DecodeLimits::default()).unwrap();
        let second = rewrite_excluding(&pack, &excluded, &mut bases.clone(), DecodeLimits::default()).unwrap();
        prop_assert_eq!(&first, &second);
        let expected: Vec<_> = original.into_iter().filter(|o| !excluded.contains(&o.0)).collect();
        // Takedown property: the output decodes without any excluded base.
        let mut scoped = bases.clone();
        scoped.objects.retain(|id, _| !excluded.contains(id));
        prop_assert_eq!(collect(&first.bytes, &mut scoped), expected);
        let mut seen = HashSet::new();
        let removed: Vec<_> = entries.iter().filter_map(|(id, _)| (excluded.contains(id) && seen.insert(*id)).then_some(*id)).collect();
        let rawified: Vec<_> = entries.iter().filter_map(|(id, base)| (!excluded.contains(id) && base.is_some_and(|base| excluded.contains(&base))).then_some(*id)).collect();
        prop_assert_eq!(&first.removed, &removed);
        prop_assert_eq!(&first.rawified, &rawified);
        prop_assert_eq!(first.unchanged, removed.is_empty() && rawified.is_empty());
        if first.unchanged { prop_assert_eq!(first.bytes, pack); }
    }
}
