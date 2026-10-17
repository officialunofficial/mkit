//! Portable length and earlier-delta eligibility vectors.
#![allow(clippy::unwrap_used)]
use mkit_core::pack::{DecodeLimits, NoExternalBases, PackEntries, PackError, decode_entries_with};

#[test]
fn unsigned_payload_boundaries_do_not_wrap_or_allocate_claims() {
    for bytes in [
        include_bytes!("../fixtures/framing/payload-high-bit.bin").as_slice(),
        include_bytes!("../fixtures/framing/payload-u32-max.bin").as_slice(),
    ] {
        assert!(matches!(
            PackEntries::new(bytes),
            Err(PackError::UnexpectedEof)
        ));
    }
}

#[test]
fn earlier_reconstructed_delta_is_an_eligible_base() {
    let pack = include_bytes!("../fixtures/framing/earlier-delta-base.bin");
    let mut objects = Vec::new();
    let report = decode_entries_with(
        pack,
        &mut NoExternalBases,
        DecodeLimits::default(),
        |entry| {
            objects.push(entry.bytes.to_vec());
            Ok(())
        },
    )
    .unwrap();
    assert_eq!((report.raw_count, report.delta_count), (1, 2));
    assert_eq!(&objects[0][10..], b"base");
    assert_eq!(&objects[1][10..], b"middle");
    assert_eq!(&objects[2][10..], b"target");
    assert!(matches!(
        decode_entries_with(
            include_bytes!("../fixtures/framing/later-delta-base.bin"),
            &mut NoExternalBases,
            DecodeLimits::default(),
            |_| Ok(())
        ),
        Err(PackError::DeltaBaseMissing(_))
    ));
}
