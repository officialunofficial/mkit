//! The portable runner carries exactly the authoritative golden vector.
#[test]
fn packaged_admission_fixture_matches_golden() {
    assert_eq!(
        include_bytes!("../fixtures/admission-challenge.bin").as_slice(),
        include_bytes!("../../../tests/golden/transport/admission-challenge.bin").as_slice(),
    );
}
