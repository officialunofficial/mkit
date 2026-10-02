use super::Profile;

#[test]
fn profiles_check_overflow_and_report_distinct_runtime_residency() {
    assert!(Profile::inline(u64::MAX, 50).is_err());
    assert!(Profile::inline(1 << 20, 0).is_err());
    assert_eq!(Profile::scheduled().resident_upper_bound(), 48 << 20);
    assert_eq!(
        Profile::inline(2 << 30, 50).unwrap().resident_upper_bound(),
        (16 << 30) + (128 << 20)
    );
}

#[test]
fn preservation_profiles_share_canonical_and_frame_admission() {
    let scheduled = Profile::scheduled();
    let inline = Profile::inline(2 << 30, 50).unwrap();
    for profile in [scheduled, inline] {
        assert_eq!(
            profile.limits.max_decoded_bytes,
            crate::indexed::geometry::CANONICAL_BYTES
        );
        assert_eq!(
            profile.limits.max_frame_bytes,
            crate::indexed::geometry::FRAME_BYTES
        );
    }
}
