#![allow(clippy::unwrap_used)]
use super::*;
#[test]
fn v050_stored_encodings() {
    for (expected, recovery, reconcile) in [
        (
            crate::stored_golden::hex_fixture!("store-watermark-WatermarkCheckpoint-00"),
            false,
            false,
        ),
        (
            crate::stored_golden::hex_fixture!("store-watermark-WatermarkCheckpoint-10"),
            true,
            false,
        ),
        (
            crate::stored_golden::hex_fixture!("store-watermark-WatermarkCheckpoint-01"),
            false,
            true,
        ),
        (
            crate::stored_golden::hex_fixture!("store-watermark-WatermarkCheckpoint-11"),
            true,
            true,
        ),
    ] {
        let row = WatermarkCheckpoint::decode(expected.as_bytes()).unwrap();
        assert_eq!(
            row.coordinator,
            Partition::Coordinator(crate::NamespaceKey::deployment_default())
        );
        assert_eq!(row.ceiling_ms, 200);
        assert_eq!(row.minimum_ms, 150);
        assert_eq!(row.cursor.as_bytes(), b"ls\0cursor");
        assert_eq!(row.recovery_generation.0.is_some(), recovery);
        assert_eq!(row.recovery_generation.1.is_some(), reconcile);
        assert_eq!(row.encode(), expected.as_bytes());
    }
}
