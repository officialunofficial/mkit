#![allow(clippy::unwrap_used)]
use super::*;
#[test]
fn v050_binary_rows() {
    use crate::stored_golden::hex_fixture;
    let header = hex_fixture!("export-header");
    let record = hex_fixture!("export-record");
    let bytes = [header.as_bytes(), record.as_bytes(), &[0, 0]].concat();
    let (h, mut reader) = ExportReader::new(&bytes).unwrap();
    assert_eq!(encode_export_header(&h).as_ref(), header.as_bytes());
    let row = reader.next().unwrap().unwrap();
    assert_eq!(
        encode_export_record(&row).unwrap().as_ref(),
        record.as_bytes()
    );
    assert!(reader.next().is_none());
}
