#![allow(clippy::unwrap_used)]
use super::*;
#[test]
fn v050_stored_encodings() {
    let expected = crate::stored_golden::hex_fixture!("published-view-Envelope");
    let repo = RepoId {
        namespace: mkit_server::NamespaceKey::deployment_default(),
        name: mkit_server::RepoName::new("sample").unwrap(),
    };
    let partition = D34Shards.ref_index(&repo, "refs/heads/main");
    let row = Envelope::decode(expected.as_bytes(), &partition, 1000).unwrap();
    assert_eq!(row.generation, 2);
    assert_eq!(row.captured_at_ms, 1000);
    assert_eq!(row.valid_until_ms, 61000);
    assert_eq!(row.rows, vec![("refs/heads/main".into(), [2; 32])]);
    assert_eq!(row.encode().unwrap(), expected.as_bytes());
}
