//! The release guard rejects test features and compiled test markers.
use std::{fs, process::Command};
#[test]
fn release_guard_rejects_stubs_and_worker_test_vars() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let dir = tempfile::tempdir().unwrap();
    let binary = dir.path().join("mkit");
    let log = dir.path().join("build.jsonl");
    let artifact = |features: Vec<&str>| serde_json::json!({"reason":"compiler-artifact","package_id":"path+file:///test#mkit-cli@0.4.2","features":features,"target":{"name":"mkit","kind":["bin"]},"executable":binary});
    for (features, marker, allowed) in [
        (vec![], "release", true),
        (vec!["stubs"], "release", false),
        (vec![], "/__stub/mode", false),
        (vec![], "TEST_OUTBOX_BACKLOG_ROWS", false),
        (vec![], "TEST_TICKET_TTL_MS", false),
    ] {
        fs::write(&binary, marker).unwrap();
        fs::write(&log, format!("{}\n", artifact(features))).unwrap();
        let out = Command::new("bash")
            .arg(root.join("scripts/check-release-artifact-features.sh"))
            .arg(&log)
            .arg(&binary)
            .output()
            .unwrap();
        assert_eq!(
            out.status.success(),
            allowed,
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}
