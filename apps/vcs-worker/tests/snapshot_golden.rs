#![cfg(feature = "managed-access")]

use mkit_vcs_worker::snapshot_wire::{
    BeginSnapshot, CleanupReply, CleanupSnapshots, ContinueSnapshot, GetSnapshotJob, JobProgress,
    JobReply, PendingReply, decode,
};

#[test]
fn owner_snapshot_endpoint_bytes_and_manifest_are_pinned() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../rust/tests/golden/hosted-snapshots");
    let manifest = std::fs::read_to_string(root.join("MANIFEST.txt")).unwrap();
    let mut names = std::collections::BTreeSet::new();
    for line in manifest.lines().filter(|line| !line.starts_with('#')) {
        let (digest, name) = line.split_once("  ").unwrap();
        assert!(names.insert(name));
        let bytes = std::fs::read(root.join(name)).unwrap();
        assert_eq!(
            mkit_vcs_worker::hashing::blake3_hex(&bytes),
            digest,
            "{name}"
        );
        assert!(bytes.ends_with(b"\n"));
        if name.ends_with("-response.json") {
            assert!(
                serde_json::from_slice::<serde_json::Value>(&bytes)
                    .unwrap()
                    .is_object()
            );
            continue;
        }
        let meta: serde_json::Value = serde_json::from_slice(
            &std::fs::read(root.join(name.replace(".json", ".meta.json"))).unwrap(),
        )
        .unwrap();
        assert_eq!(meta["method"], "POST");
        assert_eq!(
            meta["path"],
            format!(
                "/mkit/host/v1/{}",
                match name {
                    "begin.json" => "BeginSnapshot",
                    "continue.json" | "invalid-decimal.json" => "ContinueSnapshot",
                    "get.json" | "invalid-duplicate.json" => "GetSnapshotJob",
                    "cancel.json" => "CancelSnapshot",
                    "cleanup.json" => "CleanupSnapshots",
                    _ => panic!("unexpected vector {name}"),
                }
            )
        );
        assert!(root.join(meta["response"].as_str().unwrap()).is_file());
        match name {
            "begin.json" => assert!(decode::<BeginSnapshot>(&bytes).unwrap().validate()),
            "continue.json" | "cancel.json" => {
                assert!(decode::<ContinueSnapshot>(&bytes).unwrap().validate())
            }
            "get.json" => assert!(decode::<GetSnapshotJob>(&bytes).unwrap().validate()),
            "cleanup.json" => assert!(decode::<CleanupSnapshots>(&bytes).unwrap().validate()),
            "invalid-decimal.json" => {
                assert!(!decode::<ContinueSnapshot>(&bytes).unwrap().validate())
            }
            "invalid-duplicate.json" => assert!(decode::<GetSnapshotJob>(&bytes).is_err()),
            _ => unreachable!(),
        }
    }
    assert_eq!(names.len(), 22);
    let id = "1".repeat(64);
    let progress = JobProgress {
        catalog_packs: "0".into(),
        catalog_entries: "0".into(),
        reached_objects: "0".into(),
        reached_bytes: "0".into(),
        work_units: "0".into(),
        attempts: "0".into(),
        reserved_io_bytes: "0".into(),
        r2_operations: "0".into(),
    };
    let begin = JobReply {
        version: 1,
        job_id: id.clone(),
        job_generation: "1".into(),
        revision: "0".into(),
        state: "catalog".into(),
        progress,
    };
    assert_eq!(
        format!("{}\n", serde_json::to_string(&begin).unwrap()).as_bytes(),
        std::fs::read(root.join("begin-response.json")).unwrap()
    );
    let pending = PendingReply {
        version: 1,
        code: "in_progress",
        job_id: id,
    };
    assert_eq!(
        format!("{}\n", serde_json::to_string(&pending).unwrap()).as_bytes(),
        std::fs::read(root.join("pending-response.json")).unwrap()
    );
    let cleanup = CleanupReply {
        version: 1,
        cleanup_revision: "1".into(),
        affected_rows: "0".into(),
        has_more: false,
    };
    assert_eq!(
        format!("{}\n", serde_json::to_string(&cleanup).unwrap()).as_bytes(),
        std::fs::read(root.join("cleanup-response.json")).unwrap()
    );
}
