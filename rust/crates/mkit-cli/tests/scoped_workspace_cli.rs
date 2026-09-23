#![allow(clippy::unwrap_used)]

mod common;

use std::fmt::Write as _;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use mkit_core::ClosureMode;
use mkit_core::object::Identity;
use mkit_core::partial::{
    FileReplacement, PartialLimits, RemotePublicationTargetV1, ScopedWorkspaceLayout,
    export_partial_update, prepare_partial_commit, replace_files,
};
use mkit_core::protocol::{PackKey, Transport};
use mkit_core::sign::{KeyPair, save_key, sign_commit, verify_commit};
use mkit_core::transfer::encode_packlist;
use mkit_core::verify::export_closure;
use mkit_core::{Commit, EntryMode, Object, ObjectStore, RepoLayout, Tree, TreeEntry, serialize};
use mkit_transport_file::FileTransport;
use serde_json::Value;

const BASE: &str = "17963c328bb4a65dfffb659125df822a5a8b0aaca309c245c569420e243f8d90";

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/golden/partial_workspace")
        .join(name)
}

fn setup(name: &str) -> (tempfile::TempDir, PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    let workspace = temp.path().join("scoped");
    let xdg = temp.path().join("xdg");
    fs::create_dir(&xdg).unwrap();
    let bundle = fixture(name);
    let output = common::mkit(
        temp.path(),
        &xdg,
        &[
            "workspace",
            "create",
            "--bundle",
            bundle.to_str().unwrap(),
            "--base",
            BASE,
            "--accept-bundle-selection",
            workspace.to_str().unwrap(),
        ],
    );
    assert!(
        output.status.success(),
        "stderr: {}; stdout: {}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    (temp, workspace)
}

#[test]
fn core_created_non_head_target_is_typed_cli_refusal() {
    let temp = tempfile::tempdir().unwrap();
    let scoped = temp.path().join("scoped");
    let xdg = temp.path().join("xdg");
    fs::create_dir(&xdg).unwrap();
    let bundle = fs::read(fixture("plain_file.bin")).unwrap();
    let base = mkit_core::hash::from_hex(BASE).unwrap();
    let target =
        RemotePublicationTargetV1::new("mkit+file:///tmp/recipient", "repo", "refs/tags/release")
            .unwrap();
    ScopedWorkspaceLayout::create(
        &scoped,
        base,
        &[vec![b"shallow.txt".to_vec()]],
        &bundle,
        PartialLimits::default(),
        Some(target),
    )
    .unwrap();
    let pushed = common::mkit(&scoped, &xdg, &["workspace", "push"]);
    assert!(!pushed.status.success());
    assert!(String::from_utf8_lossy(&pushed.stderr).contains("refs/heads/"));
}

fn json(cwd: &Path, xdg: &Path, args: &[&str]) -> Value {
    let output = common::mkit(cwd, xdg, args);
    assert!(
        output.status.success(),
        "stderr: {}; stdout: {}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn user_signer(xdg: &Path) -> tempfile::TempDir {
    let home = std::env::var_os("HOME").expect("effective user home");
    let dir = tempfile::tempdir_in(home).unwrap();
    let key_path = dir.path().join("scoped.key");
    save_key(&key_path, &KeyPair::from_seed([29; 32])).unwrap();
    fs::create_dir_all(xdg.join("mkit")).unwrap();
    fs::write(
        xdg.join("mkit/config"),
        format!("signing_key = {}\n", key_path.display()),
    )
    .unwrap();
    dir
}

#[test]
fn offline_commit_signs_stage_a_exports_exact_bytes_and_keeps_working_b() {
    let (temp, workspace) = setup("plain_file.bin");
    let xdg = temp.path().join("xdg");
    let _key_dir = user_signer(&xdg);
    let file = workspace.join("shallow.txt");
    fs::write(&file, b"staged A\n").unwrap();
    json(
        &workspace,
        &xdg,
        &["workspace", "add", "--all", "--format=json"],
    );
    fs::write(&file, b"working B\n").unwrap();
    let committed = json(
        &workspace,
        &xdg,
        &["workspace", "commit", "-m", "offline", "--format=json"],
    );
    assert_eq!(committed["pending_status"], "prepared");
    assert_eq!(committed["coverage"]["verification"], "selected-only");
    let status = json(&workspace, &xdg, &["workspace", "status", "--format=json"]);
    assert_eq!(status["pending"]["candidate"], committed["candidate"]);
    assert_eq!(status["pending"]["status"], "prepared");
    let log = json(&workspace, &xdg, &["workspace", "log", "--format=json"]);
    assert_eq!(log["pending"]["candidate"], committed["candidate"]);
    let duplicate = common::mkit(
        &workspace,
        &xdg,
        &["workspace", "commit", "-m", "again", "--format=json"],
    );
    assert!(!duplicate.status.success());
    let first = temp.path().canonicalize().unwrap().join("update.mkwu");
    let exported = json(
        &workspace,
        &xdg,
        &[
            "workspace",
            "export",
            "--output",
            first.to_str().unwrap(),
            "--format=json",
        ],
    );
    assert_eq!(exported["pending_status"], "prepared");
    let state = ScopedWorkspaceLayout::open(&workspace)
        .unwrap()
        .read_state()
        .unwrap();
    let exact = state.pending_update_bytes().unwrap();
    assert_eq!(fs::read(&first).unwrap(), exact);
    assert_eq!(fs::read(&file).unwrap(), b"working B\n");
    let update =
        mkit_core::partial::PartialUpdate::decode(exact, state.workspace().limits()).unwrap();
    assert_eq!(
        mkit_core::hash::to_hex(update.candidate_id()),
        committed["candidate"]
    );
    let entries = mkit_core::pack::PackEntries::new(update.pack_bytes()).unwrap();
    let mut candidate = None;
    for entry in entries {
        if let mkit_core::pack::PackEntry::Raw { bytes } = entry.unwrap() {
            if let Ok(mkit_core::object::Object::Commit(commit)) =
                mkit_core::deserialize(bytes.as_ref())
            {
                candidate = Some(commit);
            }
        }
    }
    let candidate = candidate.expect("ordinary signed candidate in raw update pack");
    verify_commit(&candidate).unwrap();
    assert_eq!(
        candidate.parents,
        vec![mkit_core::hash::from_hex(BASE).unwrap()]
    );
    assert_eq!(candidate.message, b"offline");
    let repeat = common::mkit(
        &workspace,
        &xdg,
        &["workspace", "export", "--output", first.to_str().unwrap()],
    );
    assert!(!repeat.status.success());
    let inside = common::mkit(
        &workspace,
        &xdg,
        &["workspace", "export", "--output", "inside.mkwu"],
    );
    assert!(!inside.status.success());
    let pending_id = committed["candidate"].as_str().unwrap();
    let no_ack = common::mkit(
        &workspace,
        &xdg,
        &["workspace", "abandon", "--candidate", pending_id],
    );
    assert!(!no_ack.status.success());
    let abandoned = json(
        &workspace,
        &xdg,
        &[
            "workspace",
            "abandon",
            "--candidate",
            pending_id,
            "--acknowledge-possible-publication",
            "--format=json",
        ],
    );
    assert_eq!(abandoned["remote_undo"], false);
    let retained = ScopedWorkspaceLayout::open(&workspace)
        .unwrap()
        .read_state()
        .unwrap();
    assert!(retained.pending().is_none());
    assert!(!retained.stage_is_clean());
    assert_eq!(fs::read(&file).unwrap(), b"working B\n");
}

#[test]
fn missing_scoped_signer_and_noop_leave_no_pending() {
    let (temp, workspace) = setup("plain_file.bin");
    let xdg = temp.path().join("xdg");
    let clean = common::mkit(&workspace, &xdg, &["workspace", "commit", "-m", "empty"]);
    assert!(!clean.status.success());
    fs::write(workspace.join("shallow.txt"), b"edit").unwrap();
    json(
        &workspace,
        &xdg,
        &["workspace", "add", "--all", "--format=json"],
    );
    let missing = common::mkit(&workspace, &xdg, &["workspace", "commit", "-m", "unsigned"]);
    assert!(!missing.status.success());
    assert!(String::from_utf8_lossy(&missing.stderr).contains("absolute signing_key"));
    assert!(
        ScopedWorkspaceLayout::open(&workspace)
            .unwrap()
            .read_state()
            .unwrap()
            .pending()
            .is_none()
    );
}

#[test]
fn file_push_keeps_hidden_base_and_full_clone_reads_candidate() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("source");
    fs::create_dir(&source).unwrap();
    let store = ObjectStore::init(&RepoLayout::single(&source)).unwrap();
    let old = mkit_core::store_file_object(&store, b"old visible").unwrap();
    let hidden = mkit_core::store_file_object(&store, b"hidden source").unwrap();
    let root = store
        .write(
            &serialize(&Object::Tree(Tree {
                entries: vec![
                    TreeEntry {
                        name: b"a.txt".to_vec(),
                        mode: EntryMode::Blob,
                        object_hash: old,
                    },
                    TreeEntry {
                        name: b"hidden.txt".to_vec(),
                        mode: EntryMode::Blob,
                        object_hash: hidden,
                    },
                ],
            }))
            .unwrap(),
        )
        .unwrap();
    let base_key = KeyPair::from_seed([21; 32]);
    let mut base_commit = Commit::new_unannotated(
        root,
        vec![],
        Identity::ed25519(base_key.public.0),
        base_key.public.0,
        b"base".to_vec(),
        1,
        [0; 64],
    );
    base_commit.signature = sign_commit(&base_commit, &base_key).unwrap().0;
    let base = store
        .write(&serialize(&Object::Commit(base_commit)).unwrap())
        .unwrap();
    let selected = vec![vec![b"a.txt".to_vec()]];
    let bundle =
        mkit_core::partial::build_partial_snapshot(&store, base, &selected, &PartialLimits::V1)
            .unwrap();
    let bundle_file = temp.path().join("selected.mkwb");
    fs::write(&bundle_file, bundle.encode(&PartialLimits::V1).unwrap()).unwrap();

    let remote = temp.path().join("remote");
    fs::create_dir(&remote).unwrap();
    let tx = FileTransport::new(&remote);
    let closure = export_closure(&store, &base, ClosureMode::Snapshot).unwrap();
    let packs: Vec<_> = closure
        .packs
        .iter()
        .map(|pack| {
            let digest = mkit_core::hash::hash(pack);
            tx.upload_pack(pack, &PackKey::from_hash(digest)).unwrap();
            digest
        })
        .collect();
    let initial = encode_packlist(None, &packs).unwrap();
    let initial_id = mkit_core::hash::hash(&initial);
    tx.upload_blob(&initial, &PackKey::from_hash(initial_id))
        .unwrap();
    tx.write_ref("refs/heads/main", &base).unwrap();
    tx.write_ref("refs/mkit/packmap/main", &initial_id).unwrap();
    // The transient FileTransport lock directory is not required for reads;
    // publication may recreate it. Exercise a valid root without `.mkit`.
    if remote.join(".mkit").exists() {
        fs::remove_dir_all(remote.join(".mkit")).unwrap();
    }
    assert!(!remote.join(".mkit").exists());

    let scoped = temp.path().join("scoped");
    let xdg = temp.path().join("xdg");
    fs::create_dir(&xdg).unwrap();
    let _key = user_signer(&xdg);
    let created = common::mkit(
        temp.path(),
        &xdg,
        &[
            "workspace",
            "create",
            "--bundle",
            bundle_file.to_str().unwrap(),
            "--base",
            &mkit_core::hash::to_hex(&base),
            "--accept-bundle-selection",
            scoped.to_str().unwrap(),
        ],
    );
    assert!(
        created.status.success(),
        "{}",
        String::from_utf8_lossy(&created.stderr)
    );
    fs::write(scoped.join("a.txt"), b"new visible").unwrap();
    json(
        &scoped,
        &xdg,
        &["workspace", "add", "--all", "--format=json"],
    );
    let committed = json(
        &scoped,
        &xdg,
        &["workspace", "commit", "-m", "edit", "--format=json"],
    );
    let unsupported = common::mkit(
        &scoped,
        &xdg,
        &[
            "workspace",
            "push",
            "--endpoint",
            "mkit+https://host/repo",
            "--repository",
            "repo",
            "--ref",
            "refs/heads/main",
            "--format=json",
        ],
    );
    assert!(!unsupported.status.success());
    assert!(
        ScopedWorkspaceLayout::open(&scoped)
            .unwrap()
            .read_state()
            .unwrap()
            .pending()
            .unwrap()
            .operation()
            .is_none()
    );
    let partial_target = common::mkit(
        &scoped,
        &xdg,
        &[
            "workspace",
            "push",
            "--endpoint",
            "mkit+file:///tmp/repo",
            "--format=json",
        ],
    );
    assert!(!partial_target.status.success());
    let url = format!("mkit+file://{}", remote.canonicalize().unwrap().display());
    let missing_branch = common::mkit(
        &scoped,
        &xdg,
        &[
            "workspace",
            "push",
            "--endpoint",
            &url,
            "--repository",
            "repo",
            "--ref",
            "refs/heads/missing",
            "--format=json",
        ],
    );
    assert!(!missing_branch.status.success());
    tx.write_ref("refs/heads/unmapped", &base).unwrap();
    let missing_packmap = common::mkit(
        &scoped,
        &xdg,
        &[
            "workspace",
            "push",
            "--endpoint",
            &url,
            "--repository",
            "repo",
            "--ref",
            "refs/heads/unmapped",
            "--format=json",
        ],
    );
    assert!(!missing_packmap.status.success());
    fs::remove_file(remote.join("refs/heads/unmapped")).unwrap();
    let still_prepared = ScopedWorkspaceLayout::open(&scoped)
        .unwrap()
        .read_state()
        .unwrap();
    assert!(still_prepared.pending().unwrap().operation().is_none());
    assert!(still_prepared.workspace().target().is_none());
    let published = json(
        &scoped,
        &xdg,
        &[
            "workspace",
            "push",
            "--endpoint",
            &url,
            "--repository",
            "repo",
            "--ref",
            "refs/heads/main",
            "--format=json",
        ],
    );
    assert_eq!(published["publication"], "accepted");
    let candidate = mkit_core::hash::from_hex(committed["candidate"].as_str().unwrap()).unwrap();
    assert_eq!(tx.read_ref("refs/heads/main").unwrap(), Some(candidate));
    let next_node = tx.read_ref("refs/mkit/packmap/main").unwrap().unwrap();
    let chain = mkit_core::transfer::decode_packlist(
        &tx.download_blob(&PackKey::from_hash(next_node)).unwrap(),
    )
    .unwrap();
    assert_eq!(chain.prev, Some(initial_id));
    let state = ScopedWorkspaceLayout::open(&scoped)
        .unwrap()
        .read_state()
        .unwrap();
    assert!(state.pending().is_none());
    assert_eq!(*state.workspace().base_id(), candidate);
    assert!(!scoped.join("hidden.txt").exists());

    let clone = temp.path().join("clone");
    let fetched = common::mkit(temp.path(), &xdg, &["clone", &url, clone.to_str().unwrap()]);
    assert!(
        fetched.status.success(),
        "{}",
        String::from_utf8_lossy(&fetched.stderr)
    );
    let full = ObjectStore::open(&RepoLayout::single(&clone)).unwrap();
    let Object::Commit(full_candidate) = full.read_object(&candidate).unwrap() else {
        panic!("candidate commit")
    };
    let Object::Commit(local_candidate) = state.verified().base_object() else {
        panic!("accepted local commit")
    };
    assert_eq!(full_candidate.tree_hash, local_candidate.tree_hash);
    assert_eq!(
        fs::read(clone.join("hidden.txt")).unwrap(),
        b"hidden source"
    );

    let sibling = temp.path().join("sibling");
    let created = common::mkit(
        temp.path(),
        &xdg,
        &[
            "workspace",
            "create",
            "--bundle",
            bundle_file.to_str().unwrap(),
            "--base",
            &mkit_core::hash::to_hex(&base),
            "--accept-bundle-selection",
            sibling.to_str().unwrap(),
        ],
    );
    assert!(created.status.success());
    fs::write(sibling.join("a.txt"), b"sibling edit").unwrap();
    json(
        &sibling,
        &xdg,
        &["workspace", "add", "--all", "--format=json"],
    );
    json(
        &sibling,
        &xdg,
        &["workspace", "commit", "-m", "sibling", "--format=json"],
    );
    let conflict = common::mkit(
        &sibling,
        &xdg,
        &[
            "workspace",
            "push",
            "--endpoint",
            &url,
            "--repository",
            "repo",
            "--ref",
            "refs/heads/main",
            "--format=json",
        ],
    );
    assert!(!conflict.status.success());
    let result: Value = serde_json::from_slice(&conflict.stdout).unwrap();
    assert_eq!(result["publication"], "conflict");
    let draft = ScopedWorkspaceLayout::open(&sibling)
        .unwrap()
        .read_state()
        .unwrap();
    assert_eq!(
        format!("{:?}", draft.pending().unwrap().status()),
        "Conflict"
    );
    assert_eq!(*draft.workspace().base_id(), base);
    assert_eq!(fs::read(sibling.join("a.txt")).unwrap(), b"sibling edit");
    let substitution = common::mkit(
        &sibling,
        &xdg,
        &[
            "workspace",
            "push",
            "--endpoint",
            &url,
            "--repository",
            "other",
            "--ref",
            "refs/heads/main",
            "--format=json",
        ],
    );
    assert!(!substitution.status.success());

    // Simulate a lost reply or process crash after a successful remote CAS:
    // the local write-ahead Unknown is the only durable client fact.
    tx.write_ref("refs/heads/uncertain", &base).unwrap();
    tx.write_ref("refs/mkit/packmap/uncertain", &initial_id)
        .unwrap();
    let uncertain = temp.path().join("uncertain");
    let created = common::mkit(
        temp.path(),
        &xdg,
        &[
            "workspace",
            "create",
            "--bundle",
            bundle_file.to_str().unwrap(),
            "--base",
            &mkit_core::hash::to_hex(&base),
            "--accept-bundle-selection",
            uncertain.to_str().unwrap(),
        ],
    );
    assert!(created.status.success());
    fs::write(uncertain.join("a.txt"), b"uncertain edit").unwrap();
    json(
        &uncertain,
        &xdg,
        &["workspace", "add", "--all", "--format=json"],
    );
    json(
        &uncertain,
        &xdg,
        &["workspace", "commit", "-m", "uncertain", "--format=json"],
    );
    let local = ScopedWorkspaceLayout::open(&uncertain).unwrap();
    let initial_state = local.read_state().unwrap();
    let initial_id = initial_state.pending().unwrap().identity();
    let target =
        mkit_core::partial::RemotePublicationTargetV1::new(&url, "repo", "refs/heads/uncertain")
            .unwrap();
    let bound = local
        .bind_pending_publication(
            initial_state.workspace().transaction_generation(),
            &initial_id,
            target,
            [9; 32],
        )
        .unwrap();
    let identity = bound.pending().unwrap().identity();
    let sending = local
        .begin_publication(bound.workspace().transaction_generation(), &identity)
        .unwrap();
    let bytes = sending.pending_update_bytes().unwrap().to_vec();
    let context = mkit_core::partial::PartialExchangeContext::bind(
        "repo",
        "refs/heads/uncertain",
        [9; 32],
        base,
        &bytes,
    );
    assert!(matches!(
        mkit_core::partial::publish_explicit_update(&tx, &bytes, &PartialLimits::V1, &context)
            .unwrap(),
        mkit_core::partial::PublicationOutcome::Published
    ));
    drop(local);
    let restarted = ScopedWorkspaceLayout::open(&uncertain).unwrap();
    let retained = restarted.read_state().unwrap();
    assert_eq!(
        format!("{:?}", retained.pending().unwrap().status()),
        "Unknown"
    );
    assert_eq!(*retained.workspace().base_id(), base);
    assert!(
        restarted
            .begin_publication(retained.workspace().transaction_generation(), &identity)
            .is_err()
    );
    let retry = common::mkit(&uncertain, &xdg, &["workspace", "push", "--format=json"]);
    assert!(!retry.status.success());
    let swapped = common::mkit(
        &uncertain,
        &xdg,
        &[
            "workspace",
            "push",
            "--endpoint",
            &url,
            "--repository",
            "other",
            "--ref",
            "refs/heads/uncertain",
            "--format=json",
        ],
    );
    assert!(!swapped.status.success());
    assert_eq!(
        tx.read_ref("refs/heads/uncertain").unwrap(),
        Some(*identity.candidate_id())
    );
}

#[test]
fn create_requires_exact_selection_and_base_before_destination() {
    let temp = tempfile::tempdir().unwrap();
    let xdg = temp.path().join("xdg");
    fs::create_dir(&xdg).unwrap();
    let target = temp.path().join("scoped");
    let bundle = fixture("plain_file.bin");
    let args = [
        "workspace",
        "create",
        "--bundle",
        bundle.to_str().unwrap(),
        "--base",
        BASE,
        "--path",
        "other.txt",
        target.to_str().unwrap(),
    ];
    let output = common::mkit(temp.path(), &xdg, &args);
    assert!(!output.status.success());
    assert!(!target.exists());
    let no_selection = common::mkit(
        temp.path(),
        &xdg,
        &[
            "workspace",
            "create",
            "--bundle",
            bundle.to_str().unwrap(),
            "--base",
            BASE,
            target.to_str().unwrap(),
        ],
    );
    assert!(!no_selection.status.success());
    assert!(!target.exists());
    let success = common::mkit(
        temp.path(),
        &xdg,
        &[
            "workspace",
            "create",
            "--bundle",
            bundle.to_str().unwrap(),
            "--base",
            BASE,
            "--path",
            "shallow.txt",
            "--format=json",
            target.to_str().unwrap(),
        ],
    );
    assert!(
        success.status.success(),
        "{}",
        String::from_utf8_lossy(&success.stderr)
    );
    let created: Value = serde_json::from_slice(&success.stdout).unwrap();
    assert_eq!(
        created["selected_paths"],
        serde_json::json!(["shallow.txt"])
    );
    let args = [
        "workspace",
        "create",
        "--bundle",
        bundle.to_str().unwrap(),
        "--base",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "--accept-bundle-selection",
        target.to_str().unwrap(),
    ];
    let other = temp.path().join("other");
    let mut args = args;
    args[args.len() - 1] = other.to_str().unwrap();
    let output = common::mkit(temp.path(), &xdg, &args);
    assert!(!output.status.success());
    assert!(!other.exists());
}

#[test]
fn stage_a_preserves_working_b_after_restart_and_reports_extras() {
    let (temp, workspace) = setup("plain_file.bin");
    let xdg = temp.path().join("xdg");
    let file = workspace.join("shallow.txt");
    fs::write(&file, b"staged A\n").unwrap();
    let staged = json(
        &workspace,
        &xdg,
        &["workspace", "add", "--format=json", "--all"],
    );
    assert_eq!(staged["coverage"]["history"], "partial");
    fs::write(&file, b"working B\n").unwrap();
    fs::write(workspace.join("extra.txt"), b"outside content").unwrap();
    let status = json(&workspace, &xdg, &["workspace", "status", "--format=json"]);
    assert_eq!(status["files"][0]["staged"], true);
    assert_eq!(status["files"][0]["working"], true);
    assert_eq!(status["extra_paths"][0], "extra.txt");
    assert_eq!(status["extra_scan_complete"], true);
    let cached = json(
        &workspace,
        &xdg,
        &["workspace", "diff", "--cached", "--format=json"],
    );
    assert!(
        cached["changes"][0]["patch"]
            .as_str()
            .unwrap()
            .contains("staged A")
    );
    let working = json(&workspace, &xdg, &["workspace", "diff", "--format=json"]);
    assert!(
        working["changes"][0]["patch"]
            .as_str()
            .unwrap()
            .contains("working B")
    );
    assert_eq!(
        fs::read(workspace.join("extra.txt")).unwrap(),
        b"outside content"
    );
}

#[test]
fn selected_link_and_missing_file_cannot_stage() {
    let (temp, workspace) = setup("plain_file.bin");
    let xdg = temp.path().join("xdg");
    let file = workspace.join("shallow.txt");
    fs::remove_file(&file).unwrap();
    let missing = common::mkit(&workspace, &xdg, &["workspace", "add", "--all"]);
    assert!(!missing.status.success());
    std::os::unix::fs::symlink("elsewhere", &file).unwrap();
    let link = common::mkit(&workspace, &xdg, &["workspace", "add", "--all"]);
    assert!(!link.status.success());
    let state = json(&workspace, &xdg, &["workspace", "status", "--format=json"]);
    assert!(state["files"][0]["unsupported"].as_str().is_some());
}

#[test]
fn unsupported_operations_never_fall_back_to_ordinary_repository() {
    let (temp, workspace) = setup("plain_file.bin");
    let xdg = temp.path().join("xdg");
    for command in ["merge", "rebase", "checkout", "gc"] {
        let output = common::mkit(&workspace, &xdg, &["workspace", command]);
        assert!(!output.status.success(), "{command}");
        assert!(String::from_utf8_lossy(&output.stderr).contains("unsupported"));
    }
    let log = json(&workspace, &xdg, &["workspace", "log", "--format=json"]);
    assert_eq!(log["history_boundary"], "earlier history unavailable");
    assert_eq!(log["local_entries"].as_array().unwrap().len(), 1);
}

#[test]
fn mixed_batch_is_atomic_and_mode_and_hardlinks_are_rejected() {
    let (temp, workspace) = setup("shared_ancestor.bin");
    let xdg = temp.path().join("xdg");
    let original = json(&workspace, &xdg, &["workspace", "status", "--format=json"]);
    fs::write(workspace.join("shallow.txt"), b"valid edit\n").unwrap();
    let executable = workspace.join("exec.sh");
    let metadata = fs::metadata(&executable).unwrap();
    let mut permissions = metadata.permissions();
    permissions.set_mode(0o644);
    fs::set_permissions(&executable, permissions).unwrap();
    let rejected = common::mkit(&workspace, &xdg, &["workspace", "add", "--all"]);
    assert!(!rejected.status.success());
    let after = json(&workspace, &xdg, &["workspace", "status", "--format=json"]);
    assert_eq!(after["files"][2]["staged"], original["files"][2]["staged"]);
    fs::set_permissions(&executable, metadata.permissions()).unwrap();
    fs::hard_link(workspace.join("shallow.txt"), workspace.join("alias.txt")).unwrap();
    let hardlink = common::mkit(&workspace, &xdg, &["workspace", "add", "--", "shallow.txt"]);
    assert!(!hardlink.status.success());
    assert!(String::from_utf8_lossy(&hardlink.stderr).contains("linked"));
}

#[test]
fn binary_diff_and_bounded_extra_scan_are_explicit() {
    let (temp, workspace) = setup("shared_ancestor.bin");
    let xdg = temp.path().join("xdg");
    fs::write(workspace.join("range.bin"), [0, 1, 2, 3]).unwrap();
    let diff = json(
        &workspace,
        &xdg,
        &["workspace", "diff", "--format=json", "--", "range.bin"],
    );
    assert_eq!(diff["changes"].as_array().unwrap().len(), 1);
    assert!(diff["changes"][0]["patch"].is_null());
    assert!(diff["changes"][0]["after_digest"].as_str().is_some());
    for index in 0..4097 {
        fs::write(workspace.join(format!("extra-{index}")), b"").unwrap();
    }
    let status = json(&workspace, &xdg, &["workspace", "status", "--format=json"]);
    assert_eq!(status["extra_scan_complete"], false);
    assert!(status["extra_paths"].as_array().unwrap().len() > 4000);
}

#[test]
fn nested_discovery_and_corrupt_authority_never_fall_back() {
    let (temp, workspace) = setup("plain_file.bin");
    let xdg = temp.path().join("xdg");
    let nested = workspace.join("nested");
    fs::create_dir(&nested).unwrap();
    let status = json(&nested, &xdg, &["workspace", "status", "--format=json"]);
    assert_eq!(status["workspace_mode"], "scoped");
    let with_c = common::mkit(
        temp.path(),
        &xdg,
        &[
            "-C",
            nested.to_str().unwrap(),
            "workspace",
            "log",
            "--format=json",
        ],
    );
    assert!(with_c.status.success());
    fs::write(workspace.join(".mkit"), b"mkit-scoped: 1\ncorrupt").unwrap();
    let corrupt = common::mkit(&nested, &xdg, &["workspace", "status", "--format=json"]);
    assert!(!corrupt.status.success());
    let error: Value = serde_json::from_slice(&corrupt.stdout).unwrap();
    assert_eq!(error["ok"], false);
}

#[test]
fn pending_state_blocks_cli_add_and_log_labels_candidate() {
    let (temp, workspace) = setup("plain_file.bin");
    let xdg = temp.path().join("xdg");
    fs::write(workspace.join("shallow.txt"), b"staged A").unwrap();
    json(
        &workspace,
        &xdg,
        &["workspace", "add", "--all", "--format=json"],
    );
    let layout = ScopedWorkspaceLayout::open(&workspace).unwrap();
    let state = layout.read_state().unwrap();
    let path = vec![b"shallow.txt".to_vec()];
    let prepared = replace_files(
        state.verified(),
        &[FileReplacement::bytes(path, b"staged A".to_vec())],
        &PartialLimits::V1,
    )
    .unwrap();
    let signer = KeyPair::from_seed([9; 32]);
    let unsigned = prepare_partial_commit(
        state.verified(),
        &prepared,
        Identity::opaque(b"author".to_vec()),
        signer.public.0,
        b"candidate".to_vec(),
        1_700_000_100,
        &PartialLimits::V1,
    )
    .unwrap();
    let mut candidate = unsigned.clone();
    candidate.signature = sign_commit(&candidate, &signer).unwrap().0;
    let update = export_partial_update(
        state.verified(),
        &prepared,
        &unsigned,
        &candidate,
        &PartialLimits::V1,
    )
    .unwrap();
    let bytes = update.encode(&PartialLimits::V1).unwrap();
    layout
        .save_pending(
            state.workspace().transaction_generation(),
            &unsigned,
            &candidate,
            &bytes,
            None,
        )
        .unwrap();
    let refused = common::mkit(
        &workspace,
        &xdg,
        &["workspace", "add", "--all", "--format=json"],
    );
    assert!(!refused.status.success());
    let error: Value = serde_json::from_slice(&refused.stdout).unwrap();
    assert_eq!(error["ok"], false);
    let log = json(&workspace, &xdg, &["workspace", "log", "--format=json"]);
    assert_eq!(log["local_entries"][0]["kind"], "pending-candidate-id");
}

#[test]
fn json_errors_and_newline_only_diff_are_precise() {
    let (temp, workspace) = setup("plain_file.bin");
    let xdg = temp.path().join("xdg");
    let invalid = common::mkit(
        &workspace,
        &xdg,
        &["workspace", "add", "--format=json", "--unknown"],
    );
    assert!(!invalid.status.success());
    let error: Value = serde_json::from_slice(&invalid.stdout).unwrap();
    assert_eq!(error["workspace_mode"], "scoped");
    let unsupported = common::mkit(&workspace, &xdg, &["workspace", "push", "--format=json"]);
    assert!(!unsupported.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&unsupported.stdout).unwrap()["ok"],
        false
    );
    fs::write(workspace.join("shallow.txt"), b"same without newline").unwrap();
    json(
        &workspace,
        &xdg,
        &["workspace", "add", "--all", "--format=json"],
    );
    fs::write(workspace.join("shallow.txt"), b"same without newline\n").unwrap();
    let diff = json(&workspace, &xdg, &["workspace", "diff", "--format=json"]);
    let patch = diff["changes"][0]["patch"].as_str().unwrap();
    assert!(patch.contains("No newline at end of file"));
}

#[test]
fn oversized_working_file_and_large_line_diff_fall_back_safely() {
    let (temp, workspace) = setup("plain_file.bin");
    let xdg = temp.path().join("xdg");
    let file = workspace.join("shallow.txt");
    fs::OpenOptions::new()
        .write(true)
        .open(&file)
        .unwrap()
        .set_len(PartialLimits::V1.max_selected_file_bytes as u64 + 1)
        .unwrap();
    let rejected = common::mkit(
        &workspace,
        &xdg,
        &["workspace", "add", "--all", "--format=json"],
    );
    assert!(!rejected.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&rejected.stdout).unwrap()["ok"],
        false
    );
    fs::write(&file, many_lines("old")).unwrap();
    json(
        &workspace,
        &xdg,
        &["workspace", "add", "--all", "--format=json"],
    );
    fs::write(&file, many_lines("new")).unwrap();
    let diff = json(&workspace, &xdg, &["workspace", "diff", "--format=json"]);
    assert!(diff["changes"][0]["patch"].is_null());
    assert!(diff["changes"][0]["after_digest"].as_str().is_some());
}

fn many_lines(prefix: &str) -> String {
    let mut text = String::new();
    for index in 0..600 {
        writeln!(text, "{prefix}-{index}").unwrap();
    }
    text
}

#[test]
fn selected_ancestor_symlink_is_not_followed() {
    let temp = tempfile::tempdir().unwrap();
    let xdg = temp.path().join("xdg");
    let source = temp.path().join("source");
    fs::create_dir(&xdg).unwrap();
    fs::create_dir(&source).unwrap();
    for args in [vec!["init"], vec!["keygen"]] {
        let result = common::mkit(&source, &xdg, &args);
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
    fs::create_dir(source.join("nested")).unwrap();
    fs::write(source.join("nested/file.txt"), b"base content").unwrap();
    for args in [vec!["add", "nested/file.txt"], vec!["commit", "-m", "base"]] {
        let result = common::mkit(&source, &xdg, &args);
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
    let head = common::mkit(&source, &xdg, &["rev-parse", "HEAD"]);
    assert!(head.status.success());
    let base = mkit_core::hash::from_hex(String::from_utf8_lossy(&head.stdout).trim()).unwrap();
    let store =
        mkit_core::store::ObjectStore::open(&mkit_core::layout::RepoLayout::single(&source))
            .unwrap();
    let path = vec![b"nested".to_vec(), b"file.txt".to_vec()];
    let bundle =
        mkit_core::partial::build_partial_snapshot(&store, base, &[path], &PartialLimits::V1)
            .unwrap()
            .encode(&PartialLimits::V1)
            .unwrap();
    let bundle_path = temp.path().join("bundle.mkwb");
    fs::write(&bundle_path, bundle).unwrap();
    let workspace = temp.path().join("scoped");
    let result = common::mkit(
        temp.path(),
        &xdg,
        &[
            "workspace",
            "create",
            "--bundle",
            bundle_path.to_str().unwrap(),
            "--base",
            &mkit_core::hash::to_hex(&base),
            "--path",
            "nested/file.txt",
            workspace.to_str().unwrap(),
        ],
    );
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    fs::remove_file(workspace.join("nested/file.txt")).unwrap();
    fs::remove_dir(workspace.join("nested")).unwrap();
    let outside = temp.path().join("outside");
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("file.txt"), b"private bytes").unwrap();
    std::os::unix::fs::symlink(&outside, workspace.join("nested")).unwrap();
    let rejected = common::mkit(&workspace, &xdg, &["workspace", "add", "--all"]);
    assert!(!rejected.status.success());
    assert_eq!(
        fs::read(outside.join("file.txt")).unwrap(),
        b"private bytes"
    );
}

#[test]
fn aggregate_working_cap_rejects_whole_add_batch() {
    let temp = tempfile::tempdir().unwrap();
    let xdg = temp.path().join("xdg");
    let source = temp.path().join("source");
    fs::create_dir(&xdg).unwrap();
    fs::create_dir(&source).unwrap();
    for args in [vec!["init"], vec!["keygen"]] {
        assert!(common::mkit(&source, &xdg, &args).status.success());
    }
    let mut paths = Vec::new();
    for index in 0..5 {
        let name = format!("file{index}.txt");
        fs::write(source.join(&name), b"x").unwrap();
        paths.push(vec![name.into_bytes()]);
    }
    assert!(common::mkit(&source, &xdg, &["add", "."]).status.success());
    assert!(
        common::mkit(&source, &xdg, &["commit", "-m", "base"])
            .status
            .success()
    );
    let head = common::mkit(&source, &xdg, &["rev-parse", "HEAD"]);
    let base = mkit_core::hash::from_hex(String::from_utf8_lossy(&head.stdout).trim()).unwrap();
    let store =
        mkit_core::store::ObjectStore::open(&mkit_core::layout::RepoLayout::single(&source))
            .unwrap();
    let bundle =
        mkit_core::partial::build_partial_snapshot(&store, base, &paths, &PartialLimits::V1)
            .unwrap()
            .encode(&PartialLimits::V1)
            .unwrap();
    let bundle_path = temp.path().join("bundle.mkwb");
    fs::write(&bundle_path, bundle).unwrap();
    let workspace = temp.path().join("scoped");
    assert!(
        common::mkit(
            temp.path(),
            &xdg,
            &[
                "workspace",
                "create",
                "--bundle",
                bundle_path.to_str().unwrap(),
                "--base",
                &mkit_core::hash::to_hex(&base),
                "--accept-bundle-selection",
                workspace.to_str().unwrap()
            ]
        )
        .status
        .success()
    );
    for index in 0..5 {
        fs::write(
            workspace.join(format!("file{index}.txt")),
            vec![b'y'; 4 * 1024 * 1024],
        )
        .unwrap();
    }
    let rejected = common::mkit(
        &workspace,
        &xdg,
        &["workspace", "add", "--all", "--format=json"],
    );
    assert!(!rejected.status.success());
    let status = json(&workspace, &xdg, &["workspace", "status", "--format=json"]);
    assert!(
        status["files"]
            .as_array()
            .unwrap()
            .iter()
            .all(|f| f["staged"] == false)
    );
    assert!(
        status["files"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["unsupported"].as_str().is_some())
    );
}

#[test]
fn oversized_bundle_never_materializes_destination() {
    let temp = tempfile::tempdir().unwrap();
    let xdg = temp.path().join("xdg");
    fs::create_dir(&xdg).unwrap();
    let bundle = temp.path().join("oversize.mkwb");
    fs::File::create(&bundle)
        .unwrap()
        .set_len(PartialLimits::V1.max_bundle_bytes as u64 + 1)
        .unwrap();
    let destination = temp.path().join("scoped");
    let output = common::mkit(
        temp.path(),
        &xdg,
        &[
            "workspace",
            "create",
            "--bundle",
            bundle.to_str().unwrap(),
            "--base",
            BASE,
            "--accept-bundle-selection",
            destination.to_str().unwrap(),
        ],
    );
    assert!(!output.status.success());
    assert!(!destination.exists());
}
