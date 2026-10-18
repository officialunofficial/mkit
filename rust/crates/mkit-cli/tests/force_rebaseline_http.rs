//! Force pushes retain their planning dependencies across an atomic re-baseline.
#![allow(clippy::unwrap_used)]

mod common;

use common::Repo;
use mkit_cli::remote_dispatch::{pull_all, push_branch_with_depth};
use mkit_core::hash::{Hash, from_hex, hash, to_hex};
use mkit_core::layout::RepoLayout;
use mkit_core::protocol::{AdvanceOutcome, PackKey, RefWriteCondition, Transport, TransportResult};
use mkit_core::refs::{self, Ref};
use mkit_core::store::ObjectStore;
use mkit_core::transfer::decode_packlist;
use mkit_transport_http::HttpTransport;
use mockito::{Matcher, Mock, Server};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

const HEAD: &str = "refs/heads/main";
const PACKMAP: &str = "refs/mkit/packmap/main";

#[derive(Default)]
struct State {
    refs: HashMap<String, Hash>,
    blobs: HashMap<Hash, Vec<u8>>,
    advances: usize,
    conflicts: usize,
}

fn condition_holds(spec: &Value, refs: &HashMap<String, Hash>) -> bool {
    let current = refs.get(spec["ref"].as_str().unwrap());
    match spec["condition"]["kind"].as_str().unwrap() {
        "missing" => current.is_none(),
        "match" => {
            current == Some(&from_hex(spec["condition"]["expected"].as_str().unwrap()).unwrap())
        }
        other => panic!("unexpected atomic condition: {other}"),
    }
}

/// Exercise the existing JSON dialect with an atomic store behind its wire API.
fn serve(server: &mut Server, state: &Arc<Mutex<State>>) -> Vec<Mock> {
    let upload = Arc::clone(state);
    let packs = server
        .mock("POST", "/repo/packs")
        .with_body_from_request(move |request| {
            let bytes = request.body().unwrap();
            let key = hash(bytes);
            upload.lock().unwrap().blobs.insert(key, bytes.clone());
            json!({ "key": to_hex(&key) }).to_string().into_bytes()
        })
        .create();
    let reads = Arc::clone(state);
    let downloads = server
        .mock("GET", Matcher::Regex("^/repo/packs/[a-f0-9]+$".into()))
        .with_body_from_request(move |request| {
            let key = from_hex(request.path().rsplit('/').next().unwrap()).unwrap();
            reads.lock().unwrap().blobs[&key].clone()
        })
        .create();
    let existence = server
        .mock("HEAD", Matcher::Regex("^/repo/packs/[a-f0-9]+$".into()))
        .with_status(200)
        .create();
    let status = Arc::clone(state);
    let body = Arc::clone(state);
    let refs = server
        .mock("GET", Matcher::Regex("^/repo/refs/refs/.*$".into()))
        .with_status_code_from_request(move |request| {
            if status
                .lock()
                .unwrap()
                .refs
                .contains_key(&request.path()[11..])
            {
                200
            } else {
                404
            }
        })
        .with_body_from_request(move |request| {
            let refs = &body.lock().unwrap().refs;
            refs.get(&request.path()[11..])
                .map_or_else(Vec::new, |key| {
                    json!({ "hash": to_hex(key) }).to_string().into_bytes()
                })
        })
        .create();
    let listing = Arc::clone(state);
    let list = server
        .mock("GET", "/repo/refs")
        .match_query(Matcher::Any)
        .with_body_from_request(move |_| {
            let entries: Vec<_> = listing
                .lock()
                .unwrap()
                .refs
                .iter()
                .filter(|(name, _)| name.starts_with("refs/heads/"))
                .map(|(name, key)| json!({ "name": name, "hash": to_hex(key) }))
                .collect();
            json!({ "refs": entries }).to_string().into_bytes()
        })
        .create();
    let writes = Arc::clone(state);
    let advance = server
        .mock("POST", "/repo/refs/advance")
        .with_status_code_from_request(move |request| {
            let body: Value = serde_json::from_slice(request.body().unwrap()).unwrap();
            let mut state = writes.lock().unwrap();
            state.advances += 1;
            if !condition_holds(&body["packmap"], &state.refs)
                || !condition_holds(&body["head"], &state.refs)
            {
                state.conflicts += 1;
                return 412;
            }
            for spec in [&body["packmap"], &body["head"]] {
                state.refs.insert(
                    spec["ref"].as_str().unwrap().to_owned(),
                    from_hex(spec["value"].as_str().unwrap()).unwrap(),
                );
            }
            200
        })
        .with_body(r#"{"conflict":"packmap"}"#)
        .create();
    let no_put = server.mock("PUT", Matcher::Any).expect(0).create();
    vec![packs, downloads, existence, refs, list, advance, no_put]
}

struct ResetBeforeAdvance<'a> {
    inner: &'a HttpTransport,
    competing: &'a HttpTransport,
    competing_store: &'a ObjectStore,
    competing_tip: Hash,
    observed_head: Hash,
    fired: AtomicBool,
}

impl ResetBeforeAdvance<'_> {
    fn interleave(&self) {
        if !self.fired.swap(true, Ordering::SeqCst) {
            push_branch_with_depth(
                self.competing,
                self.competing_store,
                "main",
                self.competing_tip,
                RefWriteCondition::Match(self.observed_head),
                1,
            )
            .unwrap();
            let key = self.competing.read_ref(PACKMAP).unwrap().unwrap();
            let bytes = self
                .competing
                .download_blob(&PackKey::from_hash(key))
                .unwrap();
            assert!(decode_packlist(&bytes).unwrap().prev.is_none());
        }
    }
}

impl Transport for ResetBeforeAdvance<'_> {
    fn upload_pack(&self, bytes: &[u8], key: &PackKey) -> TransportResult<()> {
        self.inner.upload_pack(bytes, key)
    }
    fn download_pack(&self, key: &PackKey) -> TransportResult<Vec<u8>> {
        self.inner.download_pack(key)
    }
    fn pack_exists(&self, key: &PackKey) -> TransportResult<bool> {
        self.inner.pack_exists(key)
    }
    fn update_ref(
        &self,
        name: &str,
        condition: RefWriteCondition,
        tip: &Hash,
    ) -> TransportResult<()> {
        self.interleave();
        self.inner.update_ref(name, condition, tip)
    }
    fn read_ref(&self, name: &str) -> TransportResult<Option<Hash>> {
        self.inner.read_ref(name)
    }
    fn list_refs(&self, prefix: &str) -> TransportResult<Vec<Ref>> {
        self.inner.list_refs(prefix)
    }
    fn advance_refs(
        &self,
        head: &str,
        head_condition: RefWriteCondition,
        tip: &Hash,
        packmap: &str,
        packmap_condition: RefWriteCondition,
        node: &Hash,
    ) -> TransportResult<AdvanceOutcome> {
        self.interleave();
        self.inner
            .advance_refs(head, head_condition, tip, packmap, packmap_condition, node)
    }
    fn atomic_force_head_condition(&self, head: Option<Hash>) -> RefWriteCondition {
        self.inner.atomic_force_head_condition(head)
    }
    fn supports_atomic_advance(&self) -> bool {
        self.inner.supports_atomic_advance()
    }
}

fn head(repo: &Repo) -> Hash {
    refs::read_ref(&RepoLayout::single(repo.path()), "main")
        .unwrap()
        .unwrap()
}

fn run_rebaseline_race(appending: bool) {
    let mut server = Server::new();
    let state = Arc::new(Mutex::new(State::default()));
    let mocks = serve(&mut server, &state);
    let base_url = format!("{}/repo", server.url());
    let transport = HttpTransport::new_for_test(base_url.parse().unwrap(), None);
    let competing = HttpTransport::new_for_test(base_url.parse().unwrap(), None);
    let local = Repo::new();
    local.commit_file("f.txt", b"base", "base");
    let base = head(&local);
    let store = ObjectStore::open(&RepoLayout::single(local.path())).unwrap();
    push_branch_with_depth(
        &transport,
        &store,
        "main",
        base,
        RefWriteCondition::Missing,
        64,
    )
    .unwrap();
    local.commit_file("f.txt", b"remote", "remote");
    let remote = head(&local);
    push_branch_with_depth(
        &transport,
        &store,
        "main",
        remote,
        RefWriteCondition::Match(base),
        64,
    )
    .unwrap();

    local.ok(&["reset", "--hard", "-f", &to_hex(&base)]);
    if appending {
        local.commit_file("f.txt", b"forced", "forced");
    }
    let target = head(&local);
    let replacement = Repo::new();
    replacement.commit_file("f.txt", b"replacement", "replacement");
    let replacement_store = ObjectStore::open(&RepoLayout::single(replacement.path())).unwrap();
    let racing = ResetBeforeAdvance {
        inner: &transport,
        competing: &competing,
        competing_store: &replacement_store,
        competing_tip: head(&replacement),
        observed_head: remote,
        fired: AtomicBool::new(false),
    };
    let before = state.lock().unwrap().advances;
    push_branch_with_depth(&racing, &store, "main", target, RefWriteCondition::Any, 64).unwrap();
    assert!(racing.fired.load(Ordering::SeqCst));
    {
        let state = state.lock().unwrap();
        assert_eq!(
            state.advances - before,
            3,
            "reset, rejected stale force, replanned force"
        );
        assert_eq!(state.conflicts, 1);
        assert_eq!(state.refs[HEAD], target);
    }
    let clone = Repo::new();
    pull_all(clone.path(), &transport, "default", None).unwrap();
    assert_eq!(head(&clone), target);
    assert_eq!(
        std::fs::read(clone.path().join("f.txt")).unwrap(),
        if appending {
            b"forced".as_slice()
        } else {
            b"base".as_slice()
        }
    );
    let clone_store = ObjectStore::open(&RepoLayout::single(clone.path())).unwrap();
    assert!(clone_store.read_object(&target).is_ok());
    assert!(clone_store.read_object(&base).is_ok());
    mocks.last().unwrap().assert();
}

#[test]
fn http_head_only_force_replans_after_atomic_rebaseline() {
    run_rebaseline_race(false);
}

#[test]
fn http_appending_force_replans_after_atomic_rebaseline() {
    run_rebaseline_race(true);
}
