//! Authority-mode namespaces (SPEC-SERVER §6.2.2) through the `mkit-client`
//! backend: clone, pull and a no-op pull of a public repository whose
//! namespace is a `UUIDv7`; a signed private clone by an authorized key; and
//! uniform `not_found` for an anonymous or denied read of a private one.
#![cfg(feature = "connect-native")]
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

mod support;

use mkit_client::Client;
use mkit_core::hash::Hash;
use mkit_core::refs;
use mkit_sync::{
    ClientSource, CloneError, CloneRemote, NativeClock, NativeHttp, NoopObserver, PullOutcome,
    SyncError, SyncOptions, clone, pull,
};
use support::{
    Dalek, Live, NS, READER_SEED, STRANGER_SEED, WRITER_SEED, destination, make_private,
    push_commit,
};

fn remote(origin: &str, repository: &str) -> CloneRemote {
    CloneRemote {
        name: "default".to_owned(),
        url: format!("mkit+{origin}/{repository}"),
        kind: "http".to_owned(),
    }
}

fn clone_anonymous(
    http: &NativeHttp,
    origin: &str,
    repository: &str,
    dir: &std::path::Path,
) -> Result<mkit_sync::CloneReport, CloneError> {
    let client = Client::anonymous(http, destination(origin, repository));
    let source = ClientSource::new(&client, http);
    clone(
        dir,
        &source,
        &remote(origin, repository),
        &SyncOptions::default(),
        &NoopObserver,
    )
}

fn clone_signed(
    http: &NativeHttp,
    origin: &str,
    repository: &str,
    seed: u8,
    dir: &std::path::Path,
) -> Result<mkit_sync::CloneReport, CloneError> {
    let signer = Dalek::new(seed);
    let clock = NativeClock;
    let client = Client::signed(http, destination(origin, repository), &signer, &clock);
    let source = ClientSource::new(&client, http);
    clone(
        dir,
        &source,
        &remote(origin, repository),
        &SyncOptions::default(),
        &NoopObserver,
    )
}

fn not_found(result: Result<mkit_sync::CloneReport, CloneError>, repository: &str) -> String {
    let err = result.unwrap_err();
    let CloneError::Sync(SyncError::RepositoryNotFound { identity, .. }) = &err else {
        panic!("expected RepositoryNotFound, got {err:?}");
    };
    assert_eq!(identity, repository);
    let text = err.to_string().to_lowercase();
    for hint in ["permission", "denied"] {
        assert!(!text.contains(hint), "not a uniform absence: {text}");
    }
    err.to_string()
}

#[test]
fn a_public_authority_namespace_clones_pulls_and_no_ops() {
    let live = Live::authority();
    let http = NativeHttp::new().unwrap();
    let repository = format!("{NS}/public");
    let first = push_commit(
        &http,
        &live.origin,
        &repository,
        WRITER_SEED,
        None,
        &[("a.txt", b"public\n")],
    );
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("pub");

    let cloned = clone_anonymous(&http, &live.origin, &repository, &target).unwrap();
    assert!(matches!(
        cloned.pull.outcome,
        PullOutcome::FastForwarded { new, .. } if new == first
    ));
    assert_eq!(std::fs::read(target.join("a.txt")).unwrap(), b"public\n");

    let second = push_commit(
        &http,
        &live.origin,
        &repository,
        WRITER_SEED,
        Some(first),
        &[("a.txt", b"public\n"), ("b.txt", b"second\n")],
    );
    let client = Client::anonymous(&http, destination(&live.origin, &repository));
    let source = ClientSource::new(&client, &http);
    let pulled = pull(
        &target,
        &source,
        "default",
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap();
    assert!(matches!(
        pulled.outcome,
        PullOutcome::FastForwarded { new, .. } if new == second
    ));
    assert_eq!(std::fs::read(target.join("b.txt")).unwrap(), b"second\n");

    let again = pull(
        &target,
        &source,
        "default",
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap();
    assert!(matches!(again.outcome, PullOutcome::UpToDate { .. }));
    let head: Option<Hash> =
        refs::resolve_head(&mkit_core::layout::RepoLayout::single(&target)).unwrap();
    assert_eq!(head, Some(second), "a second pull must not move HEAD");
}

#[test]
fn a_private_repository_reads_only_for_an_authorized_signer() {
    let live = Live::authority();
    let http = NativeHttp::new().unwrap();
    let repository = format!("{NS}/private");
    push_commit(
        &http,
        &live.origin,
        &repository,
        WRITER_SEED,
        None,
        &[("secret.txt", b"private\n")],
    );
    make_private(&http, &live.origin, &repository, WRITER_SEED);
    let dir = tempfile::tempdir().unwrap();

    // The hook's reader clones it, signed.
    let target = dir.path().join("reader");
    clone_signed(&http, &live.origin, &repository, READER_SEED, &target).unwrap();
    assert_eq!(
        std::fs::read(target.join("secret.txt")).unwrap(),
        b"private\n"
    );

    // An anonymous caller, a signer the hook denies, and a missing repository
    // all get the same answer.
    let anonymous = not_found(
        clone_anonymous(&http, &live.origin, &repository, &dir.path().join("anon")),
        &repository,
    );
    let denied = not_found(
        clone_signed(
            &http,
            &live.origin,
            &repository,
            STRANGER_SEED,
            &dir.path().join("stranger"),
        ),
        &repository,
    );
    let missing_name = format!("{NS}/missing");
    let missing = not_found(
        clone_anonymous(&http, &live.origin, &missing_name, &dir.path().join("none")),
        &missing_name,
    );
    assert_eq!(
        anonymous, denied,
        "a denied read must equal an anonymous one"
    );
    assert_eq!(
        anonymous.replace("private", "R"),
        missing.replace("missing", "R"),
        "a private repository must read like a missing one"
    );

    // The hook saw envelope signers only, and the pipeline adopted none of the
    // ownership facts it was offered.
    let calls = live.calls.lock().unwrap();
    for seed in [WRITER_SEED, READER_SEED, STRANGER_SEED] {
        assert!(
            calls
                .iter()
                .any(|(p, _)| p.ed25519() == Some(&support::public_key(seed))),
            "the hook must see signer {seed:#x}"
        );
    }
    assert!(
        calls
            .iter()
            .all(|(_, facts)| !facts.owner && facts.grant.is_none())
    );
}
