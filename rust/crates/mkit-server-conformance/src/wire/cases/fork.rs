//! The embedded `ForkRepo` driver probe. `ForkRepo` has no Connect route,
//! so the native test host mounts `POST /__mkit_test/fork` through the core
//! embedded dispatch: the same signature checks, guards, job row and kind-16
//! timer as a production call. The case reports wall time and attempts for
//! each source size; embedders can collect core fork-step telemetry separately.
//!
//! Each run seeds a two-commit source of `files` blobs, forks it into a
//! fresh repository and polls `in flight` replies until the job finishes.
//! Every poll signs a fresh envelope (a new nonce), the way a real
//! embedder's retry does, so each in-window attempt drives one slice.

use std::time::{Duration, Instant};

use mkit_core::hash::{Hash, hash, to_hex};
use mkit_core::object::{Blob, Commit, EntryMode, Identity, Object, Tree, TreeEntry};
use mkit_core::pack::PackWriter;
use mkit_core::serialize::serialize;
use mkit_core::sign::{KeyPair, sign_commit};

use super::portable_reads::publish_named;
use super::{CaseResult, Ctx, Failure, ensure};
use crate::wire::sign::body_commitment;

/// The procedure the embedded dispatch authenticates (SPEC-SERVER §9.9).
const FORK_PROCEDURE: &str = "/mkit.server.v1/ForkRepo";
/// The `__test-faults`-only route that forwards to it.
const FORK_PATH: &str = "/__mkit_test/fork";
/// The `in flight` poll cadence; a real embedder polls near 100 ms.
const POLL_MS: u64 = 300;
/// A bounded total wait: the alarm cadence is 1 s per slice.
const MAX_ATTEMPTS: u32 = 1200;
/// `MKIT_FORK_PROBE_FILES=500,3000` chooses the fork sizes; the default is
/// the measurement pair.
const FILES_ENV: &str = "MKIT_FORK_PROBE_FILES";

fn commit_object(
    tree: Hash,
    parents: Vec<Hash>,
    message: &[u8],
) -> Result<(Object, Hash), Failure> {
    let signer = KeyPair::from_seed([9; 32]);
    let mut commit = Commit::new_unannotated(
        tree,
        parents,
        Identity::ed25519(signer.public.0),
        signer.public.0,
        message.to_vec(),
        42,
        [0; 64],
    );
    commit.signature = sign_commit(&commit, &signer)
        .map_err(|e| format!("sign commit: {e}"))?
        .0;
    let commit = Object::Commit(commit);
    let head = commit.id().map_err(|e| format!("commit id: {e}"))?;
    Ok((commit, head))
}

/// One pack of `files` blobs laid out over directories of
/// `FILES_PER_DIR`, plus the trees and two commits on the root, so the
/// source has real history. The directory fanout makes the fork's `Walk`
/// phase visit one object per directory — a multi-slice job at sizes a
/// flat tree would copy in one pass.
fn files_pack(files: u32) -> Result<(Vec<u8>, Hash), Failure> {
    const FILES_PER_DIR: u32 = 20;
    let mut writer = PackWriter::new_raw_only();
    let dirs = files.div_ceil(FILES_PER_DIR);
    let mut roots = Vec::with_capacity(dirs as usize);
    let mut n = 0;
    for d in 0..dirs {
        let mut entries = Vec::new();
        for _ in 0..(files - n).min(FILES_PER_DIR) {
            let blob = Object::Blob(Blob {
                data: format!("rx2 probe file {n}").into_bytes(),
            });
            let id = blob.id().map_err(|e| format!("blob id: {e}"))?;
            writer
                .push_raw(
                    id,
                    &serialize(&blob).map_err(|e| format!("blob bytes: {e}"))?,
                )
                .map_err(|e| format!("blob frame: {e}"))?;
            entries.push(TreeEntry {
                name: format!("f{n:04}").into_bytes(),
                mode: EntryMode::Blob,
                object_hash: id,
            });
            n += 1;
        }
        let dir = Object::Tree(Tree { entries });
        let dir_id = dir.id().map_err(|e| format!("tree id: {e}"))?;
        writer
            .push_raw(
                dir_id,
                &serialize(&dir).map_err(|e| format!("tree bytes: {e}"))?,
            )
            .map_err(|e| format!("tree frame: {e}"))?;
        roots.push(TreeEntry {
            name: format!("d{d:05}").into_bytes(),
            mode: EntryMode::Tree,
            object_hash: dir_id,
        });
    }
    let tree = Object::Tree(Tree { entries: roots });
    let tree_id = tree.id().map_err(|e| format!("tree id: {e}"))?;
    writer
        .push_raw(
            tree_id,
            &serialize(&tree).map_err(|e| format!("tree bytes: {e}"))?,
        )
        .map_err(|e| format!("tree frame: {e}"))?;
    let (first, head1) = commit_object(tree_id, Vec::new(), b"rx2 probe source")?;
    writer
        .push_raw(
            head1,
            &serialize(&first).map_err(|e| format!("commit bytes: {e}"))?,
        )
        .map_err(|e| format!("commit frame: {e}"))?;
    let (second, head2) = commit_object(tree_id, vec![head1], b"rx2 probe second")?;
    writer
        .push_raw(
            head2,
            &serialize(&second).map_err(|e| format!("commit bytes: {e}"))?,
        )
        .map_err(|e| format!("commit frame: {e}"))?;
    Ok((writer.finish().map_err(|e| format!("pack: {e}"))?, head2))
}

/// Publish a `files`-entry source, fork it into a fresh repository and poll
/// the embedded dispatch until the job answers. Returns the note fields.
async fn probe_once(ctx: &Ctx, files: u32) -> Result<String, Failure> {
    let signer = ctx.v2_signer("repository-a")?;
    let (pack, tip) = files_pack(files)?;
    let (source, _pending) =
        publish_named(ctx, &pack, tip, &format!("rx2-src-{files}"), None).await?;
    let (namespace, _) = source
        .rsplit_once('/')
        .ok_or("source repository has no namespace")?;
    let dest = format!("{namespace}/rx2-dst-{files}");
    // `ForkRequest::canonical_body`: magic, source, branch, tip, visibility.
    let body = format!(
        "mkit-fork:v1\n{source}\n{}\n{}\npublic",
        ctx.head("async"),
        to_hex(&tip),
    );
    let started = Instant::now();
    let mut attempts = 0u32;
    loop {
        attempts += 1;
        let mut env = signer.envelope(FORK_PROCEDURE, body_commitment(body.as_bytes()));
        env.repository = dest.clone();
        env.digest = Some(to_hex(&hash(body.as_bytes())));
        let op = signer.sign(&env);
        let reply = ctx
            .client()
            .post(
                FORK_PATH,
                "application/octet-stream",
                &op.headers,
                body.as_bytes().to_vec(),
            )
            .await?;
        if reply.status == 200 {
            let parsed: serde_json::Value = serde_json::from_slice(&reply.body)
                .map_err(|e| format!("fork reply is not JSON: {e}"))?;
            ensure!(
                parsed.get("tip").is_some() && parsed.get("pack_count").is_some(),
                "fork reply is not a result: {parsed}"
            );
            return Ok(format!(
                "files={files} fork_wall_ms={} attempts={attempts}",
                started.elapsed().as_millis(),
            ));
        }
        let code = serde_json::from_slice::<serde_json::Value>(&reply.body)
            .ok()
            .and_then(|parsed| {
                parsed
                    .get("code")
                    .and_then(|c| c.as_str())
                    .map(str::to_owned)
            })
            .unwrap_or_default();
        ensure!(
            matches!(code.as_str(), "aborted" | "unavailable"),
            "fork probe answered status {} {code}",
            reply.status,
        );
        ensure!(
            attempts < MAX_ATTEMPTS,
            "the fork never finished ({MAX_ATTEMPTS} polls)"
        );
        ctx.record_retry(&code);
        tokio::time::sleep(Duration::from_millis(POLL_MS)).await;
    }
}

/// The probe entry: one fork per size in `MKIT_FORK_PROBE_FILES`
/// (default `500,3000`), each on a fresh source and destination. The case
/// note carries the wall times and request attempt counts.
pub(super) async fn driver_probe(ctx: Ctx) -> CaseResult {
    let sizes = std::env::var(FILES_ENV)
        .ok()
        .map(|value| {
            value
                .split(',')
                .filter_map(|part| part.trim().parse::<u32>().ok())
                .collect::<Vec<_>>()
        })
        .filter(|sizes| !sizes.is_empty())
        .unwrap_or_else(|| vec![500, 3000]);
    let mut notes = Vec::new();
    for files in sizes {
        notes.push(probe_once(&ctx, files).await?);
    }
    ctx.set_note(notes.join("; "));
    Ok(())
}
