//! Compile an embedder's queries using only supported public APIs.
use mkit_server::fork::{ForkRequest, ForkResult, ForkSpec, Phase};
use mkit_server::pipeline::{Authenticated, HookSet, Pipeline, RepoVisibility, ShardMap};
use mkit_server::reads::{
    ForkJobStatus, ForkReplayIdentity, MemberReadLimits, PublishedBranch, ReadAccess,
};
use mkit_server::{BlobStore, MultipartBlobStore, NamespaceStore, RepoId, ServerError};

#[derive(Debug)]
pub struct RetainedLanding {
    pub result: ForkResult,
    pub reservation_id: String,
    pub declared_bytes: u64,
    pub authority_generation: u64,
}

#[must_use]
pub fn landing_matches(
    status: &ForkJobStatus,
    retained: &RetainedLanding,
    replay: &ForkReplayIdentity,
) -> bool {
    status.phase == Phase::Done
        && status.failure.is_none()
        && status.result.as_ref() == Some(&retained.result)
        && status.replay.as_ref().is_some_and(|original| {
            original.scope == replay.scope
                && original.fingerprint == replay.fingerprint
                && original.expires_at_ms == replay.expires_at_ms
        })
        && status.reservation.as_ref().is_some_and(|reservation| {
            reservation.id == retained.reservation_id
                && reservation.declared_bytes == retained.declared_bytes
        })
        && status.authority.as_ref().is_some_and(|authority| {
            authority.generation == Some(retained.authority_generation)
                && authority.grant_epoch.is_none()
                && !authority.creates_namespace
        })
}

// A downstream crate can compile this function without importing storage layouts,
// codecs, raw rows, index resolvers, or fork job encodings.
pub async fn embedding_queries<N: NamespaceStore, B: BlobStore>(
    store: &N,
    shards: &dyn ShardMap,
    blobs: &B,
    repo: &RepoId,
    spec: &ForkSpec,
    replay: &ForkReplayIdentity,
    retained: &RetainedLanding,
) -> Result<(), ServerError> {
    let reads = ReadAccess::new(store, shards, RepoVisibility::Public);
    let before = reads.repository_visibility(repo).await?;
    let pair = reads.published_branch(repo, "refs/heads/main").await?;
    let after = reads.repository_visibility(repo).await?;
    if let (Some(before), Some(after)) = (before, after) {
        let coherent = before.revision == after.revision;
        let _ = (coherent, after.visibility);
    }
    if let Some(pair) = pair {
        let _ = (
            pair.head,
            pair.packmap,
            pair.sequence,
            pair.published_sequence,
            pair.generation,
        );
        let _ = reads.locate_objects(repo, &[pair.head, pair.head]).await?;
        if let Some(member) = reads.locate_object(repo, &pair.head).await? {
            let _ = (
                member.pack,
                member.frame_offset,
                member.decoded_size,
                member.denied,
            );
            if let Some(inventory) = reads.member_inventory(repo, &pair.head).await? {
                let _ = (inventory.kind, inventory.canonical_len);
            }
            if let Some(canonical) = reads
                .read_member_canonical(
                    blobs,
                    repo,
                    pair.head,
                    MemberReadLimits {
                        max_delta_depth: 32,
                        max_decode_bytes: 8 << 20,
                    },
                )
                .await?
            {
                let _ = (canonical.bytes, canonical.decoded_bytes);
            }
        }
    }
    if let Some(status) = reads.fork_job_status(spec).await? {
        let _ = landing_matches(&status, retained, replay);
        let _ = (
            status.phase,
            status.failure,
            status.packs,
            status.authority,
            status.replay,
            status.reservation,
        );
    }
    if let Some(completed) = reads.recover_completed_fork(spec, replay).await? {
        let _ = (
            completed.result,
            completed.packs,
            completed.authority,
            completed.reservation,
        );
    }
    Ok(())
}

pub async fn published_for_authenticated_reader<
    B: MultipartBlobStore,
    N: NamespaceStore,
    H: HookSet,
>(
    pipeline: &Pipeline<B, N, H>,
    authenticated: &Authenticated,
    branch: &str,
) -> Result<Option<PublishedBranch>, ServerError> {
    let before = pipeline.read_ref(authenticated, branch).await?;
    let pair = pipeline
        .read_access()
        .published_branch(&authenticated.repo().repo, branch)
        .await?;
    let after = pipeline.read_ref(authenticated, branch).await?;
    if before != after || pair.as_ref().is_some_and(|pair| Some(pair.head) != after) {
        return Err(ServerError::unavailable("published branch changed; retry"));
    }
    Ok(pair)
}

pub async fn authenticated_completion<B: MultipartBlobStore, N: NamespaceStore, H: HookSet>(
    pipeline: &Pipeline<B, N, H>,
    authenticated: &Authenticated,
    request: &ForkRequest,
) -> Result<(), ServerError> {
    let _ = pipeline.read_access();
    if let Some(witness) = pipeline.completed_fork(authenticated, request).await? {
        let _ = (witness.source(), witness.destination());
    }
    Ok(())
}

#[test]
fn public_read_api_compiles_for_embedding_code() {
    // The generic functions above are type-checked as a downstream crate.
}
