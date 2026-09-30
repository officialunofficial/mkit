//! Metadata selection and repository-scoped canonical reads for HTTP proofs.
use mkit_core::hash::Hash;
use mkit_core::object::{ChunkedBlob, EntryMode, Object, ObjectType};
use mkit_core::verify::proof_size::{self, PrefixStep};

use super::resolve::{self, Budget, Env};
use super::{Fail, PreparedProof, ProofSource, TakedownGate, TakedownVerdict};
use crate::{BlobStore, BoxFuture, NamespaceStore, ServerError};

/// Prefix metadata is retained; canonical objects and proof bytes are not.
pub(crate) struct Context {
    pub commit: Hash,
    pub leaf: Hash,
    pub path: Vec<Vec<u8>>,
    pub ty: ObjectType,
    commit_len: u64,
    steps: Vec<PrefixStep>,
    leaf_len: u64,
    manifest: Option<ChunkedBlob>,
}

async fn clear(
    gate: &dyn TakedownGate,
    env: &Env<'_, impl BlobStore, impl NamespaceStore>,
    id: Hash,
) -> Result<(), Fail> {
    if gate.stops_descent(env.repo, &id) {
        return Err(Fail::NotFound);
    }
    match gate
        .check(env.repo, &id)
        .await
        .map_err(|e| Fail::from_server_error(&e))?
    {
        TakedownVerdict::Clear => Ok(()),
        TakedownVerdict::NotFound | TakedownVerdict::Respond(_) => Err(Fail::NotFound),
    }
}

/// Validate the whole context before validators or payment. A blocked
/// ancestor must never be bypassed by a cached leaf reachability answer.
pub(crate) async fn context<B: BlobStore, N: NamespaceStore>(
    env: &Env<'_, B, N>,
    gate: &dyn TakedownGate,
    commit: Hash,
    path: &[Vec<u8>],
    expected: Hash,
    budget: &mut Budget,
) -> Result<Context, Fail> {
    clear(gate, env, commit).await?;
    let located = resolve::locate(env, commit).await?;
    let bytes = resolve::load(env, commit, located, budget).await?;
    let commit_len = bytes.len() as u64;
    let mut current =
        match mkit_core::serialize::deserialize(&bytes).map_err(|_| Fail::Unavailable)? {
            Object::Commit(c) => c.tree_hash,
            Object::Remix(r) => r.tree_hash,
            _ => return Err(Fail::NotFound),
        };
    drop(bytes);
    let mut steps = Vec::new();
    for (index, name) in path.iter().enumerate() {
        clear(gate, env, current).await?;
        let located = resolve::locate(env, current).await?;
        let bytes = resolve::load(env, current, located, budget).await?;
        let Object::Tree(tree) =
            mkit_core::serialize::deserialize(&bytes).map_err(|_| Fail::Unavailable)?
        else {
            return Err(Fail::NotFound);
        };
        let position = mkit_core::merkle::tree_entry_position(&tree, name).ok_or(Fail::NotFound)?;
        let entry = &tree.entries[position as usize];
        if index + 1 < path.len() && entry.mode != EntryMode::Tree {
            return Err(Fail::NotFound);
        }
        steps.push(PrefixStep {
            name_len: name.len(),
            position,
            leaf_count: u32::try_from(tree.entries.len()).map_err(|_| Fail::Unavailable)?,
        });
        current = entry.object_hash;
    }
    if current != expected {
        return Err(Fail::NotFound);
    }
    // The caller checks the terminal leaf separately, preserving its 451
    // only after this exact context is established. Stops above it are 404.
    let located = resolve::locate(env, current).await?;
    let bytes = resolve::load(env, current, located, budget).await?;
    let leaf = mkit_core::serialize::deserialize(&bytes).map_err(|_| Fail::Unavailable)?;
    let ty = leaf.object_type();
    let manifest = match leaf {
        Object::ChunkedBlob(cb) => Some(cb),
        _ => None,
    };
    Ok(Context {
        commit,
        leaf: current,
        path: path.to_vec(),
        ty,
        commit_len,
        steps,
        leaf_len: bytes.len() as u64,
        manifest,
    })
}

impl Context {
    pub(crate) fn etag(&self, range: Option<(u64, u64)>) -> String {
        let selector = range.map_or_else(|| "object".to_owned(), |(a, b)| format!("range-{a}-{b}"));
        format!(
            "\"{}.{}.{selector}\"",
            mkit_core::hash::to_hex(&self.commit),
            mkit_core::hash::to_hex(&self.leaf)
        )
    }

    /// Establish bounds and exact size from metadata only. No chunk content
    /// after the selected span is read, including during preparation.
    pub(crate) async fn select<B: BlobStore, N: NamespaceStore>(
        &self,
        env: &Env<'_, B, N>,
        range: Option<(u64, u64)>,
    ) -> Result<PreparedProof, Fail> {
        let mut span = false;
        let encoded_len = if let Some((a, b)) = range {
            let len = b
                .checked_sub(a)
                .and_then(|n| n.checked_add(1))
                .ok_or(Fail::ProofRange)?;
            if len > env.cfg.max_proof_content_bytes {
                return Err(Fail::ProofRange);
            }
            if let Some(cb) = &self.manifest {
                if b >= cb.total_size {
                    return Err(Fail::ProofRange);
                }
                let mut sizer = proof_size::ChunkedRangeSizer::new(
                    self.commit_len,
                    &self.steps,
                    u32::try_from(cb.chunks.len()).map_err(|_| Fail::ProofRange)?,
                    a,
                    len,
                    env.cfg.max_proof_bundle_bytes,
                )
                .map_err(|_| Fail::ProofRange)?;
                let mut selected = None;
                let mut total = 0u64;
                for id in &cb.chunks {
                    let located = resolve::locate(env, *id).await?;
                    let length = located
                        .value
                        .decoded_size
                        .checked_sub(10)
                        .filter(|n| *n > 0)
                        .ok_or(Fail::Unavailable)?;
                    total = total.checked_add(length).ok_or(Fail::Unavailable)?;
                    if total > cb.total_size {
                        return Err(Fail::Unavailable);
                    }
                    if let Some(plan) = sizer.push(length).map_err(|_| Fail::ProofRange)? {
                        selected = Some(plan);
                        break;
                    }
                }
                let plan = selected.ok_or(Fail::ProofRange)?;
                span = plan.kind == mkit_core::verify::span::RangeProofKind::Mkds;
                plan.encoded_size
            } else if self.ty == ObjectType::Blob {
                proof_size::blob_range_proof_size(
                    self.commit_len,
                    &self.steps,
                    self.leaf_len,
                    a,
                    len,
                )
                .map_err(|_| Fail::ProofRange)?
            } else {
                return Err(Fail::ProofRange);
            }
        } else {
            proof_size::object_proof_size(self.commit_len, &self.steps, self.leaf_len)
                .map_err(|_| Fail::ProofRange)?
        };
        if encoded_len > env.cfg.max_proof_bundle_bytes {
            return Err(Fail::ProofRange);
        }
        Ok(PreparedProof {
            commit: self.commit,
            leaf: self.leaf,
            path: self.path.clone(),
            range,
            encoded_len,
            span,
        })
    }
}

/// The adapter may request only integrity-verified canonical objects from
/// this repository. Preceding chunks are released after each length proof.
pub(crate) struct RepositorySource<'a, B, N> {
    pub env: Env<'a, B, N>,
    pub budget: Budget,
    pub gate: &'a dyn TakedownGate,
}
impl<B: BlobStore, N: NamespaceStore> ProofSource for RepositorySource<'_, B, N> {
    fn read(&mut self, id: Hash) -> BoxFuture<'_, Result<Vec<u8>, ServerError>> {
        Box::pin(async move {
            clear(self.gate, &self.env, id)
                .await
                .map_err(|_| ServerError::unavailable("proof object unavailable"))?;
            let located = resolve::locate(&self.env, id)
                .await
                .map_err(|_| ServerError::unavailable("proof object unavailable"))?;
            let bytes = resolve::load(&self.env, id, located, &mut self.budget)
                .await
                .map_err(|_| ServerError::unavailable("proof object unavailable"))?;
            Ok(bytes.to_vec())
        })
    }
}
