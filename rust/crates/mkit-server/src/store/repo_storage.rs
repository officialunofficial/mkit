//! Exact per-repository stored-bytes accounting (SPEC-SERVER §6.5.1).
//!
//! The basis is pack bytes: the sum of the sizes of the distinct packs that
//! are members of a repository. A pack shared by two repositories counts in
//! each; nothing is deduplicated across repositories.
//!
//! The counter (`rb`) lives in the repository's coordinator, created with
//! the repository's registration. A repository's packs are consumed in many
//! ref shards, so the coordinator also holds one `rn` marker per counted
//! pack, and counts a pack exactly when it creates that marker: first
//! creation is decided by one guarded batch in one partition, whichever ref
//! shard consumed the pack and however often a relay row is redelivered.
//! Where the consuming partition is the coordinator (single-partition
//! deployments) the batch that consumes the pack counts it. Otherwise the
//! consuming batch relays the marker to the coordinator and the relay
//! target's [`RepoStorageHook`] counts it, so the value is eventually
//! consistent but never wrong. Every counter change also queues a
//! `RepoStorageChanged` outcome carrying the absolute value and its
//! monotonic version.

use std::collections::BTreeMap;

use mkit_core::hash::{Hash, hash, to_hex};

use super::codec::{self, RelayV1, RepoStorageV1, ReservationV1};
use super::keys;
use super::outbox::{OutboxBuilder, Terminal};
use super::{Key, Partition, Precondition, StoreError, Value, Write};
use crate::pipeline::ShardMap;
use crate::relay::RelayHook;
use crate::repo::{NamespaceKey, RepoId, RepoName};
use crate::rt::BoxFuture;

/// Most packs one source batch counts; the relay hook's observation budget
/// is sized for this (`MAX_TICKETS_PER_ADVANCE`).
pub const MAX_COUNTED_PACKS: usize = super::outbox::MAX_TICKETS_PER_ADVANCE;

/// A pack and its size in bytes.
pub type CountedPack = (Hash, u64);

/// A repository's wire identity: `<namespace>/<name>`, or the bare name in
/// the deployment-default namespace (as `Addressing::resolve` spells it).
#[must_use]
pub fn identity(namespace: &NamespaceKey, repo: &RepoName) -> String {
    if *namespace == NamespaceKey::deployment_default() {
        repo.as_str().to_owned()
    } else {
        format!("{}/{}", namespace.as_str(), repo.as_str())
    }
}

/// The outcome id of one counter change; unique per repository and version.
#[must_use]
pub fn outcome_id(identity: &str, version: u64) -> String {
    format!("rs:{}:{version}", &to_hex(&hash(identity.as_bytes()))[..32])
}

/// The counter a registration creates.
#[must_use]
pub fn initial_counter() -> Value {
    codec::encode_repo_storage(&RepoStorageV1::default())
}

/// Counter and marker rows an inline count of `packs` reads.
#[must_use]
pub fn read_keys(repo: &RepoName, packs: &[CountedPack]) -> Vec<Key> {
    std::iter::once(keys::repo_storage(repo))
        .chain(
            packs
                .iter()
                .map(|(pack, _)| keys::repo_storage_pack(repo, pack)),
        )
        .collect()
}

fn marker_value(bytes: u64) -> Value {
    codec::encode_u64(bytes)
}

/// Add the packs whose markers are absent to the counter, in the caller's
/// atomic fragment. Each pack carries whether its marker was observed.
/// `put_markers` is false when the fragment already writes the markers (a
/// relay target applies the relayed rows itself, and guards each marker).
#[allow(clippy::too_many_arguments)]
fn apply(
    namespace: &NamespaceKey,
    repo: &RepoName,
    counter: Option<&Value>,
    packs: &[(CountedPack, bool)],
    put_markers: bool,
    now_ms: u64,
    outbox: &mut OutboxBuilder,
    pre: &mut Vec<Precondition>,
    writes: &mut Vec<Write>,
) -> Result<(), StoreError> {
    let raw = counter.ok_or_else(|| StoreError::Corrupt("repository counter missing".into()))?;
    let mut state = codec::decode_repo_storage(raw)?;
    let mut added = 0u64;
    let mut fresh = std::collections::BTreeSet::new();
    for ((pack, bytes), counted) in packs {
        if *counted || !fresh.insert(*pack) {
            continue;
        }
        let marker = keys::repo_storage_pack(repo, pack);
        if put_markers {
            // The counter guard below already serializes every counting batch
            // of this partition, so the marker needs no guard of its own.
            writes.push(Write::Put(marker, marker_value(*bytes)));
        } else {
            pre.push(Precondition::Absent(marker));
        }
        added = added
            .checked_add(*bytes)
            .ok_or_else(|| StoreError::Corrupt("repository counter overflow".into()))?;
    }
    if fresh.is_empty() {
        return Ok(());
    }
    state.stored_bytes = state
        .stored_bytes
        .checked_add(added)
        .ok_or_else(|| StoreError::Corrupt("repository counter overflow".into()))?;
    state.version = state
        .version
        .checked_add(1)
        .ok_or_else(|| StoreError::Corrupt("repository counter version overflow".into()))?;
    let key = keys::repo_storage(repo);
    pre.push(Precondition::Equals(key.clone(), raw.clone()));
    writes.push(Write::Put(key, codec::encode_repo_storage(&state)));
    let identity = identity(namespace, repo);
    outbox.storage_changed(
        &outcome_id(&identity, state.version),
        Terminal::new(ReservationV1::RepoStorageChanged {
            repository: identity,
            occurred_at_ms: now_ms,
            stored_bytes: state.stored_bytes,
            version: state.version,
        })?,
    );
    Ok(())
}

/// Count packs consumed by one source batch. When `source` is the
/// repository's coordinator the counter changes in this same batch (`get`
/// serves the rows [`read_keys`] named); otherwise the markers are relayed to
/// the coordinator, whose [`RepoStorageHook`] counts them.
#[allow(clippy::too_many_arguments)]
pub fn plan_count<'a>(
    repo: &RepoId,
    packs: &[CountedPack],
    source: &Partition,
    shards: &dyn ShardMap,
    get: impl Fn(&Key) -> Option<&'a Value>,
    now_ms: u64,
    outbox: &mut OutboxBuilder,
    pre: &mut Vec<Precondition>,
    writes: &mut Vec<Write>,
) -> Result<(), StoreError> {
    if packs.is_empty() {
        return Ok(());
    }
    let coordinator = shards.coordinator(&repo.namespace);
    if *source != coordinator {
        outbox.relay(
            &coordinator,
            packs
                .iter()
                .map(|(pack, bytes)| {
                    (
                        keys::repo_storage_pack(&repo.name, pack),
                        marker_value(*bytes),
                    )
                })
                .collect(),
        );
        return Ok(());
    }
    let observed: Vec<_> = packs
        .iter()
        .map(|&(pack, bytes)| {
            let counted = get(&keys::repo_storage_pack(&repo.name, &pack)).is_some();
            ((pack, bytes), counted)
        })
        .collect();
    apply(
        &repo.namespace,
        &repo.name,
        get(&keys::repo_storage(&repo.name)),
        &observed,
        true,
        now_ms,
        outbox,
        pre,
        writes,
    )
}

/// Counts relayed `rn` markers in the coordinator that receives them.
///
/// Install it on every relay handler whose targets include a coordinator,
/// alongside any other hook: a coordinator that receives markers without it
/// stores them uncounted. Uses supplied observations only.
#[derive(Debug, Default, Clone, Copy)]
pub struct RepoStorageHook;

/// Marker puts of every repository the rows relay, in row order.
fn relayed(rows: &[(u64, RelayV1)]) -> Result<BTreeMap<RepoName, Vec<CountedPack>>, StoreError> {
    let mut out: BTreeMap<RepoName, Vec<CountedPack>> = BTreeMap::new();
    for (_, row) in rows {
        for (key, value) in &row.puts {
            if let Some(keys::ParsedKey::RepoStoragePack { repo, pack_id }) = keys::parse(key) {
                out.entry(repo)
                    .or_default()
                    .push((pack_id, codec::decode_u64(value)?));
            }
        }
    }
    Ok(out)
}

impl RelayHook for RepoStorageHook {
    fn read_keys(
        &self,
        target: &Partition,
        rows: &[(u64, RelayV1)],
    ) -> Result<Vec<Key>, StoreError> {
        if !matches!(target, Partition::Coordinator(_)) {
            return Ok(Vec::new());
        }
        let relayed = relayed(rows)?;
        if relayed.is_empty() {
            return Ok(Vec::new());
        }
        let mut out = vec![keys::outbox_sequence(), keys::outcome_backlog()];
        for (repo, packs) in &relayed {
            out.extend(read_keys(repo, packs));
        }
        Ok(out)
    }

    fn before_apply<'a>(
        &'a self,
        _target: &'a Partition,
        rows: &'a [(u64, RelayV1)],
        _pre: &'a mut Vec<Precondition>,
        _writes: &'a mut Vec<Write>,
    ) -> BoxFuture<'a, Result<(), StoreError>> {
        Box::pin(async move {
            if relayed(rows)?.is_empty() {
                Ok(())
            } else {
                Err(StoreError::Invalid("storage rows need observations".into()))
            }
        })
    }

    fn before_apply_observed<'a>(
        &'a self,
        target: &'a Partition,
        rows: &'a [(u64, RelayV1)],
        observed: &'a [(Key, Option<Value>)],
        pre: &'a mut Vec<Precondition>,
        writes: &'a mut Vec<Write>,
    ) -> BoxFuture<'a, Result<(), StoreError>> {
        Box::pin(async move {
            let Partition::Coordinator(namespace) = target else {
                return Ok(());
            };
            let relayed = relayed(rows)?;
            if relayed.is_empty() {
                return Ok(());
            }
            let get = |key: &Key| {
                observed
                    .iter()
                    .find(|(k, _)| k == key)
                    .map(|(_, v)| v.as_ref())
                    .ok_or_else(|| StoreError::Corrupt("missing storage observation".into()))
            };
            let mut outbox = OutboxBuilder::new(
                get(&keys::outbox_sequence())?,
                get(&keys::outcome_backlog())?,
            )?;
            // The change happened when its source batch committed.
            let now_ms = rows.iter().map(|(_, r)| r.at_ms).max().unwrap_or(0);
            for (repo, packs) in &relayed {
                if get(&keys::repo_storage(repo))?.is_none() {
                    // A corrupt store: failing here would wedge every other
                    // row this coordinator receives from the source. Drop the
                    // markers uncounted; the repository's read reports the
                    // missing counter and its inline writes fail.
                    tracing::warn!(
                        repo = repo.as_str(),
                        "repository counter missing; storage markers dropped"
                    );
                    writes.retain(|write| {
                        !matches!(write, Write::Put(key, _)
                            if matches!(keys::parse(key),
                                Some(keys::ParsedKey::RepoStoragePack { repo: r, .. }) if r == *repo))
                    });
                    continue;
                }
                let packs = packs
                    .iter()
                    .map(|&pack| {
                        Ok((
                            pack,
                            get(&keys::repo_storage_pack(repo, &pack.0))?.is_some(),
                        ))
                    })
                    .collect::<Result<Vec<_>, StoreError>>()?;
                apply(
                    namespace,
                    repo,
                    get(&keys::repo_storage(repo))?,
                    &packs,
                    false,
                    now_ms,
                    &mut outbox,
                    pre,
                    writes,
                )?;
            }
            outbox.try_finish(pre, writes)
        })
    }
}
