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
//! delivery counts it, so the value is eventually
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
use crate::repo::{NamespaceKey, RepoId, RepoName};

/// Most packs one source batch counts; the relay hook's observation budget
/// is sized for this (`MAX_TICKETS_PER_ADVANCE`).
pub(crate) const MAX_COUNTED_PACKS: usize = super::outbox::MAX_TICKETS_PER_ADVANCE;

/// A pack and its size in bytes.
pub(crate) type CountedPack = (Hash, u64);

/// A repository's wire identity: `<namespace>/<name>`, or the bare name in
/// the deployment-default namespace (as `Addressing::resolve` spells it).
#[must_use]
pub(crate) fn identity(namespace: &NamespaceKey, repo: &RepoName) -> String {
    if *namespace == NamespaceKey::deployment_default() {
        repo.as_str().to_owned()
    } else {
        format!("{}/{}", namespace.as_str(), repo.as_str())
    }
}

/// The outcome id of one counter change; unique per repository and version.
#[must_use]
pub(crate) fn outcome_id(identity: &str, version: u64) -> String {
    format!("rs:{}:{version}", &to_hex(&hash(identity.as_bytes()))[..32])
}

/// The counter a registration creates.
#[must_use]
pub(crate) fn initial_counter() -> Value {
    codec::encode_repo_storage(&RepoStorageV1::default())
}

/// Counter and marker rows an inline count of `packs` reads.
#[must_use]
pub(crate) fn read_keys(repo: &RepoName, packs: &[CountedPack]) -> Vec<Key> {
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
/// the coordinator, whose relay delivery counts them (`relay_extend`).
/// `relayed_before` says the consuming shard already holds a pack as a member.
#[allow(clippy::too_many_arguments)]
pub(crate) fn plan_count<'a>(
    repo: &RepoId,
    packs: &[CountedPack],
    source: &Partition,
    shards: &dyn ShardMap,
    get: impl Fn(&Key) -> Option<&'a Value>,
    relayed_before: impl Fn(&Hash) -> bool,
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
        // A pack this shard already holds had its marker relayed in the batch
        // that made it a member, so relaying it again only adds traffic.
        let fresh: Vec<_> = packs
            .iter()
            .filter(|(pack, _)| !relayed_before(pack))
            .map(|(pack, bytes)| {
                (
                    keys::repo_storage_pack(&repo.name, pack),
                    marker_value(*bytes),
                )
            })
            .collect();
        if !fresh.is_empty() {
            outbox.relay(&coordinator, fresh);
        }
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

/// The rows a coordinator's relay delivery observes to count `rows`' markers.
pub(crate) fn relay_read_keys(
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

/// Count the markers `rows` relay to a coordinator, in the delivery batch.
/// A repository without a counter is a corrupt store: the rows stay queued
/// (only that repository's stream stalls) until the counter exists.
pub(crate) fn relay_extend(
    target: &Partition,
    rows: &[(u64, RelayV1)],
    observed: &[(Key, Option<Value>)],
    pre: &mut Vec<Precondition>,
    writes: &mut Vec<Write>,
) -> Result<(), StoreError> {
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
    // Stamped like the sibling outcomes of the source batch: its plan time.
    let now_ms = rows.iter().map(|(_, r)| r.at_ms).max().unwrap_or(0);
    for (repo, packs) in &relayed {
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
}
