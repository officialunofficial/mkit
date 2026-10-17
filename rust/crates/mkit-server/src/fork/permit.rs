//! Membership projection permits, drained before a namespace fence moves.

use mkit_core::hash::Hash;
use serde::{Deserialize, Serialize};

use super::{ForkEnv, ForkError, ForkJobV1};
use crate::repo::{NamespaceKey, RepoName};
use crate::store::{
    Batch, BatchOutcome, Cursor, Key, NamespaceStore, Partition, Precondition, Value, codec, keys,
};

const DRAIN_ROWS: u32 = 4;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    binding: Hash,
    repo: String,
    prefix: u16,
    authority: Option<Vec<u8>>,
    epoch: Option<Vec<u8>>,
    expires_ms: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Drain {
    authority: bool,
    old: Option<Vec<u8>>,
    next: Vec<u8>,
    after: Option<Vec<u8>>,
}

fn encode<T: Serialize>(value: &T) -> Result<Value, ForkError> {
    serde_json::to_vec(value)
        .map(Value::new)
        .map_err(|_| ForkError::Unavailable("fork permit encoding"))
}
fn decode<T: serde::de::DeserializeOwned>(value: &Value) -> Result<T, ForkError> {
    serde_json::from_slice(value.as_bytes())
        .map_err(|_| ForkError::Unavailable("fork permit corrupt"))
}
fn observed(key: Key, value: Option<&Value>) -> Precondition {
    crate::store::outbox::guard(key, value)
}
fn local_value(record: &Value, active: bool) -> Value {
    Value::new([&[u8::from(active)][..], record.as_bytes()].concat())
}

/// The exact local authority a physical membership batch must guard.
pub(crate) struct Permit {
    guards: Vec<Precondition>,
}
impl Permit {
    pub(crate) fn guards(&self) -> Vec<Precondition> {
        self.guards.clone()
    }
}

/// Read the local CAS observation before registration, so a concurrent drain's
/// tombstone prevents even an installation delayed beyond coordinator removal.
pub(crate) async fn prepare<S: NamespaceStore>(
    env: &ForkEnv<'_, S>,
    job: &ForkJobV1,
    target: &Partition,
) -> Result<Permit, ForkError> {
    let dest = job.dest()?;
    if *target == env.shards.coordinator(&dest.namespace) {
        // Co-located stores compare the actual authority rows in the same
        // atomic membership batch; no distributed permission is required.
        let mut guards = job.fence_rows.guards(job);
        guards.push(Precondition::NotAfter(
            env.now().saturating_add(super::CONTENT_WINDOW),
        ));
        return Ok(Permit { guards });
    }
    let Partition::RepoIndex { ns, repo, prefix } = target else {
        return Err(ForkError::Unavailable(
            "fork permit requires membership partition",
        ));
    };
    if *ns != dest.namespace
        || *repo != dest.name
        || !env.shards.object_index_partitions(&dest).contains(target)
    {
        return Err(ForkError::Unavailable(
            "fork permit membership partition mismatch",
        ));
    }
    let local_key = keys::fork_permit_local(repo);
    let local = env.store.get(target, &local_key).await?;
    let (record, value) = register(env, job, ns, repo, *prefix).await?;
    let active = local_value(&value, true);
    let install = Batch::new()
        .require(observed(local_key.clone(), local.as_ref()))
        .require(Precondition::NotAfter(record.expires_ms))
        .put(local_key.clone(), active.clone());
    if env.store.apply(target, install).await? != BatchOutcome::Committed {
        // Sibling members in the same wave deliberately share one permit.
        // A drain tombstone or a different token never satisfies this check.
        if env.store.get(target, &local_key).await?.as_ref() != Some(&active) {
            super::job::fence_after_loss(env, job).await?;
            return Err(ForkError::Unavailable("fork permit installation raced"));
        }
    }
    Ok(Permit {
        guards: vec![
            Precondition::Equals(local_key, active),
            Precondition::NotAfter(record.expires_ms),
        ],
    })
}

fn matching_record(value: &Value, expected: &Record, now: u64) -> Result<Record, ForkError> {
    let record: Record = decode(value)?;
    matching_binding(&record, expected)?;
    if record.expires_ms <= now {
        return Err(ForkError::Unavailable("fork permit expired"));
    }
    Ok(record)
}

fn matching_binding(record: &Record, expected: &Record) -> Result<(), ForkError> {
    if record.binding != expected.binding
        || record.repo != expected.repo
        || record.prefix != expected.prefix
        || record.authority != expected.authority
        || record.epoch != expected.epoch
    {
        return Err(ForkError::Unavailable("fork permit binding changed"));
    }
    Ok(())
}

/// Reuse live tokens rather than extending them on every sibling projection.
async fn register<S: NamespaceStore>(
    env: &ForkEnv<'_, S>,
    job: &ForkJobV1,
    ns: &NamespaceKey,
    repo: &RepoName,
    prefix: u16,
) -> Result<(Record, Value), ForkError> {
    let coordinator = env.shards.coordinator(ns);
    let registry_key = keys::fork_permit(repo, prefix);
    let drain_key = keys::fork_permit_drain();
    let rows = env
        .store
        .get_many(
            &coordinator,
            &[
                keys::authority_generation(),
                keys::grant_epoch(),
                drain_key.clone(),
                registry_key.clone(),
            ],
        )
        .await?;
    let [authority, epoch, drain, previous]: [_; 4] = rows
        .try_into()
        .map_err(|_| ForkError::Unavailable("fork permit read"))?;
    job.fence_rows.check(job, &[authority, epoch])?;
    if drain.is_some() {
        return Err(ForkError::Unavailable("fork authority transition pending"));
    }
    let expected = Record {
        binding: job.binding,
        repo: repo.as_str().to_owned(),
        prefix,
        authority: job.fence_rows.authority.clone(),
        epoch: job.fence_rows.epoch.clone(),
        expires_ms: env.now().saturating_add(super::CONTENT_WINDOW),
    };
    let (record, value) = match previous.as_ref() {
        Some(value) => {
            // Validate identity even when an expired token needs replacement.
            let prior: Record = decode(value)?;
            matching_binding(&prior, &expected)?;
            if prior.expires_ms > env.now() {
                (prior, value.clone())
            } else {
                (expected.clone(), encode(&expected)?)
            }
        }
        None => (expected.clone(), encode(&expected)?),
    };
    let mut registration = Batch::new()
        .require(Precondition::Absent(drain_key))
        .require(Precondition::Equals(
            keys::fork_barrier(repo),
            Value::new(job.binding.to_vec()),
        ))
        .require(observed(registry_key.clone(), previous.as_ref()))
        .require(Precondition::NotAfter(record.expires_ms))
        .put(registry_key, value.clone())
        .put(keys::fork_permits_seen(), Value::default());
    registration
        .preconditions
        .extend(job.fence_rows.guards(job));
    if env.store.apply(&coordinator, registration).await? == BatchOutcome::Committed {
        return Ok((record, value));
    }
    registered_after_loss(env, job, ns, repo, prefix, &expected).await
}

/// Adopt only the exact token that won registration under the same live fence.
async fn registered_after_loss<S: NamespaceStore>(
    env: &ForkEnv<'_, S>,
    job: &ForkJobV1,
    ns: &NamespaceKey,
    repo: &RepoName,
    prefix: u16,
    expected: &Record,
) -> Result<(Record, Value), ForkError> {
    let rows = env
        .store
        .get_many(
            &env.shards.coordinator(ns),
            &[
                keys::fork_job(repo),
                keys::authority_generation(),
                keys::grant_epoch(),
                keys::fork_permit(repo, prefix),
                keys::fork_permit_drain(),
                keys::fork_barrier(repo),
            ],
        )
        .await?;
    let [current, authority, epoch, permit, drain, barrier]: [_; 6] = rows
        .try_into()
        .map_err(|_| ForkError::Unavailable("fork permit read"))?;
    job.fence_rows.check(job, &[authority, epoch])?;
    let current = current.ok_or(ForkError::Unavailable("fork job missing"))?;
    let current = super::decode_job(&current)?;
    if current.binding != job.binding
        || current.finished()
        || drain.is_some()
        || barrier.as_ref() != Some(&Value::new(job.binding.to_vec()))
    {
        return Err(ForkError::Unavailable("fork permit registration raced"));
    }
    let value = permit.ok_or(ForkError::Unavailable("fork permit registration raced"))?;
    let record = matching_record(&value, expected, env.now())?;
    Ok((record, value))
}

/// Invalidate and remove a completed job's permits after its destination
/// barrier is gone. Stale drivers cannot register replacements after Done.
pub(crate) async fn release<S: NamespaceStore>(
    env: &ForkEnv<'_, S>,
    job: &ForkJobV1,
) -> Result<bool, ForkError> {
    if job.phase != super::Phase::Done {
        return Err(ForkError::Unavailable(
            "fork permit cleanup before completion",
        ));
    }
    let dest = job.dest()?;
    let coordinator = env.shards.coordinator(&dest.namespace);
    let (start, end) = keys::fork_permit_repo_range(&dest.name);
    let page = env
        .store
        .scan(&coordinator, &start, &end, None, DRAIN_ROWS)
        .await?;
    if page.entries.len() > DRAIN_ROWS as usize || (page.entries.is_empty() && page.next.is_some())
    {
        return Err(ForkError::Unavailable("fork permit cleanup scan corrupt"));
    }
    for (key, value) in page.entries {
        let record: Record = decode(&value)?;
        if record.binding != job.binding
            || record.repo != dest.name.as_str()
            || key != keys::fork_permit(&dest.name, record.prefix)
        {
            return Err(ForkError::Unavailable(
                "fork permit cleanup binding changed",
            ));
        }
        let target = Partition::RepoIndex {
            ns: dest.namespace.clone(),
            repo: dest.name.clone(),
            prefix: record.prefix,
        };
        if !env.shards.object_index_partitions(&dest).contains(&target) {
            return Err(ForkError::Unavailable("fork permit cleanup target corrupt"));
        }
        let local_key = keys::fork_permit_local(&dest.name);
        let local = env.store.get(&target, &local_key).await?;
        let tombstone = local_value(&value, false);
        if local.as_ref() != Some(&tombstone) {
            let batch = Batch::new()
                .require(observed(local_key.clone(), local.as_ref()))
                .require(Precondition::NotAfter(
                    env.now().saturating_add(super::CONTENT_WINDOW),
                ))
                .put(local_key, tombstone);
            if env.store.apply(&target, batch).await? != BatchOutcome::Committed {
                return Ok(false);
            }
        }
        let batch = Batch::new()
            .require(Precondition::Absent(keys::fork_barrier(&dest.name)))
            .require(Precondition::Equals(key.clone(), value))
            .require(Precondition::NotAfter(
                env.now().saturating_add(super::CONTENT_WINDOW),
            ))
            .delete(key);
        if env.store.apply(&coordinator, batch).await? != BatchOutcome::Committed {
            return Ok(false);
        }
    }
    Ok(page.next.is_none())
}

/// Freeze registrations, invalidate at most four registered local permits, and
/// publish the new fence only after every previously registered permit is dead.
/// The drain and cursor are durable; a lost reply repeats idempotent invalidation.
#[allow(clippy::too_many_lines)] // One durable drain orders bounded invalidation before fence publication.
pub(crate) async fn transition<S: NamespaceStore>(
    env: &ForkEnv<'_, S>,
    ns: &NamespaceKey,
    fence: &Key,
    old: Option<&Value>,
    next: &Value,
    recovery_holdoff_ms: u64,
) -> Result<bool, ForkError> {
    let coordinator = env.shards.coordinator(ns);
    let drain_key = keys::fork_permit_drain();
    let rows = env
        .store
        .get_many(&coordinator, &[drain_key.clone(), keys::lease_recovery()])
        .await?;
    let [mut raw, recovery_value]: [_; 2] = rows
        .try_into()
        .map_err(|_| ForkError::Unavailable("fork permit recovery read"))?;
    let recovery = recovery_value
        .as_ref()
        .map(codec::decode_lease_recovery)
        .transpose()?;
    if recovery
        .and_then(codec::LeaseRecovery::recovery_time)
        .is_some_and(|resumed| env.now() < resumed.saturating_add(recovery_holdoff_ms))
    {
        return Ok(false);
    }
    let authority = if *fence == keys::authority_generation() {
        true
    } else if *fence == keys::grant_epoch() {
        false
    } else {
        return Err(ForkError::Unavailable("invalid fork permit fence"));
    };
    let mut drain = match &raw {
        Some(value) => decode::<Drain>(value)?,
        None => Drain {
            authority,
            old: old.map(|v| v.as_bytes().to_vec()),
            next: next.as_bytes().to_vec(),
            after: None,
        },
    };
    let requested = drain.authority == authority
        && drain.old.as_deref() == old.map(Value::as_bytes)
        && drain.next == next.as_bytes();
    // The original verified requester may never return. A later authorized
    // transition helps its durable drain, but cannot acknowledge its own
    // different target until a fresh observation starts that transition.
    let draining_fence = if drain.authority {
        keys::authority_generation()
    } else {
        keys::grant_epoch()
    };
    let draining_old = drain.old.as_ref().map(|bytes| Value::new(bytes.clone()));
    let draining_next = Value::new(drain.next.clone());
    let prior_generation = draining_old
        .as_ref()
        .map(codec::decode_u64)
        .transpose()?
        .unwrap_or(0);
    let next_generation = codec::decode_u64(&draining_next)?;
    let bootstrap = drain.authority && draining_old.is_none() && next_generation == 0;
    if !bootstrap
        && mkit_attest::grant::epoch_transition(prior_generation, next_generation)
            != mkit_attest::grant::EpochTransition::Advance
    {
        return Err(ForkError::Unavailable(
            "fork permit drain generation corrupt",
        ));
    }
    if raw.is_none() {
        let value = encode(&drain)?;
        let batch = Batch::new()
            .require(Precondition::NotAfter(
                env.now().saturating_add(super::CONTENT_WINDOW),
            ))
            .require(Precondition::Absent(drain_key.clone()))
            .require(observed(fence.clone(), old))
            .put(drain_key.clone(), value.clone());
        if env.store.apply(&coordinator, batch).await? != BatchOutcome::Committed {
            return Ok(false);
        }
        raw = Some(value);
    }
    let (start, end) = keys::fork_permit_range();
    if drain
        .after
        .as_ref()
        .is_some_and(|key| key.as_slice() < start.as_bytes() || key.as_slice() >= end.as_bytes())
    {
        return Err(ForkError::Unavailable("fork permit cursor corrupt"));
    }
    let cursor = drain.after.clone().map(Cursor::new);
    let page = env
        .store
        .scan(&coordinator, &start, &end, cursor.as_ref(), DRAIN_ROWS)
        .await?;
    if page.entries.len() > DRAIN_ROWS as usize || (page.entries.is_empty() && page.next.is_some())
    {
        return Err(ForkError::Unavailable("fork permit scan corrupt"));
    }
    for (key, value) in page.entries {
        let record: Record = decode(&value)?;
        let repo = RepoName::new(record.repo.clone())
            .map_err(|_| ForkError::Unavailable("fork permit repository corrupt"))?;
        if key != keys::fork_permit(&repo, record.prefix)
            || key < start
            || key >= end
            || drain
                .after
                .as_ref()
                .is_some_and(|after| key.as_bytes() <= after.as_slice())
        {
            return Err(ForkError::Unavailable("fork permit registry corrupt"));
        }
        let target = Partition::RepoIndex {
            ns: ns.clone(),
            repo: repo.clone(),
            prefix: record.prefix,
        };
        let dest = crate::RepoId {
            namespace: ns.clone(),
            name: repo.clone(),
        };
        if !env.shards.object_index_partitions(&dest).contains(&target) {
            return Err(ForkError::Unavailable("fork permit target corrupt"));
        }
        let local_key = keys::fork_permit_local(&repo);
        let local = env.store.get(&target, &local_key).await?;
        let tombstone = local_value(&value, false);
        if local.as_ref() != Some(&tombstone) {
            let invalidation = Batch::new()
                .require(Precondition::NotAfter(
                    env.now().saturating_add(super::CONTENT_WINDOW),
                ))
                .require(observed(local_key.clone(), local.as_ref()))
                .put(local_key, tombstone);
            if env.store.apply(&target, invalidation).await? != BatchOutcome::Committed {
                return Ok(false);
            }
        }
        let prior = raw
            .as_ref()
            .ok_or(ForkError::Unavailable("fork permit drain missing"))?;
        drain.after = Some(key.as_bytes().to_vec());
        let updated = encode(&drain)?;
        let acknowledgement = Batch::new()
            .require(Precondition::NotAfter(
                env.now().saturating_add(super::CONTENT_WINDOW),
            ))
            .require(Precondition::Equals(drain_key.clone(), prior.clone()))
            .require(Precondition::Equals(key.clone(), value))
            .delete(key)
            .put(drain_key.clone(), updated.clone());
        if env.store.apply(&coordinator, acknowledgement).await? != BatchOutcome::Committed {
            return Ok(false);
        }
        raw = Some(updated);
    }
    if page.next.is_some() {
        return Ok(false);
    }
    let finish = Batch::new()
        .require(Precondition::NotAfter(
            env.now().saturating_add(super::CONTENT_WINDOW),
        ))
        .require(Precondition::Equals(
            drain_key.clone(),
            raw.ok_or(ForkError::Unavailable("fork permit drain missing"))?,
        ))
        .require(observed(draining_fence.clone(), draining_old.as_ref()))
        .require(observed(keys::lease_recovery(), recovery_value.as_ref()))
        .put(draining_fence, draining_next)
        .delete(drain_key);
    let completed = env.store.apply(&coordinator, finish).await? == BatchOutcome::Committed;
    Ok(completed && requested)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::MemoryKv;
    use crate::pipeline::{D34Shards, ShardMap};
    use crate::rt::ManualClock;
    use futures_executor::block_on;
    use std::sync::Arc;

    #[test]
    fn drain_invalidates_both_installed_and_delayed_local_permits() {
        for (installed, bootstrap) in [(false, false), (true, false), (false, true), (true, true)] {
            let clock = Arc::new(ManualClock::new(1_000));
            let store = MemoryKv::with_clock(clock.clone());
            let shards = D34Shards;
            let ns = NamespaceKey::deployment_default();
            let repo = RepoName::new("destination").unwrap();
            let coordinator = shards.coordinator(&ns);
            let target = Partition::RepoIndex {
                ns: ns.clone(),
                repo: repo.clone(),
                prefix: 0,
            };
            let old = (!bootstrap).then(|| codec::encode_u64(0));
            let next = codec::encode_u64(u64::from(!bootstrap));
            let value = encode(&Record {
                binding: [1; 32],
                repo: repo.as_str().to_owned(),
                prefix: 0,
                authority: old.as_ref().map(|value| value.as_bytes().to_vec()),
                epoch: None,
                expires_ms: 10_000,
            })
            .unwrap();
            let active = local_value(&value, true);
            let mut registration = Batch::new()
                .put(keys::fork_permit(&repo, 0), value)
                .put(keys::fork_permits_seen(), Value::default());
            if let Some(old) = &old {
                registration = registration.put(keys::authority_generation(), old.clone());
            }
            block_on(store.apply(&coordinator, registration)).unwrap();
            if installed {
                block_on(store.apply(
                    &target,
                    Batch::new().put(keys::fork_permit_local(&repo), active.clone()),
                ))
                .unwrap();
            }
            let env = ForkEnv {
                store: &store,
                shards: &shards,
                clock: clock.as_ref(),
                takedown_denial: false,
                extract_min_bytes: None,
                limits: super::super::ForkLimits::default(),
            };
            assert!(
                block_on(transition(
                    &env,
                    &ns,
                    &keys::authority_generation(),
                    old.as_ref(),
                    &next,
                    0,
                ))
                .unwrap()
            );
            let stale = Batch::new()
                .require(Precondition::Equals(
                    keys::fork_permit_local(&repo),
                    active.clone(),
                ))
                .require(Precondition::NotAfter(10_000))
                .put(keys::membership(&repo, &[2; 32]), Value::default());
            assert!(matches!(
                block_on(store.apply(&target, stale)).unwrap(),
                BatchOutcome::PreconditionFailed { .. }
            ));
            let delayed_install = Batch::new()
                .require(Precondition::Absent(keys::fork_permit_local(&repo)))
                .require(Precondition::NotAfter(10_000))
                .put(keys::fork_permit_local(&repo), active);
            assert!(matches!(
                block_on(store.apply(&target, delayed_install)).unwrap(),
                BatchOutcome::PreconditionFailed { .. }
            ));
            assert_eq!(
                block_on(store.get(&coordinator, &keys::authority_generation())).unwrap(),
                Some(next)
            );
        }
    }

    #[test]
    fn a_drain_keeps_the_old_fence_until_every_bounded_page_is_invalidated() {
        let clock = Arc::new(ManualClock::new(1_000));
        let store = MemoryKv::with_clock(clock.clone());
        let shards = D34Shards;
        let ns = NamespaceKey::deployment_default();
        let coordinator = shards.coordinator(&ns);
        let old = codec::encode_u64(0);
        let mut initial = Batch::new().put(keys::grant_epoch(), old.clone());
        for index in 0..5 {
            let repo = RepoName::new(format!("destination-{index}")).unwrap();
            initial = initial.put(
                keys::fork_permit(&repo, 0),
                encode(&Record {
                    binding: [1; 32],
                    repo: repo.as_str().to_owned(),
                    prefix: 0,
                    authority: None,
                    epoch: Some(old.as_bytes().to_vec()),
                    expires_ms: 10_000,
                })
                .unwrap(),
            );
        }
        block_on(store.apply(&coordinator, initial)).unwrap();
        let env = ForkEnv {
            store: &store,
            shards: &shards,
            clock: clock.as_ref(),
            takedown_denial: false,
            extract_min_bytes: None,
            limits: super::super::ForkLimits::default(),
        };
        assert!(
            !block_on(transition(
                &env,
                &ns,
                &keys::grant_epoch(),
                Some(&old),
                &codec::encode_u64(1),
                0,
            ))
            .unwrap()
        );
        assert_eq!(
            block_on(store.get(&coordinator, &keys::grant_epoch())).unwrap(),
            Some(old.clone())
        );
        assert!(
            block_on(store.get(&coordinator, &keys::fork_permit_drain()))
                .unwrap()
                .is_some()
        );
        assert!(
            block_on(transition(
                &env,
                &ns,
                &keys::grant_epoch(),
                Some(&old),
                &codec::encode_u64(1),
                0,
            ))
            .unwrap()
        );
        assert_eq!(
            block_on(store.get(&coordinator, &keys::grant_epoch())).unwrap(),
            Some(codec::encode_u64(1))
        );
        assert!(
            block_on(store.get(&coordinator, &keys::fork_permit_drain()))
                .unwrap()
                .is_none()
        );
    }
    #[test]
    fn recovery_cannot_publish_a_fence_before_lost_permits_expire() {
        let clock = Arc::new(ManualClock::new(1_000));
        let store = MemoryKv::with_clock(clock.clone());
        let shards = D34Shards;
        let ns = NamespaceKey::deployment_default();
        let coordinator = shards.coordinator(&ns);
        let old = codec::encode_u64(0);
        block_on(
            store.apply(
                &coordinator,
                Batch::new()
                    .put(keys::authority_generation(), old.clone())
                    .put(
                        keys::lease_recovery(),
                        codec::encode_lease_recovery(&codec::LeaseRecovery {
                            resumed_at_ms: 1_000,
                            authority_fence: None,
                            authority_ready: None,
                            activation_only: None,
                        }),
                    ),
            ),
        )
        .unwrap();
        let env = ForkEnv {
            store: &store,
            shards: &shards,
            clock: clock.as_ref(),
            takedown_denial: false,
            extract_min_bytes: None,
            limits: super::super::ForkLimits::default(),
        };
        assert!(
            !block_on(transition(
                &env,
                &ns,
                &keys::authority_generation(),
                Some(&old),
                &codec::encode_u64(1),
                10_000
            ))
            .unwrap()
        );
        assert_eq!(
            block_on(store.get(&coordinator, &keys::authority_generation())).unwrap(),
            Some(old.clone())
        );
        clock.advance(10_000);
        assert!(
            block_on(transition(
                &env,
                &ns,
                &keys::authority_generation(),
                Some(&old),
                &codec::encode_u64(1),
                10_000
            ))
            .unwrap()
        );
    }
    #[test]
    fn later_targets_and_other_fence_kinds_redrive_an_abandoned_drain() {
        for other_kind in [false, true] {
            let clock = Arc::new(ManualClock::new(1_000));
            let store = MemoryKv::with_clock(clock.clone());
            let shards = D34Shards;
            let ns = NamespaceKey::deployment_default();
            let coordinator = shards.coordinator(&ns);
            let old = codec::encode_u64(0);
            let abandoned = encode(&Drain {
                authority: true,
                old: Some(old.as_bytes().to_vec()),
                next: codec::encode_u64(1).as_bytes().to_vec(),
                after: None,
            })
            .unwrap();
            block_on(
                store.apply(
                    &coordinator,
                    Batch::new()
                        .put(keys::authority_generation(), old.clone())
                        .put(keys::grant_epoch(), old.clone())
                        .put(keys::fork_permit_drain(), abandoned),
                ),
            )
            .unwrap();
            let env = ForkEnv {
                store: &store,
                shards: &shards,
                clock: clock.as_ref(),
                takedown_denial: false,
                extract_min_bytes: None,
                limits: super::super::ForkLimits::default(),
            };
            let requested = if other_kind {
                keys::grant_epoch()
            } else {
                keys::authority_generation()
            };
            let target = codec::encode_u64(2);
            assert!(!block_on(transition(&env, &ns, &requested, Some(&old), &target, 0)).unwrap());
            assert_eq!(
                block_on(store.get(&coordinator, &keys::authority_generation())).unwrap(),
                Some(codec::encode_u64(1))
            );
            assert_eq!(
                block_on(store.get(&coordinator, &keys::grant_epoch())).unwrap(),
                Some(old.clone())
            );
            assert!(
                block_on(store.get(&coordinator, &keys::fork_permit_drain()))
                    .unwrap()
                    .is_none()
            );
            let refreshed = if other_kind {
                old
            } else {
                codec::encode_u64(1)
            };
            assert!(
                block_on(transition(
                    &env,
                    &ns,
                    &requested,
                    Some(&refreshed),
                    &target,
                    0
                ))
                .unwrap()
            );
            assert_eq!(
                block_on(store.get(&coordinator, &requested)).unwrap(),
                Some(target)
            );
        }
    }
}
