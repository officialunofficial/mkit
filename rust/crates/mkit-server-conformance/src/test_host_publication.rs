//! Reference binding for publication controls. Eligibility applies to trusted
//! preparation; deferred work is driven through the real publication timer.

use super::*;
use mkit_server::BoxFuture;
use mkit_server::pipeline::clearance::PublicationPolicy;
use mkit_server::store::adapter_spi::publication::{
    Advance, Clearance, Pair, Publication, Witness,
};
use mkit_server::timers::{
    DueTimer, Fired, TickBudget, TimerCtx, TimerHandler, TimerKind, TimerRegistry,
};

pub(super) struct Eligibility(pub(super) ControlStore);

impl PublicationPolicy for Eligibility {
    fn prepare<'a>(
        &'a self,
        op: &'a Operation,
        value: &'a Pair,
    ) -> BoxFuture<'a, Result<Advance, ServerError>> {
        Box::pin(async move {
            let head = match &op.kind {
                mkit_server::OpKind::AdvanceRefs { head, .. } => &head.name,
                mkit_server::OpKind::UpdateRef(update) => &update.name,
                _ => {
                    return Err(ServerError::invalid_argument(
                        "publication fixture requires a ref write",
                    ));
                }
            };
            let name = mkit_server::store::adapter_spi::publication::sequence_ref(head);
            let key = (
                SinglePartition.ref_shard(&op.repo, &name),
                keys::publication(&op.repo.name, &name),
            );
            let eligible = self
                .0
                .publication_eligibility
                .lock()
                .unwrap()
                .get(&key)
                .copied()
                .unwrap_or(true);
            Ok(Advance {
                sequence: 1,
                generation: 0,
                value: value.clone(),
                operation: [0; 32],
                additions: Vec::new(),
                dependencies: Vec::new(),
                external_bases: Vec::new(),
                obligations: Vec::new(),
                state: if eligible {
                    Clearance::Cleared
                } else {
                    Clearance::Pending
                },
            })
        })
    }
    fn pack_available(&self, _: &RepoId, _: &Hash) -> bool {
        true
    }
    fn fork_version(&self, _: &RepoId) -> Option<Hash> {
        // Pack availability is constant; ref eligibility uses publication rows.
        Some([0; 32])
    }
}

/// Only the selected head's real recheck is allowed to advance during a drive.
/// Other durable timers retain their work and are scheduled for a later drive.
struct SelectedRecheck {
    store: ControlStore,
    repo: RepoName,
    head: String,
    eligible: bool,
}
impl TimerHandler<ControlStore> for SelectedRecheck {
    fn kind(&self) -> TimerKind {
        mkit_server::timers::registry::kinds::PUBLICATION_RECHECK
    }
    fn max_per_tick(&self) -> Option<u32> {
        Some(1)
    }
    fn fire<'a>(
        &'a self,
        ctx: &'a TimerCtx<'a, ControlStore>,
        timer: &'a DueTimer,
    ) -> BoxFuture<'a, Result<Fired, StoreError>> {
        Box::pin(async move {
            let key = Key::new(timer.reference.clone());
            let selected = matches!(keys::parse(&key), Some(keys::ParsedKey::Advance { repo, name, .. }) if repo == self.repo && name == self.head);
            if !selected || !self.eligible {
                return Ok(Fired::Reschedule {
                    due_at_ms: ctx
                        .now_ms
                        .saturating_add(mkit_server::store::adapter_spi::publication::RECHECK_MS),
                    value: timer.value.clone(),
                    batch: Batch::new(),
                });
            }
            mkit_server::timers::publication_recheck::PublicationRecheck::new(self.store.clone())
                .fire(ctx, timer)
                .await
        })
    }
}

impl HostState {
    fn publication_location(
        &self,
        repository: &str,
        head: &str,
    ) -> Result<(RepoId, Partition, Key), String> {
        if self.config.indexed.is_none() {
            return Err("requires indexed publication profile".into());
        }
        if !head.starts_with("refs/heads/") || !mkit_server::refs::validate_ref_name(head) {
            return Err("expected branch head".into());
        }
        let repo = self.repository(repository)?;
        let partition = SinglePartition.ref_shard(&repo, head);
        let key = keys::publication(&repo.name, head);
        Ok((repo, partition, key))
    }

    pub(super) fn set_publication_eligibility(
        &self,
        repository: &str,
        head: &str,
        eligible: bool,
    ) -> Result<(), String> {
        let (_, partition, key) = self.publication_location(repository, head)?;
        self.store
            .publication_eligibility
            .lock()
            .unwrap()
            .insert((partition, key), eligible);
        Ok(())
    }

    pub(super) async fn drive_publication(
        &self,
        repository: &str,
        head: &str,
    ) -> Result<(), String> {
        let (repo, partition, key) = self.publication_location(repository, head)?;
        let eligible = self
            .store
            .publication_eligibility
            .lock()
            .unwrap()
            .get(&(partition.clone(), key))
            .copied()
            .unwrap_or(true);
        let registry = TimerRegistry::new().register(SelectedRecheck {
            store: self.store.clone(),
            repo: repo.name,
            head: head.to_owned(),
            eligible,
        });
        // Each real alarm retains the handler's production one-fire limit.
        // Continue only while that limit deferred due work, with a fixed bound
        // matching the maximum outstanding advances in the reference fixture.
        let now = u64::try_from(self.clock.now_ms()).map_err(|_| "negative clock")?;
        for _ in 0..64 {
            let report = mkit_server::timers::run_due(
                &self.store,
                &partition,
                &registry,
                self.clock.as_ref(),
                now,
                &TickBudget::new(64, 64, 512, 10_000),
            )
            .await
            .map_err(|e| e.to_string())?;
            if report.failed > 0 {
                return Err("publication timer failed".into());
            }
            if report.deferred == 0 || report.fired == 0 {
                return Ok(());
            }
        }
        Err("publication drive exhausted its bounded alarm count".into())
    }

    pub(super) async fn observe_publication(
        &self,
        query: control::PublicationQuery,
    ) -> Result<control::PublicationObservation, String> {
        let (repo, partition, key) =
            self.publication_location(&query.acceptance.repository, &query.acceptance.head)?;
        let packs = query.acceptance.packs.clone();
        // The same mutation gate covers acceptance, pointer, and membership
        // reads; a snapshot cannot combine states from different commits.
        let _guard = self.store.gate.lock().await;
        let acceptance = self.observe_locked(query.acceptance).await?;
        let raw = self
            .store
            .inner
            .get(&partition, &key)
            .await
            .map_err(|e| e.to_string())?;
        let state = Publication::decode(raw.as_ref()).map_err(|e| e.to_string())?;
        let mut published_memberships = Vec::with_capacity(packs.len());
        for pack in packs {
            let raw = self
                .store
                .inner
                .get(
                    &partition,
                    &keys::membership(&repo.name, &parse_hash(&pack)?),
                )
                .await
                .map_err(|e| e.to_string())?;
            published_memberships.push(
                raw.as_ref()
                    .map(Witness::decode)
                    .transpose()
                    .map_err(|e| e.to_string())?
                    .is_some_and(|w| w.visible(false, state.generation)),
            );
        }
        Ok(control::PublicationObservation {
            acceptance,
            published_head: state.value.head.as_ref().map(to_hex),
            published_packmap: state.value.packmap.as_ref().map(to_hex),
            live_sequence: state.sequence,
            published_sequence: state.published,
            deletion_boundary: state.boundary,
            published_memberships,
        })
    }
}

/// Detect the reference server's guarded publication attempt, including a
/// membership-only clearance while an earlier advance still blocks the prefix.
pub(super) async fn clearance_keys(
    store: &ControlStore,
    partition: &Partition,
    batch: &Batch,
) -> Result<Vec<Key>, StoreError> {
    let mut result = Vec::new();
    for write in &batch.writes {
        let Write::Put(key, raw) = write else {
            continue;
        };
        match keys::parse(key) {
            Some(keys::ParsedKey::Publication { .. }) => {
                let next = Publication::decode(Some(raw))?;
                let prior = store.inner.get(partition, key).await?;
                let prior = Publication::decode(prior.as_ref())?;
                if next.published > prior.published {
                    result.push(key.clone());
                }
            }
            Some(keys::ParsedKey::Advance { repo, name, .. }) => {
                let next = Advance::decode(raw)?;
                let prior = store.inner.get(partition, key).await?;
                let was_cleared = prior
                    .as_ref()
                    .map(Advance::decode)
                    .transpose()?
                    .is_some_and(|a| a.state.publishable());
                if next.state.publishable() && !was_cleared {
                    result.push(keys::publication(&repo, &name));
                }
            }
            _ => {}
        }
    }
    result.sort();
    result.dedup();
    Ok(result)
}
