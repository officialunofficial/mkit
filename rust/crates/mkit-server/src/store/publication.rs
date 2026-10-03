//! `RefShard` authority for paired publication and retained inspection obligations.
//!
//! Sequence, value, membership and relay work join the caller's guarded apply.
//! Ref/`RepoIndex` projections are witnesses, never evidence of live membership.
use std::collections::BTreeSet;

use mkit_core::hash::Hash;
use serde::{Deserialize, Serialize};

use super::outbox::{OutboxBuilder, guard};
use super::{
    BlobKey, Key, NamespaceStore, Partition, Precondition, StoreError, Value, Write, codec, keys,
};
use crate::pipeline::ShardMap;
use crate::repo::{RepoId, RepoName};

/// Bound per-ref outstanding values and the one-round prefix read.
pub const MAX_UNPUBLISHED_ADVANCES: u64 = 64;
/// Maximum durable dependency/obligation entries per advance.
pub const MAX_ADVANCE_ITEMS: usize = 4096;
/// Durable blocked advances retry without client traffic every five seconds.
pub const RECHECK_MS: u64 = 5_000;

/// The branch head and packmap, or one non-branch target.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pair {
    /// Head, or the other ref's target.
    pub head: Option<Hash>,
    /// Packmap of a branch; absent for other refs.
    pub packmap: Option<Hash>,
}

/// The clearance states from SPEC-SERVER §10.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Clearance {
    /// Inspection or membership remains outstanding.
    Pending,
    /// All obligations and dependencies permit publication.
    Cleared,
    /// Quarantine requires release or re-inspection.
    Held,
    /// Rejection requires takedown completion.
    Hit,
    /// Takedown and remaining obligations are complete.
    Resolved,
}
impl Clearance {
    /// Whether this state permits membership and prefix publication.
    #[must_use]
    pub fn publishable(self) -> bool {
        matches!(self, Self::Cleared | Self::Resolved)
    }
}

/// Stable inspection identity and its independently retained result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Obligation {
    /// Stable identity; superseding an inspection uses a different id.
    pub id: Hash,
    /// The inspection result, independently of membership dependencies.
    pub state: Clearance,
}

/// One retained advance; this is also the inspector's durable handoff.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Advance {
    /// Never-reused sequence number.
    pub sequence: u64,
    /// Repository membership incarnation, supplied by lifecycle enforcement.
    pub generation: u64,
    /// Resulting paired live values.
    pub value: Pair,
    /// Packs added by this advance, including MKPL nodes.
    pub additions: Vec<Hash>,
    /// Packmap/closure dependencies; own additions may satisfy these.
    pub dependencies: Vec<Hash>,
    /// External delta source packs; own additions never satisfy these.
    pub external_bases: Vec<Hash>,
    /// Individually retained inspector obligations.
    pub obligations: Vec<Obligation>,
    /// Aggregate clearance, including dependencies and flags.
    pub state: Clearance,
    /// Logical operation correlation; never a credential.
    pub operation: Hash,
}
impl Advance {
    fn validate(&self) -> Result<(), StoreError> {
        if self.sequence == 0
            || self.additions.len() > super::outbox::MAX_TICKETS_PER_ADVANCE
            || self.dependencies.len() > MAX_ADVANCE_ITEMS
            || self.external_bases.len() > MAX_ADVANCE_ITEMS
            || self.obligations.len() > MAX_ADVANCE_ITEMS
            || !unique(&self.additions)
            || !unique(&self.dependencies)
            || !unique(&self.external_bases)
        {
            return Err(StoreError::Invalid("invalid publication advance".into()));
        }
        let ids: BTreeSet<_> = self.obligations.iter().map(|o| o.id).collect();
        if ids.len() != self.obligations.len()
            || self.state.publishable() && self.obligations.iter().any(|o| !o.state.publishable())
        {
            return Err(StoreError::Invalid(
                "invalid publication obligations".into(),
            ));
        }
        Ok(())
    }
    /// Encode a bounded v1 retained value.
    pub fn encode(&self) -> Result<Value, StoreError> {
        self.validate()?;
        encode(self)
    }
    /// Decode and validate the entire record before using any field.
    pub fn decode(value: &Value) -> Result<Self, StoreError> {
        let row: Self = decode(value)?;
        row.validate()
            .map_err(|e| StoreError::Corrupt(e.to_string().into()))?;
        Ok(row)
    }
}

/// Persistent sequence, contiguous pointer and deletion boundary.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Publication {
    /// Last successfully applied advance; never deleted or reset.
    pub sequence: u64,
    /// Greatest cleared-or-resolved prefix after the deletion boundary.
    pub published: u64,
    /// Older verdicts cannot change ref values at or below this boundary.
    pub boundary: u64,
    /// Membership incarnation; lifecycle invalidation increments this.
    pub generation: u64,
    /// Paired published values, absent at deletion.
    pub value: Pair,
}
impl Publication {
    /// Decode persistent state; absence is the only initial state.
    pub fn decode(value: Option<&Value>) -> Result<Self, StoreError> {
        let row: Self = value.map(decode).transpose()?.unwrap_or_default();
        if row.boundary > row.published || row.published > row.sequence {
            return Err(StoreError::Corrupt("invalid publication prefix".into()));
        }
        Ok(row)
    }
    /// Encode persistent state.
    pub fn encode(&self) -> Result<Value, StoreError> {
        let value = encode(self)?;
        Self::decode(Some(&value))?;
        Ok(value)
    }
}

/// A versioned local membership or published `RepoIndex` witness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Witness {
    /// Membership generation, invalidated by repository deletion.
    pub generation: u64,
    /// Advance that established clearance; zero is immediate unticketed membership.
    pub sequence: u64,
    /// Independently cleared membership, even when the ref prefix is behind.
    pub published: bool,
    /// Serving stop; applies to writers too.
    pub held: bool,
}
impl Witness {
    /// Fixed-width versioned encoding; no unchecked optional fields.
    #[must_use]
    pub fn encode(self) -> Value {
        let mut bytes = vec![1, u8::from(self.published), u8::from(self.held)];
        bytes.extend_from_slice(&self.generation.to_be_bytes());
        bytes.extend_from_slice(&self.sequence.to_be_bytes());
        Value::new(bytes)
    }
    /// Decode a witness. Empty membership is the explicitly immediate upload form.
    pub fn decode(value: &Value) -> Result<Self, StoreError> {
        let bytes = value.as_bytes();
        if bytes.is_empty() {
            return Ok(Self {
                generation: 0,
                sequence: 0,
                published: true,
                held: false,
            });
        }
        if bytes.len() != 19 || bytes[0] != 1 || bytes[1] > 1 || bytes[2] > 1 {
            return Err(StoreError::Corrupt("invalid clearance witness".into()));
        }
        let number = |offset| -> Result<u64, StoreError> {
            bytes
                .get(offset..offset + 8)
                .and_then(|b| b.try_into().ok())
                .map(u64::from_be_bytes)
                .ok_or_else(|| StoreError::Corrupt("short clearance witness".into()))
        };
        Ok(Self {
            generation: number(3)?,
            sequence: number(11)?,
            published: bytes[1] != 0,
            held: bytes[2] != 0,
        })
    }
    /// Whether the caller may use this membership in its chosen view.
    #[must_use]
    pub fn visible(self, writer: bool, generation: u64) -> bool {
        !self.held && self.generation == generation && (writer || self.published)
    }
}

fn unique(ids: &[Hash]) -> bool {
    ids.iter().collect::<BTreeSet<_>>().len() == ids.len()
}
fn encode<T: Serialize>(row: &T) -> Result<Value, StoreError> {
    let mut bytes = vec![1];
    bytes.extend(
        serde_json::to_vec(row).map_err(|_| StoreError::Invalid("publication encoding".into()))?,
    );
    if bytes.len() > super::MAX_VALUE_BYTES {
        return Err(StoreError::Invalid(
            "publication value exceeds limit".into(),
        ));
    }
    Ok(Value::new(bytes))
}
fn decode<T: serde::de::DeserializeOwned>(value: &Value) -> Result<T, StoreError> {
    let bytes = value.as_bytes();
    if bytes.first() != Some(&1) || bytes.len() > super::MAX_VALUE_BYTES {
        return Err(StoreError::Corrupt(
            "invalid publication version or size".into(),
        ));
    }
    serde_json::from_slice(&bytes[1..])
        .map_err(|_| StoreError::Corrupt("invalid publication record".into()))
}

/// Canonical shared sequence name for a branch pair, unchanged for another ref.
#[must_use]
pub fn sequence_ref(name: &str) -> String {
    mkit_attest::grant::packmap_head(name).unwrap_or_else(|| name.to_owned())
}

/// Resulting branch pair or standalone ref names in stable order.
#[must_use]
pub fn value_refs(name: &str, value: &Pair) -> Vec<(String, Option<Hash>)> {
    let mut refs = vec![(name.to_owned(), value.head)];
    if let Some(packmap) = mkit_attest::grant::head_packmap(name) {
        refs.push((packmap, value.packmap));
    }
    refs
}

/// Append one successful ref write. The caller commits this fragment with live refs.
/// A deletion is an immediate boundary; older retained obligations remain intact.
#[allow(clippy::too_many_arguments)]
pub fn append(
    repo: &RepoId,
    name: &str,
    source: &Partition,
    shards: &dyn ShardMap,
    prior: Option<&Value>,
    mut advance: Advance,
    deleted: bool,
    pre: &mut Vec<Precondition>,
    writes: &mut Vec<Write>,
    outbox: &mut OutboxBuilder,
) -> Result<Publication, StoreError> {
    let name = sequence_ref(name);
    let mut state = Publication::decode(prior)?;
    if !deleted && state.sequence - state.published >= MAX_UNPUBLISHED_ADVANCES {
        return Err(StoreError::unavailable("publication backlog full"));
    }
    state.sequence = state
        .sequence
        .checked_add(1)
        .ok_or_else(|| StoreError::Corrupt("advance sequence overflow".into()))?;
    advance.sequence = state.sequence;
    advance.generation = state.generation;
    advance.validate()?;
    if !advance.state.publishable() {
        // One timer per advance, installed in the same transaction as its retained
        // obligations. Periodic rechecks cover cross-ref publication and delayed
        // projections without an unbounded reverse dependency fanout.
        writes.push(Write::Put(
            keys::timer(
                0,
                crate::timers::registry::kinds::PUBLICATION_RECHECK.get(),
                keys::advance(&repo.name, &name, advance.sequence).as_bytes(),
            ),
            crate::timers::publication_recheck::initial_value(),
        ));
    }
    let key = keys::publication(&repo.name, &name);
    pre.push(guard(key.clone(), prior));
    if deleted {
        state.boundary = state.sequence;
        state.published = state.sequence;
        // A partial deletion removes its component immediately, but must not
        // publish the surviving live component from an uncleared advance.
        state.value = Pair {
            head: advance.value.head.and(state.value.head),
            packmap: advance.value.packmap.and(state.value.packmap),
        };
        project_refs(repo, &name, source, shards, &state.value, writes, outbox);
    } else if advance.state.publishable() && state.published + 1 == state.sequence {
        state.published = state.sequence;
        state.value = advance.value.clone();
        project_refs(repo, &name, source, shards, &state.value, writes, outbox);
    }
    // Completed obligation-free values need no retained work once the prefix
    // includes them. Keep blocked intermediates and every inspection obligation.
    if advance.sequence > state.published || !advance.obligations.is_empty() {
        writes.push(Write::Put(
            keys::advance(&repo.name, &name, advance.sequence),
            advance.encode()?,
        ));
    }
    project_members(repo, source, shards, &advance, writes, outbox);
    writes.push(Write::Put(key, state.encode()?));
    Ok(state)
}

fn project_refs(
    repo: &RepoId,
    name: &str,
    source: &Partition,
    shards: &dyn ShardMap,
    value: &Pair,
    writes: &mut Vec<Write>,
    outbox: &mut OutboxBuilder,
) {
    for (name, id) in value_refs(name, value) {
        let key = keys::published_ref(&repo.name, &name);
        writes.push(id.map_or_else(
            || Write::Delete(key.clone()),
            |id| Write::Put(key.clone(), codec::encode_ref_id(&id)),
        ));
        let target = shards.ref_index(repo, &name);
        if target != *source {
            let key = keys::published_index(&repo.name, &name);
            match id {
                Some(id) => outbox.relay(&target, vec![(key, codec::encode_ref_id(&id))]),
                None => outbox.relay_delete(&target, vec![key]),
            }
        }
    }
}
fn project_members(
    repo: &RepoId,
    source: &Partition,
    shards: &dyn ShardMap,
    advance: &Advance,
    writes: &mut Vec<Write>,
    outbox: &mut OutboxBuilder,
) {
    for pack in &advance.additions {
        let witness = Witness {
            generation: advance.generation,
            sequence: advance.sequence,
            published: advance.state.publishable(),
            held: matches!(advance.state, Clearance::Held | Clearance::Hit),
        };
        let key = keys::membership(&repo.name, pack);
        // Replace the live membership fragment rather than spending another per-ticket put.
        writes.retain(|w| !matches!(w, Write::Put(k, _) | Write::Delete(k) if k == &key));
        writes.push(Write::Put(key.clone(), witness.encode()));
        let target = shards.membership(repo, &BlobKey::pack(*pack));
        if target != *source {
            outbox.relay(&target, vec![(key, witness.encode())]);
            if witness.published {
                outbox.relay(
                    &target,
                    vec![(keys::published_member(&repo.name, pack), witness.encode())],
                );
            }
        }
    }
}

/// Read authoritative sequence state without consulting a projection.
pub async fn read<S: NamespaceStore>(
    store: &S,
    source: &Partition,
    repo: &RepoName,
    name: &str,
) -> Result<Publication, StoreError> {
    Publication::decode(
        store
            .get(source, &keys::publication(repo, &sequence_ref(name)))
            .await?
            .as_ref(),
    )
}

/// Bounded read of every value that can advance the pointer. No projection is used.
pub async fn prefix<S: NamespaceStore>(
    store: &S,
    source: &Partition,
    repo: &RepoName,
    name: &str,
    state: &Publication,
    changed: &Advance,
) -> Result<(u64, Pair), StoreError> {
    if state.sequence - state.published > MAX_UNPUBLISHED_ADVANCES {
        return Err(StoreError::Corrupt(
            "publication prefix exceeds bound".into(),
        ));
    }
    if state.published == state.sequence {
        return Ok((state.published, state.value.clone()));
    }
    let name = sequence_ref(name);
    let wanted: Vec<Key> = (state.published + 1..=state.sequence)
        .map(|sequence| keys::advance(repo, &name, sequence))
        .collect();
    let rows = store.get_many(source, &wanted).await?;
    if rows.len() != wanted.len() {
        return Err(StoreError::Corrupt("short publication prefix read".into()));
    }
    let mut result = (state.published, state.value.clone());
    for (sequence, raw) in (state.published + 1..=state.sequence).zip(rows) {
        let current = if changed.sequence == sequence {
            changed.clone()
        } else {
            Advance::decode(
                raw.as_ref()
                    .ok_or_else(|| StoreError::Corrupt("missing retained advance".into()))?,
            )?
        };
        if current.sequence != sequence || current.generation != state.generation {
            return Err(StoreError::Corrupt(
                "retained advance binding mismatch".into(),
            ));
        }
        if !current.state.publishable() {
            break;
        }
        result = (sequence, current.value);
    }
    Ok(result)
}

/// Guarded clearance fragment. A caller has verified obligations, flags and membership
/// dependencies against current witnesses before calling this function. Resolved
/// advances must already name their completed takedown replacements.
#[allow(clippy::too_many_arguments)]
pub fn clear(
    repo: &RepoId,
    name: &str,
    source: &Partition,
    shards: &dyn ShardMap,
    state_raw: &Value,
    advance_raw: &Value,
    changed: &Advance,
    eligible: (u64, Pair),
    pre: &mut Vec<Precondition>,
    writes: &mut Vec<Write>,
    outbox: &mut OutboxBuilder,
) -> Result<(), StoreError> {
    let name = sequence_ref(name);
    let mut state = Publication::decode(Some(state_raw))?;
    let old = Advance::decode(advance_raw)?;
    changed.validate()?;
    if changed.sequence != old.sequence
        || changed.sequence > state.sequence
        || changed.generation != old.generation
        || changed.generation != state.generation
        || eligible.0 < state.published
        || eligible.0 > state.sequence
        || old.state == Clearance::Hit && changed.state == Clearance::Cleared
    {
        return Err(StoreError::Invalid(
            "invalid publication clearance transition".into(),
        ));
    }
    let key = keys::advance(&repo.name, &name, changed.sequence);
    pre.push(guard(key.clone(), Some(advance_raw)));
    writes.push(Write::Put(key, changed.encode()?));
    pre.push(guard(keys::publication(&repo.name, &name), Some(state_raw)));
    project_members(repo, source, shards, changed, writes, outbox);
    if eligible.0 > state.published {
        state.published = eligible.0;
        state.value = eligible.1;
        project_refs(repo, &name, source, shards, &state.value, writes, outbox);
    }
    writes.push(Write::Put(
        keys::publication(&repo.name, &name),
        state.encode()?,
    ));
    Ok(())
}

#[cfg(test)]
#[path = "publication_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "publication_v050_tests.rs"]
mod stored_v050_tests;
