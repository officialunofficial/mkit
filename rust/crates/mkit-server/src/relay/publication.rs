//! Producer-valid legacy projection compatibility and target era fencing.
use crate::RepoName;
use crate::store::{
    Batch, Key, Partition, Precondition, StoreError, Value, Write, codec::RelayV1, keys, migration,
};

pub(super) fn repository(
    target: &Partition,
    rows: &[(u64, RelayV1)],
) -> Result<Option<RepoName>, StoreError> {
    let repo = match target {
        Partition::RefIndex { repo, .. } | Partition::RepoIndex { repo, .. } => repo,
        _ => return Ok(None),
    };
    let mut relevant = false;
    for (_, row) in rows {
        let mut count = 0;
        for key in row.puts.iter().map(|(key, _)| key).chain(&row.deletes) {
            let parsed = keys::parse(key);
            if !row.publication_era
                && matches!(
                    parsed,
                    Some(
                        keys::ParsedKey::PublishedIndex { .. }
                            | keys::ParsedKey::PublishedMember { .. }
                    )
                )
            {
                return Err(StoreError::Corrupt(
                    "published key in unversioned legacy relay".into(),
                ));
            }
            if !row.publication_era
                && row.deletes.contains(key)
                && matches!(parsed, Some(keys::ParsedKey::Membership { .. }))
            {
                return Err(StoreError::Corrupt(
                    "unsupported legacy membership deletion; drain before migration".into(),
                ));
            }
            let owner = match parsed {
                Some(
                    keys::ParsedKey::RefIndexEntry { repo, .. }
                    | keys::ParsedKey::PublishedIndex { repo, .. },
                ) if matches!(target, Partition::RefIndex { .. }) => Some(repo),
                Some(
                    keys::ParsedKey::Membership { repo, .. }
                    | keys::ParsedKey::PublishedMember { repo, .. },
                ) if matches!(target, Partition::RepoIndex { .. }) => Some(repo),
                _ => None,
            };
            if let Some(owner) = owner {
                if owner != *repo {
                    return Err(StoreError::Corrupt(
                        "publication relay repository mismatch".into(),
                    ));
                }
                relevant = true;
                count += 1;
            }
        }
        if !row.publication_era
            && count
                > if matches!(target, Partition::RefIndex { .. }) {
                    2
                } else {
                    7
                }
        {
            return Err(StoreError::Corrupt(
                "unsupported legacy publication relay; drain before migration".into(),
            ));
        }
    }
    Ok(relevant.then(|| repo.clone()))
}

/// Start initialization without applying any queued row or advancing rh.
/// The local migration handler validates history before it copies anything.
pub(super) fn initialize(
    repo: &RepoName,
    raw: Option<&Value>,
    seal: Option<&Value>,
    now_ms: u64,
) -> Result<Option<Batch>, StoreError> {
    match migration::State::decode(raw, seal)? {
        migration::State::Managed => Ok(None),
        migration::State::Initializing { .. } => {
            Err(StoreError::unavailable("publication migration in progress"))
        }
        migration::State::Legacy => {
            let mut batch =
                Batch::new().require(Precondition::NotAfter(now_ms.saturating_add(10_000)));
            batch
                .preconditions
                .extend(migration::guards(repo, raw, seal)?);
            batch.writes.extend([
                Write::Put(
                    migration::key(repo),
                    migration::State::Initializing {
                        phase: 0,
                        after: None,
                    }
                    .encode(),
                ),
                Write::Put(
                    keys::timer(
                        now_ms,
                        crate::timers::registry::kinds::PUBLICATION_MIGRATION.get(),
                        migration::key(repo).as_bytes(),
                    ),
                    Value::default(),
                ),
            ]);
            Ok(Some(batch))
        }
    }
}

/// Legacy rows were authored before inspection existed. Mirror only those
/// rows; source-authored modern pending x values are deliberately not mirrored.
pub(super) fn project(rows: &[(u64, RelayV1)], batch: &mut Batch) -> Result<(), StoreError> {
    for (_, row) in rows.iter().filter(|(_, row)| !row.publication_era) {
        for (key, value) in &row.puts {
            let published = match keys::parse(key) {
                Some(keys::ParsedKey::RefIndexEntry { repo, name }) => {
                    crate::store::codec::decode_ref_id(value)?;
                    Some(keys::published_index(&repo, &name))
                }
                Some(keys::ParsedKey::Membership { repo, pack_id }) => {
                    if !value.as_bytes().is_empty() {
                        return Err(StoreError::Corrupt(
                            "versioned membership in legacy relay".into(),
                        ));
                    }
                    Some(keys::published_member(&repo, &pack_id))
                }
                _ => None,
            };
            if let Some(published) = published {
                batch.writes.push(Write::Put(published, value.clone()));
            }
        }
        for key in &row.deletes {
            if let Some(keys::ParsedKey::RefIndexEntry { repo, name }) = keys::parse(key) {
                batch
                    .writes
                    .push(Write::Delete(keys::published_index(&repo, &name)));
            }
        }
    }
    Ok(())
}

pub(super) fn markers(repo: &RepoName) -> [Key; 2] {
    [migration::key(repo), migration::seal_key(repo)]
}
