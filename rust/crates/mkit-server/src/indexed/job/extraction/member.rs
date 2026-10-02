//! Resumable repository-member lookup and single-accumulator delta decoding.
use super::super::CacheBases;
use super::{
    BlobKey, BlobStore, Cursor, ExtractionV1, FRAGMENT, Hash, NamespaceStore, Object, Outcome,
    PackWindows, Partition, Run, SliceExtension, SliceState, Stop, Value, Write, check, codec,
    corrupt, hash, keys, n32, resolve,
};
use crate::indexed::checkpoint::MemberCursor;
use crate::store::codec::CODEC_V1;
use crate::store::index::{self, LocatedObject};
use mkit_core::pack::decode_frame_with;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Lookup {
    after: Vec<u8>,
    pages: u32,
    rows: u32,
    partitions: BTreeSet<Hash>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Frame {
    id: Hash,
    pack: Hash,
    index: Vec<u8>,
    local: bool,
}
fn encode<T: Serialize>(value: &T) -> Result<Value, Stop> {
    let mut bytes = vec![CODEC_V1];
    serde_json::to_writer(&mut bytes, value).map_err(|_| corrupt())?;
    Ok(Value::new(bytes))
}
fn decode<T: serde::de::DeserializeOwned>(raw: &Value) -> Result<T, Stop> {
    check(raw.as_bytes().len() <= 128 << 10)?;
    let Some((&CODEC_V1, body)) = raw.as_bytes().split_first() else {
        return Err(corrupt());
    };
    serde_json::from_slice(body).map_err(|_| corrupt())
}
impl<S: NamespaceStore, R: NamespaceStore, B: BlobStore, W: PackWindows, X: SliceExtension>
    Run<'_, S, R, B, W, X>
{
    fn member_limits(&self, index: index::IndexValue) -> Result<(u64, u64), Stop> {
        let budget = self.decode_limits().max_decoded_bytes;
        let wire = crate::indexed::geometry::FRAME_BYTES;
        if index.frame_length > wire
            || index.decoded_size > budget
            || index.chain_depth > self.h.cfg.max_delta_chain_depth
        {
            return Err(Stop::Outcome(Outcome::DecodeBudget));
        }
        Ok((budget, wire))
    }
    async fn member_has(&self, pack: Hash) -> Result<bool, Stop> {
        let p = self.h.shards.membership(&self.repo, &BlobKey::pack(pack));
        let key = keys::membership(&self.repo.name, &pack);
        Ok(self.remote.has(&p, &key).await?)
    }
    /// None persists a checked prefix; Some(None) is a proved membership miss.
    #[allow(clippy::too_many_lines)] // One bounded lookup page and its persisted membership prefix.
    pub(super) async fn member_lookup(
        &self,
        st: &mut SliceState,
        x: &ExtractionV1,
        ids: (Hash, Hash),
        preferred: Option<(Hash, u64)>,
        level: u32,
    ) -> Result<Option<Option<LocatedObject>>, Stop> {
        let (target, id) = ids;
        let shards = self.h.shards.as_ref();
        let repo = &self.repo;
        let key = self.aux(x, b"member-lookup", &hash(&[target, id].concat()), level);
        let raw = self.get(&key).await?;
        let mut lookup: Lookup = raw.as_ref().map(decode).transpose()?.unwrap_or_default();
        check(
            lookup.after.len() <= 4096
                && lookup.rows < 4096
                && lookup.pages.saturating_add(lookup.rows.div_ceil(128)) < 512
                && lookup.partitions.len() <= 487,
        )?;
        if lookup.rows == 0
            && lookup.pages == 0
            && let Some((pack, before)) = preferred
            && self.member_has(pack).await?
        {
            let partition = shards.object_index(repo, &id);
            let key = keys::object_index(&repo.name, &id, &pack);
            if let Some(raw) = self.remote.get(&partition, &key).await? {
                let value = codec::decode_object_index(&id, &raw)?;
                if value.frame_offset < before {
                    return Ok(Some(Some(LocatedObject { pack, value })));
                }
            }
        }
        let (start, end) = keys::object_index_range(&self.repo.name, &id);
        let after = (!lookup.after.is_empty()).then(|| Cursor::new(lookup.after.clone()));
        let page = self
            .remote
            .scan(
                &shards.object_index(repo, &id),
                &start,
                &end,
                after.as_ref(),
                8_u32.min(4096 - lookup.rows),
            )
            .await?;
        check(page.entries.len() as u64 <= u64::from((4096 - lookup.rows).min(8)))?;
        lookup.pages += u32::from(page.entries.len() < 8);
        lookup.rows += u32::try_from(page.entries.len()).map_err(|_| corrupt())?;
        let mut groups: BTreeMap<Partition, Vec<Hash>> = BTreeMap::new();
        let mut ordered = Vec::new();
        let mut capped = false;
        for (key, value) in page.entries {
            let Some(keys::ParsedKey::ObjectIndex {
                repo: found,
                object,
                pack_id,
            }) = keys::parse(&key)
            else {
                return Err(corrupt());
            };
            check(found == self.repo.name && object == id)?;
            let partition = shards.membership(repo, &BlobKey::pack(pack_id));
            let digest = hash(&partition.encode()?);
            if !lookup.partitions.contains(&digest)
                && lookup.partitions.len() == index::MAX_LOOKUP_MEMBERSHIP_READS
            {
                capped = true;
                break;
            }
            lookup.partitions.insert(digest);
            ordered.push((pack_id, value));
            groups.entry(partition).or_default().push(pack_id);
        }
        let mut members = BTreeSet::new();
        for (partition, rows) in groups {
            let keys: Vec<_> = rows
                .iter()
                .map(|pack| keys::membership(&repo.name, pack))
                .collect();
            let values = self.remote.get_many(&partition, &keys).await?;
            check(values.len() == rows.len())?;
            for (pack, value) in rows.into_iter().zip(values) {
                if value.is_some() {
                    members.insert(pack);
                }
            }
        }
        st.settled.push(Write::Delete(key.clone()));
        for (pack, value) in ordered {
            if members.contains(&pack) {
                return Ok(Some(Some(LocatedObject {
                    pack,
                    value: codec::decode_object_index(&id, &value)?,
                })));
            }
        }
        if capped
            || (page.next.is_some()
                && (lookup.rows >= 4096
                    || lookup.pages.saturating_add(lookup.rows.div_ceil(128)) >= 512))
        {
            return Err(Stop::Outcome(Outcome::BaseCapped));
        }
        let Some(next) = page.next else {
            return Ok(Some(None));
        };
        lookup.after = next.into_bytes().to_vec();
        st.settled.pop();
        st.settled.push(Write::Put(key, encode(&lookup)?));
        Ok(None)
    }
    #[allow(clippy::too_many_lines)] // A frame decode and its replay-safe accumulator checkpoint.
    pub(super) async fn incremental_member(
        &self,
        st: &mut SliceState,
        x: &mut ExtractionV1,
        id: Hash,
    ) -> Result<Option<(Object, u64)>, Stop> {
        let mut cursor = x.reconstruction.clone().unwrap_or(MemberCursor {
            target: id,
            next: id,
            ..MemberCursor::default()
        });
        check(cursor.target == id && cursor.level <= self.h.cfg.max_delta_chain_depth)?;
        let frame_key = self.aux(x, b"member-frame", &id, cursor.level);
        if !cursor.ascending {
            let packs: Vec<_> = if cursor.level == 0 {
                x.sources.iter().map(|s| s.member.pack).collect()
            } else {
                cursor
                    .preferred
                    .filter(|_| cursor.local)
                    .map(|(pack, _)| pack)
                    .into_iter()
                    .collect()
            };
            let mut staged = None;
            for pack in packs {
                if let Some(raw) = self
                    .get(&self.source_row(&pack, keys::VC_FRAME, &cursor.next))
                    .await?
                {
                    let row = super::decode_frame(&cursor.next, &raw)?;
                    if cursor.level == 0
                        || cursor
                            .preferred
                            .is_some_and(|(_, before)| row.value.frame_offset < before)
                    {
                        staged = Some(LocatedObject {
                            pack,
                            value: row.value,
                        });
                        break;
                    }
                }
            }
            let local = staged.is_some();
            let location = if local {
                staged
            } else {
                let preferred = if cursor.level > 0 && cursor.local {
                    None
                } else {
                    cursor.preferred
                };
                let Some(location) = self
                    .member_lookup(st, x, (id, cursor.next), preferred, cursor.level)
                    .await?
                else {
                    x.reconstruction = Some(cursor);
                    return Ok(None);
                };
                location
            };
            let oldest = x
                .sources
                .iter()
                .map(|s| s.member.created_at_ms)
                .min()
                .ok_or_else(corrupt)?;
            let location =
                location.ok_or_else(|| self.missing_closure(oldest, Outcome::ClosureMissing))?;
            self.member_limits(location.value)?;
            let frame = Frame {
                id: cursor.next,
                pack: location.pack,
                index: codec::encode_object_index(&cursor.next, &location.value)?
                    .as_bytes()
                    .to_vec(),
                local,
            };
            st.settled.push(Write::Put(frame_key, encode(&frame)?));
            cursor.local = local;
            if let Some(base) = location.value.delta_base {
                if cursor.level >= self.h.cfg.max_delta_chain_depth {
                    return Err(Stop::Outcome(Outcome::ExternalTooDeep));
                }
                cursor.preferred = Some((location.pack, location.value.frame_offset));
                cursor.next = base;
                cursor.level += 1;
            } else {
                cursor.ascending = true;
            }
            x.reconstruction = Some(cursor);
            return Ok(None);
        }
        let frame: Frame = decode(&self.require(&frame_key).await?)?;
        let index = codec::decode_object_index(&frame.id, &Value::new(frame.index))?;
        let (budget, wire_budget) = self.member_limits(index)?;
        if frame.local {
            check(x.sources.iter().any(|s| s.member.pack == frame.pack))?;
        } else if !self.member_has(frame.pack).await? {
            return Err(Stop::Outcome(Outcome::ClosureMissing));
        }
        let mut subjects = vec![frame.id, frame.pack];
        if let Some((base, _, _, pack)) = cursor.canonical {
            if !x.sources.iter().any(|s| s.member.pack == pack) && !self.member_has(pack).await? {
                return Err(Stop::Outcome(Outcome::ClosureMissing));
            }
            subjects.extend([base, pack]);
        }
        for subject in subjects {
            crate::takedown::denial::require_clear(self.remote, &subject)
                .await
                .map_err(|error| match error.code() {
                    crate::Code::PermissionDenied => Stop::Outcome(Outcome::Blocked),
                    _ => super::unavailable("extraction source unavailable"),
                })?;
        }
        let (version, wire) = if frame.local {
            let raw = self
                .require(&keys::verify_job(&self.repo.name, &frame.pack))
                .await?;
            let mut job = super::checkpoint::decode_job(&raw)?;
            let run = Run {
                repo: self.repo.clone(),
                pack: frame.pack,
                ..*self
            };
            let wire = run
                .read(&mut job, index.frame_offset, index.frame_length)
                .await?
                .bytes;
            (job.version, wire)
        } else {
            let prefix = resolve::frame_bytes(self.blobs, frame.pack, 0, 8, wire_budget)
                .await
                .map_err(|_| corrupt())?;
            check(&prefix[..4] == b"MKIT")?;
            let version = u32::from_le_bytes(prefix[4..8].try_into().map_err(|_| corrupt())?);
            let wire = resolve::frame_bytes(
                self.blobs,
                frame.pack,
                index.frame_offset,
                index.frame_length,
                wire_budget,
            )
            .await
            .map_err(|_| corrupt())?;
            (version, wire)
        };
        let mut depth = 0;
        if let Some((base, length, previous_depth, _)) = cursor.canonical {
            check(index.delta_base == Some(base))?;
            check(length <= budget)?;
            let bytes = self
                .fragment_bytes(x, base, b"member-bytes", length)
                .await?;
            st.cache.insert(base, Arc::from(bytes));
            depth = previous_depth.checked_add(1).ok_or_else(corrupt)?;
        } else if index.delta_base.is_some() {
            return Err(corrupt());
        }
        if depth > self.h.cfg.max_delta_chain_depth {
            return Err(Stop::Outcome(Outcome::ExternalTooDeep));
        }
        let (actual, bytes) = decode_frame_with(
            &wire,
            version,
            &mut CacheBases(&st.cache),
            crate::indexed::geometry::entry_limits(budget),
        )
        .map_err(|_| corrupt())?;
        let length = bytes.len() as u64;
        check(actual == frame.id && length == index.decoded_size)?;
        cursor.bytes = cursor.bytes.checked_add(length).ok_or_else(corrupt)?;
        st.settled.push(Write::Delete(frame_key));
        if let Some((base, length, _, _)) = cursor.canonical {
            for i in 0..length.div_ceil(FRAGMENT) {
                st.settled
                    .push(Write::Delete(self.aux(x, b"member-bytes", &base, n32(i)?)));
            }
        }
        if cursor.level == 0 {
            check(actual == cursor.target)?;
            let object = mkit_core::serialize::deserialize(&bytes).map_err(|_| corrupt())?;
            x.reconstruction = None;
            return Ok(Some((object, if frame.local { 0 } else { cursor.bytes })));
        }
        self.append_fragment(st, x, actual, b"member-bytes", 0, &bytes)
            .await?;
        cursor.level -= 1;
        cursor.canonical = Some((actual, length, depth, frame.pack));
        x.reconstruction = Some(cursor);
        Ok(None)
    }
}
