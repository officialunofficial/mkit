//! Request-local read view. Every batched read remains one underlying store call.
use super::{
    Batch, BatchOutcome, Cursor, Key, NamespaceStore, Partition, PartitionStats, RangeScan,
    ScanPage, StoreCapabilities, StoreError, Value, keys, migration, publication::Witness,
};
use crate::pipeline::clearance::PublicationPolicy;
use crate::repo::RepoId;

/// A read-only store facade selected after repository authorization.
pub struct ViewStore<'a, S> {
    /// Underlying store; mutations through the facade are refused.
    pub store: &'a S,
    /// Authorized repository identity.
    pub repo: &'a RepoId,
    /// Writer view, without conferring read permission.
    pub writer: bool,
    /// Coherent serving-stop seam, shared by writer and reader views.
    pub policy: Option<&'a dyn PublicationPolicy>,
}
impl<S> core::fmt::Debug for ViewStore<'_, S> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ViewStore")
            .field("repo", self.repo)
            .field("writer", &self.writer)
            .field("serving_stop", &self.policy.is_some())
            .finish_non_exhaustive()
    }
}
fn retag(key: &Key, from: &[u8], to: &[u8]) -> Key {
    let bytes = key.as_bytes();
    if bytes.starts_with(from) {
        Key::new([to, &bytes[from.len()..]].concat())
    } else {
        key.clone()
    }
}
impl<S: NamespaceStore> ViewStore<'_, S> {
    fn key(&self, p: &Partition, key: &Key) -> Key {
        if self.writer || !self.store.capabilities().atomic_multi_key {
            return key.clone();
        }
        let key = retag(key, b"r\0", b"pr\0");
        let key = retag(&key, b"x\0", b"py\0");
        if matches!(p, Partition::RepoIndex { .. }) {
            retag(&key, b"m\0", b"pm\0")
        } else {
            key
        }
    }
    fn mode(&self, values: &[Option<Value>]) -> Result<migration::State, StoreError> {
        if values.len() != 2 {
            return Err(StoreError::Corrupt("short view discriminator read".into()));
        }
        migration::State::decode(values[0].as_ref(), values[1].as_ref())
    }
    fn managed(state: &migration::State) -> bool {
        matches!(state, migration::State::Managed)
    }
    fn markers(&self) -> [Key; 2] {
        [
            migration::key(&self.repo.name),
            migration::seal_key(&self.repo.name),
        ]
    }
    fn marker_range(&self) -> RangeScan {
        let start = migration::key(&self.repo.name);
        let end = Key::new([start.as_bytes(), &[1]].concat());
        RangeScan {
            start,
            end,
            after: None,
            limit: 2,
        }
    }
    fn page_mode(&self, page: &ScanPage) -> Result<migration::State, StoreError> {
        let markers = self.markers();
        let values = markers
            .iter()
            .map(|marker| {
                page.entries
                    .iter()
                    .find(|(key, _)| key == marker)
                    .map(|(_, value)| value.clone())
            })
            .collect::<Vec<_>>();
        if page.entries.len() != values.iter().filter(|v| v.is_some()).count()
            || page.next.is_some()
        {
            return Err(StoreError::Corrupt(
                "invalid view discriminator range".into(),
            ));
        }
        self.mode(&values)
    }
    fn cursor(&self, cursor: Option<&Cursor>, published: bool) -> Option<Cursor> {
        cursor.map(|cursor| {
            let live = retag(
                &retag(&Key::new(cursor.as_bytes().to_vec()), b"pr\0", b"r\0"),
                b"py\0",
                b"x\0",
            );
            Cursor::new(
                if published {
                    self.key(&Partition::Namespace(self.repo.namespace.clone()), &live)
                } else {
                    live
                }
                .into_bytes(),
            )
        })
    }
    fn value(&self, key: &Key, value: Option<Value>) -> Result<Option<Value>, StoreError> {
        let Some(value) = value else {
            return Ok(None);
        };
        if let Some(keys::ParsedKey::Membership { repo, pack_id }) = keys::parse(key) {
            if repo != self.repo.name {
                return Err(StoreError::Corrupt("view repository mismatch".into()));
            }
            let witness = Witness::decode(&value)?;
            if !witness.visible(self.writer, 0)
                || self
                    .policy
                    .is_some_and(|p| !p.pack_available(self.repo, &pack_id))
            {
                return Ok(None);
            }
        }
        Ok(Some(value))
    }
    fn page(&self, mut page: ScanPage) -> ScanPage {
        if !self.writer && self.store.capabilities().atomic_multi_key {
            for (key, _) in &mut page.entries {
                *key = retag(&retag(key, b"pr\0", b"r\0"), b"py\0", b"x\0");
            }
        }
        page.next = self.cursor(page.next.as_ref(), false);
        page
    }
}
impl<S: NamespaceStore> NamespaceStore for ViewStore<'_, S> {
    fn capabilities(&self) -> StoreCapabilities {
        self.store.capabilities()
    }
    async fn get(&self, p: &Partition, key: &Key) -> Result<Option<Value>, StoreError> {
        let mut values = self.get_many(p, core::slice::from_ref(key)).await?;
        Ok(values.pop().flatten())
    }
    async fn get_many(
        &self,
        p: &Partition,
        keys: &[Key],
    ) -> Result<Vec<Option<Value>>, StoreError> {
        let published = keys.iter().map(|key| self.key(p, key)).collect::<Vec<_>>();
        let membership = keys
            .iter()
            .any(|key| matches!(keys::parse(key), Some(keys::ParsedKey::Membership { .. })));
        if !self.store.capabilities().atomic_multi_key
            || !membership && (self.writer || keys == published.as_slice())
        {
            let values = self.store.get_many(p, keys).await?;
            if values.len() != keys.len() {
                return Err(StoreError::Corrupt("short view read".into()));
            }
            return keys
                .iter()
                .zip(values)
                .map(|(key, value)| self.value(key, value))
                .collect();
        }
        // Marker observations bracket ALL candidates, including sequential defaults.
        let mut wanted = self.markers().to_vec();
        wanted.extend_from_slice(keys);
        wanted.extend_from_slice(&published);
        let history = keys
            .iter()
            .filter_map(|key| match keys::parse(key) {
                Some(keys::ParsedKey::Ref { repo, name }) => Some(keys::publication(
                    &repo,
                    &super::publication::sequence_ref(&name),
                )),
                _ => None,
            })
            .collect::<Vec<_>>();
        wanted.extend_from_slice(&history);
        wanted.extend(self.markers());
        let mut values = self.store.get_many(p, &wanted).await?;
        if values.len() != wanted.len() {
            return Err(StoreError::Corrupt("short view read".into()));
        }
        let before = self.mode(&values[..2])?;
        let after = self.mode(&values[values.len() - 2..])?;
        if matches!(after, migration::State::Legacy)
            && (keys
                .iter()
                .zip(&published)
                .enumerate()
                .any(|(index, (live, selected))| {
                    live != selected && values[2 + keys.len() + index].is_some()
                })
                || values[2 + 2 * keys.len()..values.len() - 2]
                    .iter()
                    .any(Option::is_some)
                || keys.iter().enumerate().any(|(index, key)| {
                    matches!(keys::parse(key), Some(keys::ParsedKey::Membership { .. }))
                        && values[2 + index]
                            .as_ref()
                            .is_some_and(|value| !value.as_bytes().is_empty())
                }))
        {
            return Err(StoreError::Corrupt(
                "publication history without view discriminator".into(),
            ));
        }
        if Self::managed(&before) && !Self::managed(&after) {
            return Err(StoreError::Corrupt("publication era reverted".into()));
        }
        if !Self::managed(&before) && Self::managed(&after) {
            // Initialization completed after capturing the published candidates.
            // Retry published rows only, never fetching fresh live data here.
            let mut wanted = published;
            wanted.extend(self.markers());
            values = self.store.get_many(p, &wanted).await?;
            if values.len() != wanted.len() || !Self::managed(&self.mode(&values[keys.len()..])?) {
                return Err(StoreError::Corrupt(
                    "publication era changed during retry".into(),
                ));
            }
            values.truncate(keys.len());
        } else {
            let offset = 2 + usize::from(Self::managed(&after)) * keys.len();
            values = values[offset..offset + keys.len()].to_vec();
        }
        keys.iter()
            .zip(values)
            .map(|(key, value)| self.value(key, value))
            .collect()
    }
    async fn scan(
        &self,
        p: &Partition,
        start: &Key,
        end: &Key,
        after: Option<&Cursor>,
        limit: u32,
    ) -> Result<ScanPage, StoreError> {
        let ranges = [RangeScan {
            start: start.clone(),
            end: end.clone(),
            after: after.cloned(),
            limit,
        }];
        let mut pages = self.scan_many(p, &ranges).await?;
        Ok(pages.remove(0))
    }
    async fn scan_many(
        &self,
        p: &Partition,
        ranges: &[RangeScan],
    ) -> Result<Vec<ScanPage>, StoreError> {
        if ranges.is_empty() || self.writer || !self.store.capabilities().atomic_multi_key {
            return self.store.scan_many(p, ranges).await;
        }
        let mut wanted = vec![self.marker_range()];
        for published in [false, true] {
            wanted.extend(ranges.iter().map(|range| RangeScan {
                start: if published {
                    self.key(p, &range.start)
                } else {
                    range.start.clone()
                },
                end: if published {
                    self.key(p, &range.end)
                } else {
                    range.end.clone()
                },
                after: self.cursor(range.after.as_ref(), published),
                limit: range.limit,
            }));
        }
        for tag in [b"pp".as_slice(), b"av"] {
            let (start, end) = migration::range(&self.repo.name, tag);
            wanted.push(RangeScan {
                start,
                end,
                after: None,
                limit: 1,
            });
        }
        wanted.push(self.marker_range());
        let mut captured = Vec::with_capacity(wanted.len());
        while captured.len() < wanted.len() {
            let pages = self.store.scan_many(p, &wanted[captured.len()..]).await?;
            if pages.is_empty() || pages.len() > wanted.len() - captured.len() {
                return Err(StoreError::Corrupt("short view scan".into()));
            }
            captured.extend(pages);
        }
        let before = self.page_mode(&captured[0])?;
        let after = self.page_mode(captured.last().expect("marker page"))?;
        if matches!(after, migration::State::Legacy)
            && captured[1 + ranges.len()..captured.len() - 1]
                .iter()
                .any(|page| !page.entries.is_empty() || page.next.is_some())
        {
            return Err(StoreError::Corrupt(
                "publication scan history without discriminator".into(),
            ));
        }
        if Self::managed(&before) && !Self::managed(&after) {
            return Err(StoreError::Corrupt("publication era reverted".into()));
        }
        if !Self::managed(&before) && Self::managed(&after) {
            let mut retry = wanted[1 + ranges.len()..1 + 2 * ranges.len()].to_vec();
            retry.push(self.marker_range());
            captured.clear();
            while captured.len() < retry.len() {
                let pages = self.store.scan_many(p, &retry[captured.len()..]).await?;
                if pages.is_empty() || pages.len() > retry.len() - captured.len() {
                    return Err(StoreError::Corrupt("short view retry".into()));
                }
                captured.extend(pages);
            }
            if !Self::managed(&self.page_mode(captured.last().expect("marker page"))?) {
                return Err(StoreError::Corrupt(
                    "publication era changed during scan".into(),
                ));
            }
            captured.pop();
        } else {
            let offset = 1 + usize::from(Self::managed(&after)) * ranges.len();
            captured = captured[offset..offset + ranges.len()].to_vec();
        }
        Ok(captured.into_iter().map(|page| self.page(page)).collect())
    }
    async fn apply(&self, _: &Partition, _: Batch) -> Result<BatchOutcome, StoreError> {
        Err(StoreError::Invalid(
            "read view cannot mutate storage".into(),
        ))
    }
    async fn stats(&self, p: &Partition) -> Result<PartitionStats, StoreError> {
        self.store.stats(p).await
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.store.probe().await
    }
}
