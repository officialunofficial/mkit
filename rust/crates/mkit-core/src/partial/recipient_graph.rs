//! Bounded, typed snapshot traversal over one immutable cache.

use std::collections::BTreeMap;

use crate::hash::Hash;
use crate::object::{EntryMode, Object, ObjectType, id_from_object};
use crate::serialize::{deserialize, serialize};
use crate::verify::ObjectSource;

use super::recipient::{RecipientError, RecipientLimits, RecipientUsage};

#[derive(Clone, Copy)]
enum Role {
    Base,
    Candidate,
    Tree,
    File,
    Symlink,
    Chunk,
}

pub(super) struct RecipientGraph<'a, S: ObjectSource + ?Sized> {
    source: &'a mut S,
    cache: BTreeMap<Hash, (Vec<u8>, Object)>,
    bytes: usize,
    work: usize,
    max_depth_seen: usize,
    limits: RecipientLimits,
}

impl<'a, S: ObjectSource + ?Sized> RecipientGraph<'a, S> {
    pub(super) fn new(source: &'a mut S, limits: RecipientLimits) -> Self {
        Self {
            source,
            cache: BTreeMap::new(),
            bytes: 0,
            work: 0,
            max_depth_seen: 0,
            limits,
        }
    }

    pub(super) fn usage(&self) -> RecipientUsage {
        RecipientUsage {
            objects: self.cache.len(),
            canonical_bytes: self.bytes,
            max_tree_depth: self.max_depth_seen,
            occurrences: self.work,
        }
    }

    pub(super) fn charge(&mut self, count: usize) -> Result<(), RecipientError> {
        self.work = self
            .work
            .checked_add(count)
            .ok_or(RecipientError::BudgetExceeded)?;
        if self.work > self.limits.max_occurrences {
            return Err(RecipientError::BudgetExceeded);
        }
        Ok(())
    }

    pub(super) fn object(&self, id: &Hash) -> Result<&Object, RecipientError> {
        self.cache
            .get(id)
            .map(|(_, object)| object)
            .ok_or(RecipientError::Missing(*id))
    }

    pub(super) fn root_tree(&self, id: &Hash) -> Result<Hash, RecipientError> {
        match self.object(id)? {
            Object::Commit(commit) => Ok(commit.tree_hash),
            Object::Remix(remix) => Ok(remix.tree_hash),
            _ => Err(RecipientError::WrongObjectType(*id)),
        }
    }

    pub(super) fn validate_base(&mut self, id: Hash) -> Result<(), RecipientError> {
        self.walk(id, Role::Base, &BTreeMap::new())
    }

    pub(super) fn validate_candidate(
        &mut self,
        id: Hash,
        uploaded: &BTreeMap<Hash, &[u8]>,
    ) -> Result<(), RecipientError> {
        self.walk(id, Role::Candidate, uploaded)
    }

    pub(super) fn source_bytes(&self, id: &Hash) -> Option<&[u8]> {
        self.cache.get(id).map(|(bytes, _)| bytes.as_slice())
    }

    pub(super) fn closure_work(&mut self, root: Hash) -> Result<(), RecipientError> {
        // The closure verifier walks distinct ids; reserve every edge it can
        // inspect before it starts. It reads only this cache, never the source.
        let mut seen = std::collections::BTreeSet::new();
        let mut pending = vec![root];
        while let Some(id) = pending.pop() {
            if !seen.insert(id) {
                continue;
            }
            self.charge(1)?;
            let children = crate::ops::graph::children(
                self.object(&id)?,
                crate::ops::graph::ClosureMode::Snapshot,
            );
            self.charge(children.len())?;
            pending.extend(children);
        }
        Ok(())
    }

    fn walk(
        &mut self,
        root: Hash,
        root_role: Role,
        uploaded: &BTreeMap<Hash, &[u8]>,
    ) -> Result<(), RecipientError> {
        // Depth counts Tree edges from the commit's root Tree. A shared Tree
        // reached at two depths is checked twice against the deeper depth.
        let mut pending = vec![(root, root_role, 0usize)];
        while let Some((id, role, depth)) = pending.pop() {
            self.charge(1)?;
            if matches!(role, Role::Tree) {
                if depth > self.limits.max_tree_depth {
                    return Err(RecipientError::BudgetExceeded);
                }
                self.max_depth_seen = self.max_depth_seen.max(depth);
            }
            self.ensure(id, uploaded)?;
            let object = self.object(&id)?;
            let allowed = match role {
                Role::Base => matches!(object, Object::Commit(_) | Object::Remix(_)),
                Role::Candidate => matches!(object, Object::Commit(_)),
                Role::Tree => matches!(object, Object::Tree(_)),
                Role::File => matches!(object, Object::Blob(_) | Object::ChunkedBlob(_)),
                Role::Symlink | Role::Chunk => matches!(object, Object::Blob(_)),
            };
            if !allowed {
                return Err(RecipientError::WrongObjectType(id));
            }
            match object {
                Object::Commit(commit) => {
                    if crate::sign::verify_commit(commit).is_err() {
                        return Err(RecipientError::InvalidSignature(id));
                    }
                    pending.push((commit.tree_hash, Role::Tree, 0));
                }
                Object::Remix(remix) => {
                    if crate::sign::verify_remix(remix).is_err() {
                        return Err(RecipientError::InvalidSignature(id));
                    }
                    pending.push((remix.tree_hash, Role::Tree, 0));
                }
                Object::Tree(tree) => {
                    let count = tree.entries.len();
                    self.charge(count)?;
                    let Object::Tree(tree) = self.object(&id)? else {
                        unreachable!()
                    };
                    let children = tree
                        .entries
                        .iter()
                        .map(|entry| (entry.object_hash, entry.mode))
                        .collect::<Vec<_>>();
                    for (child_id, mode) in children.into_iter().rev() {
                        let (child_role, child_depth) = match mode {
                            EntryMode::Tree => (
                                Role::Tree,
                                depth.checked_add(1).ok_or(RecipientError::BudgetExceeded)?,
                            ),
                            EntryMode::Blob | EntryMode::Executable => (Role::File, depth),
                            EntryMode::Symlink => (Role::Symlink, depth),
                        };
                        pending.push((child_id, child_role, child_depth));
                    }
                }
                Object::ChunkedBlob(manifest) => {
                    if manifest.chunks.is_empty() != (manifest.total_size == 0) {
                        return Err(RecipientError::InvalidChunkLayout);
                    }
                    let count = manifest.chunks.len();
                    let total_size = manifest.total_size;
                    let fixed = manifest.chunk_size as usize;
                    self.charge(count)?;
                    let Object::ChunkedBlob(manifest) = self.object(&id)? else {
                        unreachable!()
                    };
                    let chunks = manifest.chunks.clone();
                    let mut total = 0u64;
                    for (index, chunk_id) in chunks.iter().enumerate() {
                        self.ensure(*chunk_id, uploaded)?;
                        let Object::Blob(blob) = self.object(chunk_id)? else {
                            return Err(RecipientError::WrongObjectType(*chunk_id));
                        };
                        let length = blob.data.len();
                        if fixed != 0
                            && (length == 0
                                || (index + 1 < chunks.len() && length != fixed)
                                || (index + 1 == chunks.len() && length > fixed))
                        {
                            return Err(RecipientError::InvalidChunkLayout);
                        }
                        total = total
                            .checked_add(length as u64)
                            .ok_or(RecipientError::InvalidChunkLayout)?;
                        if total > total_size {
                            return Err(RecipientError::InvalidChunkLayout);
                        }
                        pending.push((*chunk_id, Role::Chunk, depth));
                    }
                    if total != total_size {
                        return Err(RecipientError::InvalidChunkLayout);
                    }
                }
                Object::Blob(_) => {}
                _ => return Err(RecipientError::WrongObjectType(id)),
            }
        }
        Ok(())
    }

    fn ensure(&mut self, id: Hash, uploaded: &BTreeMap<Hash, &[u8]>) -> Result<(), RecipientError> {
        if let Some(bytes) = uploaded.get(&id) {
            if let Some((existing, _)) = self.cache.get(&id) {
                if existing != bytes {
                    return Err(RecipientError::Corrupt(id));
                }
                return Ok(());
            }
            return self.insert(id, bytes);
        }
        if self.cache.contains_key(&id) {
            return Ok(());
        }
        if self.cache.len() >= self.limits.max_objects
            || self.bytes >= self.limits.max_canonical_bytes
        {
            return Err(RecipientError::BudgetExceeded);
        }
        let bytes = self
            .source
            .fetch(&id)
            .map_err(RecipientError::Source)?
            .ok_or(RecipientError::Missing(id))?;
        // The source owns its initial fetch allocation; enforce our cap before
        // cloning, retaining, or decoding returned canonical bytes.
        if bytes.len() > self.limits.max_object_bytes
            || self
                .bytes
                .checked_add(bytes.len())
                .is_none_or(|total| total > self.limits.max_canonical_bytes)
        {
            return Err(RecipientError::BudgetExceeded);
        }
        let owned = bytes.into_owned();
        self.insert(id, &owned)
    }

    fn insert(&mut self, id: Hash, bytes: &[u8]) -> Result<(), RecipientError> {
        if bytes.len() > self.limits.max_object_bytes || self.cache.len() >= self.limits.max_objects
        {
            return Err(RecipientError::BudgetExceeded);
        }
        let next = self
            .bytes
            .checked_add(bytes.len())
            .ok_or(RecipientError::BudgetExceeded)?;
        if next > self.limits.max_canonical_bytes {
            return Err(RecipientError::BudgetExceeded);
        }
        // The decoder reserves vector capacity from these counts. Check each
        // count against the physical minimum record size before decoding.
        if bytes.first() == Some(&(ObjectType::Tree as u8)) {
            if bytes.len() < 10 {
                return Err(RecipientError::Corrupt(id));
            }
            let count = u32::from_le_bytes(
                bytes[6..10]
                    .try_into()
                    .map_err(|_| RecipientError::Corrupt(id))?,
            ) as usize;
            if count > (bytes.len() - 10) / 38 {
                return Err(RecipientError::Corrupt(id));
            }
        }
        if bytes.first() == Some(&(ObjectType::ChunkedBlob as u8)) {
            if bytes.len() < 22 {
                return Err(RecipientError::Corrupt(id));
            }
            let count = u32::from_le_bytes(
                bytes[18..22]
                    .try_into()
                    .map_err(|_| RecipientError::Corrupt(id))?,
            ) as usize;
            if count > (bytes.len() - 22) / 32 {
                return Err(RecipientError::Corrupt(id));
            }
        }
        let object = deserialize(bytes).map_err(|_| RecipientError::Corrupt(id))?;
        if serialize(&object).map_err(|_| RecipientError::Corrupt(id))? != bytes
            || id_from_object(&object, bytes) != id
        {
            return Err(RecipientError::Corrupt(id));
        }
        self.cache.insert(id, (bytes.to_vec(), object));
        self.bytes = next;
        Ok(())
    }
}

pub(super) struct CachedSource<'a, S: ObjectSource + ?Sized>(pub(super) &'a RecipientGraph<'a, S>);

impl<S: ObjectSource + ?Sized> ObjectSource for CachedSource<'_, S> {
    fn fetch(
        &mut self,
        id: &Hash,
    ) -> Result<Option<std::borrow::Cow<'_, [u8]>>, crate::verify::VerifyError> {
        Ok(self.0.source_bytes(id).map(std::borrow::Cow::Borrowed))
    }
}
