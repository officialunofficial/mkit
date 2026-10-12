//! Read helpers: the packmap chain walk and filesystem-free unpacking with
//! signature verification on by default.

use crate::connect::{Clock, Error, HttpTransport, Rpc, Signer};
use crate::seams::Observer;
use mkit_core::{
    hash::{Hash, to_hex},
    pack::{self, DecodeLimits, DeltaBaseSource, PackError, decode_entries_with},
    sign,
    transfer::{self, PackListNode},
};
use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
};

pub(crate) const MAX_CHAIN_DEPTH: usize = 100_000;
pub(crate) const MAX_CHAIN_PACKS: usize = 1_000_000;

/// Walk a packmap chain from `root` along `prev`, newest node first. Bounded by
/// depth, distinct pack count and cycle detection; every node is downloaded
/// under its content commitment.
///
/// Each node goes to `visit` and is then dropped, so the walk retains only what
/// the visitor keeps.
pub(crate) async fn walk_nodes<T: HttpTransport, S: Signer, C: Clock, O: Observer>(
    rpc: &Rpc<'_, T, S, C, O>,
    root: Hash,
    head_ref: &str,
    mut visit: impl FnMut(PackListNode) -> Result<Option<Hash>, Error>,
) -> Result<(), Error> {
    let mut cursor = Some(root);
    let mut seen = HashSet::new();
    while let Some(key) = cursor {
        if seen.len() >= MAX_CHAIN_DEPTH || !seen.insert(key) {
            return Err(Error::Limit("packmap depth/cycle"));
        }
        let node = transfer::decode_packlist(&rpc.download(key, head_ref).await?)?;
        cursor = visit(node)?;
    }
    Ok(())
}

/// Walk to a flat, oldest-first pack list. Retention is bounded by the total
/// number of pack ids the nodes list (not only the distinct ones).
pub(crate) async fn resolve<T: HttpTransport, S: Signer, C: Clock, O: Observer>(
    rpc: &Rpc<'_, T, S, C, O>,
    root: Hash,
    head_ref: &str,
) -> Result<Vec<Hash>, Error> {
    let mut nodes: Vec<Vec<Hash>> = Vec::new();
    let mut listed = 0_usize;
    walk_nodes(rpc, root, head_ref, |node| {
        listed = listed.saturating_add(node.packs.len());
        if listed > MAX_CHAIN_PACKS {
            return Err(Error::Limit("packmap pack count"));
        }
        nodes.push(node.packs);
        Ok(node.prev)
    })
    .await?;
    Ok(oldest_first(nodes))
}

/// Pack ids of a walked chain, oldest first (the order a fetcher unpacks so
/// every delta base is already present). A pack named twice is listed once, at
/// its first position.
pub(crate) fn oldest_first(mut nodes: Vec<Vec<Hash>>) -> Vec<Hash> {
    nodes.reverse();
    let mut seen = HashSet::new();
    nodes
        .into_iter()
        .flatten()
        .filter(|id| seen.insert(*id))
        .collect()
}

/// Where unpacked objects go. The client holds no filesystem: a native host
/// backs this with its store, a wasm host with memory, `IndexedDB` or similar.
///
/// `put` is called in pack order, after the object's signature (when
/// verification is on) has been checked, so an object the sink holds is never
/// an unverified commit, remix or tag. A failed unpack can still leave earlier,
/// verified objects in the sink; treat the sink as staging and publish refs
/// only after `unpack` succeeds.
pub trait ObjectSink {
    /// Canonical bytes of an object the sink already holds, used as the base of
    /// a delta whose base is not in the same pack. `None` if absent. The bytes
    /// are re-hashed by the decoder, so a sink cannot substitute another object.
    /// A base is not signature-checked: the sink is expected to hold only objects
    /// it already accepted.
    ///
    /// # Errors
    /// A sink failure, which aborts the unpack.
    fn get(&mut self, id: &Hash) -> Result<Option<Vec<u8>>, String>;

    /// Store one object's canonical bytes under its id.
    ///
    /// # Errors
    /// A sink failure, which aborts the unpack.
    fn put(&mut self, id: Hash, bytes: &[u8]) -> Result<(), String>;
}

/// An in-memory sink.
#[derive(Debug, Default)]
pub struct MemorySink {
    pub objects: HashMap<Hash, Vec<u8>>,
}
impl ObjectSink for MemorySink {
    fn get(&mut self, id: &Hash) -> Result<Option<Vec<u8>>, String> {
        Ok(self.objects.get(id).cloned())
    }
    fn put(&mut self, id: Hash, bytes: &[u8]) -> Result<(), String> {
        self.objects.insert(id, bytes.to_vec());
        Ok(())
    }
}

/// Signature policy for commits, remixes and tags. The default is `Require`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum Verification {
    /// Reject an unsigned or badly signed commit, remix or tag. This checks
    /// integrity under the signer key embedded in the object; deciding whether
    /// that signer is trusted is the caller's job.
    #[default]
    Require,
    /// Explicit opt-out: store signed kinds without checking them.
    Skip,
}

/// Unpack options.
#[derive(Clone, Copy, Debug, Default)]
#[non_exhaustive]
pub struct UnpackOptions {
    pub verification: Verification,
    /// Cap on bytes one decode allocates beyond the pack itself. The default
    /// is the format maximum; size it down for a constrained host.
    pub limits: DecodeLimits,
}
impl UnpackOptions {
    #[must_use]
    pub fn with_verification(mut self, verification: Verification) -> Self {
        self.verification = verification;
        self
    }
    #[must_use]
    pub fn with_limits(mut self, limits: DecodeLimits) -> Self {
        self.limits = limits;
        self
    }
}

/// What an unpack stored.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Unpacked {
    pub raw_count: usize,
    pub delta_count: usize,
    /// Every entry's id in pack order.
    pub ids: Vec<Hash>,
}

struct SinkBases<'a, K> {
    sink: &'a RefCell<&'a mut K>,
    failure: &'a RefCell<Option<Error>>,
}
impl<K: ObjectSink> DeltaBaseSource for SinkBases<'_, K> {
    fn base(&mut self, id: &Hash) -> Result<Option<Vec<u8>>, PackError> {
        self.sink.borrow_mut().get(id).map_err(|message| {
            *self.failure.borrow_mut() = Some(Error::Sink(message));
            PackError::DeltaBaseMissing(to_hex(id))
        })
    }
}

/// Check `pack` against its requested id, decode it, verify the signed kinds
/// and hand every object to `sink`. Compressed entries need a zstd backend
/// (`pack-ruzstd`, on by default, or `pack-zstd`); without one they fail closed.
///
/// # Errors
/// A pack that does not hash to `pack_id`, a malformed pack or one beyond
/// `options.limits`, a missing delta base, a sink failure, or (with
/// [`Verification::Require`]) a commit, remix or tag whose signature does not
/// verify under its embedded signer.
pub fn unpack<K: ObjectSink>(
    pack_id: &Hash,
    pack_bytes: &[u8],
    sink: &mut K,
    options: UnpackOptions,
) -> Result<Unpacked, Error> {
    if pack::pack_key(pack_bytes) != *pack_id {
        return Err(Error::Invalid("pack content commitment"));
    }
    let sink = RefCell::new(sink);
    let failure = RefCell::new(None);
    let mut bases = SinkBases {
        sink: &sink,
        failure: &failure,
    };
    let report = decode_entries_with(pack_bytes, &mut bases, options.limits, |entry| {
        if options.verification == Verification::Require
            && let Err(error) = sign::verify_object_signature(&entry.object)
        {
            *failure.borrow_mut() = Some(Error::Signature {
                id: to_hex(&entry.id),
                reason: error.to_string(),
            });
            return Err(PackError::PackfileCorrupted);
        }
        sink.borrow_mut()
            .put(entry.id, entry.bytes)
            .map_err(|message| {
                *failure.borrow_mut() = Some(Error::Sink(message));
                PackError::PackfileCorrupted
            })
    });
    match report {
        Ok(report) => Ok(Unpacked {
            raw_count: report.raw_count,
            delta_count: report.delta_count,
            ids: report.ids,
        }),
        Err(error) => Err(failure.take().unwrap_or(Error::Pack(error))),
    }
}
