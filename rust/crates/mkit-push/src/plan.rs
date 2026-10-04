use crate::Error;
use mkit_core::{
    hash::Hash,
    pack::{self, PackWriter},
};

/// Ordered canonical input. Staging, closure selection, delta policy and
/// signature policy belong to the host. Delta bases must already be remote.
#[derive(Clone, Debug)]
pub enum Entry {
    Raw { id: Hash, bytes: Vec<u8> },
    Delta { base: Hash, stream: Vec<u8> },
}

/// Explicit limits for one advance. Larger histories are scheduled as
/// separate advances by the host, with a fresh head lease for each step.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub payload_bytes: u64,
    pub max_pack_bytes: u64,
    pub max_parts: u32,
    pub ticket_threshold_bytes: u64,
    /// Peak retained sealed input, including the packlist node.
    pub max_staged_bytes: u64,
}

impl Limits {
    pub fn from_server_info(
        info: &crate::proto::GetServerInfoResponse,
        payload_bytes: u64,
        max_staged_bytes: u64,
    ) -> Result<Self, Error> {
        if info.protocol.as_deref() != Some("mkit.transport.v1")
            || info.spec_version != Some(2)
            || info.atomic_advance != Some(true)
        {
            return Err(Error::Invalid("ticketed atomic transport required"));
        }
        Ok(Self {
            payload_bytes,
            max_pack_bytes: info
                .max_pack_bytes
                .ok_or(Error::Invalid("server pack limit"))?,
            max_parts: info.max_parts.ok_or(Error::Invalid("server part limit"))?,
            ticket_threshold_bytes: info
                .begin_upload_threshold_bytes
                .ok_or(Error::Invalid("server ticket threshold"))?,
            max_staged_bytes,
        })
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            payload_bytes: pack::MAX_TOTAL_PAYLOAD,
            max_pack_bytes: pack::MAX_TOTAL_PAYLOAD,
            max_parts: 8192,
            ticket_threshold_bytes: 0,
            max_staged_bytes: 64 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Pack {
    pub(crate) key: Hash,
    pub(crate) bytes: Vec<u8>,
}

/// Deterministic, bounded sealed data packs. Reusing the same ordered input
/// and pack encoding yields the same pack ids, allowing safe restart.
#[derive(Clone, Debug)]
pub struct Plan {
    pub(crate) packs: Vec<Pack>,
    pub(crate) limits: Limits,
}

impl Plan {
    /// Greedy next-fit, using conservative entry sizes and exact serialized
    /// frame overhead, like the CLI. Does not upload a partial plan.
    pub fn prepare(
        entries: impl IntoIterator<Item = Entry>,
        limits: Limits,
    ) -> Result<Self, Error> {
        if limits.payload_bytes == 0 || limits.max_pack_bytes == 0 || limits.max_parts == 0 {
            return Err(Error::Limit("zero pack limit"));
        }
        let mut writer = PackWriter::new();
        let mut packs = Vec::new();
        let mut staged = 0_u64;
        let cap = limits.payload_bytes.min(pack::MAX_TOTAL_PAYLOAD);
        for entry in entries {
            let size = match &entry {
                Entry::Raw { bytes, .. } => bytes.len() as u64,
                Entry::Delta { stream, .. } => (32 + stream.len()) as u64,
            };
            if writer.entry_count() > 0
                && (writer.total_payload().saturating_add(size) > cap
                    || bound(
                        writer.total_payload().saturating_add(size),
                        writer.entry_count() + 1,
                    ) > limits.max_pack_bytes)
            {
                seal(&mut writer, &mut packs, &mut staged, limits)?;
            }
            if size > cap || bound(size, 1) > limits.max_pack_bytes {
                return Err(Error::Limit("one entry exceeds pack limit"));
            }
            // Bound memory before accepting an input entry, even if it
            // compresses dramatically. The caller owns its input allocation.
            if staged
                .saturating_add(writer.total_payload())
                .saturating_add(size)
                > limits.max_staged_bytes
            {
                return Err(Error::Limit("staged input limit"));
            }
            match entry {
                Entry::Raw { id, bytes } => {
                    writer.push_raw(id, &bytes)?;
                }
                Entry::Delta { base, stream } => {
                    writer.push_delta(&base, &stream)?;
                }
            }
        }
        seal(&mut writer, &mut packs, &mut staged, limits)?;
        if !packs.is_empty() {
            // Reserve the largest node shape before any upload can reserve
            // server resources. A prior pointer adds 32 bytes.
            let ids: Vec<_> = packs.iter().map(|pack| pack.key).collect();
            let node = mkit_core::transfer::encode_packlist(Some([0; 32]), &ids)?;
            if node.len() as u64 > limits.max_pack_bytes
                || staged.saturating_add(node.len() as u64) > limits.max_staged_bytes
            {
                return Err(Error::Limit("packmap node/staged input limit"));
            }
        }
        Ok(Self { packs, limits })
    }

    pub fn pack_ids(&self) -> impl Iterator<Item = &Hash> {
        self.packs.iter().map(|pack| &pack.key)
    }
}

fn bound(payload: u64, entries: usize) -> u64 {
    payload
        .saturating_add((entries as u64).saturating_mul(pack::ENTRY_FRAME_LEN as u64))
        .saturating_add((pack::HEADER_LEN + pack::TRAILER_LEN) as u64)
}

fn seal(
    writer: &mut PackWriter,
    packs: &mut Vec<Pack>,
    staged: &mut u64,
    limits: Limits,
) -> Result<(), Error> {
    if writer.entry_count() == 0 {
        return Ok(());
    }
    let bytes = std::mem::take(writer).finish()?;
    *staged = staged.saturating_add(bytes.len() as u64);
    if bytes.len() as u64 > limits.max_pack_bytes || *staged > limits.max_staged_bytes {
        return Err(Error::Limit("sealed input limit"));
    }
    // Always reserve one of the seven ticket slots for the packlist node.
    if bytes.len() as u64 >= limits.ticket_threshold_bytes
        && packs
            .iter()
            .filter(|p| p.bytes.len() as u64 >= limits.ticket_threshold_bytes)
            .count()
            >= 6
    {
        return Err(Error::Limit(
            "advance requires more than six ticketed data packs",
        ));
    }
    packs.push(Pack {
        key: pack::pack_key(&bytes),
        bytes,
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mkit_core::{
        object::{Blob, Object},
        serialize::serialize,
    };

    #[test]
    fn ticket_budget_and_packmap_space_are_checked_before_upload() {
        let make = |salt| {
            let bytes = serialize(&Object::Blob(Blob {
                data: vec![salt; 10],
            }))
            .unwrap();
            Entry::Raw {
                id: mkit_core::hash::hash(&bytes),
                bytes,
            }
        };
        let limits = Limits {
            payload_bytes: 30,
            max_pack_bytes: 1024,
            ..Limits::default()
        };
        assert!(Plan::prepare((0..6).map(make), limits).is_ok());
        assert!(matches!(
            Plan::prepare((0..7).map(make), limits),
            Err(Error::Limit(_))
        ));
        let limits = Limits {
            max_staged_bytes: 60,
            ..Limits::default()
        };
        assert!(matches!(
            Plan::prepare([make(1)], limits),
            Err(Error::Limit(_))
        ));
    }
}
