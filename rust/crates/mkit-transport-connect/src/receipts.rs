//! Client-held receipts for resumable ticketed part uploads.

use std::collections::HashMap;
use std::sync::Mutex;

use mkit_core::protocol::{PackKey, TransportError, TransportResult};
use mkit_core::upload_parts::PartPlan;

/// The immutable ticket and pack binding used to validate saved receipts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TicketMetadata {
    pub ticket_id: [u8; 32],
    pub audience: String,
    pub repository: String,
    pub signer: String,
    pub head_ref: String,
    pub pack_key: PackKey,
    pub bytes: u64,
    pub part_size: u64,
    pub expires_unix_ms: i64,
}

/// One opaque receipt and the part geometry it acknowledges.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredPart {
    pub index: u32,
    pub len: u64,
    pub receipt: Vec<u8>,
    /// Set only by a persistent store on load, for invalid-receipt recovery.
    pub from_disk: bool,
}

/// Receipt cache boundary. A store must reject metadata or geometry mismatches
/// on load and finish `put` durably before returning.
pub trait PartReceiptStore: Send + Sync {
    fn load(&self, ticket: &TicketMetadata, plan: &PartPlan) -> TransportResult<Vec<StoredPart>>;
    fn put(&self, ticket: &TicketMetadata, part: &StoredPart) -> TransportResult<()>;
    fn forget(&self, ticket_id: &[u8; 32]) -> TransportResult<()>;
    fn sweep(&self, now_ms: i64) -> TransportResult<()>;
}

/// Process-local fallback when the caller has no persistent receipt directory.
type MemoryReceipts = HashMap<[u8; 32], (TicketMetadata, Vec<StoredPart>)>;

#[derive(Default)]
pub struct MemoryPartReceiptStore {
    entries: Mutex<MemoryReceipts>,
}

impl PartReceiptStore for MemoryPartReceiptStore {
    fn load(&self, ticket: &TicketMetadata, plan: &PartPlan) -> TransportResult<Vec<StoredPart>> {
        let entries = self
            .entries
            .lock()
            .map_err(|_| TransportError::ProtocolError)?;
        let Some((saved, parts)) = entries.get(&ticket.ticket_id) else {
            return Ok(Vec::new());
        };
        if saved != ticket {
            return Ok(Vec::new());
        }
        Ok(parts
            .iter()
            .filter(|part| {
                plan.expected_len(part.index)
                    .is_ok_and(|len| len == part.len)
            })
            .cloned()
            .collect())
    }

    fn put(&self, ticket: &TicketMetadata, part: &StoredPart) -> TransportResult<()> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| TransportError::ProtocolError)?;
        let entry = entries
            .entry(ticket.ticket_id)
            .or_insert_with(|| (ticket.clone(), Vec::new()));
        if entry.0 != *ticket {
            *entry = (ticket.clone(), Vec::new());
        }
        entry.1.retain(|saved| saved.index != part.index);
        entry.1.push(part.clone());
        Ok(())
    }

    fn forget(&self, ticket_id: &[u8; 32]) -> TransportResult<()> {
        self.entries
            .lock()
            .map_err(|_| TransportError::ProtocolError)?
            .remove(ticket_id);
        Ok(())
    }

    fn sweep(&self, now_ms: i64) -> TransportResult<()> {
        self.entries
            .lock()
            .map_err(|_| TransportError::ProtocolError)?
            .retain(|_, (ticket, _)| ticket.expires_unix_ms > now_ms);
        Ok(())
    }
}
