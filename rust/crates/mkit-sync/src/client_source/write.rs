//! Native write orchestration over the client's canonical per-RPC calls.

use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use mkit_client::proto::{self, GetServerInfoResponse, UploadTicket};
use mkit_client::{
    Error, Identity, MemoryPartReceiptStore, PartReceiptStore, StoredPart, TicketMetadata,
};
use mkit_core::hash::{Hash, to_hex};
use mkit_core::protocol::{AdvanceOutcome, CommitOutcome, PACK_BODY_LIMIT, PackKey, UploadLimits};
use mkit_core::refs::RefWriteCondition;
use mkit_core::upload_parts::PartPlan;

use super::{ClientSource, Clock, Executor, HttpTransport, Observer, Signer, source_error};
use crate::SourceError;

/// Host-owned scheduling and admission recovery. Returning `true` retries the
/// same operation; the host must bound retries and finish any wait first.
pub trait WriteRecovery {
    /// Start a logical RPC. Reset per-call helper and retry state here.
    /// This callback runs outside the asynchronous executor.
    fn before_call(&self, procedure: &str) -> Result<(), SourceError> {
        let _ = procedure;
        Ok(())
    }

    /// Decide whether to retry a failed RPC. Admission headers are supplied
    /// through the client's request policy, and policy never runs in this adapter.
    fn recover(
        &self,
        procedure: &str,
        error: &SourceError,
        attempt: u32,
    ) -> Result<bool, SourceError>;

    /// Report upload progress or refuse before the next part. A `PartSent`
    /// event follows successful durable receipt persistence.
    fn upload_event(&self, event: UploadEvent) -> Result<(), SourceError> {
        let _ = event;
        Ok(())
    }
}

/// Progress for one multipart pack upload.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum UploadEvent {
    PartsPlanned {
        parts: u32,
        resumed: u32,
        saved_bytes: u64,
        bytes: u64,
    },
    PartSent {
        index: u32,
        parts: u32,
        saved_bytes: u64,
        bytes: u64,
        resumed: u32,
    },
    /// Cancellation boundary before sending a part.
    BeforePart,
    Completing,
    Finished,
}

/// Caller-owned upload state reusable across fresh borrowed clients. A session
/// binds to one destination and signer on first use. Part receipts remain
/// caller-owned and can survive process restarts through a durable store.
#[derive(Default)]
pub struct ClientSession {
    pub(super) state: WriteState,
    binding: RefCell<Option<SessionBinding>>,
}

#[derive(PartialEq, Eq)]
struct SessionBinding {
    origin: String,
    repository: String,
    public_key: Option<Hash>,
}

impl std::fmt::Debug for ClientSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ClientSession")
            .finish_non_exhaustive()
    }
}

impl ClientSession {
    /// Configure the durable receipt store before lending this session to a
    /// source. Store replacement affects subsequent session operations.
    #[must_use]
    pub fn with_receipt_store(self, store: Arc<dyn PartReceiptStore>) -> Self {
        self.state.receipts.replace(store);
        self
    }

    pub(super) fn bind(
        &self,
        origin: &str,
        repository: &str,
        public_key: Option<Hash>,
    ) -> Result<(), SourceError> {
        let requested = SessionBinding {
            origin: origin.to_owned(),
            repository: repository.to_owned(),
            public_key,
        };
        let mut binding = self.binding.borrow_mut();
        match binding.as_ref() {
            Some(existing) if existing != &requested => Err(SourceError::InvalidResponse),
            Some(_) => Ok(()),
            None => {
                *binding = Some(requested);
                Ok(())
            }
        }
    }
}

pub(super) struct WriteState {
    info: RefCell<Option<Result<GetServerInfoResponse, ()>>>,
    tickets: RefCell<HashMap<(String, PackKey), UploadTicket>>,
    pub(super) receipts: RefCell<Arc<dyn PartReceiptStore>>,
    swept: Cell<bool>,
    ticketless: Cell<bool>,
}

impl Default for WriteState {
    fn default() -> Self {
        Self {
            info: RefCell::new(None),
            tickets: RefCell::new(HashMap::new()),
            receipts: RefCell::new(Arc::new(MemoryPartReceiptStore::default())),
            swept: Cell::new(false),
            ticketless: Cell::new(false),
        }
    }
}

impl WriteState {
    fn receipt_store(&self) -> Arc<dyn PartReceiptStore> {
        Arc::clone(&self.receipts.borrow())
    }
}

fn remote_is(error: &SourceError, code: &str) -> bool {
    matches!(error, SourceError::Remote(remote) if remote.code == code)
}

fn valid_info(info: &GetServerInfoResponse) -> bool {
    info.protocol.as_deref() == Some("mkit.transport.v1")
        && info.spec_version.is_some_and(|version| version >= 2)
        && info
            .part_size
            .is_some_and(|size| size >= 8 * 1024 * 1024 && size.is_power_of_two())
        && info.max_parts.is_some_and(|parts| parts >= 1)
        && info.max_list_refs_page_size.is_some_and(|size| size >= 1)
}

fn condition(condition: RefWriteCondition) -> (proto::RefExpectation, Option<Vec<u8>>) {
    match condition {
        RefWriteCondition::Any => (proto::RefExpectation::Any, None),
        RefWriteCondition::Missing => (proto::RefExpectation::Missing, None),
        RefWriteCondition::Match(id) => (proto::RefExpectation::Match, Some(id.to_vec())),
    }
}

impl<T: HttpTransport, S: Signer, C: Clock, E: Executor, O: Observer>
    ClientSource<'_, T, S, C, E, O>
{
    fn write_info(&self) -> Option<GetServerInfoResponse> {
        if self.write_state().info.borrow().is_none() {
            let info = match self.executor.block_on(self.client.server_info()) {
                Ok(info) if valid_info(&info) => Ok(info),
                Err(Error::Remote(remote)) if remote.code == "unimplemented" => {
                    self.write_state().ticketless.set(true);
                    Err(())
                }
                _ => Err(()),
            };
            *self.write_state().info.borrow_mut() = Some(info);
        }
        self.write_state()
            .info
            .borrow()
            .as_ref()
            .and_then(|info| info.as_ref().ok())
            .cloned()
    }

    fn write_call<R>(
        &self,
        procedure: &str,
        ticketed: bool,
        deadline: Option<i64>,
        mut call: impl FnMut(Option<&Identity>) -> Result<R, Error>,
    ) -> Result<R, SourceError> {
        let full_procedure = format!("/mkit.transport.v1.TransportService/{procedure}");
        if let Some(recovery) = self.recovery {
            recovery.before_call(&full_procedure)?;
        }
        let mut identity = self
            .client
            .public_key()
            .map(|_| self.client.new_identity())
            .transpose()
            .map_err(source_error)?;
        let mut attempt = 1;
        let mut definitive = false;
        let mut saw_pending = false;
        let mut renewed_after_unauthenticated = false;
        loop {
            let now = self.client.now_ms();
            if deadline
                .zip(now)
                .is_some_and(|(deadline, now)| now >= deadline)
            {
                return Err(SourceError::Deadline);
            }
            if let (Some(now), Some(current)) = (now, identity)
                && (now >= current.expires_at_ms
                    || (definitive && current.expires_at_ms.saturating_sub(now) <= 30_000))
            {
                identity = Some(self.client.new_identity().map_err(source_error)?);
            }
            match call(identity.as_ref()) {
                Ok(value) => return Ok(value),
                Err(error) => {
                    let mapped = source_error(error);
                    if matches!(mapped, SourceError::PaymentRequired { .. })
                        && (ticketed
                            || !matches!(procedure, "BeginUpload" | "UpdateRef" | "AdvanceRefs"))
                    {
                        return Err(mapped);
                    }
                    if matches!(mapped, SourceError::Remote(ref remote) if remote.code == "unauthenticated")
                        && identity.is_some()
                        && (procedure == "UploadPart" || saw_pending)
                        && !renewed_after_unauthenticated
                    {
                        identity = Some(self.client.new_identity().map_err(source_error)?);
                        renewed_after_unauthenticated = true;
                        continue;
                    }
                    if matches!(mapped, SourceError::PendingVerification { .. }) {
                        saw_pending = true;
                        renewed_after_unauthenticated = false;
                    }
                    let Some(recovery) = self.recovery else {
                        return Err(mapped);
                    };
                    definitive = matches!(
                        mapped,
                        SourceError::PendingVerification { .. }
                            | SourceError::MembershipNotVisible
                            | SourceError::PaymentRequired { .. }
                    );
                    if !recovery.recover(&full_procedure, &mapped, attempt)? {
                        return Err(mapped);
                    }
                    attempt = attempt.checked_add(1).ok_or(SourceError::ProtocolError)?;
                }
            }
        }
    }

    pub(super) fn write_upload(
        &self,
        bytes: &[u8],
        key: &PackKey,
        head: &str,
    ) -> Result<(), SourceError> {
        if bytes.len() as u64 > PACK_BODY_LIMIT {
            return Err(SourceError::PayloadTooLarge(bytes.len()));
        }
        let info = self.write_info();
        let ticketless = (info.is_none() && self.client.public_key().is_none())
            || self.write_state().ticketless.get()
            || info.as_ref().is_some_and(|info| {
                (bytes.len() as u64) < info.begin_upload_threshold_bytes.unwrap_or(0)
            });
        if ticketless {
            return self
                .write_call("UploadPack", false, None, |identity| {
                    self.executor.block_on(self.client.upload_pack(
                        &key.into_hash(),
                        bytes,
                        None,
                        identity,
                    ))
                })
                .map(|_| ());
        }
        if self.client.public_key().is_none() {
            return Err(SourceError::RemoteError(
                "server requires signed uploads; set `transport_auth = envelope`".to_owned(),
            ));
        }
        for restart in 0..2 {
            let begun = self.write_call("BeginUpload", false, None, |identity| {
                self.executor.block_on(self.client.begin_upload(
                    head,
                    &key.into_hash(),
                    bytes.len() as u64,
                    identity,
                ))
            });
            let begun = match begun {
                Err(error) if info.is_none() && remote_is(&error, "unimplemented") => {
                    self.write_state().ticketless.set(true);
                    return self.write_upload(bytes, key, head);
                }
                Err(SourceError::Remote(remote)) if remote.code == "unimplemented" => {
                    let message = if info
                        .as_ref()
                        .is_some_and(|info| bytes.len() as u64 > info.part_size.unwrap_or(0))
                    {
                        "server storage cannot accept packs over part_size"
                    } else {
                        "V2 server does not implement BeginUpload"
                    };
                    return Err(SourceError::RemoteError(message.to_owned()));
                }
                Err(SourceError::Remote(remote)) if remote.code == "failed_precondition" => {
                    return Err(SourceError::RemoteError(
                        if remote.message == "too many open upload tickets" {
                            remote.message
                        } else {
                            format!("upload ticket rejected: {}", remote.message)
                        },
                    ));
                }
                result => result?.value,
            };
            let ticket = match begun.result {
                Some(proto::begin_upload_response::Result::AlreadyPresent(_)) => {
                    if let Some(old) = self
                        .write_state()
                        .tickets
                        .borrow_mut()
                        .remove(&(head.to_owned(), *key))
                    {
                        self.forget_ticket(&old);
                    }
                    return Ok(());
                }
                Some(proto::begin_upload_response::Result::Ticket(ticket)) => *ticket,
                _ => return Err(SourceError::InvalidResponse),
            };
            let id: Hash = ticket
                .id
                .as_deref()
                .and_then(|id| id.try_into().ok())
                .ok_or(SourceError::InvalidResponse)?;
            let part_size = ticket.part_size.ok_or(SourceError::InvalidResponse)?;
            let expiry = ticket.expires_unix_ms.ok_or(SourceError::InvalidResponse)?;
            if ticket.token.as_ref().is_none_or(Vec::is_empty)
                || part_size < 8 * 1024 * 1024
                || !part_size.is_power_of_two()
                || expiry <= self.client.now_ms().unwrap_or(i64::MAX)
            {
                return Err(SourceError::InvalidResponse);
            }
            if let Some(old) = self
                .write_state()
                .tickets
                .borrow_mut()
                .insert((head.to_owned(), *key), ticket.clone())
                && old.id != ticket.id
            {
                self.forget_ticket(&old);
            }
            let result = if bytes.len() as u64 <= part_size {
                self.write_call("UploadPack", true, None, |identity| {
                    self.executor.block_on(self.client.upload_pack(
                        &key.into_hash(),
                        bytes,
                        ticket.token.as_deref(),
                        identity,
                    ))
                })
                .map(|_| ())
            } else {
                self.write_parts(bytes, key, head, &ticket, info.as_ref(), id)
            };
            match result {
                Ok(()) => return Ok(()),
                Err(error) if remote_is(&error, "failed_precondition") => {
                    if restart == 1 {
                        return Err(SourceError::RemoteError(
                            "upload ticket rejected".to_owned(),
                        ));
                    }
                }
                Err(error) => return Err(error),
            }
        }
        Err(SourceError::ProtocolError)
    }

    fn forget_ticket(&self, ticket: &UploadTicket) {
        if let Some(id) = ticket
            .id
            .as_deref()
            .and_then(|id| <Hash>::try_from(id).ok())
        {
            let _ = self.write_state().receipt_store().forget(&id);
        }
    }

    fn write_upload_event(&self, event: UploadEvent) -> Result<(), SourceError> {
        if let Some(recovery) = self.recovery {
            recovery.upload_event(event)?;
        }
        Ok(())
    }

    fn write_parts(
        &self,
        bytes: &[u8],
        key: &PackKey,
        head: &str,
        ticket: &UploadTicket,
        info: Option<&GetServerInfoResponse>,
        id: Hash,
    ) -> Result<(), SourceError> {
        let plan = PartPlan::new(
            bytes.len() as u64,
            ticket.part_size.unwrap_or(0),
            info.map_or(u32::MAX, |info| info.max_parts.unwrap_or(0)),
        )
        .map_err(|error| match error {
            mkit_core::upload_parts::PartError::TooManyParts => SourceError::RemoteError(
                "pack exceeds the server's maximum number of upload parts".to_owned(),
            ),
            _ => SourceError::ProtocolError,
        })?;
        let metadata = TicketMetadata {
            ticket_id: id,
            audience: self.client.destination().origin().to_owned(),
            repository: self.client.destination().repository().to_owned(),
            signer: self
                .client
                .public_key()
                .map_or_else(String::new, |key| to_hex(&key)),
            head_ref: head.to_owned(),
            pack_key: *key,
            bytes: bytes.len() as u64,
            part_size: ticket.part_size.unwrap_or(0),
            expires_unix_ms: ticket.expires_unix_ms.unwrap_or(0),
        };
        if !self.write_state().swept.replace(true) {
            let _ = self
                .write_state()
                .receipt_store()
                .sweep(self.client.now_ms().unwrap_or(0));
        }
        for invalid_retry in 0..2 {
            let mut parts = vec![None; plan.count() as usize];
            if invalid_retry == 0 {
                for part in self
                    .write_state()
                    .receipt_store()
                    .load(&metadata, &plan)
                    .map_err(SourceError::from)?
                {
                    if plan
                        .expected_len(part.index)
                        .is_ok_and(|len| len == part.len)
                        && !part.receipt.is_empty()
                        && part.receipt.len() <= 512
                    {
                        let index = part.index as usize;
                        if let Some(slot) = parts.get_mut(index) {
                            *slot = Some(part);
                        }
                    }
                }
            }
            let resumed = parts.iter().flatten().count() as u32;
            let mut saved_bytes = parts.iter().flatten().map(|part| part.len).sum::<u64>();
            self.write_upload_event(UploadEvent::PartsPlanned {
                parts: plan.count(),
                resumed,
                saved_bytes,
                bytes: bytes.len() as u64,
            })?;
            for index in 0..plan.count() {
                if parts[index as usize].is_some() {
                    continue;
                }
                self.write_upload_event(UploadEvent::BeforePart)?;
                let offset = usize::try_from(
                    plan.offset(index)
                        .map_err(|_| SourceError::InvalidResponse)?,
                )
                .map_err(|_| SourceError::InvalidResponse)?;
                let len = usize::try_from(
                    plan.expected_len(index)
                        .map_err(|_| SourceError::InvalidResponse)?,
                )
                .map_err(|_| SourceError::InvalidResponse)?;
                let slice = bytes
                    .get(offset..offset + len)
                    .ok_or(SourceError::InvalidResponse)?;
                let response = self.write_call("UploadPart", true, None, |identity| {
                    self.executor.block_on(
                        self.client
                            .upload_part(ticket, &plan, index, slice, identity),
                    )
                })?;
                let receipt = response
                    .value
                    .receipt
                    .filter(|receipt| !receipt.is_empty() && receipt.len() <= 512)
                    .ok_or(SourceError::InvalidResponse)?;
                let part = StoredPart {
                    index,
                    len: len as u64,
                    receipt,
                    from_disk: false,
                };
                self.write_state()
                    .receipt_store()
                    .put(&metadata, &part)
                    .map_err(SourceError::from)?;
                saved_bytes += part.len;
                parts[index as usize] = Some(part);
                self.write_upload_event(UploadEvent::PartSent {
                    index,
                    parts: plan.count(),
                    saved_bytes,
                    bytes: bytes.len() as u64,
                    resumed,
                })?;
            }
            let from_disk = parts.iter().flatten().any(|part| part.from_disk);
            let receipts = parts
                .into_iter()
                .flatten()
                .map(|part| part.receipt)
                .collect::<Vec<_>>();
            self.write_upload_event(UploadEvent::Completing)?;
            match self.write_call("CompleteUpload", true, None, |identity| {
                self.executor.block_on(self.client.complete_upload(
                    ticket.token.as_deref().unwrap_or_default(),
                    receipts.clone(),
                    identity,
                ))
            }) {
                Ok(_) => {
                    self.write_upload_event(UploadEvent::Finished)?;
                    return Ok(());
                }
                Err(error)
                    if matches!(&error, SourceError::Remote(remote) if remote.code == "invalid_argument" && remote.message == "invalid upload part receipt")
                        && from_disk
                        && invalid_retry == 0 =>
                {
                    self.forget_ticket(ticket)
                }
                Err(error) => return Err(error),
            }
        }
        Err(SourceError::InvalidResponse)
    }

    pub(super) fn write_update_ref(
        &self,
        name: &str,
        expected: RefWriteCondition,
        tip: &Hash,
    ) -> Result<(), SourceError> {
        let result = self
            .write_call("UpdateRef", false, None, |identity| {
                self.executor
                    .block_on(self.client.update_ref(name, expected, *tip, identity))
            })
            .map(|_| ());
        match result {
            Err(error) if remote_is(&error, "failed_precondition") => Err(SourceError::RefConflict),
            other => other,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn write_advance_refs_committing(
        &self,
        head: &str,
        head_condition: RefWriteCondition,
        tip: &Hash,
        packmap: &str,
        packmap_condition: RefWriteCondition,
        node: &Hash,
        keys: &[PackKey],
    ) -> Result<CommitOutcome, SourceError> {
        let selected = keys
            .iter()
            .filter_map(|key| {
                self.write_state()
                    .tickets
                    .borrow()
                    .get(&(head.to_owned(), *key))
                    .cloned()
                    .map(|ticket| (*key, ticket))
            })
            .collect::<Vec<_>>();
        let ids = selected
            .iter()
            .map(|(_, ticket)| ticket.id.clone().unwrap_or_default())
            .collect::<Vec<_>>();
        if ids.len() > 7 || ids.iter().collect::<HashSet<_>>().len() != ids.len() {
            return Err(SourceError::InvalidRef(
                "advance contains more than seven or duplicate upload tickets".into(),
            ));
        }
        if !ids.is_empty()
            && head
                .strip_prefix("refs/heads/")
                .filter(|branch| !branch.is_empty())
                .is_none_or(|branch| packmap != format!("refs/mkit/packmap/{branch}"))
        {
            return Err(SourceError::InvalidRef(
                "ticketed advance requires paired head and packmap refs".into(),
            ));
        }
        let deadline = selected
            .iter()
            .filter_map(|(_, ticket)| ticket.expires_unix_ms)
            .min();
        if deadline.is_some_and(|expiry| expiry <= self.client.now_ms().unwrap_or(i64::MAX)) {
            return Ok(CommitOutcome::TicketRejected);
        }
        let (head_expectation, head_expected_id) = condition(head_condition);
        let (packmap_expectation, packmap_expected_id) = condition(packmap_condition);
        let request = proto::AdvanceRefsRequest {
            head_ref: Some(head.to_owned()),
            head_expectation: Some(head_expectation.into()),
            head_expected_id,
            head_new_id: Some(tip.to_vec()),
            packmap_ref: Some(packmap.to_owned()),
            packmap_expectation: Some(packmap_expectation.into()),
            packmap_expected_id,
            packmap_new_id: Some(node.to_vec()),
            ticket_ids: ids.clone(),
            ..Default::default()
        };
        let advance_deadline = deadline.or_else(|| {
            self.client
                .now_ms()
                .map(|now| now.saturating_add(7 * 24 * 60 * 60 * 1000))
        });
        let result = self.write_call(
            "AdvanceRefs",
            !ids.is_empty(),
            advance_deadline,
            |identity| {
                self.executor
                    .block_on(self.client.advance_refs(&request, identity))
            },
        );
        let response = match result {
            Err(SourceError::Remote(remote))
                if !ids.is_empty() && remote.code == "failed_precondition" =>
            {
                return Ok(
                    if remote.message == "delta base not available in this repository" {
                        CommitOutcome::DeltaBaseUnavailable
                    } else {
                        CommitOutcome::TicketRejected
                    },
                );
            }
            Err(SourceError::Remote(remote))
                if !ids.is_empty()
                    && remote.code == "invalid_argument"
                    && remote.message == "packlist lists a pack that is not in this repository" =>
            {
                return Ok(CommitOutcome::PacklistNotInRepository);
            }
            result => result?.value,
        };
        let outcome = match response.outcome.and_then(|outcome| outcome.as_known()) {
            Some(proto::AdvanceOutcome::Committed) => AdvanceOutcome::Committed,
            Some(proto::AdvanceOutcome::HeadConflict) => AdvanceOutcome::HeadConflict,
            Some(proto::AdvanceOutcome::PackmapConflict) => AdvanceOutcome::PackmapConflict,
            _ => return Err(SourceError::InvalidResponse),
        };
        if outcome == AdvanceOutcome::Committed {
            for (key, ticket) in selected {
                let cache_key = (head.to_owned(), key);
                if self
                    .write_state()
                    .tickets
                    .borrow()
                    .get(&cache_key)
                    .is_some_and(|current| current.id == ticket.id)
                {
                    self.write_state().tickets.borrow_mut().remove(&cache_key);
                    self.forget_ticket(&ticket);
                }
            }
        }
        Ok(CommitOutcome::Advanced(outcome))
    }

    pub(super) fn write_upload_limits(&self) -> UploadLimits {
        let signed = self.client.public_key().is_some();
        match self.write_info() {
            Some(info) if info.spec_version.is_some_and(|version| version >= 2) => UploadLimits {
                max_pack_bytes: info.max_pack_bytes,
                tickets_per_advance: signed.then_some(7),
                ticket_threshold_bytes: signed
                    .then_some(info.begin_upload_threshold_bytes.unwrap_or(0)),
            },
            None if signed && !self.write_state().ticketless.get() => UploadLimits {
                max_pack_bytes: None,
                tickets_per_advance: Some(7),
                ticket_threshold_bytes: Some(0),
            },
            _ => UploadLimits::default(),
        }
    }

    pub(super) fn write_supports_atomic_advance(&self) -> bool {
        self.write_info().is_some_and(|info| {
            info.spec_version.is_some_and(|version| version >= 2)
                && info.atomic_advance == Some(true)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::{Request, Response};
    use mkit_client::{Client, Destination};
    use std::collections::VecDeque;
    use std::time::Duration;

    struct Key;
    impl Signer for Key {
        fn public_key(&self) -> Hash {
            [1; 32]
        }
        async fn sign(&self, _: &Hash) -> Result<[u8; 64], String> {
            Ok([2; 64])
        }
    }
    #[derive(Default)]
    struct Time {
        now: Cell<i64>,
        nonces: Cell<u8>,
    }
    impl Clock for Time {
        fn now_ms(&self) -> i64 {
            self.now.get()
        }
        fn nonce(&self) -> Result<Hash, String> {
            self.nonces.set(self.nonces.get() + 1);
            Ok([self.nonces.get(); 32])
        }
        async fn wait(&self, _: Duration) {
            panic!("host schedules waits")
        }
    }
    struct Channel {
        replies: RefCell<VecDeque<Response<Vec<u8>>>>,
        nonces: RefCell<Vec<String>>,
    }
    impl HttpTransport for Channel {
        async fn send(
            &self,
            request: Request<Vec<u8>>,
            _: usize,
        ) -> Result<Response<Vec<u8>>, String> {
            self.nonces.borrow_mut().push(
                request.headers()["idempotency-key"]
                    .to_str()
                    .unwrap()
                    .into(),
            );
            Ok(self
                .replies
                .borrow_mut()
                .pop_front()
                .expect("unexpected retry"))
        }
    }
    fn error(code: &str) -> Response<Vec<u8>> {
        Response::builder()
            .status(503)
            .body(format!(r#"{{"code":"{code}"}}"#).into_bytes())
            .unwrap()
    }
    fn success() -> Response<Vec<u8>> {
        Response::builder()
            .status(200)
            .header("content-type", "application/proto")
            .body(Vec::new())
            .unwrap()
    }
    struct Recovery<'a> {
        time: &'a Time,
        delay: i64,
        calls: Cell<u32>,
    }
    impl WriteRecovery for Recovery<'_> {
        fn recover(
            &self,
            procedure: &str,
            error: &SourceError,
            attempt: u32,
        ) -> Result<bool, SourceError> {
            assert_eq!(procedure, mkit_client::procedures::UPDATE_REF);
            assert!(matches!(error, SourceError::Remote(remote) if remote.code == "unavailable"));
            assert_eq!(attempt, 1);
            self.calls.set(self.calls.get() + 1);
            self.time.now.set(self.time.now.get() + self.delay);
            Ok(true)
        }
    }
    #[test]
    fn ambiguous_retries_keep_identity_until_expiry() {
        for (delay, renewed) in [(1000, false), (300_000, true)] {
            let time = Time::default();
            let channel = Channel {
                replies: RefCell::new([error("unavailable"), success()].into()),
                nonces: RefCell::new(Vec::new()),
            };
            let client = Client::signed(
                &channel,
                Destination::new("https://vcs.example.org".into(), "default".into()).unwrap(),
                &Key,
                &time,
            );
            let recovery = Recovery {
                time: &time,
                delay,
                calls: Cell::new(0),
            };
            let source = ClientSource::new(&client, &super::super::FuturesExecutor)
                .with_write_recovery(&recovery);
            source
                .write_update_ref("refs/heads/main", RefWriteCondition::Missing, &[3; 32])
                .unwrap();
            let nonces = channel.nonces.borrow();
            assert_eq!(nonces.len(), 2);
            assert_eq!(nonces[0] != nonces[1], renewed);
            assert_eq!(recovery.calls.get(), 1);
        }
    }
    struct Refusal;
    impl WriteRecovery for Refusal {
        fn recover(&self, _: &str, _: &SourceError, _: u32) -> Result<bool, SourceError> {
            Err(SourceError::AdmissionHelperFailed(
                "helper unavailable".into(),
            ))
        }
    }
    #[test]
    fn host_recovery_failure_keeps_its_error_class() {
        let channel = Channel {
            replies: RefCell::new([error("unavailable")].into()),
            nonces: RefCell::new(Vec::new()),
        };
        let time = Time::default();
        let client = Client::signed(
            &channel,
            Destination::new("https://vcs.example.org".into(), "default".into()).unwrap(),
            &Key,
            &time,
        );
        let source = ClientSource::new(&client, &super::super::FuturesExecutor)
            .with_write_recovery(&Refusal);
        assert!(
            matches!(source.write_update_ref("refs/heads/main", RefWriteCondition::Missing, &[3; 32]), Err(SourceError::AdmissionHelperFailed(message)) if message == "helper unavailable")
        );
        assert_eq!(channel.nonces.borrow().len(), 1);
    }
}
