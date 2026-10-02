//! HTTP admission and conditional paid-read outcomes (R-177).
use super::{HookSet, Pipeline, meta_error, ms};
use crate::http_objects::{
    AdmitRequest, Admitted, HttpBody, HttpObjectResponse, HttpSeams, ReadFinalizer,
};
use crate::pipeline::AdmissionInput;
use crate::rt::{Clock, Sleep};
use crate::store::codec::{self, AbortReason, ReservationV1};
use crate::store::outbox::{OutboxBuilder, Terminal};
use crate::store::{
    Batch, BatchOutcome, MultipartBlobStore, NamespaceStore, Partition, Precondition, Value, keys,
};
use crate::{Operation, ServerError};

pub(super) fn challenge_response(error: &ServerError, head: bool) -> HttpObjectResponse {
    let mut response =
        HttpObjectResponse::error(402).with_header("Content-Type", "application/json");
    for (name, value) in error.headers() {
        let name = if name.eq_ignore_ascii_case("WWW-Authenticate") {
            "WWW-Authenticate"
        } else if name.eq_ignore_ascii_case("PAYMENT-REQUIRED") {
            "PAYMENT-REQUIRED"
        } else {
            continue;
        };
        response.headers.push((name, value.clone()));
    }
    if let Some(detail) = error.details().first() {
        response = response.with_header("Content-Length", detail.value.len().to_string());
        if !head {
            response.body = HttpBody::Bytes(detail.value.clone());
        }
    }
    response
}

impl<B: MultipartBlobStore, N: NamespaceStore + Clone + 'static, H: HookSet> Pipeline<B, N, H> {
    pub(super) async fn admit_http_read(
        &self,
        seams: &HttpSeams,
        op: &Operation,
        request: &AdmitRequest<'_>,
        object: [u8; 32],
    ) -> Result<(Admitted, Option<ReadFinalizer>), ServerError> {
        let runtime = seams
            .read_runtime
            .as_ref()
            .ok_or_else(|| ServerError::unavailable("HTTP read runtime unavailable"))?;
        let partition = self.shards.coordinator(&op.repo.namespace);
        self.check_outbox_backpressure(&partition, None).await?;
        let mut input = AdmissionInput::new(op);
        input.declared_bytes = request.declared_bytes;
        input.creates_namespace = false;
        input.creates_repo = false;
        input.new_to_repo_bytes = Some(0);
        input.credential_headers = request.credential_headers;
        let allowance = self.admit_http(input).await?;
        // QuotaCharge is the internal signed-write quota contract. HTTP
        // reads have no signer or write scope; never silently ignore charges.
        if !allowance.charges.is_empty() {
            return Err(ServerError::unavailable("invalid HTTP admission decision"));
        }
        let mut admitted = Admitted {
            private: true,
            ..Admitted::default()
        };
        for (name, value) in allowance.response_headers {
            let name = if name.eq_ignore_ascii_case("Payment-Receipt") {
                "Payment-Receipt"
            } else {
                "PAYMENT-RESPONSE"
            };
            admitted.headers.push((name, value));
        }
        let Some(rid) = allowance.reservation else {
            return Ok((admitted, None));
        };
        let cfg = self
            .cfg
            .http_objects
            .as_ref()
            .ok_or_else(|| ServerError::unavailable("HTTP objects unavailable"))?;
        let repository = format!("{}/{}", op.repo.namespace.as_str(), op.repo.name.as_str());
        let created = ms(self.clock.now_ms());
        let deadline = created
            .saturating_add(u64::try_from(cfg.read_deadline.as_millis()).unwrap_or(u64::MAX));
        let pending = super::reservation::read_pending(
            repository.clone(),
            created,
            deadline,
            cfg.read_reconcile_grace,
        );
        let prior = codec::encode_reservation(&pending);
        let mut builder = OutboxBuilder::new(None, None).map_err(meta_error)?;
        builder.pending(&rid, None, &pending);
        let mut batch = Batch::new().require(Precondition::NotAfter(deadline));
        builder
            .try_finish(&mut batch.preconditions, &mut batch.writes)
            .map_err(meta_error)?;
        match self.apply_meta(&partition, batch).await? {
            BatchOutcome::Committed => {}
            _ => return Err(ServerError::unavailable("read reservation unavailable")),
        }
        let store = self.meta.clone();
        let clock = self.clock.clone();
        let sleep = runtime.sleep.clone();
        let finalizer = ReadFinalizer {
            deadline_ms: deadline,
            clock: clock.clone(),
            runtime: runtime.clone(),
            sent: 0,
            finish: Some(Box::new(move |bytes, success| {
                let occurred_at_ms = ms(clock.now_ms());
                Box::pin(async move {
                    let record = read_result(repository, object, bytes, success, occurred_at_ms);
                    settle(
                        &store,
                        &partition,
                        &rid,
                        &prior,
                        record,
                        clock.as_ref(),
                        sleep.as_ref(),
                    )
                    .await;
                })
            })),
        };
        Ok((admitted, Some(finalizer)))
    }
}

fn read_result(
    repository: String,
    object: [u8; 32],
    bytes: u64,
    success: bool,
    occurred_at_ms: u64,
) -> ReservationV1 {
    if success || bytes > 0 {
        ReservationV1::ReadServed {
            repository,
            occurred_at_ms,
            object,
            bytes_served: bytes,
        }
    } else {
        ReservationV1::Aborted {
            repository,
            occurred_at_ms,
            reason: AbortReason::Internal,
            detail: String::new(),
        }
    }
}

/// Retry I/O and arbiter contention within grace, preserving actual bytes.
async fn settle<N: NamespaceStore>(
    store: &N,
    partition: &Partition,
    rid: &str,
    prior: &Value,
    record: ReservationV1,
    clock: &dyn Clock,
    sleep: &dyn Sleep,
) {
    let Ok(ReservationV1::Pending {
        reconcile_at_ms: limit,
        ..
    }) = codec::decode_reservation(prior)
    else {
        return;
    };
    loop {
        let remaining = core::time::Duration::from_millis(limit.saturating_sub(ms(clock.now_ms())));
        match crate::rt::with_timeout(
            sleep,
            remaining,
            try_settle(store, partition, rid, prior, &record),
        )
        .await
        {
            Ok(Ok(true)) | Err(_) => return, // Reconciliation retains the durable obligation.
            Ok(Ok(false)) => {}
            Ok(Err(_)) => tracing::warn!("read settlement unavailable; retrying within grace"),
        }
        if ms(clock.now_ms()) >= limit {
            return;
        }
        sleep.sleep(core::time::Duration::from_millis(10)).await;
    }
}

async fn try_settle<N: NamespaceStore>(
    store: &N,
    partition: &Partition,
    rid: &str,
    prior: &Value,
    record: &ReservationV1,
) -> Result<bool, crate::store::StoreError> {
    let values = store
        .get_many(
            partition,
            &[
                keys::outbox_sequence(),
                keys::outcome_backlog(),
                keys::reservation(rid)?,
            ],
        )
        .await?;
    if values.get(2).and_then(Option::as_ref) != Some(prior) {
        return Ok(true);
    }
    let mut builder = OutboxBuilder::new(
        values.first().and_then(Option::as_ref),
        values.get(1).and_then(Option::as_ref),
    )?;
    builder.outcome(rid, prior, Terminal::new(record.clone())?);
    let mut batch = Batch::new();
    builder.try_finish(&mut batch.preconditions, &mut batch.writes)?;
    Ok(matches!(
        store.apply(partition, batch).await?,
        BatchOutcome::Committed
    ))
}
