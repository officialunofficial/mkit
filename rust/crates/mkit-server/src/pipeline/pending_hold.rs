//! Optional request-local waiting, outside every guarded write attempt.

use super::{
    Authenticated, HookSet, MultipartBlobStore, NamespaceStore, OpKind, PendingPack, Pipeline,
    ResponseMeta, ServerError, StoredResult, codec, keys, ms,
};
use crate::rt::{Sleep, with_timeout};
use std::{sync::Arc, time::Duration};

const POLL_MS: u64 = 100;
const SAFETY_MS: u64 = 250;

#[derive(Clone)]
pub(super) struct PendingHold {
    duration: Duration,
    sleep: Arc<dyn Sleep>,
    request_deadline_ms: u64,
}

impl<B: MultipartBlobStore, N: NamespaceStore, H: HookSet> Pipeline<B, N, H> {
    /// Wait briefly for scheduled ticket verification before retrying the full write path.
    /// The hold defaults off and is capped at two seconds. The host supplies its
    /// absolute request deadline on the injected clock; waiting leaves a 250 ms
    /// margin before that deadline and the signed envelope expiry. No request
    /// allowance is extended. A zero duration disables the hold.
    #[must_use]
    pub fn with_pending_advance_hold(
        mut self,
        duration: Duration,
        sleep: Arc<dyn Sleep>,
        request_deadline_ms: u64,
    ) -> Self {
        self.pending_hold = (!duration.is_zero()).then_some(PendingHold {
            duration: duration.min(Duration::from_secs(2)),
            sleep,
            request_deadline_ms,
        });
        self
    }

    pub(super) async fn write_with_pending_hold(
        &self,
        a: &Authenticated,
        kind: OpKind,
        implicit: Option<&[PendingPack]>,
    ) -> Result<(StoredResult, ResponseMeta), ServerError> {
        // The entire attempt returns before waiting: no snapshot, admission
        // reservation, lease grant, or write gate survives this boundary.
        let result = self.write_inner(a, kind.clone(), implicit, None).await;
        let (Some(hold), Err(error), Some(auth)) = (&self.pending_hold, &result, &a.auth) else {
            return result;
        };
        let OpKind::AdvanceRefs { head, tickets, .. } = &kind else {
            return result;
        };
        if tickets.is_empty()
            || !self.cfg.indexed.is_some_and(|config| {
                config.verification == crate::indexed::VerificationMode::Scheduled
            })
            || !error
                .details()
                .iter()
                .any(|detail| detail.type_name == "mkit.transport.v1.PendingVerification")
        {
            return result;
        }
        let now = ms(self.clock.now_ms());
        let expiry = ms(auth.expires_at_ms.saturating_sub(a.business_skew_ms));
        let allowance = hold
            .request_deadline_ms
            .min(expiry)
            .saturating_sub(SAFETY_MS);
        let duration = hold
            .duration
            .min(Duration::from_millis(allowance.saturating_sub(now)));
        if duration < Duration::from_millis(POLL_MS) {
            return result;
        }
        let hold_deadline_ms = now
            .saturating_add(u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
            .min(allowance);
        let repo = &a.repo().repo;
        let partition = self.shards.ref_shard(repo, &head.name);
        let ready = with_timeout(hold.sleep.as_ref(), duration, async {
            let ticket_keys: Vec<_> = tickets.iter().map(keys::ticket).collect();
            let rows = self.meta.get_many(&partition, &ticket_keys).await.ok()?;
            if rows.len() != tickets.len() {
                return None;
            }
            let jobs = rows
                .iter()
                .map(|row| {
                    let ticket = codec::decode_ticket(row.as_ref()?).ok()?;
                    Some(keys::verify_job(&repo.name, &ticket.pack_id))
                })
                .collect::<Option<Vec<_>>>()?;
            drop(rows);
            // One batched KV read per poll, regardless of ticket count. Never
            // trust these observations for admission or commit: only wake up.
            for _ in 0..19 {
                hold.sleep.sleep(Duration::from_millis(POLL_MS)).await;
                if ms(self.clock.now_ms()) >= hold_deadline_ms {
                    return None;
                }
                let rows = self.meta.get_many(&partition, &jobs).await.ok()?;
                if rows.len() != jobs.len() {
                    return None;
                }
                let jobs = rows
                    .iter()
                    .map(|row| crate::indexed::checkpoint::decode_job(row.as_ref()?).ok())
                    .collect::<Option<Vec<_>>>()?;
                if jobs
                    .iter()
                    .all(crate::indexed::checkpoint::VerifyJobV1::usable)
                {
                    return Some(());
                }
                if jobs.iter().any(|job| job.outcome.is_some() || job.gone) {
                    return None;
                }
            }
            hold.sleep.sleep(Duration::from_millis(POLL_MS)).await;
            None
        })
        .await;
        if matches!(ready, Ok(Some(()))) && ms(self.clock.now_ms()) < hold_deadline_ms {
            // Fresh authorization, tickets, admission, denial, CAS and final
            // guards, including the durable replay lookup for a lost reply.
            let mut fresh = a.clone();
            fresh.business_now_ms = self.clock.now_ms().saturating_add(a.business_skew_ms);
            self.write_inner(&fresh, kind, implicit, None).await
        } else {
            // Preserve the original pending bytes and typed millisecond hint.
            result
        }
    }
}
