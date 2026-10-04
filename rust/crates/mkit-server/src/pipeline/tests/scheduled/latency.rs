//! Manual-clock timelines: delivery wakes, crash recovery, and persisted hints.
use super::*;
use crate::BoxFuture;
use crate::indexed::checkpoint::{Phase, decode_job, timer_reference};
use crate::timers::{DueTimer, TimerCtx, TimerHandler, registry::kinds};
use bytes::Bytes;

struct ObservedRelay<'a>(&'a Env);
impl<S: NamespaceStore> TimerHandler<S> for ObservedRelay<'_> {
    fn kind(&self) -> crate::timers::TimerKind {
        kinds::RELAY
    }
    fn fire<'a>(
        &'a self,
        ctx: &'a TimerCtx<'a, S>,
        timer: &'a DueTimer,
    ) -> BoxFuture<'a, Result<crate::timers::Fired, crate::StoreError>> {
        Box::pin(async move {
            RelayHandler {
                target: Ref(&self.0.pipe.meta),
                hook: NoHook,
                budget: RelayBudget::default(),
            }
            .deliver_with_metrics(ctx, timer, self.0.metrics.as_ref())
            .await
        })
    }
}

fn verifier(
    env: &Env,
) -> VerifyTimer<Ref<'_, Spy>, Ref<'_, MemoryBlobStore>, BlobWindows<'_, MemoryBlobStore>> {
    VerifyTimer {
        remote: Ref(&env.pipe.meta),
        blobs: Ref(&env.pipe.blobs),
        windows: BlobWindows(&env.pipe.blobs),
        shards: env.pipe.shards.clone(),
        cfg: env.pipe.cfg.indexed.unwrap(),
        limits: SliceLimits::default(),
        lease: LeaseParams::from(&env.pipe.cfg),
        clock: env.clock.clone(),
        metrics: env.metrics.clone(),
        extension: FailClosedExtraction,
    }
}

fn assert_hint(error: &ServerError, seconds: u64) {
    assert_eq!(error.public_message(), "pack verification pending");
    assert!(
        error
            .headers()
            .contains(&("Retry-After".into(), seconds.to_string()))
    );
    let bytes = &error.details()[0].value;
    assert_eq!(bytes[0], 0x08);
    let ms = bytes[1..]
        .iter()
        .enumerate()
        .fold(0_u64, |v, (i, b)| v | (u64::from(b & 0x7f) << (7 * i)));
    assert_eq!(ms, seconds * 1_000);
}

#[test]
fn relay_delivery_resumes_promptly_and_a_lost_nudge_recovers_by_poll() {
    for missed in [false, true] {
        let events = Events::default();
        let _subscriber = tracing::subscriber::set_default(events.clone());
        let (env, owner, identity) = environment_with(Sharding::D34, scheduled());
        let (bytes, head) = pack();
        let pack_id = hash(&bytes);
        let ticket = begin_and_upload(&env, &owner, &identity, &bytes, 900);
        let request = signed(&owner, &identity, Procedure::AdvanceRefs, 901);
        let repo = env.auth(&request).unwrap().repo().repo.clone();
        let source = env.pipe.shards.ref_shard(&repo, HEAD);
        let attempt = || advance(&env, &owner, &identity, 901, head, pack_id, vec![ticket]);
        assert_hint(&attempt().unwrap_err(), 1);
        let job = || {
            decode_job(
                &block_on(
                    env.pipe
                        .meta
                        .get(&source, &keys::verify_job(&repo.name, &pack_id)),
                )
                .unwrap()
                .unwrap(),
            )
            .unwrap()
        };
        let registry = TimerRegistry::new().register(verifier(&env));
        let tick = |registry: &TimerRegistry<'_, Spy>| {
            block_on(run_due(
                &env.pipe.meta,
                &source,
                registry,
                env.clock.as_ref(),
                ms(env.clock.now_ms()),
                &TickBudget::default(),
            ))
            .unwrap()
        };
        tick(&registry);
        assert_eq!(job().phase, Phase::ClosureResolve);
        env.clock.advance(1);
        tick(&registry);
        assert_eq!(job().phase, Phase::AwaitDelivery);
        assert!(!job().usable());
        assert_hint(&attempt().unwrap_err(), 2);
        let poll_at = ms(env.clock.now_ms()) + 2_000;
        // Deliver exactly the existing relay work, simulating a crash before
        // committing its returned nudge batch in the recovery case.
        let relay_registry = TimerRegistry::new().register(ObservedRelay(&env));
        if missed {
            let timer = DueTimer {
                due_at_ms: ms(env.clock.now_ms()),
                kind: kinds::RELAY,
                reference: Bytes::new(),
                value: Value::default(),
            };
            let ctx = TimerCtx {
                store: &env.pipe.meta,
                partition: &source,
                now_ms: ms(env.clock.now_ms()),
            };
            let _lost_batch = block_on(ObservedRelay(&env).fire(&ctx, &timer)).unwrap();
        } else {
            tick(&relay_registry);
        }
        assert!(
            block_on(crate::relay::relay_delivered_through(
                &env.pipe.meta,
                &source,
                job().last_relay_seq.unwrap()
            ))
            .unwrap()
        );
        assert!(!job().usable(), "delivery alone cannot verify the pack");
        assert_hint(&attempt().unwrap_err(), if missed { 2 } else { 1 });
        tick(&registry);
        if missed {
            assert_eq!(job().phase, Phase::AwaitDelivery);
            env.clock.advance(2_000);
            tick(&registry);
        }
        assert_eq!(job().phase, Phase::Extract);
        env.clock.advance(1);
        tick(&registry);
        assert!(job().usable());
        if !missed {
            assert!(ms(env.clock.now_ms()) < poll_at);
        }
        assert_eq!(attempt().unwrap(), AdvanceOutcome::Committed);
        assert_eq!(
            attempt().unwrap(),
            AdvanceOutcome::Committed,
            "same nonce remains idempotent"
        );
        assert_timeline(&env, &events, ticket, pack_id);
    }
}

fn assert_timeline(env: &Env, events: &Events, ticket: Hash, pack_id: Hash) {
    let logs = events.0.lock().unwrap();
    let ticket_hex = mkit_core::hash::to_hex(&ticket);
    let pack_hex = mkit_core::hash::to_hex(&pack_id);
    for stage in [
        "upload_durable",
        "advance_received",
        "job_created",
        "verify_fire",
        "verify_checkpoint",
        "verification_usable",
        "final_cas",
    ] {
        assert!(
            logs.iter()
                .any(|event| event.get("stage").is_some_and(|s| s == stage)
                    && if stage == "verify_fire" {
                        event.get("pack") == Some(&pack_hex)
                    } else {
                        event.get("ticket") == Some(&ticket_hex)
                    }
                    && event
                        .get("now_ms")
                        .is_some_and(|time| time.parse::<u64>().is_ok())),
            "missing correlated {stage}: {logs:?}"
        );
    }
    assert!(logs.iter().any(|event| {
        event
            .get("event")
            .is_some_and(|s| s == "verification_checkpoint")
            && event.get("pack") == Some(&pack_hex)
            && event.get("old_phase").is_some_and(|s| s == "AwaitDelivery")
            && event.get("new_phase").is_some_and(|s| s == "Extract")
    }));
    assert!(logs.iter().any(|event| {
        event
            .get("event")
            .is_some_and(|s| s == "verification_timer_result")
            && event.get("attempt") == Some(&"0".to_owned())
            && event.get("outcome") == Some(&"committed".to_owned())
    }));
    let entry = logs
        .iter()
        .position(|event| {
            event
                .get("event")
                .is_some_and(|s| s == "verification_timer_entry")
        })
        .unwrap();
    let loaded = logs
        .iter()
        .position(|event| {
            event
                .get("event")
                .is_some_and(|s| s == "verification_slice_start")
        })
        .unwrap();
    assert!(entry < loaded, "fire entry precedes the job read");
    let metrics = env.metrics.0.lock().unwrap();
    let stages: Vec<_> = metrics
        .iter()
        .filter(|(name, _)| *name == crate::telemetry::METRIC_VERIFICATION_PROGRESS)
        .filter_map(|(_, labels)| {
            labels
                .iter()
                .find(|(key, _)| key == "stage")
                .map(|(_, stage)| stage.as_str())
        })
        .collect();
    let wanted = [
        "upload_durable",
        "advance_received",
        "job_created",
        "verify_fire",
        "verify_checkpoint",
        "relay_delivered",
        "verification_usable",
        "final_cas",
    ];
    let mut pos = 0;
    for stage in wanted {
        pos += stages[pos..]
            .iter()
            .position(|got| *got == stage)
            .unwrap_or_else(|| panic!("missing {stage}: {stages:?}"))
            + 1;
    }
}

#[test]
fn retry_hints_follow_decode_delivery_and_failure_timers_and_missing_jobs() {
    let (env, owner, identity) = environment_with(Sharding::D34, scheduled());
    let (bytes, head) = pack();
    let pack_id = hash(&bytes);
    let ticket = begin_and_upload(&env, &owner, &identity, &bytes, 910);
    let request = signed(&owner, &identity, Procedure::AdvanceRefs, 911);
    let repo = env.auth(&request).unwrap().repo().repo.clone();
    let source = env.pipe.shards.ref_shard(&repo, HEAD);
    let attempt = || advance(&env, &owner, &identity, 911, head, pack_id, vec![ticket]);
    assert_hint(&attempt().unwrap_err(), 1); // Missing job is created due now.
    let reference = timer_reference(&repo.name, &pack_id);
    let now = ms(env.clock.now_ms());
    let mut old = keys::timer(now, kinds::VERIFY.get(), &reference);
    for (delay, expected) in [(1_001, 2), (15_001, 16), (90_000, 60), (0, 1)] {
        let next = keys::timer_retry(now + delay, kinds::VERIFY.get(), &reference, now, 1);
        block_on(env.pipe.meta.apply(
            &source,
            Batch::new().delete(old).put(next.clone(), Value::default()),
        ))
        .unwrap();
        assert_hint(&attempt().unwrap_err(), expected);
        old = next;
    }
    block_on(env.pipe.meta.apply(&source, Batch::new().delete(old))).unwrap();
    assert_hint(&attempt().unwrap_err(), 1); // Missing timer has no known wake.
}

type EventFields = std::collections::BTreeMap<String, String>;
#[derive(Clone, Default)]
struct Events(Arc<Mutex<Vec<EventFields>>>);
impl tracing::Subscriber for Events {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        struct Fields(EventFields);
        impl tracing::field::Visit for Fields {
            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                self.0.insert(field.name().to_owned(), value.to_owned());
            }
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                self.0.insert(field.name().to_owned(), format!("{value:?}"));
            }
        }
        let mut fields = Fields(EventFields::new());
        event.record(&mut fields);
        self.0.lock().unwrap().push(fields.0);
    }
}
