//! Both Worker classes that hold tickets register and fire kind 2.

use mkit_server::store::adapter_spi::{codec, keys, tickets};
use mkit_server::timers::{TickBudget, registry::kinds, run_due};
use mkit_server::{
    Batch, BatchOutcome, ManualClock, MemoryBlobStore, MemoryKv, NamespaceKey, NamespaceStore,
    Partition, RepoName, Value,
};
use mkit_server_worker::adapter::{ConfigError, timer_registry_with_blobs};
use mkit_server_worker::classes::ShardClass;

#[tokio::test]
async fn single_and_ref_shard_expiry_timers_fire() {
    for class in [ShardClass::RefStore, ShardClass::RefShard] {
        let repo = RepoName::new("repo").unwrap();
        let ref_name = "refs/heads/main".to_owned();
        let partition = match class {
            ShardClass::RefStore => Partition::Namespace(NamespaceKey::deployment_default()),
            ShardClass::RefShard => Partition::Ref {
                ns: NamespaceKey::deployment_default(),
                repo: repo.clone(),
                shard_ref: ref_name.clone(),
            },
            _ => unreachable!(),
        };
        let rid = "s:1111111111111111111111111111111111111111111111111111111111111111";
        let id = tickets::ticket_id(rid);
        let ticket = codec::TicketV1 {
            authority_generation: None,
            repo: repo.clone(),
            ref_name: ref_name.clone(),
            signer: [1; 32],
            pack_id: [2; 32],
            bytes: 8 * 1024 * 1024 + 1,
            part_size: 8 * 1024 * 1024,
            expires_at_ms: 100,
            created_at_ms: 1,
            reservation_id: rid.into(),
            upload_session: None,
        };
        let store = MemoryKv::default();
        let batch = Batch::new()
            .put(keys::ticket(&id), codec::encode_ticket(&ticket))
            .put(
                keys::reservation(rid).unwrap(),
                codec::encode_reservation(&codec::ReservationV1::Ticketed { ticket_id: id }),
            )
            .put(
                keys::ticket_index(&repo, &ref_name, &ticket.pack_id, &ticket.signer).unwrap(),
                codec::encode_ref_id(&id),
            )
            .put(
                keys::tickets_per_ref(&repo, &ref_name).unwrap(),
                codec::encode_u64(1),
            )
            .put(
                keys::tickets_per_signer(&repo, &ref_name, &ticket.signer).unwrap(),
                codec::encode_u64(1),
            )
            .put(
                keys::timer(100, kinds::TICKET_EXPIRY.get(), &id),
                Value::default(),
            );
        assert_eq!(
            store.apply(&partition, batch).await.unwrap(),
            BatchOutcome::Committed
        );
        let registry = timer_registry_with_blobs(
            class,
            Ok::<_, ConfigError>(MemoryKv::default()),
            Some("free"),
            MemoryBlobStore::default(),
        );
        let report = run_due(
            &store,
            &partition,
            &registry,
            &ManualClock::new(100),
            100,
            &TickBudget::default(),
        )
        .await
        .unwrap();
        assert_eq!(report.fired, 1, "{class:?}");
        let outcome = store
            .get(&partition, &keys::reservation(rid).unwrap())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            codec::decode_reservation(&outcome),
            Ok(codec::ReservationV1::Expired { .. })
        ));
    }
}

/// Kinds 8 and 9 are registered wherever `o`/`oq` rows can live, so neither
/// is re-armed as an unknown kind: a terminal row is delivered and acked, and
/// an abandoned pending row is aborted, delivered and acked.
#[tokio::test]
async fn outcome_delivery_and_reconcile_fire_on_every_outcome_class() {
    use mkit_server::store::adapter_spi::codec::{AbortReason, PendingOp, ReservationV1};
    use mkit_server::store::adapter_spi::outbox::{OutboxBuilder, Terminal};
    for class in [
        ShardClass::RefStore,
        ShardClass::RefShard,
        ShardClass::NsCoordinator,
    ] {
        let partition = Partition::Namespace(NamespaceKey::deployment_default());
        let store = MemoryKv::default();
        let mut builder = OutboxBuilder::new(None, None).unwrap();
        builder.abort_direct(
            "done-rid",
            Terminal::new(ReservationV1::aborted(
                "repo".into(),
                100,
                AbortReason::Unspecified,
                String::new(),
                mkit_server::store::StoredProcedure::UpdateRef,
            ))
            .unwrap(),
        );
        builder.pending(
            "stale-rid",
            None,
            &ReservationV1::pending(
                "repo".into(),
                1,
                100,
                PendingOp::Write,
                mkit_server::store::StoredProcedure::UpdateRef,
            ),
        );
        let mut batch = Batch::new();
        builder
            .try_finish(&mut batch.preconditions, &mut batch.writes)
            .unwrap();
        assert_eq!(
            store.apply(&partition, batch).await.unwrap(),
            BatchOutcome::Committed
        );
        let registry = mkit_server_worker::adapter::with_outcome_timers(
            timer_registry_with_blobs(
                class,
                Ok::<_, ConfigError>(MemoryKv::default()),
                Some("free"),
                MemoryBlobStore::default(),
            ),
            class,
            Ok("https://server.example".to_owned()),
            Some("free"),
            mkit_server::pipeline::NoOutcomes,
            std::sync::Arc::new(mkit_server::ManualSleep::new()),
            std::sync::Arc::new(ManualClock::new(200)),
        );
        let mut fired = 0;
        for _ in 0..4 {
            fired += run_due(
                &store,
                &partition,
                &registry,
                &ManualClock::new(200),
                200,
                &TickBudget::default(),
            )
            .await
            .unwrap()
            .fired;
        }
        assert!(fired >= 3, "{class:?}: {fired}");
        for rid in ["done-rid", "stale-rid"] {
            assert!(
                store
                    .get(&partition, &keys::reservation(rid).unwrap())
                    .await
                    .unwrap()
                    .is_none(),
                "{class:?} {rid} was not delivered and acknowledged"
            );
        }
        assert!(
            store
                .get(&partition, &keys::outcome_backlog())
                .await
                .unwrap()
                .is_none()
        );
    }
}
