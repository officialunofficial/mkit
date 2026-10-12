use super::*;

#[test]
fn continuation_joined_closing_security_absence_precedes_corrupt_anchor() {
    for denial in [false, true] {
        for writer in [false, true] {
            for missing in [false, true] {
                let (mut fx, _, _, _) = history(3, 1, 2, denial);
                enable(&mut fx);
                let token = first(&fx, writer, 1);
                let repo = fx.repo_id("room");
                let coordinator = fx.pipe.shards.coordinator(&repo.namespace);
                let shard = fx.pipe.shards.ref_shard(&repo, HEAD);
                let publication = keys::publication(&repo.name, HEAD);
                let record = keys::repo_record(&repo.name);
                let epoch = keys::grant_epoch();
                let security_reads = Arc::new(AtomicU32::new(0));
                let anchors = Arc::new(AtomicU32::new(0));
                let security_seen = security_reads.clone();
                let anchor_seen = anchors.clone();
                Arc::get_mut(&mut fx.pipe.meta).unwrap().read_many_hook =
                    Some(Box::new(move |store, _, wanted| {
                        if wanted.contains(&record)
                            && wanted.contains(&keys::repo_visibility_revision(&repo.name))
                            && security_seen.fetch_add(1, Ordering::SeqCst) == 1
                        {
                            // Closing security is either absent or changed;
                            // either must outrank the later corrupt anchor.
                            let batch = if missing {
                                Batch::new().delete(record.clone())
                            } else {
                                Batch::new().put(epoch.clone(), codec::encode_u64(17))
                            };
                            now(store.apply(&coordinator, batch)).unwrap();
                            now(store.apply(
                                &shard,
                                Batch::new().put(publication.clone(), Value::new(b"bad".to_vec())),
                            ))
                            .unwrap();
                        }
                        if wanted.contains(&publication) {
                            anchor_seen.fetch_add(1, Ordering::SeqCst);
                        }
                    }));
                in_view(&fx, writer, |reader| {
                    assert!(
                        block_on(reader.walk_history_page_in(
                            &mut ReaderSession::default(),
                            HEAD,
                            Some(token.token.expose()),
                            1,
                        ))
                        .unwrap()
                        .is_none()
                    );
                });
                assert_eq!(security_reads.load(Ordering::SeqCst), 2);
                assert_eq!(anchors.load(Ordering::SeqCst), 2);
            }
        }
    }
}

#[test]
fn continuation_joined_prologue_anchor_absence_precedes_corrupt_security() {
    for denial in [false, true] {
        for writer in [false, true] {
            let (mut fx, _, _, _) = history(3, 1, 2, denial);
            enable(&mut fx);
            let token = first(&fx, writer, 1);
            let repo = fx.repo_id("room");
            let shard = fx.pipe.shards.ref_shard(&repo, HEAD);
            let coordinator = fx.pipe.shards.coordinator(&repo.namespace);
            let publication = keys::publication(&repo.name, HEAD);
            let record = keys::repo_record(&repo.name);
            Arc::get_mut(&mut fx.pipe.meta).unwrap().read_many_hook =
                Some(Box::new(move |store, _, wanted| {
                    if wanted.contains(&publication) {
                        now(store.apply(&shard, Batch::new().delete(publication.clone()))).unwrap();
                        now(store.apply(
                            &coordinator,
                            Batch::new().put(record.clone(), Value::new(b"bad".to_vec())),
                        ))
                        .unwrap();
                    }
                }));
            in_view(&fx, writer, |reader| {
                assert!(
                    block_on(reader.walk_history_page_in(
                        &mut ReaderSession::default(),
                        HEAD,
                        Some(token.token.expose()),
                        1,
                    ))
                    .unwrap()
                    .is_none()
                );
            });
        }
    }
}
