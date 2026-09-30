//! Private scanner bytes are bound to live upload tickets on either placement.
use super::*;
use crate::hooks::InspectVerdict;
use crate::pipeline::inspection::ContentInspector;
use crate::scanner_retrieval::{Assignment, PackGrant, RetrievalConfig, RetrievalResponse};
use crate::store::{BlobBody, BlobMeta, ByteRange, MultipartBlobStore, UnsupportedPartSink};
use crate::store::{BorrowedStore, ContentIndex};
use core::time::Duration;
use mkit_core::object::ChunkedBlob;
use mkit_core::write_auth::Headers;
use mkit_rpc::hooks::{InspectObject, InspectRetrieval};

fn scanner_config() -> Arc<RetrievalConfig> {
    Arc::new(
        RetrievalConfig::parse(
            &format!("active scanner-mac {}", to_hex(&[42; 32])),
            &to_hex(key(41).verifying_key().as_bytes()),
        )
        .unwrap(),
    )
}

fn signed_fetch(body: &[u8], identity: &str, signer: &SigningKey, now: i64) -> Headers {
    let digest = to_hex(&hash(body));
    let commitment = format!("body:{digest}");
    let envelope = SignedOp {
        context: AuthContext {
            audience: AUDIENCE,
            repository: identity,
        },
        procedure: crate::scanner_retrieval::PATH,
        commitment: &commitment,
        created_at: now,
        expires_at: now + 300_000,
        nonce: &"c1".repeat(32),
    };
    Headers {
        version: Some("2".into()),
        audience: Some(AUDIENCE.into()),
        repository: Some(identity.into()),
        public_key: Some(to_hex(signer.verifying_key().as_bytes())),
        signature: Some(to_hex_bytes(
            &signer.sign(&envelope.digest().unwrap()).to_bytes(),
        )),
        digest: Some(digest),
        commitment: Some(commitment),
        created_at: Some(now.to_string()),
        expires_at: Some((now + 300_000).to_string()),
        idempotency_key: Some("c1".repeat(32)),
    }
}

fn assignment(
    env: &Env,
    owner: &SigningKey,
    identity: &str,
    packs: &[(&[u8], Vec<Hash>)],
) -> Assignment {
    // Minting follows verification; reproduce immutable denial facts from
    // actual decoded objects for tests that mint capabilities directly.
    let temp = tempfile::tempdir().unwrap();
    let store =
        mkit_core::store::ObjectStore::init(&mkit_core::layout::RepoLayout::single(temp.path()))
            .unwrap();
    for (bytes, _) in packs {
        let decoded = mkit_core::pack::PackReader::read(bytes, &store).unwrap();
        for id in decoded.stored {
            let object = mkit_core::serialize::deserialize(&store.read(&id).unwrap()).unwrap();
            block_on(crate::takedown::inventory::stage(
                &env.pipe.meta,
                &hash(bytes),
                bytes.len() as u64,
                &id,
                &object,
                None,
                T0 as u64,
            ))
            .unwrap();
        }
        block_on(crate::takedown::inventory::complete(
            &env.pipe.meta,
            &hash(bytes),
            bytes.len() as u64,
            T0 as u64,
        ))
        .unwrap();
    }
    let auth = env
        .auth(&signed(owner, identity, Procedure::AdvanceRefs, 193_000))
        .unwrap();
    Assignment {
        namespace: auth.repo().repo.namespace.as_str().into(),
        repo_name: auth.repo().repo.name.as_str().into(),
        repository: identity.into(),
        ref_name: HEAD.into(),
        signer: owner.verifying_key().to_bytes(),
        packs: packs
            .iter()
            .map(|(bytes, tickets)| PackGrant {
                id: hash(bytes),
                length: bytes.len() as u64,
                tickets: tickets.clone(),
            })
            .collect(),
    }
}

fn mint(env: &Env, assignment: &Assignment, timeout: Duration) -> String {
    env.pipe
        .cfg
        .scanner_retrieval
        .as_ref()
        .unwrap()
        .mint(
            AUDIENCE,
            "inspection-stable",
            assignment,
            timeout,
            T0 as u64,
        )
        .unwrap()
        .capability
        .unwrap()
}

fn body(token: &str, pack: &Hash, range: Option<(u64, u64)>) -> Vec<u8> {
    let mut json = serde_json::json!({"capability": token, "pack_id": to_hex(pack)});
    if let Some((start, end)) = range {
        json["start"] = start.into();
        json["end_inclusive"] = end.into();
    }
    serde_json::to_vec(&json).unwrap()
}

fn fetch(
    env: &Env,
    identity: &str,
    token: &str,
    pack: &Hash,
    range: Option<(u64, u64)>,
) -> Result<RetrievalResponse, ServerError> {
    let body = body(token, pack, range);
    block_on(env.pipe.retrieve_scanner_pack(
        &body,
        &signed_fetch(&body, identity, &key(41), env.clock.now_ms()),
    ))
}

fn not_found(result: Result<RetrievalResponse, ServerError>) {
    let error = result.expect_err("private failures must not serve bytes");
    assert_eq!(error.code(), Code::NotFound);
    assert_eq!(error.public_message(), "pack not found");
}

#[test]
fn raw_pack_and_bounded_ranges_round_trip_on_single_and_d34() {
    for sharding in [Sharding::Single, Sharding::D34] {
        let (mut env, owner, identity) = environment_with_sharding(sharding);
        env.pipe.cfg.scanner_retrieval = Some(scanner_config());
        let (first, second, _) = split_pack();
        let one = begin_and_upload(&env, &owner, &identity, &first, 193_001);
        let two = begin_and_upload(&env, &owner, &identity, &second, 193_002);
        let assignment = assignment(
            &env,
            &owner,
            &identity,
            &[(&first, vec![one]), (&second, vec![two])],
        );
        let token = mint(&env, &assignment, Duration::from_secs(10));
        let temp = tempfile::tempdir().unwrap();
        let store = mkit_core::store::ObjectStore::init(&mkit_core::layout::RepoLayout::single(
            temp.path(),
        ))
        .unwrap();
        let mut decoded_ids = Vec::new();
        for bytes in [&first, &second] {
            let calls = env.pipe.meta.calls();
            let response = fetch(&env, &identity, &token, &hash(bytes), None).unwrap();
            assert_eq!(&response.bytes[..], bytes.as_slice());
            assert_eq!(response.start, 0);
            assert_eq!(response.total, bytes.len() as u64);
            assert!(!response.partial);
            assert!(response.bytes.len() <= crate::scanner_retrieval::MAX_RESPONSE_BYTES);
            assert!(env.pipe.meta.calls() - calls <= crate::scanner_retrieval::MAX_CALLS);
            decoded_ids.extend(
                mkit_core::pack::PackReader::read(&response.bytes, &store)
                    .unwrap()
                    .stored,
            );
            let mut rebuilt = Vec::new();
            for start in (0..bytes.len()).step_by(13) {
                let end = (start + 12).min(bytes.len() - 1);
                let range = fetch(
                    &env,
                    &identity,
                    &token,
                    &hash(bytes),
                    Some((start as u64, end as u64)),
                )
                .unwrap();
                assert_eq!(range.start, start as u64);
                assert_eq!(range.total, bytes.len() as u64);
                assert!(range.partial);
                assert!(range.bytes.len() <= 13);
                rebuilt.extend_from_slice(&range.bytes);
            }
            assert_eq!(rebuilt, *bytes);
            not_found(fetch(
                &env,
                &identity,
                &token,
                &hash(bytes),
                Some((0, bytes.len() as u64)),
            ));
            not_found(fetch(&env, &identity, &token, &hash(bytes), Some((2, 1))));
        }
        let (tree, commit, _) = signed_objects();
        decoded_ids.sort_unstable();
        let mut expected = vec![tree.id().unwrap(), commit.id().unwrap()];
        expected.sort_unstable();
        assert_eq!(decoded_ids, expected);
    }
}

#[test]
fn uniform_failures_cover_capability_scanner_origin_and_ticket_bindings() {
    let (mut env, owner, identity) = environment();
    env.pipe.cfg.scanner_retrieval = Some(scanner_config());
    let (bytes, _) = pack();
    let ticket = begin_and_upload(&env, &owner, &identity, &bytes, 193_010);
    let mut grant = assignment(&env, &owner, &identity, &[(&bytes, vec![ticket])]);
    let token = mint(&env, &grant, Duration::from_secs(1));
    assert!(fetch(&env, &identity, &token, &hash(&bytes), None).is_ok());
    not_found(fetch(&env, &identity, "", &hash(&bytes), None));
    not_found(fetch(
        &env,
        &identity,
        &format!("{token}0"),
        &hash(&bytes),
        None,
    ));
    not_found(fetch(&env, &identity, &token, &[0; 32], None));
    let request = body(&token, &hash(&bytes), None);
    not_found(block_on(
        env.pipe
            .retrieve_scanner_pack(&request, &Headers::default()),
    ));
    not_found(block_on(env.pipe.retrieve_scanner_pack(
        &request,
        &signed_fetch(&request, &identity, &key(40), T0),
    )));
    not_found(block_on(env.pipe.retrieve_scanner_pack(
        br"{}",
        &signed_fetch(br"{}", &identity, &key(41), T0),
    )));
    let mut wrong_audience = signed_fetch(&request, &identity, &key(41), T0);
    wrong_audience.audience = Some("https://other.test".into());
    not_found(block_on(
        env.pipe.retrieve_scanner_pack(&request, &wrong_audience),
    ));
    for case in 0..5 {
        let mut wrong = grant.clone();
        match case {
            0 => wrong.signer = [0; 32],
            1 => wrong.ref_name = "refs/heads/other".into(),
            2 => wrong.packs[0].length += 1,
            3 => wrong.packs[0].tickets = vec![[0; 32]],
            _ => wrong.repo_name = "other".into(),
        }
        let capability = mint(&env, &wrong, Duration::from_secs(1));
        not_found(fetch(&env, &identity, &capability, &hash(&bytes), None));
    }
    // Every ticket bound to a pack is required, even when another is open.
    grant.packs[0].tickets.push([0; 32]);
    let capability = mint(&env, &grant, Duration::from_secs(1));
    not_found(fetch(&env, &identity, &capability, &hash(&bytes), None));
    env.clock.set(T0 + 2_000);
    not_found(fetch(&env, &identity, &token, &hash(&bytes), None));
}

#[test]
fn scanner_signatures_cannot_authenticate_ordinary_client_calls() {
    let (mut env, _, identity) = environment();
    let scanner = key(41);
    for procedure in [
        Procedure::ListRefs,
        Procedure::ReadRef,
        Procedure::PackExists,
        Procedure::DownloadPack,
        Procedure::GetReceipt,
        Procedure::IssueObjectUrl,
        Procedure::UpdateRef,
        Procedure::AdvanceRefs,
        Procedure::BeginUpload,
        Procedure::CompleteUpload,
        Procedure::SetRepoVisibility,
    ] {
        let request = signed(&scanner, &identity, procedure, 193_090);
        env.pipe.cfg.scanner_retrieval = None;
        assert!(
            env.auth(&request).is_ok(),
            "valid envelope for {procedure:?}"
        );
        env.pipe.cfg.scanner_retrieval = Some(scanner_config());
        let error = env.auth(&request).err().unwrap();
        assert_eq!(error.code(), Code::Unauthenticated, "{procedure:?}");
        assert_eq!(
            error.public_message(),
            "scanner key cannot authenticate client calls"
        );
    }
}

#[test]
fn consumed_closed_and_expired_tickets_end_retrieval() {
    for sharding in [Sharding::Single, Sharding::D34] {
        for terminal in 0..3 {
            let (mut env, owner, identity) = environment_with_sharding(sharding);
            env.pipe.cfg.scanner_retrieval = Some(scanner_config());
            let (bytes, head) = pack();
            let ticket = begin_and_upload(&env, &owner, &identity, &bytes, 193_020);
            let grant = assignment(&env, &owner, &identity, &[(&bytes, vec![ticket])]);
            let token = mint(&env, &grant, Duration::from_mins(5));
            assert!(fetch(&env, &identity, &token, &hash(&bytes), None).is_ok());
            let request = signed(&owner, &identity, Procedure::AdvanceRefs, 193_021);
            let auth = env.auth(&request).unwrap();
            let partition = env.pipe.shards.ref_shard(&auth.repo().repo, HEAD);
            match terminal {
                0 => assert_eq!(
                    block_on(env.pipe.advance_refs_with_tickets(
                        &auth,
                        upd(HEAD, Missing, head),
                        upd(PACKMAP, Missing, hash(&bytes)),
                        vec![ticket]
                    ))
                    .unwrap(),
                    AdvanceOutcome::Committed
                ),
                1 => {
                    block_on(
                        env.pipe
                            .meta
                            .inner
                            .apply(&partition, Batch::new().delete(keys::ticket(&ticket))),
                    )
                    .unwrap();
                }
                _ => {
                    let raw = block_on(env.pipe.meta.inner.get(&partition, &keys::ticket(&ticket)))
                        .unwrap()
                        .unwrap();
                    let mut row = codec::decode_ticket(&raw).unwrap();
                    row.expires_at_ms = T0 as u64 + 1;
                    block_on(env.pipe.meta.inner.apply(
                        &partition,
                        Batch::new().put(keys::ticket(&ticket), codec::encode_ticket(&row)),
                    ))
                    .unwrap();
                    env.clock.set(T0 + 1);
                }
            }
            not_found(fetch(&env, &identity, &token, &hash(&bytes), None));
        }
    }
}

#[test]
fn global_block_denial_is_enforced_even_when_public_denial_flag_is_off() {
    let (mut env, owner, identity) = environment();
    assert!(!env.pipe.cfg.takedown_denial);
    env.pipe.cfg.scanner_retrieval = Some(scanner_config());
    let (bytes, _) = pack();
    let ticket = begin_and_upload(&env, &owner, &identity, &bytes, 193_030);
    let token = mint(
        &env,
        &assignment(&env, &owner, &identity, &[(&bytes, vec![ticket])]),
        Duration::from_secs(10),
    );
    assert!(fetch(&env, &identity, &token, &hash(&bytes), None).is_ok());
    block_on(
        ContentIndex::new(BorrowedStore(&env.pipe.meta)).install_block_action(
            &hash(&bytes),
            &crate::takedown::denial::BlockAction {
                id: [50; 32],
                takedown_id: [51; 32],
                reason: "manual".into(),
                blocked_at_ms: T0 as u64,
                chunk_ids: vec![],
            },
            T0 as u64,
        ),
    )
    .unwrap();
    not_found(fetch(&env, &identity, &token, &hash(&bytes), None));
    not_found(fetch(&env, &identity, &token, &hash(&bytes), Some((0, 3))));
}

#[test]
fn a_blocked_manifest_suppresses_its_chunk_in_an_otherwise_unblocked_raw_pack() {
    for sharding in [Sharding::Single, Sharding::D34] {
        let (mut env, owner, identity) = environment_with_sharding(sharding);
        env.pipe.cfg.scanner_retrieval = Some(scanner_config());
        assert!(!env.pipe.cfg.takedown_denial);
        let chunk = Object::Blob(Blob {
            data: b"shared chunk bytes".to_vec(),
        });
        let held_manifest = Object::ChunkedBlob(ChunkedBlob {
            total_size: 18,
            chunk_size: 0,
            chunks: vec![chunk.id().unwrap()],
        });
        let mut writer = PackWriter::new_raw_only();
        writer
            .push_raw(chunk.id().unwrap(), &serialize(&chunk).unwrap())
            .unwrap();
        let chunk_pack = writer.finish().unwrap();
        let (other, _) = pack();
        let chunk_ticket = begin_and_upload(&env, &owner, &identity, &chunk_pack, 193_070);
        let other_ticket = begin_and_upload(&env, &owner, &identity, &other, 193_071);
        let assignment = assignment(
            &env,
            &owner,
            &identity,
            &[
                (&chunk_pack, vec![chunk_ticket]),
                (&other, vec![other_ticket]),
            ],
        );
        let token = mint(&env, &assignment, Duration::from_secs(10));
        hold_manifest(&env, &owner, &identity, &held_manifest);
        assert!(fetch(&env, &identity, &token, &hash(&chunk_pack), None).is_ok());
        block_on(
            ContentIndex::new(BorrowedStore(&env.pipe.meta)).install_block_action(
                &held_manifest.id().unwrap(),
                &crate::takedown::denial::BlockAction {
                    id: [53; 32],
                    takedown_id: [54; 32],
                    reason: "manual".into(),
                    blocked_at_ms: T0 as u64,
                    chunk_ids: vec![chunk.id().unwrap()],
                },
                T0 as u64,
            ),
        )
        .unwrap();
        // The denied manifest is not an added pack/object in this capability;
        // its strong global chunk stop still applies to the scanner's bytes.
        not_found(fetch(&env, &identity, &token, &hash(&chunk_pack), None));
        not_found(fetch(
            &env,
            &identity,
            &token,
            &hash(&chunk_pack),
            Some((0, 3)),
        ));
        assert!(fetch(&env, &identity, &token, &hash(&other), None).is_ok());
    }
}

#[test]
fn disabled_retrieval_does_no_backend_work_and_input_output_bounds_hold() {
    let (mut env, owner, identity) = environment();
    assert!(env.pipe.cfg.scanner_retrieval.is_none());
    let body = br"{}";
    let before = env.pipe.meta.calls();
    not_found(block_on(
        env.pipe.retrieve_scanner_pack(body, &Headers::default()),
    ));
    assert_eq!(env.pipe.meta.calls(), before);
    env.pipe.cfg.scanner_retrieval = Some(scanner_config());
    env.pipe.cfg.upload_limits.max_total_bytes = 2 << 20;
    let object = Object::Blob(Blob {
        data: vec![3; crate::scanner_retrieval::MAX_RESPONSE_BYTES + 1],
    });
    let mut writer = PackWriter::new_raw_only();
    writer
        .push_raw(object.id().unwrap(), &serialize(&object).unwrap())
        .unwrap();
    let bytes = writer.finish().unwrap();
    let ticket = begin_and_upload(&env, &owner, &identity, &bytes, 193_040);
    let token = mint(
        &env,
        &assignment(&env, &owner, &identity, &[(&bytes, vec![ticket])]),
        Duration::from_secs(10),
    );
    not_found(fetch(&env, &identity, &token, &hash(&bytes), None));
    not_found(fetch(
        &env,
        &identity,
        &token,
        &hash(&bytes),
        Some((0, crate::scanner_retrieval::MAX_RESPONSE_BYTES as u64)),
    ));
    let range = fetch(
        &env,
        &identity,
        &token,
        &hash(&bytes),
        Some((0, crate::scanner_retrieval::MAX_RESPONSE_BYTES as u64 - 1)),
    )
    .unwrap();
    assert_eq!(
        range.bytes.len(),
        crate::scanner_retrieval::MAX_RESPONSE_BYTES
    );
    let oversized = vec![b' '; crate::scanner_retrieval::MAX_REQUEST_BYTES + 1];
    let before = env.pipe.meta.calls();
    not_found(block_on(env.pipe.retrieve_scanner_pack(
        &oversized,
        &signed_fetch(&oversized, &identity, &key(41), T0),
    )));
    assert_eq!(env.pipe.meta.calls(), before);
}

#[test]
fn scanner_fetches_during_inspect_and_fail_closed_window_then_retry_remints() {
    for sharding in [Sharding::Single, Sharding::D34] {
        let (mut env, owner, identity) = environment_with_sharding(sharding);
        env.pipe.cfg.scanner_retrieval = Some(scanner_config());
        env.pipe.cfg.begin_upload_threshold_bytes = 0;
        let scanner = Arc::new(LiveScanner {
            pipe: Pipeline::new(
                env.pipe.blobs.clone(),
                env.pipe.meta.inner.clone(),
                Hooks::new(),
                env.pipe.cfg.clone(),
                env.clock.clone(),
                env.metrics.clone(),
            )
            .unwrap(),
            calls: Mutex::default(),
            unavailable: AtomicBool::new(true),
        });
        let replacement = environment().0.pipe;
        env.pipe = std::mem::replace(&mut env.pipe, replacement)
            .with_inspectors(vec![scanner.clone()], 10_000)
            .unwrap();
        let (one, two, head) = inspection_packs();
        let list = encode_packlist(None, &[hash(&one), hash(&two)]).unwrap();
        let tickets = [(&one, 193_050), (&two, 193_051), (&list, 193_052)]
            .into_iter()
            .map(|(bytes, n)| begin_and_upload(&env, &owner, &identity, bytes, n))
            .collect::<Vec<_>>();
        let advance = signed(&owner, &identity, Procedure::AdvanceRefs, 193_053);
        let auth = env.auth(&advance).unwrap();
        let attempt = block_on(env.pipe.advance_refs_with_tickets(
            &auth,
            upd(HEAD, Missing, head),
            upd(PACKMAP, Missing, hash(&list)),
            tickets.clone(),
        ));
        let error = attempt.unwrap_err();
        assert_eq!(
            error.code(),
            Code::Unavailable,
            "{}",
            error.public_message()
        );
        let first = scanner.calls.lock().unwrap()[0].clone();
        assert_eq!(first.1.packs.len(), 2);
        let capability = first.1.capability.as_ref().unwrap();
        assert_eq!(
            &fetch(&env, &identity, capability, &hash(&one), None)
                .unwrap()
                .bytes[..],
            &one
        );
        let expiry = first.1.expires_at_ms.unwrap();
        env.clock.set(i64::try_from(expiry).unwrap() - 1);
        assert!(fetch(&env, &identity, capability, &hash(&two), None).is_ok());
        env.clock.set(i64::try_from(expiry).unwrap());
        not_found(fetch(&env, &identity, capability, &hash(&one), None));
        scanner.unavailable.store(false, Ordering::SeqCst);
        assert_eq!(
            block_on(env.pipe.advance_refs_with_tickets(
                &env.auth(&advance).unwrap(),
                upd(HEAD, Missing, head),
                upd(PACKMAP, Missing, hash(&list)),
                tickets
            ))
            .unwrap(),
            AdvanceOutcome::Committed
        );
        let calls = scanner.calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].0, calls[1].0);
        assert_ne!(calls[0].1.capability, calls[1].1.capability);
        assert_eq!(calls[0].1.packs, calls[1].1.packs);
        not_found(fetch(
            &env,
            &identity,
            calls[1].1.capability.as_ref().unwrap(),
            &hash(&one),
            None,
        ));
    }
}

#[test]
fn stream_lengths_are_checked_and_reads_allocate_only_the_requested_range() {
    let (mut env, owner, identity) = environment();
    env.pipe.cfg.scanner_retrieval = Some(scanner_config());
    env.pipe.cfg.begin_upload_threshold_bytes = 0;
    let (bytes, _) = pack();
    let ticket = begin_and_upload(&env, &owner, &identity, &bytes, 193_060);
    let token = mint(
        &env,
        &assignment(&env, &owner, &identity, &[(&bytes, vec![ticket])]),
        Duration::from_secs(10),
    );
    let mode = Arc::new(AtomicU32::new(0));
    let produced = Arc::new(AtomicU32::new(0));
    let peak_piece = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let ranges = Arc::new(Mutex::default());
    let pipe = Pipeline::new(
        StreamBlobs {
            inner: env.pipe.blobs.clone(),
            mode: mode.clone(),
            produced: produced.clone(),
            peak_piece: peak_piece.clone(),
            ranges: ranges.clone(),
        },
        env.pipe.meta.inner.clone(),
        Hooks::new(),
        env.pipe.cfg.clone(),
        env.clock.clone(),
        env.metrics.clone(),
    )
    .unwrap();
    let body = body(&token, &hash(&bytes), Some((1, 64)));
    let headers = signed_fetch(&body, &identity, &key(41), T0);
    let response = block_on(pipe.retrieve_scanner_pack(&body, &headers)).unwrap();
    assert_eq!(&response.bytes[..], &bytes[1..65]);
    assert_eq!(response.bytes.len(), 64);
    assert_eq!(produced.load(Ordering::SeqCst), 2);
    assert_eq!(peak_piece.load(Ordering::SeqCst), 32);
    // The source reads 64 bytes and yields 32-byte pieces; the destination
    // owns exactly the bounded 64-byte range, never a whole pack allocation.
    assert_eq!(ranges.lock().unwrap().len(), 1);
    let range = ranges.lock().unwrap()[0];
    assert_eq!((range.start, range.end_inclusive), (1, 64));
    for fault in 1..=4 {
        mode.store(fault, Ordering::SeqCst);
        produced.store(0, Ordering::SeqCst);
        not_found(block_on(pipe.retrieve_scanner_pack(&body, &headers)));
        if fault == 2 || fault == 4 {
            assert_eq!(produced.load(Ordering::SeqCst), 1);
        }
        if fault == 3 {
            assert_eq!(produced.load(Ordering::SeqCst), 0);
        }
    }
}

#[test]
fn startup_checks_every_active_retained_and_scanner_key_against_other_roles() {
    use crate::url_token::{RetiredKey, UrlTokenConfig, UrlTokenKeys};
    let (env, _, _) = environment();
    let mut base = env.pipe.cfg.clone();
    base.begin_upload_threshold_bytes = 0;
    base.scanner_retrieval = Some(Arc::new(
        RetrievalConfig::parse(
            &format!(
                "active current {}\nretained old {} 1000",
                to_hex(&[42; 32]),
                to_hex(&[48; 32])
            ),
            &to_hex(key(41).verifying_key().as_bytes()),
        )
        .unwrap(),
    ));
    assert!(crate::scanner_retrieval::service::validate_config(&base).is_ok());
    for case in 0..14 {
        let mut config = base.clone();
        match case {
            0..=4 => {
                let secret = match case {
                    0 => [42; 32],
                    1 => [48; 32],
                    2 => key(42).verifying_key().to_bytes(),
                    3 => key(48).verifying_key().to_bytes(),
                    _ => key(41).verifying_key().to_bytes(),
                };
                config.ticket_keys = Some(
                    crate::upload::token::TicketKeys::new(vec![("reuse".into(), secret)]).unwrap(),
                );
            }
            5..=7 => {
                let seed = match case {
                    5 => [42; 32],
                    6 => [41; 32],
                    _ => key(41).verifying_key().to_bytes(),
                };
                config.url_tokens = Some(UrlTokenConfig::new(
                    UrlTokenKeys::new(zeroize::Zeroizing::new(seed), vec![]).unwrap(),
                ));
            }
            8..=9 => {
                let public = key(if case == 8 { 48 } else { 41 })
                    .verifying_key()
                    .to_bytes();
                config.url_tokens = Some(UrlTokenConfig::new(
                    UrlTokenKeys::new(
                        zeroize::Zeroizing::new([49; 32]),
                        vec![RetiredKey {
                            public,
                            retired_at_ms: 1000,
                        }],
                    )
                    .unwrap(),
                ));
            }
            10..=12 => {
                config.admin_keys = vec![
                    key(match case {
                        10 => 42,
                        11 => 48,
                        _ => 41,
                    })
                    .verifying_key()
                    .to_bytes(),
                ];
            }
            _ => {
                config.authority_fence = Some(
                    crate::authority::AuthorityFence::parse(&format!(
                        "deployment {} ed25519-{}",
                        to_hex(key(41).verifying_key().as_bytes()),
                        to_hex(key(7).verifying_key().as_bytes())
                    ))
                    .unwrap(),
                );
            }
        }
        assert!(
            crate::scanner_retrieval::service::validate_config(&config).is_err(),
            "key-role collision case {case}"
        );
    }
}

struct LiveScanner {
    pipe: Pipeline<MemoryBlobStore, Arc<MemoryKv>>,
    calls: Mutex<Vec<(String, InspectRetrieval)>>,
    unavailable: AtomicBool,
}
impl ContentInspector for LiveScanner {
    fn id(&self) -> &'static str {
        "real-byte-scanner"
    }
    fn inspect<'a>(
        &'a self,
        _: &'a Operation,
        _: &'a str,
        _: &'a [InspectObject],
    ) -> crate::BoxFuture<'a, Result<InspectVerdict, ServerError>> {
        Box::pin(async { panic!("retrieval metadata must reach the scanner") })
    }
    fn inspect_with_retrieval<'a>(
        &'a self,
        op: &'a Operation,
        id: &'a str,
        objects: &'a [InspectObject],
        retrieval: Option<InspectRetrieval>,
    ) -> crate::BoxFuture<'a, Result<InspectVerdict, ServerError>> {
        Box::pin(async move {
            let retrieval = retrieval.expect("enabled Inspect includes retrieval");
            assert_eq!(
                retrieval.endpoint_path.as_deref(),
                Some(crate::scanner_retrieval::PATH)
            );
            assert_eq!(
                retrieval.packs.len(),
                2,
                "Inspect assignment excludes packlist metadata"
            );
            let identity = match &self.pipe.cfg.addressing {
                Addressing::Multi(_) => {
                    format!("{}/{}", op.repo.namespace.as_str(), op.repo.name.as_str())
                }
                _ => panic!("fixture uses Multi"),
            };
            let temp = tempfile::tempdir().unwrap();
            let store = mkit_core::store::ObjectStore::init(
                &mkit_core::layout::RepoLayout::single(temp.path()),
            )
            .unwrap();
            let mut decoded = std::collections::BTreeSet::new();
            for pack in &retrieval.packs {
                let pack_id: Hash = pack.id.as_ref().unwrap().as_slice().try_into().unwrap();
                let length = pack.length.unwrap();
                let mut bytes = Vec::new();
                for start in (0..length).step_by(17) {
                    let body = body(
                        retrieval.capability.as_ref().unwrap(),
                        &pack_id,
                        Some((start, (start + 16).min(length - 1))),
                    );
                    let response = self
                        .pipe
                        .retrieve_scanner_pack(
                            &body,
                            &signed_fetch(&body, &identity, &key(41), self.pipe.clock.now_ms()),
                        )
                        .await
                        .unwrap();
                    assert!(response.bytes.len() <= 17);
                    bytes.extend_from_slice(&response.bytes);
                }
                assert_eq!(hash(&bytes), pack_id);
                decoded.extend(
                    mkit_core::pack::PackReader::read(&bytes, &store)
                        .unwrap()
                        .stored,
                );
            }
            assert_eq!(objects.len(), 3); // Direct blob, a chunk, and its manifest.
            for metadata in objects {
                let id: Hash = metadata.id.as_ref().unwrap().as_slice().try_into().unwrap();
                assert!(
                    decoded.contains(&id),
                    "Inspect id must occur in retrieved bytes"
                );
                let raw = store.read(&id).unwrap();
                assert_eq!(metadata.size, Some(raw.len() as u64));
                let object = mkit_core::serialize::deserialize(&raw).unwrap();
                assert_eq!(object.id().unwrap(), id);
                if let Object::ChunkedBlob(manifest) = object {
                    assert_eq!(manifest.chunks.len(), 2);
                    for chunk in manifest.chunks {
                        assert!(
                            decoded.contains(&chunk),
                            "scanner derives chunk membership from manifest bytes"
                        );
                    }
                }
            }
            self.calls.lock().unwrap().push((id.to_owned(), retrieval));
            if self.unavailable.load(Ordering::SeqCst) {
                Err(ServerError::unavailable("scanner unavailable"))
            } else {
                Ok(InspectVerdict::Pass)
            }
        })
    }
}

fn inspection_packs() -> (Vec<u8>, Vec<u8>, Hash) {
    let direct = Object::Blob(Blob {
        data: b"dual file/chunk".to_vec(),
    });
    let chunk = Object::Blob(Blob {
        data: b"chunk only".to_vec(),
    });
    let manifest = Object::ChunkedBlob(ChunkedBlob {
        total_size: 25,
        chunk_size: 0,
        chunks: vec![direct.id().unwrap(), chunk.id().unwrap()],
    });
    let tree = Object::Tree(Tree {
        entries: vec![
            TreeEntry {
                name: b"direct".to_vec(),
                mode: EntryMode::Blob,
                object_hash: direct.id().unwrap(),
            },
            TreeEntry {
                name: b"manifest".to_vec(),
                mode: EntryMode::Blob,
                object_hash: manifest.id().unwrap(),
            },
        ],
    });
    let signer = KeyPair::from_seed([9; 32]);
    let mut commit = Commit::new_unannotated(
        tree.id().unwrap(),
        Vec::new(),
        Identity::ed25519(signer.public.0),
        signer.public.0,
        b"retrieval".to_vec(),
        42,
        [0; 64],
    );
    commit.signature = sign_commit(&commit, &signer).unwrap().0;
    let commit = Object::Commit(commit);
    let head = commit.id().unwrap();
    // Two added packs, so the scanner must fetch every ordered assignment.
    let mut one = PackWriter::new_raw_only();
    for object in [&tree, &commit, &direct] {
        one.push_raw(object.id().unwrap(), &serialize(object).unwrap())
            .unwrap();
    }
    let one = one.finish().unwrap();
    let mut two = PackWriter::new_raw_only();
    for object in [&chunk, &manifest] {
        two.push_raw(object.id().unwrap(), &serialize(object).unwrap())
            .unwrap();
    }
    let two = two.finish().unwrap();
    (one, two, head)
}

struct StreamBlobs {
    inner: MemoryBlobStore,
    mode: Arc<AtomicU32>,
    produced: Arc<AtomicU32>,
    peak_piece: Arc<std::sync::atomic::AtomicUsize>,
    ranges: Arc<Mutex<Vec<ByteRange>>>,
}
impl BlobStore for StreamBlobs {
    type Sink = <MemoryBlobStore as BlobStore>::Sink;
    async fn begin(&self, key: BlobKey, len: u64) -> Result<Self::Sink, StoreError> {
        self.inner.begin(key, len).await
    }
    async fn get(
        &self,
        key: &BlobKey,
        range: Option<ByteRange>,
    ) -> Result<Option<BlobBody>, StoreError> {
        let range = range.expect("scanner requests a bounded backend range");
        self.ranges.lock().unwrap().push(range);
        let Some(raw) = self.inner.get(key, Some(range)).await? else {
            return Ok(None);
        };
        let BlobBody::Bytes(bytes) = raw else {
            panic!("small stream fixture")
        };
        let mode = self.mode.load(Ordering::SeqCst);
        let advertised = bytes.len() as u64;
        let mut bytes = bytes.to_vec();
        if mode == 1 {
            bytes.pop();
        }
        if mode == 2 {
            bytes.push(0);
        }
        let produced = self.produced.clone();
        let peak = self.peak_piece.clone();
        let mut chunks = bytes
            .chunks(if mode == 2 { bytes.len() } else { 32 })
            .map(Bytes::copy_from_slice)
            .collect::<std::collections::VecDeque<_>>();
        let stream = futures::stream::poll_fn(move |_| {
            let value = chunks.pop_front().map(|piece| {
                produced.fetch_add(1, Ordering::SeqCst);
                peak.fetch_max(piece.len(), Ordering::SeqCst);
                if mode == 4 {
                    Err(StoreError::unavailable("stream fault"))
                } else {
                    Ok(piece)
                }
            });
            std::task::Poll::Ready(value)
        });
        Ok(Some(BlobBody::Stream {
            len: advertised + u64::from(mode == 3),
            stream: Box::pin(stream),
        }))
    }
    async fn head(&self, key: &BlobKey) -> Result<Option<BlobMeta>, StoreError> {
        self.inner.head(key).await
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.inner.probe().await
    }
    async fn delete(&self, key: &BlobKey) -> Result<bool, StoreError> {
        self.inner.delete(key).await
    }
}
impl MultipartBlobStore for StreamBlobs {
    type PartSink = UnsupportedPartSink;
    const MAX_PARTS: u32 = u32::MAX;
}

fn hold_manifest(env: &Env, owner: &SigningKey, identity: &str, held_manifest: &Object) {
    let mut writer = PackWriter::new_raw_only();
    writer
        .push_raw(
            held_manifest.id().unwrap(),
            &serialize(held_manifest).unwrap(),
        )
        .unwrap();
    let manifest_pack = writer.finish().unwrap();
    let held_ticket = begin_and_upload(env, owner, identity, &manifest_pack, 193_072);
    let _held_assignment =
        self::assignment(env, owner, identity, &[(&manifest_pack, vec![held_ticket])]);
    let auth = env
        .auth(&signed(owner, identity, Procedure::AdvanceRefs, 193_073))
        .unwrap();
    let repo = &auth.repo().repo;
    let source = env.pipe.shards.ref_shard(repo, HEAD);
    let plan = crate::store::index::plan_index_rows_direct(
        env.pipe.shards.as_ref(),
        repo,
        &source,
        &hash(&manifest_pack),
        &[crate::store::index::IndexEntry {
            object: held_manifest.id().unwrap(),
            value: crate::store::index::IndexValue {
                frame_offset: 12,
                frame_length: manifest_pack.len() as u64 - 44,
                wire_type: 0,
                decoded_size: serialize(held_manifest).unwrap().len() as u64,
                chain_depth: 0,
                delta_base: None,
            },
        }],
        T0 as u64,
    )
    .unwrap();
    for batch in plan.direct {
        let mut mutation = Batch::new();
        for (key, value) in batch.puts {
            mutation = mutation.put(key, value);
        }
        block_on(env.pipe.meta.inner.apply(&batch.target, mutation)).unwrap();
    }
    block_on(
        env.pipe.meta.inner.apply(
            &env.pipe
                .shards
                .membership(repo, &BlobKey::pack(hash(&manifest_pack))),
            Batch::new().put(
                keys::membership(&repo.name, &hash(&manifest_pack)),
                Value::new(vec![1]),
            ),
        ),
    )
    .unwrap();
}

struct DelayedTicketRead {
    inner: Arc<MemoryKv>,
    clock: Arc<ManualClock>,
    ticket: Hash,
    completed_at: i64,
    ticket_reads: Arc<AtomicU32>,
}

impl NamespaceStore for DelayedTicketRead {
    fn capabilities(&self) -> StoreCapabilities {
        self.inner.capabilities()
    }
    async fn get(&self, partition: &Partition, key: &Key) -> Result<Option<Value>, StoreError> {
        self.inner.get(partition, key).await
    }
    async fn get_many(
        &self,
        partition: &Partition,
        keys: &[Key],
    ) -> Result<Vec<Option<Value>>, StoreError> {
        let rows = self.inner.get_many(partition, keys).await?;
        if keys == [keys::ticket(&self.ticket)]
            && self.ticket_reads.fetch_add(1, Ordering::SeqCst) == 1
        {
            // The final strong ticket read finishes at the injected time.
            // Both the pre-read cap check and the ticket-read start were valid.
            self.clock.set(self.completed_at);
        }
        Ok(rows)
    }
    async fn scan(
        &self,
        partition: &Partition,
        start: &Key,
        end: &Key,
        after: Option<&crate::store::Cursor>,
        limit: u32,
    ) -> Result<ScanPage, StoreError> {
        self.inner.scan(partition, start, end, after, limit).await
    }
    async fn apply(&self, partition: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
        self.inner.apply(partition, batch).await
    }
    async fn stats(&self, partition: &Partition) -> Result<PartitionStats, StoreError> {
        self.inner.stats(partition).await
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.inner.probe().await
    }
}

#[test]
fn final_ticket_read_cannot_serve_bytes_after_capability_or_ticket_expiry() {
    for ticket_expires in [false, true] {
        for reaches_deadline in [false, true] {
            let (mut env, owner, identity) = environment();
            env.pipe.cfg.scanner_retrieval = Some(scanner_config());
            env.pipe.cfg.begin_upload_threshold_bytes = 0;
            let (bytes, _) = pack();
            let ticket = begin_and_upload(&env, &owner, &identity, &bytes, 193_080);
            let grant = assignment(&env, &owner, &identity, &[(&bytes, vec![ticket])]);
            let timeout = if ticket_expires {
                Duration::from_secs(10)
            } else {
                Duration::from_secs(1)
            };
            let token = mint(&env, &grant, timeout);
            let deadline = T0 + if ticket_expires { 1_000 } else { 2_000 };
            if ticket_expires {
                let auth = env
                    .auth(&signed(&owner, &identity, Procedure::AdvanceRefs, 193_081))
                    .unwrap();
                let partition = env.pipe.shards.ref_shard(&auth.repo().repo, HEAD);
                let raw = block_on(env.pipe.meta.inner.get(&partition, &keys::ticket(&ticket)))
                    .unwrap()
                    .unwrap();
                let mut row = codec::decode_ticket(&raw).unwrap();
                row.expires_at_ms = u64::try_from(deadline).unwrap();
                block_on(env.pipe.meta.inner.apply(
                    &partition,
                    Batch::new().put(keys::ticket(&ticket), codec::encode_ticket(&row)),
                ))
                .unwrap();
            }
            let ticket_reads = Arc::new(AtomicU32::new(0));
            let completed_at = deadline - i64::from(!reaches_deadline);
            let pipe = Pipeline::new(
                env.pipe.blobs.clone(),
                DelayedTicketRead {
                    inner: env.pipe.meta.inner.clone(),
                    clock: env.clock.clone(),
                    ticket,
                    completed_at,
                    ticket_reads: ticket_reads.clone(),
                },
                Hooks::new(),
                env.pipe.cfg.clone(),
                env.clock.clone(),
                env.metrics.clone(),
            )
            .unwrap();
            let request = body(&token, &hash(&bytes), None);
            let result =
                block_on(pipe.retrieve_scanner_pack(
                    &request,
                    &signed_fetch(&request, &identity, &key(41), T0),
                ));
            assert_eq!(ticket_reads.load(Ordering::SeqCst), 2);
            assert_eq!(env.clock.now_ms(), completed_at);
            if reaches_deadline {
                not_found(result);
            } else {
                assert_eq!(&result.unwrap().bytes[..], bytes.as_slice());
            }
        }
    }
}
