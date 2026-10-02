//! `BeginUpload` session lifecycle and capability checks.

use super::stream::Counting;
use super::*;
use crate::upload::token::TicketKeys;
use mkit_core::upload_parts::MIN_PART_SIZE;

fn config() -> PipelineConfig {
    let mut cfg = cfg(authv2());
    cfg.upload_limits.max_total_bytes = 4 * MIN_PART_SIZE;
    cfg.ticket_keys = Some(TicketKeys::new(vec![("active".into(), [7; 32])]).unwrap());
    cfg
}

fn begin_request(n: u32) -> Req {
    Req::signed(&key(7), Procedure::BeginUpload, b"begin", &nonce(n), T0)
}

fn ticket(result: BeginUploadResult, keys: &TicketKeys) -> crate::upload::token::TicketClaims {
    let BeginUploadResult::Ticket { token, .. } = result else {
        panic!("expected ticket")
    };
    keys.verify(&token, T0 as u64).unwrap()
}

fn begin<H: HookSet>(
    env: &Env<H>,
    req: &Req,
    id: Hash,
    bytes: u64,
) -> Result<BeginUploadResult, ServerError> {
    block_on(env.pipe.begin_upload(&env.auth(req)?, HEAD, &id, bytes))
}

#[test]
fn multipart_session_is_minted_and_live_remint_reuses_it() {
    let clock = clock();
    let env = build(config(), Spy::new(store(&clock)), Hooks::new(), clock);
    let keys = env.pipe.cfg.ticket_keys.as_ref().unwrap();
    let first = ticket(
        begin(&env, &begin_request(1), A, MIN_PART_SIZE + 1).unwrap(),
        keys,
    );
    assert!(!first.upload_session.is_empty());
    assert_eq!(env.pipe.blobs.multipart_session_count(), 1);
    let remint = ticket(
        begin(&env, &begin_request(2), A, MIN_PART_SIZE + 1).unwrap(),
        keys,
    );
    assert_eq!(remint.ticket_id, first.ticket_id);
    assert_eq!(remint.upload_session, first.upload_session);
    assert_eq!(env.pipe.blobs.multipart_session_count(), 1);
}

#[test]
fn single_part_ticket_has_no_session() {
    let clock = clock();
    let env = build(config(), Spy::new(store(&clock)), Hooks::new(), clock);
    let keys = env.pipe.cfg.ticket_keys.as_ref().unwrap();
    let claims = ticket(begin(&env, &begin_request(3), B, 1).unwrap(), keys);
    assert!(claims.upload_session.is_empty());
    assert_eq!(env.pipe.blobs.multipart_session_count(), 0);
}

#[test]
fn reserved_multipart_apply_failure_aborts_session_and_reservation() {
    let clock = clock();
    let mut spy = Spy::new(store(&clock));
    let fail = spy.fail_next_apply.clone();
    spy.after_hook = Some(Box::new(move |_, _, batch, outcome| {
        if !matches!(outcome, BatchOutcome::Committed) {
            return;
        }
        if batch.writes.iter().any(|write| {
            matches!(write, Write::Put(_, value)
            if matches!(codec::decode_reservation(value), Ok(codec::ReservationV1::Pending { .. })))
        }) {
            fail.store(true, Ordering::SeqCst);
        }
    }));
    let env = build(
        config(),
        spy,
        with_admission(Fixed(
            AdmissionDecision::allow(Vec::new()).with_reservation("multipart-rid"),
        )),
        clock,
    );
    let err = begin(&env, &begin_request(44), C, MIN_PART_SIZE + 1).unwrap_err();
    assert_eq!(err.code(), Code::Internal);
    assert_eq!(env.pipe.blobs.multipart_session_count(), 0);
    assert_one_abort(&env, "multipart-rid", codec::AbortReason::Internal);
}

#[test]
fn unsupported_backend_refuses_before_admission() {
    let clock = clock();
    let admission = SpyAdmission::default();
    let pipe = Pipeline::new(
        Counting::default(),
        Spy::new(store(&clock)),
        with_admission(admission),
        config(),
        clock,
        Arc::new(SpyMetrics::default()),
    )
    .unwrap();
    let req = begin_request(4);
    let lookup = |name: &str| {
        req.headers
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| v.clone())
    };
    let a = pipe
        .authenticate(&RequestMeta {
            procedure: Procedure::BeginUpload,
            header: &lookup,
            header_values: None,
            unary_body: Some(&req.body),
            transport_principal: None,
        })
        .unwrap();
    let err = block_on(pipe.begin_upload(&a, HEAD, &C, MIN_PART_SIZE + 1)).unwrap_err();
    assert_eq!(err.code(), Code::Unimplemented);
    assert_eq!(
        err.public_message(),
        "multipart uploads are not supported by this storage backend"
    );
    assert!(pipe.hooks.admission.0.lock().unwrap().is_empty());
    assert_eq!(pipe.meta.calls(), 0);
}

#[test]
fn failed_batch_aborts_new_session() {
    let clock = clock();
    let blobs = MemoryBlobStore::default();
    let pipe = Pipeline::new(
        blobs.clone(),
        Spy::new(store(&clock).with_fault(MemoryFault::ApplyBefore)),
        Hooks::new(),
        config(),
        clock,
        Arc::new(SpyMetrics::default()),
    )
    .unwrap();
    let req = begin_request(5);
    let lookup = |name: &str| {
        req.headers
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| v.clone())
    };
    let a = pipe
        .authenticate(&RequestMeta {
            procedure: Procedure::BeginUpload,
            header: &lookup,
            header_values: None,
            unary_body: Some(&req.body),
            transport_principal: None,
        })
        .unwrap();
    assert!(block_on(pipe.begin_upload(&a, HEAD, &A, MIN_PART_SIZE + 1)).is_err());
    assert_eq!(blobs.multipart_session_count(), 0);
}

#[test]
fn committed_batch_with_lost_reply_keeps_session_for_remint() {
    let clock = clock();
    let blobs = MemoryBlobStore::default();
    let pipe = Pipeline::new(
        blobs.clone(),
        Spy::new(store(&clock).with_fault(MemoryFault::ApplyAfterCommit)),
        Hooks::new(),
        config(),
        clock,
        Arc::new(SpyMetrics::default()),
    )
    .unwrap();
    let signed = |n: u32| {
        let req = begin_request(n);
        let lookup = |name: &str| {
            req.headers
                .iter()
                .find(|(h, _)| *h == name)
                .map(|(_, v)| v.clone())
        };
        pipe.authenticate(&RequestMeta {
            procedure: Procedure::BeginUpload,
            header: &lookup,
            header_values: None,
            unary_body: Some(&req.body),
            transport_principal: None,
        })
        .unwrap()
    };
    assert!(block_on(pipe.begin_upload(&signed(6), HEAD, &A, MIN_PART_SIZE + 1)).is_err());
    assert_eq!(blobs.multipart_session_count(), 1);
    let result = block_on(pipe.begin_upload(&signed(7), HEAD, &A, MIN_PART_SIZE + 1)).unwrap();
    let claims = ticket(result, pipe.cfg.ticket_keys.as_ref().unwrap());
    assert!(!claims.upload_session.is_empty());
    assert_eq!(blobs.multipart_session_count(), 1);
}
