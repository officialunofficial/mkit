//! `retry_after` hints a pending scheduled job answers (Lane RX2 WP1): a
//! tiny job (`VerifyJobV1::tiny`, the SP2 notion) answers the millisecond
//! wake of its persisted timer in every phase, while an undecoded or larger
//! job keeps whole-second rounding.
use super::*;

/// `PendingVerification.retry_after_ms` (field 1 varint) out of the error's
/// detail, the same bytes the wire client decodes.
fn pending_hint_ms(error: &crate::ServerError) -> u64 {
    let detail = error
        .details()
        .iter()
        .find(|detail| detail.type_name == "mkit.transport.v1.PendingVerification")
        .expect("a pending answer carries the PendingVerification detail");
    let bytes = detail.value.as_ref();
    assert_eq!(bytes.first(), Some(&0x08), "field 1 is a varint");
    let (mut value, mut shift) = (0u64, 0u32);
    for &byte in &bytes[1..] {
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return value;
        }
        shift += 7;
    }
    value
}

/// Plant `job` and the kind-7 timer due in `delay_ms`, as a slice would have
/// left them. `job.tiny()` decides the hint class.
fn plant(rig: &Rig, pack: &Hash, job: &mut VerifyJobV1, delay_ms: u64) {
    let now = u64::try_from(rig.clock.now_ms()).unwrap();
    let batch = checkpoint::write_job(Batch::new(), job, None, &rig.repo.name, pack)
        .unwrap()
        .put(
            keys::timer(
                now + delay_ms,
                crate::timers::registry::kinds::VERIFY.get(),
                &checkpoint::timer_reference(&rig.repo.name, pack),
            ),
            Value::default(),
        );
    assert_eq!(
        block_on(rig.store.apply(&rig.source(), batch)).unwrap(),
        BatchOutcome::Committed
    );
}

/// A job mid-`phase` with decode-finished counters small enough for `tiny`.
fn tiny_job(ticket: &TicketV1, id: Hash, phase: Phase) -> VerifyJobV1 {
    let mut job = VerifyJobV1::new(
        id,
        u64::try_from(NOW).unwrap(),
        ticket.bytes,
        checkpoint::DEFAULT_ENTRY_CAP,
    );
    job.phase = phase;
    job.kind = Kind::Pack;
    job.entries = 1;
    job.in_pack_bytes = ticket.bytes;
    job
}

/// What an advance consuming `ticket`'s pack answers as its poll hint.
fn hint_of(rig: &Rig, ticket: &TicketV1, id: Hash) -> u64 {
    let error = rig.check(&[(ticket, id)], [9; 32]).unwrap_err();
    assert_eq!(
        (error.code(), error.public_message()),
        (crate::Code::Unavailable, "pack verification pending"),
    );
    pending_hint_ms(&error)
}

#[test]
fn a_tiny_job_answers_sub_second_hints_in_every_phase() {
    for phase in [
        Phase::ClosureResolve,
        Phase::EmitIndex,
        Phase::AwaitDelivery,
        Phase::Extract,
        Phase::Verify,
        Phase::Recheck,
        Phase::Watch,
    ] {
        let rig = Rig::new();
        let (pack, _) = tree_pack(1, 10);
        let (ticket, id) = rig.add(&pack);
        let mut job = tiny_job(&ticket, id, phase);
        assert!(job.tiny(), "{phase:?} jobs must qualify as tiny");
        plant(&rig, &ticket.pack_id, &mut job, 250);
        assert_eq!(hint_of(&rig, &ticket, id), 250, "{phase:?}");
    }
}

#[test]
fn a_tiny_job_hint_never_drops_below_its_100_ms_floor() {
    let rig = Rig::new();
    let (pack, _) = tree_pack(1, 10);
    let (ticket, id) = rig.add(&pack);
    let mut job = tiny_job(&ticket, id, Phase::AwaitDelivery);
    // An overdue timer (due before now) still answers the floor.
    plant(&rig, &ticket.pack_id, &mut job, 0);
    assert_eq!(hint_of(&rig, &ticket, id), 100);
}

#[test]
fn a_tiny_job_hint_is_capped_at_the_pending_maximum() {
    let rig = Rig::new();
    let (pack, _) = tree_pack(1, 10);
    let (ticket, id) = rig.add(&pack);
    let mut job = tiny_job(&ticket, id, Phase::AwaitDelivery);
    plant(&rig, &ticket.pack_id, &mut job, 30_000);
    assert_eq!(hint_of(&rig, &ticket, id), 3_000);
}

#[test]
fn a_non_tiny_job_keeps_whole_second_hints() {
    let rig = Rig::new();
    let (pack, _) = tree_pack(1, 10);
    let (ticket, id) = rig.add(&pack);
    // Decode is never `tiny` (SP2: size is only known once decoded).
    let mut job = tiny_job(&ticket, id, Phase::Decode);
    assert!(!job.tiny());
    plant(&rig, &ticket.pack_id, &mut job, 250);
    assert_eq!(hint_of(&rig, &ticket, id), 1_000);
    // A larger verified job rounds up the same way.
    let mut job = tiny_job(&ticket, id, Phase::AwaitDelivery);
    job.entries = checkpoint::TINY_ENTRIES + 1;
    assert!(!job.tiny());
    plant(&rig, &ticket.pack_id, &mut job, 250);
    assert_eq!(hint_of(&rig, &ticket, id), 1_000);
}
