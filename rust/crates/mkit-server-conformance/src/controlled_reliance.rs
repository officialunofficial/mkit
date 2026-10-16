//! Portable races between a newly relied-on member and its removal.

use mkit_core::hash::{from_hex, hash, to_hex};
use mkit_transport_connect::generated::__buffa::oneof::{
    begin_upload_response::Result as BeginResult, upload_pack_request::Body as UploadBody,
};
use mkit_transport_connect::generated::{
    AdvanceOutcome, AdvanceRefsResponse, BeginUploadRequest, BeginUploadResponse,
};

use crate::control::{
    Observation, ObservationQuery, RelianceFixtureQuery, RelianceObservation, ReplayIdentity,
    Request,
};
use crate::controlled::ControlClient;
use crate::wire::cases::{
    Ctx, Exp, Failure, Signed, advance_req, sign_unary, upload_msgs, want_ok,
};
use crate::wire::client::{Rpc, RpcError};

struct Fixture {
    operation: Signed,
    query: ObservationQuery,
    head: String,
    packmap: String,
    base: String,
}

fn require_external_delta(pack: &[u8]) -> Result<(), Failure> {
    use mkit_core::pack::{DecodeLimits, NoExternalBases, PackError, decode_entries_with};
    let result = decode_entries_with(
        pack,
        &mut NoExternalBases,
        DecodeLimits::default().with_max_decoded_bytes(8 * 1_048_576),
        |_| Ok(()),
    );
    match result {
        Err(PackError::DeltaBaseMissing(_)) => Ok(()),
        other => {
            Err(format!("reliance candidate must require an external delta base: {other:?}").into())
        }
    }
}

async fn fixture(ctx: &Ctx, control: &ControlClient, gc: bool) -> Result<Fixture, Failure> {
    let signer = ctx.v2_signer("main")?;
    let head = ctx.head("reliance");
    // Derive the repository from a genuine signed operation rather than an
    // implementation-specific repository naming rule.
    let probe = sign_unary(
        &signer,
        Rpc::AdvanceRefs,
        &advance_req(
            (&head, Exp::Missing, &[0; 32]),
            (&ctx.packmap("reliance"), Exp::Missing, &[0; 32]),
        ),
        |_| {},
    );
    let repository = probe.header("x-repository").to_owned();
    let prepared = control
        .command(&Request::PrepareReliance {
            query: RelianceFixtureQuery {
                repository: repository.clone(),
                head: head.clone(),
                signer: signer.public_key_hex(),
            },
        })
        .await?
        .reliance_fixture
        .ok_or("prepare_reliance returned no fixture")?;
    if prepared.pack.len() > 1_048_576 || prepared.packmap_pack.len() > 1_048_576 {
        return Err("oversized reliance fixture".into());
    }
    let mut tickets = Vec::new();
    let (expected_head, expected_map, packs) = if gc {
        // Existing orphaned members have no live ref or pending-ticket root.
        // Creating a new pair newly relies on them without first protecting
        // the base through an uploaded delta's unexpired ticket.
        from_hex(&prepared.base_pack).map_err(|e| e.to_string())?;
        if prepared.base_pack == prepared.base_packmap {
            return Err("GC fixture base and packmap must be distinct members".into());
        }
        (
            prepared.base_head.clone(),
            prepared.base_packmap.clone(),
            vec![prepared.base_pack.clone(), prepared.base_packmap.clone()],
        )
    } else {
        let candidate_map = from_hex(&prepared.packmap).map_err(|e| e.to_string())?;
        let base_pack = from_hex(&prepared.base_pack).map_err(|e| e.to_string())?;
        if prepared.pack.is_empty()
            || prepared.packmap_pack.is_empty()
            || prepared.pack.len() > 1_048_576
            || prepared.packmap_pack.len() > 1_048_576
            || hash(&prepared.packmap_pack) != candidate_map
        {
            return Err("invalid or oversized reliance fixture".into());
        }
        let candidate_pack = to_hex(&hash(&prepared.pack));
        require_external_delta(&prepared.pack)?;
        if candidate_pack == prepared.base_pack {
            return Err("candidate must newly rely on a distinct existing member".into());
        }
        let packlist = mkit_core::transfer::decode_packlist(&prepared.packmap_pack)
            .map_err(|e| format!("reliance fixture packmap: {e}"))?;
        if packlist.prev.is_some()
            || !packlist.packs.contains(&hash(&prepared.pack))
            || !packlist.packs.contains(&base_pack)
        {
            return Err(
                "reliance fixture packmap must independently include candidate and base".into(),
            );
        }
        for pack in [&prepared.pack, &prepared.packmap_pack] {
            let pack_id = hash(pack);
            let open = sign_unary(
                &signer,
                Rpc::BeginUpload,
                &BeginUploadRequest {
                    r#ref: Some(head.clone()),
                    pack_id: Some(pack_id.to_vec()),
                    bytes: Some(pack.len() as u64),
                    ..Default::default()
                },
                |_| {},
            );
            let response: BeginUploadResponse = want_ok(ctx.send(&open).await?, "reliance ticket")?;
            let Some(BeginResult::Ticket(ticket)) = response.result else {
                return Err("reliance fixture requires a fresh ticket".into());
            };
            tickets.push(ticket.id.ok_or("reliance ticket has no id")?);
            let mut messages = upload_msgs(pack, 1);
            if let Some(UploadBody::Header(header)) = &mut messages[0].body {
                header.ticket_token = ticket.token;
            }
            let signed = signer.sign_pack(Rpc::UploadPack.procedure(), &pack_id, pack.len() as u64);
            if let Some(error) = ctx.upload_with(&messages, &signed.headers).await? {
                return Err(format!("reliance fixture upload: {error}").into());
            }
        }
        (
            prepared.head.clone(),
            prepared.packmap.clone(),
            vec![candidate_pack, prepared.base_pack.clone()],
        )
    };
    let candidate_head = from_hex(&expected_head).map_err(|e| e.to_string())?;
    let candidate_map = from_hex(&expected_map).map_err(|e| e.to_string())?;
    let mut request = advance_req(
        (&head, Exp::Missing, &candidate_head),
        (&ctx.packmap("reliance"), Exp::Missing, &candidate_map),
    );
    request.ticket_ids.clone_from(&tickets);
    let operation = sign_unary(&signer, Rpc::AdvanceRefs, &request, |_| {});
    let query = ObservationQuery {
        repository,
        head,
        replay: Some(ReplayIdentity {
            audience: operation.header("x-audience").into(),
            repository: operation.header("x-repository").into(),
            signer: operation.header("x-public-key").into(),
            nonce: operation.nonce.clone(),
        }),
        ticket_ids: tickets
            .iter()
            .map(|id| mkit_core::hash::to_hex_bytes(id))
            .collect(),
        packs,
        quota: ctx.profile().quota.map(|_| crate::control::QuotaQuery {
            signer: signer.public_key_hex(),
            window_start_ms: None,
        }),
        ..Default::default()
    };
    Ok(Fixture {
        operation,
        query,
        head: expected_head,
        packmap: expected_map,
        base: prepared.base_pack,
    })
}

async fn observe(
    control: &ControlClient,
    fixture: &Fixture,
) -> Result<RelianceObservation, Failure> {
    let snapshot = control
        .command(&Request::ObserveReliance {
            query: fixture.query.clone(),
        })
        .await?
        .reliance_observation
        .ok_or("observe_reliance returned no snapshot")?;
    if snapshot.usable_memberships.len() != 2 || snapshot.acceptance.memberships.len() != 2 {
        return Err("reliance snapshot does not preserve query order/cardinality".into());
    }
    Ok(snapshot)
}

async fn prepare_drop(control: &ControlClient, fixture: &Fixture) -> Result<(), Failure> {
    control
        .command(&Request::PrepareGcDrop {
            repository: fixture.query.repository.clone(),
            pack: fixture.base.clone(),
        })
        .await?;
    Ok(())
}

async fn drop_member(control: &ControlClient, fixture: &Fixture) -> Result<String, Failure> {
    let result = control
        .command(&Request::CommitGcDrop {
            repository: fixture.query.repository.clone(),
            pack: fixture.base.clone(),
        })
        .await?
        .gc_drop_result;
    match result.as_deref() {
        Some(result @ ("committed" | "conflict")) => Ok(result.to_owned()),
        _ => Err(format!("GC attempt returned an invalid result: {result:?}").into()),
    }
}

fn gc_result(result: Option<&str>, expected: &str) -> Result<(), Failure> {
    if result != Some(expected) {
        return Err(format!("stale GC attempt expected {expected}, got {result:?}").into());
    }
    Ok(())
}

fn exactly_one(gc_committed: bool, acceptance_committed: bool) -> Result<(), Failure> {
    if gc_committed == acceptance_committed {
        return Err(format!(
            "GC/reliance race needs exactly one winner: GC={gc_committed}, acceptance={acceptance_committed}"
        ).into());
    }
    Ok(())
}

fn dependency_refusal(error: &RpcError, lag_window_open: bool) -> bool {
    match error.code.as_str() {
        "aborted" => true,
        "failed_precondition" => error.message == "delta base not available in this repository",
        "invalid_argument" => matches!(
            error.message.as_str(),
            "open closure" | "packlist lists a pack that is not in this repository"
        ),
        "unavailable" => {
            lag_window_open
                && error.message == "repository membership not yet visible"
                && error.details.len() == 1
                && matches!(
                    error.details[0].0.as_str(),
                    "mkit.transport.v1.MembershipNotVisible"
                        | "type.googleapis.com/mkit.transport.v1.MembershipNotVisible"
                )
                && error.details[0].1.is_empty()
        }
        _ => false,
    }
}

fn no_acceptance(before: &Observation, after: &Observation) -> Result<(), Failure> {
    if before.head != after.head
        || before.packmap != after.packmap
        || before.tickets != after.tickets
        || before.quota != after.quota
        || after.memberships.first() != Some(&false)
        || after
            .replay
            .as_ref()
            .is_some_and(|r| r.result.as_deref() == Some("advance_committed"))
        || after
            .reservations
            .iter()
            .flatten()
            .any(|r| r.state == "committed")
    {
        return Err(format!(
            "removal race left acceptance effects: before={before:?}, after={after:?}"
        )
        .into());
    }
    Ok(())
}

fn accepted(
    snapshot: &RelianceObservation,
    head: &str,
    packmap: &str,
    ticket_count: usize,
) -> Result<(), Failure> {
    let state = &snapshot.acceptance;
    if snapshot.usable_memberships != [true, true]
        || state.memberships != [true, true]
        || state.head.as_deref() != Some(head)
        || state.packmap.as_deref() != Some(packmap)
        || !state.replay.as_ref().is_some_and(|r| {
            r.state == "committed" && r.result.as_deref() == Some("advance_committed")
        })
        || state.tickets.len() != ticket_count
        || state.tickets.iter().any(|ticket| {
            !ticket
                .as_ref()
                .is_some_and(|ticket| ticket.state == "consumed")
        })
        || state.reservations.len() != ticket_count + 1
        || state.reservations.iter().any(|reservation| {
            !reservation.as_ref().is_some_and(|reservation| {
                reservation.state == "committed" && reservation.terminal_count == 1
            })
        })
    {
        return Err(format!(
            "GC invalidated an accepted reliance or acceptance is incomplete: {snapshot:?}"
        )
        .into());
    }
    Ok(())
}

/// Execute one registry case; all mutations use real wire writes or named
/// semantic removal controls. No control reports whether the case passed.
pub(crate) async fn run(name: &str, ctx: Ctx, control: &ControlClient) -> Result<(), Failure> {
    if !matches!(
        name,
        "reliance.gc_drop_after_acceptance"
            | "reliance.gc_drop_before_acceptance"
            | "reliance.verdict_hide_delta_base"
    ) {
        return Err(format!("unknown reliance case {name}").into());
    }
    // Keep ticket age deterministic while the competing protocol decisions run.
    // Wall-clock scheduling cannot close a pinned business-clock lag window.
    let now_ms = ctx.server_now_ms();
    if control.command(&Request::PinClock { now_ms }).await?.now_ms != Some(now_ms) {
        return Err("reliance fixture could not pin the business clock".into());
    }
    let gc_case = name != "reliance.verdict_hide_delta_base";
    let fixture = fixture(&ctx, control, gc_case).await?;
    let before = observe(control, &fixture).await?;
    if before.usable_memberships != [gc_case, true]
        || before.acceptance.head.is_some()
        || before.acceptance.packmap.is_some()
    {
        return Err(
            "reliance fixture must seed only the unique usable base, without candidate refs".into(),
        );
    }
    if name == "reliance.gc_drop_after_acceptance" {
        prepare_drop(control, &fixture).await?;
        let response: AdvanceRefsResponse =
            want_ok(ctx.send(&fixture.operation).await?, "reliance acceptance")?;
        if response.outcome != Some(AdvanceOutcome::ADVANCE_OUTCOME_COMMITTED.into()) {
            return Err("valid reliance fixture did not commit".into());
        }
        let gc = drop_member(control, &fixture).await?;
        gc_result(Some(&gc), "conflict")?;
        let after = observe(control, &fixture).await?;
        return accepted(
            &after,
            &fixture.head,
            &fixture.packmap,
            fixture.query.ticket_ids.len(),
        );
    }
    if name == "reliance.gc_drop_before_acceptance" {
        // Capture the original candidate before acceptance planning can clear
        // its mark. A later mark/recheck would be a different GC attempt.
        prepare_drop(control, &fixture).await?;
    }
    control
        .command(&Request::Pause {
            step: "before_acceptance".into(),
            repository: fixture.query.repository.clone(),
            head: fixture.query.head.clone(),
            decision_class: None,
            occurrence: None,
            on_resume: None,
        })
        .await?;
    let pending = tokio::spawn({
        let ctx = ctx.clone();
        let operation = fixture.operation.clone();
        async move {
            ctx.client()
                .post(
                    operation.rpc.procedure(),
                    "application/proto",
                    &operation.headers,
                    operation.body,
                )
                .await
        }
    });
    control.wait_paused().await?;
    let gc_committed = if name == "reliance.gc_drop_before_acceptance" {
        drop_member(control, &fixture).await? == "committed"
    } else if name == "reliance.verdict_hide_delta_base" {
        control
            .command(&Request::HideMember {
                repository: fixture.query.repository.clone(),
                pack: fixture.base.clone(),
            })
            .await?;
        true
    } else {
        return Err(format!("unknown reliance case {name}").into());
    };
    let removed = observe(control, &fixture).await?;
    if removed.usable_memberships
        != if gc_case {
            vec![!gc_committed, true]
        } else {
            vec![false, false]
        }
    {
        return Err("removal snapshot disagrees with the competing decision".into());
    }
    control.command(&Request::Resume).await?;
    let reply = pending.await.map_err(|e| e.to_string())??;
    let result = crate::wire::client::decode_unary::<AdvanceRefsResponse>(&reply)?;
    let acceptance_committed = result.as_ref().is_ok_and(|response| {
        response.outcome == Some(AdvanceOutcome::ADVANCE_OUTCOME_COMMITTED.into())
    });
    exactly_one(gc_committed, acceptance_committed)?;
    if !gc_committed {
        let after = observe(control, &fixture).await?;
        return accepted(
            &after,
            &fixture.head,
            &fixture.packmap,
            fixture.query.ticket_ids.len(),
        );
    }
    if result
        .as_ref()
        .is_err_and(|error| error.code == "unavailable")
        && reply.headers.contains_key(http::header::RETRY_AFTER)
    {
        return Err("membership-lag refusal must not contain Retry-After".into());
    }
    let lag_window_open = !gc_case && ctx.profile().relay_lag_bound_ms > 0;
    match result {
        Err(error) if dependency_refusal(&error, lag_window_open) => {}
        other => {
            return Err(format!(
                "removed unique external base did not cause a dependency refusal: {other:?}"
            )
            .into());
        }
    }
    let after = observe(control, &fixture).await?;
    if after.usable_memberships
        != if gc_case {
            vec![false, true]
        } else {
            vec![false, false]
        }
    {
        return Err("refused reliance changed usable membership".into());
    }
    no_acceptance(&before.acceptance, &after.acceptance)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::{QuotaView, ReplayView, ReservationView, TicketView};

    fn error(code: &str, message: &str) -> RpcError {
        RpcError {
            code: code.into(),
            message: message.into(),
            http_status: 400,
            details: Vec::new(),
        }
    }

    #[test]
    fn dependency_refusal_requires_the_protocol_class_and_public_text() {
        for (code, message) in [
            ("aborted", "guard contention"),
            (
                "failed_precondition",
                "delta base not available in this repository",
            ),
            ("invalid_argument", "open closure"),
            (
                "invalid_argument",
                "packlist lists a pack that is not in this repository",
            ),
        ] {
            assert!(dependency_refusal(&error(code, message), false));
        }
        for (code, message) in [
            (
                "permission_denied",
                "delta base not available in this repository",
            ),
            ("not_found", "open closure"),
            ("failed_precondition", "unrelated guard"),
            ("invalid_argument", "malformed signature"),
            ("unavailable", "pack verification pending"),
        ] {
            assert!(!dependency_refusal(&error(code, message), true));
        }
    }

    #[test]
    fn membership_lag_requires_an_open_window_and_one_empty_typed_detail() {
        let mut lag = error("unavailable", "repository membership not yet visible");
        assert!(!dependency_refusal(&lag, true));
        lag.details.push((
            "mkit.transport.v1.MembershipNotVisible".into(),
            String::new(),
        ));
        assert!(dependency_refusal(&lag, true));
        assert!(!dependency_refusal(&lag, false));
        lag.details[0].1 = "AA==".into();
        assert!(!dependency_refusal(&lag, true));
        lag.details[0].1.clear();
        lag.details.push(lag.details[0].clone());
        assert!(!dependency_refusal(&lag, true));
        lag.details.pop();
        lag.details[0].0 = "other.Detail".into();
        assert!(!dependency_refusal(&lag, true));
    }

    #[test]
    fn candidate_requires_an_external_delta_not_plain_or_internal_content() {
        use mkit_core::object::{Blob, Object};
        use mkit_core::pack::PackWriter;
        use mkit_core::serialize::serialize;

        let base = serialize(&Object::Blob(Blob {
            data: b"base content".to_vec(),
        }))
        .unwrap();
        let target = serialize(&Object::Blob(Blob {
            data: b"target content".to_vec(),
        }))
        .unwrap();
        let stream = mkit_core::delta::encode(&base, &target).unwrap();
        let mut plain = PackWriter::new();
        plain.push_raw(hash(&base), &base).unwrap();
        assert!(require_external_delta(&plain.finish().unwrap()).is_err());
        let mut internal = PackWriter::new();
        internal.push_raw(hash(&base), &base).unwrap();
        internal.push_delta(&hash(&base), &stream).unwrap();
        assert!(require_external_delta(&internal.finish().unwrap()).is_err());
        let mut external = PackWriter::new();
        external.push_delta(&hash(&base), &stream).unwrap();
        assert!(require_external_delta(&external.finish().unwrap()).is_ok());
        assert!(require_external_delta(b"malformed").is_err());
    }

    fn untouched() -> Observation {
        Observation {
            head: None,
            packmap: None,
            replay: None,
            tickets: Vec::new(),
            reservations: Vec::new(),
            memberships: vec![false, true],
            quota: None,
        }
    }

    #[test]
    fn removal_is_allowed_but_candidate_acceptance_is_not() {
        let before = untouched();
        let mut after = before.clone();
        after.memberships[1] = false;
        after.replay = Some(ReplayView {
            state: "committed".into(),
            result: Some("failed_precondition".into()),
            fingerprint: None,
        });
        assert!(no_acceptance(&before, &after).is_ok());
        after.memberships[0] = true;
        assert!(no_acceptance(&before, &after).is_err());
        let mut before = untouched();
        before.memberships = vec![true, true];
        let mut after = before.clone();
        after.memberships = vec![false, true];
        assert!(no_acceptance(&before, &after).is_ok());
    }

    #[test]
    fn stale_gc_must_report_a_real_conflict() {
        assert!(gc_result(Some("conflict"), "conflict").is_ok());
        assert!(gc_result(Some("committed"), "conflict").is_err());
        assert!(gc_result(None, "conflict").is_err());
    }

    #[test]
    fn competing_gc_and_reliance_require_exactly_one_winner() {
        assert!(exactly_one(true, false).is_ok());
        assert!(exactly_one(false, true).is_ok());
        assert!(exactly_one(true, true).is_err());
        assert!(exactly_one(false, false).is_err());
    }

    #[test]
    fn saved_success_is_an_acceptance_effect_even_without_live_refs() {
        let before = untouched();
        let mut after = before.clone();
        after.replay = Some(ReplayView {
            state: "committed".into(),
            result: Some("advance_committed".into()),
            fingerprint: None,
        });
        assert!(no_acceptance(&before, &after).is_err());
    }

    #[test]
    fn refusal_cannot_consume_charge_or_settle() {
        let before = untouched();
        let mut after = before.clone();
        after.tickets.push(Some(TicketView {
            state: "consumed".into(),
        }));
        assert!(no_acceptance(&before, &after).is_err());
        after = before.clone();
        after.quota = Some(QuotaView { ops: 1, bytes: 1 });
        assert!(no_acceptance(&before, &after).is_err());
        after = before.clone();
        after.reservations.push(Some(ReservationView {
            state: "committed".into(),
            terminal_count: 1,
        }));
        assert!(no_acceptance(&before, &after).is_err());
    }

    #[test]
    fn accepted_reliance_requires_pair_and_complete_atomic_effects() {
        let mut state = untouched();
        state.head = Some("head".into());
        state.packmap = Some("map".into());
        state.memberships = vec![true, true];
        state.replay = Some(ReplayView {
            state: "committed".into(),
            result: Some("advance_committed".into()),
            fingerprint: None,
        });
        state.tickets = vec![
            Some(TicketView {
                state: "consumed".into()
            });
            2
        ];
        state.reservations = vec![
            Some(ReservationView {
                state: "committed".into(),
                terminal_count: 1
            });
            3
        ];
        let complete = RelianceObservation {
            acceptance: state,
            usable_memberships: vec![true, true],
        };
        assert!(accepted(&complete, "head", "map", 2).is_ok());
        let mut ticketless = complete.clone();
        ticketless.acceptance.tickets.clear();
        ticketless.acceptance.reservations.truncate(1);
        assert!(accepted(&ticketless, "head", "map", 0).is_ok());
        assert!(accepted(&ticketless, "head", "map", 2).is_err());
        assert!(accepted(&complete, "head", "map", 0).is_err());
        let mut torn = complete.clone();
        torn.acceptance.packmap = None;
        assert!(accepted(&torn, "head", "map", 2).is_err());
        let mut torn = complete.clone();
        torn.acceptance.tickets[0] = None;
        assert!(accepted(&torn, "head", "map", 2).is_err());
        let mut torn = complete.clone();
        torn.acceptance.reservations[0]
            .as_mut()
            .unwrap()
            .terminal_count = 2;
        assert!(accepted(&torn, "head", "map", 2).is_err());
        let mut torn = complete.clone();
        torn.usable_memberships[1] = false;
        assert!(accepted(&torn, "head", "map", 2).is_err());
    }
}
