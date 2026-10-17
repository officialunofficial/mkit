//! Published-clearance decisions through the portable HTTP control binding.
//! Fixtures enter through signed transport operations; controls only hold future
//! eligibility decisions, drive clearance and observe authoritative state.

use crate::control::{
    ObservationQuery, PublicationObservation, PublicationQuery, ReplayIdentity, Request,
};
use crate::controlled::ControlClient;
use crate::wire::cases::{
    CaseResult, Ctx, Exp, Failure, Signed, advance_req, ensure, sign_unary, single_file_pack,
    upload_msgs, want_ok,
};
use crate::wire::client::Rpc;
use mkit_core::hash::{Hash, hash, to_hex};
use mkit_transport_connect::generated::{
    AdvanceOutcome, AdvanceRefsResponse, BeginUploadRequest, BeginUploadResponse,
};

struct Fixture {
    ctx: Ctx,
    repository: String,
    head: String,
    packmap: String,
}

struct Advance {
    op: Signed,
    tip: Hash,
    packmap: Hash,
    query: PublicationQuery,
}

impl Fixture {
    fn new(ctx: Ctx) -> Result<Self, Failure> {
        let signer = ctx.v2_signer("main")?;
        let probe = sign_unary(
            &signer,
            Rpc::AdvanceRefs,
            &advance_req(
                (&ctx.head("main"), Exp::Missing, &[0; 32]),
                (&ctx.packmap("main"), Exp::Missing, &[0; 32]),
            ),
            |_| {},
        );
        Ok(Self {
            repository: if ctx.profile().has(crate::wire::Feature::MultiRepo) {
                let suffix = to_hex(&hash(ctx.ns().as_bytes()));
                format!(
                    "ed25519-{}/publication-{}",
                    signer.public_key_hex(),
                    &suffix[..16]
                )
            } else {
                probe.header("x-repository").into()
            },
            head: ctx.head("main"),
            packmap: ctx.packmap("main"),
            ctx,
        })
    }

    async fn eligible(&self, control: &ControlClient, eligible: bool) -> CaseResult {
        control
            .command(&Request::SetPublicationEligibility {
                repository: self.repository.clone(),
                head: self.head.clone(),
                eligible,
            })
            .await?;
        Ok(())
    }

    async fn advance(&self, ordinal: u8, previous: Option<&Advance>) -> Result<Advance, Failure> {
        let (pack, tip, _) = single_file_pack(
            b"publication.txt",
            format!("{}:{ordinal}", self.ctx.ns()).as_bytes(),
        )?;
        let pack_id = hash(&pack);
        let node =
            mkit_core::transfer::encode_packlist(None, &[pack_id]).map_err(|e| e.to_string())?;
        let packmap = hash(&node);
        let tickets = vec![self.upload(&pack).await?, self.upload(&node).await?];
        let mut request = advance_req(
            (
                &self.head,
                previous.map_or(Exp::Missing, |p| Exp::Match(&p.tip)),
                &tip,
            ),
            (
                &self.packmap,
                previous.map_or(Exp::Missing, |p| Exp::Match(&p.packmap)),
                &packmap,
            ),
        );
        request.ticket_ids.clone_from(&tickets);
        let signer = self.ctx.v2_signer("main")?;
        let op = sign_unary(&signer, Rpc::AdvanceRefs, &request, |env| {
            self.repository.clone_into(&mut env.repository);
        });
        let query = PublicationQuery {
            acceptance: ObservationQuery {
                repository: self.repository.clone(),
                head: self.head.clone(),
                replay: Some(ReplayIdentity {
                    audience: op.header("x-audience").into(),
                    repository: self.repository.clone(),
                    signer: signer.public_key_hex(),
                    nonce: op.nonce.clone(),
                }),
                ticket_ids: tickets
                    .iter()
                    .map(|id| mkit_core::hash::to_hex_bytes(id))
                    .collect(),
                packs: vec![to_hex(&pack_id), to_hex(&packmap)],
                quota: self
                    .ctx
                    .profile()
                    .quota
                    .map(|_| crate::control::QuotaQuery {
                        signer: signer.public_key_hex(),
                        window_start_ms: None,
                    }),
                ..Default::default()
            },
        };
        Ok(Advance {
            op,
            tip,
            packmap,
            query,
        })
    }

    async fn upload(&self, pack: &[u8]) -> Result<Vec<u8>, Failure> {
        let signer = self.ctx.v2_signer("main")?;
        let pack_id = hash(pack);
        let request = sign_unary(
            &signer,
            Rpc::BeginUpload,
            &BeginUploadRequest {
                r#ref: Some(self.head.clone()),
                pack_id: Some(pack_id.to_vec()),
                bytes: Some(pack.len() as u64),
                ..Default::default()
            },
            |env| self.repository.clone_into(&mut env.repository),
        );
        let reply: BeginUploadResponse =
            want_ok(self.ctx.send(&request).await?, "publication ticket")?;
        let Some(mkit_transport_connect::generated::__buffa::oneof::begin_upload_response::Result::Ticket(ticket)) = reply.result else { return Err("publication fixture expected ticket".into()); };
        let id = ticket.id.ok_or("publication ticket has no ID")?;
        let mut messages = upload_msgs(pack, 1);
        if let Some(
            mkit_transport_connect::generated::__buffa::oneof::upload_pack_request::Body::Header(
                header,
            ),
        ) = &mut messages[0].body
        {
            header.ticket_token = ticket.token;
        }
        let mut envelope = signer.envelope(
            Rpc::UploadPack.procedure(),
            crate::wire::sign::pack_commitment(&pack_id, pack.len() as u64),
        );
        self.repository.clone_into(&mut envelope.repository);
        let upload_request = signer.sign(&envelope);
        ensure!(
            self.ctx
                .upload_with(&messages, &upload_request.headers)
                .await?
                .is_none(),
            "publication fixture upload failed"
        );
        Ok(id)
    }

    async fn accept(&self, advance: &Advance) -> CaseResult {
        let reply: AdvanceRefsResponse =
            want_ok(self.ctx.send(&advance.op).await?, "publication acceptance")?;
        ensure!(
            reply.outcome == Some(AdvanceOutcome::ADVANCE_OUTCOME_COMMITTED.into()),
            "publication acceptance did not commit: {reply:?}"
        );
        Ok(())
    }

    async fn drive(&self, control: &ControlClient) -> CaseResult {
        control
            .command(&Request::AdvanceClock { delta_ms: 6_000 })
            .await?;
        control
            .command(&Request::DrivePublication {
                repository: self.repository.clone(),
                head: self.head.clone(),
            })
            .await?;
        Ok(())
    }

    async fn pause(&self, control: &ControlClient, step: &str) -> CaseResult {
        control
            .command(&Request::Pause {
                step: step.into(),
                repository: self.repository.clone(),
                head: self.head.clone(),
                decision_class: None,
                occurrence: None,
                on_resume: None,
            })
            .await?;
        Ok(())
    }

    async fn delete(&self, advance: &Advance) -> CaseResult {
        let mut request = advance_req(
            (&self.head, Exp::Match(&advance.tip), &advance.tip),
            (
                &self.packmap,
                Exp::Match(&advance.packmap),
                &advance.packmap,
            ),
        );
        request.head_new_id = None;
        request.packmap_new_id = None;
        request.delete = Some(true);
        let signer = self.ctx.v2_signer("main")?;
        let op = sign_unary(&signer, Rpc::AdvanceRefs, &request, |env| {
            self.repository.clone_into(&mut env.repository);
        });
        let reply: AdvanceRefsResponse = want_ok(self.ctx.send(&op).await?, "paired deletion")?;
        ensure!(
            reply.outcome == Some(AdvanceOutcome::ADVANCE_OUTCOME_COMMITTED.into()),
            "paired deletion did not commit"
        );
        Ok(())
    }

    async fn recreate(&self, advance: &Advance) -> CaseResult {
        let request = advance_req(
            (&self.head, Exp::Missing, &advance.tip),
            (&self.packmap, Exp::Missing, &advance.packmap),
        );
        let signer = self.ctx.v2_signer("main")?;
        let op = sign_unary(&signer, Rpc::AdvanceRefs, &request, |env| {
            self.repository.clone_into(&mut env.repository);
        });
        let reply: AdvanceRefsResponse = want_ok(self.ctx.send(&op).await?, "paired recreation")?;
        ensure!(
            reply.outcome == Some(AdvanceOutcome::ADVANCE_OUTCOME_COMMITTED.into()),
            "paired recreation did not commit"
        );
        Ok(())
    }
}

async fn observe(
    control: &ControlClient,
    advance: &Advance,
) -> Result<PublicationObservation, Failure> {
    let snapshot = control
        .command(&Request::ObservePublication {
            query: advance.query.clone(),
        })
        .await?
        .publication_observation
        .ok_or("publication observation missing")?;
    ensure!(
        snapshot.acceptance.memberships.len() == 2 && snapshot.published_memberships.len() == 2,
        "publication observation changed membership query length"
    );
    ensure!(
        snapshot.published_head.is_some() == snapshot.published_packmap.is_some(),
        "torn published pair: {snapshot:?}"
    );
    ensure!(
        snapshot.published_sequence <= snapshot.live_sequence,
        "published prefix exceeds accepted prefix: {snapshot:?}"
    );
    Ok(snapshot)
}

fn accepted(snapshot: &PublicationObservation, advance: &Advance) -> CaseResult {
    let state = &snapshot.acceptance;
    ensure!(
        state.head == Some(to_hex(&advance.tip)) && state.packmap == Some(to_hex(&advance.packmap)),
        "accepted live pair missing: {snapshot:?}"
    );
    ensure!(
        state.replay.as_ref().is_some_and(|r| r.state == "committed"
            && r.result.as_deref() == Some("advance_committed")
            && r.fingerprint.as_ref().is_some_and(|f| !f.is_empty()))
            && state.memberships == [true, true],
        "acceptance replay/membership missing: {snapshot:?}"
    );
    ensure!(
        state.tickets.len() == 2
            && state
                .tickets
                .iter()
                .all(|t| t.as_ref().is_some_and(|t| t.state == "consumed")),
        "acceptance tickets not consumed: {snapshot:?}"
    );
    ensure!(
        state.reservations.len() == 3
            && state.reservations.iter().all(|r| r
                .as_ref()
                .is_some_and(|r| r.state == "committed" && r.terminal_count == 1)),
        "acceptance terminal responsibility missing or duplicated: {snapshot:?}"
    );
    Ok(())
}

fn published(snapshot: &PublicationObservation, advance: &Advance) -> CaseResult {
    ensure!(
        snapshot.published_head == Some(to_hex(&advance.tip))
            && snapshot.published_packmap == Some(to_hex(&advance.packmap))
            && snapshot.published_memberships == [true, true],
        "published pair/members not atomic: {snapshot:?}"
    );
    ensure!(
        snapshot.published_sequence == snapshot.live_sequence,
        "largest eligible prefix not published: {snapshot:?}"
    );
    Ok(())
}

fn same_settlement(before: &PublicationObservation, after: &PublicationObservation) -> CaseResult {
    ensure!(
        before.acceptance == after.acceptance,
        "clearance repeated or changed acceptance effects: before={before:?}, after={after:?}"
    );
    Ok(())
}

async fn deferred(ctx: Ctx, control: &ControlClient) -> CaseResult {
    let fixture = Fixture::new(ctx)?;
    fixture.eligible(control, false).await?;
    let advance = fixture.advance(1, None).await?;
    fixture.accept(&advance).await?;
    let held = observe(control, &advance).await?;
    accepted(&held, &advance)?;
    ensure!(
        held.published_head.is_none() && held.published_memberships == [false, false],
        "ineligible acceptance published: {held:?}"
    );
    control
        .command(&Request::Restart {
            mode: "graceful".into(),
        })
        .await?;
    let recovered = observe(control, &advance).await?;
    ensure!(
        recovered == held,
        "restart changed deferred state before replay: {recovered:?}"
    );
    fixture.eligible(control, true).await?;
    control
        .command(&Request::AdvanceClock { delta_ms: 6_000 })
        .await?;
    fixture.pause(control, "before_published_clearance").await?;
    let drive = tokio::spawn({
        let control = control.clone();
        let repository = fixture.repository.clone();
        let branch = fixture.head.clone();
        async move {
            control
                .command(&Request::DrivePublication {
                    repository,
                    head: branch,
                })
                .await
        }
    });
    control.wait_paused().await?;
    ensure!(
        observe(control, &advance).await? == held,
        "clearance effects visible before commit"
    );
    control.command(&Request::Resume).await?;
    drive.await.map_err(|e| e.to_string())??;
    let cleared = observe(control, &advance).await?;
    same_settlement(&held, &cleared)?;
    published(&cleared, &advance)?;
    fixture.drive(control).await?;
    fixture.accept(&advance).await?;
    ensure!(
        observe(control, &advance).await? == cleared,
        "repeat clearance/replay changed accepted state"
    );
    Ok(())
}

async fn out_of_order(ctx: Ctx, control: &ControlClient) -> CaseResult {
    let fixture = Fixture::new(ctx)?;
    fixture.eligible(control, false).await?;
    let first = fixture.advance(1, None).await?;
    fixture.accept(&first).await?;
    fixture.eligible(control, true).await?;
    let second = fixture.advance(2, Some(&first)).await?;
    fixture.accept(&second).await?;
    let pending = observe(control, &second).await?;
    accepted(&pending, &second)?;
    ensure!(
        pending.published_head.is_none(),
        "later eligible advance crossed ineligible prefix: {pending:?}"
    );
    fixture.drive(control).await?;
    let cleared = observe(control, &second).await?;
    same_settlement(&pending, &cleared)?;
    published(&cleared, &second)?;
    let earlier = observe(control, &first).await?;
    ensure!(
        earlier.published_memberships == [true, true],
        "prefix clearance omitted earlier eligible membership: {earlier:?}"
    );
    Ok(())
}

async fn deletion(ctx: Ctx, control: &ControlClient) -> CaseResult {
    let fixture = Fixture::new(ctx)?;
    fixture.eligible(control, false).await?;
    let advance = fixture.advance(1, None).await?;
    fixture.accept(&advance).await?;
    fixture.delete(&advance).await?;
    let deleted = observe(control, &advance).await?;
    ensure!(
        deleted.acceptance.head.is_none() && deleted.published_head.is_none(),
        "deletion retained a ref: {deleted:?}"
    );
    fixture.eligible(control, true).await?;
    fixture.drive(control).await?;
    let after = observe(control, &advance).await?;
    ensure!(
        after.acceptance.head.is_none()
            && after.published_head.is_none()
            && after.published_packmap.is_none()
            && after.deletion_boundary == deleted.deletion_boundary,
        "old clearance crossed deletion boundary: {after:?}"
    );
    same_settlement(&deleted, &after)?;
    fixture.recreate(&advance).await?;
    let recreated = observe(control, &advance).await?;
    ensure!(
        recreated.deletion_boundary == deleted.deletion_boundary,
        "recreation reset deletion boundary"
    );
    published(&recreated, &advance)?;
    Ok(())
}

async fn combined(ctx: Ctx, control: &ControlClient) -> CaseResult {
    let fixture = Fixture::new(ctx)?;
    fixture.eligible(control, true).await?;
    let advance = fixture.advance(1, None).await?;
    fixture.accept(&advance).await?;
    let snapshot = observe(control, &advance).await?;
    accepted(&snapshot, &advance)?;
    published(&snapshot, &advance)?;
    fixture.accept(&advance).await?;
    ensure!(
        observe(control, &advance).await? == snapshot,
        "combined replay repeated acceptance or clearance"
    );
    Ok(())
}

async fn combined_race(ctx: Ctx, control: &ControlClient) -> CaseResult {
    let fixture = Fixture::new(ctx)?;
    fixture.eligible(control, true).await?;
    let first = fixture.advance(1, None).await?;
    fixture.accept(&first).await?;
    let candidate = fixture.advance(2, Some(&first)).await?;
    fixture.pause(control, "before_acceptance").await?;
    let pending = tokio::spawn({
        let ctx = fixture.ctx.clone();
        let op = candidate.op.clone();
        async move { ctx.send::<AdvanceRefsResponse>(&op).await }
    });
    control.wait_paused().await?;
    fixture.delete(&first).await?;
    fixture.recreate(&first).await?;
    let recreated = observe(control, &candidate).await?;
    control.command(&Request::Resume).await?;
    let result = pending.await.map_err(|e| e.to_string())??;
    let after = observe(control, &candidate).await?;
    match result {
        Ok(reply) if reply.outcome == Some(AdvanceOutcome::ADVANCE_OUTCOME_COMMITTED.into()) => {
            // A fresh decision may accept after recreation. Its publication must
            // retain that incarnation's deletion boundary and full pair.
            ensure!(
                after.deletion_boundary == recreated.deletion_boundary,
                "replanned acceptance lost deletion boundary"
            );
            accepted(&after, &candidate)?;
            if after.published_head == Some(to_hex(&candidate.tip)) {
                published(&after, &candidate)?;
            } else {
                ensure!(
                    after.published_head == recreated.published_head
                        && after.published_packmap == recreated.published_packmap
                        && after.published_memberships == [false, false],
                    "fallback changed published pair"
                );
            }
        }
        Err(error) => {
            ensure!(
                matches!(error.code.as_str(), "aborted" | "failed_precondition"),
                "combined race returned wrong refusal: {error}"
            );
            ensure!(
                after.acceptance.head == recreated.acceptance.head
                    && after.published_head == recreated.published_head
                    && after.published_packmap == recreated.published_packmap
                    && after.deletion_boundary == recreated.deletion_boundary
                    && after.published_memberships == [false, false]
                    && after.acceptance.memberships == [false, false]
                    && after.acceptance.tickets == recreated.acceptance.tickets
                    && after.acceptance.quota == recreated.acceptance.quota
                    && after
                        .acceptance
                        .replay
                        .as_ref()
                        .is_none_or(|r| r.result.as_deref() != Some("advance_committed"))
                    && after.acceptance.reservations.iter().take(2).eq(recreated
                        .acceptance
                        .reservations
                        .iter()
                        .take(2)),
                "failed combined commit exposed candidate: {after:?}"
            );
        }
        other => return Err(format!("unexpected combined race result: {other:?}").into()),
    }
    Ok(())
}

pub(crate) async fn run(name: &str, ctx: Ctx, control: &ControlClient) -> CaseResult {
    match name {
        "publication.deferred_restart_no_resettlement" => deferred(ctx, control).await,
        "publication.out_of_order_prefix" => out_of_order(ctx, control).await,
        "publication.deletion_boundary" => deletion(ctx, control).await,
        "publication.combined_acceptance" => combined(ctx, control).await,
        "publication.combined_deletion_race" => combined_race(ctx, control).await,
        _ => unreachable!("registered publication case"),
    }
}
