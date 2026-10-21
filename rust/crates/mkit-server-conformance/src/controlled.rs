//! Tier 2: server-control conformance over the test-only versioned HTTP binding.
//! The caller declares every expected skip; an undeclared skip or a declared
//! case that passes is a failure, matching the optional storage suite.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use mkit_core::hash::{Hash, hash, to_hex};
use mkit_transport_connect::generated::{
    AdvanceOutcome, AdvanceRefsResponse, BeginUploadRequest, BeginUploadResponse, UpdateRefResponse,
};

use crate::control::{
    self, Capabilities, Observation, ObservationQuery, ReplayIdentity, Request, ReservationView,
    Response,
};
use crate::wire::cases::{
    Ctx, Exp, Failure, Signed, advance_req, chained_file_pack, sign_unary, update_req, upload_msgs,
    want_code, want_ok,
};
use crate::wire::client::{Client, Rpc};
use crate::wire::sign::Signer;
use crate::wire::{CaseReport, Feature, Report, Verdict, WireTarget};

/// A negotiated test-control client. Construction does not enable routes on
/// the server; the server must already be an isolated, test-only build.
#[derive(Debug, Clone)]
pub struct ControlClient(Client);

impl ControlClient {
    /// Connect to the test binding at the server's base URL.
    /// # Errors
    /// Returns an error when URL/client construction fails.
    pub fn new(base_url: &url::Url) -> Result<Self, String> {
        Client::new(base_url).map(Self)
    }

    /// Negotiate exactly version 1; absent routes or malformed responses fail.
    /// # Errors
    /// HTTP, transport, JSON, or version errors.
    pub async fn capabilities(&self) -> Result<Capabilities, String> {
        let reply = self.0.get(control::CAPABILITIES_PATH).await?;
        if reply.status != 200 {
            return Err(format!("test-control negotiation: HTTP {}", reply.status));
        }
        let caps: Capabilities = serde_json::from_slice(&reply.body).map_err(|e| e.to_string())?;
        if caps.version != control::VERSION {
            return Err(format!("unsupported test-control version {}", caps.version));
        }
        if caps.durability_profile.trim().is_empty()
            || caps
                .unsupported
                .values()
                .any(|reason| reason.trim().is_empty())
        {
            return Err("test-control capabilities require a durability profile and nonempty unsupported reasons".into());
        }
        for name in &caps.controls {
            if caps.unsupported.contains_key(name) {
                return Err(format!(
                    "test control {name} is both supported and unsupported"
                ));
            }
        }
        Ok(caps)
    }

    /// Execute one command, requiring HTTP 200 and valid typed JSON.
    /// # Errors
    /// HTTP, transport, or JSON errors; unsupported controls are never success.
    pub async fn command(&self, request: &Request) -> Result<Response, String> {
        let body = serde_json::to_vec(request).map_err(|e| e.to_string())?;
        let reply = self
            .0
            .post(control::CONTROL_PATH, "application/json", &[], body)
            .await?;
        if reply.status != 200 {
            return Err(format!("test-control command: HTTP {}", reply.status));
        }
        serde_json::from_slice(&reply.body).map_err(|e| e.to_string())
    }

    pub(crate) async fn observe(&self, query: &ObservationQuery) -> Result<Observation, String> {
        self.command(&Request::Observe {
            query: query.clone(),
        })
        .await?
        .observation
        .ok_or_else(|| "observe returned no snapshot".to_owned())
    }

    pub(crate) async fn wait_paused(&self) -> Result<(), String> {
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                if self.command(&Request::BarrierStatus).await?.paused {
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .map_err(|_| "operation did not reach its armed barrier".to_owned())?
    }
}

/// Stable server-control cases and their capability requirements.
#[derive(Debug, Clone, Copy)]
pub struct Case {
    /// TAP case name.
    pub name: &'static str,
    /// Required test controls. Missing controls must have declared skip reasons.
    pub controls: &'static [&'static str],
    /// Wire capabilities required in the supplied profile.
    pub features: &'static [Feature],
}

const ACCEPT: &[Feature] = &[
    Feature::TransportWrites,
    Feature::AuthV2,
    Feature::Replay,
    Feature::AtomicAdvance,
    Feature::Tickets,
];
const FENCED_ACCEPT: &[Feature] = &[
    Feature::TransportWrites,
    Feature::AuthV2,
    Feature::Replay,
    Feature::AtomicAdvance,
    Feature::Tickets,
    Feature::AuthorityFencing,
];
const FENCED_FORK: &[Feature] = &[
    Feature::TransportWrites,
    Feature::Fork,
    Feature::AuthV2,
    Feature::Replay,
    Feature::MultiRepo,
    Feature::AuthorityFencing,
];
const FORK: &[Feature] = &[
    Feature::TransportWrites,
    Feature::Fork,
    Feature::AuthV2,
    Feature::Replay,
    Feature::MultiRepo,
];

const PUBLICATION: &[Feature] = &[
    Feature::TransportWrites,
    Feature::AuthV2,
    Feature::Replay,
    Feature::AtomicAdvance,
    Feature::Tickets,
    Feature::IndexedMode,
];

const COMBINED_PUBLICATION: &[Feature] = &[
    Feature::TransportWrites,
    Feature::AuthV2,
    Feature::Replay,
    Feature::AtomicAdvance,
    Feature::Tickets,
    Feature::IndexedMode,
    Feature::CombinedPublication,
];

const GC_RELIANCE: &[Feature] = &[
    Feature::TransportWrites,
    Feature::AuthV2,
    Feature::Replay,
    Feature::AtomicAdvance,
    Feature::Gc,
];

const INSPECTION_RELIANCE: &[Feature] = &[
    Feature::TransportWrites,
    Feature::AuthV2,
    Feature::Replay,
    Feature::AtomicAdvance,
    Feature::Tickets,
    Feature::IndexedMode,
    Feature::AsyncInspection,
];

/// Tier-2 registry. Composition cases are planned until its seam exists.
pub const CASES: &[Case] = &[
    Case {
        name: "publication.deferred_restart_no_resettlement",
        controls: &[
            "observe.publication",
            "publication.eligibility",
            "publication.drive",
            "fixture.indexed_refs",
            "fixture.ref_reservation",
            "restart.graceful",
            "pause.before_published_clearance",
            "clock.advance",
        ],
        features: PUBLICATION,
    },
    Case {
        name: "publication.out_of_order_prefix",
        controls: &[
            "observe.publication",
            "publication.eligibility",
            "publication.drive",
            "fixture.indexed_refs",
            "fixture.ref_reservation",
            "clock.advance",
        ],
        features: PUBLICATION,
    },
    Case {
        name: "publication.deletion_boundary",
        controls: &[
            "observe.publication",
            "publication.eligibility",
            "publication.drive",
            "fixture.indexed_refs",
            "fixture.ref_reservation",
            "clock.advance",
        ],
        features: PUBLICATION,
    },
    Case {
        name: "publication.combined_acceptance",
        controls: &[
            "observe.publication",
            "publication.eligibility",
            "fixture.indexed_refs",
            "fixture.ref_reservation",
        ],
        features: COMBINED_PUBLICATION,
    },
    Case {
        name: "publication.combined_deletion_race",
        controls: &[
            "observe.publication",
            "publication.eligibility",
            "fixture.indexed_refs",
            "fixture.ref_reservation",
            "pause.before_acceptance",
        ],
        features: COMBINED_PUBLICATION,
    },
    Case {
        name: "reliance.gc_drop_before_acceptance",
        controls: &[
            "reliance.fixture",
            "clock.pin",
            "reliance.observe",
            "fixture.ref_reservation",
            "pause.before_acceptance",
            "gc.prepare_drop",
            "gc.commit_drop",
        ],
        features: GC_RELIANCE,
    },
    Case {
        name: "reliance.gc_drop_after_acceptance",
        controls: &[
            "reliance.fixture",
            "clock.pin",
            "reliance.observe",
            "fixture.ref_reservation",
            "gc.prepare_drop",
            "gc.commit_drop",
        ],
        features: GC_RELIANCE,
    },
    Case {
        name: "reliance.verdict_hide_delta_base",
        controls: &[
            "reliance.fixture",
            "clock.pin",
            "reliance.observe",
            "fixture.ref_reservation",
            "pause.before_acceptance",
            "inspection.hide_member",
        ],
        features: INSPECTION_RELIANCE,
    },
    Case {
        name: "authority.setter_disabled",
        controls: &[],
        features: &[],
    },
    Case {
        name: "authority.setter_enabled",
        controls: &["authority.setter_fixture"],
        features: &[Feature::AuthoritySetter],
    },
    Case {
        name: "acceptance.before_acceptance_restart",
        controls: &["observe", "restart.graceful", "pause.before_acceptance"],
        features: ACCEPT,
    },
    Case {
        name: "acceptance.after_durable_acceptance_restart",
        controls: &[
            "observe",
            "restart.graceful",
            "pause.after_durable_acceptance_before_response",
        ],
        features: ACCEPT,
    },
    Case {
        name: "acceptance.after_response_restart",
        controls: &["observe", "restart.graceful"],
        features: ACCEPT,
    },
    Case {
        name: "acceptance.kill_recovery",
        controls: &[
            "observe",
            "restart.kill",
            "pause.after_durable_acceptance_before_response",
        ],
        features: ACCEPT,
    },
    Case {
        name: "recovery.uncertain_commit",
        controls: &["observe", "fault.uncertain_result"],
        features: ACCEPT,
    },
    Case {
        name: "guard.authority_final_boundary",
        controls: &["observe", "authority.bump", "pause.before_acceptance"],
        features: FENCED_ACCEPT,
    },
    Case {
        name: "replay.moves_and_generation",
        controls: &["observe", "authority.bump"],
        features: FENCED_ACCEPT,
    },
    Case {
        name: "fork.destination_gate_before_acceptance",
        controls: &[
            "fork.fixture",
            "fork.observe",
            "fork.invoke",
            "fork.destination_gate",
            "pause.before_acceptance",
            "decision.fork_acceptance",
        ],
        features: FORK,
    },
    Case {
        name: "fork.writer_against_registration",
        controls: &[
            "fork.fixture",
            "fork.invoke",
            "fork.observe",
            "fork.destination_gate",
            "pause.before_acceptance",
            "decision.fork_destination_claim",
        ],
        features: FORK,
    },
    Case {
        name: "fork.writer_against_acceptance",
        controls: &[
            "fork.fixture",
            "fork.invoke",
            "fork.observe",
            "fork.destination_gate",
            "pause.before_acceptance",
            "decision.fork_acceptance",
        ],
        features: FORK,
    },
    Case {
        name: "fork.leased_writer_against_registration",
        controls: &[
            "fork.fixture",
            "fork.invoke",
            "fork.observe",
            "fork.destination_gate",
            "pause.before_acceptance",
            "decision.writer_authority_ready",
        ],
        features: FORK,
    },
    Case {
        name: "fork.failed_destination_inert",
        controls: &[
            "clock.advance",
            "clock.pin",
            "restart.graceful",
            "fork.fixture",
            "fork.observe",
            "fork.invoke",
            "fork.destination_gate",
            "authority.bump",
            "fork.authority_fence",
            "pause.before_acceptance",
            "decision.fork_acceptance",
        ],
        features: FENCED_FORK,
    },
    Case {
        name: "fork.acceptance_result_replay_outcome_atomic",
        controls: &[
            "fork.fixture",
            "fork.observe",
            "fork.invoke",
            "pause.after_durable_acceptance_before_response",
            "decision.fork_acceptance",
        ],
        features: FORK,
    },
    Case {
        name: "fork.authority_at_acceptance",
        controls: &[
            "fork.fixture",
            "fork.observe",
            "fork.invoke",
            "authority.bump",
            "fork.authority_fence",
            "pause.before_acceptance",
            "decision.fork_acceptance",
        ],
        features: FENCED_FORK,
    },
    Case {
        name: "fork.authority_each_progress_commit",
        controls: &[
            "fork.fixture",
            "fork.observe",
            "fork.invoke",
            "authority.bump",
            "fork.authority_fence",
            "pause.before_acceptance",
            "decision.fork_progress",
        ],
        features: FENCED_FORK,
    },
    Case {
        name: "fork.source_moved_before_acceptance",
        controls: &[
            "fork.fixture",
            "fork.observe",
            "fork.invoke",
            "fork.final_source_proof",
            "fork.source_change.moved",
            "pause.before_acceptance",
            "decision.fork_source_proof",
        ],
        features: FORK,
    },
    Case {
        name: "fork.source_moved_after_acceptance",
        controls: &[
            "fork.fixture",
            "fork.observe",
            "fork.invoke",
            "fork.final_source_proof",
            "fork.source_change.moved",
            "pause.after_durable_acceptance_before_response",
            "decision.fork_acceptance",
        ],
        features: FORK,
    },
    Case {
        name: "fork.source_unpublished_before_acceptance",
        controls: &[
            "fork.fixture",
            "fork.observe",
            "fork.invoke",
            "fork.final_source_proof",
            "fork.source_change.unpublished",
            "pause.before_acceptance",
            "decision.fork_source_proof",
        ],
        features: FORK,
    },
    Case {
        name: "fork.source_unpublished_after_acceptance",
        controls: &[
            "fork.fixture",
            "fork.observe",
            "fork.invoke",
            "fork.final_source_proof",
            "fork.source_change.unpublished",
            "pause.after_durable_acceptance_before_response",
            "decision.fork_acceptance",
        ],
        features: FORK,
    },
    Case {
        name: "fork.source_visibility_revoked_before_acceptance",
        controls: &[
            "fork.fixture",
            "fork.observe",
            "fork.invoke",
            "fork.final_source_proof",
            "fork.source_change.visibility_revoked",
            "pause.before_acceptance",
            "decision.fork_source_proof",
        ],
        features: FORK,
    },
    Case {
        name: "fork.source_visibility_revoked_after_acceptance",
        controls: &[
            "fork.fixture",
            "fork.observe",
            "fork.invoke",
            "fork.final_source_proof",
            "fork.source_change.visibility_revoked",
            "pause.after_durable_acceptance_before_response",
            "decision.fork_acceptance",
        ],
        features: FORK,
    },
    Case {
        name: "fork.source_denied_before_acceptance",
        controls: &[
            "fork.fixture",
            "fork.observe",
            "fork.invoke",
            "fork.final_source_proof",
            "fork.source_change.denied",
            "pause.before_acceptance",
            "decision.fork_source_proof",
        ],
        features: FORK,
    },
    Case {
        name: "fork.source_denied_after_acceptance",
        controls: &[
            "fork.fixture",
            "fork.observe",
            "fork.invoke",
            "fork.final_source_proof",
            "fork.source_change.denied",
            "pause.after_durable_acceptance_before_response",
            "decision.fork_acceptance",
        ],
        features: FORK,
    },
    Case {
        name: "pack_locations.guard_refusals",
        controls: &["pack-locations.fixture", "clock.advance"],
        features: &[Feature::PackLocations],
    },
    Case {
        name: "pack_locations.corrupt_location_fallback",
        controls: &["pack-locations.fixture", "clock.advance"],
        features: &[Feature::PackLocations],
    },
    Case {
        name: "pack_locations.denial_after_issue_bound",
        controls: &["pack-locations.fixture", "clock.advance"],
        features: &[Feature::PackLocations],
    },
];

fn identity(op: &Signed) -> ReplayIdentity {
    ReplayIdentity {
        audience: op.header("x-audience").into(),
        repository: op.header("x-repository").into(),
        signer: op.header("x-public-key").into(),
        nonce: op.nonce.clone(),
    }
}

struct Fixture {
    ctx: Ctx,
    op: Signed,
    query: ObservationQuery,
    tip: Hash,
    packmap: Hash,
}

/// A real advance target: a commit pack plus the packmap node listing it.
struct Target {
    pack: Vec<u8>,
    node: Vec<u8>,
    tip: Hash,
    packmap: Hash,
}

/// Build `Target` from a real single-file pack; `parents` chain commit
/// ancestry and `previous` chains the packmap node.
fn target(
    path: &[u8],
    data: &[u8],
    parents: &[Hash],
    previous: Option<Hash>,
) -> Result<Target, Failure> {
    let (pack, tip, _) = chained_file_pack(path, data, parents)?;
    let node = mkit_core::transfer::encode_packlist(previous, &[hash(&pack)])
        .map_err(|e| e.to_string())?;
    Ok(Target {
        packmap: hash(&node),
        node,
        pack,
        tip,
    })
}

/// A signed paired advance plus the ticket IDs and pack IDs it spends.
struct Prepared {
    op: Signed,
    tickets: Vec<Vec<u8>>,
    packs: Vec<String>,
}

/// Upload `target`'s pack and packmap node through signed, ticketed
/// `UploadPack` calls on `head`, then sign the paired advance spending them.
async fn prepare(
    ctx: &Ctx,
    signer: &Signer,
    head: &str,
    packmap: &str,
    head_exp: Exp<'_>,
    packmap_exp: Exp<'_>,
    target: &Target,
) -> Result<Prepared, Failure> {
    let mut tickets = Vec::new();
    let mut packs = Vec::new();
    for bytes in [&target.pack, &target.node] {
        let pack_id = hash(bytes);
        let begin = sign_unary(
            signer,
            Rpc::BeginUpload,
            &BeginUploadRequest {
                r#ref: Some(head.to_owned()),
                pack_id: Some(pack_id.to_vec()),
                bytes: Some(bytes.len() as u64),
                ..Default::default()
            },
            |_| {},
        );
        let response: BeginUploadResponse = want_ok(ctx.send(&begin).await?, "open ticket")?;
        let Some(mkit_transport_connect::generated::__buffa::oneof::begin_upload_response::Result::Ticket(ticket)) = response.result else {
            return Err(Failure::Fail("fixture expected a new ticket".into()));
        };
        let id = ticket
            .id
            .ok_or_else(|| Failure::Fail("ticket has no ID".into()))?;
        let mut messages = upload_msgs(bytes, 1);
        if let Some(
            mkit_transport_connect::generated::__buffa::oneof::upload_pack_request::Body::Header(
                header,
            ),
        ) = &mut messages[0].body
        {
            header.ticket_token = ticket.token;
        }
        let upload = signer.sign_pack(Rpc::UploadPack.procedure(), &pack_id, bytes.len() as u64);
        if let Some(error) = ctx.upload_with(&messages, &upload.headers).await? {
            return Err(Failure::Fail(format!("fixture upload: {error}")));
        }
        tickets.push(id);
        packs.push(to_hex(&pack_id));
    }
    let mut req = advance_req(
        (head, head_exp, &target.tip),
        (packmap, packmap_exp, &target.packmap),
    );
    req.ticket_ids.clone_from(&tickets);
    let op = sign_unary(signer, Rpc::AdvanceRefs, &req, |_| {});
    Ok(Prepared { op, tickets, packs })
}

/// The shared acceptance fixture: one real commit pack and its packmap node,
/// uploaded through ticketed `UploadPack` and advanced on `main`.
async fn fixture(ctx: Ctx) -> Result<Fixture, Failure> {
    let signer = ctx.v2_signer("main")?;
    let head = ctx.head("main");
    let target = target(
        b"fixture.txt",
        format!("{}:fixture", ctx.ns()).as_bytes(),
        &[],
        None,
    )?;
    let prepared = prepare(
        &ctx,
        &signer,
        &head,
        &ctx.packmap("main"),
        Exp::Missing,
        Exp::Missing,
        &target,
    )
    .await?;
    let query = ObservationQuery {
        repository: prepared.op.header("x-repository").into(),
        head,
        replay: Some(identity(&prepared.op)),
        ticket_ids: prepared
            .tickets
            .iter()
            .map(|id| mkit_core::hash::to_hex_bytes(id))
            .collect(),
        quota: ctx.profile().quota.map(|_| control::QuotaQuery {
            signer: signer.public_key_hex(),
            window_start_ms: None,
        }),
        packs: prepared.packs,
        ..Default::default()
    };
    Ok(Fixture {
        ctx,
        op: prepared.op,
        query,
        tip: target.tip,
        packmap: target.packmap,
    })
}

/// Inferred reservations: each ticket's reservation, then the ref reservation
/// bound to the replayed write. The ref reservation is asserted only when the
/// host advertises `fixture.ref_reservation`; ticket reservations always are.
fn reservations_consistent(
    reservations: &[Option<ReservationView>],
    ticket_count: usize,
    ref_reservation: bool,
    want: impl Fn(&ReservationView) -> bool,
) -> bool {
    if reservations.len() < ticket_count
        || reservations[..ticket_count]
            .iter()
            .any(|r| !r.as_ref().is_some_and(&want))
    {
        return false;
    }
    if ref_reservation {
        reservations.len() == ticket_count + 1
            && reservations[ticket_count].as_ref().is_some_and(want)
    } else {
        ungranted(reservations, ticket_count)
    }
}

/// The op-reservation slot must be empty when the host does not advertise
/// `fixture.ref_reservation`: an unadvertised control cannot grant.
fn ungranted(reservations: &[Option<ReservationView>], slot: usize) -> bool {
    reservations.get(slot).is_none_or(Option::is_none)
}

fn consistent(
    snapshot: &Observation,
    fixture: &Fixture,
    accepted: bool,
    ref_reservation: bool,
) -> Result<(), Failure> {
    let expected = accepted.then(|| to_hex(&fixture.tip));
    let packmap = accepted.then(|| to_hex(&fixture.packmap));
    if snapshot.head != expected || snapshot.packmap != packmap {
        return Err(Failure::Fail(format!(
            "torn or unexpected pair: {snapshot:?}"
        )));
    }
    if accepted {
        if !snapshot.replay.as_ref().is_some_and(|r| {
            r.state == "committed" && r.result.as_deref() == Some("advance_committed")
        }) || snapshot.memberships != [true, true]
            || snapshot.tickets.len() != 2
            || snapshot
                .tickets
                .iter()
                .any(|t| t.as_ref().is_none_or(|t| t.state != "consumed"))
            || !reservations_consistent(&snapshot.reservations, 2, ref_reservation, |r| {
                r.state == "committed" && r.terminal_count == 1
            })
        {
            return Err(Failure::Fail(format!(
                "accepted state lacks replay, membership, closed tickets, or terminal responsibilities: {snapshot:?}"
            )));
        }
    } else if snapshot
        .replay
        .as_ref()
        .is_some_and(|r| r.state == "committed")
        || snapshot.memberships != [false, false]
        || snapshot.tickets.len() != 2
        || snapshot
            .tickets
            .iter()
            .any(|t| t.as_ref().is_none_or(|t| t.state != "live"))
        || snapshot
            .reservations
            .iter()
            .any(|r| r.as_ref().is_some_and(|r| r.terminal_count != 0))
    {
        return Err(Failure::Fail(format!(
            "pre-acceptance state has acceptance effects: {snapshot:?}"
        )));
    }
    Ok(())
}

async fn committed(ctx: &Ctx, op: &Signed) -> Result<(), Failure> {
    let response: AdvanceRefsResponse = want_ok(ctx.send(op).await?, "paired acceptance")?;
    if response.outcome != Some(AdvanceOutcome::ADVANCE_OUTCOME_COMMITTED.into()) {
        return Err(Failure::Fail(format!(
            "expected committed, got {response:?}"
        )));
    }
    Ok(())
}

async fn acceptance(
    ctx: Ctx,
    control: &ControlClient,
    step: Option<&str>,
    mode: &str,
    ref_reservation: bool,
) -> Result<(), Failure> {
    let fixture = fixture(ctx).await?;
    let before = control.observe(&fixture.query).await?;
    consistent(&before, &fixture, false, ref_reservation)?;
    let required_commit = step != Some("before_acceptance");
    let original = if let Some(step) = step {
        control
            .command(&Request::Pause {
                step: step.into(),
                decision_class: None,
                occurrence: None,
                on_resume: None,
                repository: fixture.query.repository.clone(),
                head: fixture.query.head.clone(),
            })
            .await?;
        let request = tokio::spawn({
            let ctx = fixture.ctx.clone();
            let op = fixture.op.clone();
            async move { ctx.send::<AdvanceRefsResponse>(&op).await }
        });
        control.wait_paused().await?;
        let paused = control.observe(&fixture.query).await?;
        consistent(&paused, &fixture, required_commit, ref_reservation)?;
        quota_consistent(
            &before,
            &paused,
            required_commit,
            fixture.query.quota.is_some(),
        )?;
        // Drop the response, then inspect recovery before any request can
        // reconstruct an acknowledged unit that the server lost.
        request.abort();
        paused
    } else {
        committed(&fixture.ctx, &fixture.op).await?;
        let accepted = control.observe(&fixture.query).await?;
        consistent(&accepted, &fixture, true, ref_reservation)?;
        quota_consistent(&before, &accepted, true, fixture.query.quota.is_some())?;
        accepted
    };
    control
        .command(&Request::Restart { mode: mode.into() })
        .await?;
    let recovered = control.observe(&fixture.query).await?;
    let recovered_accepted = recovery_consistent(
        &before,
        &original,
        &recovered,
        &fixture,
        required_commit,
        fixture.query.quota.is_some(),
        ref_reservation,
    )?;
    control.command(&Request::Resume).await?;
    let ctx = fixture.ctx.reconnect()?;
    committed(&ctx, &fixture.op).await?;
    let after = control.observe(&fixture.query).await?;
    consistent(&after, &fixture, true, ref_reservation)?;
    quota_consistent(&before, &after, true, fixture.query.quota.is_some())?;
    if recovered_accepted && recovered != after {
        return Err(Failure::Fail(format!(
            "replay changed recovered acceptance: recovered={recovered:?}, after={after:?}"
        )));
    }
    Ok(())
}

/// A committed unit must already exist on recovery. Replaying first would let
/// a server repair lost durability and hide the loss from the conformance case.
fn recovery_consistent(
    before: &Observation,
    original: &Observation,
    recovered: &Observation,
    fixture: &Fixture,
    required_commit: bool,
    quota_enabled: bool,
    ref_reservation: bool,
) -> Result<bool, Failure> {
    if required_commit {
        if recovered != original {
            return Err(Failure::Fail(format!(
                "recovery lost or changed accepted state before replay: original={original:?}, recovered={recovered:?}"
            )));
        }
        consistent(recovered, fixture, true, ref_reservation)?;
        return Ok(true);
    }
    if recovered.head == Some(to_hex(&fixture.tip))
        && recovered.packmap == Some(to_hex(&fixture.packmap))
    {
        consistent(recovered, fixture, true, ref_reservation)?;
        quota_consistent(before, recovered, true, quota_enabled)?;
        return Ok(true);
    }
    if recovered.head != before.head
        || recovered.packmap != before.packmap
        || recovered.replay != before.replay
        || recovered.tickets != before.tickets
        || recovered.memberships != before.memberships
        || recovered.quota != before.quota
        || recovered.reservations.len() < 2
        || before.reservations.len() < 2
        || recovered.reservations[..2] != before.reservations[..2]
        || original.reservations.len() < 2
        || (ref_reservation
            && (recovered.reservations.len() != 3
                || before.reservations.len() != 3
                || original.reservations.len() != 3
                || (original.reservations[2].is_some() && recovered.reservations[2].is_none())
                || recovered.reservations[2]
                    .as_ref()
                    .is_some_and(|reservation| {
                        !matches!(
                            (reservation.state.as_str(), reservation.terminal_count),
                            ("pending", 0) | ("aborted", 1)
                        )
                    })))
        || !(ref_reservation
            || (ungranted(&recovered.reservations, 2)
                && ungranted(&before.reservations, 2)
                && ungranted(&original.reservations, 2)))
    {
        return Err(Failure::Fail(format!(
            "recovery exposed a partial acceptance before replay: before={before:?}, recovered={recovered:?}"
        )));
    }
    Ok(false)
}

fn quota_consistent(
    before: &Observation,
    after: &Observation,
    accepted: bool,
    enabled: bool,
) -> Result<(), Failure> {
    if enabled {
        let old = before
            .quota
            .as_ref()
            .ok_or("fixture lacks initial quota charge")?;
        let new = after
            .quota
            .as_ref()
            .ok_or("acceptance lacks quota responsibility")?;
        if new.ops != old.ops + u64::from(accepted) || new.bytes != old.bytes {
            return Err(Failure::Fail(format!(
                "acceptance charge not atomic: before={old:?}, after={new:?}"
            )));
        }
    }
    Ok(())
}

async fn uncertain(
    ctx: Ctx,
    control: &ControlClient,
    ref_reservation: bool,
) -> Result<(), Failure> {
    let fixture = fixture(ctx).await?;
    control
        .command(&Request::Pause {
            step: "after_durable_acceptance_before_response".into(),
            decision_class: None,
            occurrence: None,
            on_resume: Some("uncertain_storage_result".into()),
            repository: fixture.query.repository.clone(),
            head: fixture.query.head.clone(),
        })
        .await?;
    let pending = tokio::spawn({
        let ctx = fixture.ctx.clone();
        let op = fixture.op.clone();
        async move { ctx.send::<AdvanceRefsResponse>(&op).await }
    });
    control.wait_paused().await?;
    let before = control.observe(&fixture.query).await?;
    consistent(&before, &fixture, true, ref_reservation)?;
    control.command(&Request::Resume).await?;
    let result = pending.await.map_err(|e| e.to_string())??;
    match result {
        Err(error) if matches!(error.code.as_str(), "internal" | "unavailable") => {}
        other => {
            return Err(Failure::Fail(format!(
                "uncertain storage result must remain an uncertain error, got {other:?}"
            )));
        }
    }
    let recovered = control.observe(&fixture.query).await?;
    if before != recovered {
        return Err(Failure::Fail(format!(
            "uncertain result changed accepted state before replay: before={before:?}, recovered={recovered:?}"
        )));
    }
    committed(&fixture.ctx, &fixture.op).await?;
    let after = control.observe(&fixture.query).await?;
    if before != after {
        return Err(Failure::Fail(format!(
            "uncertainty caused abort or repeated acceptance: before={before:?}, after={after:?}"
        )));
    }
    Ok(())
}

async fn replay(ctx: Ctx, control: &ControlClient, ref_reservation: bool) -> Result<(), Failure> {
    let fixture = fixture(ctx).await?;
    committed(&fixture.ctx, &fixture.op).await?;
    let before = control.observe(&fixture.query).await?;
    consistent(&before, &fixture, true, ref_reservation)?;
    let signer = fixture.ctx.v2_signer("main")?;
    // The move target descends from the accepted tip and chains its packmap:
    // a verifiable real target on any host.
    let moved_target = target(
        b"moved.txt",
        format!("{}:moved", fixture.ctx.ns()).as_bytes(),
        &[fixture.tip],
        Some(fixture.packmap),
    )?;
    let later = prepare(
        &fixture.ctx,
        &signer,
        &fixture.query.head,
        &fixture.ctx.packmap("main"),
        Exp::Match(&fixture.tip),
        Exp::Match(&fixture.packmap),
        &moved_target,
    )
    .await?;
    committed(&fixture.ctx, &later.op).await?;
    control
        .command(&Request::BumpAuthority {
            namespace: namespace(&fixture.query.repository)?.into(),
        })
        .await?;
    let moved = control.observe(&fixture.query).await?;
    committed(&fixture.ctx, &fixture.op).await?;
    let after = control.observe(&fixture.query).await?;
    if moved != after
        || after.head != Some(to_hex(&moved_target.tip))
        || after.packmap != Some(to_hex(&moved_target.packmap))
    {
        return Err(Failure::Fail(format!(
            "replay repeated an acceptance effect: before={moved:?}, after={after:?}"
        )));
    }
    Ok(())
}

fn namespace(repository: &str) -> Result<&str, Failure> {
    repository.split_once('/').map(|(ns, _)| ns).ok_or_else(|| {
        Failure::Fail("authority test requires a full namespace/repository identity".into())
    })
}

async fn guard(ctx: Ctx, control: &ControlClient, ref_reservation: bool) -> Result<(), Failure> {
    let signer = ctx.v2_signer("main")?;
    // A ticketed advance on a seed ref makes a real commit and its packmap
    // repository members; ticketless guard operations then carry verifiable
    // targets a verifying host accepts.
    let seeded = target(
        b"guard.txt",
        format!("{}:guard", ctx.ns()).as_bytes(),
        &[],
        None,
    )?;
    let seed = prepare(
        &ctx,
        &signer,
        &ctx.head("seed"),
        &ctx.packmap("seed"),
        Exp::Missing,
        Exp::Missing,
        &seeded,
    )
    .await?;
    committed(&ctx, &seed.op).await?;
    for kind in ["update", "pair", "delete"] {
        // A head-only update is judged on the resulting pair, so it writes the
        // seeded branch: its stored packmap already covers the target on a
        // verifying host. Pair and delete writes use their own ref names.
        let (head, packmap) = if kind == "update" {
            (ctx.head("seed"), ctx.packmap("seed"))
        } else {
            (ctx.head(kind), ctx.packmap(kind))
        };
        let op = match kind {
            "update" => sign_unary(
                &signer,
                Rpc::UpdateRef,
                &update_req(&head, Exp::Any, &seeded.tip),
                |_| {},
            ),
            "pair" => sign_unary(
                &signer,
                Rpc::AdvanceRefs,
                &advance_req(
                    (&head, Exp::Any, &seeded.tip),
                    (&packmap, Exp::Any, &seeded.packmap),
                ),
                |_| {},
            ),
            "delete" => {
                let deleted = target(
                    b"delete.txt",
                    format!("{}:delete", ctx.ns()).as_bytes(),
                    &[],
                    None,
                )?;
                let seed = prepare(
                    &ctx,
                    &signer,
                    &head,
                    &packmap,
                    Exp::Missing,
                    Exp::Missing,
                    &deleted,
                )
                .await?;
                committed(&ctx, &seed.op).await?;
                let mut req = advance_req(
                    (&head, Exp::Match(&deleted.tip), &deleted.tip),
                    (&packmap, Exp::Match(&deleted.packmap), &deleted.packmap),
                );
                req.head_new_id = None;
                req.packmap_new_id = None;
                req.delete = Some(true);
                sign_unary(&signer, Rpc::AdvanceRefs, &req, |_| {})
            }
            _ => unreachable!("registered guard kind"),
        };
        let query = ObservationQuery {
            repository: op.header("x-repository").into(),
            head,
            replay: Some(identity(&op)),
            quota: ctx.profile().quota.map(|_| control::QuotaQuery {
                signer: signer.public_key_hex(),
                window_start_ms: None,
            }),
            ..Default::default()
        };
        guard_refused(&ctx, control, &op, &query, ref_reservation).await?;
    }
    // A stale final guard must also leave ticket reservations and local
    // memberships untouched, while aborting the separate ref reservation.
    let ticketed = fixture(ctx).await?;
    guard_refused(
        &ticketed.ctx,
        control,
        &ticketed.op,
        &ticketed.query,
        ref_reservation,
    )
    .await
}

async fn guard_refused(
    ctx: &Ctx,
    control: &ControlClient,
    op: &Signed,
    query: &ObservationQuery,
    ref_reservation: bool,
) -> Result<(), Failure> {
    let before = control.observe(query).await?;
    control
        .command(&Request::Pause {
            step: "before_acceptance".into(),
            decision_class: None,
            occurrence: None,
            on_resume: None,
            repository: query.repository.clone(),
            head: query.head.clone(),
        })
        .await?;
    let pending = tokio::spawn({
        let ctx = ctx.clone();
        let op = op.clone();
        async move {
            ctx.client()
                .post(
                    op.rpc.procedure(),
                    "application/proto",
                    &op.headers,
                    op.body,
                )
                .await
        }
    });
    if let Err(e) = control.wait_paused().await {
        let reply = pending.await.map_err(|e| e.to_string())?;
        return Err(Failure::Fail(format!("{e}; guard op reply: {reply:?}")));
    }
    control
        .command(&Request::BumpAuthority {
            namespace: namespace(&query.repository)?.into(),
        })
        .await?;
    control.command(&Request::Resume).await?;
    let reply = pending.await.map_err(|e| e.to_string())??;
    let decoded = crate::wire::client::decode_unary::<UpdateRefResponse>(&reply)?;
    want_code(decoded, "permission_denied", "authority final guard")?;
    let after = control.observe(query).await?;
    guard_consistent(&before, &after, query.ticket_ids.len(), ref_reservation)
}

fn guard_consistent(
    before: &Observation,
    after: &Observation,
    ticket_count: usize,
    ref_reservation: bool,
) -> Result<(), Failure> {
    if before.head != after.head
        || before.packmap != after.packmap
        || before.replay != after.replay
        || before.tickets != after.tickets
        || before.memberships != after.memberships
    {
        return Err(Failure::Fail(format!(
            "guard failure committed acceptance effects: before={before:?}, after={after:?}"
        )));
    }
    if before.quota != after.quota {
        return Err(Failure::Fail(format!(
            "guard failure changed quota charge: before={:?}, after={:?}",
            before.quota, after.quota
        )));
    }
    if before.tickets.len() != ticket_count
        || before.memberships.len() != ticket_count
        || before
            .tickets
            .iter()
            .any(|ticket| ticket.as_ref().is_none_or(|ticket| ticket.state != "live"))
        || before.memberships.iter().any(|member| *member)
    {
        return Err(Failure::Fail(format!(
            "guard fixture lacks live tickets and absent memberships: {before:?}"
        )));
    }
    if before.reservations.len() < ticket_count
        || after.reservations.len() < ticket_count
        || before.reservations[..ticket_count] != after.reservations[..ticket_count]
        || before.reservations[..ticket_count]
            .iter()
            .any(|reservation| {
                !reservation.as_ref().is_some_and(|reservation| {
                    reservation.state == "ticketed" && reservation.terminal_count == 0
                })
            })
        || (ref_reservation
            && (before.reservations.len() != ticket_count + 1
                || after.reservations.len() != ticket_count + 1
                || !after.reservations[ticket_count]
                    .as_ref()
                    .is_some_and(|reservation| {
                        reservation.state == "aborted" && reservation.terminal_count == 1
                    })))
        || !(ref_reservation
            || (ungranted(&before.reservations, ticket_count)
                && ungranted(&after.reservations, ticket_count)))
    {
        return Err(Failure::Fail(format!(
            "guard failure lacks unchanged ticket reservations and exactly one aborted ref reservation: before={:?}, after={:?}",
            before.reservations, after.reservations
        )));
    }
    Ok(())
}

async fn complete_authority_setter(
    client: &Client,
    body: Vec<u8>,
) -> Result<mkit_transport_connect::generated::SetAuthorityGenerationResponse, Failure> {
    use crate::wire::client::{UNARY_PROTO, decode_unary};
    tokio::time::timeout(Duration::from_secs(45), async {
        loop {
            let reply = client.post(Rpc::SetAuthorityGeneration.procedure(), UNARY_PROTO, &[], body.clone()).await?;
            let result = decode_unary(&reply)?;
            if !matches!(&result, Err(error) if error.code == "unavailable" && error.http_status == 503) {
                return want_ok(result, "enabled setter");
            }
            let delay = reply.headers.get(http::header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok())
                .filter(|value| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
                .and_then(|value| value.parse::<u64>().ok())
                .ok_or_else(|| Failure::Fail("pending authority setter requires Retry-After delay-seconds".into()))?;
            tokio::time::sleep(Duration::from_secs(delay).max(Duration::from_millis(10))).await;
        }
    }).await.map_err(|_| Failure::Fail("authority setter did not complete within 45 seconds".into()))?
}

async fn authority_setter(
    control: &ControlClient,
    client: &Client,
    enabled: bool,
) -> Result<(), Failure> {
    use buffa::Message as _;
    use mkit_transport_connect::generated::{
        GetAuthorityGenerationRequest, GetAuthorityGenerationResponse,
        SetAuthorityGenerationRequest, SetAuthorityGenerationResponse,
    };
    let fixture = if enabled {
        Some(control.command(&Request::PrepareAuthoritySetter).await?)
    } else {
        None
    };
    let namespace = fixture
        .as_ref()
        .and_then(|f| f.authority_namespace.clone())
        .unwrap_or_else(|| format!("ed25519-{}", "11".repeat(32)));
    let get = GetAuthorityGenerationRequest {
        namespace: Some(namespace),
        ..Default::default()
    };
    let before = client
        .unary::<GetAuthorityGenerationResponse>(
            Rpc::GetAuthorityGeneration,
            get.encode_to_vec(),
            &[],
        )
        .await?;
    let set = SetAuthorityGenerationRequest {
        signed_statement: Some(if let Some(f) = &fixture {
            f.authority_statement
                .clone()
                .ok_or_else(|| Failure::Fail("setter fixture omitted statement".into()))?
        } else {
            "disabled".into()
        }),
        ..Default::default()
    };
    if let Some(fixture) = fixture {
        let before = want_ok(before, "enabled getter")?
            .generation
            .ok_or_else(|| Failure::Fail("getter omitted generation".into()))?;
        let expected = fixture
            .generation
            .ok_or_else(|| Failure::Fail("setter fixture omitted generation".into()))?;
        if expected <= before {
            return Err(Failure::Fail(
                "setter fixture must increase generation".into(),
            ));
        }
        let set = complete_authority_setter(client, set.encode_to_vec()).await?;
        let after = want_ok(
            client
                .unary::<GetAuthorityGenerationResponse>(
                    Rpc::GetAuthorityGeneration,
                    get.encode_to_vec(),
                    &[],
                )
                .await?,
            "getter after setter",
        )?;
        if set.generation != Some(expected) || after.generation != Some(expected) {
            return Err(Failure::Fail(
                "setter/getter did not retain the requested generation".into(),
            ));
        }
    } else {
        let result = client
            .unary::<SetAuthorityGenerationResponse>(
                Rpc::SetAuthorityGeneration,
                set.encode_to_vec(),
                &[],
            )
            .await?;
        for error in [
            want_code(before, "unimplemented", "disabled getter")?,
            want_code(result, "unimplemented", "disabled setter")?,
        ] {
            if error.http_status != 501 {
                return Err(Failure::Fail(format!(
                    "disabled authority RPC returned HTTP {}",
                    error.http_status
                )));
            }
        }
    }
    Ok(())
}

/// The four restart/acceptance cases share one body; only the pause step and
/// restart kind differ.
async fn acceptance_case(
    name: &str,
    ctx: Ctx,
    control: &ControlClient,
    ref_reservation: bool,
) -> Result<(), Failure> {
    let (pause, restart) = match name {
        "acceptance.before_acceptance_restart" => (Some("before_acceptance"), "graceful"),
        "acceptance.after_durable_acceptance_restart" => {
            (Some("after_durable_acceptance_before_response"), "graceful")
        }
        "acceptance.after_response_restart" => (None, "graceful"),
        "acceptance.kill_recovery" => (Some("after_durable_acceptance_before_response"), "kill"),
        _ => unreachable!("registered case"),
    };
    acceptance(ctx, control, pause, restart, ref_reservation).await
}

async fn execute_case(
    name: &str,
    ctx: Ctx,
    control: &ControlClient,
    client: &Client,
    ref_reservation: bool,
) -> Result<(), Failure> {
    match name {
        "pack_locations.guard_refusals" => {
            crate::controlled_pack_locations::guard_refusals(ctx, control).await
        }
        "pack_locations.corrupt_location_fallback" => {
            crate::controlled_pack_locations::corrupt_location_fallback(ctx, control).await
        }
        "pack_locations.denial_after_issue_bound" => {
            crate::controlled_pack_locations::denial_after_issue_bound(ctx, control).await
        }
        name if name.starts_with("publication.") => {
            crate::controlled_publication::run(name, ctx, control).await
        }
        name if name.starts_with("reliance.") => {
            crate::controlled_reliance::run(name, ctx, control).await
        }
        "authority.setter_disabled" => authority_setter(control, client, false).await,
        "authority.setter_enabled" => authority_setter(control, client, true).await,
        name if name.starts_with("acceptance.") => {
            acceptance_case(name, ctx, control, ref_reservation).await
        }
        "recovery.uncertain_commit" => uncertain(ctx, control, ref_reservation).await,
        "guard.authority_final_boundary" => guard(ctx, control, ref_reservation).await,
        "replay.moves_and_generation" => replay(ctx, control, ref_reservation).await,
        "fork.destination_gate_before_acceptance" => {
            crate::controlled_fork::destination_gate_before_acceptance(ctx, control).await
        }
        "fork.writer_against_registration" => {
            crate::controlled_fork::writer_against_registration(ctx, control).await
        }
        "fork.writer_against_acceptance" => {
            crate::controlled_fork::writer_against_acceptance(ctx, control).await
        }
        "fork.leased_writer_against_registration" => {
            crate::controlled_fork::leased_writer_against_registration(ctx, control).await
        }
        "fork.failed_destination_inert" => {
            crate::controlled_fork::failed_destination_inert(ctx, control).await
        }
        "fork.acceptance_result_replay_outcome_atomic" => {
            crate::controlled_fork::acceptance_result_replay_outcome_atomic(ctx, control).await
        }
        "fork.authority_at_acceptance" => {
            crate::controlled_fork::authority_at_acceptance(ctx, control).await
        }
        "fork.authority_each_progress_commit" => {
            crate::controlled_fork::authority_each_progress_commit(ctx, control).await
        }
        "fork.source_moved_before_acceptance" => {
            crate::controlled_fork::source_moved_before_acceptance(ctx, control).await
        }
        "fork.source_moved_after_acceptance" => {
            crate::controlled_fork::source_moved_after_acceptance(ctx, control).await
        }
        "fork.source_unpublished_before_acceptance" => {
            crate::controlled_fork::source_unpublished_before_acceptance(ctx, control).await
        }
        "fork.source_unpublished_after_acceptance" => {
            crate::controlled_fork::source_unpublished_after_acceptance(ctx, control).await
        }
        "fork.source_visibility_revoked_before_acceptance" => {
            crate::controlled_fork::source_visibility_revoked_before_acceptance(ctx, control).await
        }
        "fork.source_visibility_revoked_after_acceptance" => {
            crate::controlled_fork::source_visibility_revoked_after_acceptance(ctx, control).await
        }
        "fork.source_denied_before_acceptance" => {
            crate::controlled_fork::source_denied_before_acceptance(ctx, control).await
        }
        "fork.source_denied_after_acceptance" => {
            crate::controlled_fork::source_denied_after_acceptance(ctx, control).await
        }
        _ => unreachable!("registered case"),
    }
}

/// Run selected Tier-2 cases. `expected_skips` is keyed by stable case name and
/// contains the concrete reason the test owner accepts that coverage gap.
/// Unavailable negotiation is a failure, never an implicit skip.
pub async fn run(
    target: &WireTarget,
    expected_skips: &BTreeMap<String, String>,
    filter: Option<&str>,
) -> Report {
    run_with_control(target, &target.base_url, expected_skips, filter).await
}

/// Run Tier-2 cases with an explicit test-control HTTP origin. Transport RPCs
/// still use `target.base_url`; the binding may run at a separate origin.
pub async fn run_with_control(
    target: &WireTarget,
    control_url: &url::Url,
    expected_skips: &BTreeMap<String, String>,
    filter: Option<&str>,
) -> Report {
    let mut report = Report::default();
    if let Some((name, _)) = expected_skips.iter().find(|(name, reason)| {
        reason.trim().is_empty() || !CASES.iter().any(|case| case.name == name.as_str())
    }) {
        report.cases.push(CaseReport {
            name: "control.declarations",
            verdict: Verdict::Fail(format!("unknown or empty declared skip: {name}")),
        });
        return report;
    }
    let selected = CASES
        .iter()
        .filter(|c| filter.is_none_or(|f| c.name.contains(f)));
    let client = ControlClient::new(control_url);
    let wire_client = Client::new(&target.base_url);
    let caps = match &client {
        Ok(c) => c.capabilities().await,
        Err(e) => Err(e.clone()),
    };
    for case in selected {
        let mut missing_features: Vec<_> = case
            .features
            .iter()
            .filter(|f| !target.profile.has(**f))
            .map(|f| f.as_str())
            .collect();
        if case.name == "authority.setter_disabled" && target.profile.has(Feature::AuthoritySetter)
        {
            missing_features.push("authority-setter=off");
        }
        if !missing_features.is_empty() && caps.is_ok() {
            report.cases.push(CaseReport {
                name: case.name,
                verdict: if expected_skips.contains_key(case.name) {
                    Verdict::Fail(format!(
                        "declared skip for non-applicable feature {missing_features:?}"
                    ))
                } else {
                    Verdict::NotApplicable(format!("features {missing_features:?}"))
                },
            });
            continue;
        }
        let result = match (&client, &caps) {
            (Ok(control), Ok(caps)) => {
                let missing: Vec<_> = case
                    .controls
                    .iter()
                    .filter(|n| !caps.controls.iter().any(|s| s == **n))
                    .collect();
                if missing.is_empty() {
                    let wire_client = match &wire_client {
                        Ok(client) => client,
                        Err(reason) => {
                            report.cases.push(CaseReport {
                                name: case.name,
                                verdict: Verdict::Fail(reason.clone()),
                            });
                            continue;
                        }
                    };
                    let ctx = Ctx::new(
                        wire_client.clone(),
                        Arc::new(target.profile.clone()),
                        case.name,
                    );
                    let ref_reservation =
                        caps.controls.iter().any(|c| c == "fixture.ref_reservation");
                    let result = tokio::time::timeout(Duration::from_mins(1), async {
                        execute_case(case.name, ctx, control, wire_client, ref_reservation).await
                    })
                    .await
                    .unwrap_or_else(|_| Err(Failure::Fail("server-control case timed out".into())));
                    // Always release one-shot holds, including on a failed assertion.
                    let _ = control.command(&Request::Resume).await;
                    result
                } else {
                    Err(Failure::Skip(format!(
                        "requires controls {missing:?}; declared unsupported {:?}",
                        caps.unsupported
                    )))
                }
            }
            (_, Err(e)) | (Err(e), _) => Err(Failure::Fail(e.clone())),
        };
        let verdict = judge(result, expected_skips.get(case.name).map(String::as_str));
        report.cases.push(CaseReport {
            name: case.name,
            verdict,
        });
    }
    report
}

fn judge(result: Result<(), Failure>, expected: Option<&str>) -> Verdict {
    match (result, expected) {
        (Ok(()), None) => Verdict::Pass(None),
        (Ok(()), Some(reason)) => Verdict::Fail(format!("declared skip passed: {reason}")),
        (Err(Failure::Skip(reason)), Some(declared)) if !declared.trim().is_empty() => {
            Verdict::Skip(format!("{declared}; {reason}"))
        }
        (Err(Failure::Skip(reason)), _) => Verdict::Fail(format!("undeclared skip: {reason}")),
        (Err(Failure::Fail(reason)), _) => Verdict::Fail(reason),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn declared_skips_cannot_hide_failures_or_stale_gaps() {
        assert!(matches!(
            judge(Err(Failure::Skip("no kill".into())), None),
            Verdict::Fail(_)
        ));
        assert!(matches!(
            judge(Err(Failure::Skip("no kill".into())), Some("volatile host")),
            Verdict::Skip(_)
        ));
        assert!(matches!(
            judge(Ok(()), Some("volatile host")),
            Verdict::Fail(_)
        ));
        assert!(matches!(
            judge(
                Err(Failure::Fail("torn state".into())),
                Some("volatile host")
            ),
            Verdict::Fail(_)
        ));
    }
}
