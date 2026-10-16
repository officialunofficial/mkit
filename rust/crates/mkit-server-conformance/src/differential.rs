//! Deterministic decision equivalence over HTTP, independent of either server's
//! storage or orchestration. This does not test crash recovery or concurrency.
//!
//! Use disposable servers: the versioned fixture has fixed identities and
//! deliberately refuses a target where its branch already exists.

use std::collections::BTreeMap;
use std::time::Duration;

use buffa::Message;
use mkit_core::hash::{hash, to_hex, to_hex_bytes};
use mkit_core::object::{Commit, Identity, Object, Tree};
use mkit_core::pack::PackWriter;
use mkit_core::serialize::serialize;
use mkit_core::sign::{KeyPair, sign_commit};
use mkit_core::write_auth::{Context, Operation};
use mkit_transport_connect::generated::{
    AdvanceRefsRequest, AdvanceRefsResponse, BeginUploadRequest, BeginUploadResponse,
    UploadPackResponse,
};
use serde::Serialize;
use serde_json::{Value, json};

use crate::control::{Observation, ObservationQuery, QuotaQuery, ReplayIdentity, Request};
use crate::controlled::ControlClient;
use crate::wire::cases::{Exp, advance_req, upload_msgs};
use crate::wire::client::{Client, Rpc, frames};
use crate::wire::sign::{Envelope, SignedOp, Signer, body_commitment, pack_commitment};
use crate::wire::{Feature, WireAuth, WireTarget};

const CLOCK_MS: i64 = 1_800_000_000_000;
const HEAD: &str = "refs/heads/conformance/differential/v1";
const PACKMAP: &str = "refs/mkit/packmap/conformance/differential/v1";
const CASES: [&str; 4] = [
    "decision.acceptance",
    "decision.replay",
    "decision.paired_cas",
    "decision.refusal",
];
const FEATURES: [Feature; 5] = [
    Feature::TransportWrites,
    Feature::AuthV2,
    Feature::AtomicAdvance,
    Feature::Replay,
    Feature::Tickets,
];

/// A wire server and its independently located HTTP test-control binding.
#[derive(Debug, Clone)]
pub struct DiffTarget {
    /// Ordinary protocol endpoint and its declared optional features.
    pub wire: WireTarget,
    /// Origin exposing the versioned test-control HTTP routes.
    pub control_url: url::Url,
}

/// Versioned machine-readable decision comparison.
#[derive(Debug, Serialize)]
pub struct DiffReport {
    /// Report schema version, currently 1.
    pub version: u32,
    /// Results in deterministic fixture order.
    pub cases: Vec<DiffCase>,
}

impl DiffReport {
    /// A decision mismatch or a failed scenario makes the run fail.
    #[must_use]
    pub fn failed(&self) -> bool {
        self.cases
            .iter()
            .any(|case| matches!(case.status, DiffStatus::Mismatch | DiffStatus::Failed))
    }
}

/// Result of one protocol scenario, including structured field differences.
#[derive(Debug, Serialize)]
pub struct DiffCase {
    /// Stable case name.
    pub name: String,
    /// Equivalence and execution status; two failures are never a match.
    pub status: DiffStatus,
    /// Fields whose normalized protocol values differ.
    pub differences: Vec<FieldDifference>,
    /// Execution or feature applicability diagnostics, without credentials.
    pub reason: Option<String>,
}

/// Distinguishes equivalence from failures and absent optional features.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiffStatus {
    /// Both valid scenarios produced the same decisions.
    Matched,
    /// Both scenarios ran, but protocol fields differ.
    Mismatch,
    /// At least one scenario failed its independent conformance oracle.
    Failed,
    /// A required optional feature is undeclared.
    NotApplicable,
}

/// One path through a normalized protocol result; array order is significant.
#[derive(Debug, Serialize)]
pub struct FieldDifference {
    /// JSON pointer identifying the differing field.
    pub path: String,
    /// Reference value; `null` also represents a missing field.
    pub left: Value,
    /// Candidate value; `null` also represents a missing field.
    pub right: Value,
}

/// Compare deterministic signed decisions on two disposable servers. Each
/// target must implement its own clock and atomic-observation HTTP binding.
/// Quota state is compared when declared by the supplied profiles.
///
/// # Errors
/// Invalid endpoint, incompatible profiles, missing required controls, or
/// failed clock negotiation. Scenario failures appear in the returned report.
pub async fn run(left: &DiffTarget, right: &DiffTarget) -> Result<DiffReport, String> {
    let missing: Vec<_> = FEATURES
        .iter()
        .filter(|f| !left.wire.profile.has(**f) || !right.wire.profile.has(**f))
        .map(|f| f.as_str())
        .collect();
    if !missing.is_empty() {
        return Ok(DiffReport {
            version: 1,
            cases: CASES
                .iter()
                .map(|name| DiffCase {
                    name: (*name).into(),
                    status: DiffStatus::NotApplicable,
                    differences: Vec::new(),
                    reason: Some(format!("requires features {missing:?} on both targets")),
                })
                .collect(),
        });
    }
    if left.wire.profile.quota != right.wire.profile.quota {
        return Err("differential targets must declare identical quota policies".into());
    }
    let left_session = Session::new(left).await?;
    let right_session = Session::new(right).await?;
    let left_trace = left_session.execute().await;
    let right_trace = right_session.execute().await;
    Ok(compare_traces(&left_trace, &right_trace))
}

fn compare_traces(
    left: &Result<BTreeMap<String, Value>, String>,
    right: &Result<BTreeMap<String, Value>, String>,
) -> DiffReport {
    DiffReport {
        version: 1,
        cases: CASES
            .iter()
            .map(|name| match (left, right) {
                (Ok(left), Ok(right)) => {
                    let mut differences = Vec::new();
                    difference("", &left[*name], &right[*name], &mut differences);
                    let invalid = [&left[*name], &right[*name]].iter().any(|value| {
                        value
                            .get("oracle_error")
                            .is_some_and(|error| !error.is_null())
                    });
                    DiffCase {
                        name: (*name).into(),
                        status: if invalid {
                            DiffStatus::Failed
                        } else if differences.is_empty() {
                            DiffStatus::Matched
                        } else {
                            DiffStatus::Mismatch
                        },
                        differences,
                        reason: invalid
                            .then(|| "scenario violated its independent conformance oracle".into()),
                    }
                }
                _ => DiffCase {
                    name: (*name).into(),
                    status: DiffStatus::Failed,
                    differences: Vec::new(),
                    reason: Some(format!(
                        "scenario execution failed; left={:?}; right={:?}",
                        left.as_ref().err(),
                        right.as_ref().err()
                    )),
                },
            })
            .collect(),
    }
}

fn difference(path: &str, left: &Value, right: &Value, out: &mut Vec<FieldDifference>) {
    if left == right {
        return;
    }
    match (left, right) {
        (Value::Object(a), Value::Object(b)) => {
            let keys: std::collections::BTreeSet<_> = a.keys().chain(b.keys()).collect();
            for key in keys {
                let key_path = format!("{path}/{}", key.replace('~', "~0").replace('/', "~1"));
                match (a.get(key), b.get(key)) {
                    (Some(a), Some(b)) => difference(&key_path, a, b, out),
                    (a, b) => out.push(FieldDifference {
                        path: key_path,
                        left: a.cloned().unwrap_or(Value::Null),
                        right: b.cloned().unwrap_or(Value::Null),
                    }),
                }
            }
        }
        (Value::Array(a), Value::Array(b)) if a.len() == b.len() => {
            for (index, (a, b)) in a.iter().zip(b).enumerate() {
                difference(&format!("{path}/{index}"), a, b, out);
            }
        }
        _ => out.push(FieldDifference {
            path: path.into(),
            left: left.clone(),
            right: right.clone(),
        }),
    }
}

struct SignedRequest {
    body: Vec<u8>,
    headers: SignedOp,
    fingerprint: String,
}

struct Fixture {
    head: [u8; 32],
    packmap: [u8; 32],
    query: ObservationQuery,
    request: AdvanceRefsRequest,
    accepted: SignedRequest,
    before: Observation,
}

struct Session {
    client: Client,
    control: ControlClient,
    signer: Signer,
    audience: String,
    repository: String,
    quota: bool,
}

impl Session {
    async fn new(target: &DiffTarget) -> Result<Self, String> {
        let WireAuth::AuthV2 {
            audience,
            repository,
            ..
        } = &target.wire.profile.auth
        else {
            return Err("differential fixtures require auth-v2".into());
        };
        let control = ControlClient::new(&target.control_url)?;
        let caps = control.capabilities().await?;
        for required in ["clock.pin", "observe", "fixture.ref_reservation"] {
            if !caps.controls.iter().any(|name| name == required) {
                return Err(format!("differential target requires control {required}"));
            }
        }
        let clock = control
            .command(&Request::PinClock { now_ms: CLOCK_MS })
            .await?;
        if clock.now_ms != Some(CLOCK_MS) {
            return Err("clock pin did not acknowledge the exact fixture time".into());
        }
        let repository = if target.wire.profile.has(Feature::MultiRepo) {
            let signer = Signer::new([0x75; 32], audience, repository);
            format!("ed25519-{}/differential-v1", signer.public_key_hex())
        } else {
            repository.clone()
        };
        Ok(Self {
            client: Client::new(&target.wire.base_url)?,
            control,
            signer: Signer::new([0x75; 32], audience, &repository),
            audience: audience.clone(),
            repository,
            quota: target.wire.profile.quota.is_some(),
        })
    }

    fn sign(
        &self,
        rpc: Rpc,
        commitment: String,
        digest: Option<String>,
        label: &str,
    ) -> Result<(SignedOp, String), String> {
        let envelope = Envelope {
            version: Some("2".into()),
            audience: self.audience.clone(),
            repository: self.repository.clone(),
            procedure: rpc.procedure().into(),
            commitment,
            digest,
            created_at: CLOCK_MS,
            expires_at: CLOCK_MS + 120_000,
            nonce: to_hex(&hash(label.as_bytes())),
        };
        let fingerprint = Operation {
            context: Context {
                audience: &envelope.audience,
                repository: &envelope.repository,
            },
            procedure: &envelope.procedure,
            commitment: &envelope.commitment,
            created_at: envelope.created_at,
            expires_at: envelope.expires_at,
            nonce: &envelope.nonce,
        }
        .digest()
        .map_err(|e| e.to_string())?;
        Ok((self.signer.sign(&envelope), to_hex(&fingerprint)))
    }

    fn unary<M: Message>(
        &self,
        rpc: Rpc,
        request: &M,
        label: &str,
    ) -> Result<SignedRequest, String> {
        let body = request.encode_to_vec();
        let (headers, fingerprint) = self.sign(
            rpc,
            body_commitment(&body),
            Some(to_hex(&hash(&body))),
            label,
        )?;
        Ok(SignedRequest {
            body,
            headers,
            fingerprint,
        })
    }

    async fn snapshot(&self, query: &ObservationQuery) -> Result<Observation, String> {
        self.control
            .command(&Request::Observe {
                query: query.clone(),
            })
            .await?
            .observation
            .ok_or_else(|| "atomic observation missing".into())
    }

    async fn advance(&self, request: &SignedRequest) -> Result<i32, String> {
        // Pending verification is permission, not a decision difference. Retry
        // exactly the original signed identity within one bounded window.
        tokio::time::timeout(Duration::from_secs(45), async {
            loop {
                match self
                    .client
                    .unary::<AdvanceRefsResponse>(
                        Rpc::AdvanceRefs,
                        request.body.clone(),
                        &request.headers.headers,
                    )
                    .await?
                {
                    Ok(reply) => return Ok(reply.outcome.map_or(0, |v| v.to_i32())),
                    Err(error) if error.code == "unavailable" => {
                        tokio::time::sleep(Duration::from_millis(100)).await
                    }
                    Err(error) => return Err(format!("advance refused: {}", error.code)),
                }
            }
        })
        .await
        .map_err(|_| "advance did not resolve within fixture bound".to_owned())?
    }

    async fn upload(&self, pack: &[u8], index: usize) -> Result<Vec<u8>, String> {
        let id = hash(pack);
        let request = self.unary(
            Rpc::BeginUpload,
            &BeginUploadRequest {
                r#ref: Some(HEAD.into()),
                pack_id: Some(id.to_vec()),
                bytes: Some(pack.len() as u64),
                ..Default::default()
            },
            &format!("begin-{index}"),
        )?;
        let response = self
            .client
            .unary::<BeginUploadResponse>(Rpc::BeginUpload, request.body, &request.headers.headers)
            .await?
            .map_err(|e| format!("begin upload refused: {}", e.code))?;
        let Some(mkit_transport_connect::generated::__buffa::oneof::begin_upload_response::Result::Ticket(ticket)) = response.result else { return Err("fixture requires a fresh upload ticket".into()); };
        let ticket_id = ticket.id.ok_or("ticket lacks ID")?;
        let mut messages = upload_msgs(pack, 1);
        if let Some(
            mkit_transport_connect::generated::__buffa::oneof::upload_pack_request::Body::Header(
                header,
            ),
        ) = &mut messages[0].body
        {
            header.ticket_token = ticket.token;
        }
        let (signed, _) = self.sign(
            Rpc::UploadPack,
            pack_commitment(&id, pack.len() as u64),
            None,
            &format!("upload-{index}"),
        )?;
        let response = self
            .client
            .stream::<UploadPackResponse>(Rpc::UploadPack, frames(&messages), &signed.headers)
            .await?;
        if let Some(error) = response.error {
            return Err(format!("upload refused: {}", error.code));
        }
        Ok(ticket_id)
    }

    async fn fixture(&self) -> Result<Fixture, String> {
        let (pack, head) = canonical_pack()?;
        let pack_id = hash(&pack);
        let packlist =
            mkit_core::transfer::encode_packlist(None, &[pack_id]).map_err(|e| e.to_string())?;
        let packmap = hash(&packlist);
        let mut query = ObservationQuery {
            repository: self.repository.clone(),
            head: HEAD.into(),
            ..Default::default()
        };
        let initial = self.snapshot(&query).await?;
        if initial.head.is_some() || initial.packmap.is_some() {
            return Err(
                "differential fixture branch already exists; use disposable targets".into(),
            );
        }
        let tickets = vec![
            self.upload(&pack, 0).await?,
            self.upload(&packlist, 1).await?,
        ];
        if tickets[0] == tickets[1] || tickets.iter().any(Vec::is_empty) {
            return Err("ticket identities must be distinct and nonempty".into());
        }
        let mut request = advance_req(
            (HEAD, Exp::Missing, &head),
            (PACKMAP, Exp::Missing, &packmap),
        );
        request.ticket_ids = tickets.clone();
        let accepted = self.unary(Rpc::AdvanceRefs, &request, "accepted-pair")?;
        query.replay = Some(ReplayIdentity {
            audience: self.audience.clone(),
            repository: self.repository.clone(),
            signer: self.signer.public_key_hex(),
            nonce: accepted.headers.nonce.clone(),
        });
        query.ticket_ids = tickets.iter().map(|id| to_hex_bytes(id)).collect();
        query.packs = vec![to_hex(&pack_id), to_hex(&packmap)];
        query.quota = self.quota.then(|| QuotaQuery {
            signer: self.signer.public_key_hex(),
            window_start_ms: None,
        });
        let before = self.snapshot(&query).await?;
        if before.head.is_some()
            || before.packmap.is_some()
            || before.replay.is_some()
            || before.memberships != [false, false]
            || before.tickets.len() != 2
            || before
                .tickets
                .iter()
                .any(|ticket| ticket.as_ref().is_none_or(|ticket| ticket.state != "live"))
            || before.reservations.iter().any(|reservation| {
                reservation
                    .as_ref()
                    .is_some_and(|reservation| reservation.terminal_count != 0)
            })
        {
            return Err(
                "fixture already has acceptance effects before its signed acceptance".into(),
            );
        }
        Ok(Fixture {
            head,
            packmap,
            query,
            request,
            accepted,
            before,
        })
    }

    async fn execute(&self) -> Result<BTreeMap<String, Value>, String> {
        let Fixture {
            head,
            packmap,
            query,
            request,
            accepted,
            before,
        } = self.fixture().await?;
        let outcome = self.advance(&accepted).await?;
        if outcome != 1 {
            return Err(format!("expected acceptance, got outcome {outcome}"));
        }
        let snapshot = self.snapshot(&query).await?;
        let acceptance_error = validate_accepted(
            &snapshot,
            &head,
            &packmap,
            &accepted.fingerprint,
            &before,
            self.quota,
        )
        .err();
        let normalized = normalize(&snapshot, &accepted.fingerprint)?;
        let mut trace = BTreeMap::new();
        trace.insert(CASES[0].into(), json!({"outcome": outcome, "before": normalize(&before, &accepted.fingerprint)?, "after": normalized, "oracle_error": acceptance_error}));
        let replay = self.advance(&accepted).await?;
        let replay_snapshot = self.snapshot(&query).await?;
        if replay != outcome || replay_snapshot != snapshot {
            return Err("replay changed the saved answer or acceptance effects".into());
        }
        trace.insert(CASES[1].into(), json!({"outcome": replay, "observation": normalize(&replay_snapshot, &accepted.fingerprint)?}));
        let conflict = self.unary(
            Rpc::AdvanceRefs,
            &advance_req(
                (HEAD, Exp::Match(&[0x19; 32]), &head),
                (PACKMAP, Exp::Match(&packmap), &packmap),
            ),
            "stale-pair",
        )?;
        let outcome = self.advance(&conflict).await?;
        if outcome != 2 {
            return Err(format!("expected head conflict, got outcome {outcome}"));
        }
        let after_conflict = self.snapshot(&query).await?;
        if after_conflict.head != snapshot.head
            || after_conflict.packmap != snapshot.packmap
            || after_conflict.memberships != snapshot.memberships
            || after_conflict.tickets != snapshot.tickets
            || after_conflict.reservations != snapshot.reservations
            || after_conflict.replay != snapshot.replay
        {
            return Err("paired CAS conflict changed accepted effects".into());
        }
        trace.insert(CASES[2].into(), json!({"outcome": outcome, "observation": normalize(&after_conflict, &accepted.fingerprint)?}));
        let mut bad = self.unary(Rpc::AdvanceRefs, &request, "bad-signature")?;
        bad.headers = bad.headers.with_header("x-signature", "00".repeat(64));
        let refusal = self
            .client
            .unary::<AdvanceRefsResponse>(Rpc::AdvanceRefs, bad.body, &bad.headers.headers)
            .await?;
        let code = refusal.err().ok_or("invalid signature was accepted")?.code;
        if code != "unauthenticated" {
            return Err(format!("invalid signature refusal class: {code}"));
        }
        let after_refusal = self.snapshot(&query).await?;
        if after_refusal != after_conflict {
            return Err("invalid signature changed authoritative state".into());
        }
        trace.insert(
            CASES[3].into(),
            json!({"code": code, "observation": normalize(&after_refusal, &accepted.fingerprint)?}),
        );
        Ok(trace)
    }
}

fn validate_accepted(
    snapshot: &Observation,
    head: &[u8; 32],
    packmap: &[u8; 32],
    fingerprint: &str,
    before: &Observation,
    quota: bool,
) -> Result<(), String> {
    if quota {
        match (&before.quota, &snapshot.quota) {
            (Some(old), Some(new))
                if old.ops.checked_add(1) == Some(new.ops) && old.bytes == new.bytes => {}
            _ => return Err("acceptance quota effects are absent or charged incorrectly".into()),
        }
    }
    if snapshot.head != Some(to_hex(head))
        || snapshot.packmap != Some(to_hex(packmap))
        || snapshot.memberships != [true, true]
        || snapshot.tickets.len() != 2
        || snapshot
            .tickets
            .iter()
            .any(|ticket| ticket.as_ref().is_none_or(|t| t.state != "consumed"))
        || snapshot.reservations.len() != 3
        || snapshot.reservations.iter().any(|reservation| {
            reservation
                .as_ref()
                .is_none_or(|r| r.state != "committed" || r.terminal_count != 1)
        })
        || snapshot.replay.as_ref().is_none_or(|r| {
            r.state != "committed" || r.result.as_deref() != Some("advance_committed")
        })
    {
        return Err("acceptance observation violates atomic pair, replay, tickets, membership, or terminal responsibility".into());
    }
    normalize(snapshot, fingerprint).map(|_| ())
}

fn normalize(snapshot: &Observation, fingerprint: &str) -> Result<Value, String> {
    let mut snapshot = snapshot.clone();
    if let Some(replay) = &mut snapshot.replay {
        if replay.fingerprint.as_deref() != Some(fingerprint) {
            return Err("replay fingerprint does not bind the exact signed operation".into());
        }
        // The digest includes audience and opaque ticket IDs. Only after local
        // validation may it be replaced with its logical operation role.
        replay.fingerprint = Some("accepted-pair".into());
    }
    serde_json::to_value(snapshot).map_err(|e| e.to_string())
}

fn canonical_pack() -> Result<(Vec<u8>, [u8; 32]), String> {
    let tree = Object::Tree(Tree {
        entries: Vec::new(),
    });
    let tree_id = tree.id().map_err(|e| e.to_string())?;
    let key = KeyPair::from_seed([0x76; 32]);
    let mut commit = Commit::new_unannotated(
        tree_id,
        Vec::new(),
        Identity::ed25519(key.public.0),
        key.public.0,
        b"differential fixture".to_vec(),
        42,
        [0; 64],
    );
    commit.signature = sign_commit(&commit, &key).map_err(|e| e.to_string())?.0;
    let commit = Object::Commit(commit);
    let head = commit.id().map_err(|e| e.to_string())?;
    let mut writer = PackWriter::new_raw_only();
    for object in [tree, commit] {
        writer
            .push_raw(
                object.id().map_err(|e| e.to_string())?,
                &serialize(&object).map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;
    }
    Ok((writer.finish().map_err(|e| e.to_string())?, head))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn differences_preserve_array_order_and_terminal_multiplicity() {
        let left =
            json!({"tickets": ["consumed", "live"], "reservations": [{"terminal_count": 1}]});
        let right =
            json!({"tickets": ["live", "consumed"], "reservations": [{"terminal_count": 2}]});
        let mut differences = Vec::new();
        difference("", &left, &right, &mut differences);
        assert_eq!(differences.len(), 3);
        assert_eq!(differences[0].path, "/reservations/0/terminal_count");
    }

    #[test]
    fn two_failed_scenarios_never_count_as_equivalent() {
        let report = compare_traces(&Err("same error".into()), &Err("same error".into()));
        assert!(report.failed());
        assert!(
            report
                .cases
                .iter()
                .all(|case| case.status == DiffStatus::Failed)
        );
    }

    #[test]
    fn identical_invalid_observations_never_count_as_equivalent() {
        let trace: BTreeMap<_, _> = CASES
            .iter()
            .map(|name| {
                (
                    (*name).into(),
                    json!({"oracle_error": "missing terminal responsibility"}),
                )
            })
            .collect();
        let report = compare_traces(&Ok(trace.clone()), &Ok(trace));
        assert!(report.failed());
        assert!(
            report
                .cases
                .iter()
                .all(|case| case.status == DiffStatus::Failed)
        );
    }

    #[test]
    fn field_mismatch_fails_the_report() {
        let left: BTreeMap<_, _> = CASES
            .iter()
            .map(|name| {
                (
                    (*name).into(),
                    json!({"reservations": [{"terminal_count": 1}]}),
                )
            })
            .collect();
        let mut right = left.clone();
        right.get_mut(CASES[0]).unwrap()["reservations"][0]["terminal_count"] = json!(2);
        let report = compare_traces(&Ok(left), &Ok(right));
        assert!(report.failed());
        assert_eq!(
            report.cases[0].differences[0].path,
            "/reservations/0/terminal_count"
        );
    }

    #[test]
    fn missing_and_changed_fingerprints_fail_before_normalization() {
        let mut snapshot = Observation {
            head: None,
            packmap: None,
            replay: Some(crate::control::ReplayView {
                state: "committed".into(),
                result: Some("advance_committed".into()),
                fingerprint: None,
            }),
            tickets: vec![],
            reservations: vec![],
            memberships: vec![],
            quota: None,
        };
        assert!(normalize(&snapshot, "expected").is_err());
        snapshot.replay.as_mut().unwrap().fingerprint = Some("different".into());
        assert!(normalize(&snapshot, "expected").is_err());
        snapshot.replay.as_mut().unwrap().fingerprint = Some("expected".into());
        assert_eq!(
            normalize(&snapshot, "expected").unwrap()["replay"]["fingerprint"],
            "accepted-pair"
        );
    }

    #[test]
    fn canonical_fixture_is_byte_deterministic() {
        assert_eq!(canonical_pack().unwrap(), canonical_pack().unwrap());
    }
}
