//! MPP-shaped fixture. Credentials bind server-side to the Admit fingerprint;
//! the helper knows only the challenge. Test-only, feature `stubs`.
use super::hook::{FakeHook, HookBehavior, HookKey, Reply, SERVICE};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use buffa::Message;
use hmac::{Hmac, KeyInit, Mac};
use mkit_rpc::hooks::{self as proto, AdmitRequest, AdmitResponse, Header, OutcomeRequest};
use proto::__buffa::oneof::{admit_response::Decision, outcome::Kind};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::sync::{Arc, Mutex, PoisonError};

/// One RPC's scripted behavior. Normal admits only valid credentials.
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    /// MPP challenge and single-use credential flow.
    #[default]
    Normal,
    /// Always challenge, including a credentialed attempt.
    AlwaysChallenge,
    /// Deliberate 403 denial.
    Deny,
    /// Transport-style failure (503).
    Down,
    /// Hold a valid allowance until release.
    Hold,
    /// A reservation id forbidden by SPEC-SERVER §6.6.
    Invalid,
    /// The transport `AdmissionChallenge` golden, with repeated headers.
    Golden,
}
/// Control input. Omitted fields preserve their current values.
#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    /// Admit behavior.
    pub admit: Option<Mode>,
    /// Outcome behavior.
    pub outcome: Option<Mode>,
    /// Advertise Payment-Authorization for bearer deployments.
    pub bearer: Option<bool>,
}
/// Redacted outcome ledger entry. Repeated deliveries must carry the same
/// complete protobuf outcome, not merely the same terminal kind.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Delivery {
    /// One distinct terminal kind.
    pub kind: String,
    /// BLAKE3 of the canonical protobuf outcome (no credentials).
    pub digest: String,
    /// Typed abort reason, zero otherwise.
    pub reason: i32,
    /// At least once deliveries, including refused attempts.
    pub deliveries: u64,
    /// Successful acknowledgments.
    pub acknowledged: u64,
    /// Committed settles.
    pub settled: bool,
    /// Aborted and Expired release.
    pub released: bool,
}
#[derive(Default)]
struct State {
    admit: Mode,
    outcome: Mode,
    bearer: bool,
    spent: HashSet<String>,
    reservations: u64,
    calls: BTreeMap<String, u64>,
    outcomes: BTreeMap<String, Delivery>,
    gate: Option<Arc<tokio::sync::Semaphore>>,
}
struct Logic {
    secret: [u8; 32],
    state: Mutex<State>,
    clock: Arc<dyn Fn() -> i64 + Send + Sync>,
}
/// A running loopback stub using the shared §7.1 verifier and call recorder.
#[derive(Debug)]
pub struct MppStub {
    /// Underlying signed/isolated channel fixture.
    pub hook: FakeHook,
}
impl MppStub {
    /// Fresh per-run HMAC secret; no golden runtime key material.
    #[must_use]
    pub fn start(keys: Vec<HookKey>) -> Self {
        Self::start_on("127.0.0.1:0", keys, false)
    }
    /// Start on an IP socket address; unsigned only for a binding test.
    ///
    /// # Panics
    /// Non-loopback, failed RNG or listener startup.
    #[must_use]
    pub fn start_on(bind: &str, keys: Vec<HookKey>, unsigned: bool) -> Self {
        let mut secret = [0; 32];
        getrandom::fill(&mut secret).expect("per-run stub secret");
        let logic = Logic {
            secret,
            state: Mutex::new(State::default()),
            clock: Arc::new(now_ms),
        };
        Self {
            hook: FakeHook::start_with(bind, keys, unsigned, Some(Arc::new(logic))),
        }
    }
    /// Stub origin, also its signed channel audience.
    #[must_use]
    pub fn origin(&self) -> String {
        self.hook.origin()
    }
}
fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}
fn header(name: &str, value: String) -> Header {
    Header {
        name: Some(name.into()),
        value: Some(value),
        ..Default::default()
    }
}
fn json(msg: &impl Serialize) -> Reply {
    match serde_json::to_string(msg) {
        Ok(body) => Reply::json(body),
        Err(_) => Reply::status(500),
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChallengeId {
    id: String,
    expires: i64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Payload {
    proof: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Credential {
    challenge: ChallengeId,
    payload: Payload,
}
/// Helper algorithm. It does not know any fingerprint or secret.
///
/// # Errors
/// Malformed challenge; the error text never quotes it.
pub fn credential_for(value: &str) -> Result<String, &'static str> {
    let challenges = crate::wire::challenges::parse(value)?;
    let selected = challenges
        .iter()
        .find(|c| {
            c.scheme.eq_ignore_ascii_case("Payment")
                && c.params.contains_key("id")
                && c.params.contains_key("expires")
        })
        .ok_or("stub payment challenge missing")?;
    let challenge = ChallengeId {
        id: selected
            .params
            .get("id")
            .ok_or("challenge id missing")?
            .clone(),
        expires: selected
            .params
            .get("expires")
            .ok_or("challenge expiry missing")?
            .parse()
            .map_err(|_| "invalid challenge expiry")?,
    };
    let token = serde_json::to_vec(&Credential {
        challenge,
        payload: Payload {
            proof: "stub".into(),
        },
    })
    .map_err(|_| "credential serialization")?;
    Ok(format!("Payment {}", B64.encode(token)))
}
impl Logic {
    fn id(&self, req: &AdmitRequest, expires: i64) -> String {
        // A length-delimited protobuf fingerprint prevents concatenation ambiguity.
        let mut op = req.operation.as_option().cloned().unwrap_or_default();
        op.idempotency_key = None;
        op.owner = None;
        op.grant.take();
        op.refs.clear();
        let fingerprint = AdmitRequest {
            operation: op.into(),
            pack_id: req.pack_id.clone(),
            declared_bytes: req.declared_bytes,
            ..Default::default()
        };
        let mut mac =
            Hmac::<sha2::Sha256>::new_from_slice(&self.secret).expect("fixed-size HMAC key");
        mac.update(&fingerprint.encode_to_vec());
        mac.update(&expires.to_be_bytes());
        mkit_core::hash::to_hex_bytes(&mac.finalize().into_bytes())
    }
    fn challenge(&self, req: &AdmitRequest, bearer: bool, golden: bool) -> AdmitResponse {
        let expires = (self.clock)() / 1000 + 60;
        let id = self.id(req, expires);
        let audience = req
            .operation
            .as_option()
            .and_then(|op| op.audience.as_deref())
            .unwrap_or_default();
        let request = B64.encode(serde_json::to_vec(&serde_json::json!({"amount":"1","procedure":req.operation.as_option().and_then(|op| op.procedure.as_deref()).unwrap_or_default()})).unwrap_or_default());
        let value = format!(
            "Payment id=\"{id}\", realm=\"{audience}\", method=\"stub\", intent=\"charge\", request=\"{request}\", expires=\"{expires}\"{}",
            if bearer {
                ", header=\"Payment-Authorization\""
            } else {
                ""
            }
        );
        let mut challenges = vec![proto::Challenge {
            scheme: Some("payment".into()),
            value: Some(value.clone()),
            ..Default::default()
        }];
        let mut response_headers = vec![header("WWW-Authenticate", value)];
        let mut description = "Stub upload payment required.".to_owned();
        if golden {
            // Golden protobuf is transport vocabulary, decoded rather than JSON written by hand.
            let detail: mkit_transport_connect::generated::AdmissionChallenge = Message::decode(
                &mut include_bytes!("../../../../tests/golden/transport/admission-challenge.bin")
                    .as_slice(),
            )
            .expect("golden challenge");
            challenges = detail
                .challenges
                .into_iter()
                .map(|c| proto::Challenge {
                    scheme: c.scheme,
                    value: c.value,
                    ..Default::default()
                })
                .collect();
            description = detail.description.unwrap_or_default();
            response_headers.push(header("WWW-Authenticate", "Payment id=\"second\"".into()));
            response_headers.push(header("PAYMENT-REQUIRED", "stub".into()));
        }
        AdmitResponse {
            decision: Some(Decision::Challenge(
                proto::AdmitChallenge {
                    challenges,
                    description: Some(description),
                    response_headers,
                    ..Default::default()
                }
                .into(),
            )),
            ..Default::default()
        }
    }
    fn admit(&self, req: AdmitRequest, state: &mut State) -> Reply {
        if state.admit == Mode::Down {
            return Reply::status(503);
        }
        let deny = || {
            json(&AdmitResponse {
                decision: Some(Decision::Deny(
                    proto::Deny {
                        code: Some("permission_denied".into()),
                        message: Some("stub credential refused".into()),
                        ..Default::default()
                    }
                    .into(),
                )),
                ..Default::default()
            })
        };
        if state.admit == Mode::Deny {
            return deny();
        }
        if matches!(state.admit, Mode::AlwaysChallenge | Mode::Golden)
            || req.credential_headers.is_empty()
        {
            return json(&self.challenge(&req, state.bearer, state.admit == Mode::Golden));
        }
        if req.credential_headers.len() != 1 {
            return deny();
        }
        let h = &req.credential_headers[0];
        let name = if state.bearer {
            "payment-authorization"
        } else {
            "authorization"
        };
        if !h
            .name
            .as_deref()
            .is_some_and(|n| n.eq_ignore_ascii_case(name))
        {
            return deny();
        }
        let Some(token) = h.value.as_deref().and_then(|v| v.strip_prefix("Payment ")) else {
            return deny();
        };
        if token.len() > 8192
            || !token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
        {
            return deny();
        }
        let Ok(bytes) = B64.decode(token) else {
            return deny();
        };
        let Ok(credential) = serde_json::from_slice::<Credential>(&bytes) else {
            return deny();
        };
        let expires = credential.challenge.expires;
        let id = &credential.challenge.id;
        if expires <= (self.clock)() / 1000
            || credential.payload.proof != "stub"
            || *id != self.id(&req, expires)
            || !state.spent.insert(id.clone())
        {
            return deny();
        }
        state.reservations += 1;
        let rid = format!("stub:{}", state.reservations);
        let receipt = B64.encode(
            serde_json::to_vec(
                &serde_json::json!({"challengeId":id,"reference":rid,"status":"success"}),
            )
            .unwrap_or_default(),
        );
        let response = AdmitResponse {
            decision: Some(Decision::Allow(
                proto::AdmitAllow {
                    reservation_id: Some(if state.admit == Mode::Invalid {
                        "s:invalid".into()
                    } else {
                        rid
                    }),
                    response_headers: vec![header("Payment-Receipt", receipt)],
                    ..Default::default()
                }
                .into(),
            )),
            ..Default::default()
        };
        let reply = json(&response);
        if state.admit == Mode::Hold {
            reply.held(
                state
                    .gate
                    .get_or_insert_with(|| Arc::new(tokio::sync::Semaphore::new(0)))
                    .clone(),
            )
        } else {
            reply
        }
    }
    fn outcome(req: OutcomeRequest, state: &mut State) -> Reply {
        let Some(outcome) = req.outcome.as_option() else {
            return Reply::status(400);
        };
        let Some(id) = &outcome.reservation_id else {
            return Reply::status(400);
        };
        let (kind, reason) = match &outcome.kind {
            Some(Kind::Committed(_)) => ("committed", 0),
            Some(Kind::Aborted(a)) => ("aborted", a.reason.map_or(0, |r| r.to_i32())),
            Some(Kind::Expired(_)) => ("expired", 0),
            _ => return Reply::status(400),
        };
        let digest = mkit_core::hash::to_hex(&mkit_core::hash::hash(&outcome.encode_to_vec()));
        let d = state
            .outcomes
            .entry(id.clone())
            .or_insert_with(|| Delivery {
                kind: kind.into(),
                digest: digest.clone(),
                reason,
                deliveries: 0,
                acknowledged: 0,
                settled: false,
                released: false,
            });
        if d.digest != digest || d.kind != kind {
            return Reply::status(409);
        }
        d.deliveries += 1;
        if state.outcome == Mode::Down {
            return Reply::status(503);
        }
        d.acknowledged += 1;
        d.settled = kind == "committed";
        d.released = kind != "committed";
        json(&proto::OutcomeResponse::default())
    }
}
impl HookBehavior for Logic {
    fn reply(&self, path: &str, body: &[u8]) -> Option<Reply> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        Some(match path {
            "/__stub/mode" if body.is_empty() => json(&Settings {
                admit: Some(state.admit),
                outcome: Some(state.outcome),
                bearer: Some(state.bearer),
            }),
            "/__stub/mode" => match serde_json::from_slice::<Settings>(body) {
                Ok(s) => {
                    if let Some(mode) = s.admit {
                        state.admit = mode;
                    }
                    if let Some(mode) = s.outcome {
                        state.outcome = mode;
                    }
                    if let Some(b) = s.bearer {
                        state.bearer = b;
                    }
                    json(&serde_json::json!({}))
                }
                Err(_) => Reply::status(400),
            },
            "/__stub/calls" => json(&state.calls),
            "/__stub/outcomes" => json(&state.outcomes),
            "/__stub/release" => {
                if let Some(gate) = state.gate.take() {
                    gate.add_permits(1024);
                }
                json(&serde_json::json!({}))
            }
            _ if path == format!("{SERVICE}/Admit") => {
                *state.calls.entry("Admit".into()).or_default() += 1;
                match serde_json::from_slice(body) {
                    Ok(req) => self.admit(req, &mut state),
                    Err(_) => Reply::status(400),
                }
            }
            _ if path == format!("{SERVICE}/Outcome") => {
                *state.calls.entry("Outcome".into()).or_default() += 1;
                match serde_json::from_slice(body) {
                    Ok(req) => Self::outcome(req, &mut state),
                    Err(_) => Reply::status(400),
                }
            }
            _ => return None,
        })
    }
}

#[cfg(test)]
#[path = "mpp_tests.rs"]
mod tests;
