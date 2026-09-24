// SPDX-License-Identifier: MIT OR Apache-2.0
//! Owner-only hosted grant registry. All state and replay results share one SQL transaction.
use super::{managed::AdminWire, refstore::RefStore};
use crate::access_policy::{Identity, Policy, generation};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use mkit_hosting_policy::{grant_id, verify_signature};
use mkit_worker_common::replay::Reply;
use serde::{Deserialize, Serialize};
use worker::{Date, Request, Response, Result};

const UNAVAILABLE: &str = "{\"code\":\"unavailable\"}";
const INVALID: &str = "{\"code\":\"invalid_argument\"}";
const CONFLICT: &str = "{\"code\":\"conflict\"}";
const NOT_FOUND: &str = "{\"code\":\"not_found\"}";
const CAPACITY: &str = "{\"code\":\"resource_exhausted\"}";
const MAX_WORKSPACES: u64 = 1024;
const MAX_INCARNS: u64 = 4096;
const MAX_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Clone, Copy)]
#[cfg_attr(feature = "test-faults", derive(Serialize))]
struct Limits {
    workspaces: u64,
    incarnations: u64,
    bytes: u64,
}
impl Limits {
    fn default_profile() -> Self {
        Self {
            workspaces: MAX_WORKSPACES,
            incarnations: MAX_INCARNS,
            bytes: MAX_BYTES,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Register {
    version: u8,
    expected_grant_generation: String,
    grant: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Revoke {
    version: u8,
    workspace_id: String,
    expected_grant_generation: String,
    grant_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Get {
    version: u8,
    workspace_id: String,
}

#[derive(Serialize)]
struct MutationReply<'a> {
    version: u8,
    workspace_id: &'a str,
    grant_id: &'a str,
    grant_generation: String,
    status: &'a str,
}
#[derive(Serialize)]
struct GetReply<'a> {
    version: u8,
    workspace_id: &'a str,
    grant_id: &'a str,
    grant_generation: &'a str,
    status: &'a str,
    grant: &'a str,
    initial_base: &'a str,
    workspace_head: &'a str,
    authority_generation_matches: bool,
    time_valid: bool,
    snapshot_readiness: &'static str,
    // Owner-only test-faults diagnostic. Absent from production type and JSON.
    #[cfg(feature = "test-faults")]
    test_limits: Limits,
}
#[derive(Deserialize)]
struct Meta {
    schema_version: i64,
    workspaces: String,
    incarnations: String,
    envelope_bytes: String,
}
#[derive(Deserialize)]
struct Workspace {
    current_generation: String,
    audience: String,
    exact_ref: String,
    issuer: String,
    subject: String,
    receipt_signer: String,
    workspace_head: String,
}
#[derive(Deserialize)]
struct Incarnation {
    grant_id: String,
    envelope: String,
    authority_generation: String,
    initial_base: String,
    not_before: String,
    expires: String,
    status: String,
    consumed_operations: String,
}

fn decimal(text: &str) -> Option<u64> {
    generation(text).ok()
}
fn id(text: &str) -> bool {
    mkit_core::write_auth::is_hex(text, 32)
}
fn decode_json<T: serde::de::DeserializeOwned>(text: &str) -> Option<T> {
    let mut decoder = serde_json::Deserializer::from_str(text);
    let value = T::deserialize(&mut decoder).ok()?;
    decoder.end().ok()?;
    Some(value)
}
fn invalid() -> Result<Reply> {
    Reply::error(INVALID, 400)
}
fn conflict() -> Result<Reply> {
    Reply::error(CONFLICT, 409)
}
fn unavailable() -> Result<Reply> {
    Reply::error(UNAVAILABLE, 503)
}
fn hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}
fn now() -> u64 {
    Date::now().as_millis()
}

fn valid_wire(wire: &AdminWire, configured: &Identity) -> bool {
    wire.identity == *configured
        && wire.proof.author == configured.owner
        && mkit_core::write_auth::is_hex(&wire.proof.scope, 32)
        && mkit_core::write_auth::is_hex(&wire.proof.fingerprint, 32)
}

pub(super) enum DisclosureGrant {
    Allowed(String, String),
    Denied,
    Conflict,
}

pub(super) enum SubmissionGrant {
    Allowed {
        consumed: u64,
        maximum: u64,
        policy_generation: String,
    },
    Denied,
    Conflict,
}

impl RefStore {
    /// Submission effects require the *current* signed incarnation, not a
    /// previously verified grant or an owner's legacy transport permission.
    /// Called inside the caller's short SQL transaction, including after a
    /// nonce replay lookup. The returned counter ceiling is signed MKHG data.
    pub(super) fn submission_grant(
        &self,
        identity: &Identity,
        proof: &mkit_worker_common::replay::Proof,
        request: &crate::submission_wire::BeginSubmission,
    ) -> Result<SubmissionGrant> {
        let Some(policy) = self.read_policy(identity)? else {
            return Ok(SubmissionGrant::Denied);
        };
        let authority = policy
            .validate(identity)
            .map_err(|_| worker::Error::RustError("invalid policy".into()))?;
        let Some(workspace) = self.workspace(&identity.repository, &request.workspace_id)? else {
            return Ok(SubmissionGrant::Denied);
        };
        if workspace.audience != identity.audience
            || workspace.issuer != identity.owner
            || workspace.subject != proof.author
            || now() as i64 > proof.expires_at
        {
            return Ok(SubmissionGrant::Denied);
        }
        let row = self.incarnation(
            &identity.repository,
            &request.workspace_id,
            &workspace.current_generation,
            &workspace,
        )?;
        if row.status != "active"
            || row.grant_id != request.grant_id
            || decimal(&row.not_before).is_none_or(|start| start > now())
            || decimal(&row.expires).is_none_or(|end| now() >= end)
        {
            return Ok(SubmissionGrant::Denied);
        }
        let raw = URL_SAFE_NO_PAD
            .decode(&row.envelope)
            .map_err(|_| worker::Error::RustError("corrupt grant".into()))?;
        let grant =
            verify_signature(&raw).map_err(|_| worker::Error::RustError("corrupt grant".into()))?;
        for path in &request.selected_paths {
            if !grant
                .fields
                .entries
                .iter()
                .any(|entry| entry.mask & 1 == 1 && entry.components == *path)
            {
                return Ok(SubmissionGrant::Denied);
            }
        }
        if workspace.current_generation != request.grant_generation
            || workspace.exact_ref != request.expected_ref
            || workspace.workspace_head != request.expected_base
            || decimal(&row.authority_generation) != Some(authority)
        {
            return Ok(SubmissionGrant::Conflict);
        }
        let consumed = decimal(&row.consumed_operations)
            .ok_or_else(|| worker::Error::RustError("corrupt grant counter".into()))?;
        Ok(SubmissionGrant::Allowed {
            consumed,
            maximum: u64::from(grant.fields.max_operations),
            policy_generation: policy.generation,
        })
    }

    /// Must be in the same SQL transaction as a new lifetime identity row.
    /// An exact replay never invokes this method.
    pub(super) fn submission_charge_grant(
        &self,
        identity: &Identity,
        request: &crate::submission_wire::BeginSubmission,
        consumed: u64,
        maximum: u64,
    ) -> Result<bool> {
        let Some(next) = consumed.checked_add(1).filter(|value| *value <= maximum) else {
            return Ok(false);
        };
        #[derive(serde::Deserialize)]
        struct Charged {
            consumed_operations: String,
        }
        let rows: Vec<Charged> = self.state.storage().sql().exec(
            "UPDATE host_grant_incarnations SET consumed_operations=? WHERE repository=? AND workspace_id=? AND grant_generation=? AND grant_id=? AND consumed_operations=? AND status='active' RETURNING consumed_operations",
            vec![next.to_string().into(), identity.repository.clone().into(), request.workspace_id.clone().into(), request.grant_generation.clone().into(), request.grant_id.clone().into(), consumed.to_string().into()],
        )?.to_array()?;
        if rows.len() != 1 || rows[0].consumed_operations != next.to_string() {
            return Err(worker::Error::RustError("grant charge fence failed".into()));
        }
        Ok(true)
    }

    /// All actual changed files must be in the immutable declared selection
    /// and carry the signed READ|REPLACE bit. READ-only grants never mutate.
    pub(super) fn submission_changes_allowed(
        &self,
        identity: &Identity,
        proof: &mkit_worker_common::replay::Proof,
        request: &crate::submission_wire::BeginSubmission,
        changes: &[Vec<Vec<u8>>],
    ) -> Result<bool> {
        if !matches!(
            self.submission_grant(identity, proof, request)?,
            SubmissionGrant::Allowed { .. }
        ) {
            return Ok(false);
        }
        let workspace = self
            .workspace(&identity.repository, &request.workspace_id)?
            .ok_or_else(|| worker::Error::RustError("missing workspace".into()))?;
        let row = self.incarnation(
            &identity.repository,
            &request.workspace_id,
            &workspace.current_generation,
            &workspace,
        )?;
        let raw = URL_SAFE_NO_PAD
            .decode(&row.envelope)
            .map_err(|_| worker::Error::RustError("corrupt grant".into()))?;
        let grant =
            verify_signature(&raw).map_err(|_| worker::Error::RustError("corrupt grant".into()))?;
        for changed in changes {
            let selected = request.selected_paths.iter().any(|path| {
                path.len() == changed.len()
                    && path.iter().zip(changed).all(|(a, b)| a.as_bytes() == b)
            });
            let replace = grant.fields.entries.iter().any(|entry| {
                entry.mask == 3
                    && entry.components.len() == changed.len()
                    && entry
                        .components
                        .iter()
                        .zip(changed)
                        .all(|(a, b)| a.as_bytes() == b)
            });
            if !selected || !replace {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Live subject authority for a single exact selection. The signed MKHG
    /// is rechecked from the current registry row; a proof or structural
    /// certificate alone is never a read capability.
    pub(super) fn disclosure_grant(
        &self,
        identity: &Identity,
        proof: &mkit_worker_common::replay::Proof,
        request: &crate::snapshot_wire::GetWorkspace,
    ) -> Result<DisclosureGrant> {
        let Some(policy) = self.read_policy(identity)? else {
            return Ok(DisclosureGrant::Denied);
        };
        let authority = policy
            .validate(identity)
            .map_err(|_| worker::Error::RustError("invalid policy".into()))?;
        let Some(workspace) = self.workspace(&identity.repository, &request.workspace_id)? else {
            return Ok(DisclosureGrant::Denied);
        };
        if workspace.audience != identity.audience
            || workspace.issuer != identity.owner
            || workspace.subject != proof.author
            || Date::now().as_millis() as i64 > proof.expires_at
        {
            return Ok(DisclosureGrant::Denied);
        }
        let row = self.incarnation(
            &identity.repository,
            &request.workspace_id,
            &workspace.current_generation,
            &workspace,
        )?;
        if row.status != "active"
            || row.grant_id != request.grant_id
            || decimal(&row.not_before).is_none_or(|start| start > now())
            || decimal(&row.expires).is_none_or(|end| now() >= end)
        {
            return Ok(DisclosureGrant::Denied);
        }
        let raw = URL_SAFE_NO_PAD
            .decode(&row.envelope)
            .map_err(|_| worker::Error::RustError("corrupt grant".into()))?;
        let grant =
            verify_signature(&raw).map_err(|_| worker::Error::RustError("corrupt grant".into()))?;
        for path in &request.paths {
            if !grant
                .fields
                .entries
                .iter()
                .any(|entry| entry.mask & 1 == 1 && entry.components == *path)
            {
                return Ok(DisclosureGrant::Denied);
            }
        }
        // Only a live subject with exact READ path authority may learn that
        // its own registered context assertion is stale.
        if workspace.current_generation != request.grant_generation
            || workspace.exact_ref != request.expected_ref
            || workspace.workspace_head != request.expected_base
            || decimal(&row.authority_generation) != Some(authority)
        {
            return Ok(DisclosureGrant::Conflict);
        }
        Ok(DisclosureGrant::Allowed(
            workspace.exact_ref,
            workspace.workspace_head,
        ))
    }

    /// Recheck mutable authority fields after an R2 await. The signed
    /// envelope and exact selected paths were authenticated before the first
    /// locator; an incarnation's envelope is immutable across a generation.
    pub(super) fn disclosure_grant_current(
        &self,
        identity: &Identity,
        proof: &mkit_worker_common::replay::Proof,
        request: &crate::snapshot_wire::GetWorkspace,
    ) -> Result<bool> {
        let Some(policy) = self.read_policy(identity)? else {
            return Ok(false);
        };
        let authority = policy
            .validate(identity)
            .map_err(|_| worker::Error::RustError("invalid policy".into()))?;
        let Some(workspace) = self.workspace(&identity.repository, &request.workspace_id)? else {
            return Ok(false);
        };
        if workspace.current_generation != request.grant_generation
            || workspace.exact_ref != request.expected_ref
            || workspace.workspace_head != request.expected_base
            || workspace.audience != identity.audience
            || workspace.issuer != identity.owner
            || workspace.subject != proof.author
            || now() as i64 > proof.expires_at
        {
            return Ok(false);
        }
        #[derive(Deserialize)]
        struct Live {
            grant_id: String,
            authority_generation: String,
            not_before: String,
            expires: String,
            status: String,
        }
        let rows: Vec<Live> = self.state.storage().sql().exec(
            "SELECT grant_id,authority_generation,not_before,expires,status FROM host_grant_incarnations WHERE repository=? AND workspace_id=? AND grant_generation=?",
            vec![identity.repository.clone().into(), request.workspace_id.clone().into(), request.grant_generation.clone().into()],
        )?.to_array()?;
        let Some(row) = rows.first() else {
            return Ok(false);
        };
        Ok(rows.len() == 1
            && row.grant_id == request.grant_id
            && row.status == "active"
            && decimal(&row.authority_generation) == Some(authority)
            && decimal(&row.not_before).is_some_and(|start| start <= now())
            && decimal(&row.expires).is_some_and(|end| now() < end))
    }
    fn grant_limits(&self) -> Result<Limits> {
        let limits = Limits::default_profile();
        #[cfg(feature = "test-faults")]
        if let Ok(setting) = self.env.var("GRANT_TEST_LIMITS") {
            let value = setting.to_string();
            let parts: Vec<_> = value.split(',').collect();
            if parts.len() != 3 {
                return Err(worker::Error::RustError("invalid test grant limits".into()));
            }
            let parse = |text: &str, maximum| {
                decimal(text)
                    .filter(|v| *v > 0 && *v <= maximum)
                    .ok_or_else(|| worker::Error::RustError("invalid test grant limit".into()))
            };
            return Ok(Limits {
                workspaces: parse(parts[0], limits.workspaces)?,
                incarnations: parse(parts[1], limits.incarnations)?,
                bytes: parse(parts[2], limits.bytes)?,
            });
        }
        Ok(limits)
    }
    pub(super) async fn managed_grant(&self, req: &mut Request) -> Result<Response> {
        if req.method() != worker::Method::Post {
            return unavailable()?.response();
        }
        let wire: AdminWire = match req.json().await {
            Ok(v) => v,
            Err(_) => return invalid()?.response(),
        };
        let configured = match (
            self.env.var("AUTH_AUDIENCE"),
            self.env.var("AUTH_REPOSITORY"),
            self.env.var("MANAGED_OWNER_PUBLIC_KEY"),
        ) {
            (Ok(a), Ok(r), Ok(o)) => {
                Identity::parse(&a.to_string(), &r.to_string(), &o.to_string())
            }
            _ => Err("missing configuration"),
        };
        let Ok(configured) = configured else {
            return unavailable()?.response();
        };
        if !valid_wire(&wire, &configured) {
            return unavailable()?.response();
        }
        if Date::now().as_millis() as i64 > wire.proof.expires_at {
            return Reply::error("{\"code\":\"unauthenticated\"}", 401)?.response();
        }
        let owned = self.clone();
        let result = self.ledger.transaction(move || owned.apply_grant(wire));
        match result {
            Ok(reply) => reply.response(),
            Err(_) => unavailable()?.response(),
        }
    }

    fn apply_grant(&self, wire: AdminWire) -> Result<Reply> {
        // The configured identity is already checked at the DO boundary. The
        // persisted latch is checked here again, before any replay lookup.
        let policy = match self.read_policy(&wire.identity)? {
            Some(p) => p,
            None => return unavailable(),
        };
        let authority = policy
            .validate(&wire.identity)
            .map_err(|_| worker::Error::RustError("invalid policy".into()))?;
        match wire.operation.as_str() {
            "register_grant" => self.register(&wire, &policy, authority),
            "revoke_grant" => self.revoke(&wire),
            "get_grant" => self.get(&wire, authority),
            _ => unavailable(),
        }
    }

    fn registry_meta(&self) -> Result<Option<Meta>> {
        #[derive(Deserialize)]
        struct Name {
            name: String,
        }
        let names: Vec<Name> = self.state.storage().sql().exec(
            "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'host_grant_%' ORDER BY name", None
        )?.to_array()?;
        let actual: Vec<_> = names.iter().map(|n| n.name.as_str()).collect();
        if actual.is_empty() {
            return Ok(None);
        }
        if actual
            != [
                "host_grant_incarnations",
                "host_grant_meta",
                "host_grant_workspaces",
            ]
        {
            return Err(worker::Error::RustError("incomplete grant schema".into()));
        }
        let rows: Vec<Meta> = self.state.storage().sql().exec(
            "SELECT schema_version, workspaces, incarnations, envelope_bytes FROM host_grant_meta WHERE slot=1", None
        )?.to_array()?;
        if rows.len() != 1 {
            return Err(worker::Error::RustError("missing grant metadata".into()));
        }
        let meta = rows.into_iter().next().expect("length checked");
        if meta.schema_version != 1
            || decimal(&meta.workspaces).is_none()
            || decimal(&meta.incarnations).is_none()
            || decimal(&meta.envelope_bytes).is_none()
        {
            return Err(worker::Error::RustError("invalid grant metadata".into()));
        }
        if decimal(&meta.workspaces).unwrap() > MAX_WORKSPACES
            || decimal(&meta.incarnations).unwrap() > MAX_INCARNS
            || decimal(&meta.envelope_bytes).unwrap() > MAX_BYTES
        {
            return Err(worker::Error::RustError(
                "grant metadata exceeds cap".into(),
            ));
        }
        #[derive(Deserialize)]
        struct Count {
            n: i64,
        }
        #[derive(Deserialize)]
        struct StoredBytes {
            n: i64,
        }
        let w: Vec<Count> = self
            .state
            .storage()
            .sql()
            .exec("SELECT COUNT(*) AS n FROM host_grant_workspaces", None)?
            .to_array()?;
        let i: Vec<Count> = self
            .state
            .storage()
            .sql()
            .exec("SELECT COUNT(*) AS n FROM host_grant_incarnations", None)?
            .to_array()?;
        let b: Vec<StoredBytes> = self
            .state
            .storage()
            .sql()
            .exec(
                "SELECT COALESCE(SUM((LENGTH(envelope)*3)/4),0) AS n FROM host_grant_incarnations",
                None,
            )?
            .to_array()?;
        if w.first().map(|v| v.n as u64) != decimal(&meta.workspaces)
            || i.first().map(|v| v.n as u64) != decimal(&meta.incarnations)
            || b.first().map(|v| v.n as u64) != decimal(&meta.envelope_bytes)
        {
            return Err(worker::Error::RustError(
                "grant registry counter mismatch".into(),
            ));
        }
        Ok(Some(meta))
    }

    fn bootstrap(&self) -> Result<()> {
        self.state.storage().sql().exec("CREATE TABLE host_grant_meta (slot INTEGER PRIMARY KEY CHECK(slot=1), schema_version INTEGER NOT NULL, workspaces TEXT NOT NULL, incarnations TEXT NOT NULL, envelope_bytes TEXT NOT NULL)", None)?;
        self.state.storage().sql().exec("CREATE TABLE host_grant_workspaces (repository TEXT NOT NULL, workspace_id TEXT NOT NULL, current_generation TEXT NOT NULL, audience TEXT NOT NULL, exact_ref TEXT NOT NULL, issuer TEXT NOT NULL, subject TEXT NOT NULL, receipt_signer TEXT NOT NULL, workspace_head TEXT NOT NULL, PRIMARY KEY(repository, workspace_id))", None)?;
        self.state.storage().sql().exec("CREATE TABLE host_grant_incarnations (repository TEXT NOT NULL, workspace_id TEXT NOT NULL, grant_generation TEXT NOT NULL, grant_id TEXT NOT NULL, envelope TEXT NOT NULL, authority_generation TEXT NOT NULL, initial_base TEXT NOT NULL, not_before TEXT NOT NULL, expires TEXT NOT NULL, status TEXT NOT NULL, consumed_operations TEXT NOT NULL, PRIMARY KEY(repository, workspace_id, grant_generation), UNIQUE(repository, grant_id))", None)?;
        self.state
            .storage()
            .sql()
            .exec("INSERT INTO host_grant_meta VALUES (1,1,'0','0','0')", None)?;
        Ok(())
    }

    fn workspace(&self, repo: &str, workspace_id: &str) -> Result<Option<Workspace>> {
        let rows: Vec<Workspace> = self.state.storage().sql().exec("SELECT current_generation,audience,exact_ref,issuer,subject,receipt_signer,workspace_head FROM host_grant_workspaces WHERE repository=? AND workspace_id=?", vec![repo.into(), workspace_id.into()])?.to_array()?;
        if rows.len() > 1 {
            return Err(worker::Error::RustError("duplicate workspace".into()));
        }
        let row = rows.into_iter().next();
        if row
            .as_ref()
            .is_some_and(|w| decimal(&w.current_generation).is_none() || !id(&w.workspace_head))
        {
            return Err(worker::Error::RustError("corrupt workspace".into()));
        }
        Ok(row)
    }
    fn incarnation(
        &self,
        repo: &str,
        workspace_id: &str,
        generation: &str,
        workspace: &Workspace,
    ) -> Result<Incarnation> {
        let rows: Vec<Incarnation> = self.state.storage().sql().exec("SELECT grant_id,envelope,authority_generation,initial_base,not_before,expires,status,consumed_operations FROM host_grant_incarnations WHERE repository=? AND workspace_id=? AND grant_generation=?", vec![repo.into(), workspace_id.into(), generation.into()])?.to_array()?;
        if rows.len() != 1 {
            return Err(worker::Error::RustError(
                "missing current incarnation".into(),
            ));
        }
        let row = rows.into_iter().next().expect("length checked");
        if !id(&row.grant_id)
            || !id(&row.initial_base)
            || decimal(&row.authority_generation).is_none()
            || decimal(&row.not_before).is_none()
            || decimal(&row.expires).is_none()
            || decimal(&row.consumed_operations).is_none()
            || !["active", "revoked"].contains(&row.status.as_str())
        {
            return Err(worker::Error::RustError(
                "corrupt current incarnation".into(),
            ));
        }
        let raw = URL_SAFE_NO_PAD
            .decode(&row.envelope)
            .map_err(|_| worker::Error::RustError("corrupt envelope".into()))?;
        let grant = verify_signature(&raw)
            .map_err(|_| worker::Error::RustError("corrupt grant bytes".into()))?;
        let fields = &grant.fields;
        if URL_SAFE_NO_PAD.encode(&raw) != row.envelope
            || hex(&grant_id(&raw)) != row.grant_id
            || fields.repository != repo
            || hex(&fields.workspace_id) != workspace_id
            || fields.grant_generation.to_string() != generation
            || fields.authority_generation.to_string() != row.authority_generation
            || hex(&fields.initial_base) != row.initial_base
            || fields.not_before.to_string() != row.not_before
            || fields.expires.to_string() != row.expires
            || fields.audience != workspace.audience
            || fields.exact_ref != workspace.exact_ref
            || hex(&fields.issuer) != workspace.issuer
            || hex(&fields.subject) != workspace.subject
            || hex(&fields.receipt_signer) != workspace.receipt_signer
            || decimal(&row.consumed_operations).unwrap() > u64::from(fields.max_operations)
        {
            return Err(worker::Error::RustError(
                "grant row disagrees with signed bytes".into(),
            ));
        }
        Ok(row)
    }

    fn register(&self, wire: &AdminWire, _policy: &Policy, authority: u64) -> Result<Reply> {
        let limits = self.grant_limits()?;
        // Parse before reservation; malformed requests leave no replay state.
        let Some(request): Option<Register> = decode_json(&wire.body) else {
            return invalid();
        };
        if request.version != 1 {
            return invalid();
        }
        let Some(expected) = decimal(&request.expected_grant_generation) else {
            return invalid();
        };
        if request.grant.len() > (mkit_hosting_policy::MAX_ENVELOPE * 4).div_ceil(3) {
            return invalid();
        }
        let Ok(raw) = URL_SAFE_NO_PAD.decode(&request.grant) else {
            return invalid();
        };
        if raw.len() > mkit_hosting_policy::MAX_ENVELOPE
            || URL_SAFE_NO_PAD.encode(&raw) != request.grant
        {
            return invalid();
        }
        let Ok(grant) = verify_signature(&raw) else {
            return invalid();
        };
        let fields = &grant.fields;
        let workspace_id = hex(&fields.workspace_id);
        let grant_id = hex(&grant_id(&raw));
        let meta = self.registry_meta()?;
        let current = if meta.is_some() {
            self.workspace(&wire.identity.repository, &workspace_id)?
        } else {
            None
        };
        // Exact valid-TTL replay skips grant-time and CAS. The outer policy
        // availability was checked already. Here the pure grant fields may
        // have expired, so lookup must happen before those checks: see below.
        let prior = self
            .ledger
            .reserve(&wire.proof, Date::now().as_millis() as i64, || {
                if fields.audience != wire.identity.audience
                    || fields.repository != wire.identity.repository
                    || hex(&fields.issuer) != wire.identity.owner
                    || fields.authority_generation != authority
                    || !(fields.not_before <= now() && now() < fields.expires)
                {
                    return Ok(Some(invalid()?));
                }
                if current.as_ref().map_or(expected != 0, |w| {
                    decimal(&w.current_generation) != Some(expected)
                }) {
                    return Ok(Some(conflict()?));
                }
                if fields.grant_generation != expected.checked_add(1).unwrap_or(0) {
                    return Ok(Some(conflict()?));
                }
                if let Some(w) = &current {
                    if w.audience != fields.audience
                        || w.exact_ref != fields.exact_ref
                        || w.issuer != hex(&fields.issuer)
                        || w.subject != hex(&fields.subject)
                        || w.receipt_signer != hex(&fields.receipt_signer)
                    {
                        return Ok(Some(conflict()?));
                    }
                    let _ = self.incarnation(
                        &wire.identity.repository,
                        &workspace_id,
                        &w.current_generation,
                        w,
                    )?;
                }
                let has_refs: Vec<serde_json::Value> = self
                    .state
                    .storage()
                    .sql()
                    .exec(
                        "SELECT name FROM sqlite_master WHERE type='table' AND name='refs'",
                        None,
                    )?
                    .to_array()?;
                if has_refs.len() != 1 {
                    return Ok(Some(conflict()?));
                }
                if self.read_ref(&fields.exact_ref)?.as_deref()
                    != Some(hex(&fields.initial_base).as_str())
                {
                    return Ok(Some(conflict()?));
                }
                let (workspaces, incarnations, bytes) = meta.as_ref().map_or((0, 0, 0), |m| {
                    (
                        decimal(&m.workspaces).unwrap(),
                        decimal(&m.incarnations).unwrap(),
                        decimal(&m.envelope_bytes).unwrap(),
                    )
                });
                if workspaces
                    .checked_add(u64::from(current.is_none()))
                    .is_none_or(|v| v > limits.workspaces)
                    || incarnations
                        .checked_add(1)
                        .is_none_or(|v| v > limits.incarnations)
                    || bytes
                        .checked_add(raw.len() as u64)
                        .is_none_or(|v| v > limits.bytes)
                {
                    return Ok(Some(Reply::error(CAPACITY, 429)?));
                }
                Ok(None)
            });
        let prior = match prior {
            Ok(v) => v,
            Err(e) => return replay_error(e),
        };
        if let Some(Some(reply)) = prior {
            return Ok(reply);
        }
        if let Some(None) = prior {
            return unavailable();
        }
        if meta.is_none() {
            self.bootstrap()?;
        }
        if let Some(w) = current {
            self.state.storage().sql().exec("UPDATE host_grant_incarnations SET status='superseded' WHERE repository=? AND workspace_id=? AND grant_generation=? AND status='active'", vec![fields.repository.clone().into(), workspace_id.clone().into(), w.current_generation.into()])?;
            self.state.storage().sql().exec("UPDATE host_grant_workspaces SET current_generation=?,workspace_head=? WHERE repository=? AND workspace_id=?", vec![fields.grant_generation.to_string().into(), hex(&fields.initial_base).into(), fields.repository.clone().into(), workspace_id.clone().into()])?;
        } else {
            self.state.storage().sql().exec(
                "INSERT INTO host_grant_workspaces VALUES (?,?,?,?,?,?,?,?,?)",
                vec![
                    fields.repository.clone().into(),
                    workspace_id.clone().into(),
                    fields.grant_generation.to_string().into(),
                    fields.audience.clone().into(),
                    fields.exact_ref.clone().into(),
                    hex(&fields.issuer).into(),
                    hex(&fields.subject).into(),
                    hex(&fields.receipt_signer).into(),
                    hex(&fields.initial_base).into(),
                ],
            )?;
        }
        self.state.storage().sql().exec(
            "INSERT INTO host_grant_incarnations VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            vec![
                fields.repository.clone().into(),
                workspace_id.clone().into(),
                fields.grant_generation.to_string().into(),
                grant_id.clone().into(),
                request.grant.into(),
                authority.to_string().into(),
                hex(&fields.initial_base).into(),
                fields.not_before.to_string().into(),
                fields.expires.to_string().into(),
                "active".into(),
                "0".into(),
            ],
        )?;
        let (w, i, b) = meta.map_or((0, 0, 0), |m| {
            (
                decimal(&m.workspaces).unwrap(),
                decimal(&m.incarnations).unwrap(),
                decimal(&m.envelope_bytes).unwrap(),
            )
        });
        self.state.storage().sql().exec(
            "UPDATE host_grant_meta SET workspaces=?,incarnations=?,envelope_bytes=? WHERE slot=1",
            vec![
                (w + u64::from(expected == 0)).to_string().into(),
                (i + 1).to_string().into(),
                (b + raw.len() as u64).to_string().into(),
            ],
        )?;
        let reply = Reply::json(&MutationReply {
            version: 1,
            workspace_id: &workspace_id,
            grant_id: &grant_id,
            grant_generation: fields.grant_generation.to_string(),
            status: "active",
        })?;
        self.ledger.finish(&wire.proof, &reply)?;
        Ok(reply)
    }

    fn revoke(&self, wire: &AdminWire) -> Result<Reply> {
        let Some(request): Option<Revoke> = decode_json(&wire.body) else {
            return invalid();
        };
        if request.version != 1
            || !id(&request.workspace_id)
            || !id(&request.grant_id)
            || decimal(&request.expected_grant_generation).is_none()
        {
            return invalid();
        }
        let Some(_) = self.registry_meta()? else {
            return conflict();
        };
        let current = self.workspace(&wire.identity.repository, &request.workspace_id)?;
        let prior = self
            .ledger
            .reserve(&wire.proof, Date::now().as_millis() as i64, || {
                let Some(w) = &current else {
                    return Ok(Some(conflict()?));
                };
                if w.current_generation != request.expected_grant_generation {
                    return Ok(Some(conflict()?));
                }
                let incarnation = self.incarnation(
                    &wire.identity.repository,
                    &request.workspace_id,
                    &w.current_generation,
                    w,
                )?;
                if incarnation.status != "active" || incarnation.grant_id != request.grant_id {
                    return Ok(Some(conflict()?));
                }
                Ok(None)
            });
        let prior = match prior {
            Ok(v) => v,
            Err(e) => return replay_error(e),
        };
        if let Some(Some(reply)) = prior {
            return Ok(reply);
        }
        if let Some(None) = prior {
            return unavailable();
        }
        self.state.storage().sql().exec("UPDATE host_grant_incarnations SET status='revoked' WHERE repository=? AND workspace_id=? AND grant_generation=?", vec![wire.identity.repository.clone().into(), request.workspace_id.clone().into(), request.expected_grant_generation.clone().into()])?;
        let reply = Reply::json(&MutationReply {
            version: 1,
            workspace_id: &request.workspace_id,
            grant_id: &request.grant_id,
            grant_generation: request.expected_grant_generation,
            status: "revoked",
        })?;
        self.ledger.finish(&wire.proof, &reply)?;
        Ok(reply)
    }

    fn get(&self, wire: &AdminWire, authority: u64) -> Result<Reply> {
        let Some(request): Option<Get> = decode_json(&wire.body) else {
            return invalid();
        };
        if request.version != 1 || !id(&request.workspace_id) {
            return invalid();
        }
        let Some(_) = self.registry_meta()? else {
            return Reply::error(NOT_FOUND, 404);
        };
        let Some(workspace) = self.workspace(&wire.identity.repository, &request.workspace_id)?
        else {
            return Reply::error(NOT_FOUND, 404);
        };
        let row = self.incarnation(
            &wire.identity.repository,
            &request.workspace_id,
            &workspace.current_generation,
            &workspace,
        )?;
        let time_valid =
            decimal(&row.not_before).unwrap() <= now() && now() < decimal(&row.expires).unwrap();
        Reply::json(&GetReply {
            version: 1,
            workspace_id: &request.workspace_id,
            grant_id: &row.grant_id,
            grant_generation: &workspace.current_generation,
            status: &row.status,
            grant: &row.envelope,
            initial_base: &row.initial_base,
            workspace_head: &workspace.workspace_head,
            authority_generation_matches: decimal(&row.authority_generation) == Some(authority),
            time_valid,
            snapshot_readiness: "not_checked",
            #[cfg(feature = "test-faults")]
            test_limits: self.grant_limits()?,
        })
    }
}

fn replay_error(error: worker::Error) -> Result<Reply> {
    let text = error.to_string();
    if text.contains("nonce reused for a different operation") {
        conflict()
    } else if text.contains("signed operation expired") {
        Reply::error("{\"code\":\"unauthenticated\"}", 401)
    } else {
        unavailable()
    }
}
