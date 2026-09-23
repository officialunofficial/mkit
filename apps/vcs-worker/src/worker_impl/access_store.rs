// SPDX-License-Identifier: MIT OR Apache-2.0
//! Durable one-repository authority. Every mutation and replay result shares
//! the replay ledger's synchronous SQLite transaction.
use super::{managed::AdminWire, refstore::RefStore};
use crate::access_policy::{
    DataRoute, GetRequest, Identity, InitializeRequest, Policy, ReplaceRequest, decode, generation,
    validate_collaborators,
};
use mkit_worker_common::replay::{Proof, Reply};
use serde::Deserialize;
use worker::{Date, Request, Response, Result};

const UNAVAILABLE: &str = "{\"code\":\"unavailable\"}";
const INVALID: &str = "{\"code\":\"invalid_argument\"}";
const CONFLICT: &str = "{\"code\":\"conflict\"}";

fn replay_error(error: worker::Error) -> Result<Reply> {
    let message = error.to_string();
    if message.contains("nonce reused for a different operation") {
        Reply::error(CONFLICT, 409)
    } else if message.contains("signed operation expired") {
        Reply::error("{\"code\":\"unauthenticated\"}", 401)
    } else {
        Reply::error(UNAVAILABLE, 503)
    }
}

impl RefStore {
    pub(super) fn data_permitted(&self, proof: &Proof, route: DataRoute) -> Result<bool> {
        let identity = match (
            self.env.var("AUTH_AUDIENCE"),
            self.env.var("AUTH_REPOSITORY"),
            self.env.var("MANAGED_OWNER_PUBLIC_KEY"),
        ) {
            (Ok(a), Ok(r), Ok(o)) => {
                Identity::parse(&a.to_string(), &r.to_string(), &o.to_string())
            }
            _ => Err("missing managed configuration"),
        }
        .map_err(|_| worker::Error::RustError("invalid managed configuration".into()))?;
        if Date::now().as_millis() as i64 > proof.expires_at
            || crate::access_policy::validate_key(&proof.author).is_err()
            || !mkit_core::write_auth::is_hex(&proof.scope, 32)
            || !mkit_core::write_auth::is_hex(&proof.fingerprint, 32)
        {
            return Ok(false);
        }
        self.ensure_policy_table()?;
        let policy = self
            .read_policy(&identity)?
            .ok_or_else(|| worker::Error::RustError("managed policy uninitialized".into()))?;
        Ok(route.permits(&policy, &proof.author))
    }

    pub(super) async fn managed_access(&self, req: &mut Request) -> Result<Response> {
        if req.method() != worker::Method::Post {
            return Reply::error(UNAVAILABLE, 503)?.response();
        }
        let wire: super::wire::AccessReq = match req.json().await {
            Ok(v) => v,
            Err(_) => return Reply::error(INVALID, 400)?.response(),
        };
        let Some(route) = DataRoute::from_path(&wire.procedure) else {
            return Reply::error(UNAVAILABLE, 503)?.response();
        };
        let owned = self.clone();
        let decision = self
            .ledger
            .transaction(move || owned.data_permitted(&wire.proof, route));
        match decision {
            Ok(allowed) => Reply::json(&super::wire::AccessResp { allowed })?.response(),
            Err(_) => Reply::error(UNAVAILABLE, 503)?.response(),
        }
    }
    pub(super) async fn managed_policy(&self, req: &mut Request) -> Result<Response> {
        if req.method() != worker::Method::Post {
            return Reply::error(UNAVAILABLE, 503)?.response();
        }
        let wire: AdminWire = match req.json().await {
            Ok(v) => v,
            Err(_) => return Reply::error(INVALID, 400)?.response(),
        };
        let configured = match (
            self.env.var("AUTH_AUDIENCE"),
            self.env.var("AUTH_REPOSITORY"),
            self.env.var("MANAGED_OWNER_PUBLIC_KEY"),
        ) {
            (Ok(a), Ok(r), Ok(o)) => crate::access_policy::Identity::parse(
                &a.to_string(),
                &r.to_string(),
                &o.to_string(),
            ),
            _ => Err("missing managed configuration"),
        };
        if configured.as_ref().ok() != Some(&wire.identity) {
            return Reply::error(UNAVAILABLE, 503)?.response();
        }
        if wire.proof.author != wire.identity.owner {
            return Reply::error(UNAVAILABLE, 503)?.response();
        }
        if Date::now().as_millis() as i64 > wire.proof.expires_at {
            return Reply::error("{\"code\":\"unauthenticated\"}", 401)?.response();
        }
        if crate::access_policy::Identity::parse(
            &wire.identity.audience,
            &wire.identity.repository,
            &wire.identity.owner,
        )
        .is_err()
        {
            return Reply::error(UNAVAILABLE, 503)?.response();
        }
        if self.ledger.initialize().is_err() || self.ensure_policy_table().is_err() {
            return Reply::error(UNAVAILABLE, 503)?.response();
        }
        let owned = self.clone();
        let result = self.ledger.transaction(move || owned.apply_policy(wire));
        match result {
            Ok(reply) => reply.response(),
            Err(_) => Reply::error(UNAVAILABLE, 503)?.response(),
        }
    }

    fn ensure_policy_table(&self) -> Result<()> {
        self.state.storage().sql().exec("CREATE TABLE IF NOT EXISTS managed_policy (slot INTEGER PRIMARY KEY CHECK(slot = 1), schema_version INTEGER NOT NULL, document TEXT NOT NULL);", None)?;
        Ok(())
    }

    fn read_policy(&self, identity: &crate::access_policy::Identity) -> Result<Option<Policy>> {
        #[derive(Deserialize)]
        struct Row {
            schema_version: i64,
            document: String,
        }
        let rows: Vec<Row> = self
            .state
            .storage()
            .sql()
            .exec(
                "SELECT schema_version, document FROM managed_policy WHERE slot = 1",
                None,
            )?
            .to_array()?;
        let Some(row) = rows.into_iter().next() else {
            return Ok(None);
        };
        if row.schema_version != 1 {
            return Err(worker::Error::RustError("unknown managed schema".into()));
        }
        let policy: Policy = serde_json::from_str(&row.document)
            .map_err(|_| worker::Error::RustError("corrupt managed policy".into()))?;
        policy
            .validate(identity)
            .map_err(|_| worker::Error::RustError("managed identity mismatch".into()))?;
        Ok(Some(policy))
    }

    fn write_policy(&self, policy: &Policy) -> Result<()> {
        let document =
            serde_json::to_string(policy).map_err(|e| worker::Error::RustError(e.to_string()))?;
        self.state.storage().sql().exec("INSERT INTO managed_policy(slot, schema_version, document) VALUES (1, 1, ?) ON CONFLICT(slot) DO UPDATE SET document = excluded.document", vec![document.into()])?;
        Ok(())
    }

    fn apply_policy(&self, wire: AdminWire) -> Result<Reply> {
        let current = self.read_policy(&wire.identity)?;
        match wire.operation.as_str() {
            "get" => {
                if current.is_none() {
                    return Reply::error(UNAVAILABLE, 503);
                }
                let request: GetRequest = match decode(wire.body.as_bytes()) {
                    Ok(v) => v,
                    Err(_) => return Reply::error(INVALID, 400),
                };
                if request.version != 1 {
                    return Reply::error(INVALID, 400);
                }
                Reply::json(&current.expect("checked"))
            }
            "initialize" => {
                let request: std::result::Result<InitializeRequest, _> =
                    decode(wire.body.as_bytes());
                let valid = request.as_ref().is_ok_and(|request| {
                    request.version == 1
                        && validate_collaborators(&wire.identity.owner, &request.collaborators)
                            .is_ok()
                });
                // Replay lookup precedes the initialized check, so an exact
                // signed retry can recover its first committed result.
                let prior =
                    self.ledger
                        .reserve(&wire.proof, Date::now().as_millis() as i64, || {
                            if !valid {
                                Ok(Some(Reply::error(INVALID, 400)?))
                            } else if current.is_some() {
                                Ok(Some(Reply::error(CONFLICT, 409)?))
                            } else {
                                Ok(None)
                            }
                        });
                let prior = match prior {
                    Ok(v) => v,
                    Err(error) => return replay_error(error),
                };
                if let Some(Some(saved)) = prior {
                    return Ok(saved);
                }
                if let Some(None) = prior {
                    return Reply::error(UNAVAILABLE, 503);
                }
                let Ok(request) = request else {
                    return Reply::error(INVALID, 400);
                };
                let policy = Policy::new(&wire.identity, 1, request.collaborators);
                self.write_policy(&policy)?;
                let reply = Reply::json(&policy)?;
                self.ledger.finish(&wire.proof, &reply)?;
                Ok(reply)
            }
            "replace" => {
                let Some(mut policy) = current else {
                    return Reply::error(UNAVAILABLE, 503);
                };
                let request: std::result::Result<ReplaceRequest, _> = decode(wire.body.as_bytes());
                let expected = request
                    .as_ref()
                    .ok()
                    .and_then(|request| generation(&request.expected_generation).ok());
                let valid = request.as_ref().is_ok_and(|request| {
                    request.version == 1
                        && validate_collaborators(&wire.identity.owner, &request.collaborators)
                            .is_ok()
                }) && expected.is_some();
                let next = expected.and_then(|value| value.checked_add(1));
                let matches = generation(&policy.generation).ok() == expected;
                let prior =
                    self.ledger
                        .reserve(&wire.proof, Date::now().as_millis() as i64, || {
                            if !valid {
                                Ok(Some(Reply::error(INVALID, 400)?))
                            } else if !matches || next.is_none() {
                                Ok(Some(Reply::error(CONFLICT, 409)?))
                            } else {
                                Ok(None)
                            }
                        });
                let prior = match prior {
                    Ok(v) => v,
                    Err(error) => return replay_error(error),
                };
                if let Some(Some(saved)) = prior {
                    return Ok(saved);
                }
                if let Some(None) = prior {
                    return Reply::error(UNAVAILABLE, 503);
                }
                let Ok(request) = request else {
                    return Reply::error(INVALID, 400);
                };
                let Some(next) = next else {
                    return Reply::error(CONFLICT, 409);
                };
                policy.generation = next.to_string();
                policy.collaborators = request.collaborators;
                self.write_policy(&policy)?;
                let reply = Reply::json(&policy)?;
                self.ledger.finish(&wire.proof, &reply)?;
                Ok(reply)
            }
            _ => Reply::error(UNAVAILABLE, 503),
        }
    }
}
