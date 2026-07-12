// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The internal worker -> RefStore DO wire protocol, as a single shared set of
// types used by BOTH sides (service.rs the client, refstore.rs the DO), so a
// field rename can't silently desync them. Adapted from
// apps/repo-worker/src/worker_impl/wire.rs: no chat/reactions/room (this
// service has none), plus a new `/advance` op for the two-ref atomic CAS
// (SPEC-TRANSPORT-CONNECT §4).
//
// JSON over HTTP to a `https://refstore/<op>` URL:
//   POST /get     GetReq     -> GetResp
//   POST /update  UpdateReq  -> UpdateResp
//   POST /list    ListReq    -> ListResp
//   POST /advance AdvanceReq -> AdvanceResp
//
// `expectation` is the proto wire number (1=ANY, 2=MISSING, 3=MATCH). Hex
// fields are 64-char lowercase hex of a 32-byte object id.

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct GetReq {
    pub name: String,
}

#[derive(Serialize, Deserialize)]
pub struct GetResp {
    pub exists: bool,
    pub value: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct UpdateReq {
    pub name: String,
    pub new: String,              // 64-hex target value
    pub expectation: i32,         // proto wire number
    pub expected: Option<String>, // 64-hex (MATCH only)
}

#[derive(Serialize, Deserialize)]
pub struct UpdateResp {
    pub committed: bool,
    pub conflict: bool,
    pub current: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct ListReq {
    pub prefix: String,
}

#[derive(Serialize, Deserialize)]
pub struct ListEntry {
    pub name: String,
    pub value: String,
}

#[derive(Serialize, Deserialize)]
pub struct ListResp {
    pub refs: Vec<ListEntry>,
}

/// Two-ref atomic advance (SPEC-TRANSPORT-CONNECT §4). Evaluated inside the
/// DO's single serial `fetch` — BOTH preconditions are checked before either
/// write, so a conflict on either ref leaves BOTH refs untouched (a true
/// transaction, not the trait's default packmap-then-head fallback).
#[derive(Serialize, Deserialize)]
pub struct AdvanceReq {
    pub head_ref: String,
    pub head_expectation: i32,
    pub head_expected: Option<String>,
    pub head_new: String,

    pub packmap_ref: String,
    pub packmap_expectation: i32,
    pub packmap_expected: Option<String>,
    pub packmap_new: String,
}

/// Mirrors `mkit.transport.v1.AdvanceOutcome`'s three variants exactly (no
/// UNSPECIFIED — a call either completes or the worker maps a DO-level
/// error to a Connect error before this type is even constructed).
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AdvanceOutcome {
    Committed,
    HeadConflict,
    PackmapConflict,
}

#[derive(Serialize, Deserialize)]
pub struct AdvanceResp {
    pub outcome: AdvanceOutcome,
}
