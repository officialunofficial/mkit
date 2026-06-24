// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The internal worker -> RefStore DO wire protocol, as a single shared set of
// types used by BOTH sides:
//   - service.rs (client): serializes the request, deserializes the response.
//   - refstore.rs (DO):    deserializes the request, serializes the response.
//
// Declaring these once means a field rename can't silently desync the two
// sides — they share the literal struct. Request fields are owned `String`
// (rather than borrowed `&str`) so the DO can `Deserialize` them while the
// worker still serializes them without lifetime gymnastics; the worker-side
// allocation is negligible against the DO round-trip.
//
// JSON over HTTP to a `https://refstore/<op>` URL:
//   POST /get    GetReq    -> GetResp
//   POST /update UpdateReq -> UpdateResp
//   POST /list   ListReq   -> ListResp
//
// `expectation` is the proto wire number (1=ANY, 2=MISSING, 3=MATCH). Hex
// fields are 64-char lowercase hex of a 32-byte object id (or, for `author`,
// the Ed25519 pubkey).

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
    pub author: Option<String>,   // 64-hex Ed25519 pubkey of the writer
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
