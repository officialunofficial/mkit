//! Stored encodings written by v0.5.0, including nested row variants.
//! Fixed JSON bodies are prefixed by their literal row version in decoder tests;
//! hexadecimal fixtures contain complete binary rows. Keep these bytes unchanged.
//! Added stored fields require serde defaults so later 0.5.x keeps decoding them.
//!
//! All fixture data and decoder tests for this crate live here. Test macros expand
//! in their owning modules to access private codecs without widening visibility.
//! Existing upload goldens additionally pin receipts, tokens and marker blobs.
#![allow(clippy::unwrap_used)]

pub(crate) fn json<T: serde::Serialize + serde::de::DeserializeOwned>(
    name: &str,
    bytes: &[u8],
) -> T {
    let row: T = serde_json::from_slice(bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
    assert_eq!(serde_json::to_vec(&row).unwrap(), bytes, "{name}");
    row
}

pub(crate) fn value(body: &[u8], prefix: &[u8]) -> crate::Value {
    crate::Value::new([prefix, body].concat())
}

pub(crate) fn hex(bytes: &str) -> crate::Value {
    let bytes = bytes.trim();
    assert!(bytes.len().is_multiple_of(2));
    crate::Value::new(
        (0..bytes.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&bytes[i..i + 2], 16).unwrap())
            .collect::<Vec<_>>(),
    )
}
macro_rules! hex_fixture {
    ($name:literal) => {
        crate::stored_golden::hex(
            std::str::from_utf8(crate::stored_golden::fixture(concat!($name, ".hex"))).unwrap(),
        )
    };
}
pub(crate) use hex_fixture;

macro_rules! json_fixture {
    ($ty:ty, $name:literal) => {
        crate::stored_golden::json::<$ty>(
            $name,
            crate::stored_golden::fixture(concat!($name, ".json")),
        )
    };
}
pub(crate) use json_fixture;
macro_rules! row_fixture {
    ($name:literal, $prefix:expr) => {
        crate::stored_golden::value(
            crate::stored_golden::fixture(concat!($name, ".json")),
            $prefix,
        )
    };
}
pub(crate) use row_fixture;

// Exact original fixture bytes; tests must never regenerate this table.
// Different row types can have identical canonical bytes.
#[allow(clippy::too_many_lines, clippy::match_same_arms)]
pub(crate) fn fixture(name: &str) -> &'static [u8] {
    match name {
        "admin-Response.json" => br#"{"status":200,"content_type":"application/json","body":"eyJjb21wbGV0ZSI6ZmFsc2UsInRha2Vkb3duSWQiOiIzZmMwOGQwZWZjODY3MjhkMDc2MzZhZjUwNzI4OTNkMTZlYTE3ZjUwMGUxMGEyN2FmNWRkMjljMGIzNmMwOTRkIn0="}"#,
        "admin-automatic-Event.json" => br#"{"sourceIdentity":"7332393300","operationId":"activation:7defe718937f3b3e2f75a40dbc80265b5984e49bba83bb97483abeab2dfa2781","recordedAtMs":10,"request":{"purgeId":"purge:3be4b3321322a2143ebea087e78b2533a090d696220141879c451376b67fb5af","audience":"https://server.example","repository":"0x1111111111111111111111111111111111111111/repo","trigger":"CACHE_PURGE_TRIGGER_TAKEDOWN"}}"#,
        "admin-ledger-Head.json" => br#"{"seq":1,"hash":"3cba282494337648e7d2c3ccc4f8bd2ea09e21e90aea254fbad9fd84ab338e8d"}"#,
        "admin-ledger-Nonce.json" => br#"{"digest":"body:617023802dfbcfa6946d13ed6eb3db8c8a629e9fcd0c1e97b05285c137f8cfac","path":"/mkit.server.admin.v1.AdminService/Takedown","expiry_ms":60000,"result":null}"#,
        "admin-ledger-Operation.json" => br#"{"digest":"body:b60d070414a9c51f07464db975b5056338b4da836630209c468bab8138227947","path":"/mkit.server.admin.v1.AdminService/Takedown","result":{"status":200,"content_type":"application/json","body":"eyJjb21wbGV0ZSI6ZmFsc2UsInRha2Vkb3duSWQiOiIzZmMwOGQwZWZjODY3MjhkMDc2MzZhZjUwNzI4OTNkMTZlYTE3ZjUwMGUxMGEyN2FmNWRkMjljMGIzNmMwOTRkIn0="},"nonce":"9b6c0b98f2045fb179d7d357ac77760eca8fcf680536e0ccfb94f705d0b58ec9"}"#,
        "denial-pointer.hex" => br"010101010101010101010101010101010101010101010101010101010101010101
",
        "export-header.hex" => br"6d6b69746578700001000000010000000000000002
",
        "export-record.hex" => br"00066e726f6f74000001720000000176
",
        "hold-complete.hex" => br"01
",
        "hold-manifest.hex" => br"0101010101010101010101010101010101010101010101010101010101010101010202020202020202020202020202020202020202020202020202020202020202
",
        "hold-pending.hex" => br"00
",
        "hold-released.hex" => br"0201010101010101010101010101010101010101010101010101010101010101010202020202020202020202020202020202020202020202020202020202020202
",
        "immediate-membership.hex" => br"
",
        "indexed-checkpoint-ExtractionGroupMember.json" => br#"{"pack":[31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31],"ticket":[31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31],"bytes":0,"created_at_ms":0,"already_verified":false}"#,
        "indexed-checkpoint-ExtractionSource.json" => br#"{"member":{"pack":[52,50,116,90,234,137,8,84,48,209,74,21,62,50,144,19,86,179,55,102,126,228,100,86,179,197,106,198,33,46,179,133],"ticket":[239,15,251,233,191,150,32,109,64,198,238,108,187,78,219,77,10,15,167,103,230,250,225,86,48,18,119,91,200,87,45,17],"bytes":70377,"created_at_ms":1700000000000,"already_verified":false},"etag":"16c89a9fc48b368eb386e4bc666700fa6a91f6cbc7117c57286a2eeffd37a2d5","version":1,"entries":3,"decoded":70318,"member_body_id":null}"#,
        "indexed-checkpoint-ExtractionV1.json" => br#"{"sources":[],"group":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"stage":10,"member":0,"scan":"","staged_objects":0,"staged_bytes":0,"selected_bytes":0,"object":null,"length":0,"chunk":0,"chunk_offset":0,"written":0,"cvs":0,"root":null,"session":"","uploaded":0,"relay":null,"reconstruction":null}"#,
        "indexed-checkpoint-Kind-pack.json" => br#""pack""#,
        "indexed-checkpoint-Kind-packlist.json" => br#""packlist""#,
        "indexed-checkpoint-Kind-unknown.json" => br#""unknown""#,
        "indexed-checkpoint-MemberCursor.json" => br#"{"target":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"next":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"preferred":[[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],2],"level":3,"local":true,"ascending":false,"canonical":[[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],10,1,[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]],"bytes":11}"#,
        "indexed-checkpoint-MemberLists.json" => br#"{"satisfying":[[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]],"packlist":[[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]]}"#,
        "indexed-checkpoint-Outcome-base_capped.json" => br#""base_capped""#,
        "indexed-checkpoint-Outcome-base_missing.json" => br#""base_missing""#,
        "indexed-checkpoint-Outcome-blocked.json" => br#""blocked""#,
        "indexed-checkpoint-Outcome-closure_capped.json" => br#""closure_capped""#,
        "indexed-checkpoint-Outcome-closure_missing.json" => br#""closure_missing""#,
        "indexed-checkpoint-Outcome-decode_budget.json" => br#""decode_budget""#,
        "indexed-checkpoint-Outcome-external_too_deep.json" => br#""external_too_deep""#,
        "indexed-checkpoint-Outcome-extraction_unavailable.json" => br#""extraction_unavailable""#,
        "indexed-checkpoint-Outcome-object_blocked.json" => br#""object_blocked""#,
        "indexed-checkpoint-Outcome-open_closure.json" => br#""open_closure""#,
        "indexed-checkpoint-Outcome-packlist_missing.json" => br#""packlist_missing""#,
        "indexed-checkpoint-Phase-await_delivery.json" => br#""await_delivery""#,
        "indexed-checkpoint-Phase-closure_resolve.json" => br#""closure_resolve""#,
        "indexed-checkpoint-Phase-decode.json" => br#""decode""#,
        "indexed-checkpoint-Phase-emit_index.json" => br#""emit_index""#,
        "indexed-checkpoint-Phase-extract.json" => br#""extract""#,
        "indexed-checkpoint-Phase-recheck.json" => br#""recheck""#,
        "indexed-checkpoint-Phase-verify.json" => br#""verify""#,
        "indexed-checkpoint-Phase-watch.json" => br#""watch""#,
        "indexed-checkpoint-VerifyJobV1.json" => br#"{"generation":0,"gone":false,"member_body_id":null,"extraction_head":null,"extraction":null,"extraction_group":[],"ticket_id":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"created_at_ms":5,"pack_len":99,"phase":"decode","kind":"unknown","version":0,"cursor":"ab01","etag":null,"entries":0,"in_pack_bytes":0,"external_bytes":0,"windows_done":0,"attempts":0,"entry_cap":4096,"closure_cap":4,"restarts":0,"bad_signature":false,"extract_needed":false,"scan":"","owed":0,"final_pass":false,"last_relay_seq":null,"closure_final_at_ms":null,"packlist_prev":null,"outcome":"base_missing"}"#,
        "indexed-job-extraction-member-Frame.json" => br#"{"id":[183,90,43,217,96,248,217,54,207,97,221,120,16,77,47,39,132,95,35,65,131,31,223,220,0,46,25,212,243,244,156,129],"pack":[252,97,86,80,55,160,42,183,98,240,243,195,229,211,196,156,151,69,36,63,158,163,93,191,57,175,46,244,95,208,161,137],"index":[1,0,0,0,0,0,0,0,12,0,0,0,0,0,16,0,5,0,0,0,0,0,0,16,0,0,0,0,0,0,0],"local":true}"#,
        "indexed-job-extraction-member-Lookup.json" => br#"{"after":[1,2],"pages":1,"rows":2,"partitions":[[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]]}"#,
        "indexed-publication-resume-BaseCursor.json" => br#"{"origin":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"next":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"depth":1}"#,
        "indexed-publication-resume-Exhaustion-DecodeBudget.json" => br#""DecodeBudget""#,
        "indexed-publication-resume-Exhaustion-IndexCalls.json" => br#""IndexCalls""#,
        "indexed-publication-resume-Exhaustion-Traversal.json" => br#""Traversal""#,
        "indexed-publication-resume-Progress.json" => br#"{"binding":[142,132,182,162,244,221,12,199,13,139,236,203,26,197,95,164,168,77,35,177,4,74,159,57,124,89,249,165,187,215,35,127],"value":{"head":[121,253,71,131,234,65,19,210,17,44,94,55,143,232,214,180,37,90,221,120,156,90,174,179,73,9,177,17,42,78,236,129],"packmap":[19,209,67,107,106,41,171,130,142,62,142,11,107,55,51,81,168,75,17,7,126,252,73,219,125,81,164,233,58,168,224,56]},"generation":0,"additions":[[252,97,86,80,55,160,42,183,98,240,243,195,229,211,196,156,151,69,36,63,158,163,93,191,57,175,46,244,95,208,161,137],[19,209,67,107,106,41,171,130,142,62,142,11,107,55,51,81,168,75,17,7,126,252,73,219,125,81,164,233,58,168,224,56]],"next_packmap":null,"chain":[[19,209,67,107,106,41,171,130,142,62,142,11,107,55,51,81,168,75,17,7,126,252,73,219,125,81,164,233,58,168,224,56]],"packs":[[252,97,86,80,55,160,42,183,98,240,243,195,229,211,196,156,151,69,36,63,158,163,93,191,57,175,46,244,95,208,161,137]],"queue":[[185,67,22,18,19,251,40,175,12,224,101,65,122,226,190,234,187,215,110,119,130,83,149,175,30,82,14,1,136,226,153,107],[221,77,184,143,158,101,38,164,59,63,147,179,210,248,125,67,218,167,8,199,88,233,105,198,76,92,175,132,227,219,243,178]],"visited":[[8,145,209,53,10,57,101,48,149,31,167,222,117,55,109,16,159,145,220,66,249,41,48,97,33,9,144,239,212,98,249,64],[20,253,128,67,176,116,245,93,200,127,185,1,207,31,254,204,193,131,23,231,75,108,19,196,2,247,74,112,5,191,18,41],[121,253,71,131,234,65,19,210,17,44,94,55,143,232,214,180,37,90,221,120,156,90,174,179,73,9,177,17,42,78,236,129],[145,15,220,56,46,76,164,145,198,225,126,149,60,84,222,58,26,116,150,174,222,81,197,210,85,153,113,95,6,120,181,247],[149,225,183,231,40,26,205,137,139,149,97,112,193,243,154,181,104,49,25,154,153,88,63,41,15,141,134,46,112,128,96,206],[151,191,236,35,84,223,228,56,147,75,149,175,184,2,214,109,63,48,247,167,191,134,136,26,47,185,237,205,179,203,38,209],[183,90,43,217,96,248,217,54,207,97,221,120,16,77,47,39,132,95,35,65,131,31,223,220,0,46,25,212,243,244,156,129],[184,226,154,22,54,183,9,100,76,60,191,250,25,231,70,151,134,137,182,125,41,28,165,131,65,119,208,238,92,18,49,126],[208,36,193,151,107,238,22,113,125,59,23,251,91,79,148,129,29,194,105,19,155,37,238,119,47,115,64,85,95,104,223,107]],"dependencies":[[19,209,67,107,106,41,171,130,142,62,142,11,107,55,51,81,168,75,17,7,126,252,73,219,125,81,164,233,58,168,224,56],[252,97,86,80,55,160,42,183,98,240,243,195,229,211,196,156,151,69,36,63,158,163,93,191,57,175,46,244,95,208,161,137]],"bases":[],"bytes":7340702,"calls":43,"byte_limit":2147483648,"depth_limit":50,"base_cursor":null,"failure":null,"missing":false,"missing_base":false,"complete":false}"#,
        "indexed-publication-resume-TerminalFailure-DeltaDepth.json" => br#""DeltaDepth""#,
        "indexed-publication-resume-TerminalFailure-OpenClosure.json" => br#""OpenClosure""#,
        "indexed-selection-SelectionFact-Blob.json" => br#"{"Blob":{"size":70000}}"#,
        "indexed-selection-SelectionFact-Manifest.json" => br#"{"Manifest":{"size":70000,"chunks":[[24,23,121,127,178,207,208,61,113,229,85,5,84,6,103,228,141,38,0,125,139,227,176,233,179,113,93,97,22,3,55,52]]}}"#,
        "indexed-selection-SelectionFact-Other.json" => br#""Other""#,
        "indexed-selection-SelectionFact-Tree.json" => br#"{"Tree":{"files":[[24,23,121,127,178,207,208,61,113,229,85,5,84,6,103,228,141,38,0,125,139,227,176,233,179,113,93,97,22,3,55,52]]}}"#,
        "indexed-state-VerificationV1-pending.json" => br#"{"state":"pending","lease_until_ms":1700000030000}"#,
        "indexed-state-VerificationV1-rejected.json" => br#"{"state":"rejected","code":"invalid_argument","message":"pack exceeds indexed max_pack_bytes"}"#,
        "indexed-state-VerificationV1-verified-publication.json" => br#"{"state":"verified","pack_len":39,"verified_at_ms":1700000002000,"publication":{"binding":[142,132,182,162,244,221,12,199,13,139,236,203,26,197,95,164,168,77,35,177,4,74,159,57,124,89,249,165,187,215,35,127],"value":{"head":[121,253,71,131,234,65,19,210,17,44,94,55,143,232,214,180,37,90,221,120,156,90,174,179,73,9,177,17,42,78,236,129],"packmap":[19,209,67,107,106,41,171,130,142,62,142,11,107,55,51,81,168,75,17,7,126,252,73,219,125,81,164,233,58,168,224,56]},"generation":0,"additions":[[252,97,86,80,55,160,42,183,98,240,243,195,229,211,196,156,151,69,36,63,158,163,93,191,57,175,46,244,95,208,161,137],[19,209,67,107,106,41,171,130,142,62,142,11,107,55,51,81,168,75,17,7,126,252,73,219,125,81,164,233,58,168,224,56]],"next_packmap":null,"chain":[[19,209,67,107,106,41,171,130,142,62,142,11,107,55,51,81,168,75,17,7,126,252,73,219,125,81,164,233,58,168,224,56]],"packs":[[252,97,86,80,55,160,42,183,98,240,243,195,229,211,196,156,151,69,36,63,158,163,93,191,57,175,46,244,95,208,161,137]],"queue":[[185,67,22,18,19,251,40,175,12,224,101,65,122,226,190,234,187,215,110,119,130,83,149,175,30,82,14,1,136,226,153,107],[221,77,184,143,158,101,38,164,59,63,147,179,210,248,125,67,218,167,8,199,88,233,105,198,76,92,175,132,227,219,243,178]],"visited":[[8,145,209,53,10,57,101,48,149,31,167,222,117,55,109,16,159,145,220,66,249,41,48,97,33,9,144,239,212,98,249,64],[20,253,128,67,176,116,245,93,200,127,185,1,207,31,254,204,193,131,23,231,75,108,19,196,2,247,74,112,5,191,18,41],[121,253,71,131,234,65,19,210,17,44,94,55,143,232,214,180,37,90,221,120,156,90,174,179,73,9,177,17,42,78,236,129],[145,15,220,56,46,76,164,145,198,225,126,149,60,84,222,58,26,116,150,174,222,81,197,210,85,153,113,95,6,120,181,247],[149,225,183,231,40,26,205,137,139,149,97,112,193,243,154,181,104,49,25,154,153,88,63,41,15,141,134,46,112,128,96,206],[151,191,236,35,84,223,228,56,147,75,149,175,184,2,214,109,63,48,247,167,191,134,136,26,47,185,237,205,179,203,38,209],[183,90,43,217,96,248,217,54,207,97,221,120,16,77,47,39,132,95,35,65,131,31,223,220,0,46,25,212,243,244,156,129],[184,226,154,22,54,183,9,100,76,60,191,250,25,231,70,151,134,137,182,125,41,28,165,131,65,119,208,238,92,18,49,126],[208,36,193,151,107,238,22,113,125,59,23,251,91,79,148,129,29,194,105,19,155,37,238,119,47,115,64,85,95,104,223,107]],"dependencies":[[19,209,67,107,106,41,171,130,142,62,142,11,107,55,51,81,168,75,17,7,126,252,73,219,125,81,164,233,58,168,224,56],[252,97,86,80,55,160,42,183,98,240,243,195,229,211,196,156,151,69,36,63,158,163,93,191,57,175,46,244,95,208,161,137]],"bases":[],"bytes":7340702,"calls":43,"byte_limit":2147483648,"depth_limit":50,"base_cursor":null,"failure":null,"missing":false,"missing_base":false,"complete":false}}"#,
        "indexed-state-VerificationV1-verified.json" => br#"{"state":"verified","pack_len":1,"verified_at_ms":1}"#,
        "inspection-enabled.hex" => br"6f6e
",
        "namespace-usage.hex" => br"00000000000000050000000000000008
",
        "namespace-view.hex" => br"00000000000000050000000000000008000000000000000200000000000000030000000000000009
",
        "object-index-0.hex" => br"010000000000000008000000000000000400000000000000000a0000000000
",
        "object-index-2.hex" => br"010000000000000008000000000000000402000000000000000a00000001010202020202020202020202020202020202020202020202020202020202020202
",
        "object-index-3.hex" => br"010000000000000008000000000000000403000000000000000a0000000000
",
        "object-index-4.hex" => br"010000000000000008000000000000000404000000000000000a00000001010202020202020202020202020202020202020202020202020202020202020202
",
        "outcome-timer-start.hex" => br"
",
        "outcome-timer.hex" => br"0000000200026162
",
        "pending-holder.hex" => br"0100066e726f6f7400002b68000000000000000000000000000000000000000000000000000000000000000000726f6f7400726f6f6d010101010101010101010101010101010101010101010101010101010101010102020202020202020202020202020202020202020202020202020202020202020303030303030303030303030303030303030303030303030303030303030303040404040404040404040404040404040404040404040404040404040404040468726bb68fa868f8c28c8359cc1f2d5c955b33748e0c6b84073499464a3669c3
",
        "pipeline-revocation-RevokeCheckpoint.json" => br#"{"generation":2,"recovery":{"resumed_at_ms":3},"cursor":[1,2]}"#,
        "preservation-source-frame.hex" => br"01010101010101010101010101010101010101010101010101010101010101010202020202020202020202020202020202020202020202020202020202020202010000000000000008000000000000000400000000000000000a0000000000
",
        "preserved-piece.hex" => br"010101010101010101010101010101010101010101010101010101010101010102020202020202020202020202020202020202020202020202020202020202020000000000000003616263
",
        "publication-recheck.hex" => br"01010101010101010101010101010101010101010101010101010101010101010102000000
",
        "purge-Request.json" => br#"{"purgeId":"purge:3be4b3321322a2143ebea087e78b2533a090d696220141879c451376b67fb5af","audience":"https://server.example","repository":"0x1111111111111111111111111111111111111111/repo","trigger":"CACHE_PURGE_TRIGGER_TAKEDOWN"}"#,
        "purge-Trigger-CACHE_PURGE_TRIGGER_LEASE_DELETION.json" => br#""CACHE_PURGE_TRIGGER_LEASE_DELETION""#,
        "purge-Trigger-CACHE_PURGE_TRIGGER_MANUAL.json" => br#""CACHE_PURGE_TRIGGER_MANUAL""#,
        "purge-Trigger-CACHE_PURGE_TRIGGER_SUSPENSION.json" => br#""CACHE_PURGE_TRIGGER_SUSPENSION""#,
        "purge-Trigger-CACHE_PURGE_TRIGGER_TAKEDOWN.json" => br#""CACHE_PURGE_TRIGGER_TAKEDOWN""#,
        "purge-Trigger-CACHE_PURGE_TRIGGER_VISIBILITY_CHANGE.json" => br#""CACHE_PURGE_TRIGGER_VISIBILITY_CHANGE""#,
        "purge-delivery-Progress.json" => br#"{"checkpoint":[1,2],"local_done":true,"attempt":2}"#,
        "ref-id.hex" => br"0101010101010101010101010101010101010101010101010101010101010101
",
        "relay-ContentTakedownV1-pending.hex" => br"0100d60100066e726f6f7400002b68000000000000000000000000000000000000000000000000000000000000000000726f6f7400726f6f6d010101010101010101010101010101010101010101010101010101010101010102020202020202020202020202020202020202020202020202020202020202020303030303030303030303030303030303030303030303030303030303030303040404040404040404040404040404040404040404040404040404040404040468726bb68fa868f8c28c8359cc1f2d5c955b33748e0c6b84073499464a3669c30021017b22726561736f6e223a2272222c22626c6f636b65645f61745f6d73223a337d000000000000000500
",
        "relay-ContentTakedownV1-ready.hex" => br"0100d60100066e726f6f7400002b68000000000000000000000000000000000000000000000000000000000000000000726f6f7400726f6f6d010101010101010101010101010101010101010101010101010101010101010102020202020202020202020202020202020202020202020202020202020202020303030303030303030303030303030303030303030303030303030303030303040404040404040404040404040404040404040404040404040404040404040468726bb68fa868f8c28c8359cc1f2d5c955b33748e0c6b84073499464a3669c30021017b22726561736f6e223a2272222c22626c6f636b65645f61745f6d73223a337d0000000000000005010000000000000006
",
        "selection-page.hex" => br"03020101010101010101010101010101010101010101010101010101010101010101010000000000000008000000010000000102020202020202020202020202020202020202020202020202020202020202020000000000010202020202020202020202020202020202020202020202020202020202020202
",
        "selection-projection-0.hex" => br"02000101010101010101010101010101010101010101010101010101010101010101000000000000000800000000000000000202020202020202020202020202020202020202020202020202020202020202
",
        "selection-projection-1.hex" => br"02010101010101010101010101010101010101010101010101010101010101010101000000000000000800000001000000010202020202020202020202020202020202020202020202020202020202020202
",
        "selection-projection-2.hex" => br"02020101010101010101010101010101010101010101010101010101010101010101000000000000000000000001000000010202020202020202020202020202020202020202020202020202020202020202
",
        "selection-projection-3.hex" => br"02030101010101010101010101010101010101010101010101010101010101010101000000000000000000000000000000000202020202020202020202020202020202020202020202020202020202020202
",
        "store-codec-AbortReason-ABANDONED.json" => br#""ABANDONED""#,
        "store-codec-AbortReason-EPOCH_MISMATCH.json" => br#""EPOCH_MISMATCH""#,
        "store-codec-AbortReason-INTERNAL.json" => br#""INTERNAL""#,
        "store-codec-AbortReason-PACK_MISSING.json" => br#""PACK_MISSING""#,
        "store-codec-AbortReason-REF_CONFLICT.json" => br#""REF_CONFLICT""#,
        "store-codec-AbortReason-REPLAY_RACE.json" => br#""REPLAY_RACE""#,
        "store-codec-AbortReason-UNSPECIFIED.json" => br#""UNSPECIFIED""#,
        "store-codec-Backlog.json" => br#"{"rows":1,"bytes":129}"#,
        "store-codec-BackupStateV1.json" => br#"{"last_export_ms":10,"digest":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"r2_key":"backups/sample","last_upload_ms":11}"#,
        "store-codec-BlockV1.json" => br#"{"reason":"r","blocked_at_ms":3}"#,
        "store-codec-EpochLease.json" => br#"{"epoch":7,"expires_at_ms":999999,"config_version":1}"#,
        "store-codec-HoldV1.json" => br#"{"expires_at_ms":10000}"#,
        "store-codec-HolderV1.json" => br#"{"seq":1,"op_id":"0909090909090909090909090909090909090909090909090909090909090909"}"#,
        "store-codec-LeaseRecovery.json" => br#"{"resumed_at_ms":110}"#,
        "store-codec-LeasedShard.json" => br#"{"epoch":3,"expires_at_ms":100,"acked_epoch":2,"relay_watermark_ms":0,"sweep_due_ms":100}"#,
        "store-codec-NamespaceRecord.json" => br#"{"created_at_ms":1700000000000,"config_version":1}"#,
        "store-codec-ObjectStateV1.json" => br#"{"seq":1,"changed_at_ms":10,"holders":0,"deleting":false}"#,
        "store-codec-OutcomeRef.json" => br#"{"name":"refs/heads/main","new":"0101010101010101010101010101010101010101010101010101010101010101","deleted":false}"#,
        "store-codec-PendingOp-read.json" => br#""read""#,
        "store-codec-PendingOp-write.json" => br#""write""#,
        "store-codec-QuotaV1.json" => br#"{"window_start":1700000000000,"ops":3,"bytes":18446744073709551615}"#,
        "store-codec-RecordV1-already_exists.json" => br#"{"fingerprint":"0101010101010101010101010101010101010101010101010101010101010101","expires_at_ms":2,"state":{"state":"committed","result":{"kind":"rejected","code":"already_exists","message":"refused"}}}"#,
        "store-codec-RecordV1-failed_precondition.json" => br#"{"fingerprint":"0101010101010101010101010101010101010101010101010101010101010101","expires_at_ms":2,"state":{"state":"committed","result":{"kind":"rejected","code":"failed_precondition","message":"refused"}}}"#,
        "store-codec-RecordV1-invalid_argument.json" => br#"{"fingerprint":"0101010101010101010101010101010101010101010101010101010101010101","expires_at_ms":2,"state":{"state":"committed","result":{"kind":"rejected","code":"invalid_argument","message":"refused"}}}"#,
        "store-codec-RecordV1-not_found.json" => br#"{"fingerprint":"0101010101010101010101010101010101010101010101010101010101010101","expires_at_ms":2,"state":{"state":"committed","result":{"kind":"rejected","code":"not_found","message":"refused"}}}"#,
        "store-codec-RecordV1-out_of_range.json" => br#"{"fingerprint":"0101010101010101010101010101010101010101010101010101010101010101","expires_at_ms":2,"state":{"state":"committed","result":{"kind":"rejected","code":"out_of_range","message":"refused"}}}"#,
        "store-codec-RecordV1-permission_denied.json" => br#"{"fingerprint":"0101010101010101010101010101010101010101010101010101010101010101","expires_at_ms":2,"state":{"state":"committed","result":{"kind":"rejected","code":"permission_denied","message":"refused"}}}"#,
        "store-codec-RecordV1-unimplemented.json" => br#"{"fingerprint":"0101010101010101010101010101010101010101010101010101010101010101","expires_at_ms":2,"state":{"state":"committed","result":{"kind":"rejected","code":"unimplemented","message":"refused"}}}"#,
        "store-codec-RecordV1.json" => br#"{"fingerprint":"0909090909090909090909090909090909090909090909090909090909090909","expires_at_ms":-5,"state":{"state":"in_flight","resumable":true}}"#,
        "store-codec-RelayDtoV1.json" => br#"{"at_ms":100,"target":"78726f6f740061003900","puts":[]}"#,
        "store-codec-RelayScanDtoV1.json" => br#"{"cycle_end":65,"cursor":1,"blocked":[]}"#,
        "store-codec-RepoRecord.json" => br#"{"created_at_ms":10}"#,
        "store-codec-RepoVisibilityV1-private.json" => br#"{"visibility":"private","last_created_ms":1700000000000,"last_statement_id":"abababababababababababababababababababababababababababababababab","changed_ms":1700000000001}"#,
        "store-codec-RepoVisibilityV1-public.json" => br#"{"visibility":"public","last_created_ms":0,"last_statement_id":null}"#,
        "store-codec-ReservationV1-aborted-ABANDONED.json" => br#"{"state":"aborted","repository":"repo","occurred_at_ms":41000,"reason":"ABANDONED","detail":""}"#,
        "store-codec-ReservationV1-aborted-EPOCH_MISMATCH.json" => br#"{"state":"aborted","repository":"a","occurred_at_ms":7,"reason":"EPOCH_MISMATCH","detail":""}"#,
        "store-codec-ReservationV1-aborted-INTERNAL.json" => br#"{"state":"aborted","repository":"repo","occurred_at_ms":300,"reason":"INTERNAL","detail":"late failure"}"#,
        "store-codec-ReservationV1-aborted-PACK_MISSING.json" => br#"{"state":"aborted","repository":"a","occurred_at_ms":7,"reason":"PACK_MISSING","detail":""}"#,
        "store-codec-ReservationV1-aborted-REF_CONFLICT.json" => br#"{"state":"aborted","repository":"repo","occurred_at_ms":100,"reason":"REF_CONFLICT","detail":""}"#,
        "store-codec-ReservationV1-aborted-REPLAY_RACE.json" => br#"{"state":"aborted","repository":"a","occurred_at_ms":7,"reason":"REPLAY_RACE","detail":""}"#,
        "store-codec-ReservationV1-aborted-UNSPECIFIED.json" => br#"{"state":"aborted","repository":"repo","occurred_at_ms":10,"reason":"UNSPECIFIED","detail":""}"#,
        "store-codec-ReservationV1-committed.json" => br#"{"state":"committed","repository":"repo","occurred_at_ms":100,"bytes_stored":1,"new_to_repo":1,"new_to_store":1,"refs":[]}"#,
        "store-codec-ReservationV1-expired.json" => br#"{"state":"expired","repository":"repo","occurred_at_ms":100}"#,
        "store-codec-ReservationV1-pending.json" => br#"{"state":"pending","repository":"repo","created_at_ms":0,"reconcile_at_ms":70000,"op":"read"}"#,
        "store-codec-ReservationV1-read_served.json" => br#"{"state":"read_served","repository":"repo","occurred_at_ms":10,"object":"0101010101010101010101010101010101010101010101010101010101010101","bytes_served":8}"#,
        "store-codec-ReservationV1-ticketed.json" => br#"{"state":"ticketed","ticket_id":"47f41f02ea4892e0e916eb9b069b19d22a2528fceea619187547e24170a0300a"}"#,
        "store-codec-ResultV1-advance_committed.json" => br#"{"kind":"advance_committed"}"#,
        "store-codec-ResultV1-advance_head_conflict.json" => br#"{"kind":"advance_head_conflict"}"#,
        "store-codec-ResultV1-advance_packmap_conflict.json" => br#"{"kind":"advance_packmap_conflict"}"#,
        "store-codec-ResultV1-begin_upload_already_present.json" => br#"{"kind":"begin_upload_already_present"}"#,
        "store-codec-ResultV1-begin_upload_ticket.json" => br#"{"kind":"begin_upload_ticket","id":"0101010101010101010101010101010101010101010101010101010101010101","part_size":8388608,"expires_at_ms":2,"token_hex":"01"}"#,
        "store-codec-ResultV1-rejected.json" => br#"{"kind":"rejected","code":"permission_denied","message":"denied"}"#,
        "store-codec-ResultV1-repo_visibility.json" => br#"{"kind":"repo_visibility"}"#,
        "store-codec-ResultV1-update_ref_committed.json" => br#"{"kind":"update_ref_committed"}"#,
        "store-codec-ResultV1-update_ref_conflict.json" => br#"{"kind":"update_ref_conflict","current":null}"#,
        "store-codec-ResultV1-upload_pack.json" => br#"{"kind":"upload_pack"}"#,
        "store-codec-StateV1-advance_committed.json" => br#"{"state":"committed","result":{"kind":"advance_committed"}}"#,
        "store-codec-StateV1-advance_head_conflict.json" => br#"{"state":"committed","result":{"kind":"advance_head_conflict"}}"#,
        "store-codec-StateV1-advance_packmap_conflict.json" => br#"{"state":"committed","result":{"kind":"advance_packmap_conflict"}}"#,
        "store-codec-StateV1-begin_upload_already_present.json" => br#"{"state":"committed","result":{"kind":"begin_upload_already_present"}}"#,
        "store-codec-StateV1-begin_upload_ticket.json" => br#"{"state":"committed","result":{"kind":"begin_upload_ticket","id":"0101010101010101010101010101010101010101010101010101010101010101","part_size":8388608,"expires_at_ms":2,"token_hex":"01"}}"#,
        "store-codec-StateV1-in_flight.json" => br#"{"state":"in_flight","resumable":true}"#,
        "store-codec-StateV1-rejected.json" => br#"{"state":"committed","result":{"kind":"rejected","code":"permission_denied","message":"denied"}}"#,
        "store-codec-StateV1-repo_visibility.json" => br#"{"state":"committed","result":{"kind":"repo_visibility"}}"#,
        "store-codec-StateV1-update_ref_committed.json" => br#"{"state":"committed","result":{"kind":"update_ref_committed"}}"#,
        "store-codec-StateV1-update_ref_conflict.json" => br#"{"state":"committed","result":{"kind":"update_ref_conflict","current":null}}"#,
        "store-codec-StateV1-upload_pack.json" => br#"{"state":"committed","result":{"kind":"upload_pack"}}"#,
        "store-codec-StoredVisibility-private.json" => br#""private""#,
        "store-codec-StoredVisibility-public.json" => br#""public""#,
        "store-codec-TicketV1.json" => br#"{"repo":"repo","ref_name":"refs/heads/branch-0","signer":"0101010101010101010101010101010101010101010101010101010101010101","pack_id":"0202020202020202020202020202020202020202020202020202020202020202","bytes":8388609,"part_size":8388608,"expires_at_ms":100,"created_at_ms":1,"reservation_id":"s:0000000000000000000000000000000000000000000000000000000000000000","upload_session":null}"#,
        "store-inspection_flags-FlagSource.json" => br#"{"inspector":"inspector","inspection_id":"inspection","ref_name":"refs/heads/main","sequence":1}"#,
        "store-inspection_flags-FlagState-flagged.json" => br#""flagged""#,
        "store-inspection_flags-FlagState-released.json" => br#""released""#,
        "store-inspection_flags-FlagV1-Flagged.json" => br#"{"id":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"reason":"review","source":{"inspector":"inspector","inspection_id":"inspection","ref_name":"refs/heads/main","sequence":1},"state":"flagged","seen_sources":[[154,32,134,168,66,179,25,93,148,192,30,161,91,203,46,43,210,21,166,226,30,93,230,95,162,56,145,123,145,131,100,213]]}"#,
        "store-inspection_flags-FlagV1-Released.json" => br#"{"id":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"reason":"review","source":{"inspector":"inspector","inspection_id":"inspection","ref_name":"refs/heads/main","sequence":1},"state":"released","seen_sources":[[154,32,134,168,66,179,25,93,148,192,30,161,91,203,46,43,210,21,166,226,30,93,230,95,162,56,145,123,145,131,100,213]]}"#,
        "store-publication-Advance.json" => br#"{"sequence":2,"generation":0,"value":{"head":[170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170],"packmap":null},"additions":[],"dependencies":[],"external_bases":[],"obligations":[{"id":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"state":"held"}],"state":"held","operation":[2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2]}"#,
        "store-publication-Clearance-cleared.json" => br#""cleared""#,
        "store-publication-Clearance-held.json" => br#""held""#,
        "store-publication-Clearance-hit.json" => br#""hit""#,
        "store-publication-Clearance-pending.json" => br#""pending""#,
        "store-publication-Clearance-resolved.json" => br#""resolved""#,
        "store-publication-Obligation.json" => br#"{"id":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"state":"held"}"#,
        "store-publication-Pair.json" => br#"{"head":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"packmap":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]}"#,
        "store-publication-Publication.json" => br#"{"sequence":1,"published":1,"boundary":1,"generation":0,"value":{"head":null,"packmap":null}}"#,
        "store-watermark-WatermarkCheckpoint-00.hex" => br"02000663726f6f740000000000000000c80000000000000096ffffffffffffffff6c7300637572736f72
",
        "store-watermark-WatermarkCheckpoint-01.hex" => br"02000663726f6f740000000000000000c80000000000000096ffffffff0000000800000000000000786c7300637572736f72
",
        "store-watermark-WatermarkCheckpoint-10.hex" => br"02000663726f6f740000000000000000c8000000000000009600000016017b22726573756d65645f61745f6d73223a3131307dffffffff6c7300637572736f72
",
        "store-watermark-WatermarkCheckpoint-11.hex" => br"02000663726f6f740000000000000000c8000000000000009600000016017b22726573756d65645f61745f6d73223a3131307d0000000800000000000000786c7300637572736f72
",
        "takedown-closure-Checkpoint.json" => br#"{"next":0,"bytes":0,"frontier":[]}"#,
        "takedown-copy-Piece.json" => br#"{"storage":[28,60,116,132,79,230,94,239,211,134,102,81,78,63,216,82,44,91,210,75,35,67,105,112,101,45,105,73,130,162,152,84],"object":[59,199,152,224,42,17,207,49,106,232,184,200,24,112,106,98,91,109,137,51,138,152,89,52,86,176,218,120,147,250,51,73],"offset":1048504,"length":82}"#,
        "takedown-denial-ActionsV2-populated.json" => br#"{"version":2,"actions":[{"action":{"id":[161,83,163,222,98,5,102,165,58,207,111,195,190,59,138,50,86,77,140,180,21,50,206,184,83,33,210,83,27,56,111,202],"takedown_id":[213,244,86,136,0,47,202,83,42,150,215,157,157,20,253,196,242,133,86,123,179,45,134,209,251,103,42,29,197,149,145,99],"reason":"manual","blocked_at_ms":10,"chunk_ids":[]},"sorted_pages":false,"chunk_count":0,"chunk_digest":[175,19,73,185,245,249,161,166,160,64,77,234,54,220,201,73,155,203,37,201,173,193,18,183,204,154,147,202,228,31,50,98],"pages":[],"page_owner":[130,162,169,56,191,232,23,215,77,167,157,136,200,2,110,65,123,159,141,185,183,125,88,29,233,215,110,49,183,127,62,112],"page_action":[59,199,152,224,42,17,207,49,106,232,184,200,24,112,106,98,91,109,137,51,138,152,89,52,86,176,218,120,147,250,51,73],"pack_scope":null,"pack_digest":null}]}"#,
        "takedown-denial-ActionsV2.json" => br#"{"version":2,"actions":[{"action":{"id":[161,83,163,222,98,5,102,165,58,207,111,195,190,59,138,50,86,77,140,180,21,50,206,184,83,33,210,83,27,56,111,202],"takedown_id":[213,244,86,136,0,47,202,83,42,150,215,157,157,20,253,196,242,133,86,123,179,45,134,209,251,103,42,29,197,149,145,99],"reason":"manual","blocked_at_ms":10,"chunk_ids":[]},"sorted_pages":false,"chunk_count":0,"chunk_digest":[175,19,73,185,245,249,161,166,160,64,77,234,54,220,201,73,155,203,37,201,173,193,18,183,204,154,147,202,228,31,50,98],"pages":[],"page_owner":[130,162,169,56,191,232,23,215,77,167,157,136,200,2,110,65,123,159,141,185,183,125,88,29,233,215,110,49,183,127,62,112],"page_action":[59,199,152,224,42,17,207,49,106,232,184,200,24,112,106,98,91,109,137,51,138,152,89,52,86,176,218,120,147,250,51,73],"pack_scope":null,"pack_digest":null}]}"#,
        "takedown-denial-BlockAction.json" => br#"{"id":[161,83,163,222,98,5,102,165,58,207,111,195,190,59,138,50,86,77,140,180,21,50,206,184,83,33,210,83,27,56,111,202],"takedown_id":[213,244,86,136,0,47,202,83,42,150,215,157,157,20,253,196,242,133,86,123,179,45,134,209,251,103,42,29,197,149,145,99],"reason":"manual","blocked_at_ms":10,"chunk_ids":[]}"#,
        "takedown-denial-ChunkPage.json" => br#"{"first":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"last":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"count":2,"digest":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}"#,
        "takedown-denial-StoredAction.json" => br#"{"action":{"id":[161,83,163,222,98,5,102,165,58,207,111,195,190,59,138,50,86,77,140,180,21,50,206,184,83,33,210,83,27,56,111,202],"takedown_id":[213,244,86,136,0,47,202,83,42,150,215,157,157,20,253,196,242,133,86,123,179,45,134,209,251,103,42,29,197,149,145,99],"reason":"manual","blocked_at_ms":10,"chunk_ids":[]},"sorted_pages":false,"chunk_count":0,"chunk_digest":[175,19,73,185,245,249,161,166,160,64,77,234,54,220,201,73,155,203,37,201,173,193,18,183,204,154,147,202,228,31,50,98],"pages":[],"page_owner":[130,162,169,56,191,232,23,215,77,167,157,136,200,2,110,65,123,159,141,185,183,125,88,29,233,215,110,49,183,127,62,112],"page_action":[59,199,152,224,42,17,207,49,106,232,184,200,24,112,106,98,91,109,137,51,138,152,89,52,86,176,218,120,147,250,51,73],"pack_scope":null,"pack_digest":null}"#,
        "takedown-discovery-DiscoveryState.json" => br#"{"version":1,"namespaces":["root"],"exhaustive":true,"addressing_single":true,"single_repo":["root","repo"],"safety_cut":2,"namespace":0,"phase":0,"registry_cursor":null,"shard_cursor":null,"object_cursor":null,"repo":null,"watermark":null,"generation":null,"binding":null}"#,
        "takedown-intent-Draft.json" => br#"{"version":1,"id":[213,244,86,136,0,47,202,83,42,150,215,157,157,20,253,196,242,133,86,123,179,45,134,209,251,103,42,29,197,149,145,99],"digest":"fifty-hop-restart","created":10}"#,
        "takedown-intent-Record.json" => br#"{"version":1,"id":[7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7],"digest":"body:0808080808080808080808080808080808080808080808080808080808080808","operation":"fixture","repository":"root/repo","reason":"policy","reason_token":"policy","created":10,"pack":null,"actions":[{"object":[78,237,113,65,234,74,92,212,183,136,96,107,210,63,70,226,18,175,156,172,235,172,220,125,31,76,109,199,242,81,27,152],"descriptor_hash":[9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9]}],"activation_cursor":1,"preservation_pending":true}"#,
        "takedown-intent-Reference.json" => br#"{"object":[78,237,113,65,234,74,92,212,183,136,96,107,210,63,70,226,18,175,156,172,235,172,220,125,31,76,109,199,242,81,27,152],"descriptor_hash":[9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9]}"#,
        "takedown-inventory-Entry-0.json" => br#"{"version":1,"kind":0,"canonical_len":0,"logical_len":null,"base":null,"references":{"action":{"id":[166,115,49,245,122,246,179,116,229,69,170,5,87,203,115,174,92,44,134,207,117,38,31,227,135,116,250,254,43,84,189,114],"takedown_id":[87,87,87,87,87,87,87,87,87,87,87,87,87,87,87,87,87,87,87,87,87,87,87,87,87,87,87,87,87,87,87,87],"reason":"inventory","blocked_at_ms":0,"chunk_ids":[]},"sorted_pages":true,"chunk_count":0,"chunk_digest":[175,19,73,185,245,249,161,166,160,64,77,234,54,220,201,73,155,203,37,201,173,193,18,183,204,154,147,202,228,31,50,98],"pages":[],"page_owner":[87,87,87,87,87,87,87,87,87,87,87,87,87,87,87,87,87,87,87,87,87,87,87,87,87,87,87,87,87,87,87,87],"page_action":[166,115,49,245,122,246,179,116,229,69,170,5,87,203,115,174,92,44,134,207,117,38,31,227,135,116,250,254,43,84,189,114],"pack_scope":null,"pack_digest":null}}"#,
        "takedown-inventory-Entry-1.json" => br#"{"version":1,"kind":1,"canonical_len":1048586,"logical_len":1048576,"base":null,"references":{"action":{"id":[66,119,92,190,95,44,180,89,112,155,131,161,68,4,165,35,1,58,92,86,30,49,143,109,47,47,9,183,157,162,24,88],"takedown_id":[130,162,169,56,191,232,23,215,77,167,157,136,200,2,110,65,123,159,141,185,183,125,88,29,233,215,110,49,183,127,62,112],"reason":"inventory","blocked_at_ms":0,"chunk_ids":[]},"sorted_pages":false,"chunk_count":0,"chunk_digest":[175,19,73,185,245,249,161,166,160,64,77,234,54,220,201,73,155,203,37,201,173,193,18,183,204,154,147,202,228,31,50,98],"pages":[],"page_owner":[130,162,169,56,191,232,23,215,77,167,157,136,200,2,110,65,123,159,141,185,183,125,88,29,233,215,110,49,183,127,62,112],"page_action":[66,119,92,190,95,44,180,89,112,155,131,161,68,4,165,35,1,58,92,86,30,49,143,109,47,47,9,183,157,162,24,88],"pack_scope":null,"pack_digest":null}}"#,
        "takedown-inventory-Entry-2.json" => br#"{"version":1,"kind":2,"canonical_len":379,"logical_len":null,"base":null,"references":{"action":{"id":[208,36,193,151,107,238,22,113,125,59,23,251,91,79,148,129,29,194,105,19,155,37,238,119,47,115,64,85,95,104,223,107],"takedown_id":[252,97,86,80,55,160,42,183,98,240,243,195,229,211,196,156,151,69,36,63,158,163,93,191,57,175,46,244,95,208,161,137],"reason":"inventory","blocked_at_ms":0,"chunk_ids":[]},"sorted_pages":false,"chunk_count":9,"chunk_digest":[105,3,202,209,233,69,194,81,121,225,3,181,69,211,114,184,183,82,18,213,59,65,60,132,78,247,79,232,254,174,3,55],"pages":[{"first":[8,145,209,53,10,57,101,48,149,31,167,222,117,55,109,16,159,145,220,66,249,41,48,97,33,9,144,239,212,98,249,64],"last":[221,77,184,143,158,101,38,164,59,63,147,179,210,248,125,67,218,167,8,199,88,233,105,198,76,92,175,132,227,219,243,178],"count":9,"digest":[105,3,202,209,233,69,194,81,121,225,3,181,69,211,114,184,183,82,18,213,59,65,60,132,78,247,79,232,254,174,3,55]}],"page_owner":[252,97,86,80,55,160,42,183,98,240,243,195,229,211,196,156,151,69,36,63,158,163,93,191,57,175,46,244,95,208,161,137],"page_action":[208,36,193,151,107,238,22,113,125,59,23,251,91,79,148,129,29,194,105,19,155,37,238,119,47,115,64,85,95,104,223,107],"pack_scope":null,"pack_digest":null}}"#,
        "takedown-inventory-Entry-3.json" => br#"{"version":1,"kind":3,"canonical_len":252,"logical_len":null,"base":null,"references":{"action":{"id":[121,253,71,131,234,65,19,210,17,44,94,55,143,232,214,180,37,90,221,120,156,90,174,179,73,9,177,17,42,78,236,129],"takedown_id":[252,97,86,80,55,160,42,183,98,240,243,195,229,211,196,156,151,69,36,63,158,163,93,191,57,175,46,244,95,208,161,137],"reason":"inventory","blocked_at_ms":0,"chunk_ids":[]},"sorted_pages":false,"chunk_count":1,"chunk_digest":[222,2,74,132,93,84,147,54,5,225,81,235,37,186,160,59,68,249,49,73,128,51,192,124,100,42,244,183,112,22,151,206],"pages":[{"first":[208,36,193,151,107,238,22,113,125,59,23,251,91,79,148,129,29,194,105,19,155,37,238,119,47,115,64,85,95,104,223,107],"last":[208,36,193,151,107,238,22,113,125,59,23,251,91,79,148,129,29,194,105,19,155,37,238,119,47,115,64,85,95,104,223,107],"count":1,"digest":[222,2,74,132,93,84,147,54,5,225,81,235,37,186,160,59,68,249,49,73,128,51,192,124,100,42,244,183,112,22,151,206]}],"page_owner":[252,97,86,80,55,160,42,183,98,240,243,195,229,211,196,156,151,69,36,63,158,163,93,191,57,175,46,244,95,208,161,137],"page_action":[121,253,71,131,234,65,19,210,17,44,94,55,143,232,214,180,37,90,221,120,156,90,174,179,73,9,177,17,42,78,236,129],"pack_scope":null,"pack_digest":null}}"#,
        "takedown-inventory-Entry-4.json" => br#"{"version":1,"kind":4,"canonical_len":258,"logical_len":null,"base":null,"references":{"action":{"id":[146,19,176,169,31,100,75,135,27,179,95,249,231,55,82,244,13,239,150,67,201,3,172,20,59,98,101,67,189,47,227,15],"takedown_id":[237,221,168,59,234,96,25,92,194,229,83,38,211,165,150,178,17,18,14,6,105,54,220,115,38,179,123,169,17,153,97,92],"reason":"inventory","blocked_at_ms":0,"chunk_ids":[]},"sorted_pages":false,"chunk_count":1,"chunk_digest":[62,48,165,140,134,190,112,180,111,40,204,230,56,241,87,56,7,219,122,137,191,76,164,193,252,201,186,202,133,254,29,5],"pages":[{"first":[39,169,221,133,69,27,185,220,251,7,32,11,156,214,155,237,246,55,4,118,140,122,78,151,123,147,132,112,224,41,124,17],"last":[39,169,221,133,69,27,185,220,251,7,32,11,156,214,155,237,246,55,4,118,140,122,78,151,123,147,132,112,224,41,124,17],"count":1,"digest":[62,48,165,140,134,190,112,180,111,40,204,230,56,241,87,56,7,219,122,137,191,76,164,193,252,201,186,202,133,254,29,5]}],"page_owner":[237,221,168,59,234,96,25,92,194,229,83,38,211,165,150,178,17,18,14,6,105,54,220,115,38,179,123,169,17,153,97,92],"page_action":[146,19,176,169,31,100,75,135,27,179,95,249,231,55,82,244,13,239,150,67,201,3,172,20,59,98,101,67,189,47,227,15],"pack_scope":null,"pack_digest":null}}"#,
        "takedown-inventory-Entry-5.json" => br#"{"version":1,"kind":5,"canonical_len":4150,"logical_len":1806,"base":null,"references":{"action":{"id":[24,3,109,134,170,169,3,251,84,188,113,203,135,36,28,131,178,105,183,175,157,216,50,252,38,100,133,16,98,121,195,122],"takedown_id":[92,178,107,50,209,28,136,192,172,37,242,117,30,236,15,2,229,183,234,186,54,218,116,114,170,74,48,107,12,181,106,237],"reason":"inventory","blocked_at_ms":0,"chunk_ids":[]},"sorted_pages":false,"chunk_count":1,"chunk_digest":[18,249,56,205,156,251,126,3,158,232,219,34,86,173,230,43,250,85,250,198,219,200,229,155,64,213,166,110,245,185,125,252],"pages":[{"first":[107,65,15,249,63,59,129,120,163,121,162,237,48,243,80,228,78,201,132,168,252,10,7,171,10,191,246,149,128,177,121,145],"last":[107,65,15,249,63,59,129,120,163,121,162,237,48,243,80,228,78,201,132,168,252,10,7,171,10,191,246,149,128,177,121,145],"count":1,"digest":[18,249,56,205,156,251,126,3,158,232,219,34,86,173,230,43,250,85,250,198,219,200,229,155,64,213,166,110,245,185,125,252]}],"page_owner":[92,178,107,50,209,28,136,192,172,37,242,117,30,236,15,2,229,183,234,186,54,218,116,114,170,74,48,107,12,181,106,237],"page_action":[24,3,109,134,170,169,3,251,84,188,113,203,135,36,28,131,178,105,183,175,157,216,50,252,38,100,133,16,98,121,195,122],"pack_scope":null,"pack_digest":null}}"#,
        "takedown-inventory-Entry-7.json" => br#"{"version":1,"kind":7,"canonical_len":197,"logical_len":null,"base":null,"references":{"action":{"id":[42,48,220,78,189,101,122,190,67,146,28,97,182,21,103,169,157,245,92,0,218,102,51,164,231,30,42,209,166,246,71,58],"takedown_id":[150,225,76,243,182,151,234,145,28,176,58,4,81,145,252,252,87,174,27,183,19,207,101,106,131,248,47,254,159,193,177,85],"reason":"inventory","blocked_at_ms":0,"chunk_ids":[]},"sorted_pages":false,"chunk_count":1,"chunk_digest":[241,196,98,90,251,98,102,92,3,182,43,176,211,92,23,62,115,7,227,110,0,212,179,2,7,130,238,52,32,241,15,242],"pages":[{"first":[11,170,1,178,211,144,164,39,30,29,121,182,200,125,37,150,7,253,105,86,83,23,231,101,82,122,252,61,215,77,26,196],"last":[11,170,1,178,211,144,164,39,30,29,121,182,200,125,37,150,7,253,105,86,83,23,231,101,82,122,252,61,215,77,26,196],"count":1,"digest":[241,196,98,90,251,98,102,92,3,182,43,176,211,92,23,62,115,7,227,110,0,212,179,2,7,130,238,52,32,241,15,242]}],"page_owner":[150,225,76,243,182,151,234,145,28,176,58,4,81,145,252,252,87,174,27,183,19,207,101,106,131,248,47,254,159,193,177,85],"page_action":[42,48,220,78,189,101,122,190,67,146,28,97,182,21,103,169,157,245,92,0,218,102,51,164,231,30,42,209,166,246,71,58],"pack_scope":null,"pack_digest":null}}"#,
        "takedown-inventory-Head-sealed.json" => br#"{"version":1,"length":1057135,"count":27,"parents":0,"parent_digest":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"digest":[55,37,147,158,199,78,196,62,94,101,33,55,111,143,164,20,91,54,74,119,79,33,224,81,114,77,51,139,9,38,9,98],"complete":true,"packlist":null}"#,
        "takedown-inventory-Head.json" => br#"{"version":1,"length":1057135,"count":27,"parents":0,"parent_digest":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"digest":[55,37,147,158,199,78,196,62,94,101,33,55,111,143,164,20,91,54,74,119,79,33,224,81,114,77,51,139,9,38,9,98],"complete":false,"packlist":null}"#,
        "takedown-inventory-InventoryCursor.json" => br#"{"after":null,"count":0,"digest":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}"#,
        "takedown-inventory-PacklistFacts.json" => br#"{"prev":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"packs":[[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]]}"#,
        "takedown-source-Checkpoint.json" => br#"{"next":null,"level":50,"previous":{"id":[219,77,66,80,25,185,210,123,212,247,8,28,87,179,200,26,234,193,117,227,43,190,131,216,197,234,41,203,75,181,146,83],"pack":[130,162,169,56,191,232,23,215,77,167,157,136,200,2,110,65,123,159,141,185,183,125,88,29,233,215,110,49,183,127,62,112],"index":[1,0,0,0,0,0,0,0,12,0,0,0,0,0,16,0,15,0,0,0,0,0,0,16,0,10,0,0,0,0,0]},"lookup":{"after":[],"pages":0,"rows":0,"partitions":[]}}"#,
        "takedown-source-Frame.json" => br#"{"id":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"pack":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"index":[1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}"#,
        "takedown-source-Lookup.json" => br#"{"after":[],"pages":0,"rows":0,"partitions":[]}"#,
        "takedown-work-ObjectInfo.json" => br#"{"kind":0,"size":0,"copied":0,"chunks":0,"verified":false,"source_failed":false,"holders":null,"holders_done":true,"namespace_after":null}"#,
        "takedown-work-Phase-Acquire.json" => br#""Acquire""#,
        "takedown-work-Phase-Closure.json" => br#""Closure""#,
        "takedown-work-Phase-Discover.json" => br#""Discover""#,
        "takedown-work-Phase-Purged.json" => br#""Purged""#,
        "takedown-work-Phase-Purging.json" => br#""Purging""#,
        "takedown-work-Phase-Retain.json" => br#""Retain""#,
        "takedown-work-Phase-Seed.json" => br#""Seed""#,
        "takedown-work-State.json" => br#"{"version":1,"phase":"Retain","retain_until":1000010,"hold":false,"purged":false,"purge_after":null,"resume_phase":"Seed","next_purge_at":0,"verification":"Verified","discovery_complete":true,"seed":1,"discovery":null,"current":null,"verified_objects":2}"#,
        "takedown-work-Verification-CanonicalPending.json" => br#""CanonicalPending""#,
        "takedown-work-Verification-ManifestClosurePending.json" => br#""ManifestClosurePending""#,
        "takedown-work-Verification-SourceCorrupt.json" => br#""SourceCorrupt""#,
        "takedown-work-Verification-Verified.json" => br#""Verified""#,
        "u32.hex" => br"01020304
",
        "u64.hex" => br"0102030405060708
",
        "verification-base.hex" => br"000000000000000a000000020000000000000003
",
        "verification-frame-external.hex" => br"01010202020202020202020202020202020202020202020202020202020202020202010000000000000008000000000000000402000000000000000a00000001010202020202020202020202020202020202020202020202020202020202020202
",
        "verification-frame.hex" => br"0100010000000000000008000000000000000400000000000000000a0000000000
",
        "window-cursor.hex" => br"01e08b1e000000000000000001000000006c861e0000000000c0851e000000000001000000230000002000000000000000000000000001af1d9b331319f2773db9e1af35c0f87d88c135ff2529631a45403bdb5266a3a30001c05853ee9b6279ac7b2a0b576b8689ac1bde91cc5b515e137ca07b75565f52e7000000007ce46dcf00f88e48837c9075f2cb62f5e68d45ec6821a7c66130e119f55db46f
",
        "witness-0-0.hex" => br"01000000000000000000020000000000000003
",
        "witness-0-1.hex" => br"01000100000000000000020000000000000003
",
        "witness-1-0.hex" => br"01010000000000000000020000000000000003
",
        "witness-1-1.hex" => br"01010100000000000000020000000000000003
",
        _ => panic!("unknown stored fixture: {name}"),
    }
}

macro_rules! tests {
    (admin_automatic) => {
        use super::*;
        #[test]
        fn v050_stored_encodings() {
            let _ = crate::stored_golden::json_fixture!(Event, "admin-automatic-Event");
        }
    };
    (admin_ledger) => {
        use super::*;
        #[test]
        fn v050_stored_encodings() {
            let _ = crate::stored_golden::json_fixture!(Head, "admin-ledger-Head");
            let expected = crate::stored_golden::row_fixture!("admin-ledger-Head", b"");
            let row: Head = decode(&expected).unwrap();
            assert_eq!(encode(&row).unwrap(), expected);
            let _ = crate::stored_golden::json_fixture!(Nonce, "admin-ledger-Nonce");
            let expected = crate::stored_golden::row_fixture!("admin-ledger-Nonce", b"");
            let row: Nonce = decode(&expected).unwrap();
            assert_eq!(encode(&row).unwrap(), expected);
            let _ = crate::stored_golden::json_fixture!(Operation, "admin-ledger-Operation");
            let expected = crate::stored_golden::row_fixture!("admin-ledger-Operation", b"");
            let row: Operation = decode(&expected).unwrap();
            assert_eq!(encode(&row).unwrap(), expected);
        }
    };
    (admin_mod) => {
        use super::*;
        #[test]
        fn v050_stored_encodings() {
            let _ = crate::stored_golden::json_fixture!(Response, "admin-Response");
        }
    };
    (indexed_checkpoint) => {
        use super::*;
        #[test]
        fn v050_stored_encodings() {
            let _ = crate::stored_golden::json_fixture!(
                ExtractionGroupMember,
                "indexed-checkpoint-ExtractionGroupMember"
            );
            let _ = crate::stored_golden::json_fixture!(
                ExtractionSource,
                "indexed-checkpoint-ExtractionSource"
            );
            let _ = crate::stored_golden::json_fixture!(
                ExtractionV1,
                "indexed-checkpoint-ExtractionV1"
            );
            let _ = crate::stored_golden::json_fixture!(Kind, "indexed-checkpoint-Kind-pack");
            let _ = crate::stored_golden::json_fixture!(Kind, "indexed-checkpoint-Kind-packlist");
            let _ = crate::stored_golden::json_fixture!(Kind, "indexed-checkpoint-Kind-unknown");
            let _ = crate::stored_golden::json_fixture!(
                MemberCursor,
                "indexed-checkpoint-MemberCursor"
            );
            let _ =
                crate::stored_golden::json_fixture!(MemberLists, "indexed-checkpoint-MemberLists");
            let _ = crate::stored_golden::json_fixture!(
                Outcome,
                "indexed-checkpoint-Outcome-base_capped"
            );
            let _ = crate::stored_golden::json_fixture!(
                Outcome,
                "indexed-checkpoint-Outcome-base_missing"
            );
            let _ =
                crate::stored_golden::json_fixture!(Outcome, "indexed-checkpoint-Outcome-blocked");
            let _ = crate::stored_golden::json_fixture!(
                Outcome,
                "indexed-checkpoint-Outcome-closure_capped"
            );
            let _ = crate::stored_golden::json_fixture!(
                Outcome,
                "indexed-checkpoint-Outcome-closure_missing"
            );
            let _ = crate::stored_golden::json_fixture!(
                Outcome,
                "indexed-checkpoint-Outcome-decode_budget"
            );
            let _ = crate::stored_golden::json_fixture!(
                Outcome,
                "indexed-checkpoint-Outcome-external_too_deep"
            );
            let _ = crate::stored_golden::json_fixture!(
                Outcome,
                "indexed-checkpoint-Outcome-extraction_unavailable"
            );
            let _ = crate::stored_golden::json_fixture!(
                Outcome,
                "indexed-checkpoint-Outcome-object_blocked"
            );
            let _ = crate::stored_golden::json_fixture!(
                Outcome,
                "indexed-checkpoint-Outcome-open_closure"
            );
            let _ = crate::stored_golden::json_fixture!(
                Outcome,
                "indexed-checkpoint-Outcome-packlist_missing"
            );
            let _ = crate::stored_golden::json_fixture!(
                Phase,
                "indexed-checkpoint-Phase-await_delivery"
            );
            let _ = crate::stored_golden::json_fixture!(
                Phase,
                "indexed-checkpoint-Phase-closure_resolve"
            );
            let _ = crate::stored_golden::json_fixture!(Phase, "indexed-checkpoint-Phase-decode");
            let _ =
                crate::stored_golden::json_fixture!(Phase, "indexed-checkpoint-Phase-emit_index");
            let _ = crate::stored_golden::json_fixture!(Phase, "indexed-checkpoint-Phase-extract");
            let _ = crate::stored_golden::json_fixture!(Phase, "indexed-checkpoint-Phase-recheck");
            let _ = crate::stored_golden::json_fixture!(Phase, "indexed-checkpoint-Phase-verify");
            let _ = crate::stored_golden::json_fixture!(Phase, "indexed-checkpoint-Phase-watch");
            let _ =
                crate::stored_golden::json_fixture!(VerifyJobV1, "indexed-checkpoint-VerifyJobV1");
            let expected =
                crate::stored_golden::row_fixture!("indexed-checkpoint-VerifyJobV1", b"\x01");
            let row = decode_job(&expected).unwrap();
            assert_eq!(encode_job(&row), expected);
        }
        #[test]
        fn v050_binary_rows() {
            use crate::stored_golden::hex_fixture;
            for expected in [
                hex_fixture!("verification-frame"),
                hex_fixture!("verification-frame-external"),
            ] {
                let row = decode_frame(&[1; 32], &expected).unwrap();
                assert_eq!(encode_frame(&[1; 32], &row).unwrap(), expected);
            }
            let expected = hex_fixture!("verification-base");
            assert_eq!(encode_base(&decode_base(&expected).unwrap()), expected);
            let expected = hex_fixture!("window-cursor");
            assert_eq!(
                mkit_core::pack::window::WindowCursor::from_bytes(expected.as_bytes())
                    .unwrap()
                    .to_bytes(),
                expected.as_bytes()
            );
        }
    };
    (indexed_job_extraction_member) => {
        use super::*;
        #[test]
        fn v050_stored_encodings() {
            let _ =
                crate::stored_golden::json_fixture!(Frame, "indexed-job-extraction-member-Frame");
            let expected =
                crate::stored_golden::row_fixture!("indexed-job-extraction-member-Frame", b"\x01");
            let row: Frame = decode(&expected)
                .unwrap_or_else(|_| panic!("stored row failed decoding or encoding"));
            assert_eq!(
                encode(&row).unwrap_or_else(|_| panic!("stored row failed decoding or encoding")),
                expected
            );
            let _ =
                crate::stored_golden::json_fixture!(Lookup, "indexed-job-extraction-member-Lookup");
            let expected =
                crate::stored_golden::row_fixture!("indexed-job-extraction-member-Lookup", b"\x01");
            let row: Lookup = decode(&expected)
                .unwrap_or_else(|_| panic!("stored row failed decoding or encoding"));
            assert_eq!(
                encode(&row).unwrap_or_else(|_| panic!("stored row failed decoding or encoding")),
                expected
            );
        }
    };
    (indexed_publication_resume) => {
        use super::*;
        #[test]
        fn v050_stored_encodings() {
            let _ = crate::stored_golden::json_fixture!(
                BaseCursor,
                "indexed-publication-resume-BaseCursor"
            );
            let _ = crate::stored_golden::json_fixture!(
                Exhaustion,
                "indexed-publication-resume-Exhaustion-DecodeBudget"
            );
            let _ = crate::stored_golden::json_fixture!(
                Exhaustion,
                "indexed-publication-resume-Exhaustion-IndexCalls"
            );
            let _ = crate::stored_golden::json_fixture!(
                Exhaustion,
                "indexed-publication-resume-Exhaustion-Traversal"
            );
            let _ = crate::stored_golden::json_fixture!(
                Progress,
                "indexed-publication-resume-Progress"
            );
            let _ = crate::stored_golden::json_fixture!(
                TerminalFailure,
                "indexed-publication-resume-TerminalFailure-DeltaDepth"
            );
            let _ = crate::stored_golden::json_fixture!(
                TerminalFailure,
                "indexed-publication-resume-TerminalFailure-OpenClosure"
            );
        }
    };
    (indexed_selection) => {
        use super::*;
        #[test]
        fn v050_stored_encodings() {
            let _ = crate::stored_golden::json_fixture!(
                SelectionFact,
                "indexed-selection-SelectionFact-Blob"
            );
            let _ = crate::stored_golden::json_fixture!(
                SelectionFact,
                "indexed-selection-SelectionFact-Manifest"
            );
            let _ = crate::stored_golden::json_fixture!(
                SelectionFact,
                "indexed-selection-SelectionFact-Other"
            );
            let _ = crate::stored_golden::json_fixture!(
                SelectionFact,
                "indexed-selection-SelectionFact-Tree"
            );
        }
        #[test]
        fn v050_binary_rows() {
            use crate::stored_golden::hex_fixture;
            for expected in [
                hex_fixture!("selection-projection-0"),
                hex_fixture!("selection-projection-1"),
                hex_fixture!("selection-projection-2"),
                hex_fixture!("selection-projection-3"),
            ] {
                let row = Projection::decode(&[1; 32], &expected).unwrap();
                assert_eq!(row.encode(), expected);
                if row.kind == 1 {
                    let page = hex_fixture!("selection-page");
                    let ids: Vec<_> = row.decode_page(0, &page).unwrap().collect();
                    assert_eq!(row.encode_page(0, &ids), page);
                }
            }
        }
    };
    (indexed_state) => {
        use super::*;
        #[test]
        fn v050_stored_encodings() {
            let _ = crate::stored_golden::json_fixture!(
                VerificationV1,
                "indexed-state-VerificationV1-pending"
            );
            let expected =
                crate::stored_golden::row_fixture!("indexed-state-VerificationV1-pending", b"\x01");
            let row = decode(&expected).unwrap();
            assert_eq!(encode(&row), expected);
            let _ = crate::stored_golden::json_fixture!(
                VerificationV1,
                "indexed-state-VerificationV1-rejected"
            );
            let expected = crate::stored_golden::row_fixture!(
                "indexed-state-VerificationV1-rejected",
                b"\x01"
            );
            let row = decode(&expected).unwrap();
            assert_eq!(encode(&row), expected);
            let _ = crate::stored_golden::json_fixture!(
                VerificationV1,
                "indexed-state-VerificationV1-verified"
            );
            let expected = crate::stored_golden::row_fixture!(
                "indexed-state-VerificationV1-verified",
                b"\x01"
            );
            let row = decode(&expected).unwrap();
            assert_eq!(encode(&row), expected);
            let _ = crate::stored_golden::json_fixture!(
                VerificationV1,
                "indexed-state-VerificationV1-verified-publication"
            );
            let expected = crate::stored_golden::row_fixture!(
                "indexed-state-VerificationV1-verified-publication",
                b"\x01"
            );
            let row = decode(&expected).unwrap();
            assert_eq!(encode(&row), expected);
        }
    };
    (pipeline_revocation) => {
        use super::*;
        #[test]
        fn v050_stored_encodings() {
            use crate::pipeline::{Addressing, AuthMode, Hooks, PipelineConfig};
            use crate::{MemoryBlobStore, MemoryKv, NoopMetrics, RepoId, RepoName};
            futures_executor::block_on(async {
                let expected = crate::stored_golden::row_fixture!(
                    "pipeline-revocation-RevokeCheckpoint",
                    b"\x01"
                );
                let checkpoint = crate::stored_golden::json_fixture!(
                    RevokeCheckpoint,
                    "pipeline-revocation-RevokeCheckpoint"
                );
                let ns = NamespaceKey::deployment_default();
                let partition = Partition::Coordinator(ns.clone());
                let state = CoordinatorState {
                    kind: FenceKind::Grant,
                    epoch: checkpoint.generation,
                    epoch_value: Some(codec::encode_u64(checkpoint.generation)),
                    config_version: 1,
                    recovery: checkpoint.recovery,
                };
                let kv = MemoryKv::default();
                let key = keys::revoke_cursor(false);
                kv.apply(
                    &partition,
                    Batch::new()
                        .put(key.clone(), expected.clone())
                        .put(state.kind.key(), state.epoch_value.clone().unwrap())
                        .put(
                            keys::lease_recovery(),
                            codec::encode_lease_recovery(&state.recovery.unwrap()),
                        ),
                )
                .await
                .unwrap();
                let cfg = PipelineConfig::new(
                    Addressing::Single {
                        repo: RepoId {
                            namespace: ns,
                            name: RepoName::new("repo").unwrap(),
                        },
                    },
                    AuthMode::Open,
                    crate::upload::UploadLimits {
                        max_total_bytes: 1 << 20,
                        max_chunks: 64,
                    },
                );
                let pipe = Pipeline::new(
                    MemoryBlobStore::default(),
                    kv,
                    Hooks::new(),
                    cfg,
                    std::sync::Arc::new(crate::ManualClock::new(1000)),
                    std::sync::Arc::new(NoopMetrics),
                )
                .unwrap();
                let (raw, cursor) = pipe.read_revoke_cursor(&partition, &state).await.unwrap();
                assert_eq!(raw, Some(expected.clone()));
                assert_eq!(cursor.as_ref().unwrap().as_bytes(), [1, 2]);
                assert!(
                    pipe.save_revoke_cursor(&partition, &state, raw.as_ref(), cursor)
                        .await
                        .unwrap()
                );
                assert_eq!(
                    pipe.meta.get(&partition, &key).await.unwrap(),
                    Some(expected)
                );
            });
        }
    };
    (purge_delivery) => {
        use super::*;
        #[test]
        fn v050_stored_encodings() {
            let _ = crate::stored_golden::json_fixture!(Progress, "purge-delivery-Progress");
        }
    };
    (purge_mod) => {
        use super::*;
        #[test]
        fn v050_stored_encodings() {
            let _ = crate::stored_golden::json_fixture!(Request, "purge-Request");
            let _ = crate::stored_golden::json_fixture!(
                Trigger,
                "purge-Trigger-CACHE_PURGE_TRIGGER_LEASE_DELETION"
            );
            let _ = crate::stored_golden::json_fixture!(
                Trigger,
                "purge-Trigger-CACHE_PURGE_TRIGGER_MANUAL"
            );
            let _ = crate::stored_golden::json_fixture!(
                Trigger,
                "purge-Trigger-CACHE_PURGE_TRIGGER_SUSPENSION"
            );
            let _ = crate::stored_golden::json_fixture!(
                Trigger,
                "purge-Trigger-CACHE_PURGE_TRIGGER_TAKEDOWN"
            );
            let _ = crate::stored_golden::json_fixture!(
                Trigger,
                "purge-Trigger-CACHE_PURGE_TRIGGER_VISIBILITY_CHANGE"
            );
        }
    };
    (relay_content) => {
        use super::*;
        #[test]
        fn v050_stored_encodings() {
            for (expected, ready) in [
                (
                    crate::stored_golden::hex_fixture!("relay-ContentTakedownV1-pending"),
                    None,
                ),
                (
                    crate::stored_golden::hex_fixture!("relay-ContentTakedownV1-ready"),
                    Some(6),
                ),
            ] {
                let row = ContentTakedownV1::decode(&expected).unwrap();
                assert_eq!(row.queued_at_ms, 5);
                assert_eq!(row.ready_at_ms, ready);
                assert_eq!(row.encode().unwrap(), expected);
            }
        }
    };
    (store_codec) => {
        use super::*;
        #[test]
        fn v050_stored_encodings() {
            let expected = crate::stored_golden::row_fixture!("store-codec-BackupStateV1", b"\x01");
            let row = decode_backup_state(&expected).unwrap();
            assert_eq!(row.last_export_ms, 10);
            assert_eq!(row.digest, [1; 32]);
            assert_eq!(row.r2_key, "backups/sample");
            assert_eq!(row.last_upload_ms, 11);
            assert_eq!(encode_backup_state(&row), expected);
            let _ = crate::stored_golden::json_fixture!(OutcomeRef, "store-codec-OutcomeRef");
            let _ = crate::stored_golden::json_fixture!(
                AbortReason,
                "store-codec-AbortReason-ABANDONED"
            );
            let _ = crate::stored_golden::json_fixture!(
                AbortReason,
                "store-codec-AbortReason-EPOCH_MISMATCH"
            );
            let _ = crate::stored_golden::json_fixture!(
                AbortReason,
                "store-codec-AbortReason-INTERNAL"
            );
            let _ = crate::stored_golden::json_fixture!(
                AbortReason,
                "store-codec-AbortReason-PACK_MISSING"
            );
            let _ = crate::stored_golden::json_fixture!(
                AbortReason,
                "store-codec-AbortReason-REF_CONFLICT"
            );
            let _ = crate::stored_golden::json_fixture!(
                AbortReason,
                "store-codec-AbortReason-REPLAY_RACE"
            );
            let _ = crate::stored_golden::json_fixture!(
                AbortReason,
                "store-codec-AbortReason-UNSPECIFIED"
            );
            let _ = crate::stored_golden::json_fixture!(Backlog, "store-codec-Backlog");
            let expected = crate::stored_golden::row_fixture!("store-codec-Backlog", b"\x01");
            let row = decode_backlog(&expected).unwrap();
            assert_eq!(encode_backlog(&row), expected);
            let _ = crate::stored_golden::json_fixture!(BlockV1, "store-codec-BlockV1");
            let expected = crate::stored_golden::row_fixture!("store-codec-BlockV1", b"\x01");
            let row = decode_block_entry(&expected).unwrap();
            assert_eq!(encode_block_entry(&row), expected);
            let _ = crate::stored_golden::json_fixture!(EpochLease, "store-codec-EpochLease");
            let expected = crate::stored_golden::row_fixture!("store-codec-EpochLease", b"\x01");
            let row = decode_epoch_lease(&expected).unwrap();
            assert_eq!(encode_epoch_lease(&row), expected);
            let _ = crate::stored_golden::json_fixture!(HoldV1, "store-codec-HoldV1");
            let expected = crate::stored_golden::row_fixture!("store-codec-HoldV1", b"\x01");
            let row = decode_hold(&expected).unwrap();
            assert_eq!(encode_hold(row), expected);
            let _ = crate::stored_golden::json_fixture!(HolderV1, "store-codec-HolderV1");
            let expected = crate::stored_golden::row_fixture!("store-codec-HolderV1", b"\x01");
            let row = decode_holder(&expected).unwrap();
            assert_eq!(encode_holder(&row), expected);
            let _ = crate::stored_golden::json_fixture!(LeaseRecovery, "store-codec-LeaseRecovery");
            let expected = crate::stored_golden::row_fixture!("store-codec-LeaseRecovery", b"\x01");
            let row = decode_lease_recovery(&expected).unwrap();
            assert_eq!(encode_lease_recovery(&row), expected);
            let _ = crate::stored_golden::json_fixture!(LeasedShard, "store-codec-LeasedShard");
            let expected = crate::stored_golden::row_fixture!("store-codec-LeasedShard", b"\x01");
            let row = decode_leased_shard(&expected).unwrap();
            assert_eq!(encode_leased_shard(&row), expected);
            let _ =
                crate::stored_golden::json_fixture!(NamespaceRecord, "store-codec-NamespaceRecord");
            let expected =
                crate::stored_golden::row_fixture!("store-codec-NamespaceRecord", b"\x01");
            let row = decode_namespace_record(&expected).unwrap();
            assert_eq!(encode_namespace_record(&row), expected);
            let _ = crate::stored_golden::json_fixture!(ObjectStateV1, "store-codec-ObjectStateV1");
            let expected = crate::stored_golden::row_fixture!("store-codec-ObjectStateV1", b"\x01");
            let row = decode_object_state(&expected).unwrap();
            assert_eq!(encode_object_state(&row), expected);
            let _ = crate::stored_golden::json_fixture!(PendingOp, "store-codec-PendingOp-read");
            let _ = crate::stored_golden::json_fixture!(PendingOp, "store-codec-PendingOp-write");
            let _ = crate::stored_golden::json_fixture!(QuotaV1, "store-codec-QuotaV1");
            let expected = crate::stored_golden::row_fixture!("store-codec-QuotaV1", b"\x01");
            let row = decode_quota_state(&expected).unwrap();
            assert_eq!(encode_quota_state(&row), expected);
            let _ = crate::stored_golden::json_fixture!(RecordV1, "store-codec-RecordV1");
            let expected = crate::stored_golden::row_fixture!("store-codec-RecordV1", b"\x01");
            let row = decode_replay_record(&expected).unwrap();
            assert_eq!(encode_replay_record(&row), expected);
            let _ = crate::stored_golden::json_fixture!(
                RecordV1,
                "store-codec-RecordV1-already_exists"
            );
            let expected =
                crate::stored_golden::row_fixture!("store-codec-RecordV1-already_exists", b"\x01");
            let row = decode_replay_record(&expected).unwrap();
            assert_eq!(encode_replay_record(&row), expected);
            let _ = crate::stored_golden::json_fixture!(
                RecordV1,
                "store-codec-RecordV1-failed_precondition"
            );
            let expected = crate::stored_golden::row_fixture!(
                "store-codec-RecordV1-failed_precondition",
                b"\x01"
            );
            let row = decode_replay_record(&expected).unwrap();
            assert_eq!(encode_replay_record(&row), expected);
            let _ = crate::stored_golden::json_fixture!(
                RecordV1,
                "store-codec-RecordV1-invalid_argument"
            );
            let expected = crate::stored_golden::row_fixture!(
                "store-codec-RecordV1-invalid_argument",
                b"\x01"
            );
            let row = decode_replay_record(&expected).unwrap();
            assert_eq!(encode_replay_record(&row), expected);
            let _ = crate::stored_golden::json_fixture!(RecordV1, "store-codec-RecordV1-not_found");
            let expected =
                crate::stored_golden::row_fixture!("store-codec-RecordV1-not_found", b"\x01");
            let row = decode_replay_record(&expected).unwrap();
            assert_eq!(encode_replay_record(&row), expected);
            let _ =
                crate::stored_golden::json_fixture!(RecordV1, "store-codec-RecordV1-out_of_range");
            let expected =
                crate::stored_golden::row_fixture!("store-codec-RecordV1-out_of_range", b"\x01");
            let row = decode_replay_record(&expected).unwrap();
            assert_eq!(encode_replay_record(&row), expected);
            let _ = crate::stored_golden::json_fixture!(
                RecordV1,
                "store-codec-RecordV1-permission_denied"
            );
            let expected = crate::stored_golden::row_fixture!(
                "store-codec-RecordV1-permission_denied",
                b"\x01"
            );
            let row = decode_replay_record(&expected).unwrap();
            assert_eq!(encode_replay_record(&row), expected);
            let _ =
                crate::stored_golden::json_fixture!(RecordV1, "store-codec-RecordV1-unimplemented");
            let expected =
                crate::stored_golden::row_fixture!("store-codec-RecordV1-unimplemented", b"\x01");
            let row = decode_replay_record(&expected).unwrap();
            assert_eq!(encode_replay_record(&row), expected);
            let _ = crate::stored_golden::json_fixture!(RelayDtoV1, "store-codec-RelayDtoV1");
            let expected = crate::stored_golden::row_fixture!("store-codec-RelayDtoV1", b"\x01");
            let row = decode_relay(&expected).unwrap();
            assert_eq!(encode_relay(&row).unwrap(), expected);
            let _ =
                crate::stored_golden::json_fixture!(RelayScanDtoV1, "store-codec-RelayScanDtoV1");
            let expected =
                crate::stored_golden::row_fixture!("store-codec-RelayScanDtoV1", b"\x01");
            let row = decode_relay_scan(&expected).unwrap();
            assert_eq!(encode_relay_scan(&row).unwrap(), expected);
            let _ = crate::stored_golden::json_fixture!(RepoRecord, "store-codec-RepoRecord");
            let expected = crate::stored_golden::row_fixture!("store-codec-RepoRecord", b"\x01");
            let row = decode_repo_record(&expected).unwrap();
            assert_eq!(encode_repo_record(&row), expected);
            let _ = crate::stored_golden::json_fixture!(
                RepoVisibilityV1,
                "store-codec-RepoVisibilityV1-private"
            );
            let expected =
                crate::stored_golden::row_fixture!("store-codec-RepoVisibilityV1-private", b"\x01");
            let row = decode_repo_visibility(&expected).unwrap();
            assert_eq!(encode_repo_visibility(&row), expected);
            let _ = crate::stored_golden::json_fixture!(
                RepoVisibilityV1,
                "store-codec-RepoVisibilityV1-public"
            );
            let expected =
                crate::stored_golden::row_fixture!("store-codec-RepoVisibilityV1-public", b"\x01");
            let row = decode_repo_visibility(&expected).unwrap();
            assert_eq!(encode_repo_visibility(&row), expected);
            let _ = crate::stored_golden::json_fixture!(
                ReservationV1,
                "store-codec-ReservationV1-aborted-ABANDONED"
            );
            let expected = crate::stored_golden::row_fixture!(
                "store-codec-ReservationV1-aborted-ABANDONED",
                b"\x01"
            );
            let row = decode_reservation(&expected).unwrap();
            assert_eq!(encode_reservation(&row), expected);
            let _ = crate::stored_golden::json_fixture!(
                ReservationV1,
                "store-codec-ReservationV1-aborted-EPOCH_MISMATCH"
            );
            let expected = crate::stored_golden::row_fixture!(
                "store-codec-ReservationV1-aborted-EPOCH_MISMATCH",
                b"\x01"
            );
            let row = decode_reservation(&expected).unwrap();
            assert_eq!(encode_reservation(&row), expected);
            let _ = crate::stored_golden::json_fixture!(
                ReservationV1,
                "store-codec-ReservationV1-aborted-INTERNAL"
            );
            let expected = crate::stored_golden::row_fixture!(
                "store-codec-ReservationV1-aborted-INTERNAL",
                b"\x01"
            );
            let row = decode_reservation(&expected).unwrap();
            assert_eq!(encode_reservation(&row), expected);
            let _ = crate::stored_golden::json_fixture!(
                ReservationV1,
                "store-codec-ReservationV1-aborted-PACK_MISSING"
            );
            let expected = crate::stored_golden::row_fixture!(
                "store-codec-ReservationV1-aborted-PACK_MISSING",
                b"\x01"
            );
            let row = decode_reservation(&expected).unwrap();
            assert_eq!(encode_reservation(&row), expected);
            let _ = crate::stored_golden::json_fixture!(
                ReservationV1,
                "store-codec-ReservationV1-aborted-REF_CONFLICT"
            );
            let expected = crate::stored_golden::row_fixture!(
                "store-codec-ReservationV1-aborted-REF_CONFLICT",
                b"\x01"
            );
            let row = decode_reservation(&expected).unwrap();
            assert_eq!(encode_reservation(&row), expected);
            let _ = crate::stored_golden::json_fixture!(
                ReservationV1,
                "store-codec-ReservationV1-aborted-REPLAY_RACE"
            );
            let expected = crate::stored_golden::row_fixture!(
                "store-codec-ReservationV1-aborted-REPLAY_RACE",
                b"\x01"
            );
            let row = decode_reservation(&expected).unwrap();
            assert_eq!(encode_reservation(&row), expected);
            let _ = crate::stored_golden::json_fixture!(
                ReservationV1,
                "store-codec-ReservationV1-aborted-UNSPECIFIED"
            );
            let expected = crate::stored_golden::row_fixture!(
                "store-codec-ReservationV1-aborted-UNSPECIFIED",
                b"\x01"
            );
            let row = decode_reservation(&expected).unwrap();
            assert_eq!(encode_reservation(&row), expected);
            let _ = crate::stored_golden::json_fixture!(
                ReservationV1,
                "store-codec-ReservationV1-committed"
            );
            let expected =
                crate::stored_golden::row_fixture!("store-codec-ReservationV1-committed", b"\x01");
            let row = decode_reservation(&expected).unwrap();
            assert_eq!(encode_reservation(&row), expected);
            let _ = crate::stored_golden::json_fixture!(
                ReservationV1,
                "store-codec-ReservationV1-expired"
            );
            let expected =
                crate::stored_golden::row_fixture!("store-codec-ReservationV1-expired", b"\x01");
            let row = decode_reservation(&expected).unwrap();
            assert_eq!(encode_reservation(&row), expected);
            let _ = crate::stored_golden::json_fixture!(
                ReservationV1,
                "store-codec-ReservationV1-pending"
            );
            let expected =
                crate::stored_golden::row_fixture!("store-codec-ReservationV1-pending", b"\x01");
            let row = decode_reservation(&expected).unwrap();
            assert_eq!(encode_reservation(&row), expected);
            let _ = crate::stored_golden::json_fixture!(
                ReservationV1,
                "store-codec-ReservationV1-read_served"
            );
            let expected = crate::stored_golden::row_fixture!(
                "store-codec-ReservationV1-read_served",
                b"\x01"
            );
            let row = decode_reservation(&expected).unwrap();
            assert_eq!(encode_reservation(&row), expected);
            let _ = crate::stored_golden::json_fixture!(
                ReservationV1,
                "store-codec-ReservationV1-ticketed"
            );
            let expected =
                crate::stored_golden::row_fixture!("store-codec-ReservationV1-ticketed", b"\x01");
            let row = decode_reservation(&expected).unwrap();
            assert_eq!(encode_reservation(&row), expected);
            let _ = crate::stored_golden::json_fixture!(
                ResultV1,
                "store-codec-ResultV1-advance_committed"
            );
            let _ = crate::stored_golden::json_fixture!(
                ResultV1,
                "store-codec-ResultV1-advance_head_conflict"
            );
            let _ = crate::stored_golden::json_fixture!(
                ResultV1,
                "store-codec-ResultV1-advance_packmap_conflict"
            );
            let _ = crate::stored_golden::json_fixture!(
                ResultV1,
                "store-codec-ResultV1-begin_upload_already_present"
            );
            let _ = crate::stored_golden::json_fixture!(
                ResultV1,
                "store-codec-ResultV1-begin_upload_ticket"
            );
            let _ = crate::stored_golden::json_fixture!(ResultV1, "store-codec-ResultV1-rejected");
            let _ = crate::stored_golden::json_fixture!(
                ResultV1,
                "store-codec-ResultV1-repo_visibility"
            );
            let _ = crate::stored_golden::json_fixture!(
                ResultV1,
                "store-codec-ResultV1-update_ref_committed"
            );
            let _ = crate::stored_golden::json_fixture!(
                ResultV1,
                "store-codec-ResultV1-update_ref_conflict"
            );
            let _ =
                crate::stored_golden::json_fixture!(ResultV1, "store-codec-ResultV1-upload_pack");
            let _ = crate::stored_golden::json_fixture!(
                StateV1,
                "store-codec-StateV1-advance_committed"
            );
            let _ = crate::stored_golden::json_fixture!(
                StateV1,
                "store-codec-StateV1-advance_head_conflict"
            );
            let _ = crate::stored_golden::json_fixture!(
                StateV1,
                "store-codec-StateV1-advance_packmap_conflict"
            );
            let _ = crate::stored_golden::json_fixture!(
                StateV1,
                "store-codec-StateV1-begin_upload_already_present"
            );
            let _ = crate::stored_golden::json_fixture!(
                StateV1,
                "store-codec-StateV1-begin_upload_ticket"
            );
            let _ = crate::stored_golden::json_fixture!(StateV1, "store-codec-StateV1-in_flight");
            let _ = crate::stored_golden::json_fixture!(StateV1, "store-codec-StateV1-rejected");
            let _ =
                crate::stored_golden::json_fixture!(StateV1, "store-codec-StateV1-repo_visibility");
            let _ = crate::stored_golden::json_fixture!(
                StateV1,
                "store-codec-StateV1-update_ref_committed"
            );
            let _ = crate::stored_golden::json_fixture!(
                StateV1,
                "store-codec-StateV1-update_ref_conflict"
            );
            let _ = crate::stored_golden::json_fixture!(StateV1, "store-codec-StateV1-upload_pack");
            let _ = crate::stored_golden::json_fixture!(
                StoredVisibility,
                "store-codec-StoredVisibility-private"
            );
            let _ = crate::stored_golden::json_fixture!(
                StoredVisibility,
                "store-codec-StoredVisibility-public"
            );
            let _ = crate::stored_golden::json_fixture!(TicketV1, "store-codec-TicketV1");
            let expected = crate::stored_golden::row_fixture!("store-codec-TicketV1", b"\x01");
            let row = decode_ticket(&expected).unwrap();
            assert_eq!(encode_ticket(&row), expected);
        }
        #[test]
        fn v050_binary_rows() {
            use crate::stored_golden::hex_fixture;
            for (expected, encode, decode) in [
                (
                    hex_fixture!("object-index-0"),
                    encode_object_index,
                    decode_object_index,
                ),
                (
                    hex_fixture!("object-index-2"),
                    encode_object_index,
                    decode_object_index,
                ),
                (
                    hex_fixture!("object-index-3"),
                    encode_object_index,
                    decode_object_index,
                ),
                (
                    hex_fixture!("object-index-4"),
                    encode_object_index,
                    decode_object_index,
                ),
            ] {
                let row = decode(&[1; 32], &expected).unwrap();
                assert_eq!(encode(&[1; 32], &row).unwrap(), expected);
            }
            let expected = hex_fixture!("namespace-usage");
            assert_eq!(
                encode_namespace_usage(decode_namespace_usage(&expected).unwrap()),
                expected
            );
            let expected = hex_fixture!("namespace-view");
            assert_eq!(
                encode_namespace_view(decode_namespace_view(&expected).unwrap()),
                expected
            );
            let expected = hex_fixture!("u32");
            assert_eq!(decode_u32(&expected).unwrap(), 0x0102_0304);
            assert_eq!(encode_u32(0x0102_0304), expected);
            let expected = hex_fixture!("u64");
            assert_eq!(decode_u64(&expected).unwrap(), 0x0102_0304_0506_0708);
            assert_eq!(encode_u64(0x0102_0304_0506_0708), expected);
            let expected = hex_fixture!("ref-id");
            assert_eq!(decode_ref_id(&expected).unwrap(), [1; 32]);
            assert_eq!(encode_ref_id(&[1; 32]), expected);
        }
    };
    (store_inspection_flags) => {
        use super::*;
        #[test]
        fn v050_stored_encodings() {
            let _ = crate::stored_golden::json_fixture!(
                FlagSource,
                "store-inspection_flags-FlagSource"
            );
            let _ = crate::stored_golden::json_fixture!(
                FlagState,
                "store-inspection_flags-FlagState-flagged"
            );
            let _ = crate::stored_golden::json_fixture!(
                FlagState,
                "store-inspection_flags-FlagState-released"
            );
        }
        #[test]
        fn v050_binary_rows() {
            for body in [
                crate::stored_golden::fixture("store-inspection_flags-FlagV1-Flagged.json"),
                crate::stored_golden::fixture("store-inspection_flags-FlagV1-Released.json"),
            ] {
                let expected = crate::stored_golden::value(body, b"\x01");
                let row = decode_flag(&expected).unwrap();
                assert_eq!(encode_flag(&row).unwrap(), expected);
            }
        }
    };
    (store_inspection_holds) => {
        use super::*;
        #[test]
        fn v050_binary_rows() {
            use crate::stored_golden::hex_fixture;
            for expected in [hex_fixture!("hold-pending"), hex_fixture!("hold-complete")] {
                validate_advance_hold(&expected).unwrap();
            }
            for expected in [hex_fixture!("hold-manifest"), hex_fixture!("hold-released")] {
                let row = decode_manifest(Some(&expected)).unwrap();
                assert_eq!(encode_manifest_state(&row.ids, row.released), expected);
            }
        }
    };
    (store_inspection_mode) => {
        use super::*;
        #[test]
        fn v050_binary_rows() {
            use crate::stored_golden::hex_fixture;
            let expected = hex_fixture!("inspection-enabled");
            assert_eq!(compare(&expected, true), Outcome::Ok);
            assert_eq!(compare(&expected, false), Outcome::Disabled);
        }
    };
    (store_maintenance) => {
        use super::*;
        #[test]
        fn v050_binary_rows() {
            use crate::stored_golden::hex_fixture;
            let header = hex_fixture!("export-header");
            let record = hex_fixture!("export-record");
            let bytes = [header.as_bytes(), record.as_bytes(), &[0, 0]].concat();
            let (h, mut reader) = ExportReader::new(&bytes).unwrap();
            assert_eq!(encode_export_header(&h).as_ref(), header.as_bytes());
            let row = reader.next().unwrap().unwrap();
            assert_eq!(
                encode_export_record(&row).unwrap().as_ref(),
                record.as_bytes()
            );
            assert!(reader.next().is_none());
        }
    };
    (store_pending_holder) => {
        use super::*;
        #[test]
        fn v050_binary_rows() {
            use crate::stored_golden::hex_fixture;
            let expected = hex_fixture!("pending-holder");
            let row = PendingHolderV1::decode(&expected).unwrap();
            assert_eq!(row.object, [2; 32]);
            assert_eq!(row.encode().unwrap(), expected);
        }
    };
    (store_publication) => {
        use super::*;
        #[test]
        fn v050_stored_encodings() {
            let _ = crate::stored_golden::json_fixture!(Advance, "store-publication-Advance");
            let expected = crate::stored_golden::row_fixture!("store-publication-Advance", b"\x01");
            let row: Advance = decode(&expected).unwrap();
            assert_eq!(encode(&row).unwrap(), expected);
            let _ = crate::stored_golden::json_fixture!(
                Clearance,
                "store-publication-Clearance-cleared"
            );
            let _ =
                crate::stored_golden::json_fixture!(Clearance, "store-publication-Clearance-held");
            let _ =
                crate::stored_golden::json_fixture!(Clearance, "store-publication-Clearance-hit");
            let _ = crate::stored_golden::json_fixture!(
                Clearance,
                "store-publication-Clearance-pending"
            );
            let _ = crate::stored_golden::json_fixture!(
                Clearance,
                "store-publication-Clearance-resolved"
            );
            let _ = crate::stored_golden::json_fixture!(Obligation, "store-publication-Obligation");
            let expected =
                crate::stored_golden::row_fixture!("store-publication-Obligation", b"\x01");
            let row: Obligation = decode(&expected).unwrap();
            assert_eq!(encode(&row).unwrap(), expected);
            let _ = crate::stored_golden::json_fixture!(Pair, "store-publication-Pair");
            let expected = crate::stored_golden::row_fixture!("store-publication-Pair", b"\x01");
            let row: Pair = decode(&expected).unwrap();
            assert_eq!(encode(&row).unwrap(), expected);
            let _ =
                crate::stored_golden::json_fixture!(Publication, "store-publication-Publication");
            let expected =
                crate::stored_golden::row_fixture!("store-publication-Publication", b"\x01");
            let row: Publication = decode(&expected).unwrap();
            assert_eq!(encode(&row).unwrap(), expected);
        }
        #[test]
        fn v050_binary_rows() {
            use crate::stored_golden::hex_fixture;
            for expected in [
                hex_fixture!("witness-0-0"),
                hex_fixture!("witness-0-1"),
                hex_fixture!("witness-1-0"),
                hex_fixture!("witness-1-1"),
            ] {
                assert_eq!(Witness::decode(&expected).unwrap().encode(), expected);
            }
            let row = Witness::decode(&hex_fixture!("immediate-membership")).unwrap();
            assert!(row.published && !row.held);
            assert_eq!((row.generation, row.sequence), (0, 0));
        }
    };
    (store_watermark) => {
        use super::*;
        #[test]
        fn v050_stored_encodings() {
            for (expected, recovery, reconcile) in [
                (
                    crate::stored_golden::hex_fixture!("store-watermark-WatermarkCheckpoint-00"),
                    false,
                    false,
                ),
                (
                    crate::stored_golden::hex_fixture!("store-watermark-WatermarkCheckpoint-10"),
                    true,
                    false,
                ),
                (
                    crate::stored_golden::hex_fixture!("store-watermark-WatermarkCheckpoint-01"),
                    false,
                    true,
                ),
                (
                    crate::stored_golden::hex_fixture!("store-watermark-WatermarkCheckpoint-11"),
                    true,
                    true,
                ),
            ] {
                let row = WatermarkCheckpoint::decode(expected.as_bytes()).unwrap();
                assert_eq!(
                    row.coordinator,
                    Partition::Coordinator(crate::NamespaceKey::deployment_default())
                );
                assert_eq!(row.ceiling_ms, 200);
                assert_eq!(row.minimum_ms, 150);
                assert_eq!(row.cursor.as_bytes(), b"ls\0cursor");
                assert_eq!(row.recovery_generation.0.is_some(), recovery);
                assert_eq!(row.recovery_generation.1.is_some(), reconcile);
                assert_eq!(row.encode(), expected.as_bytes());
            }
        }
    };
    (takedown_closure) => {
        use super::*;
        #[test]
        fn v050_stored_encodings() {
            let _ = crate::stored_golden::json_fixture!(Checkpoint, "takedown-closure-Checkpoint");
        }
    };
    (takedown_copy) => {
        use super::*;
        #[test]
        fn v050_stored_encodings() {
            let _ = crate::stored_golden::json_fixture!(Piece, "takedown-copy-Piece");
        }
        #[test]
        fn v050_binary_rows() {
            use crate::stored_golden::hex_fixture;
            use futures_executor::block_on;
            let expected = hex_fixture!("preserved-piece");
            let store = crate::MemoryBlobStore::default();
            let piece = block_on(write(&store, &[1; 32], &[2; 32], 3, b"abc")).unwrap();
            let raw = block_on(store.get(&BlobKey::pack(piece.storage), None))
                .unwrap()
                .unwrap();
            let BlobBody::Bytes(raw) = raw else {
                panic!("memory body")
            };
            assert_eq!(raw.as_ref(), expected.as_bytes());
            assert_eq!(
                block_on(read(&store, &[1; 32], &piece))
                    .unwrap()
                    .unwrap()
                    .as_ref(),
                b"abc"
            );
        }
    };
    (takedown_denial) => {
        use super::*;
        #[test]
        fn v050_stored_encodings() {
            for expected in [
                crate::stored_golden::row_fixture!("takedown-denial-ActionsV2", b""),
                crate::stored_golden::row_fixture!("takedown-denial-ActionsV2-populated", b""),
            ] {
                let rows = decode_actions(Some(&expected)).unwrap();
                assert_eq!(encode_actions(rows).unwrap(), expected);
            }
            let _ = crate::stored_golden::json_fixture!(ActionsV2, "takedown-denial-ActionsV2");
            let _ = crate::stored_golden::json_fixture!(BlockAction, "takedown-denial-BlockAction");
            let _ = crate::stored_golden::json_fixture!(ChunkPage, "takedown-denial-ChunkPage");
            let _ =
                crate::stored_golden::json_fixture!(StoredAction, "takedown-denial-StoredAction");
        }
    };
    (takedown_directory) => {
        use super::*;
        #[test]
        fn v050_binary_rows() {
            use crate::stored_golden::hex_fixture;
            let expected = hex_fixture!("denial-pointer");
            assert_eq!(value(&[1; 32]), expected);
            let page = ScanPage {
                entries: vec![(key(&[1; 32]), expected)],
                next: None,
            };
            validate_page(0, &page).unwrap();
        }
    };
    (takedown_discovery) => {
        use super::*;
        #[test]
        fn v050_stored_encodings() {
            let _ = crate::stored_golden::json_fixture!(
                DiscoveryState,
                "takedown-discovery-DiscoveryState"
            );
        }
    };
    (takedown_intent) => {
        use super::*;
        #[test]
        fn v050_stored_encodings() {
            let _ = crate::stored_golden::json_fixture!(Draft, "takedown-intent-Draft");
            let expected = crate::stored_golden::row_fixture!("takedown-intent-Draft", b"");
            let row: Draft = decode(&expected).unwrap();
            assert_eq!(encode(&row).unwrap(), expected);
            let _ = crate::stored_golden::json_fixture!(Record, "takedown-intent-Record");
            let expected = crate::stored_golden::row_fixture!("takedown-intent-Record", b"");
            let row: Record = decode(&expected).unwrap();
            assert_eq!(encode(&row).unwrap(), expected);
            let _ = crate::stored_golden::json_fixture!(Reference, "takedown-intent-Reference");
        }
    };
    (takedown_inventory) => {
        use super::*;
        #[test]
        fn v050_stored_encodings() {
            let _ = crate::stored_golden::json_fixture!(Entry, "takedown-inventory-Entry-0");
            let expected = crate::stored_golden::row_fixture!("takedown-inventory-Entry-0", b"");
            let row: Entry = decode(&expected).unwrap();
            assert_eq!(encode(&row).unwrap(), expected);
            let _ = crate::stored_golden::json_fixture!(Entry, "takedown-inventory-Entry-1");
            let expected = crate::stored_golden::row_fixture!("takedown-inventory-Entry-1", b"");
            let row: Entry = decode(&expected).unwrap();
            assert_eq!(encode(&row).unwrap(), expected);
            let _ = crate::stored_golden::json_fixture!(Entry, "takedown-inventory-Entry-2");
            let expected = crate::stored_golden::row_fixture!("takedown-inventory-Entry-2", b"");
            let row: Entry = decode(&expected).unwrap();
            assert_eq!(encode(&row).unwrap(), expected);
            let _ = crate::stored_golden::json_fixture!(Entry, "takedown-inventory-Entry-3");
            let expected = crate::stored_golden::row_fixture!("takedown-inventory-Entry-3", b"");
            let row: Entry = decode(&expected).unwrap();
            assert_eq!(encode(&row).unwrap(), expected);
            let _ = crate::stored_golden::json_fixture!(Entry, "takedown-inventory-Entry-4");
            let expected = crate::stored_golden::row_fixture!("takedown-inventory-Entry-4", b"");
            let row: Entry = decode(&expected).unwrap();
            assert_eq!(encode(&row).unwrap(), expected);
            let _ = crate::stored_golden::json_fixture!(Entry, "takedown-inventory-Entry-5");
            let expected = crate::stored_golden::row_fixture!("takedown-inventory-Entry-5", b"");
            let row: Entry = decode(&expected).unwrap();
            assert_eq!(encode(&row).unwrap(), expected);
            let _ = crate::stored_golden::json_fixture!(Entry, "takedown-inventory-Entry-7");
            let expected = crate::stored_golden::row_fixture!("takedown-inventory-Entry-7", b"");
            let row: Entry = decode(&expected).unwrap();
            assert_eq!(encode(&row).unwrap(), expected);
            let _ = crate::stored_golden::json_fixture!(Head, "takedown-inventory-Head");
            let expected = crate::stored_golden::row_fixture!("takedown-inventory-Head", b"");
            let row: Head = decode(&expected).unwrap();
            assert_eq!(encode(&row).unwrap(), expected);
            let _ = crate::stored_golden::json_fixture!(
                InventoryCursor,
                "takedown-inventory-InventoryCursor"
            );
            let _ = crate::stored_golden::json_fixture!(
                PacklistFacts,
                "takedown-inventory-PacklistFacts"
            );
        }
        #[test]
        fn v050_binary_rows() {
            use futures_executor::block_on;
            let store = crate::MemoryKv::default();
            let pack = [1; 32];
            let raw = crate::stored_golden::row_fixture!("takedown-inventory-Head-sealed", b"");
            block_on(store.apply(
                &content_shard(&pack),
                Batch::new().put(head_key(&pack), raw.clone()),
            ))
            .unwrap();
            assert_eq!(
                block_on(seal(&store, &pack)).unwrap(),
                mkit_core::hash::hash(raw.as_bytes())
            );
            for (kind, body) in [
                (
                    0,
                    crate::stored_golden::fixture("takedown-inventory-Entry-0.json"),
                ),
                (
                    1,
                    crate::stored_golden::fixture("takedown-inventory-Entry-1.json"),
                ),
                (
                    2,
                    crate::stored_golden::fixture("takedown-inventory-Entry-2.json"),
                ),
                (
                    3,
                    crate::stored_golden::fixture("takedown-inventory-Entry-3.json"),
                ),
                (
                    4,
                    crate::stored_golden::fixture("takedown-inventory-Entry-4.json"),
                ),
                (
                    5,
                    crate::stored_golden::fixture("takedown-inventory-Entry-5.json"),
                ),
                (
                    7,
                    crate::stored_golden::fixture("takedown-inventory-Entry-7.json"),
                ),
            ] {
                let id = [kind; 32];
                let raw = Value::new(body.to_vec());
                block_on(store.apply(
                    &content_shard(&pack),
                    Batch::new().put(entry_key(&pack, &id), raw.clone()).put(
                        marker_key(&pack, &id),
                        Value::new(entry_digest(&id, &raw).to_vec()),
                    ),
                ))
                .unwrap();
                assert_eq!(
                    block_on(entry(&store, &pack, &id)).unwrap().unwrap().kind,
                    kind
                );
            }
        }
    };
    (takedown_source) => {
        use super::*;
        #[test]
        fn v050_stored_encodings() {
            let _ = crate::stored_golden::json_fixture!(Checkpoint, "takedown-source-Checkpoint");
            let _ = crate::stored_golden::json_fixture!(Frame, "takedown-source-Frame");
            let _ = crate::stored_golden::json_fixture!(Lookup, "takedown-source-Lookup");
        }
        #[test]
        fn v050_binary_rows() {
            use crate::stored_golden::hex_fixture;
            let expected = hex_fixture!("preservation-source-frame");
            let (id, located) = decode_frame(&expected).unwrap();
            let row = Frame {
                id,
                pack: located.pack,
                index: codec::encode_object_index(&id, &located.value)
                    .unwrap()
                    .as_bytes()
                    .to_vec(),
            };
            assert_eq!(row.encode_row().unwrap(), expected);
        }
    };
    (takedown_work) => {
        use super::*;
        #[test]
        fn v050_stored_encodings() {
            let _ = crate::stored_golden::json_fixture!(ObjectInfo, "takedown-work-ObjectInfo");
            let _ = crate::stored_golden::json_fixture!(Phase, "takedown-work-Phase-Acquire");
            let _ = crate::stored_golden::json_fixture!(Phase, "takedown-work-Phase-Closure");
            let _ = crate::stored_golden::json_fixture!(Phase, "takedown-work-Phase-Discover");
            let _ = crate::stored_golden::json_fixture!(Phase, "takedown-work-Phase-Purged");
            let _ = crate::stored_golden::json_fixture!(Phase, "takedown-work-Phase-Purging");
            let _ = crate::stored_golden::json_fixture!(Phase, "takedown-work-Phase-Retain");
            let _ = crate::stored_golden::json_fixture!(Phase, "takedown-work-Phase-Seed");
            let _ = crate::stored_golden::json_fixture!(State, "takedown-work-State");
            let _ = crate::stored_golden::json_fixture!(
                Verification,
                "takedown-work-Verification-CanonicalPending"
            );
            let _ = crate::stored_golden::json_fixture!(
                Verification,
                "takedown-work-Verification-ManifestClosurePending"
            );
            let _ = crate::stored_golden::json_fixture!(
                Verification,
                "takedown-work-Verification-SourceCorrupt"
            );
            let _ = crate::stored_golden::json_fixture!(
                Verification,
                "takedown-work-Verification-Verified"
            );
        }
    };
    (timers_outcome_delivery) => {
        use super::*;
        #[test]
        fn v050_binary_rows() {
            use crate::stored_golden::hex_fixture;
            let expected = hex_fixture!("outcome-timer");
            let (attempt, cursor) = decode_timer(&expected).unwrap();
            assert_eq!(attempt, 2);
            assert_eq!(encode_timer(attempt, cursor.as_ref()).unwrap(), expected);
            assert_eq!(
                decode_timer(&hex_fixture!("outcome-timer-start")).unwrap(),
                (0, None)
            );
        }
    };
    (timers_publication_recheck) => {
        use super::*;
        #[test]
        fn v050_binary_rows() {
            use crate::stored_golden::hex_fixture;
            let expected = hex_fixture!("publication-recheck");
            let row = Progress::decode(&expected).unwrap();
            assert_eq!(row.position, 2);
            assert_eq!(row.encode(), expected);
        }
    };
}
pub(crate) use tests;
