//! The wire cases, the per-case context and the helpers they share.
//!
//! Every case talks to the server only through [`Ctx`]'s client, names its
//! refs under `refs/heads/conformance/<run_id>/<case>/`, and asserts Connect
//! codes and typed outcomes, never message text or chunk counts.

use std::sync::{Arc, Mutex, PoisonError};

use buffa::Message;
use futures::future::BoxFuture;
use mkit_core::hash::{hash, to_hex};
use mkit_transport_connect::generated::__buffa::oneof::download_pack_response::Body as DownloadBody;
use mkit_transport_connect::generated::__buffa::oneof::upload_pack_request::Body as UploadBody;
use mkit_transport_connect::generated::{
    AdvanceOutcome, AdvanceRefsRequest, AdvanceRefsResponse, DownloadPackRequest,
    DownloadPackResponse, ListRefsRequest, ListRefsResponse, PackChunk, PackExistsRequest,
    PackExistsResponse, ReadRefRequest, ReadRefResponse, RefExpectation, UpdateRefRequest,
    UpdateRefResponse, UploadPackHeader, UploadPackRequest, UploadPackResponse,
};

use super::client::{Client, Rpc, RpcError, StreamReply, frame, frames};
use super::profile::{Feature, Milestone, Profile, WireAuth, random_bytes};
use super::sign::{Envelope, Signer, body_commitment};

mod advance;
mod auth;
mod auth_bounds;
mod concurrent;
mod download;
mod growth;
mod health;
mod list;
mod packs;
mod quota;
mod refs;
mod replay;
mod upload;

/// Why a case did not pass.
#[derive(Debug)]
pub(crate) enum Failure {
    /// An assertion failed or the server broke the protocol.
    Fail(String),
    /// The profile cannot exercise the case.
    Skip(String),
}

impl From<String> for Failure {
    fn from(msg: String) -> Self {
        Self::Fail(msg)
    }
}

impl From<&str> for Failure {
    fn from(msg: &str) -> Self {
        Self::Fail(msg.to_owned())
    }
}

/// A case's result.
pub(crate) type CaseResult = Result<(), Failure>;

/// Fail the case with a formatted message unless `cond` holds.
macro_rules! ensure {
    ($cond:expr, $($msg:tt)+) => {
        if !$cond {
            return Err($crate::wire::cases::Failure::Fail(format!($($msg)+)));
        }
    };
}
pub(crate) use ensure;

/// One wire case: a stable name, the milestone it belongs to and the
/// features it needs (`requires`) or cannot run with (`excludes`).
#[derive(Clone, Copy)]
pub struct Case {
    /// Stable name, `<group>.<case>`.
    pub name: &'static str,
    /// The milestone that introduced it.
    pub milestone: Milestone,
    /// Every feature the server must offer.
    pub requires: &'static [Feature],
    /// Features that make the case inapplicable.
    pub excludes: &'static [Feature],
    run: fn(Ctx) -> BoxFuture<'static, CaseResult>,
}

impl std::fmt::Debug for Case {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Case")
            .field("name", &self.name)
            .field("milestone", &self.milestone)
            .field("requires", &self.requires)
            .field("excludes", &self.excludes)
            .finish_non_exhaustive()
    }
}

impl Case {
    /// Why `profile` cannot run this case, if it cannot.
    #[must_use]
    pub fn skip_reason(&self, profile: &Profile) -> Option<String> {
        if self.milestone > profile.milestone {
            return Some(format!(
                "milestone {:?} is above the profile's {:?}",
                self.milestone, profile.milestone
            ));
        }
        let missing: Vec<_> = self
            .requires
            .iter()
            .filter(|f| !profile.has(**f))
            .map(|f| f.as_str())
            .collect();
        if !missing.is_empty() {
            return Some(format!("requires feature {}", missing.join(", ")));
        }
        let present: Vec<_> = self
            .excludes
            .iter()
            .filter(|f| profile.has(**f))
            .map(|f| f.as_str())
            .collect();
        if !present.is_empty() {
            return Some(format!(
                "not applicable with feature {}",
                present.join(", ")
            ));
        }
        None
    }

    pub(crate) fn run(&self, ctx: Ctx) -> BoxFuture<'static, CaseResult> {
        (self.run)(ctx)
    }
}

/// Declares the case table: `name => function, milestone, [requires], [excludes];`.
macro_rules! cases {
    ($($name:literal => $f:path, $m:ident, [$($req:ident),*], [$($ex:ident),*];)*) => {
        /// Every wire case, in run order.
        pub static CASES: &[Case] = &[$(Case {
            name: $name,
            milestone: Milestone::$m,
            requires: &[$(Feature::$req),*],
            excludes: &[$(Feature::$ex),*],
            run: |ctx| Box::pin($f(ctx)),
        }),*];
    };
}

cases! {
    "refs.read_missing" => refs::read_missing, M0, [], [];
    "refs.update_any_then_read" => refs::update_any_then_read, M0, [], [];
    "refs.update_missing_conflict_failed_precondition" => refs::update_missing_conflict, M0, [], [];
    "refs.update_match_conflict_failed_precondition" => refs::update_match_conflict, M0, [], [];
    "refs.update_unspecified_invalid_argument" => refs::update_unspecified, M0, [], [];
    "refs.update_any_with_expected_id_invalid_argument" => refs::update_any_with_expected_id, M0, [], [];
    "refs.invalid_ref_name_invalid_argument" => refs::invalid_ref_name, M0, [], [];
    "refs.name_over_512_bytes_invalid_argument" => refs::name_over_512_bytes, M0, [], [];
    "refs.non_refs_prefix_rejected" => refs::non_refs_prefix_rejected, M0, [], [];
    "refs.new_id_wrong_length_invalid_argument" => refs::new_id_wrong_length, M0, [], [];
    "refs.list_prefix_stripped" => refs::list_prefix_stripped, M0, [], [];
    "refs.list_prefix_component_boundary" => refs::list_prefix_component_boundary, M0, [], [];
    "refs.list_invalid_prefix_invalid_argument" => refs::list_invalid_prefix, M0, [], [];
    "refs.concurrent_missing_one_winner" => concurrent::missing_one_winner, M0, [], [];
    "refs.concurrent_match_one_winner" => concurrent::match_one_winner, M0, [], [];
    "advance.committed" => advance::committed, M0, [], [];
    "advance.head_conflict_typed" => advance::head_conflict_typed, M0, [], [];
    "advance.packmap_conflict_typed" => advance::packmap_conflict_typed, M0, [], [];
    "advance.atomic_both_untouched" => advance::atomic_both_untouched, M0, [AtomicAdvance], [];
    "advance.nonatomic_packmap_first" => advance::nonatomic_packmap_first, M0, [], [AtomicAdvance];
    "advance.unspecified_invalid_argument" => advance::unspecified_invalid_argument, M0, [], [];
    "advance.concurrent_one_committed" => concurrent::advance_one_committed, M0, [], [];
    "packs.exists_false_then_true" => packs::exists_false_then_true, M0, [], [];
    "packs.pack_id_wrong_length_invalid_argument" => packs::pack_id_wrong_length, M0, [], [];
    "upload.roundtrip_multi_chunk" => upload::roundtrip_multi_chunk, M0, [], [];
    "upload.empty_pack" => upload::empty_pack, M0, [], [];
    "upload.first_not_header_invalid_argument" => upload::first_not_header, M0, [], [];
    "upload.second_header_invalid_argument" => upload::second_header, M0, [], [];
    "upload.empty_message_invalid_argument" => upload::empty_message, M0, [], [];
    "upload.chunk_pack_id_mismatch_invalid_argument" => upload::chunk_pack_id_mismatch, M0, [], [];
    "upload.offset_gap_invalid_argument" => upload::offset_gap, M0, [], [];
    "upload.overrun_invalid_argument" => upload::overrun, M0, [], [];
    "upload.no_last_invalid_argument" => upload::no_last, M0, [], [];
    "upload.declared_mismatch_invalid_argument" => upload::declared_mismatch, M0, [], [];
    "upload.hash_mismatch_not_stored" => upload::hash_mismatch_not_stored, M0, [], [];
    "upload.oversize_resource_exhausted" => upload::oversize, M0, [], [];
    "upload.rejected_never_overwrites_existing" => upload::rejected_never_overwrites, M0, [], [];
    "download.not_found_before_any_message" => download::not_found_before_any_message, M0, [], [];
    "download.chunks_contiguous_ending_last" => download::chunks_contiguous_ending_last, M0, [], [];
    "health.serving" => health::serving, M0, [Health], [];
    "health.unknown_service_not_found" => health::unknown_service_not_found, M0, [Health], [];
    "auth.bearer_missing_unauthenticated" => auth::bearer_missing, M0, [Bearer], [];
    "auth.bearer_wrong_unauthenticated" => auth::bearer_wrong, M0, [Bearer], [];
    "auth.bearer_applies_to_streaming" => auth::bearer_streaming, M0, [Bearer], [];
    "auth.v2_missing_headers_unauthenticated" => auth::v2_missing_headers, M0, [AuthV2], [];
    "auth.v2_wrong_audience" => auth::v2_wrong_audience, M0, [AuthV2], [];
    "auth.v2_wrong_repository" => auth::v2_wrong_repository, M0, [AuthV2], [];
    "auth.v2_wrong_procedure" => auth::v2_wrong_procedure, M0, [AuthV2], [];
    "auth.v2_bad_signature" => auth::v2_bad_signature, M0, [AuthV2], [];
    "auth.v2_body_digest_mismatch" => auth::v2_body_digest_mismatch, M0, [AuthV2], [];
    "auth.v2_expired" => auth::v2_expired, M0, [AuthV2], [];
    "auth.v2_version_not_2" => auth::v2_version_not_2, M0, [AuthV2], [];
    "auth.v2_nonce_not_canonical" => auth_bounds::v2_nonce_not_canonical, M0, [AuthV2], [];
    "auth.v2_signature_not_strict" => auth_bounds::v2_signature_not_strict, M0, [AuthV2], [];
    "auth.v2_clock_lead_bound" => auth_bounds::v2_clock_lead_bound, M0, [AuthV2], [];
    "auth.v2_pack_commitment_mismatch" => auth::v2_pack_commitment_mismatch, M0, [AuthV2], [];
    "auth.v2_gzip_signed_fails_closed" => auth::v2_gzip_signed_fails_closed, M0, [AuthV2, StrictGzipAuth], [];
    "auth.v2_reads_unsigned_ok" => auth::v2_reads_unsigned_ok, M0, [AuthV2], [];
    "replay.same_op_returns_saved_result_after_ref_moved" => replay::same_op_after_ref_moved, M0, [AuthV2, Replay], [];
    "replay.concurrent_duplicates_all_succeed" => replay::concurrent_duplicates, M0, [AuthV2, Replay], [];
    "replay.nonce_reuse_different_op_invalid_argument" => replay::nonce_reuse_different_op, M0, [AuthV2, Replay], [];
    "replay.conflict_result_replayed" => replay::conflict_result_replayed, M0, [AuthV2, Replay], [];
    "replay.advance_replay_equals_first_result" => replay::advance_replay_equals_first, M0, [AuthV2, Replay], [];
    "replay.upload_replay_succeeds" => replay::upload_replay_succeeds, M0, [AuthV2, Replay], [];
    "replay.expired_retry_rejected" => replay::expired_retry_rejected, M0, [AuthV2, Replay, TestFaults], [];
    "quota.ops_exhaustion_resource_exhausted" => quota::ops_exhaustion, M0, [AuthV2, Quota], [];
    "quota.bytes_exhaustion_resource_exhausted" => quota::bytes_exhaustion, M0, [AuthV2, Quota], [];
    "quota.exhaustion_allocates_no_replay" => quota::exhaustion_allocates_no_replay, M0, [AuthV2, Replay, Quota], [];
    "quota.replay_not_charged" => quota::replay_not_charged, M0, [AuthV2, Replay, Quota], [];
    "growth.replay_and_quota_pruned" => growth::replay_and_quota_pruned, M0, [AuthV2, Replay, Quota, TestFaults], [];
    "list.large_response_within_limit" => list::large_response_within_limit, M0, [], [];
}

/// The context one case runs in.
#[derive(Clone)]
pub(crate) struct Ctx {
    client: Client,
    profile: Arc<Profile>,
    case: &'static str,
    note: Arc<Mutex<Option<String>>>,
}

/// A 32-byte id helper.
pub(crate) const A: [u8; 32] = [0xaa; 32];
pub(crate) const B: [u8; 32] = [0xbb; 32];
pub(crate) const C: [u8; 32] = [0xcc; 32];

/// `(expectation, expected_id)` of a ref update.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Exp<'a> {
    /// Leave `expectation` unset.
    Unset,
    Any,
    Missing,
    Match(&'a [u8]),
    /// A raw expectation with an explicit `expected_id`.
    Raw(RefExpectation, &'a [u8]),
}

impl Exp<'_> {
    fn wire(self) -> (Option<buffa::EnumValue<RefExpectation>>, Option<Vec<u8>>) {
        match self {
            Self::Unset => (None, None),
            Self::Any => (Some(RefExpectation::REF_EXPECTATION_ANY.into()), None),
            Self::Missing => (Some(RefExpectation::REF_EXPECTATION_MISSING.into()), None),
            Self::Match(id) => (
                Some(RefExpectation::REF_EXPECTATION_MATCH.into()),
                Some(id.to_vec()),
            ),
            Self::Raw(e, id) => (Some(e.into()), Some(id.to_vec())),
        }
    }
}

/// An `UpdateRefRequest`.
pub(crate) fn update_req(name: &str, exp: Exp<'_>, new: &[u8]) -> UpdateRefRequest {
    let (expectation, expected_id) = exp.wire();
    UpdateRefRequest {
        name: Some(name.to_owned()),
        expectation,
        expected_id,
        new_id: Some(new.to_vec()),
        ..Default::default()
    }
}

/// An `AdvanceRefsRequest`.
pub(crate) fn advance_req(
    (head, head_exp, head_new): (&str, Exp<'_>, &[u8]),
    (packmap, packmap_exp, packmap_new): (&str, Exp<'_>, &[u8]),
) -> AdvanceRefsRequest {
    let (head_expectation, head_expected_id) = head_exp.wire();
    let (packmap_expectation, packmap_expected_id) = packmap_exp.wire();
    AdvanceRefsRequest {
        head_ref: Some(head.to_owned()),
        head_expectation,
        head_expected_id,
        head_new_id: Some(head_new.to_vec()),
        packmap_ref: Some(packmap.to_owned()),
        packmap_expectation,
        packmap_expected_id,
        packmap_new_id: Some(packmap_new.to_vec()),
        ..Default::default()
    }
}

/// The `UploadPack` header message.
pub(crate) fn header_msg(id: &[u8], total: u64) -> UploadPackRequest {
    UploadPackRequest {
        body: Some(UploadBody::Header(Box::new(UploadPackHeader {
            pack_id: Some(id.to_vec()),
            total_bytes: Some(total),
            ..Default::default()
        }))),
        ..Default::default()
    }
}

/// An `UploadPack` chunk message.
pub(crate) fn chunk_msg(id: &[u8], offset: u64, data: &[u8], last: bool) -> UploadPackRequest {
    UploadPackRequest {
        body: Some(UploadBody::Chunk(Box::new(PackChunk {
            pack_id: Some(id.to_vec()),
            offset: Some(offset),
            data: Some(data.to_vec()),
            last: Some(last),
            ..Default::default()
        }))),
        ..Default::default()
    }
}

/// A well-formed upload of `pack` in `parts` roughly equal chunks (at least
/// one, the last flagged).
pub(crate) fn upload_msgs(pack: &[u8], parts: usize) -> Vec<UploadPackRequest> {
    let id = hash(pack);
    let mut msgs = vec![header_msg(&id, pack.len() as u64)];
    if pack.is_empty() {
        msgs.push(chunk_msg(&id, 0, &[], true));
        return msgs;
    }
    let size = pack.len().div_ceil(parts.max(1));
    let pieces: Vec<_> = pack.chunks(size).collect();
    let mut offset = 0u64;
    for (i, piece) in pieces.iter().enumerate() {
        msgs.push(chunk_msg(&id, offset, piece, i + 1 == pieces.len()));
        offset += piece.len() as u64;
    }
    msgs
}

/// `len` random bytes: a pack no other run has uploaded.
pub(crate) fn random_pack(len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        let block = random_bytes::<64>();
        let take = (len - out.len()).min(block.len());
        out.extend_from_slice(&block[..take]);
    }
    out
}

/// The `Ok` value, or a failure naming `what`.
pub(crate) fn want_ok<T>(result: Result<T, RpcError>, what: &str) -> Result<T, Failure> {
    result.map_err(|e| Failure::Fail(format!("{what}: expected ok, got {e}")))
}

/// The error, which must carry Connect code `code`.
pub(crate) fn want_code<T: std::fmt::Debug>(
    result: Result<T, RpcError>,
    code: &str,
    what: &str,
) -> Result<RpcError, Failure> {
    match result {
        Ok(v) => Err(Failure::Fail(format!(
            "{what}: expected {code}, got ok {v:?}"
        ))),
        Err(e) if e.code == code => Ok(e),
        Err(e) => Err(Failure::Fail(format!("{what}: expected {code}, got {e}"))),
    }
}

/// Which content an auth v2 signature commits to.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Commit<'a> {
    /// A unary body.
    Body(&'a [u8]),
    /// An upload: pack id and declared length.
    Pack(&'a [u8], u64),
}

/// A signed unary request: its exact body and headers, replayable byte for
/// byte, or tampered with before sending.
#[derive(Debug, Clone)]
pub(crate) struct Signed {
    pub(crate) rpc: Rpc,
    pub(crate) body: Vec<u8>,
    pub(crate) headers: Vec<(String, String)>,
    /// The `Idempotency-Key`.
    pub(crate) nonce: String,
}

impl Signed {
    /// Replace (or add) header `name`, keeping the signature.
    pub(crate) fn with_header(mut self, name: &str, value: impl Into<String>) -> Self {
        self.headers.retain(|(n, _)| n != name);
        self.headers.push((name.to_owned(), value.into()));
        self
    }

    /// The value of header `name`.
    pub(crate) fn header(&self, name: &str) -> &str {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map_or("", |(_, v)| v)
    }
}

/// Sign `msg` for `rpc` with `signer`: a fresh envelope over the exact
/// encoded bytes (`body:` commitment and `X-Digest`), which `edit` may
/// change first (dates, nonce, audience, ...).
pub(crate) fn sign_unary(
    signer: &Signer,
    rpc: Rpc,
    msg: &impl Message,
    edit: impl FnOnce(&mut Envelope),
) -> Signed {
    let body = msg.encode_to_vec();
    let mut env = signer.envelope(rpc.procedure(), body_commitment(&body));
    env.digest = Some(to_hex(&hash(&body)));
    edit(&mut env);
    let op = signer.sign(&env);
    Signed {
        rpc,
        body,
        headers: op.headers,
        nonce: op.nonce,
    }
}

impl Ctx {
    pub(crate) fn new(client: Client, profile: Arc<Profile>, case: &'static str) -> Self {
        Self {
            client,
            profile,
            case,
            note: Arc::default(),
        }
    }

    pub(crate) fn profile(&self) -> &Profile {
        &self.profile
    }

    pub(crate) fn client(&self) -> &Client {
        &self.client
    }

    /// Attach a note to a passing verdict (e.g. a measured size).
    pub(crate) fn set_note(&self, note: String) {
        *self.note.lock().unwrap_or_else(PoisonError::into_inner) = Some(note);
    }

    pub(crate) fn take_note(&self) -> Option<String> {
        self.note
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
    }

    /// `conformance/<run_id>/<case>`: this case's ref namespace.
    pub(crate) fn ns(&self) -> String {
        format!("conformance/{}/{}", self.profile.run_id, self.case)
    }

    /// `refs/heads/<ns>/<leaf>`.
    pub(crate) fn head(&self, leaf: &str) -> String {
        format!("refs/heads/{}/{leaf}", self.ns())
    }

    /// `refs/mkit/packmap/<ns>/<leaf>`: the packmap of [`Ctx::head`].
    pub(crate) fn packmap(&self, leaf: &str) -> String {
        format!("refs/mkit/packmap/{}/{leaf}", self.ns())
    }

    /// This case's signer `label` (derived from the profile seed, the run
    /// id and the case name), or `None` without auth v2.
    pub(crate) fn signer(&self, label: &str) -> Option<Signer> {
        let WireAuth::AuthV2 {
            audience,
            repository,
            seed,
        } = &self.profile.auth
        else {
            return None;
        };
        let label = format!("{}/{label}", self.case);
        Some(Signer::derive(
            seed,
            &self.profile.run_id,
            &label,
            audience,
            repository,
        ))
    }

    /// The signer, which the case's requirements guarantee exists.
    pub(crate) fn v2_signer(&self, label: &str) -> Result<Signer, Failure> {
        self.signer(label)
            .ok_or_else(|| Failure::Skip("needs an auth v2 profile".to_owned()))
    }

    /// The headers the profile's auth mode puts on `rpc`: none; the bearer
    /// token; or, for an auth v2 write, a fresh signature by signer
    /// `"main"` over `commit`. Reads are signed only with
    /// [`Profile::sign_reads`] (M2).
    pub(crate) fn auth_headers(&self, rpc: Rpc, commit: Commit<'_>) -> Vec<(String, String)> {
        self.auth_headers_as("main", rpc, commit)
    }

    /// [`Ctx::auth_headers`], signing (under auth v2) as signer `label`.
    pub(crate) fn auth_headers_as(
        &self,
        label: &str,
        rpc: Rpc,
        commit: Commit<'_>,
    ) -> Vec<(String, String)> {
        if let WireAuth::Bearer { token } = &self.profile.auth {
            return vec![("authorization".to_owned(), format!("Bearer {token}"))];
        }
        // `None` without auth v2.
        let sign = rpc.is_write() || self.profile.sign_reads;
        let signer = self.signer(label).filter(|_| sign);
        signer.map_or_else(Vec::new, |signer| {
            let op = match commit {
                Commit::Body(body) => signer.sign_body(rpc.procedure(), body),
                Commit::Pack(id, len) => signer.sign_pack(rpc.procedure(), id, len),
            };
            op.headers
        })
    }

    /// A unary call of `req`, authenticated as the profile says.
    pub(crate) async fn call<M: Message>(
        &self,
        rpc: Rpc,
        req: &impl Message,
    ) -> Result<Result<M, RpcError>, String> {
        self.call_as("main", rpc, req).await
    }

    /// [`Ctx::call`] as signer `label` (distinct signers keep concurrent
    /// writes clear of per-signer quotas).
    pub(crate) async fn call_as<M: Message>(
        &self,
        label: &str,
        rpc: Rpc,
        req: &impl Message,
    ) -> Result<Result<M, RpcError>, String> {
        let body = req.encode_to_vec();
        let headers = self.auth_headers_as(label, rpc, Commit::Body(&body));
        self.client.unary(rpc, body, &headers).await
    }

    /// Send a [`Signed`] request as it stands.
    pub(crate) async fn send<M: Message>(&self, s: &Signed) -> Result<Result<M, RpcError>, String> {
        self.client.unary(s.rpc, s.body.clone(), &s.headers).await
    }

    /// `ReadRef(name)`: `Some(id)` or `None`, checking the absent shape.
    pub(crate) async fn read(&self, name: &str) -> Result<Option<Vec<u8>>, Failure> {
        let req = ReadRefRequest {
            name: Some(name.to_owned()),
            ..Default::default()
        };
        let resp: ReadRefResponse = want_ok(self.call(Rpc::ReadRef, &req).await?, "ReadRef")?;
        let id = resp.object_id.unwrap_or_default();
        if resp.exists == Some(true) {
            ensure!(
                id.len() == 32,
                "ReadRef: exists with a {}-byte id",
                id.len()
            );
            Ok(Some(id))
        } else {
            ensure!(
                id.is_empty(),
                "ReadRef: absent ref with a non-empty object_id"
            );
            Ok(None)
        }
    }

    /// Fail unless ref `name` holds `want` (`None`: absent).
    pub(crate) async fn expect_ref(&self, name: &str, want: Option<&[u8]>) -> CaseResult {
        let got = self.read(name).await?;
        ensure!(
            got.as_deref() == want,
            "{name}: expected {}, found {}",
            show(want),
            show(got.as_deref())
        );
        Ok(())
    }

    /// `UpdateRef`.
    pub(crate) async fn update(
        &self,
        name: &str,
        exp: Exp<'_>,
        new: &[u8],
    ) -> Result<Result<UpdateRefResponse, RpcError>, String> {
        self.call(Rpc::UpdateRef, &update_req(name, exp, new)).await
    }

    /// `UpdateRef` that must succeed.
    pub(crate) async fn set(&self, name: &str, exp: Exp<'_>, new: &[u8]) -> CaseResult {
        want_ok(self.update(name, exp, new).await?, "UpdateRef")?;
        Ok(())
    }

    /// `AdvanceRefs`: its outcome (as the wire number) or error.
    pub(crate) async fn advance(
        &self,
        req: &AdvanceRefsRequest,
    ) -> Result<Result<i32, RpcError>, String> {
        let resp: Result<AdvanceRefsResponse, RpcError> = self.call(Rpc::AdvanceRefs, req).await?;
        Ok(resp.map(|r| r.outcome.map_or(0, |o| o.to_i32())))
    }

    /// `ListRefs(prefix)`: `(name, id)` pairs as returned.
    pub(crate) async fn list(
        &self,
        prefix: &str,
    ) -> Result<Result<Vec<(String, Vec<u8>)>, RpcError>, String> {
        let req = ListRefsRequest {
            prefix: Some(prefix.to_owned()),
            ..Default::default()
        };
        let resp: Result<ListRefsResponse, RpcError> = self.call(Rpc::ListRefs, &req).await?;
        Ok(resp.map(|r| {
            r.refs
                .into_iter()
                .map(|e| (e.name.unwrap_or_default(), e.object_id.unwrap_or_default()))
                .collect()
        }))
    }

    /// `PackExists(id)`.
    pub(crate) async fn exists(&self, id: &[u8]) -> Result<Result<bool, RpcError>, String> {
        let req = PackExistsRequest {
            pack_id: Some(id.to_vec()),
            ..Default::default()
        };
        let resp: Result<PackExistsResponse, RpcError> = self.call(Rpc::PackExists, &req).await?;
        Ok(resp.map(|r| r.exists == Some(true)))
    }

    /// Fail unless `PackExists(id)` answers `want`.
    pub(crate) async fn expect_exists(&self, id: &[u8], want: bool) -> CaseResult {
        let got = want_ok(self.exists(id).await?, "PackExists")?;
        ensure!(got == want, "PackExists: expected {want}, got {got}");
        Ok(())
    }

    /// `UploadPack` of `msgs`, authenticated for `commit` (`(id, len)`).
    /// `Ok(None)` on success.
    pub(crate) async fn upload_with(
        &self,
        msgs: &[UploadPackRequest],
        headers: &[(String, String)],
    ) -> Result<Option<RpcError>, Failure> {
        let reply: StreamReply<UploadPackResponse> = self
            .client
            .stream(Rpc::UploadPack, frames(msgs), headers)
            .await?;
        if let Some(e) = reply.error {
            ensure!(
                reply.messages.is_empty(),
                "UploadPack: a response message and an error ({e})"
            );
            return Ok(Some(e));
        }
        ensure!(
            reply.messages.len() == 1,
            "UploadPack: {} response messages on success, want 1",
            reply.messages.len()
        );
        Ok(None)
    }

    /// `UploadPack` of `msgs`, signed (under auth v2) for `(id, len)`.
    pub(crate) async fn upload(
        &self,
        msgs: &[UploadPackRequest],
        commit: (&[u8], u64),
    ) -> Result<Option<RpcError>, Failure> {
        let headers = self.auth_headers(Rpc::UploadPack, Commit::Pack(commit.0, commit.1));
        self.upload_with(msgs, &headers).await
    }

    /// Upload `pack` in three chunks; it must succeed.
    pub(crate) async fn put_pack(&self, pack: &[u8]) -> CaseResult {
        let id = hash(pack);
        if let Some(e) = self
            .upload(&upload_msgs(pack, 3), (&id, pack.len() as u64))
            .await?
        {
            return Err(Failure::Fail(format!("UploadPack: expected ok, got {e}")));
        }
        Ok(())
    }

    /// Upload `msgs` for `(id, len)`; it must fail with `code`.
    pub(crate) async fn upload_rejected(
        &self,
        msgs: &[UploadPackRequest],
        commit: (&[u8], u64),
        code: &str,
    ) -> CaseResult {
        match self.upload(msgs, commit).await? {
            None => Err(Failure::Fail(format!(
                "UploadPack: expected {code}, got ok"
            ))),
            Some(e) if e.code == code => Ok(()),
            Some(e) => Err(Failure::Fail(format!(
                "UploadPack: expected {code}, got {e}"
            ))),
        }
    }

    /// `DownloadPack(id)` as received.
    pub(crate) async fn download(
        &self,
        id: &[u8],
    ) -> Result<StreamReply<DownloadPackResponse>, Failure> {
        let (body, headers) = self.download_call(id);
        Ok(self
            .client
            .stream(Rpc::DownloadPack, body, &headers)
            .await?)
    }

    /// A `DownloadPack(id)` request body (one framed message) and its
    /// headers. A signed read commits to that exact body, envelope
    /// included (SPEC-WRITE-GRANTS §9.2).
    fn download_call(&self, id: &[u8]) -> (Vec<u8>, Vec<(String, String)>) {
        let req = DownloadPackRequest {
            pack_id: Some(id.to_vec()),
            ..Default::default()
        };
        let body = frame(&req.encode_to_vec());
        let headers = self.auth_headers(Rpc::DownloadPack, Commit::Body(&body));
        (body, headers)
    }

    /// Download pack `id` and check the §6.2 shape: one header, then chunks
    /// for `id` at contiguous offsets from 0, `last` exactly on the final
    /// one, the declared total. Returns the bytes.
    pub(crate) async fn fetch(&self, id: &[u8]) -> Result<Vec<u8>, Failure> {
        let reply = self.download(id).await?;
        if let Some(e) = reply.error {
            return Err(Failure::Fail(format!("DownloadPack: expected ok, got {e}")));
        }
        let mut messages = reply.messages.into_iter().map(|m| m.body);
        let total = match messages.next() {
            Some(Some(DownloadBody::Header(h))) => h.total_bytes.unwrap_or(0),
            other => {
                return Err(Failure::Fail(format!(
                    "DownloadPack: first message is not a header: {other:?}"
                )));
            }
        };
        let (mut bytes, mut saw_last) = (Vec::new(), false);
        for body in messages {
            ensure!(!saw_last, "DownloadPack: a message after the `last` chunk");
            let Some(DownloadBody::Chunk(chunk)) = body else {
                return Err(Failure::Fail(
                    "DownloadPack: a non-chunk message after the header".to_owned(),
                ));
            };
            ensure!(
                chunk.pack_id.as_deref() == Some(id),
                "DownloadPack: chunk.pack_id differs from the requested id"
            );
            ensure!(
                chunk.offset.unwrap_or(0) == bytes.len() as u64,
                "DownloadPack: chunk at offset {:?}, expected {}",
                chunk.offset,
                bytes.len()
            );
            bytes.extend_from_slice(chunk.data.as_deref().unwrap_or_default());
            saw_last = chunk.last == Some(true);
        }
        ensure!(
            saw_last,
            "DownloadPack: the stream ended without a `last` chunk"
        );
        ensure!(
            bytes.len() as u64 == total,
            "DownloadPack: header declared {total} bytes, chunks carried {}",
            bytes.len()
        );
        ensure!(
            hash(&bytes).as_slice() == id,
            "DownloadPack: BLAKE3 of the bytes differs from the pack id"
        );
        Ok(bytes)
    }
}

/// An id as short hex, or `absent`.
pub(crate) fn show(id: Option<&[u8]>) -> String {
    id.map_or_else(
        || "absent".to_owned(),
        |id| {
            let hex = mkit_core::hash::to_hex_bytes(id);
            hex.chars().take(12).collect()
        },
    )
}

/// The outcome name of a wire `AdvanceOutcome` number.
pub(crate) fn outcome_name(n: i32) -> &'static str {
    match n {
        n if n == AdvanceOutcome::ADVANCE_OUTCOME_COMMITTED as i32 => "COMMITTED",
        n if n == AdvanceOutcome::ADVANCE_OUTCOME_HEAD_CONFLICT as i32 => "HEAD_CONFLICT",
        n if n == AdvanceOutcome::ADVANCE_OUTCOME_PACKMAP_CONFLICT as i32 => "PACKMAP_CONFLICT",
        _ => "UNSPECIFIED/unknown",
    }
}

/// Fail unless `got` is the outcome `want`.
pub(crate) fn want_outcome(got: Result<i32, RpcError>, want: AdvanceOutcome) -> CaseResult {
    let got = want_ok(got, "AdvanceRefs")?;
    ensure!(
        got == want as i32,
        "AdvanceRefs: expected {}, got {}",
        outcome_name(want as i32),
        outcome_name(got)
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_download_commits_to_the_framed_request() {
        let mut profile = Profile::new(WireAuth::AuthV2 {
            audience: "https://a.test".into(),
            repository: "r".into(),
            seed: [1; 32],
        });
        profile.sign_reads = true;
        let client = Client::new(&"https://a.test".parse().unwrap()).unwrap();
        let ctx = Ctx::new(client, Arc::new(profile), "unit");
        let (body, headers) = ctx.download_call(&[7; 32]);
        let req = DownloadPackRequest {
            pack_id: Some(vec![7; 32]),
            ..Default::default()
        };
        assert_eq!(body, frame(&req.encode_to_vec()));
        let get = |name: &str| {
            headers
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.clone())
        };
        assert_eq!(get("x-content-commitment"), Some(body_commitment(&body)));
        assert_eq!(get("x-digest"), Some(to_hex(&hash(&body))));
    }
}
