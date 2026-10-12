//! Public typed per-RPC calls.
//!
//! Every call sends one request and returns. None calls [`Clock::wait`]: a
//! pending verification, membership lag, `Retry-After` hint or admission
//! challenge comes back as a typed [`Error`] the caller schedules. A signed
//! call returns the [`Identity`] it used, or uses the one the caller passes
//! exactly, so a persisted identity replays the same signed request after a
//! restart.

use crate::calls;
use crate::connect::{
    Clock, Destination, Error, HttpTransport, Identity, LIST_REFS_LIMIT, Opts, Reply, Rpc, Signer,
};
use crate::proto::{
    AdvanceRefsRequest, AdvanceRefsResponse, BeginUploadResponse, CompleteUploadResponse,
    GetServerInfoResponse, ListRefsRequest, ListRefsResponse, PackExistsRequest,
    PackExistsResponse, ReadRefRequest, ReadRefResponse, RefRedaction, UpdateRefResponse,
    UploadPackResponse, UploadPartResponse, UploadTicket,
};
use crate::seams::{NoObserver, Observer, WriteIntent, procedures};
use mkit_core::{
    hash::Hash, refs::RefWriteCondition, upload_parts::PartPlan, write_auth::ContentCommitment,
};

/// The signer type of an anonymous client. It has no values.
#[derive(Clone, Copy, Debug)]
pub enum NoSigner {}
impl Signer for NoSigner {
    fn public_key(&self) -> [u8; 32] {
        match *self {}
    }
    async fn sign(&self, _: &Hash) -> Result<[u8; 64], String> {
        match *self {}
    }
}

/// The clock type of an anonymous client. It has no values.
#[derive(Clone, Copy, Debug)]
pub enum NoClock {}
impl Clock for NoClock {
    fn now_ms(&self) -> i64 {
        match *self {}
    }
    fn nonce(&self) -> Result<Hash, String> {
        match *self {}
    }
    async fn wait(&self, _: std::time::Duration) {
        match *self {}
    }
}

/// A repository's visibility.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Visibility {
    Public,
    Private,
}

/// A ref from a listing.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct NamedRef {
    pub name: String,
    pub id: Hash,
}

/// One `ListRefs` page.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct RefPage {
    /// Names have the requested prefix stripped (SPEC-REFS §4).
    pub refs: Vec<NamedRef>,
    /// `None` ends the listing.
    pub next_page_token: Option<String>,
    /// Active takedown notices for visible refs on this page.
    pub redactions: Vec<RefRedaction>,
}

/// A protocol client for one repository on one server.
///
/// [`Client::anonymous`] sends unsigned reads. [`Client::signed`] signs every
/// RPC except discovery, as the spec requires of a client that has a signer
/// (SPEC-TRANSPORT-CONNECT §7.1). Writes need a signed client.
///
/// [`Client::with_observer`] adds host policy that runs before every write is
/// signed or sent (see "Host policy seams" in the crate README).
pub struct Client<'a, T, S = NoSigner, C = NoClock, O = NoObserver> {
    transport: &'a T,
    destination: Destination,
    auth: Option<(&'a S, &'a C)>,
    observer: &'a O,
}

impl<T, S, C, O> std::fmt::Debug for Client<'_, T, S, C, O> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("destination", &self.destination)
            .field("signed", &self.auth.is_some())
            .finish_non_exhaustive()
    }
}

impl<'a, T: HttpTransport> Client<'a, T> {
    /// A client that signs nothing.
    #[must_use]
    pub fn anonymous(transport: &'a T, destination: Destination) -> Self {
        Self {
            transport,
            destination,
            auth: None,
            observer: &NoObserver,
        }
    }
}

fn reply<R>(result: Result<(R, Option<Identity>), Error>) -> Result<Reply<R>, Error> {
    result
        .map(|(value, identity)| Reply { value, identity })
        .map_err(Error::typed)
}

fn id32(bytes: Option<&[u8]>, what: &'static str) -> Result<Hash, Error> {
    bytes
        .ok_or(Error::Invalid(what))?
        .try_into()
        .map_err(|_| Error::Invalid(what))
}

impl<'a, T: HttpTransport, S: Signer, C: Clock> Client<'a, T, S, C> {
    /// A client that signs every RPC except `GetServerInfo`.
    #[must_use]
    pub fn signed(transport: &'a T, destination: Destination, signer: &'a S, clock: &'a C) -> Self {
        Self {
            transport,
            destination,
            auth: Some((signer, clock)),
            observer: &NoObserver,
        }
    }
}

impl<'a, T, S, C, O> Client<'a, T, S, C, O> {
    /// Run `observer` before every write RPC this client sends: it can veto the
    /// write and add per-attempt headers. Order: observer, signer, deadline
    /// check, dispatch.
    #[must_use]
    pub fn with_observer<P: Observer>(self, observer: &'a P) -> Client<'a, T, S, C, P> {
        Client {
            transport: self.transport,
            destination: self.destination,
            auth: self.auth,
            observer,
        }
    }
}

impl<T: HttpTransport, S: Signer, C: Clock, O: Observer> Client<'_, T, S, C, O> {
    #[must_use]
    pub fn destination(&self) -> &Destination {
        &self.destination
    }

    fn rpc(&self) -> Rpc<'_, T, S, C, O> {
        Rpc {
            transport: self.transport,
            auth: self.auth,
            observer: self.observer,
            destination: &self.destination,
            // Per-RPC calls have no push deadline; the signed window bounds them.
            deadline_ms: i64::MAX,
        }
    }

    fn require_signer(&self) -> Result<(), Error> {
        if self.auth.is_none() {
            return Err(Error::Invalid("signed client required"));
        }
        Ok(())
    }

    /// A fresh identity from the clock, to persist before a call and pass to it.
    ///
    /// # Errors
    /// An anonymous client, or a clock that cannot supply entropy.
    pub fn new_identity(&self) -> Result<Identity, Error> {
        let (_, clock) = self.auth.ok_or(Error::Invalid("signed client required"))?;
        let created_at_ms = clock.now_ms();
        Ok(Identity {
            nonce: clock.nonce().map_err(Error::Signing)?,
            created_at_ms,
            expires_at_ms: created_at_ms.saturating_add(mkit_core::write_auth::MAX_VALIDITY_MS),
        })
    }

    /// `GetServerInfo`. Never signed.
    ///
    /// # Errors
    /// Transport, remote or decoding failures.
    pub async fn server_info(&self) -> Result<GetServerInfoResponse, Error> {
        self.destination
            .server_info(self.transport)
            .await
            .map_err(Error::typed)
    }

    /// One `ListRefs` page. `page_size` 0 asks for the server's maximum.
    ///
    /// # Errors
    /// Transport, remote or decoding failures.
    pub async fn list_refs(
        &self,
        prefix: &str,
        page_size: u32,
        page_token: &str,
        identity: Option<&Identity>,
    ) -> Result<Reply<RefPage>, Error> {
        let request = ListRefsRequest {
            prefix: Some(prefix.to_owned()),
            page_size: Some(page_size),
            page_token: Some(page_token.to_owned()),
            ..Default::default()
        };
        let opts = Opts {
            identity,
            limit: LIST_REFS_LIMIT,
            ..Opts::default()
        };
        let (page, identity): (ListRefsResponse, _) = self
            .rpc()
            .unary_with("ListRefs", &request, opts)
            .await
            .map_err(Error::typed)?;
        let refs = page
            .refs
            .iter()
            .map(|entry| {
                Ok(NamedRef {
                    name: entry.name.clone().ok_or(Error::Invalid("ref name"))?,
                    id: id32(entry.object_id.as_deref(), "ref value")?,
                })
            })
            .collect::<Result<Vec<_>, Error>>()?;
        let next_page_token = page.next_page_token.filter(|token| !token.is_empty());
        reply(Ok((
            RefPage {
                refs,
                next_page_token,
                redactions: page.ref_redactions,
            },
            identity,
        )))
    }

    /// Every ref under `prefix`, following page tokens for at most `max_pages`.
    ///
    /// # Errors
    /// A failed page, or [`Error::Limit`] if the listing is longer.
    pub async fn list_all_refs(
        &self,
        prefix: &str,
        max_pages: u32,
    ) -> Result<Vec<NamedRef>, Error> {
        let mut out = Vec::new();
        let mut token = String::new();
        for _ in 0..max_pages {
            let page = self.list_refs(prefix, 0, &token, None).await?.value;
            out.extend(page.refs);
            match page.next_page_token {
                Some(next) => token = next,
                None => return Ok(out),
            }
        }
        Err(Error::Limit("ref listing pages"))
    }

    /// `ReadRef`: the ref's object id, or `None` if it does not exist.
    ///
    /// # Errors
    /// Transport, remote or decoding failures.
    pub async fn read_ref(
        &self,
        name: &str,
        identity: Option<&Identity>,
    ) -> Result<Reply<Option<Hash>>, Error> {
        let request = ReadRefRequest {
            name: Some(name.to_owned()),
            ..Default::default()
        };
        let opts = Opts {
            identity,
            ..Opts::default()
        };
        let (response, identity): (ReadRefResponse, _) = self
            .rpc()
            .unary_with("ReadRef", &request, opts)
            .await
            .map_err(Error::typed)?;
        let value = match response.exists {
            Some(false) => None,
            Some(true) => Some(id32(response.object_id.as_deref(), "ref value")?),
            None => return Err(Error::Invalid("ref presence")),
        };
        Ok(Reply { value, identity })
    }

    /// `PackExists`. `ref_hint` names a ref whose packmap listed the pack, for
    /// read-your-writes (SPEC-TRANSPORT-CONNECT §7.9).
    ///
    /// # Errors
    /// Transport, remote or decoding failures.
    pub async fn pack_exists(
        &self,
        pack_id: &Hash,
        ref_hint: Option<&str>,
        identity: Option<&Identity>,
    ) -> Result<Reply<bool>, Error> {
        let request = PackExistsRequest {
            pack_id: Some(pack_id.to_vec()),
            ..Default::default()
        };
        let opts = Opts {
            identity,
            hint: ref_hint,
            ..Opts::default()
        };
        let (response, identity): (PackExistsResponse, _) = self
            .rpc()
            .unary_with("PackExists", &request, opts)
            .await
            .map_err(Error::typed)?;
        let value = response.exists.ok_or(Error::Invalid("pack presence"))?;
        Ok(Reply { value, identity })
    }

    /// `DownloadPack`, bounded by `max_bytes`: a larger declared size or a
    /// longer response is [`Error::Limit`]. The response cap is `max_bytes` plus
    /// 1/512 plus 8 KiB for framing, which assumes the server's chunks are at
    /// least about 30 KiB (the reference server sends 800 KiB). The pack must hash to `pack_id`.
    /// The transport buffers the response (at most `max_bytes` plus
    /// framing) and the returned pack is a second copy, so peak memory is about
    /// twice `max_bytes`.
    ///
    /// # Errors
    /// Transport, remote, limit or commitment failures.
    pub async fn download_pack(
        &self,
        pack_id: &Hash,
        ref_hint: Option<&str>,
        max_bytes: u64,
        identity: Option<&Identity>,
    ) -> Result<Reply<Vec<u8>>, Error> {
        let opts = Opts {
            identity,
            hint: ref_hint,
            ..Opts::default()
        };
        reply(self.rpc().download_with(*pack_id, max_bytes, opts).await)
    }

    /// Walk a branch's packmap chain from `packmap_root` and return its pack
    /// ids oldest first, each once. Bounded by depth and pack count; every node
    /// is checked against its content id. `ref_hint` is the packmap's ref.
    ///
    /// # Errors
    /// A download, decoding or bound failure.
    pub async fn resolve_pack_chain(
        &self,
        packmap_root: Hash,
        ref_hint: &str,
    ) -> Result<Vec<Hash>, Error> {
        crate::read::resolve(&self.rpc(), packmap_root, ref_hint)
            .await
            .map_err(Error::typed)
    }

    /// `UpdateRef`: a compare-and-swap write of `name` to `new_id`. A failed
    /// precondition is a remote error for which [`Error::is_ref_conflict`] holds.
    ///
    /// # Errors
    /// An anonymous client, an observer veto, a signer refusal, or transport and
    /// remote failures.
    pub async fn update_ref(
        &self,
        name: &str,
        expected: RefWriteCondition,
        new_id: Hash,
        identity: Option<&Identity>,
    ) -> Result<Reply<UpdateRefResponse>, Error> {
        self.require_signer()?;
        reply(calls::update_ref(&self.rpc(), name, expected, Some(new_id), identity).await)
    }

    /// `UpdateRef` with `delete`, under the same precondition rules.
    ///
    /// # Errors
    /// As [`Client::update_ref`].
    pub async fn delete_ref(
        &self,
        name: &str,
        expected: RefWriteCondition,
        identity: Option<&Identity>,
    ) -> Result<Reply<UpdateRefResponse>, Error> {
        self.require_signer()?;
        reply(calls::update_ref(&self.rpc(), name, expected, None, identity).await)
    }

    /// `SetRepoVisibility` in the signed (envelope) mode: the signer must be
    /// the repository's owner or authority, as the server decides.
    ///
    /// # Errors
    /// An anonymous client, or transport and remote failures.
    pub async fn set_repo_visibility(
        &self,
        visibility: Visibility,
        identity: Option<&Identity>,
    ) -> Result<Reply<()>, Error> {
        use crate::proto::{
            RepoVisibility, SetRepoVisibilityRequest, SetRepoVisibilityResponse,
            set_repo_visibility_request::Mode,
        };
        self.require_signer()?;
        let wire = match visibility {
            Visibility::Public => RepoVisibility::REPO_VISIBILITY_PUBLIC,
            Visibility::Private => RepoVisibility::REPO_VISIBILITY_PRIVATE,
        };
        let request = SetRepoVisibilityRequest {
            mode: Some(Mode::Visibility(wire.into())),
            ..Default::default()
        };
        let opts = Opts {
            identity,
            ..Opts::default()
        };
        let result: Result<(SetRepoVisibilityResponse, _), Error> = self
            .rpc()
            .unary_with("SetRepoVisibility", &request, opts)
            .await;
        reply(result.map(|(_, identity)| ((), identity)))
    }

    /// One `AdvanceRefs`. A pending verification returns
    /// [`Error::PendingVerification`] and a membership lag
    /// [`Error::MembershipNotVisible`], both resumable by replaying the same
    /// identity while it is valid (each replay builds an envelope, so the observer
    /// and signer run again with the same nonce and number 1). The request's ids
    /// and expectations must be well formed: the observer is told the exact ref moves it carries.
    ///
    /// # Errors
    /// An anonymous client, a malformed request, an observer veto, a signer
    /// refusal, or transport and remote failures.
    pub async fn advance_refs(
        &self,
        request: &AdvanceRefsRequest,
        identity: Option<&Identity>,
    ) -> Result<Reply<AdvanceRefsResponse>, Error> {
        self.require_signer()?;
        reply(calls::advance_refs(&self.rpc(), request, identity).await)
    }

    /// `BeginUpload`: reserve an upload for `head_ref`.
    ///
    /// # Errors
    /// An anonymous client, an observer veto, a signer refusal, or transport and
    /// remote failures (including [`Error::PaymentRequired`] when the server
    /// admits uploads).
    pub async fn begin_upload(
        &self,
        head_ref: &str,
        pack_id: &Hash,
        bytes: u64,
        identity: Option<&Identity>,
    ) -> Result<Reply<BeginUploadResponse>, Error> {
        self.require_signer()?;
        reply(calls::begin_upload(&self.rpc(), head_ref, pack_id, bytes, None, identity).await)
    }

    /// `UploadPack` of the whole `pack`, optionally under a ticket token. The
    /// framed request is buffered, so peak memory is the pack plus its frames
    /// plus the transport's replay copy. The observer's
    /// [`new_objects`](crate::WriteIntent::new_objects) and ticket ids are empty
    /// here (only the opaque token is passed).
    ///
    /// # Errors
    /// As [`Client::begin_upload`].
    pub async fn upload_pack(
        &self,
        pack_id: &Hash,
        pack: &[u8],
        ticket_token: Option<&[u8]>,
        identity: Option<&Identity>,
    ) -> Result<Reply<UploadPackResponse>, Error> {
        self.require_signer()?;
        reply(
            calls::upload_pack(
                &self.rpc(),
                pack_id,
                pack,
                None,
                ticket_token.map(<[u8]>::to_vec),
                None,
                identity,
            )
            .await,
        )
    }

    /// `UploadPart` for part `index` of a multipart upload. `plan` is the
    /// geometry the ticket's part size and the server's part limit define, and
    /// `part` must be exactly the part the plan expects at `index`.
    ///
    /// # Errors
    /// A part that does not fit the plan, otherwise as [`Client::begin_upload`].
    pub async fn upload_part(
        &self,
        ticket: &UploadTicket,
        plan: &PartPlan,
        index: u32,
        part: &[u8],
        identity: Option<&Identity>,
    ) -> Result<Reply<UploadPartResponse>, Error> {
        self.require_signer()?;
        let expected = plan
            .expected_len(index)
            .map_err(|_| Error::Invalid("part length"))?;
        if expected != part.len() as u64 {
            return Err(Error::Invalid("part length"));
        }
        let ticket_id = id32(ticket.id.as_deref(), "ticket id")?;
        reply(
            calls::upload_part(
                &self.rpc(),
                ticket_id,
                ticket.token.clone(),
                plan,
                index,
                part,
                None,
                identity,
            )
            .await,
        )
    }

    /// `CompleteUpload` with the part receipts in index order. The observer's
    /// ticket ids are empty here: only the opaque token is passed.
    ///
    /// # Errors
    /// As [`Client::begin_upload`].
    pub async fn complete_upload(
        &self,
        ticket_token: &[u8],
        receipts: Vec<Vec<u8>>,
        identity: Option<&Identity>,
    ) -> Result<Reply<CompleteUploadResponse>, Error> {
        self.require_signer()?;
        reply(
            calls::complete_upload(
                &self.rpc(),
                None,
                Some(ticket_token.to_vec()),
                receipts,
                None,
                identity,
            )
            .await,
        )
    }

    /// Build the signed auth v2 request headers for `procedure` and
    /// `commitment` without sending anything, so a host that dispatches an mkit
    /// procedure through its own binding can sign it.
    ///
    /// It runs the same pipeline as a dispatched call: with `intent`, the
    /// [`Observer`] runs (and may veto or add headers); then the signer sees the
    /// operation (and may refuse); then a window that has already ended is
    /// [`Error::EnvelopeExpired`]. One of the six
    /// transport write procedures in [`procedures`] cannot be signed without an
    /// `intent` for it. Any other procedure (for example an administrative one)
    /// reaches the signer but is observed only when the host passes an `intent`. The attempt number
    /// is always 1. The observer sees the intent the host passes: build it from
    /// the body that will be sent, because the client cannot check it against the
    /// commitment. The result carries the envelope headers
    /// (`x-envelope-version`, `x-audience`, `x-repository`, `x-content-commitment`,
    /// `x-created-at`, `x-expires-at`, `idempotency-key`, `x-public-key`,
    /// `x-signature`, and `x-digest` for a `body:` commitment) plus the
    /// observer's headers, and the [`Identity`] used. The caller supplies the
    /// body and must send the bytes the commitment covers.
    ///
    /// # Errors
    /// An anonymous client, an invalid identity or procedure, an observer veto
    /// or reserved header, a signer refusal, or an expired window.
    pub async fn sign_envelope(
        &self,
        procedure: &str,
        commitment: &ContentCommitment,
        identity: Option<&Identity>,
        intent: Option<&WriteIntent<'_>>,
    ) -> Result<SignedEnvelope, Error> {
        if let Some(intent) = intent
            && intent.procedure != procedure
        {
            return Err(Error::Invalid("intent procedure"));
        }
        let is_write = [
            procedures::BEGIN_UPLOAD,
            procedures::UPLOAD_PACK,
            procedures::UPLOAD_PART,
            procedures::COMPLETE_UPLOAD,
            procedures::ADVANCE_REFS,
            procedures::UPDATE_REF,
        ]
        .contains(&procedure);
        if is_write && intent.is_none() {
            return Err(Error::Invalid("write intent required"));
        }
        let opts = Opts {
            identity,
            intent,
            ..Opts::default()
        };
        let signed = self
            .rpc()
            .sign(procedure, &commitment.to_string(), opts, 1)
            .await?;
        Ok(SignedEnvelope {
            headers: signed.headers,
            identity: signed.identity,
        })
    }
}

/// Signed auth v2 request headers and the identity they were signed under.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct SignedEnvelope {
    pub headers: http::HeaderMap,
    pub identity: Identity,
}
