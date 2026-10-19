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
use crate::seams::{NoObserver, NoRequestPolicy, Observer, RequestPolicy, WriteIntent, procedures};
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
    /// Readable by anyone.
    Public,
    /// Readable only by callers the server's authorizer admits; everyone else
    /// sees the same answer as for a missing repository.
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
/// (SPEC-TRANSPORT-CONNECT §7.1). Unsigned writes require explicit
/// [`Client::with_unsigned_writes`] opt-in and server authorization.
///
/// [`Client::with_observer`] adds host policy for every signed or explicitly clocked
/// unsigned write (see "Host policy seams" in the crate README).
pub struct Client<'a, T, S = NoSigner, C = NoClock, O = NoObserver, P: ?Sized = NoRequestPolicy> {
    transport: &'a T,
    destination: Destination,
    auth: Option<(&'a S, &'a C)>,
    unsigned_clock: Option<&'a C>,
    observer: &'a O,
    request_policy: Option<&'a P>,
    unsigned_writes: bool,
    pack_locations: bool,
    location_lifetime: std::sync::OnceLock<Option<u64>>,
}

impl<T, S, C, O, P: ?Sized> std::fmt::Debug for Client<'_, T, S, C, O, P> {
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
            unsigned_clock: None,
            observer: &NoObserver,
            request_policy: None,
            unsigned_writes: false,
            pack_locations: true,
            location_lifetime: std::sync::OnceLock::new(),
        }
    }
}

impl<'a, T: HttpTransport, C: Clock> Client<'a, T, NoSigner, C> {
    /// An unsigned client with a host clock for replayable write metadata.
    /// Reads and discovery remain identity-free; writes still require
    /// [`with_unsigned_writes`](Self::with_unsigned_writes) opt-in.
    #[must_use]
    pub fn anonymous_with_clock(transport: &'a T, destination: Destination, clock: &'a C) -> Self {
        Self {
            transport,
            destination,
            auth: None,
            unsigned_clock: Some(clock),
            observer: &NoObserver,
            request_policy: None,
            unsigned_writes: false,
            pack_locations: true,
            location_lifetime: std::sync::OnceLock::new(),
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
    /// An unsigned client with host-selected signer and clock types. This
    /// supports hosts whose configuration selects signed or unsigned operation
    /// while keeping one concrete client type. Writes require explicit opt-in.
    #[must_use]
    pub fn unsigned(transport: &'a T, destination: Destination) -> Self {
        Self {
            transport,
            destination,
            auth: None,
            unsigned_clock: None,
            observer: &NoObserver,
            request_policy: None,
            unsigned_writes: false,
            pack_locations: true,
            location_lifetime: std::sync::OnceLock::new(),
        }
    }

    /// A client that signs every RPC except `GetServerInfo`.
    #[must_use]
    pub fn signed(transport: &'a T, destination: Destination, signer: &'a S, clock: &'a C) -> Self {
        Self {
            transport,
            destination,
            auth: Some((signer, clock)),
            unsigned_clock: None,
            observer: &NoObserver,
            request_policy: None,
            unsigned_writes: false,
            pack_locations: true,
            location_lifetime: std::sync::OnceLock::new(),
        }
    }
}

impl<'a, T, S, C, O, P: ?Sized> Client<'a, T, S, C, O, P> {
    /// Enable or disable pack-location negotiation. Enabled by default only
    /// when the channel supports credential-free location fetching. Disabling
    /// this keeps every download on the streaming RPC path.
    #[must_use]
    pub fn with_pack_locations(mut self, enabled: bool) -> Self {
        self.pack_locations = enabled;
        self
    }

    /// Opt an unsigned client into clock-backed write replay metadata. This
    /// does not enable writes or signing, and does not change a signed client's
    /// configured clock. Use [`Client::anonymous_with_clock`] when selecting a
    /// clock type for an anonymous client.
    #[must_use]
    pub fn with_unsigned_clock(mut self, clock: &'a C) -> Self {
        self.unsigned_clock = Some(clock);
        self
    }

    /// Permit unsigned transport write calls. The server still authorizes
    /// every request, using credentials supplied by the host transport. The
    /// default anonymous client remains read-only; visibility changes and
    /// envelope signing always require a signer.
    #[must_use]
    pub fn with_unsigned_writes(mut self) -> Self {
        self.unsigned_writes = true;
        self
    }

    /// Whether transport write calls are enabled for this client.
    #[must_use]
    pub fn supports_writes(&self) -> bool {
        self.auth.is_some() || self.unsigned_writes
    }

    /// Select host-owned credentials through signed or unsigned callbacks.
    /// Signed policy runs after the write observer and before signing.
    /// Discovery bypasses credential selection.
    #[must_use]
    pub fn with_request_policy<Q: RequestPolicy + ?Sized>(
        self,
        policy: &'a Q,
    ) -> Client<'a, T, S, C, O, Q> {
        Client {
            transport: self.transport,
            destination: self.destination,
            auth: self.auth,
            unsigned_clock: self.unsigned_clock,
            observer: self.observer,
            request_policy: Some(policy),
            unsigned_writes: self.unsigned_writes,
            pack_locations: self.pack_locations,
            location_lifetime: self.location_lifetime,
        }
    }

    /// Run `observer` before signed or explicitly clocked unsigned write RPCs.
    /// It can veto the write and add per-attempt headers. Order: observer,
    /// signer (when configured), deadline
    /// check, dispatch.
    #[must_use]
    pub fn with_observer<Q: Observer>(self, observer: &'a Q) -> Client<'a, T, S, C, Q, P> {
        Client {
            transport: self.transport,
            destination: self.destination,
            auth: self.auth,
            unsigned_clock: self.unsigned_clock,
            observer,
            request_policy: self.request_policy,
            unsigned_writes: self.unsigned_writes,
            pack_locations: self.pack_locations,
            location_lifetime: self.location_lifetime,
        }
    }
}

impl<T: HttpTransport, S: Signer, C: Clock, O: Observer, P: RequestPolicy + ?Sized>
    Client<'_, T, S, C, O, P>
{
    #[must_use]
    pub fn destination(&self) -> &Destination {
        &self.destination
    }

    fn rpc(&self) -> Rpc<'_, T, S, C, O, P> {
        Rpc {
            transport: self.transport,
            auth: self.auth,
            unsigned_clock: self.unsigned_clock,
            observer: self.observer,
            request_policy: self.request_policy,
            destination: &self.destination,
            // Per-RPC calls have no push deadline; the signed window bounds them.
            deadline_ms: i64::MAX,
            location_lifetime: self.pack_locations.then_some(&self.location_lifetime),
        }
    }

    /// The configured signing public key, absent for anonymous clients.
    #[must_use]
    pub fn public_key(&self) -> Option<Hash> {
        self.auth.map(|(signer, _)| signer.public_key())
    }

    /// Whether the client has a signing clock or an explicit unsigned clock.
    #[must_use]
    pub fn has_clock(&self) -> bool {
        self.clock().is_some()
    }

    fn clock(&self) -> Option<&C> {
        self.auth.map(|(_, clock)| clock).or(self.unsigned_clock)
    }

    /// Current host time, absent for unsigned clients without an explicit clock.
    #[must_use]
    pub fn now_ms(&self) -> Option<i64> {
        self.clock().map(Clock::now_ms)
    }

    fn require_write_auth(&self) -> Result<(), Error> {
        if !self.supports_writes() {
            return Err(Error::Invalid("signed client required"));
        }
        Ok(())
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
    /// An unsigned client without an explicit clock, or unavailable entropy.
    pub fn new_identity(&self) -> Result<Identity, Error> {
        let clock = self
            .clock()
            .ok_or(Error::Invalid("signed client required"))?;
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
        self.rpc()
            .unary_with(
                "GetServerInfo",
                &crate::proto::GetServerInfoRequest::default(),
                Opts::default(),
            )
            .await
            .map(|(value, _)| value)
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
            page_size: if page_size == 0
                && self.rpc().response_profile("ListRefs").omit_zero_page_size
            {
                None
            } else {
                Some(page_size)
            },
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
        mkit_core::ref_listing::validate_page(refs.iter().map(|entry| entry.name.as_str()))
            .map_err(|_| Error::Invalid("ref listing order"))?;
        if page
            .next_page_token
            .as_ref()
            .is_some_and(|token| token.len() > mkit_core::ref_listing::MAX_CURSOR_BYTES)
        {
            return Err(Error::Invalid("ref listing cursor"));
        }
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
    /// A failed page, or [`Error::Invalid`] for ordering, cursor, or resource violations.
    pub async fn list_all_refs(
        &self,
        prefix: &str,
        max_pages: u32,
    ) -> Result<Vec<NamedRef>, Error> {
        let mut listing = mkit_core::ref_listing::RefListing::new(max_pages);
        while listing.can_request() {
            let page = self
                .list_refs(prefix, 0, listing.cursor(), None)
                .await?
                .value;
            if listing
                .push(page.refs, page.next_page_token, |entry: &mut NamedRef| {
                    &mut entry.name
                })
                .map_err(|_| Error::Invalid("ref listing"))?
            {
                return listing.finish().map_err(|_| Error::Invalid("ref listing"));
            }
        }
        Err(Error::Invalid("ref listing pages"))
    }

    /// Read a namespace's grant epoch. This owner-protocol call always sends
    /// an unsigned request without a repository header, including on a signed
    /// client. A missing stored epoch is returned as zero by the server.
    ///
    /// # Errors
    /// Transport, remote or decoding failures, or a missing epoch field.
    pub async fn get_grant_epoch(&self, namespace: &str) -> Result<Reply<u64>, Error> {
        let request = crate::proto::GetGrantEpochRequest {
            namespace: Some(namespace.to_owned()),
            ..Default::default()
        };
        let (response, identity): (crate::proto::GetGrantEpochResponse, _) = self
            .rpc()
            .unsigned_unary("GetGrantEpoch", &request, false)
            .await
            .map_err(Error::typed)?;
        Ok(Reply {
            value: response.epoch.ok_or(Error::Invalid("grant epoch"))?,
            identity,
        })
    }

    /// Set a grant epoch through an owner-signed statement. The request carries
    /// the statement without an auth envelope or repository header. Pending
    /// revocation is a typed retry hint for the host to schedule.
    ///
    /// # Errors
    /// Transport, statement rejection or decoding failures.
    pub async fn set_grant_epoch(&self, statement: &str) -> Result<Reply<u64>, Error> {
        let request = crate::proto::SetGrantEpochRequest {
            signed_statement: Some(statement.to_owned()),
            ..Default::default()
        };
        let (response, identity): (crate::proto::SetGrantEpochResponse, _) = self
            .rpc()
            .unsigned_unary("SetGrantEpoch", &request, false)
            .await
            .map_err(Error::typed)?;
        Ok(Reply {
            value: response.epoch.ok_or(Error::Invalid("grant epoch"))?,
            identity,
        })
    }

    /// Set repository visibility through an owner-signed statement. The
    /// repository header is retained and no auth envelope is created.
    ///
    /// # Errors
    /// Transport, statement rejection or decoding failures.
    pub async fn visibility_statement(&self, statement: &str) -> Result<Reply<()>, Error> {
        let request = crate::proto::SetRepoVisibilityRequest {
            mode: Some(
                crate::proto::set_repo_visibility_request::Mode::SignedStatement(
                    statement.to_owned(),
                ),
            ),
            ..Default::default()
        };
        let (_, identity): (crate::proto::SetRepoVisibilityResponse, _) = self
            .rpc()
            .unsigned_unary("SetRepoVisibility", &request, true)
            .await
            .map_err(Error::typed)?;
        Ok(Reply {
            value: (),
            identity,
        })
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
            None if self
                .rpc()
                .response_profile("ReadRef")
                .missing_presence_is_false =>
            {
                None
            }
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
        let value = match response.exists {
            Some(value) => value,
            None if self
                .rpc()
                .response_profile("PackExists")
                .missing_presence_is_false =>
            {
                false
            }
            None => return Err(Error::Invalid("pack presence")),
        };
        Ok(Reply { value, identity })
    }

    /// `DownloadPack`, bounded by `max_bytes`: a larger declared size or a
    /// longer response is [`Error::Limit`]. The response cap is `max_bytes` plus
    /// 1/512 plus 8 KiB for framing, which assumes the server's chunks are at
    /// least about 30 KiB (the reference server sends 800 KiB). The pack must hash to `pack_id`.
    /// A transport with incremental responses retains the final pack and one
    /// response frame. The buffered fallback retains the response plus the
    /// returned pack, so its peak memory is about twice `max_bytes` plus framing.
    /// An individual frame is bounded by the same response cap. A failed
    /// negotiated location triggers one separately signed streaming call with
    /// a fresh identity, which is returned in the reply.
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
    /// An anonymous client without unsigned-write opt-in, an observer veto,
    /// a signer refusal, or transport and
    /// remote failures.
    pub async fn update_ref(
        &self,
        name: &str,
        expected: RefWriteCondition,
        new_id: Hash,
        identity: Option<&Identity>,
    ) -> Result<Reply<UpdateRefResponse>, Error> {
        self.require_write_auth()?;
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
        self.require_write_auth()?;
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
    /// An anonymous client without unsigned-write opt-in, a malformed request,
    /// an observer veto, a signer
    /// refusal, or transport and remote failures.
    pub async fn advance_refs(
        &self,
        request: &AdvanceRefsRequest,
        identity: Option<&Identity>,
    ) -> Result<Reply<AdvanceRefsResponse>, Error> {
        self.require_write_auth()?;
        reply(calls::advance_refs(&self.rpc(), request, identity).await)
    }

    /// `BeginUpload`: reserve an upload for `head_ref`.
    ///
    /// # Errors
    /// An anonymous client without unsigned-write opt-in, an observer veto,
    /// a signer refusal, or transport and
    /// remote failures (including [`Error::PaymentRequired`] when the server
    /// admits uploads).
    pub async fn begin_upload(
        &self,
        head_ref: &str,
        pack_id: &Hash,
        bytes: u64,
        identity: Option<&Identity>,
    ) -> Result<Reply<BeginUploadResponse>, Error> {
        self.require_write_auth()?;
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
        self.require_write_auth()?;
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
        self.require_write_auth()?;
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
        self.require_write_auth()?;
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod unsigned_write_tests {
    use super::*;
    use buffa::Message as _;
    use http::{Request, Response};
    use std::cell::Cell;
    use std::future::Future;
    use std::task::{Context, Poll, Waker};

    struct UnsignedChannel(Cell<u32>);

    impl HttpTransport for UnsignedChannel {
        async fn send(
            &self,
            request: http::Request<Vec<u8>>,
            _: usize,
        ) -> Result<http::Response<Vec<u8>>, String> {
            assert!(request.uri().path().ends_with("/UpdateRef"));
            assert!(request.headers().get("x-signature").is_none());
            assert!(request.headers().get("idempotency-key").is_none());
            self.0.set(self.0.get() + 1);
            Ok(http::Response::builder()
                .status(200)
                .header("content-type", "application/proto")
                .body(UpdateRefResponse::default().encode_to_vec())
                .unwrap())
        }
    }

    struct OwnerStatementChannel(Cell<u32>);
    impl HttpTransport for OwnerStatementChannel {
        async fn send(
            &self,
            request: http::Request<Vec<u8>>,
            _: usize,
        ) -> Result<http::Response<Vec<u8>>, String> {
            let method = request.uri().path().rsplit('/').next().unwrap();
            assert!(request.headers().get("x-signature").is_none());
            assert!(request.headers().get("idempotency-key").is_none());
            assert_eq!(
                request.headers().contains_key("x-repository"),
                method == "SetRepoVisibility"
            );
            let bytes = match method {
                "GetGrantEpoch" => {
                    let request =
                        crate::proto::GetGrantEpochRequest::decode_from_slice(request.body())
                            .unwrap();
                    assert_eq!(request.namespace.as_deref(), Some("namespace"));
                    crate::proto::GetGrantEpochResponse {
                        epoch: Some(7),
                        ..Default::default()
                    }
                    .encode_to_vec()
                }
                "SetGrantEpoch" => {
                    let request =
                        crate::proto::SetGrantEpochRequest::decode_from_slice(request.body())
                            .unwrap();
                    assert_eq!(request.signed_statement.as_deref(), Some("epoch-statement"));
                    crate::proto::SetGrantEpochResponse {
                        epoch: Some(8),
                        ..Default::default()
                    }
                    .encode_to_vec()
                }
                "SetRepoVisibility" => {
                    let request =
                        crate::proto::SetRepoVisibilityRequest::decode_from_slice(request.body())
                            .unwrap();
                    assert!(
                        matches!(request.mode, Some(crate::proto::set_repo_visibility_request::Mode::SignedStatement(statement)) if statement == "visibility-statement")
                    );
                    crate::proto::SetRepoVisibilityResponse::default().encode_to_vec()
                }
                _ => panic!("unexpected owner-protocol call"),
            };
            self.0.set(self.0.get() + 1);
            Ok(http::Response::builder()
                .status(200)
                .header("content-type", "application/proto")
                .body(bytes)
                .unwrap())
        }
    }

    struct OwnerSigner;
    impl Signer for OwnerSigner {
        fn public_key(&self) -> Hash {
            [1; 32]
        }
        async fn sign(&self, _: &Hash) -> Result<[u8; 64], String> {
            panic!("owner statements must not invoke the envelope signer")
        }
    }
    struct OwnerClock;
    impl Clock for OwnerClock {
        fn now_ms(&self) -> i64 {
            1
        }
        fn nonce(&self) -> Result<Hash, String> {
            panic!("owner statements must not generate an envelope identity")
        }
        async fn wait(&self, _: std::time::Duration) {
            panic!("owner statements must not schedule a retry")
        }
    }

    #[test]
    fn owner_statement_calls_remain_unsigned_on_a_signed_client() {
        let channel = OwnerStatementChannel(Cell::new(0));
        let destination =
            Destination::new("https://vcs.example.org".into(), "default".into()).unwrap();
        let client = Client::signed(&channel, destination, &OwnerSigner, &OwnerClock);
        let epoch = ready(client.get_grant_epoch("namespace")).unwrap();
        assert_eq!(epoch.value, 7);
        assert!(epoch.identity.is_none());
        let epoch = ready(client.set_grant_epoch("epoch-statement")).unwrap();
        assert_eq!(epoch.value, 8);
        assert!(epoch.identity.is_none());
        assert!(
            ready(client.visibility_statement("visibility-statement"))
                .unwrap()
                .identity
                .is_none()
        );
        assert_eq!(channel.0.get(), 3);
    }

    fn ready<F: Future>(future: F) -> F::Output {
        let mut future = std::pin::pin!(future);
        match future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
        {
            Poll::Ready(value) => value,
            Poll::Pending => panic!("test channel must complete immediately"),
        }
    }

    #[test]
    fn anonymous_write_requires_opt_in_and_stays_unsigned() {
        let channel = UnsignedChannel(Cell::new(0));
        let destination =
            Destination::new("https://vcs.example.org".into(), "default".into()).unwrap();
        let client = Client::anonymous(&channel, destination);
        assert!(!client.has_clock());
        assert_eq!(client.now_ms(), None);
        assert!(client.new_identity().is_err());
        assert!(!client.supports_writes());
        assert!(matches!(
            ready(client.update_ref("refs/heads/main", RefWriteCondition::Missing, [1; 32], None)),
            Err(Error::Invalid("signed client required"))
        ));
        assert_eq!(channel.0.get(), 0);
        let client = client.with_unsigned_writes().with_observer(&NoObserver);
        assert!(client.supports_writes());
        let reply =
            ready(client.update_ref("refs/heads/main", RefWriteCondition::Missing, [1; 32], None))
                .unwrap();
        assert!(reply.identity.is_none());
        assert_eq!(channel.0.get(), 1);
        assert!(ready(client.set_repo_visibility(Visibility::Public, None)).is_err());
        assert_eq!(channel.0.get(), 1);
    }
    struct UnsignedClock {
        now: Cell<i64>,
        nonces: Cell<u8>,
    }
    impl Clock for UnsignedClock {
        fn now_ms(&self) -> i64 {
            self.now.get()
        }
        fn nonce(&self) -> Result<Hash, String> {
            let value = self.nonces.get() + 1;
            self.nonces.set(value);
            Ok([value; 32])
        }
        async fn wait(&self, _: std::time::Duration) {}
    }
    struct ClockedChannel(std::cell::RefCell<Vec<http::HeaderMap>>);
    impl HttpTransport for ClockedChannel {
        async fn send(
            &self,
            request: http::Request<Vec<u8>>,
            _: usize,
        ) -> Result<http::Response<Vec<u8>>, String> {
            for header in [
                "x-signature",
                "x-public-key",
                "x-audience",
                "x-envelope-version",
                "x-digest",
            ] {
                assert!(!request.headers().contains_key(header));
            }
            let method = request.uri().path().rsplit('/').next().unwrap();
            if method != "UpdateRef" {
                for header in ["idempotency-key", "x-created-at", "x-expires-at"] {
                    assert!(!request.headers().contains_key(header));
                }
            }
            self.0.borrow_mut().push(request.headers().clone());
            let bytes = match method {
                "UpdateRef" => UpdateRefResponse::default().encode_to_vec(),
                "ReadRef" => crate::proto::ReadRefResponse {
                    exists: Some(false),
                    ..Default::default()
                }
                .encode_to_vec(),
                "GetServerInfo" => crate::proto::GetServerInfoResponse::default().encode_to_vec(),
                _ => panic!("unexpected clocked call"),
            };
            Ok(http::Response::builder()
                .header("content-type", "application/proto")
                .body(bytes)
                .unwrap())
        }
    }

    #[test]
    fn explicit_unsigned_clock_preserves_write_nonce_replay_and_expiry() {
        let channel = ClockedChannel(std::cell::RefCell::new(Vec::new()));
        let clock = UnsignedClock {
            now: Cell::new(1_000),
            nonces: Cell::new(0),
        };
        let destination =
            Destination::new("https://vcs.example.org".into(), "default".into()).unwrap();
        let client = Client::anonymous_with_clock(&channel, destination, &clock);
        assert!(client.has_clock());
        assert_eq!(client.now_ms(), Some(1_000));
        assert!(!client.supports_writes());
        let client = client.with_unsigned_writes().with_observer(&NoObserver);
        let first =
            ready(client.update_ref("refs/heads/main", RefWriteCondition::Missing, [1; 32], None))
                .unwrap();
        let identity = first.identity.unwrap();
        let replay = ready(client.update_ref(
            "refs/heads/main",
            RefWriteCondition::Missing,
            [1; 32],
            Some(&identity),
        ))
        .unwrap();
        assert_eq!(replay.identity, Some(identity));
        assert_eq!(clock.nonces.get(), 1);
        let sent = channel.0.borrow();
        for header in ["idempotency-key", "x-created-at", "x-expires-at"] {
            assert_eq!(sent[0][header], sent[1][header]);
        }
        assert_eq!(sent[0]["idempotency-key"], identity.idempotency_key());
        drop(sent);
        clock.now.set(identity.expires_at_ms);
        assert!(matches!(
            ready(client.update_ref(
                "refs/heads/main",
                RefWriteCondition::Missing,
                [1; 32],
                Some(&identity)
            )),
            Err(Error::EnvelopeExpired)
        ));
        assert_eq!(channel.0.borrow().len(), 2);
        let fresh =
            ready(client.update_ref("refs/heads/main", RefWriteCondition::Missing, [1; 32], None))
                .unwrap()
                .identity
                .unwrap();
        assert_ne!(fresh.nonce, identity.nonce);
        assert_eq!(clock.nonces.get(), 2);
    }

    #[test]
    fn explicit_unsigned_clock_does_not_add_read_or_discovery_identity() {
        let channel = ClockedChannel(std::cell::RefCell::new(Vec::new()));
        let clock = UnsignedClock {
            now: Cell::new(1_000),
            nonces: Cell::new(0),
        };
        let destination =
            Destination::new("https://vcs.example.org".into(), "default".into()).unwrap();
        let client =
            Client::anonymous_with_clock(&channel, destination, &clock).with_unsigned_writes();
        let identity = client.new_identity().unwrap();
        assert!(matches!(
            ready(client.read_ref("refs/heads/main", Some(&identity))),
            Err(Error::Invalid("identity requires a signer"))
        ));
        assert_eq!(channel.0.borrow().len(), 0);
        assert!(
            ready(client.read_ref("refs/heads/main", None))
                .unwrap()
                .identity
                .is_none()
        );
        ready(client.server_info()).unwrap();
        assert_eq!(clock.nonces.get(), 1);
        assert_eq!(channel.0.borrow().len(), 2);
    }
    struct ProfileChannel {
        status: http::StatusCode,
        content_type: Option<&'static str>,
        body: Vec<u8>,
        limit: Cell<usize>,
    }
    impl HttpTransport for ProfileChannel {
        async fn send(
            &self,
            _: http::Request<Vec<u8>>,
            limit: usize,
        ) -> Result<http::Response<Vec<u8>>, String> {
            self.limit.set(limit);
            let mut response = http::Response::builder().status(self.status);
            if let Some(content_type) = self.content_type {
                response = response.header("content-type", content_type);
            }
            Ok(response.body(self.body.clone()).unwrap())
        }
    }
    type CapturedFailure = (
        crate::FailureKind,
        String,
        Option<u16>,
        Vec<u8>,
        Option<(String, String)>,
    );
    struct ResponsePolicy(std::cell::RefCell<Vec<CapturedFailure>>);
    impl RequestPolicy for ResponsePolicy {
        fn headers(
            &self,
            _: &crate::RequestContext<'_>,
        ) -> Result<crate::RequestHeaders, crate::Veto> {
            Ok(crate::RequestHeaders::new())
        }
        fn response_limit(&self, _: &str, _: usize) -> usize {
            4 * 1024 * 1024
        }
        fn response_profile(&self, _: &str) -> crate::ResponseProfile {
            crate::ResponseProfile {
                omit_zero_page_size: true,
                ignore_invalid_ref_hints: true,
                allow_other_success_status: true,
                allow_missing_content_type: true,
                allow_content_type_prefix: true,
                missing_presence_is_false: true,
                allow_incomplete_error_fields: true,
                ..crate::ResponseProfile::default()
            }
        }
        fn map_failure(&self, failure: &crate::FailureDiagnostic<'_>) -> Option<Error> {
            assert!(
                failure
                    .procedure
                    .starts_with("/mkit.transport.v1.TransportService/")
            );
            self.0.borrow_mut().push((
                failure.kind,
                failure.cause.to_owned(),
                failure.status.map(|status| status.as_u16()),
                failure.body.unwrap_or_default().to_vec(),
                failure
                    .parsed_error
                    .map(|error| (error.code.clone(), error.message.clone())),
            ));
            Some(Error::Transport("host-mapped failure".to_owned()))
        }
    }
    fn profile_destination() -> Destination {
        Destination::new("https://vcs.example.org".into(), "default".into()).unwrap()
    }

    #[derive(Default)]
    struct ReadRequestCapture(std::cell::RefCell<Vec<Request<Vec<u8>>>>);
    impl HttpTransport for ReadRequestCapture {
        async fn send(
            &self,
            request: Request<Vec<u8>>,
            _: usize,
        ) -> Result<Response<Vec<u8>>, String> {
            let bytes = if request.uri().path().ends_with("/ListRefs") {
                ListRefsResponse::default().encode_to_vec()
            } else {
                PackExistsResponse {
                    exists: Some(false),
                    ..Default::default()
                }
                .encode_to_vec()
            };
            self.0.borrow_mut().push(request);
            Ok(Response::builder()
                .header("content-type", "application/proto")
                .body(bytes)
                .unwrap())
        }
    }
    #[test]
    fn zero_page_size_and_invalid_hints_require_explicit_host_compatibility() {
        let channel = ReadRequestCapture::default();
        let client = Client::anonymous(&channel, profile_destination());
        ready(client.list_refs("", 0, "", None)).unwrap();
        let request = channel.0.borrow();
        let list = ListRefsRequest::decode_from_slice(request[0].body()).unwrap();
        assert_eq!(list.page_size, Some(0));
        drop(request);
        assert!(matches!(
            ready(client.pack_exists(&[1; 32], Some("refs/heads/bad\nheader"), None)),
            Err(Error::Invalid("ref hint"))
        ));
        assert_eq!(channel.0.borrow().len(), 1);

        let policy = ResponsePolicy(std::cell::RefCell::new(Vec::new()));
        let client =
            Client::anonymous(&channel, profile_destination()).with_request_policy(&policy);
        ready(client.list_refs("", 0, "", None)).unwrap();
        ready(client.list_refs("", 7, "", None)).unwrap();
        for hint in ["../bad", "refs/heads/bad\nheader", "refs/heads/main"] {
            ready(client.pack_exists(&[1; 32], Some(hint), None)).unwrap();
        }
        let requests = channel.0.borrow();
        assert_eq!(
            ListRefsRequest::decode_from_slice(requests[1].body())
                .unwrap()
                .page_size,
            None
        );
        assert_eq!(
            ListRefsRequest::decode_from_slice(requests[2].body())
                .unwrap()
                .page_size,
            Some(7)
        );
        assert!(requests[3].headers().get("x-mkit-ref").is_none());
        assert!(requests[4].headers().get("x-mkit-ref").is_none());
        assert_eq!(requests[5].headers()["x-mkit-ref"], "refs/heads/main");
    }

    #[test]
    fn default_response_validation_and_budgets_stay_strict() {
        for (status, content_type) in [
            (http::StatusCode::NO_CONTENT, None),
            (http::StatusCode::OK, None),
            (http::StatusCode::OK, Some("application/proto; mode=test")),
        ] {
            let channel = ProfileChannel {
                status,
                content_type,
                body: Vec::new(),
                limit: Cell::new(0),
            };
            let client = Client::anonymous(&channel, profile_destination());
            assert!(matches!(
                ready(client.read_ref("refs/heads/main", None)),
                Err(Error::Invalid("Connect response status/encoding"))
            ));
            assert_eq!(channel.limit.get(), 1024 * 1024);
        }
    }

    #[test]
    fn host_response_profile_explicitly_selects_acceptance_presence_and_budget() {
        let policy = ResponsePolicy(std::cell::RefCell::new(Vec::new()));
        for (status, content_type) in [
            (http::StatusCode::NO_CONTENT, None),
            (http::StatusCode::OK, None),
            (http::StatusCode::OK, Some("application/proto-any-prefix")),
        ] {
            let channel = ProfileChannel {
                status,
                content_type,
                body: Vec::new(),
                limit: Cell::new(0),
            };
            let client =
                Client::anonymous(&channel, profile_destination()).with_request_policy(&policy);
            assert!(
                ready(client.read_ref("refs/heads/main", None))
                    .unwrap()
                    .value
                    .is_none()
            );
            assert!(
                !ready(client.pack_exists(&[1; 32], None, None))
                    .unwrap()
                    .value
            );
            assert_eq!(channel.limit.get(), 4 * 1024 * 1024);
        }
        assert!(policy.0.borrow().is_empty());
    }

    #[test]
    fn host_failure_mapping_receives_original_protobuf_and_http_evidence() {
        let policy = ResponsePolicy(std::cell::RefCell::new(Vec::new()));
        let invalid = vec![0xff];
        let cause = ReadRefResponse::decode_from_slice(&invalid)
            .unwrap_err()
            .to_string();
        let channel = ProfileChannel {
            status: http::StatusCode::CREATED,
            content_type: Some("application/proto"),
            body: invalid.clone(),
            limit: Cell::new(0),
        };
        let client =
            Client::anonymous(&channel, profile_destination()).with_request_policy(&policy);
        assert!(matches!(
            ready(client.read_ref("refs/heads/main", None)),
            Err(Error::Transport(_))
        ));
        {
            let observations = policy.0.borrow();
            let captured = &observations[0];
            assert_eq!(captured.0, crate::FailureKind::Decode);
            assert_eq!(captured.1, cause);
            assert_eq!(captured.2, Some(201));
            assert_eq!(captured.3, invalid);
        }
        for body in [b"backend unavailable".as_slice(), b"{}"] {
            let channel = ProfileChannel {
                status: http::StatusCode::SERVICE_UNAVAILABLE,
                content_type: Some("text/plain"),
                body: body.to_vec(),
                limit: Cell::new(0),
            };
            let client =
                Client::anonymous(&channel, profile_destination()).with_request_policy(&policy);
            assert!(matches!(
                ready(client.read_ref("refs/heads/main", None)),
                Err(Error::Transport(_))
            ));
        }
        let captures = policy.0.borrow();
        assert_eq!(captures[1].0, crate::FailureKind::Http);
        assert_eq!(captures[1].2, Some(503));
        assert_eq!(captures[1].3, b"backend unavailable");
        assert!(captures[1].4.is_none());
        assert_eq!(
            captures[2].4,
            Some(("unavailable".to_owned(), String::new()))
        );
    }

    #[test]
    fn admission_uses_actual_status_before_optional_failure_mapping() {
        let policy = ResponsePolicy(std::cell::RefCell::new(Vec::new()));
        for body in [b"{}".as_slice(), b"unusable error body"] {
            let channel = ProfileChannel {
                status: http::StatusCode::PAYMENT_REQUIRED,
                content_type: None,
                body: body.to_vec(),
                limit: Cell::new(0),
            };
            let client =
                Client::anonymous(&channel, profile_destination()).with_request_policy(&policy);
            assert!(matches!(
                ready(client.read_ref("refs/heads/main", None)),
                Err(Error::PaymentRequired(_))
            ));
        }
        assert!(policy.0.borrow().is_empty());
    }
}
