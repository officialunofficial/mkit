//! Coordinator-owned visibility indexes and bounded namespace listing.

use std::collections::VecDeque;

use subtle::ConstantTimeEq;

use super::{Authenticated, Authorizer, HookSet, Pipeline, RepoVisibility, internal, meta_error};
use crate::error::ServerError;
use crate::op::{AuthzFacts, CallerView, OpKind};
use crate::policy::AuthorizerRole;
use crate::repo::{Addressing, MAX_REPO_NAME_BYTES, RepoName};
use crate::store::{Batch, Key, MultipartBlobStore, NamespaceStore, Partition, Value, codec, keys};

/// A repository name and its effective visibility. The registry has no cheap head/update projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoEntry {
    /// Full name within the requested namespace.
    pub name: String,
    /// Explicit visibility or the current deployment default.
    pub visibility: RepoVisibility,
}

/// One bounded repository-name page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoPage {
    /// Entries in ascending byte order.
    pub repos: Vec<RepoEntry>,
    /// Opaque authenticated bytes; the binding uses unpadded base64url.
    pub next: Option<Vec<u8>>,
}

/// Append the listing projection to the very apply that writes registration/visibility.
pub(super) fn index_writes(
    batch: &mut Batch,
    repo: &RepoName,
    registered: bool,
    stored: Option<&Value>,
) -> Result<(), ServerError> {
    let visibility = stored
        .map(codec::decode_repo_visibility)
        .transpose()
        .map_err(meta_error)?;
    batch
        .writes
        .push(crate::store::Write::Delete(keys::repo_listing(repo, true)));
    batch
        .writes
        .push(crate::store::Write::Delete(keys::repo_listing(repo, false)));
    if registered {
        let explicit_public = match visibility.map(|row| row.visibility) {
            None => false,
            Some(codec::StoredVisibility::Public) => true,
            Some(codec::StoredVisibility::Private) => return Ok(()),
        };
        batch.writes.push(crate::store::Write::Put(
            keys::repo_listing(repo, explicit_public),
            Value::default(),
        ));
    }
    Ok(())
}

struct Source {
    prefix: Key,
    last: Option<String>,
    rows: VecDeque<String>,
    more: bool,
    registry: bool,
}

impl Source {
    async fn fill<N: NamespaceStore>(
        &mut self,
        store: &N,
        partition: &Partition,
    ) -> Result<(), ServerError> {
        if !self.rows.is_empty() || !self.more {
            return Ok(());
        }
        let start = self.last.as_ref().map_or_else(
            || self.prefix.clone(),
            |last| {
                let mut bytes = self.prefix.as_bytes().to_vec();
                bytes.extend_from_slice(last.as_bytes());
                bytes.push(0);
                Key::new(bytes)
            },
        );
        // All names are printable ASCII; 0xff strictly bounds the prefix range.
        let mut end = self.prefix.as_bytes().to_vec();
        end.push(0xff);
        let page = store
            .scan(partition, &start, &Key::new(end), None, 101)
            .await
            .map_err(listing_unavailable)?;
        if page.entries.len() > 101 || (page.entries.is_empty() && page.next.is_some()) {
            return Err(listing_unavailable("invalid repository listing scan"));
        }
        let mut previous: Option<String> = None;
        for (key, value) in page.entries {
            if !key.as_bytes().starts_with(self.prefix.as_bytes())
                || key.as_bytes() < start.as_bytes()
            {
                return Err(listing_unavailable("repository listing key outside range"));
            }
            let name = match (self.registry, keys::parse(&key)) {
                (true, Some(keys::ParsedKey::RepoRecord(repo))) => {
                    codec::decode_repo_record(&value).map_err(listing_unavailable)?;
                    repo.as_str().to_owned()
                }
                (false, Some(keys::ParsedKey::RepoListing { repo, .. }))
                    if value.as_bytes().is_empty() =>
                {
                    repo.as_str().to_owned()
                }
                _ => return Err(listing_unavailable("invalid repository listing row")),
            };
            if previous.as_ref().is_some_and(|last| last >= &name) {
                return Err(listing_unavailable("unordered repository listing"));
            }
            previous = Some(name.clone());
            self.rows.push_back(name);
        }
        self.more = page.next.is_some();
        Ok(())
    }
}

impl<B: MultipartBlobStore, N: NamespaceStore, H: HookSet> Pipeline<B, N, H> {
    pub(super) async fn plan_listing_visibility(
        &self,
        p: &Partition,
        repo: &crate::repo::RepoId,
        batch: &mut Batch,
    ) -> Result<(), ServerError> {
        let key = keys::repo_record(&repo.name);
        let record = self.meta.get(p, &key).await.map_err(meta_error)?;
        if let Some(value) = &record {
            codec::decode_repo_record(value).map_err(meta_error)?;
        }
        batch
            .preconditions
            .push(super::lease::observed_guard(key, record.as_ref()));
        let value = batch
            .writes
            .iter()
            .rev()
            .find_map(|write| match write {
                crate::store::Write::Put(key, value)
                    if *key == keys::repo_visibility(&repo.name) =>
                {
                    Some(value.clone())
                }
                _ => None,
            })
            .ok_or_else(|| internal("visibility projection without visibility write"))?;
        index_writes(batch, &repo.name, record.is_some(), Some(&value))
    }

    /// List a namespace without visiting private rows for the public view.
    /// Signed envelopes use the ordinary X-Repository syntax; its namespace
    /// must match `namespace`. The name is only an authorization selector for this RPC.
    /// Grants never extend listing rights. Authority hooks authorize the entire namespace.
    ///
    /// # Errors
    /// Invalid namespace/prefix/size/token, mismatched authentication, or unavailable storage/hooks.
    #[allow(clippy::too_many_lines)] // One bounded merge and its authenticated continuation.
    pub async fn list_repos_page(
        &self,
        a: &Authenticated,
        namespace: &str,
        name_prefix: &str,
        page_size: Option<u32>,
        token: Option<&[u8]>,
    ) -> Result<RepoPage, ServerError> {
        self.observe(
            a,
            self.list_repos_inner(a, namespace, name_prefix, page_size, token),
        )
        .await
    }

    #[allow(clippy::too_many_lines)] // One bounded merge and its authenticated continuation.
    async fn list_repos_inner(
        &self,
        a: &Authenticated,
        namespace: &str,
        name_prefix: &str,
        page_size: Option<u32>,
        token: Option<&[u8]>,
    ) -> Result<RepoPage, ServerError> {
        if a.write_grant.is_some() && a.auth.is_none() {
            return Err(ServerError::unauthenticated(
                "grant requires signed authentication",
            ));
        }
        if name_prefix.len() > MAX_REPO_NAME_BYTES
            || !name_prefix.bytes().all(|b| (0x21..=0x7e).contains(&b))
        {
            return Err(ServerError::invalid_argument(
                "invalid repository listing prefix",
            ));
        }
        let mut op = self.identify(
            a,
            OpKind::ListRepos {
                name_prefix: name_prefix.into(),
            },
        )?;
        if namespace != op.repo.namespace.as_str() {
            return Err(ServerError::invalid_argument(
                "invalid repository listing namespace or prefix",
            ));
        }
        let size = match page_size.unwrap_or(0) {
            0 => 100,
            n @ 1..=100 => n as usize,
            _ => {
                return Err(ServerError::invalid_argument(
                    "repository page size exceeds 100",
                ));
            }
        };
        if let Addressing::Single { repo } = &self.cfg.addressing {
            self.hooks
                .authorizer()
                .authorize(&op)
                .await
                .map_err(ServerError::strip_admission_shape)?;
            if token.is_some() {
                return Err(invalid_token());
            }
            return Ok(RepoPage {
                repos: if repo.name.as_str().starts_with(name_prefix) {
                    vec![RepoEntry {
                        name: repo.name.as_str().into(),
                        visibility: RepoVisibility::Public,
                    }]
                } else {
                    Vec::new()
                },
                next: None,
            });
        }
        let owner = a.auth.is_some()
            && a.write_grant.is_none()
            && matches!(mkit_core::repo_identity::Namespace::parse(namespace),
                Ok(mkit_core::repo_identity::Namespace::Ed25519(key)) if a.principal.ed25519() == Some(&key));
        let mut full = owner;
        if a.auth.is_some()
            && a.write_grant.is_none()
            && (owner || self.cfg.authorizer_role == AuthorizerRole::Authority)
        {
            op.authz = AuthzFacts {
                owner,
                caller_view: if owner {
                    CallerView::Writer
                } else {
                    CallerView::Reader
                },
                ..AuthzFacts::default()
            };
            match self.hooks.authorizer().authorize(&op).await {
                Ok(_) => full |= self.cfg.authorizer_role == AuthorizerRole::Authority,
                Err(error)
                    if !owner
                        && matches!(
                            error.code(),
                            crate::Code::PermissionDenied | crate::Code::NotFound
                        ) => {}
                Err(error) => return Err(error.strip_admission_shape()),
            }
        }
        let keyset = self.cfg.ticket_keys.as_ref().ok_or_else(|| {
            ServerError::failed_precondition("repository listing requires deployment MAC keys")
        })?;
        let binding = blake3::hash(
            &serde_json::to_vec(&(
                "ListRepos v1",
                namespace,
                name_prefix,
                full,
                self.cfg.default_repo_visibility == RepoVisibility::Public,
                a.principal.ed25519(),
                match &self.cfg.auth {
                    super::AuthMode::AuthV2(cfg) => cfg.audience(),
                    _ => "",
                },
            ))
            .map_err(|_| internal("repository listing binding"))?,
        );
        let last = token
            .map(|bytes| decode_token(keyset, bytes, binding.as_bytes()))
            .transpose()?;
        if last
            .as_ref()
            .is_some_and(|last| !last.starts_with(name_prefix))
        {
            return Err(invalid_token());
        }
        let prefixes = if full {
            vec![Key::new(b"rr\0".to_vec())]
        } else if self.cfg.default_repo_visibility == RepoVisibility::Public {
            vec![
                keys::repo_listing_prefix(true),
                keys::repo_listing_prefix(false),
            ]
        } else {
            vec![keys::repo_listing_prefix(true)]
        };
        let mut sources: Vec<_> = prefixes
            .into_iter()
            .map(|mut prefix| {
                let base = prefix.as_bytes().to_vec();
                let mut bytes = base;
                bytes.extend_from_slice(name_prefix.as_bytes());
                prefix = Key::new(bytes);
                // last is a full name; strip the requested prefix before extending this range.
                Source {
                    prefix,
                    last: last.as_ref().map(|name| name[name_prefix.len()..].into()),
                    rows: VecDeque::new(),
                    more: true,
                    registry: full,
                }
            })
            .collect();
        let partition = self.shards.coordinator(&op.repo.namespace);
        let mut names = Vec::with_capacity(size);
        loop {
            for source in &mut sources {
                source.fill(&self.meta, &partition).await?;
            }
            let next = sources
                .iter()
                .enumerate()
                .filter_map(|(i, source)| source.rows.front().map(|name| (i, name)))
                .min_by(|a, b| a.1.cmp(b.1));
            let Some((index, _)) = next else {
                break;
            };
            if names.len() == size {
                break;
            }
            let name = sources[index]
                .rows
                .pop_front()
                .ok_or_else(|| internal("repository listing merge"))?;
            sources[index].last = Some(name[name_prefix.len()..].into());
            if names.last().is_some_and(|last| last >= &name) {
                return Err(internal("duplicate repository listing row"));
            }
            names.push(name);
        }
        let more = sources.iter().any(|source| !source.rows.is_empty());
        let visibility = if full {
            let wanted: Vec<_> = names
                .iter()
                .map(|name| RepoName::new(name.clone()).map(|repo| keys::repo_visibility(&repo)))
                .collect::<Result<_, _>>()?;
            let rows = if wanted.is_empty() {
                Vec::new()
            } else {
                self.meta
                    .get_many(&partition, &wanted)
                    .await
                    .map_err(listing_unavailable)?
            };
            if rows.len() != names.len() {
                return Err(listing_unavailable("short repository visibility read"));
            }
            rows.into_iter()
                .map(|row| {
                    let row = row
                        .as_ref()
                        .map(codec::decode_repo_visibility)
                        .transpose()
                        .map_err(listing_unavailable)?;
                    Ok(
                        if super::repo_is_private(row.as_ref(), self.cfg.default_repo_visibility) {
                            RepoVisibility::Private
                        } else {
                            RepoVisibility::Public
                        },
                    )
                })
                .collect::<Result<Vec<_>, ServerError>>()?
        } else {
            vec![RepoVisibility::Public; names.len()]
        };
        let next = if more {
            let last = names
                .last()
                .ok_or_else(|| internal("empty repository continuation"))?;
            Some(encode_token(keyset, binding.as_bytes(), last)?)
        } else {
            None
        };
        Ok(RepoPage {
            repos: names
                .into_iter()
                .zip(visibility)
                .map(|(name, visibility)| RepoEntry { name, visibility })
                .collect(),
            next,
        })
    }
}

fn listing_unavailable(error: impl std::fmt::Display) -> ServerError {
    tracing::warn!(detail = %error, "repository listing failed");
    ServerError::unavailable("repository listing unavailable")
}

fn invalid_token() -> ServerError {
    ServerError::invalid_argument("invalid repository page token")
}

fn encode_token(
    keys: &crate::upload::token::TicketKeys,
    binding: &[u8; 32],
    last: &str,
) -> Result<Vec<u8>, ServerError> {
    let (id, key) = keys.listing_signing_key();
    let mut bytes = vec![1, u8::try_from(id.len()).map_err(|_| invalid_token())?];
    bytes.extend_from_slice(id.as_bytes());
    bytes.extend_from_slice(binding);
    bytes.extend_from_slice(last.as_bytes());
    bytes.extend_from_slice(blake3::keyed_hash(&key, &bytes).as_bytes());
    Ok(bytes)
}

fn decode_token(
    keys: &crate::upload::token::TicketKeys,
    bytes: &[u8],
    binding: &[u8; 32],
) -> Result<String, ServerError> {
    if bytes.len() > 2 + 32 + 32 + MAX_REPO_NAME_BYTES + 32 || bytes.first() != Some(&1) {
        return Err(invalid_token());
    }
    let id_len = usize::from(*bytes.get(1).ok_or_else(invalid_token)?);
    let tag_at = bytes.len().checked_sub(32).ok_or_else(invalid_token)?;
    let message = bytes.get(..tag_at).ok_or_else(invalid_token)?;
    let id = message.get(2..2 + id_len).ok_or_else(invalid_token)?;
    let key = keys
        .listing_verification_key(id)
        .ok_or_else(invalid_token)?;
    if !bool::from(
        blake3::keyed_hash(&key, message)
            .as_bytes()
            .as_slice()
            .ct_eq(&bytes[tag_at..]),
    ) || message.get(2 + id_len..2 + id_len + 32) != Some(binding.as_slice())
    {
        return Err(invalid_token());
    }
    let name = std::str::from_utf8(message.get(2 + id_len + 32..).ok_or_else(invalid_token)?)
        .map_err(|_| invalid_token())?;
    RepoName::new(name).map_err(|_| invalid_token())?;
    Ok(name.into())
}
