//! Stateless upload ticket authentication (STC §7.6). Only the key id is
//! inspected before authenticating the bytes; claims are decoded afterwards.

use std::collections::BTreeSet;
use std::fmt;

use mkit_core::hash::{Hash, from_hex};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::error::{Code, ServerError};

/// Domain separator for the ticket-token MAC key.
pub const TICKET_TOKEN_CONTEXT: &str = "mkit-server ticket token v1";
/// Reserved for WP-1.11: derive receipt keys from the same deployment secret.
pub const PART_RECEIPT_CONTEXT: &str = "mkit-server part receipt v1";

/// Authenticated, deployment-bound upload claims. Clients treat their encoding
/// as opaque; no metadata read is needed to verify them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TicketClaims {
    /// Reservation-derived ticket id.
    pub ticket_id: Hash,
    /// Canonical deployment audience.
    pub audience: String,
    /// Full repository identity, including namespace.
    pub repository: String,
    /// Signer permitted to upload and consume this ticket.
    pub signer: Hash,
    /// Expected pack commitment.
    pub pack_id: Hash,
    /// Declared pack byte count.
    pub bytes: u64,
    /// Server-selected part geometry.
    pub part_size: u64,
    /// Expiry on the business clock, Unix milliseconds.
    pub expires_at_ms: u64,
    /// Backend multipart identifier; empty before WP-1.11.
    pub upload_session: Vec<u8>,
}

impl TicketClaims {
    /// Bind the ticket to the caller before an RPC checks its own payload fields.
    pub fn check_principal(
        &self,
        audience: &str,
        repository: &str,
        signer: &Hash,
    ) -> Result<(), ServerError> {
        if self.audience != audience || self.repository != repository || self.signer != *signer {
            return Err(ServerError::new(
                Code::PermissionDenied,
                "upload ticket binding mismatch",
            ));
        }
        Ok(())
    }

    /// Check the request binding after token verification. Ticket, part and
    /// receipt-specific commitments are checked by their respective RPCs.
    pub fn check_binding(
        &self,
        audience: &str,
        repository: &str,
        signer: &Hash,
        pack_id: &Hash,
        bytes: u64,
    ) -> Result<(), ServerError> {
        self.check_principal(audience, repository, signer)?;
        if self.pack_id != *pack_id || self.bytes != bytes {
            return Err(ServerError::new(
                Code::PermissionDenied,
                "upload ticket binding mismatch",
            ));
        }
        Ok(())
    }
}

#[derive(Clone)]
struct TicketKey {
    id: String,
    secret: Zeroizing<Hash>,
}

impl PartialEq for TicketKey {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && bool::from(self.secret.ct_eq(&*other.secret))
    }
}

impl Eq for TicketKey {}

impl TicketKey {
    fn mac_key(&self) -> Zeroizing<Hash> {
        Zeroizing::new(blake3::derive_key(TICKET_TOKEN_CONTEXT, &*self.secret))
    }

    fn receipt_mac_key(&self) -> Zeroizing<Hash> {
        Zeroizing::new(blake3::derive_key(PART_RECEIPT_CONTEXT, &*self.secret))
    }
}

/// Signing and accepted keys. The first key signs and every listed key verifies.
/// Secrets, including derived MAC keys, are zeroed when dropped.
#[derive(Clone, PartialEq, Eq)]
pub struct TicketKeys {
    keys: Vec<TicketKey>,
}

impl fmt::Debug for TicketKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TicketKeys")
            .field(
                "key_ids",
                &self.keys.iter().map(|key| &key.id).collect::<Vec<_>>(),
            )
            .finish_non_exhaustive()
    }
}

/// Invalid deployment key configuration. Never contains secret input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid ticket keys: expected unique key ids and 64 hex digits per key")]
pub struct TicketKeyError;

impl TicketKeys {
    /// The active key id and a domain-separated receipt MAC key. The source
    /// secret is never exposed; the derived key is wiped after use.
    pub(crate) fn receipt_signing_key(&self) -> (&str, Zeroizing<Hash>) {
        let key = &self.keys[0];
        (&key.id, key.receipt_mac_key())
    }

    /// A domain-separated receipt MAC key for an accepted key id.
    pub(crate) fn receipt_verification_key(&self, id: &[u8]) -> Option<Zeroizing<Hash>> {
        self.keys
            .iter()
            .find(|key| key.id.as_bytes() == id)
            .map(TicketKey::receipt_mac_key)
    }

    /// Validate an ordered key set. It must be nonempty; ids must be unique,
    /// 1–32 ASCII bytes from `[A-Za-z0-9._-]`.
    pub fn new(keys: Vec<(String, Hash)>) -> Result<Self, TicketKeyError> {
        // Wrap before validation so even rejected configuration is wiped.
        let keys: Vec<_> = keys
            .into_iter()
            .map(|(id, secret)| TicketKey {
                id,
                secret: Zeroizing::new(secret),
            })
            .collect();
        let mut ids = BTreeSet::new();
        if keys.is_empty()
            || keys
                .iter()
                .any(|key| !valid_id(&key.id) || !ids.insert(&key.id))
        {
            return Err(TicketKeyError);
        }
        Ok(Self { keys })
    }

    /// Parse `<key-id> <64 hex>` lines, ignoring blank lines and `#` comments.
    /// The first line signs; all lines verify. Errors never echo input.
    pub fn parse(text: &str) -> Result<Self, TicketKeyError> {
        let mut keys = Vec::new();
        let mut ids = BTreeSet::new();
        for line in text.lines().map(str::trim) {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut fields = line.split_whitespace();
            let id = fields.next().ok_or(TicketKeyError)?;
            let secret = fields.next().ok_or(TicketKeyError)?;
            if fields.next().is_some() || !valid_id(id) || !ids.insert(id) {
                return Err(TicketKeyError);
            }
            let secret = Zeroizing::new(from_hex(secret).map_err(|_| TicketKeyError)?);
            keys.push(TicketKey {
                id: id.into(),
                secret,
            });
        }
        if keys.is_empty() {
            return Err(TicketKeyError);
        }
        Ok(Self { keys })
    }

    /// Parse an owned deployment secret, wiping its source text when parsing
    /// completes, including on invalid configuration.
    pub fn parse_secret(text: String) -> Result<Self, TicketKeyError> {
        let text = Zeroizing::new(text);
        Self::parse(&text)
    }

    /// Whether `secret` is any key's source secret, in constant time.
    /// `Pipeline::new` refuses a URL-token key that repeats one
    /// (SPEC-WRITE-GRANTS §9.4's dedicated-key rule), and the native adapter
    /// refuses a hook seed that does (SPEC-SERVER §7.1).
    #[must_use]
    pub fn contains_secret(&self, secret: &[u8; 32]) -> bool {
        self.keys
            .iter()
            .any(|key| bool::from(key.secret.ct_eq(secret)))
    }

    /// Mint a token from trusted claims.
    ///
    /// # Panics
    /// If audience, repository or session exceeds the encoding's u16 length.
    /// RPC callers build claims from validated repository and ticket rows.
    #[must_use]
    pub fn mint(&self, claims: &TicketClaims) -> Vec<u8> {
        let key = &self.keys[0]; // constructors enforce a nonempty key set
        let id_len = u8::try_from(key.id.len()).expect("validated ticket key id");
        let mut bytes = vec![1, id_len];
        bytes.extend_from_slice(key.id.as_bytes());
        bytes.extend_from_slice(&claims.ticket_id);
        append_field(&mut bytes, claims.audience.as_bytes());
        append_field(&mut bytes, claims.repository.as_bytes());
        bytes.extend_from_slice(&claims.signer);
        bytes.extend_from_slice(&claims.pack_id);
        for number in [claims.bytes, claims.part_size, claims.expires_at_ms] {
            bytes.extend_from_slice(&number.to_be_bytes());
        }
        append_field(&mut bytes, &claims.upload_session);
        bytes.extend_from_slice(blake3::keyed_hash(&key.mac_key(), &bytes).as_bytes());
        bytes
    }

    /// Authenticate first, decode next, then check expiry on the business clock.
    /// Malformed, unknown, invalid and expired tokens are failed preconditions.
    pub fn verify(&self, token: &[u8], now_ms: u64) -> Result<TicketClaims, ServerError> {
        let tag_at = token.len().checked_sub(32).ok_or_else(invalid_token)?;
        let (message, tag) = token.split_at(tag_at);
        let id_len = usize::from(*message.get(1).ok_or_else(invalid_token)?);
        let id = message.get(2..2 + id_len).ok_or_else(invalid_token)?;
        let key = self
            .keys
            .iter()
            .find(|key| key.id.as_bytes() == id)
            .ok_or_else(invalid_token)?;
        let expected = blake3::keyed_hash(&key.mac_key(), message);
        if !bool::from(expected.as_bytes().as_slice().ct_eq(tag)) {
            return Err(invalid_token());
        }

        let mut reader = Reader(message);
        if reader.take(1)? != [1] {
            return Err(invalid_token());
        }
        reader.take(1 + id_len)?;
        let claims = TicketClaims {
            ticket_id: reader.array()?,
            audience: reader.text()?,
            repository: reader.text()?,
            signer: reader.array()?,
            pack_id: reader.array()?,
            bytes: u64::from_be_bytes(reader.array()?),
            part_size: u64::from_be_bytes(reader.array()?),
            expires_at_ms: u64::from_be_bytes(reader.array()?),
            upload_session: reader.field()?.to_vec(),
        };
        if !reader.0.is_empty() || claims.expires_at_ms <= now_ms {
            return Err(invalid_token());
        }
        Ok(claims)
    }
}

impl std::str::FromStr for TicketKeys {
    type Err = TicketKeyError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::parse(text)
    }
}

fn valid_id(id: &str) -> bool {
    (1..=32).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn append_field(bytes: &mut Vec<u8>, field: &[u8]) {
    let length = u16::try_from(field.len()).expect("validated ticket claim length");
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(field);
}

fn invalid_token() -> ServerError {
    ServerError::new(Code::FailedPrecondition, "invalid or expired upload ticket")
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], ServerError> {
        let bytes = self.0.get(..length).ok_or_else(invalid_token)?;
        self.0 = &self.0[length..];
        Ok(bytes)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], ServerError> {
        self.take(N)?.try_into().map_err(|_| invalid_token())
    }

    fn field(&mut self) -> Result<&'a [u8], ServerError> {
        let length = u16::from_be_bytes(self.array()?);
        self.take(usize::from(length))
    }

    fn text(&mut self) -> Result<String, ServerError> {
        std::str::from_utf8(self.field()?)
            .map(str::to_owned)
            .map_err(|_| invalid_token())
    }
}

#[cfg(test)]
#[path = "token_tests.rs"]
mod tests;
