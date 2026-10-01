use std::collections::BTreeSet;

use ed25519_dalek::{Signature, VerifyingKey};
use mkit_core::hash::{hash, to_hex};
use serde::Deserialize;

use crate::{ServerError, auth_v2};

use super::{BodyCapture, Headers};

/// Required admin envelope headers, in canonical envelope field order.
pub const HEADER_NAMES: [&str; 8] = [
    "x-mkit-admin-version",
    "x-mkit-admin-key-id",
    "x-mkit-admin-audience",
    "x-mkit-admin-created-at",
    "x-mkit-admin-expires-at",
    "x-mkit-admin-nonce",
    "x-mkit-admin-digest",
    "x-mkit-admin-signature",
];

/// Public operator keys and the deployment's canonical signing origin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub(crate) audience: String,
    keys: Vec<Key>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Key {
    id: String,
    public: [u8; 32],
    before: Option<i64>,
    after: Option<i64>,
    roles: BTreeSet<String>,
}

impl Config {
    /// Parse the §16.3 key list; empty lists disable the service.
    ///
    /// # Errors
    /// Invalid origins, duplicate keys or roles, malformed keys and bounds.
    pub fn parse(audience: &str, json: &str) -> Result<Self, ServerError> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Entry {
            key_id: String,
            alg: String,
            public_key: String,
            not_before_ms: Option<String>,
            not_after_ms: Option<String>,
            roles: Vec<String>,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct List {
            version: u32,
            keys: Vec<Entry>,
        }
        if json.len() > 64 * 1024 {
            return Err(invalid("admin key list too large"));
        }
        mkit_core::write_auth::validate_audience(audience)
            .map_err(|_| invalid("invalid admin audience"))?;
        let list: List =
            serde_json::from_str(json).map_err(|_| invalid("invalid admin key list"))?;
        if list.keys.len() > 128 {
            return Err(invalid("too many admin keys"));
        }
        if list.version != 1 {
            return Err(invalid("invalid admin key-list version"));
        }
        let mut keys: Vec<Key> = Vec::new();
        for e in list.keys {
            if !identifier(&e.key_id, 64, false)
                || e.alg != "ed25519"
                || keys.iter().any(|k| k.id == e.key_id)
            {
                return Err(invalid("invalid or duplicate admin key id"));
            }
            let public =
                hex::<32>(&e.public_key).ok_or_else(|| invalid("invalid admin public key"))?;
            VerifyingKey::from_bytes(&public).map_err(|_| invalid("invalid Ed25519 admin key"))?;
            let bound = |s: Option<String>| {
                s.map(|s| {
                    decimal_i64(&s).ok_or_else(|| invalid("invalid admin key validity bound"))
                })
                .transpose()
            };
            let before = bound(e.not_before_ms)?;
            let after = bound(e.not_after_ms)?;
            if before.zip(after).is_some_and(|(b, a)| b > a) {
                return Err(invalid("invalid admin key validity interval"));
            }
            let mut roles = BTreeSet::new();
            for role in e.roles {
                if !matches!(
                    role.as_str(),
                    "lease" | "moderation" | "grants" | "audit" | "all"
                ) || !roles.insert(role)
                {
                    return Err(invalid("invalid or duplicate admin role"));
                }
            }
            if roles.is_empty() {
                return Err(invalid("admin key requires roles"));
            }
            keys.push(Key {
                id: e.key_id,
                public,
                before,
                after,
                roles,
            });
        }
        Ok(Self {
            audience: audience.to_owned(),
            keys,
        })
    }

    /// Whether a nonempty key list enables the admin service.
    #[must_use]
    pub fn enabled(&self) -> bool {
        !self.keys.is_empty()
    }

    /// Configured public keys for checking other credential domains.
    #[must_use]
    pub fn public_keys(&self) -> Vec<[u8; 32]> {
        self.keys.iter().map(|k| k.public).collect()
    }

    /// Reject sharing an admin key with another credential role.
    ///
    /// # Errors
    /// A configured admin public key occurs in `other`.
    pub fn check_separation(&self, other: &[[u8; 32]]) -> Result<(), ServerError> {
        if self.keys.iter().any(|k| other.contains(&k.public)) {
            return Err(invalid("admin credentials must use distinct keys"));
        }
        Ok(())
    }

    pub(crate) fn verify(
        &self,
        path: &str,
        headers: &Headers,
        body: &BodyCapture,
        now: i64,
    ) -> Result<Verified, ServerError> {
        check_headers(headers)?;
        if !self.enabled() {
            return Err(ServerError::unauthenticated("admin service disabled"));
        }
        let h = HEADER_NAMES
            .map(|name| one(headers, name).ok_or_else(|| unauth("missing admin header")));
        let [
            version,
            id,
            audience,
            created,
            expiry,
            nonce,
            digest,
            signature,
        ] = h;
        if version? != "1" {
            return Err(unauth("unsupported admin version"));
        }
        let id = id?;
        let audience = audience?;
        let created = created?;
        let expiry = expiry?;
        let nonce = nonce?;
        let digest = digest?;
        let signature = signature?;
        let key = self
            .keys
            .iter()
            .find(|k| k.id == id)
            .ok_or_else(|| unauth("unknown admin key"))?;
        let created_ms =
            decimal_u64(created).ok_or_else(|| unauth("invalid admin creation time"))?;
        let expiry_ms = decimal_u64(expiry).ok_or_else(|| unauth("invalid admin expiry time"))?;
        let now_ms = u64::try_from(now).map_err(|_| unauth("invalid backend clock"))?;
        let nonce_bytes = hex::<32>(nonce).ok_or_else(|| unauth("invalid admin nonce"))?;
        let signature = hex::<64>(signature).ok_or_else(|| unauth("invalid admin signature"))?;
        if audience != self.audience
            || !path.starts_with(super::PREFIX)
            || expiry_ms <= created_ms
            || expiry_ms - created_ms > 300_000
            || created_ms > now_ms.saturating_add(30_000)
            || expiry_ms <= now_ms
            || key
                .before
                .is_some_and(|b| i128::from(created_ms) < i128::from(b))
            || key
                .after
                .is_some_and(|a| i128::from(created_ms) > i128::from(a))
            || path == super::READ_PRESERVED_PATH
                && (key.before.is_some_and(|b| now < b) || key.after.is_some_and(|a| now > a))
            || digest != body.digest()
        {
            return Err(unauth("invalid admin envelope"));
        }
        let canonical = format!(
            "mkit-admin:v1\n{id}\n{audience}\n{path}\n{digest}\n{created}\n{expiry}\n{nonce}"
        );
        let public =
            VerifyingKey::from_bytes(&key.public).map_err(|_| unauth("invalid admin key"))?;
        public
            .verify_strict(
                &hash(canonical.as_bytes()),
                &Signature::from_bytes(&signature),
            )
            .map_err(|_| unauth("invalid admin signature"))?;
        let replay_key = to_hex(&hash(
            format!("{audience}\n{id}\n{}", to_hex(&nonce_bytes)).as_bytes(),
        ));
        Ok(Verified {
            actor: id.to_owned(),
            nonce: nonce.to_owned(),
            digest: digest.to_owned(),
            path: path.to_owned(),
            replay_key,
            expiry_ms,
            roles: key.roles.clone(),
        })
    }
}

pub(crate) struct Verified {
    pub actor: String,
    pub nonce: String,
    pub digest: String,
    pub path: String,
    pub replay_key: String,
    pub expiry_ms: u64,
    pub roles: BTreeSet<String>,
}

pub(crate) fn check_headers(headers: &Headers) -> Result<(), ServerError> {
    let admin = headers
        .iter()
        .any(|(n, _)| n.to_ascii_lowercase().starts_with("x-mkit-admin-"));
    if admin
        && headers.iter().any(|(n, _)| {
            auth_v2::HEADER_NAMES
                .iter()
                .any(|a| n.eq_ignore_ascii_case(a))
                || n.eq_ignore_ascii_case("x-write-grant")
        })
    {
        return Err(invalid("mixed admin and write credentials"));
    }
    if one(headers, HEADER_NAMES[0]) != Some("1") {
        return Err(unauth("missing or unsupported admin version"));
    }
    for name in HEADER_NAMES {
        if one(headers, name).is_none_or(|s| s.contains(',')) {
            return Err(unauth("missing, repeated or joined admin header"));
        }
    }
    Ok(())
}

fn one<'a>(headers: &'a Headers, name: &str) -> Option<&'a str> {
    let mut values = headers.iter().filter(|(n, _)| n.eq_ignore_ascii_case(name));
    let value = values.next()?.1.as_str();
    values.next().is_none().then_some(value)
}

pub(crate) fn identifier(s: &str, max: usize, operation: bool) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-') || operation && b == b':'
        })
}
pub(crate) fn decimal_u64(s: &str) -> Option<u64> {
    s.parse::<u64>().ok().filter(|n| n.to_string() == s)
}
fn decimal_i64(s: &str) -> Option<i64> {
    s.parse::<i64>().ok().filter(|n| n.to_string() == s)
}
pub(crate) fn hex<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != 2 * N
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let mut out = [0; N];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}
pub(crate) fn invalid(message: &str) -> ServerError {
    ServerError::invalid_argument(message.to_owned())
}
fn unauth(message: &str) -> ServerError {
    ServerError::unauthenticated(message.to_owned())
}
