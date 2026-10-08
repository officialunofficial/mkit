//! Dedicated, versioned MACs for selected-ref structural continuation evidence.
//!
//! The v2 wire format is a fixed-order binary payload (see `encode`), never
//! JSON: version byte, order byte, length-bounded scope strings, fences, a
//! provenance witness chain and, for all-parent paging, a verbatim
//! [`TimestampDiscovery`] snapshot. v1 JSON tokens are rejected wholesale.
#[cfg(feature = "http-objects")]
use crate::HistoryStateLimit;
#[cfg(feature = "http-objects")]
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use mkit_core::hash::{Hash, from_hex};
#[cfg(feature = "http-objects")]
use mkit_core::history_order::TimestampDiscovery;
#[cfg(feature = "http-objects")]
use std::collections::BTreeSet;
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

/// Domain-separated structural evidence; never a bearer authorization grant.
pub const DOMAIN: &str = "mkit-history-continuation:v2";
/// Bound stop-sensitive provenance and parsing allocation across a paging chain.
pub const MAX_WITNESS: usize = 1024;
#[cfg(feature = "http-objects")]
const MAX_PAYLOAD: usize = 65_536;
/// `base64url_nopad(65_536)` = `87_382` payload chars + `.` + 43 MAC chars.
#[cfg(feature = "http-objects")]
const MAX_TOKEN: usize = 87_426;
#[cfg(feature = "http-objects")]
const VERSION: u8 = 0x02;
#[cfg(feature = "http-objects")]
const ORDER_FIRST_PARENT: u8 = 0x00;
#[cfg(feature = "http-objects")]
const ORDER_TIMESTAMP: u8 = 0x01;
#[cfg(feature = "http-objects")]
const MAX_REALM: usize = 2048;
#[cfg(feature = "http-objects")]
const MAX_NAME: usize = 4096;
#[cfg(feature = "http-objects")]
const NO_PREDECESSOR: u16 = u16::MAX;

/// Invalid configuration; secret inputs never appear in diagnostics.
#[derive(Debug, Clone, Copy, thiserror::Error)]
#[error("invalid history continuation configuration")]
pub struct ConfigError;

/// Deployment realm, dedicated active secret and fixed maximum lifetime.
/// Replacing the active key immediately invalidates outstanding continuations.
#[derive(Clone)]
pub struct HistoryTokenConfig {
    secret: std::sync::Arc<Zeroizing<Hash>>,
    realm: String,
    ttl_ms: u64,
}
impl core::fmt::Debug for HistoryTokenConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HistoryTokenConfig")
            .field("realm", &self.realm)
            .field("ttl_ms", &self.ttl_ms)
            .finish_non_exhaustive()
    }
}
impl HistoryTokenConfig {
    /// Derived public role key, reserved against client/owner authentication.
    #[must_use]
    pub fn public_key(&self) -> Hash {
        ed25519_dalek::SigningKey::from_bytes(&self.secret)
            .verifying_key()
            .to_bytes()
    }
    /// Reject published role material that exposes or reuses the MAC secret.
    /// # Errors
    /// A raw or derived cross-role collision.
    pub fn check_public_roles(&self, public: &[Hash]) -> Result<(), ConfigError> {
        if public
            .iter()
            .any(|p| *p == self.public_key() || bool::from(p.ct_eq(&**self.secret)))
        {
            return Err(ConfigError);
        }
        Ok(())
    }
    /// Constant-time role-separation check without exposing secret material.
    #[must_use]
    pub fn contains_secret(&self, candidate: &Hash) -> bool {
        bool::from(candidate.ct_eq(&**self.secret))
    }
    /// Configure one dedicated secret. Realm must uniquely identify the backend.
    /// # Errors
    /// Empty/oversized realm, zero secret, or lifetime outside 1–900000 ms.
    pub fn new(secret: Zeroizing<Hash>, realm: String, ttl_ms: u64) -> Result<Self, ConfigError> {
        if realm.is_empty()
            || realm.len() > 2048
            || *secret == [0; 32]
            || !(1..=900_000).contains(&ttl_ms)
        {
            return Err(ConfigError);
        }
        Ok(Self {
            secret: std::sync::Arc::new(secret),
            realm,
            ttl_ms,
        })
    }
    /// Parse the deployment key-file pattern: one `active <64 hex>` line.
    /// Blank lines/comments are allowed. No retired key remains redeemable.
    /// The owned source text is wiped after parsing.
    /// # Errors
    /// Invalid key-file grammar or configuration.
    pub fn parse_key_file_secret(
        text: String,
        realm: String,
        ttl_ms: u64,
    ) -> Result<Self, ConfigError> {
        let text = Zeroizing::new(text);
        let mut lines = text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'));
        let fields: Vec<_> = lines
            .next()
            .ok_or(ConfigError)?
            .split_whitespace()
            .collect();
        let ["active", hex] = fields.as_slice() else {
            return Err(ConfigError);
        };
        let secret = Zeroizing::new(from_hex(hex).map_err(|_| ConfigError)?);
        if lines.next().is_some() {
            return Err(ConfigError);
        }
        Self::new(secret, realm, ttl_ms)
    }
    #[cfg(feature = "http-objects")]
    pub(crate) fn ttl_ms(&self) -> u64 {
        self.ttl_ms
    }
    #[cfg(feature = "http-objects")]
    pub(crate) fn realm(&self) -> &str {
        &self.realm
    }
    pub(crate) fn check_roles(
        &self,
        cfg: &crate::pipeline::PipelineConfig,
    ) -> Result<(), ConfigError> {
        use crate::policy::NamespacePolicy;
        use mkit_core::repo_identity::Namespace;
        match &cfg.addressing {
            crate::Addressing::Single { repo } => {
                if let Ok(Namespace::Ed25519(key)) = Namespace::parse(repo.namespace.as_str()) {
                    self.check_public_roles(&[key])?;
                }
            }
            crate::Addressing::Multi(multi) => {
                if let NamespacePolicy::Allowlist(namespaces) = &multi.namespace_policy {
                    for namespace in namespaces {
                        if let Namespace::Ed25519(key) = namespace {
                            self.check_public_roles(&[*key])?;
                        }
                    }
                }
            }
        }
        let secret: &Hash = &self.secret;
        let public = self.public_key();
        if cfg
            .ticket_keys
            .as_ref()
            .is_some_and(|keys| keys.contains_ed25519_public(&public))
            || cfg.url_tokens.as_ref().is_some_and(|t| {
                t.keys().contains_secret(secret)
                    || t.keys().public_keys().any(|p| p == public || p == *secret)
            })
            || cfg
                .scanner_retrieval
                .as_ref()
                .is_some_and(|s| s.check_role_keys(&[public], &[*secret]).is_err())
            || cfg
                .admin_keys
                .iter()
                .any(|p| *p == public || bool::from(p.ct_eq(secret)))
            || cfg
                .authority_fence
                .as_ref()
                .is_some_and(|f| f.public_keys().any(|p| p == public || p == *secret))
            || cfg.receipt_publication.as_ref().is_some_and(|r| {
                r.public_keys()
                    .iter()
                    .any(|p| *p == public || *p == *secret)
            })
        {
            return Err(ConfigError);
        }
        Ok(())
    }
    #[cfg(feature = "http-objects")]
    fn mac(&self, payload: &[u8]) -> Hash {
        let key = Zeroizing::new(blake3::derive_key(DOMAIN, &**self.secret));
        *blake3::keyed_hash(&key, payload).as_bytes()
    }
    #[cfg(feature = "http-objects")]
    pub(crate) fn mint(&self, claims: &Claims) -> Result<String, HistoryStateLimit> {
        self.mint_purpose(claims, DOMAIN)
    }
    /// Mint with a caller-chosen purpose; test-only so foreign-purpose tokens
    /// prove the domain check.
    #[cfg(all(test, feature = "http-objects"))]
    pub(crate) fn mint_purpose_test(
        &self,
        claims: &Claims,
        purpose: &str,
    ) -> Result<String, HistoryStateLimit> {
        self.mint_purpose(claims, purpose)
    }
    #[cfg(feature = "http-objects")]
    fn mint_purpose(&self, claims: &Claims, purpose: &str) -> Result<String, HistoryStateLimit> {
        let payload = encode(claims, purpose)?;
        Ok(format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(&payload),
            URL_SAFE_NO_PAD.encode(self.mac(&payload))
        ))
    }
    #[cfg(feature = "http-objects")]
    pub(crate) fn verify(&self, token: &str) -> Result<Claims, ()> {
        if token.len() > MAX_TOKEN {
            return Err(());
        }
        let (payload, mac) = token.split_once('.').ok_or(())?;
        if mac.len() != 43 {
            return Err(());
        }
        let mac = URL_SAFE_NO_PAD.decode(mac).map_err(|_| ())?;
        let payload = URL_SAFE_NO_PAD.decode(payload).map_err(|_| ())?;
        if payload.len() > MAX_PAYLOAD || !bool::from(self.mac(&payload).as_slice().ct_eq(&mac)) {
            return Err(());
        }
        // Authenticate before allocating the bounded graph/strings.
        let claims = decode(&payload)?;
        if claims.realm != self.realm
            || claims.issued >= claims.expires
            || claims.expires - claims.issued > self.ttl_ms
        {
            return Err(());
        }
        Ok(claims)
    }
}

/// One proven node carried by a v2 token; `predecessor` is the index of the
/// node that proved it, `None` on the single root (node 0 only).
#[cfg(feature = "http-objects")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WitnessNode {
    pub id: Hash,
    pub predecessor: Option<u16>,
}

/// The walk the token resumes: a first-parent cursor or a timestamp-ordered
/// discovery frontier.
#[cfg(feature = "http-objects")]
#[derive(Debug, Clone)]
pub(crate) enum ClaimState {
    /// First-parent paging; the cursor is the last witness node.
    FirstParent,
    /// A sealed [`TimestampDiscovery`] snapshot between steps.
    TimestampDiscovery(TimestampDiscovery),
}

/// Authenticated v2 claims; v1 JSON tokens are rejected by the decoder.
#[cfg(feature = "http-objects")]
#[derive(Debug, Clone)]
pub(crate) struct Claims {
    pub realm: String,
    pub namespace: String,
    pub repository: String,
    pub reference: String,
    pub writer: bool,
    pub credential: Hash,
    pub anchor: Hash,
    pub publication: crate::store::publication::Publication,
    pub security: Hash,
    pub issued: u64,
    pub expires: u64,
    pub state: ClaimState,
    pub witness: Vec<WitnessNode>,
}

#[cfg(feature = "http-objects")]
fn field(out: &mut Vec<u8>, bytes: &[u8], max: usize) -> Result<(), HistoryStateLimit> {
    if bytes.len() > max || bytes.len() > u16::MAX as usize {
        return Err(HistoryStateLimit::TokenBytes);
    }
    out.extend_from_slice(
        &u16::try_from(bytes.len())
            .map_err(|_| HistoryStateLimit::TokenBytes)?
            .to_le_bytes(),
    );
    out.extend_from_slice(bytes);
    Ok(())
}

/// Fixed-order little-endian payload; every field is length-checked so a
/// malformed token never drives allocation.
#[cfg(feature = "http-objects")]
fn encode(claims: &Claims, purpose: &str) -> Result<Vec<u8>, HistoryStateLimit> {
    if claims.witness.is_empty() || claims.witness.len() > MAX_WITNESS {
        return Err(HistoryStateLimit::TokenBytes);
    }
    let mut out = Vec::new();
    out.push(VERSION);
    out.push(match claims.state {
        ClaimState::FirstParent => ORDER_FIRST_PARENT,
        ClaimState::TimestampDiscovery(_) => ORDER_TIMESTAMP,
    });
    field(&mut out, purpose.as_bytes(), u16::MAX as usize)?;
    field(&mut out, claims.realm.as_bytes(), MAX_REALM)?;
    field(&mut out, claims.namespace.as_bytes(), MAX_NAME)?;
    field(&mut out, claims.repository.as_bytes(), MAX_NAME)?;
    field(&mut out, claims.reference.as_bytes(), MAX_NAME)?;
    out.push(u8::from(claims.writer));
    out.extend_from_slice(&claims.credential);
    out.extend_from_slice(&claims.anchor);
    let publication = claims
        .publication
        .encode()
        .map_err(|_| HistoryStateLimit::TokenBytes)?;
    field(
        &mut out,
        publication.as_bytes(),
        crate::store::MAX_VALUE_BYTES,
    )?;
    out.extend_from_slice(&claims.security);
    out.extend_from_slice(&claims.issued.to_le_bytes());
    out.extend_from_slice(&claims.expires.to_le_bytes());
    out.extend_from_slice(
        &u16::try_from(claims.witness.len())
            .map_err(|_| HistoryStateLimit::TokenBytes)?
            .to_le_bytes(),
    );
    for node in &claims.witness {
        out.extend_from_slice(&node.id);
        out.extend_from_slice(&node.predecessor.unwrap_or(NO_PREDECESSOR).to_le_bytes());
    }
    if let ClaimState::TimestampDiscovery(walk) = &claims.state {
        let snapshot = walk.encode();
        out.extend_from_slice(
            &u32::try_from(snapshot.len())
                .map_err(|_| HistoryStateLimit::TokenBytes)?
                .to_le_bytes(),
        );
        out.extend_from_slice(&snapshot);
    }
    if out.len() > MAX_PAYLOAD {
        return Err(HistoryStateLimit::TokenBytes);
    }
    Ok(out)
}

#[cfg(feature = "http-objects")]
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}
#[cfg(feature = "http-objects")]
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], ()> {
        let end = self.at.checked_add(n).ok_or(())?;
        let bytes = self.bytes.get(self.at..end).ok_or(())?;
        self.at = end;
        Ok(bytes)
    }
    fn u8(&mut self) -> Result<u8, ()> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, ()> {
        Ok(u16::from_le_bytes(
            self.take(2)?.try_into().map_err(|_| ())?,
        ))
    }
    fn u32(&mut self) -> Result<u32, ()> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().map_err(|_| ())?,
        ))
    }
    fn u64(&mut self) -> Result<u64, ()> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().map_err(|_| ())?,
        ))
    }
    fn hash(&mut self) -> Result<Hash, ()> {
        self.take(32)?.try_into().map_err(|_| ())
    }
    fn str(&mut self, max: usize) -> Result<String, ()> {
        let len = usize::from(self.u16()?);
        if len > max {
            return Err(());
        }
        core::str::from_utf8(self.take(len)?)
            .map(str::to_owned)
            .map_err(|_| ())
    }
    fn done(&self) -> Result<(), ()> {
        if self.at == self.bytes.len() {
            Ok(())
        } else {
            Err(())
        }
    }
}

#[cfg(feature = "http-objects")]
fn decode(payload: &[u8]) -> Result<Claims, ()> {
    let mut r = Reader {
        bytes: payload,
        at: 0,
    };
    if r.u8()? != VERSION {
        return Err(());
    }
    let order = r.u8()?;
    if !matches!(order, ORDER_FIRST_PARENT | ORDER_TIMESTAMP) {
        return Err(());
    }
    if r.str(u16::MAX as usize)? != DOMAIN {
        return Err(());
    }
    let realm = r.str(MAX_REALM)?;
    let namespace = r.str(MAX_NAME)?;
    let repository = r.str(MAX_NAME)?;
    let reference = r.str(MAX_NAME)?;
    let writer = match r.u8()? {
        0x00 => false,
        0x01 => true,
        _ => return Err(()),
    };
    let credential = r.hash()?;
    let anchor = r.hash()?;
    let publication = {
        let len = usize::from(r.u16()?);
        let value = crate::Value::new(r.take(len)?.to_vec());
        crate::store::publication::Publication::decode(Some(&value)).map_err(|_| ())?
    };
    let security = r.hash()?;
    let issued = r.u64()?;
    let expires = r.u64()?;
    let witness_len = usize::from(r.u16()?);
    if witness_len == 0 || witness_len > MAX_WITNESS {
        return Err(());
    }
    let mut witness = Vec::with_capacity(witness_len);
    let mut seen = BTreeSet::new();
    for index in 0..witness_len {
        let id = r.hash()?;
        let predecessor = match r.u16()? {
            NO_PREDECESSOR => None,
            p => Some(p),
        };
        // Exactly one root, first, and predecessors always earlier.
        match (index, predecessor) {
            (0, None) => {}
            (_, Some(p)) if usize::from(p) < index => {}
            _ => return Err(()),
        }
        if !seen.insert(id) {
            return Err(());
        }
        witness.push(WitnessNode { id, predecessor });
    }
    let state = match order {
        ORDER_FIRST_PARENT => {
            let linear = witness
                .iter()
                .enumerate()
                .all(|(i, n)| i == 0 || n.predecessor == u16::try_from(i - 1).ok());
            if !linear {
                return Err(());
            }
            ClaimState::FirstParent
        }
        ORDER_TIMESTAMP => {
            let len = usize::try_from(r.u32()?).map_err(|_| ())?;
            let walk = TimestampDiscovery::decode(r.take(len)?).map_err(|_| ())?;
            // Only a sealed, between-steps state whose pending ids all carry
            // provenance is redeemable.
            if walk.selected().is_some() || !walk.sealed() {
                return Err(());
            }
            let ids: BTreeSet<Hash> = witness.iter().map(|n| n.id).collect();
            if walk.pending().iter().any(|e| !ids.contains(&e.id)) {
                return Err(());
            }
            ClaimState::TimestampDiscovery(walk)
        }
        _ => return Err(()),
    };
    r.done()?;
    Ok(Claims {
        realm,
        namespace,
        repository,
        reference,
        writer,
        credential,
        anchor,
        publication,
        security,
        issued,
        expires,
        state,
        witness,
    })
}

#[cfg(all(test, feature = "http-objects"))]
mod tests {
    use super::*;
    fn config(seed: u8) -> HistoryTokenConfig {
        HistoryTokenConfig::new(Zeroizing::new([seed; 32]), "realm".into(), 1000)
            .expect("valid dedicated key fixture")
    }
    fn claims() -> Claims {
        Claims {
            realm: "realm".into(),
            namespace: "namespace".into(),
            repository: "repo".into(),
            reference: "refs/heads/main".into(),
            writer: false,
            credential: [0; 32],
            anchor: [1; 32],
            publication: crate::store::publication::Publication::default(),
            security: [2; 32],
            issued: 1,
            expires: 1001,
            state: ClaimState::FirstParent,
            witness: vec![WitnessNode {
                id: [1; 32],
                predecessor: None,
            }],
        }
    }
    fn id(seed: usize) -> Hash {
        let mut id = [0; 32];
        id[..8].copy_from_slice(&(seed as u64).to_le_bytes());
        id
    }
    /// A chain witness of `len` nodes: node 0 is the root.
    fn chain_witness(len: usize) -> Vec<WitnessNode> {
        (0..len)
            .map(|i| WitnessNode {
                id: id(i + 1),
                predecessor: u16::try_from(i).ok().filter(|i| *i > 0).map(|i| i - 1),
            })
            .collect()
    }
    /// Drive the reducer to 192 emitted ids with 256 keyed pending slots.
    fn full_walk() -> TimestampDiscovery {
        use mkit_core::history_order::{ParentEdge, PendingCandidate, WalkStep};
        let mut walk = TimestampDiscovery::new();
        walk.push(PendingCandidate {
            id: id(0),
            timestamp: Some(1),
        })
        .expect("a fresh walk accepts its seed");
        let mut emitted = 0usize;
        loop {
            match walk.step().expect("a keyed walk steps without refills") {
                WalkStep::Done | WalkStep::NeedTimestamp(_) => {
                    unreachable!("all edges carry keys")
                }
                WalkStep::Emit(_) => {
                    // Distinct synthetic parent ids so every insert is new;
                    // 64 3-parent emits then 127 2-parent emits reach 255
                    // pending, and a final single-parent emit peaks at 256.
                    let degree = match emitted {
                        ..64 => 3,
                        64..191 => 2,
                        _ => 1,
                    };
                    let edges: Vec<ParentEdge> = (0..degree)
                        .map(|n| ParentEdge {
                            id: id(100_000 + emitted * 3 + n),
                            timestamp: Some(1),
                            enqueue: true,
                        })
                        .collect();
                    walk.emit(&edges).expect("keyed edges fit the caps");
                    emitted += 1;
                    if emitted == 192 {
                        break;
                    }
                }
                _ => unreachable!("walk is canonical"),
            }
        }
        assert_eq!(walk.pending().len(), 256);
        walk
    }
    #[test]
    fn dedicated_history_mac_rejects_rotation_other_purposes_and_noncanonical_encodings() {
        let cfg = config(91);
        let token = cfg.mint(&claims()).unwrap();
        assert!(cfg.verify(&token).is_ok());
        assert!(config(92).verify(&token).is_err());
        for bad in [
            format!("{token}="),
            format!("{token}."),
            "=".repeat(MAX_TOKEN + 1),
        ] {
            assert!(cfg.verify(&bad).is_err());
        }
        let foreign = cfg
            .mint_purpose_test(&claims(), crate::url_token::DOMAIN)
            .unwrap();
        assert!(cfg.verify(&foreign).is_err());
        let (payload, _) = token.split_once('.').unwrap();
        let bytes = URL_SAFE_NO_PAD.decode(payload).unwrap();
        let raw_mac = blake3::keyed_hash(&[91; 32], &bytes);
        assert!(
            cfg.verify(&format!(
                "{payload}.{}",
                URL_SAFE_NO_PAD.encode(raw_mac.as_bytes())
            ))
            .is_err()
        );
        let mut oversized = claims();
        oversized.witness = chain_witness(MAX_WITNESS + 1);
        assert_eq!(
            cfg.mint(&oversized),
            Err(crate::HistoryStateLimit::TokenBytes)
        );
        assert!(!format!("{cfg:?}").contains(&mkit_core::hash::to_hex(&[91; 32])));
    }
    #[test]
    fn v1_json_tokens_are_rejected() {
        let cfg = config(91);
        // The v1 envelope: JSON claims under the v1 derived key.
        let zero = vec![0u8; 32];
        let one = vec![1u8; 32];
        let two = vec![2u8; 32];
        let payload = serde_json::json!({
            "version": 1,
            "purpose": "mkit-history-continuation:v1",
            "realm": "realm",
            "namespace": "namespace",
            "repository": "repo",
            "reference": "refs/heads/main",
            "writer": false,
            "credential": zero,
            "anchor": one.clone(),
            "publication": null,
            "security": two,
            "issued": 1,
            "expires": 1001,
            "cursor": one.clone(),
            "ancestry": vec![one],
        });
        let bytes = serde_json::to_vec(&payload).unwrap();
        let key = blake3::derive_key("mkit-history-continuation:v1", &[91; 32]);
        let mac = blake3::keyed_hash(&key, &bytes);
        let token = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(&bytes),
            URL_SAFE_NO_PAD.encode(mac.as_bytes())
        );
        assert!(cfg.verify(&token).is_err());
    }
    #[test]
    fn cap_sized_timestamp_claims_stay_bounded() {
        let realm = "r".repeat(MAX_REALM);
        let cfg = HistoryTokenConfig::new(Zeroizing::new([91; 32]), realm.clone(), 1000)
            .expect("max-length realm configures");
        let mut claims = Claims {
            realm,
            namespace: "n".repeat(MAX_NAME),
            repository: "p".repeat(MAX_NAME),
            reference: "f".repeat(MAX_NAME),
            state: ClaimState::TimestampDiscovery(full_walk()),
            witness: Vec::new(),
            ..claims()
        };
        // All 256 pending ids must be witnessed; pad the remaining witness
        // slots with children of the root to reach MAX_WITNESS.
        let pending: Vec<Hash> = match &claims.state {
            ClaimState::TimestampDiscovery(walk) => walk.pending().iter().map(|e| e.id).collect(),
            ClaimState::FirstParent => unreachable!(),
        };
        assert_eq!(pending.len(), 256);
        claims.witness = pending
            .iter()
            .enumerate()
            .map(|(i, &pid)| WitnessNode {
                id: pid,
                predecessor: if i == 0 { None } else { Some(0) },
            })
            .chain((0..MAX_WITNESS - 256).map(|i| WitnessNode {
                id: id(500_000 + i),
                predecessor: Some(0),
            }))
            .collect();
        // Every pending id must appear in the witness, so the graph is fixed;
        // fit the three scope strings into what MAX_PAYLOAD leaves.
        let mut probe = claims.clone();
        probe.namespace.clear();
        probe.repository.clear();
        probe.reference.clear();
        let room = MAX_PAYLOAD - encode(&probe, DOMAIN).unwrap().len();
        let each = (room / 3).min(MAX_NAME);
        claims.namespace = "n".repeat(each);
        claims.repository = "p".repeat(each);
        claims.reference = "f".repeat((room - 2 * each).min(MAX_NAME));
        let token = cfg.mint(&claims).unwrap();
        assert!(token.len() <= MAX_TOKEN, "{}", token.len());
        let decoded = cfg.verify(&token).unwrap();
        match decoded.state {
            ClaimState::TimestampDiscovery(mut walk) => {
                // A redeemed walk is sealed: seeding is refused.
                assert_eq!(
                    walk.push(mkit_core::history_order::PendingCandidate {
                        id: id(9_999_999),
                        timestamp: None,
                    }),
                    Err(mkit_core::history_order::HistoryOrderError::WalkStarted)
                );
            }
            ClaimState::FirstParent => panic!("order lost"),
        }
    }
    #[test]
    fn oversized_strings_and_payloads_fail_as_token_bytes() {
        let cfg = config(91);
        let mut oversized = claims();
        oversized.realm = "r".repeat(MAX_REALM + 1);
        assert_eq!(
            cfg.mint(&oversized),
            Err(crate::HistoryStateLimit::TokenBytes)
        );
        // A first-parent claim cannot reach the payload cap (it carries no
        // snapshot); the timestamp snapshot of a full state plus maximum
        // strings does.
        let mut largest = claims();
        largest.realm = "r".repeat(MAX_REALM);
        largest.namespace = "n".repeat(MAX_NAME);
        largest.repository = "p".repeat(MAX_NAME);
        largest.reference = "f".repeat(MAX_NAME);
        largest.witness = chain_witness(MAX_WITNESS);
        largest.state = ClaimState::TimestampDiscovery(full_walk());
        assert_eq!(
            cfg.mint(&largest),
            Err(crate::HistoryStateLimit::TokenBytes)
        );
    }
    #[test]
    fn history_key_files_and_cross_role_reuse_fail_closed() {
        let cfg = config(91);
        assert!(cfg.check_public_roles(&[cfg.public_key()]).is_err());
        assert!(cfg.check_public_roles(&[[91; 32]]).is_err());
        assert!(cfg.check_public_roles(&[[90; 32]]).is_ok());
        assert!(HistoryTokenConfig::new(Zeroizing::new([0; 32]), "realm".into(), 1000).is_err());
        assert!(
            HistoryTokenConfig::parse_key_file_secret(
                format!("active {}", mkit_core::hash::to_hex(&[91; 32])),
                "realm".into(),
                1000
            )
            .is_ok()
        );
        assert!(
            HistoryTokenConfig::parse_key_file_secret(
                format!(
                    "active {}\nretired {} 1",
                    mkit_core::hash::to_hex(&[91; 32]),
                    mkit_core::hash::to_hex(&[92; 32])
                ),
                "realm".into(),
                1000
            )
            .is_err()
        );
        let mut pipeline = crate::pipeline::PipelineConfig::new(
            crate::Addressing::Multi(crate::MultiAddressing::new()),
            crate::pipeline::AuthMode::Open,
            crate::upload::UploadLimits::new(1024, 1),
        );
        pipeline.ticket_keys =
            Some(crate::upload::token::TicketKeys::new(vec![("ticket".into(), [91; 32])]).unwrap());
        assert!(cfg.check_roles(&pipeline).is_err());
    }
}
