//! What the suite may assume about the server under test: its auth mode,
//! limits and capabilities. Built from flags, a TOML file, or both
//! ([`ProfileSpec`]); flags win.

use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;

use serde::Deserialize;

/// How the server authenticates transport RPCs.
#[derive(Clone, PartialEq, Eq)]
pub enum WireAuth {
    /// No authentication (`mkit-server serve --unsafe-allow-any-peer`, open deployments).
    None,
    /// `Authorization: Bearer <token>` on every transport RPC.
    Bearer {
        /// The token.
        token: String,
    },
    /// Auth v2 signed writes (SPEC-TRANSPORT-CONNECT §7.1); reads unsigned.
    AuthV2 {
        /// The server's canonical origin, byte for byte.
        audience: String,
        /// The repository identity the server is configured with.
        repository: String,
        /// Seed every case signer is derived from (see
        /// [`super::sign::Signer::derive`]).
        seed: [u8; 32],
    },
}

impl fmt::Debug for WireAuth {
    // Never print the token or the seed.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => f.write_str("None"),
            Self::Bearer { .. } => f.write_str("Bearer"),
            Self::AuthV2 {
                audience,
                repository,
                ..
            } => f
                .debug_struct("AuthV2")
                .field("audience", audience)
                .field("repository", repository)
                .finish_non_exhaustive(),
        }
    }
}

/// A per-signer write quota the server enforces, for the `quota.*` cases.
/// Declare it only for a disposable server with a tiny quota: the cases
/// exhaust it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuotaLimits {
    /// Writes allowed per window.
    pub max_ops: u32,
    /// `UploadPack` bytes allowed per window.
    pub max_bytes: u64,
    /// Window length, ms (the growth case skews past it).
    pub window_ms: i64,
}

/// The milestone a case belongs to (reconciliation R-12).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Milestone {
    /// Today's wire: no wire change.
    M0,
    /// Addressing, namespace policy, tickets.
    M1,
    /// Grants, signed reads.
    M2,
    /// Admission, outcomes.
    M3,
    /// Indexed mode, HTTP objects.
    M4,
    /// Leases, takedown, receipts, admin.
    M5,
}

impl FromStr for Milestone {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        Ok(match s.to_ascii_uppercase().as_str() {
            "M0" => Self::M0,
            "M1" => Self::M1,
            "M2" => Self::M2,
            "M3" => Self::M3,
            "M4" => Self::M4,
            "M5" => Self::M5,
            _ => return Err(format!("unknown milestone `{s}` (M0..M5)")),
        })
    }
}

/// A capability a case may require. In M0 the runner derives the set from
/// the profile; from M1 on it will come from `GetServerInfo` (WP-1.6)
/// adjusted by `--features`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Feature {
    /// Bearer-token authentication (from `--auth bearer`).
    Bearer,
    /// Auth v2 signed writes (from `--auth auth-v2`).
    AuthV2,
    /// `AdvanceRefs` commits both refs atomically.
    AtomicAdvance,
    /// A replay ledger for signed writes (implied by auth v2 in M0).
    Replay,
    /// A declared per-signer quota ([`Profile::quota`]).
    Quota,
    /// The server honors the `test-faults` request directives and serves
    /// `GET /__mkit_test/stats`.
    TestFaults,
    /// The server fires due timers on its own clock (a driver runs).
    Timers,
    /// The server serves `grpc.health.v1.Health`. No mkit spec requires
    /// it, so a profile declares it.
    Health,
    /// Opt-in: the server rejects an auth v2 signature over a gzip-encoded
    /// body. SPEC-WRITE-GRANTS §9.2 has yet to say whether `body:` commits
    /// to the encoded or the decoded bytes (the M2 spec pass, WP-2.6/2.9).
    StrictGzipAuth,
    /// Multi-repository addressing (M1).
    MultiRepo,
    /// Upload tickets and resumable parts (M1).
    Tickets,
    /// Write grants (M2).
    Grants,
    /// Signed reads and private repositories (M2).
    SignedReads,
    /// Admission challenges (M3).
    Admission,
    /// Indexed mode (M4).
    IndexedMode,
    /// Plain-HTTP object serving (M4).
    HttpObjects,
    /// Epoch leases and GC (M5).
    Leases,
    /// Takedown (M5).
    Takedown,
    /// Storage receipts (M5).
    Receipts,
    /// Admin RPCs (M5).
    Admin,
}

const FEATURE_NAMES: [(Feature, &str); 20] = [
    (Feature::Bearer, "bearer"),
    (Feature::AuthV2, "auth-v2"),
    (Feature::AtomicAdvance, "atomic-advance"),
    (Feature::Replay, "replay"),
    (Feature::Quota, "quota"),
    (Feature::TestFaults, "test-faults"),
    (Feature::Timers, "timers"),
    (Feature::Health, "health"),
    (Feature::StrictGzipAuth, "strict-gzip-auth"),
    (Feature::MultiRepo, "multi-repo"),
    (Feature::Tickets, "tickets"),
    (Feature::Grants, "grants"),
    (Feature::SignedReads, "signed-reads"),
    (Feature::Admission, "admission"),
    (Feature::IndexedMode, "indexed-mode"),
    (Feature::HttpObjects, "http-objects"),
    (Feature::Leases, "leases"),
    (Feature::Takedown, "takedown"),
    (Feature::Receipts, "receipts"),
    (Feature::Admin, "admin"),
];

impl Feature {
    /// The flag spelling, e.g. `atomic-advance`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        FEATURE_NAMES
            .iter()
            .find(|(f, _)| *f == self)
            .map_or("?", |(_, name)| name)
    }
}

impl FromStr for Feature {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        let wanted = s.trim().replace('_', "-").to_ascii_lowercase();
        FEATURE_NAMES
            .iter()
            .find(|(_, name)| *name == wanted)
            .map(|(f, _)| *f)
            .ok_or_else(|| format!("unknown feature `{s}`"))
    }
}

/// Default `list.large_response_within_limit` population.
pub const DEFAULT_LIST_REFS: u32 = 10_000;

/// Default [`Profile::replay_prune_grace_ms`]: mkit-server's grace after an
/// envelope's expiry before its replay record may be pruned.
pub const DEFAULT_REPLAY_PRUNE_GRACE_MS: i64 = 60_000;

/// Default [`Profile::duplicate_retry_ms`].
pub const DEFAULT_DUPLICATE_RETRY_MS: u64 = 10_000;

/// Everything the suite assumes about one server.
#[derive(Debug, Clone)]
pub struct Profile {
    /// How transport RPCs authenticate.
    pub auth: WireAuth,
    /// `true`: head/packmap conflicts leave both refs untouched.
    pub atomic_advance: bool,
    /// The largest pack the server accepts; the oversize case sends a
    /// header declaring one byte more.
    pub max_pack_bytes: u64,
    /// Enables the `quota.*` cases.
    pub quota: Option<QuotaLimits>,
    /// Random per run: every ref is `refs/heads/conformance/<run_id>/<case>/..`.
    pub run_id: String,
    /// The highest milestone whose cases run.
    pub milestone: Milestone,
    /// What the server offers; a case runs only if it has every feature it
    /// requires.
    pub features: BTreeSet<Feature>,
    /// Refs `list.large_response_within_limit` creates.
    pub list_refs: u32,
    /// How long after an envelope's expiry the server may keep its replay
    /// record before pruning it; the growth case waits it out. No spec
    /// fixes it (a record MUST outlive the signed expiry, §7.1).
    pub replay_prune_grace_ms: i64,
    /// How long `replay.concurrent_duplicates_all_succeed` keeps retrying a
    /// duplicate answered with the retryable `aborted`.
    pub duplicate_retry_ms: u64,
    /// Sign read RPCs too (SPEC-WRITE-GRANTS §9.2, M2). Off in M0, where
    /// reads are unsigned; the hook the M2 signed-read cases turn on.
    pub sign_reads: bool,
    /// The server started empty for this run and has no other writers, so
    /// a whole-server `ListRefs("")` is bounded by this run's own refs.
    /// Off by default: on a long-lived server such a listing grows with
    /// every run (and a unary listing has no paging before M1, WP-1.27).
    pub fresh_target: bool,
}

impl Profile {
    /// A profile for `auth` with M0 defaults: non-atomic advance, the
    /// `mkit serve` pack cap (4 GiB), no quota, a random run id, and the
    /// features `auth` implies.
    #[must_use]
    pub fn new(auth: WireAuth) -> Self {
        let mut profile = Self {
            auth,
            atomic_advance: false,
            max_pack_bytes: mkit_core::protocol::PACK_BODY_LIMIT,
            quota: None,
            run_id: random_hex::<8>(),
            milestone: Milestone::M0,
            features: BTreeSet::new(),
            list_refs: DEFAULT_LIST_REFS,
            replay_prune_grace_ms: DEFAULT_REPLAY_PRUNE_GRACE_MS,
            duplicate_retry_ms: DEFAULT_DUPLICATE_RETRY_MS,
            sign_reads: false,
            fresh_target: false,
        };
        profile.derive_features();
        profile
    }

    /// Recompute the M0 features from the fields: `Bearer`, `AuthV2` and
    /// `Replay` from the auth mode, `AtomicAdvance`, `Quota`. Features the
    /// fields cannot express (e.g. `TestFaults`) are kept.
    pub fn derive_features(&mut self) {
        let derived = [
            (
                Feature::Bearer,
                matches!(self.auth, WireAuth::Bearer { .. }),
            ),
            (
                Feature::AuthV2,
                matches!(self.auth, WireAuth::AuthV2 { .. }),
            ),
            (
                Feature::Replay,
                matches!(self.auth, WireAuth::AuthV2 { .. }),
            ),
            (Feature::AtomicAdvance, self.atomic_advance),
            (Feature::Quota, self.quota.is_some()),
        ];
        for (feature, on) in derived {
            if on {
                self.features.insert(feature);
            } else {
                self.features.remove(&feature);
            }
        }
    }

    /// Whether the server offers `feature`.
    #[must_use]
    pub fn has(&self, feature: Feature) -> bool {
        self.features.contains(&feature)
    }
}

/// `N` random bytes as lowercase hex.
pub(crate) fn random_hex<const N: usize>() -> String {
    mkit_core::hash::to_hex_bytes(&random_bytes::<N>())
}

/// `N` bytes from the OS RNG.
pub(crate) fn random_bytes<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    if let Err(e) = getrandom::fill(&mut out) {
        // No usable OS RNG: nothing in this suite can run safely.
        panic!("OS random number generator failed: {e}");
    }
    out
}

/// A partial profile, as read from TOML or flags. [`ProfileSpec::merge`]
/// layers flags over a file, [`ProfileSpec::build`] validates the result.
///
/// ```toml
/// auth = "auth-v2"            # none | bearer | auth-v2
/// audience = "http://localhost:8791"
/// repository = "default"
/// random_signer = true        # or signer_seed_env = "VAR" (or signer_seed_hex)
/// atomic_advance = true
/// max_pack_bytes = 67108864
/// milestone = "M0"
/// features = ["test-faults"]  # added to the derived set; "-name" removes one
/// ```
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileSpec {
    /// `none`, `bearer` or `auth-v2`.
    pub auth: Option<String>,
    /// The environment variable holding the bearer token (never the token
    /// itself, so it stays out of files and process listings).
    pub bearer_token_env: Option<String>,
    /// Auth v2 audience.
    pub audience: Option<String>,
    /// Auth v2 repository.
    pub repository: Option<String>,
    /// Auth v2 signer seed, 64 hex characters.
    pub signer_seed_hex: Option<String>,
    /// The environment variable holding the signer seed (64 hex), which
    /// keeps it out of files and process listings.
    pub signer_seed_env: Option<String>,
    /// Use a random auth v2 signer seed.
    pub random_signer: Option<bool>,
    /// The server commits `AdvanceRefs` atomically.
    pub atomic_advance: Option<bool>,
    /// The server's pack cap.
    pub max_pack_bytes: Option<u64>,
    /// Declared quota: writes per window.
    pub quota_ops: Option<u32>,
    /// Declared quota: bytes per window.
    pub quota_bytes: Option<u64>,
    /// Declared quota window, ms (default one hour).
    pub quota_window_ms: Option<i64>,
    /// Highest milestone to run.
    pub milestone: Option<String>,
    /// Features added to the derived set (`-name` removes one).
    pub features: Option<Vec<String>>,
    /// Fixed run id (default random).
    pub run_id: Option<String>,
    /// Refs the large-listing case creates.
    pub list_refs: Option<u32>,
    /// See [`Profile::replay_prune_grace_ms`].
    pub replay_prune_grace_ms: Option<i64>,
    /// See [`Profile::duplicate_retry_ms`].
    pub duplicate_retry_ms: Option<u64>,
    /// See [`Profile::sign_reads`].
    pub sign_reads: Option<bool>,
    /// See [`Profile::fresh_target`].
    pub fresh_target: Option<bool>,
}

impl ProfileSpec {
    /// Parse a TOML profile.
    ///
    /// # Errors
    /// Malformed TOML or an unknown key.
    pub fn from_toml(text: &str) -> Result<Self, String> {
        toml::from_str(text).map_err(|e| format!("profile: {e}"))
    }

    /// `self` with every field `over` sets replaced. The signer is one
    /// choice: if `over` names any signer source, `self`'s are dropped.
    #[must_use]
    pub fn merge(self, over: Self) -> Self {
        let over_signer = over.signer_seed_hex.is_some()
            || over.signer_seed_env.is_some()
            || over.random_signer.is_some();
        let (signer_seed_hex, signer_seed_env, random_signer) = if over_signer {
            (
                over.signer_seed_hex,
                over.signer_seed_env,
                over.random_signer,
            )
        } else {
            (
                self.signer_seed_hex,
                self.signer_seed_env,
                self.random_signer,
            )
        };
        Self {
            auth: over.auth.or(self.auth),
            bearer_token_env: over.bearer_token_env.or(self.bearer_token_env),
            audience: over.audience.or(self.audience),
            repository: over.repository.or(self.repository),
            signer_seed_hex,
            signer_seed_env,
            random_signer,
            atomic_advance: over.atomic_advance.or(self.atomic_advance),
            max_pack_bytes: over.max_pack_bytes.or(self.max_pack_bytes),
            quota_ops: over.quota_ops.or(self.quota_ops),
            quota_bytes: over.quota_bytes.or(self.quota_bytes),
            quota_window_ms: over.quota_window_ms.or(self.quota_window_ms),
            milestone: over.milestone.or(self.milestone),
            features: over.features.or(self.features),
            run_id: over.run_id.or(self.run_id),
            list_refs: over.list_refs.or(self.list_refs),
            replay_prune_grace_ms: over.replay_prune_grace_ms.or(self.replay_prune_grace_ms),
            duplicate_retry_ms: over.duplicate_retry_ms.or(self.duplicate_retry_ms),
            sign_reads: over.sign_reads.or(self.sign_reads),
            fresh_target: over.fresh_target.or(self.fresh_target),
        }
    }

    /// The profile this spec describes; `env` looks up environment
    /// variables (the bearer token, the signer seed).
    ///
    /// # Errors
    /// A missing or inconsistent field.
    pub fn build(self, env: impl Fn(&str) -> Option<String>) -> Result<Profile, String> {
        let auth = match self.auth.as_deref().unwrap_or("none") {
            "none" => WireAuth::None,
            "bearer" => {
                let var = self
                    .bearer_token_env
                    .ok_or("--auth bearer needs --bearer-token-env VAR")?;
                let token = env(&var).ok_or_else(|| format!("${var} is not set"))?;
                WireAuth::Bearer { token }
            }
            "auth-v2" => {
                let audience = self.audience.ok_or("--auth auth-v2 needs --audience")?;
                mkit_core::write_auth::validate_audience(&audience)
                    .map_err(|e| format!("--audience {audience}: {e}"))?;
                let repository = self.repository.ok_or("--auth auth-v2 needs --repository")?;
                let random = self.random_signer.unwrap_or(false);
                let seed = match (self.signer_seed_hex, self.signer_seed_env, random) {
                    (Some(hex), None, false) => mkit_core::hash::from_hex(&hex)
                        .map_err(|_| "--signer-seed-hex needs 64 hex characters".to_owned())?,
                    (None, Some(var), false) => {
                        let hex = env(&var).ok_or_else(|| format!("${var} is not set"))?;
                        mkit_core::hash::from_hex(hex.trim())
                            .map_err(|_| format!("${var} needs 64 hex characters"))?
                    }
                    (None, None, true) => random_bytes::<32>(),
                    _ => {
                        return Err("--auth auth-v2 needs exactly one of --signer-seed-env, \
                             --signer-seed-hex, --random-signer"
                            .to_owned());
                    }
                };
                WireAuth::AuthV2 {
                    audience,
                    repository,
                    seed,
                }
            }
            other => return Err(format!("unknown auth mode `{other}` (none|bearer|auth-v2)")),
        };
        let mut profile = Profile::new(auth);
        profile.atomic_advance = self.atomic_advance.unwrap_or(false);
        if let Some(max) = self.max_pack_bytes {
            profile.max_pack_bytes = max;
        }
        profile.quota = match (self.quota_ops, self.quota_bytes) {
            (None, None) => None,
            (Some(max_ops), Some(max_bytes)) => Some(QuotaLimits {
                max_ops,
                max_bytes,
                window_ms: self.quota_window_ms.unwrap_or(3_600_000),
            }),
            _ => return Err("--quota-ops and --quota-bytes go together".to_owned()),
        };
        if let Some(m) = self.milestone {
            profile.milestone = m.parse()?;
        }
        if let Some(run_id) = self.run_id {
            let valid = !run_id.is_empty()
                && run_id.len() <= 32
                && run_id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-');
            if !valid {
                return Err("--run-id: 1 to 32 of [A-Za-z0-9-]".to_owned());
            }
            profile.run_id = run_id;
        }
        if let Some(n) = self.list_refs {
            profile.list_refs = n;
        }
        if let Some(ms) = self.replay_prune_grace_ms {
            profile.replay_prune_grace_ms = ms;
        }
        if let Some(ms) = self.duplicate_retry_ms {
            profile.duplicate_retry_ms = ms;
        }
        profile.sign_reads = self.sign_reads.unwrap_or(false);
        profile.fresh_target = self.fresh_target.unwrap_or(false);
        profile.derive_features();
        // `name` adds a feature to the derived set, `-name` removes one.
        for entry in self.features.unwrap_or_default() {
            match entry.strip_prefix('-') {
                Some(name) => profile.features.remove(&name.parse()?),
                None => profile.features.insert(entry.parse()?),
            };
        }
        Ok(profile)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn toml_and_flags_merge_flags_win() {
        let file = ProfileSpec::from_toml(
            "auth = \"auth-v2\"\naudience = \"http://localhost:8791\"\nrepository = \"a\"\n\
             random_signer = true\natomic_advance = true\nmax_pack_bytes = 10\n",
        )
        .unwrap();
        let flags = ProfileSpec {
            repository: Some("b".into()),
            ..ProfileSpec::default()
        };
        let p = file.merge(flags).build(|_| None).unwrap();
        let WireAuth::AuthV2 { repository, .. } = &p.auth else {
            panic!("{:?}", p.auth);
        };
        assert_eq!(repository, "b");
        assert_eq!(p.max_pack_bytes, 10);
        for f in [Feature::AuthV2, Feature::Replay, Feature::AtomicAdvance] {
            assert!(p.has(f), "{f:?}");
        }
        assert!(!p.has(Feature::Quota));
    }

    #[test]
    fn invalid_specs_are_refused() {
        let bad = [
            "auth = \"bearer\"\nbearer_token_env = \"NOPE\"",
            "auth = \"auth-v2\"\naudience = \"http://x.test/\"\nrepository = \"r\"\nrandom_signer = true",
            "auth = \"auth-v2\"\naudience = \"http://x.test\"\nrepository = \"r\"",
            "quota_ops = 3",
            "milestone = \"M9\"",
            "features = [\"warp-drive\"]",
            "unknown_key = 1",
        ];
        for text in bad {
            let built = ProfileSpec::from_toml(text).and_then(|s| s.build(|_| None));
            assert!(built.is_err(), "{text}");
        }
    }

    #[test]
    fn flags_override_the_file_signer_and_seeds_come_from_env() {
        let file = ProfileSpec::from_toml(
            "auth = \"auth-v2\"\naudience = \"http://localhost:1\"\nrepository = \"r\"\n\
             random_signer = true",
        )
        .unwrap();
        let flags = ProfileSpec {
            signer_seed_env: Some("SEED".into()),
            ..ProfileSpec::default()
        };
        let seed = "ab".repeat(32);
        let p = file
            .merge(flags)
            .build(|v| (v == "SEED").then(|| seed.clone()))
            .unwrap();
        let WireAuth::AuthV2 { seed: got, .. } = p.auth else {
            panic!("{:?}", p.auth);
        };
        assert_eq!(got, [0xab; 32]);
    }

    #[test]
    fn features_add_to_and_remove_from_the_derived_set() {
        let spec = ProfileSpec::from_toml(
            "auth = \"auth-v2\"\naudience = \"http://localhost:1\"\nrepository = \"r\"\n\
             random_signer = true\nfeatures = [\"test-faults\", \"-replay\"]",
        )
        .unwrap();
        let p = spec.build(|_| None).unwrap();
        assert!(p.has(Feature::AuthV2) && p.has(Feature::TestFaults));
        assert!(!p.has(Feature::Replay));
    }

    #[test]
    fn debug_hides_secrets() {
        let auth = WireAuth::Bearer {
            token: "s3cret".into(),
        };
        assert!(!format!("{auth:?}").contains("s3cret"));
    }

    #[test]
    fn feature_names_round_trip() {
        for (feature, name) in FEATURE_NAMES {
            assert_eq!(name.parse::<Feature>().unwrap(), feature);
            assert_eq!(feature.as_str(), name);
        }
    }
}
