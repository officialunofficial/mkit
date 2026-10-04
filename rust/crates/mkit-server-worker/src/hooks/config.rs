//! The hook vars (WP-3.9). The service binding is named [`BINDING`]; which
//! stages call it is `HOOK_ROLES`, with no default, because a hook Worker may
//! implement any subset (the 3.14 reference Worker answers only Admit and
//! Outcome).

use core::time::Duration;

use mkit_server::policy::AuthorizerRole;

use crate::adapter::ConfigError;

/// The service binding to the hook Worker.
pub const BINDING: &str = "ADMISSION_HOOK";
/// `HOOK_ROLES`: comma-separated `authorize`, `admit`, `outcome`, `cache-purge`, `inspect`.
pub const ROLES_VAR: &str = "HOOK_ROLES";
/// `HOOK_TIMEOUT_MS`: the bound on one hook call.
pub const TIMEOUT_VAR: &str = "HOOK_TIMEOUT_MS";
/// `AUTHORIZER_ROLE`: `check` (default) or `authority`.
pub const AUTHORIZER_ROLE_VAR: &str = "AUTHORIZER_ROLE";
/// The default per-call timeout (SPEC-SERVER §8, informative).
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
/// The longest `HOOK_TIMEOUT_MS`, in milliseconds. Delivery (kind 8) is always
/// bounded by [`crate::adapter::OUTCOME_SINK_TIMEOUT`] as well.
pub const MAX_TIMEOUT_MS: u64 = 30_000;

/// Which stages call the hook Worker.
// Protocol roles are independently selectable, including purge-only sinks.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct HookRoles {
    /// Stage 2 over `Authorize`.
    pub authorize: bool,
    /// Stage 3 over `Admit`.
    pub admit: bool,
    /// Stage 8 over `Outcome` (kind-8 delivery).
    pub outcome: bool,
    /// Signed global cache invalidation (Paid-only).
    pub cache_purge: bool,
    /// Stage 5 synchronous fail-closed Inspect.
    pub inspect: bool,
}

/// The parsed hook vars.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct HookVars {
    /// The stages that are remote.
    pub roles: HookRoles,
    /// The bound on one call (`HOOK_TIMEOUT_MS`).
    pub timeout: Duration,
    /// `AUTHORIZER_ROLE`.
    pub authorizer_role: AuthorizerRole,
    /// Signed HTTPS channel; absent uses the service binding.
    pub http: Option<HttpVars>,
    /// Maximum metadata objects per Inspect call.
    pub inspect_batch_max_objects: usize,
}

fn config(message: impl Into<String>) -> ConfigError {
    ConfigError(message.into())
}

fn parse_inspection(
    enabled: bool,
    var: &impl Fn(&str) -> Option<String>,
) -> Result<usize, ConfigError> {
    let inspection_vars = [
        "INSPECT_MODE",
        "INSPECT_ON_UNAVAILABLE",
        "INSPECT_BATCH_MAX_OBJECTS",
    ];
    if !enabled && inspection_vars.iter().any(|name| var(name).is_some()) {
        return Err(config("inspection options need inspect in HOOK_ROLES"));
    }
    if var("INSPECT_MODE").is_some_and(|v| v != "sync")
        || var("INSPECT_ON_UNAVAILABLE").is_some_and(|v| v != "fail_closed")
    {
        return Err(config("launch inspection requires sync and fail_closed"));
    }
    let inspect_batch_max_objects = var("INSPECT_BATCH_MAX_OBJECTS").map_or(Ok(10_000), |v| {
        v.parse::<usize>()
            .ok()
            .filter(|n| (1..=10_000).contains(n))
            .ok_or_else(|| config("INSPECT_BATCH_MAX_OBJECTS must be 1..=10000"))
    })?;
    Ok(inspect_batch_max_objects)
}

impl HookVars {
    /// The hook vars of `var`; `None` when none is set (no remote hooks).
    ///
    /// # Errors
    /// A role list that is empty, has an unknown or repeated role;
    /// `HOOK_TIMEOUT_MS` outside 1..=30000; an unknown `AUTHORIZER_ROLE`;
    /// `AUTHORIZER_ROLE` without the `authorize` role; or a timeout or
    /// authorizer role set without `HOOK_ROLES`.
    pub fn parse(var: &impl Fn(&str) -> Option<String>) -> Result<Option<Self>, ConfigError> {
        let http = HttpVars::parse(var)?;
        let Some(list) = var(ROLES_VAR) else {
            if http.is_some() {
                return Err(config("HOOK_URL needs HOOK_ROLES"));
            }
            if [
                TIMEOUT_VAR,
                AUTHORIZER_ROLE_VAR,
                "INSPECT_MODE",
                "INSPECT_ON_UNAVAILABLE",
                "INSPECT_BATCH_MAX_OBJECTS",
            ]
            .iter()
            .any(|name| var(name).is_some())
            {
                return Err(config(format!(
                    "{TIMEOUT_VAR} and {AUTHORIZER_ROLE_VAR} need {ROLES_VAR}"
                )));
            }
            return Ok(None);
        };
        let mut roles = HookRoles::default();
        for name in list.split(',').map(str::trim) {
            let slot = match name {
                "authorize" => &mut roles.authorize,
                "admit" => &mut roles.admit,
                "outcome" => &mut roles.outcome,
                "cache-purge" => &mut roles.cache_purge,
                "inspect" => &mut roles.inspect,
                _ => {
                    return Err(config(format!(
                        "{ROLES_VAR} must list authorize, admit, outcome, cache-purge and inspect, comma separated"
                    )));
                }
            };
            if *slot {
                return Err(config(format!("{ROLES_VAR} repeats {name}")));
            }
            *slot = true;
        }
        if roles.cache_purge && http.is_none() {
            return Err(config("cache-purge requires signed HTTPS HOOK_URL"));
        }
        let inspect_batch_max_objects = parse_inspection(roles.inspect, var)?;
        let timeout = match var(TIMEOUT_VAR) {
            None => DEFAULT_TIMEOUT,
            Some(text) => text
                .parse::<u64>()
                .ok()
                .filter(|ms| (1..=MAX_TIMEOUT_MS).contains(ms))
                .map(Duration::from_millis)
                .ok_or_else(|| config(format!("{TIMEOUT_VAR} must be 1..=30000")))?,
        };
        let authorizer_role = match var(AUTHORIZER_ROLE_VAR).as_deref() {
            None | Some("check") => AuthorizerRole::Check,
            Some("authority") => AuthorizerRole::Authority,
            Some(_) => {
                return Err(config(format!(
                    "{AUTHORIZER_ROLE_VAR} must be check or authority"
                )));
            }
        };
        if !roles.authorize && var(AUTHORIZER_ROLE_VAR).is_some() {
            return Err(config(format!(
                "{AUTHORIZER_ROLE_VAR} needs the authorize role in {ROLES_VAR}"
            )));
        }
        Ok(Some(Self {
            roles,
            timeout,
            authorizer_role,
            http,
            inspect_batch_max_objects,
        }))
    }

    /// Check the vars against the binding: roles without a binding, and a
    /// binding without roles, are both refused, so the hook stages a
    /// deployment expects are never silently absent.
    ///
    /// # Errors
    /// Either half without the other.
    pub fn check_binding(vars: Option<&Self>, binding_present: bool) -> Result<(), ConfigError> {
        if vars.is_some_and(|v| v.http.is_some()) {
            return if binding_present {
                Err(config("HOOK_URL and ADMISSION_HOOK are mutually exclusive"))
            } else {
                Ok(())
            };
        }
        match (vars, binding_present) {
            (Some(_), false) => Err(config(format!(
                "{ROLES_VAR} is set but the {BINDING} service binding is not configured"
            ))),
            (None, true) => Err(config(format!(
                "the {BINDING} service binding is configured but {ROLES_VAR} is not set"
            ))),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(pairs: &[(&str, &str)]) -> Result<Option<HookVars>, ConfigError> {
        HookVars::parse(&|name: &str| {
            pairs
                .iter()
                .find(|(n, _)| *n == name)
                .map(|(_, v)| (*v).to_owned())
        })
    }

    #[test]
    fn no_vars_mean_no_remote_hooks() {
        assert_eq!(parse(&[]).unwrap(), None);
    }

    #[test]
    fn roles_parse_with_defaults() {
        let vars = parse(&[("HOOK_ROLES", "admit, outcome")]).unwrap().unwrap();
        assert_eq!(
            vars.roles,
            HookRoles {
                authorize: false,
                admit: true,
                outcome: true,
                cache_purge: false,
                inspect: false
            }
        );
        assert_eq!(vars.timeout, DEFAULT_TIMEOUT);
        assert_eq!(vars.authorizer_role, AuthorizerRole::Check);
        let all = parse(&[("HOOK_ROLES", "authorize,admit,outcome")])
            .unwrap()
            .unwrap();
        assert!(all.roles.authorize && all.roles.admit && all.roles.outcome);
    }

    #[test]
    fn roles_are_required_and_strict() {
        for bad in [
            "",
            " ",
            "admit,",
            "admit,,outcome",
            "inspect,inspect",
            "Admit",
            "admit;outcome",
            "admit,admit",
        ] {
            let err = parse(&[("HOOK_ROLES", bad)]).unwrap_err();
            assert!(err.0.contains("HOOK_ROLES"), "{bad:?}: {err}");
        }
        // The other vars mean nothing without the roles.
        for var in ["HOOK_TIMEOUT_MS", "AUTHORIZER_ROLE"] {
            let err = parse(&[(var, "5")]).unwrap_err();
            assert!(err.0.contains("HOOK_ROLES"), "{var}: {err}");
        }
    }

    #[test]
    fn the_timeout_is_bounded() {
        let ok = |value: &str| parse(&[("HOOK_ROLES", "admit"), ("HOOK_TIMEOUT_MS", value)]);
        assert_eq!(ok("1").unwrap().unwrap().timeout, Duration::from_millis(1));
        assert_eq!(
            ok("30000").unwrap().unwrap().timeout,
            Duration::from_secs(30)
        );
        for bad in ["0", "30001", "-1", "5s", "", "1.5"] {
            assert!(ok(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn the_authorizer_role_needs_the_authorize_role() {
        let vars = parse(&[
            ("HOOK_ROLES", "authorize"),
            ("AUTHORIZER_ROLE", "authority"),
        ])
        .unwrap()
        .unwrap();
        assert_eq!(vars.authorizer_role, AuthorizerRole::Authority);
        assert!(parse(&[("HOOK_ROLES", "admit"), ("AUTHORIZER_ROLE", "authority")]).is_err());
        assert!(parse(&[("HOOK_ROLES", "authorize"), ("AUTHORIZER_ROLE", "root")]).is_err());
        let check = parse(&[("HOOK_ROLES", "authorize"), ("AUTHORIZER_ROLE", "check")])
            .unwrap()
            .unwrap();
        assert_eq!(check.authorizer_role, AuthorizerRole::Check);
    }

    #[test]
    fn the_binding_and_the_roles_come_together() {
        let vars = parse(&[("HOOK_ROLES", "admit")]).unwrap();
        assert!(HookVars::check_binding(vars.as_ref(), true).is_ok());
        assert!(HookVars::check_binding(None, false).is_ok());
        let err = HookVars::check_binding(vars.as_ref(), false).unwrap_err();
        assert!(err.0.contains(BINDING), "{err}");
        let err = HookVars::check_binding(None, true).unwrap_err();
        assert!(err.0.contains(ROLES_VAR), "{err}");
    }
}

/// Validated HTTP channel configuration. Debug redacts the endpoint path.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct HttpVars {
    /// Endpoint, including an optional path prefix.
    pub endpoint: super::fetch::Endpoint,
    /// Signed request lifetime, independently bounded from the call timeout.
    pub validity: Duration,
}

impl HttpVars {
    /// Construct explicit deployment settings; fields may be adjusted before use.
    #[must_use]
    pub fn new(endpoint: super::fetch::Endpoint, validity: Duration) -> Self {
        Self { endpoint, validity }
    }
}

impl HttpVars {
    fn parse(var: &impl Fn(&str) -> Option<String>) -> Result<Option<Self>, ConfigError> {
        let Some(url) = var("HOOK_URL") else {
            if var("HOOK_SIGNATURE_VALIDITY_MS").is_some() {
                return Err(config("HOOK_SIGNATURE_VALIDITY_MS needs HOOK_URL"));
            }
            return Ok(None);
        };
        if !cfg!(feature = "signed-http-hooks") {
            return Err(config("HOOK_URL requires signed-http-hooks (Stage 2)"));
        }
        let validity = var("HOOK_SIGNATURE_VALIDITY_MS").map_or(Ok(60_000), |text| {
            text.parse::<u64>()
                .ok()
                .filter(|ms| (1..=300_000).contains(ms))
                .ok_or_else(|| config("HOOK_SIGNATURE_VALIDITY_MS must be 1..=300000"))
        })?;
        Ok(Some(Self {
            endpoint: super::fetch::Endpoint::new(&url)?,
            validity: Duration::from_millis(validity),
        }))
    }
}

/// Parse the native key grammar, wiping the input and decoded seed on drop.
///
/// # Errors
/// A missing or malformed key, or reuse of any accepted ticket secret.
pub fn http_signer(
    text: Option<String>,
    vars: &HttpVars,
    tickets: Option<&mkit_server::upload::token::TicketKeys>,
    other_keys: &[[u8; 32]],
) -> Result<mkit_server::hooks::HookSigner, ConfigError> {
    use mkit_core::hash::from_hex;
    use mkit_server::hooks::HookSigner;
    use zeroize::Zeroizing;
    let text = Zeroizing::new(text.ok_or_else(|| config("HOOK_URL needs MKIT_HOOK_KEY secret"))?);
    let bad = || config("MKIT_HOOK_KEY must be one line `<key-id> <64 hex seed>`");
    let mut lines = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'));
    let line = lines.next().ok_or_else(bad)?;
    if lines.next().is_some() {
        return Err(bad());
    }
    let mut fields = line.split_whitespace();
    let id = fields.next().ok_or_else(bad)?;
    let seed = Zeroizing::new(from_hex(fields.next().ok_or_else(bad)?).map_err(|_| bad())?);
    if fields.next().is_some() {
        return Err(bad());
    }
    if tickets.is_some_and(|keys| keys.contains_secret(&seed)) {
        return Err(config(
            "hook key must differ from every accepted ticket secret",
        ));
    }
    if other_keys.contains(&*seed) {
        return Err(config(
            "hook key must differ from other configured role keys",
        ));
    }
    let signer = HookSigner::new(id, seed)
        .and_then(|s| s.with_validity(vars.validity))
        .map_err(|_| bad())?;
    if tickets.is_some_and(|keys| keys.contains_ed25519_public(&signer.public_key())) {
        return Err(config(
            "hook public key must differ from ticket secret material",
        ));
    }
    if other_keys.contains(&signer.public_key()) {
        return Err(config(
            "hook key must differ from other configured role keys",
        ));
    }
    Ok(signer)
}

#[cfg(test)]
mod http_tests {
    use super::*;
    use mkit_server::hooks::{HookVerifier, VerifierKey};
    use mkit_server::upload::token::TicketKeys;

    fn vars() -> HttpVars {
        HttpVars::new(
            super::super::fetch::Endpoint::new("https://hooks.example/prefix").unwrap(),
            Duration::from_mins(1),
        )
    }
    fn parse(pairs: &[(&str, &str)]) -> Result<Option<HookVars>, ConfigError> {
        HookVars::parse(&|name| {
            pairs
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| value.to_string())
        })
    }
    #[test]
    fn key_grammar_redaction_and_all_ticket_keys() {
        let vars = vars();
        for text in [
            "",
            "secret",
            "id secret",
            "id 00 extra",
            "id 00\nid 00",
            "bad/id 0000000000000000000000000000000000000000000000000000000000000000",
        ] {
            let err = http_signer(Some(text.into()), &vars, None, &[]).unwrap_err();
            assert!(!err.0.contains("secret"));
        }
        assert!(http_signer(None, &vars, None, &[]).is_err());
        let text = format!("# comment\nkey-1 {}\n", "19".repeat(32));
        let tickets = TicketKeys::new(vec![
            ("active".into(), [1; 32]),
            ("retired".into(), [0x19; 32]),
        ])
        .unwrap();
        assert!(http_signer(Some(text.clone()), &vars, Some(&tickets), &[]).is_err());
        let public = http_signer(Some(text.clone()), &vars, None, &[])
            .unwrap()
            .public_key();
        assert!(http_signer(Some(text), &vars, None, &[public]).is_err());
    }
    #[test]
    fn signed_exact_bytes_verify_for_endpoint_origin() {
        let vars = vars();
        let signer =
            http_signer(Some(format!("key {}", "17".repeat(32))), &vars, None, &[]).unwrap();
        let verifier = HookVerifier::new(
            vars.endpoint.origin(),
            vec![VerifierKey::new("key", signer.public_key())],
            || 100_000,
        )
        .with_replay_protection();
        let procedure = "/mkit.server.hooks.v1.HooksService/Admit";
        let body =
            br#"{ "credentialHeaders": [{"name":"Payment-Authorization","value":"opaque"}] }"#;
        let headers = signer
            .headers(vars.endpoint.origin(), procedure, body, 100_000, &[9; 32])
            .unwrap();
        let headers = headers
            .iter()
            .map(|(n, v)| (*n, v.as_str()))
            .collect::<Vec<_>>();
        verifier.verify(procedure, &headers, body).unwrap();
        assert!(verifier.verify(procedure, &headers, body).is_err());
        assert!(verifier.verify(procedure, &headers, b"{}").is_err());
    }

    #[test]
    fn hook_seed_cannot_be_another_roles_published_public_key() {
        let public =
            mkit_server::hooks::HookSigner::new("token", zeroize::Zeroizing::new([34; 32]))
                .unwrap()
                .public_key();
        let text = format!("hook {}", mkit_core::hash::to_hex(&public));
        assert!(
            http_signer(Some(text), &vars(), None, &[public]).is_err(),
            "published role bytes would disclose the hook signing seed"
        );
    }
    #[test]
    fn http_configuration_is_complete_and_validity_bounded() {
        assert!(parse(&[("HOOK_SIGNATURE_VALIDITY_MS", "1")]).is_err());
        assert!(parse(&[("HOOK_URL", "https://hooks.example")]).is_err());
        for value in ["0", "300001", "-1", ""] {
            assert!(
                parse(&[
                    ("HOOK_URL", "https://hooks.example"),
                    ("HOOK_ROLES", "admit"),
                    ("HOOK_SIGNATURE_VALIDITY_MS", value)
                ])
                .is_err()
            );
        }
        let parsed = parse(&[
            ("HOOK_URL", "https://hooks.example"),
            ("HOOK_ROLES", "admit"),
        ]);
        if cfg!(feature = "signed-http-hooks") {
            assert_eq!(
                parsed.unwrap().unwrap().http.unwrap().validity,
                Duration::from_mins(1)
            );
        } else {
            assert!(parsed.is_err());
        }
    }
}

#[cfg(test)]
mod purge_tests {
    use super::*;
    #[test]
    fn purge_only_is_signed_and_never_activates_other_roles() {
        let var = |name: &str| match name {
            "HOOK_ROLES" => Some("cache-purge".into()),
            "HOOK_URL" => Some("https://hooks.example/prefix".into()),
            _ => None,
        };
        let parsed = HookVars::parse(&var);
        if cfg!(feature = "signed-http-hooks") {
            let roles = parsed.unwrap().unwrap().roles;
            assert!(roles.cache_purge);
            assert!(!roles.authorize && !roles.admit && !roles.outcome);
        } else {
            assert!(parsed.is_err());
        }
        assert!(
            HookVars::parse(&|name| (name == "HOOK_ROLES").then(|| "cache-purge".into())).is_err()
        );
    }
}

#[cfg(test)]
mod inspection_tests {
    use super::*;

    fn parse(extra: &[(&str, &str)]) -> Result<Option<HookVars>, ConfigError> {
        HookVars::parse(&|name| {
            if name == ROLES_VAR {
                return Some("inspect".into());
            }
            extra
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| (*value).into())
        })
    }

    #[test]
    fn launch_inspection_configuration_is_strict_and_bounded() {
        let vars = parse(&[]).unwrap().unwrap();
        assert!(vars.roles.inspect);
        assert_eq!(vars.inspect_batch_max_objects, 10_000);
        assert_eq!(
            parse(&[("INSPECT_BATCH_MAX_OBJECTS", "1")])
                .unwrap()
                .unwrap()
                .inspect_batch_max_objects,
            1
        );
        for pair in [
            ("INSPECT_MODE", "async"),
            ("INSPECT_ON_UNAVAILABLE", "publish"),
            ("INSPECT_BATCH_MAX_OBJECTS", "0"),
            ("INSPECT_BATCH_MAX_OBJECTS", "10001"),
        ] {
            assert!(parse(&[pair]).is_err());
        }
        assert!(HookVars::parse(&|name| (name == "INSPECT_MODE").then(|| "sync".into())).is_err());
    }
}
