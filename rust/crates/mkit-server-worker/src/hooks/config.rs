//! The hook vars (WP-3.9). The service binding is named [`BINDING`]; which
//! stages call it is `HOOK_ROLES`, with no default, because a hook Worker may
//! implement any subset (the 3.14 reference Worker answers only Admit and
//! Outcome).

use core::time::Duration;

use mkit_server::policy::AuthorizerRole;

use crate::adapter::ConfigError;

/// The service binding to the hook Worker.
pub const BINDING: &str = "ADMISSION_HOOK";
/// `HOOK_ROLES`: a comma list of `authorize`, `admit` and `outcome`.
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HookRoles {
    /// Stage 2 over `Authorize`.
    pub authorize: bool,
    /// Stage 3 over `Admit`.
    pub admit: bool,
    /// Stage 8 over `Outcome` (kind-8 delivery).
    pub outcome: bool,
}

/// The parsed hook vars.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HookVars {
    /// The stages that are remote.
    pub roles: HookRoles,
    /// The bound on one call (`HOOK_TIMEOUT_MS`).
    pub timeout: Duration,
    /// `AUTHORIZER_ROLE`.
    pub authorizer_role: AuthorizerRole,
}

fn config(message: impl Into<String>) -> ConfigError {
    ConfigError(message.into())
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
        let Some(list) = var(ROLES_VAR) else {
            if var(TIMEOUT_VAR).is_some() || var(AUTHORIZER_ROLE_VAR).is_some() {
                return Err(config(format!(
                    "{TIMEOUT_VAR} and {AUTHORIZER_ROLE_VAR} need {ROLES_VAR}"
                )));
            }
            return Ok(None);
        };
        let mut roles = HookRoles {
            authorize: false,
            admit: false,
            outcome: false,
        };
        for name in list.split(',').map(str::trim) {
            let slot = match name {
                "authorize" => &mut roles.authorize,
                "admit" => &mut roles.admit,
                "outcome" => &mut roles.outcome,
                _ => {
                    return Err(config(format!(
                        "{ROLES_VAR} must list authorize, admit and outcome, comma separated"
                    )));
                }
            };
            if *slot {
                return Err(config(format!("{ROLES_VAR} repeats {name}")));
            }
            *slot = true;
        }
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
        }))
    }

    /// Check the vars against the binding: roles without a binding, and a
    /// binding without roles, are both refused, so the hook stages a
    /// deployment expects are never silently absent.
    ///
    /// # Errors
    /// Either half without the other.
    pub fn check_binding(vars: Option<&Self>, binding_present: bool) -> Result<(), ConfigError> {
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
                outcome: true
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
            "inspect",
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
