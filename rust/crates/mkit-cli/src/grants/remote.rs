//! Picking the remote a grant, epoch or visibility command talks to, the
//! audience it signs for, and waiting for the server to finish (WP-2.14).

use std::time::Duration;

use mkit_attest::grant::{Namespace, is_loopback_origin};
use mkit_core::repo_identity::RepositoryIdentity;
use mkit_transport_connect::{Completion, audience_from_url, repository_identity_from_url};

use crate::config::{self, LayeredConfig};

/// A Connect remote resolved from a remote name or an `mkit+https://` URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub name: String,
    pub endpoint: String,
    /// The repository config chose it, so the credential-trust gate applies.
    pub repo_chosen: bool,
}

impl Target {
    /// The auth v2 audience for this remote: its origin.
    ///
    /// # Errors
    /// The endpoint is not an `mkit+https://` or loopback `mkit+http://` URL.
    pub fn audience(&self) -> Result<String, String> {
        audience_from_url(&self.endpoint).ok_or_else(|| {
            format!(
                "`{}` is not an mkit+https:// (or loopback mkit+http://) remote",
                self.endpoint
            )
        })
    }

    /// The repository the URL names, if it names a full `<namespace>/<name>`.
    #[must_use]
    pub fn repository(&self) -> Option<RepositoryIdentity> {
        repository_identity_from_url(&self.endpoint)
            .ok()
            .filter(|id| id.namespace().is_some())
    }

    /// The namespace in the URL's repository, if any.
    #[must_use]
    pub fn namespace(&self) -> Option<Namespace> {
        self.repository().and_then(|id| id.namespace().copied())
    }

    /// Whether this is a loopback `mkit+http://` remote: the one place a
    /// loopback audience is acceptable (a development server).
    #[must_use]
    pub fn is_loopback_dev(&self) -> bool {
        self.endpoint.starts_with("mkit+http://")
            && self.audience().is_ok_and(|a| is_loopback_origin(&a))
    }
}

/// Resolve `arg` as a remote name, or take it as a URL if it starts with
/// `mkit+`. With no `arg`, the user's `trusted_remote_endpoint`.
///
/// # Errors
/// An unknown remote, or nothing to fall back on.
pub fn resolve_target(cfg: &LayeredConfig, arg: Option<&str>) -> Result<Target, String> {
    match arg {
        Some(url) if url.starts_with("mkit+") => Ok(Target {
            name: url.to_owned(),
            endpoint: url.to_owned(),
            repo_chosen: false,
        }),
        Some(name) => {
            let resolved = config::resolve_remote(cfg, name).ok_or_else(|| {
                format!("no remote named `{name}` (add one with `mkit remote add`, or pass an mkit+https:// URL)")
            })?;
            Ok(Target {
                name: resolved.name,
                endpoint: resolved.endpoint,
                repo_chosen: resolved.repo_chosen,
            })
        }
        None => {
            let trusted = cfg.user.trusted_remote_endpoint.trim();
            if trusted.is_empty() {
                return Err(
                    "no remote given and no trusted remote configured (set one with `mkit config trusted_remote_endpoint <url>`)"
                        .to_owned(),
                );
            }
            Ok(Target {
                name: "trusted".to_owned(),
                endpoint: trusted.to_owned(),
                repo_chosen: false,
            })
        }
    }
}

/// SPEC-WRITE-GRANTS §3.2: a loopback audience is refused unless the remote
/// itself is a loopback `mkit+http://` development remote. Every local
/// deployment shares a loopback audience, so a statement signed for one
/// would verify at all of them.
///
/// # Errors
/// A loopback audience and a remote that isn't a loopback dev remote.
pub fn check_audiences(audiences: &[String], remote: Option<&Target>) -> Result<(), String> {
    for audience in audiences {
        if is_loopback_origin(audience) && !remote.is_some_and(Target::is_loopback_dev) {
            return Err(format!(
                "audience {audience} is a loopback address, which every local server shares; \
                 refusing to sign for it unless the remote is itself a loopback mkit+http:// development remote"
            ));
        }
    }
    Ok(())
}

/// How [`drive`] ended.
#[derive(Debug, PartialEq, Eq)]
pub enum Driven<T> {
    Done(T),
    /// The next wait would pass `timeout`; `waited` was spent.
    TimedOut {
        waited: Duration,
    },
    /// `sleep` returned false (Ctrl-C).
    Cancelled,
}

/// Call `call` until it is [`Completion::Done`], waiting the server's
/// `Retry-After` between calls. `call` sends the same request every time: the
/// caller signs once and re-sends the identical statement bytes (SPEC-WRITE-GRANTS
/// §5.2: the same epoch is a retry), never a fresh nonce. The wait is bounded
/// by `timeout`, counted as time spent sleeping, and `sleep` may cancel.
///
/// # Errors
/// Whatever `call` returns.
pub fn drive<T, E>(
    mut call: impl FnMut() -> Result<Completion<T>, E>,
    timeout: Duration,
    mut sleep: impl FnMut(Duration) -> bool,
) -> Result<Driven<T>, E> {
    let mut waited = Duration::ZERO;
    loop {
        match call()? {
            Completion::Done(value) => return Ok(Driven::Done(value)),
            Completion::Pending { retry_after } => {
                if waited.saturating_add(retry_after) > timeout {
                    return Ok(Driven::TimedOut { waited });
                }
                if !sleep(retry_after) {
                    return Ok(Driven::Cancelled);
                }
                waited += retry_after;
            }
        }
    }
}

/// Sleep for `duration` in short slices so Ctrl-C is prompt. Returns false if
/// the process was asked to shut down.
#[must_use]
pub fn interruptible_sleep(duration: Duration) -> bool {
    let slice = Duration::from_millis(100);
    let mut left = duration;
    while !left.is_zero() {
        if crate::signal::is_shutdown() {
            return false;
        }
        let step = left.min(slice);
        std::thread::sleep(step);
        left -= step;
    }
    !crate::signal::is_shutdown()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(url: &str) -> Target {
        Target {
            name: "t".into(),
            endpoint: url.into(),
            repo_chosen: false,
        }
    }

    #[test]
    fn loopback_audiences_need_a_loopback_dev_remote() {
        let audiences = |a: &str| vec![a.to_owned()];
        let dev = target("mkit+http://127.0.0.1:8080");
        let prod = target("mkit+https://git.example.com");
        for loopback in [
            "http://localhost:8080",
            "http://127.0.0.1:8080",
            "http://127.9.9.9",
            "http://[::1]:8080",
        ] {
            assert!(
                check_audiences(&audiences(loopback), Some(&prod)).is_err(),
                "{loopback}"
            );
            assert!(
                check_audiences(&audiences(loopback), None).is_err(),
                "{loopback}"
            );
        }
        assert!(check_audiences(&audiences("http://127.0.0.1:8080"), Some(&dev)).is_ok());
        assert!(check_audiences(&audiences("https://git.example.com"), Some(&prod)).is_ok());
        assert!(target("mkit+http://127.0.0.1:8080").is_loopback_dev());
        assert!(!target("mkit+https://git.example.com").is_loopback_dev());
    }

    #[test]
    fn audience_and_namespace_come_from_the_url() {
        let t =
            target("mkit+https://git.example.com/0x8ba1f109551bd432803012645ac136ddd64dba72/site");
        assert_eq!(t.audience().unwrap(), "https://git.example.com");
        assert_eq!(
            t.namespace().unwrap().to_string(),
            "0x8ba1f109551bd432803012645ac136ddd64dba72"
        );
        assert!(target("mkit+https://git.example.com").namespace().is_none());
        assert!(target("https://git.example.com").audience().is_err());
    }

    #[test]
    fn drive_resends_until_done_and_sums_the_waits() {
        let mut calls: u64 = 0;
        let mut slept = Vec::new();
        let outcome: Result<Driven<u64>, ()> = drive(
            || {
                calls += 1;
                Ok(if calls < 4 {
                    Completion::Pending {
                        retry_after: Duration::from_secs(calls),
                    }
                } else {
                    Completion::Done(9)
                })
            },
            Duration::from_mins(1),
            |d| {
                slept.push(d);
                true
            },
        );
        assert_eq!(outcome, Ok(Driven::Done(9)));
        assert_eq!(calls, 4);
        assert_eq!(
            slept,
            [
                Duration::from_secs(1),
                Duration::from_secs(2),
                Duration::from_secs(3)
            ]
        );
    }

    #[test]
    fn drive_stops_at_the_total_timeout_and_on_cancel() {
        let pending = || -> Result<Completion<()>, ()> {
            Ok(Completion::Pending {
                retry_after: Duration::from_secs(4),
            })
        };
        // 4 + 4 fit in 10 s; a third wait would end at 12 s.
        let mut sleeps = 0;
        let outcome = drive(pending, Duration::from_secs(10), |_| {
            sleeps += 1;
            true
        });
        assert_eq!(
            outcome,
            Ok(Driven::TimedOut {
                waited: Duration::from_secs(8)
            })
        );
        assert_eq!(sleeps, 2);
        let outcome = drive(pending, Duration::from_secs(10), |_| false);
        assert_eq!(outcome, Ok(Driven::Cancelled));
        // Errors from the call pass straight through.
        let outcome: Result<Driven<()>, &str> =
            drive(|| Err("boom"), Duration::from_secs(1), |_| true);
        assert_eq!(outcome, Err("boom"));
    }
}
