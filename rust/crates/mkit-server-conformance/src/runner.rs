//! Standalone runner profiles and versioned, credential-free result envelopes.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use url::Url;

use crate::controlled::ControlClient;
use crate::wire::{ProfileSpec, Report, Verdict, WireTarget};

/// Versioned TOML input for the standalone `run` and `diff` commands.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerProfile {
    /// Profile format version, currently 1.
    pub version: u32,
    /// The server's optional wire features and authentication settings.
    pub wire: ProfileSpec,
    /// HTTP test-control binding and required capabilities.
    #[serde(default)]
    pub control: ControlProfile,
}

/// Test-control declarations for an isolated server under test.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlProfile {
    /// Separate control origin; absent means the wire base URL.
    pub url: Option<Url>,
    /// Capabilities the runner must negotiate before running any cases.
    #[serde(default)]
    pub controls: Vec<String>,
    /// Known gaps in declared features, keyed by stable Tier-2 case name.
    #[serde(default)]
    pub declared_skips: BTreeMap<String, String>,
}

impl RunnerProfile {
    /// Parse strict TOML without including profile contents in diagnostics.
    ///
    /// # Errors
    /// Unknown fields, unsupported versions, or invalid declarations.
    pub fn from_toml(text: &str) -> Result<Self, String> {
        let profile: Self = toml::from_str(text).map_err(|_| "invalid runner profile TOML")?;
        if profile.version != 1 {
            return Err("unsupported runner profile version (expected 1)".into());
        }
        if profile
            .control
            .controls
            .iter()
            .any(|name| name.trim().is_empty())
        {
            return Err("control capability names must be nonempty".into());
        }
        if profile.control.declared_skips.iter().any(|(name, reason)| {
            reason.trim().is_empty() || !crate::controlled::CASES.iter().any(|c| c.name == name)
        }) {
            return Err("declared skips require known case names and nonempty reasons".into());
        }
        Ok(profile)
    }
}

/// Validate a standalone runner URL without exposing credentials in errors.
///
/// # Errors
/// Unsupported schemes, missing hosts, credentials, fragments, or queries.
pub fn validate_url(url: &Url) -> Result<(), String> {
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(
            "runner URLs require HTTP(S), a host, and no credentials, query, or fragment".into(),
        );
    }
    Ok(())
}

/// Negotiate required controls before any test effects.
///
/// # Errors
/// Unavailable HTTP binding, incompatible version, or a missing capability.
pub async fn negotiate(url: &Url, required: &[String]) -> Result<(), String> {
    validate_url(url)?;
    let caps = ControlClient::new(url)?.capabilities().await?;
    for name in required {
        if !caps.controls.contains(name) {
            return Err(format!(
                "required test-control capability is unavailable: {name}"
            ));
        }
    }
    Ok(())
}

/// One serializable result, independent of the library's Rust enum layout.
#[derive(Debug, Serialize)]
pub struct JsonCase {
    /// Stable case name.
    pub name: String,
    /// `pass`, `fail`, `skip`, or `not_applicable`.
    pub status: &'static str,
    /// Diagnostic, optional pass note, feature, or declared gap reason.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Version 1 machine-readable standalone suite report.
#[derive(Debug, Serialize)]
pub struct JsonReport {
    /// JSON schema version.
    pub version: u32,
    /// Command that produced this report.
    pub command: &'static str,
    /// Whether every executed case passed.
    pub passed: bool,
    /// Per-case outcomes, in execution order.
    pub cases: Vec<JsonCase>,
}

impl JsonReport {
    /// Convert suite results without embedding the authentication profile.
    #[must_use]
    pub fn from_report(report: &Report) -> Self {
        let cases = report
            .cases
            .iter()
            .map(|case| {
                let (status, detail) = match &case.verdict {
                    Verdict::Pass(note) => ("pass", note.clone()),
                    Verdict::Fail(reason) => ("fail", Some(reason.clone())),
                    Verdict::Skip(reason) => ("skip", Some(reason.clone())),
                    Verdict::NotApplicable(feature) => ("not_applicable", Some(feature.clone())),
                };
                JsonCase {
                    name: case.name.into(),
                    status,
                    detail,
                }
            })
            .collect();
        Self {
            version: 1,
            command: "run",
            passed: !report.failed(),
            cases,
        }
    }
}

/// Redact configured authentication material from one untrusted text value.
#[must_use]
pub fn redact(mut text: String, auth: &crate::wire::WireAuth) -> String {
    let secret = match auth {
        crate::wire::WireAuth::None => return text,
        crate::wire::WireAuth::Bearer { token } => token.clone(),
        crate::wire::WireAuth::AuthV2 { seed, .. } => mkit_core::hash::to_hex_bytes(seed),
    };
    if !secret.is_empty() {
        text = text.replace(&secret, "[REDACTED]");
        if matches!(auth, crate::wire::WireAuth::AuthV2 { .. }) {
            text = text.replace(&secret.to_uppercase(), "[REDACTED]");
        }
    }
    text
}

/// Redact only diagnostic contents, preserving case names and verdict variants.
#[must_use]
pub fn redact_report(report: &Report, auth: &crate::wire::WireAuth) -> Report {
    let mut sanitized = report.clone();
    for line in &mut sanitized.preamble {
        *line = redact(std::mem::take(line), auth);
    }
    for case in &mut sanitized.cases {
        let detail = match &mut case.verdict {
            Verdict::Pass(note) => note.as_mut(),
            Verdict::Fail(reason) | Verdict::Skip(reason) => Some(reason),
            Verdict::NotApplicable(_) => None,
        };
        if let Some(detail) = detail {
            *detail = redact(std::mem::take(detail), auth);
        }
    }
    sanitized
}

/// Redact JSON string values recursively, preserving keys, numbers and booleans.
/// Call only on untrusted diagnostic values, never on report schema fields.
pub fn redact_value(value: &mut serde_json::Value, auth: &crate::wire::WireAuth) {
    match value {
        serde_json::Value::String(text) => *text = redact(std::mem::take(text), auth),
        serde_json::Value::Array(values) => {
            for value in values {
                redact_value(value, auth);
            }
        }
        serde_json::Value::Object(values) => {
            for value in values.values_mut() {
                redact_value(value, auth);
            }
        }
        _ => {}
    }
}

/// Execute selected Tier-1 and Tier-2 suites using separate HTTP bindings.
///
/// # Errors
/// Invalid URLs, failed negotiation, or an empty case selection.
pub async fn run(
    target: &WireTarget,
    control_url: &Url,
    profile: &ControlProfile,
    wire: bool,
    controlled: bool,
    filter: Option<&str>,
) -> Result<Report, String> {
    validate_url(&target.base_url)?;
    negotiate(control_url, &profile.controls).await?;
    let mut report = Report::default();
    if wire {
        let results = crate::wire::run(target, filter).await;
        report.cases.extend(results.cases);
    }
    if controlled {
        let results = crate::controlled::run_with_control(
            target,
            control_url,
            &profile.declared_skips,
            filter,
        )
        .await;
        report.cases.extend(results.cases);
    }
    if report.cases.is_empty() {
        return Err("no cases match the runner selection".into());
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::CaseReport;

    #[test]
    fn strict_profiles_do_not_echo_secrets_in_errors() {
        let sample = RunnerProfile::from_toml(include_str!("../fixtures/runner.toml")).unwrap();
        assert_eq!(sample.version, 1);
        assert_eq!(sample.control.controls.len(), 3);
        assert!(sample.wire.build(|_| Some("11".repeat(32))).is_ok());
        let error =
            RunnerProfile::from_toml("version=1\nsecret='private-value'\n[wire]").unwrap_err();
        assert!(!error.contains("private-value"));
        assert!(RunnerProfile::from_toml("version=2\n[wire]").is_err());
        assert!(RunnerProfile::from_toml("version=1\n[wire]\nunknown=true").is_err());
        assert!(RunnerProfile::from_toml("version=1\n[wire]\n[control]\ncontrols=['']").is_err());
        assert!(
            RunnerProfile::from_toml(
                "version=1\n[wire]\n[control.declared_skips]\nunknown='reason'"
            )
            .is_err()
        );
    }

    #[test]
    fn json_preserves_distinct_case_statuses() {
        let report = Report {
            preamble: vec!["not emitted".into()],
            cases: vec![
                CaseReport {
                    name: "passed",
                    verdict: Verdict::Pass(None),
                },
                CaseReport {
                    name: "failed",
                    verdict: Verdict::Fail("reason".into()),
                },
                CaseReport {
                    name: "skipped",
                    verdict: Verdict::Skip("known gap".into()),
                },
                CaseReport {
                    name: "absent",
                    verdict: Verdict::NotApplicable("fork".into()),
                },
            ],
        };
        let value = serde_json::to_value(JsonReport::from_report(&report)).unwrap();
        assert_eq!(value["version"], 1);
        assert_eq!(value["passed"], false);
        assert_eq!(value["cases"][2]["status"], "skip");
        assert_eq!(value["cases"][3]["status"], "not_applicable");
        assert!(!value.to_string().contains("not emitted"));
    }

    #[test]
    fn short_credentials_preserve_json_schema_and_tap_markers() {
        for secret in [
            "true",
            "version",
            "ok",
            "pass",
            "a",
            "fork",
            "tickets",
            "private\"value",
        ] {
            let auth = crate::wire::WireAuth::Bearer {
                token: secret.into(),
            };
            let report = Report {
                preamble: vec![format!("reflected {secret}")],
                cases: vec![
                    CaseReport {
                        name: "pass.version",
                        verdict: Verdict::Pass(Some(format!("reflected {secret}"))),
                    },
                    CaseReport {
                        name: "absent.feature",
                        verdict: Verdict::NotApplicable(secret.into()),
                    },
                ],
            };
            let sanitized = redact_report(&report, &auth);
            let json = serde_json::to_string(&JsonReport::from_report(&sanitized)).unwrap();
            let value: serde_json::Value = serde_json::from_str(&json).unwrap();
            assert_eq!(value["version"], 1);
            assert_eq!(value["passed"], true);
            assert_eq!(value["cases"][0]["name"], "pass.version");
            assert_eq!(value["cases"][0]["status"], "pass");
            assert_eq!(value["cases"][0]["detail"], "reflected [REDACTED]");
            assert_eq!(value["cases"][1]["status"], "not_applicable");
            assert_eq!(value["cases"][1]["detail"], secret);
            assert!(
                sanitized
                    .tap()
                    .contains("ok 1 - pass.version # reflected [REDACTED]")
            );
            assert!(
                sanitized
                    .tap()
                    .contains("# pass 1 fail 0 skip 0 not-applicable 1")
            );
            let mut diagnostic = serde_json::json!({"version": [secret, true, 1]});
            redact_value(&mut diagnostic, &auth);
            assert_eq!(
                diagnostic,
                serde_json::json!({"version": ["[REDACTED]", true, 1]})
            );
        }
    }

    #[test]
    fn runner_urls_reject_inline_credentials() {
        for raw in [
            "ftp://localhost/",
            "https://user:secret@localhost/",
            "https://localhost/?token=secret",
        ] {
            assert!(validate_url(&Url::parse(raw).unwrap()).is_err());
        }
        assert!(validate_url(&Url::parse("https://localhost/control/").unwrap()).is_ok());
    }
}
