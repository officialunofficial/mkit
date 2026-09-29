//! User-scoped executable admission responder. Server input and stdout are untrusted.
use std::collections::HashSet;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use mkit_transport_connect::admission::{
    AdmissionContext, AdmissionResponder, AdmissionResponderError,
};
use serde::Deserialize;
use serde::de::{MapAccess, Visitor};

const MAX_STDOUT: usize = 128 * 1024;
const DEADLINE: Duration = Duration::from_mins(2);

// The helper stays in mkit's foreground process group, so it can prompt on
// the terminal (for example to confirm a payment) and receives Ctrl-C with
// mkit. A descendant that keeps an inherited pipe open cannot extend the wait:
// unfinished reader and writer threads are skipped at the deadline.
fn stop_helper(child: &mut std::process::Child) {
    let _ = child.kill();
    let _ = child.wait();
}

pub(crate) struct ExecResponder {
    pub path: PathBuf,
}

struct HelperOutput(Vec<(String, String)>);
impl<'de> Deserialize<'de> for HelperOutput {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct OutputVisitor;
        impl<'de> Visitor<'de> for OutputVisitor {
            type Value = HelperOutput;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("an object mapping header names to strings")
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
                let mut seen = HashSet::new();
                let mut headers = Vec::new();
                while let Some((name, value)) = map.next_entry::<String, String>()? {
                    if !seen.insert(name.clone()) {
                        return Err(serde::de::Error::custom("duplicate key"));
                    }
                    headers.push((name, value));
                }
                Ok(HelperOutput(headers))
            }
        }
        deserializer.deserialize_map(OutputVisitor)
    }
}

fn parse_stdout(bytes: &[u8]) -> Result<Vec<(String, String)>, AdmissionResponderError> {
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let output = HelperOutput::deserialize(&mut decoder)
        .and_then(|output| {
            decoder.end()?;
            Ok(output)
        })
        .map_err(|_| {
            AdmissionResponderError::Failed(
                "helper output must be one JSON object of string headers".into(),
            )
        })?;
    if output.0.is_empty() {
        return Err(AdmissionResponderError::Failed(
            "helper returned no headers".into(),
        ));
    }
    Ok(output.0)
}

impl AdmissionResponder for ExecResponder {
    fn respond(
        &self,
        ctx: &AdmissionContext<'_>,
    ) -> Result<Vec<(String, String)>, AdmissionResponderError> {
        self.run(ctx, DEADLINE)
    }
}

impl ExecResponder {
    // Keep the child, pipes, and deadline in one scope so no blocking I/O
    // can accidentally outlive the wall-clock bound.
    #[allow(clippy::too_many_lines)]
    fn run(
        &self,
        ctx: &AdmissionContext<'_>,
        deadline: Duration,
    ) -> Result<Vec<(String, String)>, AdmissionResponderError> {
        let start = Instant::now();
        if !self.path.is_absolute() {
            return Err(AdmissionResponderError::Configuration(
                "admission_helper must be an absolute path".into(),
            ));
        }
        if !self.path.is_file() {
            return Err(AdmissionResponderError::Configuration(
                "admission_helper path does not name a file".into(),
            ));
        }
        crate::progress::suspend_for_admission();
        let schemes = ctx
            .required
            .challenges
            .iter()
            .map(|c| c.scheme.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        eprintln!(
            "remote requires admission for {} (schemes: {schemes}); running admission helper",
            ctx.procedure.rsplit('/').next().unwrap_or(ctx.procedure)
        );
        let mut headers = serde_json::Map::new();
        if !ctx.required.www_authenticate.is_empty() {
            headers.insert(
                "www-authenticate".into(),
                serde_json::json!(ctx.required.www_authenticate),
            );
        }
        if !ctx.required.payment_required.is_empty() {
            headers.insert(
                "payment-required".into(),
                serde_json::json!(ctx.required.payment_required),
            );
        }
        let input = serde_json::json!({
            "origin": ctx.origin,
            "repository": ctx.repository,
            "procedure": ctx.procedure,
            "description": ctx.required.description,
            "challenges": ctx.required.challenges.iter().map(|c| serde_json::json!({"scheme": c.scheme, "value": c.value})).collect::<Vec<_>>(),
            "headers": headers,
        });
        let bytes = serde_json::to_vec(&input)
            .map_err(|_| AdmissionResponderError::Failed("cannot encode helper input".into()))?;
        let mut command = Command::new(&self.path);
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        let mut child = command
            .spawn()
            .map_err(|_| AdmissionResponderError::Failed("cannot start admission helper".into()))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| AdmissionResponderError::Failed("cannot open helper stdin".into()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| AdmissionResponderError::Failed("cannot open helper stdout".into()))?;
        let (write_sender, write_receiver) = mpsc::channel();
        let writer = thread::spawn(move || {
            let mut stdin = stdin;
            let _ = write_sender.send(stdin.write_all(&bytes));
        });
        let (sender, receiver) = mpsc::channel();
        let reader = thread::spawn(move || {
            let stdout = stdout;
            let mut output = Vec::new();
            let result = stdout
                .take((MAX_STDOUT + 1) as u64)
                .read_to_end(&mut output)
                .map(|_| output);
            let _ = sender.send(result);
        });
        let mut output = None;
        let mut wrote_input = None;
        let mut status = None;
        loop {
            if let Ok(result) = receiver.try_recv() {
                let Ok(bytes) = result else {
                    stop_helper(&mut child);
                    return Err(AdmissionResponderError::Failed(
                        "cannot read helper stdout".into(),
                    ));
                };
                if bytes.len() > MAX_STDOUT {
                    stop_helper(&mut child);
                    return Err(AdmissionResponderError::Failed(
                        "helper stdout exceeds 128 KiB".into(),
                    ));
                }
                output = Some(bytes);
            }
            if let Ok(result) = write_receiver.try_recv() {
                // A helper that exits without reading all of stdin closes the
                // pipe; its exit status and output decide the result.
                wrote_input = Some(match result {
                    Ok(()) => true,
                    Err(error) => error.kind() == std::io::ErrorKind::BrokenPipe,
                });
            }
            if crate::signal::is_shutdown() {
                stop_helper(&mut child);
                return Err(AdmissionResponderError::Failed(
                    "admission helper interrupted".into(),
                ));
            }
            if start.elapsed() >= deadline {
                stop_helper(&mut child);
                // A descendant could have moved to another process group.
                // Never block past the deadline waiting for its inherited pipe.
                if writer.is_finished() {
                    let _ = writer.join();
                }
                if reader.is_finished() {
                    let _ = reader.join();
                }
                return Err(AdmissionResponderError::Failed(
                    "admission helper timed out".into(),
                ));
            }
            if status.is_none()
                && let Ok(Some(exit)) = child.try_wait()
            {
                status = Some(exit);
            }
            if status.is_some() && output.is_some() && wrote_input.is_some() {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        let _ = writer.join();
        let _ = reader.join();
        if wrote_input != Some(true) {
            return Err(AdmissionResponderError::Failed(
                "cannot write helper stdin".into(),
            ));
        }
        if !status.expect("helper exited").success() {
            return Err(AdmissionResponderError::Failed(
                "admission helper exited unsuccessfully".into(),
            ));
        }
        let output = output.expect("reader completed");
        if output.len() > MAX_STDOUT {
            return Err(AdmissionResponderError::Failed(
                "helper stdout exceeds 128 KiB".into(),
            ));
        }
        parse_stdout(&output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mkit_core::protocol::{AdmissionChallengeEntry, AdmissionRequired};
    use std::os::unix::fs::PermissionsExt;

    fn context(required: &AdmissionRequired) -> AdmissionContext<'_> {
        AdmissionContext {
            origin: "https://example.invalid",
            repository: "default",
            procedure: "/mkit.transport.v1.TransportService/UpdateRef",
            required,
        }
    }

    fn script(body: &str) -> (tempfile::TempDir, ExecResponder) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("helper.sh");
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o700);
        std::fs::set_permissions(&path, perms).unwrap();
        (dir, ExecResponder { path })
    }

    #[test]
    fn output_shape_and_duplicates() {
        for invalid in [
            "[]",
            "{}",
            "{\"X\":1}",
            "{\"X\":\"a\",\"X\":\"b\"}",
            "{\"X\":\"a\"} {}",
        ] {
            assert!(parse_stdout(invalid.as_bytes()).is_err(), "{invalid}");
        }
        assert_eq!(
            parse_stdout(b"{\"X\":\"a\"}").unwrap(),
            [("X".into(), "a".into())]
        );
    }

    #[test]
    fn exec_happy_path_and_stdin_shape() {
        let dir = tempfile::tempdir().unwrap();
        let stdin = dir.path().join("stdin.json");
        let body = format!(
            "cat > '{}'; printf '%s' '{{\"Payment-Authorization\":\"Payment secret\"}}'",
            stdin.display()
        );
        let (_script_dir, helper) = script(&body);
        let required = AdmissionRequired::new(
            vec![AdmissionChallengeEntry {
                scheme: "pay".into(),
                value: "opaque".into(),
            }],
            "untrusted".into(),
            vec!["Payment x".into()],
            vec!["invoice".into()],
        );
        let result = helper.respond(&context(&required)).unwrap();
        assert_eq!(result[0].0, "Payment-Authorization");
        let input: serde_json::Value =
            serde_json::from_slice(&std::fs::read(stdin).unwrap()).unwrap();
        assert_eq!(
            input,
            serde_json::json!({
                "origin": "https://example.invalid",
                "repository": "default",
                "procedure": "/mkit.transport.v1.TransportService/UpdateRef",
                "description": "untrusted",
                "challenges": [{"scheme": "pay", "value": "opaque"}],
                "headers": {"www-authenticate": ["Payment x"], "payment-required": ["invoice"]}
            })
        );
    }

    #[test]
    fn exec_failures_are_bounded_and_redacted() {
        let required = AdmissionRequired::new(Vec::new(), String::new(), Vec::new(), Vec::new());
        let relative = ExecResponder {
            path: "relative".into(),
        };
        assert!(matches!(
            relative.respond(&context(&required)),
            Err(AdmissionResponderError::Configuration(_))
        ));
        let missing = ExecResponder {
            path: std::env::temp_dir().join("missing-admission-helper-9e5d8a6f"),
        };
        assert!(matches!(
            missing.respond(&context(&required)),
            Err(AdmissionResponderError::Configuration(_))
        ));
        let (_dir, nonzero) = script("printf secret; exit 7");
        assert!(
            !nonzero
                .respond(&context(&required))
                .unwrap_err()
                .to_string()
                .contains("secret")
        );
        let (_dir, oversized) = script("head -c 131073 /dev/zero");
        assert!(
            oversized
                .respond(&context(&required))
                .unwrap_err()
                .to_string()
                .contains("128 KiB")
        );
        let (_dir, timeout) = script("sleep 5 & exit 0");
        let start = Instant::now();
        assert!(
            timeout
                .run(&context(&required), Duration::from_millis(100))
                .unwrap_err()
                .to_string()
                .contains("timed out")
        );
        assert!(start.elapsed() < Duration::from_secs(2));
        let (_dir, no_stdin_read) = script("printf '%s' '{\"X\":\"a\"}'");
        assert!(no_stdin_read.respond(&context(&required)).is_ok());
    }
}
