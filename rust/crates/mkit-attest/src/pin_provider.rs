//! `PinProvider` — sources a PIN in response to a signer's `PinPrompt`
//! frame (SPEC-EXTERNAL-SIGNER §4).
//!
//! mkit never puts a PIN on argv or in an environment variable — see
//! `docs/specs/SPEC-EXTERNAL-SIGNER.md` §2 and `docs/THREAT-MODEL.md`
//! §3.2 (the same same-host-different-UID exposure class that key-file
//! confidentiality defends against: a PIN on argv is readable by any
//! other local user via `ps` / `/proc/<pid>/cmdline`).
//! [`ExternalSigner`](crate::signer_external::ExternalSigner) sources
//! the PIN exclusively through this trait; the default
//! [`TtyPinProvider`] reads it interactively from the controlling
//! terminal. This mirrors mkit-keystore's `YubiKey` backend contract
//! (`backend_yubikey.rs`'s `ensure_openpgp_interaction_available`):
//! PINs are sourced through an explicit prompt provider, never
//! silently — a caller that wants non-interactive behaviour must
//! supply its own [`PinProvider`] rather than relying on an implicit
//! environment-variable fallback.

use std::io::{BufRead as _, Write as _};

use crate::Error;

/// What a signer's `PinPrompt` frame told the host, decoded from the
/// wire type into a small, protocol-agnostic struct so
/// implementations of [`PinProvider`] don't need to depend on
/// `mkit-rpc`.
#[derive(Debug, Clone, Default)]
pub struct PinPromptInfo {
    /// Human-readable reason the signer gave for the prompt. May be
    /// empty.
    pub reason: String,
    /// Retries remaining before the key locks. `0` means "the signer
    /// didn't say" (SPEC-EXTERNAL-SIGNER §4), NOT "zero retries left".
    pub retries_remaining: u32,
    /// `true` if the signer wants a PIN typed; `false` if it is only
    /// asking for a touch / biometric gesture. The returned string is
    /// ignored by the signer in that case, but a `PinResponse` frame
    /// is still sent to unblock it.
    pub wants_pin: bool,
}

/// Supplies a PIN when an external signer emits a `PinPrompt` mid-sign.
pub trait PinProvider: std::fmt::Debug {
    /// Return the PIN to send back in a `PinResponse`.
    ///
    /// # Errors
    /// Implementations should fail closed rather than silently
    /// supplying an empty or synthetic PIN. Any error here aborts the
    /// whole sign conversation — the child is killed and reaped by
    /// [`ExternalSigner`](crate::signer_external::ExternalSigner).
    fn provide_pin(&self, prompt: &PinPromptInfo) -> Result<String, Error>;
}

/// Default [`PinProvider`]: prompts interactively on the controlling
/// terminal (the prompt text goes to stderr, the answer is read from
/// stdin) and never touches argv or environment variables.
///
/// Terminal echo is suppressed on Unix via a best-effort `stty -echo`
/// / `stty echo` toggle around the read — no `unsafe`, no extra
/// dependency (mirrors how
/// [`ExternalSigner`](crate::signer_external::ExternalSigner) itself
/// already shells out to the signer subprocess via `std::process`).
/// If `stty` is unavailable (non-interactive stdin, a sandboxed
/// environment, a non-Unix target) the PIN is still read, just
/// visibly; callers that need a hard no-echo guarantee should supply
/// their own [`PinProvider`].
#[derive(Debug, Default, Clone, Copy)]
pub struct TtyPinProvider;

impl PinProvider for TtyPinProvider {
    fn provide_pin(&self, prompt: &PinPromptInfo) -> Result<String, Error> {
        // A touch/biometric-only prompt has nothing for a human to
        // type; the signer ignores `PinResponse.pin` in that case,
        // but it still expects a `PinResponse` frame to unblock
        // (SPEC-EXTERNAL-SIGNER §4), so answer with an empty PIN
        // rather than prompting for one.
        if !prompt.wants_pin {
            return Ok(String::new());
        }

        let label = if prompt.reason.is_empty() {
            "PIN".to_owned()
        } else {
            prompt.reason.clone()
        };
        let hint = if prompt.retries_remaining > 0 {
            format!(
                "{label} ({} attempt(s) remaining): ",
                prompt.retries_remaining
            )
        } else {
            format!("{label}: ")
        };

        let mut stderr = std::io::stderr();
        stderr
            .write_all(hint.as_bytes())
            .and_then(|()| stderr.flush())
            .map_err(|e| Error::ExternalSignerSpawn(format!("PIN prompt write failed: {e}")))?;

        let echo_was_disabled = disable_terminal_echo();
        let mut line = String::new();
        let read_result = std::io::stdin().lock().read_line(&mut line);
        if echo_was_disabled {
            restore_terminal_echo();
            // `stty -echo` also swallows the visible newline from the
            // Enter keystroke; emit one so anything printed next
            // doesn't run into the prompt line.
            let _ = stderr.write_all(b"\n");
        }
        read_result.map_err(|e| Error::ExternalSignerSpawn(format!("PIN read failed: {e}")))?;

        Ok(line.trim_end_matches(['\n', '\r']).to_owned())
    }
}

#[cfg(unix)]
fn disable_terminal_echo() -> bool {
    std::process::Command::new("stty")
        .arg("-echo")
        .status()
        .is_ok_and(|status| status.success())
}

#[cfg(unix)]
fn restore_terminal_echo() {
    let _ = std::process::Command::new("stty").arg("echo").status();
}

#[cfg(not(unix))]
fn disable_terminal_echo() -> bool {
    false
}

#[cfg(not(unix))]
fn restore_terminal_echo() {}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct FakePinProvider {
        pin: String,
    }

    impl PinProvider for FakePinProvider {
        fn provide_pin(&self, _prompt: &PinPromptInfo) -> Result<String, Error> {
            Ok(self.pin.clone())
        }
    }

    #[test]
    fn fake_provider_returns_configured_pin() {
        let p = FakePinProvider {
            pin: "1234".to_owned(),
        };
        let info = PinPromptInfo {
            reason: "authenticator locked".to_owned(),
            retries_remaining: 3,
            wants_pin: true,
        };
        assert_eq!(p.provide_pin(&info).unwrap(), "1234");
    }

    #[test]
    fn pin_prompt_info_defaults_are_zeroed() {
        let info = PinPromptInfo::default();
        assert_eq!(info.reason, "");
        assert_eq!(info.retries_remaining, 0);
        assert!(!info.wants_pin);
    }

    #[derive(Debug)]
    struct FailingPinProvider;

    impl PinProvider for FailingPinProvider {
        fn provide_pin(&self, _prompt: &PinPromptInfo) -> Result<String, Error> {
            Err(Error::ExternalSignerFailed(
                "user declined PIN entry".into(),
            ))
        }
    }

    #[test]
    fn failing_provider_propagates_error() {
        let p = FailingPinProvider;
        let err = p.provide_pin(&PinPromptInfo::default()).unwrap_err();
        assert!(matches!(err, Error::ExternalSignerFailed(_)));
    }
}
