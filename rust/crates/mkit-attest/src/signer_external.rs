//! External signer — subprocess-based [`Signer`] impl.
//!
//! Protocol (SPEC-ATTESTATIONS §6.2):
//!
//! ```text
//! spawn  <binary> [args...]             (args empty by default; see `with_args`)
//! write  {"pae_base64":"<...>"}\n       to child stdin, then close stdin
//! read   {"keyid":"<...>","sig_base64":"<...>"} on child stdout
//! wait   exit 0 on success; non-zero surfaces ExternalSignerFailed
//! ```
//!
//! `keyid` is only known after the first sign call; `keyid()` before
//! that returns `Error::KeyIdNotKnownUntilFirstSign`.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use serde::Deserialize;

use crate::Error;
use crate::algorithm::Algorithm;
use crate::signer::Signer;

/// Cap for each of child-stdout and child-stderr. 1 MiB is generous —
/// the protocol response is a single JSON line.
const MAX_DRAIN: usize = 1024 * 1024;

#[derive(Debug)]
pub struct ExternalSigner {
    binary_path: PathBuf,
    cached_keyid: Option<String>,
    algorithm: Algorithm,
    /// Extra argv tokens passed verbatim to the child process via
    /// `Command::args`. Empty by default — matches the zero-argv
    /// default documented in SPEC-EXTERNAL-SIGNER §2. Populated by
    /// [`ExternalSigner::with_args`].
    args: Vec<String>,
}

impl ExternalSigner {
    /// Construct an external signer wrapping `binary_path`.
    ///
    /// The path MUST be absolute. A relative path is rejected with
    /// [`Error::ExternalSignerRelativePath`]: at spawn time, a
    /// relative path would resolve against the current `PATH` (or
    /// CWD on Windows) and pick up a same-named binary planted by an
    /// attacker earlier in the search order. Forcing absolute paths
    /// at construction closes that TOCTOU hole and makes the
    /// resolution deterministic at config-time rather than spawn-time.
    ///
    /// # Errors
    ///
    /// [`Error::ExternalSignerRelativePath`] if `binary_path` is not
    /// absolute.
    pub fn new(binary_path: impl Into<PathBuf>) -> Result<Self, Error> {
        Self::with_algorithm(binary_path, Algorithm::Ed25519)
    }

    /// Like [`Self::new`] but records a caller-asserted algorithm.
    ///
    /// The subprocess protocol (SPEC-ATTESTATIONS §6.2) does not carry
    /// an algorithm field on the wire, so the host declares it at
    /// construction time. Defaults to [`Algorithm::Ed25519`] via
    /// [`Self::new`] for backward compatibility.
    ///
    /// # Errors
    ///
    /// See [`Self::new`].
    pub fn with_algorithm(
        binary_path: impl Into<PathBuf>,
        algorithm: Algorithm,
    ) -> Result<Self, Error> {
        let binary_path = binary_path.into();
        if !binary_path.is_absolute() {
            return Err(Error::ExternalSignerRelativePath(
                binary_path.display().to_string(),
            ));
        }
        Ok(Self {
            binary_path,
            cached_keyid: None,
            algorithm,
            args: Vec::new(),
        })
    }

    /// Attach extra argv tokens to be passed verbatim to the child
    /// process on every sign call. Each element is one argv entry —
    /// no shell interpolation, no splitting on whitespace. Calling
    /// this replaces any previously-set args.
    ///
    /// Use this when the external signer binary needs per-invocation
    /// flags (`sign --tag prod`, `--key /path/to/key`, etc.) that
    /// the zero-argv default doesn't cover. Motivated by multi-key
    /// workflows where wrapping the real signer in a shell script
    /// just to hardcode an argv is clumsy. See SPEC-EXTERNAL-SIGNER
    /// §2 for the argv contract.
    #[must_use]
    pub fn with_args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args = args.into_iter().map(Into::into).collect();
        self
    }
}

impl Signer for ExternalSigner {
    fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    fn keyid(&self) -> Result<String, Error> {
        self.cached_keyid
            .clone()
            .ok_or(Error::KeyIdNotKnownUntilFirstSign)
    }

    fn sign(&mut self, pae: &[u8]) -> Result<Vec<u8>, Error> {
        let request = format!("{{\"pae_base64\":\"{}\"}}\n", B64.encode(pae));

        let mut child = Command::new(&self.binary_path)
            .args(&self.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| Error::ExternalSignerSpawn(e.to_string()))?;

        // Write request, close stdin.
        {
            let stdin = child
                .stdin
                .as_mut()
                .ok_or_else(|| Error::ExternalSignerSpawn("stdin not piped".into()))?;
            stdin
                .write_all(request.as_bytes())
                .map_err(|e| Error::ExternalSignerSpawn(format!("write: {e}")))?;
        }
        // Drop stdin handle so the child sees EOF.
        drop(child.stdin.take());

        // Drain stdout, then stderr; both bounded.
        let stdout = drain(
            child
                .stdout
                .take()
                .ok_or_else(|| Error::ExternalSignerSpawn("stdout not piped".into()))?,
        )?;
        let stderr = drain(
            child
                .stderr
                .take()
                .ok_or_else(|| Error::ExternalSignerSpawn("stderr not piped".into()))?,
        )?;

        let status = child
            .wait()
            .map_err(|e| Error::ExternalSignerSpawn(format!("wait: {e}")))?;

        if !status.success() {
            // Surface the child's stderr to the caller via the error
            // payload so the caller can decide what to log.
            let msg = String::from_utf8_lossy(&stderr).into_owned();
            return Err(Error::ExternalSignerFailed(msg));
        }

        let line = trim_trailing(&stdout, b"\r\n ");
        let parsed = parse_response(line)?;

        self.cached_keyid = Some(parsed.keyid);
        Ok(parsed.sig)
    }
}

fn drain<R: Read>(mut r: R) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = r
            .read(&mut chunk)
            .map_err(|e| Error::ExternalSignerSpawn(format!("read: {e}")))?;
        if n == 0 {
            break;
        }
        if out.len() + n > MAX_DRAIN {
            return Err(Error::ExternalSignerOutputTooLarge);
        }
        out.extend_from_slice(&chunk[..n]);
    }
    Ok(out)
}

fn trim_trailing<'a>(buf: &'a [u8], drop_set: &[u8]) -> &'a [u8] {
    let mut end = buf.len();
    while end > 0 && drop_set.contains(&buf[end - 1]) {
        end -= 1;
    }
    &buf[..end]
}

#[derive(Debug, Deserialize)]
struct ResponseShape {
    keyid: String,
    sig_base64: String,
}

struct Parsed {
    keyid: String,
    sig: Vec<u8>,
}

fn parse_response(line: &[u8]) -> Result<Parsed, Error> {
    let parsed: ResponseShape =
        serde_json::from_slice(line).map_err(|_| Error::ExternalSignerBadResponse)?;
    let sig = B64
        .decode(parsed.sig_base64.as_bytes())
        .map_err(|_| Error::ExternalSignerBadResponse)?;
    Ok(Parsed {
        keyid: parsed.keyid,
        sig,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn write_script(dir: &std::path::Path, name: &str, body: &str) -> PathBuf {
        let p = dir.join(name);
        {
            let mut f = std::fs::File::create(&p).expect("create");
            f.write_all(b"#!/bin/sh\n").unwrap();
            f.write_all(body.as_bytes()).unwrap();
            f.write_all(b"\n").unwrap();
            // Drop `f` at end of this block so the kernel considers the file
            // closed before the caller exec()s it. Without this, Linux can
            // return ETXTBSY ("Text file busy") when a parallel cargo-test
            // harness races the write-then-spawn window.
            f.sync_all().unwrap();
        }
        let mut perm = std::fs::metadata(&p).unwrap().permissions();
        perm.set_mode(0o755);
        std::fs::set_permissions(&p, perm).unwrap();
        p
    }

    /// Retry wrapper around `ExternalSigner::sign` that tolerates the
    /// one transient failure mode tests can hit on Linux: ETXTBSY
    /// ("Text file busy") surfacing through `ExternalSignerSpawn`. The
    /// error can fire briefly after writing the script even when the
    /// File handle has been dropped, because the kernel hasn't flushed
    /// the close-vs-exec ordering yet under load. Retry up to 5 times
    /// with 20ms backoff before bubbling up.
    #[cfg(unix)]
    fn sign_retry_on_etxtbsy(ext: &mut ExternalSigner, pae: &[u8]) -> Result<Vec<u8>, Error> {
        for _ in 0..5 {
            match ext.sign(pae) {
                Err(Error::ExternalSignerSpawn(msg)) if msg.contains("Text file busy") => {
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                other => return other,
            }
        }
        ext.sign(pae)
    }

    #[cfg(unix)]
    #[test]
    fn echoes_keyid_and_sig() {
        // Ignore stdin; emit a fixed response. "AQID" = base64(\x01\x02\x03).
        let body = "cat >/dev/null; \
                    printf '{\"keyid\":\"test:abc\",\"sig_base64\":\"AQID\"}\\n'";
        let tmp = tempfile::tempdir().unwrap();
        let path = write_script(tmp.path(), "signer.sh", body);

        let mut ext = ExternalSigner::new(path).expect("tempdir path is absolute");
        // keyid before any sign call → error.
        assert!(matches!(
            ext.keyid(),
            Err(Error::KeyIdNotKnownUntilFirstSign)
        ));

        let sig = sign_retry_on_etxtbsy(&mut ext, b"DSSEv1 4 test 0 ").unwrap();
        assert_eq!(sig, vec![0x01, 0x02, 0x03]);

        let kid = ext.keyid().unwrap();
        assert_eq!(kid, "test:abc");
    }

    #[test]
    fn new_rejects_relative_path() {
        let err = ExternalSigner::new("mkit-signer").unwrap_err();
        assert!(matches!(err, Error::ExternalSignerRelativePath(_)));
    }

    #[cfg(unix)]
    #[test]
    fn new_accepts_absolute_path() {
        ExternalSigner::new("/usr/bin/foo").expect("absolute path accepted");
    }

    #[cfg(unix)]
    #[test]
    fn passes_argv_entries_to_child() {
        // Helper script: writes its own argv (joined by pipes) as the
        // keyid, and returns a fixed dummy signature. Proves each
        // `with_args` entry becomes a separate argv token, verbatim.
        let body = "cat >/dev/null; \
                    kid=\"argv:$1|$2|$3\"; \
                    printf '{\"keyid\":\"%s\",\"sig_base64\":\"AQID\"}\\n' \"$kid\"";
        let tmp = tempfile::tempdir().unwrap();
        let path = write_script(tmp.path(), "argvecho.sh", body);

        let mut ext = ExternalSigner::new(path)
            .expect("tempdir path is absolute")
            .with_args(["sign", "--tag", "demo"]);

        let _ = sign_retry_on_etxtbsy(&mut ext, b"DSSEv1 4 test 0 ").unwrap();
        let kid = ext.keyid().unwrap();
        assert_eq!(kid, "argv:sign|--tag|demo");
    }

    #[cfg(unix)]
    #[test]
    fn nonzero_exit_surfaces_failed() {
        let body = "cat >/dev/null; printf 'boom\\n' 1>&2; exit 1";
        let tmp = tempfile::tempdir().unwrap();
        let path = write_script(tmp.path(), "bad.sh", body);

        let mut ext = ExternalSigner::new(path).expect("tempdir path is absolute");
        match sign_retry_on_etxtbsy(&mut ext, b"DSSEv1 4 test 0 ") {
            Err(Error::ExternalSignerFailed(msg)) => assert!(msg.contains("boom")),
            other => panic!("expected ExternalSignerFailed, got {other:?}"),
        }
    }
}
