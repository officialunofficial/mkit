//! External signer — subprocess-based [`Signer`] impl.
//!
//! Protocol (SPEC-ATTESTATIONS §6.2):
//!
//! ```text
//! spawn  <binary>                       (no args)
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
use crate::signer::Signer;

/// Cap for each of child-stdout and child-stderr. 1 MiB is generous —
/// the protocol response is a single JSON line.
const MAX_DRAIN: usize = 1024 * 1024;

#[derive(Debug)]
pub struct ExternalSigner {
    binary_path: PathBuf,
    cached_keyid: Option<String>,
}

impl ExternalSigner {
    #[must_use]
    pub fn new(binary_path: impl Into<PathBuf>) -> Self {
        Self {
            binary_path: binary_path.into(),
            cached_keyid: None,
        }
    }
}

impl Signer for ExternalSigner {
    fn keyid(&self) -> Result<String, Error> {
        self.cached_keyid
            .clone()
            .ok_or(Error::KeyIdNotKnownUntilFirstSign)
    }

    fn sign(&mut self, pae: &[u8]) -> Result<Vec<u8>, Error> {
        let request = format!("{{\"pae_base64\":\"{}\"}}\n", B64.encode(pae));

        let mut child = Command::new(&self.binary_path)
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
            // payload (the Zig version uses `std.debug.print`; we keep
            // the bytes inside the error so the caller can decide).
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

        let mut ext = ExternalSigner::new(path);
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

    #[cfg(unix)]
    #[test]
    fn nonzero_exit_surfaces_failed() {
        let body = "cat >/dev/null; printf 'boom\\n' 1>&2; exit 1";
        let tmp = tempfile::tempdir().unwrap();
        let path = write_script(tmp.path(), "bad.sh", body);

        let mut ext = ExternalSigner::new(path);
        match sign_retry_on_etxtbsy(&mut ext, b"DSSEv1 4 test 0 ") {
            Err(Error::ExternalSignerFailed(msg)) => assert!(msg.contains("boom")),
            other => panic!("expected ExternalSignerFailed, got {other:?}"),
        }
    }
}
