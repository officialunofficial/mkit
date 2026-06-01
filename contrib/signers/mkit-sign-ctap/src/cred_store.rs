//! Tiny JSON metadata store mapping `credential_id` → (rp_id, pubkey,
//! keyid) at `$HOME/.mkit-sign-ctap/credentials.json`.
//!
//! This is NOT a key store — the private key lives on the
//! authenticator, never here. All we persist is the handful of
//! attributes a caller needs to go from "I have a credential_id" to
//! "I know what rp_id + pubkey the verifier will want". Signing requires
//! this metadata so the signer can return the public key mkit verifies
//! against the WebAuthn assertion.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::SignerError;

/// One stored credential.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Record {
    /// base64url-no-pad of the credential_id bytes returned by the
    /// authenticator during enrolment.
    pub credential_id_b64url: String,
    /// SEC1-uncompressed (65 bytes, leading 0x04) pubkey as lowercase
    /// hex. Stored uncompressed because CTAP emits that shape; the
    /// verifier accepts both compressed and uncompressed.
    pub public_key_sec1_uncompressed_hex: String,
    pub rp_id: String,
    pub user_name: String,
    /// Convenience: precomputed `p256:<hex-compressed>` keyid. Empty
    /// string if the enrolment path couldn't compute it (older
    /// authenticators that don't emit the full COSE pubkey).
    pub keyid: String,
}

/// Wrapper around the JSON file. `Store::default()` yields an empty
/// store with no on-disk backing — useful when the caller has no
/// permissions to write `~/.mkit-sign-ctap/`.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Store {
    #[serde(default)]
    credentials: Vec<Record>,
}

impl Store {
    /// Load from `path`. A missing file is NOT an error — we treat it
    /// as an empty store so enrolment can create it fresh.
    ///
    /// # Errors
    /// Surfaces parse / IO failures as [`SignerError::Store`].
    pub fn load(path: &Path) -> Result<Self, SignerError> {
        match fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| SignerError::Store(format!("parse {}: {e}", path.display()))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(SignerError::Store(format!("read {}: {e}", path.display()))),
        }
    }

    /// Atomically write to `path`. Creates the parent dir if needed.
    ///
    /// # Errors
    /// Any IO failure surfaces as [`SignerError::Store`].
    pub fn save(&self, path: &Path) -> Result<(), SignerError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| SignerError::Store(format!("mkdir {}: {e}", parent.display())))?;
        }
        // Write to a sibling tempfile + rename so a crash never leaves
        // a half-written credentials.json.
        let tmp = path.with_extension("json.tmp");
        let bytes = serde_json::to_vec_pretty(self)
            .map_err(|e| SignerError::Store(format!("encode: {e}")))?;
        {
            let mut f = fs::File::create(&tmp)
                .map_err(|e| SignerError::Store(format!("create {}: {e}", tmp.display())))?;
            f.write_all(&bytes)
                .map_err(|e| SignerError::Store(format!("write {}: {e}", tmp.display())))?;
            f.sync_all()
                .map_err(|e| SignerError::Store(format!("fsync {}: {e}", tmp.display())))?;
        }
        fs::rename(&tmp, path)
            .map_err(|e| SignerError::Store(format!("rename {}: {e}", path.display())))?;
        // Best-effort chmod 0600. Metadata is not secret, but the
        // keyid names a credential and we don't want to leak
        // enumeration fodder on a multi-user host.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }

    /// Insert or replace by `credential_id_b64url`. Matching is exact.
    pub fn upsert(&mut self, rec: Record) {
        if let Some(existing) = self
            .credentials
            .iter_mut()
            .find(|r| r.credential_id_b64url == rec.credential_id_b64url)
        {
            *existing = rec;
        } else {
            self.credentials.push(rec);
        }
    }

    pub fn find_by_credential_id(&self, credential_id_b64url: &str) -> Option<&Record> {
        self.credentials
            .iter()
            .find(|r| r.credential_id_b64url == credential_id_b64url)
    }

    pub fn records(&self) -> &[Record] {
        &self.credentials
    }
}

/// `$HOME/.mkit-sign-ctap/credentials.json`. Not `$XDG_DATA_HOME`
/// because the integration target here is "user's home dir" — other
/// mkit signers (Secure Enclave) keep their state under `~/.mkit-*`
/// and we match the convention.
pub fn default_path() -> Result<PathBuf, SignerError> {
    let home = dirs::home_dir().ok_or(SignerError::Store(
        "cannot resolve HOME directory".to_owned(),
    ))?;
    Ok(home.join(".mkit-sign-ctap").join("credentials.json"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn rec(id: &str) -> Record {
        Record {
            credential_id_b64url: id.to_owned(),
            public_key_sec1_uncompressed_hex: "04".to_owned() + &"aa".repeat(64),
            rp_id: "mkit.local".to_owned(),
            user_name: "alice".to_owned(),
            keyid: format!("p256:{}", "bb".repeat(33)),
        }
    }

    #[test]
    fn roundtrip_load_save() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("credentials.json");
        let mut s = Store::default();
        s.upsert(rec("ABC"));
        s.upsert(rec("XYZ"));
        s.save(&path).unwrap();

        let loaded = Store::load(&path).unwrap();
        assert_eq!(loaded.records().len(), 2);
        assert_eq!(loaded.find_by_credential_id("ABC").unwrap(), &rec("ABC"));
    }

    #[test]
    fn load_missing_is_empty() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("does-not-exist.json");
        let loaded = Store::load(&path).unwrap();
        assert!(loaded.records().is_empty());
    }

    #[test]
    fn upsert_replaces() {
        let mut s = Store::default();
        s.upsert(rec("A"));
        let mut updated = rec("A");
        updated.user_name = "bob".into();
        s.upsert(updated.clone());
        assert_eq!(s.records().len(), 1);
        assert_eq!(s.find_by_credential_id("A").unwrap().user_name, "bob");
    }
}
