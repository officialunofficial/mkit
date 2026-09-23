//! Run only against disposable local workerd after managed_disclosure.py --hold.
use std::{env, sync::Arc};

use ed25519_dalek::{Signer as _, SigningKey};
use mkit_core::{
    hash::{from_hex, to_hex_bytes},
    partial::ScopedWorkspaceLayout,
};
use mkit_transport_connect::{
    ConnectTransport, EnvelopeSigner, HostedWorkspaceRequest, hosted_partial_limits,
};

struct Subject(SigningKey);
impl EnvelopeSigner for Subject {
    fn public_key_hex(&self) -> String {
        to_hex_bytes(&self.0.verifying_key().to_bytes())
    }
    fn sign_hex(&self, digest: &[u8; 32]) -> Result<String, String> {
        Ok(to_hex_bytes(&self.0.sign(digest).to_bytes()))
    }
}

#[test]
fn actual_native_to_local_workerd_selected_bundle_and_layout() {
    let Ok(base) = env::var("MKIT_HOSTED_TEST_BASE") else {
        return;
    };
    let grant_id = env::var("MKIT_HOSTED_TEST_GRANT").expect("grant id");
    let base = from_hex(&base).unwrap();
    let endpoint = "mkit+http://localhost:8791/managed-test";
    let transport = ConnectTransport::connect_with_signed_reads(
        endpoint,
        Arc::new(Subject(SigningKey::from_bytes(&[8; 32]))),
    )
    .unwrap();
    let paths = vec![vec![b"file0000".to_vec()]];
    let request = HostedWorkspaceRequest {
        workspace_id: "0b".repeat(32),
        grant_id,
        grant_generation: env::var("MKIT_HOSTED_TEST_GENERATION").unwrap_or_else(|_| "1".into()),
        expected_ref: "refs/heads/snapshot-test".into(),
        expected_base: base,
        paths: paths.clone(),
    };
    let limits = hosted_partial_limits();
    let result = transport
        .get_hosted_workspace(&request, base, &paths, &limits)
        .unwrap();
    assert_eq!(result.verified().paths(), paths);
    assert_eq!(result.verified().files().len(), 1);
    let temp = tempfile::tempdir().unwrap();
    let layout = ScopedWorkspaceLayout::create(
        &temp.path().join("scoped"),
        base,
        &paths,
        result.bytes(),
        limits,
        None,
    )
    .unwrap();
    assert!(layout.root().join("file0000").is_file());
}
