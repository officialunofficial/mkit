//! Native HTTPS trust: compiled Mozilla roots plus an explicit PEM CA file.
use std::{path::Path, sync::Arc};

use connectrpc::rustls::{
    ClientConfig, RootCertStore,
    pki_types::{CertificateDer, pem::PemObject},
};
use mkit_core::protocol::{TransportError, TransportResult};

/// Extra native HTTPS trust file; takes precedence over the caller's config path.
pub const CA_FILE_ENV: &str = "MKIT_SSL_CA_FILE";

fn invalid(path: &Path, message: &str) -> TransportError {
    TransportError::TlsConfiguration(format!("CA file {}: {message}", path.display()))
}

fn root_store(ca_file: Option<&Path>) -> TransportResult<RootCertStore> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(path) = ca_file {
        // Parse one snapshot: validation and certificate loading must see the
        // same file even if an operator replaces it concurrently.
        let bytes =
            std::fs::read(path).map_err(|_| invalid(path, "cannot read certificate file"))?;
        if !matched_pem_sections(&bytes) {
            return Err(invalid(path, "unmatched PEM section framing"));
        }
        let certificates = CertificateDer::pem_slice_iter(&bytes);
        let mut added = 0;
        for certificate in certificates {
            let certificate =
                certificate.map_err(|_| invalid(path, "cannot read or parse PEM certificates"))?;
            roots
                .add(certificate)
                .map_err(|_| invalid(path, "invalid certificate"))?;
            added += 1;
        }
        if added == 0 {
            return Err(invalid(path, "no PEM certificates found"));
        }
    }
    Ok(roots)
}

// The dependency PEM parser tolerates a nested BEGIN by replacing an open
// section. Reject that recovery, orphan ENDs and unterminated sections before
// handing certificate decoding and DER validation to the existing parser.
fn matched_pem_sections(bytes: &[u8]) -> bool {
    let mut section = None;
    for line in bytes.split(|byte| *byte == b'\n').map(<[u8]>::trim_ascii) {
        if line.starts_with(b"-----BEGIN") {
            let Some(label) = line
                .strip_prefix(b"-----BEGIN ")
                .and_then(|line| line.strip_suffix(b"-----"))
            else {
                return false;
            };
            if section.is_some() || label.is_empty() {
                return false;
            }
            section = Some(label);
        } else if line.starts_with(b"-----END") {
            let label = line
                .strip_prefix(b"-----END ")
                .and_then(|line| line.strip_suffix(b"-----"));
            if section.is_none() || label != section {
                return false;
            }
            section = None;
        }
    }
    section.is_none()
}

/// Build native HTTPS configuration without weakening verification.
/// Environment selection overrides the caller's optional config path. Added
/// certificates augment Mozilla roots; certificate chains and hostnames are
/// checked by rustls. Browser clients keep browser-managed trust.
/// # Errors
/// A selected CA file is missing, unreadable, malformed, or contains no certificates.
pub fn client_config(ca_file: Option<&Path>) -> TransportResult<Arc<ClientConfig>> {
    let selected = std::env::var_os(CA_FILE_ENV);
    let path = selected.as_deref().map(Path::new).or(ca_file);
    let roots = root_store(path)?;
    // Keep a consuming application's already-installed provider, if any.
    let _ = connectrpc::rustls::crypto::ring::default_provider().install_default();
    Ok(Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn ca() -> &'static Path {
        Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/ca/ca.crt"
        ))
    }
    #[test]
    fn pem_certificates_augment_every_mozilla_root() {
        let original = root_store(None).unwrap();
        let added = root_store(Some(ca())).unwrap();
        assert_eq!(added.len(), original.len() + 1);
        assert_eq!(&added.roots[..original.len()], original.roots.as_slice());
        let bundle = tempfile::NamedTempFile::new().unwrap();
        let cert = std::fs::read(ca()).unwrap();
        std::fs::write(bundle.path(), [cert.clone(), cert].concat()).unwrap();
        assert_eq!(
            root_store(Some(bundle.path())).unwrap().len(),
            original.len() + 2
        );
    }
    #[test]
    fn unmatched_certificate_frame_cannot_be_hidden_by_a_valid_certificate() {
        let file = tempfile::NamedTempFile::new().unwrap();
        for prefix in [
            b"-----BEGIN CERTIFICATE-----\n".as_slice(),
            b"-----END CERTIFICATE-----\n",
        ] {
            let mut bytes = prefix.to_vec();
            bytes.extend(std::fs::read(ca()).unwrap());
            std::fs::write(file.path(), bytes).unwrap();
            assert!(
                root_store(Some(file.path())).is_err(),
                "invalid framing must fail even when a later certificate is valid"
            );
        }
    }
    #[test]
    fn bad_or_unreadable_selected_files_are_hard_errors() {
        let dir = tempfile::tempdir().unwrap();
        for contents in [
            b"".as_slice(),
            b"not a certificate",
            b"-----BEGIN CERTIFICATE-----\nnot-base64!!\n-----END CERTIFICATE-----\n",
            b"-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n",
            b"-----BEGIN CERTIFICATE-----\nAQID\n",
        ] {
            let path = dir.path().join("invalid.crt");
            std::fs::write(&path, contents).unwrap();
            assert!(matches!(
                root_store(Some(&path)),
                Err(TransportError::TlsConfiguration(_))
            ));
        }
        for path in [dir.path().join("missing.crt"), dir.path().to_owned()] {
            let error = root_store(Some(&path)).unwrap_err();
            assert!(matches!(error, TransportError::TlsConfiguration(_)));
            assert!(error.to_string().contains(&path.display().to_string()));
        }
        let partial = dir.path().join("partial.crt");
        let mut bytes = std::fs::read(ca()).unwrap();
        bytes.extend_from_slice(b"-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n");
        std::fs::write(&partial, bytes).unwrap();
        assert!(
            root_store(Some(&partial)).is_err(),
            "one valid certificate cannot hide a bad later certificate"
        );
    }
}
