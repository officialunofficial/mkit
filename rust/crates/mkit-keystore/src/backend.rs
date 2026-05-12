//! Backend construction helpers.

use crate::{BackendKind, Error, Keystore, Result, SoftwareKeystore};

/// Open a backend by family.
///
/// Backends that are not implemented or not compiled in for the current target
/// fail closed with a typed unavailable-backend error.
pub fn open_backend(kind: BackendKind) -> Result<Box<dyn Keystore>> {
    match kind {
        BackendKind::Software => Ok(Box::new(SoftwareKeystore::new()?)),
        other => Err(Error::BackendUnavailable(format!(
            "backend `{other}` is not implemented in this build"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_backend_fails_closed() {
        match open_backend(BackendKind::YubiKey) {
            Err(Error::BackendUnavailable(_)) => {}
            Err(error) => panic!("unexpected error: {error}"),
            Ok(_) => panic!("unexpected backend"),
        }
    }
}
