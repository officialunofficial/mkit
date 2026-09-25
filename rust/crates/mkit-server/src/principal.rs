//! Principals: who a request acts as (PRD §5.4 stage 1, identity mapping).

/// The identity a request was mapped to. Non-exhaustive: M2 may add a
/// caller-view class.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Principal {
    /// No credentials.
    Anonymous,
    /// An auth v2 signer.
    Signer {
        /// The signer's raw Ed25519 public key.
        ed25519: [u8; 32],
    },
    /// Holder of a deployment-wide shared bearer token (today's
    /// `mkit serve --http`).
    BearerHolder,
    /// The authenticated peer of an encrypted (`enc`) listener.
    TransportPeer {
        /// The peer's raw Ed25519 static key.
        ed25519: [u8; 32],
    },
    /// `mkit serve` over stdio. The identity is the ssh forced command
    /// (SSH-SECURITY §5). `key` is always `None` in M0; WP-1.15 sets it from
    /// `mkit serve --principal <ed25519-hex>`.
    SshForcedCommand {
        /// The Ed25519 key the forced command names, if any.
        key: Option<[u8; 32]>,
    },
}

impl Principal {
    /// The principal's Ed25519 public key, when it has one.
    #[must_use]
    pub fn ed25519(&self) -> Option<&[u8; 32]> {
        match self {
            Self::Signer { ed25519 } | Self::TransportPeer { ed25519 } => Some(ed25519),
            Self::SshForcedCommand { key } => key.as_ref(),
            Self::Anonymous | Self::BearerHolder => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ed25519_accessor_covers_ssh_key_some_and_none() {
        let key = [7u8; 32];
        assert_eq!(Principal::Signer { ed25519: key }.ed25519(), Some(&key));
        assert_eq!(
            Principal::TransportPeer { ed25519: key }.ed25519(),
            Some(&key)
        );
        assert_eq!(
            Principal::SshForcedCommand { key: Some(key) }.ed25519(),
            Some(&key)
        );
        assert_eq!(Principal::SshForcedCommand { key: None }.ed25519(), None);
        assert_eq!(Principal::Anonymous.ed25519(), None);
        assert_eq!(Principal::BearerHolder.ed25519(), None);
    }
}
