//! TLS 1.3 key-exchange policy and evidence for TLS and QUIC.

use core::fmt;

use super::Group;

/// The key exchanges this end permits. Certificate authentication has its own policy.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum KeyExchangeProfile {
    /// Offer X25519MLKEM768 and X25519. A server prefers the hybrid group, even when it needs a second ClientHello.
    #[default]
    Default,
    /// Require X25519MLKEM768. A classical-only peer cannot complete the handshake.
    Strict,
    /// Use only X25519 for this configuration.
    Classical,
}

impl KeyExchangeProfile {
    /// The explanation to retain if the completed handshake selects X25519.
    pub(super) fn if_classical(self, default: ClassicalSelection) -> Option<ClassicalSelection> {
        match self {
            Self::Default => Some(default),
            Self::Strict => None,
            Self::Classical => Some(ClassicalSelection::ExplicitProfile),
        }
    }
}

/// Why the authenticated handshake selected a classical key exchange.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClassicalSelection {
    /// The server selected X25519 from this client's offer of both hybrid and classical groups.
    PeerSelected,
    /// This default server received a client offer without X25519MLKEM768.
    NoHybridOffer,
    /// The caller explicitly configured this end to use only X25519.
    ExplicitProfile,
}

impl fmt::Display for Group {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::X25519_MLKEM768 => f.write_str("X25519MLKEM768"),
            Self::X25519 => f.write_str("X25519"),
            Self(code) => write!(f, "0x{code:04x}"),
        }
    }
}
