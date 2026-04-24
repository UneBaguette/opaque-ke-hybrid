//! Error types for the `opaque-ke-hybrid` crate.

use core::fmt;

/// Errors that can occur during a hybrid OPAQUE + ML-KEM login.
#[derive(Debug)]
pub enum HybridError {
    /// Error from underlying opaque-ke protocol
    Protocol(opaque_ke::errors::ProtocolError),
    /// ML-KEM decapsulation failed
    DecapsulationFailed,
    /// ML-KEM encapsulation failed
    EncapsulationFailed,
    /// Serialization/deserialization error
    Serialization,
    /// HKDF key derivation failed
    KeyDerivation,
}

impl fmt::Display for HybridError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(e) => write!(f, "OPAQUE protocol error: {e}"),
            Self::DecapsulationFailed => write!(f, "ML-KEM decapsulation failed"),
            Self::EncapsulationFailed => write!(f, "ML-KEM encapsulation failed"),
            Self::Serialization => write!(f, "Serialization error"),
            Self::KeyDerivation => write!(f, "Hybrid key derivation failed"),
        }
    }
}

impl std::error::Error for HybridError {}

impl From<opaque_ke::errors::ProtocolError> for HybridError {
    fn from(e: opaque_ke::errors::ProtocolError) -> Self {
        Self::Protocol(e)
    }
}
