//! Hybrid message types wrapping opaque-ke messages with ML-KEM material.
//!
//! Wire format:
//!
//! `HybridCredentialRequest`  = `CredentialRequest` bytes || `mlkem_ek` bytes
//! `HybridCredentialResponse` = `CredentialResponse` bytes || `mlkem_ct` bytes
//!
//! All sizes are statically known. No length prefix required.

use crate::error::HybridError;

/// Byte length of an ML-KEM-768 encapsulation key.
pub const EK_LEN: usize = 1184;
/// Byte length of an ML-KEM-768 ciphertext.
pub const CT_LEN: usize = 1088;

/// Wraps a serialized [`opaque_ke::CredentialRequest`] with an ML-KEM-768
/// encapsulation key. Sent client to server at login start.
pub struct HybridCredentialRequest {
    opaque_bytes: Vec<u8>,
    mlkem_ek: [u8; EK_LEN],
}

/// Wraps a serialized [`opaque_ke::CredentialResponse`] with an ML-KEM-768
/// ciphertext. Sent server to client at login response.
pub struct HybridCredentialResponse {
    opaque_bytes: Vec<u8>,
    mlkem_ct: [u8; CT_LEN],
}

impl HybridCredentialRequest {
    /// Construct from serialized opaque-ke bytes and an ML-KEM encapsulation key.
    #[must_use]
    pub fn new(opaque_bytes: Vec<u8>, mlkem_ek: [u8; EK_LEN]) -> Self {
        Self {
            opaque_bytes,
            mlkem_ek,
        }
    }

    /// Returns the serialized opaque-ke credential request bytes.
    #[must_use]
    pub fn opaque_bytes(&self) -> &[u8] {
        &self.opaque_bytes
    }

    /// Returns the ML-KEM-768 encapsulation key bytes.
    #[must_use]
    pub fn mlkem_ek(&self) -> &[u8; EK_LEN] {
        &self.mlkem_ek
    }

    /// Serialize for transmission.
    ///
    /// Format: `[opaque_ke bytes][mlkem_ek (1184 bytes)]`
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.opaque_bytes.len() + EK_LEN);

        out.extend_from_slice(&self.opaque_bytes);
        out.extend_from_slice(&self.mlkem_ek);

        out
    }

    /// Deserialize from bytes.
    ///
    /// Splits the last 1184 bytes as the ML-KEM encapsulation key,
    /// the rest as the opaque-ke credential request.
    ///
    /// # Errors
    ///
    /// Returns [`HybridError::Serialization`] if the input is shorter than the expected ML-KEM key length.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, HybridError> {
        if bytes.len() < EK_LEN {
            return Err(HybridError::Serialization);
        }

        let split = bytes.len() - EK_LEN;

        Ok(Self {
            opaque_bytes: bytes[..split].to_vec(),
            mlkem_ek: bytes[split..]
                .try_into()
                .map_err(|_| HybridError::Serialization)?,
        })
    }
}

impl HybridCredentialResponse {
    /// Construct from serialized opaque-ke bytes and an ML-KEM ciphertext.
    #[must_use]
    pub fn new(opaque_bytes: Vec<u8>, mlkem_ct: [u8; CT_LEN]) -> Self {
        Self {
            opaque_bytes,
            mlkem_ct,
        }
    }

    /// Returns the serialized opaque-ke credential response bytes.
    #[must_use]
    pub fn opaque_bytes(&self) -> &[u8] {
        &self.opaque_bytes
    }

    /// Returns the ML-KEM-768 ciphertext bytes.
    #[must_use]
    pub fn mlkem_ct(&self) -> &[u8; CT_LEN] {
        &self.mlkem_ct
    }

    /// Serialize for transmission.
    ///
    /// Format: `[opaque_ke bytes][mlkem_ct (1088 bytes)]`
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.opaque_bytes.len() + CT_LEN);

        out.extend_from_slice(&self.opaque_bytes);
        out.extend_from_slice(&self.mlkem_ct);

        out
    }

    /// Deserialize from bytes.
    ///
    /// Splits the last 1088 bytes as the ML-KEM ciphertext,
    /// the rest as the opaque-ke credential response.
    ///
    /// # Errors
    ///
    /// Returns [`HybridError::Serialization`] if the input is too short or malformed.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, HybridError> {
        if bytes.len() < CT_LEN {
            return Err(HybridError::Serialization);
        }

        let split = bytes.len() - CT_LEN;

        Ok(Self {
            opaque_bytes: bytes[..split].to_vec(),
            mlkem_ct: bytes[split..]
                .try_into()
                .map_err(|_| HybridError::Serialization)?,
        })
    }
}
