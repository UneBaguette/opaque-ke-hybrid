//! Hybrid client login wrapping [`ClientLogin`] with ML-KEM-768.

use ml_kem::array::Array;
use ml_kem::{
    Encoded, EncodedSizeUser, KemCore, MlKem768, MlKem768Params,
    kem::{Decapsulate, DecapsulationKey},
};
use opaque_ke::rand::{CryptoRng, RngCore};
use opaque_ke::{
    CipherSuite, ClientLogin, ClientLoginFinishParameters, CredentialFinalization,
    CredentialResponse,
};
use zeroize::Zeroizing;

use crate::combine::{HYBRID_KEY_LEN, combine};
use crate::error::HybridError;
use crate::messages::{CT_LEN, EK_LEN, HybridCredentialRequest};

/// Client state held between [`HybridClientLogin::start`] and [`HybridClientLogin::finish`].
pub struct HybridClientLogin<CS: CipherSuite> {
    opaque_state: ClientLogin<CS>,
    mlkem_dk: DecapsulationKey<MlKem768Params>,
}

/// Result of [`HybridClientLogin::start`].
pub struct HybridClientLoginStartResult<CS: CipherSuite> {
    /// Client state to persist for the finish step
    pub state: HybridClientLogin<CS>,
    /// Hybrid message to send to the server
    pub message: HybridCredentialRequest,
    /// The raw opaque-ke KE1 message, caller must serialize this themselves
    /// using `result.message.serialize()` where the trait bounds are in scope
    pub opaque_message: opaque_ke::CredentialRequest<CS>,
}

/// Result of [`HybridClientLogin::finish`].
pub struct HybridClientLoginFinishResult<CS: CipherSuite> {
    /// Combined hybrid session key
    pub session_key: Zeroizing<[u8; HYBRID_KEY_LEN]>,
    /// Credential finalization message to send to the server
    pub message: CredentialFinalization<CS>,
}

impl<CS: CipherSuite> HybridClientLogin<CS> {
    /// Start a hybrid login.
    ///
    /// Runs [`ClientLogin::start`] and generates an ephemeral ML-KEM-768
    /// keypair. The encapsulation key is sent to the server inside
    /// [`HybridCredentialRequest`].
    pub fn start(
        rng: &mut (impl CryptoRng + RngCore),
        password: &[u8],
    ) -> Result<HybridClientLoginStartResult<CS>, HybridError> {
        let opaque_result = ClientLogin::<CS>::start(rng, password)?;

        let (mlkem_dk, mlkem_ek) = MlKem768::generate(rng);

        let mlkem_ek_bytes: [u8; EK_LEN] = mlkem_ek
            .as_bytes()
            .as_slice()
            .try_into()
            .map_err(|_| HybridError::Serialization)?;

        // NOTE: we return opaque_message raw so the caller can serialize it
        // where the internal opaque-ke trait bounds are satisfied
        Ok(HybridClientLoginStartResult {
            state: HybridClientLogin {
                opaque_state: opaque_result.state,
                mlkem_dk,
            },
            // opaque_bytes left empty, caller fills it via opaque_message.serialize()
            message: HybridCredentialRequest::new(vec![], mlkem_ek_bytes),
            opaque_message: opaque_result.message,
        })
    }

    /// Returns the underlying opaque-ke client state for serialization
    /// at API boundaries.
    pub fn opaque_state(&self) -> &ClientLogin<CS> {
        &self.opaque_state
    }

    /// Serialize the ML-KEM-768 decapsulation key for storage at API boundaries.
    /// Treat this with the same care as [`ClientLogin::serialize`]
    /// It is secret key material.
    pub fn mlkem_dk_bytes(&self) -> Vec<u8> {
        self.mlkem_dk.as_bytes().as_slice().to_vec()
    }

    /// Reconstruct a [`HybridClientLogin`] from an already-deserialized
    /// [`ClientLogin`] and raw ML-KEM decapsulation key bytes.
    ///
    /// Intended for use at any API boundary where client state must be
    /// serialized between the start and finish steps.
    ///
    /// # Errors
    ///
    /// Returns [`HybridError::Serialization`] if `mlkem_dk_bytes` is not
    /// a valid ML-KEM-768 decapsulation key.
    pub fn from_parts(
        opaque_state: ClientLogin<CS>,
        mlkem_dk_bytes: &[u8],
    ) -> Result<Self, HybridError> {
        let encoded = Encoded::<DecapsulationKey<MlKem768Params>>::try_from(mlkem_dk_bytes)
            .map_err(|_| HybridError::Serialization)?;
        let mlkem_dk = DecapsulationKey::<MlKem768Params>::from_bytes(&encoded);

        Ok(Self {
            opaque_state,
            mlkem_dk,
        })
    }

    /// Finish a hybrid login.
    ///
    /// Accepts the already-deserialized [`CredentialResponse`]. The caller
    /// is responsible for deserializing it where the required bounds are
    /// in scope. Also accepts the raw ML-KEM ciphertext bytes separately
    /// via [`HybridCredentialResponse`].
    ///
    /// Combines both session keys via HKDF-SHA512.
    pub fn finish(
        self,
        rng: &mut (impl CryptoRng + RngCore),
        password: &[u8],
        opaque_response: CredentialResponse<CS>,
        mlkem_ct_bytes: &[u8; CT_LEN],
        params: ClientLoginFinishParameters<CS>,
    ) -> Result<HybridClientLoginFinishResult<CS>, HybridError> {
        let opaque_result = self
            .opaque_state
            .finish(rng, password, opaque_response, params)?;

        let mlkem_ct = Array::from(*mlkem_ct_bytes);

        let mlkem_ss = self
            .mlkem_dk
            .decapsulate(&mlkem_ct)
            .map_err(|_| HybridError::DecapsulationFailed)?;

        let session_key = combine(&opaque_result.session_key, &mlkem_ss)?;

        Ok(HybridClientLoginFinishResult {
            session_key,
            message: opaque_result.message,
        })
    }
}
