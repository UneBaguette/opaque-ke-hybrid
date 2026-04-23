//! Hybrid server login wrapping [`ServerLogin`] with ML-KEM-768.

use ml_kem::{
    EncodedSizeUser, MlKem768Params,
    array::Array,
    kem::{Encapsulate, EncapsulationKey},
};
use opaque_ke::rand::{CryptoRng, RngCore};
use opaque_ke::{
    CipherSuite, CredentialFinalization, CredentialRequest, ServerLogin, ServerLoginParameters,
    ServerRegistration, ServerSetup,
};
use zeroize::Zeroizing;

use crate::combine::{HYBRID_KEY_LEN, combine};
use crate::error::HybridError;
use crate::messages::{CT_LEN, EK_LEN, HybridCredentialResponse};

/// Server state held between [`HybridServerLogin::start`] and
/// [`HybridServerLogin::finish`].
pub struct HybridServerLogin<CS: CipherSuite> {
    opaque_state: opaque_ke::ServerLogin<CS>,
    /// ML-KEM shared secret — held until finish to combine with opaque_ss
    mlkem_ss: Zeroizing<Vec<u8>>,
}

/// Result of [`HybridServerLogin::start`].
pub struct HybridServerLoginStartResult<CS: CipherSuite> {
    /// Server state to persist for the finish step
    pub state: HybridServerLogin<CS>,
    /// Hybrid message to send to the client
    pub message: HybridCredentialResponse,
    /// Raw opaque-ke KE2 message
    pub opaque_message: opaque_ke::CredentialResponse<CS>,
}

/// Result of [`HybridServerLogin::finish`].
pub struct HybridServerLoginFinishResult {
    /// Combined hybrid session key : HKDF(opaque_ss || mlkem_ss).
    /// Matches the client's session key on successful login.
    pub session_key: Zeroizing<[u8; HYBRID_KEY_LEN]>,
}

impl<CS: CipherSuite> HybridServerLogin<CS> {
    /// Start a hybrid server login.
    ///
    /// Runs [`ServerLogin::start`] with the opaque-ke credential request,
    /// then encapsulates against the client's ML-KEM encapsulation key.
    /// The ciphertext is sent back inside [`HybridCredentialResponse`].
    pub fn start(
        rng: &mut (impl CryptoRng + RngCore),
        server_setup: &ServerSetup<CS>,
        password_file: Option<ServerRegistration<CS>>,
        opaque_request: CredentialRequest<CS>,
        mlkem_ek_bytes: &[u8; EK_LEN],
        username: &[u8],
        params: ServerLoginParameters,
    ) -> Result<HybridServerLoginStartResult<CS>, HybridError> {
        // Standard opaque-ke server start
        let opaque_result = ServerLogin::start(
            rng,
            server_setup,
            password_file,
            opaque_request,
            username,
            params,
        )?;

        // Reconstruct client's encapsulation key from bytes
        let mlkem_ek_array = Array::from(*mlkem_ek_bytes);
        let mlkem_ek = EncapsulationKey::<MlKem768Params>::from_bytes(&mlkem_ek_array);

        // Encapsulate. Produces ciphertext to send + shared secret to keep
        let (mlkem_ct, mlkem_ss) = mlkem_ek
            .encapsulate(rng)
            .map_err(|_| HybridError::EncapsulationFailed)?;

        // Serialize mlkem_ct to fixed-size array
        let mlkem_ct_bytes: [u8; CT_LEN] = mlkem_ct
            .as_slice()
            .try_into()
            .map_err(|_| HybridError::Serialization)?;

        Ok(HybridServerLoginStartResult {
            state: HybridServerLogin {
                opaque_state: opaque_result.state,
                // store mlkem_ss zeroized until finish
                mlkem_ss: Zeroizing::new(mlkem_ss.to_vec()),
            },
            // opaque_bytes left empty, caller fills via opaque_message.serialize()
            message: HybridCredentialResponse::new(vec![], mlkem_ct_bytes),
            opaque_message: opaque_result.message,
        })
    }

    /// Finish a hybrid server login.
    ///
    /// Runs [`ServerLogin::finish`] and combines the opaque session key
    /// with the stored ML-KEM shared secret via HKDF-SHA512.
    pub fn finish(
        self,
        opaque_finalization: CredentialFinalization<CS>,
        params: ServerLoginParameters,
    ) -> Result<HybridServerLoginFinishResult, HybridError> {
        let opaque_result = self.opaque_state.finish(opaque_finalization, params)?;

        let session_key = combine(opaque_result.session_key.as_ref(), &self.mlkem_ss)?;

        Ok(HybridServerLoginFinishResult { session_key })
    }
}
