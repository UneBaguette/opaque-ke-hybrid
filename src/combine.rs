//! Combines the OPAQUE session key and ML-KEM shared secret into a single
//! hybrid session key using HKDF-SHA512.
//!
//! Construction:
//! `hybrid_key = HKDF-SHA512(salt=none, ikm=opaque_ss || mlkem_ss, info="opaque-ke-hybrid-v1")`

use hkdf::Hkdf;
use sha2::Sha512;
use zeroize::Zeroizing;

use crate::error::HybridError;

/// Domain separation label for the hybrid key derivation.
const HYBRID_INFO: &[u8] = b"opaque-ke-hybrid-v1";

/// Output length of the hybrid session key in bytes (64 bytes = 512 bits).
pub const HYBRID_KEY_LEN: usize = 64;

/// Combines an OPAQUE session key and an ML-KEM shared secret into a single
/// hybrid session key via HKDF-SHA512.
///
/// Both inputs must be present, if either is compromised the other still
/// provides full classical or post-quantum security respectively.
pub fn combine(
    opaque_session_key: &[u8],
    mlkem_shared_secret: &[u8],
) -> Result<Zeroizing<[u8; HYBRID_KEY_LEN]>, HybridError> {
    // Concatenate both secrets as IKM
    let mut ikm = Zeroizing::new(Vec::with_capacity(
        opaque_session_key.len() + mlkem_shared_secret.len(),
    ));

    ikm.extend_from_slice(opaque_session_key);
    ikm.extend_from_slice(mlkem_shared_secret);

    let hkdf = Hkdf::<Sha512>::new(None, ikm.as_slice());

    let mut out = Zeroizing::new([0u8; HYBRID_KEY_LEN]);

    hkdf.expand(HYBRID_INFO, out.as_mut_slice())
        .map_err(|_| HybridError::KeyDerivation)?;

    Ok(out)
}
