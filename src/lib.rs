//! **ML-KEM** hybrid extension for **opaque-ke**.
//!
//! Adds post-quantum hardening to the **AKE** layer by running
//! **ML-KEM-768** in parallel with the existing **`TripleDh`** key exchange,
//! combining both shared secrets via **HKDF-SHA512**.
//!
//! The session key produced by this crate is resistant to
//! **harvest-now-decrypt-later** attacks by a future quantum adversary,
//! while preserving all existing **OPAQUE** security guarantees.
//!
//! ## Limitations
//!
//! **Security note:** This crate uses a parallel hybrid combiner.
//! Recent research ([draft-vos-cfrg-pqpake](https://datatracker.ietf.org/doc/draft-vos-cfrg-pqpake/))
//! suggests a sequential composition is theoretically stronger.
//! This crate remains a practical improvement over plain **OPAQUE**
//! for **harvest-now-decrypt-later** threats today.

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::pedantic)]

pub mod client;
pub mod error;
pub mod messages;
pub mod server;

pub(crate) mod combine;

pub use opaque_ke;
