//! ML-KEM hybrid extension for opaque-ke.
//!
//! Adds post-quantum hardening to the AKE layer by running
//! ML-KEM-768 in parallel with the existing TripleDh key exchange,
//! combining both shared secrets via HKDF.
//!
//! # Example
//! ```rust
//! use opaque_ke_hybrid::client::HybridClientLogin;
//! use opaque_ke_hybrid::server::HybridServerLogin;
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::pedantic)]

pub mod client;
pub mod server;
pub mod combine;
pub mod messages;
pub mod error;

pub use opaque_ke;
pub use ml_kem;