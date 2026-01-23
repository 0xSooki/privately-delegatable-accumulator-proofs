//! Privacy-Preserving Accumulator Proofs
//!
//! This library provides implementations of cryptographic accumulators
//!
//! ## Features
//!
//! - `rsa`: RSA-based accumulator implementation
//! - `bilinear`: Bilinear pairing-based accumulator implementation
//!
//! ## Example
//!
//! ```rust,ignore
//! use privacy_preserving_accumulators::RsaAccumulator;
//!
//! let mut acc = RsaAccumulator::setup();
//! ```

#[cfg(feature = "rsa")]
pub mod rsa_accumulator;

#[cfg(feature = "bilinear")]
pub mod bilinear_accumulator;

pub mod traits;

#[cfg(feature = "rsa")]
pub use rsa_accumulator::RsaAccumulator;

#[cfg(feature = "bilinear")]
pub use bilinear_accumulator::BilinearAccumulator;

pub use traits::Accumulator;
