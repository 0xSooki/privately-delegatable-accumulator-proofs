//! Private Accumulator Proof Delegation.
//!
//! This library provides implementations of cryptographic accumulators with
//! support for privacy-preserving (blinded) proof updates.
//!
//! # Cargo features
//!
//! - `rsa` *(default)* — RSA-group and class-group based accumulators.
//! - `bilinear` *(default)* — KZG / bilinear-pairing based accumulator.
//! - `class-group` — class-group (`class_group`/`curv-kzen`) backend for the
//!   RSA-style accumulator. Off by default because `curv` brings a number of
//!   transitive dependencies.
//! - `serde` — `serde::Serialize` / `serde::Deserialize` implementations for
//!   all RSA proof types. Bilinear proof types always implement
//!   `ark_serialize::CanonicalSerialize` / `CanonicalDeserialize`.
//!
//! # Example
//!
//! ```no_run
//! use num_bigint::BigUint;
//! use private_accumulator_proof_delegation::{rsa_group::RsaGroup, RsaAccumulator};
//!
//! let mut acc = RsaAccumulator::<RsaGroup>::setup();
//! let ep = acc.add_raw(&BigUint::from(7u32));
//! let proof = acc.mem_proof_create_raw(&ep).unwrap();
//! assert!(acc.mem_ver_raw(&proof, &ep));
//! ```

pub mod error;

#[cfg(feature = "rsa")]
pub mod rsa_accumulator;

#[cfg(any(feature = "rsa", feature = "bilinear"))]
pub mod groups;

#[cfg(feature = "bilinear")]
pub mod bilinear_accumulator;

#[cfg(feature = "rsa")]
pub mod math;
pub mod nizk;
pub mod traits;

pub use error::{AccumulatorError, AccumulatorResult};
pub use traits::{Accumulator, Group, PrivatelyDelegatableAccumulator};

#[cfg(feature = "rsa")]
pub use rsa_accumulator::RsaAccumulator;

#[cfg(feature = "rsa")]
pub use groups::rsa_group;

#[cfg(feature = "bilinear")]
pub use groups::bilinear_group;

#[cfg(feature = "bilinear")]
pub use bilinear_accumulator::BilinearAccumulator;

#[cfg(feature = "rsa")]
pub use rsa_accumulator::{
    RsaBlindedMembershipProof, RsaBlindedNonMembershipProof, RsaDleqProof, RsaMembershipProof,
    RsaNizkAux, RsaNonMembershipProof, RsaUpdatedBlindedMembershipProof,
    RsaUpdatedBlindedNonMembershipProof,
};

#[cfg(feature = "bilinear")]
pub use bilinear_accumulator::{
    MembershipProof as BilinearMembershipProof, NonMembershipProof as BilinearNonMembershipProof,
};
