use crate::traits::Group;
use num_bigint::{BigInt, BigUint};
use rand::thread_rng;
use rand::RngCore;
use std::collections::HashSet;
use zeroize::Zeroizing;

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(transparent)
)]
pub struct RsaMembershipProof(pub BigUint);

/// A non-membership witness `(a, b)` such that `acc^a · b^x = g`.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RsaNonMembershipProof {
    pub a: BigInt,
    pub b: BigUint,
}

/// A blinded membership witness.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(transparent)
)]
pub struct RsaBlindedMembershipProof(pub BigUint);

/// A blinded non-membership witness `(value, q)` where `value = element * q`.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RsaBlindedNonMembershipProof {
    pub value: BigUint,
    pub q: BigUint,
}

/// A single DLEQ proof `(a, b, z)`.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RsaDleqProof {
    pub a: BigUint,
    pub b: BigUint,
    pub z: BigUint,
}

/// Auxiliary NIZK data accompanying an updated blinded membership proof.
///
/// Contains two DLEQ proofs: `pi1` witnesses the accumulator update and
/// `pi2` witnesses the blinded proof update.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RsaNizkAux {
    pub pi1: RsaDleqProof,
    pub pi2: RsaDleqProof,
}

/// An updated blinded membership witness `(a, b)` together with its NIZK
/// auxiliary data.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RsaUpdatedBlindedMembershipProof {
    pub a: BigUint,
    pub b: BigUint,
}

/// An updated blinded non-membership witness `(a, b)`.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RsaUpdatedBlindedNonMembershipProof {
    pub a: BigInt,
    pub b: BigUint,
}

pub(super) type Aux = ((BigUint, BigUint, BigUint), (BigUint, BigUint, BigUint));
pub(super) type UpdatedBlindProof = ((BigUint, BigUint), Aux, BigUint);

impl RsaMembershipProof {
    pub fn from_raw(v: BigUint) -> Self {
        Self(v)
    }
    pub fn into_raw(self) -> BigUint {
        self.0
    }
}

impl RsaNonMembershipProof {
    pub fn from_raw(a: BigInt, b: BigUint) -> Self {
        Self { a, b }
    }
    pub fn into_raw(self) -> (BigInt, BigUint) {
        (self.a, self.b)
    }
}

impl RsaBlindedMembershipProof {
    pub fn from_raw(v: BigUint) -> Self {
        Self(v)
    }
    pub fn into_raw(self) -> BigUint {
        self.0
    }
}

impl RsaBlindedNonMembershipProof {
    pub fn from_raw(value: BigUint, q: BigUint) -> Self {
        Self { value, q }
    }
    pub fn into_raw(self) -> (BigUint, BigUint) {
        (self.value, self.q)
    }
}

impl RsaDleqProof {
    pub fn from_raw(t: (BigUint, BigUint, BigUint)) -> Self {
        Self {
            a: t.0,
            b: t.1,
            z: t.2,
        }
    }
    pub fn into_raw(self) -> (BigUint, BigUint, BigUint) {
        (self.a, self.b, self.z)
    }
}

impl RsaNizkAux {
    pub fn from_raw(t: Aux) -> Self {
        Self {
            pi1: RsaDleqProof::from_raw(t.0),
            pi2: RsaDleqProof::from_raw(t.1),
        }
    }
    pub fn into_raw(self) -> Aux {
        (self.pi1.into_raw(), self.pi2.into_raw())
    }
}

impl RsaUpdatedBlindedMembershipProof {
    pub fn from_raw(a: BigUint, b: BigUint) -> Self {
        Self { a, b }
    }
    pub fn into_raw(self) -> (BigUint, BigUint) {
        (self.a, self.b)
    }
}

impl RsaUpdatedBlindedNonMembershipProof {
    pub fn from_raw(a: BigInt, b: BigUint) -> Self {
        Self { a, b }
    }
    pub fn into_raw(self) -> (BigInt, BigUint) {
        (self.a, self.b)
    }
}

#[derive(Clone, Debug)]
pub struct RsaAccumulator<G: Group> {
    pub group: G,
    pub acc: G::Element,
    pub set: HashSet<G::Exponent>,
}

impl<G: Group> RsaAccumulator<G> {
    pub fn add_raw<T: ToString>(&mut self, element: &T) -> G::Exponent {
        let x_str = element.to_string();
        let x_prime = self.group.hash_to_prime(x_str.as_bytes());

        if self.set.insert(x_prime.clone()) {
            self.acc = self.group.exp(&self.acc, &x_prime);
        }

        x_prime
    }

    pub fn mem_ver_raw(&self, proof: &G::Element, element: &G::Exponent) -> bool {
        self.group.exp(proof, element) == self.acc
    }

    pub fn blind_mem_proof_raw(&self, proof: &G::Element) -> (G::Element, G::Exponent) {
        let blinder = self.sample_blinder();
        let mask = self.group.exp(&self.group.g(), &blinder);
        let blinded_proof = self.group.mul(proof, &mask);
        (blinded_proof, blinder)
    }

    pub fn unblind_mem_proof_raw(
        &self,
        blinded_proof: &G::Element,
        st: &G::Exponent,
    ) -> G::Element {
        let st_mask = self.group.exp(&self.group.g(), st);
        let st_inv = self.group.inv(&st_mask);
        self.group.mul(blinded_proof, &st_inv)
    }

    fn sample_blinder(&self) -> G::Exponent {
        let mut seed = Zeroizing::new([0u8; 32]);
        thread_rng().fill_bytes(seed.as_mut());
        self.group.hash_to_prime(seed.as_ref())
    }
}

#[cfg(feature = "class-group")]
mod class_group;
mod rsa;
