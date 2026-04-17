use std::fmt::Debug;
use std::hash::Hash;

/// Trait for groups
pub trait Group: Clone + Debug {
    /// The element type in the group
    type Element: Clone + Debug + Eq + Hash;

    /// The exponent/scalar type
    type Exponent: Clone + Debug + Eq + Hash;

    /// Setup/initialize the group with necessary parameters
    fn setup() -> Self;

    /// Get the generator element
    fn g(&self) -> Self::Element;

    /// Identity element of the group
    fn id(&self) -> Self::Element;

    /// Group operation: multiply two elements
    fn mul(&self, a: &Self::Element, b: &Self::Element) -> Self::Element;

    /// Inverse of a group element
    fn inv(&self, element: &Self::Element) -> Self::Element;

    /// Exponentiation: base^exponent (derived operation)
    fn exp(&self, base: &Self::Element, exponent: &Self::Exponent) -> Self::Element;

    /// Identity element for exponents (usually 1)
    fn exp_id() -> Self::Exponent;

    /// Multiply two exponents
    fn exp_mul(a: &Self::Exponent, b: &Self::Exponent) -> Self::Exponent;

    /// Add two exponents
    fn exp_add(a: &Self::Exponent, b: &Self::Exponent) -> Self::Exponent;

    /// Serialize a group element to bytes
    fn element_to_bytes(&self, element: &Self::Element) -> Vec<u8>;

    /// Hash arbitrary data to a prime exponent
    fn hash_to_prime(&self, data: &[u8]) -> Self::Exponent;
}

/// Trait for accumulators with membership proofs
pub trait Accumulator {
    type Group: Group;
    type Element;
    type MembershipProof;
    type NonMembershipProof;
    type NonMembershipProduct;

    /// Create a new accumulator with the given group
    fn new(group: Self::Group) -> Self;

    /// Add an element to the accumulator
    fn add(&mut self, element: &Self::Element) -> <Self::Group as Group>::Exponent;

    /// Delete an element from the accumulator
    fn del(&mut self, element: &Self::Element);

    /// Get the current accumulator value
    fn value(&self) -> &<Self::Group as Group>::Element;

    /// Create a membership proof for an element
    fn mem_proof_create(&self, element: &<Self::Group as Group>::Exponent)
        -> Self::MembershipProof;

    /// Verify a membership proof
    fn mem_ver(
        &self,
        proof: &Self::MembershipProof,
        element: &<Self::Group as Group>::Exponent,
    ) -> bool;

    /// Create a non-membership proof for an element
    fn non_mem_proof_create(
        &self,
        element: &Self::Element,
        prod: &Self::NonMembershipProduct,
    ) -> Self::NonMembershipProof;

    /// Verify a non-membership proof
    fn non_mem_ver(&self, proof: &Self::NonMembershipProof, element: &Self::Element) -> bool;
}

pub trait PrivatelyDelegatableAccumulator: Accumulator {
    type BlindedMembershipProof;
    type MembershipBlindingFactor;
    type UpdatedBlindedMembershipProof;
    type MembershipUpdateAux;
    type BlindedNonMembershipProof;
    type UpdatedBlindedNonMembershipProof;
    type Delta;

    /// Blind a membership proof
    fn blind_mem_proof(
        &self,
        proof: &Self::MembershipProof,
    ) -> (Self::BlindedMembershipProof, Self::MembershipBlindingFactor);

    /// Update a blinded membership proof
    fn blind_mem_proof_upd(
        &self,
        acc_t: &<Self::Group as Group>::Element,
        blinded_proof: &Self::BlindedMembershipProof,
        delta: &Self::Delta,
    ) -> (
        Self::UpdatedBlindedMembershipProof,
        Self::MembershipUpdateAux,
        <Self::Group as Group>::Element,
    );

    /// Verify an updated blinded membership proof
    fn ver_blind_mem_proof_upd(
        &self,
        acc_t: &<Self::Group as Group>::Element,
        blinded_proof: &Self::BlindedMembershipProof,
        upd_blinded_proof: &Self::UpdatedBlindedMembershipProof,
        aux: &Self::MembershipUpdateAux,
    ) -> bool;

    /// Unblind a membership proof
    fn unblind_mem_proof(
        &self,
        blinded_proof: &Self::BlindedMembershipProof,
        st: &Self::MembershipBlindingFactor,
    ) -> Self::MembershipProof;

    /// Blind a non-membership proof
    fn blind_non_mem_proof(&self, element: &Self::Element) -> Self::BlindedNonMembershipProof;

    fn blind_non_mem_proof_upd(
        &self,
        blinded_non_mem_proof: &Self::BlindedNonMembershipProof,
        delta: &Self::Delta,
    ) -> Self::UpdatedBlindedNonMembershipProof;

    fn ver_blind_non_mem_proof_upd(
        &self,
        acc_t_prime: &<Self::Group as Group>::Element,
        blinded_non_mem_proof: &Self::BlindedNonMembershipProof,
        upd_blinded_non_mem_proof: &Self::UpdatedBlindedNonMembershipProof,
    ) -> bool;

    fn unblind_non_mem_proof(
        &self,
        st: &<Self::Group as Group>::Exponent,
        upd_blinded_non_mem_proof: &Self::UpdatedBlindedNonMembershipProof,
    ) -> Self::NonMembershipProof;
}
