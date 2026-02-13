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
    fn gen(&self) -> Self::Element;
    
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
    
    /// Hash arbitrary data to a prime exponent
    fn hash_to_prime(&self, data: &[u8]) -> Self::Exponent;
}

/// Trait for accumulators with membership proofs
pub trait Accumulator {
    type Group: Group;
    type Element;
    type MembershipProof;
    type NonMembershipProof;
    
    /// Create a new accumulator with the given group
    fn new(group: Self::Group) -> Self;
    
    /// Add an element to the accumulator
    fn add(&mut self, element: &Self::Element) -> <Self::Group as Group>::Exponent;
    
    /// Delete an element from the accumulator
    fn del(&mut self, element: &Self::Element);
    
    /// Get the current accumulator value
    fn value(&self) -> &<Self::Group as Group>::Element;
    
    /// Create a membership proof for an element
    fn mem_proof_create(&self, element: &<Self::Group as Group>::Exponent) -> Self::MembershipProof;
    
    /// Verify a membership proof
    fn mem_ver(
        &self,
        proof: &Self::MembershipProof,
        element: &<Self::Group as Group>::Exponent,
    ) -> bool;
    
    /// Create a non-membership proof for an element
    fn non_mem_proof_create(&self, element: &Self::Element) -> Self::NonMembershipProof;
    
    /// Verify a non-membership proof
    fn non_mem_ver(
        &self,
        proof: &Self::NonMembershipProof,
        element: &Self::Element,
    ) -> bool;


    // Blind a proof
    //fn blind_proof(&self, proof: &BigUint) -> (BigUint, BigUint)

    // Verify a blinded proof
    // Unblind a proof
}
