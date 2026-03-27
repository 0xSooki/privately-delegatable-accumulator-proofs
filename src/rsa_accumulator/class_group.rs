use super::RsaAccumulator;
use crate::groups::class_group::{ClassGroup, ClassGroupElement, ClassGroupExponent};
use crate::traits::{Accumulator, Group, PrivatelyDelegatableAccumulator};
use curv::BigInt;
use num_integer::{ExtendedGcd, Integer};
use num_traits::{One, Zero};
use std::collections::HashSet;

fn class_exp_to_num(exp: &ClassGroupExponent) -> BigInt {
    exp.0.clone()
}

fn class_group_signed_exp(
    group: &ClassGroup,
    base: &ClassGroupElement,
    exponent: &BigInt,
) -> ClassGroupElement {
    if exponent < &BigInt::zero() {
        let pos = group.exp(base, &ClassGroupExponent((-exponent).clone()));
        group.inv(&pos)
    } else {
        group.exp(base, &ClassGroupExponent(exponent.clone()))
    }
}

impl RsaAccumulator<ClassGroup> {
    pub fn setup() -> RsaAccumulator<ClassGroup> {
        let group = ClassGroup::setup();
        Self::new(group)
    }

    pub fn del<T: ToString>(&mut self, element: &T) {
        let x_str = element.to_string();
        let x_prime = ClassGroup::hash_bytes_to_prime(x_str.as_bytes());
        let x_exp = ClassGroupExponent(x_prime);

        if self.set.remove(&x_exp) {
            self.acc = self
                .set
                .iter()
                .filter(|&e| e != &x_exp)
                .fold(self.group.g(), |acc, x| self.group.exp(&acc, &x));
        }
    }

    fn calculate_product_unreduced(&self) -> BigInt {
        self.set
            .iter()
            .map(class_exp_to_num)
            .fold(BigInt::one(), |acc, v| acc * v)
    }

    pub fn non_mem_proof_create(&self, x: &ClassGroupExponent) -> (BigInt, ClassGroupElement) {
        let s = self.calculate_product_unreduced();
        let x_num = class_exp_to_num(x);

        let ExtendedGcd { gcd, x: a, y: b } = Integer::extended_gcd(&s, &x_num);
        assert_eq!(
            gcd,
            BigInt::one(),
            "non-member prime must be coprime with accumulator set product"
        );

        let b_elem = class_group_signed_exp(&self.group, &self.group.g(), &b);
        (a, b_elem)
    }

    pub fn non_mem_ver(&self, proof: &(BigInt, ClassGroupElement), x: &ClassGroupExponent) -> bool {
        let lhs = class_group_signed_exp(&self.group, &self.acc, &proof.0);
        let rhs = self.group.exp(&proof.1, x);
        self.group.mul(&lhs, &rhs) == self.group.g()
    }
}

impl Accumulator for RsaAccumulator<ClassGroup> {
    type Group = ClassGroup;
    type Element = ClassGroupExponent;
    type MembershipProof = ClassGroupElement;
    type NonMembershipProof = (BigInt, ClassGroupElement);

    fn new(group: Self::Group) -> Self {
        let acc = group.g();
        Self {
            group,
            acc,
            set: HashSet::new(),
        }
    }

    fn add(&mut self, element: &Self::Element) -> <Self::Group as Group>::Exponent {
        if !self.set.contains(element) {
            self.set.insert(element.clone());
            self.acc = self.group.exp(&self.acc, element);
        }
        element.clone()
    }

    fn del(&mut self, element: &Self::Element) {
        if self.set.remove(element) {
            let mask = self.group.exp(&self.group.g(), element);
            let mask_inv = self.group.inv(&mask);
            self.acc = self.group.mul(&self.acc, &mask_inv);
        }
    }

    fn value(&self) -> &<Self::Group as Group>::Element {
        self.value()
    }

    fn mem_proof_create(
        &self,
        element: &<Self::Group as Group>::Exponent,
    ) -> Self::MembershipProof {
        self.mem_proof_create(element)
    }

    fn mem_ver(
        &self,
        proof: &Self::MembershipProof,
        element: &<Self::Group as Group>::Exponent,
    ) -> bool {
        self.mem_ver(proof, element)
    }

    fn non_mem_proof_create(&self, element: &Self::Element) -> Self::NonMembershipProof {
        self.non_mem_proof_create(element)
    }

    fn non_mem_ver(&self, proof: &Self::NonMembershipProof, element: &Self::Element) -> bool {
        self.non_mem_ver(proof, element)
    }
}

impl PrivatelyDelegatableAccumulator for RsaAccumulator<ClassGroup> {
    type BlindedMembershipProof = ClassGroupElement;
    type MembershipBlindingFactor = ClassGroupExponent;
    type UpdatedBlindedMembershipProof = ClassGroupElement;
    type MembershipUpdateAux = ClassGroupExponent;
    type BlindedNonMembershipProof = ClassGroupExponent;
    type UpdatedBlindedNonMembershipProof = (BigInt, ClassGroupElement);

    fn blind_mem_proof(
        &self,
        proof: &Self::MembershipProof,
    ) -> (Self::BlindedMembershipProof, Self::MembershipBlindingFactor) {
        self.blind_mem_proof(proof)
    }

    fn blind_mem_proof_upd(
        &self,
        elem_in: Vec<Self::Element>,
        _elem_out: Vec<Self::Element>,
        acc_t: &<Self::Group as Group>::Element,
        blinded_proof: &Self::BlindedMembershipProof,
    ) -> (
        Self::UpdatedBlindedMembershipProof,
        Self::MembershipUpdateAux,
        <Self::Group as Group>::Element,
    ) {
        let delta = elem_in
            .iter()
            .cloned()
            .fold(ClassGroup::exp_id(), |acc, x| ClassGroup::exp_mul(&acc, &x));
        let upd = self.group.exp(blinded_proof, &delta);
        let _ = acc_t;
        (upd, delta, self.acc.clone())
    }

    fn ver_blind_mem_proof_upd(
        &self,
        acc_t: &<Self::Group as Group>::Element,
        blinded_proof: &Self::BlindedMembershipProof,
        upd_blinded_proof: &Self::UpdatedBlindedMembershipProof,
        aux: &Self::MembershipUpdateAux,
    ) -> bool {
        let expected_upd = self.group.exp(blinded_proof, aux);
        let expected_acc = self.group.exp(acc_t, aux);
        expected_upd == *upd_blinded_proof && expected_acc == self.acc
    }

    fn unblind_mem_proof(
        &self,
        blinded_proof: &Self::BlindedMembershipProof,
        st: &Self::MembershipBlindingFactor,
    ) -> Self::MembershipProof {
        self.unblind_mem_proof(blinded_proof, st)
    }

    fn blind_non_mem_proof(&self, element: &Self::Element) -> Self::BlindedNonMembershipProof {
        element.clone()
    }

    fn blind_non_mem_proof_upd(
        &self,
        blinded_non_mem_proof: &Self::BlindedNonMembershipProof,
    ) -> Self::UpdatedBlindedNonMembershipProof {
        self.non_mem_proof_create(blinded_non_mem_proof)
    }

    fn ver_blind_non_mem_proof_upd(
        &self,
        acc_t_prime: &<Self::Group as Group>::Element,
        blinded_non_mem_proof: &Self::BlindedNonMembershipProof,
        upd_blinded_non_mem_proof: &Self::UpdatedBlindedNonMembershipProof,
    ) -> bool {
        let lhs = class_group_signed_exp(&self.group, acc_t_prime, &upd_blinded_non_mem_proof.0);
        let rhs = self
            .group
            .exp(&upd_blinded_non_mem_proof.1, blinded_non_mem_proof);
        self.group.mul(&lhs, &rhs) == self.group.g()
    }

    fn unblind_non_mem_proof(
        &self,
        _st: &<Self::Group as Group>::Exponent,
        upd_blinded_non_mem_proof: &Self::UpdatedBlindedNonMembershipProof,
    ) -> Self::NonMembershipProof {
        upd_blinded_non_mem_proof.clone()
    }
}
