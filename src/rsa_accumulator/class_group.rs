use super::RsaAccumulator;
use crate::error::{AccumulatorError, AccumulatorResult};
use crate::groups::class_group::{
    ClassGroup, ClassGroupElement, ClassGroupExponent, PARI_STACK_SIZE_BYTES,
};
use crate::nizk::NIZK;
use crate::traits::{Accumulator, Group, PrivatelyDelegatableAccumulator};
use class_group::pari_init;
use curv::BigInt;
use num_integer::{ExtendedGcd, Integer};
use num_traits::{One, Zero};
use rand::{thread_rng, RngCore};
use std::collections::HashSet;

type ClassGroupProof = (
    ClassGroupElement,
    ClassGroupElement,
    ClassGroupElement,
    ClassGroupElement,
    ClassGroupExponent,
);
type ClassGroupAux = (ClassGroupProof, ClassGroupProof);

fn class_exp_to_num(exp: &ClassGroupExponent) -> BigInt {
    exp.0.clone()
}

fn class_group_signed_exp(
    group: &ClassGroup,
    base: &ClassGroupElement,
    exponent: &BigInt,
) -> ClassGroupElement {
    if exponent < &BigInt::zero() {
        let positive = ClassGroupExponent((-exponent).clone());
        let pos = group.exp(base, &positive);
        group.inv(&pos)
    } else {
        group.exp(base, &ClassGroupExponent(exponent.clone()))
    }
}

impl RsaAccumulator<ClassGroup> {
    pub fn setup() -> Self {
        let group = ClassGroup::setup();
        Self::new(group)
    }

    pub fn setup_trapdoorless() -> Self {
        Self::setup()
    }

    pub fn calculate_product(&self) -> ClassGroupExponent {
        self.set
            .iter()
            .fold(ClassGroup::exp_id(), |acc, v| ClassGroup::exp_mul(&acc, v))
    }

    pub fn calculate_product_unreduced(&self) -> BigInt {
        self.set
            .iter()
            .map(class_exp_to_num)
            .fold(BigInt::one(), |acc, v| acc * v)
    }

    pub fn del_raw(&mut self, element: &ClassGroupExponent) {
        if self.set.remove(element) {
            let product = self.calculate_product();
            self.acc = self.group.exp(&self.group.g(), &product);
        }
    }

    pub fn mem_proof_create_raw(
        &self,
        element: &ClassGroupExponent,
    ) -> AccumulatorResult<ClassGroupElement> {
        if !self.set.contains(element) {
            return Err(AccumulatorError::ElementNotInSet);
        }

        let product = self
            .set
            .iter()
            .filter(|e| *e != element)
            .fold(ClassGroup::exp_id(), |acc, e| ClassGroup::exp_mul(&acc, e));

        Ok(self.group.exp(&self.group.g(), &product))
    }

    pub fn non_mem_proof_create_raw(
        &self,
        element: &ClassGroupExponent,
        prod: &BigInt,
    ) -> AccumulatorResult<(BigInt, ClassGroupElement)> {
        let x_int = class_exp_to_num(element);

        let ExtendedGcd { gcd, x: a, y: b } = Integer::extended_gcd(prod, &x_int);
        if gcd != BigInt::one() {
            return Err(AccumulatorError::NotCoprime);
        }

        Ok((a, class_group_signed_exp(&self.group, &self.group.g(), &b)))
    }

    pub fn non_mem_ver_raw(
        &self,
        proof: &(BigInt, ClassGroupElement),
        element: &ClassGroupExponent,
    ) -> bool {
        let lhs = class_group_signed_exp(&self.group, &self.acc, &proof.0);
        let rhs = self.group.exp(&proof.1, element);
        self.group.mul(&lhs, &rhs) == self.group.g()
    }

    pub fn blind_mem_proof_upd_raw(
        &self,
        acc_t: &ClassGroupElement,
        blinded_proof: &ClassGroupElement,
        delta: &BigInt,
    ) -> AccumulatorResult<(
        (ClassGroupElement, ClassGroupElement),
        ClassGroupAux,
        ClassGroupElement,
    )> {
        if delta < &BigInt::zero() {
            return Err(AccumulatorError::NegativeDelta);
        }

        let delta_exp = ClassGroupExponent(delta.clone());

        let acc_t_prime = &self.acc;
        let a = self.group.exp(blinded_proof, &delta_exp);
        let g = self.group.g();
        let b = self.group.exp(&g, &delta_exp);

        let nizk = NIZK::setup(&self.group);
        let pi1 = nizk.prove_dleq(blinded_proof, &a, acc_t, acc_t_prime, &delta_exp);
        let pi2 = nizk.prove_dleq(&g, &b, blinded_proof, &a, &delta_exp);

        Ok(((a, b), (pi1, pi2), self.acc.clone()))
    }

    pub fn ver_blind_mem_proof_upd_raw(
        &self,
        acc_t: &ClassGroupElement,
        blinded_proof: &ClassGroupElement,
        upd_blinded_proof: &(ClassGroupElement, ClassGroupElement),
        aux: &ClassGroupAux,
    ) -> bool {
        let pi1 = &aux.0;
        let pi2 = &aux.1;

        let a = &upd_blinded_proof.0;
        let b = &upd_blinded_proof.1;
        let nizk = NIZK::setup(&self.group);
        let acc_t_prime = &self.acc;
        let g = self.group.g();

        let d1 = nizk.verify_dleq(blinded_proof, a, acc_t, acc_t_prime, pi1);
        let d2 = nizk.verify_dleq(&g, b, blinded_proof, a, pi2);
        d1 && d2
    }

    pub fn blind_non_mem_proof_raw(
        &self,
        element: &ClassGroupExponent,
    ) -> (ClassGroupExponent, ClassGroupExponent) {
        if self.set.contains(element) {
            (
                ClassGroupExponent(BigInt::zero()),
                ClassGroupExponent(BigInt::one()),
            )
        } else {
            let mut seed = zeroize::Zeroizing::new([0u8; 32]);
            thread_rng().fill_bytes(seed.as_mut());

            let q = self.group.hash_to_prime(seed.as_ref());
            let blinded = ClassGroupExponent(&element.0 * &q.0);
            (blinded, q)
        }
    }

    pub fn blind_non_mem_proof_upd_raw(
        &self,
        blinded_non_mem_proof: &ClassGroupExponent,
        delta: &BigInt,
    ) -> AccumulatorResult<(BigInt, ClassGroupElement)> {
        let blinded_int = class_exp_to_num(blinded_non_mem_proof);
        let ExtendedGcd { gcd, x: a, y: b } = Integer::extended_gcd(delta, &blinded_int);
        if gcd != BigInt::one() {
            return Err(AccumulatorError::NotCoprime);
        }

        Ok((a, class_group_signed_exp(&self.group, &self.group.g(), &b)))
    }

    pub fn ver_blind_non_mem_proof_upd_raw(
        &self,
        acc_t_prime: &ClassGroupElement,
        blinded_non_mem_proof: &ClassGroupExponent,
        upd_blinded_non_mem_proof: &(BigInt, ClassGroupElement),
    ) -> bool {
        let a = &upd_blinded_non_mem_proof.0;
        let b = &upd_blinded_non_mem_proof.1;

        let lhs = class_group_signed_exp(&self.group, acc_t_prime, a);
        let rhs = self.group.exp(b, blinded_non_mem_proof);
        self.group.mul(&lhs, &rhs) == self.group.g()
    }

    pub fn unblind_non_mem_proof_raw(
        &self,
        st: &ClassGroupExponent,
        upd_blinded_non_mem_proof: &(BigInt, ClassGroupElement),
    ) -> (BigInt, ClassGroupElement) {
        let a = &upd_blinded_non_mem_proof.0;
        let b = &upd_blinded_non_mem_proof.1;
        let b_prime = self.group.exp(b, st);
        (a.clone(), b_prime)
    }
}

impl Accumulator for RsaAccumulator<ClassGroup> {
    type Group = ClassGroup;
    type Element = ClassGroupExponent;
    type MembershipProof = ClassGroupElement;
    type NonMembershipProof = (BigInt, ClassGroupElement);

    fn new(group: Self::Group) -> Self {
        unsafe { pari_init(PARI_STACK_SIZE_BYTES, 2) };
        let acc = group.g();
        Self {
            group,
            acc,
            set: HashSet::new(),
        }
    }

    fn add(&mut self, element: &Self::Element) -> <Self::Group as Group>::Exponent {
        self.add_raw(element)
    }

    fn del(&mut self, element: &Self::Element) {
        self.del_raw(element)
    }

    fn value(&self) -> &<Self::Group as Group>::Element {
        self.value()
    }

    fn mem_proof_create(
        &self,
        element: &<Self::Group as Group>::Exponent,
    ) -> AccumulatorResult<Self::MembershipProof> {
        self.mem_proof_create_raw(element)
    }

    fn mem_ver(
        &self,
        proof: &Self::MembershipProof,
        element: &<Self::Group as Group>::Exponent,
    ) -> bool {
        self.mem_ver_raw(proof, element)
    }

    fn non_mem_proof_create(
        &self,
        element: &Self::Element,
    ) -> AccumulatorResult<Self::NonMembershipProof> {
        let product = self.calculate_product_unreduced();
        self.non_mem_proof_create_raw(element, &product)
    }

    fn non_mem_ver(&self, proof: &Self::NonMembershipProof, element: &Self::Element) -> bool {
        self.non_mem_ver_raw(proof, element)
    }
}

impl PrivatelyDelegatableAccumulator for RsaAccumulator<ClassGroup> {
    type BlindedMembershipProof = ClassGroupElement;
    type MembershipBlindingFactor = ClassGroupExponent;
    type UpdatedBlindedMembershipProof = (ClassGroupElement, ClassGroupElement);
    type MembershipUpdateAux = ClassGroupAux;
    type BlindedNonMembershipProof = (ClassGroupExponent, ClassGroupExponent);
    type UpdatedBlindedNonMembershipProof = (BigInt, ClassGroupElement);
    type Delta = Vec<ClassGroupExponent>;

    fn blind_mem_proof(
        &self,
        proof: &Self::MembershipProof,
    ) -> (Self::BlindedMembershipProof, Self::MembershipBlindingFactor) {
        self.blind_mem_proof_raw(proof)
    }

    fn blind_mem_proof_upd(
        &self,
        acc_t: &<Self::Group as Group>::Element,
        blinded_proof: &Self::BlindedMembershipProof,
        delta: &Self::Delta,
    ) -> AccumulatorResult<(
        Self::UpdatedBlindedMembershipProof,
        Self::MembershipUpdateAux,
        <Self::Group as Group>::Element,
    )> {
        let product = delta
            .iter()
            .map(class_exp_to_num)
            .fold(BigInt::one(), |acc, v| acc * v);
        self.blind_mem_proof_upd_raw(acc_t, blinded_proof, &product)
    }

    fn ver_blind_mem_proof_upd(
        &self,
        acc_t: &<Self::Group as Group>::Element,
        blinded_proof: &Self::BlindedMembershipProof,
        upd_blinded_proof: &Self::UpdatedBlindedMembershipProof,
        aux: &Self::MembershipUpdateAux,
    ) -> bool {
        self.ver_blind_mem_proof_upd_raw(acc_t, blinded_proof, upd_blinded_proof, aux)
    }

    fn unblind_mem_proof(
        &self,
        blinded_proof: &Self::BlindedMembershipProof,
        st: &Self::MembershipBlindingFactor,
    ) -> Self::MembershipProof {
        self.unblind_mem_proof_raw(blinded_proof, st)
    }

    fn blind_non_mem_proof(&self, element: &Self::Element) -> Self::BlindedNonMembershipProof {
        self.blind_non_mem_proof_raw(element)
    }

    fn blind_non_mem_proof_upd(
        &self,
        blinded_non_mem_proof: &Self::BlindedNonMembershipProof,
        delta: &Self::Delta,
    ) -> AccumulatorResult<Self::UpdatedBlindedNonMembershipProof> {
        let product = delta
            .iter()
            .map(class_exp_to_num)
            .fold(BigInt::one(), |acc, v| acc * v);
        self.blind_non_mem_proof_upd_raw(&blinded_non_mem_proof.0, &product)
    }

    fn ver_blind_non_mem_proof_upd(
        &self,
        acc_t_prime: &<Self::Group as Group>::Element,
        blinded_non_mem_proof: &Self::BlindedNonMembershipProof,
        upd_blinded_non_mem_proof: &Self::UpdatedBlindedNonMembershipProof,
    ) -> bool {
        self.ver_blind_non_mem_proof_upd_raw(
            acc_t_prime,
            &blinded_non_mem_proof.0,
            upd_blinded_non_mem_proof,
        )
    }

    fn unblind_non_mem_proof(
        &self,
        st: &<Self::Group as Group>::Exponent,
        upd_blinded_non_mem_proof: &Self::UpdatedBlindedNonMembershipProof,
    ) -> Self::NonMembershipProof {
        self.unblind_non_mem_proof_raw(st, upd_blinded_non_mem_proof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash_input(acc: &RsaAccumulator<ClassGroup>, value: u32) -> ClassGroupExponent {
        acc.group.hash_to_prime(value.to_string().as_bytes())
    }

    #[test]
    fn test_acc_add_del_no_change() {
        let mut acc = RsaAccumulator::<ClassGroup>::setup_trapdoorless();
        let initial_acc = acc.acc.clone();
        let element = "test_element";

        let ep = acc.add_raw(&element);
        acc.del_raw(&ep);

        assert_eq!(
            acc.acc, initial_acc,
            "Accumulator value should be unchanged after add and remove of the same element"
        );
    }

    #[test]
    fn test_gen_mem_proof() {
        let mut acc = RsaAccumulator::<ClassGroup>::setup_trapdoorless();
        let element = 7usize;
        let ep = acc.add_raw(&element);

        for i in 2..5 {
            acc.add_raw(&i);
        }

        let proof = acc.mem_proof_create_raw(&ep).unwrap();
        assert!(acc.mem_ver_raw(&proof, &ep));
    }

    #[test]
    fn test_non_mem_proof() {
        let mut acc = RsaAccumulator::<ClassGroup>::setup_trapdoorless();

        acc.add_raw(&2u32);
        acc.add_raw(&3u32);
        acc.add_raw(&7u32);

        let non_member = hash_input(&acc, 5u32);

        let prod = acc.calculate_product_unreduced();
        let proof = acc.non_mem_proof_create_raw(&non_member, &prod).unwrap();
        assert!(
            acc.non_mem_ver_raw(&proof, &non_member),
            "Non-membership proof should verify"
        );
    }

    #[test]
    fn test_blind_unblind_mem() {
        let mut acc = RsaAccumulator::<ClassGroup>::setup_trapdoorless();

        let element = 7usize;
        let ep = acc.add_raw(&element);

        for i in 2..5 {
            acc.add_raw(&i);
        }

        let proof = acc.mem_proof_create_raw(&ep).unwrap();
        let blinded_proof = acc.blind_mem_proof_raw(&proof);

        assert!(
            blinded_proof.0 != proof,
            "Proof is not blinded successfully"
        );

        let unblinded_proof = acc.unblind_mem_proof_raw(&blinded_proof.0, &blinded_proof.1);
        assert!(
            unblinded_proof == proof,
            "Proof is not unblinded successfully"
        );
    }

    #[test]
    fn test_blind_mem_proof_upd_ver() {
        let mut acc = RsaAccumulator::<ClassGroup>::setup_trapdoorless();

        let ep = acc.add_raw(&200003u32);
        let acc_t = acc.acc.clone();
        let proof = acc.mem_proof_create_raw(&ep).unwrap();

        let elements_in = vec![65537u32, 100003u32, 104729u32, 1299709u32, 15485863u32]
            .iter()
            .map(|e| acc.add_raw(e))
            .collect::<Vec<_>>();
        let delta = elements_in
            .iter()
            .fold(ClassGroup::exp_id(), |prod, e| {
                ClassGroup::exp_mul(&prod, e)
            })
            .0;

        let blinded_proof = acc.blind_mem_proof_raw(&proof);
        let upd_blind_proof = acc
            .blind_mem_proof_upd_raw(&acc_t, &blinded_proof.0, &delta)
            .unwrap();

        assert!(acc.ver_blind_mem_proof_upd_raw(
            &acc_t,
            &blinded_proof.0,
            &upd_blind_proof.0,
            &upd_blind_proof.1
        ));
    }

    #[test]
    fn test_blind_unblind_non_mem() {
        let mut acc = RsaAccumulator::<ClassGroup>::setup_trapdoorless();

        for i in 2..5 {
            acc.add_raw(&i);
        }

        let non_member = hash_input(&acc, 7u32);
        let blinded_proof = acc.blind_non_mem_proof_raw(&non_member);

        for i in 10..12 {
            acc.add_raw(&i);
        }

        let delta = acc.calculate_product_unreduced();
        let upd_blind_non_mem_proof = acc
            .blind_non_mem_proof_upd_raw(&blinded_proof.0, &delta)
            .unwrap();

        let unblinded_proof =
            acc.unblind_non_mem_proof_raw(&blinded_proof.1, &upd_blind_non_mem_proof);
        assert!(
            acc.non_mem_ver_raw(&unblinded_proof, &non_member),
            "Non-membership proof should verify after unblinding"
        );
    }

    #[test]
    fn test_blind_non_mem_proof_upd_ver() {
        let mut acc = RsaAccumulator::<ClassGroup>::setup_trapdoorless();

        let non_member = hash_input(&acc, 200003u32);
        let blinded_proof = acc.blind_non_mem_proof_raw(&non_member);

        let elements_in = vec![65537u32, 100003u32, 104729u32, 1299709u32, 15485863u32];

        for elem in &elements_in {
            acc.add_raw(elem);
        }

        let acc_t_prime = acc.acc.clone();
        let delta = acc.calculate_product_unreduced();
        let upd_blind_proof = acc
            .blind_non_mem_proof_upd_raw(&blinded_proof.0, &delta)
            .unwrap();

        assert!(
            acc.ver_blind_non_mem_proof_upd_raw(&acc_t_prime, &blinded_proof.0, &upd_blind_proof),
            "Couldnt verify"
        );
    }
}
