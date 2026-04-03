use super::RsaAccumulator;
use crate::groups::class_group::{ClassGroup, ClassGroupElement, ClassGroupExponent};
use crate::nizk::NIZK;
use crate::traits::{Accumulator, Group, PrivatelyDelegatableAccumulator};
use class_group::pari_init;
use curv::BigInt;
use num_integer::{ExtendedGcd, Integer};
use num_traits::{One, Zero};
use rand::{thread_rng, RngCore};
use std::collections::HashSet;

const PARI_STACK_SIZE_BYTES: usize = 1_000_000_000;

type ClassGroupProof = (ClassGroupElement, ClassGroupElement, ClassGroupExponent);
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

    pub fn del(&mut self, element: &ClassGroupExponent) {
        if self.set.remove(element) {
            let product = self.calculate_product();
            self.acc = self.group.exp(&self.group.g(), &product);
        }
    }

    pub fn mem_proof_create(&self, element: &ClassGroupExponent) -> ClassGroupElement {
        if !self.set.contains(element) {
            panic!("Element not in accumulator set");
        }

        let product = self
            .set
            .iter()
            .filter(|e| *e != element)
            .fold(ClassGroup::exp_id(), |acc, e| ClassGroup::exp_mul(&acc, e));

        self.group.exp(&self.group.g(), &product)
    }

    pub fn non_mem_proof_create(
        &self,
        element: &ClassGroupExponent,
        prod: &BigInt,
    ) -> (BigInt, ClassGroupElement) {
        let x_int = class_exp_to_num(element);

        let ExtendedGcd { gcd, x: a, y: b } = Integer::extended_gcd(prod, &x_int);
        assert_eq!(
            gcd,
            BigInt::one(),
            "non-member prime must be coprime with accumulator set product"
        );

        (a, class_group_signed_exp(&self.group, &self.group.g(), &b))
    }

    pub fn non_mem_ver(
        &self,
        proof: &(BigInt, ClassGroupElement),
        element: &ClassGroupExponent,
    ) -> bool {
        let lhs = class_group_signed_exp(&self.group, &self.acc, &proof.0);
        let rhs = self.group.exp(&proof.1, element);
        self.group.mul(&lhs, &rhs) == self.group.g()
    }

    pub fn blind_mem_proof_upd(
        &self,
        elem_in: Vec<ClassGroupExponent>,
        _elem_out: Vec<ClassGroupExponent>,
        acc_t: &ClassGroupElement,
        blinded_proof: &ClassGroupElement,
    ) -> (
        (ClassGroupElement, ClassGroupElement),
        ClassGroupAux,
        ClassGroupElement,
    ) {
        let delta = elem_in
            .iter()
            .fold(ClassGroup::exp_id(), |acc, x| ClassGroup::exp_mul(&acc, x));

        let acc_t_prime = &self.acc;
        let a = self.group.exp(blinded_proof, &delta);
        let g = self.group.g();
        let b = self.group.exp(&g, &delta);

        let nizk = NIZK::setup(&self.group);
        let pi1 = nizk.prove_dleq(blinded_proof, &a, acc_t, acc_t_prime, &delta);
        let pi2 = nizk.prove_dleq(&g, &b, blinded_proof, &a, &delta);

        ((a, b), (pi1, pi2), self.acc.clone())
    }

    pub fn ver_blind_mem_proof_upd(
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

    pub fn blind_non_mem_proof(
        &self,
        element: &ClassGroupExponent,
    ) -> (ClassGroupExponent, ClassGroupExponent) {
        if self.set.contains(element) {
            (
                ClassGroupExponent(BigInt::zero()),
                ClassGroupExponent(BigInt::one()),
            )
        } else {
            let mut seed = [0u8; 32];
            thread_rng().fill_bytes(&mut seed);

            let q = self.group.hash_to_prime(&seed);
            let blinded = ClassGroupExponent(&element.0 * &q.0);
            (blinded, q)
        }
    }

    pub fn blind_non_mem_proof_upd(
        &self,
        blinded_non_mem_proof: &ClassGroupExponent,
        delta: &BigInt,
    ) -> (BigInt, ClassGroupElement) {
        let blinded_int = class_exp_to_num(blinded_non_mem_proof);
        let ExtendedGcd { gcd, x: a, y: b } = Integer::extended_gcd(delta, &blinded_int);
        assert_eq!(
            gcd,
            BigInt::one(),
            "blinded value must be coprime with accumulator set product"
        );

        (a, class_group_signed_exp(&self.group, &self.group.g(), &b))
    }

    pub fn ver_blind_non_mem_proof_upd(
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

    pub fn unblind_non_mem_proof(
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
    type NonMembershipProduct = BigInt;

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
        self.add(element)
    }

    fn del(&mut self, element: &Self::Element) {
        self.del(element)
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

    fn non_mem_proof_create(
        &self,
        element: &Self::Element,
        prod: &Self::NonMembershipProduct,
    ) -> Self::NonMembershipProof {
        self.non_mem_proof_create(element, prod)
    }

    fn non_mem_ver(&self, proof: &Self::NonMembershipProof, element: &Self::Element) -> bool {
        self.non_mem_ver(proof, element)
    }
}

impl PrivatelyDelegatableAccumulator for RsaAccumulator<ClassGroup> {
    type BlindedMembershipProof = ClassGroupElement;
    type MembershipBlindingFactor = ClassGroupExponent;
    type UpdatedBlindedMembershipProof = (ClassGroupElement, ClassGroupElement);
    type MembershipUpdateAux = ClassGroupAux;
    type BlindedNonMembershipProof = (ClassGroupExponent, ClassGroupExponent);
    type UpdatedBlindedNonMembershipProof = (BigInt, ClassGroupElement);
    type Delta = BigInt;

    fn blind_mem_proof(
        &self,
        proof: &Self::MembershipProof,
    ) -> (Self::BlindedMembershipProof, Self::MembershipBlindingFactor) {
        self.blind_mem_proof(proof)
    }

    fn blind_mem_proof_upd(
        &self,
        elem_in: Vec<Self::Element>,
        elem_out: Vec<Self::Element>,
        acc_t: &<Self::Group as Group>::Element,
        blinded_proof: &Self::BlindedMembershipProof,
    ) -> (
        Self::UpdatedBlindedMembershipProof,
        Self::MembershipUpdateAux,
        <Self::Group as Group>::Element,
    ) {
        self.blind_mem_proof_upd(elem_in, elem_out, acc_t, blinded_proof)
    }

    fn ver_blind_mem_proof_upd(
        &self,
        acc_t: &<Self::Group as Group>::Element,
        blinded_proof: &Self::BlindedMembershipProof,
        upd_blinded_proof: &Self::UpdatedBlindedMembershipProof,
        aux: &Self::MembershipUpdateAux,
    ) -> bool {
        self.ver_blind_mem_proof_upd(acc_t, blinded_proof, upd_blinded_proof, aux)
    }

    fn unblind_mem_proof(
        &self,
        blinded_proof: &Self::BlindedMembershipProof,
        st: &Self::MembershipBlindingFactor,
    ) -> Self::MembershipProof {
        self.unblind_mem_proof(blinded_proof, st)
    }

    fn blind_non_mem_proof(&self, element: &Self::Element) -> Self::BlindedNonMembershipProof {
        self.blind_non_mem_proof(element)
    }

    fn blind_non_mem_proof_upd(
        &self,
        blinded_non_mem_proof: &Self::BlindedNonMembershipProof,
        delta: &Self::Delta,
    ) -> Self::UpdatedBlindedNonMembershipProof {
        self.blind_non_mem_proof_upd(&blinded_non_mem_proof.0, delta)
    }

    fn ver_blind_non_mem_proof_upd(
        &self,
        acc_t_prime: &<Self::Group as Group>::Element,
        blinded_non_mem_proof: &Self::BlindedNonMembershipProof,
        upd_blinded_non_mem_proof: &Self::UpdatedBlindedNonMembershipProof,
    ) -> bool {
        self.ver_blind_non_mem_proof_upd(
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
        self.unblind_non_mem_proof(st, upd_blinded_non_mem_proof)
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

        let ep = acc.add(&element);
        acc.del(&ep);

        assert_eq!(
            acc.acc, initial_acc,
            "Accumulator value should be unchanged after add and remove of the same element"
        );
    }

    #[test]
    fn test_gen_mem_proof() {
        let mut acc = RsaAccumulator::<ClassGroup>::setup_trapdoorless();
        let element = 7usize;
        let ep = acc.add(&element);

        for i in 2..5 {
            acc.add(&i);
        }

        let proof = acc.mem_proof_create(&ep);
        assert!(acc.mem_ver(&proof, &ep));
    }

    #[test]
    fn test_non_mem_proof() {
        let mut acc = RsaAccumulator::<ClassGroup>::setup_trapdoorless();

        acc.add(&2u32);
        acc.add(&3u32);
        acc.add(&7u32);

        let non_member = hash_input(&acc, 5u32);

        let prod = acc.calculate_product_unreduced();
        let proof = acc.non_mem_proof_create(&non_member, &prod);
        assert!(
            acc.non_mem_ver(&proof, &non_member),
            "Non-membership proof should verify"
        );
    }

    #[test]
    fn test_blind_unblind_mem() {
        let mut acc = RsaAccumulator::<ClassGroup>::setup_trapdoorless();

        let element = 7usize;
        let ep = acc.add(&element);

        for i in 2..5 {
            acc.add(&i);
        }

        let proof = acc.mem_proof_create(&ep);
        let blinded_proof = acc.blind_mem_proof(&proof);

        assert!(
            blinded_proof.0 != proof,
            "Proof is not blinded successfully"
        );

        let unblinded_proof = acc.unblind_mem_proof(&blinded_proof.0, &blinded_proof.1);
        assert!(
            unblinded_proof == proof,
            "Proof is not unblinded successfully"
        );
    }

    #[test]
    fn test_blind_mem_proof_upd_ver() {
        let mut acc = RsaAccumulator::<ClassGroup>::setup_trapdoorless();

        let ep = acc.add(&200003u32);
        let acc_t = acc.acc.clone();
        let proof = acc.mem_proof_create(&ep);

        let elements_in = vec![65537u32, 100003u32, 104729u32, 1299709u32, 15485863u32]
            .iter()
            .map(|e| acc.add(e))
            .collect::<Vec<_>>();

        let elements_out = vec![];

        let blinded_proof = acc.blind_mem_proof(&proof);
        let upd_blind_proof =
            acc.blind_mem_proof_upd(elements_in, elements_out, &acc_t, &blinded_proof.0);

        assert!(acc.ver_blind_mem_proof_upd(
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
            acc.add(&i);
        }

        let non_member = hash_input(&acc, 7u32);
        let blinded_proof = acc.blind_non_mem_proof(&non_member);

        for i in 10..12 {
            acc.add(&i);
        }

        let delta = acc.calculate_product_unreduced();
        let upd_blind_non_mem_proof = acc.blind_non_mem_proof_upd(&blinded_proof.0, &delta);

        let unblinded_proof = acc.unblind_non_mem_proof(&blinded_proof.1, &upd_blind_non_mem_proof);
        assert!(
            acc.non_mem_ver(&unblinded_proof, &non_member),
            "Non-membership proof should verify after unblinding"
        );
    }

    #[test]
    fn test_blind_non_mem_proof_upd_ver() {
        let mut acc = RsaAccumulator::<ClassGroup>::setup_trapdoorless();

        let non_member = hash_input(&acc, 200003u32);
        let blinded_proof = acc.blind_non_mem_proof(&non_member);

        let elements_in = vec![65537u32, 100003u32, 104729u32, 1299709u32, 15485863u32];

        for elem in &elements_in {
            acc.add(elem);
        }

        let acc_t_prime = acc.acc.clone();
        let delta = acc.calculate_product_unreduced();
        let upd_blind_proof = acc.blind_non_mem_proof_upd(&blinded_proof.0, &delta);

        assert!(
            acc.ver_blind_non_mem_proof_upd(&acc_t_prime, &blinded_proof.0, &upd_blind_proof),
            "Couldnt verify"
        );
    }
}
