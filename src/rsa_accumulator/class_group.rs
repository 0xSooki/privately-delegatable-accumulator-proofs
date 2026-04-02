use super::RsaAccumulator;
use crate::groups::class_group::{ClassGroup, ClassGroupElement, ClassGroupExponent};
use crate::traits::{Accumulator, Group, PrivatelyDelegatableAccumulator};
use class_group::pari_init;
use curv::BigInt;
use num_bigint::BigUint;
use num_integer::{ExtendedGcd, Integer};
use num_traits::{One, Zero};
use std::collections::HashSet;

const PARI_STACK_SIZE_BYTES: usize = 1_000_000_000;

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

    pub fn del(&mut self, element: &ClassGroupExponent) {
        if self.set.remove(element) {
            self.acc = self
                .set
                .iter()
                .filter(|&e| e != element)
                .fold(self.group.g(), |acc, x| self.group.exp(&acc, &x));
        }
    }

    fn calculate_product_unreduced(&self) -> BigInt {
        self.set
            .iter()
            .map(class_exp_to_num)
            .fold(BigInt::one(), |acc, v| acc * v)
    }

    pub fn non_mem_proof_create(
        &self,
        x: &ClassGroupExponent,
        prod: &BigInt,
    ) -> (BigInt, ClassGroupElement) {
        let x_num = class_exp_to_num(x);

        let ExtendedGcd { gcd, x: a, y: b } = Integer::extended_gcd(prod, &x_num);
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
        unsafe { pari_init(PARI_STACK_SIZE_BYTES, 2) };
        let x_str = format!("{:?}", element);
        let x_prime = self.group.hash_to_prime(x_str.as_bytes());
        if !self.set.contains(&x_prime) {
            self.set.insert(x_prime.clone());
            self.acc = self.group.exp(&self.acc, &x_prime);
        }
        x_prime.clone()
    }

    fn del(&mut self, element: &Self::Element) {
        unsafe { pari_init(PARI_STACK_SIZE_BYTES, 2) };
        if self.set.remove(element) {
            self.acc = self
                .set
                .iter()
                .fold(self.group.g(), |acc, x| self.group.exp(&acc, x));
        }
    }

    fn value(&self) -> &<Self::Group as Group>::Element {
        self.value()
    }

    fn mem_proof_create(
        &self,
        element: &<Self::Group as Group>::Exponent,
    ) -> Self::MembershipProof {
        unsafe { pari_init(PARI_STACK_SIZE_BYTES, 2) };
        if !self.set.contains(&element) {
            panic!("Element not in accumulator set");
        }
        let prod = self
            .set
            .iter()
            .filter(|s| *s != element)
            .fold(ClassGroup::exp_id(), |acc, s| ClassGroup::exp_mul(&acc, s));
        self.group.exp(&self.group.g(), &prod)
    }

    fn mem_ver(
        &self,
        proof: &Self::MembershipProof,
        element: &<Self::Group as Group>::Exponent,
    ) -> bool {
        unsafe { pari_init(PARI_STACK_SIZE_BYTES, 2) };
        self.group.exp(proof, element) == self.acc
    }

    fn non_mem_proof_create(
        &self,
        element: &Self::Element,
        prod: &Self::NonMembershipProduct,
    ) -> Self::NonMembershipProof {
        unsafe { pari_init(PARI_STACK_SIZE_BYTES, 2) };
        self.non_mem_proof_create(element, prod)
    }

    fn non_mem_ver(&self, proof: &Self::NonMembershipProof, element: &Self::Element) -> bool {
        unsafe { pari_init(PARI_STACK_SIZE_BYTES, 2) };
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
        unsafe { pari_init(PARI_STACK_SIZE_BYTES, 2) };
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
        unsafe { pari_init(PARI_STACK_SIZE_BYTES, 2) };
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
        unsafe { pari_init(PARI_STACK_SIZE_BYTES, 2) };
        let expected_upd = self.group.exp(blinded_proof, aux);
        let expected_acc = self.group.exp(acc_t, aux);
        expected_upd == *upd_blinded_proof && expected_acc == self.acc
    }

    fn unblind_mem_proof(
        &self,
        blinded_proof: &Self::BlindedMembershipProof,
        st: &Self::MembershipBlindingFactor,
    ) -> Self::MembershipProof {
        unsafe { pari_init(PARI_STACK_SIZE_BYTES, 2) };
        self.unblind_mem_proof(blinded_proof, st)
    }

    fn blind_non_mem_proof(
        &self,
        element: &Self::Element,
        _prod: &Option<BigUint>,
    ) -> Self::BlindedNonMembershipProof {
        unsafe { pari_init(PARI_STACK_SIZE_BYTES, 2) };
        element.clone()
    }

    fn blind_non_mem_proof_upd(
        &self,
        blinded_non_mem_proof: &Self::BlindedNonMembershipProof,
    ) -> Self::UpdatedBlindedNonMembershipProof {
        unsafe { pari_init(PARI_STACK_SIZE_BYTES, 2) };
        self.non_mem_proof_create(blinded_non_mem_proof, &self.calculate_product_unreduced())
    }

    fn ver_blind_non_mem_proof_upd(
        &self,
        acc_t_prime: &<Self::Group as Group>::Element,
        blinded_non_mem_proof: &Self::BlindedNonMembershipProof,
        upd_blinded_non_mem_proof: &Self::UpdatedBlindedNonMembershipProof,
    ) -> bool {
        unsafe { pari_init(PARI_STACK_SIZE_BYTES, 2) };
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
        unsafe { pari_init(PARI_STACK_SIZE_BYTES, 2) };
        upd_blinded_non_mem_proof.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::{Accumulator, Group, PrivatelyDelegatableAccumulator};

    fn hash_input(acc: &RsaAccumulator<ClassGroup>, value: u32) -> ClassGroupExponent {
        acc.group.hash_to_prime(value.to_string().as_bytes())
    }

    #[test]
    fn test_acc_add_del_no_change() {
        let mut acc = RsaAccumulator::<ClassGroup>::setup();
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
        let mut acc = RsaAccumulator::<ClassGroup>::setup();
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
        let mut acc = RsaAccumulator::<ClassGroup>::setup();

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
        let mut acc = RsaAccumulator::<ClassGroup>::setup();

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
        let mut acc = RsaAccumulator::<ClassGroup>::setup();

        let ep = acc.add(&200003u32);

        let acct = acc.acc.clone();

        let proof = acc.mem_proof_create(&ep);

        let elements_in = vec![65537u32, 100003u32, 104729u32, 1299709u32, 15485863u32];

        let elements_out = vec![];
        let elements_in = elements_in.iter().map(|e| acc.add(e)).collect::<Vec<_>>();

        let blinded_proof = acc.blind_mem_proof(&proof);

        let upd_blind_proof =
            acc.blind_mem_proof_upd(elements_in, elements_out, &acct, &blinded_proof.0);

        assert!(acc.ver_blind_mem_proof_upd(
            &acct,
            &blinded_proof.0,
            &upd_blind_proof.0,
            &upd_blind_proof.1
        ));
    }

    #[test]
    fn test_blind_unblind_non_mem() {
        let mut acc = RsaAccumulator::<ClassGroup>::setup();

        for i in 2..5 {
            acc.add(&i);
        }

        let non_member = hash_input(&acc, 7u32);

        let blinded_proof = acc.blind_non_mem_proof(&non_member, &None);

        for i in 10..12 {
            acc.add(&i);
        }

        let upd_blind_non_mem_proof = acc.blind_non_mem_proof_upd(&blinded_proof);

        let unblinded_proof = acc.unblind_non_mem_proof(&blinded_proof, &upd_blind_non_mem_proof);
        assert!(
            acc.non_mem_ver(&unblinded_proof, &non_member),
            "Non-membership proof should verify after unblinding"
        );
    }

    #[test]
    fn test_blind_non_mem_proof_upd_ver() {
        let mut acc = RsaAccumulator::<ClassGroup>::setup();

        let non_member = hash_input(&acc, 200003u32);

        let blinded_proof = acc.blind_non_mem_proof(&non_member, &None);

        let elements_in = vec![65537u32, 100003u32, 104729u32, 1299709u32, 15485863u32];

        for elem in &elements_in {
            acc.add(elem);
        }

        let acctprime = acc.acc.clone();

        let upd_blind_proof = acc.blind_non_mem_proof_upd(&blinded_proof);

        assert!(
            acc.ver_blind_non_mem_proof_upd(&acctprime, &blinded_proof, &upd_blind_proof),
            "Couldnt verify"
        );
    }
}
