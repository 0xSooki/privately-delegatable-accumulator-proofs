use super::{Aux, RsaAccumulator, UpdatedBlindProof};
use crate::groups::rsa_group::{RsaGroup, MODULUS_SIZE};
use crate::nizk::NIZK;
use crate::traits::{Accumulator, Group, PrivatelyDelegatableAccumulator};
use glass_pumpkin::safe_prime;
use num_bigint::{BigInt, BigUint, RandBigInt, ToBigInt, ToBigUint};
use num_integer::{ExtendedGcd, Integer};
use num_traits::One;
use rand::thread_rng;
use std::collections::HashSet;

impl RsaAccumulator<RsaGroup> {
    pub fn setup() -> Self {
        let mut rng = rand::thread_rng();

        let p_uint = safe_prime::new(MODULUS_SIZE as usize).unwrap();
        let q_uint = safe_prime::new(MODULUS_SIZE as usize).unwrap();
        let p = BigUint::from(p_uint);
        let q = BigUint::from(q_uint);

        let n = &p * &q;
        let order = (&p - BigUint::one()) * (&q - BigUint::one());

        let g = rng.gen_biguint_range(&BigUint::one(), &n);
        let group = RsaGroup::new(n, g, Some(order));

        Self::new(group)
    }

    pub fn setup_from_params(p: BigUint, q: BigUint, g: BigUint, order: Option<BigUint>) -> Self {
        let n = &p * &q;
        let group = RsaGroup::new(n, g, order);
        Self::new(group)
    }

    pub fn setup_trapdoorless() -> Self {
        let mut rng = rand::thread_rng();

        let p_uint = safe_prime::new(MODULUS_SIZE as usize).unwrap();
        let q_uint = safe_prime::new(MODULUS_SIZE as usize).unwrap();
        let p = BigUint::from(p_uint);
        let q = BigUint::from(q_uint);
        let n = &p * &q;

        let g = rng.gen_biguint_range(&BigUint::one(), &n);
        let group = RsaGroup::new(n, g, None);

        Self::new(group)
    }

    pub fn calculate_product(&self) -> BigUint {
        if let Some(o) = self.group.order() {
            self.set.iter().fold(BigUint::one(), |acc, v| (acc * v) % o)
        } else {
            self.set.iter().product()
        }
    }

    pub fn del(&mut self, element: &BigUint) {
        if self.set.remove(&element) {
            if let Some(o) = self.group.order() {
                let x_mod_inv = element.modinv(&o).unwrap();
                self.acc = self.group.exp(&self.acc, &x_mod_inv);
            } else {
                let product = self.calculate_product();
                self.acc = self.group.exp(&self.group.g(), &product);
            }
        }
    }

    pub fn mem_proof_create(&self, element: &BigUint) -> BigUint {
        if !self.set.contains(&element) {
            panic!("Element not in accumulator set");
        }

        if let Some(o) = self.group.order() {
            let x_mod_inv = element.modinv(&o).unwrap();
            self.group.exp(&self.acc, &x_mod_inv)
        } else {
            let product = self.set.iter().filter(|&e| e != element).product();
            self.group.exp(&self.group.g(), &product)
        }
    }

    pub fn non_mem_proof_create(&self, element: &BigUint, prod: &BigInt) -> (BigInt, BigUint) {
        let x_prime_int = BigInt::from(element.clone());

        let ExtendedGcd { gcd, x: a, y: b } = Integer::extended_gcd(prod, &x_prime_int);
        assert_eq!(
            gcd,
            BigInt::one(),
            "non-member prime must be coprime with accumulator set product"
        );

        if let Some(o) = self.group.order() {
            let totient_int = o.to_bigint().unwrap();
            let a_mod = ((a % &totient_int) + &totient_int) % &totient_int;
            let b_mod = (((b % &totient_int) + &totient_int) % &totient_int)
                .to_biguint()
                .unwrap();
            (a_mod, self.group.exp(&self.group.g(), &b_mod))
        } else {
            (a, self.group.signed_exp(&self.group.g(), &b))
        }
    }

    pub fn non_mem_ver(&self, proof: &(BigInt, BigUint), element: &BigUint) -> bool {
        let lhs = self.group.signed_exp(&self.acc, &proof.0);
        let rhs = self.group.exp(&proof.1, &element);
        self.group.mul(&lhs, &rhs) == self.group.g()
    }

    pub fn blind_mem_proof_upd(
        &self,
        elem_in: Vec<BigUint>,
        _elem_out: Vec<BigUint>,
        acc_t: &BigUint,
        blinded_proof: &BigUint,
    ) -> UpdatedBlindProof {
        let mut delta = BigUint::one();
        for elem in &elem_in {
            delta *= elem;
        }

        let acc_t_prime = &self.acc;
        let a = self.group.exp(blinded_proof, &delta);
        let g = self.group.g();
        let b = self.group.exp(&g, &delta);

        let nizk = NIZK::setup(&self.group);
        let pi1 = NIZK::prove_dleq(&nizk, blinded_proof, &a, acc_t, acc_t_prime, &delta);
        let pi2 = NIZK::prove_dleq(&nizk, &g, &b, blinded_proof, &a, &delta);

        let upd_blinded_proof = (a, b);
        let aux = (pi1, pi2);
        (upd_blinded_proof, aux, self.acc.clone())
    }

    pub fn ver_blind_mem_proof_upd(
        &self,
        acc_t: &BigUint,
        blinded_proof: &BigUint,
        upd_blinded_proof: &(BigUint, BigUint),
        aux: &Aux,
    ) -> bool {
        let pi1 = &aux.0;
        let pi2 = &aux.1;

        let a = &upd_blinded_proof.0;
        let b = &upd_blinded_proof.1;
        let nizk = NIZK::setup(&self.group);
        let acc_t_prime = &self.acc;
        let g = self.group.g();

        let d1 = NIZK::verify_dleq(&nizk, blinded_proof, a, acc_t, acc_t_prime, pi1);
        let d2 = NIZK::verify_dleq(&nizk, &g, b, blinded_proof, a, pi2);
        d1 && d2
    }

    pub fn blind_non_mem_proof(&self, element: &BigUint) -> (BigUint, BigUint) {
        if self.set.contains(element) {
            (BigUint::from(0u32), BigUint::from(1u32))
        } else {
            let mut rng = thread_rng();

            let seed = rng.gen_biguint(128);
            let q = self
                .group
                .hash_to_prime(seed.to_bytes_be().as_slice())
                .to_biguint()
                .unwrap();

            let blinded_non_mem_proof = element * &q;
            (blinded_non_mem_proof, q)
        }
    }

    pub fn blind_non_mem_proof_upd(
        &self,
        blinded_non_mem_proof: &BigUint,
        delta: &BigInt,
    ) -> (BigInt, BigUint) {
        let blinded_int = BigInt::from(blinded_non_mem_proof.clone());
        let ExtendedGcd { gcd, x: a, y: b } = Integer::extended_gcd(delta, &blinded_int);
        assert_eq!(
            gcd,
            BigInt::one(),
            "blinded value must be coprime with accumulator set product"
        );

        if let Some(t) = self.group.order() {
            let totient_int = t.to_bigint().unwrap();
            let a_mod = ((a % &totient_int) + &totient_int) % &totient_int;
            let b_mod = (((b % &totient_int) + &totient_int) % &totient_int)
                .to_biguint()
                .unwrap();
            (a_mod, self.group.exp(&self.group.g(), &b_mod))
        } else {
            (a, self.group.signed_exp(&self.group.g(), &b))
        }
    }

    pub fn ver_blind_non_mem_proof_upd(
        &self,
        acc_t_prime: &BigUint,
        blinded_non_mem_proof: &BigUint,
        upd_blinded_non_mem_proof: &(BigInt, BigUint),
    ) -> bool {
        let a = &upd_blinded_non_mem_proof.0;
        let b = &upd_blinded_non_mem_proof.1;

        let lhs = self.group.signed_exp(acc_t_prime, a);
        let rhs = self.group.exp(b, blinded_non_mem_proof);
        self.group.mul(&lhs, &rhs) == self.group.g()
    }

    pub fn unblind_non_mem_proof(
        &self,
        st: &BigUint,
        upd_blinded_non_mem_proof: &(BigInt, BigUint),
    ) -> (BigInt, BigUint) {
        let a = &upd_blinded_non_mem_proof.0;
        let b = &upd_blinded_non_mem_proof.1;
        let b_prime = self.group.exp(b, st);
        (a.clone(), b_prime)
    }

    pub fn calculate_product_unreduced(&self) -> BigUint {
        self.set.iter().product()
    }
}

impl Accumulator for RsaAccumulator<RsaGroup> {
    type Group = RsaGroup;
    type Element = BigUint;
    type MembershipProof = BigUint;
    type NonMembershipProof = (BigInt, BigUint);
    type NonMembershipProduct = BigInt;

    fn new(group: Self::Group) -> Self {
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

impl PrivatelyDelegatableAccumulator for RsaAccumulator<RsaGroup> {
    type BlindedMembershipProof = BigUint;
    type MembershipBlindingFactor = BigUint;
    type UpdatedBlindedMembershipProof = (BigUint, BigUint);
    type MembershipUpdateAux = Aux;
    type BlindedNonMembershipProof = (BigUint, BigUint);
    type UpdatedBlindedNonMembershipProof = (BigInt, BigUint);
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
mod trapdoored_tests {
    use super::*;
    use crate::groups::rsa_group::RsaGroup;
    use num_bigint::BigUint;

    #[test]
    fn test_acc_add_del_no_change() {
        let mut acc = RsaAccumulator::<RsaGroup>::setup();
        let initial_acc = acc.acc.clone();
        let element = BigUint::from_bytes_be(b"test_element");

        let ep = acc.add(&element);
        acc.del(&ep);

        assert_eq!(
            acc.acc, initial_acc,
            "Accumulator value should be unchanged after add and remove of the same element"
        );
    }

    #[test]
    fn test_gen_mem_proof() {
        let mut acc = RsaAccumulator::<RsaGroup>::setup();
        let element = BigUint::from(7usize);
        let ep = acc.add(&element);

        for i in 2..5 {
            acc.add(&BigUint::from(i as usize));
        }

        let proof = acc.mem_proof_create(&ep);

        assert!(acc.mem_ver(&proof, &ep));
    }

    #[test]
    fn test_non_mem_proof() {
        let mut acc = RsaAccumulator::<RsaGroup>::setup();

        acc.add(&BigUint::from(2u32));
        acc.add(&BigUint::from(3u32));
        acc.add(&BigUint::from(7u32));

        let non_member = BigUint::from(5u32);

        let proof = acc.non_mem_proof_create(
            &non_member,
            &acc.calculate_product_unreduced().to_bigint().unwrap(),
        );
        assert!(
            acc.non_mem_ver(&proof, &non_member),
            "Non-membership proof should verify"
        );
    }

    #[test]
    fn test_blind_unblind_mem() {
        let mut acc = RsaAccumulator::<RsaGroup>::setup();

        let element = BigUint::from(7usize);
        let ep: BigUint = acc.add(&element);

        for i in 2..5 {
            acc.add(&BigUint::from(i as usize));
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
        let mut acc = RsaAccumulator::<RsaGroup>::setup();

        let ep = acc.add(&BigUint::from(200003u32));

        let acct = acc.acc.clone();

        let proof = acc.mem_proof_create(&ep);

        let elements_in = vec![
            BigUint::from(65537u32),
            BigUint::from(100003u32),
            BigUint::from(104729u32),
            BigUint::from(1299709u32),
            BigUint::from(15485863u32),
        ];

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
        let mut acc = RsaAccumulator::<RsaGroup>::setup();

        for i in 2..5 {
            acc.add(&BigUint::from(i as usize));
        }

        let non_member = BigUint::from(7usize);

        let blinded_proof = acc.blind_non_mem_proof(&non_member);

        for i in 10..12 {
            acc.add(&BigUint::from(i as usize));
        }

        let upd_blind_non_mem_proof = acc.blind_non_mem_proof_upd(
            &blinded_proof.0,
            &BigInt::from(acc.calculate_product_unreduced()),
        );

        let unblinded_proof = acc.unblind_non_mem_proof(&blinded_proof.1, &upd_blind_non_mem_proof);
        assert!(
            acc.non_mem_ver(&unblinded_proof, &non_member),
            "Non-membership proof should verify after unblinding"
        );
    }

    #[test]
    fn test_blind_non_mem_proof_upd_ver() {
        let mut acc = RsaAccumulator::<RsaGroup>::setup();

        let non_member = BigUint::from(200003u32);

        let blinded_proof = acc.blind_non_mem_proof(&non_member);

        let elements_in = vec![
            BigUint::from(65537u32),
            BigUint::from(100003u32),
            BigUint::from(104729u32),
            BigUint::from(1299709u32),
            BigUint::from(15485863u32),
        ];

        for elem in &elements_in {
            acc.add(elem);
        }

        let acctprime = acc.acc.clone();

        let upd_blind_proof = acc.blind_non_mem_proof_upd(
            &blinded_proof.0,
            &BigInt::from(acc.calculate_product_unreduced()),
        );

        assert!(
            acc.ver_blind_non_mem_proof_upd(&acctprime, &blinded_proof.0, &upd_blind_proof),
            "Couldnt verify"
        );
    }
}

#[cfg(test)]
mod trapdoorless_tests {
    use super::*;
    use crate::groups::rsa_group::RsaGroup;
    use num_bigint::BigUint;

    #[test]
    fn test_acc_add_del_no_change() {
        let mut acc = RsaAccumulator::<RsaGroup>::setup_trapdoorless();
        let initial_acc = acc.acc.clone();
        let element = BigUint::from_bytes_be(b"test_element");

        let ep = acc.add(&element);
        acc.del(&ep);

        assert_eq!(
            acc.acc, initial_acc,
            "Accumulator value should be unchanged after add and remove of the same element"
        );
    }

    #[test]
    fn test_gen_mem_proof() {
        let mut acc = RsaAccumulator::<RsaGroup>::setup_trapdoorless();
        let element = BigUint::from(7usize);

        let ep = acc.add(&element);

        for i in 2..5 {
            acc.add(&BigUint::from(i as usize));
        }

        let proof = acc.mem_proof_create(&ep);

        assert!(acc.mem_ver(&proof, &ep));
    }

    #[test]
    fn test_non_mem_proof() {
        let mut acc = RsaAccumulator::<RsaGroup>::setup_trapdoorless();

        acc.add(&BigUint::from(2u32));
        acc.add(&BigUint::from(3u32));
        acc.add(&BigUint::from(7u32));

        let non_member = BigUint::from(5u32);

        let proof = acc.non_mem_proof_create(
            &non_member,
            &(acc.calculate_product_unreduced().to_bigint().unwrap()),
        );
        assert!(
            acc.non_mem_ver(&proof, &non_member),
            "Non-membership proof should verify"
        );
    }

    #[test]
    fn test_blind_unblind_mem() {
        let mut acc = RsaAccumulator::<RsaGroup>::setup_trapdoorless();

        let element = BigUint::from(7usize);
        let ep: BigUint = acc.add(&element);

        for i in 2..5 {
            acc.add(&BigUint::from(i as usize));
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
        let mut acc = RsaAccumulator::<RsaGroup>::setup_trapdoorless();

        let ep = acc.add(&BigUint::from(200003u32));

        let acct = acc.acc.clone();

        let proof = acc.mem_proof_create(&ep);

        let blinded_proof = acc.blind_mem_proof(&proof);

        let elements = vec![
            BigUint::from(65537u32),
            BigUint::from(100003u32),
            BigUint::from(104729u32),
            BigUint::from(1299709u32),
            BigUint::from(15485863u32),
        ];

        let elements_out = vec![];

        let elements_in = elements.iter().map(|e| acc.add(e)).collect::<Vec<_>>();

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
        let mut acc = RsaAccumulator::<RsaGroup>::setup_trapdoorless();

        for i in 2..5 {
            acc.add(&BigUint::from(i as usize));
        }

        let non_member = BigUint::from(7usize);

        let blinded_proof = acc.blind_non_mem_proof(&non_member);

        for i in 10..12 {
            acc.add(&BigUint::from(i as usize));
        }

        let upd_blind_non_mem_proof = acc.blind_non_mem_proof_upd(
            &blinded_proof.0,
            &BigInt::from(acc.calculate_product_unreduced()),
        );

        let unblinded_proof = acc.unblind_non_mem_proof(&blinded_proof.1, &upd_blind_non_mem_proof);
        assert!(
            acc.non_mem_ver(&unblinded_proof, &non_member),
            "Non-membership proof should verify after unblinding"
        );
    }

    #[test]
    fn test_blind_non_mem_proof_upd_ver() {
        let mut acc = RsaAccumulator::<RsaGroup>::setup_trapdoorless();

        let non_member = BigUint::from(200003u32);

        let blinded_proof = acc.blind_non_mem_proof(&non_member);

        let elements_in = vec![
            BigUint::from(65537u32),
            BigUint::from(100003u32),
            BigUint::from(104729u32),
            BigUint::from(1299709u32),
            BigUint::from(15485863u32),
        ];

        for elem in &elements_in {
            acc.add(elem);
        }

        let acctprime = acc.acc.clone();

        let upd_blind_proof = acc.blind_non_mem_proof_upd(
            &blinded_proof.0,
            &BigInt::from(acc.calculate_product_unreduced()),
        );

        assert!(
            acc.ver_blind_non_mem_proof_upd(&acctprime, &blinded_proof.0, &upd_blind_proof),
            "Couldnt verify"
        );
    }
}
