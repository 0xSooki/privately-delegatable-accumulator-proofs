use super::{Aux, RsaAccumulator, UpdatedBlindProof, KEY_SIZE};
use crate::groups::rsa_group::RsaGroup;
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

        let p_uint = safe_prime::new(KEY_SIZE as usize).unwrap();
        let q_uint = safe_prime::new(KEY_SIZE as usize).unwrap();
        let p = BigUint::from(p_uint);
        let q = BigUint::from(q_uint);

        let n = &p * &q;
        let totient = (&p - BigUint::one()) * (&q - BigUint::one());

        let g = rng.gen_biguint_range(&BigUint::one(), &n);
        let group = RsaGroup::new(n, g, Some(totient));

        Self::new(group)
    }

    pub fn setup_trapdoorless() -> Self {
        let mut rng = rand::thread_rng();

        let p_uint = safe_prime::new(KEY_SIZE as usize).unwrap();
        let q_uint = safe_prime::new(KEY_SIZE as usize).unwrap();
        let p = BigUint::from(p_uint);
        let q = BigUint::from(q_uint);
        let n = &p * &q;

        let g = rng.gen_biguint_range(&BigUint::one(), &n);
        let group = RsaGroup::new(n, g, None);

        Self::new(group)
    }

    fn calculate_product(&self) -> BigUint {
        if let Some(t) = self.group.totient() {
            self.set.iter().fold(BigUint::one(), |acc, v| (acc * v) % t)
        } else {
            self.set.iter().product()
        }
    }

    pub fn del(&mut self, element: &BigUint) {
        let x_str = element.to_string();
        let x_prime = self.group.hash_to_prime(x_str.as_bytes());

        if self.set.remove(&x_prime) {
            if let Some(t) = self.group.totient() {
                let x_mod_inv = x_prime.modinv(&t).unwrap();
                self.acc = self.group.exp(&self.acc, &x_mod_inv);
            } else {
                let product = self.calculate_product();
                self.acc = self.group.exp(&self.group.g(), &product);
            }
        }
    }

    pub fn mem_proof_create(&self, x: &BigUint) -> BigUint {
        if !self.set.contains(&x) {
            panic!("Element not in accumulator set");
        }

        if let Some(t) = self.group.totient() {
            let x_mod_inv = x.modinv(&t).unwrap();
            self.group.exp(&self.acc, &x_mod_inv)
        } else {
            let product = self.calculate_product();
            let proof_exp = product / x;
            self.group.exp(&self.acc, &proof_exp)
        }
    }

    pub fn non_mem_proof_create(&self, x: &BigUint) -> (BigInt, BigUint) {
        let s = BigInt::from(self.calculate_product_unreduced());

        let x_str = x.to_string();
        let x_prime = self.group.hash_to_prime(x_str.as_bytes());
        let x_prime_int = BigInt::from(x_prime.clone());

        let ExtendedGcd { gcd, x: a, y: b } = Integer::extended_gcd(&s, &x_prime_int);
        assert_eq!(
            gcd,
            BigInt::one(),
            "non-member prime must be coprime with accumulator set product"
        );

        if let Some(t) = self.group.totient() {
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

    pub fn non_mem_ver(&self, proof: &(BigInt, BigUint), x: &BigUint) -> bool {
        let x_str = x.to_string();
        let x_prime = self.group.hash_to_prime(x_str.as_bytes());

        let lhs = self.group.signed_exp(&self.acc, &proof.0);
        let rhs = self.group.exp(&proof.1, &x_prime);
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
            let x_str = elem.to_string();
            let x_prime = self.group.hash_to_prime(x_str.as_bytes());
            delta *= &x_prime;
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

    pub fn blind_non_mem_proof(&self, x: &BigUint) -> (BigUint, BigUint) {
        let x_str = x.to_string();
        let x_prime = self.group.hash_to_prime(x_str.as_bytes());

        if self.set.contains(&x_prime) {
            (BigUint::from(0u32), BigUint::from(1u32))
        } else {
            let mut rng = thread_rng();
            let s = self.calculate_product_unreduced();

            let q = loop {
                let seed = rng.gen_biguint(128);
                let q_candidate = self
                    .group
                    .hash_to_prime(seed.to_bytes_be().as_slice())
                    .to_biguint()
                    .unwrap();
                if q_candidate.gcd(&s) == BigUint::one() {
                    break q_candidate;
                }
            };

            let blinded_non_mem_proof = x_prime * &q;
            (blinded_non_mem_proof, q)
        }
    }

    pub fn blind_non_mem_proof_upd(&self, blinded_non_mem_proof: &BigUint) -> (BigInt, BigUint) {
        let s = BigInt::from(self.calculate_product_unreduced());

        let blinded_int = BigInt::from(blinded_non_mem_proof.clone());
        let ExtendedGcd { gcd, x: a, y: b } = Integer::extended_gcd(&s, &blinded_int);
        assert_eq!(
            gcd,
            BigInt::one(),
            "blinded value must be coprime with accumulator set product"
        );

        if let Some(t) = self.group.totient() {
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

    fn calculate_product_unreduced(&self) -> BigUint {
        self.set.iter().cloned().product()
    }
}

impl Accumulator for RsaAccumulator<RsaGroup> {
    type Group = RsaGroup;
    type Element = BigUint;
    type MembershipProof = BigUint;
    type NonMembershipProof = (BigInt, BigUint);

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

    fn non_mem_proof_create(&self, element: &Self::Element) -> Self::NonMembershipProof {
        self.non_mem_proof_create(element)
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
    ) -> Self::UpdatedBlindedNonMembershipProof {
        self.blind_non_mem_proof_upd(&blinded_non_mem_proof.0)
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
