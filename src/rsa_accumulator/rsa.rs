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
    /// Creates a new RSA accumulator with randomly generated safe prime parameters.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use num_bigint::BigUint;
    /// use privacy_preserving_accumulators::{rsa_group::RsaGroup, RsaAccumulator};
    ///
    /// // Generates 3072-bit safe primes; use setup_from_params for faster tests.
    /// let mut acc = RsaAccumulator::<RsaGroup>::setup();
    /// let ep = acc.add(&BigUint::from(7u32));
    /// let proof = acc.mem_proof_create(&ep);
    /// assert!(acc.mem_ver(&proof, &ep));
    /// ```
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

    /// Creates a new RSA accumulator from explicit parameters.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use num_bigint::BigUint;
    /// use privacy_preserving_accumulators::{rsa_group::RsaGroup, RsaAccumulator};
    ///
    /// let acc = RsaAccumulator::<RsaGroup>::setup_from_params(
    ///     BigUint::from(61u32),
    ///     BigUint::from(53u32),
    ///     BigUint::from(2u32),
    ///     Some(BigUint::from(3120u32)),
    /// );
    /// assert_eq!(acc.value(), &BigUint::from(2u32));
    /// ```
    pub fn setup_from_params(p: BigUint, q: BigUint, g: BigUint, order: Option<BigUint>) -> Self {
        let n = &p * &q;
        let group = RsaGroup::new(n, g, order);
        Self::new(group)
    }

    /// Creates a new RSA accumulator without knowledge of the group order (trapdoorless).
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use num_bigint::BigUint;
    /// use privacy_preserving_accumulators::{rsa_group::RsaGroup, RsaAccumulator};
    ///
    /// // Generates 3072-bit safe primes; use setup_from_params for faster tests.
    /// let mut acc = RsaAccumulator::<RsaGroup>::setup_trapdoorless();
    /// let ep = acc.add(&BigUint::from(7u32));
    /// let proof = acc.mem_proof_create(&ep);
    /// assert!(acc.mem_ver(&proof, &ep));
    /// ```
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

    /// Sets the group order (totient) on the accumulator, enabling trapdoor-based operations.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use num_bigint::BigUint;
    /// use privacy_preserving_accumulators::{rsa_group::RsaGroup, RsaAccumulator};
    ///
    /// let mut acc = RsaAccumulator::<RsaGroup>::setup_from_params(
    ///     BigUint::from(61u32),
    ///     BigUint::from(53u32),
    ///     BigUint::from(2u32),
    ///     None,
    /// );
    /// acc.set_group_order(Some(BigUint::from(3120u32)));
    /// let ep = acc.add(&BigUint::from(7u32));
    /// assert!(acc.mem_ver(&acc.mem_proof_create(&ep), &ep));
    /// ```
    pub fn set_group_order(&mut self, order: Option<BigUint>) {
        self.group.set_order(order);
    }

    /// Removes the group order from the accumulator, switching to trapdoorless mode.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use num_bigint::BigUint;
    /// use privacy_preserving_accumulators::{rsa_group::RsaGroup, RsaAccumulator};
    ///
    /// let mut acc = RsaAccumulator::<RsaGroup>::setup_from_params(
    ///     BigUint::from(61u32),
    ///     BigUint::from(53u32),
    ///     BigUint::from(2u32),
    ///     Some(BigUint::from(3120u32)),
    /// );
    /// acc.clear_group_order();
    /// let ep = acc.add(&BigUint::from(7u32));
    /// assert!(acc.mem_ver(&acc.mem_proof_create(&ep), &ep));
    /// ```
    pub fn clear_group_order(&mut self) {
        self.group.set_order(None);
    }

    /// Returns the product of all elements in the set, reduced modulo the group order if available.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use num_bigint::BigUint;
    /// use privacy_preserving_accumulators::{rsa_group::RsaGroup, RsaAccumulator};
    ///
    /// let mut acc = RsaAccumulator::<RsaGroup>::setup_from_params(
    ///     BigUint::from(61u32),
    ///     BigUint::from(53u32),
    ///     BigUint::from(2u32),
    ///     Some(BigUint::from(3120u32)),
    /// );
    /// acc.add(&BigUint::from(2u32));
    /// acc.add(&BigUint::from(3u32));
    /// // Result is reduced modulo the group order (3120).
    /// assert!(acc.calculate_product() < BigUint::from(3120u32));
    /// ```
    pub fn calculate_product(&self) -> BigUint {
        if let Some(o) = self.group.order() {
            self.set.iter().fold(BigUint::one(), |acc, v| (acc * v) % o)
        } else {
            self.set.iter().product()
        }
    }

    /// Removes an element from the accumulator, updating the accumulated value.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use num_bigint::BigUint;
    /// use privacy_preserving_accumulators::{rsa_group::RsaGroup, RsaAccumulator};
    ///
    /// let mut acc = RsaAccumulator::<RsaGroup>::setup_from_params(
    ///     BigUint::from(61u32),
    ///     BigUint::from(53u32),
    ///     BigUint::from(2u32),
    ///     Some(BigUint::from(3120u32)),
    /// );
    /// let initial = acc.value().clone();
    /// let ep = acc.add(&BigUint::from(7u32));
    /// acc.del(&ep);
    /// assert_eq!(acc.value(), &initial);
    /// ```
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

    /// Creates a membership proof for an element in the accumulator.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use num_bigint::BigUint;
    /// use privacy_preserving_accumulators::{rsa_group::RsaGroup, RsaAccumulator};
    ///
    /// let mut acc = RsaAccumulator::<RsaGroup>::setup_from_params(
    ///     BigUint::from(61u32),
    ///     BigUint::from(53u32),
    ///     BigUint::from(2u32),
    ///     Some(BigUint::from(3120u32)),
    /// );
    /// let ep = acc.add(&BigUint::from(7u32));
    /// acc.add(&BigUint::from(11u32));
    /// let proof = acc.mem_proof_create(&ep);
    /// assert!(acc.mem_ver(&proof, &ep));
    /// ```
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

    /// Creates a non-membership proof for an element not in the accumulator.
    ///
    /// `prod` must be the product of all prime elements currently in the accumulator set.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use num_bigint::{BigInt, BigUint, ToBigInt};
    /// use privacy_preserving_accumulators::{rsa_group::RsaGroup, RsaAccumulator};
    ///
    /// let mut acc = RsaAccumulator::<RsaGroup>::setup_from_params(
    ///     BigUint::from(61u32),
    ///     BigUint::from(53u32),
    ///     BigUint::from(2u32),
    ///     Some(BigUint::from(3120u32)),
    /// );
    /// acc.add(&BigUint::from(2u32));
    /// acc.add(&BigUint::from(3u32));
    /// let non_member = BigUint::from(5u32);
    /// let product = acc.calculate_product_unreduced().to_bigint().unwrap();
    /// let proof = acc.non_mem_proof_create(&non_member, &product);
    /// assert!(acc.non_mem_ver(&proof, &non_member));
    /// ```
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

    /// Verifies a non-membership proof for a given element.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use num_bigint::{BigInt, BigUint, ToBigInt};
    /// use privacy_preserving_accumulators::{rsa_group::RsaGroup, RsaAccumulator};
    ///
    /// let mut acc = RsaAccumulator::<RsaGroup>::setup_from_params(
    ///     BigUint::from(61u32),
    ///     BigUint::from(53u32),
    ///     BigUint::from(2u32),
    ///     Some(BigUint::from(3120u32)),
    /// );
    /// acc.add(&BigUint::from(2u32));
    /// acc.add(&BigUint::from(3u32));
    /// let non_member = BigUint::from(5u32);
    /// let product = acc.calculate_product_unreduced().to_bigint().unwrap();
    /// let proof = acc.non_mem_proof_create(&non_member, &product);
    /// assert!(acc.non_mem_ver(&proof, &non_member));
    /// ```
    pub fn non_mem_ver(&self, proof: &(BigInt, BigUint), element: &BigUint) -> bool {
        let lhs = self.group.signed_exp(&self.acc, &proof.0);
        let rhs = self.group.exp(&proof.1, &element);
        self.group.mul(&lhs, &rhs) == self.group.g()
    }

    /// Updates a blinded membership proof after new elements are added to the accumulator.
    ///
    /// Returns the updated blinded proof, a NIZK auxiliary proof, and the new accumulator value.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use num_bigint::BigUint;
    /// use privacy_preserving_accumulators::{rsa_group::RsaGroup, RsaAccumulator};
    ///
    /// let mut acc = RsaAccumulator::<RsaGroup>::setup_from_params(
    ///     BigUint::from(61u32),
    ///     BigUint::from(53u32),
    ///     BigUint::from(2u32),
    ///     Some(BigUint::from(3120u32)),
    /// );
    /// let ep = acc.add(&BigUint::from(7u32));
    /// let acc_t = acc.value().clone();
    /// let proof = acc.mem_proof_create(&ep);
    /// let (blinded_proof, _st) = acc.blind_mem_proof(&proof);
    /// let new_elem = acc.add(&BigUint::from(11u32));
    /// let upd = acc.blind_mem_proof_upd(vec![new_elem], vec![], &acc_t, &blinded_proof);
    /// assert!(acc.ver_blind_mem_proof_upd(&acc_t, &blinded_proof, &upd.0, &upd.1));
    /// ```
    pub fn blind_mem_proof_upd(
        &self,
        elem_in: Vec<BigUint>,
        _elem_out: Vec<BigUint>,
        acc_t: &BigUint,
        blinded_proof: &BigUint,
    ) -> UpdatedBlindProof {
        let mut delta = BigUint::one();
        if let Some(o) = self.group.order() {
            for elem in elem_in {
                delta = (delta * elem) % o;
            }
        } else {
            for elem in elem_in {
                delta *= elem;
            }
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

    /// Verifies that a blinded membership proof was correctly updated using NIZK proofs.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use num_bigint::BigUint;
    /// use privacy_preserving_accumulators::{rsa_group::RsaGroup, RsaAccumulator};
    ///
    /// let mut acc = RsaAccumulator::<RsaGroup>::setup_from_params(
    ///     BigUint::from(61u32),
    ///     BigUint::from(53u32),
    ///     BigUint::from(2u32),
    ///     Some(BigUint::from(3120u32)),
    /// );
    /// let ep = acc.add(&BigUint::from(7u32));
    /// let acc_t = acc.value().clone();
    /// let proof = acc.mem_proof_create(&ep);
    /// let (blinded_proof, _st) = acc.blind_mem_proof(&proof);
    /// let new_elem = acc.add(&BigUint::from(11u32));
    /// let upd = acc.blind_mem_proof_upd(vec![new_elem], vec![], &acc_t, &blinded_proof);
    /// assert!(acc.ver_blind_mem_proof_upd(&acc_t, &blinded_proof, &upd.0, &upd.1));
    /// ```
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

    /// Creates a blinded non-membership proof for an element not in the accumulator.
    ///
    /// The blinded proof is `element * q` for a randomly chosen prime `q` (the blinding factor).
    /// Returns `(0, 1)` if the element is already a member.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use num_bigint::BigUint;
    /// use privacy_preserving_accumulators::{rsa_group::RsaGroup, RsaAccumulator};
    ///
    /// let acc = RsaAccumulator::<RsaGroup>::setup_from_params(
    ///     BigUint::from(61u32),
    ///     BigUint::from(53u32),
    ///     BigUint::from(2u32),
    ///     Some(BigUint::from(3120u32)),
    /// );
    /// let non_member = BigUint::from(17u32);
    /// let (blinded, q) = acc.blind_non_mem_proof(&non_member);
    /// assert_eq!(blinded, &non_member * &q);
    /// ```
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

    /// Updates a blinded non-membership proof after accumulator changes.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use num_bigint::{BigInt, BigUint};
    /// use privacy_preserving_accumulators::{rsa_group::RsaGroup, RsaAccumulator};
    ///
    /// let acc = RsaAccumulator::<RsaGroup>::setup_from_params(
    ///     BigUint::from(61u32),
    ///     BigUint::from(53u32),
    ///     BigUint::from(2u32),
    ///     Some(BigUint::from(3120u32)),
    /// );
    ///
    /// // With an empty set, the accumulator value is g and delta = 1.
    /// let blinded_non_member = BigUint::from(17u32);
    /// let updated = acc.blind_non_mem_proof_upd(&blinded_non_member, &BigInt::from(1u32));
    ///
    /// assert!(acc.ver_blind_non_mem_proof_upd(
    ///     acc.value(),
    ///     &blinded_non_member,
    ///     &updated,
    /// ));
    /// ```
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

    /// Verifies that a blinded non-membership proof was correctly updated.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use num_bigint::{BigInt, BigUint};
    /// use privacy_preserving_accumulators::{rsa_group::RsaGroup, RsaAccumulator};
    ///
    /// let acc = RsaAccumulator::<RsaGroup>::setup_from_params(
    ///     BigUint::from(61u32),
    ///     BigUint::from(53u32),
    ///     BigUint::from(2u32),
    ///     Some(BigUint::from(3120u32)),
    /// );
    /// let non_member = BigUint::from(17u32);
    /// let blinded = acc.blind_non_mem_proof(&non_member);
    /// let upd = acc.blind_non_mem_proof_upd(&blinded.0, &BigInt::from(1i32));
    /// assert!(acc.ver_blind_non_mem_proof_upd(acc.value(), &blinded.0, &upd));
    /// ```
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

    /// Unblinds an updated non-membership proof using the original blinding factor.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use num_bigint::{BigInt, BigUint, ToBigInt};
    /// use privacy_preserving_accumulators::{rsa_group::RsaGroup, RsaAccumulator};
    ///
    /// let mut acc = RsaAccumulator::<RsaGroup>::setup_from_params(
    ///     BigUint::from(61u32),
    ///     BigUint::from(53u32),
    ///     BigUint::from(2u32),
    ///     Some(BigUint::from(3120u32)),
    /// );
    /// let non_member = BigUint::from(17u32);
    /// let (blinded, q) = acc.blind_non_mem_proof(&non_member);
    /// acc.add(&BigUint::from(5u32));
    /// let product = acc.calculate_product_unreduced().to_bigint().unwrap();
    /// let upd = acc.blind_non_mem_proof_upd(&blinded, &product);
    /// let proof = acc.unblind_non_mem_proof(&q, &upd);
    /// assert!(acc.non_mem_ver(&proof, &non_member));
    /// ```
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

    /// Returns the product of all elements in the set without modular reduction.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use num_bigint::BigUint;
    /// use privacy_preserving_accumulators::{rsa_group::RsaGroup, RsaAccumulator};
    ///
    /// let mut acc = RsaAccumulator::<RsaGroup>::setup_from_params(
    ///     BigUint::from(61u32),
    ///     BigUint::from(53u32),
    ///     BigUint::from(2u32),
    ///     Some(BigUint::from(3120u32)),
    /// );
    /// let ep1 = acc.add(&BigUint::from(2u32));
    /// let ep2 = acc.add(&BigUint::from(3u32));
    /// // Each element is stored as its hash-to-prime representative.
    /// assert_eq!(acc.calculate_product_unreduced(), &ep1 * &ep2);
    /// ```
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
