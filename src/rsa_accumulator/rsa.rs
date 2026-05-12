use super::{Aux, RsaAccumulator, UpdatedBlindProof};
use crate::error::{AccumulatorError, AccumulatorResult};
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
    /// use private_accumulator_proof_delegation::{rsa_group::RsaGroup, RsaAccumulator};
    ///
    /// // Generates 3072-bit safe primes; use setup_from_params for faster tests.
    /// let mut acc = RsaAccumulator::<RsaGroup>::setup();
    /// let ep = acc.add_raw(&BigUint::from(7u32));
    /// let proof = acc.mem_proof_create_raw(&ep).unwrap();
    /// assert!(acc.mem_ver_raw(&proof, &ep));
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
    /// use private_accumulator_proof_delegation::{rsa_group::RsaGroup, RsaAccumulator};
    ///
    /// let acc = RsaAccumulator::<RsaGroup>::setup_from_params(
    ///     BigUint::from(61u32),
    ///     BigUint::from(53u32),
    ///     BigUint::from(2u32),
    ///     Some(BigUint::from(3120u32)),
    /// );
    /// assert_eq!(acc.value_raw(), &BigUint::from(2u32));
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
    /// use private_accumulator_proof_delegation::{rsa_group::RsaGroup, RsaAccumulator};
    ///
    /// // Generates 3072-bit safe primes; use setup_from_params for faster tests.
    /// let mut acc = RsaAccumulator::<RsaGroup>::setup_trapdoorless();
    /// let ep = acc.add_raw(&BigUint::from(7u32));
    /// let proof = acc.mem_proof_create_raw(&ep).unwrap();
    /// assert!(acc.mem_ver_raw(&proof, &ep));
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
    /// use private_accumulator_proof_delegation::{rsa_group::RsaGroup, RsaAccumulator};
    ///
    /// let mut acc = RsaAccumulator::<RsaGroup>::setup_from_params(
    ///     BigUint::from(61u32),
    ///     BigUint::from(53u32),
    ///     BigUint::from(2u32),
    ///     None,
    /// );
    /// acc.set_group_order(Some(BigUint::from(3120u32)));
    /// let ep = acc.add_raw(&BigUint::from(7u32));
    /// assert!(acc.mem_ver_raw(&acc.mem_proof_create_raw(&ep).unwrap(), &ep));
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
    /// use private_accumulator_proof_delegation::{rsa_group::RsaGroup, RsaAccumulator};
    ///
    /// let mut acc = RsaAccumulator::<RsaGroup>::setup_from_params(
    ///     BigUint::from(61u32),
    ///     BigUint::from(53u32),
    ///     BigUint::from(2u32),
    ///     Some(BigUint::from(3120u32)),
    /// );
    /// acc.clear_group_order();
    /// let ep = acc.add_raw(&BigUint::from(7u32));
    /// assert!(acc.mem_ver_raw(&acc.mem_proof_create_raw(&ep).unwrap(), &ep));
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
    /// use private_accumulator_proof_delegation::{rsa_group::RsaGroup, RsaAccumulator};
    ///
    /// let mut acc = RsaAccumulator::<RsaGroup>::setup_from_params(
    ///     BigUint::from(61u32),
    ///     BigUint::from(53u32),
    ///     BigUint::from(2u32),
    ///     Some(BigUint::from(3120u32)),
    /// );
    /// acc.add_raw(&BigUint::from(2u32));
    /// acc.add_raw(&BigUint::from(3u32));
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
    /// use private_accumulator_proof_delegation::{rsa_group::RsaGroup, RsaAccumulator};
    ///
    /// let mut acc = RsaAccumulator::<RsaGroup>::setup_from_params(
    ///     BigUint::from(61u32),
    ///     BigUint::from(53u32),
    ///     BigUint::from(2u32),
    ///     Some(BigUint::from(3120u32)),
    /// );
    /// let initial = acc.value_raw().clone();
    /// let ep = acc.add_raw(&BigUint::from(7u32));
    /// acc.del_raw(&ep);
    /// assert_eq!(acc.value_raw(), &initial);
    /// ```
    pub fn del_raw(&mut self, element: &BigUint) {
        if self.set.remove(element) {
            if let Some(o) = self.group.order() {
                let x_mod_inv = element
                    .modinv(o)
                    .expect("modinv exists because element is coprime with the group order");
                self.acc = self.group.exp(&self.acc, &x_mod_inv);
            } else {
                let product = self.calculate_product();
                self.acc = self.group.exp(&self.group.g(), &product);
            }
        }
    }

    /// Creates a membership proof for an element in the accumulator.
    ///
    /// # Errors
    ///
    /// Returns [`AccumulatorError::ElementNotInSet`] if `element` is not in
    /// the accumulator set.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use num_bigint::BigUint;
    /// use private_accumulator_proof_delegation::{rsa_group::RsaGroup, RsaAccumulator};
    ///
    /// let mut acc = RsaAccumulator::<RsaGroup>::setup_from_params(
    ///     BigUint::from(61u32),
    ///     BigUint::from(53u32),
    ///     BigUint::from(2u32),
    ///     Some(BigUint::from(3120u32)),
    /// );
    /// let ep = acc.add_raw(&BigUint::from(7u32));
    /// acc.add_raw(&BigUint::from(11u32));
    /// let proof = acc.mem_proof_create_raw(&ep).unwrap();
    /// assert!(acc.mem_ver_raw(&proof, &ep));
    /// ```
    pub fn mem_proof_create_raw(&self, element: &BigUint) -> AccumulatorResult<BigUint> {
        if !self.set.contains(element) {
            return Err(AccumulatorError::ElementNotInSet);
        }

        let proof = if let Some(o) = self.group.order() {
            let x_mod_inv = element
                .modinv(o)
                .expect("modinv exists because element is coprime with the group order");
            self.group.exp(&self.acc, &x_mod_inv)
        } else {
            let product = self.set.iter().filter(|&e| e != element).product();
            self.group.exp(&self.group.g(), &product)
        };
        Ok(proof)
    }

    /// Creates a non-membership proof for an element not in the accumulator.
    ///
    /// `delta` must be the product of all prime elements currently in the accumulator set.
    ///
    /// # Errors
    ///
    /// Returns [`AccumulatorError::NotCoprime`] if `element` is not coprime
    /// with `delta` (including the case where it is already a member).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use num_bigint::{BigInt, BigUint, ToBigInt};
    /// use private_accumulator_proof_delegation::{rsa_group::RsaGroup, RsaAccumulator};
    ///
    /// let mut acc = RsaAccumulator::<RsaGroup>::setup_from_params(
    ///     BigUint::from(61u32),
    ///     BigUint::from(53u32),
    ///     BigUint::from(2u32),
    ///     Some(BigUint::from(3120u32)),
    /// );
    /// acc.add_raw(&BigUint::from(2u32));
    /// acc.add_raw(&BigUint::from(3u32));
    /// let non_member = BigUint::from(5u32);
    /// let product = acc.calculate_product_unreduced().to_bigint().unwrap();
    /// let proof = acc.non_mem_proof_create_raw(&non_member, &product).unwrap();
    /// assert!(acc.non_mem_ver_raw(&proof, &non_member));
    /// ```
    pub fn non_mem_proof_create_raw(
        &self,
        element: &BigUint,
        delta: &BigInt,
    ) -> AccumulatorResult<(BigInt, BigUint)> {
        let x_prime_int = BigInt::from(element.clone());

        let ExtendedGcd { gcd, x: a, y: b } = Integer::extended_gcd(delta, &x_prime_int);
        if gcd != BigInt::one() {
            return Err(AccumulatorError::NotCoprime);
        }

        let proof = if let Some(o) = self.group.order() {
            let totient_int = o.to_bigint().expect("BigUint always converts to BigInt");
            let a_mod = a.mod_floor(&totient_int);
            let b_mod = b
                .mod_floor(&totient_int)
                .to_biguint()
                .expect("mod_floor output is non-negative");
            (a_mod, self.group.exp(&self.group.g(), &b_mod))
        } else {
            (a, self.group.signed_exp(&self.group.g(), &b))
        };
        Ok(proof)
    }

    /// Verifies a non-membership proof for a given element.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use num_bigint::{BigInt, BigUint, ToBigInt};
    /// use private_accumulator_proof_delegation::{rsa_group::RsaGroup, RsaAccumulator};
    ///
    /// let mut acc = RsaAccumulator::<RsaGroup>::setup_from_params(
    ///     BigUint::from(61u32),
    ///     BigUint::from(53u32),
    ///     BigUint::from(2u32),
    ///     Some(BigUint::from(3120u32)),
    /// );
    /// acc.add_raw(&BigUint::from(2u32));
    /// acc.add_raw(&BigUint::from(3u32));
    /// let non_member = BigUint::from(5u32);
    /// let product = acc.calculate_product_unreduced().to_bigint().unwrap();
    /// let proof = acc.non_mem_proof_create_raw(&non_member, &product).unwrap();
    /// assert!(acc.non_mem_ver_raw(&proof, &non_member));
    /// ```
    pub fn non_mem_ver_raw(&self, proof: &(BigInt, BigUint), element: &BigUint) -> bool {
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
    /// use num_bigint::{BigInt, BigUint};
    /// use private_accumulator_proof_delegation::{rsa_group::RsaGroup, RsaAccumulator};
    ///
    /// let mut acc = RsaAccumulator::<RsaGroup>::setup_from_params(
    ///     BigUint::from(61u32),
    ///     BigUint::from(53u32),
    ///     BigUint::from(2u32),
    ///     Some(BigUint::from(3120u32)),
    /// );
    /// let ep = acc.add_raw(&BigUint::from(7u32));
    /// let acc_t = acc.value_raw().clone();
    /// let proof = acc.mem_proof_create_raw(&ep).unwrap();
    /// let (blinded_proof, _st) = acc.blind_mem_proof_raw(&proof);
    /// let elements_in = vec![BigUint::from(11u32), BigUint::from(13u32)];
    /// let eps: Vec<BigUint> = elements_in.iter().map(|e| acc.add_raw(e)).collect();
    /// let delta = if let Some(o) = acc.group.order() {
    ///     eps.iter().fold(BigUint::from(1u32), |delta, e| (delta * e) % o)
    /// } else {
    ///     eps.iter().fold(BigUint::from(1u32), |delta, e| delta * e)
    /// };
    /// let delta_int = BigInt::from(delta);
    /// let upd = acc.blind_mem_proof_upd_raw(&acc_t, &blinded_proof, &delta_int).unwrap();
    /// assert!(acc.ver_blind_mem_proof_upd_raw(&acc_t, &blinded_proof, &upd.0, &upd.1));
    /// ```
    pub fn blind_mem_proof_upd_raw(
        &self,
        acc_t: &BigUint,
        blinded_proof: &BigUint,
        delta: &BigInt,
    ) -> AccumulatorResult<UpdatedBlindProof> {
        let mut delta_uint = delta.to_biguint().ok_or(AccumulatorError::NegativeDelta)?;

        if let Some(order) = self.group.order() {
            delta_uint %= order;
        }

        let acc_t_prime = &self.acc;
        let a = self.group.exp(blinded_proof, &delta_uint);
        let g = self.group.g();
        let b = self.group.exp(&g, &delta_uint);

        let nizk = NIZK::setup(&self.group);
        let pi1 = NIZK::prove_dleq(&nizk, blinded_proof, &a, acc_t, acc_t_prime, &delta_uint);
        let pi2 = NIZK::prove_dleq(&nizk, &g, &b, blinded_proof, &a, &delta_uint);

        let upd_blinded_proof = (a, b);
        let aux = (pi1, pi2);
        Ok((upd_blinded_proof, aux, self.acc.clone()))
    }

    /// Verifies that a blinded membership proof was correctly updated using NIZK proofs.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use num_bigint::{BigInt, BigUint};
    /// use private_accumulator_proof_delegation::{rsa_group::RsaGroup, RsaAccumulator};
    ///
    /// let mut acc = RsaAccumulator::<RsaGroup>::setup_from_params(
    ///     BigUint::from(61u32),
    ///     BigUint::from(53u32),
    ///     BigUint::from(2u32),
    ///     Some(BigUint::from(3120u32)),
    /// );
    /// let ep = acc.add_raw(&BigUint::from(7u32));
    /// let acc_t = acc.value_raw().clone();
    /// let proof = acc.mem_proof_create_raw(&ep).unwrap();
    /// let (blinded_proof, _st) = acc.blind_mem_proof_raw(&proof);
    /// let elements_in = vec![BigUint::from(11u32), BigUint::from(13u32)];
    /// let eps: Vec<BigUint> = elements_in.iter().map(|e| acc.add_raw(e)).collect();
    /// let delta = if let Some(o) = acc.group.order() {
    ///     eps.iter().fold(BigUint::from(1u32), |delta, e| (delta * e) % o)
    /// } else {
    ///     eps.iter().fold(BigUint::from(1u32), |delta, e| delta * e)
    /// };
    /// let delta_int = BigInt::from(delta);
    /// let upd = acc.blind_mem_proof_upd_raw(&acc_t, &blinded_proof, &delta_int).unwrap();
    /// assert!(acc.ver_blind_mem_proof_upd_raw(&acc_t, &blinded_proof, &upd.0, &upd.1));
    /// ```
    pub fn ver_blind_mem_proof_upd_raw(
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
    /// use private_accumulator_proof_delegation::{rsa_group::RsaGroup, RsaAccumulator};
    ///
    /// let acc = RsaAccumulator::<RsaGroup>::setup_from_params(
    ///     BigUint::from(61u32),
    ///     BigUint::from(53u32),
    ///     BigUint::from(2u32),
    ///     Some(BigUint::from(3120u32)),
    /// );
    /// let non_member = BigUint::from(17u32);
    /// let (blinded, q) = acc.blind_non_mem_proof_raw(&non_member);
    /// assert_eq!(blinded, &non_member * &q);
    /// ```
    pub fn blind_non_mem_proof_raw(&self, element: &BigUint) -> (BigUint, BigUint) {
        if self.set.contains(element) {
            (BigUint::from(0u32), BigUint::from(1u32))
        } else {
            let mut rng = thread_rng();

            let seed = rng.gen_biguint(128);
            let q = self
                .group
                .hash_to_prime(seed.to_bytes_be().as_slice())
                .to_biguint()
                .expect("hash_to_prime always returns a positive prime");

            let blinded_non_mem_proof = element * &q;
            (blinded_non_mem_proof, q)
        }
    }

    /// Updates a blinded non-membership proof after accumulator changes.
    ///
    /// # Errors
    ///
    /// Returns [`AccumulatorError::NotCoprime`] if the blinded value shares
    /// a prime factor with `delta`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use num_bigint::{BigInt, BigUint};
    /// use private_accumulator_proof_delegation::{rsa_group::RsaGroup, RsaAccumulator};
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
    /// let updated = acc.blind_non_mem_proof_upd_raw(&blinded_non_member, &BigInt::from(1u32)).unwrap();
    ///
    /// assert!(acc.ver_blind_non_mem_proof_upd_raw(
    ///     acc.value_raw(),
    ///     &blinded_non_member,
    ///     &updated,
    /// ));
    /// ```
    pub fn blind_non_mem_proof_upd_raw(
        &self,
        blinded_non_mem_proof: &BigUint,
        delta: &BigInt,
    ) -> AccumulatorResult<(BigInt, BigUint)> {
        let blinded_int = BigInt::from(blinded_non_mem_proof.clone());
        let ExtendedGcd { gcd, x: a, y: b } = Integer::extended_gcd(delta, &blinded_int);
        if gcd != BigInt::one() {
            return Err(AccumulatorError::NotCoprime);
        }

        let proof = if let Some(t) = self.group.order() {
            let totient_int = t.to_bigint().expect("BigUint always converts to BigInt");
            let a_mod = a.mod_floor(&totient_int);
            let b_mod = b
                .mod_floor(&totient_int)
                .to_biguint()
                .expect("mod_floor output is non-negative");
            (a_mod, self.group.exp(&self.group.g(), &b_mod))
        } else {
            (a, self.group.signed_exp(&self.group.g(), &b))
        };
        Ok(proof)
    }

    /// Verifies that a blinded non-membership proof was correctly updated.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use num_bigint::{BigInt, BigUint};
    /// use private_accumulator_proof_delegation::{rsa_group::RsaGroup, RsaAccumulator};
    ///
    /// let acc = RsaAccumulator::<RsaGroup>::setup_from_params(
    ///     BigUint::from(61u32),
    ///     BigUint::from(53u32),
    ///     BigUint::from(2u32),
    ///     Some(BigUint::from(3120u32)),
    /// );
    /// let non_member = BigUint::from(17u32);
    /// let blinded = acc.blind_non_mem_proof_raw(&non_member);
    /// let upd = acc.blind_non_mem_proof_upd_raw(&blinded.0, &BigInt::from(1i32)).unwrap();
    /// assert!(acc.ver_blind_non_mem_proof_upd_raw(acc.value_raw(), &blinded.0, &upd));
    /// ```
    pub fn ver_blind_non_mem_proof_upd_raw(
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
    /// use private_accumulator_proof_delegation::{rsa_group::RsaGroup, RsaAccumulator};
    ///
    /// let mut acc = RsaAccumulator::<RsaGroup>::setup_from_params(
    ///     BigUint::from(61u32),
    ///     BigUint::from(53u32),
    ///     BigUint::from(2u32),
    ///     Some(BigUint::from(3120u32)),
    /// );
    /// let non_member = BigUint::from(17u32);
    /// let (blinded, q) = acc.blind_non_mem_proof_raw(&non_member);
    /// acc.add_raw(&BigUint::from(5u32));
    /// let product = acc.calculate_product_unreduced().to_bigint().unwrap();
    /// let upd = acc.blind_non_mem_proof_upd_raw(&blinded, &product).unwrap();
    /// let proof = acc.unblind_non_mem_proof_raw(&q, &upd);
    /// assert!(acc.non_mem_ver_raw(&proof, &non_member));
    /// ```
    pub fn unblind_non_mem_proof_raw(
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
    /// use private_accumulator_proof_delegation::{rsa_group::RsaGroup, RsaAccumulator};
    ///
    /// let mut acc = RsaAccumulator::<RsaGroup>::setup_from_params(
    ///     BigUint::from(61u32),
    ///     BigUint::from(53u32),
    ///     BigUint::from(2u32),
    ///     Some(BigUint::from(3120u32)),
    /// );
    /// let ep1 = acc.add_raw(&BigUint::from(2u32));
    /// let ep2 = acc.add_raw(&BigUint::from(3u32));
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

    fn new(group: Self::Group) -> Self {
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
        self.value_raw()
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
        let product = self
            .calculate_product_unreduced()
            .to_bigint()
            .expect("BigUint always converts to BigInt");
        self.non_mem_proof_create_raw(element, &product)
    }

    fn non_mem_ver(&self, proof: &Self::NonMembershipProof, element: &Self::Element) -> bool {
        self.non_mem_ver_raw(proof, element)
    }
}

impl PrivatelyDelegatableAccumulator for RsaAccumulator<RsaGroup> {
    type BlindedMembershipProof = BigUint;
    type MembershipBlindingFactor = BigUint;
    type UpdatedBlindedMembershipProof = (BigUint, BigUint);
    type MembershipUpdateAux = Aux;
    type BlindedNonMembershipProof = (BigUint, BigUint);
    type UpdatedBlindedNonMembershipProof = (BigInt, BigUint);
    type Delta = Vec<BigUint>;

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
        let product = if let Some(o) = self.group.order() {
            delta.iter().fold(BigUint::one(), |acc, e| (acc * e) % o)
        } else {
            delta.iter().fold(BigUint::one(), |acc, e| acc * e)
        };
        let delta_int = product
            .to_bigint()
            .expect("BigUint always converts to BigInt");
        self.blind_mem_proof_upd_raw(acc_t, blinded_proof, &delta_int)
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
        let product: BigUint = delta.iter().product();
        let delta_int = product
            .to_bigint()
            .expect("BigUint always converts to BigInt");
        self.blind_non_mem_proof_upd_raw(&blinded_non_mem_proof.0, &delta_int)
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
mod trapdoored_tests {
    use super::*;
    use crate::groups::rsa_group::RsaGroup;
    use num_bigint::BigUint;

    #[test]
    fn test_acc_add_del_no_change() {
        let mut acc = RsaAccumulator::<RsaGroup>::setup();
        let initial_acc = acc.acc.clone();
        let element = BigUint::from_bytes_be(b"test_element");

        let ep = acc.add_raw(&element);
        acc.del_raw(&ep);

        assert_eq!(
            acc.acc, initial_acc,
            "Accumulator value should be unchanged after add and remove of the same element"
        );
    }

    #[test]
    fn test_gen_mem_proof() {
        let mut acc = RsaAccumulator::<RsaGroup>::setup();
        let element = BigUint::from(7usize);
        let ep = acc.add_raw(&element);

        for i in 2..5 {
            acc.add_raw(&BigUint::from(i as usize));
        }

        let proof = acc.mem_proof_create_raw(&ep).unwrap();

        assert!(acc.mem_ver_raw(&proof, &ep));
    }

    #[test]
    fn test_non_mem_proof() {
        let mut acc = RsaAccumulator::<RsaGroup>::setup();

        acc.add_raw(&BigUint::from(2u32));
        acc.add_raw(&BigUint::from(3u32));
        acc.add_raw(&BigUint::from(7u32));

        let non_member = BigUint::from(5u32);

        let proof = acc
            .non_mem_proof_create_raw(
                &non_member,
                &acc.calculate_product_unreduced().to_bigint().unwrap(),
            )
            .unwrap();
        assert!(
            acc.non_mem_ver_raw(&proof, &non_member),
            "Non-membership proof should verify"
        );
    }

    #[test]
    fn test_blind_unblind_mem() {
        let mut acc = RsaAccumulator::<RsaGroup>::setup();

        let element = BigUint::from(7usize);
        let ep: BigUint = acc.add_raw(&element);

        for i in 2..5 {
            acc.add_raw(&BigUint::from(i as usize));
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
        let mut acc = RsaAccumulator::<RsaGroup>::setup();

        let ep = acc.add_raw(&BigUint::from(200003u32));

        let acct = acc.acc.clone();

        let proof = acc.mem_proof_create_raw(&ep).unwrap();

        let elements_in = vec![
            BigUint::from(65537u32),
            BigUint::from(100003u32),
            BigUint::from(104729u32),
            BigUint::from(1299709u32),
            BigUint::from(15485863u32),
        ];

        let elements_in = elements_in
            .iter()
            .map(|e| acc.add_raw(e))
            .collect::<Vec<_>>();
        let delta = if let Some(o) = acc.group.order() {
            elements_in
                .iter()
                .fold(BigUint::one(), |delta, e| (delta * e) % o)
        } else {
            elements_in
                .iter()
                .fold(BigUint::one(), |delta, e| delta * e)
        };
        let delta_int = delta.to_bigint().unwrap();

        let blinded_proof = acc.blind_mem_proof_raw(&proof);

        let upd_blind_proof = acc
            .blind_mem_proof_upd_raw(&acct, &blinded_proof.0, &delta_int)
            .unwrap();

        assert!(acc.ver_blind_mem_proof_upd_raw(
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
            acc.add_raw(&BigUint::from(i as usize));
        }

        let non_member = BigUint::from(7usize);

        let blinded_proof = acc.blind_non_mem_proof_raw(&non_member);

        for i in 10..12 {
            acc.add_raw(&BigUint::from(i as usize));
        }

        let upd_blind_non_mem_proof = acc
            .blind_non_mem_proof_upd_raw(
                &blinded_proof.0,
                &BigInt::from(acc.calculate_product_unreduced()),
            )
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
        let mut acc = RsaAccumulator::<RsaGroup>::setup();

        let non_member = BigUint::from(200003u32);

        let blinded_proof = acc.blind_non_mem_proof_raw(&non_member);

        let elements_in = vec![
            BigUint::from(65537u32),
            BigUint::from(100003u32),
            BigUint::from(104729u32),
            BigUint::from(1299709u32),
            BigUint::from(15485863u32),
        ];

        for elem in &elements_in {
            acc.add_raw(elem);
        }

        let acctprime = acc.acc.clone();

        let upd_blind_proof = acc
            .blind_non_mem_proof_upd_raw(
                &blinded_proof.0,
                &BigInt::from(acc.calculate_product_unreduced()),
            )
            .unwrap();

        assert!(
            acc.ver_blind_non_mem_proof_upd_raw(&acctprime, &blinded_proof.0, &upd_blind_proof),
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

        let ep = acc.add_raw(&element);
        acc.del_raw(&ep);

        assert_eq!(
            acc.acc, initial_acc,
            "Accumulator value should be unchanged after add and remove of the same element"
        );
    }

    #[test]
    fn test_gen_mem_proof() {
        let mut acc = RsaAccumulator::<RsaGroup>::setup_trapdoorless();
        let element = BigUint::from(7usize);

        let ep = acc.add_raw(&element);

        for i in 2..5 {
            acc.add_raw(&BigUint::from(i as usize));
        }

        let proof = acc.mem_proof_create_raw(&ep).unwrap();

        assert!(acc.mem_ver_raw(&proof, &ep));
    }

    #[test]
    fn test_non_mem_proof() {
        let mut acc = RsaAccumulator::<RsaGroup>::setup_trapdoorless();

        acc.add_raw(&BigUint::from(2u32));
        acc.add_raw(&BigUint::from(3u32));
        acc.add_raw(&BigUint::from(7u32));

        let non_member = BigUint::from(5u32);

        let proof = acc
            .non_mem_proof_create_raw(
                &non_member,
                &(acc.calculate_product_unreduced().to_bigint().unwrap()),
            )
            .unwrap();
        assert!(
            acc.non_mem_ver_raw(&proof, &non_member),
            "Non-membership proof should verify"
        );
    }

    #[test]
    fn test_blind_unblind_mem() {
        let mut acc = RsaAccumulator::<RsaGroup>::setup_trapdoorless();

        let element = BigUint::from(7usize);
        let ep: BigUint = acc.add_raw(&element);

        for i in 2..5 {
            acc.add_raw(&BigUint::from(i as usize));
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
        let mut acc = RsaAccumulator::<RsaGroup>::setup_trapdoorless();

        let ep = acc.add_raw(&BigUint::from(200003u32));

        let acct = acc.acc.clone();

        let proof = acc.mem_proof_create_raw(&ep).unwrap();

        let blinded_proof = acc.blind_mem_proof_raw(&proof);

        let elements = vec![
            BigUint::from(65537u32),
            BigUint::from(100003u32),
            BigUint::from(104729u32),
            BigUint::from(1299709u32),
            BigUint::from(15485863u32),
        ];

        let elements_in = elements.iter().map(|e| acc.add_raw(e)).collect::<Vec<_>>();
        let delta = if let Some(o) = acc.group.order() {
            elements_in
                .iter()
                .fold(BigUint::one(), |delta, e| (delta * e) % o)
        } else {
            elements_in
                .iter()
                .fold(BigUint::one(), |delta, e| delta * e)
        };
        let delta_int = delta.to_bigint().unwrap();

        let upd_blind_proof = acc
            .blind_mem_proof_upd_raw(&acct, &blinded_proof.0, &delta_int)
            .unwrap();

        assert!(acc.ver_blind_mem_proof_upd_raw(
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
            acc.add_raw(&BigUint::from(i as usize));
        }

        let non_member = BigUint::from(7usize);

        let blinded_proof = acc.blind_non_mem_proof_raw(&non_member);

        for i in 10..12 {
            acc.add_raw(&BigUint::from(i as usize));
        }

        let upd_blind_non_mem_proof = acc
            .blind_non_mem_proof_upd_raw(
                &blinded_proof.0,
                &BigInt::from(acc.calculate_product_unreduced()),
            )
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
        let mut acc = RsaAccumulator::<RsaGroup>::setup_trapdoorless();

        let non_member = BigUint::from(200003u32);

        let blinded_proof = acc.blind_non_mem_proof_raw(&non_member);

        let elements_in = vec![
            BigUint::from(65537u32),
            BigUint::from(100003u32),
            BigUint::from(104729u32),
            BigUint::from(1299709u32),
            BigUint::from(15485863u32),
        ];

        for elem in &elements_in {
            acc.add_raw(elem);
        }

        let acctprime = acc.acc.clone();

        let upd_blind_proof = acc
            .blind_non_mem_proof_upd_raw(
                &blinded_proof.0,
                &BigInt::from(acc.calculate_product_unreduced()),
            )
            .unwrap();

        assert!(
            acc.ver_blind_non_mem_proof_upd_raw(&acctprime, &blinded_proof.0, &upd_blind_proof),
            "Couldnt verify"
        );
    }
}
