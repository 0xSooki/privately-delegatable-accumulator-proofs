use crate::nizk;
use crate::nizk::NIZK;
use crate::rsa_group;
use crate::rsa_group::RsaGroup;
use crate::traits::Group;
use glass_pumpkin::safe_prime;
use num_bigint::{BigInt, BigUint, RandBigInt, ToBigInt, ToBigUint};
use num_integer::gcd;
use num_integer::ExtendedGcd;
use num_integer::Integer;
use num_traits::{One, Zero};
use rand::random;
use rand::thread_rng;
use std::collections::HashSet;
use std::iter::Product;

type Aux = ((BigUint, BigUint, BigUint), (BigUint, BigUint, BigUint));
type UpdatedBlindProof = ((BigUint, BigUint), Aux, BigUint);

extern crate primes;

const KEY_SIZE: u64 = 256; // This key size is just for demonstration

#[derive(Clone, Debug)]
pub struct RsaAccumulator {
    pub group: RsaGroup,
    pub n: BigUint,
    pub g: BigUint,
    pub acc: BigUint,
    pub totient: Option<BigUint>,
    pub set: HashSet<BigUint>,
}

impl RsaAccumulator {
    pub fn setup() -> Self {
        let mut rng = rand::thread_rng();

        let p_uint = safe_prime::new(KEY_SIZE as usize).unwrap();
        let q_uint = safe_prime::new(KEY_SIZE as usize).unwrap();
        //println!("setup: {:?}, {:?}", p_uint, q_uint);
        let p = BigUint::from(p_uint);
        let q = BigUint::from(q_uint);

        let n = &p * &q;
        let totient = (&p - BigUint::one()) * (&q - BigUint::one());

        // use quadratic residue for generator
        let g = rng.gen_biguint_range(&BigUint::one(), &n);
        let group = RsaGroup::new(n.clone(), g.clone(), Some(totient.clone()));

        RsaAccumulator {
            group,
            n,
            g: g.clone(),
            acc: g,
            totient: Some(totient),
            set: HashSet::new(),
        }
    }

    pub fn setup_trapdoorless() -> Self {
        let mut rng = rand::thread_rng();

        let p_uint = safe_prime::new(KEY_SIZE as usize).unwrap();
        let q_uint = safe_prime::new(KEY_SIZE as usize).unwrap();
        let p = BigUint::from(p_uint);
        let q = BigUint::from(q_uint);
        let n = &p * &q;

        let g = rng.gen_biguint_range(&BigUint::one(), &n);
        let group = RsaGroup::new(n.clone(), g.clone(), None);

        RsaAccumulator {
            group,
            n,
            g: g.clone(),
            acc: g,
            totient: None,
            set: HashSet::new(),
        }
    }

    pub fn add(&mut self, mut x: &BigUint) -> BigUint {
        let x_str = x.to_string();
        let prime_u128 = self.group.hash_to_prime(x_str.as_bytes());
        let x_prime = BigUint::from(prime_u128);

        // This ensures x is coprime to the totient, so its modular inverse exists.
        // Otherwise, removing the element may fail if the inverse does not exist.
        if self.set.contains(&x_prime) {
        } else {
            self.set.insert(x_prime.clone());
            self.acc = self.acc.modpow(&x_prime, &self.n);
        }
        x_prime
    }

    pub fn del(&mut self, x: &BigUint) {
        // If elements are hashed to primes during addition, the modular inverse will exist.
        // This ensures deletion works without panicking.
        // `cargo run` won't panick.
        let x_str = x.to_string();
        let prime_u128 = self.group.hash_to_prime(x_str.as_bytes());
        let x_prime = BigUint::from(prime_u128);

        if !self.set.contains(&x_prime) {
        } else {
            self.set.remove(&x_prime);

            let product = RsaAccumulator::calculate_product(&self);
            self.acc = self.g.modpow(&product, &self.n);
        }
    }

    pub fn calculate_product(&self) -> BigUint {
        if self.set.is_empty() {
            return BigUint::one();
        }
        let mut product = BigUint::one();

        for s in self.set.clone() {
            product *= s;
        }

        if let Some(t) = self.totient.as_ref() {
            //println!("TRAPDOORED:");
            //print!("{:?}", self.reduce_exp(product.clone()));
            self.reduce_exp(product)
        } else {
            //println!("TRAPDOORLESS:");
            //print!("{:?}", product.clone());
            product
        }
    }

    pub fn mem_proof_create(&mut self, x: &BigUint) -> BigUint {
        let mut prod = BigUint::one();
        for s in &self.set {
            if !s.eq(&x) {
                prod *= s;
            }
        }
        prod = self.reduce_exp(prod);
        let proof = self.g.modpow(&prod, &self.n);
        proof
    }

    pub fn non_mem_proof_create(&self, x: &BigUint) -> (BigInt, BigUint) {
        let p = self.calculate_product();
        let s = BigInt::from(p);

        let x_str = x.to_string();
        let prime_u128 = self.group.hash_to_prime(x_str.as_bytes());
        let x_prime = BigUint::from(prime_u128);
        let x_prime_int = BigInt::from(x_prime.clone());

        let ExtendedGcd { gcd, x, y } = Integer::extended_gcd(&s, &x_prime_int);
        assert_eq!(
            gcd,
            BigInt::one(),
            "non-member prime must be coprime with accumulator set product"
        );
        if let Some(t) = self.totient.as_ref() {
            let totient_int = t.to_bigint().unwrap();
            let a = ((x % &totient_int) + &totient_int) % &totient_int;
            let b = (((y % &totient_int) + &totient_int) % &totient_int)
                .to_biguint()
                .unwrap();
            (a, self.g.modpow(&b, &self.n))
        } else {
            let a = x.clone();

            let b_bigint = y.clone();

            if b_bigint < BigInt::ZERO {
                let inv_g = self.g.modinv(&self.n).unwrap();

                let abs_b = (-b_bigint).to_biguint().unwrap();

                let non_mem_proof_create = (a, inv_g.modpow(&abs_b, &self.n));
                non_mem_proof_create
            } else {
                let b = y.to_biguint().unwrap();

                let non_mem_proof_create = (a, self.g.modpow(&b, &self.n));
                non_mem_proof_create
            }
        }
    }

    pub fn mem_ver(&self, proof: &BigUint, x: &BigUint) -> bool {
        proof.modpow(&x, &self.n) == self.acc
    }

    pub fn non_mem_ver(&self, proof: &(BigInt, BigUint), x: &BigUint) -> bool {
        let x_str = x.to_string();
        let prime_u128 = self.group.hash_to_prime(x_str.as_bytes());
        let x_prime = BigUint::from(prime_u128);
        if proof.0 < BigInt::ZERO {
            //println!("A NEGATIV");
            let inv_acct = self.acc.modinv(&self.n).unwrap();
            let abs_a = (-&proof.0).to_biguint().unwrap();
            (inv_acct.modpow(&abs_a, &self.n) * &proof.1.modpow(&x_prime, &self.n)) % &self.n
                == self.g
        } else {
            //println!("A POZITIV");
            //println!("{:?}", (self.acc.modpow(&proof.0.to_biguint().unwrap(), &self.n) * &proof.1.modpow(&x_prime, &self.n)) % &self.n);
            //println!("{:?}", self.g);
            (self.acc.modpow(&proof.0.to_biguint().unwrap(), &self.n)
                * &proof.1.modpow(&x_prime, &self.n))
                % &self.n
                == self.g
        }
    }

    pub fn blind_mem_proof(&self, mem_proof: &BigUint) -> (BigUint, BigUint) {
        let mut rng = thread_rng();
        let st = rng.gen_biguint(128);
        let blinded_proof = (mem_proof * self.g.modpow(&st, &self.n)) % &self.n;
        (blinded_proof, st)
    }

    pub fn blind_mem_proof_upd(
        &self,
        elem_in: Vec<BigUint>,
        elem_out: Vec<BigUint>,
        acc_t: &BigUint,
        blinded_proof: &BigUint,
    ) -> UpdatedBlindProof {
        let mut delta = BigUint::one();
        for elem in &elem_in {
            let x_str = elem.to_string();
            let x_prime = self.group.hash_to_prime(x_str.as_bytes());
            delta *= &x_prime;
        }
        let acct_tprime = &self.acc;
        let a = blinded_proof.modpow(&delta, &self.n);
        let b = self.g.modpow(&delta, &self.n);

        let nizk = NIZK::setup(&self.group);
        let pi1 = NIZK::prove_dleq(&nizk, blinded_proof, &a, acc_t, &acct_tprime, &delta);
        let pi2 = NIZK::prove_dleq(&nizk, &self.g, &b, blinded_proof, &a, &delta);

        let upd_blinded_proof = (a, b);
        let aux = (pi1, pi2);
        (upd_blinded_proof, aux, acc_t.clone())
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
        let acct_tprime = &self.acc;

        let d1 = NIZK::verify_dleq(&nizk, &blinded_proof, &a, &acc_t, &acct_tprime, &pi1);
        let d2 = NIZK::verify_dleq(&nizk, &self.g, &b, &blinded_proof, &a, &pi2);
        d1 && d2
    }

    pub fn unblind_mem_proof(&self, blinded_proof: &BigUint, st: &BigUint) -> BigUint {
        let st_inv = self.g.modpow(&st, &self.n).modinv(&self.n).unwrap();
        let proof = blinded_proof * st_inv % &self.n;
        proof
    }

    pub fn blind_non_mem_proof(&self, x: &BigUint) -> (BigUint, BigUint) {
        let x_str = x.to_string();
        let prime_u128 = self.group.hash_to_prime(x_str.as_bytes());
        let x_prime = BigUint::from(prime_u128);

        if self.set.contains(&x_prime) {
            return (BigUint::from(0u32), BigUint::from(1u32));
        } else {
            let mut rng = thread_rng();
            let s = self.calculate_product();

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

            return (blinded_non_mem_proof, q);
        }
    }

    pub fn blind_non_mem_proof_upd(&self, blinded_non_mem_proof: &BigUint) -> (BigInt, BigUint) {
        let p = self.calculate_product();
        let s = BigInt::from(p);

        let bnmp_str_int = BigInt::from(blinded_non_mem_proof.clone());
        let ExtendedGcd { gcd, x, y } = Integer::extended_gcd(&s, &bnmp_str_int);
        assert_eq!(
            gcd,
            BigInt::one(),
            "blinded value must be coprime with accumulator set product"
        );

        if let Some(t) = self.totient.as_ref() {
            let totient_int = t.to_bigint().unwrap();
            let a = ((x % &totient_int) + &totient_int) % &totient_int;
            let b = (((y % &totient_int) + &totient_int) % &totient_int)
                .to_biguint()
                .unwrap();
            let upd_blinded_non_mem_proof = (a, self.g.modpow(&b, &self.n));
            upd_blinded_non_mem_proof
        } else {
            let a = x.clone();

            let b_bigint = y.clone();

            if b_bigint < BigInt::ZERO {
                let inv_g = self.g.modinv(&self.n).unwrap();

                let abs_b = (-b_bigint).to_biguint().unwrap();

                let upd_blinded_non_mem_proof = (a, inv_g.modpow(&abs_b, &self.n));
                upd_blinded_non_mem_proof
            } else {
                let b = y.to_biguint().unwrap();

                let upd_blinded_non_mem_proof = (a, self.g.modpow(&b, &self.n));
                upd_blinded_non_mem_proof
            }
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
        let y = blinded_non_mem_proof;

        //println!("A:");
        //print!("{:?}", a);

        if a < &BigInt::ZERO {
            //println!("A NEGATIV");
            let inv_acc_t_prime = acc_t_prime.modinv(&self.n).unwrap();
            let abs_a = (-a).to_biguint().unwrap();
            self.g == (inv_acc_t_prime.modpow(&abs_a, &self.n) * b.modpow(&y, &self.n)) % &self.n
        } else {
            //println!("A POZITIV");
            self.g
                == (acc_t_prime.modpow(&a.to_biguint().unwrap(), &self.n) * b.modpow(&y, &self.n))
                    % &self.n
        }
    }

    pub fn unblind_non_mem_proof(
        &self,
        st: &BigUint,
        upd_blinded_non_mem_proof: &(BigInt, BigUint),
    ) -> (BigInt, BigUint) {
        //QUESTION is it a problem to change the return value here to (BigInt, BigUint) from (BigInt, BigUint) in order to handle to negativ 'a' from bezout coefficient from upd_blinded_non_mem_proof? but in this case we dont 'handle' it just return the ublinded updated non mem proof as it is
        let a = &upd_blinded_non_mem_proof.0;
        let b = &upd_blinded_non_mem_proof.1;
        let q = st;
        let b_prime = b.modpow(&q, &self.n);

        let upd_unblinded_non_mem_proof = (a.clone(), b_prime);
        return upd_unblinded_non_mem_proof;
    }

    fn reduce_exp(&self, exp: BigUint) -> BigUint {
        match &self.totient {
            Some(t) => exp % t,
            None => exp,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigUint;

    #[test]
    fn test_acc_add_del_no_change() {
        let mut acc = RsaAccumulator::setup();
        let initial_acc = acc.acc.clone();
        let element = BigUint::from_bytes_be(b"test_element");

        acc.add(&element);
        acc.del(&element);

        assert_eq!(
            acc.acc, initial_acc,
            "Accumulator value should be unchanged after add and remove of the same element"
        );
    }

    #[test]
    fn test_gen_mem_proof() {
        let mut acc = RsaAccumulator::setup();
        let element = BigUint::from(7 as usize);
        let ep = acc.add(&element);

        for i in 2..5 {
            acc.add(&BigUint::from(i as usize));
        }

        let proof = acc.mem_proof_create(&ep);

        assert!(acc.mem_ver(&proof, &ep));
    }

    #[test]
    fn test_non_mem_proof() {
        let mut acc = RsaAccumulator::setup();

        acc.add(&BigUint::from(2u32));
        acc.add(&BigUint::from(3u32));
        acc.add(&BigUint::from(7u32));

        let non_member = BigUint::from(5u32);

        let proof = acc.non_mem_proof_create(&non_member);
        assert!(
            acc.non_mem_ver(&proof, &non_member),
            "Non-membership proof should verify"
        );
    }

    #[test]
    fn test_blind_unblind_mem() {
        let mut acc = RsaAccumulator::setup();

        let element = BigUint::from(7 as usize);
        let ep: BigUint = acc.add(&element);

        for i in 2..5 {
            acc.add(&BigUint::from(i as usize));
        }

        let proof = acc.mem_proof_create(&ep);

        let blinded_proof = acc.blind_mem_proof(&proof);

        /*
                let elements_in = vec![
                    BigUint::from(65537u32),
                    BigUint::from(100003u32),
                    BigUint::from(104729u32),
                    BigUint::from(1299709u32),
                    BigUint::from(15485863u32),
                ];

                let elements_out = vec![];
                for elem in &elements_in {
                    acc.add(&elem);
                }

                let upd_blind_non_mem_proof = acc.blind_mem_proof_upd(elements_in, elements_out, &acct_prime, &blinded_proof);

        */
        assert!(
            blinded_proof.0 != proof,
            "Proof is not blinded successfully"
        );

        let unblinded_proof = acc.unblind_mem_proof(&blinded_proof.0, &blinded_proof.1);
        //println!("{:?}, {:?}", proof, unblinded_proof);
        assert!(
            unblinded_proof == proof,
            "Proof is not unblinded successfully"
        );
    }

    #[test]
    fn test_blind_mem_proof_upd_ver() {
        let mut acc = RsaAccumulator::setup();

        let ep = acc.add(&BigUint::from(200003u32));

        let acct = acc.acc.clone();

        let proof = acc.mem_proof_create(&ep);

        let blinded_proof = acc.blind_mem_proof(&proof);

        let elements_in = vec![
            BigUint::from(65537u32),
            BigUint::from(100003u32),
            BigUint::from(104729u32),
            BigUint::from(1299709u32),
            BigUint::from(15485863u32),
        ];

        let elements_out = vec![];
        for elem in &elements_in {
            acc.add(&elem);
        }

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
        let mut acc = RsaAccumulator::setup();

        for i in 2..5 {
            acc.add(&BigUint::from(i as usize));
        }

        let non_member = BigUint::from(7 as usize);

        let blinded_proof = acc.blind_non_mem_proof(&non_member);

        for i in 10..12 {
            acc.add(&BigUint::from(i as usize));
        }

        let upd_blind_non_mem_proof = acc.blind_non_mem_proof_upd(&blinded_proof.0);

        let unblinded_proof = acc.unblind_non_mem_proof(&blinded_proof.1, &upd_blind_non_mem_proof);
        assert!(
            acc.non_mem_ver(&unblinded_proof, &non_member),
            "Non-membership proof should verify after unblinding"
        );
    }

    #[test]
    fn test_blind_non_mem_proof_upd_ver() {
        let mut acc = RsaAccumulator::setup();

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
            acc.add(&elem);
        }

        let acctprime = acc.acc.clone();

        let upd_blind_proof = acc.blind_non_mem_proof_upd(&blinded_proof.0);

        assert!(
            acc.ver_blind_non_mem_proof_upd(&acctprime, &blinded_proof.0, &upd_blind_proof),
            "Couldnt verify"
        );
    }
}
