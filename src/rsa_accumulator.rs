use glass_pumpkin::safe_prime;
use num_bigint::{BigInt, BigUint, RandBigInt, ToBigInt, ToBigUint};
use num_integer::ExtendedGcd;
use num_integer::Integer;
use num_traits::One;
use primes::hash_to_prime;
use rand::random;
use rand::thread_rng;
use std::collections::HashSet;
use crate::rsa_group;
use crate::traits::Group;
use crate::rsa_group::RsaGroup;


extern crate primes;

const KEY_SIZE: u64 = 128; // This key size is just for demonstration

#[derive(Clone, Debug)]
pub struct RsaAccumulator {
    pub group: RsaGroup,
    pub n: BigUint,
    pub g: BigUint,
    pub acc: BigUint,
    pub totient: BigUint,
    pub set: HashSet<BigUint>,
}

impl RsaAccumulator {
    pub fn setup() -> Self {
        let mut rng = rand::thread_rng();

        let p_uint = safe_prime::new(KEY_SIZE as usize).unwrap();
        let q_uint = safe_prime::new(KEY_SIZE as usize).unwrap();
        println!("setup: {:?}, {:?}", p_uint, q_uint);
        let p = BigUint::from(p_uint);
        let q = BigUint::from(q_uint);

        let n = &p * &q;
        let totient = (&p - BigUint::one()) * (&q - BigUint::one());
        
        // use quadratic residue for generator
        let g = rng.gen_biguint_range(&BigUint::one(), &n);
        let group = RsaGroup::new(n.clone(), g.clone(), Some(totient.clone()));


        RsaAccumulator {
            group: group,
            n,
            g: g.clone(),
            acc: g,
            totient: totient,
            set: HashSet::new(),
        }
    }

    pub fn add(&mut self, mut x: &BigUint) -> BigUint {
        let x_str = x.to_string();
        let vec = vec![x_str.as_str()];
        let prime_u128 = primes::hash_to_prime(vec);
        let x_prime = BigUint::from(prime_u128);
        //TODO find a crate that converts hash to prime determinstically

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
        let vec = vec![x_str.as_str()];
        let prime_u128 = primes::hash_to_prime(vec);
        let x_prime = BigUint::from(prime_u128);

        if !self.set.contains(&x_prime) {
        } else {
            self.set.remove(&x_prime);

            let product = self.calculate_product(&self.set);
            self.acc = self.g.modpow(&product, &self.n);
        }
    }

    fn calculate_product(&self, set: &HashSet<BigUint>) -> BigUint {
        if set.is_empty() {
            return BigUint::one();
        }
        let mut product = BigUint::one();
        for s in set {
            product *= s;
        }
        product
    }

    pub fn mem_proof_create(&mut self, x: &BigUint) -> BigUint {
        let mut prod = BigUint::one();
        for s in &self.set {
            if !s.eq(&x) {
                prod *= s;
            }
        }
        let proof = self.g.modpow(&(&prod % &self.totient), &self.n);
        proof
    }

    pub fn non_mem_proof_create(&self, x: &BigUint) -> (BigUint, BigUint, BigUint) {
        let p = self.calculate_product(&self.set);
        let s = BigInt::from(p);

        let x_str = x.to_string();
        let vec = vec![x_str.as_str()];
        let prime_u128 = primes::hash_to_prime(vec);
        let x_prime = BigUint::from(prime_u128);
        let x_int = BigInt::from(x_prime.clone());

        let ExtendedGcd { gcd, x, y } = Integer::extended_gcd(&s, &x_int);

        let totient_int = self.totient.to_bigint().unwrap();
        let a = ((x % &totient_int + &totient_int) % &totient_int)
            .to_biguint()
            .unwrap();
        let b = (((&y) % &totient_int + &totient_int) % &totient_int)
            .to_biguint()
            .unwrap();
        (x_prime, a, self.g.modpow(&b, &self.n))
    }

    pub fn mem_ver(&self, proof: &BigUint, x: &BigUint) -> bool {
        proof.modpow(&x, &self.n) == self.acc
    }

    pub fn non_mem_ver(&self, proof: &(BigUint, BigUint, BigUint), x: &BigUint) -> bool {
        (self.acc.modpow(&proof.1, &self.n) * &proof.2.modpow(&proof.0, &self.n)) % &self.n
            == self.g
    }

    pub fn blind_proof(&self, proof: &BigUint) -> (BigUint, BigUint) {
        let mut rng = thread_rng();
        let mut st = rng.gen_biguint(128) % &self.totient;
        let blinded_proof = (proof * self.g.modpow(&st, &self.n)) % &self.n;
        (blinded_proof, st)
    }

    pub fn blind_proof_upd(&self, blinded_proof: &BigUint) -> BigUint {
        let mut rng = thread_rng();
        let r = rng.gen_biguint(128) % &self.totient;
        let delta = self.calculate_product(&self.set);
        let pi_delta = blinded_proof.modpow(&delta, &self.n);
        let bproof_bytes = blinded_proof.to_bytes_be();
        let pi_delta_bytes = pi_delta.to_bytes_be();
        let acc_bytes = self.acc.to_bytes_be();
        let accd_bytes = self.acc.modpow(&delta, &self.n).to_bytes_be();
        let mut bytes_data = Vec::with_capacity(bproof_bytes.len() + pi_delta_bytes.len() + acc_bytes.len() + accd_bytes.len());
        bytes_data.extend_from_slice(&bproof_bytes);
        bytes_data.extend_from_slice(&pi_delta_bytes);
        bytes_data.extend_from_slice(&acc_bytes);
        bytes_data.extend_from_slice(&accd_bytes);

        let e: <RsaGroup as Group>::Exponent = self.group.hash_to_prime(&bytes_data);
        let z = r + e*delta;
        z
    }

    pub fn ver_blind_proof_upd(&self, blinded_proof: &BigUint) -> BigUint {
        unimplemented!("Verify blind proof update using Chaum-Pedersen proofs")
    }

    pub fn unblind_proof(&self, blinded_proof: &BigUint, st: &BigUint) -> BigUint {
        let st_inv = self.g.modpow(&st, &self.n).modinv(&self.n).unwrap();
        let proof = blinded_proof * st_inv % &self.n;
        proof
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigUint;
    use num_traits::FromPrimitive;

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
    fn test_blind_unblind() {
        let mut acc = RsaAccumulator::setup();
      
        let element = BigUint::from(7 as usize);
        let ep = acc.add(&element);

        for i in 2..5 {
            acc.add(&BigUint::from(i as usize));
        }

        let proof = acc.mem_proof_create(&ep);

        let blinded_proof = acc.blind_proof(&proof);

        assert!(blinded_proof.0 != proof, "Proof is not blinded successfully");

        let unblinded_proof = acc.unblind_proof(&blinded_proof.0, &blinded_proof.1);
        println!("{:?}, {:?}", proof, unblinded_proof);
        assert!(unblinded_proof == proof, "Proof is not unblinded successfully");
    }
}
