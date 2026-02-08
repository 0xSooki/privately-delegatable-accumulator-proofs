use num_bigint::{BigInt, BigUint, RandBigInt, ToBigUint, ToBigInt};
use num_traits::One;
use num_integer::ExtendedGcd;
use std::collections::HashSet;
use glass_pumpkin::prime;
use num_integer::Integer;
extern crate primes;

const KEY_SIZE: u64 = 512; // This key size is just for demonstration

#[derive(Clone, Debug)]
pub struct RsaAccumulator {
    pub n: BigUint,
    pub g: BigUint,
    pub acc: BigUint,
    pub totient: BigUint,
    pub set: HashSet<BigUint>,
}

impl RsaAccumulator {
    pub fn setup() -> Self {
        let mut rng = rand::thread_rng();

        // to be replaced by safe primes
        let p_uint = prime::new(KEY_SIZE as usize).unwrap();
        let q_uint = prime::new(KEY_SIZE as usize).unwrap();

        let p = BigUint::from(p_uint);
        let q = BigUint::from(q_uint);

        let n = &p * &q;
        let totient = (&p-BigUint::one())*(&q-BigUint::one());

        // use quadratic residue for generator
        let g = rng.gen_biguint_range(&BigUint::one(), &n);

        RsaAccumulator {
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

        if !self.set.contains(&x_prime) {}
        else {
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
            if!s.eq(&x) {
                prod *= s;
            }
        }
        let proof = self.g.modpow(&(&prod % &self.totient), &self.n);
        proof
    }

    pub fn non_mem_proof_create(&self, x: &BigUint) -> (BigUint, BigUint) {
        let p = self.calculate_product(&self.set);
        let s = BigInt::from(p);
        let x_int = BigInt::from(x.clone());
        let ExtendedGcd { gcd, x, y  } = Integer::extended_gcd(&s,&x_int);

        let a = (x + self.n.to_bigint().unwrap()).to_biguint().unwrap() % &self.n;
        let b = (y + self.n.to_bigint().unwrap()).to_biguint().unwrap() % &self.n;
 
        (a, self.g.modpow(&b, &self.n))
    }

    pub fn mem_ver(&self, proof: &BigUint, x: &BigUint) -> bool {
        proof.modpow(&x, &self.n) == self.acc
    }

    pub fn non_mem_ver(&self, proof: &(BigUint, BigUint), x: &BigUint) -> bool {
        (self.acc.modpow(&proof.0, &self.n) * &proof.1) % &self.n == self.g
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_acc_add_del_no_change() {
        let mut acc = RsaAccumulator::setup();
        let initial_acc = acc.acc.clone();
        let element = BigUint::from_bytes_be(b"test_element");

        acc.add(&element);
        acc.del(&element);

        assert_eq!(acc.acc, initial_acc, "Accumulator value should be unchanged after add and remove of the same element");
    }

    fn test_gen_mem_proof() {
        let mut acc = RsaAccumulator::setup();
        let element = BigUint::from(7 as usize);
        let ep = acc.add(&element);
    
        for i in 2..5 {
            acc.add(&BigUint::from(i as usize));
        }

        let proof = acc.mem_proof_create(&ep);

        assert_eq!(acc.mem_ver(&proof, &ep), true);
    }
}
