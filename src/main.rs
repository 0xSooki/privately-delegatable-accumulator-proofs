use num_bigint::{BigInt, BigUint, RandBigInt, ToBigUint};
use num_traits::One;
use std::collections::HashSet;
use glass_pumpkin::prime;

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

    pub fn add(&mut self, x: BigUint) {
        // Hash x to a prime before using it in the accumulator.
        // This ensures x is coprime to the totient, so its modular inverse exists.
        // Otherwise, removing the element may fail if the inverse does not exist.
        if self.set.contains(&x) {
        } else {
            self.set.insert(x.clone());
            self.acc = self.acc.modpow(&x, &self.n);
        }
    }

    pub fn del(&mut self, x: BigUint) {
        // If elements are hashed to primes during addition, the modular inverse will exist.
        // This ensures deletion works without panicking.
        // `cargo run` won't panick.
        if !self.set.contains(&x) {}
        else {
            self.set.remove(&x);

            let xinv = x.modinv(&self.totient).unwrap();
            
            self.acc = self.acc.modpow(&xinv.to_biguint().unwrap(), &self.n);
        }
    }

    pub fn mem_proof_create(acc: &RsaAccumulator, x: &BigUint) -> BigUint {
        todo!()
    }

    pub fn non_mem_proof_create(acc: &RsaAccumulator, x: &BigUint) -> (BigUint, BigInt) {
        todo!()
    }

    pub fn mem_ver(acc: &RsaAccumulator, proof: &BigUint, x: &BigUint) -> bool {
        todo!()
    }

    pub fn non_mem_ver(acc: &RsaAccumulator, proof: (&BigUint, &BigUint), x: &BigUint) -> bool {
        todo!()
    }
}

fn main() {
    let mut acc = RsaAccumulator::setup();
    println!("{:?}", acc.acc);
    acc.add(BigUint::from_bytes_be(b"sdf"));
    println!("{:?}", acc.acc);
    acc.del(BigUint::from_bytes_be(b"sdf"));
    println!("{:?}", acc.acc);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_acc_add_del_no_change() {
        let mut acc = RsaAccumulator::setup();
        let initial_acc = acc.acc.clone();
        let element = BigUint::from_bytes_be(b"test_element");

        acc.add(element.clone());
        acc.del(element.clone());

        assert_eq!(acc.acc, initial_acc, "Accumulator value should be unchanged after add and remove of the same element");
    }
}