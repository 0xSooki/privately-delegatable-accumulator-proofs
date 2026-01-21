use num_bigint::{BigInt, BigUint, RandBigInt, ToBigInt, ToBigUint};
use num_traits::{One, Zero};
use num_integer::{Integer, ExtendedGcd};
use std::collections::{hash_set, HashSet};
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
        if(self.set.contains(&x)) {
        } else {
            self.set.insert(x.clone());
            self.acc = self.acc.modpow(&x, &self.n);
        }
    }

    pub fn del(&mut self, x: BigUint) {
        if(!self.set.contains(&x)){}
        else {
            self.set.remove(&x);

            let xinv = x.modinv(&self.n).unwrap();
            
            self.acc = self.acc.modpow(&xinv.to_biguint().unwrap(), &self.n);
        }
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
    fn test_acc_add() {

    }
}