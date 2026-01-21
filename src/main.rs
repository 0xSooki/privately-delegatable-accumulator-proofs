use num_bigint::{BigInt, RandBigInt, Sign};
use num_integer::Integer;
use num_traits::{One, Zero};
use std::collections::{hash_set, HashSet};
use glass_pumpkin::prime;

const KEY_SIZE: u64 = 512; // This key size is just for demonstration

#[derive(Clone, Debug)]
pub struct RsaAccumulator {
    pub n: BigInt,
    pub g: BigInt,
    pub acc: BigInt,
    pub set: HashSet<BigInt>,
}

impl RsaAccumulator {
    pub fn setup() -> Self {
        let mut rng = rand::thread_rng();

        let p_uint = prime::new(KEY_SIZE as usize).unwrap();
        let q_uint = prime::new(KEY_SIZE as usize).unwrap();

        let p = BigInt::from(p_uint);
        let q = BigInt::from(q_uint);

        let n = &p * &q;

        let g = rng.gen_bigint_range(&BigInt::from(2), &n);

        RsaAccumulator {
            n,
            g: g.clone(),
            acc: g,
            set: HashSet::new(),
        }
    }
}

fn main() {

    let mut acc = RsaAccumulator::setup();
}
