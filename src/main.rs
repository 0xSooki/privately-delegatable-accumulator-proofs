use num_bigint::{BigInt, RandBigInt, Sign};
use num_integer::Integer;
use num_traits::{One, Zero};
use std::collections::{hash_set, HashSet};

const KEY_SIZE: u64 = 512; // This key size is just for demonstration

#[derive(Clone, Debug)]
pub struct RsaAccumulator {
    pub n: BigInt,
    pub g: BigInt,
    pub acc: BigInt,
    pub set: HashSet<BigInt>,
}


fn main() {
    println!("Hello, world!");
}
