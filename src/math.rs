use num_bigint::{BigInt, BigUint};
use num_traits::{One, Zero};

pub fn pow(base: &BigUint, exp: &BigUint) -> BigUint {
    let mut base = base.clone();
    let mut exp = exp.clone();
    let mut acc = BigUint::one();

    while !exp.is_zero() {
        if (&exp & BigUint::one()) == BigUint::one() {
            acc *= &base;
        }
        exp >>= 1;
        if !exp.is_zero() {
            base = &base * &base;
        }
    }

    acc
}