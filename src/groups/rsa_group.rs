use crate::traits::Group;
use glass_pumpkin::safe_prime;
use num_bigint::{BigInt, BigUint, RandBigInt, Sign};
use num_integer::Integer;
use num_traits::{One, Zero};
use rust_miller_rabin::miller_rabin::miller_rabin;
use sha256::digest;

#[cfg(test)]
pub const MODULUS_SIZE: u64 = 128;

#[cfg(not(test))]
pub const MODULUS_SIZE: u64 = 3072;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TrapdoorMode {
    WithTrapdoor,
    Trapdoorless,
}

#[derive(Clone, Debug)]
pub struct RsaGroup {
    pub n: BigUint,
    pub g: BigUint,
    order: Option<BigUint>,
}

impl RsaGroup {
    pub fn new(n: BigUint, g: BigUint, order: Option<BigUint>) -> Self {
        Self { n, g, order }
    }
}

impl Group for RsaGroup {
    type Element = BigUint;
    type Exponent = BigUint;

    fn setup() -> Self {
        let mut rng = rand::thread_rng();

        let p_uint = safe_prime::new(MODULUS_SIZE as usize).unwrap();
        let q_uint = safe_prime::new(MODULUS_SIZE as usize).unwrap();

        let p = BigUint::from(p_uint);
        let q = BigUint::from(q_uint);

        let n = &p * &q;
        let order = (&p - BigUint::one()) * (&q - BigUint::one());

        // use quadratic residue for generator
        let g = rng.gen_biguint_range(&BigUint::one(), &n);

        RsaGroup {
            n,
            g,
            order: Some(order),
        }
    }

    fn g(&self) -> Self::Element {
        self.g.clone()
    }

    fn id(&self) -> Self::Element {
        BigUint::one()
    }

    fn mul(&self, a: &Self::Element, b: &Self::Element) -> Self::Element {
        (a * b) % &self.n
    }

    fn inv(&self, element: &Self::Element) -> Self::Element {
        element.modinv(&self.n).unwrap()
    }

    fn exp(&self, base: &Self::Element, exponent: &Self::Exponent) -> Self::Element {
        base.modpow(exponent, &self.n)
    }

    fn exp_id() -> Self::Exponent {
        BigUint::one()
    }

    fn exp_mul(a: &Self::Exponent, b: &Self::Exponent) -> Self::Exponent {
        a * b
    }

    fn exp_add(a: &Self::Exponent, b: &Self::Exponent) -> Self::Exponent {
        a + b
    }

    fn element_to_bytes(&self, element: &Self::Element) -> Vec<u8> {
        element.to_bytes_be()
    }

    fn hash_to_prime(&self, data: &[u8]) -> Self::Exponent {
        let hash_hex = digest(data);
        let mut candidate = BigUint::parse_bytes(hash_hex.as_bytes(), 16).unwrap();

        if candidate.is_even() {
            candidate += 1u32;
        }

        loop {
            let candidate_signed = BigInt::from_biguint(Sign::Plus, candidate.clone());
            if miller_rabin(&candidate_signed) {
                return candidate;
            }
            candidate += 2u32;
        }
    }
}

impl RsaGroup {
    pub fn setup_trapdoorless() -> Self {
        let mut rng = rand::thread_rng();

        let p_uint = safe_prime::new(MODULUS_SIZE as usize).unwrap();
        let q_uint = safe_prime::new(MODULUS_SIZE as usize).unwrap();

        let p = BigUint::from(p_uint);
        let q = BigUint::from(q_uint);

        let n = &p * &q;
        let g = rng.gen_biguint_range(&BigUint::one(), &n);

        RsaGroup { n, g, order: None }
    }

    pub fn from_modulus(n: BigUint, g: BigUint) -> Self {
        RsaGroup { n, g, order: None }
    }

    pub fn mode(&self) -> TrapdoorMode {
        if self.order.is_some() {
            TrapdoorMode::WithTrapdoor
        } else {
            TrapdoorMode::Trapdoorless
        }
    }

    pub fn has_trapdoor(&self) -> bool {
        self.order.is_some()
    }

    pub fn order(&self) -> Option<&BigUint> {
        self.order.as_ref()
    }

    pub fn set_order(&mut self, order: Option<BigUint>) {
        self.order = order;
    }

    pub fn modulus(&self) -> &BigUint {
        &self.n
    }

    pub fn signed_exp(&self, base: &BigUint, exponent: &BigInt) -> BigUint {
        if *exponent >= BigInt::zero() {
            base.modpow(&exponent.to_biguint().unwrap(), &self.n)
        } else {
            let base_inv = self.inv(base);
            let abs_exp = (-exponent).to_biguint().unwrap();
            base_inv.modpow(&abs_exp, &self.n)
        }
    }
}
