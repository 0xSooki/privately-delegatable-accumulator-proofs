use crate::traits::Group;
use glass_pumpkin::{prime, safe_prime};
use num_bigint::{BigInt, BigUint, RandBigInt};
use num_traits::{One, Zero};
use sha2::{Digest, Sha256};

#[cfg(test)]
pub const MODULUS_SIZE: u64 = 128;

#[cfg(not(test))]
pub const MODULUS_SIZE: u64 = 1536;

pub const PRIME_BITS: u32 = 256;

pub const STATISTICAL_SECURITY_BITS: u64 = 256;

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

impl Drop for RsaGroup {
    fn drop(&mut self) {
        if let Some(o) = self.order.as_mut() {
            *o = BigUint::zero();
        }
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

        let h = rng.gen_biguint_range(&BigUint::one(), &n);
        let g = (&h * &h) % &n;

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

    fn exp_div_rem(a: &Self::Exponent, b: &Self::Exponent) -> (Self::Exponent, Self::Exponent) {
        (a / b, a % b)
    }

    fn element_to_bytes(&self, element: &Self::Element) -> Vec<u8> {
        element.to_bytes_be()
    }

    fn hash_to_prime(&self, data: &[u8]) -> Self::Exponent {
        const SMALL_PRIMES: &[u32] = &[
            3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83,
            89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179,
            181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251,
        ];

        let target_bytes = ((PRIME_BITS + 7) / 8) as usize;
        let blocks = (target_bytes + 31) / 32; // SHA-256 block = 32 bytes
        let mut raw = Vec::with_capacity(blocks * 32);
        for ctr in 0u64..blocks as u64 {
            let mut h = Sha256::new();
            h.update(b"PADP-v1/hash-to-prime:");
            h.update(data);
            h.update(b":");
            h.update(ctr.to_le_bytes());
            raw.extend_from_slice(&h.finalize());
        }
        raw.truncate(target_bytes);

        raw[0] |= 0x80;
        *raw.last_mut().unwrap() |= 0x01;

        let mut candidate = BigUint::from_bytes_be(&raw);

        loop {
            if !SMALL_PRIMES
                .iter()
                .any(|&p| (&candidate % p).is_zero() && candidate != BigUint::from(p))
            {
                if prime::check(&candidate) {
                    return candidate;
                }
            }
            candidate += 2u32;
        }
    }

    fn random_exponent(&self) -> Self::Exponent {
        let bits = self.n.bits() + STATISTICAL_SECURITY_BITS;
        rand::thread_rng().gen_biguint(bits)
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
        let h = rng.gen_biguint_range(&BigUint::one(), &n);
        let g = (&h * &h) % &n;

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
