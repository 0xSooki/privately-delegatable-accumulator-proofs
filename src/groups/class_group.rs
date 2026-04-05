use crate::traits::Group;
use class_group::pari_init;
use class_group::primitives::is_prime;
use curv::arithmetic::traits::*;
use curv::cryptographic_primitives::hashing::HmacExt;
use curv::BigInt;
use hmac::Hmac;
use sha2::Sha512;
use sha256::digest;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::ops::Shl;
use std::sync::OnceLock;

pub use ::class_group::{
    bn_to_gen, pari_qf_comp_to_decimal_string, ABDeltaTriple, BinaryQF, BinaryQFCompressed,
};

pub use ::class_group::primitives;

static CLASS_GROUP_128_SETUP: OnceLock<ClassGroup> = OnceLock::new();

pub const DISC_SIZE: usize = 50;
pub const PARI_STACK_SIZE_BYTES: usize = 100_000_000_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClassGroupElement(pub BinaryQF);

impl Hash for ClassGroupElement {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.to_bytes().hash(state);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClassGroupExponent(pub BigInt);

impl Hash for ClassGroupExponent {
    fn hash<H: Hasher>(&self, state: &mut H) {
        BigInt::to_bytes(&self.0).hash(state);
    }
}

impl fmt::Display for ClassGroupExponent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = BigInt::to_bytes(&self.0);
        if bytes.is_empty() {
            return write!(f, "0");
        }
        for b in bytes {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct ClassGroup {
    pub discriminant: BigInt,
    pub generator: BinaryQF,
}

impl ClassGroup {
    pub fn from_params(discriminant: BigInt, generator_prime: BigInt) -> Self {
        assert!(
            discriminant < BigInt::zero(),
            "discriminant must be negative"
        );
        assert_eq!(
            discriminant.mod_floor(&BigInt::from(4)),
            BigInt::one(),
            "discriminant must satisfy delta = 1 (mod 4)"
        );
        assert!(
            generator_prime > BigInt::one(),
            "generator_prime must be > 1"
        );
        assert!(
            generator_prime.mod_floor(&BigInt::from(2)) == BigInt::one(),
            "generator_prime must be odd"
        );

        let generator = BinaryQF::primeform(&discriminant, &generator_prime).reduce();
        Self {
            discriminant,
            generator,
        }
    }

    pub fn new(discriminant: BigInt, generator_prime: BigInt) -> Self {
        Self::from_params(discriminant, generator_prime)
    }

    pub fn setup_with_params(discriminant: BigInt, generator_prime: BigInt) -> Self {
        Self::from_params(discriminant, generator_prime)
    }

    pub fn setup_security() -> Self {
        CLASS_GROUP_128_SETUP
            .get_or_init(|| {
                unsafe {
                    pari_init(PARI_STACK_SIZE_BYTES, 2);
                }

                let mut disc = -BigInt::sample(DISC_SIZE);
                while disc.mod_floor(&BigInt::from(4)) != BigInt::one() || !is_prime(&(-&disc)) {
                    disc = -BigInt::sample(DISC_SIZE);
                }

                let x = BigInt::sample(DISC_SIZE);
                let (a, b) = Self::h_g(&disc, &x);
                let params = ABDeltaTriple { a, b, delta: disc };
                let generator = BinaryQF::binary_quadratic_form_disc(&params).reduce();

                Self {
                    discriminant: params.delta.clone(),
                    generator,
                }
            })
            .clone()
    }

    pub fn principal(&self) -> BinaryQF {
        BinaryQF::binary_quadratic_form_principal(&self.discriminant)
    }

    pub fn compose(&self, a: &BinaryQF, b: &BinaryQF) -> BinaryQF {
        a.compose(b).reduce()
    }

    pub fn inverse(&self, element: &BinaryQF) -> BinaryQF {
        element.inverse().reduce()
    }

    pub fn exp_qf(&self, base: &BinaryQF, exponent: &BigInt) -> BinaryQF {
        base.exp(exponent).reduce()
    }

    pub fn hash_bytes_to_prime(data: &[u8]) -> BigInt {
        let hash_hex = digest(data);
        let mut candidate = BigInt::from_str_radix(&hash_hex, 16)
            .expect("sha256 digest must be parseable as a hex integer");

        if candidate.modulus(&BigInt::from(2)) == BigInt::zero() {
            candidate += BigInt::one();
        }

        while !primitives::is_prime(&candidate) {
            candidate += BigInt::from(2);
        }

        candidate
    }

    /// https://github.com/ZenGo-X/class/blob/ab50f60fab91cd2f307914663f5d079cf7f70643/src/primitives/vdf.rs#L110
    /// helper function H_G(x)
    /// Claudio algorithm:
    /// 1) i = 0,
    /// 2) r = prng(x,i)
    /// 3) b = 2r + 1 // guarantee division by 4 later
    /// 4) u = (b^2 - delta^2) / 4   // = ac
    /// 5) choose small c at random and check if u/c is integral
    /// 6) if true: take a = u/c
    /// 7) if false : i++; goto 2.
    fn h_g(disc: &BigInt, x: &BigInt) -> (BigInt, BigInt) {
        let mut i = 0;
        let two = BigInt::from(2);
        let max = BigInt::from(20);
        let mut b = &two * Self::prng(x, i, disc.bit_length()) + BigInt::one();
        let mut c = two.clone();
        let mut b2_minus_disc: BigInt = b.pow(2) - disc;
        let four = BigInt::from(4);
        let mut u = b2_minus_disc.div_floor(&four);
        while u.mod_floor(&c) != BigInt::zero() {
            b = &two * Self::prng(x, i, disc.bit_length()) + BigInt::one();
            b2_minus_disc = b.pow(2) - disc;
            u = b2_minus_disc.div_floor(&four);
            i += 1;
            c = (&c.next_prime()).mod_floor(&max);
        }
        let a = u.div_floor(&c);
        (a, b)
    }

    fn prng(seed: &BigInt, i: usize, bitlen: usize) -> BigInt {
        let i_bn = BigInt::from(i as i32);
        let mut res = Hmac::<Sha512>::new_bigint(&i_bn)
            .chain_bigint(seed)
            .result_bigint();
        let mut tmp: BigInt = res.clone();
        let mut res_bit_len = res.bit_length();
        while res_bit_len < bitlen {
            tmp = Hmac::<Sha512>::new_bigint(&i_bn)
                .chain_bigint(&tmp)
                .result_bigint();
            res = &res.shl(res_bit_len) + &tmp;
            res_bit_len = res.bit_length();
        }
        // prune to get |res| = bitlen
        res >> (res_bit_len - bitlen)
    }
}

impl Group for ClassGroup {
    type Element = ClassGroupElement;
    type Exponent = ClassGroupExponent;

    fn setup() -> Self {
        Self::setup_security()
    }

    fn g(&self) -> Self::Element {
        ClassGroupElement(self.generator.clone())
    }

    fn id(&self) -> Self::Element {
        ClassGroupElement(self.principal())
    }

    fn mul(&self, a: &Self::Element, b: &Self::Element) -> Self::Element {
        ClassGroupElement(self.compose(&a.0, &b.0))
    }

    fn inv(&self, element: &Self::Element) -> Self::Element {
        ClassGroupElement(self.inverse(&element.0))
    }

    fn exp(&self, base: &Self::Element, exponent: &Self::Exponent) -> Self::Element {
        ClassGroupElement(self.exp_qf(&base.0, &exponent.0))
    }

    fn exp_id() -> Self::Exponent {
        ClassGroupExponent(BigInt::one())
    }

    fn exp_mul(a: &Self::Exponent, b: &Self::Exponent) -> Self::Exponent {
        ClassGroupExponent(&a.0 * &b.0)
    }

    fn exp_add(a: &Self::Exponent, b: &Self::Exponent) -> Self::Exponent {
        ClassGroupExponent(&a.0 + &b.0)
    }

    fn element_to_bytes(&self, element: &Self::Element) -> Vec<u8> {
        element.0.to_bytes()
    }

    fn hash_to_prime(&self, data: &[u8]) -> Self::Exponent {
        ClassGroupExponent(Self::hash_bytes_to_prime(data))
    }
}
