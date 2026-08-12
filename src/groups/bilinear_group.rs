use crate::traits::Group;
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::{One, PrimeField};
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::kzg10::KZG10;
use ark_std::rand::Rng;
use sha2::{Digest, Sha256};

#[derive(Clone, Debug)]
pub struct BilinearG1<E: Pairing> {
    pub crs_g1: Vec<E::G1Affine>,
    pub crs_g2: Vec<E::G2Affine>,
}

impl<E: Pairing> BilinearG1<E> {
    pub fn new<R: Rng>(rng: &mut R, max_elements: usize) -> Self {
        let pp = KZG10::<E, DensePolynomial<E::ScalarField>>::setup(max_elements, false, rng)
            .expect("KZG setup failed");
        Self {
            crs_g1: pp.powers_of_g.to_vec(),
            crs_g2: vec![pp.h, pp.beta_h],
        }
    }
}

impl<E: Pairing> Group for BilinearG1<E> {
    type Element = E::G1Affine;
    type Exponent = E::ScalarField;

    fn setup() -> Self {
        let mut rng = rand::thread_rng();
        Self::new(&mut rng, 64)
    }

    fn g(&self) -> Self::Element {
        self.crs_g1[0]
    }

    fn id(&self) -> Self::Element {
        E::G1Affine::zero()
    }

    fn mul(&self, a: &Self::Element, b: &Self::Element) -> Self::Element {
        (a.into_group() + b.into_group()).into_affine()
    }

    fn inv(&self, element: &Self::Element) -> Self::Element {
        (-element.into_group()).into_affine()
    }

    fn exp(&self, base: &Self::Element, exponent: &Self::Exponent) -> Self::Element {
        (base.into_group() * *exponent).into_affine()
    }

    fn exp_id() -> Self::Exponent {
        E::ScalarField::one()
    }

    fn exp_mul(a: &Self::Exponent, b: &Self::Exponent) -> Self::Exponent {
        *a * *b
    }

    fn exp_add(a: &Self::Exponent, b: &Self::Exponent) -> Self::Exponent {
        *a + *b
    }

    fn exp_div_rem(a: &Self::Exponent, b: &Self::Exponent) -> (Self::Exponent, Self::Exponent) {
        use ark_ff::Zero;
        assert!(!b.is_zero(), "division by zero exponent");
        (*a / *b, E::ScalarField::zero())
    }

    fn element_to_bytes(&self, element: &Self::Element) -> Vec<u8> {
        use ark_serialize::CanonicalSerialize;
        let mut buf = Vec::with_capacity(element.compressed_size());
        element
            .serialize_compressed(&mut buf)
            .expect("G1Affine compressed serialization is infallible");
        buf
    }

    fn hash_to_prime(&self, data: &[u8]) -> Self::Exponent {
        let digest = Sha256::digest(data);
        E::ScalarField::from_le_bytes_mod_order(&digest)
    }

    fn random_exponent(&self) -> Self::Exponent {
        use ark_ff::UniformRand;
        E::ScalarField::rand(&mut rand::thread_rng())
    }
}
