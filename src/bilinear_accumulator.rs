use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::{One, Zero};
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial};
use ark_poly_commit::kzg10::{Powers, KZG10};
use ark_std::rand::Rng;
use num_bigint::BigUint;
use rand::thread_rng;
use std::borrow::Cow;
use std::collections::HashSet;
use std::usize::MAX;

#[derive(Clone, Debug)]
pub struct MembershipProof<E: Pairing> {
    pub pi: E::G1Affine,
}

#[derive(Clone, Debug)]
pub struct NonMembershipProof<E: Pairing> {
    pub y: E::ScalarField,
    pub b: E::G1Affine,
}

#[derive(Clone, Debug)]
pub struct BilinearAccumulator<E: Pairing> {
    crs_g1: Vec<E::G1Affine>,
    crs_g2: Vec<E::G2Affine>,
    acc: E::G1Affine,
    poly: DensePolynomial<E::ScalarField>,
    elements: HashSet<E::ScalarField>,
}

impl<E: Pairing> BilinearAccumulator<E> {
    pub fn setup<R: Rng>(rng: &mut R, max_elements: usize) -> BilinearAccumulator<E> {
        let pp = KZG10::<E, DensePolynomial<E::ScalarField>>::setup(MAX, false, rng)
            .expect("KZG setup failed");

        let crs_g1: Vec<E::G1Affine> = pp.powers_of_g.to_vec();
        let g2 = pp.h;
        let g2_tau = pp.beta_h;
        let crs_g2 = vec![g2, g2_tau];

        let poly = DensePolynomial::from_coefficients_vec(vec![E::ScalarField::one()]);
        let acc = crs_g1[0];

        BilinearAccumulator {
            crs_g1,
            crs_g2,
            acc,
            poly,
            elements: HashSet::new(),
        }
    }

    pub fn add(&mut self, s: &E::ScalarField) -> bool {
        let factor =
            DensePolynomial::from_coefficients_vec(vec![-s.to_owned(), E::ScalarField::one()]);
        self.poly = &self.poly * &factor;
        self.acc = self.kzg_com(&self.poly);
        true
    }

    pub fn del(&mut self, s: &E::ScalarField) -> bool {
        let (q, _) = Self::syn_div(&self.poly, s);
        self.poly = q;

        self.acc = self.kzg_com(&self.poly);
        true
    }

    pub fn mem_proof_create(&self, s: &E::ScalarField) -> MembershipProof<E> {
        todo!()
    }

    pub fn mem_ver() {
        todo!()
    }

    pub fn non_mem_proof_create() {
        todo!()
    }

    pub fn non_mem_ver() {
        todo!()
    }

    fn kzg_com(&self, poly: &DensePolynomial<E::ScalarField>) -> E::G1Affine {
        let powers = Powers::<E> {
            powers_of_g: Cow::Borrowed(&self.crs_g1),
            powers_of_gamma_g: Cow::Borrowed(Default::default()),
        };

        let (com, _) = KZG10::commit(&powers, poly, None, None).expect("Commitment fialed");
        com.0
    }

    fn syn_div(
        poly: &DensePolynomial<E::ScalarField>,
        c: &E::ScalarField,
    ) -> (DensePolynomial<E::ScalarField>, E::ScalarField) {
        let coeffs = poly.coeffs();
        if coeffs.len() <= 1 {
            let r = coeffs.first().copied().unwrap_or_else(E::ScalarField::zero);
            return (DensePolynomial::zero(), r);
        }
        let n = coeffs.len();
        // work high-to-low
        let mut q = vec![E::ScalarField::zero(); n - 1];
        q[n - 2] = coeffs[n - 1];
        for i in (0..n - 2).rev() {
            q[i] = coeffs[i + 1] + *c * q[i + 1];
        }
        let r = coeffs[0] + *c * q[0];
        (DensePolynomial::from_coefficients_vec(q), r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Bls12_381;
    use num_bigint::BigUint;

    #[test]
    pub fn test_syn_div() {
        let poly = DensePolynomial::<ark_bls12_381::Fr>::from_coefficients_vec(vec![
            -ark_bls12_381::Fr::from(42u64),
            ark_bls12_381::Fr::from(0u64),
            -ark_bls12_381::Fr::from(12u64),
            ark_bls12_381::Fr::from(1u64),
        ]);
        let d = ark_bls12_381::Fr::from(3u64);
        let (q, r) = BilinearAccumulator::<Bls12_381>::syn_div(&poly, &d);
        let res = DensePolynomial::<ark_bls12_381::Fr>::from_coefficients_vec(vec![
            -ark_bls12_381::Fr::from(27u64),
            -ark_bls12_381::Fr::from(9u64),
            ark_bls12_381::Fr::from(1u64),
        ]);
        assert_eq!(q, res);
        assert_eq!(r, -ark_bls12_381::Fr::from(123u64));
    }
}
