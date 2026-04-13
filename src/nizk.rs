use crate::traits::Group;
#[cfg(feature = "bilinear")]
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
#[cfg(feature = "bilinear")]
use ark_ff::{BigInteger, One, PrimeField, Zero};
#[cfg(feature = "bilinear")]
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial};
#[cfg(feature = "bilinear")]
use ark_poly_commit::kzg10::{Powers, KZG10};
use rand::thread_rng;
use rand::RngCore;
#[cfg(feature = "bilinear")]
use sha2::{Digest, Sha256};

type Proof<G> = (
    <G as Group>::Element,
    <G as Group>::Element,
    <G as Group>::Exponent,
);

#[derive(Debug, Clone)]
pub struct NIZK<'a, G: Group> {
    group: &'a G,
}

impl<'a, G: Group> NIZK<'a, G> {
    pub fn setup(group: &'a G) -> NIZK<'a, G> {
        NIZK { group }
    }

    fn challenge(
        &self,
        g: &G::Element,
        u: &G::Element,
        h: &G::Element,
        v: &G::Element,
        a: &G::Element,
        b: &G::Element,
    ) -> G::Exponent {
        let g_bytes = self.group.element_to_bytes(g);
        let h_bytes = self.group.element_to_bytes(h);
        let u_bytes = self.group.element_to_bytes(u);
        let v_bytes = self.group.element_to_bytes(v);
        let a_bytes = self.group.element_to_bytes(a);
        let b_bytes = self.group.element_to_bytes(b);

        let parts = [&g_bytes, &h_bytes, &u_bytes, &v_bytes, &a_bytes, &b_bytes];

        let mut bytes_data = Vec::with_capacity(parts.iter().map(|p| p.len()).sum());
        for p in parts {
            bytes_data.extend_from_slice(p);
        }

        self.group.hash_to_prime(&bytes_data)
    }

    pub fn prove_dleq(
        &self,
        g: &G::Element,
        u: &G::Element,
        h: &G::Element,
        v: &G::Element,
        w: &G::Exponent,
    ) -> Proof<G> {
        let mut rng = thread_rng();
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);

        let r = self.group.hash_to_prime(&seed);
        let a = self.group.exp(g, &r);
        let b = self.group.exp(h, &r);

        let e = self.challenge(g, u, h, v, &a, &b);
        let z = G::exp_add(&r, &G::exp_mul(&e, w));
        (a, b, z)
    }

    pub fn verify_dleq(
        &self,
        g: &G::Element,
        u: &G::Element,
        h: &G::Element,
        v: &G::Element,
        proof: &Proof<G>,
    ) -> bool {
        let a = &proof.0;
        let b = &proof.1;
        let z = &proof.2;

        let e = self.challenge(g, u, h, v, a, b);
        let lhs_1 = self.group.exp(g, z);
        let lhs_2 = self.group.exp(h, z);

        let rhs_1 = self.group.mul(a, &self.group.exp(u, &e));
        let rhs_2 = self.group.mul(b, &self.group.exp(v, &e));

        lhs_1 == rhs_1 && lhs_2 == rhs_2
    }
}

#[cfg(feature = "bilinear")]
#[derive(Clone, Debug, PartialEq)]
pub struct PoeStarProof<E: Pairing> {
    pub q: E::G1Affine,
}

#[cfg(feature = "bilinear")]
#[derive(Clone, Debug, PartialEq)]
pub struct PoeEqAndProof<E: Pairing> {
    pub left: PoeStarProof<E>,
    pub right: PoeStarProof<E>,
    pub beta: E::ScalarField,
}

#[cfg(feature = "bilinear")]
pub struct BilinearNIZK;

#[cfg(feature = "bilinear")]
impl BilinearNIZK {
    fn fs<E: Pairing>(
        g: &E::G1Affine,
        u: &E::G1Affine,
        h: &E::G1Affine,
        v: &E::G1Affine,
        poly: &DensePolynomial<E::ScalarField>,
    ) -> E::ScalarField
    where
        E::ScalarField: PrimeField,
    {
        let mut hasher = Sha256::new();
        hasher.update(b"poe_eq_and_sigma_g1");
        hasher.update(format!("{:?}", g).as_bytes());
        hasher.update(format!("{:?}", u).as_bytes());
        hasher.update(format!("{:?}", h).as_bytes());
        hasher.update(format!("{:?}", v).as_bytes());

        for coeff in poly.coeffs() {
            let coeff_bytes = coeff.into_bigint().to_bytes_le();
            hasher.update((coeff_bytes.len() as u64).to_le_bytes());
            hasher.update(&coeff_bytes);
        }

        let digest = hasher.finalize();
        let mut alpha = E::ScalarField::from_le_bytes_mod_order(&digest);
        if alpha.is_zero() {
            alpha = E::ScalarField::one();
        }
        alpha
    }

    fn syn_div_by_x_minus_c<E: Pairing>(
        poly: &DensePolynomial<E::ScalarField>,
        c: &E::ScalarField,
    ) -> (DensePolynomial<E::ScalarField>, E::ScalarField) {
        let coeffs = poly.coeffs();
        if coeffs.len() <= 1 {
            let r = coeffs.first().copied().unwrap_or_else(E::ScalarField::zero);
            return (DensePolynomial::zero(), r);
        }

        let n = coeffs.len();
        let mut q = vec![E::ScalarField::zero(); n - 1];
        q[n - 2] = coeffs[n - 1];
        for i in (0..n - 2).rev() {
            q[i] = coeffs[i + 1] + *c * q[i + 1];
        }

        let r = coeffs[0] + *c * q[0];
        (DensePolynomial::from_coefficients_vec(q), r)
    }

    fn syn_div_by_x_plus_alpha<E: Pairing>(
        poly: &DensePolynomial<E::ScalarField>,
        alpha: &E::ScalarField,
    ) -> (DensePolynomial<E::ScalarField>, E::ScalarField) {
        let c = -*alpha;
        Self::syn_div_by_x_minus_c::<E>(poly, &c)
    }

    pub fn com<E: Pairing>(
        powers: &Powers<E>,
        poly: &DensePolynomial<E::ScalarField>,
    ) -> Option<E::G1Affine> {
        let (commitment, _) =
            KZG10::<E, DensePolynomial<E::ScalarField>>::commit(powers, poly, None, None).ok()?;
        Some(commitment.0)
    }

    pub fn prove_poe_eq<E: Pairing>(
        powers_for_g: &Powers<E>,
        powers_for_h: &Powers<E>,
        powers_for_g1: &Powers<E>,
        g: &E::G1Affine,
        u: &E::G1Affine,
        h: &E::G1Affine,
        v: &E::G1Affine,
        poly: &DensePolynomial<E::ScalarField>,
    ) -> Option<(
        E::G1Affine,
        E::G1Affine,
        E::G1Affine,
        E::ScalarField,
        E::G1Affine,
    )>
    where
        E::ScalarField: PrimeField,
    {
        if powers_for_g.powers_of_g.first() != Some(g)
            || powers_for_h.powers_of_g.first() != Some(h)
        {
            return None;
        }

        let alpha = Self::fs::<E>(g, u, h, v, poly);
        let (h_poly, beta) = Self::syn_div_by_x_plus_alpha::<E>(poly, &alpha);

        let qg = Self::com::<E>(powers_for_g, &h_poly)?;
        let qh = Self::com::<E>(powers_for_h, &h_poly)?;
        let gwidehat = Self::com::<E>(powers_for_g1, &h_poly)?;
        let gwidetilde = Self::com::<E>(powers_for_g1, poly)?;

        Some((qg, qh, gwidehat, beta, gwidetilde))
    }

    pub fn verify_poe_eq<E: Pairing>(
        g1: &E::G1Affine,
        g: &E::G1Affine,
        u: &E::G1Affine,
        h: &E::G1Affine,
        v: &E::G1Affine,
        g2: &E::G2Affine,
        g2_s: &E::G2Affine,
        poly: &DensePolynomial<E::ScalarField>,
        proof: &(
            E::G1Affine,
            E::G1Affine,
            E::G1Affine,
            E::ScalarField,
            E::G1Affine,
        ),
    ) -> bool
    where
        E::ScalarField: PrimeField,
    {
        let alpha = Self::fs::<E>(g, u, h, v, poly);
        let beta = proof.3;

        let g2_s_plus_alpha = (g2_s.into_group() + g2.into_group() * alpha).into_affine();

        let pairing1 = E::multi_pairing(
            [proof.0, (g.into_group() * beta).into_affine()],
            [g2_s_plus_alpha, *g2],
        );

        let pairing2 = E::multi_pairing(
            [proof.1, (h.into_group() * beta).into_affine()],
            [g2_s_plus_alpha, *g2],
        );

        let pairing5 = E::multi_pairing(
            [proof.2, (g1.into_group() * beta).into_affine()],
            [g2_s_plus_alpha, *g2],
        );

        let pairing_u = E::pairing(*u, *g2);
        let pairing_v = E::pairing(*v, *g2);
        let pairing_gwidetilde = E::pairing(proof.4, *g2);

        pairing1 == pairing_u && pairing2 == pairing_v && pairing5 == pairing_gwidetilde
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::groups::rsa_group::RsaGroup;
    use crate::traits::Group;
    use num_bigint::BigUint;

    #[test]
    pub fn test_dleq() {
        let pp = BigUint::from(12345u32);
        let group = RsaGroup::new(pp.clone(), pp.clone(), Some(pp));

        let nizk = NIZK::setup(&group);
        let g = BigUint::from(2u32);
        let h = BigUint::from(3u32);

        let w = BigUint::from(42u32);
        let u = group.exp(&g, &w);
        let v = group.exp(&h, &w);

        let proof = nizk.prove_dleq(&g, &u, &h, &v, &w);

        assert!(nizk.verify_dleq(&g, &u, &h, &v, &proof));
    }

    #[test]
    pub fn test_dleq_wrong() {
        let pp = BigUint::from(12345u32);
        let group = RsaGroup::new(pp.clone(), pp.clone(), Some(pp));
        let nizk = NIZK::setup(&group);

        let g = BigUint::from(2u32);
        let h = BigUint::from(3u32);

        let w = BigUint::from(42u32);
        let u = group.exp(&g, &w);
        let v = group.exp(&h, &w);

        let proof = nizk.prove_dleq(&g, &u, &h, &v, &w);

        let invalid_proof = (proof.0, proof.1, BigUint::from(0u32));

        assert!(!nizk.verify_dleq(&g, &u, &h, &v, &invalid_proof));
    }

    #[cfg(feature = "class-group")]
    #[test]
    pub fn test_dleq_class_group() {
        use crate::groups::class_group::{ClassGroup, ClassGroupExponent};
        let group = ClassGroup::setup();
        let nizk = NIZK::setup(&group);

        let g = group.g();
        let h = group.g();

        let w = ClassGroupExponent(curv::BigInt::from(42));
        let u = group.exp(&g, &w);
        let v = group.exp(&h, &w);

        let proof = nizk.prove_dleq(&g, &u, &h, &v, &w);

        assert!(nizk.verify_dleq(&g, &u, &h, &v, &proof));
    }
}

#[cfg(all(test, feature = "bilinear"))]
mod bilinear_poe_tests {
    use super::*;
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
    use ark_poly_commit::kzg10::Powers;
    use std::borrow::Cow;

    fn build_powers(
        degree: usize,
    ) -> (
        Powers<'static, Bls12_381>,
        <Bls12_381 as Pairing>::G2Affine,
        <Bls12_381 as Pairing>::G2Affine,
    ) {
        let mut rng = ark_std::test_rng();
        let pp = KZG10::<Bls12_381, DensePolynomial<Fr>>::setup(degree + 1, false, &mut rng)
            .expect("KZG setup failed");

        let powers_of_g: Vec<<Bls12_381 as Pairing>::G1Affine> =
            pp.powers_of_g.iter().take(degree + 1).copied().collect();

        let powers = Powers {
            powers_of_g: Cow::Owned(powers_of_g),
            powers_of_gamma_g: Cow::Owned(vec![]),
        };

        (powers, pp.h, pp.beta_h)
    }

    fn scale_powers_for_base(
        base_powers: &Powers<'static, Bls12_381>,
        base_scalar: Fr,
    ) -> Powers<'static, Bls12_381> {
        let scaled_powers_of_g: Vec<<Bls12_381 as Pairing>::G1Affine> = base_powers
            .powers_of_g
            .iter()
            .map(|g_pow| (g_pow.into_group() * base_scalar).into_affine())
            .collect();

        Powers {
            powers_of_g: Cow::Owned(scaled_powers_of_g),
            powers_of_gamma_g: Cow::Owned(vec![]),
        }
    }

    #[test]
    fn poe_eq_and_sigma_verifies_valid_proof() {
        let degree = 8;

        let (powers_g1, g2, g2_s) = build_powers(degree);
        let powers_g = scale_powers_for_base(&powers_g1, Fr::from(7u64));
        let powers_h = scale_powers_for_base(&powers_g1, Fr::from(13u64));

        let g = powers_g
            .powers_of_g
            .first()
            .copied()
            .expect("CRS must include base element");
        let h = powers_h
            .powers_of_g
            .first()
            .copied()
            .expect("CRS must include base element");

        let poly = DensePolynomial::from_coefficients_vec(vec![
            Fr::from(5u64),
            Fr::from(3u64),
            Fr::from(11u64),
        ]);

        let u = BilinearNIZK::com::<Bls12_381>(&powers_g, &poly)
            .expect("CRS length must cover polynomial degree");
        let v = BilinearNIZK::com::<Bls12_381>(&powers_h, &poly)
            .expect("CRS length must cover polynomial degree");

        let proof = BilinearNIZK::prove_poe_eq::<Bls12_381>(
            &powers_g, &powers_h, &powers_g1, &g, &u, &h, &v, &poly,
        )
        .expect("CRS vectors must be consistent and long enough");

        assert!(BilinearNIZK::verify_poe_eq::<Bls12_381>(
            &powers_g1.powers_of_g[0],
            &g,
            &u,
            &h,
            &v,
            &g2,
            &g2_s,
            &poly,
            &proof,
        ));
    }

    #[test]
    fn poe_eq_and_sigma_rejects_tampered_component() {
        let degree = 8;

        let (powers_g1, g2, g2_s) = build_powers(degree);
        let powers_g = scale_powers_for_base(&powers_g1, Fr::from(7u64));
        let powers_h = scale_powers_for_base(&powers_g1, Fr::from(13u64));

        let g = powers_g
            .powers_of_g
            .first()
            .copied()
            .expect("CRS must include base element");
        let h = powers_h
            .powers_of_g
            .first()
            .copied()
            .expect("CRS must include base element");

        let poly = DensePolynomial::from_coefficients_vec(vec![
            Fr::from(5u64),
            Fr::from(3u64),
            Fr::from(11u64),
        ]);

        let u = BilinearNIZK::com::<Bls12_381>(&powers_g, &poly)
            .expect("CRS length must cover polynomial degree");
        let v = BilinearNIZK::com::<Bls12_381>(&powers_h, &poly)
            .expect("CRS length must cover polynomial degree");

        let proof = BilinearNIZK::prove_poe_eq::<Bls12_381>(
            &powers_g, &powers_h, &powers_g1, &g, &u, &h, &v, &poly,
        )
        .expect("CRS vectors must be consistent and long enough");

        let bad_q_v = (proof.1.into_group() + g.into_group()).into_affine();
        let bad_proof = (proof.0, bad_q_v, proof.2, proof.3, proof.4);

        assert!(!BilinearNIZK::verify_poe_eq::<Bls12_381>(
            &powers_g1.powers_of_g[0],
            &g,
            &u,
            &h,
            &v,
            &g2,
            &g2_s,
            &poly,
            &bad_proof,
        ));
    }

    #[test]
    fn poe_eq_and_sigma_rejects_wrong_statement() {
        let degree = 8;

        let (powers_g1, g2, g2_s) = build_powers(degree);
        let powers_g = scale_powers_for_base(&powers_g1, Fr::from(7u64));
        let powers_h = scale_powers_for_base(&powers_g1, Fr::from(13u64));

        let g = powers_g
            .powers_of_g
            .first()
            .copied()
            .expect("CRS must include base element");
        let h = powers_h
            .powers_of_g
            .first()
            .copied()
            .expect("CRS must include base element");

        let poly = DensePolynomial::from_coefficients_vec(vec![
            Fr::from(5u64),
            Fr::from(3u64),
            Fr::from(11u64),
        ]);
        let wrong_poly = DensePolynomial::from_coefficients_vec(vec![
            Fr::from(5u64),
            Fr::from(9u64),
            Fr::from(11u64),
        ]);

        let u = BilinearNIZK::com::<Bls12_381>(&powers_g, &poly)
            .expect("CRS length must cover polynomial degree");
        let v = BilinearNIZK::com::<Bls12_381>(&powers_h, &poly)
            .expect("CRS length must cover polynomial degree");

        let proof = BilinearNIZK::prove_poe_eq::<Bls12_381>(
            &powers_g, &powers_h, &powers_g1, &g, &u, &h, &v, &poly,
        )
        .expect("CRS vectors must be consistent and long enough");

        assert!(!BilinearNIZK::verify_poe_eq::<Bls12_381>(
            &powers_g1.powers_of_g[0],
            &g,
            &u,
            &h,
            &v,
            &g2,
            &g2_s,
            &wrong_poly,
            &proof,
        ));
    }
}
