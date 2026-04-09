use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::{Field, One, PrimeField, UniformRand, Zero};
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial};
use ark_poly_commit::kzg10::{Powers, KZG10};
use ark_std::rand::Rng;
use rand::thread_rng;
use std::borrow::Cow;
use std::collections::HashSet;

use crate::nizk;

#[derive(Clone, Debug, PartialEq)]
pub struct MembershipProof<E: Pairing> {
    pub pi: E::G1Affine,
}

#[derive(Clone, Debug, PartialEq)]
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
        let pp = KZG10::<E, DensePolynomial<E::ScalarField>>::setup(max_elements, false, rng)
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

    pub fn value(&self) -> E::G1Affine {
        self.acc
    }

    pub fn add(&mut self, element: &E::ScalarField) -> bool {
        if self.elements.contains(&element) {
            return false;
        }
        let factor = DensePolynomial::from_coefficients_vec(vec![
            -element.to_owned(),
            E::ScalarField::one(),
        ]);
        self.poly = &self.poly * &factor;
        self.acc = self.kzg_com(&None, &self.poly);
        self.elements.insert(element.to_owned());
        true
    }

    pub fn del(&mut self, element: E::ScalarField) -> bool {
        if !self.elements.contains(&element) {
            return false;
        }
        let (q, r) = Self::syn_div(&self.poly, &element);
        debug_assert!(r.is_zero(), "element is a root; r must be 0");
        self.poly = q;
        self.acc = self.kzg_com(&None, &self.poly);
        self.elements.remove(&element);
        true
    }

    pub fn mem_proof_create(&self, element: E::ScalarField) -> Option<MembershipProof<E>> {
        if !self.elements.contains(&element) {
            return None;
        }
        let (q, _) = Self::syn_div(&self.poly, &element);
        Some(MembershipProof {
            pi: self.kzg_com(&None, &q),
        })
    }

    pub fn non_mem_proof_create(&self, element: E::ScalarField) -> Option<NonMembershipProof<E>> {
        if self.elements.contains(&element) {
            return None;
        }
        let (q, r) = Self::syn_div(&self.poly, &element);
        Some(NonMembershipProof {
            y: r,
            b: self.kzg_com(&None, &q),
        })
    }

    pub fn mem_ver(&self, proof: &MembershipProof<E>, element: E::ScalarField) -> bool {
        let g2 = self.crs_g2[0];
        let g2_tau = self.crs_g2[1];

        let g2_tau_minus_s = (g2_tau.into_group() - g2.into_group() * element).into_affine();

        let lhs = E::pairing(proof.pi, g2_tau_minus_s);
        let rhs = E::pairing(self.acc, g2);
        lhs == rhs
    }

    pub fn non_mem_ver(&self, proof: &NonMembershipProof<E>, element: E::ScalarField) -> bool {
        let g1 = self.crs_g1[0];
        let g2 = self.crs_g2[0];
        let g2_tau = self.crs_g2[1];

        let g2_tau_minus_s = (g2_tau.into_group() - g2.into_group() * element).into_affine();

        let y_g1 = (g1.into_group() * proof.y).into_affine();

        let lhs = E::multi_pairing([proof.b, y_g1], [g2_tau_minus_s, g2]);
        let rhs = E::pairing(self.acc, g2);
        lhs == rhs
    }

    pub fn blind_mem_proof<R: Rng>(
        &self,
        rng: &mut R,
        q: &DensePolynomial<E::ScalarField>,
        k: usize,
    ) -> Option<(Vec<E::G1Affine>, E::ScalarField)> {
        let r = E::ScalarField::rand(rng);
        let mut crs_prime = Vec::with_capacity(k);
        for i in 0..=k {
            let mut coeffs = vec![E::ScalarField::zero(); i];
            coeffs.extend(q.coeffs().iter().map(|c| *c * r));
            let r_xi_q = DensePolynomial::from_coefficients_vec(coeffs);
            crs_prime.push(self.kzg_com(&None, &r_xi_q));
        }
        Some((crs_prime, r))
    }

    pub fn blind_mem_proof_upd(
        &self,
        x: Vec<E::ScalarField>,
        pi: &E::G1Affine,
        acc_t: &E::G1Affine,
        crs_prime: Vec<E::G1Affine>,
        q_star: DensePolynomial<E::ScalarField>,
    ) -> (
        E::G1Affine,
        nizk::PoeEqAndProof<E>,
        DensePolynomial<E::ScalarField>,
    )
    where
        E::ScalarField: PrimeField,
    {
        let acc_t_prime = self.acc;

        let mut s_t_poly = self.poly.clone();
        for xi in &x {
            let (q, r) = Self::syn_div(&s_t_poly, xi);
            debug_assert!(r.is_zero(), "added element must divide updated polynomial");
            s_t_poly = q;
        }

        let pi_prime = self.kzg_com(&Some(crs_prime.clone()), &q_star);

        let required_len = q_star.coeffs().len();

        let mut powers_acc_t = Vec::with_capacity(required_len);
        for i in 0..required_len {
            let mut coeffs = vec![E::ScalarField::zero(); i];
            coeffs.extend(s_t_poly.coeffs().iter().copied());
            let shifted = DensePolynomial::from_coefficients_vec(coeffs);
            powers_acc_t.push(self.kzg_com(&None, &shifted));
        }

        debug_assert_eq!(powers_acc_t.first(), Some(acc_t));

        let powers_for_acc_t = Powers::<E> {
            powers_of_g: Cow::Owned(powers_acc_t),
            powers_of_gamma_g: Cow::Owned(vec![]),
        };

        let powers_for_pi = Powers::<E> {
            powers_of_g: Cow::Owned(crs_prime.into_iter().take(required_len).collect()),
            powers_of_gamma_g: Cow::Owned(vec![]),
        };

        let poe_eq_proof = nizk::BilinearNIZK::prove_poe_eq::<E>(
            &powers_for_acc_t,
            &powers_for_pi,
            acc_t,
            &acc_t_prime,
            pi,
            &pi_prime,
            &q_star,
        )
        .expect("PoEEq proof creation failed");

        (pi_prime, poe_eq_proof, q_star)
    }

    pub fn ver_blind_mem_proof_upd(
        &self,
        pi: &E::G1Affine,
        pi_prime: &E::G1Affine,
        acc_t: &E::G1Affine,
        delta: &DensePolynomial<E::ScalarField>,
        poe_eq_proof: &nizk::PoeEqAndProof<E>,
    ) -> bool
    where
        E::ScalarField: PrimeField,
    {
        let acc_t_prime = &self.acc;
        let g2 = &self.crs_g2[0];
        let g2_s = &self.crs_g2[1];

        nizk::BilinearNIZK::verify_poe_eq::<E>(
            acc_t,
            acc_t_prime,
            pi,
            pi_prime,
            g2,
            g2_s,
            delta,
            poe_eq_proof,
        )
    }

    pub fn unblind_mem_proof(pi_prime: &E::G1Affine, r: &E::ScalarField) -> E::G1Affine {
        let r_inv = r.inverse().expect("r must be nonzero");
        (pi_prime.into_group() * r_inv).into_affine()
    }

    pub fn blind_non_mem_proof(
        &self,
        proof: &NonMembershipProof<E>,
        element: E::ScalarField,
    ) -> (
        (
            (<E as Pairing>::G1Affine, <E as Pairing>::G1Affine),
            <E as Pairing>::ScalarField,
        ),
        <E as Pairing>::ScalarField,
    ) {
        let mut rng = thread_rng();
        let r = E::ScalarField::rand(&mut rng);

        let (q_poly, rem) = Self::syn_div(&self.poly, &element);
        debug_assert_eq!(
            rem, proof.y,
            "proof scalar must match reminder from division"
        );
        let mut x_q_coeffs = vec![E::ScalarField::zero()];
        x_q_coeffs.extend(q_poly.coeffs().iter().copied());
        let x_q = DensePolynomial::from_coefficients_vec(x_q_coeffs);
        let b_tau = self.kzg_com(&None, &x_q);

        let crs_prime = (
            (proof.b.into_group() * r).into_affine(),
            (b_tau.into_group() * r).into_affine(),
        );

        let blinded_non_mem_proof = (crs_prime, r * proof.y);
        (blinded_non_mem_proof, r)
    }

    pub fn blind_non_mem_proof_upd(
        &self,
        blinded_non_mem_proof: &(
            (<E as Pairing>::G1Affine, <E as Pairing>::G1Affine),
            <E as Pairing>::ScalarField,
        ),
        acc_t: &E::G1Affine,
        sn_plus_one: &E::ScalarField,
    ) -> (
        (<E as Pairing>::G1Affine, <E as Pairing>::ScalarField),
        nizk::PoeEqAndProof<E>,
        DensePolynomial<E::ScalarField>,
    )
    where
        E::ScalarField: PrimeField,
    {
        let (crs_prime, y_prime) = blinded_non_mem_proof;
        let q_prime = (crs_prime.1.into_group()
            - crs_prime.0.into_group() * sn_plus_one.to_owned())
        .into_affine();

        let y_prime_t_prime = y_prime.to_owned() * sn_plus_one.to_owned();

        let delta =
            DensePolynomial::from_coefficients_vec(vec![-*sn_plus_one, E::ScalarField::one()]);

        let acc_t_prime = self.acc;
        let acc_t_tau =
            (acc_t_prime.into_group() + acc_t.into_group() * sn_plus_one.to_owned()).into_affine();

        let powers_for_acc_t = Powers::<E> {
            powers_of_g: Cow::Owned(vec![acc_t.to_owned(), acc_t_tau]),
            powers_of_gamma_g: Cow::Owned(vec![]),
        };

        let powers_for_q_base = Powers::<E> {
            powers_of_g: Cow::Owned(vec![crs_prime.0, crs_prime.1]),
            powers_of_gamma_g: Cow::Owned(vec![]),
        };

        let poe_eq_proof = nizk::BilinearNIZK::prove_poe_eq::<E>(
            &powers_for_acc_t,
            &powers_for_q_base,
            acc_t,
            &acc_t_prime,
            &crs_prime.0,
            &q_prime,
            &delta,
        )
        .expect("PoEEq proof creation failed");

        ((q_prime, y_prime_t_prime), poe_eq_proof, delta)
    }

    pub fn ver_blind_non_mem_proof_upd(
        &self,
        acc_t: &E::G1Affine,
        blinded_non_mem_proof: &(
            (<E as Pairing>::G1Affine, <E as Pairing>::G1Affine),
            <E as Pairing>::ScalarField,
        ),
        upd_blinded_non_mem_proof: &(<E as Pairing>::G1Affine, <E as Pairing>::ScalarField),
        delta: &DensePolynomial<E::ScalarField>,
        poe_eq_proof: &nizk::PoeEqAndProof<E>,
    ) -> bool
    where
        E::ScalarField: PrimeField,
    {
        let acc_t_prime = &self.acc;
        let g2 = &self.crs_g2[0];
        let g2_s = &self.crs_g2[1];

        let (crs_prime, _) = blinded_non_mem_proof;
        let (q_prime, _) = upd_blinded_non_mem_proof;

        nizk::BilinearNIZK::verify_poe_eq::<E>(
            acc_t,
            acc_t_prime,
            &crs_prime.0,
            q_prime,
            g2,
            g2_s,
            delta,
            poe_eq_proof,
        )
    }

    pub fn unblind_non_mem_proof(
        &self,
        blinded_non_mem_proof: &(E::G1Affine, E::ScalarField),
        st: &(E::ScalarField, E::ScalarField),
        element: E::ScalarField,
    ) -> NonMembershipProof<E> {
        let (q_prime, y_prime_t_prime) = &blinded_non_mem_proof;
        let (r, y_prime_t) = st;
        let r_inv = r.inverse().expect("r must be nonzero");
        let g1 = self.crs_g1[0];

        let y_t = y_prime_t.to_owned() * r_inv;
        let q = (q_prime.into_group() * r_inv + g1.into_group() * y_t).into_affine();
        let y_t_prime = y_t * element.to_owned() - (y_prime_t_prime.to_owned() * r_inv);

        NonMembershipProof { b: q, y: y_t_prime }
    }

    fn kzg_com(
        &self,
        crs: &Option<Vec<E::G1Affine>>,
        poly: &DensePolynomial<E::ScalarField>,
    ) -> E::G1Affine {
        let powers = if let Some(custom_crs) = crs {
            Powers::<E> {
                powers_of_g: Cow::Borrowed(custom_crs.as_slice()),
                powers_of_gamma_g: Cow::Owned(vec![]),
            }
        } else {
            Powers::<E> {
                powers_of_g: Cow::Borrowed(&self.crs_g1),
                powers_of_gamma_g: Cow::Owned(vec![]),
            }
        };

        let (com, _) = KZG10::commit(&powers, poly, None, None).expect("Commitment failed");
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

    #[test]
    fn mem_ver_passes_for_member() {
        use ark_std::test_rng;
        let mut acc = BilinearAccumulator::<Bls12_381>::setup(&mut test_rng(), 16);
        let elements: Vec<ark_bls12_381::Fr> = (1u64..=4).map(ark_bls12_381::Fr::from).collect();
        for e in &elements {
            acc.add(e);
        }
        let proof = acc
            .mem_proof_create(elements[2])
            .expect("Membership proof creation failed");
        assert!(acc.mem_ver(&proof, elements[2]));
    }

    #[test]
    fn non_mem_ver_passes_for_non_member() {
        use ark_std::test_rng;
        let mut acc = BilinearAccumulator::<Bls12_381>::setup(&mut test_rng(), 16);
        let elements: Vec<ark_bls12_381::Fr> = (1u64..=4).map(ark_bls12_381::Fr::from).collect();
        for e in &elements {
            acc.add(e);
        }
        let proof = acc
            .non_mem_proof_create(ark_bls12_381::Fr::from(666))
            .expect("Non-membership proof creation failed");
        assert!(acc.non_mem_ver(&proof, ark_bls12_381::Fr::from(666)));
    }

    #[test]
    fn mem_ver_not_pass_for_non_member() {
        use ark_std::test_rng;
        let mut acc = BilinearAccumulator::<Bls12_381>::setup(&mut test_rng(), 16);
        let elements: Vec<ark_bls12_381::Fr> = (1u64..=4).map(ark_bls12_381::Fr::from).collect();
        for e in &elements {
            acc.add(e);
        }
        assert_eq!(acc.mem_proof_create(ark_bls12_381::Fr::from(666)), None);
    }

    #[test]
    fn non_mem_ver_not_pass_for_member() {
        use ark_std::test_rng;
        let mut acc = BilinearAccumulator::<Bls12_381>::setup(&mut test_rng(), 16);
        let elements: Vec<ark_bls12_381::Fr> = (1u64..=4).map(ark_bls12_381::Fr::from).collect();
        for e in &elements {
            acc.add(e);
        }
        assert_eq!(acc.non_mem_proof_create(elements[2]), None);
    }

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

    #[test]
    pub fn test_blind_upd_mem_proof_after_additions() {
        use ark_std::test_rng;
        let mut acc = BilinearAccumulator::<Bls12_381>::setup(&mut test_rng(), 16);

        let initial_elements: Vec<ark_bls12_381::Fr> =
            (1u64..=3).map(ark_bls12_381::Fr::from).collect();
        for e in &initial_elements {
            acc.add(e);
        }
        let element = initial_elements[1];
        let _proof = acc
            .mem_proof_create(element)
            .expect("Membership proof creation failed");
        let acc_t = acc.value();

        let s = initial_elements.iter().fold(
            DensePolynomial::from_coefficients_vec(vec![ark_bls12_381::Fr::one()]),
            |acc, xi| {
                let factor =
                    DensePolynomial::from_coefficients_vec(vec![-*xi, ark_bls12_381::Fr::one()]);
                &acc * &factor
            },
        );
        let (q, _) = BilinearAccumulator::<Bls12_381>::syn_div(&s, &element);

        let added_elements: Vec<ark_bls12_381::Fr> =
            (4u64..=5).map(ark_bls12_381::Fr::from).collect();
        let num_added = added_elements.len();

        let (crs_prime, r) = acc
            .blind_mem_proof(&mut test_rng(), &q, num_added)
            .expect("Blind membership proof creation failed");
        let pi_blinded = crs_prime
            .first()
            .copied()
            .expect("blinded CRS must include base term");

        for e in &added_elements {
            acc.add(e);
        }

        let q_star = added_elements.iter().fold(
            DensePolynomial::from_coefficients_vec(vec![ark_bls12_381::Fr::one()]),
            |acc, xi| {
                let factor =
                    DensePolynomial::from_coefficients_vec(vec![-*xi, ark_bls12_381::Fr::one()]);
                &acc * &factor
            },
        );

        let (pi_prime, poe_eq_proof, delta) =
            acc.blind_mem_proof_upd(added_elements, &pi_blinded, &acc_t, crs_prime, q_star);

        assert!(acc.ver_blind_mem_proof_upd(&pi_blinded, &pi_prime, &acc_t, &delta, &poe_eq_proof,));

        let pi = BilinearAccumulator::<Bls12_381>::unblind_mem_proof(&pi_prime, &r);
        let updated_proof = MembershipProof { pi };

        assert!(acc.mem_ver(&updated_proof, element));
    }

    #[test]
    pub fn test_blind_upd_non_mem_proof_after_additions() {
        use ark_std::test_rng;
        let mut acc = BilinearAccumulator::<Bls12_381>::setup(&mut test_rng(), 16);
        let initial_elements: Vec<ark_bls12_381::Fr> =
            (1u64..=3).map(ark_bls12_381::Fr::from).collect();
        for e in &initial_elements {
            acc.add(e);
        }

        let non_member = ark_bls12_381::Fr::from(666u64);

        let proof = acc
            .non_mem_proof_create(non_member)
            .expect("Non-membership proof creation failed");

        assert!(acc.non_mem_ver(&proof, non_member), "initial should verify");

        let (blinded_non_mem_proof, r) = acc.blind_non_mem_proof(&proof, non_member);
        let acc_t = acc.value();

        let sn_plus_one = ark_bls12_381::Fr::from(67u64);
        acc.add(&sn_plus_one);

        let (pi_prime_t_prime, poe_eq_proof, delta) =
            acc.blind_non_mem_proof_upd(&blinded_non_mem_proof, &acc_t, &sn_plus_one);

        assert!(acc.ver_blind_non_mem_proof_upd(
            &acc_t,
            &blinded_non_mem_proof,
            &pi_prime_t_prime,
            &delta,
            &poe_eq_proof,
        ));

        let updated_proof =
            acc.unblind_non_mem_proof(&pi_prime_t_prime, &(r, blinded_non_mem_proof.1), non_member);

        assert!(
            acc.non_mem_ver(&updated_proof, non_member),
            "updated should verify"
        );
    }
}
