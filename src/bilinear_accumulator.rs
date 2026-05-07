use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::{Field, One, PrimeField, UniformRand, Zero};
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial};
use ark_poly_commit::kzg10::{Powers, KZG10};
use ark_std::rand::Rng;
use rand::thread_rng;
use std::borrow::Cow;
use std::collections::HashSet;

use crate::error::{AccumulatorError, AccumulatorResult};
use crate::groups::bilinear_group::BilinearG1;
use crate::nizk;
use crate::traits::{Accumulator, Group, PrivatelyDelegatableAccumulator};

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
pub struct ProverMembershipProof<E: Pairing> {
    pub proof: MembershipProof<E>,
    pub element: E::ScalarField,
    pub witness_poly: DensePolynomial<E::ScalarField>,
}

#[derive(Clone, Debug)]
pub struct BlindedMembershipBundle<E: Pairing> {
    pub pi_blinded: E::G1Affine,
    pub crs_prime: Vec<E::G1Affine>,
    pub poly_s: DensePolynomial<E::ScalarField>,
}

#[derive(Clone, Debug)]
pub struct UpdatedBlindedMembershipBundle<E: Pairing> {
    pub pi_prime: E::G1Affine,
    pub q_star: DensePolynomial<E::ScalarField>,
}

pub type MembershipUpdateAux<E> = (
    <E as Pairing>::G1Affine,
    <E as Pairing>::G1Affine,
    <E as Pairing>::G1Affine,
    <E as Pairing>::ScalarField,
    <E as Pairing>::G1Affine,
);

#[derive(Clone, Debug)]
pub struct BlindedNonMembershipBundle<E: Pairing> {
    pub crs_prime: (E::G1Affine, E::G1Affine),
    pub y_prime: E::ScalarField,
    pub r: E::ScalarField,
    pub element: E::ScalarField,
    pub acc_t: E::G1Affine,
}

#[derive(Clone, Debug)]
pub struct UpdatedBlindedNonMembershipBundle<E: Pairing> {
    pub q_prime: E::G1Affine,
    pub y_prime_t_prime: E::ScalarField,
    pub g2_sn_plus_one: E::G2Affine,
    pub y_prime_t: E::ScalarField,
    pub element: E::ScalarField,
}

#[derive(Clone, Debug)]
pub struct BilinearAccumulator<E: Pairing> {
    pub group: BilinearG1<E>,
    acc: E::G1Affine,
    poly: DensePolynomial<E::ScalarField>,
    elements: HashSet<E::ScalarField>,
}

impl<E: Pairing> BilinearAccumulator<E> {
    pub fn setup<R: Rng>(rng: &mut R, max_elements: usize) -> BilinearAccumulator<E> {
        let group = BilinearG1::<E>::new(rng, max_elements);
        let poly = DensePolynomial::from_coefficients_vec(vec![E::ScalarField::one()]);
        let acc = group.crs_g1[0];

        BilinearAccumulator {
            group,
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
        let g2 = self.group.crs_g2[0];
        let g2_tau = self.group.crs_g2[1];

        let g2_tau_minus_s = (g2_tau.into_group() - g2.into_group() * element).into_affine();

        let lhs = E::pairing(proof.pi, g2_tau_minus_s);
        let rhs = E::pairing(self.acc, g2);
        lhs == rhs
    }

    pub fn non_mem_ver(&self, proof: &NonMembershipProof<E>, element: E::ScalarField) -> bool {
        let g1 = self.group.crs_g1[0];
        let g2 = self.group.crs_g2[0];
        let g2_tau = self.group.crs_g2[1];

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
        pi: &E::G1Affine,
        acc_t: &E::G1Affine,
        crs_prime: Vec<E::G1Affine>,
        q_star: DensePolynomial<E::ScalarField>,
        powers_acc_t: Vec<E::G1Affine>,
    ) -> (
        E::G1Affine,
        (
            E::G1Affine,
            E::G1Affine,
            E::G1Affine,
            E::ScalarField,
            E::G1Affine,
        ),
        DensePolynomial<E::ScalarField>,
    )
    where
        E::ScalarField: PrimeField,
    {
        let acc_t_prime = self.acc;

        let pi_prime = self.kzg_com(&Some(crs_prime.clone()), &q_star);

        let required_len = q_star.coeffs().len();

        assert!(
            powers_acc_t.len() >= required_len,
            "powers_acc_t must have at least {} elements",
            required_len
        );

        let powers_for_acc_t = Powers::<E> {
            powers_of_g: Cow::Owned(powers_acc_t.into_iter().take(required_len).collect()),
            powers_of_gamma_g: Cow::Borrowed(&[]),
        };

        let powers_for_pi = Powers::<E> {
            powers_of_g: Cow::Owned(crs_prime.into_iter().take(required_len).collect()),
            powers_of_gamma_g: Cow::Borrowed(&[]),
        };

        let powers_for_g1 = Powers::<E> {
            powers_of_g: Cow::Owned(
                self.group
                    .crs_g1
                    .iter()
                    .copied()
                    .take(required_len)
                    .collect(),
            ),
            powers_of_gamma_g: Cow::Borrowed(&[]),
        };

        let poe_eq_proof = nizk::BilinearNIZK::prove_poe_eq::<E>(
            &powers_for_acc_t,
            &powers_for_pi,
            &powers_for_g1,
            acc_t,
            &acc_t_prime,
            pi,
            &pi_prime,
            &q_star,
        )
        .expect("PoEEq proof creation failed");

        (pi_prime, poe_eq_proof, q_star)
    }

    pub fn shift_com(
        &self,
        poly: &DensePolynomial<E::ScalarField>,
        len: usize,
    ) -> Vec<E::G1Affine> {
        let mut shifted_coms = Vec::with_capacity(len);
        for i in 0..len {
            let mut coeffs = vec![E::ScalarField::zero(); i];
            coeffs.extend(poly.coeffs().iter().copied());
            let shifted = DensePolynomial::from_coefficients_vec(coeffs);
            shifted_coms.push(self.kzg_com(&None, &shifted));
        }
        shifted_coms
    }

    pub fn ver_blind_mem_proof_upd(
        &self,
        pi: &E::G1Affine,
        pi_prime: &E::G1Affine,
        acc_t: &E::G1Affine,
        delta: &DensePolynomial<E::ScalarField>,
        poe_eq_proof: &(
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
        let acc_t_prime = &self.acc;
        let g1 = &self.group.crs_g1[0];
        let g2 = &self.group.crs_g2[0];
        let g2_s = &self.group.crs_g2[1];

        nizk::BilinearNIZK::verify_poe_eq::<E>(
            g1,
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
        _acc_t: &E::G1Affine,
        sn_plus_one: &E::ScalarField,
    ) -> ((E::G1Affine, E::ScalarField), E::G2Affine) {
        let (crs_prime, y_prime) = blinded_non_mem_proof;
        let q_prime = (crs_prime.1.into_group()
            - crs_prime.0.into_group() * sn_plus_one.to_owned())
        .into_affine();

        let y_prime_t_prime = y_prime.to_owned() * sn_plus_one.to_owned();

        let g2 = self.group.crs_g2[0];

        let g2_sn_plus_one = (g2.into_group() * sn_plus_one.to_owned()).into_affine();

        ((q_prime, y_prime_t_prime), g2_sn_plus_one)
    }

    pub fn ver_blind_non_mem_proof_upd(
        &self,
        acc_t: &E::G1Affine,
        blinded_non_mem_proof: &(
            (<E as Pairing>::G1Affine, <E as Pairing>::G1Affine),
            <E as Pairing>::ScalarField,
        ),
        upd_blinded_non_mem_proof: &(<E as Pairing>::G1Affine, <E as Pairing>::ScalarField),
        g2_sn_plus_one: &E::G2Affine,
    ) -> bool
    where
        E::ScalarField: PrimeField,
    {
        let acc_t_prime = &self.acc;
        let g2 = self.group.crs_g2[0];
        let g2_tau = self.group.crs_g2[1];

        let (crs_prime, _) = blinded_non_mem_proof;
        let (q_prime, _) = upd_blinded_non_mem_proof;

        let g2_tau_minus_sn_plus_one =
            (g2_tau.into_group() - g2_sn_plus_one.into_group()).into_affine();

        let acc_update_ok =
            E::pairing(acc_t, g2_tau_minus_sn_plus_one) == E::pairing(acc_t_prime, g2);
        if !acc_update_ok {
            return false;
        }

        let lhs = E::multi_pairing(
            [q_prime.to_owned(), crs_prime.0],
            [g2, g2_sn_plus_one.to_owned()],
        );
        let rhs = E::pairing(crs_prime.1, g2);
        lhs == rhs
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
        let g1 = self.group.crs_g1[0];

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
                powers_of_gamma_g: Cow::Borrowed(&[]),
            }
        } else {
            Powers::<E> {
                powers_of_g: Cow::Borrowed(&self.group.crs_g1),
                powers_of_gamma_g: Cow::Borrowed(&[]),
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

impl<E: Pairing> Accumulator for BilinearAccumulator<E>
where
    E::ScalarField: PrimeField,
{
    type Group = BilinearG1<E>;
    type Element = E::ScalarField;
    type MembershipProof = ProverMembershipProof<E>;
    type NonMembershipProof = NonMembershipProof<E>;
    type NonMembershipProduct = ();

    fn new(group: Self::Group) -> Self {
        let acc = group.crs_g1[0];
        Self {
            group,
            acc,
            poly: DensePolynomial::from_coefficients_vec(vec![E::ScalarField::one()]),
            elements: HashSet::new(),
        }
    }

    fn add(&mut self, element: &Self::Element) -> <Self::Group as Group>::Exponent {
        BilinearAccumulator::<E>::add(self, element);
        *element
    }

    fn del(&mut self, element: &Self::Element) {
        BilinearAccumulator::<E>::del(self, *element);
    }

    fn value(&self) -> &<Self::Group as Group>::Element {
        &self.acc
    }

    fn mem_proof_create(
        &self,
        element: &<Self::Group as Group>::Exponent,
    ) -> AccumulatorResult<Self::MembershipProof> {
        if !self.elements.contains(element) {
            return Err(AccumulatorError::ElementNotInSet);
        }
        let (witness_poly, _) = Self::syn_div(&self.poly, element);
        let pi = self.kzg_com(&None, &witness_poly);
        Ok(ProverMembershipProof {
            proof: MembershipProof { pi },
            element: *element,
            witness_poly,
        })
    }

    fn mem_ver(
        &self,
        proof: &Self::MembershipProof,
        element: &<Self::Group as Group>::Exponent,
    ) -> bool {
        BilinearAccumulator::<E>::mem_ver(self, &proof.proof, *element)
    }

    fn non_mem_proof_create(
        &self,
        element: &Self::Element,
        _prod: &Self::NonMembershipProduct,
    ) -> AccumulatorResult<Self::NonMembershipProof> {
        BilinearAccumulator::<E>::non_mem_proof_create(self, *element)
            .ok_or(AccumulatorError::NotCoprime)
    }

    fn non_mem_ver(&self, proof: &Self::NonMembershipProof, element: &Self::Element) -> bool {
        BilinearAccumulator::<E>::non_mem_ver(self, proof, *element)
    }
}

impl<E: Pairing> PrivatelyDelegatableAccumulator for BilinearAccumulator<E>
where
    E::ScalarField: PrimeField,
{
    type BlindedMembershipProof = BlindedMembershipBundle<E>;
    type MembershipBlindingFactor = E::ScalarField;
    type UpdatedBlindedMembershipProof = UpdatedBlindedMembershipBundle<E>;
    type MembershipUpdateAux = MembershipUpdateAux<E>;
    type BlindedNonMembershipProof = BlindedNonMembershipBundle<E>;
    type UpdatedBlindedNonMembershipProof = UpdatedBlindedNonMembershipBundle<E>;
    type Delta = DensePolynomial<E::ScalarField>;

    fn blind_mem_proof(
        &self,
        proof: &Self::MembershipProof,
    ) -> (Self::BlindedMembershipProof, Self::MembershipBlindingFactor) {
        let mut rng = thread_rng();
        let k = self
            .group
            .crs_g1
            .len()
            .saturating_sub(self.poly.coeffs().len());
        let (crs_prime, r) =
            BilinearAccumulator::<E>::blind_mem_proof(self, &mut rng, &proof.witness_poly, k)
                .expect("blind_mem_proof returns Some for any polynomial");
        let pi_blinded = crs_prime[0];
        let bundle = BlindedMembershipBundle {
            pi_blinded,
            crs_prime,
            poly_s: self.poly.clone(),
        };
        (bundle, r)
    }

    fn blind_mem_proof_upd(
        &self,
        acc_t: &<Self::Group as Group>::Element,
        blinded_proof: &Self::BlindedMembershipProof,
        delta: &Self::Delta,
    ) -> AccumulatorResult<(
        Self::UpdatedBlindedMembershipProof,
        Self::MembershipUpdateAux,
        <Self::Group as Group>::Element,
    )> {
        let q_star = delta.clone();
        let powers_acc_t = self.shift_com(&blinded_proof.poly_s, q_star.coeffs().len());
        let (pi_prime, poe_eq_proof, q_star_back) = BilinearAccumulator::<E>::blind_mem_proof_upd(
            self,
            &blinded_proof.pi_blinded,
            acc_t,
            blinded_proof.crs_prime.clone(),
            q_star,
            powers_acc_t,
        );
        Ok((
            UpdatedBlindedMembershipBundle {
                pi_prime,
                q_star: q_star_back,
            },
            poe_eq_proof,
            self.acc,
        ))
    }

    fn ver_blind_mem_proof_upd(
        &self,
        acc_t: &<Self::Group as Group>::Element,
        blinded_proof: &Self::BlindedMembershipProof,
        upd_blinded_proof: &Self::UpdatedBlindedMembershipProof,
        aux: &Self::MembershipUpdateAux,
    ) -> bool {
        BilinearAccumulator::<E>::ver_blind_mem_proof_upd(
            self,
            &blinded_proof.pi_blinded,
            &upd_blinded_proof.pi_prime,
            acc_t,
            &upd_blinded_proof.q_star,
            aux,
        )
    }

    fn unblind_mem_proof(
        &self,
        blinded_proof: &Self::BlindedMembershipProof,
        st: &Self::MembershipBlindingFactor,
    ) -> Self::MembershipProof {
        let pi = BilinearAccumulator::<E>::unblind_mem_proof(&blinded_proof.pi_blinded, st);
        ProverMembershipProof {
            proof: MembershipProof { pi },
            element: E::ScalarField::zero(),
            witness_poly: DensePolynomial::zero(),
        }
    }

    fn blind_non_mem_proof(&self, element: &Self::Element) -> Self::BlindedNonMembershipProof {
        let proof = BilinearAccumulator::<E>::non_mem_proof_create(self, *element)
            .expect("blind_non_mem_proof: element must not currently be a member");
        let (((b_r, b_tau_r), y_prime), r) =
            BilinearAccumulator::<E>::blind_non_mem_proof(self, &proof, *element);
        BlindedNonMembershipBundle {
            crs_prime: (b_r, b_tau_r),
            y_prime,
            r,
            element: *element,
            acc_t: self.acc,
        }
    }

    fn blind_non_mem_proof_upd(
        &self,
        blinded_non_mem_proof: &Self::BlindedNonMembershipProof,
        delta: &Self::Delta,
    ) -> AccumulatorResult<Self::UpdatedBlindedNonMembershipProof> {
        let coeffs = delta.coeffs();
        if coeffs.len() != 2 || !coeffs[1].is_one() {
            return Err(AccumulatorError::NotCoprime);
        }
        let sn_plus_one = -coeffs[0];
        let blinded_inner = (
            blinded_non_mem_proof.crs_prime,
            blinded_non_mem_proof.y_prime,
        );
        let ((q_prime, y_prime_t_prime), g2_sn_plus_one) =
            BilinearAccumulator::<E>::blind_non_mem_proof_upd(
                self,
                &blinded_inner,
                &blinded_non_mem_proof.acc_t,
                &sn_plus_one,
            );
        Ok(UpdatedBlindedNonMembershipBundle {
            q_prime,
            y_prime_t_prime,
            g2_sn_plus_one,
            y_prime_t: blinded_non_mem_proof.y_prime,
            element: blinded_non_mem_proof.element,
        })
    }

    fn ver_blind_non_mem_proof_upd(
        &self,
        _acc_t_prime: &<Self::Group as Group>::Element,
        blinded_non_mem_proof: &Self::BlindedNonMembershipProof,
        upd_blinded_non_mem_proof: &Self::UpdatedBlindedNonMembershipProof,
    ) -> bool {
        let blinded_inner = (
            blinded_non_mem_proof.crs_prime,
            blinded_non_mem_proof.y_prime,
        );
        let upd_inner = (
            upd_blinded_non_mem_proof.q_prime,
            upd_blinded_non_mem_proof.y_prime_t_prime,
        );
        BilinearAccumulator::<E>::ver_blind_non_mem_proof_upd(
            self,
            &blinded_non_mem_proof.acc_t,
            &blinded_inner,
            &upd_inner,
            &upd_blinded_non_mem_proof.g2_sn_plus_one,
        )
    }

    fn unblind_non_mem_proof(
        &self,
        st: &<Self::Group as Group>::Exponent,
        upd_blinded_non_mem_proof: &Self::UpdatedBlindedNonMembershipProof,
    ) -> Self::NonMembershipProof {
        let upd_inner = (
            upd_blinded_non_mem_proof.q_prime,
            upd_blinded_non_mem_proof.y_prime_t_prime,
        );
        let st_pair = (*st, upd_blinded_non_mem_proof.y_prime_t);
        BilinearAccumulator::<E>::unblind_non_mem_proof(
            self,
            &upd_inner,
            &st_pair,
            upd_blinded_non_mem_proof.element,
        )
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

        let powers_acc_t = acc.shift_com(&s, q_star.coeffs().len());

        let (pi_prime, poe_eq_proof, delta) =
            acc.blind_mem_proof_upd(&pi_blinded, &acc_t, crs_prime, q_star, powers_acc_t);

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

        let (pi_prime_t_prime, g2_sn_plus_one) =
            acc.blind_non_mem_proof_upd(&blinded_non_mem_proof, &acc_t, &sn_plus_one);

        assert!(acc.ver_blind_non_mem_proof_upd(
            &acc_t,
            &blinded_non_mem_proof,
            &pi_prime_t_prime,
            &g2_sn_plus_one,
        ));

        let updated_proof =
            acc.unblind_non_mem_proof(&pi_prime_t_prime, &(r, blinded_non_mem_proof.1), non_member);

        assert!(
            acc.non_mem_ver(&updated_proof, non_member),
            "updated should verify"
        );
    }
}

#[cfg(test)]
mod trait_tests {
    use super::*;
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_std::test_rng;

    fn linear_factor(x: Fr) -> DensePolynomial<Fr> {
        DensePolynomial::from_coefficients_vec(vec![-x, Fr::one()])
    }

    fn product_poly(elements: &[Fr]) -> DensePolynomial<Fr> {
        elements.iter().fold(
            DensePolynomial::from_coefficients_vec(vec![Fr::one()]),
            |acc, x| &acc * &linear_factor(*x),
        )
    }

    #[test]
    fn trait_mem_proof_roundtrip() {
        let group = BilinearG1::<Bls12_381>::new(&mut test_rng(), 16);
        let mut acc = <BilinearAccumulator<Bls12_381> as Accumulator>::new(group);
        let elements: Vec<Fr> = (1u64..=4).map(Fr::from).collect();
        for e in &elements {
            <BilinearAccumulator<Bls12_381> as Accumulator>::add(&mut acc, e);
        }
        let proof =
            <BilinearAccumulator<Bls12_381> as Accumulator>::mem_proof_create(&acc, &elements[2])
                .expect("trait mem_proof_create");
        assert!(<BilinearAccumulator<Bls12_381> as Accumulator>::mem_ver(
            &acc,
            &proof,
            &elements[2]
        ));
    }

    #[test]
    fn trait_non_mem_proof_roundtrip() {
        let group = BilinearG1::<Bls12_381>::new(&mut test_rng(), 16);
        let mut acc = <BilinearAccumulator<Bls12_381> as Accumulator>::new(group);
        for e in (1u64..=4).map(Fr::from) {
            <BilinearAccumulator<Bls12_381> as Accumulator>::add(&mut acc, &e);
        }
        let non_member = Fr::from(666u64);
        let proof = <BilinearAccumulator<Bls12_381> as Accumulator>::non_mem_proof_create(
            &acc,
            &non_member,
            &(),
        )
        .expect("trait non_mem_proof_create");
        assert!(
            <BilinearAccumulator<Bls12_381> as Accumulator>::non_mem_ver(&acc, &proof, &non_member)
        );
    }

    #[test]
    fn trait_blind_mem_proof_upd_roundtrip() {
        let group = BilinearG1::<Bls12_381>::new(&mut test_rng(), 32);
        let mut acc = <BilinearAccumulator<Bls12_381> as Accumulator>::new(group);
        let initial: Vec<Fr> = (1u64..=3).map(Fr::from).collect();
        for e in &initial {
            <BilinearAccumulator<Bls12_381> as Accumulator>::add(&mut acc, e);
        }
        let element = initial[1];
        let proof =
            <BilinearAccumulator<Bls12_381> as Accumulator>::mem_proof_create(&acc, &element)
                .expect("mem proof");

        let acc_t = *<BilinearAccumulator<Bls12_381> as Accumulator>::value(&acc);
        let (blinded, st) =
            <BilinearAccumulator<Bls12_381> as PrivatelyDelegatableAccumulator>::blind_mem_proof(
                &acc, &proof,
            );

        let added: Vec<Fr> = (4u64..=5).map(Fr::from).collect();
        for e in &added {
            <BilinearAccumulator<Bls12_381> as Accumulator>::add(&mut acc, e);
        }
        let delta = product_poly(&added);

        let (upd, aux, _new_acc) =
            <BilinearAccumulator<Bls12_381> as PrivatelyDelegatableAccumulator>::blind_mem_proof_upd(
                &acc, &acc_t, &blinded, &delta,
            )
            .expect("upd");
        assert!(<BilinearAccumulator<Bls12_381> as PrivatelyDelegatableAccumulator>::ver_blind_mem_proof_upd(
            &acc, &acc_t, &blinded, &upd, &aux,
        ));

        let unblinded =
            <BilinearAccumulator<Bls12_381> as PrivatelyDelegatableAccumulator>::unblind_mem_proof(
                &acc,
                &BlindedMembershipBundle {
                    pi_blinded: upd.pi_prime,
                    crs_prime: blinded.crs_prime.clone(),
                    poly_s: blinded.poly_s.clone(),
                },
                &st,
            );
        assert!(<BilinearAccumulator<Bls12_381> as Accumulator>::mem_ver(
            &acc, &unblinded, &element,
        ));
    }

    #[test]
    fn trait_blind_non_mem_proof_upd_roundtrip() {
        let group = BilinearG1::<Bls12_381>::new(&mut test_rng(), 16);
        let mut acc = <BilinearAccumulator<Bls12_381> as Accumulator>::new(group);
        for e in (1u64..=3).map(Fr::from) {
            <BilinearAccumulator<Bls12_381> as Accumulator>::add(&mut acc, &e);
        }
        let non_member = Fr::from(666u64);
        let blinded =
            <BilinearAccumulator<Bls12_381> as PrivatelyDelegatableAccumulator>::blind_non_mem_proof(
                &acc, &non_member,
            );

        let added = Fr::from(67u64);
        <BilinearAccumulator<Bls12_381> as Accumulator>::add(&mut acc, &added);
        let delta = linear_factor(added);

        let upd =
            <BilinearAccumulator<Bls12_381> as PrivatelyDelegatableAccumulator>::blind_non_mem_proof_upd(
                &acc, &blinded, &delta,
            )
            .expect("non-mem upd");
        let acc_t_prime = *<BilinearAccumulator<Bls12_381> as Accumulator>::value(&acc);
        assert!(<BilinearAccumulator<Bls12_381> as PrivatelyDelegatableAccumulator>::ver_blind_non_mem_proof_upd(
            &acc, &acc_t_prime, &blinded, &upd,
        ));

        let unblinded =
            <BilinearAccumulator<Bls12_381> as PrivatelyDelegatableAccumulator>::unblind_non_mem_proof(
                &acc, &blinded.r, &upd,
            );
        assert!(
            <BilinearAccumulator<Bls12_381> as Accumulator>::non_mem_ver(
                &acc,
                &unblinded,
                &non_member,
            )
        );
    }
}
