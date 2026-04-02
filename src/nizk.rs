use crate::traits::Group;
use rand::thread_rng;
use rand::RngCore;

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

    pub fn prove_poe() {
        unimplemented!("implement DLEq...")
    }

    pub fn verify_poe() {
        unimplemented!("implement DLEq...")
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
