use crate::traits::Group;
use num_bigint::BigUint;
use rand::thread_rng;
use rand::RngCore;
use std::collections::HashSet;

pub(super) type Aux = ((BigUint, BigUint, BigUint), (BigUint, BigUint, BigUint));
pub(super) type UpdatedBlindProof = ((BigUint, BigUint), Aux, BigUint);

pub(super) const KEY_SIZE: u64 = 256; // This key size is just for demonstration

#[derive(Clone, Debug)]
pub struct RsaAccumulator<G: Group> {
    pub group: G,
    pub acc: G::Element,
    pub set: HashSet<G::Exponent>,
}

impl<G: Group> RsaAccumulator<G> {
    pub fn new(group: G) -> Self {
        let acc = group.g();
        Self {
            group,
            acc,
            set: HashSet::new(),
        }
    }

    pub fn value(&self) -> &G::Element {
        &self.acc
    }

    pub fn add<T: ToString>(&mut self, element: &T) -> G::Exponent {
        let x_str = element.to_string();
        let x_prime = self.group.hash_to_prime(x_str.as_bytes());

        if !self.set.contains(&x_prime) {
            self.set.insert(x_prime.clone());
            self.acc = self.group.exp(&self.acc, &x_prime);
        }

        x_prime
    }

    pub fn mem_ver(&self, proof: &G::Element, x: &G::Exponent) -> bool {
        self.group.exp(proof, x) == self.acc
    }

    pub fn blind_mem_proof(&self, proof: &G::Element) -> (G::Element, G::Exponent) {
        let blinder = self.sample_blinder();
        let mask = self.group.exp(&self.group.g(), &blinder);
        let blinded_proof = self.group.mul(proof, &mask);
        (blinded_proof, blinder)
    }

    pub fn unblind_mem_proof(&self, blinded_proof: &G::Element, st: &G::Exponent) -> G::Element {
        let st_mask = self.group.exp(&self.group.g(), st);
        let st_inv = self.group.inv(&st_mask);
        self.group.mul(blinded_proof, &st_inv)
    }

    fn sample_blinder(&self) -> G::Exponent {
        let mut rng = thread_rng();
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        self.group.hash_to_prime(&seed)
    }
}

#[cfg(feature = "class-group")]
mod class_group;
mod rsa;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::groups::rsa_group::RsaGroup;
    use num_bigint::BigUint;

    #[test]
    fn test_acc_add_del_no_change() {
        let mut acc = RsaAccumulator::<RsaGroup>::setup();
        let initial_acc = acc.acc.clone();
        let element = BigUint::from_bytes_be(b"test_element");

        acc.add(&element);
        acc.del(&element);

        assert_eq!(
            acc.acc, initial_acc,
            "Accumulator value should be unchanged after add and remove of the same element"
        );
    }

    #[test]
    fn test_gen_mem_proof() {
        let mut acc = RsaAccumulator::<RsaGroup>::setup();
        let element = BigUint::from(7usize);
        let ep = acc.add(&element);

        for i in 2..5 {
            acc.add(&BigUint::from(i as usize));
        }

        let proof = acc.mem_proof_create(&ep);

        assert!(acc.mem_ver(&proof, &ep));
    }

    #[test]
    fn test_non_mem_proof() {
        let mut acc = RsaAccumulator::<RsaGroup>::setup();

        acc.add(&BigUint::from(2u32));
        acc.add(&BigUint::from(3u32));
        acc.add(&BigUint::from(7u32));

        let non_member = BigUint::from(5u32);

        let proof = acc.non_mem_proof_create(&non_member);
        assert!(
            acc.non_mem_ver(&proof, &non_member),
            "Non-membership proof should verify"
        );
    }

    #[test]
    fn test_blind_unblind_mem() {
        let mut acc = RsaAccumulator::<RsaGroup>::setup();

        let element = BigUint::from(7usize);
        let ep: BigUint = acc.add(&element);

        for i in 2..5 {
            acc.add(&BigUint::from(i as usize));
        }

        let proof = acc.mem_proof_create(&ep);

        let blinded_proof = acc.blind_mem_proof(&proof);

        assert!(
            blinded_proof.0 != proof,
            "Proof is not blinded successfully"
        );

        let unblinded_proof = acc.unblind_mem_proof(&blinded_proof.0, &blinded_proof.1);
        assert!(
            unblinded_proof == proof,
            "Proof is not unblinded successfully"
        );
    }

    #[test]
    fn test_blind_mem_proof_upd_ver() {
        let mut acc = RsaAccumulator::<RsaGroup>::setup();

        let ep = acc.add(&BigUint::from(200003u32));

        let acct = acc.acc.clone();

        let proof = acc.mem_proof_create(&ep);

        let blinded_proof = acc.blind_mem_proof(&proof);

        let elements_in = vec![
            BigUint::from(65537u32),
            BigUint::from(100003u32),
            BigUint::from(104729u32),
            BigUint::from(1299709u32),
            BigUint::from(15485863u32),
        ];

        let elements_out = vec![];
        for elem in &elements_in {
            acc.add(elem);
        }

        let upd_blind_proof =
            acc.blind_mem_proof_upd(elements_in, elements_out, &acct, &blinded_proof.0);

        assert!(acc.ver_blind_mem_proof_upd(
            &acct,
            &blinded_proof.0,
            &upd_blind_proof.0,
            &upd_blind_proof.1
        ));
    }

    #[test]
    fn test_blind_unblind_non_mem() {
        let mut acc = RsaAccumulator::<RsaGroup>::setup();

        for i in 2..5 {
            acc.add(&BigUint::from(i as usize));
        }

        let non_member = BigUint::from(7usize);

        let blinded_proof = acc.blind_non_mem_proof(&non_member);

        for i in 10..12 {
            acc.add(&BigUint::from(i as usize));
        }

        let upd_blind_non_mem_proof = acc.blind_non_mem_proof_upd(&blinded_proof.0);

        let unblinded_proof = acc.unblind_non_mem_proof(&blinded_proof.1, &upd_blind_non_mem_proof);
        assert!(
            acc.non_mem_ver(&unblinded_proof, &non_member),
            "Non-membership proof should verify after unblinding"
        );
    }

    #[test]
    fn test_blind_non_mem_proof_upd_ver() {
        let mut acc = RsaAccumulator::<RsaGroup>::setup();

        let non_member = BigUint::from(200003u32);

        let blinded_proof = acc.blind_non_mem_proof(&non_member);

        let elements_in = vec![
            BigUint::from(65537u32),
            BigUint::from(100003u32),
            BigUint::from(104729u32),
            BigUint::from(1299709u32),
            BigUint::from(15485863u32),
        ];

        for elem in &elements_in {
            acc.add(elem);
        }

        let acctprime = acc.acc.clone();

        let upd_blind_proof = acc.blind_non_mem_proof_upd(&blinded_proof.0);

        assert!(
            acc.ver_blind_non_mem_proof_upd(&acctprime, &blinded_proof.0, &upd_blind_proof),
            "Couldnt verify"
        );
    }
}
