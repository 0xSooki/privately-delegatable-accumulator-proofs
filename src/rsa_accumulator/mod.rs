use crate::traits::Group;
use num_bigint::BigUint;
use rand::thread_rng;
use rand::RngCore;
use std::collections::HashSet;

pub(super) type Aux = ((BigUint, BigUint, BigUint), (BigUint, BigUint, BigUint));
pub(super) type UpdatedBlindProof = ((BigUint, BigUint), Aux, BigUint);

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

        if self.set.insert(x_prime.clone()) {
            self.acc = self.group.exp(&self.acc, &x_prime);
        }

        x_prime
    }

    pub fn mem_ver(&self, proof: &G::Element, element: &G::Exponent) -> bool {
        self.group.exp(proof, element) == self.acc
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
