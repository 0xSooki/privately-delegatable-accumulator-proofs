use num_bigint::{BigUint, RandBigInt};
use rand::thread_rng;
use sha256::digest;
use crate::math::pow;
use crate::rsa_group::RsaGroup;
use crate::traits::Group;

type Proof = (BigUint, BigUint, BigUint);


#[derive(Debug, Clone)]
pub struct Transcript {
  a: BigUint,
  b: BigUint,
  z: BigUint
}

#[derive(Debug, Clone)]
pub struct NIZK<'a> {

  group: &'a RsaGroup,
}

impl NIZK<'_> {

  pub fn setup(group: &RsaGroup) -> NIZK<'_> {
    
    NIZK { 
        group: group,
    }
  }

  pub fn prove_dleq(&self, g: &BigUint, u: &BigUint, h: &BigUint, v: &BigUint, w: &BigUint) -> Proof {
  
    let mut rng = thread_rng();
    let r = rng.gen_biguint(128);
    let a = self.group.exp(&g, &r);
    let b = self.group.exp(&h, &r);

    let g_bytes = g.to_bytes_be();
    let h_bytes = h.to_bytes_be();
    let u_bytes = u.to_bytes_be();
    let v_bytes = v.to_bytes_be();
    let a_bytes = a.to_bytes_be();
    let b_bytes = b.to_bytes_be();

    let parts = [&g_bytes, &h_bytes, &u_bytes, &v_bytes, &a_bytes, &b_bytes];
  
    let mut bytes_data = Vec::with_capacity(parts.iter().map(|p| p.len()).sum());
    for p in parts {
      bytes_data.extend_from_slice(p);
    }

    let e: <RsaGroup as Group>::Exponent = self.group.hash_to_prime(&bytes_data);
    let z = r + e*w;
    (a,b,z)
  }

    pub fn verify_dleq(&mut self, g: &BigUint, u: &BigUint, h: &BigUint, v: &BigUint, proof: &Proof) -> bool {
        let a = &proof.0;
        let b = &proof.1;
        let z = &proof.2;
        let g_bytes = g.to_bytes_be();
        let h_bytes = h.to_bytes_be();
        let u_bytes = u.to_bytes_be();
        let v_bytes = v.to_bytes_be();
        let a_bytes = a.to_bytes_be();
        let b_bytes = b.to_bytes_be();
    
        let parts = [&g_bytes, &h_bytes, &u_bytes, &v_bytes, &a_bytes, &b_bytes];
        let mut bytes_data = Vec::with_capacity(parts.iter().map(|p| p.len()).sum());
    
        for p in parts {
          bytes_data.extend_from_slice(p);
        }
    
        let e: <RsaGroup as Group>::Exponent = self.group.hash_to_prime(&bytes_data);
        let aue = a * self.group.exp(u, &e);
        let bve = b * self.group.exp(v, &e);
        self.group.exp(&g, &z) == aue && self.group.exp(&h, &z) == bve
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
    use num_bigint::BigUint;

    #[test]
    pub fn test_dleq() {
        let pp = BigUint::from(12345u32);
        let group = RsaGroup::new(pp.clone(), pp.clone(), Some(pp));

        let mut nizk = NIZK::setup(&group);
        let modulus = BigUint::from(10007u32);
        let g = BigUint::from(2u32);
        let h = BigUint::from(3u32);

        let w = BigUint::from(42u32);
        let u = g.modpow(&w, &modulus);
        let v = h.modpow(&w, &modulus);

        let proof = nizk.prove_dleq(&g, &u, &h, &v, &w);

        assert!(nizk.verify_dleq(&g, &u, &h, &v, &proof));
    }
  }