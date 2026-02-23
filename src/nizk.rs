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
pub struct NIZK {

  pp: BigUint,
  group: RsaGroup,
}

impl NIZK {

  pub fn setup(pp: &BigUint, group: RsaGroup) -> NIZK {
    
    NIZK { 
        pp: pp.clone(),
        group: group,
    }
  }

  pub fn prove_dleq(&mut self, g: &BigUint, u: &BigUint, h: &BigUint, v: &BigUint, w: &BigUint) -> Proof {
    let mut rng = thread_rng();
    let r = rng.gen_biguint(128);
    let a = pow(&g, &r);
    let b = pow(&h, &r);
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

    pub fn verify_dleq(&mut self, g: &BigUint, u: &BigUint, h: &BigUint, v: &BigUint, proof: Proof) -> bool {
        let a = proof.0;
        let b = proof.1;
        let z = proof.2;
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
        let aue = a * pow(u,&e);
        let bve = b * pow(v, &e);
        pow(&g, &z) == aue && pow(&h, &z) == bve
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
    use num_traits::FromPrimitive;

    #[test]
    pub fn test_dleq() {

    }
  }