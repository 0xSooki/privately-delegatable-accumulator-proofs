//! Smoke tests that exercise the same logic as the `cargo-fuzz` targets but
//! with a small fixed corpus, so they run under `cargo test` in CI without
//! requiring a nightly toolchain or the `libfuzzer-sys` crate.
//!
//! Each test validates the fuzz harness invariants on a handful of
//! representative inputs, catching regressions before they reach the fuzzer.

use num_bigint::{BigInt, BigUint, Sign};
use num_traits::One;
use private_accumulator_proof_delegation::{
    groups::rsa_group::RsaGroup, rsa_accumulator::RsaAccumulator,
};

fn small_acc() -> RsaAccumulator<RsaGroup> {
    RsaAccumulator::<RsaGroup>::setup_from_params(
        BigUint::from(61u32),
        BigUint::from(53u32),
        BigUint::from(2u32),
        Some(BigUint::from(3120u32)),
    )
}

/// Mirrors the `fuzz_rsa_mem_ver` invariant: `mem_ver_raw` must not panic.
fn smoke_mem_ver(data: &[u8]) {
    fn split3(data: &[u8]) -> (&[u8], &[u8], &[u8]) {
        if data.is_empty() {
            return (&[], &[], &[]);
        }
        let n = data.len();
        (&data[..n / 3], &data[n / 3..2 * n / 3], &data[2 * n / 3..])
    }

    let acc = small_acc();
    let (_, b_bytes, c_bytes) = split3(data);
    let proof = if b_bytes.is_empty() {
        BigUint::from(0u32)
    } else {
        BigUint::from_bytes_be(b_bytes)
    };
    let element = if c_bytes.is_empty() {
        BigUint::from(1u32)
    } else {
        BigUint::from_bytes_be(c_bytes)
    };
    let _ = acc.mem_ver_raw(&proof, &element);
}

#[test]
fn smoke_mem_ver_all_zeros() {
    smoke_mem_ver(&[0u8; 12]);
}
#[test]
fn smoke_mem_ver_all_ones() {
    smoke_mem_ver(&[0xffu8; 12]);
}
#[test]
fn smoke_mem_ver_empty() {
    smoke_mem_ver(&[]);
}
#[test]
fn smoke_mem_ver_valid_proof() {
    let mut acc = small_acc();
    let ep = acc.add_raw(&BigUint::from(7u32));
    let proof = acc.mem_proof_create_raw(&ep).unwrap();
    // A legitimate proof must verify
    assert!(acc.mem_ver_raw(&proof, &ep));
    // Smoke the no-panic invariant with its bytes
    let proof_bytes = proof.to_bytes_be();
    smoke_mem_ver(&proof_bytes);
}
#[test]
fn smoke_mem_ver_wrong_proof() {
    let mut acc = small_acc();
    let ep = acc.add_raw(&BigUint::from(7u32));
    let proof = acc.mem_proof_create_raw(&ep).unwrap();
    // Mutate: increment proof by 1
    let wrong = &proof + BigUint::one();
    assert!(!acc.mem_ver_raw(&wrong, &ep));
}

fn smoke_non_mem_ver(data: &[u8]) {
    if data.len() < 3 {
        return;
    }
    let acc = small_acc();
    let sign = if data[0] % 2 == 0 {
        Sign::Plus
    } else {
        Sign::Minus
    };
    let rem = &data[1..];
    let chunk = (rem.len() / 3).max(1);
    let a_bytes = if rem.len() >= chunk {
        &rem[..chunk]
    } else {
        &[]
    };
    let b_bytes = if rem.len() >= 2 * chunk {
        &rem[chunk..2 * chunk]
    } else {
        &[]
    };
    let elem_bytes = if rem.len() >= 2 * chunk {
        &rem[2 * chunk..]
    } else {
        &[]
    };

    let a_mag = if a_bytes.is_empty() {
        BigUint::from(0u32)
    } else {
        BigUint::from_bytes_be(a_bytes)
    };
    let a = BigInt::from_biguint(sign, a_mag);
    let b = if b_bytes.is_empty() {
        BigUint::from(1u32)
    } else {
        BigUint::from_bytes_be(b_bytes)
    };
    let element = if elem_bytes.is_empty() {
        BigUint::from(1u32)
    } else {
        BigUint::from_bytes_be(elem_bytes)
    };
    let _ = acc.non_mem_ver_raw(&(a, b), &element);
}

#[test]
fn smoke_non_mem_ver_zeros() {
    smoke_non_mem_ver(&[0u8; 15]);
}
#[test]
fn smoke_non_mem_ver_ones() {
    smoke_non_mem_ver(&[0xffu8; 15]);
}
#[test]
fn smoke_non_mem_ver_valid() {
    let mut acc = small_acc();
    acc.add_raw(&BigUint::from(2u32));
    acc.add_raw(&BigUint::from(3u32));
    let non_member = BigUint::from(5u32);
    use num_bigint::ToBigInt;
    let product = acc.calculate_product_unreduced().to_bigint().unwrap();
    let proof = acc.non_mem_proof_create_raw(&non_member, &product).unwrap();
    assert!(acc.non_mem_ver_raw(&proof, &non_member));
}

const SMALL_PRIMES: &[u32] = &[
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
];

fn smoke_delegation(data: &[u8]) {
    if data.len() < 2 {
        return;
    }

    let mut acc = small_acc();

    let target_idx = (data[0] as usize) % SMALL_PRIMES.len();
    let target_val = BigUint::from(SMALL_PRIMES[target_idx]);

    let ep = acc.add_raw(&target_val);
    let acc_t = acc.acc.clone();
    let proof = match acc.mem_proof_create_raw(&ep) {
        Ok(p) => p,
        Err(_) => return,
    };

    let (blinded_proof, _st) = acc.blind_mem_proof_raw(&proof);

    let mut eps_added: Vec<BigUint> = Vec::new();
    for &byte in &data[1..] {
        let idx = (byte as usize) % SMALL_PRIMES.len();
        let val = BigUint::from(SMALL_PRIMES[idx]);
        if val != target_val {
            let ep2 = acc.add_raw(&val);
            eps_added.push(ep2);
        }
    }

    if eps_added.is_empty() {
        return;
    }

    let delta_int = if let Some(o) = acc.group.order() {
        let prod = eps_added.iter().fold(BigUint::one(), |a, e| (a * e) % o);
        BigInt::from(prod)
    } else {
        BigInt::from(eps_added.iter().fold(BigUint::one(), |a, e| a * e))
    };

    let upd = match acc.blind_mem_proof_upd_raw(&acc_t, &blinded_proof, &delta_int) {
        Ok(u) => u,
        Err(_) => return,
    };

    let nizk_ok = acc.ver_blind_mem_proof_upd_raw(&acc_t, &blinded_proof, &upd.0, &upd.1);
    assert!(
        nizk_ok,
        "NIZK verification failed for a legitimately executed update"
    );
}

#[test]
fn smoke_delegation_corpus_a() {
    // target=2, add 3 then 5
    smoke_delegation(&[0u8, 1, 2]);
}
#[test]
fn smoke_delegation_corpus_b() {
    // target=7, add 11, 13, 17
    smoke_delegation(&[3u8, 4, 5, 6]);
}
#[test]
fn smoke_delegation_corpus_c() {
    // target=41, add many primes
    smoke_delegation(&[15u8, 0, 1, 2, 3, 4, 5, 6, 7, 8]);
}
#[test]
fn smoke_delegation_empty_additions() {
    smoke_delegation(&[5u8]);
}
#[test]
fn smoke_delegation_all_same_as_target() {
    smoke_delegation(&[0u8, 0, 0, 0]);
}

#[cfg(feature = "bilinear")]
mod bilinear_smoke {
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_serialize::CanonicalDeserialize;
    use ark_std::test_rng;
    use private_accumulator_proof_delegation::bilinear_accumulator::{
        BilinearAccumulator, MembershipProof,
    };

    fn acc_with_elements() -> BilinearAccumulator<Bls12_381> {
        let mut rng = test_rng();
        let mut a = BilinearAccumulator::<Bls12_381>::setup(&mut rng, 16);
        for i in 1u64..=4 {
            a.add_raw(&Fr::from(i));
        }
        a
    }

    fn smoke_bilinear_mem_ver(data: &[u8]) {
        let a = acc_with_elements();
        use ark_bls12_381::G1Affine;
        let pi: G1Affine = match G1Affine::deserialize_compressed(data) {
            Ok(p) => p,
            Err(_) => return,
        };
        let proof = MembershipProof::<Bls12_381> { pi };
        let _ = a.mem_ver_raw(&proof, Fr::from(999u64));
    }

    #[test]
    fn smoke_bilinear_zeros() {
        smoke_bilinear_mem_ver(&[0u8; 48]);
    }

    #[test]
    fn smoke_bilinear_short_input() {
        smoke_bilinear_mem_ver(&[0u8; 4]);
    }

    #[test]
    fn smoke_bilinear_valid_proof() {
        let mut rng = test_rng();
        let mut a = BilinearAccumulator::<Bls12_381>::setup(&mut rng, 16);
        let e = Fr::from(42u64);
        a.add_raw(&e);
        let proof = a.mem_proof_create_raw(e).expect("in set");
        // A valid proof for a member must verify
        assert!(a.mem_ver_raw(&proof, e));
        // And a valid proof for a non-member must not
        assert!(!a.mem_ver_raw(&proof, Fr::from(99u64)));
    }
}
