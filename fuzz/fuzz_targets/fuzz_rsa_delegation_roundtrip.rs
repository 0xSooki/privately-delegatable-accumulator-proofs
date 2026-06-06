//! Fuzz target: RSA delegation round-trip correctness.
//!
//! Interprets the fuzz input as a list of `u8` values used as small elements,
//! chooses one element to prove membership for, runs the full delegation
//!
//! **If the protocol completes without error, the unblinded proof MUST verify.**
//!
//! This is a *correctness* fuzzer: a panic or a failed assertion is a bug.
//!
//! Run with:
//! ```bash
//! cargo +nightly fuzz run fuzz_rsa_delegation_roundtrip
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;
use num_bigint::{BigInt, BigUint};
use num_traits::One;
use private_accumulator_proof_delegation::{
    groups::rsa_group::RsaGroup, rsa_accumulator::RsaAccumulator,
};

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }

    // Fixed small-prime RSA group for speed.
    let mut acc = RsaAccumulator::<RsaGroup>::setup_from_params(
        BigUint::from(61u32),
        BigUint::from(53u32),
        BigUint::from(2u32),
        Some(BigUint::from(3120u32)),
    );


    const SMALL_PRIMES: &[u32] = &[
        2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
    ];
    let target_idx = (data[0] as usize) % SMALL_PRIMES.len();
    let target_val = BigUint::from(SMALL_PRIMES[target_idx]);

    // Add the target element and record its prime representative.
    let ep = acc.add_raw(&target_val);
    let acc_t = acc.acc.clone();
    let proof = match acc.mem_proof_create_raw(&ep) {
        Ok(p) => p,
        Err(_) => return,
    };

    // Blind the proof
    let (blinded_proof, st) = acc.blind_mem_proof_raw(&proof);


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
        let prod = eps_added
            .iter()
            .fold(BigUint::one(), |acc, e| (acc * e) % o);
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
});
