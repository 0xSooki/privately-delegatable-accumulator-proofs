//! Fuzz target: RSA membership proof verifier.
//!
//! Feeds arbitrary bytes as `(acc_value, proof, element)` triplets.
//! Because the values are arbitrary (not cryptographically valid), the
//! verifier should simply return `false` — it must never panic or exhibit
//! undefined behaviour.
//!
//! Run with:
//! ```bash
//! cargo +nightly fuzz run fuzz_rsa_mem_ver
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;
use num_bigint::BigUint;
use private_accumulator_proof_delegation::{
    groups::rsa_group::RsaGroup, rsa_accumulator::RsaAccumulator,
};

/// Split `data` into three roughly equal slices.
fn split3(data: &[u8]) -> (&[u8], &[u8], &[u8]) {
    if data.is_empty() {
        return (&[], &[], &[]);
    }
    let n = data.len();
    let a = n / 3;
    let b = 2 * n / 3;
    (&data[..a], &data[a..b], &data[b..])
}

fuzz_target!(|data: &[u8]| {
    // Use a small, fixed modulus so the test is fast and deterministic.
    // p=61, q=53, g=2, order=3120
    let acc = RsaAccumulator::<RsaGroup>::setup_from_params(
        BigUint::from(61u32),
        BigUint::from(53u32),
        BigUint::from(2u32),
        Some(BigUint::from(3120u32)),
    );

    let (a_bytes, b_bytes, c_bytes) = split3(data);

    // Parse arbitrary bytes as big-endian unsigned integers.
    // Empty byte slice → 0.
    let _acc_val = if a_bytes.is_empty() {
        BigUint::from(0u32)
    } else {
        BigUint::from_bytes_be(a_bytes)
    };
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

    // `mem_ver_raw` must never panic, regardless of inputs.
    // A random proof will almost certainly not verify — that's expected.
    let _ = acc.mem_ver_raw(&proof, &element);
});
