//! Fuzz target: RSA non-membership proof verifier.
//!
//! Feeds arbitrary bytes as `(acc_value, a_sign_byte, a_bytes, b_bytes,
//! element_bytes)` to `non_mem_ver_raw`.  The verifier must never panic.
//!
//! Run with:
//! ```bash
//! cargo +nightly fuzz run fuzz_rsa_non_mem_ver
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;
use num_bigint::{BigInt, BigUint, Sign};
use private_accumulator_proof_delegation::{
    groups::rsa_group::RsaGroup, rsa_accumulator::RsaAccumulator,
};

fuzz_target!(|data: &[u8]| {
    if data.len() < 3 {
        return;
    }

    let acc = RsaAccumulator::<RsaGroup>::setup_from_params(
        BigUint::from(61u32),
        BigUint::from(53u32),
        BigUint::from(2u32),
        Some(BigUint::from(3120u32)),
    );

    // Byte 0: sign of `a` (even → Plus, odd → Minus)
    let sign = if data[0] % 2 == 0 { Sign::Plus } else { Sign::Minus };
    let n = data.len();
    // Split remaining bytes into three equal portions
    let rem = &data[1..];
    let chunk = if rem.is_empty() { 1 } else { (rem.len() / 3).max(1) };

    let a_bytes = if rem.len() >= chunk { &rem[..chunk] } else { &[] as &[u8] };
    let b_bytes = if rem.len() >= 2 * chunk {
        &rem[chunk..2 * chunk]
    } else {
        &[] as &[u8]
    };
    let elem_bytes = if rem.len() >= 2 * chunk { &rem[2 * chunk..] } else { &[] as &[u8] };

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

    // Must not panic.
    let _ = acc.non_mem_ver_raw(&(a, b), &element);
    let _ = n; // suppress unused warning
});
