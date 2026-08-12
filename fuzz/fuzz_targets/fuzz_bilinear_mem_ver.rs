//! Fuzz target: bilinear (KZG) membership proof verifier.
//!
//! Decodes arbitrary bytes as a compressed G1 point (the proof `pi`) via
//! `ark_serialize`, then calls `mem_ver_raw` against a fixed accumulator.
//! The verifier must never panic regardless of whether deserialization
//! succeeds or fails.
//!
//! Run with:
//! ```bash
//! cargo +nightly fuzz run fuzz_bilinear_mem_ver
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;

use ark_bls12_381::{Bls12_381, Fr, G1Affine};
use ark_serialize::CanonicalDeserialize;
use ark_std::test_rng;
use private_accumulator_proof_delegation::{
    bilinear_accumulator::{BilinearAccumulator, MembershipProof},
};

use std::sync::OnceLock;

static ACC: OnceLock<BilinearAccumulator<Bls12_381>> = OnceLock::new();

fn acc() -> &'static BilinearAccumulator<Bls12_381> {
    ACC.get_or_init(|| {
        let mut rng = test_rng();
        let mut a = BilinearAccumulator::<Bls12_381>::setup(&mut rng, 16);
        // Pre-populate with a few elements
        for i in 1u64..=4 {
            a.add_raw(&Fr::from(i));
        }
        a
    })
}

fuzz_target!(|data: &[u8]| {
    let a = acc();

    let pi: G1Affine = match G1Affine::deserialize_compressed(data) {
        Ok(p) => p,
        Err(_) => return,
    };

    let proof = MembershipProof::<Bls12_381> { pi };

    let element = Fr::from(999u64);

    let _ = a.mem_ver_raw(&proof, element);
});
