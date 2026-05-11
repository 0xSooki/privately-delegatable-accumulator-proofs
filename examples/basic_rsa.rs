//! Basic usage of the RSA accumulator: add elements, prove membership and
//! non-membership, then verify.
//!
//! Run with: `cargo run --example basic_rsa --release`

use num_bigint::{BigUint, ToBigInt};
use private_accumulator_proof_delegation::rsa_group::RsaGroup;
use private_accumulator_proof_delegation::RsaAccumulator;

fn main() {
    let mut acc = RsaAccumulator::<RsaGroup>::setup();

    let element = BigUint::from(7u32);
    let ep = acc.add_raw(&element);
    for i in 2u32..5 {
        acc.add_raw(&BigUint::from(i));
    }

    let proof = acc
        .mem_proof_create_raw(&ep)
        .expect("element was just added; proof must exist");
    println!("membership verifies: {}", acc.mem_ver_raw(&proof, &ep));

    let non_element = BigUint::from(383u32);
    let product = acc
        .calculate_product_unreduced()
        .to_bigint()
        .expect("product of positive BigUints is always representable as BigInt");
    let non_proof = acc
        .non_mem_proof_create_raw(&non_element, &product)
        .expect("non-element is coprime with the set product");
    println!(
        "non-membership verifies: {}",
        acc.non_mem_ver_raw(&non_proof, &non_element)
    );
}
