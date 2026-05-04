# private-accumulator-proof-delegation

Cryptographic accumulators with privately delegatable proof updates in Rust. Supports RSA, class-group, and bilinear constructions.

[![GitHub Actions](https://github.com/GlaszBoti/private-accumulator-proof-delegation/actions/workflows/rust.yml/badge.svg)](https://github.com/GlaszBoti/private-accumulator-proof-delegation/actions)
[![Documentation](https://docs.rs/private-accumulator-proof-delegation/badge.svg)](https://docs.rs/private-accumulator-proof-delegation)
[![IACR ePrint](https://img.shields.io/badge/IACR%20ePrint-2026%2F832-blue)](https://eprint.iacr.org/2026/832)

## Documentation

Clone the repository and run `cd privacy-preserving-accumulator-proofs/ && cargo doc --open`

## Add `private-accumulator-proof-delegation` to your repository

```toml
[dependencies]
private-accumulator-proof-delegation = "0.1.0"
```

## Example

```rust
use num_bigint::{BigUint, ToBigInt};
use private_accumulator_proof_delegation::rsa_group::RsaGroup;
use private_accumulator_proof_delegation::RsaAccumulator;

let mut acc = RsaAccumulator::<RsaGroup>::setup();

// Add elements to the accumulator
let element = BigUint::from(7u32);
let ep = acc.add(&element);
for i in 2u32..5 {
    acc.add(&BigUint::from(i));
}

// Prove and verify membership
let proof = acc
    .mem_proof_create(&ep)
    .expect("element was just added; proof must exist");
assert!(acc.mem_ver(&proof, &ep));

// Prove and verify non-membership
let non_element = BigUint::from(383u32);
let product = acc.calculate_product_unreduced().to_bigint().unwrap();
let non_proof = acc
    .non_mem_proof_create(&non_element, &product)
    .expect("non-element is coprime with the set product");
assert!(acc.non_mem_ver(&non_proof, &non_element));
```

A runnable version lives in [`examples/basic_rsa.rs`](examples/basic_rsa.rs):

```bash
cargo run --example basic_rsa --release
```

## Running the tests

```bash
cargo test
```

The default features (`rsa`, `bilinear`) require no system dependencies. The optional `class-group` feature pulls in `class_group`/`curv-kzen` and requires GMP and PARI to be installed (`brew install gmp pari` on macOS, `apt-get install libgmp-dev pari-gp` on Debian/Ubuntu):

```bash
cargo test --features class-group
```

## Features

- **RSA accumulator** — membership and non-membership proofs in groups of unknown order.
- **Class-group instantiation** — a trapdoorless alternative to RSA: no trusted setup, at the cost of larger group elements and slower operations.
- **Bilinear accumulator** — KZG-style construction over BLS12-381.
- **Privacy-preserving update delegation** — clients blind their proofs before sending them to an untrusted server, the server updates the blinded proof, and the client verifies the work via NIZK proofs of discrete-log equality and unblinds to recover a valid up-to-date proof. The server learns nothing about the underlying element.
- **Cargo features** to opt into individual constructions: `rsa` and `bilinear` are on by default; enable `class-group` for the trapdoorless variant.

## Benchmarks

```bash
cargo bench
```

Plotting helpers in `figures/` reproduce the benchmark figures from the accompanying paper. They require Python with `pandas`, `matplotlib`, and `seaborn` installed.

## Acknowledgements

This library builds on the work of the [arkworks](https://github.com/arkworks-rs) ecosystem (`ark-ec`, `ark-ff`, `ark-poly-commit`, `ark-bls12-381`), the [`class_group`](https://crates.io/crates/class_group) and [`curv-kzen`](https://crates.io/crates/curv-kzen) crates for class-group arithmetic, and [`glass_pumpkin`](https://crates.io/crates/glass_pumpkin) for safe-prime generation.
