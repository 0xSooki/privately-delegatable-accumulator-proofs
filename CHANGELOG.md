# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.2.0] - 2026-06-06

### Breaking Changes

- **Separated low- and high-level APIs.** Raw/internal methods are now in a distinct
  layer from the high-level trait-based API. Callers that previously mixed both
  layers will need to choose one or import the appropriate trait.
- **High-level proof creation and update methods now take `Vec<Element>`** instead of
  a caller-precomputed delta. The delta is now computed internally.
- **Zeroizing added to randomness buffers and NIZK transcript serialization.**
  Types that previously implemented `Clone` freely may now require explicit handling
  of zeroized memory.
- **`serde` format changed.** `BigUint` and `BigInt` values now serialize using
  `num-bigint`'s built-in serde support (digit arrays) instead of the previous
  custom hex-string encoding. Persisted data from pre-release development builds
  is not compatible.

### Added

- Bilinear group and accumulator trait implementations (`Group`, `Accumulator`,
  `PrivatelyDelegatableAccumulator`) for the KZG/BLS12-381 backend.
- `serde` feature: `Serialize`/`Deserialize` for all RSA proof types
  (`RsaMembershipProof`, `RsaNonMembershipProof`, `RsaBlindedMembershipProof`,
  `RsaBlindedNonMembershipProof`, `RsaDleqProof`, `RsaNizkAux`,
  `RsaUpdatedBlindedMembershipProof`, `RsaUpdatedBlindedNonMembershipProof`)
  and for `AccumulatorError`.
- `value()` / `value_raw()` accessor methods on `RsaAccumulator` for reading the
  current accumulator element without accessing the field directly.
- Four `cargo-fuzz` targets: `fuzz_rsa_mem_ver`, `fuzz_rsa_non_mem_ver`,
  `fuzz_rsa_delegation_roundtrip`, `fuzz_bilinear_mem_ver`.
- Smoke test suite (`tests/fuzz_smoke.rs`) that exercises the fuzz target invariants
  against a fixed corpus so they run under `cargo test` without a nightly toolchain.
- Serde roundtrip integration tests (`tests/serde_roundtrip.rs`) for all RSA proof
  types and bilinear ark-serialize round-trips.

### Fixed

- Benchmark binaries failed to compile after the `.value()` API change introduced a
  borrow-checker conflict (`&Element` held across a mutable borrow). Fixed by
  copying the owned value immediately (`*acc.value()`).
- `bench_o1_bilinear_vs_class_vs_rsa` was missing the `Accumulator` trait import
  required to call `.value()`.

### Removed

- `serde_impls` module (`src/serde_impls.rs`) and its custom hex-string serializers
  for `BigUint`/`BigInt`. Replaced by enabling the `"serde"` feature of `num-bigint`.

---

## [0.1.1] - 2026-05-04

### Added

- IACR ePrint badge in README.

### Removed

- Benchmark CI workflows (benchmarks are run locally).

---

## [0.1.0] - 2026-05-04

Initial public release.

### Added

- RSA-group accumulator with membership and non-membership proofs.
- Privacy-preserving (blinded) proof delegation protocol with NIZK verification.
- Class-group backend (behind the `class-group` feature flag).
- KZG/bilinear-pairing accumulator (behind the `bilinear` feature flag).
- `AccumulatorError` enum with structured error handling across all proof operations.
- `basic_rsa.rs` usage example.
- Optimized `powers_of_gamma_g` computation and prime sieving.
- Criterion benchmark suite.

[Unreleased]: https://github.com/GlaszBoti/private-accumulator-proof-delegation/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/GlaszBoti/private-accumulator-proof-delegation/compare/v0.1.1...v1.2.0
[0.1.1]: https://github.com/GlaszBoti/private-accumulator-proof-delegation/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/GlaszBoti/private-accumulator-proof-delegation/releases/tag/v0.1.0
