# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
## [0.1.3] - 2026-08-17

### Added
- Implement bilinear group and accumulator traits for the bilinear accumulator
- Add zeroizing for randomness generation and serializaition for NIZK transcripts *(breaking)*
- Add serialization for proofs and intermediate values
- Add DST for challenge generation
- **nizk**: Replace chaum-pedersen DLEq with Thakur's DLEq proof
- **bilinear**: Optimize memory management
- **nizk**: Optimize memory management
- **cargo**: Add compile time optimizations
- **class**: Update to 128-bit security


### Changed
- Separate low and high level apis *(breaking)*
- Update high level apis for proof creation and updates by taking a vector of elements instead of precomputed deltas *(breaking)*
- Add value_raw and value api for backward compatibility


### Documentation
- Add badges for crates.io and licenses
- Update README.md


### Fixed
- Remove Debug formatting for element_to_bytes
- **benchmarks**: Change base size sweep to inserted elements


### Testing
- Add fuzz/smoke and serde roundtrip tests


## [0.1.1] - 2026-05-04

### Documentation
- Add iacr badge to paper


### Removed
- **benchmarks**: Remove benchmark workflows


## [0.1.0] - 2026-05-04

### Added
- **rsa_acc**: Add trapdoor/trapdoorless separation
- **bilinear_acc**: Add create_mem_proof & mem_ver
- **bilinear_acc**: Implement non-membership proof creation and verification
- **bilinear_acc**: Add blind function signatures for membership and non-membership
- **bilinear_acc**: Update kzg_com to accept optional CRS and implement blind_mem_proof
- **bilinear_acc**: Add blind membership proof update and tests
- Update Cargo.lock with new dependencies and versions
- **benchmarks**: Add new benchmarks for bilinear and rsa accumulator
- **bilinear_acc**: Add non-membership proof blinding, unblinding and update
- *****: Generalize rsa accumulator & add class group instantiation
- **rsa_acc**: Initialize pari in accumulator methods and add tests for membership proofs
- **config**: Add sequential test running for class group
- **accumulator**: Update blind non-membership proof methods to include delta as argument
- **rsa_accumulator**: Implement class_group.rs
- **dependencies**: Add sha2 and hmac crates; update class_group version
- **benchmarks**: Add benchmark for bilinear vs class vs rsa trapdoorless
- **workflow**: Add benchmark workflow for bilinear vs class vs RSA trapdoorless
- **data**: Add performance data for bilinear, class, and RSA trapdoorless proofs
- **benchmarks**: Add RSA trapdoored proofs to bilinear vs class vs RSA trapdoorless benchmarks
- **benchmarks**: Add new benchmarks for blind mem proof updates
- **benchmarks**: Update plotting script and CSV data for RSA trapdoored proofs
- **data**: Add updated benchmark CSV files and plotting script
- **data**: Add new benchmark CSV files and update plotting script for overhead
- **plot**: Add compatibility fix for tikzplotlib
- **nizk**: Add prove and verify methods for PoEEq proofs
- **bilinear**: Update non-membership proof with PoEEq proof and update verification
- **bilinear**: Add q_star parameter to blind_mem_proof_upd and update accordingly
- **figures**: Add Jupyter notebook and load benchmark data
- **cargo.toml**: Add benchmark for bilinear vs class vs rsa
- **benches**: Add new benchmark for O(1) bilinear vs class vs RSA operations
- **data**: Add O(1) mean and variance table for benchmarks
- **nizk**: Refactor PoeEqAndProof structure and update proof methods
- **nizk**: Refactor proof structure and update proof methods in BilinearNIZK
- **case_study**: Add RSA based case study
- **benchmarks**: Update benchmark implementations and CSV data for bilinear proofs
- **figures**: Add updared case study figures for bilinear and RSA
- **rsa**: Add documentation and example for blind non-membership proof update
- **ci**: Add documentation tests to CI workflow
- **rsa**: Refactor blind membership proof update to use delta directly assuming caching
- **nizk**: Add dleq_challenge and poe_eq_challenge methods for benchmarking
- **bench**: Add benchmark for bilinear update breakdown
- **figures**: Add benchmarks and script to visualize update breakdown percentages
- **errors**: Introduce AccumulatorError enum for error handling in accumulator operations
- **accumulator**: Enhance error handling in (non-)membership proofs and update return types to AccumulatorResult
- **example**: Add basic RSA accumulator usage example
- **cargo**: Update package metadata and dependencies in Cargo.toml
- **benchmarks**: Unwrap proofs in benchmark functions for error handling
- **data**: Update performance metrics and add new benchmark results


### Changed
- **bilinear_acc**: Add validation logic for accumulator functions
- **bilinear_acc**: Improve tests and add test cases for membership verification
- **rsa_acc**: Optimize product for mem_proof_create
- **rsa_group, rsa_acc**: Rename 'totient' to 'order'
- **class_group**: Remove redundant ensure_pari_init calls and use pari_init directly
- **accumulator**: Update non-membership proof methods to include product parameter and adjust sample sizes in benchmarks
- **traits**: Remove prod argument from blind_non_mem_proof
- **rsa_group, rsa_accumulator**: Replace KEY_SIZE with MODULUS_SIZE for consistency
- **benchmarks**: Compute all values in a single pass and use black box
- **benchmarks**: Move benchmark_bilinear_vs_class_vs_rsa_trapdoorless to a new file
- **bilinear**: Assume powers_acc_t caching
- **bilinear**: Simplify proof update logic and remove unused variables
- **rsa**: Update variable names
- Update module paths from privacy_preserving_accumulators to private_accumulator_proof_delegation
- *****: Optimize powers_of_gamma_g and add prime sieving
- **benchmarks**: Fix benchmarking logic for bilinear non-mem proof updates


### Documentation
- Extend readme with overview, features and installation steps
- Repository link to placeholder


### Fixed
- **rsa_accumulator**: Switch to safe primes & fix non mem proof
- **nizk.rs**: Do modpow using n
- **nizk.rs**: Raise g & h to the witness
- **rsa_acc**: Add has_to_prime for elem_in
- *****: Run cargo format
- Add Cargo.lock to .gitignore
- **bench**: Format bench_rsa.rs
- Add Cargo.lock to .gitignore
- **rsa_acc**: Fix non-membership proof update, blinding and verification
- **rsa_acc**: Add gcd(q,s)=1 in blind_non_mem_proof
- **bench**: Add group instance
- **.gitignore**: Add .DS_Store to ignore list
- **rsa_acc**: Fix ill-formed tests
- **bench**: Remove element for non_mem_proof_create
- **bench_rsa**: Optimize running time for benchmarks
- **bench_rsa**: Optimize running time for privacy overhead benchmarks
- **benchmark**: Remove previous CSV outputs before running benchmarks
- **workflow**: Update with correct command
- **bench_rsa**: Remove unnecessary product argument from blind_non_mem_proof calls
- **workflow**: Increase timeout for benchmark job to 180 minutes
- **class_group**: Update DISC_SIZE constant
- **benchmarks**: Update bilinear accumulator setup and make non-membership proof interactive
- **.gitignore**: Add 'misc/' directory to ignore list
- **data**: Update performance data for bilinear membership and non-membership proofs
- **workflows**: Change trigger from push to pull_request for benchmark workflows
- **rsa**: Change doctests of mem_proof_upd and ver_mem_proof_upd due to delta change in previous commit
- **rsa**: Change the element addition to the accumulator for memproofupd and vermemproofupd
- **ci**: Remove redundant doc test step from CI workflow


### Testing
- **rsa_acc**: Mirror rsa group instance tests to class group


[0.1.3]: https://github.com/GlaszBoti/private-accumulator-proof-delegation/compare/v0.1.1...v0.1.3
[0.1.1]: https://github.com/GlaszBoti/private-accumulator-proof-delegation/compare/v0.1.0...v0.1.1

