use ark_bls12_381::{Bls12_381, Fr};
use ark_std::{test_rng, time::Duration};
use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use num_bigint::BigUint;
use num_traits::ToPrimitive;
use privacy_preserving_accumulators::{
    groups::RsaGroup, BilinearAccumulator, Group, RsaAccumulator,
};

fn benchmark_blind_mem_proof(c: &mut Criterion) {
    let mut group = c.benchmark_group("membership_proofs");

    group.sample_size(100);

    let element = BigUint::from(7 as usize);

    group.bench_function("blind_mem_proof", |b| {
        b.iter_batched(
            || {
                let mut acc = RsaAccumulator::<RsaGroup>::setup();

                let ep: BigUint = acc.add(&element);

                for i in 2..5 {
                    acc.add(&BigUint::from(i as usize));
                }

                let proof = acc.mem_proof_create(&ep);

                (acc, proof)
            },
            |(acc, proof)| {
                acc.blind_mem_proof(&proof);
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

fn benchmark_unblind_mem_proof(c: &mut Criterion) {
    let mut group = c.benchmark_group("membership_proofs");

    group.sample_size(100);

    group.bench_function("unblind_mem_proof", |b| {
        b.iter_batched(
            || {
                let mut acc = RsaAccumulator::<RsaGroup>::setup();

                let element = BigUint::from(7 as usize);
                let ep: BigUint = acc.add(&element);

                for i in 2..5 {
                    acc.add(&BigUint::from(i as usize));
                }

                let proof = acc.mem_proof_create(&ep);

                let blinded_proof = acc.blind_mem_proof(&proof);

                (acc, blinded_proof)
            },
            |(acc, blindedproof)| {
                acc.unblind_mem_proof(&blindedproof.0, &blindedproof.1);
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

fn benchmark_ver_blind_mem_proof_upd(c: &mut Criterion) {
    let mut group = c.benchmark_group("membership_proofs");

    group.sample_size(100);

    group.measurement_time(Duration::from_secs(10));

    group.bench_function("ver_blind_mem_proof_upd", |b| {
        b.iter_batched(
            || {
                let mut acc = RsaAccumulator::<RsaGroup>::setup();

                let ep = acc.add(&BigUint::from(200003u32));

                let acct = acc.acc.clone();

                let proof = acc.mem_proof_create(&ep);

                let blinded_proof = acc.blind_mem_proof(&proof);

                let elements_in = vec![
                    BigUint::from(65537u32),
                    BigUint::from(100003u32),
                    BigUint::from(104729u32),
                    BigUint::from(1299709u32),
                    BigUint::from(15485863u32),
                ];

                let elements_out = vec![];
                for elem in &elements_in {
                    acc.add(&elem);
                }

                let updated_blind_proof =
                    acc.blind_mem_proof_upd(elements_in, elements_out, &acct, &blinded_proof.0);

                (acc, acct, blinded_proof, updated_blind_proof)
            },
            |(acc, acct, blindedproof, updated_blind_proof)| {
                acc.ver_blind_mem_proof_upd(
                    &acct,
                    &blindedproof.0,
                    &updated_blind_proof.0,
                    &updated_blind_proof.1,
                )
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

fn benchmark_blind_mem_proof_upd(c: &mut Criterion) {
    let mut group = c.benchmark_group("membership_proofs");

    group.sample_size(10);

    group.measurement_time(Duration::from_secs(10));

    let sizes = [10, 200, 400, 600, 800, 1000];

    for size in sizes.iter() {
        group.bench_with_input(
            BenchmarkId::new("blind_mem_proof_upd", size),
            size,
            |b, &n| {
                b.iter_batched(
                    || {
                        let mut acc = RsaAccumulator::<RsaGroup>::setup();

                        let ep = acc.add(&BigUint::from(200003u32));

                        let acct = acc.acc.clone();

                        let proof = acc.mem_proof_create(&ep);

                        let blinded_proof = acc.blind_mem_proof(&proof);

                        let mut elements_in = Vec::new();

                        for i in 0..n {
                            let elem = BigUint::from(i as u64);
                            elements_in.push(elem);
                        }

                        let elements_out = vec![];
                        for elem in &elements_in {
                            acc.add(&elem);
                        }

                        (acc, elements_in, elements_out, acct, blinded_proof)
                    },
                    |(acc, elements_in, elements_out, acct, blinded_proof)| {
                        acc.blind_mem_proof_upd(elements_in, elements_out, &acct, &blinded_proof.0);
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

fn benchmark_blind_non_mem_proof(c: &mut Criterion) {
    let mut group = c.benchmark_group("non_membership_proofs");

    group.sample_size(100);

    group.bench_function("blind_non_mem_proof", |b| {
        b.iter_batched(
            || {
                let mut acc = RsaAccumulator::<RsaGroup>::setup();

                for i in 2..5 {
                    acc.add(&BigUint::from(i as usize));
                }

                let non_member = BigUint::from(7 as usize);

                (acc, non_member)
            },
            |(acc, non_member)| {
                acc.blind_non_mem_proof(&non_member);
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

fn benchmark_unblind_non_mem_proof(c: &mut Criterion) {
    let mut group = c.benchmark_group("non_membership_proofs");

    group.sample_size(100);

    group.bench_function("unblind_non_mem_proof", |b| {
        b.iter_batched(
            || {
                let mut acc = RsaAccumulator::<RsaGroup>::setup();

                for i in 2..5 {
                    acc.add(&BigUint::from(i as usize));
                }

                let non_member = BigUint::from(7 as usize);

                let blinded_proof = acc.blind_non_mem_proof(&non_member);

                for i in 10..12 {
                    acc.add(&BigUint::from(i as usize));
                }

                let upd_blind_non_mem_proof = acc.blind_non_mem_proof_upd(&blinded_proof.0);

                (acc, blinded_proof, upd_blind_non_mem_proof)
            },
            |(acc, blindedproof, upd_blind_non_mem_proof)| {
                acc.unblind_non_mem_proof(&blindedproof.1, &upd_blind_non_mem_proof);
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

fn benchmark_ver_blind_non_mem_proof_upd(c: &mut Criterion) {
    let mut group = c.benchmark_group("non_membership_proofs");

    group.sample_size(100);

    group.measurement_time(Duration::from_secs(10));

    group.bench_function("ver_blind_non_mem_proof_upd", |b| {
        b.iter_batched(
            || {
                let mut acc = RsaAccumulator::<RsaGroup>::setup();

                let non_member = BigUint::from(200003u32);

                let blinded_proof = acc.blind_non_mem_proof(&non_member);

                let elements_in = vec![
                    BigUint::from(65537u32),
                    BigUint::from(100003u32),
                    BigUint::from(104729u32),
                    BigUint::from(1299709u32),
                    BigUint::from(15485863u32),
                ];

                for elem in &elements_in {
                    acc.add(&elem);
                }

                let acct_prime = acc.acc.clone();

                let updated_blind_proof = acc.blind_non_mem_proof_upd(&blinded_proof.0);

                (acc, acct_prime, blinded_proof, updated_blind_proof)
            },
            |(acc, acct_prime, blindedproof, updated_blind_proof)| {
                acc.ver_blind_non_mem_proof_upd(&acct_prime, &blindedproof.0, &updated_blind_proof)
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

fn benchmark_blind_non_mem_proof_upd(c: &mut Criterion) {
    let mut group = c.benchmark_group("non_membership_proofs");

    group.sample_size(10);

    group.measurement_time(Duration::from_secs(10));

    let sizes = [10, 200, 400, 600, 800, 1000];

    for size in sizes.iter() {
        group.bench_with_input(
            BenchmarkId::new("blind_non_mem_proof_upd", size),
            size,
            |b, &n| {
                b.iter_batched(
                    || {
                        let mut acc = RsaAccumulator::<RsaGroup>::setup();

                        let non_member = BigUint::from(200003u32);

                        let blinded_non_mem_proof = acc.blind_non_mem_proof(&non_member);

                        let mut elements_in = Vec::new();

                        for i in 0..n {
                            let elem = BigUint::from(i as u64);
                            elements_in.push(elem);
                        }

                        //let elements_out: Vec<BigUint> = vec![];
                        for elem in &elements_in {
                            acc.add(&elem);
                        }

                        (acc, blinded_non_mem_proof)
                    },
                    |(acc, blinded_non_mem_proof)| {
                        acc.blind_non_mem_proof_upd(&blinded_non_mem_proof.0);
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

fn benchmark_accumulator_compare(c: &mut Criterion) {
    let mut group = c.benchmark_group("accumulator_compare");

    group.sample_size(50);

    let sizes = [10usize, 100, 500];

    for size in sizes.iter() {
        group.bench_with_input(BenchmarkId::new("rsa_add_n", size), size, |b, &n| {
            b.iter_batched(
                || {
                    let mut acc = RsaAccumulator::<RsaGroup>::setup();
                    let elements: Vec<BigUint> = (1u64..=n as u64).map(BigUint::from).collect();
                    (acc, elements)
                },
                |(mut acc, elements)| {
                    for elem in elements {
                        acc.add(&elem);
                    }
                },
                BatchSize::SmallInput,
            );
        });

        group.bench_with_input(BenchmarkId::new("bilinear_add_n", size), size, |b, &n| {
            b.iter_batched(
                || {
                    let mut rng = test_rng();
                    let mut acc = BilinearAccumulator::<Bls12_381>::setup(&mut rng, n + 1);
                    let elements: Vec<Fr> = (1u64..=n as u64).map(Fr::from).collect();
                    (acc, elements)
                },
                |(mut acc, elements)| {
                    for elem in elements {
                        acc.add(&elem);
                    }
                },
                BatchSize::SmallInput,
            );
        });

        group.bench_with_input(BenchmarkId::new("rsa_mem_proof", size), size, |b, &n| {
            b.iter_batched(
                || {
                    let mut acc = RsaAccumulator::<RsaGroup>::setup();
                    let mut target_prime = None;
                    for i in 1u64..=n as u64 {
                        let prime = acc.add(&BigUint::from(i));
                        if i == 1 {
                            target_prime = Some(prime);
                        }
                    }
                    (acc, target_prime.expect("target prime"))
                },
                |(mut acc, target_prime)| {
                    let proof = acc.mem_proof_create(&target_prime);
                    let _ = acc.mem_ver(&proof, &target_prime);
                },
                BatchSize::SmallInput,
            );
        });

        group.bench_with_input(
            BenchmarkId::new("bilinear_mem_proof", size),
            size,
            |b, &n| {
                b.iter_batched(
                    || {
                        let mut rng = test_rng();
                        let mut acc = BilinearAccumulator::<Bls12_381>::setup(&mut rng, n + 1);
                        let target = Fr::from(1u64);
                        for i in 1u64..=n as u64 {
                            let element = Fr::from(i);
                            acc.add(&element);
                        }
                        (acc, target)
                    },
                    |(acc, target)| {
                        let proof = acc.mem_proof_create(target).expect("membership proof");
                        let _ = acc.mem_ver(&proof, target);
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

fn benchmark_trapdoored_vs_trapdoorless_accumulator(c: &mut Criterion) {
    let mut group = c.benchmark_group("trapdoored_vs_trapdoorless_accumulator");

    group.sample_size(25);

    let sizes = [8usize, 16, 32, 64, 128, 256, 512, 1024];

    for size in sizes.iter() {
        group.bench_with_input(
            BenchmarkId::new("trapdoored_non_mem_blind_proof_upd", size),
            size,
            |b, &n| {
                b.iter_batched(
                    || {
                        let mut acc = RsaAccumulator::<RsaGroup>::setup();
                        let non_member = BigUint::from(200003u64);

                        let blinded_non_mem_proof = acc.blind_non_mem_proof(&non_member);

                        let mut elements_in = Vec::new();

                        for i in 0..n {
                            let i_bytes = i.to_be_bytes();
                            let prime = acc.group.hash_to_prime(&i_bytes);
                            let elem = BigUint::from(prime);
                            elements_in.push(elem);
                        }

                        //let elements_out: Vec<BigUint> = vec![];
                        for elem in &elements_in {
                            acc.add(&elem);
                        }

                        (acc, blinded_non_mem_proof)
                    },
                    |(acc, blinded_non_mem_proof)| {
                        acc.blind_non_mem_proof_upd(&blinded_non_mem_proof.0);
                    },
                    BatchSize::SmallInput,
                );
            },
        );

        group.bench_with_input(
            BenchmarkId::new("trapdoorless_non_mem_blind_proof_upd", size),
            size,
            |b, &n| {
                b.iter_batched(
                    || {
                        let mut acc = RsaAccumulator::setup_trapdoorless();
                        let non_member = BigUint::from(200003u32);

                        let blinded_non_mem_proof = acc.blind_non_mem_proof(&non_member);

                        let mut elements_in = Vec::new();

                        for i in 0..n {
                            let i_bytes = i.to_be_bytes();
                            let prime = acc.group.hash_to_prime(&i_bytes);
                            let elem = BigUint::from(prime);
                            elements_in.push(elem);
                        }

                        //let elements_out: Vec<BigUint> = vec![];
                        for elem in &elements_in {
                            acc.add(&elem);
                        }

                        (acc, blinded_non_mem_proof)
                    },
                    |(acc, blinded_non_mem_proof)| {
                        acc.blind_non_mem_proof_upd(&blinded_non_mem_proof.0);
                    },
                    BatchSize::SmallInput,
                );
            },
        );

        group.bench_with_input(
            BenchmarkId::new("trapdoored_mem_proof_create", size),
            size,
            |b, &n| {
                b.iter_batched(
                    || {
                        let mut acc = RsaAccumulator::<RsaGroup>::setup();
                        let element = BigUint::from(200003u64);
                        let ep = acc.add(&element);

                        let mut elements_in = Vec::new();

                        for i in 0..n {
                            let i_bytes = i.to_be_bytes();
                            let prime = acc.group.hash_to_prime(&i_bytes);
                            let elem = BigUint::from(prime);
                            elements_in.push(elem);
                        }

                        for elem in &elements_in {
                            acc.add(&elem);
                        }

                        (acc, ep)
                    },
                    |(mut acc, ep)| {
                        acc.mem_proof_create(&ep);
                    },
                    BatchSize::SmallInput,
                );
            },
        );

        group.bench_with_input(
            BenchmarkId::new("trapdoorless_mem_proof_create", size),
            size,
            |b, &n| {
                b.iter_batched(
                    || {
                        let mut acc = RsaAccumulator::setup_trapdoorless();
                        let element = BigUint::from(200003u64);
                        let ep = acc.add(&element);

                        let mut elements_in = Vec::new();

                        for i in 0..n {
                            let i_bytes = i.to_be_bytes();
                            let prime = acc.group.hash_to_prime(&i_bytes);
                            let elem = BigUint::from(prime);
                            elements_in.push(elem);
                        }

                        for elem in &elements_in {
                            acc.add(&elem);
                        }

                        (acc, ep)
                    },
                    |(mut acc, ep)| {
                        acc.mem_proof_create(&ep);
                    },
                    BatchSize::SmallInput,
                );
            },
        );

        group.bench_with_input(
            BenchmarkId::new("trapdoored_non_mem_proof_create", size),
            size,
            |b, &n| {
                b.iter_batched(
                    || {
                        let mut acc = RsaAccumulator::<RsaGroup>::setup();
                        let non_element = BigUint::from(200003u64);

                        let mut elements_in = Vec::new();

                        for i in 0..n {
                            let i_bytes = i.to_be_bytes();
                            let prime = acc.group.hash_to_prime(&i_bytes);
                            let elem = BigUint::from(prime);
                            elements_in.push(elem);
                        }

                        for elem in &elements_in {
                            acc.add(&elem);
                        }
                        // TODO calculate s* and pass to non_mem_proof_create as a paramater

                        (acc, non_element)
                    },
                    |(acc, non_element)| {
                        acc.non_mem_proof_create(&non_element);
                    },
                    BatchSize::SmallInput,
                );
            },
        );

        group.bench_with_input(
            BenchmarkId::new("trapdoorless_non_mem_proof_create", size),
            size,
            |b, &n| {
                b.iter_batched(
                    || {
                        let mut acc = RsaAccumulator::setup_trapdoorless();
                        let non_element = BigUint::from(200003u64);

                        let mut elements_in = Vec::new();

                        for i in 0..n {
                            let i_bytes = i.to_be_bytes();
                            let prime = acc.group.hash_to_prime(&i_bytes);
                            let elem = BigUint::from(prime);
                            elements_in.push(elem);
                        }

                        for elem in &elements_in {
                            acc.add(&elem);
                        }

                        (acc, non_element)
                    },
                    |(acc, non_element)| {
                        acc.non_mem_proof_create(&non_element);
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

fn benchmark_privacy_overhead_trapdoored(c: &mut Criterion) {
    let mut group = c.benchmark_group("trapdoored_privacy_overhead");

    group.sample_size(25);

    let sizes = [8usize, 16, 32, 64, 128, 256, 512, 1024];

    for size in sizes.iter() {
        group.bench_with_input(
            BenchmarkId::new("non_mem_proof_standard", size),
            size,
            |b, &n| {
                b.iter_batched(
                    || {
                        let mut acc = RsaAccumulator::<RsaGroup>::setup();
                        let non_member = BigUint::from(200003u64);

                        let mut elements = Vec::new();

                        for i in 0..n {
                            let i_bytes = i.to_be_bytes();
                            let prime = acc.group.hash_to_prime(&i_bytes);
                            let elem = BigUint::from(prime);
                            elements.push(elem);
                        }

                        for elem in &elements {
                            acc.add(&elem);
                        }
                        // TODO calculate s* and pass to non_mem_proof_create as a paramater

                        (acc, non_member)
                    },
                    |(acc, non_member)| {
                        acc.non_mem_proof_create(&non_member);
                    },
                    BatchSize::SmallInput,
                );
            },
        );

        group.bench_with_input(
            BenchmarkId::new("non_mem_proof_blinded", size),
            size,
            |b, &n| {
                b.iter_batched(
                    || {
                        let mut acc = RsaAccumulator::<RsaGroup>::setup();

                        let non_member = BigUint::from(200003u64);

                        let blinded_non_mem_proof = acc.blind_non_mem_proof(&non_member);

                        let mut elements = Vec::new();

                        for i in 0..n {
                            let i_bytes = i.to_be_bytes();
                            let prime = acc.group.hash_to_prime(&i_bytes);
                            let elem = BigUint::from(prime);
                            elements.push(elem);
                        }

                        //let elements_out: Vec<BigUint> = vec![];
                        for elem in &elements {
                            acc.add(&elem);
                        }

                        (acc, blinded_non_mem_proof)
                    },
                    |(acc, blinded_non_mem_proof)| {
                        acc.blind_non_mem_proof_upd(&blinded_non_mem_proof.0);
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }
}

fn benchmark_privacy_overhead_trapdoorless(c: &mut Criterion) {
    let mut group = c.benchmark_group("trapdoorless_privacy_overhead");

    group.sample_size(25);

    let sizes = [8usize, 16, 32, 64, 128, 256, 512, 1024];

    for size in sizes.iter() {
        group.bench_with_input(
            BenchmarkId::new("non_mem_proof_standard", size),
            size,
            |b, &n| {
                b.iter_batched(
                    || {
                        let mut acc = RsaAccumulator::<RsaGroup>::setup_trapdoorless();
                        let non_member = BigUint::from(200003u64);

                        let mut elements = Vec::new();

                        for i in 0..n {
                            let i_bytes = i.to_be_bytes();
                            let prime = acc.group.hash_to_prime(&i_bytes);
                            let elem = BigUint::from(prime);
                            elements.push(elem);
                        }

                        for elem in &elements {
                            acc.add(&elem);
                        }
                        // TODO calculate s* and pass to non_mem_proof_create as a paramater

                        (acc, non_member)
                    },
                    |(acc, non_member)| {
                        acc.non_mem_proof_create(&non_member);
                    },
                    BatchSize::SmallInput,
                );
            },
        );

        group.bench_with_input(
            BenchmarkId::new("non_mem_proof_blinded", size),
            size,
            |b, &n| {
                b.iter_batched(
                    || {
                        let mut acc = RsaAccumulator::<RsaGroup>::setup_trapdoorless();

                        let non_member = BigUint::from(200003u64);

                        let blinded_non_mem_proof = acc.blind_non_mem_proof(&non_member);

                        let mut elements = Vec::new();

                        for i in 0..n {
                            let i_bytes = i.to_be_bytes();
                            let prime = acc.group.hash_to_prime(&i_bytes);
                            let elem = BigUint::from(prime);
                            elements.push(elem);
                        }

                        //let elements_out: Vec<BigUint> = vec![];
                        for elem in &elements {
                            acc.add(&elem);
                        }

                        (acc, blinded_non_mem_proof)
                    },
                    |(acc, blinded_non_mem_proof)| {
                        acc.blind_non_mem_proof_upd(&blinded_non_mem_proof.0);
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }
}

criterion_group!(
    benches,
    benchmark_blind_mem_proof,
    benchmark_unblind_mem_proof,
    benchmark_ver_blind_mem_proof_upd,
    benchmark_blind_mem_proof_upd,
    benchmark_blind_non_mem_proof,
    benchmark_unblind_non_mem_proof,
    benchmark_ver_blind_non_mem_proof_upd,
    benchmark_blind_non_mem_proof_upd,
    benchmark_accumulator_compare,
    benchmark_trapdoored_vs_trapdoorless_accumulator,
    benchmark_privacy_overhead_trapdoored,
    benchmark_privacy_overhead_trapdoorless
);
criterion_main!(benches);
