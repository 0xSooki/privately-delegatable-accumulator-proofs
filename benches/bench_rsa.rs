use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::Zero;
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial};
use ark_std::{test_rng, time::Duration};
use criterion::{black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use num_bigint::{BigInt, BigUint};
#[cfg(feature = "class-group")]
use privacy_preserving_accumulators::groups::ClassGroup;
use privacy_preserving_accumulators::{
    groups::RsaGroup, BilinearAccumulator, Group, RsaAccumulator,
};

fn syn_div_fr(poly: &DensePolynomial<Fr>, c: &Fr) -> (DensePolynomial<Fr>, Fr) {
    let coeffs = poly.coeffs();
    if coeffs.len() <= 1 {
        let r = coeffs.first().copied().unwrap_or_else(Fr::zero);
        return (DensePolynomial::zero(), r);
    }
    let n = coeffs.len();
    let mut q = vec![Fr::zero(); n - 1];
    q[n - 2] = coeffs[n - 1];
    for i in (0..n - 2).rev() {
        q[i] = coeffs[i + 1] + *c * q[i + 1];
    }
    let r = coeffs[0] + *c * q[0];
    (DensePolynomial::from_coefficients_vec(q), r)
}

fn benchmark_blind_mem_proof(c: &mut Criterion) {
    let mut group = c.benchmark_group("membership_proofs");

    group.sample_size(10);

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

    group.sample_size(10);

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

    group.sample_size(10);

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

    group.sample_size(10);

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

    group.sample_size(10);

    group.bench_function("unblind_non_mem_proof", |b| {
        b.iter_batched(
            || {
                let mut acc = RsaAccumulator::<RsaGroup>::setup();

                for i in 2..5 {
                    acc.add(&BigUint::from(i as usize));
                }

                let non_member = BigUint::from(7 as usize);

                let prod = Some(acc.calculate_product_unreduced());
                let blinded_proof = acc.blind_non_mem_proof(&non_member);

                for i in 10..12 {
                    acc.add(&BigUint::from(i as usize));
                }

                let upd_blind_non_mem_proof = acc.blind_non_mem_proof_upd(
                    &blinded_proof.0,
                    &BigInt::from(acc.calculate_product()),
                );

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

    group.sample_size(10);

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

                let updated_blind_proof = acc.blind_non_mem_proof_upd(
                    &blinded_proof.0,
                    &BigInt::from(acc.calculate_product()),
                );

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

                        let delta = BigInt::from(acc.calculate_product_unreduced());

                        (acc, blinded_non_mem_proof, delta)
                    },
                    |(acc, blinded_non_mem_proof, delta)| {
                        acc.blind_non_mem_proof_upd(&blinded_non_mem_proof.0, &delta);
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

    group.sample_size(10);

    let sizes = [10usize, 100, 500];

    for size in sizes.iter() {
        group.bench_with_input(BenchmarkId::new("rsa_add_n", size), size, |b, &n| {
            b.iter_batched(
                || {
                    let acc = RsaAccumulator::<RsaGroup>::setup();
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
                    let acc = BilinearAccumulator::<Bls12_381>::setup(&mut rng, n + 1);
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
                |(acc, target_prime)| {
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

    group.sample_size(10);

    let sizes = [8usize, 16, 32, 64, 128, 256, 512, 1024];
    let max_size = *sizes.iter().max().unwrap();

    // TRAPDOORED
    let temp_acc_td = RsaAccumulator::<RsaGroup>::setup();

    let all_primes_td: Vec<BigUint> = (0..max_size)
        .map(|i| temp_acc_td.group.hash_to_prime(&i.to_be_bytes()))
        .collect();

    // TRAPDOORLESS
    let temp_acc_tl = RsaAccumulator::<RsaGroup>::setup_trapdoorless();

    let all_primes_tl: Vec<BigUint> = (0..max_size)
        .map(|i| temp_acc_tl.group.hash_to_prime(&i.to_be_bytes()))
        .collect();

    let non_element = BigUint::from(741569u64);
    let element = BigUint::from(200003u64);

    for &size in sizes.iter() {
        // TRAPDOORED
        let mut base_acc_td = RsaAccumulator::<RsaGroup>::setup();
        let ep_td = base_acc_td.add(&element);
        for i in 0..size {
            base_acc_td.add(&all_primes_td[i]);
        }

        let trapdoored_blinded_non_mem_proof = base_acc_td.blind_non_mem_proof(&non_element);

        // TRAPDOORLESS
        let mut base_acc_tl = RsaAccumulator::<RsaGroup>::setup_trapdoorless();
        let ep_tl = base_acc_tl.add(&element);
        for i in 0..size {
            base_acc_tl.add(&all_primes_tl[i]);
        }

        let trapdoorless_blinded_non_mem_proof = base_acc_tl.blind_non_mem_proof(&non_element);

        let prod_td = Some(base_acc_td.calculate_product());

        let prod_tl = Some(base_acc_tl.calculate_product());

        group.bench_with_input(
            BenchmarkId::new("trapdoored_non_mem_blind_proof_upd", size),
            &size,
            |b, &_n| {
                b.iter_batched(
                    || {
                        (
                            base_acc_td.clone(),
                            trapdoored_blinded_non_mem_proof.clone(),
                            BigInt::from(prod_td.clone().unwrap()),
                        )
                    },
                    |(acc, blinded_non_mem_proof, delta)| {
                        acc.blind_non_mem_proof_upd(&blinded_non_mem_proof.0, &delta);
                    },
                    BatchSize::SmallInput,
                );
            },
        );

        group.bench_with_input(
            BenchmarkId::new("trapdoorless_non_mem_blind_proof_upd", size),
            &size,
            |b, &_n| {
                b.iter_batched(
                    || {
                        (
                            base_acc_tl.clone(),
                            trapdoorless_blinded_non_mem_proof.clone(),
                            BigInt::from(prod_tl.clone().unwrap()),
                        )
                    },
                    |(acc, blinded_non_mem_proof, delta)| {
                        acc.blind_non_mem_proof_upd(&blinded_non_mem_proof.0, &delta);
                    },
                    BatchSize::SmallInput,
                );
            },
        );

        group.bench_with_input(
            BenchmarkId::new("trapdoored_mem_proof_create", size),
            &size,
            |b, &n| {
                b.iter_batched(
                    || (base_acc_td.clone(), ep_td.clone()),
                    |(acc, ep)| {
                        acc.mem_proof_create(&ep);
                    },
                    BatchSize::SmallInput,
                );
            },
        );

        group.bench_with_input(
            BenchmarkId::new("trapdoorless_mem_proof_create", size),
            &size,
            |b, &_n| {
                b.iter_batched(
                    || (base_acc_tl.clone(), ep_tl.clone()),
                    |(acc, ep)| {
                        acc.mem_proof_create(&ep);
                    },
                    BatchSize::SmallInput,
                );
            },
        );

        group.bench_with_input(
            BenchmarkId::new("trapdoored_non_mem_proof_create", size),
            &size,
            |b, &n| {
                b.iter_batched(
                    || {
                        (
                            base_acc_td.clone(),
                            non_element.clone(),
                            BigInt::from(prod_td.clone().unwrap()),
                        )
                    },
                    |(acc, non_member, prod)| {
                        acc.non_mem_proof_create(&non_member, &prod);
                    },
                    BatchSize::SmallInput,
                );
            },
        );

        group.bench_with_input(
            BenchmarkId::new("trapdoorless_non_mem_proof_create", size),
            &size,
            |b, &_n| {
                b.iter_batched(
                    || {
                        (
                            base_acc_tl.clone(),
                            non_element.clone(),
                            BigInt::from(prod_tl.clone().unwrap()),
                        )
                    },
                    |(acc, non_member, prod)| {
                        acc.non_mem_proof_create(&non_member, &prod);
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

fn benchmark_bilinear_vs_class_vs_rsa_trapdoorless(c: &mut Criterion) {
    #[cfg(not(feature = "class-group"))]
    {
        let _ = c;
        return;
    }

    #[cfg(feature = "class-group")]
    {
        let mut group = c.benchmark_group("bilinear_vs_class_vs_rsa_trapdoorless");

        group.sample_size(10);

        let sizes = [8usize, 16, 32, 64, 128, 256, 512, 1024];
        let max_size = *sizes.iter().max().unwrap();

        let temp_acc_rsa = RsaAccumulator::<RsaGroup>::setup_trapdoorless();
        let rsa_template = temp_acc_rsa.clone();
        let all_primes_rsa: Vec<BigUint> = (0..max_size)
            .map(|i| temp_acc_rsa.group.hash_to_prime(&i.to_be_bytes()))
            .collect();
        let all_update_primes_rsa: Vec<BigUint> = (max_size..(2 * max_size))
            .map(|i| temp_acc_rsa.group.hash_to_prime(&i.to_be_bytes()))
            .collect();

        let temp_acc_rsa_td = RsaAccumulator::<RsaGroup>::setup();
        let rsa_td_template = temp_acc_rsa_td.clone();
        let all_primes_rsa_td: Vec<BigUint> = (0..max_size)
            .map(|i| temp_acc_rsa_td.group.hash_to_prime(&i.to_be_bytes()))
            .collect();
        let all_update_primes_rsa_td: Vec<BigUint> = (max_size..(2 * max_size))
            .map(|i| temp_acc_rsa_td.group.hash_to_prime(&i.to_be_bytes()))
            .collect();

        let temp_acc_class = RsaAccumulator::<ClassGroup>::setup_trapdoorless();
        let class_template = temp_acc_class.clone();
        let all_primes_class: Vec<_> = (0..max_size)
            .map(|i| temp_acc_class.group.hash_to_prime(&i.to_be_bytes()))
            .collect();
        let all_update_primes_class: Vec<_> = (max_size..(2 * max_size))
            .map(|i| temp_acc_class.group.hash_to_prime(&i.to_be_bytes()))
            .collect();

        let mut rng = test_rng();
        let bilinear_template =
            BilinearAccumulator::<Bls12_381>::setup(&mut rng, (2 * max_size) + 8);

        let all_elements_bilinear: Vec<Fr> = (1u64..=(max_size as u64)).map(Fr::from).collect();
        let all_update_elements_bilinear: Vec<Fr> = ((max_size as u64) + 1
            ..=((2 * max_size) as u64))
            .map(Fr::from)
            .collect();

        let non_element_rsa = BigUint::from(741569u64);
        let element_rsa = BigUint::from(200003u64);

        let non_element_class = temp_acc_class.group.hash_to_prime(&741569u64.to_be_bytes());
        let element_class = 200003u64;

        let non_element_bilinear = Fr::from(741569u64);
        let element_bilinear = Fr::from(200003u64);

        let mut running_rsa = rsa_template.clone();
        let ep_rsa = running_rsa.add(&element_rsa);

        let mut running_rsa_td = rsa_td_template.clone();
        let ep_rsa_td = running_rsa_td.add(&element_rsa);

        let mut running_class = class_template.clone();
        let ep_class = running_class.add(&element_class);

        let mut running_bilinear = bilinear_template.clone();
        running_bilinear.add(&element_bilinear);

        let mut prev_size = 0usize;

        for &size in sizes.iter() {
            for i in prev_size..size {
                running_rsa.add(&all_primes_rsa[i]);
                running_rsa_td.add(&all_primes_rsa_td[i]);
                running_class.add(&all_primes_class[i]);
                running_bilinear.add(&all_elements_bilinear[i]);
            }
            prev_size = size;

            let base_acc_rsa = running_rsa.clone();
            let rsa_blinded_non_mem_proof = base_acc_rsa.blind_non_mem_proof(&non_element_rsa);
            let rsa_delta = BigInt::from(base_acc_rsa.calculate_product());

            let base_acc_rsa_td = running_rsa_td.clone();
            let rsa_td_blinded_non_mem_proof =
                base_acc_rsa_td.blind_non_mem_proof(&non_element_rsa);
            let rsa_delta_td = BigInt::from(base_acc_rsa_td.calculate_product());

            let base_acc_class = running_class.clone();
            let class_blinded_non_mem_proof =
                base_acc_class.blind_non_mem_proof(&non_element_class);
            let class_delta = base_acc_class.calculate_product_unreduced();

            let base_acc_bilinear = running_bilinear.clone();
            let bilinear_non_mem_proof = base_acc_bilinear
                .non_mem_proof_create(non_element_bilinear)
                .expect("bilinear non-membership proof");
            let bilinear_update_elements = all_update_elements_bilinear[..size].to_vec();
            let rsa_update_elements = all_update_primes_rsa[..size].to_vec();
            let rsa_td_update_elements = all_update_primes_rsa_td[..size].to_vec();
            let class_update_elements = all_update_primes_class[..size].to_vec();

            let mut s_poly = DensePolynomial::from_coefficients_vec(vec![Fr::from(1u64)]);
            let mut current_elements_bilinear = Vec::with_capacity(size + 1);
            current_elements_bilinear.push(element_bilinear);
            current_elements_bilinear.extend_from_slice(&all_elements_bilinear[..size]);
            for xi in &current_elements_bilinear {
                let factor = DensePolynomial::from_coefficients_vec(vec![-*xi, Fr::from(1u64)]);
                s_poly = &s_poly * &factor;
            }
            let (bilinear_q, _) = syn_div_fr(&s_poly, &element_bilinear);

            group.bench_with_input(
                BenchmarkId::new("rsa_trapdoorless_non_mem_blind_proof_upd", size),
                &size,
                |b, &_n| {
                    b.iter(|| {
                        black_box(base_acc_rsa.blind_non_mem_proof_upd(
                            black_box(&rsa_blinded_non_mem_proof.0),
                            black_box(&rsa_delta),
                        ));
                    });
                },
            );

            group.bench_with_input(
                BenchmarkId::new("rsa_trapdoored_non_mem_blind_proof_upd", size),
                &size,
                |b, &_n| {
                    b.iter(|| {
                        black_box(base_acc_rsa_td.blind_non_mem_proof_upd(
                            black_box(&rsa_td_blinded_non_mem_proof.0),
                            black_box(&rsa_delta_td),
                        ));
                    });
                },
            );

            group.bench_with_input(
                BenchmarkId::new("class_non_mem_blind_proof_upd", size),
                &size,
                |b, &_n| {
                    b.iter(|| {
                        black_box(base_acc_class.blind_non_mem_proof_upd(
                            black_box(&class_blinded_non_mem_proof.0),
                            black_box(&class_delta),
                        ));
                    });
                },
            );

            group.bench_with_input(
                BenchmarkId::new("bilinear_non_mem_blind_proof_upd", size),
                &size,
                |b, &n| {
                    b.iter_batched(
                        || (base_acc_bilinear.clone(), bilinear_non_mem_proof.clone()),
                        |(mut acc, mut proof)| {
                            for sn_plus_one in bilinear_update_elements.iter().take(n) {
                                let (blinded_non_mem_proof, r) =
                                    acc.blind_non_mem_proof(&proof, non_element_bilinear);
                                acc.add(sn_plus_one);
                                let blinded_updated_proof = acc
                                    .blind_non_mem_proof_upd(&blinded_non_mem_proof, sn_plus_one);
                                proof = acc.unblind_non_mem_proof(
                                    &blinded_updated_proof,
                                    &(r, blinded_non_mem_proof.1),
                                    non_element_bilinear,
                                );
                            }
                            black_box(proof);
                        },
                        BatchSize::SmallInput,
                    );
                },
            );

            group.bench_with_input(
                BenchmarkId::new("rsa_trapdoorless_mem_blind_proof_upd", size),
                &size,
                |b, &_n| {
                    b.iter_batched(
                        || {
                            let mut acc = base_acc_rsa.clone();
                            let acc_t = acc.acc.clone();
                            let proof = acc.mem_proof_create(&ep_rsa);
                            let blinded_proof = acc.blind_mem_proof(&proof);
                            let elements_in = rsa_update_elements.clone();
                            for elem in &elements_in {
                                acc.add(elem);
                            }
                            (acc, elements_in, acc_t, blinded_proof)
                        },
                        |(acc, elements_in, acc_t, blinded_proof)| {
                            black_box(acc.blind_mem_proof_upd(
                                elements_in,
                                vec![],
                                &acc_t,
                                &blinded_proof.0,
                            ));
                        },
                        BatchSize::SmallInput,
                    );
                },
            );

            group.bench_with_input(
                BenchmarkId::new("rsa_trapdoored_mem_blind_proof_upd", size),
                &size,
                |b, &_n| {
                    b.iter_batched(
                        || {
                            let mut acc = base_acc_rsa_td.clone();
                            let acc_t = acc.acc.clone();
                            let proof = acc.mem_proof_create(&ep_rsa_td);
                            let blinded_proof = acc.blind_mem_proof(&proof);
                            let elements_in = rsa_td_update_elements.clone();
                            for elem in &elements_in {
                                acc.add(elem);
                            }
                            (acc, elements_in, acc_t, blinded_proof)
                        },
                        |(acc, elements_in, acc_t, blinded_proof)| {
                            black_box(acc.blind_mem_proof_upd(
                                elements_in,
                                vec![],
                                &acc_t,
                                &blinded_proof.0,
                            ));
                        },
                        BatchSize::SmallInput,
                    );
                },
            );

            group.bench_with_input(
                BenchmarkId::new("class_mem_blind_proof_upd", size),
                &size,
                |b, &_n| {
                    b.iter_batched(
                        || {
                            let mut acc = base_acc_class.clone();
                            let acc_t = acc.acc.clone();
                            let proof = acc.mem_proof_create(&ep_class);
                            let blinded_proof = acc.blind_mem_proof(&proof);
                            let elements_in = class_update_elements.clone();
                            for elem in &elements_in {
                                acc.add(elem);
                            }
                            (acc, elements_in, acc_t, blinded_proof)
                        },
                        |(acc, elements_in, acc_t, blinded_proof)| {
                            black_box(acc.blind_mem_proof_upd(
                                elements_in,
                                vec![],
                                &acc_t,
                                &blinded_proof.0,
                            ));
                        },
                        BatchSize::SmallInput,
                    );
                },
            );

            group.bench_with_input(
                BenchmarkId::new("bilinear_mem_blind_proof_upd", size),
                &size,
                |b, &_n| {
                    b.iter_batched(
                        || {
                            let mut acc = base_acc_bilinear.clone();
                            let elements_in = bilinear_update_elements.clone();
                            let mut rng = test_rng();
                            let (crs_prime, _r) = acc
                                .blind_mem_proof(&mut rng, &bilinear_q, elements_in.len())
                                .expect("bilinear blind membership proof");
                            for elem in &elements_in {
                                acc.add(elem);
                            }
                            (acc, elements_in, crs_prime)
                        },
                        |(acc, elements_in, crs_prime)| {
                            let _ = black_box(acc.blind_mem_proof_upd(elements_in, crs_prime));
                        },
                        BatchSize::SmallInput,
                    );
                },
            );

            group.bench_with_input(
                BenchmarkId::new("rsa_trapdoorless_mem_proof_create", size),
                &size,
                |b, &_n| {
                    b.iter(|| {
                        black_box(base_acc_rsa.mem_proof_create(black_box(&ep_rsa)));
                    });
                },
            );

            group.bench_with_input(
                BenchmarkId::new("rsa_trapdoored_mem_proof_create", size),
                &size,
                |b, &_n| {
                    b.iter(|| {
                        black_box(base_acc_rsa_td.mem_proof_create(black_box(&ep_rsa_td)));
                    });
                },
            );

            group.bench_with_input(
                BenchmarkId::new("class_mem_proof_create", size),
                &size,
                |b, &_n| {
                    b.iter(|| {
                        black_box(base_acc_class.mem_proof_create(black_box(&ep_class)));
                    });
                },
            );

            group.bench_with_input(
                BenchmarkId::new("bilinear_mem_proof_create", size),
                &size,
                |b, &_n| {
                    b.iter(|| {
                        black_box(
                            base_acc_bilinear
                                .mem_proof_create(black_box(element_bilinear))
                                .expect("bilinear membership proof"),
                        );
                    });
                },
            );

            group.bench_with_input(
                BenchmarkId::new("rsa_trapdoorless_non_mem_proof_create", size),
                &size,
                |b, &_n| {
                    b.iter(|| {
                        black_box(base_acc_rsa.non_mem_proof_create(
                            black_box(&non_element_rsa),
                            black_box(&rsa_delta),
                        ));
                    });
                },
            );

            group.bench_with_input(
                BenchmarkId::new("rsa_trapdoored_non_mem_proof_create", size),
                &size,
                |b, &_n| {
                    b.iter(|| {
                        black_box(base_acc_rsa_td.non_mem_proof_create(
                            black_box(&non_element_rsa),
                            black_box(&rsa_delta_td),
                        ));
                    });
                },
            );

            group.bench_with_input(
                BenchmarkId::new("class_non_mem_proof_create", size),
                &size,
                |b, &_n| {
                    b.iter(|| {
                        black_box(base_acc_class.non_mem_proof_create(
                            black_box(&non_element_class),
                            black_box(&class_delta),
                        ));
                    });
                },
            );

            group.bench_with_input(
                BenchmarkId::new("bilinear_non_mem_proof_create", size),
                &size,
                |b, &_n| {
                    b.iter(|| {
                        black_box(
                            base_acc_bilinear
                                .non_mem_proof_create(black_box(non_element_bilinear))
                                .expect("bilinear non-membership proof"),
                        );
                    });
                },
            );
        }

        group.finish();
    }
}

fn benchmark_privacy_overhead_trapdoored(c: &mut Criterion) {
    let mut group = c.benchmark_group("trapdoored_privacy_overhead");

    group.sample_size(10);

    let sizes = [8usize, 16, 32, 64, 128, 256, 512, 1024];
    let max_size = *sizes.iter().max().unwrap();

    let temp_acc = RsaAccumulator::<RsaGroup>::setup();

    let all_primes: Vec<BigUint> = (0..max_size)
        .map(|i| temp_acc.group.hash_to_prime(&i.to_be_bytes()))
        .collect();

    let non_element = BigUint::from(741569u64);

    for &size in sizes.iter() {
        let mut base_acc = RsaAccumulator::<RsaGroup>::setup();
        for i in 0..size {
            base_acc.add(&all_primes[i]);
        }

        let trapdoored_blinded_non_mem_proof = base_acc.blind_non_mem_proof(&non_element);

        let delta = Some(base_acc.calculate_product());

        group.bench_with_input(
            BenchmarkId::new("non_mem_proof_standard", size),
            &size,
            |b, &_n| {
                b.iter_batched(
                    || {
                        (
                            base_acc.clone(),
                            non_element.clone(),
                            BigInt::from(delta.clone().unwrap()),
                        )
                    },
                    |(acc, non_member, prod)| {
                        acc.non_mem_proof_create(&non_member, &prod);
                    },
                    BatchSize::SmallInput,
                );
            },
        );

        group.bench_with_input(
            BenchmarkId::new("non_mem_proof_blinded", size),
            &size,
            |b, &_n| {
                b.iter_batched(
                    || {
                        (
                            base_acc.clone(),
                            trapdoored_blinded_non_mem_proof.clone(),
                            BigInt::from(delta.clone().unwrap()),
                        )
                    },
                    |(acc, blinded_non_mem_proof, delta)| {
                        acc.blind_non_mem_proof_upd(&blinded_non_mem_proof.0, &delta);
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }
}

fn benchmark_privacy_overhead_trapdoorless(c: &mut Criterion) {
    let mut group = c.benchmark_group("trapdoorless_privacy_overhead");

    group.sample_size(10);

    let sizes = [8usize, 16, 32, 64, 128, 256, 512, 1024];
    let max_size = *sizes.iter().max().unwrap();

    let temp_acc = RsaAccumulator::<RsaGroup>::setup_trapdoorless();

    let all_primes: Vec<BigUint> = (0..max_size)
        .map(|i| temp_acc.group.hash_to_prime(&i.to_be_bytes()))
        .collect();

    let non_element = BigUint::from(741569u64);

    for &size in sizes.iter() {
        let mut base_acc = RsaAccumulator::<RsaGroup>::setup_trapdoorless();
        for i in 0..size {
            base_acc.add(&all_primes[i]);
        }

        let trapdoorless_blinded_non_mem_proof = base_acc.blind_non_mem_proof(&non_element);

        let delta = Some(base_acc.calculate_product());

        group.bench_with_input(
            BenchmarkId::new("non_mem_proof_standard", size),
            &size,
            |b, &_n| {
                b.iter_batched(
                    || {
                        (
                            base_acc.clone(),
                            non_element.clone(),
                            BigInt::from(delta.clone().unwrap()),
                        )
                    },
                    |(acc, non_member, prod)| {
                        acc.non_mem_proof_create(&non_member, &prod);
                    },
                    BatchSize::SmallInput,
                );
            },
        );

        group.bench_with_input(
            BenchmarkId::new("non_mem_proof_blinded", size),
            &size,
            |b, &_n| {
                b.iter_batched(
                    || {
                        (
                            base_acc.clone(),
                            trapdoorless_blinded_non_mem_proof.clone(),
                            BigInt::from(delta.clone().unwrap()),
                        )
                    },
                    |(acc, blinded_non_mem_proof, delta)| {
                        acc.blind_non_mem_proof_upd(&blinded_non_mem_proof.0, &delta);
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
    benchmark_bilinear_vs_class_vs_rsa_trapdoorless,
    benchmark_privacy_overhead_trapdoored,
    benchmark_privacy_overhead_trapdoorless
);
criterion_main!(benches);
