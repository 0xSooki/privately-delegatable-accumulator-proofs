#![allow(unused_must_use)]

use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::Zero;
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial};
use ark_std::test_rng;
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
                        || {
                            let mut acc_for_chain = base_acc_bilinear.clone();
                            let mut proof_for_chain = bilinear_non_mem_proof.clone();
                            let mut prepared_inputs = Vec::with_capacity(n);

                            for sn_plus_one in bilinear_update_elements.iter().take(n) {
                                let (blinded_non_mem_proof, r) = acc_for_chain
                                    .blind_non_mem_proof(&proof_for_chain, non_element_bilinear);
                                let acc_t = acc_for_chain.value();

                                let mut acc_after_update = acc_for_chain.clone();
                                acc_after_update.add(sn_plus_one);

                                let (blinded_updated_proof, _g2_sn_plus_one) = acc_after_update
                                    .blind_non_mem_proof_upd(
                                        &blinded_non_mem_proof,
                                        &acc_t,
                                        sn_plus_one,
                                    );

                                proof_for_chain = acc_after_update.unblind_non_mem_proof(
                                    &blinded_updated_proof,
                                    &(r, blinded_non_mem_proof.1),
                                    non_element_bilinear,
                                );

                                prepared_inputs.push((blinded_non_mem_proof, acc_t, *sn_plus_one));
                                acc_for_chain = acc_after_update;
                            }

                            prepared_inputs
                        },
                        |prepared_inputs| {
                            for (blinded_non_mem_proof, acc_t, sn_plus_one) in prepared_inputs {
                                let _ = black_box(base_acc_bilinear.blind_non_mem_proof_upd(
                                    black_box(&blinded_non_mem_proof),
                                    black_box(&acc_t),
                                    black_box(&sn_plus_one),
                                ));
                            }
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
                            let proof = acc
                                .mem_proof_create(&ep_rsa)
                                .expect("rsa trapdoorless membership proof");
                            let blinded_proof = acc.blind_mem_proof(&proof);
                            let elements_in = rsa_update_elements.clone();
                            for elem in &elements_in {
                                acc.add(elem);
                            }

                            let delta = if let Some(o) = acc.group.order() {
                                elements_in
                                    .iter()
                                    .fold(BigUint::from(1u32), |prod, e| (prod * e) % o)
                            } else {
                                elements_in
                                    .iter()
                                    .fold(BigUint::from(1u32), |prod, e| prod * e)
                            };
                            let delta_int = BigInt::from(delta);

                            (acc, delta_int, acc_t, blinded_proof)
                        },
                        |(acc, delta_int, acc_t, blinded_proof)| {
                            black_box(acc.blind_mem_proof_upd(
                                &acc_t,
                                &blinded_proof.0,
                                &delta_int,
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
                            let proof = acc
                                .mem_proof_create(&ep_rsa_td)
                                .expect("rsa trapdoored membership proof");
                            let blinded_proof = acc.blind_mem_proof(&proof);
                            let elements_in = rsa_td_update_elements.clone();
                            for elem in &elements_in {
                                acc.add(elem);
                            }

                            let delta = if let Some(o) = acc.group.order() {
                                elements_in
                                    .iter()
                                    .fold(BigUint::from(1u32), |prod, e| (prod * e) % o)
                            } else {
                                elements_in
                                    .iter()
                                    .fold(BigUint::from(1u32), |prod, e| prod * e)
                            };
                            let delta_int = BigInt::from(delta);

                            (acc, delta_int, acc_t, blinded_proof)
                        },
                        |(acc, delta_int, acc_t, blinded_proof)| {
                            black_box(acc.blind_mem_proof_upd(
                                &acc_t,
                                &blinded_proof.0,
                                &delta_int,
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
                            let proof = acc
                                .mem_proof_create(&ep_class)
                                .expect("class-group membership proof");
                            let blinded_proof = acc.blind_mem_proof(&proof);
                            let elements_in = class_update_elements.clone();
                            for elem in &elements_in {
                                acc.add(elem);
                            }
                            let delta = elements_in
                                .iter()
                                .fold(ClassGroup::exp_id(), |prod, e| {
                                    ClassGroup::exp_mul(&prod, e)
                                })
                                .0;
                            (acc, delta, acc_t, blinded_proof)
                        },
                        |(acc, delta, acc_t, blinded_proof)| {
                            black_box(acc.blind_mem_proof_upd(&acc_t, &blinded_proof.0, &delta));
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
                            let pi_blinded = crs_prime
                                .first()
                                .copied()
                                .expect("blinded CRS must include base term");
                            let acc_t = acc.value();
                            let q_star = elements_in.iter().fold(
                                DensePolynomial::from_coefficients_vec(vec![Fr::from(1u64)]),
                                |acc_poly, xi| {
                                    let factor = DensePolynomial::from_coefficients_vec(vec![
                                        -*xi,
                                        Fr::from(1u64),
                                    ]);
                                    &acc_poly * &factor
                                },
                            );
                            for elem in &elements_in {
                                acc.add(elem);
                            }
                            let powers_acc_t = acc.shift_com(&s_poly, q_star.coeffs().len());
                            (acc, pi_blinded, acc_t, crs_prime, q_star, powers_acc_t)
                        },
                        |(acc, pi_blinded, acc_t, crs_prime, q_star, powers_acc_t)| {
                            let _ = black_box(acc.blind_mem_proof_upd(
                                &pi_blinded,
                                &acc_t,
                                crs_prime,
                                q_star,
                                powers_acc_t,
                            ));
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

criterion_group!(benches, benchmark_bilinear_vs_class_vs_rsa_trapdoorless,);
criterion_main!(benches);
