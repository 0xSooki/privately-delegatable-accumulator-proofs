#![allow(unused_must_use)]

use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::Zero;
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial};
use ark_std::test_rng;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use num_bigint::{BigInt, BigUint};
#[cfg(feature = "class-group")]
use private_accumulator_proof_delegation::groups::ClassGroup;
use private_accumulator_proof_delegation::{
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
        const BASE_SIZE: usize = 64;
        const UPDATE_SIZES: [usize; 8] = [8, 16, 32, 64, 128, 256, 512, 1024];

        fn rsa_update_delta(acc: &RsaAccumulator<RsaGroup>, exps: &[BigUint]) -> BigInt {
            let product = if let Some(o) = acc.group.order() {
                exps.iter()
                    .fold(BigUint::from(1u32), |prod, e| (prod * e) % o)
            } else {
                exps.iter().fold(BigUint::from(1u32), |prod, e| prod * e)
            };
            BigInt::from(product)
        }

        let mut group = c.benchmark_group("bilinear_vs_class_vs_rsa_trapdoorless");

        group.sample_size(10);

        let max_k = *UPDATE_SIZES.iter().max().unwrap();

        let element_rsa = BigUint::from(200003u64);
        let non_element_rsa = BigUint::from(741569u64);
        let element_class = 200003u64;
        let element_bilinear = Fr::from(200003u64);
        let non_element_bilinear = Fr::from(741569u64);

        let mut base_acc_rsa = RsaAccumulator::<RsaGroup>::setup_trapdoorless();
        let base_inputs_rsa: Vec<BigUint> = (0..BASE_SIZE)
            .map(|i| base_acc_rsa.group.hash_to_prime(&i.to_be_bytes()))
            .collect();
        let update_inputs_rsa: Vec<BigUint> = (BASE_SIZE..(BASE_SIZE + max_k))
            .map(|i| base_acc_rsa.group.hash_to_prime(&i.to_be_bytes()))
            .collect();
        let ep_rsa = base_acc_rsa.add_raw(&element_rsa);
        for input in &base_inputs_rsa {
            base_acc_rsa.add_raw(input);
        }

        let mut base_acc_rsa_td = RsaAccumulator::<RsaGroup>::setup();
        let base_inputs_rsa_td: Vec<BigUint> = (0..BASE_SIZE)
            .map(|i| base_acc_rsa_td.group.hash_to_prime(&i.to_be_bytes()))
            .collect();
        let update_inputs_rsa_td: Vec<BigUint> = (BASE_SIZE..(BASE_SIZE + max_k))
            .map(|i| base_acc_rsa_td.group.hash_to_prime(&i.to_be_bytes()))
            .collect();
        let ep_rsa_td = base_acc_rsa_td.add_raw(&element_rsa);
        for input in &base_inputs_rsa_td {
            base_acc_rsa_td.add_raw(input);
        }

        let mut base_acc_class = RsaAccumulator::<ClassGroup>::setup_trapdoorless();
        let base_inputs_class: Vec<_> = (0..BASE_SIZE)
            .map(|i| base_acc_class.group.hash_to_prime(&i.to_be_bytes()))
            .collect();
        let update_inputs_class: Vec<_> = (BASE_SIZE..(BASE_SIZE + max_k))
            .map(|i| base_acc_class.group.hash_to_prime(&i.to_be_bytes()))
            .collect();
        let non_element_class = base_acc_class.group.hash_to_prime(&741569u64.to_be_bytes());
        let ep_class = base_acc_class.add_raw(&element_class);
        for input in &base_inputs_class {
            base_acc_class.add_raw(input);
        }

        let mut rng = test_rng();
        let mut base_acc_bilinear =
            BilinearAccumulator::<Bls12_381>::setup(&mut rng, BASE_SIZE + max_k + 8);
        let base_elements_bilinear: Vec<Fr> = (1u64..=(BASE_SIZE as u64)).map(Fr::from).collect();
        let update_elements_bilinear: Vec<Fr> = ((BASE_SIZE as u64) + 1
            ..=((BASE_SIZE + max_k) as u64))
            .map(Fr::from)
            .collect();
        base_acc_bilinear.add_raw(&element_bilinear);
        for element in &base_elements_bilinear {
            base_acc_bilinear.add_raw(element);
        }

        let rsa_acc_t = base_acc_rsa.acc.clone();
        let rsa_mem_proof = base_acc_rsa
            .mem_proof_create_raw(&ep_rsa)
            .expect("rsa trapdoorless membership proof");
        let rsa_blinded_mem_proof = base_acc_rsa.blind_mem_proof_raw(&rsa_mem_proof);
        let rsa_blinded_non_mem_proof = base_acc_rsa.blind_non_mem_proof_raw(&non_element_rsa);

        let rsa_td_acc_t = base_acc_rsa_td.acc.clone();
        let rsa_td_mem_proof = base_acc_rsa_td
            .mem_proof_create_raw(&ep_rsa_td)
            .expect("rsa trapdoored membership proof");
        let rsa_td_blinded_mem_proof = base_acc_rsa_td.blind_mem_proof_raw(&rsa_td_mem_proof);
        let rsa_td_blinded_non_mem_proof =
            base_acc_rsa_td.blind_non_mem_proof_raw(&non_element_rsa);

        let class_acc_t = base_acc_class.acc.clone();
        let class_mem_proof = base_acc_class
            .mem_proof_create_raw(&ep_class)
            .expect("class-group membership proof");
        let class_blinded_mem_proof = base_acc_class.blind_mem_proof_raw(&class_mem_proof);
        let class_blinded_non_mem_proof =
            base_acc_class.blind_non_mem_proof_raw(&non_element_class);

        let bilinear_acc_t = *base_acc_bilinear.value();
        let bilinear_non_mem_proof = base_acc_bilinear
            .non_mem_proof_create_raw(non_element_bilinear)
            .expect("bilinear non-membership proof");

        let mut s_poly_base = DensePolynomial::from_coefficients_vec(vec![Fr::from(1u64)]);
        for xi in std::iter::once(&element_bilinear).chain(base_elements_bilinear.iter()) {
            let factor = DensePolynomial::from_coefficients_vec(vec![-*xi, Fr::from(1u64)]);
            s_poly_base = &s_poly_base * &factor;
        }
        let (bilinear_q, _) = syn_div_fr(&s_poly_base, &element_bilinear);

        let mut running_rsa = base_acc_rsa.clone();
        let mut running_rsa_td = base_acc_rsa_td.clone();
        let mut running_class = base_acc_class.clone();
        let mut running_bilinear = base_acc_bilinear.clone();

        let mut update_exps_rsa: Vec<BigUint> = Vec::with_capacity(max_k);
        let mut update_exps_rsa_td: Vec<BigUint> = Vec::with_capacity(max_k);
        let mut update_exps_class: Vec<_> = Vec::with_capacity(max_k);

        let mut prev_k = 0usize;

        for &k in UPDATE_SIZES.iter() {
            for i in prev_k..k {
                update_exps_rsa.push(running_rsa.add_raw(&update_inputs_rsa[i]));
                update_exps_rsa_td.push(running_rsa_td.add_raw(&update_inputs_rsa_td[i]));
                update_exps_class.push(running_class.add_raw(&update_inputs_class[i]));
                running_bilinear.add_raw(&update_elements_bilinear[i]);
            }
            prev_k = k;

            let rsa_upd_acc = running_rsa.clone();
            let rsa_td_upd_acc = running_rsa_td.clone();
            let class_upd_acc = running_class.clone();
            let bilinear_upd_acc = running_bilinear.clone();

            let rsa_upd_delta = rsa_update_delta(&rsa_upd_acc, &update_exps_rsa);
            let rsa_td_upd_delta = rsa_update_delta(&rsa_td_upd_acc, &update_exps_rsa_td);
            let class_upd_delta = update_exps_class
                .iter()
                .fold(ClassGroup::exp_id(), |prod, e| {
                    ClassGroup::exp_mul(&prod, e)
                })
                .0;

            let rsa_full_delta = BigInt::from(rsa_upd_acc.calculate_product());
            let rsa_td_full_delta = BigInt::from(rsa_td_upd_acc.calculate_product());
            let class_full_delta = class_upd_acc.calculate_product_unreduced();

            let bilinear_update_elements = &update_elements_bilinear[..k];

            let (bilinear_crs_prime, _r) = base_acc_bilinear
                .blind_mem_proof_raw(&mut rng, &bilinear_q, k)
                .expect("bilinear blind membership proof");
            let bilinear_pi_blinded = bilinear_crs_prime
                .first()
                .copied()
                .expect("blinded CRS must include base term");
            let bilinear_q_star = bilinear_update_elements.iter().fold(
                DensePolynomial::from_coefficients_vec(vec![Fr::from(1u64)]),
                |acc_poly, xi| {
                    let factor = DensePolynomial::from_coefficients_vec(vec![-*xi, Fr::from(1u64)]);
                    &acc_poly * &factor
                },
            );
            let bilinear_powers_acc_t =
                bilinear_upd_acc.shift_com(&s_poly_base, bilinear_q_star.coeffs().len());

            let bilinear_non_mem_chain = {
                let mut acc_for_chain = base_acc_bilinear.clone();
                let mut proof_for_chain = bilinear_non_mem_proof.clone();
                let mut prepared_inputs = Vec::with_capacity(k);

                for sn_plus_one in bilinear_update_elements.iter() {
                    let (blinded_non_mem_proof, r) = acc_for_chain
                        .blind_non_mem_proof_raw(&proof_for_chain, non_element_bilinear);
                    let acc_t = *acc_for_chain.value();

                    let mut acc_after_update = acc_for_chain.clone();
                    acc_after_update.add_raw(sn_plus_one);

                    let (blinded_updated_proof, _g2_sn_plus_one) = acc_after_update
                        .blind_non_mem_proof_upd_raw(&blinded_non_mem_proof, &acc_t, sn_plus_one);

                    proof_for_chain = acc_after_update.unblind_non_mem_proof_raw(
                        &blinded_updated_proof,
                        &(r, blinded_non_mem_proof.1),
                        non_element_bilinear,
                    );

                    prepared_inputs.push((blinded_non_mem_proof, acc_t, *sn_plus_one));
                    acc_for_chain = acc_after_update;
                }

                prepared_inputs
            };

            group.bench_with_input(
                BenchmarkId::new("rsa_trapdoorless_non_mem_blind_proof_upd", k),
                &k,
                |b, &_n| {
                    b.iter(|| {
                        black_box(rsa_upd_acc.blind_non_mem_proof_upd_raw(
                            black_box(&rsa_blinded_non_mem_proof.0),
                            black_box(&rsa_full_delta),
                        ));
                    });
                },
            );

            group.bench_with_input(
                BenchmarkId::new("rsa_trapdoored_non_mem_blind_proof_upd", k),
                &k,
                |b, &_n| {
                    b.iter(|| {
                        black_box(rsa_td_upd_acc.blind_non_mem_proof_upd_raw(
                            black_box(&rsa_td_blinded_non_mem_proof.0),
                            black_box(&rsa_td_full_delta),
                        ));
                    });
                },
            );

            group.bench_with_input(
                BenchmarkId::new("class_non_mem_blind_proof_upd", k),
                &k,
                |b, &_n| {
                    b.iter(|| {
                        black_box(class_upd_acc.blind_non_mem_proof_upd_raw(
                            black_box(&class_blinded_non_mem_proof.0),
                            black_box(&class_full_delta),
                        ));
                    });
                },
            );

            group.bench_with_input(
                BenchmarkId::new("bilinear_non_mem_blind_proof_upd", k),
                &k,
                |b, &_n| {
                    b.iter(|| {
                        for (blinded_non_mem_proof, acc_t, sn_plus_one) in
                            bilinear_non_mem_chain.iter()
                        {
                            let _ = black_box(bilinear_upd_acc.blind_non_mem_proof_upd_raw(
                                black_box(blinded_non_mem_proof),
                                black_box(acc_t),
                                black_box(sn_plus_one),
                            ));
                        }
                    });
                },
            );

            group.bench_with_input(
                BenchmarkId::new("rsa_trapdoorless_mem_blind_proof_upd", k),
                &k,
                |b, &_n| {
                    b.iter(|| {
                        black_box(rsa_upd_acc.blind_mem_proof_upd_raw(
                            black_box(&rsa_acc_t),
                            black_box(&rsa_blinded_mem_proof.0),
                            black_box(&rsa_upd_delta),
                        ));
                    });
                },
            );

            group.bench_with_input(
                BenchmarkId::new("rsa_trapdoored_mem_blind_proof_upd", k),
                &k,
                |b, &_n| {
                    b.iter(|| {
                        black_box(rsa_td_upd_acc.blind_mem_proof_upd_raw(
                            black_box(&rsa_td_acc_t),
                            black_box(&rsa_td_blinded_mem_proof.0),
                            black_box(&rsa_td_upd_delta),
                        ));
                    });
                },
            );

            group.bench_with_input(
                BenchmarkId::new("class_mem_blind_proof_upd", k),
                &k,
                |b, &_n| {
                    b.iter(|| {
                        black_box(class_upd_acc.blind_mem_proof_upd_raw(
                            black_box(&class_acc_t),
                            black_box(&class_blinded_mem_proof.0),
                            black_box(&class_upd_delta),
                        ));
                    });
                },
            );

            group.bench_with_input(
                BenchmarkId::new("bilinear_mem_blind_proof_upd", k),
                &k,
                |b, &_n| {
                    b.iter(|| {
                        black_box(bilinear_upd_acc.blind_mem_proof_upd_raw(
                            black_box(&bilinear_pi_blinded),
                            black_box(&bilinear_acc_t),
                            black_box(&bilinear_crs_prime),
                            black_box(&bilinear_q_star),
                            black_box(&bilinear_powers_acc_t),
                        ));
                    });
                },
            );

            group.bench_with_input(
                BenchmarkId::new("rsa_trapdoorless_mem_proof_create", k),
                &k,
                |b, &_n| {
                    b.iter(|| {
                        black_box(rsa_upd_acc.mem_proof_create_raw(black_box(&ep_rsa)));
                    });
                },
            );

            group.bench_with_input(
                BenchmarkId::new("rsa_trapdoored_mem_proof_create", k),
                &k,
                |b, &_n| {
                    b.iter(|| {
                        black_box(rsa_td_upd_acc.mem_proof_create_raw(black_box(&ep_rsa_td)));
                    });
                },
            );

            group.bench_with_input(
                BenchmarkId::new("class_mem_proof_create", k),
                &k,
                |b, &_n| {
                    b.iter(|| {
                        black_box(class_upd_acc.mem_proof_create_raw(black_box(&ep_class)));
                    });
                },
            );

            group.bench_with_input(
                BenchmarkId::new("bilinear_mem_proof_create", k),
                &k,
                |b, &_n| {
                    b.iter(|| {
                        black_box(
                            bilinear_upd_acc
                                .mem_proof_create_raw(black_box(element_bilinear))
                                .expect("bilinear membership proof"),
                        );
                    });
                },
            );

            group.bench_with_input(
                BenchmarkId::new("rsa_trapdoorless_non_mem_proof_create", k),
                &k,
                |b, &_n| {
                    b.iter(|| {
                        black_box(rsa_upd_acc.non_mem_proof_create_raw(
                            black_box(&non_element_rsa),
                            black_box(&rsa_full_delta),
                        ));
                    });
                },
            );

            group.bench_with_input(
                BenchmarkId::new("rsa_trapdoored_non_mem_proof_create", k),
                &k,
                |b, &_n| {
                    b.iter(|| {
                        black_box(rsa_td_upd_acc.non_mem_proof_create_raw(
                            black_box(&non_element_rsa),
                            black_box(&rsa_td_full_delta),
                        ));
                    });
                },
            );

            group.bench_with_input(
                BenchmarkId::new("class_non_mem_proof_create", k),
                &k,
                |b, &_n| {
                    b.iter(|| {
                        black_box(class_upd_acc.non_mem_proof_create_raw(
                            black_box(&non_element_class),
                            black_box(&class_full_delta),
                        ));
                    });
                },
            );

            group.bench_with_input(
                BenchmarkId::new("bilinear_non_mem_proof_create", k),
                &k,
                |b, &_n| {
                    b.iter(|| {
                        black_box(
                            bilinear_upd_acc
                                .non_mem_proof_create_raw(black_box(non_element_bilinear))
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
