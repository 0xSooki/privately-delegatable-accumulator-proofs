use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::Zero;
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial};
use ark_std::test_rng;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
#[cfg(feature = "class-group")]
use private_accumulator_proof_delegation::groups::ClassGroup;
use private_accumulator_proof_delegation::{
    groups::RsaGroup, BilinearAccumulator, Group, RsaAccumulator,
};

const MEMBER_RAW: u64 = 200_003;
const NON_MEMBER_RAW: u64 = 741_569;
const UPDATE_RAW: u64 = 900_001;

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

fn build_poly_from_roots(roots: &[Fr]) -> DensePolynomial<Fr> {
    roots.iter().fold(
        DensePolynomial::from_coefficients_vec(vec![Fr::from(1u64)]),
        |acc_poly, xi| {
            let factor = DensePolynomial::from_coefficients_vec(vec![-*xi, Fr::from(1u64)]);
            &acc_poly * &factor
        },
    )
}

fn benchmark_o1_membership_ops(c: &mut Criterion) {
    let mut group = c.benchmark_group("o1_membership_proofs");
    group.sample_size(10);

    let mut rsa_acc_mem = RsaAccumulator::<RsaGroup>::setup_trapdoorless();
    let rsa_ep = rsa_acc_mem.add_raw(&MEMBER_RAW);
    for v in [2u64, 3, 5, 7, 11] {
        rsa_acc_mem.add_raw(&v);
    }
    let rsa_mem_proof = rsa_acc_mem.mem_proof_create_raw(&rsa_ep).unwrap();
    let rsa_blinded_mem = rsa_acc_mem.blind_mem_proof_raw(&rsa_mem_proof);

    let mut rsa_acc_mem_upd = rsa_acc_mem.clone();
    let rsa_blinded_mem_for_ver = rsa_blinded_mem.0.clone();
    let rsa_acc_t = rsa_acc_mem_upd.value_raw().clone();
    let rsa_update_exp = rsa_acc_mem_upd.add_raw(&UPDATE_RAW);
    let rsa_update_delta = num_bigint::BigInt::from(rsa_update_exp);
    let (rsa_upd_blinded_mem, rsa_mem_aux, _) = rsa_acc_mem_upd
        .blind_mem_proof_upd_raw(&rsa_acc_t, &rsa_blinded_mem_for_ver, &rsa_update_delta)
        .unwrap();

    group.bench_function("rsa_blind_mem_proof", |b| {
        b.iter(|| {
            let _ = black_box(rsa_acc_mem.blind_mem_proof_raw(&rsa_mem_proof));
        });
    });

    group.bench_function("rsa_unblind_mem_proof", |b| {
        b.iter(|| {
            let _ = black_box(
                rsa_acc_mem.unblind_mem_proof_raw(&rsa_blinded_mem.0, &rsa_blinded_mem.1),
            );
        });
    });

    group.bench_function("rsa_ver_blind_mem_proof_upd", |b| {
        b.iter(|| {
            black_box(rsa_acc_mem_upd.ver_blind_mem_proof_upd_raw(
                &rsa_acc_t,
                &rsa_blinded_mem_for_ver,
                &rsa_upd_blinded_mem,
                &rsa_mem_aux,
            ));
        });
    });

    #[cfg(feature = "class-group")]
    {
        let mut class_acc_mem = RsaAccumulator::<ClassGroup>::setup_trapdoorless();
        let class_ep = class_acc_mem.add_raw(&MEMBER_RAW);
        for v in [2u64, 3, 5, 7, 11] {
            class_acc_mem.add_raw(&v);
        }
        let class_mem_proof = class_acc_mem.mem_proof_create_raw(&class_ep).unwrap();
        let class_blinded_mem = class_acc_mem.blind_mem_proof_raw(&class_mem_proof);

        let mut class_acc_mem_upd = class_acc_mem.clone();
        let class_blinded_mem_for_ver = class_blinded_mem.0.clone();
        let class_acc_t = class_acc_mem_upd.value_raw().clone();
        let class_update_exp = class_acc_mem_upd.add_raw(&UPDATE_RAW);
        let class_update_delta = class_update_exp.0.clone();
        let (class_upd_blinded_mem, class_mem_aux, _) = class_acc_mem_upd
            .blind_mem_proof_upd_raw(
                &class_acc_t,
                &class_blinded_mem_for_ver,
                &class_update_delta,
            )
            .unwrap();

        group.bench_function("class_blind_mem_proof", |b| {
            b.iter(|| {
                let _ = black_box(class_acc_mem.blind_mem_proof_raw(&class_mem_proof));
            });
        });

        group.bench_function("class_unblind_mem_proof", |b| {
            b.iter(|| {
                let _ = black_box(
                    class_acc_mem.unblind_mem_proof_raw(&class_blinded_mem.0, &class_blinded_mem.1),
                );
            });
        });

        group.bench_function("class_ver_blind_mem_proof_upd", |b| {
            b.iter(|| {
                black_box(class_acc_mem_upd.ver_blind_mem_proof_upd_raw(
                    &class_acc_t,
                    &class_blinded_mem_for_ver,
                    &class_upd_blinded_mem,
                    &class_mem_aux,
                ));
            });
        });
    }

    let member = Fr::from(MEMBER_RAW);
    let update = Fr::from(UPDATE_RAW);
    let other_roots = [2u64, 3, 5, 7, 11].map(Fr::from);

    let mut bilinear_acc_mem = {
        let mut rng = test_rng();
        BilinearAccumulator::<Bls12_381>::setup(&mut rng, 64)
    };
    bilinear_acc_mem.add_raw(&member);
    for x in other_roots {
        bilinear_acc_mem.add_raw(&x);
    }

    let mut roots = vec![member];
    roots.extend_from_slice(&other_roots);
    let bilinear_s_poly = build_poly_from_roots(&roots);
    let (bilinear_q, _) = syn_div_fr(&bilinear_s_poly, &member);

    group.bench_function("bilinear_blind_mem_proof", |b| {
        b.iter(|| {
            let mut rng = test_rng();
            let _ = black_box(
                bilinear_acc_mem
                    .blind_mem_proof_raw(&mut rng, &bilinear_q, 1)
                    .expect("bilinear blind membership proof"),
            );
        });
    });

    let (bilinear_crs_prime, bilinear_r) = {
        let mut rng = test_rng();
        bilinear_acc_mem
            .blind_mem_proof_raw(&mut rng, &bilinear_q, 1)
            .expect("bilinear blind membership proof")
    };
    let bilinear_pi_blinded = bilinear_crs_prime
        .first()
        .copied()
        .expect("blinded CRS must include base term");

    let mut bilinear_acc_mem_upd = bilinear_acc_mem.clone();
    let bilinear_acc_t = bilinear_acc_mem_upd.value_raw();
    let bilinear_q_star = DensePolynomial::from_coefficients_vec(vec![-update, Fr::from(1u64)]);
    let bilinear_powers_acc_t =
        bilinear_acc_mem_upd.shift_com(&bilinear_s_poly, bilinear_q_star.coeffs().len());
    bilinear_acc_mem_upd.add_raw(&update);
    let (bilinear_pi_prime, bilinear_mem_poe_eq_proof, bilinear_mem_delta) = bilinear_acc_mem_upd
        .blind_mem_proof_upd_raw(
            &bilinear_pi_blinded,
            &bilinear_acc_t,
            bilinear_crs_prime,
            bilinear_q_star,
            bilinear_powers_acc_t,
        );

    group.bench_function("bilinear_unblind_mem_proof", |b| {
        b.iter(|| {
            let _ = black_box(BilinearAccumulator::<Bls12_381>::unblind_mem_proof_raw(
                &bilinear_pi_prime,
                &bilinear_r,
            ));
        });
    });

    group.bench_function("bilinear_ver_blind_mem_proof_upd", |b| {
        b.iter(|| {
            black_box(bilinear_acc_mem_upd.ver_blind_mem_proof_upd_raw(
                &bilinear_pi_blinded,
                &bilinear_pi_prime,
                &bilinear_acc_t,
                &bilinear_mem_delta,
                &bilinear_mem_poe_eq_proof,
            ));
        });
    });

    group.finish();
}

fn benchmark_o1_non_membership_ops(c: &mut Criterion) {
    let mut group = c.benchmark_group("o1_non_membership_proofs");
    group.sample_size(10);
    let update = Fr::from(UPDATE_RAW);

    let mut rsa_acc_non_mem = RsaAccumulator::<RsaGroup>::setup_trapdoorless();
    for v in [2u64, 3, 5, 7, 11] {
        rsa_acc_non_mem.add_raw(&v);
    }
    let rsa_non_member = num_bigint::BigUint::from(NON_MEMBER_RAW);
    let rsa_blinded_non_mem = rsa_acc_non_mem.blind_non_mem_proof_raw(&rsa_non_member);

    let mut rsa_acc_non_mem_upd = rsa_acc_non_mem.clone();
    rsa_acc_non_mem_upd.add_raw(&UPDATE_RAW);
    let rsa_acc_t_prime = rsa_acc_non_mem_upd.value_raw().clone();
    let rsa_delta = num_bigint::BigInt::from(rsa_acc_non_mem_upd.calculate_product());
    let rsa_upd_blinded_non_mem = rsa_acc_non_mem_upd
        .blind_non_mem_proof_upd_raw(&rsa_blinded_non_mem.0, &rsa_delta)
        .unwrap();

    group.bench_function("rsa_blind_non_mem_proof", |b| {
        b.iter(|| {
            let _ = black_box(rsa_acc_non_mem.blind_non_mem_proof_raw(&rsa_non_member));
        });
    });

    group.bench_function("rsa_unblind_non_mem_proof", |b| {
        b.iter(|| {
            let _ = black_box(
                rsa_acc_non_mem_upd
                    .unblind_non_mem_proof_raw(&rsa_blinded_non_mem.1, &rsa_upd_blinded_non_mem),
            );
        });
    });

    group.bench_function("rsa_ver_blind_non_mem_proof_upd", |b| {
        b.iter(|| {
            black_box(rsa_acc_non_mem_upd.ver_blind_non_mem_proof_upd_raw(
                &rsa_acc_t_prime,
                &rsa_blinded_non_mem.0,
                &rsa_upd_blinded_non_mem,
            ));
        });
    });

    #[cfg(feature = "class-group")]
    {
        let mut class_acc_non_mem = RsaAccumulator::<ClassGroup>::setup_trapdoorless();
        for v in [2u64, 3, 5, 7, 11] {
            class_acc_non_mem.add_raw(&v);
        }
        let class_non_member = class_acc_non_mem
            .group
            .hash_to_prime(&NON_MEMBER_RAW.to_be_bytes());
        let class_blinded_non_mem = class_acc_non_mem.blind_non_mem_proof_raw(&class_non_member);

        let mut class_acc_non_mem_upd = class_acc_non_mem.clone();
        class_acc_non_mem_upd.add_raw(&UPDATE_RAW);
        let class_acc_t_prime = class_acc_non_mem_upd.value_raw().clone();
        let class_delta = class_acc_non_mem_upd.calculate_product_unreduced();
        let class_upd_blinded_non_mem = class_acc_non_mem_upd
            .blind_non_mem_proof_upd_raw(&class_blinded_non_mem.0, &class_delta)
            .unwrap();

        group.bench_function("class_blind_non_mem_proof", |b| {
            b.iter(|| {
                let _ = black_box(class_acc_non_mem.blind_non_mem_proof_raw(&class_non_member));
            });
        });

        group.bench_function("class_unblind_non_mem_proof", |b| {
            b.iter(|| {
                let _ = black_box(class_acc_non_mem_upd.unblind_non_mem_proof_raw(
                    &class_blinded_non_mem.1,
                    &class_upd_blinded_non_mem,
                ));
            });
        });

        group.bench_function("class_ver_blind_non_mem_proof_upd", |b| {
            b.iter(|| {
                black_box(class_acc_non_mem_upd.ver_blind_non_mem_proof_upd_raw(
                    &class_acc_t_prime,
                    &class_blinded_non_mem.0,
                    &class_upd_blinded_non_mem,
                ));
            });
        });
    }

    let mut bilinear_acc_non_mem = {
        let mut rng = test_rng();
        BilinearAccumulator::<Bls12_381>::setup(&mut rng, 64)
    };
    for v in [2u64, 3, 5, 7, 11] {
        bilinear_acc_non_mem.add_raw(&Fr::from(v));
    }
    let bilinear_non_member = Fr::from(NON_MEMBER_RAW);
    let bilinear_non_mem_proof = bilinear_acc_non_mem
        .non_mem_proof_create_raw(bilinear_non_member)
        .expect("bilinear non-membership proof");
    let (bilinear_blinded_non_mem, bilinear_non_mem_r) =
        bilinear_acc_non_mem.blind_non_mem_proof_raw(&bilinear_non_mem_proof, bilinear_non_member);

    let mut bilinear_acc_non_mem_upd = bilinear_acc_non_mem.clone();
    let bilinear_acc_t = bilinear_acc_non_mem_upd.value_raw();
    bilinear_acc_non_mem_upd.add_raw(&update);
    let (bilinear_upd_blinded_non_mem, bilinear_g2_sn_plus_one) = bilinear_acc_non_mem_upd
        .blind_non_mem_proof_upd_raw(&bilinear_blinded_non_mem, &bilinear_acc_t, &update);

    group.bench_function("bilinear_blind_non_mem_proof", |b| {
        b.iter(|| {
            let _ = black_box(
                bilinear_acc_non_mem
                    .blind_non_mem_proof_raw(&bilinear_non_mem_proof, bilinear_non_member),
            );
        });
    });

    group.bench_function("bilinear_unblind_non_mem_proof", |b| {
        b.iter(|| {
            let _ = black_box(bilinear_acc_non_mem_upd.unblind_non_mem_proof_raw(
                &bilinear_upd_blinded_non_mem,
                &(bilinear_non_mem_r, bilinear_blinded_non_mem.1),
                bilinear_non_member,
            ));
        });
    });

    group.bench_function("bilinear_ver_blind_non_mem_proof_upd", |b| {
        b.iter(|| {
            black_box(bilinear_acc_non_mem_upd.ver_blind_non_mem_proof_upd_raw(
                &bilinear_acc_t,
                &bilinear_blinded_non_mem,
                &bilinear_upd_blinded_non_mem,
                &bilinear_g2_sn_plus_one,
            ));
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    benchmark_o1_membership_ops,
    benchmark_o1_non_membership_ops
);
criterion_main!(benches);
